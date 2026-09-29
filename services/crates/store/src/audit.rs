//! The audit log: one record per read or write of tenant data, and per denial.
//!
//! Records go to their own table through the function's own role, which can only `PutItem`, and
//! the table's resource policy denies updates and deletes to everyone. Writes are fail-closed:
//! callers must propagate the error and fail the request.

use std::collections::HashMap;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::AttributeValue;
use domain::{Channel, Principal, TenantId, TenantScope};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use ulid::Ulid;

use crate::time_fmt::{day, ts_millis};
use crate::{Page, StoreError, cursor, keys, metrics};

/// Hot retention in DynamoDB. Long-term retention belongs in an archive (see DESIGN).
const HOT_RETENTION: Duration = Duration::days(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Action {
    #[serde(rename = "me.read")]
    MeRead,
    #[serde(rename = "conversation.list")]
    ConversationList,
    #[serde(rename = "message.list")]
    MessageList,
    #[serde(rename = "message.create")]
    MessageCreate,
    #[serde(rename = "message.ingest")]
    MessageIngest,
    #[serde(rename = "people.list")]
    PeopleList,
    #[serde(rename = "search.query")]
    SearchQuery,
    #[serde(rename = "audit.read")]
    AuditRead,
    #[serde(rename = "isolation.probe")]
    IsolationProbe,
    #[serde(rename = "platform.stats")]
    PlatformStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied,
    DeniedByIam,
    Error,
    Duplicate,
}

#[derive(Debug, Clone, Serialize)]
pub struct Actor {
    #[serde(rename = "type")]
    pub kind: String,
    pub sub: Option<String>,
    pub username: Option<String>,
    pub role_at_time: Option<String>,
    pub groups: Vec<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

impl Actor {
    pub fn user(p: &Principal, source_ip: Option<String>, user_agent: Option<String>) -> Self {
        Self {
            kind: "user".into(),
            sub: Some(p.sub.to_string()),
            username: Some(p.username.clone()),
            role_at_time: Some(p.role.as_str().into()),
            groups: p.groups.clone(),
            source_ip,
            user_agent,
        }
    }

    pub fn integration(ch: Channel, source_ip: Option<String>, user_agent: Option<String>) -> Self {
        Self {
            kind: format!("integration:{ch}"),
            sub: None,
            username: None,
            role_at_time: None,
            groups: Vec::new(),
            source_ip,
            user_agent,
        }
    }

    /// The actor key for GSI1 (AP13).
    fn id(&self) -> &str {
        self.sub.as_deref().unwrap_or(&self.kind)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

impl Resource {
    pub fn new(kind: &str, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RequestInfo {
    pub api_request_id: Option<String>,
    pub lambda_request_id: Option<String>,
    pub route: String,
    /// A hash of the query parameters, never the values (data minimisation).
    pub params_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub tenant_id: TenantId,
    pub actor: Actor,
    pub action: Action,
    pub resource: Option<Resource>,
    pub outcome: Outcome,
    pub reason: Option<String>,
    pub result_count: Option<u32>,
    pub request: RequestInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    #[serde(rename = "fn")]
    pub fn_name: String,
    pub version: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `sha256:<hex>` of a raw query string, for `RequestInfo::params_hash`.
pub fn hash_params(raw_query: &str) -> Option<String> {
    (!raw_query.is_empty()).then(|| format!("sha256:{}", sha256_hex(raw_query.as_bytes())))
}

/// Builds the stored record: the event plus id, timestamp and service, and a `record_hash` over
/// the canonical JSON (serde_json sorts object keys) of everything else.
pub fn build_record(
    ev: &AuditEvent,
    service: &ServiceInfo,
    now: OffsetDateTime,
    event_id: Ulid,
) -> Value {
    let mut record = serde_json::to_value(ev).unwrap_or_default();
    record["event_id"] = json!(event_id.to_string());
    record["ts"] = json!(ts_millis(now));
    record["service"] = serde_json::to_value(service).unwrap_or_default();
    let hash = sha256_hex(record.to_string().as_bytes());
    record["record_hash"] = json!(format!("sha256:{hash}"));
    record
}

pub struct AuditWriter {
    client: Client,
    table: String,
    service: ServiceInfo,
}

impl AuditWriter {
    /// `client` uses the function's own role (PutItem on the audit table only).
    pub fn new(client: Client, table: impl Into<String>, service: ServiceInfo) -> Self {
        Self {
            client,
            table: table.into(),
            service,
        }
    }

    /// Writes one record. On error the caller must fail the request (fail-closed).
    pub async fn write(&self, ev: &AuditEvent) -> Result<String, StoreError> {
        let now = OffsetDateTime::now_utc();
        let event_id = Ulid::generate();
        let record = build_record(ev, &self.service, now, event_id);
        let ts = ts_millis(now);

        let result = async {
            let mut item: HashMap<String, AttributeValue> = serde_dynamo::to_item(&record)?;
            let s = |v: String| AttributeValue::S(v);
            item.insert("PK".into(), s(keys::audit_pk(&ev.tenant_id, &day(now))));
            item.insert("SK".into(), s(format!("{ts}#{event_id}")));
            item.insert(
                "GSI1PK".into(),
                s(keys::actor_gsi1pk(&ev.tenant_id, ev.actor.id())),
            );
            item.insert("GSI1SK".into(), s(ts.clone()));
            item.insert(
                "expires_at".into(),
                AttributeValue::N((now + HOT_RETENTION).unix_timestamp().to_string()),
            );
            self.client
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item))
                .condition_expression("attribute_not_exists(PK)")
                .send()
                .await
                .map_err(StoreError::from_sdk)?;
            Ok::<_, StoreError>(())
        }
        .await;

        match result {
            Ok(()) => {
                metrics::count("AuditWritten", &[]);
                Ok(event_id.to_string())
            }
            Err(e) => {
                metrics::count("AuditWriteFailed", &[]);
                tracing::error!(error = %e, action = ?ev.action, "audit write failed");
                Err(e)
            }
        }
    }
}

/// AP12: a tenant's audit trail for one day, newest first. Uses tenant-scoped credentials, so
/// an admin can only ever read their own tenant's trail.
pub struct AuditReader {
    client: Client,
    table: String,
    scope: TenantScope,
}

impl AuditReader {
    pub fn new(client: Client, table: impl Into<String>, scope: TenantScope) -> Self {
        Self {
            client,
            table: table.into(),
            scope,
        }
    }

    pub async fn list_day(
        &self,
        day: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> Result<Page<Value>, StoreError> {
        let pk = keys::audit_pk(self.scope.tenant_id(), day);
        let start = cursor.map(|c| cursor::decode(c, &pk, "")).transpose()?;
        let out = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("PK = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(pk))
            .scan_index_forward(false)
            .limit(limit.clamp(1, 100))
            .set_exclusive_start_key(start)
            .send()
            .await
            .map_err(StoreError::from_sdk)?;
        let mut items = Vec::new();
        for item in out.items.unwrap_or_default() {
            let mut v: Value = serde_dynamo::from_item(item)?;
            if let Some(obj) = v.as_object_mut() {
                for k in ["PK", "SK", "GSI1PK", "GSI1SK", "expires_at"] {
                    obj.remove(k);
                }
            }
            items.push(v);
        }
        Ok(Page {
            items,
            next_cursor: out.last_evaluated_key.as_ref().and_then(cursor::encode),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn event() -> AuditEvent {
        AuditEvent {
            tenant_id: TenantId::parse("acme").unwrap(),
            actor: Actor::integration(Channel::Slack, None, None),
            action: Action::MessageIngest,
            resource: Some(Resource::new("conversation", "c_ops")),
            outcome: Outcome::Allowed,
            reason: None,
            result_count: None,
            request: RequestInfo {
                route: "POST /inbound/{channel}".into(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn record_hash_covers_the_record_and_is_stable() {
        let svc = ServiceInfo {
            fn_name: "ingest".into(),
            version: "abc".into(),
        };
        let now = datetime!(2026-09-30 09:15:02.123 UTC);
        let id = Ulid::nil();
        let a = build_record(&event(), &svc, now, id);
        let b = build_record(&event(), &svc, now, id);
        assert_eq!(a["record_hash"], b["record_hash"]);
        assert_eq!(a["action"], "message.ingest");
        assert_eq!(a["actor"]["type"], "integration:slack");

        let mut changed = event();
        changed.outcome = Outcome::Duplicate;
        assert_ne!(
            build_record(&changed, &svc, now, id)["record_hash"],
            a["record_hash"]
        );
    }

    #[test]
    fn params_are_hashed_not_stored() {
        let h = hash_params("q=outage").unwrap();
        assert!(h.starts_with("sha256:"));
        assert!(!h.contains("outage"));
        assert_eq!(hash_params(""), None);
    }
}
