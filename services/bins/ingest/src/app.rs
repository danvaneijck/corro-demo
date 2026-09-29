//! The webhook pipeline: adapter by path → signature check → parse → route lookup →
//! tenant-scoped client for the route's tenant → identity lookup → idempotent append → audit.
//!
//! Always answers 2xx for events it has handled or deliberately ignored, so providers don't
//! retry them; 5xx only when a retry could help (the append is idempotent, so retries are safe).

use std::sync::Arc;
use std::time::{Duration, Instant};

use adapters::{Inbound, InboundMessage, adapter_for, channel_key, verify};
use domain::{CanonicalMessage, Channel, IntegrationPrincipal, MAX_BODY_CHARS, Sender};
use lambda_http::http::StatusCode;
use lambda_http::request::RequestContext;
use lambda_http::{Body, Error, Request, RequestExt, Response};
use moka::future::Cache;
use serde_json::{Value, json};
use store::{
    Action, Actor, AppendOutcome, AuditEvent, AuditWriter, InboxRepo, Outcome, RequestInfo,
    Resource, RouteRepo, ServiceInfo, StoreError, TenantCredsProvider, metrics,
};
use time::OffsetDateTime;
use tracing::{Instrument, field};

pub enum Clients {
    Sts(Box<TenantCredsProvider>),
    /// Tests against DynamoDB Local, which has no IAM. Not compiled into the Lambda.
    #[cfg(test)]
    Fixed(aws_sdk_dynamodb::Client),
}

impl Clients {
    async fn client_for(
        &self,
        scope: &domain::TenantScope,
    ) -> Result<aws_sdk_dynamodb::Client, StoreError> {
        match self {
            Clients::Sts(p) => p.client_for(scope).await,
            #[cfg(test)]
            Clients::Fixed(c) => Ok(c.clone()),
        }
    }
}

/// The webhook root key from Secrets Manager, re-read every 5 minutes so a rotation applies
/// without a redeploy.
pub enum Keys {
    Secret {
        sm: aws_sdk_secretsmanager::Client,
        arn: String,
        cache: Cache<(), Arc<Vec<u8>>>,
    },
    #[cfg(test)]
    Fixed(Vec<u8>),
}

impl Keys {
    async fn root(&self) -> Result<Arc<Vec<u8>>, String> {
        match self {
            Keys::Secret { sm, arn, cache } => cache
                .try_get_with((), async {
                    let out = sm
                        .get_secret_value()
                        .secret_id(arn)
                        .send()
                        .await
                        .map_err(|e| e.to_string())?;
                    let v: Value = serde_json::from_str(out.secret_string().unwrap_or_default())
                        .map_err(|e| e.to_string())?;
                    let root = v["root"]
                        .as_str()
                        .filter(|r| !r.is_empty())
                        .ok_or("secret has no root key")?;
                    Ok::<_, String>(Arc::new(root.as_bytes().to_vec()))
                })
                .await
                .map_err(|e| (*e).clone()),
            #[cfg(test)]
            Keys::Fixed(k) => Ok(Arc::new(k.clone())),
        }
    }
}

pub struct State {
    pub clients: Clients,
    pub keys: Keys,
    pub routes: RouteRepo,
    /// The function's own role: ROUTE# reads, audit appends, PLATFORM#STATS#* counters.
    pub own: aws_sdk_dynamodb::Client,
    pub audit: AuditWriter,
    pub table: String,
}

fn env(name: &str) -> Result<String, Error> {
    std::env::var(name).map_err(|_| format!("missing env var {name}").into())
}

impl State {
    pub async fn from_env() -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        // The function's own role: GetItem on ROUTE#* only, and PutItem on the audit table.
        let own = aws_sdk_dynamodb::Client::new(&config);
        let table = env("TABLE")?;
        Ok(Self {
            clients: Clients::Sts(Box::new(TenantCredsProvider::new(
                &config,
                env("TENANT_ROLE_ARN")?,
                "ingest",
            ))),
            keys: Keys::Secret {
                sm: aws_sdk_secretsmanager::Client::new(&config),
                arn: env("SECRET_ARN")?,
                cache: Cache::builder()
                    .time_to_live(Duration::from_secs(300))
                    .build(),
            },
            routes: RouteRepo::new(own.clone(), &table),
            own: own.clone(),
            audit: AuditWriter::new(
                own,
                env("AUDIT_TABLE")?,
                ServiceInfo {
                    fn_name: "ingest-fn".into(),
                    version: env("GIT_SHA").unwrap_or_else(|_| "unknown".into()),
                },
            ),
            table,
        })
    }
}

struct Meta {
    route_key: String,
    api_request_id: Option<String>,
    source_ip: Option<String>,
    user_agent: Option<String>,
}

fn meta(req: &Request) -> Meta {
    match req.request_context_ref() {
        Some(RequestContext::ApiGatewayV2(ctx)) => Meta {
            route_key: ctx.route_key.clone().unwrap_or_default(),
            api_request_id: ctx.request_id.clone(),
            source_ip: ctx.http.source_ip.clone(),
            user_agent: ctx.http.user_agent.clone(),
        },
        _ => Meta {
            route_key: String::new(),
            api_request_id: None,
            source_ip: None,
            user_agent: None,
        },
    }
}

fn reply(status: StatusCode, body: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static headers are valid")
}

fn error(status: StatusCode, code: &str) -> Response<Body> {
    reply(status, json!({ "error": code }))
}

pub async fn handle(state: &State, req: Request) -> Result<Response<Body>, Error> {
    let started = Instant::now();
    let m = meta(&req);
    let channel = req
        .path_parameters_ref()
        .and_then(|p| p.first("channel"))
        .unwrap_or("")
        .to_owned();
    let span = tracing::info_span!(
        "webhook",
        channel = %channel,
        api_request_id = m.api_request_id.as_deref().unwrap_or(""),
        tenant_id = field::Empty,
        outcome = field::Empty,
    );
    async move {
        let resp = pipeline(state, &req, &m, &channel).await;
        tracing::info!(
            status = resp.status().as_u16(),
            latency_ms = started.elapsed().as_millis() as u64,
            "webhook done"
        );
        Ok(resp)
    }
    .instrument(span)
    .await
}

async fn pipeline(state: &State, req: &Request, m: &Meta, channel: &str) -> Response<Body> {
    if m.route_key != "POST /inbound/{channel}" {
        return error(StatusCode::NOT_FOUND, "not_found");
    }
    let Some(adapter) = Channel::parse_inbound(channel).and_then(adapter_for) else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    let ch = adapter.channel();

    let root = match state.keys.root().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "could not load webhook keys");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
        }
    };
    let now = OffsetDateTime::now_utc();
    let (ts_header, sig_header) = adapter.signature_headers();
    let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());
    let body = req.body().as_ref();
    if let Err(e) = verify(
        &channel_key(&root, ch),
        header(ts_header),
        body,
        header(sig_header),
        now.unix_timestamp(),
    ) {
        // No tenant is known yet, so there's nothing to audit against: metric and log only.
        metrics::count(
            "WebhookRejected",
            &[("channel", ch.as_str()), ("reason", e.as_str())],
        );
        tracing::warn!(reason = e.as_str(), "webhook signature rejected");
        tracing::Span::current().record("outcome", "rejected");
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match adapter.parse(body, now) {
        Err(e) => {
            metrics::count(
                "WebhookRejected",
                &[("channel", ch.as_str()), ("reason", "malformed")],
            );
            tracing::warn!(error = %e, "webhook body rejected");
            error(StatusCode::BAD_REQUEST, "bad_request")
        }
        Ok(Inbound::UrlVerification { challenge }) => {
            reply(StatusCode::OK, json!({ "challenge": challenge }))
        }
        Ok(Inbound::Ignored { reason }) => {
            tracing::Span::current().record("outcome", "ignored");
            reply(StatusCode::OK, json!({ "ok": true, "ignored": reason }))
        }
        Ok(Inbound::Message(msg)) => deliver(state, m, ch, msg, now).await,
    }
}

async fn deliver(
    state: &State,
    m: &Meta,
    ch: Channel,
    msg: InboundMessage,
    now: OffsetDateTime,
) -> Response<Body> {
    let route = match state.routes.get(ch, &msg.address).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            // Accept and drop, so the provider doesn't retry forever; the metric shows it.
            metrics::count("UnroutedMessage", &[("channel", ch.as_str())]);
            tracing::warn!(
                address = msg.address.as_str(),
                "no route for inbound address"
            );
            return reply(StatusCode::OK, json!({ "ok": true, "ignored": "no_route" }));
        }
        Err(e) => {
            tracing::error!(error = %e, "route lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
        }
    };
    // The tenant comes from the route record, never from the payload.
    let principal = IntegrationPrincipal::from_route(ch, route.tenant_id.clone());
    tracing::Span::current().record("tenant_id", route.tenant_id.as_str());

    let result: Result<(AppendOutcome, String), StoreError> = async {
        let scope = principal.scope();
        let repo = InboxRepo::new(state.clients.client_for(&scope).await?, &state.table, scope);
        let sender = match repo.resolve_identity(ch, &msg.sender).await? {
            Some(user_id) => Sender::User { user_id },
            None => Sender::External {
                address: msg.sender.to_string(),
                display_name: msg.sender_display,
            },
        };
        let message = CanonicalMessage {
            message_id: ulid::Ulid::generate(),
            conversation_id: route.conversation_id.clone(),
            channel: ch,
            sender,
            // Providers don't retry on a too-long body, so truncate rather than reject.
            body_text: msg.text.chars().take(MAX_BODY_CHARS).collect(),
            sent_at: msg.sent_at,
            received_at: now,
            external_id: Some(msg.external_id),
        };
        let outcome = repo.append_message(&message).await?;
        Ok((outcome, message.message_id.to_string()))
    }
    .await;

    let (outcome, reason) = match &result {
        Ok((AppendOutcome::Appended, _)) => (Outcome::Allowed, None),
        Ok((AppendOutcome::Duplicate, _)) => {
            (Outcome::Duplicate, Some("already_delivered".to_owned()))
        }
        Err(StoreError::AccessDenied) => {
            (Outcome::DeniedByIam, Some("iam_access_denied".to_owned()))
        }
        Err(e) => (Outcome::Error, Some(e.code().to_owned())),
    };
    tracing::Span::current().record("outcome", field::debug(outcome));

    // The message is written before its audit record. If the audit write fails the provider gets
    // a 500 and retries, and the retry is audited (as a duplicate). Writing both in one
    // cross-table transaction would close that gap.
    let event = AuditEvent {
        tenant_id: route.tenant_id.clone(),
        actor: Actor::integration(ch, m.source_ip.clone(), m.user_agent.clone()),
        action: Action::MessageIngest,
        resource: Some(Resource::new(
            "conversation",
            route.conversation_id.as_str(),
        )),
        outcome,
        reason,
        result_count: None,
        request: RequestInfo {
            api_request_id: m.api_request_id.clone(),
            lambda_request_id: None,
            route: m.route_key.clone(),
            params_hash: None,
        },
    };
    if state.audit.write(&event).await.is_err() {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }

    match result {
        Ok((AppendOutcome::Appended, id)) => {
            metrics::count("MessagesIngested", &[("channel", ch.as_str())]);
            store::platform::count_message_best_effort(
                &state.own,
                &state.table,
                &route.tenant_id,
                ch,
            )
            .await;
            reply(
                StatusCode::OK,
                json!({ "ok": true, "outcome": "appended", "message_id": id }),
            )
        }
        Ok((AppendOutcome::Duplicate, _)) => {
            metrics::count("DuplicateDelivery", &[("channel", ch.as_str())]);
            reply(
                StatusCode::OK,
                json!({ "ok": true, "outcome": "duplicate" }),
            )
        }
        // The route points at a conversation that doesn't exist. Retrying can't fix that, so
        // accept and drop (like an unknown route) instead of making the provider retry forever.
        Err(StoreError::NotFound) => {
            metrics::count("UnroutedMessage", &[("channel", ch.as_str())]);
            tracing::warn!(conversation = %route.conversation_id, "route points at a missing conversation");
            reply(
                StatusCode::OK,
                json!({ "ok": true, "ignored": "conversation_missing" }),
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "ingest failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}

#[cfg(test)]
mod tests;
