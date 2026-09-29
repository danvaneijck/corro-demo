//! End-to-end pipeline tests against DynamoDB Local (set `DYNAMODB_ENDPOINT`), using HTTP API
//! events shaped exactly like API Gateway's, with fake verified claims. DynamoDB Local has no
//! IAM, so these cover the app layer; the deployed probe covers IAM.

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{Credentials, Region};
use domain::{ConvId, TenantId, TenantScope, UserId};
use serde_json::{Value, json};
use store::admin::{Admin, create_table};
use store::{AuditReader, TenantUser};

use super::*;

struct Env {
    client: Client,
    table: String,
    audit_table: String,
}

async fn setup() -> Option<Env> {
    let endpoint = std::env::var("DYNAMODB_ENDPOINT").ok()?;
    let conf = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(Region::new("ap-southeast-2"))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new("local", "local", None, None, "test"))
        .build();
    let client = Client::from_conf(conf);
    let id = ulid::Ulid::generate().to_string().to_lowercase();
    let (table, audit_table) = (format!("inbox-{id}"), format!("audit-{id}"));
    create_table(&client, &table).await.unwrap();
    create_table(&client, &audit_table).await.unwrap();
    seed(&client, &table).await;
    Some(Env {
        client,
        table,
        audit_table,
    })
}

macro_rules! env_or_skip {
    () => {
        match setup().await {
            Some(env) => env,
            None => {
                eprintln!("DYNAMODB_ENDPOINT not set; skipping");
                return;
            }
        }
    };
}

fn scope(t: &str) -> TenantScope {
    TenantScope::for_operator(TenantId::parse(t).unwrap())
}

/// acme: alice (admin), bob, carol. c_ops = all three, c_eng = alice + bob. globex: dave in c_ops.
async fn seed(client: &Client, table: &str) {
    let admin = Admin::new(client.clone(), table);
    let (acme, globex) = (scope("acme"), scope("globex"));
    for (u, role) in [("alice", "admin"), ("bob", "member"), ("carol", "member")] {
        let user = TenantUser {
            user_id: UserId::parse(u).unwrap(),
            email: format!("{u}@acme.test"),
            display_name: u.into(),
            role: role.into(),
        };
        admin.put_user(&acme, &user).await.unwrap();
    }
    let c = |s| ConvId::parse(s).unwrap();
    let u = |s| UserId::parse(s).unwrap();
    admin
        .put_conversation(&acme, &c("c_ops"), "#ops")
        .await
        .unwrap();
    admin
        .put_conversation(&acme, &c("c_eng"), "#eng")
        .await
        .unwrap();
    for (conv, user) in [
        ("c_ops", "alice"),
        ("c_ops", "bob"),
        ("c_ops", "carol"),
        ("c_eng", "alice"),
        ("c_eng", "bob"),
    ] {
        admin
            .put_member(&acme, &c(conv), &u(user), "member")
            .await
            .unwrap();
    }
    admin
        .put_conversation(&globex, &c("c_ops"), "#globex-ops")
        .await
        .unwrap();
    admin
        .put_member(&globex, &c("c_ops"), &u("dave"), "member")
        .await
        .unwrap();
}

fn state(env: &Env, audit_table: &str) -> State {
    State {
        clients: Clients::Fixed(env.client.clone()),
        audit: AuditWriter::new(
            env.client.clone(),
            audit_table,
            ServiceInfo {
                fn_name: "api-fn".into(),
                version: "test".into(),
            },
        ),
        table: env.table.clone(),
        audit_table: env.audit_table.clone(),
        search: DdbScanFallback::default(),
        probe_enabled: true,
        web: WebConfig {
            region: "ap-southeast-2".into(),
            user_pool_id: "pool".into(),
            client_id: "client".into(),
        },
    }
}

struct Call<'a> {
    route_key: &'a str,
    path: String,
    user: Option<(&'a str, &'a str, &'a str)>,
    id: Option<&'a str>,
    query: Vec<(&'a str, String)>,
    body: Option<Value>,
}

fn call<'a>(route_key: &'a str, user: Option<(&'a str, &'a str, &'a str)>) -> Call<'a> {
    let path = route_key.split_once(' ').unwrap().1.to_owned();
    Call {
        route_key,
        path,
        user,
        id: None,
        query: vec![],
        body: None,
    }
}

impl<'a> Call<'a> {
    fn id(mut self, id: &'a str) -> Self {
        self.path = self.path.replace("{id}", id);
        self.id = Some(id);
        self
    }
    fn q(mut self, k: &'a str, v: impl Into<String>) -> Self {
        self.query.push((k, v.into()));
        self
    }
    fn body(mut self, b: Value) -> Self {
        self.body = Some(b);
        self
    }

    fn request(&self) -> Request {
        let method = self.route_key.split_once(' ').unwrap().0;
        let raw_query: Vec<String> = self.query.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let qsp: Map<String, Value> = self
            .query
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();
        let authorizer = self.user.map(|(sub, tenant, role)| {
            json!({ "jwt": { "claims": {
                "sub": sub, "custom:tenant_id": tenant, "custom:role": role, "email": format!("{sub}@{tenant}.test"),
            }, "scopes": null } })
        });
        let event = json!({
            "version": "2.0",
            "routeKey": self.route_key,
            "rawPath": self.path,
            "rawQueryString": raw_query.join("&"),
            "headers": { "user-agent": "test", "content-type": "application/json" },
            "queryStringParameters": if qsp.is_empty() { Value::Null } else { Value::Object(qsp) },
            "pathParameters": self.id.map(|id| json!({ "id": id })),
            "requestContext": {
                "accountId": "000000000000", "apiId": "api", "domainName": "example", "domainPrefix": "example",
                "http": { "method": method, "path": self.path, "protocol": "HTTP/1.1",
                          "sourceIp": "203.0.113.4", "userAgent": "test" },
                "requestId": "req-1", "routeKey": self.route_key, "stage": "$default",
                "time": "30/Sep/2026:09:15:02 +0000", "timeEpoch": 0,
                "authorizer": authorizer,
            },
            "body": self.body.as_ref().map(|b| b.to_string()),
            "isBase64Encoded": false,
        });
        lambda_http::request::from_str(&event.to_string()).expect("valid HTTP API event")
    }

    async fn send(self, state: &State) -> (u16, Value) {
        let resp = handle(state, self.request()).await.unwrap();
        let status = resp.status().as_u16();
        let body = match resp.body() {
            Body::Text(t) => serde_json::from_str(t).unwrap_or(Value::String(t.clone())),
            Body::Binary(b) => serde_json::from_slice(b).unwrap_or(Value::Null),
            Body::Empty => Value::Null,
            _ => Value::Null,
        };
        (status, body)
    }
}

const ALICE: Option<(&str, &str, &str)> = Some(("alice", "acme", "admin"));
const BOB: Option<(&str, &str, &str)> = Some(("bob", "acme", "member"));
const CAROL: Option<(&str, &str, &str)> = Some(("carol", "acme", "member"));
const DAVE: Option<(&str, &str, &str)> = Some(("dave", "globex", "member"));

async fn audit_log(env: &Env, tenant: &str) -> Vec<Value> {
    let today = store::time_fmt::day(time::OffsetDateTime::now_utc());
    AuditReader::new(env.client.clone(), &env.audit_table, scope(tenant))
        .list_day(&today, 100, None)
        .await
        .unwrap()
        .items
}

fn find<'v>(log: &'v [Value], action: &str, outcome: &str) -> Option<&'v Value> {
    log.iter()
        .find(|r| r["action"] == action && r["outcome"] == outcome)
}

#[tokio::test]
async fn post_then_list_messages_and_both_are_audited() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);

    let (status, msg) = call("POST /conversations/{id}/messages", ALICE)
        .id("c_ops")
        .body(json!({ "text": "Outage in region B" }))
        .send(&st)
        .await;
    assert_eq!(status, 201);
    assert_eq!(msg["channel"], "native");

    let (status, page) = call("GET /conversations/{id}/messages", BOB)
        .id("c_ops")
        .send(&st)
        .await;
    assert_eq!(status, 200);
    assert_eq!(page["items"][0]["body_text"], "Outage in region B");

    let log = audit_log(&env, "acme").await;
    assert!(find(&log, "message.create", "allowed").is_some());
    let list = find(&log, "message.list", "allowed").unwrap();
    assert_eq!(list["result_count"], 1);
    assert_eq!(list["actor"]["sub"], "bob");
    assert_eq!(list["resource"]["id"], "c_ops");
    assert!(
        list.get("body_text").is_none(),
        "no message content in audit"
    );
}

#[tokio::test]
async fn non_member_gets_404_and_the_denial_is_audited() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);

    let (status, body) = call("GET /conversations/{id}/messages", CAROL)
        .id("c_eng")
        .send(&st)
        .await;
    assert_eq!((status, body), (404, json!({ "error": "not_found" })));

    let log = audit_log(&env, "acme").await;
    let denial = find(&log, "message.list", "denied").unwrap();
    assert_eq!(denial["reason"], "not_member");
    assert_eq!(denial["actor"]["sub"], "carol");
}

#[tokio::test]
async fn another_tenants_conversation_is_404() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);
    // globex has no c_eng; acme's c_eng is invisible to dave.
    let (status, _) = call("GET /conversations/{id}/messages", DAVE)
        .id("c_eng")
        .send(&st)
        .await;
    assert_eq!(status, 404);
    // Both tenants have a c_ops: dave sees globex's, which is empty.
    call("POST /conversations/{id}/messages", ALICE)
        .id("c_ops")
        .body(json!({ "text": "acme only" }))
        .send(&st)
        .await;
    let (status, page) = call("GET /conversations/{id}/messages", DAVE)
        .id("c_ops")
        .send(&st)
        .await;
    assert_eq!(status, 200);
    assert_eq!(page["items"], json!([]));
}

#[tokio::test]
async fn audit_log_is_admin_only_and_the_403_is_audited() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);

    let (status, body) = call("GET /audit", BOB).send(&st).await;
    assert_eq!((status, body), (403, json!({ "error": "forbidden" })));

    let (status, body) = call("GET /audit", ALICE).send(&st).await;
    assert_eq!(status, 200);
    let items = body["items"].as_array().unwrap();
    let bobs = items.iter().find(|r| r["actor"]["sub"] == "bob").unwrap();
    assert_eq!(
        (bobs["outcome"].as_str(), bobs["reason"].as_str()),
        (Some("denied"), Some("requires_admin"))
    );
}

#[tokio::test]
async fn audit_write_failure_fails_closed() {
    let env = env_or_skip!();
    let st = state(&env, "no-such-table");
    let (status, body) = call("GET /conversations", ALICE).send(&st).await;
    assert_eq!(
        (status, body),
        (500, json!({ "error": "internal_error" })),
        "no data without an audit record"
    );
}

#[tokio::test]
async fn input_is_validated() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);

    let long = "x".repeat(domain::MAX_BODY_CHARS + 1);
    let (status, _) = call("POST /conversations/{id}/messages", ALICE)
        .id("c_ops")
        .body(json!({ "text": long }))
        .send(&st)
        .await;
    assert_eq!(status, 400);
    let (status, _) = call("POST /conversations/{id}/messages", ALICE)
        .id("c_ops")
        .body(json!({ "nope": 1 }))
        .send(&st)
        .await;
    assert_eq!(status, 400);
    let (status, _) = call("GET /conversations/{id}/messages", ALICE)
        .id("c_ops")
        .q("cursor", "dGFtcGVyZWQ")
        .send(&st)
        .await;
    assert_eq!(status, 400);
    let (status, _) = call("GET /search", ALICE).q("q", "x").send(&st).await;
    assert_eq!(status, 400);
    let (status, _) = call("GET /audit", ALICE)
        .q("date", "yesterday")
        .send(&st)
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn missing_claims_and_unknown_routes() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);
    assert_eq!(call("GET /me", None).send(&st).await.0, 401);
    assert_eq!(call("DELETE /me", ALICE).send(&st).await.0, 404);
    let (status, cfg) = call("GET /config.json", None).send(&st).await;
    assert_eq!((status, cfg["clientId"].as_str()), (200, Some("client")));
}

#[tokio::test]
async fn people_and_search() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);
    call("POST /conversations/{id}/messages", BOB)
        .id("c_eng")
        .body(json!({ "text": "Planned OUTAGE tonight" }))
        .send(&st)
        .await;

    let (status, people) = call("GET /people", ALICE).send(&st).await;
    assert_eq!(status, 200);
    let got: Vec<(String, u64)> = people["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["display_name"].as_str().unwrap().to_owned(),
                p["shared"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(got, vec![("bob".to_owned(), 2), ("carol".to_owned(), 1)]);

    let (_, hits) = call("GET /search", ALICE).q("q", "outage").send(&st).await;
    assert_eq!(hits["items"].as_array().unwrap().len(), 1);
    let (_, hits) = call("GET /search", CAROL).q("q", "outage").send(&st).await;
    assert_eq!(hits["items"], json!([]), "carol isn't in c_eng");
}

#[tokio::test]
async fn probe_reports_a_breach_when_nothing_blocks_it() {
    // DynamoDB Local has no IAM, so the cross-tenant read succeeds. The handler must treat that
    // as an isolation failure, not a success. (Deployed, IAM returns AccessDenied instead.)
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);
    let (status, body) = call("GET /debug/probe", ALICE)
        .q("tenant", "globex")
        .send(&st)
        .await;
    assert_eq!((status, body), (500, json!({ "error": "internal_error" })));
    let (status, _) = call("GET /debug/probe", ALICE)
        .q("tenant", "acme")
        .send(&st)
        .await;
    assert_eq!(status, 400);

    let disabled = State {
        probe_enabled: false,
        ..state(&env, &env.audit_table)
    };
    assert_eq!(
        call("GET /debug/probe", ALICE)
            .q("tenant", "globex")
            .send(&disabled)
            .await
            .0,
        404
    );
}
