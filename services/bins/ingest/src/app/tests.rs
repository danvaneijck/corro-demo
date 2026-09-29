//! Webhook pipeline tests against DynamoDB Local (set `DYNAMODB_ENDPOINT`), with requests
//! signed the way `scripts/sign-webhook.sh` signs them.

use adapters::sign;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{Credentials, Region};
use domain::{ConvId, ExternalId, RouteAddress, TenantId, TenantScope, UserId};
use serde_json::{Value, json};
use store::admin::{Admin, create_table};
use store::{AuditReader, InboxRepo};

use super::*;

const ROOT: &[u8] = b"test-root-key";
const SLACK: &[u8] = include_bytes!("../../../../../fixtures/slack_message.json");
const SMS: &[u8] = include_bytes!("../../../../../fixtures/sms_message.txt");

struct Env {
    client: Client,
    table: String,
    audit_table: String,
}

fn scope(t: &str) -> TenantScope {
    TenantScope::for_operator(TenantId::parse(t).unwrap())
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
    let env = Env {
        client,
        table: format!("inbox-{id}"),
        audit_table: format!("audit-{id}"),
    };
    create_table(&env.client, &env.table).await.unwrap();
    create_table(&env.client, &env.audit_table).await.unwrap();

    let admin = Admin::new(env.client.clone(), &env.table);
    let acme = scope("acme");
    let x = |s| ExternalId::parse(s).unwrap();
    admin
        .put_conversation(&acme, &ConvId::parse("c_ops").unwrap(), "#ops")
        .await
        .unwrap();
    admin
        .put_conversation(&acme, &ConvId::parse("c_sms").unwrap(), "SMS line")
        .await
        .unwrap();
    admin
        .put_route(
            Channel::Slack,
            &RouteAddress::new(&[&x("T0ACME"), &x("C0OPS")]),
            &acme,
            &ConvId::parse("c_ops").unwrap(),
        )
        .await
        .unwrap();
    admin
        .put_route(
            Channel::Sms,
            &RouteAddress::new(&[&x("+61400000001")]),
            &acme,
            &ConvId::parse("c_sms").unwrap(),
        )
        .await
        .unwrap();
    admin
        .put_ident(
            &acme,
            Channel::Slack,
            &x("U024BE7LH"),
            &UserId::parse("bob").unwrap(),
        )
        .await
        .unwrap();
    Some(env)
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

fn state(env: &Env, audit_table: &str) -> State {
    State {
        clients: Clients::Fixed(env.client.clone()),
        keys: Keys::Fixed(ROOT.to_vec()),
        routes: RouteRepo::new(env.client.clone(), &env.table),
        own: env.client.clone(),
        audit: AuditWriter::new(
            env.client.clone(),
            audit_table,
            ServiceInfo {
                fn_name: "ingest-fn".into(),
                version: "test".into(),
            },
        ),
        table: env.table.clone(),
    }
}

enum Sig {
    Valid,
    Wrong,
    StaleBy(i64),
    Missing,
}

fn request(channel: &str, body: &[u8], sig: Sig) -> Request {
    let ch = Channel::parse_inbound(channel);
    let (ts_h, sig_h, content_type) = match ch {
        Some(Channel::Sms) => (
            "x-webhook-timestamp",
            "x-webhook-signature",
            "application/x-www-form-urlencoded",
        ),
        _ => (
            "x-slack-request-timestamp",
            "x-slack-signature",
            "application/json",
        ),
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let key = ch.map(|c| channel_key(ROOT, c)).unwrap_or_default();
    let mut headers = serde_json::Map::new();
    headers.insert("content-type".into(), json!(content_type));
    match sig {
        Sig::Missing => {}
        Sig::Valid | Sig::Wrong | Sig::StaleBy(_) => {
            let ts = match sig {
                Sig::StaleBy(s) => now - s,
                _ => now,
            }
            .to_string();
            let signing_key: &[u8] = if matches!(sig, Sig::Wrong) {
                b"attacker"
            } else {
                &key
            };
            headers.insert(ts_h.into(), json!(ts));
            headers.insert(sig_h.into(), json!(sign(signing_key, &ts, body)));
        }
    }
    let path = format!("/inbound/{channel}");
    let event = json!({
        "version": "2.0", "routeKey": "POST /inbound/{channel}", "rawPath": path, "rawQueryString": "",
        "headers": headers,
        "pathParameters": { "channel": channel },
        "requestContext": {
            "accountId": "000000000000", "apiId": "api", "domainName": "example", "domainPrefix": "example",
            "http": { "method": "POST", "path": path, "protocol": "HTTP/1.1", "sourceIp": "198.51.100.7", "userAgent": "Slackbot 1.0" },
            "requestId": "req-1", "routeKey": "POST /inbound/{channel}", "stage": "$default",
            "time": "30/Sep/2026:09:15:02 +0000", "timeEpoch": 0,
        },
        "body": std::str::from_utf8(body).unwrap(),
        "isBase64Encoded": false,
    });
    lambda_http::request::from_str(&event.to_string()).unwrap()
}

async fn send(st: &State, req: Request) -> (u16, Value) {
    let resp = handle(st, req).await.unwrap();
    let status = resp.status().as_u16();
    let body = match resp.body() {
        Body::Text(t) => serde_json::from_str(t).unwrap_or(Value::Null),
        _ => Value::Null,
    };
    (status, body)
}

async fn messages(env: &Env, conv: &str) -> Vec<CanonicalMessage> {
    InboxRepo::new(env.client.clone(), &env.table, scope("acme"))
        .list_messages(&ConvId::parse(conv).unwrap(), 50, None)
        .await
        .unwrap()
        .items
}

async fn audit_log(env: &Env) -> Vec<Value> {
    let today = store::time_fmt::day(OffsetDateTime::now_utc());
    AuditReader::new(env.client.clone(), &env.audit_table, scope("acme"))
        .list_day(&today, 100, None)
        .await
        .unwrap()
        .items
}

#[tokio::test]
async fn slack_message_is_stored_once_and_both_deliveries_are_audited() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);

    let (status, body) = send(&st, request("slack", SLACK, Sig::Valid)).await;
    assert_eq!((status, body["outcome"].as_str()), (200, Some("appended")));
    // Slack retries the same event.
    let (status, body) = send(&st, request("slack", SLACK, Sig::Valid)).await;
    assert_eq!((status, body["outcome"].as_str()), (200, Some("duplicate")));

    let msgs = messages(&env, "c_ops").await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].sender,
        Sender::User {
            user_id: UserId::parse("bob").unwrap()
        },
        "linked Slack identity"
    );
    assert_eq!(msgs[0].channel, Channel::Slack);

    let log = audit_log(&env).await;
    let outcomes: Vec<&str> = log.iter().map(|r| r["outcome"].as_str().unwrap()).collect();
    assert_eq!(outcomes, vec!["duplicate", "allowed"]);
    assert!(
        log.iter()
            .all(|r| r["actor"]["type"] == "integration:slack")
    );
}

#[tokio::test]
async fn sms_form_post_is_translated() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);
    let (status, _) = send(&st, request("sms", SMS, Sig::Valid)).await;
    assert_eq!(status, 200);
    let msgs = messages(&env, "c_sms").await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].body_text, "Is the outage fixed?");
    assert!(
        matches!(&msgs[0].sender, Sender::External { address, .. } if address == "+61400000999")
    );
}

#[tokio::test]
async fn bad_signatures_are_rejected_and_nothing_is_written() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);
    for sig in [Sig::Wrong, Sig::Missing, Sig::StaleBy(301)] {
        let (status, body) = send(&st, request("slack", SLACK, sig)).await;
        assert_eq!((status, body), (401, json!({ "error": "unauthorized" })));
    }
    // An SMS signed with the Slack key is also rejected: keys are per channel.
    let now = OffsetDateTime::now_utc().unix_timestamp().to_string();
    let mut req = request("sms", SMS, Sig::Missing);
    req.headers_mut()
        .insert("x-webhook-timestamp", now.parse().unwrap());
    req.headers_mut().insert(
        "x-webhook-signature",
        sign(&channel_key(ROOT, Channel::Slack), &now, SMS)
            .parse()
            .unwrap(),
    );
    assert_eq!(send(&st, req).await.0, 401);

    assert!(messages(&env, "c_ops").await.is_empty());
    assert!(audit_log(&env).await.is_empty());
}

#[tokio::test]
async fn handshake_ignored_events_and_unknown_routes() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);

    let verification = include_bytes!("../../../../../fixtures/slack_url_verification.json");
    let (status, body) = send(&st, request("slack", verification, Sig::Valid)).await;
    assert_eq!(status, 200);
    assert!(body["challenge"].as_str().unwrap().starts_with("3eZbrw"));

    let bot = include_bytes!("../../../../../fixtures/slack_bot_message.json");
    assert_eq!(
        send(&st, request("slack", bot, Sig::Valid)).await.1["ignored"],
        "message_subtype"
    );

    let unrouted = br#"{"type":"event_callback","team_id":"T0OTHER","event_id":"Ev9","event":{"type":"message","channel":"C1","user":"U1","text":"hi","ts":"1790672400.0001"}}"#;
    assert_eq!(
        send(&st, request("slack", unrouted, Sig::Valid)).await.1["ignored"],
        "no_route"
    );

    assert_eq!(send(&st, request("fax", b"{}", Sig::Valid)).await.0, 404);
    assert_eq!(send(&st, request("email", b"{}", Sig::Valid)).await.0, 404);
    assert!(messages(&env, "c_ops").await.is_empty());
}

#[tokio::test]
async fn audit_failure_returns_500_so_the_provider_retries() {
    let env = env_or_skip!();
    let broken = state(&env, "no-such-table");
    assert_eq!(
        send(&broken, request("slack", SLACK, Sig::Valid)).await.0,
        500
    );
    // The retry (with audit working) is recorded as a duplicate, so the event is in the trail.
    let st = state(&env, &env.audit_table);
    assert_eq!(
        send(&st, request("slack", SLACK, Sig::Valid)).await.1["outcome"],
        "duplicate"
    );
    assert_eq!(audit_log(&env).await[0]["outcome"], "duplicate");
}

#[tokio::test]
async fn route_to_a_missing_conversation_is_dropped_not_retried() {
    let env = env_or_skip!();
    let admin = Admin::new(env.client.clone(), &env.table);
    let addr = RouteAddress::new(&[
        &ExternalId::parse("T0ACME").unwrap(),
        &ExternalId::parse("C0GONE").unwrap(),
    ]);
    admin
        .put_route(
            Channel::Slack,
            &addr,
            &scope("acme"),
            &ConvId::parse("c_gone").unwrap(),
        )
        .await
        .unwrap();
    let body = br#"{"type":"event_callback","team_id":"T0ACME","event_id":"EvGone1","event":{"type":"message","channel":"C0GONE","user":"U1","text":"hi","ts":"1790672400.0001"}}"#;
    let (status, reply) = send(
        &state(&env, &env.audit_table),
        request("slack", body, Sig::Valid),
    )
    .await;
    assert_eq!(
        (status, reply["ignored"].as_str()),
        (200, Some("conversation_missing"))
    );
    let log = audit_log(&env).await;
    assert_eq!(
        (log[0]["outcome"].as_str(), log[0]["reason"].as_str()),
        (Some("error"), Some("not_found"))
    );
}

#[tokio::test]
async fn new_messages_are_counted_for_platform_stats_duplicates_are_not() {
    let env = env_or_skip!();
    let st = state(&env, &env.audit_table);
    send(&st, request("slack", SLACK, Sig::Valid)).await;
    send(&st, request("slack", SLACK, Sig::Valid)).await; // duplicate
    send(&st, request("sms", SMS, Sig::Valid)).await;
    let stats = store::platform::read_stats(&env.client, &env.table, 1)
        .await
        .unwrap();
    let acme = stats[0]
        .tenants
        .iter()
        .find(|t| t.tenant_id == "acme")
        .unwrap();
    assert_eq!(
        (
            acme.messages.get("slack"),
            acme.messages.get("sms"),
            acme.total
        ),
        (Some(&1), Some(&1), 2)
    );
}
