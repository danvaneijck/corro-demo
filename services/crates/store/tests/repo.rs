//! Repository tests against DynamoDB Local. They run when `DYNAMODB_ENDPOINT` is set
//! (e.g. `http://localhost:8000`) and are skipped otherwise, so `cargo test` works offline.
//!
//! DynamoDB Local doesn't evaluate IAM, so these cover the app layer. The IAM boundary is
//! checked against the deployed stack by the isolation probe.

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{Credentials, Region};
use domain::{Channel, ConvId, ExternalId, RouteAddress, Sender, TenantId, TenantScope, UserId};
use store::admin::{Admin, create_table};
use store::{
    Action, Actor, AppendOutcome, AuditEvent, AuditReader, AuditWriter, InboxRepo, Outcome,
    RequestInfo, RouteRepo, ServiceInfo, StoreError, TenantUser, new_message,
};

struct Env {
    client: Client,
    table: String,
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
    let table = format!("t-{}", ulid::Ulid::generate().to_string().to_lowercase());
    create_table(&client, &table).await.expect("create table");
    Some(Env { client, table })
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
fn uid(s: &str) -> UserId {
    UserId::parse(s).unwrap()
}
fn cid(s: &str) -> ConvId {
    ConvId::parse(s).unwrap()
}
fn ext(s: &str) -> ExternalId {
    ExternalId::parse(s).unwrap()
}

fn external_msg(conv: &str, body: &str, external_id: Option<&str>) -> domain::CanonicalMessage {
    new_message(
        cid(conv),
        Channel::Slack,
        Sender::External {
            address: "U999".into(),
            display_name: None,
        },
        body.into(),
        external_id.map(ext),
    )
}

/// acme: alice + bob in c_ops and c_eng, carol in c_ops only. globex: dave in c_ops (same id!).
async fn seed(env: &Env) {
    let admin = Admin::new(env.client.clone(), &env.table);
    let acme = scope("acme");
    let globex = scope("globex");
    admin.put_tenant(&acme, "Acme").await.unwrap();
    for (u, role) in [("alice", "admin"), ("bob", "member"), ("carol", "member")] {
        let user = TenantUser {
            user_id: uid(u),
            email: format!("{u}@acme.test"),
            display_name: u.into(),
            role: role.into(),
        };
        admin.put_user(&acme, &user).await.unwrap();
    }
    for (c, name) in [("c_ops", "#ops"), ("c_eng", "#eng")] {
        admin.put_conversation(&acme, &cid(c), name).await.unwrap();
    }
    for (c, u) in [
        ("c_ops", "alice"),
        ("c_ops", "bob"),
        ("c_ops", "carol"),
        ("c_eng", "alice"),
        ("c_eng", "bob"),
    ] {
        admin
            .put_member(&acme, &cid(c), &uid(u), "member")
            .await
            .unwrap();
    }
    admin
        .put_ident(&acme, Channel::Slack, &ext("U024BE7LH"), &uid("bob"))
        .await
        .unwrap();
    admin
        .put_conversation(&globex, &cid("c_ops"), "#globex-ops")
        .await
        .unwrap();
    admin
        .put_member(&globex, &cid("c_ops"), &uid("dave"), "member")
        .await
        .unwrap();
}

#[tokio::test]
async fn append_is_idempotent_on_duplicate_external_id() {
    let env = env_or_skip!();
    seed(&env).await;
    let repo = InboxRepo::new(env.client.clone(), &env.table, scope("acme"));

    let first = repo
        .append_message(&external_msg("c_ops", "hello", Some("Ev1")))
        .await
        .unwrap();
    // The provider retries: same external id, but a fresh message id.
    let again = repo
        .append_message(&external_msg("c_ops", "hello", Some("Ev1")))
        .await
        .unwrap();
    assert_eq!(first, AppendOutcome::Appended);
    assert_eq!(again, AppendOutcome::Duplicate);

    let page = repo.list_messages(&cid("c_ops"), 50, None).await.unwrap();
    assert_eq!(page.items.len(), 1);

    // Same external id in another tenant is a different event.
    let globex = InboxRepo::new(env.client.clone(), &env.table, scope("globex"));
    let other = globex
        .append_message(&external_msg("c_ops", "hi", Some("Ev1")))
        .await
        .unwrap();
    assert_eq!(other, AppendOutcome::Appended);
}

#[tokio::test]
async fn append_updates_last_message_at_and_rejects_unknown_conversation() {
    let env = env_or_skip!();
    seed(&env).await;
    let repo = InboxRepo::new(env.client.clone(), &env.table, scope("acme"));

    let err = repo
        .append_message(&external_msg("c_nope", "x", None))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound), "{err:?}");

    repo.append_message(&external_msg("c_eng", "x", None))
        .await
        .unwrap();
    let convs = repo.list_user_conversations(&uid("alice")).await.unwrap();
    assert_eq!(convs.len(), 2);
    assert_eq!(
        convs[0].conversation_id,
        cid("c_eng"),
        "most recently active first"
    );
    assert!(convs[0].last_message_at.is_some());
}

#[tokio::test]
async fn pages_newest_first_and_rejects_a_cursor_from_another_conversation() {
    let env = env_or_skip!();
    seed(&env).await;
    let repo = InboxRepo::new(env.client.clone(), &env.table, scope("acme"));
    for i in 0..25 {
        repo.append_message(&external_msg("c_ops", &format!("m{i}"), None))
            .await
            .unwrap();
    }
    repo.append_message(&external_msg("c_eng", "eng", None))
        .await
        .unwrap();

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = repo
            .list_messages(&cid("c_ops"), 10, cursor.as_deref())
            .await
            .unwrap();
        seen.extend(page.items.into_iter().map(|m| m.message_id));
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen.len(), 25);
    assert!(
        seen.windows(2).all(|w| w[0] > w[1]),
        "newest first, no repeats"
    );

    // A cursor minted for c_ops can't be used to page c_eng.
    let page = repo.list_messages(&cid("c_ops"), 5, None).await.unwrap();
    let foreign = page.next_cursor.unwrap();
    let err = repo
        .list_messages(&cid("c_eng"), 5, Some(&foreign))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidCursor));
}

#[tokio::test]
async fn membership_and_people() {
    let env = env_or_skip!();
    seed(&env).await;
    let acme = InboxRepo::new(env.client.clone(), &env.table, scope("acme"));

    assert!(acme.is_member(&cid("c_ops"), &uid("carol")).await.unwrap());
    assert!(!acme.is_member(&cid("c_eng"), &uid("carol")).await.unwrap());

    let peers = acme.co_members(&uid("alice")).await.unwrap();
    let got: Vec<(&str, u32)> = peers
        .iter()
        .map(|p| (p.user_id.as_str(), p.shared))
        .collect();
    assert_eq!(got, vec![("bob", 2), ("carol", 1)]);

    assert_eq!(acme.tenant_users().await.unwrap().len(), 3);
    assert_eq!(
        acme.resolve_identity(Channel::Slack, &ext("U024BE7LH"))
            .await
            .unwrap(),
        Some(uid("bob"))
    );
    assert_eq!(
        acme.resolve_identity(Channel::Slack, &ext("U000"))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn same_ids_in_another_tenant_are_invisible() {
    let env = env_or_skip!();
    seed(&env).await;
    let acme = InboxRepo::new(env.client.clone(), &env.table, scope("acme"));
    let globex = InboxRepo::new(env.client.clone(), &env.table, scope("globex"));
    acme.append_message(&external_msg("c_ops", "acme secret", None))
        .await
        .unwrap();

    // Both tenants have a conversation called c_ops; each sees only its own.
    assert_eq!(
        globex
            .conversation(&cid("c_ops"))
            .await
            .unwrap()
            .unwrap()
            .name,
        "#globex-ops"
    );
    assert!(
        globex
            .list_messages(&cid("c_ops"), 50, None)
            .await
            .unwrap()
            .items
            .is_empty()
    );
    assert!(
        !globex
            .is_member(&cid("c_ops"), &uid("alice"))
            .await
            .unwrap()
    );
    assert!(globex.tenant_users().await.unwrap().is_empty());
    assert!(globex.co_members(&uid("alice")).await.unwrap().is_empty());
}

#[tokio::test]
async fn routes_resolve_to_tenant_and_conversation() {
    let env = env_or_skip!();
    let admin = Admin::new(env.client.clone(), &env.table);
    let addr = RouteAddress::new(&[&ext("T0ACME"), &ext("C0OPS")]);
    admin
        .put_route(Channel::Slack, &addr, &scope("acme"), &cid("c_ops"))
        .await
        .unwrap();

    let routes = RouteRepo::new(env.client.clone(), &env.table);
    let r = routes.get(Channel::Slack, &addr).await.unwrap().unwrap();
    assert_eq!(
        (r.tenant_id.as_str(), r.conversation_id.as_str()),
        ("acme", "c_ops")
    );
    let unknown = RouteAddress::new(&[&ext("T0ACME"), &ext("C0NOPE")]);
    assert_eq!(routes.get(Channel::Slack, &unknown).await.unwrap(), None);
}

#[tokio::test]
async fn audit_records_are_written_and_read_per_tenant() {
    let env = env_or_skip!();
    let writer = AuditWriter::new(
        env.client.clone(),
        &env.table,
        ServiceInfo {
            fn_name: "test".into(),
            version: "dev".into(),
        },
    );
    let event = |tenant: &str, outcome| AuditEvent {
        tenant_id: TenantId::parse(tenant).unwrap(),
        actor: Actor::integration(Channel::Sms, None, None),
        action: Action::MessageIngest,
        resource: None,
        outcome,
        reason: None,
        result_count: None,
        request: RequestInfo {
            route: "POST /inbound/{channel}".into(),
            ..Default::default()
        },
    };
    writer
        .write(&event("acme", Outcome::Allowed))
        .await
        .unwrap();
    writer
        .write(&event("acme", Outcome::Duplicate))
        .await
        .unwrap();
    writer
        .write(&event("globex", Outcome::Allowed))
        .await
        .unwrap();

    let today = store::time_fmt::day(time::OffsetDateTime::now_utc());
    let reader = AuditReader::new(env.client.clone(), &env.table, scope("acme"));
    let page = reader.list_day(&today, 50, None).await.unwrap();
    assert_eq!(page.items.len(), 2);
    for r in &page.items {
        assert_eq!(r["tenant_id"], "acme");
        assert!(r["record_hash"].as_str().unwrap().starts_with("sha256:"));
        assert!(r.get("PK").is_none(), "keys are stripped");
    }
    assert_eq!(page.items[0]["outcome"], "duplicate", "newest first");
}
