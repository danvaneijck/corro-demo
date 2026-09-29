//! Seeds the demo: Cognito users, then tenants, conversations, members, identity links, routes
//! and messages. Runs locally with your AWS profile (operator credentials, not the Lambdas').
//!
//! It wipes the inbox table first (including de-duplication records), so it's also the reset.
//! The audit table is append-only and is never touched.
//!
//!   DEMO_PASSWORD=... cargo run -p seed --release

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use aws_sdk_cognitoidentityprovider::types::{AttributeType, MessageActionType};
use aws_sdk_dynamodb::types::{AttributeValue, DeleteRequest, WriteRequest};
use domain::{
    CanonicalMessage, Channel, ConvId, ExternalId, RouteAddress, Sender, TenantId, TenantScope,
    UserId,
};
use store::admin::Admin;
use store::{InboxRepo, TenantUser};
use time::OffsetDateTime;
use ulid::Ulid;

const STACK: &str = "CorroDemo";

struct DemoUser {
    key: &'static str,
    email: &'static str,
    name: &'static str,
    tenant: &'static str,
    role: &'static str,
}

const USERS: &[DemoUser] = &[
    DemoUser {
        key: "alice",
        email: "alice@acme.test",
        name: "Alice Nguyen",
        tenant: "acme",
        role: "admin",
    },
    DemoUser {
        key: "bob",
        email: "bob@acme.test",
        name: "Bob Okafor",
        tenant: "acme",
        role: "member",
    },
    DemoUser {
        key: "carol",
        email: "carol@acme.test",
        name: "Carol Singh",
        tenant: "acme",
        role: "member",
    },
    DemoUser {
        key: "dave",
        email: "dave@globex.test",
        name: "Dave Walker",
        tenant: "globex",
        role: "admin",
    },
];

/// (tenant, conversation id, name, members)
const CONVERSATIONS: &[(&str, &str, &str, &[&str])] = &[
    ("acme", "c_ops", "#ops", &["alice", "bob", "carol"]),
    ("acme", "c_eng", "#eng", &["alice", "bob"]),
    ("acme", "c_sms", "SMS line", &["alice"]),
    ("globex", "c_ward", "Ward 4 handover", &["dave"]),
];

/// (channel, address parts, tenant, conversation)
const ROUTES: &[(Channel, &[&str], &str, &str)] = &[
    (Channel::Slack, &["T0ACME", "C0OPS"], "acme", "c_ops"),
    (Channel::Sms, &["+61400000001"], "acme", "c_sms"),
    (Channel::Slack, &["T0GLOBEX", "C0WARD"], "globex", "c_ward"),
];

/// Bob's Slack user id, so Slack messages from him show as Bob.
const BOB_SLACK: &str = "U024BE7LH";

/// (conversation, sender, text). Sender is a user key, `slack:<id>` or `sms:<number>`.
const MESSAGES: &[(&str, &str, &str, &str)] = &[
    (
        "acme",
        "c_ops",
        "alice",
        "Morning all. Change freeze starts Thursday 6pm.",
    ),
    (
        "acme",
        "c_ops",
        "bob",
        "Noted. I'll get the patching done before then.",
    ),
    (
        "acme",
        "c_ops",
        "carol",
        "Can we confirm who's on call this weekend?",
    ),
    ("acme", "c_ops", "alice", "Bob this weekend, me as backup."),
    (
        "acme",
        "c_ops",
        "slack:U07EXTVEND",
        "Vendor here: maintenance window confirmed for Sat 2am.",
    ),
    ("acme", "c_ops", "bob", "Thanks, adding it to the calendar."),
    (
        "acme",
        "c_ops",
        "carol",
        "Seeing elevated latency on the citizen portal.",
    ),
    (
        "acme",
        "c_ops",
        "bob",
        "Looking. Region B load balancer health checks are flapping.",
    ),
    (
        "acme",
        "c_ops",
        "alice",
        "Declaring a minor outage for region B. Bob is incident lead.",
    ),
    (
        "acme",
        "c_ops",
        "bob",
        "Traffic shifted to region A. Error rate dropping.",
    ),
    (
        "acme",
        "c_ops",
        "carol",
        "Portal response times back under 300ms.",
    ),
    (
        "acme",
        "c_ops",
        "bob",
        "Root cause: expired cert on one target group. Renewed.",
    ),
    (
        "acme",
        "c_ops",
        "alice",
        "Great work. Post-incident review Friday 10am.",
    ),
    ("acme", "c_ops", "carol", "I'll draft the timeline."),
    (
        "acme",
        "c_ops",
        "slack:U07EXTVEND",
        "Our side is clear too. Closing our ticket.",
    ),
    (
        "acme",
        "c_ops",
        "bob",
        "Adding a cert-expiry alarm so this can't recur.",
    ),
    (
        "acme",
        "c_ops",
        "alice",
        "Please include that in the review actions.",
    ),
    (
        "acme",
        "c_ops",
        "carol",
        "Timeline draft is in the shared drive.",
    ),
    ("acme", "c_ops", "bob", "Reviewed, looks accurate."),
    ("acme", "c_ops", "alice", "Thanks both. Closing the outage."),
    (
        "acme",
        "c_eng",
        "bob",
        "PR for the cert-expiry alarm is up.",
    ),
    (
        "acme",
        "c_eng",
        "alice",
        "Approved. Can you add a runbook link to the alarm?",
    ),
    (
        "acme",
        "c_eng",
        "bob",
        "Done. Deploying after the freeze lifts.",
    ),
    (
        "acme",
        "c_eng",
        "alice",
        "Also: the outage review needs a DR test date.",
    ),
    ("acme", "c_eng", "bob", "Pencilled in for the 14th."),
    (
        "acme",
        "c_sms",
        "sms:+61400000777",
        "Hi, is the portal working again? Couldn't lodge my form.",
    ),
    (
        "acme",
        "c_sms",
        "alice",
        "Yes, it's back. Sorry for the disruption.",
    ),
    (
        "globex",
        "c_ward",
        "dave",
        "Handover: bed 12 needs obs every 2 hours.",
    ),
    (
        "globex",
        "c_ward",
        "dave",
        "Pharmacy system outage 3-4am, paper charts used.",
    ),
    (
        "globex",
        "c_ward",
        "dave",
        "Outage resolved, charts backfilled.",
    ),
];

fn scope(t: &str) -> Result<TenantScope> {
    Ok(TenantScope::for_operator(TenantId::parse(t)?))
}

async fn stack_outputs(cfn: &aws_sdk_cloudformation::Client) -> Result<HashMap<String, String>> {
    let out = cfn
        .describe_stacks()
        .stack_name(STACK)
        .send()
        .await
        .context("describe CorroDemo stack")?;
    let stack = out.stacks().first().context("stack CorroDemo not found")?;
    Ok(stack
        .outputs()
        .iter()
        .filter_map(|o| Some((o.output_key()?.to_owned(), o.output_value()?.to_owned())))
        .collect())
}

/// Creates the user if needed, (re)sets its attributes and permanent password, returns its sub.
async fn upsert_user(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    pool: &str,
    u: &DemoUser,
    password: &str,
) -> Result<String> {
    let attr = |n: &str, v: &str| AttributeType::builder().name(n).value(v).build();
    let exists = cognito
        .admin_get_user()
        .user_pool_id(pool)
        .username(u.email)
        .send()
        .await
        .is_ok();
    if !exists {
        cognito
            .admin_create_user()
            .user_pool_id(pool)
            .username(u.email)
            .message_action(MessageActionType::Suppress)
            .user_attributes(attr("email", u.email)?)
            .user_attributes(attr("email_verified", "true")?)
            .user_attributes(attr("custom:tenant_id", u.tenant)?)
            .user_attributes(attr("custom:role", u.role)?)
            .send()
            .await
            .with_context(|| format!("create {}", u.email))?;
    } else {
        // tenant_id is immutable, so only the role can be corrected on an existing user.
        cognito
            .admin_update_user_attributes()
            .user_pool_id(pool)
            .username(u.email)
            .user_attributes(attr("custom:role", u.role)?)
            .send()
            .await?;
    }
    cognito
        .admin_set_user_password()
        .user_pool_id(pool)
        .username(u.email)
        .password(password)
        .permanent(true)
        .send()
        .await
        .with_context(|| {
            format!(
                "set password for {} (does DEMO_PASSWORD meet the pool policy?)",
                u.email
            )
        })?;
    let user = cognito
        .admin_get_user()
        .user_pool_id(pool)
        .username(u.email)
        .send()
        .await?;
    let sub = user
        .user_attributes()
        .iter()
        .find(|a| a.name() == "sub")
        .and_then(|a| a.value())
        .context("user has no sub")?;
    Ok(sub.to_owned())
}

/// Deletes every item in the inbox table.
async fn wipe(ddb: &aws_sdk_dynamodb::Client, table: &str) -> Result<usize> {
    let keys: Vec<HashMap<String, AttributeValue>> = ddb
        .scan()
        .table_name(table)
        .projection_expression("PK, SK")
        .into_paginator()
        .items()
        .send()
        .collect::<Result<Vec<_>, _>>()
        .await?;
    for chunk in keys.chunks(25) {
        let mut pending: Vec<WriteRequest> = chunk
            .iter()
            .map(|k| {
                let del = DeleteRequest::builder().set_key(Some(k.clone())).build()?;
                Ok(WriteRequest::builder().delete_request(del).build())
            })
            .collect::<Result<_>>()?;
        while !pending.is_empty() {
            let out = ddb
                .batch_write_item()
                .request_items(table, pending)
                .send()
                .await?;
            pending = out
                .unprocessed_items
                .and_then(|mut u| u.remove(table))
                .unwrap_or_default();
        }
    }
    Ok(keys.len())
}

#[tokio::main]
async fn main() -> Result<()> {
    let password = std::env::var("DEMO_PASSWORD").context("set DEMO_PASSWORD (never committed)")?;
    if password.len() < 12 {
        bail!("DEMO_PASSWORD must be at least 12 characters (pool policy)");
    }
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let outputs = stack_outputs(&aws_sdk_cloudformation::Client::new(&config)).await?;
    let out = |k: &str| {
        outputs
            .get(k)
            .cloned()
            .with_context(|| format!("stack output {k} missing"))
    };
    let (table, pool) = (out("InboxTableName")?, out("UserPoolId")?);
    let ddb = aws_sdk_dynamodb::Client::new(&config);
    let cognito = aws_sdk_cognitoidentityprovider::Client::new(&config);

    println!("wiping {table}");
    println!("  deleted {} items", wipe(&ddb, &table).await?);

    let mut subs: HashMap<&str, UserId> = HashMap::new();
    for u in USERS {
        let sub = upsert_user(&cognito, &pool, u, &password).await?;
        println!(
            "user {:<18} {:<7} {:<6} sub={sub}",
            u.email, u.tenant, u.role
        );
        subs.insert(u.key, UserId::parse(&sub)?);
    }
    let uid = |k: &str| {
        subs.get(k)
            .cloned()
            .with_context(|| format!("unknown user {k}"))
    };

    let admin = Admin::new(ddb.clone(), &table);
    admin.put_tenant(&scope("acme")?, "Acme Gov").await?;
    admin.put_tenant(&scope("globex")?, "Globex Health").await?;
    for u in USERS {
        let user = TenantUser {
            user_id: uid(u.key)?,
            email: u.email.into(),
            display_name: u.name.into(),
            role: u.role.into(),
        };
        admin.put_user(&scope(u.tenant)?, &user).await?;
    }
    for (tenant, conv, name, members) in CONVERSATIONS {
        let (s, c) = (scope(tenant)?, ConvId::parse(conv)?);
        admin.put_conversation(&s, &c, name).await?;
        for (i, m) in members.iter().enumerate() {
            admin
                .put_member(&s, &c, &uid(m)?, if i == 0 { "owner" } else { "member" })
                .await?;
        }
    }
    admin
        .put_ident(
            &scope("acme")?,
            Channel::Slack,
            &ExternalId::parse(BOB_SLACK)?,
            &uid("bob")?,
        )
        .await?;
    for (ch, parts, tenant, conv) in ROUTES {
        let parts = parts
            .iter()
            .map(|p| ExternalId::parse(p))
            .collect::<Result<Vec<_>, _>>()?;
        let addr = RouteAddress::new(&parts.iter().collect::<Vec<_>>());
        admin
            .put_route(*ch, &addr, &scope(tenant)?, &ConvId::parse(conv)?)
            .await?;
    }
    println!(
        "tenants, {} conversations, members, identity link, {} routes",
        CONVERSATIONS.len(),
        ROUTES.len()
    );

    // Messages spread over the last few hours, oldest first, so ids sort by time.
    let start = SystemTime::now() - Duration::from_secs(4 * 3600);
    for (i, (tenant, conv, from, text)) in MESSAGES.iter().enumerate() {
        let at = start + Duration::from_secs(i as u64 * 7 * 60);
        let when = OffsetDateTime::from(at);
        let (channel, sender) = match from.split_once(':') {
            Some(("slack", id)) => (
                Channel::Slack,
                Sender::External {
                    address: (*id).into(),
                    display_name: Some("Vendor (Slack)".into()),
                },
            ),
            Some(("sms", number)) => (
                Channel::Sms,
                Sender::External {
                    address: (*number).into(),
                    display_name: None,
                },
            ),
            _ => (
                Channel::Native,
                Sender::User {
                    user_id: uid(from)?,
                },
            ),
        };
        let msg = CanonicalMessage {
            message_id: Ulid::from_datetime(at),
            conversation_id: ConvId::parse(conv)?,
            channel,
            sender,
            body_text: (*text).into(),
            sent_at: when,
            received_at: when,
            external_id: None,
        };
        InboxRepo::new(ddb.clone(), &table, scope(tenant)?)
            .append_message(&msg)
            .await?;
    }
    println!("{} messages", MESSAGES.len());
    println!("done. Sign in with any seeded email and DEMO_PASSWORD.");
    Ok(())
}
