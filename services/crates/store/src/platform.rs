//! Content-free platform analytics: message counts per tenant, per channel, per day.
//!
//! This is the deliberate, narrow cross-tenant path. Counters live under `PLATFORM#STATS#<day>`
//! with one item per tenant. The functions' own roles may only `UpdateItem` keys under
//! `PLATFORM#STATS#*`, and reads go through a separate `PlatformReadRole` that may only `Query`
//! keys under `PLATFORM#*`: it can count messages across tenants but can't read any of them.

use std::collections::HashMap;
use std::time::Duration;

use aws_config::SdkConfig;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::Credentials;
use aws_sdk_dynamodb::types::AttributeValue;
use domain::{Channel, TenantId};
use moka::future::Cache;
use serde::Serialize;
use time::OffsetDateTime;

use crate::time_fmt::day;
use crate::{StoreError, keys, metrics};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TenantCounts {
    pub tenant_id: String,
    pub messages: HashMap<String, u64>,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DayStats {
    pub date: String,
    pub tenants: Vec<TenantCounts>,
}

/// Adds one to today's counter for a tenant and channel. Uses the function's own role.
pub async fn count_message(
    client: &Client,
    table: &str,
    tenant: &TenantId,
    ch: Channel,
) -> Result<(), StoreError> {
    client
        .update_item()
        .table_name(table)
        .key(
            "PK",
            AttributeValue::S(keys::platform_stats_pk(&day(OffsetDateTime::now_utc()))),
        )
        .key("SK", AttributeValue::S(keys::platform_stats_sk(tenant)))
        .update_expression("ADD #n :one")
        .expression_attribute_names("#n", format!("msgs_{ch}"))
        .expression_attribute_values(":one", AttributeValue::N("1".into()))
        .send()
        .await
        .map_err(StoreError::from_sdk)?;
    Ok(())
}

/// Best-effort: analytics must never fail a message delivery. Failures are logged and counted.
pub async fn count_message_best_effort(
    client: &Client,
    table: &str,
    tenant: &TenantId,
    ch: Channel,
) {
    if let Err(e) = count_message(client, table, tenant, ch).await {
        metrics::count("PlatformCounterFailed", &[]);
        tracing::warn!(error = %e, "platform counter update failed");
    }
}

/// Reads the last `days` days of counters with a client from [`PlatformCredsProvider`].
pub async fn read_stats(
    client: &Client,
    table: &str,
    days: u32,
) -> Result<Vec<DayStats>, StoreError> {
    let today = OffsetDateTime::now_utc();
    let mut out = Vec::new();
    for back in 0..days {
        let date = day(today - time::Duration::days(i64::from(back)));
        let items: Vec<HashMap<String, AttributeValue>> = client
            .query()
            .table_name(table)
            .key_condition_expression("PK = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(keys::platform_stats_pk(&date)))
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<_>, _>>()
            .await
            .map_err(StoreError::from_sdk)?;
        let mut tenants: Vec<TenantCounts> = items
            .into_iter()
            .filter_map(|item| {
                let tenant = item.get("SK")?.as_s().ok()?.strip_prefix("T#")?.to_owned();
                let messages: HashMap<String, u64> = item
                    .iter()
                    .filter_map(|(k, v)| {
                        let ch = k.strip_prefix("msgs_")?;
                        Some((ch.to_owned(), v.as_n().ok()?.parse().ok()?))
                    })
                    .collect();
                let total = messages.values().sum();
                Some(TenantCounts {
                    tenant_id: tenant,
                    messages,
                    total,
                })
            })
            .collect();
        tenants.sort_by(|a, b| b.total.cmp(&a.total).then(a.tenant_id.cmp(&b.tenant_id)));
        out.push(DayStats { date, tenants });
    }
    Ok(out)
}

/// A DynamoDB client from `PlatformReadRole` (no session tags; its policy only allows
/// `PLATFORM#*` keys). Cached for 14 minutes.
pub struct PlatformCredsProvider {
    sts: aws_sdk_sts::Client,
    base: SdkConfig,
    role_arn: String,
    cache: Cache<(), Client>,
}

impl PlatformCredsProvider {
    pub fn new(base: &SdkConfig, role_arn: impl Into<String>) -> Self {
        Self {
            sts: aws_sdk_sts::Client::new(base),
            base: base.clone(),
            role_arn: role_arn.into(),
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(840))
                .max_capacity(1)
                .build(),
        }
    }

    pub async fn client(&self) -> Result<Client, StoreError> {
        self.cache
            .try_get_with((), self.assume())
            .await
            .map_err(|e| (*e).clone())
    }

    async fn assume(&self) -> Result<Client, StoreError> {
        let resp = self
            .sts
            .assume_role()
            .role_arn(&self.role_arn)
            .role_session_name("platform-stats")
            .duration_seconds(900)
            .send()
            .await
            .map_err(|e| {
                StoreError::Sts(aws_sdk_sts::error::DisplayErrorContext(&e).to_string())
            })?;
        let c = resp
            .credentials()
            .ok_or_else(|| StoreError::Sts("no credentials returned".into()))?;
        let creds = Credentials::new(
            c.access_key_id(),
            c.secret_access_key(),
            Some(c.session_token().to_owned()),
            std::time::SystemTime::try_from(*c.expiration()).ok(),
            "platform-sts",
        );
        let conf = aws_sdk_dynamodb::config::Builder::from(&self.base)
            .credentials_provider(creds)
            .build();
        Ok(Client::from_conf(conf))
    }
}
