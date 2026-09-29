//! Per-tenant DynamoDB clients built from STS credentials tagged with `tenant_id`.
//!
//! IAM on the `TenantDataRole` only allows keys that start with `T#<that tenant>#`, so a client
//! from here physically can't read another tenant's data, whatever the calling code does.

use std::time::{Duration, SystemTime};

use aws_config::SdkConfig;
use aws_sdk_dynamodb::config::Credentials;
use aws_sdk_sts::types::Tag;
use domain::{TenantId, TenantScope};
use moka::future::Cache;

use crate::{StoreError, metrics};

/// STS sessions last 15 minutes; cached clients are dropped a minute before that.
const SESSION_SECS: i32 = 900;
const CACHE_TTL: Duration = Duration::from_secs(840);

pub struct TenantCredsProvider {
    sts: aws_sdk_sts::Client,
    base: SdkConfig,
    role_arn: String,
    fn_name: String,
    cache: Cache<TenantId, aws_sdk_dynamodb::Client>,
}

impl TenantCredsProvider {
    pub fn new(base: &SdkConfig, role_arn: impl Into<String>, fn_name: impl Into<String>) -> Self {
        Self {
            sts: aws_sdk_sts::Client::new(base),
            base: base.clone(),
            role_arn: role_arn.into(),
            fn_name: fn_name.into(),
            cache: Cache::builder()
                .time_to_live(CACHE_TTL)
                .max_capacity(1_000)
                .build(),
        }
    }

    /// A DynamoDB client that can only touch this tenant's keys.
    pub async fn client_for(
        &self,
        scope: &TenantScope,
    ) -> Result<aws_sdk_dynamodb::Client, StoreError> {
        let tenant = scope.tenant_id().clone();
        self.cache
            .try_get_with(tenant.clone(), self.assume(tenant))
            .await
            .map_err(|e| (*e).clone())
    }

    async fn assume(&self, tenant: TenantId) -> Result<aws_sdk_dynamodb::Client, StoreError> {
        metrics::count("StsCacheMiss", &[]);
        let tag = Tag::builder()
            .key("tenant_id")
            .value(tenant.as_str())
            .build()
            .map_err(|e| StoreError::Sts(e.to_string()))?;
        let resp = self
            .sts
            .assume_role()
            .role_arn(&self.role_arn)
            .role_session_name(format!("{tenant}-{}", self.fn_name))
            .duration_seconds(SESSION_SECS)
            .tags(tag)
            .send()
            .await
            .map_err(|e| {
                StoreError::Sts(aws_sdk_sts::error::DisplayErrorContext(&e).to_string())
            })?;
        let c = resp
            .credentials()
            .ok_or_else(|| StoreError::Sts("no credentials returned".into()))?;
        let expiry = SystemTime::try_from(*c.expiration()).ok();
        let creds = Credentials::new(
            c.access_key_id(),
            c.secret_access_key(),
            Some(c.session_token().to_owned()),
            expiry,
            "tenant-sts",
        );
        // Built from the shared config, so the HTTP client and connection pool are reused.
        let conf = aws_sdk_dynamodb::config::Builder::from(&self.base)
            .credentials_provider(creds)
            .build();
        Ok(aws_sdk_dynamodb::Client::from_conf(conf))
    }
}
