//! AP1: inbound address → tenant and conversation. Used by ingest-fn with its own role, which
//! may only read `ROUTE#*` keys.

use std::time::Duration;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::AttributeValue;
use domain::{Channel, ConvId, RouteAddress, TenantId};
use moka::future::Cache;
use serde::Deserialize;

use crate::{StoreError, keys};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Route {
    pub tenant_id: TenantId,
    pub conversation_id: ConvId,
}

/// Routes are read-mostly and content-free, so they're cached for a minute. A route change
/// takes up to 60 s to apply.
const ROUTE_TTL: Duration = Duration::from_secs(60);

pub struct RouteRepo {
    client: Client,
    table: String,
    cache: Cache<String, Option<Route>>,
}

impl RouteRepo {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
            cache: Cache::builder()
                .time_to_live(ROUTE_TTL)
                .max_capacity(10_000)
                .build(),
        }
    }

    pub async fn get(&self, ch: Channel, addr: &RouteAddress) -> Result<Option<Route>, StoreError> {
        let pk = keys::route_pk(ch, addr);
        self.cache
            .try_get_with(pk.clone(), self.fetch(pk))
            .await
            .map_err(|e| (*e).clone())
    }

    async fn fetch(&self, pk: String) -> Result<Option<Route>, StoreError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("PK", AttributeValue::S(pk))
            .key("SK", AttributeValue::S(keys::ROUTE_SK.to_owned()))
            .send()
            .await
            .map_err(StoreError::from_sdk)?;
        out.item
            .map(serde_dynamo::from_item)
            .transpose()
            .map_err(Into::into)
    }
}
