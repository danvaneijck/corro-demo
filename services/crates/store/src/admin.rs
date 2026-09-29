//! Operator writes: tables for local testing, and seed data. Behind the `admin` feature, so the
//! Lambda binaries don't contain it. Uses an unscoped client (your profile, or DynamoDB Local).

use std::collections::HashMap;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement,
    KeyType, Projection, ProjectionType, ScalarAttributeType,
};
use domain::{Channel, ConvId, ExternalId, RouteAddress, TenantScope, UserId};
use time::OffsetDateTime;

use crate::time_fmt::ts_millis;
use crate::{StoreError, TenantUser, keys};

pub struct Admin {
    client: Client,
    table: String,
}

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

impl Admin {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }

    async fn put(&self, attrs: Vec<(&str, String)>) -> Result<(), StoreError> {
        let item: HashMap<String, AttributeValue> = attrs
            .into_iter()
            .map(|(k, v)| (k.to_owned(), s(v)))
            .collect();
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(StoreError::from_sdk)?;
        Ok(())
    }

    pub async fn put_tenant(&self, scope: &TenantScope, name: &str) -> Result<(), StoreError> {
        self.put(vec![
            ("PK", keys::tenant_pk(scope)),
            ("SK", keys::META_SK.into()),
            ("tenant_id", scope.tenant_id().to_string()),
            ("name", name.into()),
            ("created_at", ts_millis(OffsetDateTime::now_utc())),
        ])
        .await
    }

    pub async fn put_user(&self, scope: &TenantScope, u: &TenantUser) -> Result<(), StoreError> {
        self.put(vec![
            ("PK", keys::tenant_pk(scope)),
            ("SK", keys::user_sk(&u.user_id)),
            ("user_id", u.user_id.to_string()),
            ("email", u.email.clone()),
            ("display_name", u.display_name.clone()),
            ("role", u.role.clone()),
        ])
        .await
    }

    pub async fn put_conversation(
        &self,
        scope: &TenantScope,
        conv: &ConvId,
        name: &str,
    ) -> Result<(), StoreError> {
        self.put(vec![
            ("PK", keys::conv_pk(scope, conv)),
            ("SK", keys::META_SK.into()),
            ("GSI1PK", keys::convs_gsi1pk(scope)),
            ("GSI1SK", keys::conv_gsi1sk(conv)),
            ("conversation_id", conv.to_string()),
            ("name", name.into()),
        ])
        .await
    }

    pub async fn put_member(
        &self,
        scope: &TenantScope,
        conv: &ConvId,
        user: &UserId,
        role: &str,
    ) -> Result<(), StoreError> {
        self.put(vec![
            ("PK", keys::conv_pk(scope, conv)),
            ("SK", keys::member_sk(user)),
            ("GSI1PK", keys::user_gsi1pk(scope, user)),
            ("GSI1SK", keys::conv_gsi1sk(conv)),
            ("conversation_id", conv.to_string()),
            ("user_id", user.to_string()),
            ("joined_at", ts_millis(OffsetDateTime::now_utc())),
            ("conv_role", role.into()),
        ])
        .await
    }

    pub async fn put_ident(
        &self,
        scope: &TenantScope,
        ch: Channel,
        ext: &ExternalId,
        user: &UserId,
    ) -> Result<(), StoreError> {
        self.put(vec![
            ("PK", keys::ident_pk(scope, ch, ext)),
            ("SK", keys::IDENT_SK.into()),
            ("user_id", user.to_string()),
        ])
        .await
    }

    pub async fn put_route(
        &self,
        ch: Channel,
        addr: &RouteAddress,
        scope: &TenantScope,
        conv: &ConvId,
    ) -> Result<(), StoreError> {
        self.put(vec![
            ("PK", keys::route_pk(ch, addr)),
            ("SK", keys::ROUTE_SK.into()),
            ("tenant_id", scope.tenant_id().to_string()),
            ("conversation_id", conv.to_string()),
        ])
        .await
    }
}

/// Creates a table shaped like `inbox` / `audit` (PK, SK, GSI1). For DynamoDB Local.
pub async fn create_table(client: &Client, name: &str) -> Result<(), StoreError> {
    let attr = |n: &str| {
        AttributeDefinition::builder()
            .attribute_name(n)
            .attribute_type(ScalarAttributeType::S)
            .build()
    };
    let key = |n: &str, t: KeyType| {
        KeySchemaElement::builder()
            .attribute_name(n)
            .key_type(t)
            .build()
    };
    let gsi = GlobalSecondaryIndex::builder()
        .index_name(keys::GSI1)
        .key_schema(key("GSI1PK", KeyType::Hash)?)
        .key_schema(key("GSI1SK", KeyType::Range)?)
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()?;
    client
        .create_table()
        .table_name(name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(attr("PK")?)
        .attribute_definitions(attr("SK")?)
        .attribute_definitions(attr("GSI1PK")?)
        .attribute_definitions(attr("GSI1SK")?)
        .key_schema(key("PK", KeyType::Hash)?)
        .key_schema(key("SK", KeyType::Range)?)
        .global_secondary_indexes(gsi)
        .send()
        .await
        .map_err(StoreError::from_sdk)?;
    Ok(())
}
