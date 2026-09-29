//! Tenant data access. Every method builds its keys from the repo's [`TenantScope`]; callers
//! pass ids, never key strings.

use std::collections::HashMap;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::types::{AttributeValue, KeysAndAttributes, Put, TransactWriteItem, Update};
use domain::{CanonicalMessage, Channel, ConvId, ExternalId, TenantId, TenantScope, UserId};
use futures::{StreamExt, TryStreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_dynamo::{from_item, from_items, to_item};
use time::{Duration, OffsetDateTime};

use crate::error::is_access_denied;
use crate::time_fmt::ts_millis;
use crate::{StoreError, cursor, keys};

type Item = HashMap<String, AttributeValue>;

/// De-duplication records outlive any provider's retry window.
const DEDUP_TTL: Duration = Duration::days(7);
pub const MAX_PAGE: i32 = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub conversation_id: ConvId,
    pub name: String,
    #[serde(default)]
    pub last_message_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub user_id: UserId,
    pub joined_at: String,
    #[serde(default)]
    pub conv_role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantUser {
    pub user_id: UserId,
    pub email: String,
    pub display_name: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Peer {
    pub user_id: UserId,
    pub shared: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    /// The provider delivered this event before; nothing was written.
    Duplicate,
}

#[derive(Clone)]
pub struct InboxRepo {
    client: Client,
    table: String,
    scope: TenantScope,
}

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

fn key(pk: String, sk: impl Into<String>) -> Item {
    HashMap::from([("PK".to_owned(), s(pk)), ("SK".to_owned(), s(sk))])
}

impl InboxRepo {
    /// `client` should come from [`crate::TenantCredsProvider::client_for`] with the same scope.
    pub fn new(client: Client, table: impl Into<String>, scope: TenantScope) -> Self {
        Self {
            client,
            table: table.into(),
            scope,
        }
    }

    pub fn scope(&self) -> &TenantScope {
        &self.scope
    }

    async fn get(&self, pk: String, sk: impl Into<String>) -> Result<Option<Item>, StoreError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .set_key(Some(key(pk, sk)))
            .send()
            .await
            .map_err(StoreError::from_sdk)?;
        Ok(out.item)
    }

    /// Queries a whole partition (or GSI1 partition), following pagination.
    async fn query_all(
        &self,
        index: Option<&str>,
        pk: String,
        sk_prefix: Option<&str>,
    ) -> Result<Vec<Item>, StoreError> {
        let (pk_name, sk_name) = if index.is_some() {
            ("GSI1PK", "GSI1SK")
        } else {
            ("PK", "SK")
        };
        let mut q = self
            .client
            .query()
            .table_name(&self.table)
            .set_index_name(index.map(str::to_owned))
            .expression_attribute_names("#pk", pk_name)
            .expression_attribute_values(":pk", s(pk));
        q = match sk_prefix {
            Some(prefix) => q
                .key_condition_expression("#pk = :pk AND begins_with(#sk, :sk)")
                .expression_attribute_names("#sk", sk_name)
                .expression_attribute_values(":sk", s(prefix)),
            None => q.key_condition_expression("#pk = :pk"),
        };
        q.into_paginator()
            .items()
            .send()
            .try_collect()
            .await
            .map_err(StoreError::from_sdk)
    }

    /// AP6: is this user a member of the conversation? Never cached.
    pub async fn is_member(&self, conv: &ConvId, user: &UserId) -> Result<bool, StoreError> {
        Ok(self
            .get(keys::conv_pk(&self.scope, conv), keys::member_sk(user))
            .await?
            .is_some())
    }

    pub async fn conversation(
        &self,
        conv: &ConvId,
    ) -> Result<Option<ConversationSummary>, StoreError> {
        match self
            .get(keys::conv_pk(&self.scope, conv), keys::META_SK)
            .await?
        {
            Some(item) => Ok(Some(from_item(item)?)),
            None => Ok(None),
        }
    }

    /// AP5: messages newest first. The cursor must belong to this conversation's partition.
    pub async fn list_messages(
        &self,
        conv: &ConvId,
        limit: i32,
        cursor: Option<&str>,
    ) -> Result<Page<CanonicalMessage>, StoreError> {
        let pk = keys::conv_pk(&self.scope, conv);
        let start = cursor
            .map(|c| cursor::decode(c, &pk, keys::MSG_PREFIX))
            .transpose()?;
        let out = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("PK = :pk AND begins_with(SK, :msg)")
            .expression_attribute_values(":pk", s(&pk))
            .expression_attribute_values(":msg", s(keys::MSG_PREFIX))
            .scan_index_forward(false)
            .limit(limit.clamp(1, MAX_PAGE))
            .set_exclusive_start_key(start)
            .send()
            .await
            .map_err(StoreError::from_sdk)?;
        Ok(Page {
            items: from_items(out.items.unwrap_or_default())?,
            next_cursor: out.last_evaluated_key.as_ref().and_then(cursor::encode),
        })
    }

    /// AP8: ids of the conversations a user belongs to (GSI1 over MEMBER items).
    pub async fn user_conversation_ids(&self, user: &UserId) -> Result<Vec<ConvId>, StoreError> {
        #[derive(Deserialize)]
        struct M {
            conversation_id: ConvId,
        }
        let items = self
            .query_all(Some(keys::GSI1), keys::user_gsi1pk(&self.scope, user), None)
            .await?;
        let members: Vec<M> = from_items(items)?;
        Ok(members.into_iter().map(|m| m.conversation_id).collect())
    }

    /// AP8 + BatchGet of each conversation's META, most recently active first.
    pub async fn list_user_conversations(
        &self,
        user: &UserId,
    ) -> Result<Vec<ConversationSummary>, StoreError> {
        let ids = self.user_conversation_ids(user).await?;
        let mut convs = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(100) {
            let mut pending: Vec<Item> = chunk
                .iter()
                .map(|c| key(keys::conv_pk(&self.scope, c), keys::META_SK))
                .collect();
            // A few retries for unprocessed keys; plenty at demo volume.
            for _ in 0..3 {
                if pending.is_empty() {
                    break;
                }
                let req = KeysAndAttributes::builder()
                    .set_keys(Some(pending))
                    .build()?;
                let out = self
                    .client
                    .batch_get_item()
                    .request_items(&self.table, req)
                    .send()
                    .await
                    .map_err(StoreError::from_sdk)?;
                if let Some(mut found) = out.responses {
                    convs.extend(from_items::<_, ConversationSummary>(
                        found.remove(&self.table).unwrap_or_default(),
                    )?);
                }
                pending = out
                    .unprocessed_keys
                    .and_then(|mut u| u.remove(&self.table))
                    .map(|k| k.keys)
                    .unwrap_or_default();
            }
        }
        convs.sort_by(|a, b| {
            b.last_message_at
                .cmp(&a.last_message_at)
                .then(a.name.cmp(&b.name))
        });
        Ok(convs)
    }

    /// AP7 (members part).
    pub async fn conversation_members(&self, conv: &ConvId) -> Result<Vec<Member>, StoreError> {
        let items = self
            .query_all(
                None,
                keys::conv_pk(&self.scope, conv),
                Some(keys::MEMBER_PREFIX),
            )
            .await?;
        Ok(from_items(items)?)
    }

    /// AP9: people who share conversations with `user`, and how many. Two hops: the user's
    /// conversations, then each one's members (8 in flight at a time).
    pub async fn co_members(&self, user: &UserId) -> Result<Vec<Peer>, StoreError> {
        let convs = self.user_conversation_ids(user).await?;
        let lists: Vec<Vec<Member>> = stream::iter(convs)
            .map(|c| async move { self.conversation_members(&c).await })
            .buffer_unordered(8)
            .try_collect()
            .await?;
        let mut counts: HashMap<UserId, u32> = HashMap::new();
        for m in lists.into_iter().flatten().filter(|m| &m.user_id != user) {
            *counts.entry(m.user_id).or_default() += 1;
        }
        let mut peers: Vec<Peer> = counts
            .into_iter()
            .map(|(user_id, shared)| Peer { user_id, shared })
            .collect();
        peers.sort_by(|a, b| b.shared.cmp(&a.shared).then(a.user_id.cmp(&b.user_id)));
        Ok(peers)
    }

    /// AP10: users in the tenant.
    pub async fn tenant_users(&self) -> Result<Vec<TenantUser>, StoreError> {
        let items = self
            .query_all(None, keys::tenant_pk(&self.scope), Some(keys::USER_PREFIX))
            .await?;
        Ok(from_items(items)?)
    }

    pub async fn tenant_user(&self, user: &UserId) -> Result<Option<TenantUser>, StoreError> {
        match self
            .get(keys::tenant_pk(&self.scope), keys::user_sk(user))
            .await?
        {
            Some(item) => Ok(Some(from_item(item)?)),
            None => Ok(None),
        }
    }

    /// AP2: map an external sender to an internal user, if one is linked.
    pub async fn resolve_identity(
        &self,
        ch: Channel,
        ext: &ExternalId,
    ) -> Result<Option<UserId>, StoreError> {
        #[derive(Deserialize)]
        struct Ident {
            user_id: UserId,
        }
        match self
            .get(keys::ident_pk(&self.scope, ch, ext), keys::IDENT_SK)
            .await?
        {
            Some(item) => Ok(Some(from_item::<_, Ident>(item)?.user_id)),
            None => Ok(None),
        }
    }

    /// AP3 + AP4 in one transaction: the de-duplication record (if the message has a provider
    /// id), the message, and the conversation's `last_message_at`. A redelivered event cancels
    /// the whole transaction, so nothing is written twice.
    pub async fn append_message(
        &self,
        msg: &CanonicalMessage,
    ) -> Result<AppendOutcome, StoreError> {
        let pk = keys::conv_pk(&self.scope, &msg.conversation_id);
        let mut tx = Vec::with_capacity(3);

        if let Some(ext) = &msg.external_id {
            let expires = (msg.received_at + DEDUP_TTL).unix_timestamp();
            let mut dedup = key(
                keys::dedup_pk(&self.scope, msg.channel, ext),
                keys::DEDUP_SK,
            );
            dedup.insert("message_id".into(), s(msg.message_id.to_string()));
            dedup.insert("expires_at".into(), AttributeValue::N(expires.to_string()));
            tx.push(put(&self.table, dedup, Some("attribute_not_exists(PK)"))?);
        }

        let mut item: Item = to_item(msg)?;
        item.extend(key(pk.clone(), keys::msg_sk(msg.message_id)));
        item.insert("tenant_id".into(), s(self.scope.tenant_id().as_str()));
        tx.push(put(&self.table, item, None)?);

        let touch = Update::builder()
            .table_name(&self.table)
            .set_key(Some(key(pk, keys::META_SK)))
            .update_expression("SET last_message_at = :t")
            .condition_expression("attribute_exists(PK)")
            .expression_attribute_values(":t", s(ts_millis(msg.received_at)))
            .build()?;
        tx.push(TransactWriteItem::builder().update(touch).build());

        let has_dedup = msg.external_id.is_some();
        match self
            .client
            .transact_write_items()
            .set_transact_items(Some(tx))
            .send()
            .await
        {
            Ok(_) => Ok(AppendOutcome::Appended),
            Err(e) if is_access_denied(&e) => Err(StoreError::AccessDenied),
            Err(e) => {
                let code = e.code().map(str::to_owned);
                match e.into_service_error() {
                    TransactWriteItemsError::TransactionCanceledException(c) => {
                        let reasons: Vec<Option<&str>> =
                            c.cancellation_reasons().iter().map(|r| r.code()).collect();
                        let failed = |i: usize| {
                            reasons.get(i).copied().flatten() == Some("ConditionalCheckFailed")
                        };
                        if has_dedup && failed(0) {
                            Ok(AppendOutcome::Duplicate)
                        } else if failed(reasons.len().saturating_sub(1)) {
                            Err(StoreError::NotFound) // the conversation doesn't exist
                        } else {
                            Err(StoreError::Dynamo(format!(
                                "transaction cancelled: {reasons:?}"
                            )))
                        }
                    }
                    other => Err(StoreError::Dynamo(format!(
                        "{}: {other}",
                        code.unwrap_or_default()
                    ))),
                }
            }
        }
    }

    /// The isolation probe: deliberately reads another tenant's meta item with *this* tenant's
    /// credentials, skipping every app-layer check. The only function that builds a key for a
    /// tenant other than the scope's. With a correctly scoped client, IAM denies it.
    pub async fn isolation_probe(&self, other: &TenantId) -> Result<(), StoreError> {
        self.get(format!("T#{other}#TENANT"), keys::META_SK)
            .await
            .map(|_| ())
    }
}

fn put(table: &str, item: Item, condition: Option<&str>) -> Result<TransactWriteItem, StoreError> {
    let p = Put::builder()
        .table_name(table)
        .set_item(Some(item))
        .set_condition_expression(condition.map(str::to_owned))
        .build()?;
    Ok(TransactWriteItem::builder().put(p).build())
}

/// A message for `conv` received now, for native posts and tests.
pub fn new_message(
    conv: ConvId,
    channel: Channel,
    sender: domain::Sender,
    body_text: String,
    external_id: Option<ExternalId>,
) -> CanonicalMessage {
    let now = OffsetDateTime::now_utc();
    CanonicalMessage {
        message_id: ulid::Ulid::generate(),
        conversation_id: conv,
        channel,
        sender,
        body_text,
        sent_at: now,
        received_at: now,
        external_id,
    }
}
