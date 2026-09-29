//! The `MessageSearch` trait and its DynamoDB fallback implementation.
//!
//! The API only talks to the trait, so a real index (OpenSearch, with tenant routing and a
//! mandatory tenant filter; see DESIGN §3) can replace the fallback without changing `/search`.

use domain::{Channel, ConvId, UserId};
use futures::{StreamExt, TryStreamExt, stream};
use serde::Serialize;
use store::{InboxRepo, StoreError};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hit {
    pub conversation_id: ConvId,
    pub message_id: String,
    pub channel: Channel,
    pub body_text: String,
    #[serde(with = "time::serde::rfc3339")]
    pub sent_at: OffsetDateTime,
}

pub const MIN_QUERY_CHARS: usize = 2;
pub const MAX_QUERY_CHARS: usize = 100;

/// Searches only conversations the user belongs to, within the repo's tenant scope.
pub trait MessageSearch {
    fn search(
        &self,
        repo: &InboxRepo,
        user: &UserId,
        query: &str,
    ) -> impl Future<Output = Result<Vec<Hit>, StoreError>> + Send;
}

/// Zero-cost fallback: reads the last `per_conversation` messages of each of the user's
/// conversations and does a case-insensitive substring match. Fine for a demo; it doesn't scale
/// and only sees recent messages, which is why the design has a real index behind the same trait.
pub struct DdbScanFallback {
    pub per_conversation: i32,
    pub max_hits: usize,
}

impl Default for DdbScanFallback {
    fn default() -> Self {
        Self {
            per_conversation: 50,
            max_hits: 20,
        }
    }
}

impl MessageSearch for DdbScanFallback {
    async fn search(
        &self,
        repo: &InboxRepo,
        user: &UserId,
        query: &str,
    ) -> Result<Vec<Hit>, StoreError> {
        let needle = query.to_lowercase();
        let convs = repo.user_conversation_ids(user).await?;
        let per_conversation = self.per_conversation;
        let pages: Vec<_> = stream::iter(convs)
            .map(|c| async move { repo.list_messages(&c, per_conversation, None).await })
            .buffer_unordered(8)
            .try_collect()
            .await?;
        let mut hits: Vec<Hit> = pages
            .into_iter()
            .flat_map(|p| p.items)
            .filter(|m| m.body_text.to_lowercase().contains(&needle))
            .map(|m| Hit {
                conversation_id: m.conversation_id,
                message_id: m.message_id.to_string(),
                channel: m.channel,
                body_text: m.body_text,
                sent_at: m.sent_at,
            })
            .collect();
        hits.sort_by(|a, b| b.message_id.cmp(&a.message_id));
        hits.truncate(self.max_hits);
        Ok(hits)
    }
}
