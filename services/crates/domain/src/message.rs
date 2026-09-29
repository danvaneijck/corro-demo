//! The canonical message every channel adapter translates into.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ulid::Ulid;

use crate::ids::{Channel, ConvId, ExternalId, UserId};

/// Who sent a message: a known user in the tenant, or someone outside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Sender {
    User {
        user_id: UserId,
    },
    External {
        address: String,
        display_name: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalMessage {
    /// A ULID, so ids sort by receive time.
    pub message_id: Ulid,
    pub conversation_id: ConvId,
    pub channel: Channel,
    pub sender: Sender,
    pub body_text: String,
    /// When the provider says it was sent. Can be out of order (email).
    #[serde(with = "time::serde::rfc3339")]
    pub sent_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    /// The provider's id, used for de-duplication. `None` for native messages.
    pub external_id: Option<ExternalId>,
}

/// Maximum message body accepted from any channel, in characters.
pub const MAX_BODY_CHARS: usize = 1000;
