//! Channel adapters (Slack, SMS) that verify and translate inbound webhooks.
//!
//! Each adapter knows its provider's wire format and signature headers, and turns a request
//! into an [`Inbound`]: a provider-neutral message plus the address it was sent to. Routing to a
//! tenant happens after this, from the address, never from anything the payload claims.

pub mod signature;
mod slack;
mod sms;

use domain::{Channel, ExternalId, RouteAddress};
use time::OffsetDateTime;

pub use signature::{SignatureError, channel_key, sign, verify};
pub use slack::SlackAdapter;
pub use sms::SmsAdapter;

/// A message as the provider described it, before routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundMessage {
    /// Where it was sent: looked up as `ROUTE#<channel>#<address>`.
    pub address: RouteAddress,
    /// The provider's event id, for de-duplicating retries.
    pub external_id: ExternalId,
    /// The sender's id at the provider, for identity lookup.
    pub sender: ExternalId,
    pub sender_display: Option<String>,
    pub text: String,
    pub sent_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Message(InboundMessage),
    /// Slack's endpoint check: echo the challenge back.
    UrlVerification {
        challenge: String,
    },
    /// A valid event we deliberately don't store (bot messages, edits, other event types).
    Ignored {
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("malformed body: {0}")]
    Malformed(String),
    #[error("missing field {0}")]
    Missing(&'static str),
    #[error("invalid field {0}")]
    Invalid(&'static str),
}

pub trait ChannelAdapter: Send + Sync {
    fn channel(&self) -> Channel;
    /// Header names carrying the timestamp and the `v0=` signature.
    fn signature_headers(&self) -> (&'static str, &'static str);
    fn parse(&self, body: &[u8], now: OffsetDateTime) -> Result<Inbound, ParseError>;
}

pub fn adapter_for(ch: Channel) -> Option<&'static dyn ChannelAdapter> {
    match ch {
        Channel::Slack => Some(&SlackAdapter),
        Channel::Sms => Some(&SmsAdapter),
        Channel::Email | Channel::Native => None,
    }
}

pub(crate) fn ext(value: &str, field: &'static str) -> Result<ExternalId, ParseError> {
    ExternalId::parse(value).map_err(|_| ParseError::Invalid(field))
}
