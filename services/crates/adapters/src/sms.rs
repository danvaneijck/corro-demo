//! SMS in the shape Twilio posts it: `application/x-www-form-urlencoded` with `From`, `To`,
//! `Body` and `MessageSid`. A different wire format from Slack on purpose: that's the protocol
//! translation.

use std::collections::HashMap;

use domain::{Channel, RouteAddress};
use time::OffsetDateTime;

use crate::{ChannelAdapter, Inbound, InboundMessage, ParseError, ext};

pub struct SmsAdapter;

impl ChannelAdapter for SmsAdapter {
    fn channel(&self) -> Channel {
        Channel::Sms
    }

    fn signature_headers(&self) -> (&'static str, &'static str) {
        ("x-webhook-timestamp", "x-webhook-signature")
    }

    fn parse(&self, body: &[u8], now: OffsetDateTime) -> Result<Inbound, ParseError> {
        let form: HashMap<String, String> = form_urlencoded::parse(body).into_owned().collect();
        let field = |k: &'static str| {
            form.get(k)
                .map(String::as_str)
                .ok_or(ParseError::Missing(k))
        };
        let from = field("From")?;
        Ok(Inbound::Message(InboundMessage {
            // Routed on the number it was sent to.
            address: RouteAddress::new(&[&ext(field("To")?, "To")?]),
            external_id: ext(field("MessageSid")?, "MessageSid")?,
            sender: ext(from, "From")?,
            sender_display: Some(from.to_owned()),
            text: field("Body")?.to_owned(),
            // Twilio doesn't send a timestamp with inbound SMS.
            sent_at: now,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-09-30 09:00 UTC);

    #[test]
    fn translates_a_form_post() {
        let body = include_bytes!("../../../../fixtures/sms_message.txt");
        let Inbound::Message(m) = SmsAdapter.parse(body, NOW).unwrap() else {
            panic!("expected a message")
        };
        assert_eq!(m.address.as_str(), "+61400000001");
        assert_eq!(m.sender.as_str(), "+61400000999");
        assert_eq!(m.external_id.as_str(), "SM0123456789abcdef0123456789abcdef");
        assert_eq!(m.text, "Is the outage fixed?");
        assert_eq!(m.sent_at, NOW);
    }

    #[test]
    fn requires_every_field() {
        let body = b"From=%2B61400000999&Body=hi&MessageSid=SM1";
        assert_eq!(SmsAdapter.parse(body, NOW), Err(ParseError::Missing("To")));
    }

    #[test]
    fn rejects_key_injection_in_the_number() {
        let body = b"To=%2B614%23x&From=%2B61400000999&Body=hi&MessageSid=SM1";
        assert_eq!(SmsAdapter.parse(body, NOW), Err(ParseError::Invalid("To")));
    }
}
