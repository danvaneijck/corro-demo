//! Slack Events API: JSON `event_callback` envelopes, plus the `url_verification` handshake.

use domain::{Channel, RouteAddress};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::{ChannelAdapter, Inbound, InboundMessage, ParseError, ext};

pub struct SlackAdapter;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Envelope {
    UrlVerification {
        challenge: String,
    },
    EventCallback {
        team_id: String,
        event_id: String,
        event: Event,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "type")]
    kind: String,
    subtype: Option<String>,
    channel: Option<String>,
    user: Option<String>,
    text: Option<String>,
    ts: Option<String>,
}

/// Slack's `ts` is `<unix seconds>.<micros>`.
fn parse_ts(ts: &str) -> Option<OffsetDateTime> {
    let (secs, micros) = ts.split_once('.').unwrap_or((ts, "0"));
    let secs: i64 = secs.parse().ok()?;
    let micros: i64 = format!("{micros:0<6}").get(..6)?.parse().ok()?;
    let nanos = i128::from(secs) * 1_000_000_000 + i128::from(micros) * 1_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()
}

impl ChannelAdapter for SlackAdapter {
    fn channel(&self) -> Channel {
        Channel::Slack
    }

    fn signature_headers(&self) -> (&'static str, &'static str) {
        ("x-slack-request-timestamp", "x-slack-signature")
    }

    fn parse(&self, body: &[u8], now: OffsetDateTime) -> Result<Inbound, ParseError> {
        let env: Envelope =
            serde_json::from_slice(body).map_err(|e| ParseError::Malformed(e.to_string()))?;
        let (team_id, event_id, event) = match env {
            Envelope::UrlVerification { challenge } => {
                return Ok(Inbound::UrlVerification { challenge });
            }
            Envelope::EventCallback {
                team_id,
                event_id,
                event,
            } => (team_id, event_id, event),
            Envelope::Other => {
                return Ok(Inbound::Ignored {
                    reason: "unsupported_envelope",
                });
            }
        };
        if event.kind != "message" {
            return Ok(Inbound::Ignored {
                reason: "unsupported_event",
            });
        }
        // Bot posts, edits, deletions, joins and so on all carry a subtype.
        if event.subtype.is_some() {
            return Ok(Inbound::Ignored {
                reason: "message_subtype",
            });
        }
        let channel = event.channel.ok_or(ParseError::Missing("event.channel"))?;
        let user = event.user.ok_or(ParseError::Missing("event.user"))?;
        let text = event.text.ok_or(ParseError::Missing("event.text"))?;
        let sent_at = event.ts.as_deref().and_then(parse_ts).unwrap_or(now);
        Ok(Inbound::Message(InboundMessage {
            address: RouteAddress::new(&[
                &ext(&team_id, "team_id")?,
                &ext(&channel, "event.channel")?,
            ]),
            // Slack retries the same event with the same event_id.
            external_id: ext(&event_id, "event_id")?,
            sender: ext(&user, "event.user")?,
            sender_display: None,
            text,
            sent_at,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-09-30 09:00 UTC);

    #[test]
    fn translates_a_message_event() {
        let body = include_bytes!("../../../../fixtures/slack_message.json");
        let Inbound::Message(m) = SlackAdapter.parse(body, NOW).unwrap() else {
            panic!("expected a message")
        };
        assert_eq!(m.address.as_str(), "T0ACME#C0OPS");
        assert_eq!(m.external_id.as_str(), "Ev08MFMKH6");
        assert_eq!(m.sender.as_str(), "U024BE7LH");
        assert_eq!(m.text, "Heads up: the region B outage is resolved.");
        assert_eq!(m.sent_at, datetime!(2026-09-29 09:00:00.0001 UTC));
    }

    #[test]
    fn answers_url_verification() {
        let body = include_bytes!("../../../../fixtures/slack_url_verification.json");
        assert!(
            matches!(SlackAdapter.parse(body, NOW).unwrap(), Inbound::UrlVerification { challenge } if challenge.starts_with("3eZbrw"))
        );
    }

    #[test]
    fn ignores_bot_messages_and_other_events() {
        let body = include_bytes!("../../../../fixtures/slack_bot_message.json");
        assert_eq!(
            SlackAdapter.parse(body, NOW).unwrap(),
            Inbound::Ignored {
                reason: "message_subtype"
            }
        );
        let reaction = br#"{"type":"event_callback","team_id":"T1","event_id":"Ev1","event":{"type":"reaction_added"}}"#;
        assert_eq!(
            SlackAdapter.parse(reaction, NOW).unwrap(),
            Inbound::Ignored {
                reason: "unsupported_event"
            }
        );
        assert_eq!(
            SlackAdapter
                .parse(br#"{"type":"app_rate_limited"}"#, NOW)
                .unwrap(),
            Inbound::Ignored {
                reason: "unsupported_envelope"
            }
        );
    }

    #[test]
    fn rejects_key_injection_in_ids() {
        let body = br#"{"type":"event_callback","team_id":"T1#C9","event_id":"Ev1","event":{"type":"message","channel":"C1","user":"U1","text":"x"}}"#;
        assert_eq!(
            SlackAdapter.parse(body, NOW),
            Err(ParseError::Invalid("team_id"))
        );
    }

    #[test]
    fn rejects_malformed_and_incomplete_bodies() {
        assert!(matches!(
            SlackAdapter.parse(b"not json", NOW),
            Err(ParseError::Malformed(_))
        ));
        let no_text = br#"{"type":"event_callback","team_id":"T1","event_id":"Ev1","event":{"type":"message","channel":"C1","user":"U1"}}"#;
        assert_eq!(
            SlackAdapter.parse(no_text, NOW),
            Err(ParseError::Missing("event.text"))
        );
    }
}
