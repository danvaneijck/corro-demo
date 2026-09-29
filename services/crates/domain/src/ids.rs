//! Validated identifiers. Anything that ends up inside a DynamoDB key goes through one of these,
//! so no key segment can contain `#` (the key separator) or `*` (an IAM wildcard).

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind}: {reason}")]
pub struct IdError {
    pub kind: &'static str,
    pub reason: &'static str,
}

macro_rules! validated_id {
    ($(#[$doc:meta])* $name:ident, $kind:literal, $check:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn parse(s: &str) -> Result<Self, IdError> {
                let check: fn(&str) -> Result<(), &'static str> = $check;
                check(s).map_err(|reason| IdError { kind: $kind, reason })?;
                Ok(Self(s.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(s: String) -> Result<Self, IdError> {
                Self::parse(&s)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

fn charset(s: &str, min: usize, max: usize, ok: impl Fn(char) -> bool) -> Result<(), &'static str> {
    if s.len() < min {
        return Err("too short");
    }
    if s.len() > max {
        return Err("too long");
    }
    if !s.chars().all(ok) {
        return Err("invalid character");
    }
    Ok(())
}

validated_id!(
    /// `^[a-z0-9-]{3,32}$`. Also the value of the `tenant_id` session tag.
    TenantId,
    "tenant id",
    |s| charset(s, 3, 32, |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
);

validated_id!(
    /// A Cognito `sub` (a UUID), used as the internal user id.
    UserId,
    "user id",
    |s| charset(s, 1, 64, |c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
);

validated_id!(
    /// A conversation id such as `c_ops`.
    ConvId,
    "conversation id",
    |s| charset(s, 1, 64, |c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
);

validated_id!(
    /// An identifier supplied by an external provider: a Slack user or event id, a phone number,
    /// an email address. Printable ASCII with no `#` or `*`.
    ExternalId,
    "external id",
    |s| charset(s, 1, 128, |c| c.is_ascii_graphic() && c != '#' && c != '*')
);

/// The inbound address a route is keyed on, built from validated parts joined with `#`
/// (for Slack: team id and channel id; for SMS: the destination number).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAddress(String);

impl RouteAddress {
    pub fn new(parts: &[&ExternalId]) -> Self {
        let joined = parts
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join("#");
        Self(joined)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The channel a message arrived on. `Native` is a message posted through the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Slack,
    Sms,
    Email,
    Native,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Slack => "slack",
            Channel::Sms => "sms",
            Channel::Email => "email",
            Channel::Native => "native",
        }
    }

    /// Parses an inbound (webhook) channel. `native` isn't accepted: it has no webhook.
    pub fn parse_inbound(s: &str) -> Option<Self> {
        match s {
            "slack" => Some(Channel::Slack),
            "sms" => Some(Channel::Sms),
            "email" => Some(Channel::Email),
            _ => None,
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_accepts_valid() {
        for ok in ["acme", "globex", "gov-agency-01", "abc"] {
            assert!(TenantId::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn tenant_id_rejects_key_and_wildcard_characters() {
        for bad in [
            "ab",
            "Acme",
            "acme#x",
            "acme*",
            "a c m e",
            "",
            &"a".repeat(33),
            "acme/x",
        ] {
            assert!(TenantId::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ids_reject_separator() {
        assert!(ConvId::parse("c_ops#MSG").is_err());
        assert!(UserId::parse("u#1").is_err());
        assert!(ExternalId::parse("T1#C1").is_err());
        assert!(ExternalId::parse("*").is_err());
        assert!(ExternalId::parse("+61400000001").is_ok());
        assert!(ExternalId::parse("support@acme.test").is_ok());
    }

    #[test]
    fn deserialisation_validates() {
        let bad: Result<TenantId, _> = serde_json::from_str("\"ACME#\"");
        assert!(bad.is_err());
        let good: TenantId = serde_json::from_str("\"acme\"").unwrap();
        assert_eq!(good.as_str(), "acme");
    }

    #[test]
    fn route_address_joins_parts() {
        let team = ExternalId::parse("T0ACME").unwrap();
        let chan = ExternalId::parse("C0OPS").unwrap();
        assert_eq!(RouteAddress::new(&[&team, &chan]).as_str(), "T0ACME#C0OPS");
    }
}
