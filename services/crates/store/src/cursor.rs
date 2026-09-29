//! Opaque pagination cursors: base64url of the `LastEvaluatedKey`.
//!
//! On the way back in, the cursor's partition key must equal the partition being paged and its
//! sort key must carry the expected prefix, so a crafted cursor can't pivot to another
//! conversation or tenant. (IAM would reject a cross-tenant key anyway.)

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::StoreError;

#[derive(Serialize, Deserialize)]
struct CursorKey {
    pk: String,
    sk: String,
}

pub fn encode(last_key: &HashMap<String, AttributeValue>) -> Option<String> {
    let s = |k: &str| last_key.get(k).and_then(|v| v.as_s().ok()).cloned();
    let key = CursorKey {
        pk: s("PK")?,
        sk: s("SK")?,
    };
    Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&key).ok()?))
}

pub fn decode(
    cursor: &str,
    expected_pk: &str,
    sk_prefix: &str,
) -> Result<HashMap<String, AttributeValue>, StoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| StoreError::InvalidCursor)?;
    let key: CursorKey = serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidCursor)?;
    if key.pk != expected_pk || !key.sk.starts_with(sk_prefix) {
        return Err(StoreError::InvalidCursor);
    }
    Ok(HashMap::from([
        ("PK".to_owned(), AttributeValue::S(key.pk)),
        ("SK".to_owned(), AttributeValue::S(key.sk)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pk: &str, sk: &str) -> HashMap<String, AttributeValue> {
        HashMap::from([
            ("PK".to_owned(), AttributeValue::S(pk.to_owned())),
            ("SK".to_owned(), AttributeValue::S(sk.to_owned())),
        ])
    }

    #[test]
    fn round_trips() {
        let c = encode(&key("T#acme#CONV#c1", "MSG#01J")).unwrap();
        let back = decode(&c, "T#acme#CONV#c1", "MSG#").unwrap();
        assert_eq!(back, key("T#acme#CONV#c1", "MSG#01J"));
    }

    #[test]
    fn cursor_with_foreign_pk_is_rejected() {
        // Same tenant, other conversation.
        let other_conv = encode(&key("T#acme#CONV#c_secret", "MSG#01J")).unwrap();
        assert!(matches!(
            decode(&other_conv, "T#acme#CONV#c1", "MSG#"),
            Err(StoreError::InvalidCursor)
        ));
        // Other tenant.
        let other_tenant = encode(&key("T#globex#CONV#c1", "MSG#01J")).unwrap();
        assert!(matches!(
            decode(&other_tenant, "T#acme#CONV#c1", "MSG#"),
            Err(StoreError::InvalidCursor)
        ));
    }

    #[test]
    fn cursor_with_wrong_sk_prefix_is_rejected() {
        // Pointing at the member list instead of messages.
        let c = encode(&key("T#acme#CONV#c1", "MEMBER#u1")).unwrap();
        assert!(matches!(
            decode(&c, "T#acme#CONV#c1", "MSG#"),
            Err(StoreError::InvalidCursor)
        ));
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in ["", "!!!", "bm90IGpzb24", "eyJwayI6MX0"] {
            assert!(
                matches!(
                    decode(bad, "T#acme#CONV#c1", "MSG#"),
                    Err(StoreError::InvalidCursor)
                ),
                "{bad}"
            );
        }
    }
}
