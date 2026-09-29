//! Webhook signatures: HMAC-SHA256 over `v0:<timestamp>:<raw body>`, sent as `v0=<hex>` (the
//! Slack scheme). The demo uses it for SMS too; a real Twilio integration would verify
//! `X-Twilio-Signature` (HMAC-SHA1 over URL + sorted params) instead.

use domain::Channel;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Requests older or newer than this are rejected, which bounds replay.
pub const MAX_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("missing signature or timestamp")]
    Missing,
    #[error("malformed signature or timestamp")]
    Malformed,
    #[error("timestamp outside the replay window")]
    Stale,
    #[error("signature mismatch")]
    Mismatch,
}

impl SignatureError {
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureError::Missing => "missing",
            SignatureError::Malformed => "malformed",
            SignatureError::Stale => "stale",
            SignatureError::Mismatch => "mismatch",
        }
    }
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// The per-channel signing key: `HMAC-SHA256(root, "webhook/<channel>")`. One generated root
/// secret, a different key per channel.
pub fn channel_key(root: &[u8], ch: Channel) -> [u8; 32] {
    hmac(root, &[b"webhook/", ch.as_str().as_bytes()])
}

/// `v0=<hex>` for a body at a timestamp. Used by tests and the signing script's equivalent.
pub fn sign(key: &[u8], ts: &str, body: &[u8]) -> String {
    format!(
        "v0={}",
        hex::encode(hmac(key, &[b"v0:", ts.as_bytes(), b":", body]))
    )
}

/// Checks the timestamp window first (cheap), then the signature in constant time.
pub fn verify(
    key: &[u8],
    ts: Option<&str>,
    body: &[u8],
    sig: Option<&str>,
    now: i64,
) -> Result<(), SignatureError> {
    let (ts, sig) = ts.zip(sig).ok_or(SignatureError::Missing)?;
    let ts_secs: i64 = ts.parse().map_err(|_| SignatureError::Malformed)?;
    // abs_diff can't overflow, unlike (now - ts).abs() with an extreme timestamp.
    if now.abs_diff(ts_secs) > MAX_SKEW_SECS.unsigned_abs() {
        return Err(SignatureError::Stale);
    }
    let given = sig
        .strip_prefix("v0=")
        .and_then(|h| hex::decode(h).ok())
        .ok_or(SignatureError::Malformed)?;
    let expected = hmac(key, &[b"v0:", ts.as_bytes(), b":", body]);
    if bool::from(expected.as_slice().ct_eq(&given)) {
        Ok(())
    } else {
        Err(SignatureError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key";
    const NOW: i64 = 1_790_672_400;

    #[test]
    fn accepts_a_valid_signature() {
        let sig = sign(KEY, "1790672400", b"{}");
        assert_eq!(
            verify(KEY, Some("1790672400"), b"{}", Some(&sig), NOW),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_tampered_body_or_wrong_key() {
        let sig = sign(KEY, "1790672400", b"{\"a\":1}");
        assert_eq!(
            verify(KEY, Some("1790672400"), b"{\"a\":2}", Some(&sig), NOW),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify(b"other", Some("1790672400"), b"{\"a\":1}", Some(&sig), NOW),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn rejects_a_stale_timestamp_even_with_a_valid_signature() {
        let old = (NOW - MAX_SKEW_SECS - 1).to_string();
        let sig = sign(KEY, &old, b"{}");
        assert_eq!(
            verify(KEY, Some(&old), b"{}", Some(&sig), NOW),
            Err(SignatureError::Stale)
        );
        let future = (NOW + MAX_SKEW_SECS + 1).to_string();
        let sig = sign(KEY, &future, b"{}");
        assert_eq!(
            verify(KEY, Some(&future), b"{}", Some(&sig), NOW),
            Err(SignatureError::Stale)
        );
    }

    #[test]
    fn rejects_extreme_timestamps_without_overflowing() {
        for ts in [i64::MIN, i64::MIN + NOW, i64::MAX] {
            let ts = ts.to_string();
            let sig = sign(KEY, &ts, b"{}");
            assert_eq!(
                verify(KEY, Some(&ts), b"{}", Some(&sig), NOW),
                Err(SignatureError::Stale),
                "{ts}"
            );
        }
    }

    #[test]
    fn rejects_missing_and_malformed_headers() {
        assert_eq!(
            verify(KEY, None, b"{}", Some("v0=00"), NOW),
            Err(SignatureError::Missing)
        );
        assert_eq!(
            verify(KEY, Some("1790672400"), b"{}", None, NOW),
            Err(SignatureError::Missing)
        );
        assert_eq!(
            verify(KEY, Some("soon"), b"{}", Some("v0=00"), NOW),
            Err(SignatureError::Malformed)
        );
        assert_eq!(
            verify(KEY, Some("1790672400"), b"{}", Some("sha256=00"), NOW),
            Err(SignatureError::Malformed)
        );
        assert_eq!(
            verify(KEY, Some("1790672400"), b"{}", Some("v0=zz"), NOW),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn channel_keys_differ() {
        assert_ne!(
            channel_key(b"root", Channel::Slack),
            channel_key(b"root", Channel::Sms)
        );
    }

    #[test]
    fn matches_the_openssl_recipe_in_sign_webhook_sh() {
        // printf 'webhook/slack' | openssl dgst -sha256 -hmac root -hex
        assert_eq!(
            hex::encode(channel_key(b"root", Channel::Slack)),
            "22eee56b79e99a8010aa9eeff46c9599d5c4b28ac36d7e75c53c1aaf725caca9"
        );
    }
}
