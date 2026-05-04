//! HMAC-SHA256 signing for outbound webhook payloads.
//!
//! Format on the wire: `X-Allowthem-Signature: t=<unix-seconds>,v1=<hex>`,
//! where the hex is `HMAC-SHA256(key, "{timestamp}.{body}")`. Mirrors
//! Stripe's signed-payload scheme so integrators with prior Stripe
//! work can reuse verification snippets.
//!
//! Used by:
//! - [`crate::WebhookEmailSender`] (epic c8m.2)
//! - `WebhookWorker` (epic 7xw.2) — adopt `sign_payload` during that
//!   implementation instead of a separate local signer.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Error returned by [`verify_payload`].
#[derive(Debug, thiserror::Error)]
pub enum SigError {
    /// Header could not be parsed (missing `t=` or `v1=` parts).
    #[error("malformed signature header")]
    Malformed,
    /// HMAC did not match.
    #[error("signature mismatch")]
    Mismatch,
    /// Timestamp is outside the allowed tolerance window.
    #[error("signature timestamp out of tolerance")]
    Stale,
}

/// Sign `body` with `secret` and `timestamp` (Unix seconds).
///
/// Returns the value for the `X-Allowthem-Signature` header:
/// `t=<timestamp>,v1=<hex>`.
///
/// The signed material is `"{timestamp}.{body}"` — same scheme as Stripe
/// so customers with prior integrations can reuse verification snippets.
pub fn sign_payload(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    format!("t={timestamp},v1={}", hex::encode(tag))
}

/// Verify a `X-Allowthem-Signature` header value.
///
/// `now_unix_seconds` is the current time; `tolerance_seconds` is the
/// maximum allowed age of the timestamp (replay protection). Pass `0`
/// for `tolerance_seconds` to skip the freshness check entirely.
///
/// Returns `Ok(())` on success, `Err(SigError)` otherwise.
pub fn verify_payload(
    secret: &[u8],
    body: &[u8],
    signature_header: &str,
    now_unix_seconds: i64,
    tolerance_seconds: i64,
) -> Result<(), SigError> {
    // Parse "t=<ts>,v1=<hex>" — both parts required.
    let mut ts_part: Option<i64> = None;
    let mut sig_hex: Option<String> = None;
    for part in signature_header.split(',') {
        if let Some(v) = part.strip_prefix("t=") {
            ts_part = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("v1=") {
            sig_hex = Some(v.to_owned());
        }
    }
    let timestamp = ts_part.ok_or(SigError::Malformed)?;
    let sig_bytes =
        hex::decode(sig_hex.ok_or(SigError::Malformed)?).map_err(|_| SigError::Malformed)?;

    // Freshness check.
    if tolerance_seconds > 0 {
        let age = now_unix_seconds.saturating_sub(timestamp);
        if age > tolerance_seconds {
            return Err(SigError::Stale);
        }
    }

    // Recompute and compare in constant time.
    let expected = sign_payload(secret, timestamp, body);
    // Extract the hex portion after "v1=".
    let expected_hex = expected.split("v1=").nth(1).ok_or(SigError::Malformed)?;
    let expected_bytes = hex::decode(expected_hex).map_err(|_| SigError::Malformed)?;

    if sig_bytes.ct_eq(&expected_bytes).into() {
        Ok(())
    } else {
        Err(SigError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret";
    const TS: i64 = 1_700_000_000;
    const BODY: &[u8] = b"{}";

    #[test]
    fn golden_value() {
        // Pinned to catch accidental format drift.
        let sig = sign_payload(SECRET, TS, BODY);
        // Recompute inline for the pin — changing the algorithm breaks this.
        let mut mac = <hmac::Hmac<sha2::Sha256>>::new_from_slice(SECRET).unwrap();
        mac.update(format!("{TS}.").as_bytes());
        mac.update(BODY);
        let expected_hex = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, format!("t={TS},v1={expected_hex}"));
    }

    #[test]
    fn round_trip() {
        let sig = sign_payload(SECRET, TS, BODY);
        assert!(verify_payload(SECRET, BODY, &sig, TS, 0).is_ok());
    }

    #[test]
    fn tampered_body_fails() {
        let sig = sign_payload(SECRET, TS, BODY);
        let tampered = b"{\"x\":1}";
        assert!(matches!(
            verify_payload(SECRET, tampered, &sig, TS, 0),
            Err(SigError::Mismatch)
        ));
    }

    #[test]
    fn tampered_secret_fails() {
        let sig = sign_payload(b"key-a", TS, BODY);
        assert!(matches!(
            verify_payload(b"key-b", BODY, &sig, TS, 0),
            Err(SigError::Mismatch)
        ));
    }

    #[test]
    fn stale_timestamp() {
        let old_ts = TS - 600;
        let sig = sign_payload(SECRET, old_ts, BODY);
        assert!(matches!(
            verify_payload(SECRET, BODY, &sig, TS, 300),
            Err(SigError::Stale)
        ));
    }

    #[test]
    fn malformed_header_no_t() {
        // "v1=abc" — missing t= part
        let sig = sign_payload(SECRET, TS, BODY);
        let v1_only = sig.split(',').find(|p| p.starts_with("v1=")).unwrap();
        assert!(matches!(
            verify_payload(SECRET, BODY, v1_only, TS, 0),
            Err(SigError::Malformed)
        ));
    }
}
