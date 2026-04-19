use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::types::SessionToken;

type HmacSha256 = Hmac<Sha256>;

/// Derive a CSRF token from a session token and server secret.
///
/// Input: UTF-8 bytes of the base64url session token string (not decoded bytes).
/// Returns a 64-char lowercase hex string. Pure function — no DB access.
pub fn derive_csrf_token(session_token: &SessionToken, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(session_token.as_str().as_bytes());
    let result = mac.finalize();
    format!("{:x}", result.into_bytes())
}

/// Verify a submitted CSRF token against the expected derivation.
///
/// Uses constant-time comparison to prevent timing attacks.
/// Returns false if lengths differ or bytes do not match.
pub fn verify_csrf_token(session_token: &SessionToken, secret: &[u8], submitted: &str) -> bool {
    let expected = derive_csrf_token(session_token, secret);
    if expected.len() != submitted.len() {
        return false;
    }
    expected.as_bytes().ct_eq(submitted.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(s: &str) -> SessionToken {
        SessionToken::from_encoded(s.to_string())
    }

    const SECRET: &[u8] = b"test-secret-key-32bytes-padding!";

    #[test]
    fn derive_is_deterministic() {
        let t = token("abc123");
        let a = derive_csrf_token(&t, SECRET);
        let b = derive_csrf_token(&t, SECRET);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_differs_for_different_tokens() {
        let a = derive_csrf_token(&token("token_a"), SECRET);
        let b = derive_csrf_token(&token("token_b"), SECRET);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_differs_for_different_secrets() {
        let t = token("same_token");
        let a = derive_csrf_token(&t, b"secret_one_32bytes_padding_here!");
        let b = derive_csrf_token(&t, b"secret_two_32bytes_padding_here!");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_accepts_correct_token() {
        let t = token("abc123");
        let csrf = derive_csrf_token(&t, SECRET);
        assert!(verify_csrf_token(&t, SECRET, &csrf));
    }

    #[test]
    fn verify_rejects_wrong_token() {
        let t = token("abc123");
        assert!(!verify_csrf_token(&t, SECRET, "wrong_token_value"));
    }

    #[test]
    fn verify_rejects_different_length() {
        let t = token("abc123");
        assert!(!verify_csrf_token(&t, SECRET, "short"));
    }

    #[test]
    fn output_is_64_hex_chars() {
        let t = token("any_token_value");
        let csrf = derive_csrf_token(&t, SECRET);
        assert_eq!(csrf.len(), 64);
        assert!(csrf.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
