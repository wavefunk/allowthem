use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::AuthError;
use crate::types::{
    ApplicationId, AuthorizationCodeId, ConsentId, TokenHash, UserId,
};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub id: AuthorizationCodeId,
    pub application_id: ApplicationId,
    pub user_id: UserId,
    pub code_hash: TokenHash,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Consent {
    pub id: ConsentId,
    pub user_id: UserId,
    pub application_id: ApplicationId,
    pub scopes: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The set of supported OIDC scopes.
const SUPPORTED_SCOPES: &[&str] = &["openid", "profile", "email"];

/// Parse and validate a space-separated scope string.
///
/// Rules:
/// - `openid` must be present (this is an OIDC provider).
/// - All scopes must be in `SUPPORTED_SCOPES`.
///
/// Returns the validated scopes as a `Vec<String>`.
pub fn validate_scopes(scope_str: &str) -> Result<Vec<String>, AuthError> {
    let scopes: Vec<String> = scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    if scopes.is_empty() || !scopes.iter().any(|s| s == "openid") {
        return Err(AuthError::InvalidAuthorizationRequest(
            "scope must include openid".into(),
        ));
    }

    for scope in &scopes {
        if !SUPPORTED_SCOPES.contains(&scope.as_str()) {
            return Err(AuthError::InvalidAuthorizationRequest(
                format!("unsupported scope: {scope}"),
            ));
        }
    }

    Ok(scopes)
}

/// Generate a raw authorization code: 32 random bytes, base64url-encoded.
///
/// Same pattern as `sessions::generate_token()`. Returns the raw code string
/// to include in the redirect URI. The caller must hash it before storage.
pub fn generate_authorization_code() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    Base64UrlUnpadded::encode_string(&bytes)
}

/// Hash a raw authorization code with SHA-256.
///
/// Returns the hex-encoded digest as a `TokenHash`. Same pattern as
/// `sessions::hash_token()`.
pub fn hash_authorization_code(raw: &str) -> TokenHash {
    let digest = Sha256::digest(raw.as_bytes());
    TokenHash::new_unchecked(format!("{digest:x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_scopes_openid_only() {
        let scopes = validate_scopes("openid").unwrap();
        assert_eq!(scopes, vec!["openid"]);
    }

    #[test]
    fn valid_scopes_all_three() {
        let scopes = validate_scopes("openid profile email").unwrap();
        assert_eq!(scopes, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn missing_openid_is_rejected() {
        let err = validate_scopes("profile email").unwrap_err();
        assert!(matches!(err, AuthError::InvalidAuthorizationRequest(_)));
    }

    #[test]
    fn empty_scope_is_rejected() {
        let err = validate_scopes("").unwrap_err();
        assert!(matches!(err, AuthError::InvalidAuthorizationRequest(_)));
    }

    #[test]
    fn whitespace_only_scope_is_rejected() {
        let err = validate_scopes("   ").unwrap_err();
        assert!(matches!(err, AuthError::InvalidAuthorizationRequest(_)));
    }

    #[test]
    fn unknown_scope_is_rejected() {
        let err = validate_scopes("openid admin").unwrap_err();
        assert!(matches!(err, AuthError::InvalidAuthorizationRequest(_)));
    }

    #[test]
    fn duplicate_openid_is_fine() {
        let scopes = validate_scopes("openid openid profile").unwrap();
        assert_eq!(scopes, vec!["openid", "openid", "profile"]);
    }

    #[test]
    fn code_is_43_chars() {
        let code = generate_authorization_code();
        assert_eq!(code.len(), 43, "32 bytes base64url = 43 chars");
    }

    #[test]
    fn code_is_url_safe() {
        let code = generate_authorization_code();
        assert!(
            code.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "code must be URL-safe base64url: got {code}"
        );
    }

    #[test]
    fn two_codes_differ() {
        let a = generate_authorization_code();
        let b = generate_authorization_code();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_is_deterministic() {
        let code = generate_authorization_code();
        let h1 = hash_authorization_code(&code);
        let h2 = hash_authorization_code(&code);
        assert_eq!(format!("{h1:?}"), format!("{h2:?}"));
    }

    #[test]
    fn different_codes_produce_different_hashes() {
        let a = generate_authorization_code();
        let b = generate_authorization_code();
        let ha = hash_authorization_code(&a);
        let hb = hash_authorization_code(&b);
        assert_ne!(format!("{ha:?}"), format!("{hb:?}"));
    }
}
