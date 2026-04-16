use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::db::Db;
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

impl Db {
    /// Check whether the user has an existing consent that covers all requested scopes.
    pub async fn has_sufficient_consent(
        &self,
        user_id: UserId,
        application_id: ApplicationId,
        requested_scopes: &[String],
    ) -> Result<bool, AuthError> {
        let consent = self.get_consent(user_id, application_id).await?;
        let Some(consent) = consent else {
            return Ok(false);
        };
        let stored: Vec<String> = serde_json::from_str(&consent.scopes)
            .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let stored_set: std::collections::HashSet<&str> =
            stored.iter().map(|s| s.as_str()).collect();
        Ok(requested_scopes
            .iter()
            .all(|s| stored_set.contains(s.as_str())))
    }

    /// Record or update user consent for an application.
    ///
    /// Stored scopes become the union of existing and new scopes (consent is additive).
    pub async fn upsert_consent(
        &self,
        user_id: UserId,
        application_id: ApplicationId,
        scopes: &[String],
    ) -> Result<(), AuthError> {
        let id = ConsentId::new();
        let scopes_json =
            serde_json::to_string(scopes).expect("Vec<String> serializes to JSON");
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let existing = self.get_consent(user_id, application_id).await?;
        let merged_json = if let Some(existing) = existing {
            let mut stored: Vec<String> = serde_json::from_str(&existing.scopes)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?;
            for scope in scopes {
                if !stored.contains(scope) {
                    stored.push(scope.clone());
                }
            }
            serde_json::to_string(&stored).expect("Vec<String> serializes to JSON")
        } else {
            scopes_json
        };

        sqlx::query(
            "INSERT INTO allowthem_consents \
             (id, user_id, application_id, scopes, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5) \
             ON CONFLICT(user_id, application_id) DO UPDATE SET scopes = ?4, updated_at = ?5",
        )
        .bind(id)
        .bind(user_id)
        .bind(application_id)
        .bind(&merged_json)
        .bind(&now)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    /// Get the consent record for a user and application, if any.
    pub async fn get_consent(
        &self,
        user_id: UserId,
        application_id: ApplicationId,
    ) -> Result<Option<Consent>, AuthError> {
        sqlx::query_as::<_, Consent>(
            "SELECT id, user_id, application_id, scopes, created_at, updated_at \
             FROM allowthem_consents WHERE user_id = ? AND application_id = ?",
        )
        .bind(user_id)
        .bind(application_id)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Create an authorization code record. Expires after 10 minutes.
    pub async fn create_authorization_code(
        &self,
        application_id: ApplicationId,
        user_id: UserId,
        code_hash: &TokenHash,
        redirect_uri: &str,
        scopes: &[String],
        code_challenge: &str,
        code_challenge_method: &str,
        nonce: Option<&str>,
    ) -> Result<AuthorizationCode, AuthError> {
        let id = AuthorizationCodeId::new();
        let scopes_json =
            serde_json::to_string(scopes).expect("Vec<String> serializes to JSON");
        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let expires_at = now + chrono::Duration::minutes(10);
        let expires_str = expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_authorization_codes \
             (id, application_id, user_id, code_hash, redirect_uri, scopes, \
              code_challenge, code_challenge_method, nonce, expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(id)
        .bind(application_id)
        .bind(user_id)
        .bind(code_hash)
        .bind(redirect_uri)
        .bind(&scopes_json)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(nonce)
        .bind(&expires_str)
        .bind(&now_str)
        .execute(self.pool())
        .await?;

        sqlx::query_as::<_, AuthorizationCode>(
            "SELECT id, application_id, user_id, code_hash, redirect_uri, scopes, \
             code_challenge, code_challenge_method, nonce, expires_at, used_at, created_at \
             FROM allowthem_authorization_codes WHERE id = ?",
        )
        .bind(id)
        .fetch_one(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Look up an authorization code by its hash.
    pub async fn get_authorization_code_by_hash(
        &self,
        code_hash: &TokenHash,
    ) -> Result<Option<AuthorizationCode>, AuthError> {
        sqlx::query_as::<_, AuthorizationCode>(
            "SELECT id, application_id, user_id, code_hash, redirect_uri, scopes, \
             code_challenge, code_challenge_method, nonce, expires_at, used_at, created_at \
             FROM allowthem_authorization_codes WHERE code_hash = ?",
        )
        .bind(code_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Mark an authorization code as used.
    pub async fn mark_authorization_code_used(
        &self,
        id: AuthorizationCodeId,
    ) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result = sqlx::query(
            "UPDATE allowthem_authorization_codes SET used_at = ? WHERE id = ?",
        )
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }
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
