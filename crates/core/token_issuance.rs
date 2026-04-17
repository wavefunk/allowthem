use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::applications::Application;
use crate::authorization::hash_authorization_code;
use crate::db::Db;
use crate::error::AuthError;
use crate::signing_keys::SigningKey;
use crate::types::{
    ApplicationId, AuthorizationCodeId, RefreshTokenId, TokenHash, UserId,
};

// ---------------------------------------------------------------------------
// Token endpoint error type
// ---------------------------------------------------------------------------

/// Token endpoint errors mapping to RFC 6749 Section 5.2 error codes.
///
/// Separate from `AuthError` — these map directly to OAuth2 error codes
/// with specific HTTP status rules. The route handler converts these to
/// JSON error responses.
#[derive(Debug)]
pub enum TokenError {
    InvalidRequest(String),
    InvalidClient(String),
    InvalidGrant(String),
    UnsupportedGrantType,
    ServerError(String),
}

// ---------------------------------------------------------------------------
// Token response
// ---------------------------------------------------------------------------

/// JSON response body for a successful token exchange.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    pub id_token: String,
}

// ---------------------------------------------------------------------------
// Refresh token row type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: RefreshTokenId,
    pub application_id: ApplicationId,
    pub user_id: UserId,
    pub token_hash: TokenHash,
    pub scopes: String,
    pub authorization_code_id: Option<AuthorizationCodeId>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// JWT claims (private — serialization only)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct AccessTokenJwtClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    scope: String,
}

#[derive(Debug, Serialize)]
struct IdTokenJwtClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    at_hash: Option<String>,
    auth_time: i64,
}

// ---------------------------------------------------------------------------
// PKCE verification
// ---------------------------------------------------------------------------

/// Verify code_verifier against stored code_challenge (S256).
///
/// `BASE64URL_NO_PAD(SHA256(code_verifier)) == code_challenge`
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = Base64UrlUnpadded::encode_string(&digest);
    computed == code_challenge
}

// ---------------------------------------------------------------------------
// at_hash computation
// ---------------------------------------------------------------------------

/// Compute at_hash: left 128 bits of SHA-256 of access token, base64url encoded.
///
/// Per OIDC Core Section 3.1.3.6.
pub fn compute_at_hash(access_token_jwt: &str) -> String {
    let digest = Sha256::digest(access_token_jwt.as_bytes());
    Base64UrlUnpadded::encode_string(&digest[..16])
}

// ---------------------------------------------------------------------------
// Token minting
// ---------------------------------------------------------------------------

/// Mint an RS256-signed access token JWT.
///
/// Header: `alg: RS256`, `kid`, `typ: at+jwt` (RFC 9068).
/// Claims: `sub` (UserId), `iss`, `aud` (client_id), `exp`, `iat`, `scope`.
pub fn mint_access_token(
    sub: UserId,
    issuer: &str,
    audience: &str,
    scope: &str,
    kid: &str,
    private_key_pem: &str,
    ttl_secs: i64,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = AccessTokenJwtClaims {
        sub: sub.to_string(),
        iss: issuer.to_owned(),
        aud: audience.to_owned(),
        exp: now + ttl_secs,
        iat: now,
        scope: scope.to_owned(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    header.typ = Some("at+jwt".into());

    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| AuthError::SigningKey(e.to_string()))?;
    encode(&header, &claims, &key).map_err(|e| AuthError::SigningKey(e.to_string()))
}

/// Mint an RS256-signed ID token JWT.
///
/// Header: `alg: RS256`, `kid`, `typ: JWT`.
/// Claims: `sub`, `iss`, `aud`, `exp`, `iat`, `nonce` (optional), `at_hash`, `auth_time`.
pub fn mint_id_token(
    sub: UserId,
    issuer: &str,
    audience: &str,
    nonce: Option<&str>,
    at_hash: &str,
    auth_time: i64,
    kid: &str,
    private_key_pem: &str,
    ttl_secs: i64,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = IdTokenJwtClaims {
        sub: sub.to_string(),
        iss: issuer.to_owned(),
        aud: audience.to_owned(),
        exp: now + ttl_secs,
        iat: now,
        nonce: nonce.map(|s| s.to_owned()),
        at_hash: Some(at_hash.to_owned()),
        auth_time,
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    header.typ = Some("JWT".into());

    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| AuthError::SigningKey(e.to_string()))?;
    encode(&header, &claims, &key).map_err(|e| AuthError::SigningKey(e.to_string()))
}

// ---------------------------------------------------------------------------
// Refresh token generation
// ---------------------------------------------------------------------------

/// Generate a raw refresh token: 32 random bytes, base64url-encoded.
pub fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    Base64UrlUnpadded::encode_string(&bytes)
}

/// Hash a raw refresh token with SHA-256.
pub fn hash_refresh_token(raw: &str) -> TokenHash {
    let digest = Sha256::digest(raw.as_bytes());
    TokenHash::new_unchecked(format!("{digest:x}"))
}

// ---------------------------------------------------------------------------
// Db methods for refresh tokens
// ---------------------------------------------------------------------------

impl Db {
    /// Create a refresh token record. Expires after 30 days.
    pub async fn create_refresh_token(
        &self,
        application_id: ApplicationId,
        user_id: UserId,
        token_hash: &TokenHash,
        scopes: &[String],
        authorization_code_id: Option<AuthorizationCodeId>,
    ) -> Result<RefreshToken, AuthError> {
        let id = RefreshTokenId::new();
        let scopes_json =
            serde_json::to_string(scopes).expect("Vec<String> serializes to JSON");
        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let expires_at = now + chrono::Duration::days(30);
        let expires_str = expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_refresh_tokens \
             (id, application_id, user_id, token_hash, scopes, \
              authorization_code_id, expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(id)
        .bind(application_id)
        .bind(user_id)
        .bind(token_hash)
        .bind(&scopes_json)
        .bind(authorization_code_id)
        .bind(&expires_str)
        .bind(&now_str)
        .execute(self.pool())
        .await?;

        sqlx::query_as::<_, RefreshToken>(
            "SELECT id, application_id, user_id, token_hash, scopes, \
             authorization_code_id, expires_at, revoked_at, created_at \
             FROM allowthem_refresh_tokens WHERE id = ?",
        )
        .bind(id)
        .fetch_one(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Revoke all refresh tokens issued from a specific authorization code.
    ///
    /// Used for code-reuse detection (RFC 6749 Section 10.5).
    pub async fn revoke_refresh_tokens_by_auth_code(
        &self,
        authorization_code_id: AuthorizationCodeId,
    ) -> Result<u64, AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result = sqlx::query(
            "UPDATE allowthem_refresh_tokens \
             SET revoked_at = ? \
             WHERE authorization_code_id = ? AND revoked_at IS NULL",
        )
        .bind(&now)
        .bind(authorization_code_id)
        .execute(self.pool())
        .await?;

        Ok(result.rows_affected())
    }

    /// Look up a refresh token by its SHA-256 hash.
    ///
    /// Returns `Ok(None)` if no token matches. The caller must hash
    /// the raw token before calling this method.
    pub async fn get_refresh_token_by_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<RefreshToken>, AuthError> {
        sqlx::query_as::<_, RefreshToken>(
            "SELECT id, application_id, user_id, token_hash, scopes, \
             authorization_code_id, expires_at, revoked_at, created_at \
             FROM allowthem_refresh_tokens WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Revoke a single refresh token by setting revoked_at to now.
    ///
    /// Used during token rotation: the old refresh token is revoked
    /// before the new one is issued.
    pub async fn revoke_refresh_token(&self, id: RefreshTokenId) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        sqlx::query(
            "UPDATE allowthem_refresh_tokens SET revoked_at = ? WHERE id = ?",
        )
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Exchange orchestration
// ---------------------------------------------------------------------------

/// Exchange an authorization code for tokens.
///
/// Performs all validation (code lookup, used check, expiry, client binding,
/// redirect_uri match, PKCE), then mints access token, ID token, and
/// refresh token.
///
/// The caller is responsible for client authentication (verifying
/// client_id + client_secret) before calling this function.
///
/// The caller provides the `SigningKey` (for `kid`) and decrypted private
/// key PEM (for JWT signing) — obtained via `AllowThem::get_decrypted_signing_key()`.
pub async fn exchange_authorization_code(
    db: &Db,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    application: &Application,
    issuer: &str,
    signing_key: &SigningKey,
    private_key_pem: &str,
) -> Result<TokenResponse, TokenError> {
    // 1. Hash the presented code and look it up
    let code_hash = hash_authorization_code(code);
    let auth_code = db
        .get_authorization_code_by_hash(&code_hash)
        .await
        .map_err(|e| TokenError::ServerError(e.to_string()))?
        .ok_or_else(|| TokenError::InvalidGrant("invalid authorization code".into()))?;

    // 2. Check if already used — triggers revocation
    if auth_code.used_at.is_some() {
        let _ = db
            .revoke_refresh_tokens_by_auth_code(auth_code.id)
            .await;
        return Err(TokenError::InvalidGrant(
            "authorization code already used".into(),
        ));
    }

    // 3. Mark as used immediately (defense-in-depth against replay)
    db.mark_authorization_code_used(auth_code.id)
        .await
        .map_err(|e| TokenError::ServerError(e.to_string()))?;

    // 4. Check expiry
    if auth_code.expires_at < Utc::now() {
        return Err(TokenError::InvalidGrant(
            "authorization code expired".into(),
        ));
    }

    // 5. Check client binding
    if auth_code.application_id != application.id {
        return Err(TokenError::InvalidGrant(
            "code was issued to a different client".into(),
        ));
    }

    // 6. Check redirect_uri match
    if auth_code.redirect_uri != redirect_uri {
        return Err(TokenError::InvalidGrant("redirect_uri mismatch".into()));
    }

    // 7. Verify PKCE
    if !verify_pkce_s256(code_verifier, &auth_code.code_challenge) {
        return Err(TokenError::InvalidGrant(
            "PKCE verification failed".into(),
        ));
    }

    // 8. Parse scopes to space-delimited string
    let scopes: Vec<String> = serde_json::from_str(&auth_code.scopes)
        .map_err(|e| TokenError::ServerError(e.to_string()))?;
    let scopes_str = scopes.join(" ");

    // 9. Mint access token
    let kid = signing_key.id.to_string();
    let access_token = mint_access_token(
        auth_code.user_id,
        issuer,
        application.client_id.as_str(),
        &scopes_str,
        &kid,
        private_key_pem,
        3600,
    )
    .map_err(|e| TokenError::ServerError(e.to_string()))?;

    // 10. Compute at_hash and auth_time
    let at_hash = compute_at_hash(&access_token);
    let auth_time = auth_code.created_at.timestamp();

    // 11. Mint ID token
    let id_token = mint_id_token(
        auth_code.user_id,
        issuer,
        application.client_id.as_str(),
        auth_code.nonce.as_deref(),
        &at_hash,
        auth_time,
        &kid,
        private_key_pem,
        3600,
    )
    .map_err(|e| TokenError::ServerError(e.to_string()))?;

    // 12. Generate and store refresh token
    let raw_refresh = generate_refresh_token();
    let refresh_hash = hash_refresh_token(&raw_refresh);
    db.create_refresh_token(
        application.id,
        auth_code.user_id,
        &refresh_hash,
        &scopes,
        Some(auth_code.id),
    )
    .await
    .map_err(|e| TokenError::ServerError(e.to_string()))?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: raw_refresh,
        id_token,
    })
}

/// Exchange a refresh token for a new access token and rotated refresh token.
///
/// Validates the presented refresh token (hash match, not revoked, not expired,
/// bound to this client), enforces scope subset rules, revokes the old token,
/// and issues a new access token and a new refresh token.
///
/// The caller is responsible for client authentication before calling this
/// function. `requested_scopes` is the parsed `scope` parameter from the
/// request — if `None`, the original scopes from the stored token are used.
pub async fn exchange_refresh_token(
    db: &Db,
    raw_token: &str,
    requested_scopes: Option<&str>,
    application: &Application,
    issuer: &str,
    signing_key: &SigningKey,
    private_key_pem: &str,
) -> Result<TokenResponse, TokenError> {
    // 1. Hash the raw token and look it up
    let hash = hash_refresh_token(raw_token);
    let stored = db
        .get_refresh_token_by_hash(&hash)
        .await
        .map_err(|e| TokenError::ServerError(e.to_string()))?
        .ok_or_else(|| TokenError::InvalidGrant("invalid refresh token".into()))?;

    // 2. Check not revoked
    if stored.revoked_at.is_some() {
        return Err(TokenError::InvalidGrant(
            "refresh token has been revoked".into(),
        ));
    }

    // 3. Check not expired
    if stored.expires_at < Utc::now() {
        return Err(TokenError::InvalidGrant(
            "refresh token has expired".into(),
        ));
    }

    // 4. Check client binding
    if stored.application_id != application.id {
        return Err(TokenError::InvalidGrant(
            "refresh token was issued to a different client".into(),
        ));
    }

    // 5. Resolve effective scopes
    let original_scopes: Vec<String> = serde_json::from_str(&stored.scopes)
        .map_err(|e| TokenError::ServerError(e.to_string()))?;

    let effective_scopes = match requested_scopes {
        Some(s) if !s.is_empty() => {
            let requested: Vec<&str> = s.split_whitespace().collect();
            for scope in &requested {
                if !original_scopes.iter().any(|orig| orig == scope) {
                    return Err(TokenError::InvalidGrant(
                        "requested scope exceeds original grant".into(),
                    ));
                }
            }
            requested.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        }
        _ => original_scopes.clone(),
    };

    let scopes_str = effective_scopes.join(" ");

    // 6. Revoke old token before issuing new ones
    db.revoke_refresh_token(stored.id)
        .await
        .map_err(|e| TokenError::ServerError(e.to_string()))?;

    // 7. Mint access token
    let kid = signing_key.id.to_string();
    let access_token = mint_access_token(
        stored.user_id,
        issuer,
        application.client_id.as_str(),
        &scopes_str,
        &kid,
        private_key_pem,
        3600,
    )
    .map_err(|e| TokenError::ServerError(e.to_string()))?;

    // 8. Compute at_hash and mint ID token
    let at_hash = compute_at_hash(&access_token);
    let auth_time = stored.created_at.timestamp();
    let id_token = mint_id_token(
        stored.user_id,
        issuer,
        application.client_id.as_str(),
        None,
        &at_hash,
        auth_time,
        &kid,
        private_key_pem,
        3600,
    )
    .map_err(|e| TokenError::ServerError(e.to_string()))?;

    // 9. Generate and store new refresh token (rotation)
    let new_raw = generate_refresh_token();
    let new_hash = hash_refresh_token(&new_raw);
    db.create_refresh_token(
        application.id,
        stored.user_id,
        &new_hash,
        &effective_scopes,
        stored.authorization_code_id,
    )
    .await
    .map_err(|e| TokenError::ServerError(e.to_string()))?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: new_raw,
        id_token,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_keys::decrypt_private_key;
    use crate::types::Email;
    use jsonwebtoken::Algorithm;
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;

    const ENC_KEY: [u8; 32] = [0x42; 32];
    const ISSUER: &str = "https://auth.example.com";

    async fn test_db() -> Db {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = SqlitePool::connect_with(opts).await.unwrap();
        Db::new(pool).await.unwrap()
    }

    // PKCE tests

    #[test]
    fn verify_pkce_s256_valid() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = Base64UrlUnpadded::encode_string(&digest);
        assert!(verify_pkce_s256(verifier, &challenge));
    }

    #[test]
    fn verify_pkce_s256_wrong_verifier() {
        let verifier = "correct_verifier";
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = Base64UrlUnpadded::encode_string(&digest);
        assert!(!verify_pkce_s256("wrong_verifier", &challenge));
    }

    #[test]
    fn verify_pkce_s256_empty_verifier() {
        let verifier = "actual_verifier";
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = Base64UrlUnpadded::encode_string(&digest);
        assert!(!verify_pkce_s256("", &challenge));
    }

    // at_hash tests

    #[test]
    fn compute_at_hash_deterministic() {
        let input = "eyJhbGciOiJSUzI1NiJ9.test.sig";
        let h1 = compute_at_hash(input);
        let h2 = compute_at_hash(input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_at_hash_known_value() {
        // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        // First 16 bytes = 9f86d081884c7d659a2feaa0c55ad015
        // base64url of those bytes
        let hash = compute_at_hash("test");
        let digest = Sha256::digest(b"test");
        let expected = Base64UrlUnpadded::encode_string(&digest[..16]);
        assert_eq!(hash, expected);
    }

    // Refresh token tests

    #[test]
    fn refresh_token_is_43_chars() {
        let token = generate_refresh_token();
        assert_eq!(token.len(), 43, "32 bytes base64url = 43 chars");
    }

    #[test]
    fn refresh_token_is_url_safe() {
        let token = generate_refresh_token();
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "token must be URL-safe: got {token}"
        );
    }

    #[test]
    fn hash_refresh_token_deterministic() {
        let token = generate_refresh_token();
        let h1 = hash_refresh_token(&token);
        let h2 = hash_refresh_token(&token);
        assert_eq!(format!("{h1:?}"), format!("{h2:?}"));
    }

    // Minting tests (require signing key from DB)

    #[tokio::test]
    async fn mint_access_token_roundtrip() {
        let db = test_db().await;
        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        db.activate_signing_key(key.id).await.unwrap();
        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();
        let kid = key.id.to_string();

        let user_id = UserId::new();
        let token = mint_access_token(
            user_id,
            ISSUER,
            "ath_test_client",
            "openid profile",
            &kid,
            &pem,
            3600,
        )
        .unwrap();

        // Validate using the existing access_tokens module
        let claims = db.validate_access_token(&token, ISSUER).await.unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.scope, "openid profile");
        assert_eq!(claims.iss, ISSUER);
    }

    #[tokio::test]
    async fn mint_id_token_contains_nonce() {
        let db = test_db().await;
        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();
        let kid = key.id.to_string();

        let user_id = UserId::new();
        let token = mint_id_token(
            user_id,
            ISSUER,
            "ath_test_client",
            Some("test_nonce_123"),
            "test_at_hash",
            1234567890,
            &kid,
            &pem,
            3600,
        )
        .unwrap();

        // Decode without verification to inspect claims
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let payload = base64ct::Base64UrlUnpadded::decode_vec(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["nonce"], "test_nonce_123");
        assert_eq!(claims["at_hash"], "test_at_hash");
        assert_eq!(claims["auth_time"], 1234567890);
    }

    #[tokio::test]
    async fn mint_id_token_omits_nonce_when_none() {
        let db = test_db().await;
        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();
        let kid = key.id.to_string();

        let user_id = UserId::new();
        let token = mint_id_token(
            user_id, ISSUER, "ath_test_client", None, "hash", 0, &kid, &pem, 3600,
        )
        .unwrap();

        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let payload = base64ct::Base64UrlUnpadded::decode_vec(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(claims.get("nonce").is_none());
    }

    // Exchange orchestration tests

    /// Helper: create user, application, signing key, authorization code
    async fn setup_exchange(
        db: &Db,
    ) -> (Application, SigningKey, String, String, String, String) {
        let email = Email::new("exchange@example.com".into()).unwrap();
        let user = db.create_user(email, "password123", None).await.unwrap();

        let (app, _secret) = db
            .create_application(
                "ExchangeApp".to_string(),
                vec!["https://example.com/callback".to_string()],
                false,
                Some(user.id),
                None,
                None,
            )
            .await
            .unwrap();

        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        db.activate_signing_key(key.id).await.unwrap();
        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();

        // Create a PKCE challenge from a known verifier
        let code_verifier = "test_verifier_string_with_enough_entropy_1234567890";
        let digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = Base64UrlUnpadded::encode_string(&digest);

        let raw_code = crate::authorization::generate_authorization_code();
        let code_hash = hash_authorization_code(&raw_code);
        db.create_authorization_code(
            app.id,
            user.id,
            &code_hash,
            "https://example.com/callback",
            &["openid".to_string(), "profile".to_string()],
            &code_challenge,
            "S256",
            Some("test_nonce"),
        )
        .await
        .unwrap();

        (
            app,
            key,
            pem,
            raw_code,
            code_verifier.to_string(),
            "https://example.com/callback".to_string(),
        )
    }

    #[tokio::test]
    async fn exchange_valid_code() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let resp = exchange_authorization_code(
            &db,
            &raw_code,
            &redirect_uri,
            &verifier,
            &app,
            ISSUER,
            &key,
            &pem,
        )
        .await
        .unwrap();

        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert!(!resp.access_token.is_empty());
        assert!(!resp.refresh_token.is_empty());
        assert!(!resp.id_token.is_empty());

        // Validate the access token
        let claims = db
            .validate_access_token(&resp.access_token, ISSUER)
            .await
            .unwrap();
        assert_eq!(claims.scope, "openid profile");
    }

    #[tokio::test]
    async fn exchange_used_code_triggers_revocation() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        // First exchange succeeds
        let _resp = exchange_authorization_code(
            &db,
            &raw_code,
            &redirect_uri,
            &verifier,
            &app,
            ISSUER,
            &key,
            &pem,
        )
        .await
        .unwrap();

        // Second exchange with same code fails
        let err = exchange_authorization_code(
            &db,
            &raw_code,
            &redirect_uri,
            &verifier,
            &app,
            ISSUER,
            &key,
            &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("already used")));
    }

    #[tokio::test]
    async fn exchange_wrong_redirect_uri() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, _) = setup_exchange(&db).await;

        let err = exchange_authorization_code(
            &db,
            &raw_code,
            "https://evil.example.com/callback",
            &verifier,
            &app,
            ISSUER,
            &key,
            &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("redirect_uri")));
    }

    #[tokio::test]
    async fn exchange_bad_pkce() {
        let db = test_db().await;
        let (app, key, pem, raw_code, _, redirect_uri) = setup_exchange(&db).await;

        let err = exchange_authorization_code(
            &db,
            &raw_code,
            &redirect_uri,
            "wrong_verifier",
            &app,
            ISSUER,
            &key,
            &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("PKCE")));
    }

    #[tokio::test]
    async fn exchange_invalid_code() {
        let db = test_db().await;
        let (app, key, pem, _, verifier, redirect_uri) = setup_exchange(&db).await;

        let err = exchange_authorization_code(
            &db,
            "nonexistent_code",
            &redirect_uri,
            &verifier,
            &app,
            ISSUER,
            &key,
            &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("invalid")));
    }

    #[tokio::test]
    async fn exchange_expired_code() {
        let db = test_db().await;
        let email = Email::new("expired@example.com".into()).unwrap();
        let user = db.create_user(email, "password123", None).await.unwrap();

        let (app, _) = db
            .create_application(
                "ExpiredApp".to_string(),
                vec!["https://example.com/callback".to_string()],
                false, Some(user.id), None, None,
            )
            .await
            .unwrap();

        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        db.activate_signing_key(key.id).await.unwrap();
        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();

        let code_verifier = "test_verifier_expired";
        let digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = Base64UrlUnpadded::encode_string(&digest);

        let raw_code = crate::authorization::generate_authorization_code();
        let code_hash = hash_authorization_code(&raw_code);
        db.create_authorization_code(
            app.id, user.id, &code_hash, "https://example.com/callback",
            &["openid".to_string()], &code_challenge, "S256", None,
        ).await.unwrap();

        // Expire the code
        sqlx::query(
            "UPDATE allowthem_authorization_codes SET expires_at = '2020-01-01T00:00:00.000Z' WHERE code_hash = ?",
        )
        .bind(&code_hash)
        .execute(db.pool())
        .await
        .unwrap();

        let err = exchange_authorization_code(
            &db, &raw_code, "https://example.com/callback", code_verifier,
            &app, ISSUER, &key, &pem,
        ).await.unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("expired")));
    }

    #[tokio::test]
    async fn exchange_wrong_client() {
        let db = test_db().await;
        let (_, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let email_b = Email::new("other@example.com".into()).unwrap();
        let user_b = db.create_user(email_b, "password123", None).await.unwrap();
        let (app_b, _) = db
            .create_application(
                "OtherApp".to_string(),
                vec!["https://other.example.com/callback".to_string()],
                false, Some(user_b.id), None, None,
            )
            .await
            .unwrap();

        let err = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app_b, ISSUER, &key, &pem,
        ).await.unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("different client")));
    }

    #[tokio::test]
    async fn access_token_has_correct_typ_header() {
        let db = test_db().await;
        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();

        let token = mint_access_token(
            UserId::new(), ISSUER, "client", "openid", &key.id.to_string(), &pem, 3600,
        ).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(header.alg, Algorithm::RS256);
        assert!(header.kid.is_some());
    }

    #[tokio::test]
    async fn id_token_has_correct_typ_header() {
        let db = test_db().await;
        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();

        let token = mint_id_token(
            UserId::new(), ISSUER, "client", None, "hash", 0, &key.id.to_string(), &pem, 3600,
        ).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        assert_eq!(header.alg, Algorithm::RS256);
    }

    #[tokio::test]
    async fn exchange_id_token_at_hash_matches_access_token() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let resp = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        ).await.unwrap();

        let parts: Vec<&str> = resp.id_token.splitn(3, '.').collect();
        let payload = base64ct::Base64UrlUnpadded::decode_vec(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        let expected = compute_at_hash(&resp.access_token);
        assert_eq!(claims["at_hash"].as_str().unwrap(), expected);
    }

    #[tokio::test]
    async fn exchange_creates_refresh_token_in_db() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let resp = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        ).await.unwrap();

        let refresh_hash = hash_refresh_token(&resp.refresh_token);
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM allowthem_refresh_tokens WHERE token_hash = ?",
        )
        .bind(&refresh_hash)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(count.0, 1, "refresh token should be stored in DB");
    }

    // Db method tests for refresh token lookup and revocation (M42)

    #[tokio::test]
    async fn get_refresh_token_by_hash_returns_token() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let resp = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let hash = hash_refresh_token(&resp.refresh_token);
        let stored = db.get_refresh_token_by_hash(&hash).await.unwrap().unwrap();
        assert_eq!(stored.application_id, app.id);
        assert_eq!(stored.revoked_at, None);
    }

    #[tokio::test]
    async fn get_refresh_token_by_hash_returns_none_for_unknown() {
        let db = test_db().await;
        let unknown = hash_refresh_token("nonexistent_raw_token");
        let result = db.get_refresh_token_by_hash(&unknown).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn revoke_refresh_token_sets_revoked_at() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let resp = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let hash = hash_refresh_token(&resp.refresh_token);
        let stored = db.get_refresh_token_by_hash(&hash).await.unwrap().unwrap();
        assert!(stored.revoked_at.is_none());

        db.revoke_refresh_token(stored.id).await.unwrap();

        let after = db.get_refresh_token_by_hash(&hash).await.unwrap().unwrap();
        assert!(after.revoked_at.is_some());
    }

    #[tokio::test]
    async fn revoke_refresh_token_idempotent() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let resp = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let hash = hash_refresh_token(&resp.refresh_token);
        let stored = db.get_refresh_token_by_hash(&hash).await.unwrap().unwrap();

        db.revoke_refresh_token(stored.id).await.unwrap();
        db.revoke_refresh_token(stored.id).await.unwrap();
    }

    // exchange_refresh_token integration tests (M42)

    #[tokio::test]
    async fn exchange_refresh_token_valid() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let resp = exchange_refresh_token(
            &db, &initial.refresh_token, None, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        assert!(!resp.access_token.is_empty());
        assert!(!resp.refresh_token.is_empty());
        assert_ne!(resp.refresh_token, initial.refresh_token);
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);

        let claims = db.validate_access_token(&resp.access_token, ISSUER).await.unwrap();
        assert_eq!(claims.scope, "openid profile");
    }

    #[tokio::test]
    async fn exchange_refresh_token_revokes_old_token() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let old_hash = hash_refresh_token(&initial.refresh_token);
        exchange_refresh_token(
            &db, &initial.refresh_token, None, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let old_stored = db.get_refresh_token_by_hash(&old_hash).await.unwrap().unwrap();
        assert!(old_stored.revoked_at.is_some(), "old token should be revoked");
    }

    #[tokio::test]
    async fn exchange_refresh_token_revoked_token_fails() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        // First exchange succeeds, revoking the token
        exchange_refresh_token(
            &db, &initial.refresh_token, None, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        // Second exchange with the same (now revoked) token fails
        let err = exchange_refresh_token(
            &db, &initial.refresh_token, None, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("revoked")));
    }

    #[tokio::test]
    async fn exchange_refresh_token_expired_fails() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let hash = hash_refresh_token(&initial.refresh_token);
        sqlx::query(
            "UPDATE allowthem_refresh_tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE token_hash = ?",
        )
        .bind(&hash)
        .execute(db.pool())
        .await
        .unwrap();

        let err = exchange_refresh_token(
            &db, &initial.refresh_token, None, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("expired")));
    }

    #[tokio::test]
    async fn exchange_refresh_token_wrong_client_fails() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let email_b = Email::new("other_refresh@example.com".into()).unwrap();
        let user_b = db.create_user(email_b, "password123", None).await.unwrap();
        let (app_b, _) = db
            .create_application(
                "OtherRefreshApp".to_string(),
                vec!["https://other.example.com/callback".to_string()],
                false,
                Some(user_b.id),
                None,
                None,
            )
            .await
            .unwrap();

        let err = exchange_refresh_token(
            &db, &initial.refresh_token, None, &app_b, ISSUER, &key, &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("different client")));
    }

    #[tokio::test]
    async fn exchange_refresh_token_scope_subset_succeeds() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let resp = exchange_refresh_token(
            &db, &initial.refresh_token, Some("openid"), &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let claims = db.validate_access_token(&resp.access_token, ISSUER).await.unwrap();
        assert_eq!(claims.scope, "openid");
    }

    #[tokio::test]
    async fn exchange_refresh_token_scope_escalation_fails() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let err = exchange_refresh_token(
            &db, &initial.refresh_token, Some("openid admin"), &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("exceeds")));
    }

    #[tokio::test]
    async fn exchange_refresh_token_no_scope_uses_original() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;

        let initial = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let resp = exchange_refresh_token(
            &db, &initial.refresh_token, None, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let claims = db.validate_access_token(&resp.access_token, ISSUER).await.unwrap();
        assert_eq!(claims.scope, "openid profile");
    }

    #[tokio::test]
    async fn exchange_refresh_token_invalid_hash_fails() {
        let db = test_db().await;
        let (app, key, pem, raw_code, verifier, redirect_uri) = setup_exchange(&db).await;
        let _ = exchange_authorization_code(
            &db, &raw_code, &redirect_uri, &verifier, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap();

        let err = exchange_refresh_token(
            &db, "totally_invalid_garbage_token", None, &app, ISSUER, &key, &pem,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant(ref msg) if msg.contains("invalid")));
    }
}
