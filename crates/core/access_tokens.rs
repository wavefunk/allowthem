use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::Db;
use crate::error::{AccessTokenError, AuthError};
use crate::types::UserId;

/// Validated claims extracted from an RS256-signed access token.
///
/// The `sub` value is `User.id.to_string()` and MUST remain identical
/// to the `sub` claim in ID tokens issued by the token endpoint (M41).
/// OIDC Core Section 5.3.4 requires this consistency.
#[derive(Debug, Clone)]
pub struct AccessTokenClaims {
    pub sub: UserId,
    pub scope: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

/// Raw claims for `jsonwebtoken::decode()`. Private — callers use `AccessTokenClaims`.
#[derive(Debug, Deserialize)]
struct RawAccessTokenClaims {
    sub: String,
    scope: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    permissions: Vec<String>,
}

/// Check if a space-delimited scope string contains a specific scope.
///
/// This utility may move to `authorization.rs` when that module exists (M39).
pub fn has_scope(scope_string: &str, target: &str) -> bool {
    scope_string.split(' ').any(|s| s == target)
}

impl Db {
    /// Validate an RS256-signed access token JWT.
    ///
    /// Steps:
    /// 1. Decode the JWT header to extract `kid`.
    /// 2. Look up the signing key by `kid` in the database.
    /// 3. Verify the RS256 signature using the public key PEM.
    /// 4. Check `exp` against the current time.
    /// 5. Verify `iss` matches `expected_issuer`.
    /// 6. Parse `sub` as `UserId` and return `AccessTokenClaims`.
    pub async fn validate_access_token(
        &self,
        token: &str,
        expected_issuer: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        // Step 1: decode header to extract kid
        let header = decode_header(token)
            .map_err(|e| AuthError::AccessToken(AccessTokenError::MalformedToken(e.to_string())))?;

        // Step 2: extract kid
        let kid_str = header.kid.ok_or_else(|| {
            AuthError::AccessToken(AccessTokenError::MalformedToken("missing kid".into()))
        })?;

        // Step 3: parse kid as UUID then SigningKeyId
        let kid_uuid = Uuid::parse_str(&kid_str)
            .map_err(|_| AuthError::AccessToken(AccessTokenError::UnknownKid(kid_str.clone())))?;
        let kid_id = crate::types::SigningKeyId::from_uuid(kid_uuid);

        // Step 4: fetch signing key
        let key = self.get_signing_key(kid_id).await.map_err(|e| match e {
            AuthError::NotFound => AuthError::AccessToken(AccessTokenError::UnknownKid(kid_str)),
            other => other,
        })?;

        // Step 5: build decoding key from public PEM
        let decoding_key = DecodingKey::from_rsa_pem(key.public_key_pem.as_bytes())
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;

        // Step 6: build validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[expected_issuer]);
        validation.validate_aud = false;
        validation.leeway = 0;

        // Step 7: decode and verify
        let token_data = decode::<RawAccessTokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                let err = match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AccessTokenError::Expired,
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        AccessTokenError::InvalidSignature
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                        AccessTokenError::InvalidClaims("invalid issuer".into())
                    }
                    _ => AccessTokenError::InvalidClaims(e.to_string()),
                };
                AuthError::AccessToken(err)
            })?;

        let raw = token_data.claims;

        // Step 8: parse sub as UUID
        let sub_uuid = Uuid::parse_str(&raw.sub).map_err(|_| {
            AuthError::AccessToken(AccessTokenError::InvalidClaims("invalid sub".into()))
        })?;

        Ok(AccessTokenClaims {
            sub: UserId::from_uuid(sub_uuid),
            scope: raw.scope,
            iss: raw.iss,
            aud: raw.aud,
            exp: raw.exp,
            iat: raw.iat,
            email: raw.email,
            email_verified: raw.email_verified,
            username: raw.username,
            roles: raw.roles,
            permissions: raw.permissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_keys::decrypt_private_key;
    use base64ct::{Base64UrlUnpadded as _, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;
    use uuid::Uuid;

    const ENC_KEY: [u8; 32] = [0x42; 32];
    const ISSUER: &str = "https://auth.example.com";

    async fn test_db() -> Db {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = SqlitePool::connect_with(opts).await.unwrap();
        Db::new(pool).await.unwrap()
    }

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        scope: String,
        iss: String,
        aud: String,
        exp: i64,
        iat: i64,
        email: String,
        email_verified: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
    }

    /// Create a signing key in the DB and return the signed JWT string.
    async fn sign_test_jwt(
        db: &Db,
        sub: &str,
        scope: &str,
        issuer: &str,
        exp_offset_secs: i64,
    ) -> (String, crate::types::SigningKeyId) {
        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        db.activate_signing_key(key.id).await.unwrap();

        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();

        let now = chrono::Utc::now().timestamp();
        let claims = TestClaims {
            sub: sub.to_string(),
            scope: scope.to_string(),
            iss: issuer.to_string(),
            aud: "ath_test_client".to_string(),
            exp: now + exp_offset_secs,
            iat: now,
            email: "test@example.com".to_string(),
            email_verified: true,
            username: Some("testuser".to_string()),
            roles: vec!["admin".to_string()],
            permissions: vec!["posts:write".to_string()],
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key.id.to_string());

        let token = encode(&header, &claims, &encoding_key).unwrap();
        (token, key.id)
    }

    #[tokio::test]
    async fn validate_access_token_valid() {
        let db = test_db().await;
        let sub = UserId::new().to_string();
        let (token, _) = sign_test_jwt(&db, &sub, "openid profile", ISSUER, 300).await;

        let claims = db.validate_access_token(&token, ISSUER).await.unwrap();
        assert_eq!(claims.sub.to_string(), sub);
        assert_eq!(claims.scope, "openid profile");
        assert_eq!(claims.iss, ISSUER);
    }

    #[tokio::test]
    async fn validate_access_token_expired() {
        let db = test_db().await;
        let sub = UserId::new().to_string();
        let (token, _) = sign_test_jwt(&db, &sub, "openid", ISSUER, -60).await;

        let err = db.validate_access_token(&token, ISSUER).await.unwrap_err();
        assert!(matches!(
            err,
            AuthError::AccessToken(AccessTokenError::Expired)
        ));
    }

    #[tokio::test]
    async fn validate_access_token_wrong_issuer() {
        let db = test_db().await;
        let sub = UserId::new().to_string();
        let (token, _) = sign_test_jwt(&db, &sub, "openid", "https://wrong.example.com", 300).await;

        let err = db.validate_access_token(&token, ISSUER).await.unwrap_err();
        assert!(matches!(
            err,
            AuthError::AccessToken(AccessTokenError::InvalidClaims(_))
        ));
        if let AuthError::AccessToken(AccessTokenError::InvalidClaims(msg)) = err {
            assert!(msg.contains("issuer"));
        }
    }

    #[tokio::test]
    async fn validate_access_token_unknown_kid() {
        let db = test_db().await;
        let sub = UserId::new().to_string();
        let (token, _) = sign_test_jwt(&db, &sub, "openid", ISSUER, 300).await;

        // Tamper: reconstruct token with a random kid not in DB
        let random_kid = Uuid::new_v4().to_string();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let fake_header = base64ct::Base64UrlUnpadded::encode_string(
            format!(r#"{{"alg":"RS256","kid":"{random_kid}","typ":"JWT"}}"#).as_bytes(),
        );
        let tampered = format!("{}.{}.{}", fake_header, parts[1], parts[2]);

        let err = db
            .validate_access_token(&tampered, ISSUER)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AuthError::AccessToken(AccessTokenError::UnknownKid(_))
        ));
    }

    #[tokio::test]
    async fn validate_access_token_bad_signature() {
        let db = test_db().await;
        let sub = UserId::new().to_string();

        // Sign with key1's private key
        let key1 = db.create_signing_key(&ENC_KEY).await.unwrap();
        db.activate_signing_key(key1.id).await.unwrap();

        // Create key2 (different key pair) — sign payload with key2's private key
        let key2 = db.create_signing_key(&ENC_KEY).await.unwrap();
        db.activate_signing_key(key2.id).await.unwrap();

        let pem2 = decrypt_private_key(&key2, &ENC_KEY).unwrap();
        let encoding_key2 = EncodingKey::from_rsa_pem(pem2.as_bytes()).unwrap();

        let now = chrono::Utc::now().timestamp();
        let claims = TestClaims {
            sub: sub.clone(),
            scope: "openid".to_string(),
            iss: ISSUER.to_string(),
            aud: "ath_test_client".to_string(),
            exp: now + 300,
            iat: now,
            email: "test@example.com".to_string(),
            email_verified: true,
            username: None,
            roles: vec![],
            permissions: vec![],
        };

        // Set kid to key1's id but sign with key2's private key
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key1.id.to_string());
        let token = encode(&header, &claims, &encoding_key2).unwrap();

        let err = db.validate_access_token(&token, ISSUER).await.unwrap_err();
        assert!(matches!(
            err,
            AuthError::AccessToken(AccessTokenError::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn validate_access_token_missing_kid() {
        let db = test_db().await;
        let sub = UserId::new().to_string();
        let key = db.create_signing_key(&ENC_KEY).await.unwrap();
        db.activate_signing_key(key.id).await.unwrap();

        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();

        let now = chrono::Utc::now().timestamp();
        let claims = TestClaims {
            sub: sub.clone(),
            scope: "openid".to_string(),
            iss: ISSUER.to_string(),
            aud: "ath_test_client".to_string(),
            exp: now + 300,
            iat: now,
            email: "test@example.com".to_string(),
            email_verified: true,
            username: None,
            roles: vec![],
            permissions: vec![],
        };

        // No kid in header
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let err = db.validate_access_token(&token, ISSUER).await.unwrap_err();
        assert!(matches!(
            err,
            AuthError::AccessToken(AccessTokenError::MalformedToken(_))
        ));
    }

    #[tokio::test]
    async fn has_scope_present() {
        assert!(has_scope("openid profile email", "profile"));
    }

    #[tokio::test]
    async fn has_scope_absent() {
        assert!(!has_scope("openid profile", "email"));
    }

    #[tokio::test]
    async fn has_scope_no_partial_match() {
        assert!(!has_scope("openid profile_extended", "profile"));
    }
}
