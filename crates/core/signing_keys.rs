//! RS256 signing key management — key generation, encrypted storage, JWKS, and OIDC discovery.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::{OsRng, RngCore};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;

use crate::db::Db;
use crate::error::AuthError;
use crate::types::SigningKeyId;

/// An RS256 signing key pair stored in the database.
///
/// The private key is AES-256-GCM encrypted at rest. Call `decrypt_private_key`
/// to recover the PKCS#8 PEM for signing.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SigningKey {
    pub id: SigningKeyId,
    pub private_key_enc: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub public_key_pem: String,
    pub algorithm: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Decrypt a signing key's private key PEM from its encrypted storage.
///
/// Uses AES-256-GCM with the stored nonce. Returns the PKCS#8 PEM string.
/// This is a free function — decryption is pure computation, not a `Db` method.
pub fn decrypt_private_key(
    key: &SigningKey,
    encryption_key: &[u8; 32],
) -> Result<String, AuthError> {
    let cipher = Aes256Gcm::new(encryption_key.into());
    let nonce = Nonce::from_slice(&key.private_key_nonce);
    let plaintext = cipher
        .decrypt(nonce, key.private_key_enc.as_slice())
        .map_err(|e| AuthError::SigningKey(e.to_string()))?;
    String::from_utf8(plaintext).map_err(|e| AuthError::SigningKey(e.to_string()))
}

impl Db {
    /// Generate an RS256 key pair, encrypt the private key, and store both in the database.
    ///
    /// The new key is NOT automatically marked active — call `activate_signing_key` separately.
    pub async fn create_signing_key(
        &self,
        encryption_key: &[u8; 32],
    ) -> Result<SigningKey, AuthError> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;
        let pem_bytes = private_pem.as_bytes();

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new(encryption_key.into());
        let private_key_enc = cipher
            .encrypt(nonce, pem_bytes)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;

        let public_key_pem = RsaPublicKey::from(&private_key)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;

        let id = SigningKeyId::new();

        sqlx::query(
            "INSERT INTO allowthem_signing_keys \
             (id, private_key_enc, private_key_nonce, public_key_pem, algorithm, is_active) \
             VALUES (?, ?, ?, ?, 'RS256', 0)",
        )
        .bind(id)
        .bind(&private_key_enc)
        .bind(nonce_bytes.as_slice())
        .bind(&public_key_pem)
        .execute(self.pool())
        .await?;

        let key = SigningKey {
            id,
            private_key_enc,
            private_key_nonce: nonce_bytes.to_vec(),
            public_key_pem,
            algorithm: "RS256".to_string(),
            is_active: false,
            created_at: Utc::now(),
        };

        Ok(key)
    }

    /// Mark a key as the active signing key. Deactivates all other keys in a single transaction.
    ///
    /// Returns `AuthError::NotFound` if the key ID does not exist.
    pub async fn activate_signing_key(&self, key_id: SigningKeyId) -> Result<(), AuthError> {
        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        sqlx::query("UPDATE allowthem_signing_keys SET is_active = 0 WHERE is_active = 1")
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        let result = sqlx::query("UPDATE allowthem_signing_keys SET is_active = 1 WHERE id = ?")
            .bind(key_id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        if result.rows_affected() == 0 {
            tx.rollback().await.map_err(AuthError::Database)?;
            return Err(AuthError::NotFound);
        }

        tx.commit().await.map_err(AuthError::Database)?;
        Ok(())
    }

    /// Generate a new key and activate it, deactivating the current active key.
    ///
    /// Combines creation and activation in a single transaction.
    pub async fn rotate_signing_key(
        &self,
        encryption_key: &[u8; 32],
    ) -> Result<SigningKey, AuthError> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;
        let pem_bytes = private_pem.as_bytes();

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new(encryption_key.into());
        let private_key_enc = cipher
            .encrypt(nonce, pem_bytes)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;

        let public_key_pem = RsaPublicKey::from(&private_key)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;

        let id = SigningKeyId::new();

        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        sqlx::query(
            "INSERT INTO allowthem_signing_keys \
             (id, private_key_enc, private_key_nonce, public_key_pem, algorithm, is_active) \
             VALUES (?, ?, ?, ?, 'RS256', 0)",
        )
        .bind(id)
        .bind(&private_key_enc)
        .bind(nonce_bytes.as_slice())
        .bind(&public_key_pem)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        sqlx::query("UPDATE allowthem_signing_keys SET is_active = 0 WHERE is_active = 1")
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        sqlx::query("UPDATE allowthem_signing_keys SET is_active = 1 WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        tx.commit().await.map_err(AuthError::Database)?;

        let key = SigningKey {
            id,
            private_key_enc,
            private_key_nonce: nonce_bytes.to_vec(),
            public_key_pem,
            algorithm: "RS256".to_string(),
            is_active: true,
            created_at: Utc::now(),
        };

        Ok(key)
    }

    /// Get the currently active signing key.
    ///
    /// Returns `AuthError::NotFound` if no key is active.
    pub async fn get_active_signing_key(&self) -> Result<SigningKey, AuthError> {
        sqlx::query_as(
            "SELECT id, private_key_enc, private_key_nonce, public_key_pem, \
             algorithm, is_active, created_at \
             FROM allowthem_signing_keys WHERE is_active = 1 LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }

    /// Get all signing keys ordered by creation date descending.
    ///
    /// Used by the JWKS endpoint to serve all public keys (active + rotated-out).
    pub async fn get_all_signing_keys(&self) -> Result<Vec<SigningKey>, AuthError> {
        Ok(sqlx::query_as(
            "SELECT id, private_key_enc, private_key_nonce, public_key_pem, \
             algorithm, is_active, created_at \
             FROM allowthem_signing_keys ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await?)
    }

    /// Get a specific signing key by ID.
    ///
    /// Returns `AuthError::NotFound` if no key matches the ID.
    pub async fn get_signing_key(&self, id: SigningKeyId) -> Result<SigningKey, AuthError> {
        sqlx::query_as(
            "SELECT id, private_key_enc, private_key_nonce, public_key_pem, \
             algorithm, is_active, created_at \
             FROM allowthem_signing_keys WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }
}

/// A single JWK entry for the JWKS endpoint.
#[derive(Debug, Serialize)]
pub struct JwkEntry {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub n: String,
    pub e: String,
}

/// The full JWKS document.
#[derive(Debug, Serialize)]
pub struct JwkSet {
    pub keys: Vec<JwkEntry>,
}

/// Build a JWKS document from all signing keys.
///
/// Parses each key's public PEM to extract the RSA modulus and exponent,
/// base64url-encoding them per RFC 7518 Section 6.3.1.
pub fn build_jwks(keys: &[SigningKey]) -> Result<JwkSet, AuthError> {
    let mut entries = Vec::with_capacity(keys.len());
    for key in keys {
        let pub_key = RsaPublicKey::from_public_key_pem(&key.public_key_pem)
            .map_err(|e| AuthError::SigningKey(e.to_string()))?;
        let n = Base64UrlUnpadded::encode_string(&pub_key.n().to_bytes_be());
        let e = Base64UrlUnpadded::encode_string(&pub_key.e().to_bytes_be());
        entries.push(JwkEntry {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: key.id.to_string(),
            n,
            e,
        });
    }
    Ok(JwkSet { keys: entries })
}

/// OpenID Connect discovery metadata.
///
/// See: <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>
#[derive(Debug, Serialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub scopes_supported: Vec<&'static str>,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
}

/// Build the OIDC discovery document for the given issuer URL.
pub fn build_discovery(issuer: &str) -> OidcDiscovery {
    OidcDiscovery {
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        issuer: issuer.to_string(),
        scopes_supported: vec!["openid", "profile", "email"],
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        token_endpoint_auth_methods_supported: vec!["client_secret_post", "client_secret_basic"],
        code_challenge_methods_supported: vec!["S256"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;

    const ENC_KEY_A: [u8; 32] = [0x42; 32];
    const ENC_KEY_B: [u8; 32] = [0x99; 32];

    async fn test_db() -> Db {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = SqlitePool::connect_with(opts).await.unwrap();
        Db::new(pool).await.unwrap()
    }

    #[test]
    fn decrypt_round_trip() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let pem_bytes = pem.as_bytes();

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new((&ENC_KEY_A).into());
        let ciphertext = cipher.encrypt(nonce, pem_bytes).unwrap();

        let public_key_pem = RsaPublicKey::from(&private_key)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let key = SigningKey {
            id: SigningKeyId::new(),
            private_key_enc: ciphertext,
            private_key_nonce: nonce_bytes.to_vec(),
            public_key_pem,
            algorithm: "RS256".to_string(),
            is_active: false,
            created_at: Utc::now(),
        };

        let decrypted = decrypt_private_key(&key, &ENC_KEY_A).unwrap();
        assert_eq!(decrypted.as_bytes(), pem_bytes);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let pem_bytes = pem.as_bytes();

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new((&ENC_KEY_A).into());
        let ciphertext = cipher.encrypt(nonce, pem_bytes).unwrap();

        let public_key_pem = RsaPublicKey::from(&private_key)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let key = SigningKey {
            id: SigningKeyId::new(),
            private_key_enc: ciphertext,
            private_key_nonce: nonce_bytes.to_vec(),
            public_key_pem,
            algorithm: "RS256".to_string(),
            is_active: false,
            created_at: Utc::now(),
        };

        let result = decrypt_private_key(&key, &ENC_KEY_B);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[tokio::test]
    async fn create_signing_key_stores_row() {
        let db = test_db().await;
        let key = db.create_signing_key(&ENC_KEY_A).await.unwrap();
        assert!(!key.is_active, "new key must not be active");

        let fetched = db.get_signing_key(key.id).await.unwrap();
        assert_eq!(fetched.id, key.id);
        assert_eq!(fetched.algorithm, "RS256");
        assert!(!fetched.is_active);
    }

    #[tokio::test]
    async fn activate_signing_key_marks_active() {
        let db = test_db().await;
        let key1 = db.create_signing_key(&ENC_KEY_A).await.unwrap();
        let key2 = db.create_signing_key(&ENC_KEY_A).await.unwrap();

        db.activate_signing_key(key2.id).await.unwrap();

        let fetched1 = db.get_signing_key(key1.id).await.unwrap();
        let fetched2 = db.get_signing_key(key2.id).await.unwrap();
        assert!(!fetched1.is_active, "first key must be inactive");
        assert!(fetched2.is_active, "second key must be active");
    }

    #[tokio::test]
    async fn activate_nonexistent_returns_not_found() {
        let db = test_db().await;
        let fake_id = SigningKeyId::new();
        let result = db.activate_signing_key(fake_id).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }

    #[tokio::test]
    async fn rotate_signing_key_single_active() {
        let db = test_db().await;
        let key1 = db.create_signing_key(&ENC_KEY_A).await.unwrap();
        db.activate_signing_key(key1.id).await.unwrap();

        let new_key = db.rotate_signing_key(&ENC_KEY_A).await.unwrap();

        let active = db.get_active_signing_key().await.unwrap();
        assert_eq!(active.id, new_key.id, "new key must be the active one");

        let old = db.get_signing_key(key1.id).await.unwrap();
        assert!(!old.is_active, "old key must be inactive after rotation");
    }

    #[tokio::test]
    async fn get_all_signing_keys_returns_all() {
        let db = test_db().await;
        let k1 = db.create_signing_key(&ENC_KEY_A).await.unwrap();
        let k2 = db.create_signing_key(&ENC_KEY_A).await.unwrap();

        let all = db.get_all_signing_keys().await.unwrap();
        assert_eq!(all.len(), 2);
        let ids: Vec<_> = all.iter().map(|k| k.id).collect();
        assert!(ids.contains(&k1.id));
        assert!(ids.contains(&k2.id));
    }

    #[test]
    fn build_jwks_output_format() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key_pem = RsaPublicKey::from(&private_key)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let id = SigningKeyId::new();
        let key = SigningKey {
            id,
            private_key_enc: vec![],
            private_key_nonce: vec![],
            public_key_pem,
            algorithm: "RS256".to_string(),
            is_active: true,
            created_at: Utc::now(),
        };

        let jwks = build_jwks(&[key]).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        let entry = &jwks.keys[0];
        assert_eq!(entry.kty, "RSA");
        assert_eq!(entry.alg, "RS256");
        assert_eq!(entry.use_, "sig");
        assert!(!entry.n.is_empty(), "modulus must be non-empty");
        assert!(!entry.e.is_empty(), "exponent must be non-empty");
        assert_eq!(entry.kid, id.to_string());
    }

    #[test]
    fn build_jwks_empty() {
        let jwks = build_jwks(&[]).unwrap();
        assert!(jwks.keys.is_empty(), "empty input yields empty JWKS");
    }

    #[test]
    fn build_discovery_fields() {
        let issuer = "https://auth.example.com";
        let doc = build_discovery(issuer);

        assert_eq!(doc.issuer, issuer);
        assert_eq!(
            doc.authorization_endpoint,
            "https://auth.example.com/oauth/authorize"
        );
        assert_eq!(doc.token_endpoint, "https://auth.example.com/oauth/token");
        assert_eq!(
            doc.userinfo_endpoint,
            "https://auth.example.com/oauth/userinfo"
        );
        assert_eq!(
            doc.jwks_uri,
            "https://auth.example.com/.well-known/jwks.json"
        );
        assert!(!doc.scopes_supported.is_empty());
        assert!(!doc.response_types_supported.is_empty());
        assert!(!doc.grant_types_supported.is_empty());
        assert!(!doc.subject_types_supported.is_empty());
        assert!(!doc.id_token_signing_alg_values_supported.is_empty());
        assert!(!doc.token_endpoint_auth_methods_supported.is_empty());
        assert!(!doc.code_challenge_methods_supported.is_empty());
    }
}
