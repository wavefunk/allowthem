use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::AuthError;
use crate::types::{Session, SessionId, SessionToken, TokenHash, UserId};

/// Generate a cryptographically random session token.
///
/// Fills 32 bytes from the OS random source and encodes them as base64url
/// without padding, producing a 43-character string.
pub fn generate_token() -> SessionToken {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    SessionToken::from_encoded(Base64UrlUnpadded::encode_string(&bytes))
}

/// Hash a session token with SHA-256.
///
/// The resulting hex string (64 chars) is what is stored in the database.
/// The raw token is never persisted.
pub fn hash_token(token: &SessionToken) -> TokenHash {
    let digest = Sha256::digest(token.as_str().as_bytes());
    TokenHash::new_unchecked(format!("{digest:x}"))
}

impl Db {
    /// Insert a new session record and return it.
    ///
    /// The caller is responsible for hashing the token before calling this function
    /// via `hash_token()`. The raw token must never be passed here.
    pub async fn create_session(
        &self,
        user_id: UserId,
        token_hash: TokenHash,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Session, AuthError> {
        let id = SessionId::new();
        let expires_at_str = expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        sqlx::query_as::<_, Session>(
            "INSERT INTO allowthem_sessions (id, token_hash, user_id, ip_address, user_agent, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING id, token_hash, user_id, ip_address, user_agent, expires_at, created_at",
        )
        .bind(id)
        .bind(token_hash)
        .bind(user_id)
        .bind(ip_address)
        .bind(user_agent)
        .bind(expires_at_str)
        .fetch_one(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Look up a session by raw token.
    ///
    /// Hashes the token internally and queries by hash. Expired sessions
    /// (where `expires_at` is in the past) are excluded. Returns `None`
    /// when no matching active session is found.
    pub async fn lookup_session(&self, token: &SessionToken) -> Result<Option<Session>, AuthError> {
        let hash = hash_token(token);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        sqlx::query_as::<_, Session>(
            "SELECT id, token_hash, user_id, ip_address, user_agent, expires_at, created_at
             FROM allowthem_sessions
             WHERE token_hash = ? AND expires_at > ?",
        )
        .bind(hash)
        .bind(now)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }
}
