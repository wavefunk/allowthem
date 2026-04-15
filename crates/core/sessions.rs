use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::AuthError;
use crate::types::{Session, SessionId, SessionToken, TokenHash, UserId};

/// Configuration for session lifecycle and cookie generation.
pub struct SessionConfig {
    /// How long a session lives. Default: 24 hours.
    pub ttl: Duration,
    /// Name of the session cookie. Default: `"allowthem_session"`.
    pub cookie_name: &'static str,
    /// Whether to set the `Secure` attribute on the cookie.
    /// Should be `true` in production (HTTPS), `false` in local dev.
    pub secure: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::hours(24),
            cookie_name: "allowthem_session",
            secure: true,
        }
    }
}

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

    /// Validate a session token and optionally extend it.
    ///
    /// Fetches the active session by token hash. If the session is past the
    /// halfway point of its TTL (`now > expires_at - ttl/2`), it is renewed
    /// by setting `expires_at = now + ttl`. Returns the session with the
    /// updated expiry, or `None` if no active session was found.
    pub async fn validate_session(
        &self,
        token: &SessionToken,
        ttl: Duration,
    ) -> Result<Option<Session>, AuthError> {
        let session = match self.lookup_session(token).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let now = Utc::now();
        let halfway = session.expires_at - ttl / 2;

        if now > halfway {
            let new_expires_at = now + ttl;
            let new_expires_str = new_expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            let hash = hash_token(token);
            sqlx::query("UPDATE allowthem_sessions SET expires_at = ? WHERE token_hash = ?")
                .bind(&new_expires_str)
                .bind(hash)
                .execute(self.pool())
                .await
                .map_err(AuthError::Database)?;

            return Ok(Some(Session {
                expires_at: new_expires_at,
                ..session
            }));
        }

        Ok(Some(session))
    }

    /// Delete a single session by raw token.
    ///
    /// Returns `true` if a session was found and deleted, `false` if no
    /// matching session existed.
    pub async fn delete_session(&self, token: &SessionToken) -> Result<bool, AuthError> {
        let hash = hash_token(token);
        let result = sqlx::query("DELETE FROM allowthem_sessions WHERE token_hash = ?")
            .bind(hash)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all sessions for a user.
    ///
    /// Returns the number of sessions that were deleted.
    pub async fn delete_user_sessions(&self, user_id: &UserId) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_sessions WHERE user_id = ?")
            .bind(*user_id)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(result.rows_affected())
    }
}

/// Build a `Set-Cookie` header value for the given session token.
///
/// Attributes: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` derived from
/// `config.ttl`. The `Secure` attribute is added only when `config.secure` is
/// `true`. The `Domain` attribute is omitted when `domain` is empty.
pub fn session_cookie(token: &SessionToken, config: &SessionConfig, domain: &str) -> String {
    let max_age = config.ttl.num_seconds();
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        config.cookie_name,
        token.as_str(),
        max_age,
    );
    if !domain.is_empty() {
        cookie.push_str("; Domain=");
        cookie.push_str(domain);
    }
    if config.secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Extract the session token from a `Cookie` header value.
///
/// Searches the semicolon-separated list of `name=value` pairs for
/// `cookie_name`. Returns `None` if the cookie is absent.
pub fn parse_session_cookie(cookie_header: &str, cookie_name: &str) -> Option<SessionToken> {
    for pair in cookie_header.split("; ") {
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == cookie_name
        {
            return Some(SessionToken::from_encoded(value.trim().to_string()));
        }
    }
    None
}
