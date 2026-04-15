use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::AuthError;
use crate::types::{Email, InvitationId, UserId};

/// A single-use invitation token record.
///
/// Returned by `Db::create_invitation` and `Db::validate_invitation`.
/// The `token_hash` is never exposed — only the raw token (returned once
/// at creation) can be used to validate.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Invitation {
    pub id: InvitationId,
    pub email: Option<Email>,
    pub metadata: Option<String>,
    pub invited_by: Option<UserId>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Generate a cryptographically random invitation token.
///
/// Fills 32 bytes from the OS random source and encodes as base64url without
/// padding, producing a 43-character string suitable for inclusion in a URL.
fn generate_invitation_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    Base64UrlUnpadded::encode_string(&bytes)
}

/// Hash a raw invitation token with SHA-256.
///
/// Returns the hex-encoded digest. This is what is stored in the database.
/// The raw token is only ever shown once, at creation time.
fn hash_invitation_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
}

impl Db {
    /// Create an invitation. Returns the raw token (shown once) and the
    /// `Invitation` record.
    ///
    /// If `email` is `Some`, the invitation is targeted at that address.
    /// If `email` is `None`, it is an open invitation usable by anyone.
    pub async fn create_invitation(
        &self,
        email: Option<&Email>,
        metadata: Option<&str>,
        invited_by: Option<UserId>,
        expires_at: DateTime<Utc>,
    ) -> Result<(String, Invitation), AuthError> {
        let id = InvitationId::new();
        let raw_token = generate_invitation_token();
        let token_hash = hash_invitation_token(&raw_token);
        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let expires_str = expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_invitations \
             (id, email, token_hash, metadata, invited_by, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(email)
        .bind(&token_hash)
        .bind(metadata)
        .bind(invited_by)
        .bind(&expires_str)
        .bind(&now_str)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;

        let inv = Invitation {
            id,
            email: email.cloned(),
            metadata: metadata.map(String::from),
            invited_by,
            expires_at,
            consumed_at: None,
            created_at: now,
        };

        Ok((raw_token, inv))
    }

    /// Mark an invitation as consumed.
    ///
    /// Uses `consumed_at IS NULL` as a concurrency guard. Returns `Ok(())`
    /// on success. Returns `Err(AuthError::Gone)` if already consumed — the
    /// caller should treat this as a race loss.
    pub async fn consume_invitation(&self, id: InvitationId) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let result = sqlx::query(
            "UPDATE allowthem_invitations SET consumed_at = ? \
             WHERE id = ? AND consumed_at IS NULL",
        )
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::Gone);
        }

        Ok(())
    }

    /// Validate a raw invitation token.
    ///
    /// Returns `Some(Invitation)` if the token exists, is not expired, and has
    /// not been consumed. Returns `None` otherwise. The caller is responsible
    /// for checking email match on targeted invitations.
    pub async fn validate_invitation(
        &self,
        raw_token: &str,
    ) -> Result<Option<Invitation>, AuthError> {
        let token_hash = hash_invitation_token(raw_token);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query_as::<_, Invitation>(
            "SELECT id, email, metadata, invited_by, expires_at, consumed_at, created_at \
             FROM allowthem_invitations \
             WHERE token_hash = ? AND expires_at > ? AND consumed_at IS NULL",
        )
        .bind(&token_hash)
        .bind(&now)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::db::Db;
    use crate::error::AuthError;
    use crate::types::Email;

    async fn test_db() -> Db {
        Db::connect("sqlite::memory:").await.expect("in-memory db")
    }

    #[tokio::test]
    async fn create_invitation_returns_raw_token_and_invitation() {
        let db = test_db().await;
        let email = Email::new("invite@example.com".to_string()).unwrap();
        let expires = Utc::now() + Duration::hours(24);

        let (raw_token, inv) = db
            .create_invitation(Some(&email), Some(r#"{"role":"editor"}"#), None, expires)
            .await
            .expect("create_invitation");

        assert!(!raw_token.is_empty());
        assert_eq!(inv.email.as_ref().unwrap().as_str(), "invite@example.com");
        assert_eq!(inv.metadata.as_deref(), Some(r#"{"role":"editor"}"#));
        assert!(inv.invited_by.is_none());
        assert!(inv.consumed_at.is_none());
    }

    #[tokio::test]
    async fn create_open_invitation_has_no_email() {
        let db = test_db().await;
        let expires = Utc::now() + Duration::hours(24);

        let (_raw, inv) = db
            .create_invitation(None, None, None, expires)
            .await
            .expect("create open invitation");

        assert!(inv.email.is_none());
        assert!(inv.metadata.is_none());
    }

    #[tokio::test]
    async fn validate_returns_invitation_for_valid_token() {
        let db = test_db().await;
        let email = Email::new("v@example.com".to_string()).unwrap();
        let expires = Utc::now() + Duration::hours(24);
        let (raw, _) = db
            .create_invitation(Some(&email), Some("{}"), None, expires)
            .await
            .unwrap();

        let inv = db.validate_invitation(&raw).await.expect("validate");
        assert!(inv.is_some());
        let inv = inv.unwrap();
        assert_eq!(inv.email.as_ref().unwrap().as_str(), "v@example.com");
    }

    #[tokio::test]
    async fn validate_returns_none_for_garbage_token() {
        let db = test_db().await;
        let result = db
            .validate_invitation("not-a-real-token")
            .await
            .expect("validate");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn validate_returns_none_for_expired_token() {
        let db = test_db().await;
        let expires = Utc::now() - Duration::hours(1);
        let (raw, _) = db
            .create_invitation(None, None, None, expires)
            .await
            .unwrap();

        let result = db.validate_invitation(&raw).await.expect("validate");
        assert!(result.is_none(), "expired invitation must return None");
    }

    #[tokio::test]
    async fn consume_marks_invitation_consumed() {
        let db = test_db().await;
        let expires = Utc::now() + Duration::hours(24);
        let (raw, inv) = db
            .create_invitation(None, None, None, expires)
            .await
            .unwrap();

        db.consume_invitation(inv.id).await.expect("consume");

        // Validation must now return None.
        let result = db.validate_invitation(&raw).await.expect("validate");
        assert!(result.is_none(), "consumed invitation must not validate");
    }

    #[tokio::test]
    async fn consume_twice_returns_gone() {
        let db = test_db().await;
        let expires = Utc::now() + Duration::hours(24);
        let (_, inv) = db
            .create_invitation(None, None, None, expires)
            .await
            .unwrap();

        db.consume_invitation(inv.id).await.expect("first consume");

        let err = db
            .consume_invitation(inv.id)
            .await
            .expect_err("second consume should fail");
        assert!(
            matches!(err, AuthError::Gone),
            "expected AuthError::Gone, got {err:?}"
        );
    }
}
