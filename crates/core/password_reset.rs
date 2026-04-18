use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::email::{EmailMessage, EmailSender};
use crate::error::AuthError;
use crate::password::hash_password;
use crate::types::{Email, ResetTokenId, UserId};

const RESET_TTL_MINUTES: i64 = 30;

/// Generate a cryptographically random reset token.
///
/// Fills 32 bytes from the OS random source and encodes as base64url without
/// padding, producing a 43-character string suitable for inclusion in a URL.
fn generate_reset_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    Base64UrlUnpadded::encode_string(&bytes)
}

/// Hash a raw reset token with SHA-256.
///
/// Returns the hex-encoded digest. This is what is stored in the database.
/// The raw token is only ever sent to the user via email.
fn hash_reset_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
}

impl Db {
    /// Create a password reset token for the user with the given email.
    ///
    /// Looks up the user by email. If found, inserts a new reset token record
    /// (hashed) and returns the raw token for inclusion in the reset URL.
    /// Returns `None` if no user exists for that email (caller should not
    /// reveal this to prevent email enumeration).
    pub async fn create_password_reset(&self, email: &Email) -> Result<Option<String>, AuthError> {
        let user = match self.get_user_by_email(email).await {
            Ok(u) => u,
            Err(AuthError::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };

        let raw_token = generate_reset_token();
        let token_hash = hash_reset_token(&raw_token);
        let id = ResetTokenId::new();
        let expires_at = Utc::now() + Duration::minutes(RESET_TTL_MINUTES);
        let expires_at_str = expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_password_reset_tokens \
             (id, user_id, token_hash, expires_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user.id)
        .bind(&token_hash)
        .bind(&expires_at_str)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;

        Ok(Some(raw_token))
    }

    /// Validate a raw reset token.
    ///
    /// Hashes the token and looks it up in the database. Returns the associated
    /// `UserId` and token record ID if the token exists, has not expired, and has
    /// not been used. Returns `None` if the token is invalid or expired.
    pub async fn validate_reset_token(
        &self,
        raw_token: &str,
    ) -> Result<Option<(ResetTokenId, UserId)>, AuthError> {
        let token_hash = hash_reset_token(raw_token);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let row: Option<(ResetTokenId, UserId)> = sqlx::query_as(
            "SELECT id, user_id FROM allowthem_password_reset_tokens \
             WHERE token_hash = ? AND expires_at > ? AND used_at IS NULL",
        )
        .bind(&token_hash)
        .bind(&now)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)?;

        Ok(row)
    }

    /// Execute a password reset: update the password and mark the token used.
    ///
    /// Runs atomically in a transaction:
    /// 1. Validate the token (not expired, not used).
    /// 2. Mark the token as used (`used_at = now`).
    /// 3. Hash the new password.
    /// 4. Update the user's `password_hash` and `updated_at`.
    ///
    /// Returns `Ok(true)` on success, `Ok(false)` if the token was invalid.
    pub async fn execute_reset(
        &self,
        raw_token: &str,
        new_password: &str,
    ) -> Result<bool, AuthError> {
        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        let token_hash = hash_reset_token(raw_token);
        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        // Step 1 & 2: fetch and mark used atomically within the transaction.
        let row: Option<(ResetTokenId, UserId)> = sqlx::query_as(
            "SELECT id, user_id FROM allowthem_password_reset_tokens \
             WHERE token_hash = ? AND expires_at > ? AND used_at IS NULL",
        )
        .bind(&token_hash)
        .bind(&now_str)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        let (token_id, user_id) = match row {
            None => return Ok(false),
            Some(r) => r,
        };

        sqlx::query("UPDATE allowthem_password_reset_tokens SET used_at = ? WHERE id = ?")
            .bind(&now_str)
            .bind(token_id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        // Step 3 & 4: hash password and update user.
        let pw_hash = hash_password(new_password)?;

        sqlx::query("UPDATE allowthem_users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(pw_hash)
            .bind(&now_str)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        tx.commit().await.map_err(AuthError::Database)?;

        Ok(true)
    }

    /// Send a password reset email for the given address.
    ///
    /// Calls `create_password_reset` to generate a token. If the email exists,
    /// constructs a reset URL using `base_url` and delivers it via `sender`.
    /// If the email does not exist, returns `Ok(())` silently (no enumeration).
    pub async fn send_password_reset(
        &self,
        email: &Email,
        base_url: &str,
        sender: &dyn EmailSender,
    ) -> Result<(), AuthError> {
        let raw_token = match self.create_password_reset(email).await? {
            None => return Ok(()),
            Some(t) => t,
        };

        let reset_url = format!("{}/auth/reset-password?token={}", base_url, raw_token);
        let body = format!(
            "You requested a password reset. Click the link below to set a new password:\n\n{}\n\nThis link expires in {} minutes.",
            reset_url, RESET_TTL_MINUTES,
        );
        let html = format!(
            "<p>You requested a password reset. <a href=\"{}\">Click here to set a new password</a>.</p><p>This link expires in {} minutes.</p>",
            reset_url, RESET_TTL_MINUTES,
        );

        let message = EmailMessage {
            to: email.as_str(),
            subject: "Reset your password",
            body: &body,
            html: Some(&html),
        };

        sender
            .send(message)
            .await
            .map_err(|e| AuthError::Email(e.to_string()))
    }
}

/// Expiry timestamp for a reset token, given a reference time.
///
/// Used in tests to avoid hardcoding durations.
#[allow(dead_code)]
pub fn reset_expires_at(from: DateTime<Utc>) -> DateTime<Utc> {
    from + Duration::minutes(RESET_TTL_MINUTES)
}

#[cfg(test)]
mod tests {
    use crate::db::Db;
    use crate::email::LogEmailSender;
    use crate::types::Email;

    async fn test_db() -> Db {
        Db::connect("sqlite::memory:").await.expect("in-memory db")
    }

    async fn make_user(db: &Db) -> Email {
        let email = Email::new("reset@example.com".to_string()).unwrap();
        db.create_user(email.clone(), "initial-password", None, None)
            .await
            .expect("create user");
        email
    }

    #[tokio::test]
    async fn create_reset_returns_token_for_known_email() {
        let db = test_db().await;
        let email = make_user(&db).await;
        let token = db
            .create_password_reset(&email)
            .await
            .expect("create_password_reset");
        assert!(token.is_some(), "should return a token for a known email");
        let raw = token.unwrap();
        assert!(!raw.is_empty(), "token must not be empty");
    }

    #[tokio::test]
    async fn create_reset_returns_none_for_unknown_email() {
        let db = test_db().await;
        let email = Email::new("nobody@example.com".to_string()).unwrap();
        let token = db
            .create_password_reset(&email)
            .await
            .expect("create_password_reset");
        assert!(token.is_none(), "should return None for unknown email");
    }

    #[tokio::test]
    async fn validate_reset_token_returns_ids_for_valid_token() {
        let db = test_db().await;
        let email = make_user(&db).await;
        let raw = db
            .create_password_reset(&email)
            .await
            .expect("create")
            .unwrap();
        let result = db.validate_reset_token(&raw).await.expect("validate");
        assert!(result.is_some(), "valid token must return Some");
    }

    #[tokio::test]
    async fn validate_reset_token_returns_none_for_garbage() {
        let db = test_db().await;
        let _ = make_user(&db).await;
        let result = db
            .validate_reset_token("not-a-real-token")
            .await
            .expect("validate");
        assert!(result.is_none(), "invalid token must return None");
    }

    #[tokio::test]
    async fn execute_reset_changes_password_and_marks_token_used() {
        let db = test_db().await;
        let email = make_user(&db).await;
        let raw = db
            .create_password_reset(&email)
            .await
            .expect("create")
            .unwrap();

        let success = db
            .execute_reset(&raw, "new-secure-password")
            .await
            .expect("execute_reset");
        assert!(success, "execute_reset must return true on success");

        // Token is now used — a second attempt must fail.
        let again = db
            .execute_reset(&raw, "another-password")
            .await
            .expect("second execute_reset");
        assert!(!again, "used token must not be reusable");

        // Verify the new password works for login.
        let user = db
            .find_for_login("reset@example.com")
            .await
            .expect("find_for_login");
        let valid = crate::password::verify_password(
            "new-secure-password",
            user.password_hash.as_ref().unwrap(),
        )
        .expect("verify");
        assert!(valid, "new password must verify correctly");
    }

    #[tokio::test]
    async fn send_password_reset_succeeds_for_known_email() {
        let db = test_db().await;
        let email = make_user(&db).await;
        let sender = LogEmailSender;
        let result = db
            .send_password_reset(&email, "https://example.com", &sender)
            .await;
        assert!(
            result.is_ok(),
            "send_password_reset must succeed for known email"
        );
    }

    #[tokio::test]
    async fn send_password_reset_is_silent_for_unknown_email() {
        let db = test_db().await;
        let email = Email::new("ghost@example.com".to_string()).unwrap();
        let sender = LogEmailSender;
        let result = db
            .send_password_reset(&email, "https://example.com", &sender)
            .await;
        assert!(
            result.is_ok(),
            "send_password_reset must not error for unknown email"
        );
    }
}
