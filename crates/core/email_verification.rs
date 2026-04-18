use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::email::{EmailMessage, EmailSender};
use crate::error::AuthError;
use crate::types::{Email, UserId, VerificationTokenId};

const VERIFICATION_TTL_HOURS: i64 = 24;

fn generate_verification_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    Base64UrlUnpadded::encode_string(&bytes)
}

fn hash_verification_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
}

impl Db {
    pub async fn create_email_verification(
        &self,
        user_id: UserId,
    ) -> Result<String, AuthError> {
        let raw_token = generate_verification_token();
        let token_hash = hash_verification_token(&raw_token);
        let id = VerificationTokenId::new();
        let expires_at = Utc::now() + Duration::hours(VERIFICATION_TTL_HOURS);
        let expires_at_str = expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_email_verification_tokens \
             (id, user_id, token_hash, expires_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(&token_hash)
        .bind(&expires_at_str)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;

        Ok(raw_token)
    }

    pub async fn verify_email(&self, raw_token: &str) -> Result<bool, AuthError> {
        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        let token_hash = hash_verification_token(raw_token);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let row: Option<(VerificationTokenId, UserId)> = sqlx::query_as(
            "SELECT id, user_id FROM allowthem_email_verification_tokens \
             WHERE token_hash = ? AND expires_at > ? AND used_at IS NULL",
        )
        .bind(&token_hash)
        .bind(&now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        let (token_id, user_id) = match row {
            None => return Ok(false),
            Some(r) => r,
        };

        sqlx::query(
            "UPDATE allowthem_email_verification_tokens SET used_at = ? WHERE id = ?",
        )
        .bind(&now)
        .bind(token_id)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        sqlx::query(
            "UPDATE allowthem_users SET email_verified = 1, updated_at = ? WHERE id = ?",
        )
        .bind(&now)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        tx.commit().await.map_err(AuthError::Database)?;

        Ok(true)
    }

    pub async fn send_verification_email(
        &self,
        user_id: UserId,
        email: &Email,
        base_url: &str,
        sender: &dyn EmailSender,
    ) -> Result<(), AuthError> {
        let raw_token = self.create_email_verification(user_id).await?;

        let verify_url = format!("{}/auth/verify-email?token={}", base_url, raw_token);
        let body = format!(
            "Please verify your email address by clicking the link below:\n\n{}\n\nThis link expires in {} hours.",
            verify_url, VERIFICATION_TTL_HOURS,
        );
        let html = format!(
            "<p>Please verify your email address. <a href=\"{}\">Click here to verify</a>.</p>\
             <p>This link expires in {} hours.</p>",
            verify_url, VERIFICATION_TTL_HOURS,
        );

        let message = EmailMessage {
            to: email.as_str(),
            subject: "Verify your email address",
            body: &body,
            html: Some(&html),
        };

        sender
            .send(message)
            .await
            .map_err(|e| AuthError::Email(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Db;
    use crate::email::LogEmailSender;
    use crate::types::Email;

    async fn test_db() -> Db {
        Db::connect("sqlite::memory:").await.expect("in-memory db")
    }

    async fn make_user(db: &Db) -> (crate::types::UserId, Email) {
        let email = Email::new("verify@example.com".to_string()).unwrap();
        let user = db
            .create_user(email.clone(), "test-password", None)
            .await
            .expect("create user");
        (user.id, email)
    }

    #[tokio::test]
    async fn create_verification_returns_token() {
        let db = test_db().await;
        let (user_id, _) = make_user(&db).await;
        let token = db
            .create_email_verification(user_id)
            .await
            .expect("create verification");
        assert!(!token.is_empty());
    }

    #[tokio::test]
    async fn verify_email_succeeds_with_valid_token() {
        let db = test_db().await;
        let (user_id, email) = make_user(&db).await;
        let token = db
            .create_email_verification(user_id)
            .await
            .expect("create");
        let result = db.verify_email(&token).await.expect("verify");
        assert!(result, "valid token must verify");

        let user = db.get_user_by_email(&email).await.expect("get user");
        assert!(user.email_verified, "user must be marked verified");
    }

    #[tokio::test]
    async fn verify_email_fails_with_garbage_token() {
        let db = test_db().await;
        let _ = make_user(&db).await;
        let result = db.verify_email("not-a-real-token").await.expect("verify");
        assert!(!result, "garbage token must fail");
    }

    #[tokio::test]
    async fn verify_email_fails_when_already_used() {
        let db = test_db().await;
        let (user_id, _) = make_user(&db).await;
        let token = db
            .create_email_verification(user_id)
            .await
            .expect("create");
        let first = db.verify_email(&token).await.expect("first verify");
        assert!(first);
        let second = db.verify_email(&token).await.expect("second verify");
        assert!(!second, "used token must not work again");
    }

    #[tokio::test]
    async fn send_verification_email_succeeds() {
        let db = test_db().await;
        let (user_id, email) = make_user(&db).await;
        let sender = LogEmailSender;
        let result = db
            .send_verification_email(user_id, &email, "https://example.com", &sender)
            .await;
        assert!(result.is_ok());
    }
}
