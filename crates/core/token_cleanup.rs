use chrono::Utc;

use crate::db::Db;
use crate::error::AuthError;

impl Db {
    pub async fn cleanup_expired_tokens(&self) -> Result<u64, AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let r1 = sqlx::query(
            "DELETE FROM allowthem_password_reset_tokens \
             WHERE expires_at <= ? OR used_at IS NOT NULL",
        )
        .bind(&now)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;

        let r2 = sqlx::query(
            "DELETE FROM allowthem_email_verification_tokens \
             WHERE expires_at <= ? OR used_at IS NOT NULL",
        )
        .bind(&now)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;

        Ok(r1.rows_affected() + r2.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::db::Db;
    use crate::types::{Email, ResetTokenId, VerificationTokenId, UserId};

    async fn test_db() -> Db {
        Db::connect("sqlite::memory:").await.expect("in-memory db")
    }

    async fn make_user(db: &Db) -> UserId {
        let email = Email::new("cleanup@example.com".to_string()).unwrap();
        let user = db
            .create_user(email, "test-password", None)
            .await
            .expect("create user");
        user.id
    }

    async fn insert_reset_token(db: &Db, user_id: UserId, expires_at: &str, used: bool) {
        let id = ResetTokenId::new();
        let used_at = if used {
            Some(Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO allowthem_password_reset_tokens \
             (id, user_id, token_hash, expires_at, used_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(format!("reset-hash-{}", uuid::Uuid::now_v7()))
        .bind(expires_at)
        .bind(used_at.as_deref())
        .execute(db.pool())
        .await
        .expect("insert reset token");
    }

    async fn insert_verification_token(db: &Db, user_id: UserId, expires_at: &str, used: bool) {
        let id = VerificationTokenId::new();
        let used_at = if used {
            Some(Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO allowthem_email_verification_tokens \
             (id, user_id, token_hash, expires_at, used_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(format!("verify-hash-{}", uuid::Uuid::now_v7()))
        .bind(expires_at)
        .bind(used_at.as_deref())
        .execute(db.pool())
        .await
        .expect("insert verification token");
    }

    async fn count_reset_tokens(db: &Db) -> i64 {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM allowthem_password_reset_tokens")
                .fetch_one(db.pool())
                .await
                .expect("count");
        count
    }

    async fn count_verification_tokens(db: &Db) -> i64 {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM allowthem_email_verification_tokens")
                .fetch_one(db.pool())
                .await
                .expect("count");
        count
    }

    #[tokio::test]
    async fn cleanup_removes_expired_tokens() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        let past = (Utc::now() - Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let future = (Utc::now() + Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        insert_reset_token(&db, user_id, &past, false).await;
        insert_reset_token(&db, user_id, &future, false).await;
        insert_verification_token(&db, user_id, &past, false).await;
        insert_verification_token(&db, user_id, &future, false).await;

        let removed = db.cleanup_expired_tokens().await.expect("cleanup");
        assert_eq!(removed, 2, "should remove 1 expired reset + 1 expired verification");
        assert_eq!(count_reset_tokens(&db).await, 1);
        assert_eq!(count_verification_tokens(&db).await, 1);
    }

    #[tokio::test]
    async fn cleanup_removes_used_tokens() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        let future = (Utc::now() + Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        insert_reset_token(&db, user_id, &future, true).await;
        insert_verification_token(&db, user_id, &future, true).await;

        let removed = db.cleanup_expired_tokens().await.expect("cleanup");
        assert_eq!(removed, 2, "should remove used tokens even if not expired");
    }

    #[tokio::test]
    async fn cleanup_preserves_active_tokens() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        let future = (Utc::now() + Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        insert_reset_token(&db, user_id, &future, false).await;
        insert_verification_token(&db, user_id, &future, false).await;

        let removed = db.cleanup_expired_tokens().await.expect("cleanup");
        assert_eq!(removed, 0, "should not remove active tokens");
        assert_eq!(count_reset_tokens(&db).await, 1);
        assert_eq!(count_verification_tokens(&db).await, 1);
    }
}
