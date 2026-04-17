use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::AuthError;
use crate::sessions::generate_token;
use crate::types::{ApiTokenId, ApiTokenInfo, TokenHash, UserId};

/// Hash a raw API token string with SHA-256.
///
/// Returns the hex-encoded digest as a `TokenHash`. This is a standalone
/// function rather than reusing `sessions::hash_token` to avoid coupling
/// through the `SessionToken` type.
fn hash_api_token(raw: &str) -> TokenHash {
    let digest = Sha256::digest(raw.as_bytes());
    TokenHash::new_unchecked(format!("{digest:x}"))
}

impl Db {
    /// Generate and store a new API token for the user.
    ///
    /// Returns the raw token string (shown once, never stored) and
    /// `ApiTokenInfo` metadata. The caller must present the raw token to the
    /// user — it cannot be retrieved again.
    pub async fn create_api_token(
        &self,
        user_id: UserId,
        name: &str,
        expires_at: Option<DateTime<Utc>>,
        metadata: Option<&str>,
    ) -> Result<(String, ApiTokenInfo), AuthError> {
        let id = ApiTokenId::new();
        let raw_session_token = generate_token();
        let raw = raw_session_token.as_str().to_string();
        let token_hash = hash_api_token(&raw);
        let expires_str = expires_at.map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());

        let info = sqlx::query_as::<_, ApiTokenInfo>(
            "INSERT INTO allowthem_api_tokens (id, user_id, name, token_hash, expires_at, metadata)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING id, user_id, name, metadata, expires_at, created_at",
        )
        .bind(id)
        .bind(user_id)
        .bind(name)
        .bind(token_hash)
        .bind(expires_str)
        .bind(metadata)
        .fetch_one(self.pool())
        .await
        .map_err(AuthError::Database)?;

        Ok((raw, info))
    }

    /// Validate a raw bearer token.
    ///
    /// Hashes the token and queries by hash. Tokens with a past `expires_at`
    /// are excluded. Returns `Some((UserId, ApiTokenInfo))` if valid, `None` otherwise.
    pub async fn validate_api_token(
        &self,
        raw_token: &str,
    ) -> Result<Option<(UserId, ApiTokenInfo)>, AuthError> {
        let hash = hash_api_token(raw_token);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let info = sqlx::query_as::<_, ApiTokenInfo>(
            "SELECT id, user_id, name, metadata, expires_at, created_at
             FROM allowthem_api_tokens
             WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(hash)
        .bind(now)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)?;

        Ok(info.map(|i| (i.user_id, i)))
    }

    /// List all API tokens for a user (metadata only, no hashes).
    pub async fn list_api_tokens(&self, user_id: UserId) -> Result<Vec<ApiTokenInfo>, AuthError> {
        sqlx::query_as::<_, ApiTokenInfo>(
            "SELECT id, user_id, name, metadata, expires_at, created_at
             FROM allowthem_api_tokens
             WHERE user_id = ?
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Delete a single API token by ID.
    ///
    /// Returns `true` if a token was found and deleted.
    pub async fn delete_api_token(&self, id: ApiTokenId) -> Result<bool, AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_api_tokens WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all API tokens for a user.
    ///
    /// Returns the number of tokens deleted.
    pub async fn delete_user_api_tokens(&self, user_id: UserId) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_api_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::db::Db;
    use crate::types::{Email, UserId};

    async fn test_db() -> Db {
        Db::connect("sqlite::memory:")
            .await
            .expect("in-memory test db")
    }

    async fn create_test_user(db: &Db) -> UserId {
        let email = Email::new(format!("user_{}@example.com", uuid::Uuid::now_v7())).unwrap();
        let user = db.create_user(email, "password123", None).await.unwrap();
        user.id
    }

    #[tokio::test]
    async fn test_create_and_validate_api_token() {
        let db = test_db().await;
        let user_id = create_test_user(&db).await;

        let (raw, info) = db
            .create_api_token(user_id, "my-token", None, None)
            .await
            .unwrap();

        assert_eq!(info.user_id, user_id);
        assert_eq!(info.name, "my-token");
        assert!(info.expires_at.is_none());
        assert!(info.metadata.is_none());

        let result = db.validate_api_token(&raw).await.unwrap();
        let (uid, _token_info) = result.expect("token must be valid");
        assert_eq!(uid, user_id);
    }

    #[tokio::test]
    async fn test_expired_api_token_rejected() {
        let db = test_db().await;
        let user_id = create_test_user(&db).await;

        let past = Utc::now() - Duration::hours(1);
        let (raw, _) = db
            .create_api_token(user_id, "expired-token", Some(past), None)
            .await
            .unwrap();

        let result = db.validate_api_token(&raw).await.unwrap();
        assert!(result.is_none(), "expired token must be rejected");
    }

    #[tokio::test]
    async fn test_deleted_api_token_rejected() {
        let db = test_db().await;
        let user_id = create_test_user(&db).await;

        let (raw, info) = db
            .create_api_token(user_id, "delete-me", None, None)
            .await
            .unwrap();

        let deleted = db.delete_api_token(info.id).await.unwrap();
        assert!(deleted);

        let result = db.validate_api_token(&raw).await.unwrap();
        assert!(result.is_none(), "deleted token must be rejected");
    }

    #[tokio::test]
    async fn test_list_api_tokens() {
        let db = test_db().await;
        let user_id = create_test_user(&db).await;

        db.create_api_token(user_id, "token-a", None, None).await.unwrap();
        db.create_api_token(user_id, "token-b", None, None).await.unwrap();

        let tokens = db.list_api_tokens(user_id).await.unwrap();
        assert_eq!(tokens.len(), 2);
        // token_hash is not present in ApiTokenInfo — verify by checking names only
        let names: Vec<&str> = tokens.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"token-a"));
        assert!(names.contains(&"token-b"));
    }

    #[tokio::test]
    async fn test_cascade_delete_removes_api_tokens() {
        let db = test_db().await;
        let user_id = create_test_user(&db).await;

        db.create_api_token(user_id, "to-be-cascaded", None, None)
            .await
            .unwrap();

        // Delete the user — token should cascade
        db.delete_user(user_id).await.unwrap();

        let token_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_api_tokens WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(db.pool())
                .await
                .unwrap();

        assert_eq!(token_count, 0, "api tokens must cascade-delete with user");
    }

    #[tokio::test]
    async fn test_create_with_metadata() {
        let db = test_db().await;
        let user_id = create_test_user(&db).await;

        let (raw, info) = db
            .create_api_token(user_id, "meta-token", None, Some("key=value"))
            .await
            .unwrap();

        assert_eq!(info.metadata.as_deref(), Some("key=value"));

        // validate returns correct metadata
        let (uid, token_info) = db
            .validate_api_token(&raw)
            .await
            .unwrap()
            .expect("token must be valid");
        assert_eq!(uid, user_id);
        assert_eq!(token_info.metadata.as_deref(), Some("key=value"));

        // list also returns correct metadata
        let tokens = db.list_api_tokens(user_id).await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].metadata.as_deref(), Some("key=value"));
    }
}
