use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::Db;
use crate::error::AuthError;
use crate::password::hash_password;
use crate::types::{Email, User, UserId, Username};

/// Map a SQLite UNIQUE constraint violation to `AuthError::Conflict`.
///
/// SQLite UNIQUE violations include the constraint name in the message,
/// e.g. "UNIQUE constraint failed: allowthem_users.email".
pub(crate) fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") {
            if msg.contains("email") {
                return AuthError::Conflict("email already exists".into());
            }
            if msg.contains("username") {
                return AuthError::Conflict("username already exists".into());
            }
            return AuthError::Conflict(msg.to_string());
        }
    }
    AuthError::Database(err)
}

/// Parameters for searching/filtering users in the admin directory.
pub struct SearchUsersParams<'a> {
    pub query: Option<&'a str>,
    pub is_active: Option<bool>,
    pub has_mfa: Option<bool>,
    pub limit: u32,
    pub offset: u32,
}

/// User with MFA enrollment status, for list display.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserListEntry {
    pub id: UserId,
    pub email: Email,
    pub username: Option<Username>,
    pub is_active: bool,
    pub has_mfa: bool,
    pub created_at: DateTime<Utc>,
}

/// Result of a paginated user search.
pub struct SearchUsersResult {
    pub users: Vec<UserListEntry>,
    pub total: u32,
}

/// Opaque keyset cursor for paginating `list_users_paginated`.
///
/// Encodes `(created_at, id)` as a base64url-encoded JSON blob.
pub struct UserCursor {
    pub created_at: DateTime<Utc>,
    pub id: UserId,
}

#[derive(Serialize, Deserialize)]
struct RawUserCursor {
    ca: String,
    id: String,
}

impl UserCursor {
    pub fn from_entry(entry: &UserListEntry) -> Self {
        Self {
            created_at: entry.created_at,
            id: entry.id,
        }
    }

    pub fn encode(&self) -> String {
        let raw = RawUserCursor {
            ca: self.created_at.to_rfc3339(),
            id: self.id.to_string(),
        };
        let json = serde_json::to_string(&raw).expect("RawUserCursor serializes");
        Base64UrlUnpadded::encode_string(json.as_bytes())
    }

    pub fn decode(s: &str) -> Option<Self> {
        let bytes = Base64UrlUnpadded::decode_vec(s).ok()?;
        let raw: RawUserCursor = serde_json::from_slice(&bytes).ok()?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&raw.ca)
            .ok()?
            .with_timezone(&Utc);
        let id = raw.id.parse::<uuid::Uuid>().ok().map(UserId::from_uuid)?;
        Some(Self { created_at, id })
    }
}

impl Db {
    /// Create a user with email, plaintext password, optional username, and optional custom data.
    ///
    /// Hashes the password with Argon2id (via `password::hash_password`).
    /// Returns the created User (without password_hash in the returned struct).
    pub async fn create_user(
        &self,
        email: Email,
        password: &str,
        username: Option<Username>,
        custom_data: Option<&Value>,
    ) -> Result<User, AuthError> {
        let id = UserId::new();
        let pw_hash = hash_password(password)?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_users \
             (id, email, username, password_hash, email_verified, is_active, created_at, updated_at, custom_data) \
             VALUES (?1, ?2, ?3, ?4, 0, 1, ?5, ?5, ?6)",
        )
        .bind(id)
        .bind(&email)
        .bind(&username)
        .bind(&pw_hash)
        .bind(&now)
        .bind(custom_data.map(sqlx::types::Json))
        .execute(self.pool())
        .await
        .map_err(map_unique_violation)?;

        self.get_user(id).await
    }

    /// Import a user with a pre-existing password hash (for migration from external systems).
    /// The hash must be a valid Argon2 PHC string. No validation is performed on it.
    pub async fn create_user_with_hash(
        &self,
        email: Email,
        password_hash: &str,
        username: Option<Username>,
        custom_data: Option<&Value>,
    ) -> Result<User, AuthError> {
        let id = UserId::new();
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at, custom_data)
             VALUES (?1, ?2, ?3, ?4, 0, 1, ?5, ?5, ?6)",
        )
        .bind(id)
        .bind(&email)
        .bind(&username)
        .bind(password_hash)
        .bind(&now)
        .bind(custom_data.map(sqlx::types::Json))
        .execute(self.pool())
        .await
        .map_err(map_unique_violation)?;

        self.get_user(id).await
    }

    /// Look up a user by ID. Returns User with password_hash = None.
    pub async fn get_user(&self, id: UserId) -> Result<User, AuthError> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, username, NULL as password_hash, \
             email_verified, is_active, created_at, updated_at, custom_data \
             FROM allowthem_users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }

    /// Look up a user by email. Returns User with password_hash = None.
    pub async fn get_user_by_email(&self, email: &Email) -> Result<User, AuthError> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, username, NULL as password_hash, \
             email_verified, is_active, created_at, updated_at, custom_data \
             FROM allowthem_users WHERE email = ?",
        )
        .bind(email)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }

    /// Look up a user by username. Returns User with password_hash = None.
    pub async fn get_user_by_username(&self, username: &Username) -> Result<User, AuthError> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, username, NULL as password_hash, \
             email_verified, is_active, created_at, updated_at, custom_data \
             FROM allowthem_users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }

    /// Look up a user by email OR username for login.
    ///
    /// Returns User WITH password_hash populated. The caller is responsible
    /// for calling `verify_password()` to check the password.
    pub async fn find_for_login(&self, identifier: &str) -> Result<User, AuthError> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, username, password_hash, \
             email_verified, is_active, created_at, updated_at, custom_data \
             FROM allowthem_users WHERE email = ?1 OR username = ?1",
        )
        .bind(identifier)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }

    /// Update a user's email. Also updates updated_at.
    pub async fn update_user_email(&self, id: UserId, email: Email) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result =
            sqlx::query("UPDATE allowthem_users SET email = ?1, updated_at = ?2 WHERE id = ?3")
                .bind(&email)
                .bind(&now)
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_unique_violation)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Update a user's username (set or clear). Also updates updated_at.
    pub async fn update_user_username(
        &self,
        id: UserId,
        username: Option<Username>,
    ) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result =
            sqlx::query("UPDATE allowthem_users SET username = ?1, updated_at = ?2 WHERE id = ?3")
                .bind(&username)
                .bind(&now)
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_unique_violation)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Update a user's is_active flag. Also updates updated_at.
    pub async fn update_user_active(&self, id: UserId, is_active: bool) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result =
            sqlx::query("UPDATE allowthem_users SET is_active = ?1, updated_at = ?2 WHERE id = ?3")
                .bind(is_active)
                .bind(&now)
                .bind(id)
                .execute(self.pool())
                .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Delete a user by ID. Cascades to sessions, user_roles, user_permissions.
    pub async fn delete_user(&self, id: UserId) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_users WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// List all users ordered by `created_at ASC`. Returns User with `password_hash = None`.
    pub async fn list_users(&self) -> Result<Vec<User>, AuthError> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, username, NULL as password_hash, \
             email_verified, is_active, created_at, updated_at, custom_data \
             FROM allowthem_users ORDER BY created_at ASC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Paginated list of users using a `(created_at, id)` keyset cursor.
    ///
    /// Limits are capped at 200. Pass `None` for cursor to start from the beginning.
    /// Results are ordered oldest-first.
    pub async fn list_users_paginated(
        &self,
        limit: u32,
        cursor: Option<&UserCursor>,
    ) -> Result<Vec<UserListEntry>, AuthError> {
        let limit = (limit as i64).min(200);
        match cursor {
            None => sqlx::query_as::<_, UserListEntry>(
                "SELECT u.id, u.email, u.username, u.is_active, \
                 EXISTS (SELECT 1 FROM allowthem_mfa_secrets \
                         WHERE user_id = u.id AND enabled = 1) AS has_mfa, \
                 u.created_at \
                 FROM allowthem_users u \
                 ORDER BY u.created_at ASC, u.id ASC \
                 LIMIT ?",
            )
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .map_err(AuthError::Database),
            Some(c) => {
                let ca = c.created_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
                sqlx::query_as::<_, UserListEntry>(
                    "SELECT u.id, u.email, u.username, u.is_active, \
                     EXISTS (SELECT 1 FROM allowthem_mfa_secrets \
                             WHERE user_id = u.id AND enabled = 1) AS has_mfa, \
                     u.created_at \
                     FROM allowthem_users u \
                     WHERE (u.created_at > ?1 OR (u.created_at = ?1 AND u.id > ?2)) \
                     ORDER BY u.created_at ASC, u.id ASC \
                     LIMIT ?3",
                )
                .bind(&ca)
                .bind(c.id)
                .bind(limit)
                .fetch_all(self.pool())
                .await
                .map_err(AuthError::Database)
            }
        }
    }

    /// Search and filter users with pagination.
    ///
    /// Builds a dynamic query with optional search term (matched against
    /// email and username via LIKE), status filter, and MFA filter.
    /// Returns matching users with their MFA enrollment status.
    pub async fn search_users(
        &self,
        params: SearchUsersParams<'_>,
    ) -> Result<SearchUsersResult, AuthError> {
        let mut where_clauses: Vec<String> = Vec::new();
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(q) = params.query {
            let trimmed = q.trim();
            if !trimmed.is_empty() {
                let escaped = trimmed
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                let pattern = format!("%{escaped}%");
                where_clauses
                    .push("(u.email LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\')".into());
                bind_values.push(pattern.clone());
                bind_values.push(pattern);
            }
        }

        if let Some(active) = params.is_active {
            where_clauses.push("u.is_active = ?".into());
            bind_values.push(if active { "1".into() } else { "0".into() });
        }

        if let Some(has_mfa) = params.has_mfa {
            let exists = if has_mfa { "EXISTS" } else { "NOT EXISTS" };
            where_clauses.push(format!(
                "{exists} (SELECT 1 FROM allowthem_mfa_secrets WHERE user_id = u.id AND enabled = 1)"
            ));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let count_sql: &'static str = Box::leak(
            format!("SELECT COUNT(*) FROM allowthem_users u {where_sql}").into_boxed_str(),
        );
        let mut count_query = sqlx::query_scalar::<_, i64>(count_sql);
        for val in &bind_values {
            count_query = count_query.bind(val);
        }
        let total = count_query
            .fetch_one(self.pool())
            .await
            .map_err(AuthError::Database)? as u32;

        let data_sql: &'static str = Box::leak(
            format!(
                "SELECT u.id, u.email, u.username, u.is_active, \
                 EXISTS (SELECT 1 FROM allowthem_mfa_secrets \
                         WHERE user_id = u.id AND enabled = 1) as has_mfa, \
                 u.created_at \
                 FROM allowthem_users u {where_sql} \
                 ORDER BY u.created_at ASC \
                 LIMIT ? OFFSET ?"
            )
            .into_boxed_str(),
        );
        let mut data_query = sqlx::query_as::<_, UserListEntry>(data_sql);
        for val in &bind_values {
            data_query = data_query.bind(val);
        }
        data_query = data_query.bind(params.limit).bind(params.offset);

        let users = data_query
            .fetch_all(self.pool())
            .await
            .map_err(AuthError::Database)?;

        Ok(SearchUsersResult { users, total })
    }

    /// Update a user's password. Hashes `new_password` with Argon2id and stores it.
    ///
    /// Returns `AuthError::NotFound` if no user with `id` exists.
    pub async fn update_user_password(
        &self,
        id: UserId,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let pw_hash = hash_password(new_password)?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result = sqlx::query(
            "UPDATE allowthem_users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(&pw_hash)
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Set a user's password hash to NULL.
    ///
    /// Used by admin force-password-reset to invalidate the current password.
    /// The login flow falls back to a dummy hash when `password_hash` is NULL,
    /// so `verify_password` will always fail.
    pub async fn clear_password_hash(&self, id: UserId) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result = sqlx::query(
            "UPDATE allowthem_users SET password_hash = NULL, updated_at = ? WHERE id = ?",
        )
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Get a user's custom data.
    ///
    /// Returns `Err(NotFound)` if no user with `id` exists.
    /// Returns `Ok(None)` if the user exists but has no custom data.
    pub async fn get_custom_data(&self, id: &UserId) -> Result<Option<Value>, AuthError> {
        let row: Option<(Option<Value>,)> =
            sqlx::query_as("SELECT custom_data FROM allowthem_users WHERE id = ?")
                .bind(id)
                .fetch_optional(self.pool())
                .await?;

        match row {
            None => Err(AuthError::NotFound),
            Some((data,)) => Ok(data),
        }
    }

    /// Set a user's custom data. Also updates `updated_at`.
    ///
    /// Returns `Err(NotFound)` if no user with `id` exists.
    pub async fn set_custom_data(&self, id: &UserId, data: &Value) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let result = sqlx::query(
            "UPDATE allowthem_users SET custom_data = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(sqlx::types::Json(data))
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Delete (clear) a user's custom data by setting it to NULL. Also updates `updated_at`.
    ///
    /// Idempotent -- succeeds even if custom data is already NULL.
    pub async fn delete_custom_data(&self, id: &UserId) -> Result<(), AuthError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        sqlx::query("UPDATE allowthem_users SET custom_data = NULL, updated_at = ?1 WHERE id = ?2")
            .bind(&now)
            .bind(id)
            .execute(self.pool())
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{AllowThem, AllowThemBuilder};

    async fn setup() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap()
    }

    async fn make_user(db: &Db, tag: u32) -> crate::types::User {
        let email = Email::new(format!("user{tag}@example.com")).unwrap();
        db.create_user(email, "pw123456", None, None).await.unwrap()
    }

    #[tokio::test]
    async fn user_cursor_encode_decode_roundtrip() {
        let ath = setup().await;
        let db = ath.db();
        let user = make_user(db, 1).await;
        let entries = db.list_users_paginated(10, None).await.unwrap();
        assert_eq!(entries.len(), 1);
        let cursor = UserCursor::from_entry(&entries[0]);
        let encoded = cursor.encode();
        let decoded = UserCursor::decode(&encoded).unwrap();
        assert_eq!(decoded.id, user.id);
    }

    #[tokio::test]
    async fn list_users_paginated_returns_first_page() {
        let ath = setup().await;
        let db = ath.db();
        for i in 0..5 {
            make_user(db, i).await;
        }
        let page = db.list_users_paginated(3, None).await.unwrap();
        assert_eq!(page.len(), 3);
    }

    #[tokio::test]
    async fn list_users_paginated_cursor_advances() {
        let ath = setup().await;
        let db = ath.db();
        for i in 0..5 {
            make_user(db, i + 10).await;
        }
        let page1 = db.list_users_paginated(3, None).await.unwrap();
        assert_eq!(page1.len(), 3);
        let cursor = UserCursor::from_entry(page1.last().unwrap());
        let page2 = db.list_users_paginated(3, Some(&cursor)).await.unwrap();
        assert_eq!(page2.len(), 2);
        assert!(!page2.iter().any(|u| page1.iter().any(|v| v.id == u.id)));
    }
}
