use chrono::Utc;

use crate::db::Db;
use crate::error::AuthError;
use crate::password::hash_password;
use crate::types::{Email, User, UserId, Username};

/// Map a SQLite UNIQUE constraint violation to `AuthError::Conflict`.
///
/// SQLite UNIQUE violations include the constraint name in the message,
/// e.g. "UNIQUE constraint failed: allowthem_users.email".
fn map_unique_violation(err: sqlx::Error) -> AuthError {
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

impl Db {
    /// Create a user with email, plaintext password, and optional username.
    ///
    /// Hashes the password with Argon2id (via `password::hash_password`).
    /// Returns the created User (without password_hash in the returned struct).
    pub async fn create_user(
        &self,
        email: Email,
        password: &str,
        username: Option<Username>,
    ) -> Result<User, AuthError> {
        let id = UserId::new();
        let pw_hash = hash_password(password)?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_users \
             (id, email, username, password_hash, email_verified, is_active, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, 0, 1, ?5, ?5)",
        )
        .bind(id)
        .bind(&email)
        .bind(&username)
        .bind(&pw_hash)
        .bind(&now)
        .execute(self.pool())
        .await
        .map_err(map_unique_violation)?;

        self.get_user(id).await
    }

    /// Look up a user by ID. Returns User with password_hash = None.
    pub async fn get_user(&self, id: UserId) -> Result<User, AuthError> {
        sqlx::query_as::<_, User>(
            "SELECT id, email, username, NULL as password_hash, \
             email_verified, is_active, created_at, updated_at \
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
             email_verified, is_active, created_at, updated_at \
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
             email_verified, is_active, created_at, updated_at \
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
             email_verified, is_active, created_at, updated_at \
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
             email_verified, is_active, created_at, updated_at \
             FROM allowthem_users ORDER BY created_at ASC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Update a user's password. Hashes `new_password` with Argon2id and stores it.
    ///
    /// Returns `AuthError::NotFound` if no user with `id` exists.
    pub async fn update_user_password(&self, id: UserId, new_password: &str) -> Result<(), AuthError> {
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
}
