use crate::db::Db;
use crate::error::AuthError;
use crate::types::{Role, RoleId, RoleName, UserId};

/// Map a SQLite UNIQUE constraint violation on `allowthem_roles.name` to
/// `AuthError::Conflict`. Other errors pass through as `AuthError::Database`.
fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") && msg.contains("name") {
            return AuthError::Conflict("role name already exists".into());
        }
    }
    AuthError::Database(err)
}

impl Db {
    /// Create a role with a unique name and optional description.
    pub async fn create_role(
        &self,
        name: &RoleName,
        description: Option<&str>,
    ) -> Result<Role, AuthError> {
        let id = RoleId::new();
        sqlx::query_as::<_, Role>(
            "INSERT INTO allowthem_roles (id, name, description) \
             VALUES (?, ?, ?) \
             RETURNING id, name, description, created_at",
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .fetch_one(self.pool())
        .await
        .map_err(map_unique_violation)
    }

    /// Get a role by ID. Returns `None` if not found.
    pub async fn get_role(&self, id: &RoleId) -> Result<Option<Role>, AuthError> {
        sqlx::query_as::<_, Role>(
            "SELECT id, name, description, created_at FROM allowthem_roles WHERE id = ?",
        )
        .bind(*id)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Get a role by name. Returns `None` if not found.
    pub async fn get_role_by_name(&self, name: &RoleName) -> Result<Option<Role>, AuthError> {
        sqlx::query_as::<_, Role>(
            "SELECT id, name, description, created_at FROM allowthem_roles WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// List all roles, ordered by creation time.
    pub async fn list_roles(&self) -> Result<Vec<Role>, AuthError> {
        sqlx::query_as::<_, Role>(
            "SELECT id, name, description, created_at FROM allowthem_roles ORDER BY created_at",
        )
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Delete a role by ID. Returns `true` if a row was deleted, `false` if not found.
    ///
    /// Cascades to `allowthem_user_roles` and `allowthem_role_permissions`.
    pub async fn delete_role(&self, id: &RoleId) -> Result<bool, AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_roles WHERE id = ?")
            .bind(*id)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Assign a role to a user. Silently succeeds if already assigned (idempotent).
    pub async fn assign_role(&self, user_id: &UserId, role_id: &RoleId) -> Result<(), AuthError> {
        sqlx::query("INSERT OR IGNORE INTO allowthem_user_roles (user_id, role_id) VALUES (?, ?)")
            .bind(*user_id)
            .bind(*role_id)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(())
    }

    /// Unassign a role from a user. Returns `true` if removed, `false` if the assignment
    /// did not exist.
    pub async fn unassign_role(
        &self,
        user_id: &UserId,
        role_id: &RoleId,
    ) -> Result<bool, AuthError> {
        let result =
            sqlx::query("DELETE FROM allowthem_user_roles WHERE user_id = ? AND role_id = ?")
                .bind(*user_id)
                .bind(*role_id)
                .execute(self.pool())
                .await
                .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Check whether a user has a specific role by name.
    pub async fn has_role(
        &self,
        user_id: &UserId,
        role_name: &RoleName,
    ) -> Result<bool, AuthError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) \
             FROM allowthem_user_roles ur \
             JOIN allowthem_roles r ON r.id = ur.role_id \
             WHERE ur.user_id = ? AND r.name = ?",
        )
        .bind(*user_id)
        .bind(role_name)
        .fetch_one(self.pool())
        .await
        .map_err(AuthError::Database)?;
        Ok(count > 0)
    }

    /// Return all roles assigned to a user, ordered by creation time.
    pub async fn get_user_roles(&self, user_id: &UserId) -> Result<Vec<Role>, AuthError> {
        sqlx::query_as::<_, Role>(
            "SELECT r.id, r.name, r.description, r.created_at \
             FROM allowthem_roles r \
             JOIN allowthem_user_roles ur ON ur.role_id = r.id \
             WHERE ur.user_id = ? \
             ORDER BY r.created_at",
        )
        .bind(*user_id)
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }
}
