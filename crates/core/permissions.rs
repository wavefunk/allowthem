use crate::db::Db;
use crate::error::AuthError;
use crate::types::{Permission, PermissionId, PermissionName, RoleId, UserId};

/// Map a SQLite UNIQUE constraint violation on `allowthem_permissions.name` to
/// `AuthError::Conflict`. Other errors pass through as `AuthError::Database`.
fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") && msg.contains("name") {
            return AuthError::Conflict("permission name already exists".into());
        }
    }
    AuthError::Database(err)
}

impl Db {
    /// Create a permission with a unique name and optional description.
    pub async fn create_permission(
        &self,
        name: &PermissionName,
        description: Option<&str>,
    ) -> Result<Permission, AuthError> {
        let id = PermissionId::new();
        sqlx::query_as::<_, Permission>(
            "INSERT INTO allowthem_permissions (id, name, description) \
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

    /// Get a permission by ID. Returns `None` if not found.
    pub async fn get_permission(&self, id: &PermissionId) -> Result<Option<Permission>, AuthError> {
        sqlx::query_as::<_, Permission>(
            "SELECT id, name, description, created_at FROM allowthem_permissions WHERE id = ?",
        )
        .bind(*id)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Get a permission by name. Returns `None` if not found.
    pub async fn get_permission_by_name(
        &self,
        name: &PermissionName,
    ) -> Result<Option<Permission>, AuthError> {
        sqlx::query_as::<_, Permission>(
            "SELECT id, name, description, created_at FROM allowthem_permissions WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// List all permissions, ordered by creation time.
    pub async fn list_permissions(&self) -> Result<Vec<Permission>, AuthError> {
        sqlx::query_as::<_, Permission>(
            "SELECT id, name, description, created_at \
             FROM allowthem_permissions \
             ORDER BY created_at",
        )
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Delete a permission by ID. Returns `true` if a row was deleted, `false` if not found.
    ///
    /// Cascades to `allowthem_role_permissions` and `allowthem_user_permissions`.
    pub async fn delete_permission(&self, id: &PermissionId) -> Result<bool, AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_permissions WHERE id = ?")
            .bind(*id)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Assign a permission to a role. Idempotent — silently succeeds if already assigned.
    pub async fn assign_permission_to_role(
        &self,
        role_id: &RoleId,
        permission_id: &PermissionId,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT OR IGNORE INTO allowthem_role_permissions (role_id, permission_id) \
             VALUES (?, ?)",
        )
        .bind(*role_id)
        .bind(*permission_id)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;
        Ok(())
    }

    /// Assign a permission directly to a user. Idempotent — silently succeeds if already assigned.
    pub async fn assign_permission_to_user(
        &self,
        user_id: &UserId,
        permission_id: &PermissionId,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT OR IGNORE INTO allowthem_user_permissions (user_id, permission_id) \
             VALUES (?, ?)",
        )
        .bind(*user_id)
        .bind(*permission_id)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;
        Ok(())
    }

    /// Unassign a permission from a role. Returns `true` if removed, `false` if not found.
    pub async fn unassign_permission_from_role(
        &self,
        role_id: &RoleId,
        permission_id: &PermissionId,
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(
            "DELETE FROM allowthem_role_permissions WHERE role_id = ? AND permission_id = ?",
        )
        .bind(*role_id)
        .bind(*permission_id)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Unassign a permission from a user. Returns `true` if removed, `false` if not found.
    pub async fn unassign_permission_from_user(
        &self,
        user_id: &UserId,
        permission_id: &PermissionId,
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(
            "DELETE FROM allowthem_user_permissions WHERE user_id = ? AND permission_id = ?",
        )
        .bind(*user_id)
        .bind(*permission_id)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Check whether a user has a permission by name via either path:
    /// direct user assignment or any of the user's roles.
    pub async fn has_permission(
        &self,
        user_id: &UserId,
        perm_name: &PermissionName,
    ) -> Result<bool, AuthError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1
               FROM allowthem_user_permissions up
               JOIN allowthem_permissions p ON p.id = up.permission_id
               WHERE up.user_id = ? AND p.name = ?
               UNION ALL
               SELECT 1
               FROM allowthem_role_permissions rp
               JOIN allowthem_user_roles ur ON ur.role_id = rp.role_id
               JOIN allowthem_permissions p ON p.id = rp.permission_id
               WHERE ur.user_id = ? AND p.name = ?
             )",
        )
        .bind(*user_id)
        .bind(perm_name)
        .bind(*user_id)
        .bind(perm_name)
        .fetch_one(self.pool())
        .await
        .map_err(AuthError::Database)?;
        Ok(exists)
    }

    /// Return all permissions for a user — both directly assigned and via roles —
    /// deduplicated and ordered by name.
    pub async fn get_user_permissions(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<Permission>, AuthError> {
        sqlx::query_as::<_, Permission>(
            "SELECT DISTINCT p.id, p.name, p.description, p.created_at
             FROM allowthem_permissions p
             WHERE p.id IN (
               SELECT permission_id FROM allowthem_user_permissions WHERE user_id = ?
               UNION
               SELECT rp.permission_id
               FROM allowthem_role_permissions rp
               JOIN allowthem_user_roles ur ON ur.role_id = rp.role_id
               WHERE ur.user_id = ?
             )
             ORDER BY p.name",
        )
        .bind(*user_id)
        .bind(*user_id)
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }
}
