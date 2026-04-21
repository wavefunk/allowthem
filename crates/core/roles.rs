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

    /// Update a role's name and description. Returns the updated role.
    ///
    /// Returns `AuthError::NotFound` if no role with `id` exists.
    /// Returns `AuthError::Conflict` if `name` is already taken by another role.
    pub async fn update_role(
        &self,
        id: &RoleId,
        name: &RoleName,
        description: Option<&str>,
    ) -> Result<Role, AuthError> {
        sqlx::query_as::<_, Role>(
            "UPDATE allowthem_roles SET name = ?1, description = ?2 WHERE id = ?3 \
             RETURNING id, name, description, created_at",
        )
        .bind(name)
        .bind(description)
        .bind(*id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_unique_violation)?
        .ok_or(AuthError::NotFound)
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

    /// Create each named role if it does not already exist.
    ///
    /// Returns roles in the same order as `names`. Idempotent: existing roles
    /// are fetched, not re-created. Duplicates within `names` are allowed; each
    /// name is resolved independently.
    pub async fn bootstrap_roles(&self, names: &[&str]) -> Result<Vec<Role>, AuthError> {
        let mut roles = Vec::with_capacity(names.len());
        for &name in names {
            let rn = RoleName::new(name);
            let role = match self.get_role_by_name(&rn).await? {
                Some(r) => r,
                None => self.create_role(&rn, None).await?,
            };
            roles.push(role);
        }
        Ok(roles)
    }

    /// Return the name of the first role in `hierarchy` that the user holds.
    ///
    /// `hierarchy[0]` is treated as the highest role. Returns `None` if the user
    /// holds none of the listed roles. An empty `hierarchy` always returns `None`.
    pub async fn resolve_highest_role(
        &self,
        user_id: &UserId,
        hierarchy: &[&str],
    ) -> Result<Option<String>, AuthError> {
        for &name in hierarchy {
            let rn = RoleName::new(name);
            if self.has_role(user_id, &rn).await? {
                return Ok(Some(name.to_owned()));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{AllowThem, AllowThemBuilder};
    use crate::types::Email;

    async fn setup() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn update_role_changes_name_and_description() {
        let ath = setup().await;
        let db = ath.db();
        let rn = RoleName::new("old-name");
        let role = db.create_role(&rn, Some("old desc")).await.unwrap();
        let new_name = RoleName::new("new-name");
        let updated = db
            .update_role(&role.id, &new_name, Some("new desc"))
            .await
            .unwrap();
        assert_eq!(updated.name.as_str(), "new-name");
        assert_eq!(updated.description.as_deref(), Some("new desc"));
        assert_eq!(updated.id, role.id);
    }

    #[tokio::test]
    async fn update_role_not_found_returns_error() {
        let ath = setup().await;
        let db = ath.db();
        let missing = RoleId::new();
        let name = RoleName::new("x");
        let err = db.update_role(&missing, &name, None).await.unwrap_err();
        assert!(matches!(err, AuthError::NotFound));
    }

    #[tokio::test]
    async fn bootstrap_roles_creates_missing_roles() {
        let ath = setup().await;
        let db = ath.db();
        let roles = db.bootstrap_roles(&["admin", "editor"]).await.unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].name.as_str(), "admin");
        assert_eq!(roles[1].name.as_str(), "editor");
    }

    #[tokio::test]
    async fn bootstrap_roles_idempotent() {
        let ath = setup().await;
        let db = ath.db();
        let first = db.bootstrap_roles(&["admin", "editor"]).await.unwrap();
        let second = db.bootstrap_roles(&["admin", "editor"]).await.unwrap();
        assert_eq!(first[0].id, second[0].id);
        assert_eq!(first[1].id, second[1].id);
    }

    #[tokio::test]
    async fn bootstrap_roles_returns_in_input_order() {
        let ath = setup().await;
        let db = ath.db();
        let roles = db
            .bootstrap_roles(&["viewer", "admin", "editor"])
            .await
            .unwrap();
        assert_eq!(roles[0].name.as_str(), "viewer");
        assert_eq!(roles[1].name.as_str(), "admin");
        assert_eq!(roles[2].name.as_str(), "editor");
    }

    #[tokio::test]
    async fn bootstrap_roles_mixed_existing_and_new() {
        let ath = setup().await;
        let db = ath.db();
        let rn = RoleName::new("admin");
        db.create_role(&rn, None).await.unwrap();
        let roles = db.bootstrap_roles(&["admin", "viewer"]).await.unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].name.as_str(), "admin");
        assert_eq!(roles[1].name.as_str(), "viewer");
    }

    #[tokio::test]
    async fn bootstrap_roles_empty_slice_returns_empty_vec() {
        let ath = setup().await;
        let db = ath.db();
        let roles = db.bootstrap_roles(&[]).await.unwrap();
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn resolve_highest_role_returns_first_match() {
        let ath = setup().await;
        let db = ath.db();
        let email = Email::new("user@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let roles = db
            .bootstrap_roles(&["admin", "editor", "viewer"])
            .await
            .unwrap();
        db.assign_role(&user.id, &roles[1].id).await.unwrap(); // editor
        db.assign_role(&user.id, &roles[2].id).await.unwrap(); // viewer
        let result = db
            .resolve_highest_role(&user.id, &["admin", "editor", "viewer"])
            .await
            .unwrap();
        assert_eq!(result, Some("editor".to_owned()));
    }

    #[tokio::test]
    async fn resolve_highest_role_returns_none_when_no_roles() {
        let ath = setup().await;
        let db = ath.db();
        let email = Email::new("noroles@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let result = db
            .resolve_highest_role(&user.id, &["admin", "editor"])
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_highest_role_returns_none_for_empty_hierarchy() {
        let ath = setup().await;
        let db = ath.db();
        let email = Email::new("emptyhier@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let result = db.resolve_highest_role(&user.id, &[]).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_highest_role_returns_highest_when_user_has_all() {
        let ath = setup().await;
        let db = ath.db();
        let email = Email::new("allroles@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let roles = db
            .bootstrap_roles(&["admin", "editor", "viewer"])
            .await
            .unwrap();
        for role in &roles {
            db.assign_role(&user.id, &role.id).await.unwrap();
        }
        let result = db
            .resolve_highest_role(&user.id, &["admin", "editor", "viewer"])
            .await
            .unwrap();
        assert_eq!(result, Some("admin".to_owned()));
    }

    #[tokio::test]
    async fn resolve_highest_role_only_considers_listed_roles() {
        let ath = setup().await;
        let db = ath.db();
        let email = Email::new("unlisted@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let rn = RoleName::new("superuser");
        let role = db.create_role(&rn, None).await.unwrap();
        db.assign_role(&user.id, &role.id).await.unwrap();
        let result = db
            .resolve_highest_role(&user.id, &["admin", "editor"])
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
