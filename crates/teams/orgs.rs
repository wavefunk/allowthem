use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::{RoleId, UserId};

use crate::handle::Teams;
use crate::types::{Org, OrgId, OrgMembershipId, OrgSlug};

fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") {
            if msg.contains("slug") {
                return AuthError::Conflict("org slug already exists".into());
            }
            return AuthError::Conflict(msg.to_string());
        }
    }
    AuthError::Database(err)
}

impl Teams {
    pub async fn create_org(
        &self,
        name: &str,
        slug: &OrgSlug,
        owner_id: UserId,
        owner_role_id: RoleId,
    ) -> Result<Org, AuthError> {
        let pool = self.teams_db().pool();
        let id = OrgId::new();
        let membership_id = OrgMembershipId::new();
        let now = chrono::Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let mut tx = pool.begin().await.map_err(AuthError::Database)?;

        sqlx::query(
            "INSERT INTO allowthem_orgs (id, name, slug, owner_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(slug)
        .bind(owner_id)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;

        sqlx::query(
            "INSERT INTO allowthem_org_members (id, org_id, user_id, role_id, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(membership_id)
        .bind(id)
        .bind(owner_id)
        .bind(owner_role_id)
        .bind(&now_str)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        tx.commit().await.map_err(AuthError::Database)?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgCreated,
                Some(&owner_id),
                Some(&id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(Org {
            id,
            name: name.to_owned(),
            slug: slug.clone(),
            owner_id,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_org(&self, id: OrgId) -> Result<Option<Org>, AuthError> {
        sqlx::query_as::<_, Org>(
            "SELECT id, name, slug, owner_id, created_at, updated_at \
             FROM allowthem_orgs WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn get_org_by_slug(&self, slug: &OrgSlug) -> Result<Option<Org>, AuthError> {
        sqlx::query_as::<_, Org>(
            "SELECT id, name, slug, owner_id, created_at, updated_at \
             FROM allowthem_orgs WHERE slug = ?",
        )
        .bind(slug)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn list_orgs_for_user(&self, user_id: UserId) -> Result<Vec<Org>, AuthError> {
        sqlx::query_as::<_, Org>(
            "SELECT o.id, o.name, o.slug, o.owner_id, o.created_at, o.updated_at \
             FROM allowthem_orgs o \
             JOIN allowthem_org_members m ON m.org_id = o.id \
             WHERE m.user_id = ? \
             ORDER BY o.created_at",
        )
        .bind(user_id)
        .fetch_all(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn update_org(
        &self,
        id: OrgId,
        name: &str,
        slug: &OrgSlug,
    ) -> Result<Org, AuthError> {
        let now_str = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let result = sqlx::query(
            "UPDATE allowthem_orgs SET name = ?, slug = ?, updated_at = ? WHERE id = ?",
        )
        .bind(name)
        .bind(slug)
        .bind(&now_str)
        .bind(id)
        .execute(self.teams_db().pool())
        .await
        .map_err(map_unique_violation)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgUpdated,
                None,
                Some(&id.to_string()),
                None,
                None,
                None,
            )
            .await;

        self.get_org(id).await?.ok_or(AuthError::NotFound)
    }

    pub async fn delete_org(&self, id: OrgId) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_orgs WHERE id = ?")
            .bind(id)
            .execute(self.teams_db().pool())
            .await
            .map_err(AuthError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgDeleted,
                None,
                Some(&id.to_string()),
                None,
                None,
                None,
            )
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use allowthem_core::AllowThemBuilder;
    use allowthem_core::types::RoleName;

    use super::*;
    use crate::Teams;

    async fn setup() -> (Teams, UserId, RoleId) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let teams = Teams::builder()
            .with_pool(ath.db().pool().clone())
            .build()
            .await
            .unwrap();
        let email = allowthem_core::Email::new("owner@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let role = ath
            .db()
            .create_role(&RoleName::new("owner"), None)
            .await
            .unwrap();
        (teams, user.id, role.id)
    }

    #[tokio::test]
    async fn create_and_get_org() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("acme").unwrap();
        let org = teams
            .create_org("Acme Corp", &slug, owner_id, role_id)
            .await
            .unwrap();

        assert_eq!(org.name, "Acme Corp");
        assert_eq!(org.slug, slug);
        assert_eq!(org.owner_id, owner_id);

        let fetched = teams.get_org(org.id).await.unwrap().unwrap();
        assert_eq!(fetched.id, org.id);
        assert_eq!(fetched.name, org.name);
    }

    #[tokio::test]
    async fn create_org_duplicate_slug_fails() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("dupe-slug").unwrap();
        teams
            .create_org("First Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let err = teams
            .create_org("Second Org", &slug, owner_id, role_id)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Conflict(_)));
    }

    #[tokio::test]
    async fn get_org_by_slug() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("find-by-slug").unwrap();
        let org = teams
            .create_org("By Slug Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let found = teams.get_org_by_slug(&slug).await.unwrap().unwrap();
        assert_eq!(found.id, org.id);

        let missing_slug = OrgSlug::new("no-such-slug").unwrap();
        let none = teams.get_org_by_slug(&missing_slug).await.unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn update_org() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("update-me").unwrap();
        let org = teams
            .create_org("Original Name", &slug, owner_id, role_id)
            .await
            .unwrap();

        let new_slug = OrgSlug::new("updated-slug").unwrap();
        let updated = teams
            .update_org(org.id, "Updated Name", &new_slug)
            .await
            .unwrap();

        assert_eq!(updated.name, "Updated Name");
        assert_eq!(updated.slug, new_slug);
    }

    #[tokio::test]
    async fn delete_org() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("delete-me").unwrap();
        let org = teams
            .create_org("To Delete", &slug, owner_id, role_id)
            .await
            .unwrap();

        teams.delete_org(org.id).await.unwrap();

        let result = teams.get_org(org.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_org_returns_not_found() {
        let (teams, _, _) = setup().await;
        let missing_id = OrgId::new();
        let err = teams.delete_org(missing_id).await.unwrap_err();
        assert!(matches!(err, AuthError::NotFound));
    }
}
