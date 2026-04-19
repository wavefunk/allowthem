use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::{RoleId, UserId};

use crate::handle::Teams;
use crate::types::{OrgId, OrgMembership, OrgMembershipId};

impl Teams {
    pub async fn get_org_membership(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<Option<OrgMembership>, AuthError> {
        sqlx::query_as::<_, OrgMembership>(
            "SELECT id, org_id, user_id, role_id, created_at \
             FROM allowthem_org_members \
             WHERE org_id = ? AND user_id = ?",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn add_org_member(
        &self,
        org_id: OrgId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<OrgMembership, AuthError> {
        let id = OrgMembershipId::new();
        let now = chrono::Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_org_members (id, org_id, user_id, role_id, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(org_id)
        .bind(user_id)
        .bind(role_id)
        .bind(&now_str)
        .execute(self.teams_db().pool())
        .await
        .map_err(|err| {
            if let sqlx::Error::Database(ref db_err) = err {
                let msg = db_err.message();
                if msg.contains("UNIQUE constraint failed") {
                    return AuthError::Conflict("user is already a member of this org".into());
                }
            }
            AuthError::Database(err)
        })?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgMemberAdded,
                Some(&user_id),
                Some(&org_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(OrgMembership {
            id,
            org_id,
            user_id,
            role_id,
            created_at: now,
        })
    }

    pub async fn remove_org_member(&self, org_id: OrgId, user_id: UserId) -> Result<(), AuthError> {
        // Verify the user is actually a member and they aren't the owner.
        let org = sqlx::query_as::<_, crate::types::Org>(
            "SELECT id, name, slug, owner_id, created_at, updated_at \
             FROM allowthem_orgs WHERE id = ?",
        )
        .bind(org_id)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)?
        .ok_or(AuthError::NotFound)?;

        if org.owner_id == user_id {
            return Err(AuthError::Forbidden("cannot remove org owner".into()));
        }

        let pool = self.teams_db().pool();
        let mut tx = pool.begin().await.map_err(AuthError::Database)?;

        // Remove from all teams within this org first.
        sqlx::query(
            "DELETE FROM allowthem_team_members \
             WHERE user_id = ? AND team_id IN \
             (SELECT id FROM allowthem_teams WHERE org_id = ?)",
        )
        .bind(user_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        let result =
            sqlx::query("DELETE FROM allowthem_org_members WHERE org_id = ? AND user_id = ?")
                .bind(org_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(AuthError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        tx.commit().await.map_err(AuthError::Database)?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgMemberRemoved,
                Some(&user_id),
                Some(&org_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(())
    }

    pub async fn update_org_member_role(
        &self,
        org_id: OrgId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), AuthError> {
        let result = sqlx::query(
            "UPDATE allowthem_org_members SET role_id = ? \
             WHERE org_id = ? AND user_id = ?",
        )
        .bind(role_id)
        .bind(org_id)
        .bind(user_id)
        .execute(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgMemberRoleChanged,
                Some(&user_id),
                Some(&org_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(())
    }

    pub async fn list_org_members(&self, org_id: OrgId) -> Result<Vec<OrgMembership>, AuthError> {
        sqlx::query_as::<_, OrgMembership>(
            "SELECT id, org_id, user_id, role_id, created_at \
             FROM allowthem_org_members \
             WHERE org_id = ? \
             ORDER BY created_at",
        )
        .bind(org_id)
        .fetch_all(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn transfer_ownership(
        &self,
        org_id: OrgId,
        new_owner_id: UserId,
    ) -> Result<(), AuthError> {
        // New owner must already be a member of the org.
        let membership = self.get_org_membership(org_id, new_owner_id).await?;
        if membership.is_none() {
            return Err(AuthError::Forbidden(
                "new owner must be a member of the org".into(),
            ));
        }

        let now_str = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let result =
            sqlx::query("UPDATE allowthem_orgs SET owner_id = ?, updated_at = ? WHERE id = ?")
                .bind(new_owner_id)
                .bind(&now_str)
                .bind(org_id)
                .execute(self.teams_db().pool())
                .await
                .map_err(AuthError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgOwnershipTransferred,
                Some(&new_owner_id),
                Some(&org_id.to_string()),
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
    use crate::types::OrgSlug;

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

    // Helper: creates a second user and a member role on the same db as `teams`.
    async fn add_second_user(teams: &Teams, email_str: &str) -> UserId {
        // We can use the core_db on the Teams handle directly.
        let email = allowthem_core::Email::new(email_str.into()).unwrap();
        let user = teams
            .core_db()
            .create_user(email, "password456", None, None)
            .await
            .unwrap();
        user.id
    }

    async fn member_role(teams: &Teams) -> RoleId {
        teams
            .core_db()
            .create_role(&RoleName::new("member"), None)
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn create_org_adds_owner_as_member() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("owner-as-member").unwrap();
        let org = teams
            .create_org("Owner Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let membership = teams
            .get_org_membership(org.id, owner_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(membership.user_id, owner_id);
        assert_eq!(membership.org_id, org.id);
    }

    #[tokio::test]
    async fn add_and_list_org_members() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("list-members").unwrap();
        let org = teams
            .create_org("List Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let member_id = add_second_user(&teams, "member@example.com").await;
        let m_role = member_role(&teams).await;
        teams
            .add_org_member(org.id, member_id, m_role)
            .await
            .unwrap();

        let members = teams.list_org_members(org.id).await.unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|m| m.user_id == owner_id));
        assert!(members.iter().any(|m| m.user_id == member_id));
    }

    #[tokio::test]
    async fn add_duplicate_member_fails() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("dupe-member").unwrap();
        let org = teams
            .create_org("Dupe Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let member_id = add_second_user(&teams, "dupe@example.com").await;
        let m_role = member_role(&teams).await;
        teams
            .add_org_member(org.id, member_id, m_role)
            .await
            .unwrap();

        let err = teams
            .add_org_member(org.id, member_id, m_role)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Conflict(_)));
    }

    #[tokio::test]
    async fn remove_org_member() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("remove-member").unwrap();
        let org = teams
            .create_org("Remove Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let member_id = add_second_user(&teams, "removeme@example.com").await;
        let m_role = member_role(&teams).await;
        teams
            .add_org_member(org.id, member_id, m_role)
            .await
            .unwrap();

        teams.remove_org_member(org.id, member_id).await.unwrap();

        let membership = teams.get_org_membership(org.id, member_id).await.unwrap();
        assert!(membership.is_none());
    }

    #[tokio::test]
    async fn cannot_remove_owner() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("cant-remove-owner").unwrap();
        let org = teams
            .create_org("Owner Protected Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let err = teams.remove_org_member(org.id, owner_id).await.unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }

    #[tokio::test]
    async fn update_member_role() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("update-role").unwrap();
        let org = teams
            .create_org("Role Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let member_id = add_second_user(&teams, "roleupdate@example.com").await;
        let m_role = member_role(&teams).await;
        teams
            .add_org_member(org.id, member_id, m_role)
            .await
            .unwrap();

        let new_role = teams
            .core_db()
            .create_role(&RoleName::new("admin"), None)
            .await
            .unwrap();

        teams
            .update_org_member_role(org.id, member_id, new_role.id)
            .await
            .unwrap();

        let updated = teams
            .get_org_membership(org.id, member_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.role_id, new_role.id);
    }

    #[tokio::test]
    async fn list_orgs_for_user() {
        let (teams, owner_id, role_id) = setup().await;
        let slug1 = OrgSlug::new("user-org-one").unwrap();
        let slug2 = OrgSlug::new("user-org-two").unwrap();
        teams
            .create_org("Org One", &slug1, owner_id, role_id)
            .await
            .unwrap();
        teams
            .create_org("Org Two", &slug2, owner_id, role_id)
            .await
            .unwrap();

        let orgs = teams.list_orgs_for_user(owner_id).await.unwrap();
        assert_eq!(orgs.len(), 2);
    }

    #[tokio::test]
    async fn transfer_ownership() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("transfer-ownership").unwrap();
        let org = teams
            .create_org("Transfer Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let new_owner_id = add_second_user(&teams, "newowner@example.com").await;
        let m_role = member_role(&teams).await;
        teams
            .add_org_member(org.id, new_owner_id, m_role)
            .await
            .unwrap();

        teams
            .transfer_ownership(org.id, new_owner_id)
            .await
            .unwrap();

        let updated_org = teams.get_org(org.id).await.unwrap().unwrap();
        assert_eq!(updated_org.owner_id, new_owner_id);
    }

    #[tokio::test]
    async fn transfer_to_non_member_fails() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("transfer-non-member").unwrap();
        let org = teams
            .create_org("Non-member Transfer Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        // Create a user who is NOT a member of the org.
        let non_member_id = add_second_user(&teams, "nonmember@example.com").await;

        let err = teams
            .transfer_ownership(org.id, non_member_id)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }
}
