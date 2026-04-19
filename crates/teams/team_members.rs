use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::{RoleId, UserId};

use crate::handle::Teams;
use crate::types::{TeamId, TeamMembership, TeamMembershipId};

impl Teams {
    pub async fn add_team_member(
        &self,
        team_id: TeamId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<TeamMembership, AuthError> {
        // Look up team to get org_id for membership check.
        let team = self
            .get_team(team_id)
            .await?
            .ok_or(AuthError::NotFound)?;

        // User must already be an org member.
        let membership = self.get_org_membership(team.org_id, user_id).await?;
        if membership.is_none() {
            return Err(AuthError::Forbidden(
                "user must be an org member before joining a team".into(),
            ));
        }

        let id = TeamMembershipId::new();
        let now = chrono::Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_team_members (id, team_id, user_id, role_id, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(team_id)
        .bind(user_id)
        .bind(role_id)
        .bind(&now_str)
        .execute(self.teams_db().pool())
        .await
        .map_err(|err| {
            if let sqlx::Error::Database(ref db_err) = err {
                let msg = db_err.message();
                if msg.contains("UNIQUE constraint failed") {
                    return AuthError::Conflict(
                        "user is already a member of this team".into(),
                    );
                }
            }
            AuthError::Database(err)
        })?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::TeamMemberAdded,
                Some(&user_id),
                Some(&team_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(TeamMembership {
            id,
            team_id,
            user_id,
            role_id,
            created_at: now,
        })
    }

    pub async fn remove_team_member(
        &self,
        team_id: TeamId,
        user_id: UserId,
    ) -> Result<(), AuthError> {
        let result =
            sqlx::query("DELETE FROM allowthem_team_members WHERE team_id = ? AND user_id = ?")
                .bind(team_id)
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
                AuditEvent::TeamMemberRemoved,
                Some(&user_id),
                Some(&team_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(())
    }

    pub async fn update_team_member_role(
        &self,
        team_id: TeamId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), AuthError> {
        let result = sqlx::query(
            "UPDATE allowthem_team_members SET role_id = ? \
             WHERE team_id = ? AND user_id = ?",
        )
        .bind(role_id)
        .bind(team_id)
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
                AuditEvent::TeamMemberRoleChanged,
                Some(&user_id),
                Some(&team_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(())
    }

    pub async fn list_team_members(
        &self,
        team_id: TeamId,
    ) -> Result<Vec<TeamMembership>, AuthError> {
        sqlx::query_as::<_, TeamMembership>(
            "SELECT id, team_id, user_id, role_id, created_at \
             FROM allowthem_team_members \
             WHERE team_id = ? \
             ORDER BY created_at",
        )
        .bind(team_id)
        .fetch_all(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }
}

#[cfg(test)]
mod tests {
    use allowthem_core::types::RoleName;
    use allowthem_core::AllowThemBuilder;

    use super::*;
    use crate::types::{OrgId, OrgSlug, TeamSlug};
    use crate::Teams;

    async fn setup() -> (Teams, OrgId, UserId, RoleId) {
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
            .create_role(&RoleName::new("member"), None)
            .await
            .unwrap();
        let slug = OrgSlug::new("test-org").unwrap();
        let org = teams
            .create_org("Test Org", &slug, user.id, role.id)
            .await
            .unwrap();
        (teams, org.id, user.id, role.id)
    }

    async fn add_second_user(teams: &Teams, email_str: &str) -> UserId {
        let email = allowthem_core::Email::new(email_str.into()).unwrap();
        teams
            .core_db()
            .create_user(email, "password456", None, None)
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn add_team_member_requires_org_membership() {
        let (teams, org_id, _, role_id) = setup().await;
        let team_slug = TeamSlug::new("eng").unwrap();
        let team = teams
            .create_team(org_id, "Engineering", &team_slug)
            .await
            .unwrap();

        // Create a user who is NOT an org member.
        let outsider = add_second_user(&teams, "outsider@example.com").await;

        let err = teams
            .add_team_member(team.id, outsider, role_id)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }

    #[tokio::test]
    async fn add_and_list_team_members() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let team_slug = TeamSlug::new("design").unwrap();
        let team = teams
            .create_team(org_id, "Design", &team_slug)
            .await
            .unwrap();

        teams
            .add_team_member(team.id, owner_id, role_id)
            .await
            .unwrap();

        let members = teams.list_team_members(team.id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].user_id, owner_id);
    }

    #[tokio::test]
    async fn add_duplicate_team_member_fails() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let team_slug = TeamSlug::new("dupe-team").unwrap();
        let team = teams
            .create_team(org_id, "Dupe Team", &team_slug)
            .await
            .unwrap();

        teams
            .add_team_member(team.id, owner_id, role_id)
            .await
            .unwrap();

        let err = teams
            .add_team_member(team.id, owner_id, role_id)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Conflict(_)));
    }

    #[tokio::test]
    async fn remove_team_member() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let team_slug = TeamSlug::new("remove-team").unwrap();
        let team = teams
            .create_team(org_id, "Remove Team", &team_slug)
            .await
            .unwrap();

        teams
            .add_team_member(team.id, owner_id, role_id)
            .await
            .unwrap();

        teams
            .remove_team_member(team.id, owner_id)
            .await
            .unwrap();

        let members = teams.list_team_members(team.id).await.unwrap();
        assert!(members.is_empty());
    }

    #[tokio::test]
    async fn remove_nonexistent_team_member_fails() {
        let (teams, org_id, _, _) = setup().await;
        let team_slug = TeamSlug::new("ghost-team").unwrap();
        let team = teams
            .create_team(org_id, "Ghost Team", &team_slug)
            .await
            .unwrap();

        let ghost = add_second_user(&teams, "ghost@example.com").await;

        let err = teams
            .remove_team_member(team.id, ghost)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::NotFound));
    }

    #[tokio::test]
    async fn update_team_member_role() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let team_slug = TeamSlug::new("role-team").unwrap();
        let team = teams
            .create_team(org_id, "Role Team", &team_slug)
            .await
            .unwrap();

        teams
            .add_team_member(team.id, owner_id, role_id)
            .await
            .unwrap();

        let new_role = teams
            .core_db()
            .create_role(&RoleName::new("lead"), None)
            .await
            .unwrap();

        teams
            .update_team_member_role(team.id, owner_id, new_role.id)
            .await
            .unwrap();

        let members = teams.list_team_members(team.id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role_id, new_role.id);
    }

    #[tokio::test]
    async fn removing_org_member_cascades_to_team_members() {
        let (teams, org_id, _owner_id, role_id) = setup().await;
        let team_slug = TeamSlug::new("cascade-team").unwrap();
        let team = teams
            .create_team(org_id, "Cascade Team", &team_slug)
            .await
            .unwrap();

        // Add a second user to the org and the team.
        let member_id = add_second_user(&teams, "member@example.com").await;
        teams
            .add_org_member(org_id, member_id, role_id)
            .await
            .unwrap();
        teams
            .add_team_member(team.id, member_id, role_id)
            .await
            .unwrap();

        // Confirm team membership exists.
        let before = teams.list_team_members(team.id).await.unwrap();
        assert!(before.iter().any(|m| m.user_id == member_id));

        // Remove from org.
        teams.remove_org_member(org_id, member_id).await.unwrap();

        // Team membership should be gone.
        let after = teams.list_team_members(team.id).await.unwrap();
        assert!(!after.iter().any(|m| m.user_id == member_id));
    }

    #[tokio::test]
    async fn list_teams_for_user() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let slug1 = TeamSlug::new("team-one").unwrap();
        let slug2 = TeamSlug::new("team-two").unwrap();
        let team1 = teams
            .create_team(org_id, "Team One", &slug1)
            .await
            .unwrap();
        let team2 = teams
            .create_team(org_id, "Team Two", &slug2)
            .await
            .unwrap();

        teams
            .add_team_member(team1.id, owner_id, role_id)
            .await
            .unwrap();
        teams
            .add_team_member(team2.id, owner_id, role_id)
            .await
            .unwrap();

        let user_teams = teams.list_teams_for_user(owner_id).await.unwrap();
        assert_eq!(user_teams.len(), 2);
        assert!(user_teams.iter().any(|t| t.id == team1.id));
        assert!(user_teams.iter().any(|t| t.id == team2.id));
    }
}
