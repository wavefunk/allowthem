use allowthem_core::UserId;
use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;

use crate::handle::Teams;
use crate::types::{OrgId, Team, TeamId, TeamSlug};

fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") && msg.contains("slug") {
            return AuthError::Conflict("team slug already exists in this org".into());
        }
    }
    AuthError::Database(err)
}

impl Teams {
    pub async fn create_team(
        &self,
        org_id: OrgId,
        name: &str,
        slug: &TeamSlug,
    ) -> Result<Team, AuthError> {
        let id = TeamId::new();
        let now = chrono::Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_teams (id, org_id, name, slug, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(org_id)
        .bind(name)
        .bind(slug)
        .bind(&now_str)
        .bind(&now_str)
        .execute(self.teams_db().pool())
        .await
        .map_err(map_unique_violation)?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::TeamCreated,
                None,
                Some(&id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(Team {
            id,
            org_id,
            name: name.to_owned(),
            slug: slug.clone(),
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_team(&self, id: TeamId) -> Result<Option<Team>, AuthError> {
        sqlx::query_as::<_, Team>(
            "SELECT id, org_id, name, slug, created_at, updated_at \
             FROM allowthem_teams WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn get_team_by_slug(
        &self,
        org_id: OrgId,
        slug: &TeamSlug,
    ) -> Result<Option<Team>, AuthError> {
        sqlx::query_as::<_, Team>(
            "SELECT id, org_id, name, slug, created_at, updated_at \
             FROM allowthem_teams WHERE org_id = ? AND slug = ?",
        )
        .bind(org_id)
        .bind(slug)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn list_teams_for_org(&self, org_id: OrgId) -> Result<Vec<Team>, AuthError> {
        sqlx::query_as::<_, Team>(
            "SELECT id, org_id, name, slug, created_at, updated_at \
             FROM allowthem_teams WHERE org_id = ? \
             ORDER BY created_at",
        )
        .bind(org_id)
        .fetch_all(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn list_teams_for_user(&self, user_id: UserId) -> Result<Vec<Team>, AuthError> {
        sqlx::query_as::<_, Team>(
            "SELECT t.id, t.org_id, t.name, t.slug, t.created_at, t.updated_at \
             FROM allowthem_teams t \
             JOIN allowthem_team_members m ON m.team_id = t.id \
             WHERE m.user_id = ? \
             ORDER BY t.created_at",
        )
        .bind(user_id)
        .fetch_all(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn update_team(
        &self,
        id: TeamId,
        name: &str,
        slug: &TeamSlug,
    ) -> Result<Team, AuthError> {
        let now_str = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let result = sqlx::query(
            "UPDATE allowthem_teams SET name = ?, slug = ?, updated_at = ? WHERE id = ?",
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

        self.get_team(id).await?.ok_or(AuthError::NotFound)
    }

    pub async fn delete_team(&self, id: TeamId) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_teams WHERE id = ?")
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
                AuditEvent::TeamDeleted,
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
    use crate::types::OrgSlug;

    async fn setup() -> (Teams, OrgId) {
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
        let slug = OrgSlug::new("test-org").unwrap();
        let org = teams
            .create_org("Test Org", &slug, user.id, role.id)
            .await
            .unwrap();
        (teams, org.id)
    }

    #[tokio::test]
    async fn create_and_get_team() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("engineering").unwrap();
        let team = teams
            .create_team(org_id, "Engineering", &slug)
            .await
            .unwrap();

        assert_eq!(team.name, "Engineering");
        assert_eq!(team.slug, slug);
        assert_eq!(team.org_id, org_id);

        let fetched = teams.get_team(team.id).await.unwrap().unwrap();
        assert_eq!(fetched.id, team.id);
        assert_eq!(fetched.name, team.name);
    }

    #[tokio::test]
    async fn duplicate_slug_in_same_org_fails() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("same-slug").unwrap();
        teams
            .create_team(org_id, "First Team", &slug)
            .await
            .unwrap();

        let err = teams
            .create_team(org_id, "Second Team", &slug)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Conflict(_)));
    }

    #[tokio::test]
    async fn get_team_by_slug() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("find-me").unwrap();
        let team = teams.create_team(org_id, "Find Me", &slug).await.unwrap();

        let found = teams
            .get_team_by_slug(org_id, &slug)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, team.id);

        let missing = TeamSlug::new("no-such-team").unwrap();
        let none = teams.get_team_by_slug(org_id, &missing).await.unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn list_teams_for_org() {
        let (teams, org_id) = setup().await;
        let slug1 = TeamSlug::new("team-alpha").unwrap();
        let slug2 = TeamSlug::new("team-beta").unwrap();
        teams.create_team(org_id, "Alpha", &slug1).await.unwrap();
        teams.create_team(org_id, "Beta", &slug2).await.unwrap();

        let list = teams.list_teams_for_org(org_id).await.unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|t| t.slug == slug1));
        assert!(list.iter().any(|t| t.slug == slug2));
    }

    #[tokio::test]
    async fn update_team() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("update-me").unwrap();
        let team = teams.create_team(org_id, "Original", &slug).await.unwrap();

        let new_slug = TeamSlug::new("updated-slug").unwrap();
        let updated = teams
            .update_team(team.id, "Updated Name", &new_slug)
            .await
            .unwrap();

        assert_eq!(updated.name, "Updated Name");
        assert_eq!(updated.slug, new_slug);
    }

    #[tokio::test]
    async fn delete_team() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("delete-me").unwrap();
        let team = teams.create_team(org_id, "To Delete", &slug).await.unwrap();

        teams.delete_team(team.id).await.unwrap();

        let result = teams.get_team(team.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_team_returns_not_found() {
        let (teams, _) = setup().await;
        let missing_id = TeamId::new();
        let err = teams.delete_team(missing_id).await.unwrap_err();
        assert!(matches!(err, AuthError::NotFound));
    }
}
