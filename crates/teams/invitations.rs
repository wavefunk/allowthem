use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use allowthem_core::Invitation;
use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::types::{Email, InvitationId, RoleId, UserId};

use crate::handle::Teams;
use crate::types::{OrgId, OrgMembership};

/// Parse the org metadata JSON stored in an invitation.
///
/// Returns `None` if the metadata string is absent, malformed, or missing
/// the required fields — callers in list/filter code skip those invitations
/// rather than failing the whole operation.
fn parse_org_metadata(metadata: &str) -> Option<(OrgId, RoleId)> {
    let v: serde_json::Value = serde_json::from_str(metadata).ok()?;
    let org_str = v.get("org_id")?.as_str()?;
    let role_str = v.get("role_id")?.as_str()?;
    let org_uuid = Uuid::parse_str(org_str).ok()?;
    let role_uuid = Uuid::parse_str(role_str).ok()?;
    Some((OrgId::from_uuid(org_uuid), RoleId::from_uuid(role_uuid)))
}

impl Teams {
    /// Invite an email address to join an org with a given role.
    ///
    /// Returns the raw invitation token (shown once) and the `Invitation`
    /// record. Returns `AuthError::Conflict` if a pending invitation already
    /// exists for this email+org combination.
    pub async fn invite_to_org(
        &self,
        org_id: OrgId,
        email: &Email,
        role_id: RoleId,
        invited_by: UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<(String, Invitation), AuthError> {
        // Duplicate-invite guard: check pending invitations for this org.
        let pending = self.list_pending_org_invitations(org_id).await?;
        let already_invited = pending.iter().any(|inv| inv.email.as_ref() == Some(email));
        if already_invited {
            return Err(AuthError::Conflict(
                "a pending invitation already exists for this email in this org".into(),
            ));
        }

        let metadata = json!({
            "org_id": org_id.to_string(),
            "role_id": role_id.to_string(),
        })
        .to_string();

        let result = self
            .core_db()
            .create_invitation(Some(email), Some(&metadata), Some(invited_by), expires_at)
            .await?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgInvitationCreated,
                Some(&invited_by),
                Some(&org_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(result)
    }

    /// Accept an invitation token and add the user to the org.
    ///
    /// If the user is already a member of the org, the invitation is consumed
    /// and the existing membership is returned (idempotent). Returns
    /// `AuthError::NotFound` if the token is invalid or expired.
    pub async fn accept_invitation(
        &self,
        raw_token: &str,
        user_id: UserId,
    ) -> Result<OrgMembership, AuthError> {
        let invitation = self
            .core_db()
            .validate_invitation(raw_token)
            .await?
            .ok_or(AuthError::NotFound)?;

        let metadata = invitation
            .metadata
            .as_deref()
            .ok_or_else(|| AuthError::Validation("invitation metadata is missing".into()))?;

        let (org_id, role_id) = parse_org_metadata(metadata)
            .ok_or_else(|| AuthError::Validation("invitation metadata is malformed".into()))?;

        // Idempotent: if already a member, just consume the invitation
        if let Some(existing) = self.get_org_membership(org_id, user_id).await? {
            self.core_db().consume_invitation(invitation.id).await?;
            let _ = self
                .core_db()
                .log_audit(
                    AuditEvent::OrgInvitationAccepted,
                    Some(&user_id),
                    Some(&org_id.to_string()),
                    None,
                    None,
                    None,
                )
                .await;
            return Ok(existing);
        }

        // Consume invitation + create membership in a single transaction
        // so the invitation is not burned if membership creation fails.
        let pool = self.teams_db().pool();
        let mut tx = pool.begin().await.map_err(AuthError::Database)?;

        let now_str = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let consume_result = sqlx::query(
            "UPDATE allowthem_invitations SET consumed_at = ? \
             WHERE id = ? AND consumed_at IS NULL",
        )
        .bind(&now_str)
        .bind(invitation.id)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        if consume_result.rows_affected() == 0 {
            return Err(AuthError::Gone);
        }

        let membership_id = crate::types::OrgMembershipId::new();
        sqlx::query(
            "INSERT INTO allowthem_org_members (id, org_id, user_id, role_id, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(membership_id)
        .bind(org_id)
        .bind(user_id)
        .bind(role_id)
        .bind(&now_str)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        tx.commit().await.map_err(AuthError::Database)?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgInvitationAccepted,
                Some(&user_id),
                Some(&org_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(OrgMembership {
            id: membership_id,
            org_id,
            user_id,
            role_id,
            created_at: chrono::Utc::now(),
        })
    }

    /// Decline an invitation token.
    ///
    /// Validates and consumes the invitation without creating a membership.
    /// Returns `AuthError::NotFound` if the token is invalid or expired.
    pub async fn decline_invitation(&self, raw_token: &str) -> Result<(), AuthError> {
        let invitation = self
            .core_db()
            .validate_invitation(raw_token)
            .await?
            .ok_or(AuthError::NotFound)?;

        self.core_db().consume_invitation(invitation.id).await?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgInvitationDeclined,
                None,
                None,
                None,
                None,
                None,
            )
            .await;

        Ok(())
    }

    /// Revoke (delete) an invitation by ID.
    ///
    /// Permanently removes the invitation record. Returns `AuthError::NotFound`
    /// if no invitation with that ID exists.
    pub async fn revoke_invitation(&self, invitation_id: InvitationId) -> Result<(), AuthError> {
        self.core_db().delete_invitation(invitation_id).await?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgInvitationRevoked,
                None,
                Some(&invitation_id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(())
    }

    /// List all pending invitations for a given org.
    ///
    /// Filters core's pending invitations by matching `org_id` in metadata.
    /// Invitations with malformed or missing metadata are silently skipped.
    pub async fn list_pending_org_invitations(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<Invitation>, AuthError> {
        let all_pending = self.core_db().list_pending_invitations().await?;
        let filtered = all_pending
            .into_iter()
            .filter(|inv| {
                inv.metadata
                    .as_deref()
                    .and_then(parse_org_metadata)
                    .map(|(oid, _)| oid == org_id)
                    .unwrap_or(false)
            })
            .collect();
        Ok(filtered)
    }

    /// Resolve all pending org invitations for a specific email address.
    ///
    /// Returns invitations that match the email AND have an `org_id` in
    /// metadata. Invitations with malformed metadata are silently skipped.
    pub async fn resolve_invitations_for_email(
        &self,
        email: &Email,
    ) -> Result<Vec<Invitation>, AuthError> {
        let all_pending = self.core_db().list_pending_invitations().await?;
        let filtered = all_pending
            .into_iter()
            .filter(|inv| {
                let email_matches = inv.email.as_ref() == Some(email);
                let has_org_metadata = inv
                    .metadata
                    .as_deref()
                    .and_then(parse_org_metadata)
                    .is_some();
                email_matches && has_org_metadata
            })
            .collect();
        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use allowthem_core::AllowThemBuilder;
    use allowthem_core::types::RoleName;

    use super::*;
    use crate::Teams;
    use crate::types::OrgSlug;

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
        let slug = OrgSlug::new("inv-org").unwrap();
        let org = teams
            .create_org("Inv Org", &slug, user.id, role.id)
            .await
            .unwrap();
        (teams, org.id, user.id, role.id)
    }

    #[tokio::test]
    async fn invite_and_accept() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let invite_email = Email::new("invited@example.com".into()).unwrap();
        let invitee = teams
            .core_db()
            .create_user(invite_email.clone(), "pass456", None, None)
            .await
            .unwrap();

        let expires = Utc::now() + Duration::hours(24);
        let (token, _inv) = teams
            .invite_to_org(org_id, &invite_email, role_id, owner_id, expires)
            .await
            .unwrap();

        let membership = teams.accept_invitation(&token, invitee.id).await.unwrap();
        assert_eq!(membership.org_id, org_id);
        assert_eq!(membership.user_id, invitee.id);
        assert_eq!(membership.role_id, role_id);
    }

    #[tokio::test]
    async fn accept_when_already_member_is_idempotent() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let member_email = Email::new("alreadymember@example.com".into()).unwrap();
        let member = teams
            .core_db()
            .create_user(member_email.clone(), "pass789", None, None)
            .await
            .unwrap();

        // Add the user as a member directly first.
        teams
            .add_org_member(org_id, member.id, role_id)
            .await
            .unwrap();

        // Now invite the same email.
        let expires = Utc::now() + Duration::hours(24);
        let (token, _inv) = teams
            .invite_to_org(org_id, &member_email, role_id, owner_id, expires)
            .await
            .unwrap();

        // Accept should succeed and return the existing membership.
        let membership = teams.accept_invitation(&token, member.id).await.unwrap();
        assert_eq!(membership.user_id, member.id);
        assert_eq!(membership.org_id, org_id);

        // Invitation is consumed — list should be empty now.
        let pending = teams.list_pending_org_invitations(org_id).await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn decline_invitation() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let invite_email = Email::new("decline@example.com".into()).unwrap();
        let invitee = teams
            .core_db()
            .create_user(invite_email.clone(), "pass000", None, None)
            .await
            .unwrap();

        let expires = Utc::now() + Duration::hours(24);
        let (token, _inv) = teams
            .invite_to_org(org_id, &invite_email, role_id, owner_id, expires)
            .await
            .unwrap();

        teams.decline_invitation(&token).await.unwrap();

        // After declining, the token is consumed — accept should fail.
        let err = teams
            .accept_invitation(&token, invitee.id)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::NotFound));
    }

    #[tokio::test]
    async fn revoke_invitation() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let invite_email = Email::new("revoke@example.com".into()).unwrap();

        let expires = Utc::now() + Duration::hours(24);
        let (_token, inv) = teams
            .invite_to_org(org_id, &invite_email, role_id, owner_id, expires)
            .await
            .unwrap();

        teams.revoke_invitation(inv.id).await.unwrap();

        let pending = teams.list_pending_org_invitations(org_id).await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn list_pending_org_invitations() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let email_a = Email::new("lista@example.com".into()).unwrap();
        let email_b = Email::new("listb@example.com".into()).unwrap();

        let expires = Utc::now() + Duration::hours(24);
        teams
            .invite_to_org(org_id, &email_a, role_id, owner_id, expires)
            .await
            .unwrap();
        teams
            .invite_to_org(org_id, &email_b, role_id, owner_id, expires)
            .await
            .unwrap();

        let pending = teams.list_pending_org_invitations(org_id).await.unwrap();
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn resolve_invitations_for_email() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let email_target = Email::new("target@example.com".into()).unwrap();
        let email_other = Email::new("other@example.com".into()).unwrap();

        let expires = Utc::now() + Duration::hours(24);
        teams
            .invite_to_org(org_id, &email_target, role_id, owner_id, expires)
            .await
            .unwrap();
        teams
            .invite_to_org(org_id, &email_other, role_id, owner_id, expires)
            .await
            .unwrap();

        let resolved = teams
            .resolve_invitations_for_email(&email_target)
            .await
            .unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].email.as_ref(), Some(&email_target));
    }

    #[tokio::test]
    async fn duplicate_invite_same_email_same_org_fails() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let invite_email = Email::new("dupe@example.com".into()).unwrap();
        let expires = Utc::now() + Duration::hours(24);

        teams
            .invite_to_org(org_id, &invite_email, role_id, owner_id, expires)
            .await
            .unwrap();

        let err = teams
            .invite_to_org(org_id, &invite_email, role_id, owner_id, expires)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Conflict(_)));
    }

    #[tokio::test]
    async fn accept_expired_invitation_fails() {
        let (teams, org_id, owner_id, role_id) = setup().await;

        let invite_email = Email::new("expired@example.com".into()).unwrap();
        let invitee = teams
            .core_db()
            .create_user(invite_email.clone(), "passexp", None, None)
            .await
            .unwrap();

        // Create with a past expiry — invite_to_org uses list_pending which
        // only shows non-expired, so duplicate check won't block us here.
        let metadata = serde_json::json!({
            "org_id": org_id.to_string(),
            "role_id": role_id.to_string(),
        })
        .to_string();
        let expires_past = Utc::now() - Duration::hours(1);
        let (token, _inv) = teams
            .core_db()
            .create_invitation(
                Some(&invite_email),
                Some(&metadata),
                Some(owner_id),
                expires_past,
            )
            .await
            .unwrap();

        let err = teams
            .accept_invitation(&token, invitee.id)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::NotFound));
    }
}
