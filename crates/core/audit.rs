use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::db::Db;
use crate::error::AuthError;
use crate::types::{AuditEntryId, UserId};

/// Every type of authentication event that can be recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(rename_all = "snake_case")]
pub enum AuditEvent {
    Login,
    LoginFailed,
    Logout,
    Register,
    PasswordChange,
    PasswordReset,
    RoleAssigned,
    RoleUnassigned,
    PermissionAssigned,
    PermissionUnassigned,
    SessionCreated,
    SessionExpired,
    UserUpdated,
    UserDeleted,
    MfaEnabled,
    MfaDisabled,
    MfaChallengeSuccess,
    MfaChallengeFailed,
    OrgCreated,
    OrgUpdated,
    OrgDeleted,
    OrgMemberAdded,
    OrgMemberRemoved,
    OrgMemberRoleChanged,
    OrgOwnershipTransferred,
    TeamCreated,
    TeamUpdated,
    TeamDeleted,
    TeamMemberAdded,
    TeamMemberRemoved,
    TeamMemberRoleChanged,
    OrgInvitationCreated,
    OrgInvitationAccepted,
    OrgInvitationDeclined,
    OrgInvitationRevoked,
}

/// A single record in the audit log.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: AuditEntryId,
    pub event_type: AuditEvent,
    pub user_id: Option<UserId>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Map an `AuditEvent` variant to its snake_case database value.
///
/// `AuditEvent` has `#[sqlx(rename_all = "snake_case")]` but no matching
/// serde attribute. This function provides the canonical snake_case string
/// for use in dynamic SQL bind values.
fn event_to_slug(event: &AuditEvent) -> &'static str {
    match event {
        AuditEvent::Login => "login",
        AuditEvent::LoginFailed => "login_failed",
        AuditEvent::Logout => "logout",
        AuditEvent::Register => "register",
        AuditEvent::PasswordChange => "password_change",
        AuditEvent::PasswordReset => "password_reset",
        AuditEvent::RoleAssigned => "role_assigned",
        AuditEvent::RoleUnassigned => "role_unassigned",
        AuditEvent::PermissionAssigned => "permission_assigned",
        AuditEvent::PermissionUnassigned => "permission_unassigned",
        AuditEvent::SessionCreated => "session_created",
        AuditEvent::SessionExpired => "session_expired",
        AuditEvent::UserUpdated => "user_updated",
        AuditEvent::UserDeleted => "user_deleted",
        AuditEvent::MfaEnabled => "mfa_enabled",
        AuditEvent::MfaDisabled => "mfa_disabled",
        AuditEvent::MfaChallengeSuccess => "mfa_challenge_success",
        AuditEvent::MfaChallengeFailed => "mfa_challenge_failed",
        AuditEvent::OrgCreated => "org_created",
        AuditEvent::OrgUpdated => "org_updated",
        AuditEvent::OrgDeleted => "org_deleted",
        AuditEvent::OrgMemberAdded => "org_member_added",
        AuditEvent::OrgMemberRemoved => "org_member_removed",
        AuditEvent::OrgMemberRoleChanged => "org_member_role_changed",
        AuditEvent::OrgOwnershipTransferred => "org_ownership_transferred",
        AuditEvent::TeamCreated => "team_created",
        AuditEvent::TeamUpdated => "team_updated",
        AuditEvent::TeamDeleted => "team_deleted",
        AuditEvent::TeamMemberAdded => "team_member_added",
        AuditEvent::TeamMemberRemoved => "team_member_removed",
        AuditEvent::TeamMemberRoleChanged => "team_member_role_changed",
        AuditEvent::OrgInvitationCreated => "org_invitation_created",
        AuditEvent::OrgInvitationAccepted => "org_invitation_accepted",
        AuditEvent::OrgInvitationDeclined => "org_invitation_declined",
        AuditEvent::OrgInvitationRevoked => "org_invitation_revoked",
    }
}

/// Parameters for searching/filtering audit log entries.
pub struct SearchAuditParams<'a> {
    pub user_id: Option<UserId>,
    pub event_type: Option<&'a AuditEvent>,
    pub is_success: Option<bool>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: u32,
    pub offset: u32,
}

/// An audit log entry with the user's email resolved via LEFT JOIN.
/// Used for admin list display — avoids showing raw UUIDs.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditListEntry {
    pub id: AuditEntryId,
    pub event_type: AuditEvent,
    pub user_id: Option<UserId>,
    pub user_email: Option<String>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Result of a paginated audit log search.
pub struct SearchAuditResult {
    pub entries: Vec<AuditListEntry>,
    pub total: u32,
}

/// Opaque keyset cursor for paginating `list_audit_paginated`.
///
/// Encodes `(created_at, id)` as a base64url-encoded JSON blob.
pub struct AuditCursor {
    pub created_at: DateTime<Utc>,
    pub id: AuditEntryId,
}

#[derive(Serialize, Deserialize)]
struct RawAuditCursor {
    ca: String,
    id: String,
}

impl AuditCursor {
    pub fn from_entry(entry: &AuditListEntry) -> Self {
        Self {
            created_at: entry.created_at,
            id: entry.id,
        }
    }

    pub fn encode(&self) -> String {
        let raw = RawAuditCursor {
            ca: self.created_at.to_rfc3339(),
            id: self.id.to_string(),
        };
        let json = serde_json::to_string(&raw).expect("RawAuditCursor serializes");
        Base64UrlUnpadded::encode_string(json.as_bytes())
    }

    pub fn decode(s: &str) -> Option<Self> {
        let bytes = Base64UrlUnpadded::decode_vec(s).ok()?;
        let raw: RawAuditCursor = serde_json::from_slice(&bytes).ok()?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&raw.ca)
            .ok()?
            .with_timezone(&Utc);
        let id = raw
            .id
            .parse::<uuid::Uuid>()
            .ok()
            .map(AuditEntryId::from_uuid)?;
        Some(Self { created_at, id })
    }
}

impl Db {
    /// Record an audit event.
    ///
    /// `user_id` may be `None` for events where no authenticated user is
    /// involved (e.g. a failed login attempt against an unknown email).
    pub async fn log_audit(
        &self,
        event_type: AuditEvent,
        user_id: Option<&UserId>,
        target_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        detail: Option<&str>,
    ) -> Result<(), AuthError> {
        let id = AuditEntryId::new();
        sqlx::query(
            "INSERT INTO allowthem_audit_log
             (id, event_type, user_id, target_id, ip_address, user_agent, detail)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(event_type)
        .bind(user_id.copied())
        .bind(target_id)
        .bind(ip_address)
        .bind(user_agent)
        .bind(detail)
        .execute(self.pool())
        .await
        .map_err(AuthError::Database)?;
        Ok(())
    }

    /// Retrieve audit log entries, optionally filtered by user.
    ///
    /// Results are ordered by `created_at` descending (newest first).
    pub async fn get_audit_log(
        &self,
        user_id: Option<&UserId>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEntry>, AuthError> {
        match user_id {
            Some(uid) => {
                sqlx::query_as::<_, AuditEntry>(
                    "SELECT id, event_type, user_id, target_id, ip_address, user_agent, detail, created_at
                     FROM allowthem_audit_log
                     WHERE user_id = ?
                     ORDER BY created_at DESC
                     LIMIT ? OFFSET ?",
                )
                .bind(*uid)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.pool())
                .await
                .map_err(AuthError::Database)
            }
            None => {
                sqlx::query_as::<_, AuditEntry>(
                    "SELECT id, event_type, user_id, target_id, ip_address, user_agent, detail, created_at
                     FROM allowthem_audit_log
                     ORDER BY created_at DESC
                     LIMIT ? OFFSET ?",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.pool())
                .await
                .map_err(AuthError::Database)
            }
        }
    }

    /// Retrieve audit log entries filtered by event type.
    ///
    /// Results are ordered by `created_at` descending (newest first).
    pub async fn get_audit_log_by_event(
        &self,
        event_type: AuditEvent,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEntry>, AuthError> {
        sqlx::query_as::<_, AuditEntry>(
            "SELECT id, event_type, user_id, target_id, ip_address, user_agent, detail, created_at
             FROM allowthem_audit_log
             WHERE event_type = ?
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(event_type)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Get the most recent login timestamp for a user, if any.
    ///
    /// Returns `None` if the user has never logged in (no audit entry
    /// with event_type = 'login' for this user_id).
    pub async fn last_login_at(&self, user_id: UserId) -> Result<Option<DateTime<Utc>>, AuthError> {
        sqlx::query_scalar(
            "SELECT MAX(created_at) FROM allowthem_audit_log \
             WHERE user_id = ? AND event_type = 'login'",
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Paginated list of audit entries using a `(created_at, id)` keyset cursor.
    ///
    /// Ordered newest-first. Pass `None` for cursor to start from the beginning.
    /// Limits are capped at 200.
    pub async fn list_audit_paginated(
        &self,
        limit: u32,
        cursor: Option<&AuditCursor>,
    ) -> Result<Vec<AuditListEntry>, AuthError> {
        let limit = (limit as i64).min(200);
        match cursor {
            None => sqlx::query_as::<_, AuditListEntry>(
                "SELECT a.id, a.event_type, a.user_id, u.email AS user_email, \
                 a.target_id, a.ip_address, a.user_agent, a.detail, a.created_at \
                 FROM allowthem_audit_log a \
                 LEFT JOIN allowthem_users u ON a.user_id = u.id \
                 ORDER BY a.created_at DESC, a.id DESC \
                 LIMIT ?",
            )
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .map_err(AuthError::Database),
            Some(c) => {
                let ca = c.created_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
                sqlx::query_as::<_, AuditListEntry>(
                    "SELECT a.id, a.event_type, a.user_id, u.email AS user_email, \
                     a.target_id, a.ip_address, a.user_agent, a.detail, a.created_at \
                     FROM allowthem_audit_log a \
                     LEFT JOIN allowthem_users u ON a.user_id = u.id \
                     WHERE (a.created_at < ?1 OR (a.created_at = ?1 AND a.id < ?2)) \
                     ORDER BY a.created_at DESC, a.id DESC \
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

    /// Search and filter audit log entries with pagination.
    ///
    /// Builds a dynamic query with optional filters for user, event type,
    /// outcome, and date range. LEFT JOINs `allowthem_users` for email
    /// resolution. Follows the same dynamic-SQL pattern as `search_users`.
    pub async fn search_audit_log(
        &self,
        params: SearchAuditParams<'_>,
    ) -> Result<SearchAuditResult, AuthError> {
        // Build WHERE clauses and bind values. user_id is bound separately
        // because it is a UUID (not a String), and sqlx needs the correct
        // type for TEXT column comparison in SQLite.
        let mut where_clauses: Vec<String> = Vec::new();
        let mut string_binds: Vec<String> = Vec::new();

        if params.user_id.is_some() {
            where_clauses.push("a.user_id = ?".into());
            // Bound separately below — position tracked by clause order
        }

        if let Some(event) = params.event_type {
            where_clauses.push("a.event_type = ?".into());
            string_binds.push(event_to_slug(event).to_string());
        }

        match params.is_success {
            Some(true) => {
                where_clauses.push("a.event_type != 'login_failed'".into());
            }
            Some(false) => {
                where_clauses.push("a.event_type = 'login_failed'".into());
            }
            None => {}
        }

        if let Some(from) = params.from {
            where_clauses.push("a.created_at >= ?".into());
            string_binds.push(from.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
        }

        if let Some(to) = params.to {
            where_clauses.push("a.created_at < ?".into());
            string_binds.push(to.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // Count query
        let count_sql: &'static str = Box::leak(
            format!("SELECT COUNT(*) FROM allowthem_audit_log a {where_sql}").into_boxed_str(),
        );
        let mut count_query = sqlx::query_scalar::<_, i64>(count_sql);
        // Bind user_id first (it's the first WHERE clause if present)
        if let Some(uid) = params.user_id {
            count_query = count_query.bind(uid);
        }
        for val in &string_binds {
            count_query = count_query.bind(val);
        }
        let total = count_query
            .fetch_one(self.pool())
            .await
            .map_err(AuthError::Database)? as u32;

        // Data query with LEFT JOIN for user email
        let data_sql: &'static str = Box::leak(
            format!(
                "SELECT a.id, a.event_type, a.user_id, u.email AS user_email, \
                 a.target_id, a.ip_address, a.user_agent, a.detail, a.created_at \
                 FROM allowthem_audit_log a \
                 LEFT JOIN allowthem_users u ON a.user_id = u.id \
                 {where_sql} \
                 ORDER BY a.created_at DESC \
                 LIMIT ? OFFSET ?"
            )
            .into_boxed_str(),
        );
        let mut data_query = sqlx::query_as::<_, AuditListEntry>(data_sql);
        if let Some(uid) = params.user_id {
            data_query = data_query.bind(uid);
        }
        for val in &string_binds {
            data_query = data_query.bind(val);
        }
        data_query = data_query.bind(params.limit).bind(params.offset);

        let entries = data_query
            .fetch_all(self.pool())
            .await
            .map_err(AuthError::Database)?;

        Ok(SearchAuditResult { entries, total })
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

    async fn log_event(db: &Db, tag: u32) {
        db.log_audit(
            AuditEvent::Login,
            None,
            Some(&format!("target-{tag}")),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn audit_cursor_encode_decode_roundtrip() {
        let ath = setup().await;
        let db = ath.db();
        log_event(db, 1).await;
        let entries = db.list_audit_paginated(10, None).await.unwrap();
        assert_eq!(entries.len(), 1);
        let cursor = AuditCursor::from_entry(&entries[0]);
        let encoded = cursor.encode();
        let decoded = AuditCursor::decode(&encoded).unwrap();
        assert_eq!(decoded.id, entries[0].id);
    }

    #[tokio::test]
    async fn list_audit_paginated_returns_first_page() {
        let ath = setup().await;
        let db = ath.db();
        for i in 0..5 {
            log_event(db, i).await;
        }
        let page = db.list_audit_paginated(3, None).await.unwrap();
        assert_eq!(page.len(), 3);
    }

    #[tokio::test]
    async fn list_audit_paginated_cursor_advances() {
        let ath = setup().await;
        let db = ath.db();
        for i in 0..5 {
            log_event(db, i + 10).await;
        }
        let page1 = db.list_audit_paginated(3, None).await.unwrap();
        assert_eq!(page1.len(), 3);
        let cursor = AuditCursor::from_entry(page1.last().unwrap());
        let page2 = db.list_audit_paginated(3, Some(&cursor)).await.unwrap();
        assert_eq!(page2.len(), 2);
        assert!(!page2.iter().any(|e| page1.iter().any(|f| f.id == e.id)));
    }
}
