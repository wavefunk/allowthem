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
}
