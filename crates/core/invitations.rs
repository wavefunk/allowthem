use chrono::{DateTime, Utc};

use crate::types::{Email, InvitationId, UserId};

/// A single-use invitation token record.
///
/// Returned by `Db::create_invitation` and `Db::validate_invitation`.
/// The `token_hash` is never exposed — only the raw token (returned once
/// at creation) can be used to validate.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Invitation {
    pub id: InvitationId,
    pub email: Option<Email>,
    pub metadata: Option<String>,
    pub invited_by: Option<UserId>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
