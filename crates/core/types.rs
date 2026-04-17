use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
        #[sqlx(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

id_newtype!(UserId);
id_newtype!(SessionId);
id_newtype!(RoleId);
id_newtype!(PermissionId);
id_newtype!(ResetTokenId);
id_newtype!(AuditEntryId);
id_newtype!(ApiTokenId);
id_newtype!(OAuthAccountId);
id_newtype!(OAuthStateId);
id_newtype!(MfaSecretId);
id_newtype!(MfaRecoveryCodeId);
id_newtype!(MfaChallengeId);
id_newtype!(InvitationId);
id_newtype!(ApplicationId);
id_newtype!(AuthorizationCodeId);
id_newtype!(RefreshTokenId);
id_newtype!(ConsentId);
id_newtype!(SigningKeyId);

/// Email address. Validated at construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct Email(String);

impl Email {
    /// Create an `Email` after basic format validation.
    ///
    /// Checks: exactly one `@`, non-empty local part, non-empty domain
    /// with at least one `.`. Not RFC 5322 compliant — intentionally simple.
    pub fn new(s: String) -> Result<Self, crate::error::AuthError> {
        let trimmed = s.trim().to_string();
        let parts: Vec<&str> = trimmed.splitn(3, '@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(crate::error::AuthError::InvalidEmail);
        }
        if !parts[1].contains('.') {
            return Err(crate::error::AuthError::InvalidEmail);
        }
        Ok(Self(trimmed))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// Optional display/login alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct Username(String);

impl Username {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// Argon2id hash output stored as PHC string.
/// Not Serialize — password hashes must never appear in API responses.
/// Not PartialEq/Eq — forces callers to use constant-time comparison via Argon2 verify.
#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(transparent)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// SHA-256 hash of the raw session token, stored in the DB.
/// The raw token is only held in memory or in the cookie — never persisted.
/// Not PartialEq/Eq — forces callers to use constant-time comparison.
#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(transparent)]
pub struct TokenHash(String);

impl TokenHash {
    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// A raw session token — 32 random bytes encoded as base64url (no padding).
/// This is what is placed in the session cookie. Never persisted to the database.
/// The SHA-256 hash of this value is stored as `TokenHash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    pub fn from_encoded(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Public-facing OAuth client identifier.
///
/// Format: `ath_` prefix + 24 random bytes base64url-encoded (32 chars) = 36 chars total.
/// The prefix makes client IDs recognizable in logs and configs. The 192 bits of
/// entropy from the random portion ensures collision resistance without coordination.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct ClientId(String);

impl ClientId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A raw OAuth client secret — returned once on application creation.
///
/// 32 random bytes base64url-encoded (43 chars). Same entropy as session tokens.
/// The Argon2 hash of this value is stored as `client_secret_hash` in the
/// applications table. Never persisted.
#[derive(Debug, Clone)]
pub struct ClientSecret(String);

impl ClientSecret {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// A role name as defined by the integrating application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// A permission scope as defined by the integrating application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct PermissionName(String);

impl PermissionName {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub username: Option<Username>,
    #[serde(skip_serializing)]
    pub password_hash: Option<PasswordHash>,
    pub email_verified: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: SessionId,
    pub token_hash: TokenHash,
    pub user_id: UserId,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Role {
    pub id: RoleId,
    pub name: RoleName,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRole {
    pub user_id: UserId,
    pub role_id: RoleId,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Permission {
    pub id: PermissionId,
    pub name: PermissionName,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RolePermission {
    pub role_id: RoleId,
    pub permission_id: PermissionId,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserPermission {
    pub user_id: UserId,
    pub permission_id: PermissionId,
}

/// Metadata for an API token. Does not include the token hash.
/// The raw token is only returned once, at creation time.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ApiTokenInfo {
    pub id: ApiTokenId,
    pub user_id: UserId,
    pub name: String,
    pub metadata: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
