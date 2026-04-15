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

/// Email address. Validated at construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct Email(String);

impl Email {
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// Optional display/login alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct Username(String);

impl Username {
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
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// SHA-256 hash of the raw session token, stored in the DB.
/// The raw token is only held in memory or in the cookie — never persisted.
/// Not PartialEq/Eq — forces callers to use constant-time comparison.
#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(transparent)]
pub struct TokenHash(String);

impl TokenHash {
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// A role name as defined by the integrating application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(s)
    }
}

/// A permission scope as defined by the integrating application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct PermissionName(String);

impl PermissionName {
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
