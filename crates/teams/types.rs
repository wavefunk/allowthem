use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use allowthem_core::error::AuthError;

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type)]
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

id_newtype!(OrgId);
id_newtype!(TeamId);
id_newtype!(OrgMembershipId);
id_newtype!(TeamMembershipId);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct OrgSlug(String);

impl OrgSlug {
    pub fn new(s: impl Into<String>) -> Result<Self, AuthError> {
        let s = s.into();
        validate_slug(&s)?;
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OrgSlug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct TeamSlug(String);

impl TeamSlug {
    pub fn new(s: impl Into<String>) -> Result<Self, AuthError> {
        let s = s.into();
        validate_slug(&s)?;
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TeamSlug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

fn validate_slug(s: &str) -> Result<(), AuthError> {
    if s.is_empty() {
        return Err(AuthError::Validation("slug cannot be empty".into()));
    }
    if s.len() > 128 {
        return Err(AuthError::Validation("slug too long (max 128 chars)".into()));
    }
    if !s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(AuthError::Validation(
            "slug must contain only lowercase letters, digits, and hyphens".into(),
        ));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(AuthError::Validation("slug cannot start or end with a hyphen".into()));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Org {
    pub id: OrgId,
    pub name: String,
    pub slug: OrgSlug,
    pub owner_id: allowthem_core::UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Team {
    pub id: TeamId,
    pub org_id: OrgId,
    pub name: String,
    pub slug: TeamSlug,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OrgMembership {
    pub id: OrgMembershipId,
    pub org_id: OrgId,
    pub user_id: allowthem_core::UserId,
    pub role_id: allowthem_core::RoleId,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TeamMembership {
    pub id: TeamMembershipId,
    pub team_id: TeamId,
    pub user_id: allowthem_core::UserId,
    pub role_id: allowthem_core::RoleId,
    pub created_at: DateTime<Utc>,
}
