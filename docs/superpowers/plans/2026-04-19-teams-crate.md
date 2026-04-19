# Teams Crate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `allowthem-teams` crate that provides org/team management with memberships, invitations, and scoped roles.

**Architecture:** New `crates/teams/` crate depends on `allowthem-core` for `Db`, types, errors, and invitations. Pure data/logic layer — no axum dependency. Server integration (extractors, middleware, routes) goes in `allowthem-server` which gains `allowthem-teams` as a dependency.

**Tech Stack:** Rust, SQLite via SQLx, chrono, uuid, serde/serde_json. Reuses `allowthem-core` types and `id_newtype!` macro.

**Spec:** `docs/superpowers/specs/2026-04-19-teams-crate-design.md`

---

### Task 1: Add `Forbidden` variant to core's `AuthError`

**Files:**
- Modify: `crates/core/error.rs:19-98`
- Modify: `crates/core/audit.rs:9-70` (add new AuditEvent variants)
- Modify: `crates/core/core.rs` (re-export stays via `pub use error::AuthError`)

- [ ] **Step 1: Add `Forbidden` variant to `AuthError`**

In `crates/core/error.rs`, add after the `Gone` variant (line 73):

```rust
    #[error("forbidden: {0}")]
    Forbidden(String),
```

- [ ] **Step 2: Add teams-related `AuditEvent` variants**

In `crates/core/audit.rs`, add to the `AuditEvent` enum after `MfaChallengeFailed`:

```rust
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
```

- [ ] **Step 3: Add slug mappings to `event_to_slug`**

In the `event_to_slug` function in `crates/core/audit.rs`, add arms after the `MfaChallengeFailed` arm:

```rust
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
```

- [ ] **Step 4: Verify compilation**

Run: `just check`
Expected: Compiles successfully. No existing code matches on `AuthError` exhaustively (all uses are `match` with specific arms + `_` wildcards or `map_err`), so adding a variant should not break anything.

- [ ] **Step 5: Run existing tests**

Run: `just test`
Expected: All existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/core/error.rs crates/core/audit.rs
git commit -m "feat(core): add Forbidden error variant and teams audit events"
```

---

### Task 2: Scaffold the teams crate with types and migration

**Files:**
- Create: `crates/teams/Cargo.toml`
- Create: `crates/teams/teams.rs`
- Create: `crates/teams/types.rs`
- Create: `crates/teams/migrations/20260419000001_teams_tables.sql`

- [ ] **Step 1: Create `crates/teams/Cargo.toml`**

```toml
[package]
name = "allowthem-teams"
version.workspace = true
authors.workspace = true
description = "Organization and team management for allowthem"
edition.workspace = true
license.workspace = true
repository.workspace = true

[lib]
path = "./teams.rs"

[dependencies]
allowthem-core = { path = "../core" }
sqlx.workspace = true
chrono.workspace = true
uuid.workspace = true
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
tokio.workspace = true
```

- [ ] **Step 2: Create the migration SQL**

Create `crates/teams/migrations/20260419000001_teams_tables.sql`:

```sql
CREATE TABLE IF NOT EXISTS allowthem_orgs (
    id         TEXT PRIMARY KEY NOT NULL,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    owner_id   TEXT NOT NULL REFERENCES allowthem_users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS allowthem_teams (
    id         TEXT PRIMARY KEY NOT NULL,
    org_id     TEXT NOT NULL REFERENCES allowthem_orgs(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(org_id, slug)
);

CREATE TABLE IF NOT EXISTS allowthem_org_members (
    id         TEXT PRIMARY KEY NOT NULL,
    org_id     TEXT NOT NULL REFERENCES allowthem_orgs(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES allowthem_roles(id),
    created_at TEXT NOT NULL,
    UNIQUE(org_id, user_id)
);

CREATE TABLE IF NOT EXISTS allowthem_team_members (
    id         TEXT PRIMARY KEY NOT NULL,
    team_id    TEXT NOT NULL REFERENCES allowthem_teams(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES allowthem_roles(id),
    created_at TEXT NOT NULL,
    UNIQUE(team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON allowthem_org_members(user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON allowthem_team_members(user_id);
```

- [ ] **Step 3: Create `crates/teams/types.rs`**

```rust
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
```

- [ ] **Step 4: Create `crates/teams/teams.rs`**

```rust
pub mod types;

pub use types::*;
```

- [ ] **Step 5: Verify compilation**

Run: `just check`
Expected: Workspace compiles. The teams crate is auto-discovered via `members = ["crates/*"]`.

- [ ] **Step 6: Commit**

```bash
git add crates/teams/
git commit -m "feat(teams): scaffold crate with types, IDs, slugs, and migration"
```

---

### Task 3: TeamsDb and handle with migration runner

**Files:**
- Create: `crates/teams/db.rs`
- Create: `crates/teams/handle.rs`
- Modify: `crates/teams/teams.rs`

- [ ] **Step 1: Write test for TeamsDb construction**

Add to `crates/teams/db.rs`:

```rust
use allowthem_core::error::AuthError;
use sqlx::SqlitePool;

pub struct TeamsDb {
    pool: SqlitePool,
}

impl TeamsDb {
    pub async fn new(pool: SqlitePool) -> Result<Self, AuthError> {
        sqlx::migrate!("./migrations")
            .set_ignore_missing(true)
            .run(&pool)
            .await
            .map_err(sqlx::Error::from)?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub async fn test_pool() -> SqlitePool {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        SqlitePool::connect_with(opts).await.unwrap()
    }

    use std::str::FromStr;

    #[tokio::test]
    async fn teams_db_runs_migrations() {
        let pool = test_pool().await;
        // Run core migrations first (teams tables reference core tables)
        allowthem_core::Db::new(pool.clone()).await.unwrap();
        let db = TeamsDb::new(pool).await;
        assert!(db.is_ok());
    }
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p allowthem-teams db::tests::teams_db_runs_migrations`
Expected: PASS

- [ ] **Step 3: Create `crates/teams/handle.rs`**

```rust
use std::sync::Arc;

use allowthem_core::Db;
use allowthem_core::error::AuthError;
use sqlx::SqlitePool;

use crate::db::TeamsDb;

struct TeamsInner {
    teams_db: TeamsDb,
    core_db: Db,
}

#[derive(Clone)]
pub struct Teams {
    inner: Arc<TeamsInner>,
}

impl Teams {
    pub fn builder() -> TeamsBuilder {
        TeamsBuilder { pool: None }
    }

    pub fn teams_db(&self) -> &TeamsDb {
        &self.inner.teams_db
    }

    pub fn core_db(&self) -> &Db {
        &self.inner.core_db
    }
}

pub struct TeamsBuilder {
    pool: Option<SqlitePool>,
}

impl TeamsBuilder {
    pub fn with_pool(mut self, pool: SqlitePool) -> Self {
        self.pool = Some(pool);
        self
    }

    pub async fn build(self) -> Result<Teams, AuthError> {
        let pool = self
            .pool
            .ok_or_else(|| AuthError::Validation("pool is required".into()))?;
        // Core migrations first — teams tables reference core tables via FK
        let core_db = Db::new(pool.clone()).await?;
        let teams_db = TeamsDb::new(pool).await?;
        Ok(Teams {
            inner: Arc::new(TeamsInner { teams_db, core_db }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::test_pool;

    #[tokio::test]
    async fn build_teams_handle() {
        let pool = test_pool().await;
        // Core migrations must run first
        Db::new(pool.clone()).await.unwrap();
        let teams = Teams::builder().with_pool(pool).build().await;
        assert!(teams.is_ok());
    }

    #[tokio::test]
    async fn build_without_pool_fails() {
        let result = Teams::builder().build().await;
        assert!(result.is_err());
    }
}
```

- [ ] **Step 4: Update `crates/teams/teams.rs`**

```rust
pub mod db;
pub mod handle;
pub mod types;

pub use handle::{Teams, TeamsBuilder};
pub use types::*;
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p allowthem-teams`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/teams/db.rs crates/teams/handle.rs crates/teams/teams.rs
git commit -m "feat(teams): add TeamsDb and Teams handle with builder"
```

---

### Task 4: Org CRUD operations

**Files:**
- Create: `crates/teams/orgs.rs`
- Modify: `crates/teams/teams.rs`

- [ ] **Step 1: Write tests for org CRUD**

Create `crates/teams/orgs.rs` with the full implementation and tests. The impl methods go on `Teams` (the handle), using `self.teams_db().pool()` for teams queries and `self.core_db()` for core queries (audit, users).

```rust
use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::{RoleId, UserId};

use crate::handle::Teams;
use crate::types::{Org, OrgId, OrgMembershipId, OrgSlug};

fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") {
            if msg.contains("slug") {
                return AuthError::Conflict("org slug already exists".into());
            }
            return AuthError::Conflict(msg.to_string());
        }
    }
    AuthError::Database(err)
}

impl Teams {
    pub async fn create_org(
        &self,
        name: &str,
        slug: &OrgSlug,
        owner_id: UserId,
        owner_role_id: RoleId,
    ) -> Result<Org, AuthError> {
        let pool = self.teams_db().pool();
        let id = OrgId::new();
        let membership_id = OrgMembershipId::new();
        let now = chrono::Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let mut tx = pool.begin().await.map_err(AuthError::Database)?;

        sqlx::query(
            "INSERT INTO allowthem_orgs (id, name, slug, owner_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(slug)
        .bind(owner_id)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;

        sqlx::query(
            "INSERT INTO allowthem_org_members (id, org_id, user_id, role_id, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(membership_id)
        .bind(id)
        .bind(owner_id)
        .bind(owner_role_id)
        .bind(&now_str)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::Database)?;

        tx.commit().await.map_err(AuthError::Database)?;

        let _ = self
            .core_db()
            .log_audit(
                AuditEvent::OrgCreated,
                Some(&owner_id),
                Some(&id.to_string()),
                None,
                None,
                None,
            )
            .await;

        Ok(Org {
            id,
            name: name.to_owned(),
            slug: slug.clone(),
            owner_id,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_org(&self, id: OrgId) -> Result<Option<Org>, AuthError> {
        sqlx::query_as::<_, Org>(
            "SELECT id, name, slug, owner_id, created_at, updated_at \
             FROM allowthem_orgs WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn get_org_by_slug(&self, slug: &OrgSlug) -> Result<Option<Org>, AuthError> {
        sqlx::query_as::<_, Org>(
            "SELECT id, name, slug, owner_id, created_at, updated_at \
             FROM allowthem_orgs WHERE slug = ?",
        )
        .bind(slug)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn list_orgs_for_user(&self, user_id: UserId) -> Result<Vec<Org>, AuthError> {
        sqlx::query_as::<_, Org>(
            "SELECT o.id, o.name, o.slug, o.owner_id, o.created_at, o.updated_at \
             FROM allowthem_orgs o \
             JOIN allowthem_org_members m ON m.org_id = o.id \
             WHERE m.user_id = ? \
             ORDER BY o.created_at",
        )
        .bind(user_id)
        .fetch_all(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn update_org(
        &self,
        id: OrgId,
        name: &str,
        slug: &OrgSlug,
    ) -> Result<Org, AuthError> {
        let now_str = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let result = sqlx::query(
            "UPDATE allowthem_orgs SET name = ?, slug = ?, updated_at = ? WHERE id = ?",
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

        self.get_org(id)
            .await?
            .ok_or(AuthError::NotFound)
    }

    pub async fn delete_org(&self, id: OrgId) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_orgs WHERE id = ?")
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
                AuditEvent::OrgDeleted,
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
    use allowthem_core::{AllowThemBuilder, RoleName};

    use super::*;
    use crate::handle::Teams;

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

    #[tokio::test]
    async fn create_and_get_org() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("my-org").unwrap();
        let org = teams
            .create_org("My Org", &slug, owner_id, role_id)
            .await
            .unwrap();
        assert_eq!(org.name, "My Org");
        assert_eq!(org.slug.as_str(), "my-org");
        assert_eq!(org.owner_id, owner_id);

        let fetched = teams.get_org(org.id).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id, org.id);
    }

    #[tokio::test]
    async fn create_org_duplicate_slug_fails() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("dup-slug").unwrap();
        teams
            .create_org("Org 1", &slug, owner_id, role_id)
            .await
            .unwrap();

        let result = teams
            .create_org("Org 2", &slug, owner_id, role_id)
            .await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
    }

    #[tokio::test]
    async fn get_org_by_slug() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("slug-lookup").unwrap();
        let org = teams
            .create_org("Slug Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let fetched = teams.get_org_by_slug(&slug).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id, org.id);
    }

    #[tokio::test]
    async fn update_org() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("old-slug").unwrap();
        let org = teams
            .create_org("Old Name", &slug, owner_id, role_id)
            .await
            .unwrap();

        let new_slug = OrgSlug::new("new-slug").unwrap();
        let updated = teams.update_org(org.id, "New Name", &new_slug).await.unwrap();
        assert_eq!(updated.name, "New Name");
        assert_eq!(updated.slug.as_str(), "new-slug");
    }

    #[tokio::test]
    async fn delete_org() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("doomed").unwrap();
        let org = teams
            .create_org("Doomed Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        teams.delete_org(org.id).await.unwrap();
        let fetched = teams.get_org(org.id).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_org_returns_not_found() {
        let (teams, _, _) = setup().await;
        let result = teams.delete_org(OrgId::new()).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }
}
```

- [ ] **Step 2: Add module to `crates/teams/teams.rs`**

```rust
pub mod db;
pub mod handle;
pub mod orgs;
pub mod types;

pub use handle::{Teams, TeamsBuilder};
pub use types::*;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p allowthem-teams orgs::tests`
Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add crates/teams/orgs.rs crates/teams/teams.rs
git commit -m "feat(teams): add org CRUD operations"
```

---

### Task 5: Org membership operations

**Files:**
- Create: `crates/teams/org_members.rs`
- Modify: `crates/teams/teams.rs`

- [ ] **Step 1: Write org membership methods and tests**

Create `crates/teams/org_members.rs`. This includes `transfer_ownership` since it depends on `get_org_membership`:

```rust
use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::{RoleId, UserId};

use crate::handle::Teams;
use crate::types::{OrgId, OrgMembership, OrgMembershipId};

impl Teams {
    pub async fn transfer_ownership(
        &self,
        org_id: OrgId,
        new_owner_id: UserId,
    ) -> Result<(), AuthError> {
        let membership = self.get_org_membership(org_id, new_owner_id).await?;
        if membership.is_none() {
            return Err(AuthError::NotFound);
        }

        let now_str = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let result = sqlx::query(
            "UPDATE allowthem_orgs SET owner_id = ?, updated_at = ? WHERE id = ?",
        )
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
                None,
                Some(&org_id.to_string()),
                None,
                None,
                Some(&new_owner_id.to_string()),
            )
            .await;

        Ok(())
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
                    return AuthError::Conflict("user already a member of this org".into());
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

    pub async fn remove_org_member(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<(), AuthError> {
        // Cannot remove the owner
        let org = self
            .get_org(org_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if org.owner_id == user_id {
            return Err(AuthError::Forbidden(
                "cannot remove the org owner".into(),
            ));
        }

        let pool = self.teams_db().pool();
        let mut tx = pool.begin().await.map_err(AuthError::Database)?;

        // Remove from all teams in this org
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

        // Remove org membership
        let result = sqlx::query(
            "DELETE FROM allowthem_org_members WHERE org_id = ? AND user_id = ?",
        )
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
            "UPDATE allowthem_org_members SET role_id = ? WHERE org_id = ? AND user_id = ?",
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

    pub async fn list_org_members(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<OrgMembership>, AuthError> {
        sqlx::query_as::<_, OrgMembership>(
            "SELECT id, org_id, user_id, role_id, created_at \
             FROM allowthem_org_members WHERE org_id = ? \
             ORDER BY created_at",
        )
        .bind(org_id)
        .fetch_all(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }

    pub async fn get_org_membership(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<Option<OrgMembership>, AuthError> {
        sqlx::query_as::<_, OrgMembership>(
            "SELECT id, org_id, user_id, role_id, created_at \
             FROM allowthem_org_members WHERE org_id = ? AND user_id = ?",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(self.teams_db().pool())
        .await
        .map_err(AuthError::Database)
    }
}

#[cfg(test)]
mod tests {
    use allowthem_core::{AllowThemBuilder, RoleName};

    use super::*;
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

    #[tokio::test]
    async fn create_org_adds_owner_as_member() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("mem-org").unwrap();
        let org = teams
            .create_org("Mem Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let membership = teams.get_org_membership(org.id, owner_id).await.unwrap();
        assert!(membership.is_some());
        assert_eq!(membership.unwrap().role_id, role_id);
    }

    #[tokio::test]
    async fn add_and_list_org_members() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("list-org").unwrap();
        let org = teams
            .create_org("List Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let member_role = teams
            .core_db()
            .create_role(&RoleName::new("member"), None)
            .await
            .unwrap();
        let email2 = allowthem_core::Email::new("member@example.com".into()).unwrap();
        let user2 = teams
            .core_db()
            .create_user(email2, "password123", None, None)
            .await
            .unwrap();

        teams
            .add_org_member(org.id, user2.id, member_role.id)
            .await
            .unwrap();

        let members = teams.list_org_members(org.id).await.unwrap();
        assert_eq!(members.len(), 2);
    }

    #[tokio::test]
    async fn add_duplicate_member_fails() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("dup-org").unwrap();
        let org = teams
            .create_org("Dup Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let result = teams.add_org_member(org.id, owner_id, role_id).await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
    }

    #[tokio::test]
    async fn remove_org_member() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("rm-org").unwrap();
        let org = teams
            .create_org("Rm Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let email2 = allowthem_core::Email::new("removable@example.com".into()).unwrap();
        let user2 = teams
            .core_db()
            .create_user(email2, "password123", None, None)
            .await
            .unwrap();
        teams
            .add_org_member(org.id, user2.id, role_id)
            .await
            .unwrap();

        teams.remove_org_member(org.id, user2.id).await.unwrap();
        let membership = teams.get_org_membership(org.id, user2.id).await.unwrap();
        assert!(membership.is_none());
    }

    #[tokio::test]
    async fn cannot_remove_owner() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("owner-org").unwrap();
        let org = teams
            .create_org("Owner Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let result = teams.remove_org_member(org.id, owner_id).await;
        assert!(matches!(result, Err(AuthError::Forbidden(_))));
    }

    #[tokio::test]
    async fn update_member_role() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("role-org").unwrap();
        let org = teams
            .create_org("Role Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let new_role = teams
            .core_db()
            .create_role(&RoleName::new("admin"), None)
            .await
            .unwrap();
        teams
            .update_org_member_role(org.id, owner_id, new_role.id)
            .await
            .unwrap();

        let membership = teams
            .get_org_membership(org.id, owner_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(membership.role_id, new_role.id);
    }

    #[tokio::test]
    async fn list_orgs_for_user() {
        let (teams, owner_id, role_id) = setup().await;
        let slug1 = OrgSlug::new("user-org-a").unwrap();
        let slug2 = OrgSlug::new("user-org-b").unwrap();
        teams
            .create_org("Org A", &slug1, owner_id, role_id)
            .await
            .unwrap();
        teams
            .create_org("Org B", &slug2, owner_id, role_id)
            .await
            .unwrap();

        let orgs = teams.list_orgs_for_user(owner_id).await.unwrap();
        assert_eq!(orgs.len(), 2);
    }

    #[tokio::test]
    async fn transfer_ownership() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("xfer-org").unwrap();
        let org = teams
            .create_org("Xfer Org", &slug, owner_id, role_id)
            .await
            .unwrap();

        let email2 = allowthem_core::Email::new("new-owner@example.com".into()).unwrap();
        let user2 = teams
            .core_db()
            .create_user(email2, "password123", None, None)
            .await
            .unwrap();
        teams
            .add_org_member(org.id, user2.id, role_id)
            .await
            .unwrap();

        teams.transfer_ownership(org.id, user2.id).await.unwrap();
        let updated = teams.get_org(org.id).await.unwrap().unwrap();
        assert_eq!(updated.owner_id, user2.id);
    }

    #[tokio::test]
    async fn transfer_to_non_member_fails() {
        let (teams, owner_id, role_id) = setup().await;
        let slug = OrgSlug::new("no-xfer").unwrap();
        let org = teams
            .create_org("No Xfer", &slug, owner_id, role_id)
            .await
            .unwrap();

        let result = teams.transfer_ownership(org.id, UserId::new()).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }
}
```

- [ ] **Step 2: Add module to `crates/teams/teams.rs`**

Add `pub mod org_members;` to the module list.

- [ ] **Step 3: Run tests**

Run: `cargo test -p allowthem-teams org_members::tests`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add crates/teams/org_members.rs crates/teams/teams.rs
git commit -m "feat(teams): add org membership CRUD with owner protection"
```

---

### Task 6: Team CRUD operations

**Files:**
- Create: `crates/teams/team_ops.rs`
- Modify: `crates/teams/teams.rs`

- [ ] **Step 1: Write team CRUD methods and tests**

Create `crates/teams/team_ops.rs`:

```rust
use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::UserId;

use crate::handle::Teams;
use crate::types::{OrgId, Team, TeamId, TeamSlug};

fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") {
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
                Some(&org_id.to_string()),
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
    use allowthem_core::{AllowThemBuilder, RoleName};

    use super::*;
    use crate::handle::Teams;
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
        assert_eq!(team.org_id, org_id);

        let fetched = teams.get_team(team.id).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id, team.id);
    }

    #[tokio::test]
    async fn duplicate_slug_in_same_org_fails() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("dup-team").unwrap();
        teams
            .create_team(org_id, "Team A", &slug)
            .await
            .unwrap();

        let result = teams.create_team(org_id, "Team B", &slug).await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
    }

    #[tokio::test]
    async fn get_team_by_slug() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("find-me").unwrap();
        let team = teams
            .create_team(org_id, "Find Me", &slug)
            .await
            .unwrap();

        let fetched = teams.get_team_by_slug(org_id, &slug).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id, team.id);
    }

    #[tokio::test]
    async fn list_teams_for_org() {
        let (teams, org_id) = setup().await;
        let s1 = TeamSlug::new("team-a").unwrap();
        let s2 = TeamSlug::new("team-b").unwrap();
        teams.create_team(org_id, "A", &s1).await.unwrap();
        teams.create_team(org_id, "B", &s2).await.unwrap();

        let list = teams.list_teams_for_org(org_id).await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn update_team() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("old-team").unwrap();
        let team = teams
            .create_team(org_id, "Old", &slug)
            .await
            .unwrap();

        let new_slug = TeamSlug::new("new-team").unwrap();
        let updated = teams
            .update_team(team.id, "New", &new_slug)
            .await
            .unwrap();
        assert_eq!(updated.name, "New");
        assert_eq!(updated.slug.as_str(), "new-team");
    }

    #[tokio::test]
    async fn delete_team() {
        let (teams, org_id) = setup().await;
        let slug = TeamSlug::new("doomed-team").unwrap();
        let team = teams
            .create_team(org_id, "Doomed", &slug)
            .await
            .unwrap();

        teams.delete_team(team.id).await.unwrap();
        let fetched = teams.get_team(team.id).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_team_returns_not_found() {
        let (teams, _) = setup().await;
        let result = teams.delete_team(TeamId::new()).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }
}
```

- [ ] **Step 2: Add module to `crates/teams/teams.rs`**

Add `pub mod team_ops;` to the module list.

- [ ] **Step 3: Run tests**

Run: `cargo test -p allowthem-teams team_ops::tests`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add crates/teams/team_ops.rs crates/teams/teams.rs
git commit -m "feat(teams): add team CRUD operations"
```

---

### Task 7: Team membership operations

**Files:**
- Create: `crates/teams/team_members.rs`
- Modify: `crates/teams/teams.rs`

- [ ] **Step 1: Write team membership methods and tests**

Create `crates/teams/team_members.rs`:

```rust
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
        // Look up which org this team belongs to
        let team = self
            .get_team(team_id)
            .await?
            .ok_or(AuthError::NotFound)?;

        // Enforce: user must be an org member
        let org_membership = self.get_org_membership(team.org_id, user_id).await?;
        if org_membership.is_none() {
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
                    return AuthError::Conflict("user already a member of this team".into());
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
        let result = sqlx::query(
            "DELETE FROM allowthem_team_members WHERE team_id = ? AND user_id = ?",
        )
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
            "UPDATE allowthem_team_members SET role_id = ? WHERE team_id = ? AND user_id = ?",
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
             FROM allowthem_team_members WHERE team_id = ? \
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
    use allowthem_core::{AllowThemBuilder, RoleName};

    use super::*;
    use crate::types::{OrgId, OrgSlug, TeamSlug};

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

    #[tokio::test]
    async fn add_team_member_requires_org_membership() {
        let (teams, org_id, _, role_id) = setup().await;
        let slug = TeamSlug::new("eng").unwrap();
        let team = teams
            .create_team(org_id, "Engineering", &slug)
            .await
            .unwrap();

        // Non-org-member should be rejected
        let outsider = UserId::new();
        let result = teams.add_team_member(team.id, outsider, role_id).await;
        assert!(matches!(result, Err(AuthError::Forbidden(_))));
    }

    #[tokio::test]
    async fn add_and_list_team_members() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let slug = TeamSlug::new("eng").unwrap();
        let team = teams
            .create_team(org_id, "Engineering", &slug)
            .await
            .unwrap();

        // Owner is already an org member
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
        let slug = TeamSlug::new("dup").unwrap();
        let team = teams
            .create_team(org_id, "Dup", &slug)
            .await
            .unwrap();

        teams
            .add_team_member(team.id, owner_id, role_id)
            .await
            .unwrap();
        let result = teams.add_team_member(team.id, owner_id, role_id).await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
    }

    #[tokio::test]
    async fn remove_team_member() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let slug = TeamSlug::new("rm-team").unwrap();
        let team = teams
            .create_team(org_id, "Rm", &slug)
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
        let slug = TeamSlug::new("no-rm").unwrap();
        let team = teams
            .create_team(org_id, "No Rm", &slug)
            .await
            .unwrap();

        let result = teams.remove_team_member(team.id, UserId::new()).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }

    #[tokio::test]
    async fn update_team_member_role() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let slug = TeamSlug::new("role-team").unwrap();
        let team = teams
            .create_team(org_id, "Role", &slug)
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
        assert_eq!(members[0].role_id, new_role.id);
    }

    #[tokio::test]
    async fn removing_org_member_cascades_to_team_members() {
        let (teams, org_id, _, role_id) = setup().await;
        let slug = TeamSlug::new("cascade").unwrap();
        let team = teams
            .create_team(org_id, "Cascade", &slug)
            .await
            .unwrap();

        // Add second user to org and team
        let email2 = allowthem_core::Email::new("cascadee@example.com".into()).unwrap();
        let user2 = teams
            .core_db()
            .create_user(email2, "password123", None, None)
            .await
            .unwrap();
        teams
            .add_org_member(org_id, user2.id, role_id)
            .await
            .unwrap();
        teams
            .add_team_member(team.id, user2.id, role_id)
            .await
            .unwrap();

        // Remove from org — should cascade to team
        teams.remove_org_member(org_id, user2.id).await.unwrap();

        let members = teams.list_team_members(team.id).await.unwrap();
        assert!(members.is_empty());
    }

    #[tokio::test]
    async fn list_teams_for_user() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let s1 = TeamSlug::new("team-x").unwrap();
        let s2 = TeamSlug::new("team-y").unwrap();
        let t1 = teams.create_team(org_id, "X", &s1).await.unwrap();
        let t2 = teams.create_team(org_id, "Y", &s2).await.unwrap();

        teams
            .add_team_member(t1.id, owner_id, role_id)
            .await
            .unwrap();
        teams
            .add_team_member(t2.id, owner_id, role_id)
            .await
            .unwrap();

        let user_teams = teams.list_teams_for_user(owner_id).await.unwrap();
        assert_eq!(user_teams.len(), 2);
    }
}
```

- [ ] **Step 2: Add module to `crates/teams/teams.rs`**

Add `pub mod team_members;` to the module list.

- [ ] **Step 3: Run tests**

Run: `cargo test -p allowthem-teams team_members::tests`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add crates/teams/team_members.rs crates/teams/teams.rs
git commit -m "feat(teams): add team membership with org membership enforcement"
```

---

### Task 8: Invitation operations (delegating to core)

**Files:**
- Create: `crates/teams/invitations.rs`
- Modify: `crates/teams/teams.rs`

- [ ] **Step 1: Write invitation wrapper methods and tests**

Create `crates/teams/invitations.rs`:

```rust
use chrono::{DateTime, Utc};
use serde_json::json;

use allowthem_core::Invitation;
use allowthem_core::audit::AuditEvent;
use allowthem_core::error::AuthError;
use allowthem_core::types::{Email, InvitationId, RoleId, UserId};

use crate::handle::Teams;
use crate::types::{OrgId, OrgMembership};

impl Teams {
    pub async fn invite_to_org(
        &self,
        org_id: OrgId,
        email: &Email,
        role_id: RoleId,
        invited_by: UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<(String, Invitation), AuthError> {
        // Check for existing pending invite for this email+org
        let pending = self.list_pending_org_invitations(org_id).await?;
        let already_invited = pending.iter().any(|inv| {
            inv.email
                .as_ref()
                .map(|e| e.as_str() == email.as_str())
                .unwrap_or(false)
        });
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

        let (raw_token, invitation) = self
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
                Some(email.as_str()),
            )
            .await;

        Ok((raw_token, invitation))
    }

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

        let metadata: serde_json::Value = serde_json::from_str(
            invitation.metadata.as_deref().ok_or(AuthError::NotFound)?,
        )
        .map_err(|_| AuthError::Validation("invalid invitation metadata".into()))?;

        let org_id_str = metadata["org_id"]
            .as_str()
            .ok_or(AuthError::Validation("missing org_id in metadata".into()))?;
        let role_id_str = metadata["role_id"]
            .as_str()
            .ok_or(AuthError::Validation("missing role_id in metadata".into()))?;

        let org_id = OrgId::from_uuid(
            uuid::Uuid::parse_str(org_id_str)
                .map_err(|_| AuthError::Validation("invalid org_id".into()))?,
        );
        let role_id = RoleId::from_uuid(
            uuid::Uuid::parse_str(role_id_str)
                .map_err(|_| AuthError::Validation("invalid role_id".into()))?,
        );

        // Check if already a member — idempotent
        if let Some(existing) = self.get_org_membership(org_id, user_id).await? {
            self.core_db().consume_invitation(invitation.id).await?;
            return Ok(existing);
        }

        // Consume invitation and create membership
        self.core_db().consume_invitation(invitation.id).await?;
        let membership = self.add_org_member(org_id, user_id, role_id).await?;

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

        Ok(membership)
    }

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

    pub async fn revoke_invitation(
        &self,
        invitation_id: InvitationId,
    ) -> Result<(), AuthError> {
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

    pub async fn list_pending_org_invitations(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<Invitation>, AuthError> {
        let all_pending = self.core_db().list_pending_invitations().await?;
        let org_id_str = org_id.to_string();

        Ok(all_pending
            .into_iter()
            .filter(|inv| {
                inv.metadata
                    .as_deref()
                    .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
                    .and_then(|v| v["org_id"].as_str().map(|s| s == org_id_str))
                    .unwrap_or(false)
            })
            .collect())
    }

    pub async fn resolve_invitations_for_email(
        &self,
        email: &Email,
    ) -> Result<Vec<Invitation>, AuthError> {
        let all_pending = self.core_db().list_pending_invitations().await?;

        Ok(all_pending
            .into_iter()
            .filter(|inv| {
                let is_org_invite = inv
                    .metadata
                    .as_deref()
                    .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
                    .map(|v| v.get("org_id").is_some())
                    .unwrap_or(false);

                let email_matches = inv
                    .email
                    .as_ref()
                    .map(|e| e.as_str() == email.as_str())
                    .unwrap_or(false);

                is_org_invite && email_matches
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use allowthem_core::{AllowThemBuilder, RoleName};

    use super::*;
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
        let invitee_email = Email::new("invitee@example.com".into()).unwrap();
        let expires = Utc::now() + Duration::hours(24);

        let (raw_token, invitation) = teams
            .invite_to_org(org_id, &invitee_email, role_id, owner_id, expires)
            .await
            .unwrap();
        assert!(!raw_token.is_empty());
        assert!(invitation.metadata.is_some());

        // Create the invitee user
        let invitee = teams
            .core_db()
            .create_user(invitee_email, "password123", None, None)
            .await
            .unwrap();

        let membership = teams
            .accept_invitation(&raw_token, invitee.id)
            .await
            .unwrap();
        assert_eq!(membership.org_id, org_id);
        assert_eq!(membership.user_id, invitee.id);
        assert_eq!(membership.role_id, role_id);
    }

    #[tokio::test]
    async fn accept_when_already_member_is_idempotent() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let invitee_email = Email::new("already@example.com".into()).unwrap();
        let expires = Utc::now() + Duration::hours(24);

        let (raw_token, _) = teams
            .invite_to_org(org_id, &invitee_email, role_id, owner_id, expires)
            .await
            .unwrap();

        // Create invitee and add them directly
        let invitee = teams
            .core_db()
            .create_user(invitee_email, "password123", None, None)
            .await
            .unwrap();
        teams
            .add_org_member(org_id, invitee.id, role_id)
            .await
            .unwrap();

        // Accepting should succeed (idempotent)
        let membership = teams
            .accept_invitation(&raw_token, invitee.id)
            .await
            .unwrap();
        assert_eq!(membership.org_id, org_id);
    }

    #[tokio::test]
    async fn decline_invitation() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let email = Email::new("decliner@example.com".into()).unwrap();
        let expires = Utc::now() + Duration::hours(24);

        let (raw_token, _) = teams
            .invite_to_org(org_id, &email, role_id, owner_id, expires)
            .await
            .unwrap();

        teams.decline_invitation(&raw_token).await.unwrap();

        // Token should no longer validate
        let result = teams.accept_invitation(&raw_token, owner_id).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }

    #[tokio::test]
    async fn revoke_invitation() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let email = Email::new("revoked@example.com".into()).unwrap();
        let expires = Utc::now() + Duration::hours(24);

        let (_, invitation) = teams
            .invite_to_org(org_id, &email, role_id, owner_id, expires)
            .await
            .unwrap();

        teams.revoke_invitation(invitation.id).await.unwrap();

        let pending = teams
            .list_pending_org_invitations(org_id)
            .await
            .unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn list_pending_org_invitations() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let expires = Utc::now() + Duration::hours(24);

        let e1 = Email::new("a@example.com".into()).unwrap();
        let e2 = Email::new("b@example.com".into()).unwrap();
        teams
            .invite_to_org(org_id, &e1, role_id, owner_id, expires)
            .await
            .unwrap();
        teams
            .invite_to_org(org_id, &e2, role_id, owner_id, expires)
            .await
            .unwrap();

        let pending = teams
            .list_pending_org_invitations(org_id)
            .await
            .unwrap();
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn resolve_invitations_for_email() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let expires = Utc::now() + Duration::hours(24);

        let target = Email::new("target@example.com".into()).unwrap();
        let other = Email::new("other@example.com".into()).unwrap();
        teams
            .invite_to_org(org_id, &target, role_id, owner_id, expires)
            .await
            .unwrap();
        teams
            .invite_to_org(org_id, &other, role_id, owner_id, expires)
            .await
            .unwrap();

        let resolved = teams
            .resolve_invitations_for_email(&target)
            .await
            .unwrap();
        assert_eq!(resolved.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_invite_same_email_same_org_fails() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let email = Email::new("dup@example.com".into()).unwrap();
        let expires = Utc::now() + Duration::hours(24);

        teams
            .invite_to_org(org_id, &email, role_id, owner_id, expires)
            .await
            .unwrap();

        let result = teams
            .invite_to_org(org_id, &email, role_id, owner_id, expires)
            .await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
    }

    #[tokio::test]
    async fn accept_expired_invitation_fails() {
        let (teams, org_id, owner_id, role_id) = setup().await;
        let email = Email::new("expired@example.com".into()).unwrap();
        let expires = Utc::now() - Duration::hours(1);

        let (raw_token, _) = teams
            .invite_to_org(org_id, &email, role_id, owner_id, expires)
            .await
            .unwrap();

        let result = teams.accept_invitation(&raw_token, owner_id).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }
}
```

- [ ] **Step 2: Add module to `crates/teams/teams.rs`**

Add `pub mod invitations;` to the module list.

- [ ] **Step 3: Run tests**

Run: `cargo test -p allowthem-teams invitations::tests`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add crates/teams/invitations.rs crates/teams/teams.rs
git commit -m "feat(teams): add invitation operations delegating to core"
```

---

### Task 9: Final exports and full test suite

**Files:**
- Modify: `crates/teams/teams.rs`

- [ ] **Step 1: Finalize `crates/teams/teams.rs` with all re-exports**

```rust
pub mod db;
pub mod handle;
pub mod invitations;
pub mod org_members;
pub mod orgs;
pub mod team_members;
pub mod team_ops;
pub mod types;

pub use handle::{Teams, TeamsBuilder};
pub use types::*;
```

- [ ] **Step 2: Run the full test suite**

Run: `just test`
Expected: All workspace tests pass, including all new teams crate tests and all existing core/server/binary tests.

- [ ] **Step 3: Run clippy**

Run: `just clippy`
Expected: No warnings.

- [ ] **Step 4: Run fmt**

Run: `just fmt`
Expected: No changes needed (or formats cleanly).

- [ ] **Step 5: Commit any fmt changes**

```bash
git add -A
git commit -m "chore(teams): finalize exports and pass clippy/fmt"
```

---

### Task 10: Update sqlx offline cache

**Files:**
- Modify: `.sqlx/` directory (regenerated)

- [ ] **Step 1: Regenerate sqlx offline cache**

Run: `just sqlx-prepare`
Expected: The `.sqlx/` directory is updated with query metadata for the new teams crate queries.

- [ ] **Step 2: Verify build with offline mode**

Run: `just check`
Expected: Compiles successfully with the updated offline cache.

- [ ] **Step 3: Commit**

```bash
git add .sqlx/ Cargo.lock
git commit -m "chore: update sqlx offline cache for teams crate"
```
