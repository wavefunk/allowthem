# Teams Crate Design

## Overview

A new `allowthem-teams` crate that adds multi-tenant organization and team management to allowthem. Integrators create orgs, create teams within orgs, assign (and invite) members with roles, and manage them. The crate is purely additive — integrators who don't need multi-tenancy don't pay for it.

## Decisions

- **Flat hierarchy**: Orgs contain teams. No nesting of teams within teams.
- **Orgs always required**: Every team belongs to exactly one org. Apps can make orgs transparent to users if they only want to surface teams.
- **Single owner**: Every org has exactly one owner (the creator). Ownership is transferable. Destructive operations require the owner.
- **Scoped role reuse**: Reuses the existing `allowthem_roles` and `allowthem_permissions` tables. Scoping happens via the membership FK — a user can hold different roles in different orgs/teams.
- **Separate membership tables**: `org_members` and `team_members` as distinct tables. Org membership is a prerequisite for team membership, enforced at the application layer.
- **Standalone handle**: The teams crate gets its own `Teams` handle constructed with the same `SqlitePool` from `AllowThem`. Owns its own migrations.
- **Invitation reuse**: Delegates to core's existing invitation system (`allowthem_invitations`) with JSON metadata for org/role context. No separate invitation tables.
- **Both invite paths**: Direct-add for existing users, email-based invite for users not yet registered.

## Domain Types

### ID types (using `id_newtype!` from core)

- `OrgId`
- `TeamId`
- `OrgMembershipId`
- `TeamMembershipId`

### Structs

```rust
pub struct Org {
    pub id: OrgId,
    pub name: String,
    pub slug: OrgSlug,
    pub owner_id: UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Team {
    pub id: TeamId,
    pub org_id: OrgId,
    pub name: String,
    pub slug: TeamSlug,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct OrgMembership {
    pub id: OrgMembershipId,
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role_id: RoleId,
    pub created_at: DateTime<Utc>,
}

pub struct TeamMembership {
    pub id: TeamMembershipId,
    pub team_id: TeamId,
    pub user_id: UserId,
    pub role_id: RoleId,
    pub created_at: DateTime<Utc>,
}
```

### Validated newtypes

- `OrgSlug(String)` — URL-safe, lowercase, hyphens. Globally unique.
- `TeamSlug(String)` — URL-safe, lowercase, hyphens. Unique within an org.

### InvitationStatus

Not a separate type — core's `Invitation` tracks status via `consumed_at`. Pending = unconsumed + not expired.

## Database Schema

Four new tables. Invitations use core's existing `allowthem_invitations`.

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

### Cascade behavior

- Deleting an org cascades to teams, org_members (via DB FK cascade). Team cascade deletes team_members.
- Removing a user from an org also removes them from all teams in that org — enforced at application layer in a transaction.

## Teams Handle

```rust
pub struct Teams {
    inner: Arc<TeamsInner>,
}

struct TeamsInner {
    db: TeamsDb,
}
```

`TeamsDb` wraps `SqlitePool`, runs its own migrations via `sqlx::migrate!("./migrations").set_ignore_missing(true)`.

### Builder

```rust
Teams::builder()
    .with_pool(pool)  // from AllowThem::db().pool().clone()
    .build()
    .await?
```

## API Surface

### Org operations

- `create_org(name, slug, owner_id, owner_role_id) -> Result<Org>` — creates org + adds owner as first org member with the given role
- `get_org(org_id) -> Result<Option<Org>>`
- `get_org_by_slug(slug) -> Result<Option<Org>>`
- `list_orgs_for_user(user_id) -> Result<Vec<Org>>`
- `update_org(org_id, name, slug) -> Result<Org>`
- `delete_org(org_id) -> Result<()>`
- `transfer_ownership(org_id, new_owner_id) -> Result<()>` — new owner must be an existing org member

### Org membership

- `add_org_member(org_id, user_id, role_id) -> Result<OrgMembership>`
- `remove_org_member(org_id, user_id) -> Result<()>` — fails if user is owner; removes from all teams in org (transaction)
- `update_org_member_role(org_id, user_id, role_id) -> Result<()>`
- `list_org_members(org_id) -> Result<Vec<OrgMembership>>`
- `get_org_membership(org_id, user_id) -> Result<Option<OrgMembership>>`

### Team operations

- `create_team(org_id, name, slug) -> Result<Team>`
- `get_team(team_id) -> Result<Option<Team>>`
- `get_team_by_slug(org_id, slug) -> Result<Option<Team>>`
- `list_teams_for_org(org_id) -> Result<Vec<Team>>`
- `list_teams_for_user(user_id) -> Result<Vec<Team>>`
- `update_team(team_id, name, slug) -> Result<Team>`
- `delete_team(team_id) -> Result<()>`

### Team membership

- `add_team_member(team_id, user_id, role_id) -> Result<TeamMembership>` — enforces org membership
- `remove_team_member(team_id, user_id) -> Result<()>`
- `update_team_member_role(team_id, user_id, role_id) -> Result<()>`
- `list_team_members(team_id) -> Result<Vec<TeamMembership>>`

### Invitations (delegates to core)

- `invite_to_org(org_id, email, role_id, invited_by, expires_at) -> Result<(String, Invitation)>` — calls `core::Db::create_invitation` with metadata `{"org_id": "...", "role_id": "..."}`
- `accept_invitation(raw_token, user_id) -> Result<OrgMembership>` — validates via core, parses metadata, creates org membership, consumes invitation (transaction)
- `decline_invitation(raw_token) -> Result<()>` — validates and consumes
- `list_pending_org_invitations(org_id) -> Result<Vec<Invitation>>` — filters core's pending invitations by metadata
- `revoke_invitation(invitation_id) -> Result<()>` — delegates to `core::Db::delete_invitation`
- `resolve_invitations_for_email(email) -> Result<Vec<Invitation>>` — surfaces pending org invites for a newly registered user

### Audit events

All mutating operations call `core::Db::log_audit()`. New `AuditEvent` variants added to core:

`OrgCreated`, `OrgUpdated`, `OrgDeleted`, `OrgMemberAdded`, `OrgMemberRemoved`, `OrgMemberRoleChanged`, `OrgOwnershipTransferred`, `TeamCreated`, `TeamUpdated`, `TeamDeleted`, `TeamMemberAdded`, `TeamMemberRemoved`, `TeamMemberRoleChanged`, `OrgInvitationCreated`, `OrgInvitationAccepted`, `OrgInvitationDeclined`, `OrgInvitationRevoked`

## Error Handling

Reuses `AuthError` from core. Existing variants cover most cases:

| Scenario | Error |
|----------|-------|
| Duplicate slug | `Conflict("org slug already exists")` |
| Duplicate team slug in org | `Conflict("team slug already exists in org")` |
| User already a member | `Conflict("user already a member")` |
| Org/team/membership not found | `NotFound` |
| Invitation already consumed | `Gone` (from core) |
| Add to team without org membership | `Forbidden` |
| Remove owner from org | `Forbidden` |
| Transfer ownership to non-member | `Forbidden` |
| Accept invitation when already member | Idempotent — consume invitation, return existing membership |

**New variant in core:** `AuthError::Forbidden` — for domain-level authorization failures (not HTTP-specific).

**Transactions:** Multi-step operations use `sqlx::Transaction`:
- `create_org` — create org + add owner as member with provided role
- `remove_org_member` — delete org membership + team memberships in that org
- `accept_invitation` — validate + consume + create membership

## Server Integration

### Extractors

```rust
pub struct OrgMember {
    pub user: User,
    pub org: Org,
    pub membership: OrgMembership,
}

pub struct TeamMember {
    pub user: User,
    pub team: Team,
    pub membership: TeamMembership,
}
```

Both validate session first (reusing AuthClient), then look up membership. Reject: 401 unauthenticated, 404 org/team not found, 403 not a member.

### Middleware

- `require_org_role(role_name)` — checks user's role in the org from path param
- `require_org_permission(permission_name)` — same, scoped to org

### Routes

Produced by the teams crate, merged into the main router by the integrator:

```rust
let ath = AllowThemBuilder::new(url).build().await?;
let teams = Teams::builder().with_pool(ath.db().pool().clone()).build().await?;

let auth_routes = AllRoutesBuilder::new().all_routes().build(&ath)?;
let team_routes = teams_routes(&teams, &ath);

let app = Router::new()
    .merge(auth_routes)
    .merge(team_routes);
```

### Route layout

```
POST   /orgs                                  — create org
GET    /orgs                                  — list user's orgs
GET    /orgs/:org_id                          — get org
PUT    /orgs/:org_id                          — update org
DELETE /orgs/:org_id                          — delete org
POST   /orgs/:org_id/transfer                 — transfer ownership

GET    /orgs/:org_id/members                  — list members
POST   /orgs/:org_id/members                  — add member (direct)
DELETE /orgs/:org_id/members/:user_id         — remove member
PUT    /orgs/:org_id/members/:user_id/role    — update role

POST   /orgs/:org_id/invitations              — create invitation
GET    /orgs/:org_id/invitations              — list pending
DELETE /orgs/:org_id/invitations/:id          — revoke

POST   /invitations/accept                    — accept (token in body)
POST   /invitations/decline                   — decline (token in body)

POST   /orgs/:org_id/teams                    — create team
GET    /orgs/:org_id/teams                    — list teams in org
GET    /teams/:team_id                        — get team
PUT    /teams/:team_id                        — update team
DELETE /teams/:team_id                        — delete team

GET    /teams/:team_id/members                — list members
POST   /teams/:team_id/members                — add member
DELETE /teams/:team_id/members/:user_id       — remove member
PUT    /teams/:team_id/members/:user_id/role  — update role
```

### Authorization

The teams crate provides data lookups. The integrator (or standalone binary) decides which roles authorize which actions:

- Org creation: any authenticated user
- Org mutation/deletion: owner only
- Member management: determined by user's role in the org
- Team creation: determined by org role
- Team member management: determined by team role or org role

## Crate Structure

```
crates/teams/
├── Cargo.toml
├── teams.rs            # lib root, re-exports
├── types.rs            # OrgId, TeamId, OrgSlug, TeamSlug, domain structs
├── handle.rs           # Teams handle + builder
├── db.rs               # TeamsDb wrapper, migrations
├── orgs.rs             # Org CRUD on TeamsDb
├── org_members.rs      # Org membership methods
├── team_ops.rs         # Team CRUD on TeamsDb
├── team_members.rs     # Team membership methods
├── invitations.rs      # Wrapper around core invitations
├── migrations/
│   └── YYYYMMDDHHMMSS_teams_tables.sql
```

### Dependencies

```toml
[dependencies]
allowthem-core = { path = "../core" }
sqlx = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
```

No axum dependency — pure data/logic layer. Server extractors, middleware, and routes live in `allowthem-server` which gains `allowthem-teams` as a dependency.

## Systems Reused from Core

| System | How reused |
|--------|-----------|
| Invitations | Delegates to `core::Db` methods, stores org context in metadata JSON |
| Roles/Permissions | Existing tables referenced via FK in membership tables |
| Audit logging | Extends `AuditEvent` enum, calls `core::Db::log_audit()` |
| Users | `get_user_by_email()` for direct-add |
| Types | `id_newtype!` macro for new IDs |
| Errors | `AuthError` reused directly, one new variant (`Forbidden`) |
| Email | `EmailSender` trait for invitation emails |
| Extractors | Pattern followed for OrgMember/TeamMember |
| Middleware | Pattern followed for require_org_role |
