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
