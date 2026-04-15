-- Block 1: Core tables for allowthem authentication

CREATE TABLE IF NOT EXISTS allowthem_users (
    id              TEXT    PRIMARY KEY NOT NULL,
    email           TEXT    NOT NULL UNIQUE,
    username        TEXT    UNIQUE,
    password_hash   TEXT,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_sessions (
    id              TEXT    PRIMARY KEY NOT NULL,
    token_hash      TEXT    NOT NULL UNIQUE,
    user_id         TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    ip_address      TEXT,
    user_agent      TEXT,
    expires_at      TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_roles (
    id              TEXT    PRIMARY KEY NOT NULL,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_user_roles (
    user_id         TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    role_id         TEXT    NOT NULL REFERENCES allowthem_roles(id) ON DELETE CASCADE,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS allowthem_permissions (
    id              TEXT    PRIMARY KEY NOT NULL,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_role_permissions (
    role_id         TEXT    NOT NULL REFERENCES allowthem_roles(id) ON DELETE CASCADE,
    permission_id   TEXT    NOT NULL REFERENCES allowthem_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS allowthem_user_permissions (
    user_id         TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    permission_id   TEXT    NOT NULL REFERENCES allowthem_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, permission_id)
);

-- Indexes for common query patterns
-- Note: allowthem_users.email and allowthem_users.username already have implicit B-tree
-- indexes from their UNIQUE constraints. No additional indexes needed for those columns.

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON allowthem_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON allowthem_sessions(expires_at);
