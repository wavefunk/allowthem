-- M35: OIDC application registry tables

CREATE TABLE IF NOT EXISTS allowthem_applications (
    id                  TEXT    PRIMARY KEY NOT NULL,
    name                TEXT    NOT NULL,
    client_id           TEXT    NOT NULL UNIQUE,
    client_secret_hash  TEXT    NOT NULL,
    redirect_uris       TEXT    NOT NULL DEFAULT '[]',  -- JSON array of strings
    logo_url            TEXT,
    primary_color       TEXT,
    is_trusted          INTEGER NOT NULL DEFAULT 0,
    created_by          TEXT    REFERENCES allowthem_users(id) ON DELETE SET NULL,
    is_active           INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_authorization_codes (
    id                      TEXT    PRIMARY KEY NOT NULL,
    application_id          TEXT    NOT NULL REFERENCES allowthem_applications(id) ON DELETE CASCADE,
    user_id                 TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    code_hash               TEXT    NOT NULL UNIQUE,
    redirect_uri            TEXT    NOT NULL,
    scopes                  TEXT    NOT NULL DEFAULT '[]',  -- JSON array of strings
    code_challenge          TEXT    NOT NULL,
    code_challenge_method   TEXT    NOT NULL DEFAULT 'S256',
    expires_at              TEXT    NOT NULL,
    used_at                 TEXT,
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_refresh_tokens (
    id              TEXT    PRIMARY KEY NOT NULL,
    application_id  TEXT    NOT NULL REFERENCES allowthem_applications(id) ON DELETE CASCADE,
    user_id         TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    token_hash      TEXT    NOT NULL UNIQUE,
    scopes          TEXT    NOT NULL DEFAULT '[]',  -- JSON array of strings
    expires_at      TEXT    NOT NULL,
    revoked_at      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_consents (
    id              TEXT    PRIMARY KEY NOT NULL,
    user_id         TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    application_id  TEXT    NOT NULL REFERENCES allowthem_applications(id) ON DELETE CASCADE,
    scopes          TEXT    NOT NULL DEFAULT '[]',  -- JSON array of strings
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(user_id, application_id)
);

-- Explicit named index on client_id for lookup visibility (UNIQUE constraint
-- creates the index implicitly, but named indexes match the convention in
-- 20260415000003_api_tokens.sql)
CREATE INDEX IF NOT EXISTS idx_applications_client_id
    ON allowthem_applications(client_id);

-- FK-column indexes (pattern: idx_sessions_user_id, idx_api_tokens_user_id)
CREATE INDEX IF NOT EXISTS idx_authorization_codes_application_id
    ON allowthem_authorization_codes(application_id);

CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id
    ON allowthem_authorization_codes(user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_application_id
    ON allowthem_refresh_tokens(application_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id
    ON allowthem_refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_consents_user_id
    ON allowthem_consents(user_id);

CREATE INDEX IF NOT EXISTS idx_consents_application_id
    ON allowthem_consents(application_id);

-- Expiry indexes for cleanup queries (pattern: idx_sessions_expires_at)
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at
    ON allowthem_authorization_codes(expires_at);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON allowthem_refresh_tokens(expires_at);
