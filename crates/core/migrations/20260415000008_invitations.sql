CREATE TABLE IF NOT EXISTS allowthem_invitations (
    id          TEXT PRIMARY KEY NOT NULL,
    email       TEXT,
    token_hash  TEXT NOT NULL,
    metadata    TEXT,
    invited_by  TEXT REFERENCES allowthem_users(id) ON DELETE SET NULL,
    expires_at  TEXT NOT NULL,
    consumed_at TEXT,
    created_at  TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token_hash ON allowthem_invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON allowthem_invitations(email);
