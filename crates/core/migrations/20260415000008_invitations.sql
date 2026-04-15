CREATE TABLE allowthem_invitations (
    id          TEXT PRIMARY KEY NOT NULL,
    email       TEXT,
    token_hash  TEXT NOT NULL,
    metadata    TEXT,
    invited_by  TEXT,
    expires_at  TEXT NOT NULL,
    consumed_at TEXT,
    created_at  TEXT NOT NULL,

    FOREIGN KEY (invited_by) REFERENCES allowthem_users(id)
);

CREATE UNIQUE INDEX idx_invitations_token_hash ON allowthem_invitations(token_hash);
CREATE INDEX idx_invitations_email ON allowthem_invitations(email);
