-- Make client_secret_hash nullable to support public clients (no client secret).
-- SQLite requires table recreation to change NOT NULL constraints.
PRAGMA foreign_keys = OFF;

CREATE TABLE allowthem_applications_new (
    id                  BLOB    PRIMARY KEY,
    name                TEXT    NOT NULL,
    client_id           TEXT    NOT NULL UNIQUE,
    client_type         TEXT    NOT NULL DEFAULT 'confidential'
                                CHECK (client_type IN ('confidential', 'public')),
    client_secret_hash  TEXT,
    redirect_uris       TEXT    NOT NULL,
    logo_url            TEXT,
    primary_color       TEXT,
    is_trusted          INTEGER NOT NULL DEFAULT 0,
    created_by          BLOB    REFERENCES allowthem_users(id),
    is_active           INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO allowthem_applications_new
    SELECT id, name, client_id, client_type, client_secret_hash, redirect_uris,
           logo_url, primary_color, is_trusted, created_by, is_active, created_at, updated_at
    FROM allowthem_applications;

DROP TABLE allowthem_applications;
ALTER TABLE allowthem_applications_new RENAME TO allowthem_applications;

PRAGMA foreign_keys = ON;
