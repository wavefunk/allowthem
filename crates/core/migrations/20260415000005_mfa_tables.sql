-- Block 7: MFA tables (TOTP secrets and recovery codes)

CREATE TABLE IF NOT EXISTS allowthem_mfa_secrets (
    id          TEXT    PRIMARY KEY NOT NULL,
    user_id     TEXT    NOT NULL UNIQUE REFERENCES allowthem_users(id) ON DELETE CASCADE,
    secret      TEXT    NOT NULL,  -- AES-256-GCM encrypted, base64-encoded
    enabled     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS allowthem_mfa_recovery_codes (
    id          TEXT    PRIMARY KEY NOT NULL,
    user_id     TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    code_hash   TEXT    NOT NULL,
    used_at     TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Note: allowthem_mfa_secrets.user_id already has an implicit B-tree index
-- from its UNIQUE constraint. No additional index needed (same pattern as
-- allowthem_users.email -- see block1 migration).

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id
    ON allowthem_mfa_recovery_codes(user_id);
