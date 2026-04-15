-- Block 7: MFA challenge tokens for two-step login

CREATE TABLE IF NOT EXISTS allowthem_mfa_challenges (
    id          TEXT    PRIMARY KEY NOT NULL,
    token_hash  TEXT    NOT NULL UNIQUE,
    user_id     TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    expires_at  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id
    ON allowthem_mfa_challenges(user_id);
