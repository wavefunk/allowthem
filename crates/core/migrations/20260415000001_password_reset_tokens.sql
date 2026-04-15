-- Block 2: Password reset tokens

CREATE TABLE IF NOT EXISTS allowthem_password_reset_tokens (
    id          TEXT    PRIMARY KEY NOT NULL,
    user_id     TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    token_hash  TEXT    NOT NULL UNIQUE,
    expires_at  TEXT    NOT NULL,
    used_at     TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id
    ON allowthem_password_reset_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at
    ON allowthem_password_reset_tokens(expires_at);
