CREATE TABLE IF NOT EXISTS allowthem_api_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON allowthem_api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON allowthem_api_tokens(token_hash);
