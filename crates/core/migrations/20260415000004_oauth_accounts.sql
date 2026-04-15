-- Block 6: OAuth state management and account linking

CREATE TABLE IF NOT EXISTS allowthem_oauth_states (
    id                    TEXT    PRIMARY KEY NOT NULL,
    state_hash            TEXT    NOT NULL UNIQUE,
    provider              TEXT    NOT NULL,
    redirect_uri          TEXT    NOT NULL,
    pkce_verifier         TEXT    NOT NULL,
    post_login_redirect   TEXT,
    expires_at            TEXT    NOT NULL,
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at
    ON allowthem_oauth_states(expires_at);

CREATE TABLE IF NOT EXISTS allowthem_oauth_accounts (
    id                  TEXT    PRIMARY KEY NOT NULL,
    user_id             TEXT    NOT NULL REFERENCES allowthem_users(id) ON DELETE CASCADE,
    provider            TEXT    NOT NULL,
    provider_user_id    TEXT    NOT NULL,
    email               TEXT    NOT NULL,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id
    ON allowthem_oauth_accounts(user_id);
