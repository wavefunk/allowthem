ALTER TABLE allowthem_refresh_tokens ADD COLUMN authorization_code_id TEXT
    REFERENCES allowthem_authorization_codes(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_authorization_code_id
    ON allowthem_refresh_tokens(authorization_code_id);
