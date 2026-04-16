CREATE TABLE IF NOT EXISTS allowthem_signing_keys (
    id                  TEXT    PRIMARY KEY NOT NULL,
    private_key_enc     BLOB    NOT NULL,
    private_key_nonce   BLOB    NOT NULL,
    public_key_pem      TEXT    NOT NULL,
    algorithm           TEXT    NOT NULL DEFAULT 'RS256',
    is_active           INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_is_active
    ON allowthem_signing_keys(is_active);
