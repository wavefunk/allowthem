CREATE TABLE allowthem_social_providers (
    id                    TEXT PRIMARY KEY,
    provider_type         TEXT NOT NULL
                            CHECK (provider_type IN
                              ('google','github','apple','microsoft','custom_oidc')),
    display_name          TEXT NOT NULL,
    client_id             TEXT NOT NULL,
    client_secret_enc     BLOB NOT NULL,
    client_secret_nonce   BLOB NOT NULL,
    scopes                TEXT NOT NULL,         -- JSON array
    enabled               INTEGER NOT NULL DEFAULT 1
                            CHECK (enabled IN (0, 1)),
    priority              INTEGER NOT NULL DEFAULT 0,
    config                TEXT,                  -- JSON, custom_oidc only
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- list_enabled queries hit (enabled, priority).
CREATE INDEX idx_allowthem_social_providers_enabled_priority
    ON allowthem_social_providers (enabled, priority);

-- One configured provider per (provider_type, display_name) avoids
-- accidental duplicates (e.g., two "Google" rows). display_name is
-- the dashboard label; provider_type alone is too narrow because a
-- tenant might want "Google (work)" + "Google (personal)" eventually
-- — relax later if requested.
CREATE UNIQUE INDEX idx_allowthem_social_providers_type_displayname
    ON allowthem_social_providers (provider_type, display_name);
