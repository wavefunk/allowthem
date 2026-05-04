-- Per-tenant email-sender configuration.
-- Single-row table: forces 0 or 1 row per tenant DB. Tenants without a
-- row default to managed mode at runtime. The `mode` discriminator
-- selects which override block applies. Per-mode field-presence
-- validation is the CRUD setter's responsibility (column-level CHECKs
-- would be unwieldy in SQL).
CREATE TABLE allowthem_email_config (
    singleton TEXT PRIMARY KEY DEFAULT 'singleton'
                 CHECK (singleton = 'singleton'),
    mode      TEXT NOT NULL CHECK (mode IN ('managed', 'smtp', 'webhook')),

    -- SMTP override (non-NULL when mode = 'smtp')
    smtp_host           TEXT,
    smtp_port           INTEGER,
    smtp_username       TEXT,
    smtp_password_enc   BLOB,
    smtp_password_nonce BLOB,
    smtp_from_address   TEXT,
    smtp_tls            TEXT CHECK (smtp_tls IN ('none', 'starttls', 'implicit')),

    -- Webhook override (non-NULL when mode = 'webhook')
    webhook_url           TEXT,
    webhook_secret_enc    BLOB,
    webhook_secret_nonce  BLOB,

    -- Managed override: optional From-address (e.g. `noreply@auth.acme.com`).
    -- Default at send time is `<local>@mail.<base_domain>` with display name
    -- = tenant.name.
    managed_from_address  TEXT,

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
