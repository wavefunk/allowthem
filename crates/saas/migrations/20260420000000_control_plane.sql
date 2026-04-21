-- Control plane schema for allowthem SaaS mode.
-- This DB (control.db) is separate from every tenant DB — no cross-file FKs.
-- Timestamps use TEXT/ISO 8601 to roundtrip cleanly with sqlx chrono.

CREATE TABLE tenant_plans (
    id          BLOB PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    mau_limit   INTEGER NOT NULL,
    price_cents INTEGER NOT NULL,
    features    TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE tenants (
    id           BLOB PRIMARY KEY,
    name         TEXT NOT NULL,
    slug         TEXT NOT NULL UNIQUE,
    owner_email  TEXT NOT NULL,
    plan_id      BLOB NOT NULL REFERENCES tenant_plans(id),
    status       TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    db_path      TEXT NOT NULL,
    last_seen_at TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_tenants_slug     ON tenants(slug);
CREATE INDEX idx_tenants_status   ON tenants(status);
CREATE INDEX idx_tenants_lastseen ON tenants(last_seen_at);

CREATE TABLE tenant_usage (
    id               BLOB PRIMARY KEY,
    tenant_id        BLOB NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period           TEXT NOT NULL,
    mau_count        INTEGER NOT NULL DEFAULT 0,
    limit_reached_at TEXT,
    notified_at      TEXT,
    UNIQUE (tenant_id, period)
);

CREATE INDEX idx_tenant_usage_tenant_period ON tenant_usage(tenant_id, period);

CREATE TABLE tenant_active_users (
    -- user_id references a user in the tenant's own DB file; no FK across files.
    tenant_id     BLOB NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       BLOB NOT NULL,
    period        TEXT NOT NULL,
    first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (tenant_id, user_id, period)
);

CREATE TABLE tenant_api_keys (
    id           BLOB PRIMARY KEY,
    tenant_id    BLOB NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     BLOB NOT NULL UNIQUE,
    scope        TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT,
    revoked_at   TEXT,
    last_used_at TEXT
);

CREATE INDEX idx_tenant_api_keys_hash   ON tenant_api_keys(key_hash);
CREATE INDEX idx_tenant_api_keys_tenant ON tenant_api_keys(tenant_id);

CREATE TABLE tenant_members (
    id          BLOB PRIMARY KEY,
    tenant_id   BLOB NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
    invited_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    accepted_at TEXT,
    UNIQUE (tenant_id, email)
);

CREATE TABLE control_audit_events (
    id         BLOB PRIMARY KEY,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    tenant_id  BLOB REFERENCES tenants(id),
    context    TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
