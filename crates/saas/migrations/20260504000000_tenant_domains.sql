-- Custom domain registry for tenants.
-- Tracks domain ownership verification and (future) cert lifecycle.

CREATE TABLE tenant_domains (
    id              BLOB PRIMARY KEY,
    tenant_id       BLOB NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL UNIQUE,        -- always lowercase
    status          TEXT NOT NULL CHECK (status IN ('pending_verification','verified','active','failed')),
    dns_target      TEXT NOT NULL,
    verified_at     TEXT,
    cert_expires_at TEXT,
    last_error      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_tenant_domains_tenant ON tenant_domains(tenant_id);
CREATE INDEX idx_tenant_domains_status ON tenant_domains(status);
