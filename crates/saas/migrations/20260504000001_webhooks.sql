-- Webhook subscriptions per tenant.
--
-- `secret_key` is the HMAC-SHA256 signing key for outbound payloads.
-- Stored cleartext at v1; epic 7xw.3 will migrate it to encrypted columns
-- once the management API is in place to mediate set/get.
CREATE TABLE tenant_webhooks (
    id          BLOB PRIMARY KEY,
    tenant_id   BLOB NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    secret_key  TEXT NOT NULL,
    event_types TEXT NOT NULL,                 -- JSON array of event_type strings
    enabled     INTEGER NOT NULL DEFAULT 1
                  CHECK (enabled IN (0, 1)),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_tenant_webhooks_tenant_enabled
    ON tenant_webhooks (tenant_id, enabled);

-- Outbox of pending and completed deliveries.
CREATE TABLE webhook_deliveries (
    id              BLOB PRIMARY KEY,
    tenant_id       BLOB NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    webhook_id      BLOB NOT NULL REFERENCES tenant_webhooks(id) ON DELETE CASCADE,
    event_id        TEXT NOT NULL,             -- AuthEvent.event_id (UUIDv7 string)
    event_type      TEXT NOT NULL,
    payload         TEXT NOT NULL,             -- canonical JSON
    status          TEXT NOT NULL
                      CHECK (status IN ('pending','in_flight','delivered','failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    next_retry_at   TEXT,                      -- NULL means "eligible immediately"
    response_code   INTEGER,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Worker poll: WHERE status='pending' AND (next_retry_at IS NULL OR next_retry_at <= now)
CREATE INDEX idx_webhook_deliveries_due
    ON webhook_deliveries (status, next_retry_at);

-- One delivery per (webhook, event) — idempotency for the sink's INSERT
-- and across retries from a re-emit of the same source event.
CREATE UNIQUE INDEX idx_webhook_deliveries_webhook_event
    ON webhook_deliveries (webhook_id, event_id);
