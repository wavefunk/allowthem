-- Default plan tiers. IDs are randomblob(16) — opaque, not UUIDv7.
-- These are never referenced externally; internal opaque handles only.
-- Kept in a separate migration so seed changes remain auditable.
INSERT INTO tenant_plans (id, name, mau_limit, price_cents, features) VALUES
    (randomblob(16), 'dev',     1000,    0, '{"support":"community"}'),
    (randomblob(16), 'starter', 10000,  900, '{}'),
    (randomblob(16), 'growth',  50000, 4900, '{}'),
    (randomblob(16), 'scale',  500000, 29900, '{}');
