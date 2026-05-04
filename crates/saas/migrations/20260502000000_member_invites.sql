-- Add invite-token columns to tenant_members for the dashboard team-invite
-- flow (99c.5 §3 / Step 14).
--
-- SQLite forbids inline UNIQUE on `ALTER TABLE ADD COLUMN`. Use a partial
-- unique index instead, which also keeps the constraint scoped to non-NULL
-- rows: existing tenant_members rows (auto-inserted by `provision_tenant`)
-- carry NULL hashes that would otherwise clash under a naive table-level
-- UNIQUE.

ALTER TABLE tenant_members ADD COLUMN invite_token_hash BLOB;
ALTER TABLE tenant_members ADD COLUMN invite_token_expires_at INTEGER;

CREATE UNIQUE INDEX idx_tenant_members_invite_token_hash
    ON tenant_members(invite_token_hash)
    WHERE invite_token_hash IS NOT NULL;
