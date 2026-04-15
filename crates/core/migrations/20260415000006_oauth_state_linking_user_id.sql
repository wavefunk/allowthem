-- Add linking_user_id to oauth_states to support the account-linking flow.
-- NULL = login flow (existing behaviour). Non-NULL = link flow (link to authenticated user).
ALTER TABLE allowthem_oauth_states ADD COLUMN linking_user_id TEXT;
