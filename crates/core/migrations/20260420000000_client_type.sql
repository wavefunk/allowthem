-- Add client_type column to allowthem_applications.
-- Existing rows default to 'confidential' to preserve current behavior.
ALTER TABLE allowthem_applications
    ADD COLUMN client_type TEXT NOT NULL DEFAULT 'confidential'
        CHECK (client_type IN ('confidential', 'public'));
