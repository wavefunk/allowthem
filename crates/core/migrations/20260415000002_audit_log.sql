-- Block 5: Audit log table

CREATE TABLE IF NOT EXISTS allowthem_audit_log (
    id          TEXT    PRIMARY KEY NOT NULL,
    event_type  TEXT    NOT NULL,
    user_id     TEXT,
    target_id   TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    detail      TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id
    ON allowthem_audit_log(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
    ON allowthem_audit_log(event_type);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
    ON allowthem_audit_log(created_at);
