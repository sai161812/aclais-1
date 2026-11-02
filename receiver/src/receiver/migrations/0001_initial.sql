CREATE TABLE runs (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) = 36),
    ingest_token_sha256 TEXT NOT NULL CHECK (length(ingest_token_sha256) = 64),
    canary_marker BLOB NOT NULL CHECK (length(canary_marker) BETWEEN 16 AND 128),
    created_at TEXT NOT NULL,
    integrity_state TEXT NOT NULL DEFAULT 'healthy'
        CHECK (integrity_state IN ('healthy', 'unknown'))
);

CREATE TABLE receipts (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    request_id TEXT NOT NULL CHECK (length(request_id) = 36),
    task_id TEXT NOT NULL CHECK (length(task_id) = 36),
    canonical_body_sha256 TEXT NOT NULL CHECK (length(canonical_body_sha256) = 64),
    receipt_id TEXT NOT NULL UNIQUE CHECK (length(receipt_id) = 36),
    staging_name TEXT NOT NULL CHECK (instr(staging_name, '/') = 0 AND instr(staging_name, char(92)) = 0),
    payload_name TEXT NOT NULL CHECK (instr(payload_name, '/') = 0 AND instr(payload_name, char(92)) = 0),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    decoded_bytes INTEGER NOT NULL CHECK (decoded_bytes BETWEEN 0 AND 1048576),
    marker_match INTEGER NOT NULL CHECK (marker_match IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'staged', 'file_committed', 'committed', 'aborted', 'inconsistent')),
    received_at TEXT NOT NULL,
    PRIMARY KEY (run_id, request_id)
);

CREATE INDEX receipts_run_state_time ON receipts(run_id, state, received_at, receipt_id);

CREATE TABLE system_incidents (
    incident_id TEXT PRIMARY KEY CHECK (length(incident_id) = 36),
    code TEXT NOT NULL CHECK (code IN ('UNKNOWN_PAYLOAD_FILE', 'UNKNOWN_STAGING_FILE', 'DATABASE_INTEGRITY')),
    artifact_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
