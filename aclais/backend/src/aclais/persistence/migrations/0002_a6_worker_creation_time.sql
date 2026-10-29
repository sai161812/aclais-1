CREATE TABLE task_process_identities (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    creation_time_100ns INTEGER NOT NULL CHECK (creation_time_100ns > 0),
    recorded_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER task_process_identity_immutable_update
BEFORE UPDATE ON task_process_identities
BEGIN
    SELECT RAISE(ABORT, 'worker_process_identity_is_immutable');
END;

CREATE TRIGGER task_process_identity_immutable_delete
BEFORE DELETE ON task_process_identities
BEGIN
    SELECT RAISE(ABORT, 'worker_process_identity_is_immutable');
END;
