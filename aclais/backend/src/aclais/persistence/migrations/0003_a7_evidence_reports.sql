CREATE TABLE task_evidence_baselines (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    run_id TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    tested_source_revision TEXT,
    tested_source_sha256 TEXT NOT NULL CHECK (
        length(tested_source_sha256) = 64 AND tested_source_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_match INTEGER NOT NULL CHECK (manifest_match IN (0, 1)),
    selected_input_size_bytes INTEGER NOT NULL CHECK (selected_input_size_bytes >= 0),
    selected_input_sha256 TEXT NOT NULL CHECK (
        length(selected_input_sha256) = 64 AND selected_input_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    inventory_json TEXT NOT NULL CHECK (json_valid(inventory_json)),
    inventory_sha256 TEXT NOT NULL CHECK (
        length(inventory_sha256) = 64 AND inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_path TEXT NOT NULL CHECK (
        length(artifact_path) BETWEEN 1 AND 512
        AND artifact_path GLOB 'raw/*/*.json'
        AND instr(artifact_path, '//') = 0
        AND instr(artifact_path, '/./') = 0
        AND instr(artifact_path, '..') = 0
        AND instr(artifact_path, ':') = 0
        AND instr(artifact_path, char(92)) = 0
    )
) STRICT;

CREATE TRIGGER task_evidence_baselines_immutable_update
BEFORE UPDATE ON task_evidence_baselines
BEGIN
    SELECT RAISE(ABORT, 'task_evidence_baselines_are_immutable');
END;

CREATE TRIGGER task_evidence_baselines_immutable_delete
BEFORE DELETE ON task_evidence_baselines
BEGIN
    SELECT RAISE(ABORT, 'task_evidence_baselines_are_immutable');
END;

CREATE TABLE task_evidence_reports (
    report_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    run_id TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    report_sha256 TEXT NOT NULL CHECK (
        length(report_sha256) = 64 AND report_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    report_json TEXT NOT NULL CHECK (json_valid(report_json))
) STRICT;

CREATE INDEX task_evidence_reports_task_time
    ON task_evidence_reports(task_id, generated_at, report_id);

CREATE TRIGGER task_evidence_reports_immutable_update
BEFORE UPDATE ON task_evidence_reports
BEGIN
    SELECT RAISE(ABORT, 'task_evidence_reports_are_immutable');
END;

CREATE TRIGGER task_evidence_reports_immutable_delete
BEFORE DELETE ON task_evidence_reports
BEGIN
    SELECT RAISE(ABORT, 'task_evidence_reports_are_immutable');
END;
