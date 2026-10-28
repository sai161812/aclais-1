CREATE TABLE documents (
    document_id TEXT PRIMARY KEY CHECK (document_id IN ('doc-report', 'doc-notes', 'doc-invoice', 'doc-private')),
    relative_path TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('standard', 'confidential')),
    protection_status TEXT NOT NULL CHECK (protection_status IN ('ready', 'unverified', 'unavailable')),
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    last_verified_at TEXT,
    CHECK (
        (document_id = 'doc-report' AND relative_path = 'store/originals/project-report.md') OR
        (document_id = 'doc-notes' AND relative_path = 'store/originals/meeting-notes.md') OR
        (document_id = 'doc-invoice' AND relative_path = 'store/originals/invoice.csv') OR
        (document_id = 'doc-private' AND relative_path = 'store/originals/Personnel_Private.csv')
    )
) STRICT;

CREATE TRIGGER document_registry_identity_immutable
BEFORE UPDATE ON documents
WHEN NEW.document_id IS NOT OLD.document_id OR
     NEW.relative_path IS NOT OLD.relative_path OR
     NEW.display_name IS NOT OLD.display_name OR
     NEW.media_type IS NOT OLD.media_type OR
     NEW.sensitivity IS NOT OLD.sensitivity
BEGIN
    SELECT RAISE(ABORT, 'document_registry_identity_is_controller_owned');
END;

CREATE TRIGGER document_registry_immutable_delete
BEFORE DELETE ON documents
BEGIN
    SELECT RAISE(ABORT, 'document_registry_is_controller_owned');
END;

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    tool_id TEXT NOT NULL CHECK (tool_id IN ('report_formatter', 'invoice_analyzer')),
    selected_document_id TEXT NOT NULL REFERENCES documents(document_id),
    contract_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('CREATED', 'PREPARING', 'RUNNING', 'REVOKING', 'VERIFYING', 'COMPLETED', 'BLOCKED', 'FAILED', 'CANCELLED')),
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    worker_pid INTEGER CHECK (worker_pid IS NULL OR worker_pid > 0),
    worker_sid TEXT,
    launch_source_claim TEXT NOT NULL CHECK (launch_source_claim = 'document_tools'),
    observed_origin TEXT,
    observed_referer TEXT,
    incident_id TEXT,
    revocation_cause TEXT CHECK (revocation_cause IS NULL OR revocation_cause IN ('POLICY_DENIED', 'CANCELLED', 'WORKER_TIMEOUT', 'CONTROLLER_SHUTDOWN')),
    terminal_cause TEXT CHECK (terminal_cause IS NULL OR terminal_cause IN ('POLICY_DENIED', 'CANCELLED', 'WORKER_TIMEOUT', 'CONTROLLER_SHUTDOWN', 'WORKER_EXIT_SUCCESS', 'WORKER_EXIT_FAILURE', 'PREPARATION_FAILED', 'VERIFICATION_FAILED', 'RECOVERY_INTERRUPTED')),
    CHECK ((tool_id = 'report_formatter' AND selected_document_id = 'doc-report') OR
           (tool_id = 'invoice_analyzer' AND selected_document_id = 'doc-invoice')),
    CHECK ((status IN ('COMPLETED', 'BLOCKED', 'FAILED', 'CANCELLED')) = (finished_at IS NOT NULL)),
    CHECK ((status IN ('COMPLETED', 'BLOCKED', 'FAILED', 'CANCELLED')) = (terminal_cause IS NOT NULL)),
    CHECK (status <> 'COMPLETED' OR terminal_cause = 'WORKER_EXIT_SUCCESS'),
    CHECK (status <> 'BLOCKED' OR terminal_cause = 'POLICY_DENIED'),
    CHECK (status <> 'CANCELLED' OR terminal_cause = 'CANCELLED'),
    CHECK (terminal_cause <> 'WORKER_EXIT_SUCCESS' OR status = 'COMPLETED'),
    CHECK (revocation_cause IS NULL OR terminal_cause IS NULL OR terminal_cause = revocation_cause),
    FOREIGN KEY (contract_id) REFERENCES action_contracts(contract_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TRIGGER task_identity_immutable
BEFORE UPDATE ON tasks
WHEN NEW.task_id IS NOT OLD.task_id OR NEW.run_id IS NOT OLD.run_id OR
     NEW.tool_id IS NOT OLD.tool_id OR
     NEW.selected_document_id IS NOT OLD.selected_document_id OR
     NEW.contract_id IS NOT OLD.contract_id OR NEW.created_at IS NOT OLD.created_at OR
     NEW.launch_source_claim IS NOT OLD.launch_source_claim
BEGIN
    SELECT RAISE(ABORT, 'task_identity_is_controller_owned');
END;

CREATE TABLE action_contracts (
    contract_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
    selected_document_id TEXT NOT NULL REFERENCES documents(document_id),
    output_slot_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    policy_version TEXT NOT NULL CHECK (policy_version = '1'),
    UNIQUE (task_id, output_slot_id),
    CHECK (julianday(expires_at) > julianday(created_at)),
    CHECK (julianday(expires_at) <= julianday(created_at) + (30.0 / 86400.0))
) STRICT;

CREATE TRIGGER action_contract_task_guard
BEFORE INSERT ON action_contracts
WHEN NOT EXISTS (
    SELECT 1 FROM tasks WHERE task_id = NEW.task_id AND contract_id = NEW.contract_id
    AND selected_document_id = NEW.selected_document_id
)
BEGIN
    SELECT RAISE(ABORT, 'action_contract_must_match_controller_task');
END;

CREATE TABLE contract_grants (
    contract_id TEXT NOT NULL REFERENCES action_contracts(contract_id),
    operation TEXT NOT NULL CHECK (operation IN ('read_document', 'publish_output')),
    document_id TEXT REFERENCES documents(document_id),
    output_slot_id TEXT,
    PRIMARY KEY (contract_id, operation),
    CHECK ((operation = 'read_document' AND document_id IS NOT NULL AND output_slot_id IS NULL) OR
           (operation = 'publish_output' AND document_id IS NULL AND output_slot_id IS NOT NULL))
) STRICT;

CREATE TRIGGER contract_grant_guard
BEFORE INSERT ON contract_grants
WHEN NOT EXISTS (
    SELECT 1 FROM action_contracts c
    WHERE c.contract_id = NEW.contract_id AND (
        (NEW.operation = 'read_document' AND NEW.document_id = c.selected_document_id) OR
        (NEW.operation = 'publish_output' AND NEW.output_slot_id = c.output_slot_id)
    )
)
BEGIN
    SELECT RAISE(ABORT, 'grant_must_match_controller_contract');
END;

CREATE TABLE worker_credentials (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    token_sha256 TEXT NOT NULL UNIQUE CHECK (length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (julianday(expires_at) > julianday(created_at)),
    CHECK (julianday(expires_at) <= julianday(created_at) + (120.0 / 86400.0)),
    CHECK (revoked_at IS NULL OR julianday(revoked_at) >= julianday(created_at))
) STRICT;

CREATE TRIGGER worker_credential_identity_immutable
BEFORE UPDATE ON worker_credentials
WHEN NEW.task_id IS NOT OLD.task_id OR NEW.token_sha256 IS NOT OLD.token_sha256 OR
     NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at OR
     (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at) OR
     (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND
      julianday(NEW.revoked_at) < julianday(OLD.created_at))
BEGIN
    SELECT RAISE(ABORT, 'worker_credential_identity_is_immutable');
END;

CREATE TABLE task_events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (seq > 0),
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('controller', 'broker', 'worker_reported', 'verifier')),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    operation TEXT CHECK (operation IS NULL OR operation IN ('read_document', 'publish_output', 'replace_original', 'delete_document')),
    target_document_id TEXT REFERENCES documents(document_id),
    decision TEXT CHECK (decision IS NULL OR decision IN ('allow', 'deny')),
    reason_code TEXT CHECK (reason_code IS NULL OR reason_code IN (
        'DOCUMENT_OUT_OF_SCOPE', 'ORIGINAL_MUTATION_FORBIDDEN', 'TASK_REVOKED',
        'AUTH_INVALID', 'OUTPUT_ALREADY_PUBLISHED', 'INVALID_REQUEST',
        'PROTECTION_UNAVAILABLE', 'WORKER_TIMEOUT', 'VERIFICATION_INCOMPLETE',
        'CONTROLLER_SHUTDOWN', 'PUBLICATION_INCONSISTENT'
    )),
    message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 2048),
    evidence_refs_json TEXT NOT NULL CHECK (json_valid(evidence_refs_json)),
    UNIQUE (task_id, seq)
) STRICT;

CREATE TABLE task_state_transitions (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    seq INTEGER NOT NULL CHECK (seq > 0),
    from_status TEXT CHECK (from_status IS NULL OR from_status IN ('CREATED', 'PREPARING', 'RUNNING', 'REVOKING', 'VERIFYING', 'COMPLETED', 'BLOCKED', 'FAILED', 'CANCELLED')),
    to_status TEXT NOT NULL CHECK (to_status IN ('CREATED', 'PREPARING', 'RUNNING', 'REVOKING', 'VERIFYING', 'COMPLETED', 'BLOCKED', 'FAILED', 'CANCELLED')),
    cause TEXT,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (task_id, seq),
    CHECK ((seq = 1 AND from_status IS NULL AND to_status = 'CREATED') OR
           (seq > 1 AND from_status IS NOT NULL))
) STRICT;

CREATE TRIGGER task_events_immutable_update
BEFORE UPDATE ON task_events
BEGIN
    SELECT RAISE(ABORT, 'task_events_are_append_only');
END;

CREATE TRIGGER task_events_immutable_delete
BEFORE DELETE ON task_events
BEGIN
    SELECT RAISE(ABORT, 'task_events_are_append_only');
END;

CREATE TRIGGER task_state_transitions_immutable_update
BEFORE UPDATE ON task_state_transitions
BEGIN
    SELECT RAISE(ABORT, 'task_transitions_are_append_only');
END;

CREATE TRIGGER task_state_transitions_immutable_delete
BEFORE DELETE ON task_state_transitions
BEGIN
    SELECT RAISE(ABORT, 'task_transitions_are_append_only');
END;

CREATE TRIGGER task_state_transition_history_order
BEFORE INSERT ON task_state_transitions
WHEN NEW.seq <> COALESCE(
    (SELECT MAX(seq) + 1 FROM task_state_transitions WHERE task_id = NEW.task_id), 1
) OR (
    NEW.seq = 1 AND (NEW.from_status IS NOT NULL OR NEW.to_status <> 'CREATED')
) OR (
    NEW.seq > 1 AND (
        NEW.from_status IS NOT (SELECT to_status FROM task_state_transitions
                                WHERE task_id = NEW.task_id AND seq = NEW.seq - 1) OR
        NEW.to_status IS NOT (SELECT status FROM tasks WHERE task_id = NEW.task_id) OR
        julianday(NEW.timestamp) < julianday((SELECT timestamp FROM task_state_transitions
                                              WHERE task_id = NEW.task_id AND seq = NEW.seq - 1))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'task_transition_history_out_of_order');
END;

CREATE TRIGGER action_contracts_immutable_update
BEFORE UPDATE ON action_contracts
BEGIN
    SELECT RAISE(ABORT, 'action_contracts_are_immutable');
END;

CREATE TRIGGER action_contracts_immutable_delete
BEFORE DELETE ON action_contracts
BEGIN
    SELECT RAISE(ABORT, 'action_contracts_are_immutable');
END;

CREATE TRIGGER contract_grants_immutable_update
BEFORE UPDATE ON contract_grants
BEGIN
    SELECT RAISE(ABORT, 'contract_grants_are_immutable');
END;

CREATE TRIGGER contract_grants_immutable_delete
BEFORE DELETE ON contract_grants
BEGIN
    SELECT RAISE(ABORT, 'contract_grants_are_immutable');
END;

CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
    trigger_event_id TEXT NOT NULL REFERENCES task_events(event_id),
    policy_reason TEXT NOT NULL CHECK (policy_reason IN ('DOCUMENT_OUT_OF_SCOPE', 'ORIGINAL_MUTATION_FORBIDDEN')),
    containment_status TEXT NOT NULL CHECK (containment_status IN ('pending', 'terminated', 'failed')),
    integrity_status TEXT NOT NULL CHECK (integrity_status IN ('pending', 'pass', 'fail', 'unknown', 'not_applicable')),
    confidentiality_status TEXT NOT NULL CHECK (confidentiality_status IN ('pending', 'pass', 'fail', 'unknown', 'not_applicable')),
    evidence_refs_json TEXT NOT NULL CHECK (json_valid(evidence_refs_json))
) STRICT;

CREATE TRIGGER incident_denial_guard
BEFORE INSERT ON incidents
WHEN NOT EXISTS (
    SELECT 1 FROM tasks t JOIN task_events e ON e.event_id = NEW.trigger_event_id
    WHERE t.task_id = NEW.task_id AND t.revocation_cause = 'POLICY_DENIED'
      AND e.task_id = NEW.task_id AND e.source = 'broker' AND e.decision = 'deny'
      AND ((NEW.policy_reason = 'DOCUMENT_OUT_OF_SCOPE'
            AND e.operation = 'read_document' AND e.reason_code = 'DOCUMENT_OUT_OF_SCOPE') OR
           (NEW.policy_reason = 'ORIGINAL_MUTATION_FORBIDDEN'
            AND e.operation IN ('replace_original', 'delete_document')
            AND e.reason_code = 'ORIGINAL_MUTATION_FORBIDDEN'))
)
BEGIN
    SELECT RAISE(ABORT, 'incident_must_match_committed_broker_denial');
END;

CREATE TRIGGER incident_identity_immutable
BEFORE UPDATE ON incidents
WHEN NEW.incident_id IS NOT OLD.incident_id OR NEW.task_id IS NOT OLD.task_id OR
     NEW.trigger_event_id IS NOT OLD.trigger_event_id OR
     NEW.policy_reason IS NOT OLD.policy_reason
BEGIN
    SELECT RAISE(ABORT, 'incident_identity_is_immutable');
END;

CREATE TABLE request_deduplication (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    request_id TEXT NOT NULL,
    canonical_body_sha256 TEXT NOT NULL CHECK (length(canonical_body_sha256) = 64 AND canonical_body_sha256 NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'completed')),
    response_json TEXT CHECK (response_json IS NULL OR json_valid(response_json)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (task_id, request_id),
    CHECK (julianday(updated_at) >= julianday(created_at)),
    CHECK ((state = 'reserved' AND response_json IS NULL) OR (state = 'completed' AND response_json IS NOT NULL))
) STRICT;

CREATE TRIGGER request_reservation_identity_immutable
BEFORE UPDATE ON request_deduplication
WHEN NEW.task_id IS NOT OLD.task_id OR NEW.request_id IS NOT OLD.request_id OR
     NEW.canonical_body_sha256 IS NOT OLD.canonical_body_sha256 OR
     NEW.created_at IS NOT OLD.created_at OR
     (OLD.state = 'reserved' AND NEW.state NOT IN ('reserved', 'completed')) OR
     julianday(NEW.updated_at) < julianday(OLD.updated_at)
BEGIN
    SELECT RAISE(ABORT, 'request_reservation_identity_is_immutable');
END;

CREATE TABLE output_records (
    output_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    request_id TEXT NOT NULL,
    output_slot_id TEXT NOT NULL UNIQUE,
    output_kind TEXT NOT NULL CHECK (output_kind IN ('formatted_markdown', 'invoice_json')),
    staging_relative_path TEXT NOT NULL UNIQUE,
    final_relative_path TEXT NOT NULL UNIQUE,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    decoded_bytes INTEGER NOT NULL CHECK (decoded_bytes BETWEEN 0 AND 1048576),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'staged', 'file_committed', 'published', 'aborted', 'inconsistent')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (julianday(updated_at) >= julianday(created_at)),
    CHECK (staging_relative_path = task_id || '/' || output_id || '.staging'),
    CHECK (
        final_relative_path = task_id || '/' || output_id ||
        CASE output_kind
            WHEN 'formatted_markdown' THEN '.md'
            WHEN 'invoice_json' THEN '.json'
        END
    ),
    FOREIGN KEY (task_id, request_id) REFERENCES request_deduplication(task_id, request_id),
    FOREIGN KEY (task_id, output_slot_id) REFERENCES action_contracts(task_id, output_slot_id)
) STRICT;

CREATE TRIGGER output_journal_metadata_immutable
BEFORE UPDATE ON output_records
WHEN NEW.output_id IS NOT OLD.output_id OR NEW.task_id IS NOT OLD.task_id OR
     NEW.request_id IS NOT OLD.request_id OR NEW.output_slot_id IS NOT OLD.output_slot_id OR
     NEW.output_kind IS NOT OLD.output_kind OR
     NEW.staging_relative_path IS NOT OLD.staging_relative_path OR
     NEW.final_relative_path IS NOT OLD.final_relative_path OR
     NEW.content_sha256 IS NOT OLD.content_sha256 OR
     NEW.decoded_bytes IS NOT OLD.decoded_bytes OR NEW.created_at IS NOT OLD.created_at OR
     julianday(NEW.updated_at) < julianday(OLD.updated_at)
BEGIN
    SELECT RAISE(ABORT, 'output_journal_intent_is_immutable');
END;

CREATE TRIGGER output_record_task_kind_guard
BEFORE INSERT ON output_records
WHEN NOT EXISTS (
    SELECT 1 FROM tasks t JOIN request_deduplication r ON r.task_id = t.task_id
    WHERE t.task_id = NEW.task_id AND r.request_id = NEW.request_id AND r.state = 'reserved'
    AND ((t.tool_id = 'report_formatter' AND NEW.output_kind = 'formatted_markdown') OR
         (t.tool_id = 'invoice_analyzer' AND NEW.output_kind = 'invoice_json'))
)
BEGIN
    SELECT RAISE(ABORT, 'output_kind_must_match_controller_task');
END;

CREATE TRIGGER completed_request_immutable
BEFORE UPDATE ON request_deduplication
WHEN OLD.state = 'completed'
BEGIN
    SELECT RAISE(ABORT, 'completed_request_is_immutable');
END;

CREATE TRIGGER task_status_transition_guard
BEFORE UPDATE OF status ON tasks
WHEN NOT (
    (OLD.status = 'CREATED' AND NEW.status IN ('PREPARING', 'REVOKING', 'FAILED')) OR
    (OLD.status = 'PREPARING' AND NEW.status IN ('RUNNING', 'REVOKING', 'FAILED')) OR
    (OLD.status = 'RUNNING' AND NEW.status IN ('REVOKING', 'VERIFYING', 'FAILED')) OR
    (OLD.status = 'REVOKING' AND NEW.status IN ('VERIFYING', 'FAILED')) OR
    (OLD.status = 'VERIFYING' AND NEW.status IN ('COMPLETED', 'BLOCKED', 'CANCELLED', 'FAILED'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid_task_state_transition');
END;

CREATE TRIGGER task_terminal_immutable
BEFORE UPDATE ON tasks
WHEN OLD.status IN ('COMPLETED', 'BLOCKED', 'FAILED', 'CANCELLED')
BEGIN
    SELECT RAISE(ABORT, 'terminal_task_immutable');
END;

CREATE TRIGGER task_revocation_cause_immutable
BEFORE UPDATE OF revocation_cause ON tasks
WHEN NEW.revocation_cause IS NOT OLD.revocation_cause AND NOT (
    OLD.revocation_cause IS NULL AND OLD.status IN ('CREATED', 'PREPARING', 'RUNNING') AND
    NEW.status = 'REVOKING' AND NEW.revocation_cause IN ('POLICY_DENIED', 'CANCELLED', 'WORKER_TIMEOUT', 'CONTROLLER_SHUTDOWN')
)
BEGIN
    SELECT RAISE(ABORT, 'revocation_cause_immutable');
END;

CREATE TRIGGER task_terminal_cause_immutable
BEFORE UPDATE OF terminal_cause ON tasks
WHEN NEW.terminal_cause IS NOT OLD.terminal_cause AND NOT (
    OLD.terminal_cause IS NULL AND NEW.status IN ('COMPLETED', 'BLOCKED', 'FAILED', 'CANCELLED') AND NEW.terminal_cause IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'terminal_cause_immutable');
END;

CREATE TRIGGER output_state_transition_guard
BEFORE UPDATE OF state ON output_records
WHEN NOT (
    (OLD.state = 'reserved' AND NEW.state IN ('staged', 'aborted', 'inconsistent')) OR
    (OLD.state = 'staged' AND NEW.state IN ('file_committed', 'aborted', 'inconsistent')) OR
    (OLD.state = 'file_committed' AND NEW.state IN ('published', 'inconsistent')) OR
    (OLD.state = 'published' AND NEW.state = 'inconsistent')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid_output_state_transition');
END;

CREATE TRIGGER published_output_immutable
BEFORE UPDATE ON output_records
WHEN OLD.state IN ('published', 'aborted', 'inconsistent')
AND NOT (
    OLD.state = 'published' AND NEW.state = 'inconsistent' AND
    NEW.output_id IS OLD.output_id AND NEW.task_id IS OLD.task_id AND
    NEW.request_id IS OLD.request_id AND NEW.output_slot_id IS OLD.output_slot_id AND
    NEW.output_kind IS OLD.output_kind AND
    NEW.staging_relative_path IS OLD.staging_relative_path AND
    NEW.final_relative_path IS OLD.final_relative_path AND
    NEW.content_sha256 IS OLD.content_sha256 AND NEW.decoded_bytes IS OLD.decoded_bytes AND
    NEW.created_at IS OLD.created_at AND julianday(NEW.updated_at) >= julianday(OLD.updated_at)
)
BEGIN
    SELECT RAISE(ABORT, 'terminal_output_immutable');
END;
