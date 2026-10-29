from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aclais.persistence.database import (
    TRUSTED_DOCUMENTS,
    Database,
    DatabaseError,
    RequestConflict,
    RequestDisposition,
    RequestInProgress,
    _migration_contents,
    canonical_body_sha256,
)
from aclais.persistence.models import (
    BrokerOutputAllowed,
    CreateTaskRequest,
    Incident,
    JournalState,
    RevocationCause,
    TaskStatus,
    TerminalCause,
)

pytestmark = pytest.mark.portable

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "a4-create-task-request.json"


def request() -> CreateTaskRequest:
    return CreateTaskRequest.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


def task(db: Database, *, now: datetime = NOW):
    return db.create_task(request(), run_id=uuid4(), now=now)


def running_task(db: Database, *, now: datetime = NOW):
    record = task(db, now=now)
    record = db.transition_task(
        record.task_id,
        TaskStatus.PREPARING,
        now=now + timedelta(seconds=1),
    )
    return db.transition_task(record.task_id, TaskStatus.RUNNING, now=now + timedelta(seconds=2))


def test_fresh_database_reopen_and_seeded_registry(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    db = Database(path)
    with db._connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 4
        assert connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 4

    public_documents = db.documents().model_dump_json()
    assert "originals" not in public_documents
    assert "Personnel_Private.csv" not in public_documents
    assert [doc.id for doc in db.documents().documents] == [
        "doc-invoice",
        "doc-notes",
        "doc-private",
        "doc-report",
    ]

    created = task(db)
    reopened = Database(path)
    assert reopened.get_task(created.task_id) == created
    assert reopened.get_contract(created.task_id) == db.get_contract(created.task_id)


def test_migration_checksum_mismatch_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    db = Database(path)
    with db._connection() as connection:
        connection.execute("UPDATE schema_migrations SET sha256 = ?", ("0" * 64,))
    with pytest.raises(DatabaseError, match="applied database migration is missing or changed"):
        Database(path)


def test_migration_failure_rolls_back_ddl(tmp_path: Path) -> None:
    migration = tmp_path / "0001_broken.sql"
    migration.write_text(
        "CREATE TABLE migration_rollback_probe (id INTEGER PRIMARY KEY);\n"
        "CREAT TABLE invalid_syntax (id INTEGER);\n",
        encoding="utf-8",
    )
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT, "
        "sha256 TEXT, applied_at TEXT)"
    )
    with pytest.raises(sqlite3.Error):
        Database._apply_migration(connection, migration, 1)
    assert (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='migration_rollback_probe'"
        ).fetchone()
        is None
    )
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    connection.close()


def test_migration_checksum_normalizes_git_line_endings(tmp_path: Path) -> None:
    migration = tmp_path / "0001_newline_test.sql"
    migration.write_bytes(b"CREATE TABLE example (id INTEGER);\r\n")
    crlf_hash = hashlib.sha256(_migration_contents(migration)).hexdigest()
    migration.write_bytes(b"CREATE TABLE example (id INTEGER);\n")
    lf_hash = hashlib.sha256(_migration_contents(migration)).hexdigest()
    assert crlf_hash == lf_hash


def test_task_contract_grants_are_fixed_and_paths_are_controller_owned(tmp_path: Path) -> None:
    with pytest.raises(FrozenInstanceError):
        TRUSTED_DOCUMENTS[0].relative_path = "D:/client-selected.csv"
    db = Database(tmp_path / "state.sqlite3")
    created = task(db)
    contract = db.get_contract(created.task_id)
    assert contract is not None
    assert contract.task_id == created.task_id
    assert contract.allowed_operations == ("read_document", "publish_output")
    assert contract.selected_document_id == "doc-report"
    assert contract.expires_at - contract.created_at == timedelta(seconds=30)
    with db._connection() as connection:
        grants = connection.execute(
            "SELECT operation, document_id, output_slot_id FROM contract_grants "
            "WHERE contract_id = ? ORDER BY operation",
            (str(contract.contract_id),),
        ).fetchall()
    assert [(row[0], row[1], row[2]) for row in grants] == [
        ("publish_output", None, str(contract.output_slot_id)),
        ("read_document", "doc-report", None),
    ]
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="task_identity_is_controller_owned"),
    ):
        connection.execute(
            "UPDATE tasks SET tool_id='invoice_analyzer', selected_document_id='doc-invoice' "
            "WHERE task_id=?",
            (str(created.task_id),),
        )


def test_contract_deadline_stays_within_sqlite_bound_at_fractional_second_precision(
    tmp_path: Path,
) -> None:
    db = Database(tmp_path / "state.sqlite3")
    created_at = datetime(2026, 10, 29, 3, 43, 20, 151754, tzinfo=UTC)
    created = task(db, now=created_at)
    contract = db.get_contract(created.task_id)
    assert contract is not None
    assert timedelta(0) < contract.expires_at - contract.created_at <= timedelta(seconds=30)
    with (
        db._connection() as connection,
        pytest.raises(
            sqlite3.IntegrityError, match="document_registry_identity_is_controller_owned"
        ),
    ):
        connection.execute(
            "UPDATE documents SET relative_path='store/originals/untrusted.csv' "
            "WHERE document_id='doc-report'"
        )
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="contract_grants_are_immutable"),
    ):
        connection.execute(
            "DELETE FROM contract_grants WHERE contract_id = ?",
            (str(contract.contract_id),),
        )
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="grant_must_match_controller_contract"),
    ):
        connection.execute(
            "INSERT INTO contract_grants(contract_id, operation, document_id, output_slot_id) "
            "VALUES (?, 'read_document', 'doc-private', NULL)",
            (str(contract.contract_id),),
        )

    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload.update({"permissions": ["delete_document"], "selected_path": "C:/private.csv"})
    with pytest.raises(ValidationError):
        CreateTaskRequest.model_validate(payload)
    with pytest.raises(ValidationError):
        CreateTaskRequest.model_validate(
            {
                "schema_version": 1,
                "tool_id": "invoice_analyzer",
                "selected_document_id": "doc-report",
                "launch_source_claim": "document_tools",
            }
        )


def test_identifiers_are_canonical_and_validated(tmp_path: Path) -> None:
    db = Database(tmp_path / "state.sqlite3")
    for value in ("../state.sqlite3", "not-a-uuid", "00000000000000000000000000000000"):
        with pytest.raises((ValidationError, ValueError)):
            db.get_task(value)
    with pytest.raises(ValidationError):
        db.get_task("550E8400-E29B-41D4-A716-446655440000")


def test_task_transition_guard_terminal_immutability_and_order(tmp_path: Path) -> None:
    db = Database(tmp_path / "state.sqlite3")
    created = task(db)
    with pytest.raises(ValueError, match="invalid task state"):
        db.transition_task(created.task_id, TaskStatus.RUNNING)
    prepared = db.transition_task(
        created.task_id, TaskStatus.PREPARING, now=NOW + timedelta(seconds=1)
    )
    with pytest.raises(ValueError, match="cannot move backwards"):
        db.transition_task(
            prepared.task_id,
            TaskStatus.RUNNING,
            now=NOW + timedelta(milliseconds=500),
        )
    running = db.transition_task(
        prepared.task_id, TaskStatus.RUNNING, now=NOW + timedelta(seconds=2)
    )
    verifying = db.transition_task(
        running.task_id, TaskStatus.VERIFYING, now=NOW + timedelta(seconds=3)
    )
    with pytest.raises(ValueError, match="only a verified zero exit"):
        db.transition_task(
            verifying.task_id,
            TaskStatus.COMPLETED,
            now=NOW + timedelta(seconds=3, milliseconds=500),
            terminal_cause=TerminalCause.WORKER_EXIT_FAILURE,
        )
    assert db.get_task(verifying.task_id).status == TaskStatus.VERIFYING
    completed = db.transition_task(
        verifying.task_id,
        TaskStatus.COMPLETED,
        now=NOW + timedelta(seconds=4),
        terminal_cause=TerminalCause.WORKER_EXIT_SUCCESS,
    )
    assert completed.status == TaskStatus.COMPLETED
    with pytest.raises(ValueError, match="invalid task state"):
        db.transition_task(completed.task_id, TaskStatus.FAILED)
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="terminal_task_immutable"),
    ):
        connection.execute(
            "UPDATE tasks SET status='FAILED' WHERE task_id=?", (str(completed.task_id),)
        )

    history = db.transitions(created.task_id)
    assert [item.seq for item in history] == [1, 2, 3, 4, 5]
    assert [item.to_status for item in history] == [
        TaskStatus.CREATED,
        TaskStatus.PREPARING,
        TaskStatus.RUNNING,
        TaskStatus.VERIFYING,
        TaskStatus.COMPLETED,
    ]
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="task_transitions_are_append_only"),
    ):
        connection.execute(
            "UPDATE task_state_transitions SET cause='tampered' WHERE task_id=? AND seq=1",
            (str(created.task_id),),
        )


def test_revocation_cause_is_immutable_and_incident_requires_policy_event(tmp_path: Path) -> None:
    db = Database(tmp_path / "state.sqlite3")
    current = running_task(db)
    current = db.transition_task(
        current.task_id,
        TaskStatus.REVOKING,
        now=NOW + timedelta(seconds=3),
        revocation_cause=RevocationCause.POLICY_DENIED,
    )
    denial = db.append_event(
        current.task_id,
        source="broker",
        kind="operation_denied",
        message="A forbidden original mutation request was denied.",
        timestamp=NOW + timedelta(seconds=4),
        operation="replace_original",
        target_document_id="doc-report",
        decision="deny",
        reason_code="ORIGINAL_MUTATION_FORBIDDEN",
    )
    incident = Incident(
        incident_id=uuid4(),
        task_id=current.task_id,
        trigger_event_id=denial.event_id,
        policy_reason="ORIGINAL_MUTATION_FORBIDDEN",
        containment_status="pending",
        integrity_status="pending",
        confidentiality_status="pending",
        evidence_refs=("task/events/1.json",),
    )
    db.create_incident(incident)
    assert db.get_task(current.task_id).incident_id == incident.incident_id
    db.transition_task(current.task_id, TaskStatus.VERIFYING, now=NOW + timedelta(seconds=5))
    blocked = db.transition_task(
        current.task_id,
        TaskStatus.BLOCKED,
        now=NOW + timedelta(seconds=6),
        terminal_cause=TerminalCause.POLICY_DENIED,
    )
    assert blocked.status == TaskStatus.BLOCKED

    other = running_task(db, now=NOW + timedelta(minutes=1))
    other_event = db.append_event(
        other.task_id,
        source="broker",
        kind="operation_denied",
        message="Synthetic denial without committed revocation.",
        operation="delete_document",
        target_document_id="doc-report",
        decision="deny",
    )
    with pytest.raises(ValueError, match="incidents require"):
        db.create_incident(
            incident.model_copy(
                update={
                    "incident_id": uuid4(),
                    "task_id": other.task_id,
                    "trigger_event_id": other_event.event_id,
                }
            )
        )


def test_credentials_are_hash_only_bounded_unique_and_expiring(tmp_path: Path) -> None:
    db = Database(tmp_path / "state.sqlite3")
    current = running_task(db)
    token_hash = hashlib.sha256(b"synthetic-token-only").hexdigest()
    record = db.create_credential_hash(
        current.task_id,
        token_hash,
        created_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(seconds=122),
    )
    assert record.token_sha256 == token_hash
    with db._connection() as connection:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(worker_credentials)")
        }
        stored_hash = connection.execute(
            "SELECT token_sha256 FROM worker_credentials WHERE task_id = ?",
            (str(current.task_id),),
        ).fetchone()[0]
    assert "token" not in columns
    assert stored_hash == token_hash
    assert db.credential_is_valid(
        current.task_id, token_hash, at=NOW + timedelta(seconds=121, milliseconds=999)
    )
    assert not db.credential_is_valid(current.task_id, token_hash, at=record.expires_at)
    assert not db.credential_is_valid(current.task_id, "0" * 64, at=record.created_at)
    with pytest.raises(ValidationError):
        db.create_credential_hash(
            current.task_id,
            hashlib.sha256(b"too-long-synthetic-token").hexdigest(),
            created_at=record.created_at,
            expires_at=record.expires_at + timedelta(microseconds=1),
        )
    with pytest.raises(sqlite3.IntegrityError):
        db.create_credential_hash(
            current.task_id,
            hashlib.sha256(b"second-synthetic-token").hexdigest(),
            created_at=record.created_at,
            expires_at=record.expires_at,
        )
    other = running_task(db, now=NOW + timedelta(minutes=1))
    with pytest.raises(sqlite3.IntegrityError):
        db.create_credential_hash(
            other.task_id,
            token_hash,
            created_at=record.created_at,
            expires_at=record.expires_at,
        )
    db.revoke_credential(current.task_id, at=NOW + timedelta(seconds=10))
    assert db.credential_hash(current.task_id).revoked_at == NOW + timedelta(seconds=10)
    assert not db.credential_is_valid(current.task_id, token_hash, at=NOW + timedelta(seconds=11))
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="worker_credential_identity_is_immutable"),
    ):
        connection.execute(
            "UPDATE worker_credentials SET token_sha256=? WHERE task_id=?",
            ("e" * 64, str(current.task_id)),
        )


def test_events_are_append_ordered_even_if_timestamps_repeat(tmp_path: Path) -> None:
    db = Database(tmp_path / "state.sqlite3")
    current = task(db)
    first = db.append_event(
        current.task_id,
        source="controller",
        kind="created",
        message="Synthetic task created.",
        timestamp=NOW,
    )
    second = db.append_event(
        current.task_id,
        source="worker_reported",
        kind="progress",
        message="Synthetic worker report.",
        timestamp=NOW,
    )
    assert [event.seq for event in db.events(current.task_id)] == [1, 2]
    assert db.events(current.task_id, after_seq=1) == (second,)
    assert first.event_id != second.event_id
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="task_events_are_append_only"),
    ):
        connection.execute(
            "DELETE FROM task_events WHERE task_id=? AND seq=1", (str(current.task_id),)
        )
    with pytest.raises(ValueError):
        db.events(current.task_id, after_seq=-1)
    with pytest.raises(ValueError, match="999,999,999"):
        db.events(current.task_id, after_seq=1_000_000_000)
    with pytest.raises(ValidationError):
        db.append_event(
            current.task_id,
            source="worker_reported",
            kind="progress",
            message="Untrusted evidence path.",
            evidence_refs=("../../outside.txt",),
        )
    with pytest.raises(ValidationError):
        db.append_event(
            current.task_id,
            source="controller",
            kind="policy_denied",
            message="Unknown synthetic reason code.",
            reason_code="MADE_UP_REASON",
        )


def test_request_dedup_output_journal_and_unique_output_slot(tmp_path: Path) -> None:
    db = Database(tmp_path / "state.sqlite3")
    current = task(db)
    request_id = uuid4()
    body_hash = "a" * 64
    assert db.begin_request(current.task_id, request_id, body_hash, now=NOW) == (
        RequestDisposition.NEW,
        None,
    )
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="request_reservation_identity_is_immutable"),
    ):
        connection.execute(
            "UPDATE request_deduplication SET canonical_body_sha256=? "
            "WHERE task_id=? AND request_id=?",
            ("f" * 64, str(current.task_id), str(request_id)),
        )
    with pytest.raises(RequestInProgress):
        db.begin_request(current.task_id, request_id, body_hash, now=NOW)
    with pytest.raises(RequestConflict):
        db.begin_request(current.task_id, request_id, "b" * 64, now=NOW)

    output = db.reserve_output(current.task_id, request_id, "c" * 64, 14, now=NOW)
    assert output.state == JournalState.RESERVED
    assert output.staging_relative_path == f"{current.task_id}/{output.output_id}.staging"
    assert output.final_relative_path == f"{current.task_id}/{output.output_id}.md"
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="output_journal_intent_is_immutable"),
    ):
        connection.execute(
            "UPDATE output_records SET final_relative_path=? WHERE output_id=?",
            ("../../replacement.md", str(output.output_id)),
        )
    response = BrokerOutputAllowed(
        schema_version=1,
        decision="allow",
        output_id=output.output_id,
        sha256=output.content_sha256,
    )
    db.complete_request(current.task_id, request_id, body_hash, response, now=NOW)
    disposition, replay = db.begin_request(current.task_id, request_id, body_hash, now=NOW)
    assert disposition == RequestDisposition.REPLAY
    assert replay == response.model_dump(mode="json")
    with (
        db._connection() as connection,
        pytest.raises(sqlite3.IntegrityError, match="completed_request_is_immutable"),
    ):
        connection.execute(
            "UPDATE request_deduplication SET response_json='{}' WHERE task_id=? AND request_id=?",
            (str(current.task_id), str(request_id)),
        )
    expected_hash = hashlib.sha256(
        json.dumps(
            response.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    assert canonical_body_sha256(response) == expected_hash

    output = db.transition_output(
        output.output_id, JournalState.STAGED, now=NOW + timedelta(seconds=1)
    )
    output = db.transition_output(
        output.output_id, JournalState.FILE_COMMITTED, now=NOW + timedelta(seconds=2)
    )
    output = db.transition_output(
        output.output_id, JournalState.PUBLISHED, now=NOW + timedelta(seconds=3)
    )
    assert db.output_journal(output.output_id).state == JournalState.PUBLISHED
    metadata = db.published_output(output.output_id)
    assert metadata.file_name == f"{output.output_id}.md"
    assert metadata.decoded_bytes == 14
    output = db.transition_output(
        output.output_id, JournalState.INCONSISTENT, now=NOW + timedelta(seconds=4)
    )
    assert output.state == JournalState.INCONSISTENT
    assert db.published_output(output.output_id) is None
    with pytest.raises(sqlite3.IntegrityError, match="terminal_output_immutable"):
        db.transition_output(output.output_id, JournalState.STAGED)

    second_request_id = uuid4()
    db.begin_request(current.task_id, second_request_id, "d" * 64, now=NOW)
    with pytest.raises(sqlite3.IntegrityError):
        db.reserve_output(current.task_id, second_request_id, "e" * 64, 2, now=NOW)
