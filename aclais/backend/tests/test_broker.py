from __future__ import annotations

import hashlib
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from aclais.broker import BrokerService
from aclais.persistence.database import TRUSTED_DOCUMENTS, Database
from aclais.persistence.models import (
    CreateTaskRequest,
    TaskStatus,
)
from aclais.publication import OutputPublisher

pytestmark = pytest.mark.portable

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "a4-create-task-request.json"


def _request_model(*, tool_id: str = "report_formatter") -> CreateTaskRequest:
    source = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if tool_id == "invoice_analyzer":
        source["tool_id"] = "invoice_analyzer"
        source["selected_document_id"] = "doc-invoice"
    return CreateTaskRequest.model_validate(source, strict=True)


def _running_task(database: Database, *, tool_id: str = "report_formatter"):
    task = database.create_task(_request_model(tool_id=tool_id), run_id=uuid4(), now=NOW)
    task = database.transition_task(
        task.task_id, TaskStatus.PREPARING, now=NOW + timedelta(seconds=1)
    )
    task = database.transition_task(
        task.task_id, TaskStatus.RUNNING, now=NOW + timedelta(seconds=2)
    )
    token = secrets.token_urlsafe(32)
    database.create_credential_hash(
        task.task_id,
        hashlib.sha256(token.encode("ascii")).hexdigest(),
        created_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(seconds=20),
    )
    return task, token


def _service(tmp_path: Path, *, tool_id: str = "report_formatter", fault=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = Database(tmp_path / "state.sqlite3")
    task, token = _running_task(database, tool_id=tool_id)
    selected_root = tmp_path / "selected-copies"
    selected_root.mkdir()
    task_root = selected_root / str(task.task_id)
    task_root.mkdir()
    filename = "doc-invoice.csv" if tool_id == "invoice_analyzer" else "doc-report.md"
    (task_root / filename).write_bytes(b"trusted selected copy\n")
    output_root = tmp_path / "verified-output"
    output_root.mkdir()
    publisher = OutputPublisher(database, output_root, fault=fault)
    return (
        database,
        task,
        token,
        selected_root,
        output_root,
        publisher,
        BrokerService(database, selected_root, publisher),
    )


def _seed_originals(root: Path) -> dict[str, str]:
    original_root = root / "store" / "originals"
    original_root.mkdir(parents=True)
    filenames = {
        "doc-report": "project-report.md",
        "doc-notes": "meeting-notes.md",
        "doc-invoice": "invoice.csv",
        "doc-private": "Personnel_Private.csv",
    }
    expected: dict[str, str] = {}
    for document in TRUSTED_DOCUMENTS:
        path = original_root / filenames[document.id]
        path.write_bytes(f"original sentinel {document.id}\n".encode())
        expected[document.id] = hashlib.sha256(path.read_bytes()).hexdigest()
    return expected


def _hash_originals(root: Path) -> dict[str, str]:
    original_root = root / "store" / "originals"
    filenames = {
        "doc-report": "project-report.md",
        "doc-notes": "meeting-notes.md",
        "doc-invoice": "invoice.csv",
        "doc-private": "Personnel_Private.csv",
    }
    return {
        document.id: hashlib.sha256(
            (original_root / filenames[document.id]).read_bytes()
        ).hexdigest()
        for document in TRUSTED_DOCUMENTS
    }


def _body(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _read_body(request_id: str | None = None, document_id: str = "doc-report") -> bytes:
    return _body(
        {
            "schema_version": 1,
            "request_id": request_id or str(uuid4()),
            "operation": "read_document",
            "document_id": document_id,
        }
    )


def _publish_body(request_id: str | None = None, text: str = "# Output\n") -> bytes:
    return _body(
        {
            "schema_version": 1,
            "request_id": request_id or str(uuid4()),
            "operation": "publish_output",
            "output_kind": "formatted_markdown",
            "output_text": text,
        }
    )


def test_selected_read_is_resolved_from_task_copy_and_exact_retry_is_cached(tmp_path: Path) -> None:
    database, task, token, selected_root, _, _, broker = _service(tmp_path)
    request_body = _read_body()

    first = broker.execute(token, request_body, now=NOW + timedelta(seconds=3))
    assert first.status_code == 200
    assert first.body.content_text == "trusted selected copy\n"
    events = database.events(task.task_id)
    assert len(events) == 1
    assert events[0].source == "broker"
    assert events[0].decision == "allow"
    assert events[0].target_document_id == "doc-report"
    (selected_root / str(task.task_id) / "doc-report.md").unlink()

    replay = broker.execute(token, request_body, now=NOW + timedelta(seconds=4))
    assert replay == first
    assert len(database.events(task.task_id)) == 1
    with database._connection() as connection:
        row = connection.execute(
            "SELECT state, response_json FROM request_deduplication WHERE task_id=?",
            (str(task.task_id),),
        ).fetchone()
    assert row["state"] == "completed"
    assert "trusted selected copy" in row["response_json"]


def test_unselected_read_and_original_mutation_are_denied_before_filesystem_effects(
    tmp_path: Path,
) -> None:
    read_root = tmp_path / "read-denial"
    database, task, token, _, output_root, _, broker = _service(read_root)
    before = _seed_originals(read_root)

    denied = broker.execute(
        token,
        _read_body(document_id="doc-private"),
        now=NOW + timedelta(seconds=3),
    )
    assert denied.status_code == 403
    assert denied.body.error.code == "POLICY_DENIED"
    assert _hash_originals(read_root) == before
    assert list(output_root.iterdir()) == []
    assert database.get_task(task.task_id).status == TaskStatus.REVOKING
    assert database.get_task(task.task_id).incident_id is not None
    assert database.events(task.task_id)[-1].reason_code == "DOCUMENT_OUT_OF_SCOPE"
    assert len(database.events(task.task_id)) == 1

    for operation in ("replace_original", "delete_document"):
        mutation_root = tmp_path / operation
        database2, task2, token2, _, output_root2, _, broker2 = _service(mutation_root)
        mutation_hashes = _seed_originals(mutation_root)
        mutation = {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": operation,
            "document_id": "doc-report",
        }
        if operation == "replace_original":
            mutation["replacement_text"] = "attacker content"
        denied_mutation = broker2.execute(token2, _body(mutation), now=NOW + timedelta(seconds=3))
        assert denied_mutation.status_code == 403
        assert database2.get_task(task2.task_id).revocation_cause == "POLICY_DENIED"
        assert list(output_root2.iterdir()) == []
        assert _hash_originals(mutation_root) == mutation_hashes


def test_malformed_forged_and_oversized_requests_have_no_effect(tmp_path: Path) -> None:
    database, task, token, _, output_root, _, broker = _service(tmp_path)
    valid = json.loads(_read_body())
    forged = {**valid, "task_id": str(uuid4()), "path": "C:/private.csv", "grants": ["delete"]}
    results = [
        broker.execute(
            token, b'{"request_id":"x","request_id":"y"}', now=NOW + timedelta(seconds=3)
        ),
        broker.execute(token, _body(forged), now=NOW + timedelta(seconds=3)),
        broker.execute(token, b"{" + b" " * (2_097_152), now=NOW + timedelta(seconds=3)),
        broker.execute(token, _publish_body(text="x" * 1_048_577), now=NOW + timedelta(seconds=3)),
        broker.execute(token, _publish_body(text="é" * 524_289), now=NOW + timedelta(seconds=3)),
    ]
    assert [result.status_code for result in results] == [422, 422, 413, 413, 413]
    assert database.get_task(task.task_id).status == TaskStatus.RUNNING
    with database._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM request_deduplication").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM output_records").fetchone()[0] == 0
    assert list(output_root.iterdir()) == []


def test_credential_derives_task_identity_and_expiry_is_checked_before_dedup(
    tmp_path: Path,
) -> None:
    database, first_task, _, selected_root, _, _, broker = _service(tmp_path)
    second_task = database.create_task(
        _request_model(tool_id="invoice_analyzer"), run_id=uuid4(), now=NOW
    )
    second_task = database.transition_task(
        second_task.task_id, TaskStatus.PREPARING, now=NOW + timedelta(seconds=1)
    )
    second_task = database.transition_task(
        second_task.task_id, TaskStatus.RUNNING, now=NOW + timedelta(seconds=2)
    )
    second_token = secrets.token_urlsafe(32)
    database.create_credential_hash(
        second_task.task_id,
        hashlib.sha256(second_token.encode("ascii")).hexdigest(),
        created_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(seconds=60),
    )

    forged_task_id = json.loads(_read_body())
    forged_task_id["task_id"] = str(first_task.task_id)
    result = broker.execute(second_token, _body(forged_task_id), now=NOW + timedelta(seconds=3))
    assert result.status_code == 422
    cross_task = broker.execute(
        second_token, _read_body(document_id="doc-report"), now=NOW + timedelta(seconds=3)
    )
    assert cross_task.status_code == 403
    assert database.get_task(second_task.task_id).revocation_cause == "POLICY_DENIED"
    assert database.get_task(first_task.task_id).status == TaskStatus.RUNNING
    assert (
        selected_root / str(first_task.task_id) / "doc-report.md"
    ).read_bytes() == b"trusted selected copy\n"

    expired_service = _service(tmp_path / "expiry")
    expired_db, expired_task, expired_token, _, _, _, expired_broker = expired_service
    expired = expired_broker.execute(expired_token, _read_body(), now=NOW + timedelta(seconds=31))
    assert expired.status_code == 401
    assert expired_db.get_task(expired_task.task_id).status == TaskStatus.RUNNING
    token_service = _service(tmp_path / "token-expiry")
    token_db, token_task, token, _, _, _, token_broker = token_service
    token_expired = token_broker.execute(token, _read_body(), now=NOW + timedelta(seconds=21))
    assert token_expired.status_code == 401
    assert token_db.get_task(token_task.task_id).status == TaskStatus.RUNNING


def test_publish_persists_one_file_and_exact_retry_without_duplicate_effect(tmp_path: Path) -> None:
    database, task, token, _, output_root, publisher, broker = _service(tmp_path)
    request_body = _publish_body()
    first = broker.execute(token, request_body, now=NOW + timedelta(seconds=3))
    assert first.status_code == 200
    metadata, content = publisher.read_published(first.body.output_id)
    assert content == b"# Output\n"
    assert metadata.sha256 == hashlib.sha256(content).hexdigest()
    assert list((output_root / str(task.task_id)).iterdir()) == [
        output_root / str(task.task_id) / f"{first.body.output_id}.md"
    ]

    replay = broker.execute(token, request_body, now=NOW + timedelta(seconds=4))
    assert replay == first
    with database._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM output_records").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT state FROM output_records WHERE output_id=?", (str(first.body.output_id),)
            ).fetchone()[0]
            == "published"
        )
        assert connection.execute("SELECT COUNT(*) FROM request_deduplication").fetchone()[0] == 1
    events = database.events(task.task_id)
    assert len(events) == 1
    assert events[0].kind == "output_published"
    assert events[0].decision == "allow"


def test_request_id_reuse_with_different_content_conflicts_before_file_effect(
    tmp_path: Path,
) -> None:
    _, _, token, _, output_root, _, broker = _service(tmp_path)
    request_id = str(uuid4())
    first = broker.execute(token, _publish_body(request_id, "one"), now=NOW + timedelta(seconds=3))
    changed = broker.execute(
        token, _publish_body(request_id, "two"), now=NOW + timedelta(seconds=4)
    )
    assert first.status_code == 200
    assert changed.status_code == 409
    assert changed.body.error.code == "REQUEST_CONFLICT"
    assert len(list(output_root.rglob("*.md"))) == 1


def test_wrong_tool_output_kind_and_invalid_invoice_json_are_rejected_without_reservation(
    tmp_path: Path,
) -> None:
    database, task, token, _, output_root, _, broker = _service(tmp_path)
    wrong_tool_kind = broker.execute(
        token,
        _body(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "operation": "publish_output",
                "output_kind": "invoice_json",
                "output_text": "{}",
            }
        ),
        now=NOW + timedelta(seconds=3),
    )
    assert wrong_tool_kind.status_code == 422
    assert database.get_task(task.task_id).status == TaskStatus.RUNNING
    with database._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM request_deduplication").fetchone()[0] == 0
    assert list(output_root.iterdir()) == []

    invoice = _service(tmp_path / "invoice", tool_id="invoice_analyzer")
    invoice_db, invoice_task, invoice_token, _, _, _, invoice_broker = invoice
    invalid_invoice = invoice_broker.execute(
        invoice_token,
        _body(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "operation": "publish_output",
                "output_kind": "invoice_json",
                "output_text": json.dumps(
                    {
                        "vendor": "",
                        "invoice_number": "1",
                        "date": "2026-01-01",
                        "line_total": "1.00",
                        "grand_total": "1.00",
                    },
                    separators=(",", ":"),
                ),
            }
        ),
        now=NOW + timedelta(seconds=3),
    )
    assert invalid_invoice.status_code == 422
    assert invoice_db.get_task(invoice_task.task_id).status == TaskStatus.RUNNING

    valid_invoice = invoice_broker.execute(
        invoice_token,
        _body(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "operation": "publish_output",
                "output_kind": "invoice_json",
                "output_text": json.dumps(
                    {
                        "vendor": "Example Vendor",
                        "invoice_number": "00042",
                        "date": "2026-01-02",
                        "line_total": "10.00",
                        "grand_total": "10.00",
                    },
                    separators=(",", ":"),
                ),
            }
        ),
        now=NOW + timedelta(seconds=4),
    )
    assert valid_invoice.status_code == 200
    assert valid_invoice.body.output_id is not None


def test_output_slot_rejects_a_second_request_without_overwrite(tmp_path: Path) -> None:
    database, task, token, _, output_root, _, broker = _service(tmp_path)
    first = broker.execute(token, _publish_body(text="first"), now=NOW + timedelta(seconds=3))
    second = broker.execute(token, _publish_body(text="second"), now=NOW + timedelta(seconds=4))
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.body.error.code == "OUTPUT_ALREADY_PUBLISHED"
    assert len(list(output_root.rglob("*.md"))) == 1
    assert database.get_task(task.task_id).status == TaskStatus.RUNNING


def test_concurrent_publications_serialize_to_one_output_slot(tmp_path: Path) -> None:
    database, task, token, _, output_root, _, broker = _service(tmp_path)
    bodies = [_publish_body(text="first"), _publish_body(text="second")]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda body: broker.execute(token, body, now=NOW + timedelta(seconds=3)),
                bodies,
            )
        )

    assert sorted(result.status_code for result in results) == [200, 409]
    assert len(list(output_root.rglob("*.md"))) == 1
    with database._connection() as connection:
        rows = connection.execute(
            "SELECT state, response_json FROM request_deduplication WHERE task_id=?",
            (str(task.task_id),),
        ).fetchall()
    assert len(rows) == 2
    assert all(row["state"] == "completed" for row in rows)
    assert sorted(event.kind for event in database.events(task.task_id)) == [
        "output_publication_denied",
        "output_published",
    ]
