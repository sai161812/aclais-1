from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

import aclais.publication as publication_module
from aclais.broker import BrokerService
from aclais.persistence.database import (
    Database,
    DatabaseError,
    canonical_body_sha256,
)
from aclais.persistence.models import (
    BrokerPublishOutputRequest,
    CreateTaskRequest,
    JournalState,
    TaskStatus,
)
from aclais.publication import (
    OutputCollision,
    OutputPublisher,
    OutputUnavailable,
    SimulatedPublicationCrash,
    _move_without_replace,
)

pytestmark = pytest.mark.portable

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "a4-create-task-request.json"


def _fixture_request() -> CreateTaskRequest:
    return CreateTaskRequest.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


def _running(database: Database):
    task = database.create_task(_fixture_request(), run_id=uuid4(), now=NOW)
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


def _body(request_id: str | None = None, text: str = "# Safe\n") -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "request_id": request_id or str(uuid4()),
            "operation": "publish_output",
            "output_kind": "formatted_markdown",
            "output_text": text,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _harness(tmp_path: Path, fault=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = Database(tmp_path / "state.sqlite3")
    task, token = _running(database)
    selected_root = tmp_path / "selected"
    selected_root.mkdir()
    output_root = tmp_path / "verified-output"
    output_root.mkdir()
    publisher = OutputPublisher(database, output_root, fault=fault)
    broker = BrokerService(database, selected_root, publisher)
    return database, task, token, output_root, publisher, broker


class _FailOnce:
    def __init__(self, boundary: str) -> None:
        self.boundary = boundary
        self.fired = False

    def __call__(self, boundary: str) -> None:
        if not self.fired and boundary == self.boundary:
            self.fired = True
            raise SimulatedPublicationCrash(boundary)


@pytest.mark.parametrize(
    "boundary",
    [
        "stage_created",
        "stage_written",
        "stage_flushed",
        "staged_recorded",
        "before_move",
        "after_move",
        "final_verified",
        "before_final_commit",
        "after_final_commit",
    ],
)
def test_exact_retry_recovers_each_publication_crash_boundary(
    tmp_path: Path, boundary: str
) -> None:
    fault = _FailOnce(boundary)
    database, task, token, output_root, publisher, broker = _harness(tmp_path, fault)
    request_body = _body()
    with pytest.raises(SimulatedPublicationCrash, match=boundary):
        broker.execute(token, request_body, now=NOW + timedelta(seconds=3))

    # Reopen SQLite too: recovery must use only durable state after a process crash.
    database = Database(database.path)
    publisher = OutputPublisher(database, output_root)
    broker = BrokerService(database, tmp_path / "selected", publisher)
    recovered = broker.execute(token, request_body, now=NOW + timedelta(seconds=4))
    assert recovered.status_code == 200
    metadata, content = publisher.read_published(recovered.body.output_id)
    assert content == b"# Safe\n"
    assert metadata.decoded_bytes == len(content)
    assert len(list((output_root / str(task.task_id)).glob("*.md"))) == 1
    assert database.output_journal(recovered.body.output_id).state == JournalState.PUBLISHED
    with database._connection() as connection:
        assert (
            connection.execute(
                "SELECT state FROM request_deduplication WHERE task_id=?", (str(task.task_id),)
            ).fetchone()[0]
            == "completed"
        )


def test_exact_retry_after_durable_output_reservation_uses_database_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, task, token, output_root, _, broker = _harness(tmp_path)
    original_reserve = database.reserve_output

    def crash_after_reserve(*args, **kwargs):
        original_reserve(*args, **kwargs)
        raise SimulatedPublicationCrash("after_output_reservation")

    monkeypatch.setattr(database, "reserve_output", crash_after_reserve)
    request_body = _body()
    with pytest.raises(SimulatedPublicationCrash, match="after_output_reservation"):
        broker.execute(token, request_body, now=NOW + timedelta(seconds=3))
    assert not list(output_root.rglob("*"))

    database = Database(database.path)
    publisher = OutputPublisher(database, output_root)
    broker = BrokerService(database, tmp_path / "selected", publisher)
    recovered = broker.execute(token, request_body, now=NOW + timedelta(seconds=4))
    assert recovered.status_code == 200
    assert len(list(output_root.rglob("*.md"))) == 1
    record = database.output_journal(recovered.body.output_id)
    assert record is not None
    assert record.state == JournalState.PUBLISHED


def test_retry_reflushes_a_complete_but_uncommitted_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fault = _FailOnce("stage_written")
    database, task, token, _, publisher, broker = _harness(tmp_path, fault)
    request_body = _body()
    with pytest.raises(SimulatedPublicationCrash):
        broker.execute(token, request_body, now=NOW + timedelta(seconds=3))

    flush_calls = 0
    original_flush = publication_module._flush_to_disk

    def track_flush(stream):
        nonlocal flush_calls
        flush_calls += 1
        original_flush(stream)

    monkeypatch.setattr(publication_module, "_flush_to_disk", track_flush)
    publisher._fault = None
    recovered = broker.execute(token, request_body, now=NOW + timedelta(seconds=4))
    assert recovered.status_code == 200
    assert flush_calls == 1
    request_id = json.loads(request_body)["request_id"]
    record = database.output_for_request(task_id=task.task_id, request_id=request_id)
    assert record is not None
    assert record.state == JournalState.PUBLISHED


def test_finalization_database_failure_withholds_then_retry_commits(tmp_path: Path) -> None:
    database, task, token, output_root, publisher, broker = _harness(tmp_path)
    original_finalize = database.finalize_output_publication

    def fail_finalize(*args, **kwargs):
        raise DatabaseError("injected final transaction failure")

    database.finalize_output_publication = fail_finalize  # type: ignore[method-assign]
    request_body = _body()
    failed = broker.execute(token, request_body, now=NOW + timedelta(seconds=3))
    assert failed.status_code == 503
    with database._connection() as connection:
        row = connection.execute("SELECT * FROM output_records").fetchone()
    assert row["state"] == "staged"
    assert list(output_root.rglob("*.staging")) == []
    assert len(list(output_root.rglob("*.md"))) == 1
    with pytest.raises(OutputUnavailable):
        publisher.read_published(row["output_id"])

    database.finalize_output_publication = original_finalize  # type: ignore[method-assign]
    recovered = broker.execute(token, request_body, now=NOW + timedelta(seconds=4))
    assert recovered.status_code == 200
    assert database.output_journal(row["output_id"]).state == JournalState.PUBLISHED
    assert len(list(output_root.rglob("*.md"))) == 1


def test_destination_collision_is_never_overwritten_and_is_withheld(tmp_path: Path) -> None:
    database, task, _, output_root, publisher, _ = _harness(tmp_path)
    request_id = uuid4()
    request = BrokerPublishOutputRequest(
        schema_version=1,
        request_id=request_id,
        operation="publish_output",
        output_kind="formatted_markdown",
        output_text="expected content",
    )
    body_hash = canonical_body_sha256(request)
    database.begin_request(task.task_id, request_id, body_hash, now=NOW + timedelta(seconds=3))
    payload = request.output_text.encode("utf-8")
    record = database.reserve_output(
        task.task_id,
        request_id,
        hashlib.sha256(payload).hexdigest(),
        len(payload),
        now=NOW + timedelta(seconds=3),
    )
    _, final = publisher.paths(record)
    final.parent.mkdir()
    final.write_bytes(b"do not replace\n")

    with pytest.raises(OutputCollision):
        publisher.publish(record, request)
    assert final.read_bytes() == b"do not replace\n"
    assert database.output_journal(record.output_id).state == JournalState.INCONSISTENT
    with pytest.raises(OutputUnavailable):
        publisher.read_published(record.output_id)


def test_destination_collision_racing_the_no_replace_move_marks_inconsistent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, task, token, output_root, _, broker = _harness(tmp_path)
    request_body = _body()
    original_move = publication_module._move_without_replace

    def collide_at_move(source: Path, destination: Path) -> None:
        destination.write_bytes(b"preexisting collision")
        original_move(source, destination)

    monkeypatch.setattr(publication_module, "_move_without_replace", collide_at_move)
    failed = broker.execute(token, request_body, now=NOW + timedelta(seconds=3))
    assert failed.status_code == 503
    request_id = json.loads(request_body)["request_id"]
    record = database.output_for_request(task.task_id, request_id)
    assert record is not None
    assert record.state == JournalState.INCONSISTENT
    final = output_root / record.final_relative_path
    assert final.read_bytes() == b"preexisting collision"
    with pytest.raises(OutputUnavailable):
        OutputPublisher(database, output_root).read_published(record.output_id)


def test_published_file_tampering_is_detected_and_withheld(tmp_path: Path) -> None:
    database, _, token, output_root, publisher, broker = _harness(tmp_path)
    result = broker.execute(token, _body(), now=NOW + timedelta(seconds=3))
    metadata = database.published_output(result.body.output_id)
    final = output_root / str(metadata.task_id) / metadata.file_name
    final.write_bytes(b"changed after publication")

    with pytest.raises(OutputUnavailable):
        publisher.read_published(result.body.output_id)
    assert database.output_journal(result.body.output_id).state == JournalState.INCONSISTENT


@pytest.mark.windows_enforcement
@pytest.mark.skipif(os.name != "nt", reason="requires the actual Windows filesystem API")
def test_windows_movefileex_is_no_replace_and_uses_ntfs(tmp_path: Path) -> None:
    import ctypes

    filesystem_name = ctypes.create_unicode_buffer(32)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_volume_information = kernel32.GetVolumeInformationW
    get_volume_information.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    )
    get_volume_information.restype = ctypes.c_int
    volume_root = str(Path(tmp_path.anchor))
    if not get_volume_information(
        volume_root, None, 0, None, None, None, filesystem_name, len(filesystem_name)
    ):
        raise OSError(ctypes.get_last_error(), "GetVolumeInformationW failed")
    assert filesystem_name.value == "NTFS"

    source = tmp_path / "source.tmp"
    destination = tmp_path / "output.md"
    source.write_bytes(b"new")
    destination.write_bytes(b"existing")
    with pytest.raises(OutputCollision):
        _move_without_replace(source, destination)
    assert source.read_bytes() == b"new"
    assert destination.read_bytes() == b"existing"

    _move_without_replace(source, tmp_path / "output-unique.md")
    assert not source.exists()
    assert (tmp_path / "output-unique.md").read_bytes() == b"new"
