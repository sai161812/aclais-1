from __future__ import annotations

import base64
import hashlib
import shutil
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

import receiver.database as database_module
from receiver.database import InjectedCrash, ReceiverStore, StorageIntegrityUnknown
from receiver.models import CreateRunRequest, IngestRequest
from support import CANARY_MARKER

pytestmark = pytest.mark.portable

_INGEST_TOKEN = "synthetic-run-ingest-token-fixture-0123456789"


def _request(run_id, *, request_id=None, payload: bytes | None = None) -> IngestRequest:
    raw = payload if payload is not None else b"synthetic receipt " + CANARY_MARKER.encode("ascii")
    return IngestRequest(
        schema_version=1,
        request_id=request_id or uuid4(),
        run_id=run_id,
        task_id=uuid4(),
        payload_base64=base64.b64encode(raw).decode("ascii"),
    )


def _store(root: Path, *, fault_hook=None) -> tuple[ReceiverStore, object]:
    store = ReceiverStore(root, fault_hook=fault_hook)
    store.initialize()
    run_id = uuid4()
    store.create_run(
        CreateRunRequest(schema_version=1, run_id=run_id, canary_marker=CANARY_MARKER),
        ingest_token=_INGEST_TOKEN,
    )
    return store, run_id


@pytest.mark.parametrize(
    ("crash_step", "recovered_before_retry"),
    [
        ("after_reservation", 0),
        ("after_stage_flush", 1),
        ("after_staged", 1),
        ("after_rename", 1),
        ("after_file_committed", 1),
        ("before_commit", 1),
    ],
)
def test_crash_recovery_yields_at_most_one_receipt_and_exact_retry(
    tmp_path: Path, crash_step: str, recovered_before_retry: int
) -> None:
    request_id = uuid4()
    run_id = uuid4()

    def fail(step: str) -> None:
        if step == crash_step:
            raise InjectedCrash("private failure injection")

    store = ReceiverStore(tmp_path / crash_step, fault_hook=fail)
    store.initialize()
    store.create_run(
        CreateRunRequest(schema_version=1, run_id=run_id, canary_marker=CANARY_MARKER),
        ingest_token=_INGEST_TOKEN,
    )
    request = _request(run_id, request_id=request_id)
    with pytest.raises(InjectedCrash):
        store.ingest(_INGEST_TOKEN, request)

    recovered = ReceiverStore(tmp_path / crash_step)
    recovered.initialize()
    receipts = recovered.get_receipts(run_id)
    assert len(receipts.receipts) == recovered_before_retry
    replay = recovered.ingest(_INGEST_TOKEN, request)
    replay_again = recovered.ingest(_INGEST_TOKEN, request)
    assert len(recovered.get_receipts(run_id).receipts) == 1
    assert len(list((tmp_path / crash_step / "payloads").glob("*.bin"))) == 1
    if recovered_before_retry:
        assert replay.receipt_id == receipts.receipts[0].receipt_id
    else:
        assert replay.receipt_id == replay_again.receipt_id
    assert replay.sha256 == hashlib.sha256(request.decoded_payload).hexdigest()


def test_missing_or_tampered_committed_payload_never_becomes_empty(tmp_path: Path) -> None:
    root = tmp_path / "tamper"
    store, run_id = _store(root)
    request = _request(run_id)
    receipt = store.ingest(_INGEST_TOKEN, request)
    payload_path = root / "payloads" / f"{receipt.receipt_id}.bin"
    payload_path.write_bytes(b"tampered synthetic content")
    with pytest.raises(StorageIntegrityUnknown):
        store.get_receipts(run_id)

    reopened = ReceiverStore(root)
    reopened.initialize()
    with pytest.raises(StorageIntegrityUnknown):
        reopened.get_receipts(run_id)


def test_missing_committed_payload_is_marked_unknown_after_restart(tmp_path: Path) -> None:
    root = tmp_path / "missing"
    store, run_id = _store(root)
    receipt = store.ingest(_INGEST_TOKEN, _request(run_id))
    (root / "payloads" / f"{receipt.receipt_id}.bin").unlink()
    reopened = ReceiverStore(root)
    reopened.initialize()
    with pytest.raises(StorageIntegrityUnknown):
        reopened.get_receipts(run_id)


def test_corrupt_journal_filename_is_rejected_without_touching_outside_path(
    tmp_path: Path,
) -> None:
    store, run_id = _store(tmp_path / "path-integrity")
    receipt = store.ingest(_INGEST_TOKEN, _request(run_id))
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"untouched outside file")
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE receipts SET payload_name=? WHERE receipt_id=?",
            (f"{uuid4()}.bin", str(receipt.receipt_id)),
        )

    reopened = ReceiverStore(store.data_root)
    reopened.initialize()
    assert outside.read_bytes() == b"untouched outside file"
    with pytest.raises(StorageIntegrityUnknown):
        reopened.get_receipts(run_id)
    with pytest.raises(StorageIntegrityUnknown):
        reopened._receipt_paths(
            {
                "receipt_id": str(receipt.receipt_id),
                "staging_name": f"{receipt.receipt_id}.stage",
                "payload_name": "../outside.bin",
            }
        )
    assert outside.read_bytes() == b"untouched outside file"


def test_unknown_payload_file_is_quarantined_and_service_stays_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "orphan"
    store = ReceiverStore(root)
    store.initialize()
    orphan = root / "payloads" / "unknown.bin"
    orphan.write_bytes(b"synthetic orphan")

    reopened = ReceiverStore(root)
    reopened.initialize()
    with sqlite3.connect(root / "receiver.sqlite3") as db:
        incident_count = db.execute("SELECT count(*) FROM system_incidents").fetchone()[0]
    assert incident_count == 1
    assert not orphan.exists()
    assert len(list((root / "quarantine").glob("*.quarantined"))) == 1
    with pytest.raises(StorageIntegrityUnknown):
        reopened.health_status()


def test_changed_migration_is_rejected_on_reopen(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "migration"
    original, _ = _store(root)
    assert original.health_status() == "ready"
    migration_dir = tmp_path / "changed-migrations"
    migration_dir.mkdir()
    migration = database_module._MIGRATIONS / "0001_initial.sql"
    shutil.copyfile(migration, migration_dir / migration.name)
    with (migration_dir / migration.name).open("ab") as output:
        output.write(b"\n-- changed content\n")
    monkeypatch.setattr(database_module, "_MIGRATIONS", migration_dir)
    reopened = ReceiverStore(root)
    with pytest.raises(RuntimeError):
        reopened.initialize()
