"""Portable owned-fixture transactions; these tests do not establish Windows ACLs."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest

from aclais import operator
from aclais.persistence.database import Database
from aclais.persistence.models import CreateTaskRequest, HealthCheck
from aclais.readiness import Readiness, ReadinessError

pytestmark = pytest.mark.portable


def test_bootstrap_browser_failure_never_logs_exception_or_secret(monkeypatch, caplog):
    def fail(*_args, **_kwargs):
        raise RuntimeError("SYNTHETIC-BOOTSTRAP-ONLY should never reach a log")

    monkeypatch.setattr("webbrowser.open", fail)
    operator.open_owner_bootstrap("http://127.0.0.1:8765/owner#SYNTHETIC-BOOTSTRAP-ONLY")
    assert "owner_bootstrap_browser_open_failed" in caplog.text
    assert "SYNTHETIC-BOOTSTRAP-ONLY" not in caplog.text
    assert "RuntimeError" not in caplog.text


def test_failed_controller_never_advertises_ready_even_with_installed_workers(
    tmp_path, monkeypatch
):
    for tool in ("report_formatter", "invoice_analyzer"):
        entry = tmp_path / "code/document-tools/workers" / tool / "entrypoint.py"
        entry.parent.mkdir(parents=True)
        entry.write_text("# readiness fixture only; never executed\n")
    readiness = Readiness(type("Layout", (), {"root": tmp_path})())
    monkeypatch.setattr(
        readiness,
        "check",
        lambda: (
            HealthCheck(id="owned_installation", status="pass", summary="Portable fixture only."),
        ),
    )
    assert readiness.health().protection_ready
    health = readiness.health(controller_accepting=False)
    assert not health.protection_ready
    assert health.status == "unavailable"
    assert any(
        item.id == "controller_lifecycle" and item.status == "fail" for item in health.checks
    )
    assert any(item.id == "g1_protection" and item.status == "fail" for item in health.checks)


@pytest.fixture
def owned(tmp_path: Path):
    root = tmp_path / "owned-lab"
    for directory in ("state", "baseline", "evidence/raw"):
        (root / directory).mkdir(parents=True)
    records = []
    for relative, template in operator.FIXTURES.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        content = (operator.TEMPLATES / template).read_bytes()
        target.write_bytes(content)
        records.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest()})
    (root / "baseline/Personnel_Private.csv").write_bytes(
        (root / "store/originals/Personnel_Private.csv").read_bytes()
    )
    root_id = str(uuid.uuid4())
    sentinel = {"root_id": root_id, "root_path": str(root), "owner_sid": "synthetic-owner"}
    (root / ".owner-sentinel.json").write_bytes(operator.encode(sentinel))
    (root / "state/installation.json").write_bytes(
        operator.encode({**sentinel, "fixtures": records})
    )
    (root / "state/trusted-state.json").write_bytes(operator.encode({"fixture_hashes": records}))
    (root / "evidence/raw/previous-evidence.json").write_text('{"synthetic":true}')
    return root, root_id


def test_reset_rotates_marker_archives_evidence_and_preserves_history(owned):
    root, _ = owned
    db = Database(root / "state/controller.sqlite3")
    operator.reset_fixtures(root, "synthetic-owner")
    first = (root / "state/run-secret.json").read_bytes()
    operator.reset_fixtures(root, "synthetic-owner")
    assert (root / "state/run-secret.json").read_bytes() != first
    manifest = json.loads((root / "state/installation.json").read_text())
    for record in manifest["fixtures"]:
        assert hashlib.sha256((root / record["path"]).read_bytes()).hexdigest() == record["sha256"]
    assert db.task_summaries() == ()
    assert len(list((root / "evidence/archives").iterdir())) == 2
    assert len(list((root / "evidence/archives").glob("*/raw/previous-evidence.json"))) == 2


def test_reset_failure_rolls_back_all_written_files(owned, monkeypatch):
    root, _ = owned
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    original = operator.atomic_write
    calls = 0

    def fail_once(path, content):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("injected reset interruption")
        original(path, content)

    monkeypatch.setattr(operator, "atomic_write", fail_once)
    with pytest.raises(OSError):
        operator.reset_fixtures(root, "synthetic-owner")
    for relative, content in before.items():
        assert (root / relative).read_bytes() == content
    assert not (root / "state/reset-in-progress.json").exists()


def test_operator_rejects_wrong_owner_paths_active_tasks_and_root_id(owned):
    root, root_id = owned
    with pytest.raises(ValueError):
        operator.reset_fixtures(root, "different-owner")
    with pytest.raises(ValueError):
        operator.plain(root, "../outside")
    with pytest.raises(ReadinessError):
        operator.retire_owned_root(root, "synthetic-owner", str(uuid.uuid4()))
    db = Database(root / "state/controller.sqlite3")
    db.create_task(
        CreateTaskRequest(
            schema_version=1,
            tool_id="report_formatter",
            selected_document_id="doc-report",
            launch_source_claim="document_tools",
        )
    )
    with pytest.raises(ReadinessError):
        operator.reset_fixtures(root, "synthetic-owner")
    with pytest.raises(ReadinessError):
        operator.retire_owned_root(root, "synthetic-owner", root_id)


def test_retirement_archives_owned_root_and_preserves_unknown_local_file(owned):
    root, root_id = owned
    (root / "keep.txt").write_text("synthetic operator file")
    archive = operator.retire_owned_root(root, "synthetic-owner", root_id)
    assert not root.exists()
    assert (archive / "keep.txt").read_text() == "synthetic operator file"


def test_failed_readiness_clears_protection_and_refuses_launch(monkeypatch, tmp_path):
    def fail(**_kwargs):
        raise ReadinessError("synthetic boundary failure")

    monkeypatch.setattr("aclais.readiness.boundary_check", fail)
    readiness = Readiness(type("Layout", (), {"root": tmp_path})())
    health = readiness.health()
    assert not health.protection_ready
    assert next(c for c in health.checks if c.id == "g1_protection").status == "fail"
    with pytest.raises(ReadinessError):
        readiness.require_core()
