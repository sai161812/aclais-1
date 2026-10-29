from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aclais.evidence import (
    FixtureVerifier,
    VerificationTimeout,
    sanitized_report_summary,
    scan_inventory,
)
from aclais.launcher.models import CapturedLine
from aclais.persistence.database import Database, utc_now
from aclais.persistence.models import (
    CreateTaskRequest,
    EvidenceCheck,
    EvidenceReport,
    InventoryEntry,
    TaskStatus,
)
from aclais.publication import OutputPublisher
from tests.fixtures.receiver_adapter import FixtureReceiverAdapter

pytestmark = pytest.mark.portable


@dataclass
class Harness:
    database: Database
    task: object
    fixture_root: Path
    original: Path
    selected_copy: Path
    verifier: FixtureVerifier
    baseline: object
    publisher: OutputPublisher


def _harness(tmp_path: Path) -> Harness:
    database = Database(tmp_path / "controller.sqlite3")
    request = CreateTaskRequest(
        schema_version=1,
        tool_id="report_formatter",
        selected_document_id="doc-report",
        launch_source_claim="document_tools",
    )
    task = database.create_task(request, run_id=uuid4(), now=utc_now())
    fixture_root = tmp_path / "store"
    originals = fixture_root / "selected"
    originals.mkdir(parents=True)
    original = originals / "report.md"
    original.write_bytes(b"synthetic protected original\n")
    selected_copy = tmp_path / "work" / str(task.task_id) / "report.md"
    selected_copy.parent.mkdir(parents=True)
    selected_copy.write_bytes(original.read_bytes())
    raw_root = tmp_path / "evidence" / "raw"
    output_root = tmp_path / "verified-output"
    output_root.mkdir()
    publisher = OutputPublisher(database, output_root)
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    verifier = FixtureVerifier(
        database,
        fixture_root,
        raw_root,
        expected_fixtures=(("store/selected/report.md", digest),),
        source_root=Path(__file__).resolve().parents[1] / "src" / "aclais",
        source_revision="a" * 40,
    )
    baseline = verifier.capture_baseline(task, selected_copy)
    # PID/SID/job enforcement is covered by the actual Windows lane.
    task_with_identity = task.model_copy(
        update={"worker_pid": 45001, "worker_sid": "S-1-5-21-test"}
    )
    return Harness(
        database=database,
        task=task_with_identity,
        fixture_root=fixture_root,
        original=original,
        selected_copy=selected_copy,
        verifier=verifier,
        baseline=baseline,
        publisher=publisher,
    )


def _verify(
    harness: Harness,
    *,
    selected_input: Path | None = None,
    receiver=None,
    worker_observations=(),
    worker_exit_observed: bool = True,
    termination_confirmed: bool = True,
) -> EvidenceReport:
    return harness.verifier.verify_after_termination(
        harness.task,
        harness.baseline,
        termination_confirmed=termination_confirmed,
        worker_exit_observed=worker_exit_observed,
        worker_creation_time_100ns=551_000,
        worker_result=None,
        selected_input=selected_input or harness.selected_copy,
        outputs=(),
        publisher=harness.publisher,
        receiver_adapter=receiver,
        worker_observations=worker_observations,
    )


def test_inventory_detects_changed_file_name_size_and_hash(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.original.write_bytes(b"modified protected original with a different size\n")
    report = _verify(harness)
    assert report.overall_status == "fail"
    assert report.integrity_status == "fail"
    assert report.changed_files == ("selected/report.md",)
    before = next(item for item in report.file_inventory_before if item.entry_type == "file")
    after = next(item for item in report.file_inventory_after if item.entry_type == "file")
    assert before.relative_path == after.relative_path
    assert before.exists and after.exists
    assert before.size_bytes != after.size_bytes
    assert before.sha256 != after.sha256


def test_inventory_detects_missing_file(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.original.unlink()
    report = _verify(harness)
    assert report.overall_status == "fail"
    assert report.missing_files == ("selected/report.md",)
    assert tuple(item.relative_path for item in report.file_inventory_after) == ("selected",)


def test_inventory_detects_renamed_file_by_hash_and_size(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.original.rename(harness.original.with_name("renamed.md"))
    report = _verify(harness)
    assert report.overall_status == "fail"
    assert report.renamed_files == ("selected/report.md -> selected/renamed.md",)
    assert report.added_files == report.missing_files == ()


def test_inventory_detects_new_file(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    (harness.fixture_root / "selected" / "new-note.txt").write_text(
        "synthetic extra file\n", encoding="utf-8"
    )
    report = _verify(harness)
    assert report.overall_status == "fail"
    assert report.added_files == ("selected/new-note.txt",)


@pytest.mark.parametrize("name", ["selected//report.md", "selected/./report.md"])
def test_inventory_rejects_noncanonical_relative_names(name: str) -> None:
    with pytest.raises(ValidationError):
        InventoryEntry(
            entry_type="file",
            relative_path=name,
            exists=True,
            size_bytes=1,
            sha256=hashlib.sha256(b"x").hexdigest(),
        )


def test_evidence_references_reject_noncanonical_relative_paths() -> None:
    with pytest.raises(ValidationError):
        EvidenceCheck(
            id="inventory",
            source="verifier",
            status="pass",
            observed="unchanged",
            expected="unchanged",
            artifact_path="raw//task/report.json",
        )


def test_selected_copy_hash_is_compared_before_and_after(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.selected_copy.write_bytes(b"altered selected copy\n")
    report = _verify(harness)
    assert report.overall_status == "fail"
    assert report.selected_input_size_before_bytes != report.selected_input_size_after_bytes
    assert report.selected_input_sha256_before != report.selected_input_sha256_after
    assert any(
        check.id == "selected_input_hash" and check.status == "fail" for check in report.checks
    )


def test_inventory_timeout_is_unknown_and_never_green(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    def timeout_after_baseline(root: Path, **kwargs):
        raise VerificationTimeout("test_timeout")

    harness.verifier.scanner = timeout_after_baseline
    report = _verify(harness)
    assert report.overall_status == "unknown"
    assert report.integrity_status == "unknown"
    assert any(check.observed == "timeout" for check in report.checks)


def test_unavailable_baseline_remains_unknown_without_a_final_scan(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    calls = 0

    def count_scans(root: Path, **kwargs):
        nonlocal calls
        calls += 1
        return scan_inventory(root, **kwargs)

    harness.verifier.scanner = count_scans
    report = harness.verifier.verify_after_termination(
        harness.task,
        None,
        termination_confirmed=True,
        worker_exit_observed=False,
        worker_creation_time_100ns=551_000,
        worker_result=None,
        selected_input=harness.selected_copy,
        outputs=(),
        publisher=harness.publisher,
    )
    assert calls == 0
    assert report.overall_status == "unknown"
    assert report.integrity_status == "unknown"
    assert any(
        check.id == "fixture_baseline_available" and check.status == "unknown"
        for check in report.checks
    )


def test_final_inventory_waits_for_confirmed_worker_termination(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    calls = 0

    def count_scans(root: Path, **kwargs):
        nonlocal calls
        calls += 1
        return scan_inventory(root, **kwargs)

    harness.verifier.scanner = count_scans
    report = _verify(
        harness,
        worker_exit_observed=False,
        termination_confirmed=False,
    )
    assert calls == 0
    assert report.overall_status == "unknown"
    assert report.worker_exit_observed is False
    assert report.worker_termination_confirmed is False
    assert report.file_inventory_after == ()
    assert "final_inventory_deferred_until_containment_is_confirmed" in report.differences


def test_missing_identity_during_preparation_keeps_final_state_unknown(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.task = harness.task.model_copy(
        update={"worker_pid": None, "worker_sid": None, "status": TaskStatus.PREPARING}
    )
    calls = 0

    def count_scans(root: Path, **kwargs):
        nonlocal calls
        calls += 1
        return scan_inventory(root, **kwargs)

    harness.verifier.scanner = count_scans
    report = _verify(harness, termination_confirmed=True, worker_exit_observed=False)
    assert calls == 0
    assert report.overall_status == "unknown"
    assert report.worker_termination_confirmed is False
    assert report.controller_process_observation is None


def test_baseline_and_report_reopen_with_immutable_digest_checked_records(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    assert harness.database.evidence_response(harness.task.task_id).status == "pending"
    report = _verify(harness)
    reopened = Database(harness.database.path)
    assert reopened.evidence_baseline(harness.task.task_id) == harness.baseline
    stored = reopened.evidence_response(harness.task.task_id)
    assert stored.status == "complete"
    assert stored.report == report
    with pytest.raises(sqlite3.IntegrityError, match="task_evidence_baselines_are_immutable"):
        with reopened._connection() as connection:
            connection.execute(
                "UPDATE task_evidence_baselines SET manifest_match=0 WHERE task_id=?",
                (str(harness.task.task_id),),
            )
    with pytest.raises(sqlite3.IntegrityError, match="task_evidence_reports_are_immutable"):
        with reopened._connection() as connection:
            connection.execute(
                "UPDATE task_evidence_reports SET report_json='{}' WHERE task_id=?",
                (str(harness.task.task_id),),
            )


def test_worker_observation_is_distinct_and_cannot_supply_verifier_result(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    worker_claim = "ACLAIS_ENFORCEMENT_PASS: protected data was never read"
    harness.database.append_event(
        harness.task.task_id,
        source="broker",
        kind="operation_denied",
        message="Controller broker denied an out-of-scope read.",
        decision="deny",
    )
    report = _verify(
        harness,
        worker_observations=(CapturedLine(channel="stdout", text=worker_claim),),
    )
    assert report.overall_status == "pass"
    assert report.worker_observation_count == 1
    assert {event.source for event in harness.database.events(harness.task.task_id)} >= {
        "broker",
        "worker_reported",
        "verifier",
    }
    assert all(
        worker_claim not in event.message
        for event in harness.database.events(harness.task.task_id)
    )
    artifact_ref = report.checks[0].artifact_path
    assert artifact_ref is not None
    raw_report_path = tmp_path / "evidence" / "raw" / Path(artifact_ref).relative_to("raw")
    raw_payload = json.loads(raw_report_path.read_text(encoding="utf-8"))
    assert worker_claim in json.dumps(raw_payload)
    safe_summary = json.dumps(sanitized_report_summary(report))
    assert worker_claim not in safe_summary
    assert "selected/report.md" not in safe_summary
    assert harness.verifier.source_sha256 == report.tested_source_sha256


def test_worker_observation_input_is_bounded(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    calls = 0

    def observations():
        nonlocal calls
        for _ in range(2048):
            calls += 1
            yield CapturedLine(channel="stdout", text="synthetic observation")

    report = _verify(harness, worker_observations=observations())
    assert report.worker_observation_count == calls == 1024


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("healthy_empty", "pass"),
        ("positive_receipt", "fail"),
        ("unknown_run", "unknown"),
        ("outage", "unknown"),
    ],
)
def test_receiver_scenarios_preserve_unknown_and_positive_evidence(
    tmp_path: Path, scenario: str, expected: str
) -> None:
    harness = _harness(tmp_path)
    adapter = FixtureReceiverAdapter(scenario, harness.task.run_id)
    report = _verify(harness, receiver=adapter)
    assert report.overall_status == expected
    assert report.receiver_status == expected
