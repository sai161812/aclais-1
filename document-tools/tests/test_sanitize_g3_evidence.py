from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "document-tools" / "scripts"))

import sanitize_g3_report_formatter as sanitizer  # noqa: E402

pytestmark = pytest.mark.portable

WORKER_SID = "S-1-5-21-11-22-33-1006"
WORKER_TREE_HASH = "a" * 64
OUTPUT_HASH = hashlib.sha256(b"same useful synthetic output").hexdigest()
FILE_NAMES = (
    "Personnel_Private.csv",
    "invoice.csv",
    "meeting-notes.md",
    "project-report.md",
)


def _inventory(*, report_hash: str = "1" * 64, notes_exists: bool = True):
    hashes = {
        "Personnel_Private.csv": "2" * 64,
        "invoice.csv": "3" * 64,
        "meeting-notes.md": "4" * 64,
        "project-report.md": report_hash,
    }
    return [
        {
            "path": name,
            "exists": name != "meeting-notes.md" or notes_exists,
            "type": "file" if name != "meeting-notes.md" or notes_exists else "missing",
            "size_bytes": 16 if name != "meeting-notes.md" or notes_exists else None,
            "sha256": hashes[name] if name != "meeting-notes.md" or notes_exists else None,
        }
        for name in FILE_NAMES
    ]


def _attempt(operation: str, target: str, *, baseline: bool):
    item = {
        "kind": "direct_attempt",
        "operation": operation,
        "target": target,
        "result": "succeeded" if baseline else "denied",
    }
    if not baseline:
        item.update(
            {
                "error_type": "PermissionError",
                "errno": 13,
                "winerror": None if operation == "overwrite" else 5,
            }
        )
    return item


def _raw_report():
    output_before = _inventory()
    output_after = _inventory(report_hash="5" * 64, notes_exists=False)
    protected_inventory = _inventory()
    observations_baseline = [
        {"kind": "useful_output_published", "sha256": OUTPUT_HASH, "bytes": 466},
        _attempt("overwrite", "store/originals/project-report.md", baseline=True),
        _attempt("delete", "store/originals/meeting-notes.md", baseline=True),
        {"kind": "broker_denial_observed", "status_code": 403},
    ]
    observations_protected = [
        {"kind": "useful_output_published", "sha256": OUTPUT_HASH, "bytes": 466},
        _attempt("overwrite", "store/originals/project-report.md", baseline=False),
        _attempt("delete", "store/originals/meeting-notes.md", baseline=False),
    ]
    protected_events = [
        {"operation": "read_document", "decision": "allow", "reason_code": None},
        {"operation": "publish_output", "decision": "allow", "reason_code": None},
        {
            "operation": "replace_original",
            "decision": "deny",
            "reason_code": "ORIGINAL_MUTATION_FORBIDDEN",
        },
    ]
    return {
        "schema_version": 1,
        "checkpoint": "G3_REPORT_FORMATTER",
        "tested_source_digest_sha256": "b" * 64,
        "worker_tree_sha256_baseline": WORKER_TREE_HASH,
        "worker_source_tree_sha256": WORKER_TREE_HASH,
        "worker_tree_sha256_protected_before": WORKER_TREE_HASH,
        "worker_tree_sha256_protected_after": WORKER_TREE_HASH,
        "worker_sid": WORKER_SID,
        "worker_is_administrator": False,
        "owner_approval_action_observed": True,
        "approval_get_task_count_before": 0,
        "approval_get_task_count_after": 0,
        "document_tools_cookie_count": 0,
        "baseline": {
            "operations": ["read_document", "publish_output", "replace_original"],
            "stdout_observations": observations_baseline,
            "useful_output_content_verified": True,
            "exit_code": 0,
            "process_tree_stopped": True,
            "worker_sid": WORKER_SID,
            "output_sha256": OUTPUT_HASH,
            "output_bytes": 466,
            "original_inventory_before": output_before,
            "original_inventory_after": output_after,
        },
        "protected": {
            "broker_events": protected_events,
            "stdout_observations": observations_protected,
            "status": "FAILED",
            "revocation_cause": "POLICY_DENIED",
            "terminal_cause": "POLICY_DENIED",
            "worker_sid": WORKER_SID,
            "process_stopped_independently": True,
            "evidence_worker_termination_confirmed": True,
            "evidence_process_tree_stopped": True,
            "evidence_assigned_to_job_before_resume": True,
            "useful_output_content_verified": True,
            "output_sha256": OUTPUT_HASH,
            "output_bytes": 466,
            "original_inventory_before": protected_inventory,
            "original_inventory_after": protected_inventory,
            "evidence_overall_status": "unknown",
            "evidence_integrity_status": "pass",
            "evidence_confidentiality_status": "unknown",
            "evidence_receiver_status": "unknown",
        },
    }


def test_sanitized_report_omits_fixture_names_and_content_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert sanitizer.ROOT == REPOSITORY_ROOT
    monkeypatch.setattr(
        sanitizer,
        "_current_source_digest",
        lambda: {"sha256": "b" * 64, "file_count": 174},
    )

    raw = _raw_report()
    report = sanitizer.validate(raw)
    encoded = json.dumps(report, sort_keys=True)

    for name in FILE_NAMES:
        assert name not in encoded
    for item in raw["protected"]["original_inventory_before"]:
        assert item["sha256"] not in encoded
    for item in raw["baseline"]["original_inventory_before"]:
        if item["sha256"] is not None:
            assert item["sha256"] not in encoded
    assert OUTPUT_HASH not in encoded
    assert "original_inventory_before" not in encoded
    assert "original_inventory_after" not in encoded
    assert report["baseline"]["original_records_changed"] == 2
    assert report["baseline"]["original_record_count"] == 4
    assert report["protected"]["independent_inventory_unchanged"] is True
    assert report["protected"]["evidence_confidentiality_status"] == "unknown"
    assert report["protected"]["direct_attempts"][0]["errno"] == 13
    assert report["protected"]["direct_attempts"][0]["winerror"] is None
    assert report["protected"]["direct_attempts"][1]["winerror"] == 5


def test_sanitizer_rejects_changed_protected_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sanitizer,
        "_current_source_digest",
        lambda: {"sha256": "b" * 64, "file_count": 174},
    )
    raw = _raw_report()
    changed = _inventory(report_hash="6" * 64)
    raw["protected"]["original_inventory_after"] = changed

    with pytest.raises(sanitizer.EvidenceError, match="inventory changed"):
        sanitizer.validate(raw)
