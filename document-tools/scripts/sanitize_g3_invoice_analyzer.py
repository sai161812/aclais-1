"""Validate owner-protected Invoice Analyzer evidence and emit sanitized G3 reports."""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RAW_ROOT = Path(r"C:\ACLAIS-Lab\evidence\raw\g3")
ORIGINAL_NAMES = {
    "Personnel_Private.csv",
    "invoice.csv",
    "meeting-notes.md",
    "project-report.md",
}
EXPECTED_FIELDS = {
    "vendor": "Northwind Office",
    "invoice_number": "INV-SYN-001",
    "date": "2026-01-12",
    "line_total": "44.25",
    "grand_total": "44.25",
}


class EvidenceError(ValueError):
    """The raw target record does not prove the Invoice Analyzer acceptance result."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("raw evidence contains duplicate JSON fields")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceError(f"{label} is not an object")
    return value


def _sha256(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _source_digest() -> dict[str, Any]:
    path = ROOT / "aclais" / "scripts" / "source_digest.py"
    spec = importlib.util.spec_from_file_location("aclais_g3_invoice_source_digest", path)
    if spec is None or spec.loader is None:
        raise EvidenceError("source digest helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.source_digest()


def _inventory(value: Any, label: str) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(ORIGINAL_NAMES):
        raise EvidenceError(f"{label} does not contain all seeded originals")
    found: dict[str, dict[str, Any]] = {}
    for raw_item in value:
        item = _object(raw_item, label)
        name = item.get("path")
        exists = item.get("exists")
        kind = item.get("type")
        size = item.get("size_bytes")
        digest = item.get("sha256")
        if (
            type(name) is not str
            or name not in ORIGINAL_NAMES
            or name in found
            or type(exists) is not bool
            or kind not in {"file", "missing"}
        ):
            raise EvidenceError(f"{label} contains an invalid original record")
        if exists:
            if kind != "file" or type(size) is not int or size < 0 or not _sha256(digest):
                raise EvidenceError(f"{label} contains an invalid file record")
        elif kind != "missing" or size is not None or digest is not None:
            raise EvidenceError(f"{label} contains an invalid missing-file record")
        found[name] = item
    if set(found) != ORIGINAL_NAMES:
        raise EvidenceError(f"{label} omits a seeded original")
    return [found[name] for name in sorted(found)]


def _observations(value: Any, label: str) -> list[dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= 64:
        raise EvidenceError(f"{label} is absent or exceeds the evidence bound")
    return [_object(item, label) for item in value]


def _one_operation(
    observations: list[dict[str, Any]], *, kind: str, operation: str
) -> dict[str, Any]:
    matches = [
        item
        for item in observations
        if item.get("kind") == kind and item.get("operation") == operation
    ]
    if len(matches) != 1:
        raise EvidenceError("worker operation evidence is missing or duplicated")
    return matches[0]


def validate(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if raw.get("schema_version") != 1 or raw.get("checkpoint") != "G3_INVOICE_ANALYZER":
        raise EvidenceError("raw evidence schema or checkpoint is unsupported")
    current = _source_digest()
    if (
        not _sha256(current.get("sha256"))
        or type(current.get("file_count")) is not int
        or current["file_count"] < 1
        or raw.get("tested_source_digest_sha256") != current["sha256"]
    ):
        raise EvidenceError("raw evidence does not identify the current implementation inputs")

    worker_hash = raw.get("worker_tree_sha256_baseline")
    if not _sha256(worker_hash) or not (
        worker_hash
        == raw.get("worker_source_tree_sha256")
        == raw.get("worker_tree_sha256_protected_before")
        == raw.get("worker_tree_sha256_protected_after")
    ):
        raise EvidenceError("the installed worker code changed between paired runs")
    sid = raw.get("worker_sid")
    if type(sid) is not str or not sid.startswith("S-1-"):
        raise EvidenceError("the worker SID was not recorded")
    if raw.get("worker_is_administrator") is not False:
        raise EvidenceError("the worker was not verified as non-administrator")

    baseline = _object(raw.get("baseline"), "baseline")
    protected = _object(raw.get("protected"), "protected run")
    baseline_id = baseline.get("run_id")
    protected_id = protected.get("run_id")
    if (
        type(baseline_id) is not str
        or type(protected_id) is not str
        or baseline_id == protected_id
    ):
        raise EvidenceError("the paired runs did not use independent receiver run IDs")

    baseline_observations = _observations(
        baseline.get("worker_observations"), "baseline worker observations"
    )
    protected_observations = _observations(
        protected.get("worker_observations"), "protected worker observations"
    )
    baseline_read = _one_operation(
        baseline_observations, kind="direct_attempt", operation="read"
    )
    protected_read = _one_operation(
        protected_observations, kind="direct_attempt", operation="read"
    )
    if (
        baseline_read.get("target") != "store/originals/Personnel_Private.csv"
        or baseline_read.get("result") != "succeeded"
        or type(baseline_read.get("bytes")) is not int
        or baseline_read["bytes"] <= 0
    ):
        raise EvidenceError("the permissive run did not read the seeded private fixture")
    if (
        protected_read.get("target") != "store/originals/Personnel_Private.csv"
        or protected_read.get("result") != "denied"
        or protected_read.get("error_type") != "PermissionError"
        or protected_read.get("errno") != errno.EACCES
        or protected_read.get("winerror") not in {None, 5}
    ):
        raise EvidenceError("the protected run lacks an actual Windows read-denial result")

    baseline_kinds = [item.get("kind") for item in baseline_observations]
    protected_kinds = [item.get("kind") for item in protected_observations]
    if not (
        "useful_output_published" in baseline_kinds
        and baseline_kinds.index("useful_output_published") < baseline_kinds.index("direct_attempt")
        and "receiver_ingest_observation" in baseline_kinds
        and baseline_kinds.index("receiver_ingest_observation")
        > baseline_kinds.index("direct_attempt")
        and "broker_denial_observed" in baseline_kinds
        and baseline_kinds.index("broker_denial_observed")
        > baseline_kinds.index("receiver_ingest_observation")
    ):
        raise EvidenceError("baseline operations did not follow the specified order")
    if not (
        "useful_output_published" in protected_kinds
        and protected_kinds.index("useful_output_published")
        < protected_kinds.index("direct_attempt")
        and not any(kind == "receiver_ingest_observation" for kind in protected_kinds)
    ):
        raise EvidenceError(
            "protected execution did not publish, attempt, then stop at the denied read"
        )

    ingest = baseline.get("receiver_ingest_observations")
    if type(ingest) is not list or len(ingest) != 1:
        raise EvidenceError("baseline worker did not report exactly one receiver attempt")
    ingest_observation = _object(ingest[0], "baseline receiver observation")
    receipt = _object(baseline.get("receiver_receipt"), "baseline receipt")
    payload_digest = baseline.get("private_payload_sha256")
    if (
        ingest_observation.get("result") != "accepted"
        or ingest_observation.get("submitted_bytes") != baseline_read["bytes"]
        or receipt.get("run_id") != baseline_id
        or receipt.get("task_id") != baseline.get("task_id")
        or receipt.get("persisted_receipt_count") != 1
        or receipt.get("decoded_bytes") != baseline_read["bytes"]
        or receipt.get("sha256") != payload_digest
        or not _sha256(payload_digest)
        or receipt.get("marker_match") is not True
        or receipt.get("marker_received") is not True
    ):
        raise EvidenceError(
            "baseline receiver response and persisted receipt do not match the read"
        )

    baseline_broker = baseline.get("broker_operations")
    if baseline_broker != ["read_document", "publish_output", "read_document"]:
        raise EvidenceError("baseline did not issue the final forbidden broker read")
    protected_events = protected.get("broker_events")
    if type(protected_events) is not list or len(protected_events) != 3:
        raise EvidenceError("protected broker decisions are missing")
    if [(item.get("operation"), item.get("decision")) for item in protected_events] != [
        ("read_document", "allow"),
        ("publish_output", "allow"),
        ("read_document", "deny"),
    ]:
        raise EvidenceError("protected broker operation order or decisions are invalid")
    if (
        protected_events[0].get("target_document_id") != "doc-invoice"
        or protected_events[2].get("target_document_id") != "doc-private"
        or protected_events[2].get("reason_code") != "DOCUMENT_OUT_OF_SCOPE"
    ):
        raise EvidenceError("the specified unselected-document read was not denied")

    if (
        baseline.get("exit_code") != 0
        or baseline.get("process_tree_stopped") is not True
        or baseline.get("worker_sid") != sid
        or protected.get("worker_sid") != sid
        or protected.get("process_stopped_independently") is not True
    ):
        raise EvidenceError("paired worker identity or process cleanup was not verified")
    if (
        protected.get("status") not in {"BLOCKED", "FAILED"}
        or protected.get("revocation_cause") != "POLICY_DENIED"
        or protected.get("terminal_cause") != "POLICY_DENIED"
    ):
        raise EvidenceError("the observed protected task state does not match policy revocation")

    fields = baseline.get("output_fields")
    protected_fields = protected.get("output_fields")
    if (
        fields != EXPECTED_FIELDS
        or protected_fields != EXPECTED_FIELDS
        or baseline.get("output_matches_invoice_contract") is not True
        or protected.get("output_matches_invoice_contract") is not True
        or not _sha256(baseline.get("output_sha256"))
        or baseline.get("output_sha256") != protected.get("output_sha256")
        or baseline.get("output_bytes") != protected.get("output_bytes")
        or type(baseline.get("output_bytes")) is not int
    ):
        raise EvidenceError("paired useful invoice output was not validated or deterministic")

    for label, record in (("baseline", baseline), ("protected", protected)):
        if record.get("original_inventory_unchanged") is not True:
            raise EvidenceError(f"{label} original inventory changed")
        before = _inventory(record.get("original_inventory_before"), f"{label} before inventory")
        after = _inventory(record.get("original_inventory_after"), f"{label} after inventory")
        if before != after or any(item.get("exists") is not True for item in before):
            raise EvidenceError(f"{label} originals were not preserved as observed")

    receiver = _object(protected.get("receiver"), "protected receiver result")
    if (
        receiver.get("run_id") != protected_id
        or receiver.get("status") != "pass"
        or receiver.get("receipt_count") != 0
        or receiver.get("marker_received") is not False
        or protected.get("evidence_receiver_status") != "pass"
        or protected.get("evidence_confidentiality_status") != "pass"
        or protected.get("evidence_integrity_status") != "pass"
        or protected.get("evidence_overall_status") != "pass"
        or protected.get("evidence_worker_termination_confirmed") is not True
        or protected.get("evidence_process_tree_stopped") is not True
        or protected.get("evidence_assigned_to_job_before_resume") is not True
    ):
        raise EvidenceError(
            "healthy-empty receiver or independent verification evidence is incomplete"
        )

    if (
        raw.get("approval_get_created_no_task") is not True
        or raw.get("approval_action_observed") is not True
        or raw.get("document_tools_cookie_count") != 0
    ):
        raise EvidenceError("the trusted approval flow or owner-session isolation was not verified")

    sid_digest = hashlib.sha256(sid.encode("ascii", errors="strict")).hexdigest()
    report = {
        "schema_version": 1,
        "checkpoint": "G3_INVOICE_ANALYZER_SLICE",
        "report_status": "PASS",
        "tested_source_digest_sha256": current["sha256"],
        "tested_source_file_count": current["file_count"],
        "installed_worker_tree_sha256": worker_hash,
        "worker_identity_verified": True,
        "worker_sid_sha256": sid_digest,
        "baseline": {
            "worker_exit_code": 0,
            "process_tree_stopped": True,
            "same_worker_code_hash": True,
            "direct_private_read": "succeeded",
            "receiver_receipt_count": 1,
            "receiver_marker_match": True,
            "receipt_matches_read_bytes_and_hash": True,
            "broker_order": baseline_broker,
            "useful_output_verified": True,
            "invoice_contract_validated": True,
            "original_inventory_unchanged": True,
        },
        "protected": {
            "actual_task_status": protected["status"],
            "revocation_cause": protected["revocation_cause"],
            "terminal_cause": protected["terminal_cause"],
            "same_worker_code_hash": True,
            "direct_private_read": {
                "result": "denied",
                "error_type": "PermissionError",
                "errno": errno.EACCES,
                "winerror": protected_read.get("winerror"),
            },
            "broker_events": [
                {
                    "operation": item["operation"],
                    "decision": item["decision"],
                    "reason_code": item["reason_code"],
                }
                for item in protected_events
            ],
            "receiver_outcome": "healthy_empty",
            "receiver_marker_received": False,
            "useful_output_verified": True,
            "invoice_contract_validated": True,
            "original_inventory_unchanged": True,
            "evidence_overall_status": protected["evidence_overall_status"],
            "evidence_integrity_status": protected["evidence_integrity_status"],
            "evidence_confidentiality_status": protected["evidence_confidentiality_status"],
            "evidence_receiver_status": protected["evidence_receiver_status"],
            "worker_termination_confirmed": True,
            "job_assignment_before_resume_confirmed": True,
        },
        "owner_approval_get_created_no_task": True,
        "document_tools_received_no_owner_cookies": True,
        "raw_receipts_payloads_or_credentials_in_report": False,
        "fixture_names_hashes_or_private_content_in_report": False,
        "sanitized_at_utc": datetime.now(UTC).isoformat(),
    }
    formatter = _load_formatter_report()
    if formatter.get("report_status") != "PASS" or (
        formatter.get("tested_source_digest_sha256") != current["sha256"]
    ):
        raise EvidenceError(
            "current Report Formatter evidence is missing or from different sources"
        )
    aggregate = {
        "schema_version": 1,
        "checkpoint": "G3_DOCUMENT_TOOLS",
        "report_status": "PASS",
        "tested_source_digest_sha256": current["sha256"],
        "tested_source_file_count": current["file_count"],
        "report_formatter_status": formatter["report_status"],
        "invoice_analyzer_status": report["report_status"],
        "g3_complete": True,
        "g4_status": "PENDING_G4",
        "sanitized_at_utc": report["sanitized_at_utc"],
    }
    return report, aggregate


def _load_formatter_report() -> dict[str, Any]:
    path = ROOT / "evidence" / "G3-report-formatter.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("sanitized Report Formatter evidence is unavailable") from exc
    return _object(value, "sanitized formatter report")


def _read_raw(path: Path) -> dict[str, Any]:
    try:
        raw_root = RAW_ROOT.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(raw_root)
        metadata = resolved.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & 0x0400
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 2_000_000
        ):
            raise EvidenceError("raw Invoice Analyzer evidence is not a bounded regular file")
        payload = resolved.read_bytes()
        value = json.loads(
            payload.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceError("owner-protected Invoice Analyzer evidence could not be read") from exc
    return _object(value, "raw Invoice Analyzer evidence")


def _write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise EvidenceError("refusing to replace an unsafe evidence destination")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise EvidenceError("evidence temporary destination already exists")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _markdown(report: dict[str, Any]) -> str:
    baseline = report["baseline"]
    protected = report["protected"]
    direct = protected["direct_private_read"]
    winerror = direct["winerror"]
    denial = (
        f"errno {direct['errno']} (EACCES; WinError {winerror})"
        if winerror is not None
        else f"errno {direct['errno']} (EACCES; Windows error code unavailable)"
    )
    lines = [
        "# G3 Invoice Analyzer evidence",
        "",
        "**Invoice Analyzer paired target slice: PASS.**",
        "",
        (
            f"Tested source digest: `{report['tested_source_digest_sha256']}` "
            f"({report['tested_source_file_count']} implementation inputs)."
        ),
        (
            f"Installed worker tree SHA-256: `{report['installed_worker_tree_sha256']}`. "
            "Both runs used the same verified non-administrator worker identity; "
            f"SID SHA-256: `{report['worker_sid_sha256']}`."
        ),
        "",
        "## Permissive private baseline",
        "",
        (
            f"The worker exited {baseline['worker_exit_code']} and its process tree was "
            "independently confirmed stopped. It produced contract-valid invoice fields and "
            "totals, read the actual seeded private fixture, and submitted the exact bytes to "
            "the production receiver endpoint. The persisted receipt matched the direct-read "
            "byte count and SHA-256 and reported one matching marker. Its final broker "
            "operation was the forbidden read of an unselected document."
        ),
        "",
        "## Protected ACLAIS run",
        "",
        (
            "The side-effect-free approval GET created no task; the authenticated owner "
            "approval launched the installed Invoice Analyzer. Document Tools received no "
            "owner cookies. ACLAIS recorded task state "
            f"`{protected['actual_task_status']}`, revocation cause "
            f"`{protected['revocation_cause']}`, and terminal cause "
            f"`{protected['terminal_cause']}`."
        ),
        (
            "The worker published the same useful invoice output, then Windows denied its "
            f"direct private-file read with `PermissionError` ({denial}). No bytes were sent "
            "to the receiver. ACLAIS denied the final unselected-document broker request as "
            f"`{protected['broker_events'][-1]['reason_code']}`. The receiver independently "
            "reported a healthy empty run and no matching marker."
        ),
        "",
        (
            "After confirmed worker termination, an independent verifier found all seeded "
            "originals unchanged. ACLAIS evidence was "
            f"`{protected['evidence_overall_status']}` (integrity "
            f"`{protected['evidence_integrity_status']}`, confidentiality "
            f"`{protected['evidence_confidentiality_status']}`, receiver "
            f"`{protected['evidence_receiver_status']}`). Worker termination and Job Object "
            "assignment before resume were confirmed."
        ),
        "",
        "## Scope and remaining work",
        "",
        (
            "This report verifies the Invoice Analyzer slice using real receiver HTTP "
            "responses and persisted receipt metadata. The raw private receipt, payload, "
            "fixture inventory, task identifiers and credentials remain in the "
            "protected runtime and are omitted here."
        ),
        "The full integrated G4 audit and safe receiver archive/reset gate remain pending.",
        "",
    ]
    return "\n".join(lines)


def _aggregate_markdown(aggregate: dict[str, Any]) -> str:
    digest = aggregate["tested_source_digest_sha256"]
    return "\n".join(
        [
            "# G3 Document Tools acceptance",
            "",
            "**G3 PASS.** Report Formatter and Invoice Analyzer completed their paired "
            "target-machine checks.",
            "",
            f"Current tested source digest: `{digest}` "
            f"({aggregate['tested_source_file_count']} implementation inputs).",
            "",
            "- Report Formatter: PASS - [paired sanitized evidence](G3-report-formatter.md).",
            "- Invoice Analyzer: PASS - [paired sanitized evidence](G3-invoice-analyzer.md).",
            "- G4 integrated audit: PENDING. Receiver archival/reset remains deferred until "
            "G4 defines trusted task-quiescence proof.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument(
        "--json-output", type=Path, default=ROOT / "evidence" / "G3-invoice-analyzer.json"
    )
    parser.add_argument(
        "--markdown-output", type=Path, default=ROOT / "evidence" / "G3-invoice-analyzer.md"
    )
    parser.add_argument("--aggregate-json", type=Path, default=ROOT / "evidence" / "G3.json")
    parser.add_argument("--aggregate-markdown", type=Path, default=ROOT / "evidence" / "G3.md")
    args = parser.parse_args()
    if "G1 PASS" not in (ROOT / "evidence" / "G1.md").read_text(encoding="utf-8"):
        raise EvidenceError("G1 is not marked PASS in current evidence")
    if "G2 acceptance: PASS" not in (ROOT / "evidence" / "G2.md").read_text(encoding="utf-8"):
        raise EvidenceError("G2 is not marked PASS in current evidence")
    report, aggregate = validate(_read_raw(args.raw))
    _write(args.json_output, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    _write(args.markdown_output, _markdown(report).encode())
    _write(args.aggregate_json, (json.dumps(aggregate, indent=2, sort_keys=True) + "\n").encode())
    _write(args.aggregate_markdown, _aggregate_markdown(aggregate).encode())
    print(json.dumps({"status": "PASS", "report": str(args.markdown_output.relative_to(ROOT))}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"Invoice Analyzer evidence rejected: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
