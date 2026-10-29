"""Validate raw, owner-protected G3 evidence and emit a bounded sanitized report."""

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
DIRECT_TARGETS = (
    "store/originals/project-report.md",
    "store/originals/meeting-notes.md",
)
EXPECTED_BROKER_ORDER = ("read_document", "publish_output", "replace_original")


class EvidenceError(ValueError):
    """The raw record does not prove the required paired-run observations."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("raw evidence contains duplicate JSON fields")
        result[key] = value
    return result


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceError(f"{label} is not an object")
    return value


def _validated_inventory(value: Any, label: str) -> list[dict[str, Any]]:
    """Validate exact originals privately; never return these fields in the report."""
    if type(value) is not list or len(value) != 4:
        raise EvidenceError(f"{label} must contain the four seeded original records")
    names: set[str] = set()
    sanitized: list[dict[str, Any]] = []
    for entry in value:
        item = _mapping(entry, label)
        name = item.get("path")
        exists = item.get("exists")
        kind = item.get("type")
        size = item.get("size_bytes")
        digest = item.get("sha256")
        if (
            type(name) is not str
            or name
            not in {
                "Personnel_Private.csv",
                "invoice.csv",
                "meeting-notes.md",
                "project-report.md",
            }
            or name in names
            or type(exists) is not bool
            or kind not in {"file", "missing"}
        ):
            raise EvidenceError(f"{label} contains an unexpected original record")
        names.add(name)
        if exists:
            if type(size) is not int or size < 0 or not _is_sha256(digest):
                raise EvidenceError(f"{label} has an invalid existing-file record")
            sanitized.append({"name": name, "exists": True, "size_bytes": size, "sha256": digest})
        else:
            if kind != "missing" or size is not None or digest is not None:
                raise EvidenceError(f"{label} has an invalid missing-file record")
            sanitized.append({"name": name, "exists": False, "size_bytes": None, "sha256": None})
    if names != {
        "Personnel_Private.csv",
        "invoice.csv",
        "meeting-notes.md",
        "project-report.md",
    }:
        raise EvidenceError(f"{label} omits one or more seeded original names")
    return sorted(sanitized, key=lambda item: item["name"].casefold())


def _is_sha256(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _observations(value: Any, label: str) -> list[dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= 32:
        raise EvidenceError(f"{label} is missing or unbounded")
    return [_mapping(item, label) for item in value]


def _direct_attempts(observations: list[dict[str, Any]], *, baseline: bool) -> list[dict[str, Any]]:
    attempts = [item for item in observations if item.get("kind") == "direct_attempt"]
    expected_results = ("succeeded", "succeeded") if baseline else ("denied", "denied")
    if len(attempts) != 2:
        raise EvidenceError("the worker did not report exactly two direct mutation attempts")
    result: list[dict[str, Any]] = []
    for item, target, operation, expected in zip(
        attempts, DIRECT_TARGETS, ("overwrite", "delete"), expected_results, strict=True
    ):
        if (
            item.get("operation") != operation
            or item.get("target") != target
            or item.get("result") != expected
        ):
            raise EvidenceError("the direct filesystem effect differs from the required outcome")
        if baseline:
            if "winerror" in item or "errno" in item:
                raise EvidenceError("successful permissive attempts unexpectedly report errors")
            result.append({"operation": operation, "result": expected})
        else:
            if item.get("error_type") != "PermissionError":
                raise EvidenceError("protected direct attempt lacks a permission-denied error")
            if type(item.get("errno")) is not int or item["errno"] != errno.EACCES:
                raise EvidenceError("protected direct attempt lacks the OS access-denied errno")
            winerror = item.get("winerror")
            if winerror is not None and (type(winerror) is not int or winerror != 5):
                raise EvidenceError("protected direct attempt has an unexpected Windows error")
            result.append(
                {
                    "operation": operation,
                    "result": expected,
                    "error_type": item.get("error_type"),
                    "errno": item["errno"],
                    "winerror": item["winerror"],
                }
            )
    return result


def _current_source_digest() -> dict[str, Any]:
    path = ROOT / "aclais" / "scripts" / "source_digest.py"
    spec = importlib.util.spec_from_file_location("aclais_source_digest", path)
    if spec is None or spec.loader is None:
        raise EvidenceError("the source digest helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.source_digest()


def _read_raw(path: Path) -> dict[str, Any]:
    try:
        resolved_root = RAW_ROOT.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
        metadata = resolved_path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & 0x0400
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 2_000_000
        ):
            raise EvidenceError("raw evidence is not a bounded regular file")
        raw = resolved_path.read_bytes()
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceError("raw G3 evidence could not be read safely") from exc
    return _mapping(value, "raw evidence")


def validate(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema_version") != 1 or raw.get("checkpoint") != "G3_REPORT_FORMATTER":
        raise EvidenceError("raw evidence schema or checkpoint is not supported")

    current_digest = _current_source_digest()
    if raw.get("tested_source_digest_sha256") != current_digest.get("sha256"):
        raise EvidenceError("raw evidence does not identify the current implementation sources")
    if type(current_digest.get("file_count")) is not int or current_digest["file_count"] < 1:
        raise EvidenceError("the current source digest is invalid")

    baseline = _mapping(raw.get("baseline"), "baseline")
    protected = _mapping(raw.get("protected"), "protected run")
    worker_hash = raw.get("worker_tree_sha256_baseline")
    if not _is_sha256(worker_hash) or not (
        worker_hash
        == raw.get("worker_source_tree_sha256")
        == raw.get("worker_tree_sha256_protected_before")
        == raw.get("worker_tree_sha256_protected_after")
    ):
        raise EvidenceError("the installed worker source changed between paired runs")
    worker_sid = raw.get("worker_sid")
    if type(worker_sid) is not str or not worker_sid.startswith("S-1-"):
        raise EvidenceError("the worker identity was not recorded")
    if raw.get("worker_is_administrator") is not False:
        raise EvidenceError("the worker identity is missing or is an administrator")

    baseline_operations = baseline.get("operations")
    if baseline_operations != list(EXPECTED_BROKER_ORDER):
        raise EvidenceError("baseline broker operation order differs from the required sequence")
    protected_events = protected.get("broker_events")
    if type(protected_events) is not list or len(protected_events) != 3:
        raise EvidenceError("protected broker decisions are missing or unbounded")
    if tuple(item.get("operation") for item in protected_events) != EXPECTED_BROKER_ORDER:
        raise EvidenceError("protected broker operation order differs from the required sequence")
    decisions = tuple(item.get("decision") for item in protected_events)
    if decisions != ("allow", "allow", "deny"):
        raise EvidenceError("broker decisions do not prove useful output then mutation denial")
    if protected_events[2].get("reason_code") != "ORIGINAL_MUTATION_FORBIDDEN":
        raise EvidenceError("the final protected broker request was not the specified denial")

    baseline_observations = _observations(
        baseline.get("stdout_observations"), "baseline observations"
    )
    protected_observations = _observations(
        protected.get("stdout_observations"), "protected observations"
    )
    baseline_direct = _direct_attempts(baseline_observations, baseline=True)
    protected_direct = _direct_attempts(protected_observations, baseline=False)
    for label, observations in (
        ("baseline", baseline_observations),
        ("protected", protected_observations),
    ):
        kinds = [item.get("kind") for item in observations]
        if "useful_output_published" not in kinds:
            raise EvidenceError("worker observations omit useful output publication")
        output_index = kinds.index("useful_output_published")
        attempts = [index for index, kind in enumerate(kinds) if kind == "direct_attempt"]
        if len(attempts) != 2 or output_index >= min(attempts):
            raise EvidenceError("worker operations were not observed in the specified order")
        if label == "baseline":
            if "broker_denial_observed" not in kinds:
                raise EvidenceError("the permissive broker denial was not observed by the worker")
            if kinds.index("broker_denial_observed") <= max(attempts):
                raise EvidenceError("the baseline broker denial was observed out of order")
        elif (
            "broker_denial_observed" in kinds
            and kinds.index("broker_denial_observed") <= max(attempts)
        ):
            raise EvidenceError("protected worker denial observation was out of order")

    if baseline.get("useful_output_content_verified") is not True:
        raise EvidenceError("baseline useful output was not independently inspected")
    if baseline.get("exit_code") != 0 or baseline.get("process_tree_stopped") is not True:
        raise EvidenceError("baseline worker did not exit successfully and cleanly")
    if baseline.get("worker_sid") != worker_sid or protected.get("worker_sid") != worker_sid:
        raise EvidenceError("paired runs did not use the same recorded worker identity")
    if protected.get("status") not in {"BLOCKED", "FAILED"}:
        raise EvidenceError("protected ACLAIS task state was not recorded truthfully")
    if protected.get("revocation_cause") != "POLICY_DENIED":
        raise EvidenceError("protected run did not record broker-policy revocation")
    if protected.get("terminal_cause") != "POLICY_DENIED":
        raise EvidenceError("protected run did not preserve the policy-denial terminal cause")
    if (
        protected.get("process_stopped_independently") is not True
        or protected.get("evidence_worker_termination_confirmed") is not True
        or protected.get("evidence_process_tree_stopped") is not True
        or protected.get("evidence_assigned_to_job_before_resume") is not True
    ):
        raise EvidenceError("protected worker termination or containment lacks confirmation")
    if protected.get("useful_output_content_verified") is not True:
        raise EvidenceError("protected useful output was not independently inspected")
    if (
        not _is_sha256(protected.get("output_sha256"))
        or type(protected.get("output_bytes")) is not int
    ):
        raise EvidenceError("protected publication metadata is invalid")
    if baseline.get("output_sha256") != protected.get("output_sha256"):
        # Same selected input and same code should produce deterministic content in both runs.
        raise EvidenceError("paired runs produced different formatter output hashes")
    if baseline.get("output_bytes") != protected.get("output_bytes"):
        raise EvidenceError("paired runs produced different formatter output sizes")

    before = _validated_inventory(
        protected.get("original_inventory_before"), "protected before inventory"
    )
    after = _validated_inventory(
        protected.get("original_inventory_after"), "protected after inventory"
    )
    if before != after:
        raise EvidenceError("independent original-file inventory changed during the protected run")
    baseline_before = _validated_inventory(
        baseline.get("original_inventory_before"), "baseline before inventory"
    )
    baseline_after = _validated_inventory(
        baseline.get("original_inventory_after"), "baseline after inventory"
    )
    before_map = {item["name"]: item for item in baseline_before}
    after_map = {item["name"]: item for item in baseline_after}
    if (
        before_map["project-report.md"].get("sha256")
        == after_map["project-report.md"].get("sha256")
        or after_map["meeting-notes.md"]["exists"] is not False
        or before_map["invoice.csv"] != after_map["invoice.csv"]
        or before_map["Personnel_Private.csv"] != after_map["Personnel_Private.csv"]
    ):
        raise EvidenceError("permissive baseline did not show the two real filesystem effects")
    baseline_changed_count = sum(
        before_item != after_item
        for before_item, after_item in zip(baseline_before, baseline_after, strict=True)
    )

    if (
        raw.get("owner_approval_action_observed") is not True
        or raw.get("approval_get_task_count_before") != raw.get("approval_get_task_count_after")
        or raw.get("document_tools_cookie_count") != 0
    ):
        raise EvidenceError("trusted owner approval or browser-origin isolation was not verified")
    if protected.get("evidence_overall_status") not in {"pass", "unknown"}:
        raise EvidenceError("actual verifier status is absent")
    if protected.get("evidence_integrity_status") != "pass":
        raise EvidenceError("the independent ACLAIS integrity verifier did not pass")
    if protected.get("evidence_confidentiality_status") not in {"pass", "unknown"}:
        raise EvidenceError("the actual confidentiality-verification status is invalid")
    if protected.get("evidence_receiver_status") not in {"pass", "unknown"}:
        raise EvidenceError("the actual receiver status is invalid")

    return {
        "schema_version": 1,
        "checkpoint": "G3_REPORT_FORMATTER_SLICE",
        "report_status": "PASS",
        "g3_overall_status": "INCOMPLETE_INVOICE_ANALYZER_PENDING",
        "tested_source_digest_sha256": current_digest["sha256"],
        "tested_source_file_count": current_digest["file_count"],
        "installed_worker_tree_sha256": worker_hash,
        "worker_identity_verified": True,
        "worker_sid_sha256": hashlib.sha256(worker_sid.encode("ascii")).hexdigest(),
        "baseline": {
            "worker_exit_code": 0,
            "process_tree_stopped": True,
            "same_worker_code_hash": True,
            "direct_attempts": baseline_direct,
            "broker_order": list(baseline_operations),
            "output_bytes": baseline["output_bytes"],
            "useful_output_verified": True,
            "same_useful_output_as_protected_run": True,
            "original_record_count": len(baseline_before),
            "original_records_changed": baseline_changed_count,
        },
        "protected": {
            "actual_task_status": protected["status"],
            "revocation_cause": protected["revocation_cause"],
            "terminal_cause": protected["terminal_cause"],
            "same_worker_code_hash": True,
            "direct_attempts": protected_direct,
            "worker_observed_final_denial": "broker_denial_observed"
            in [item.get("kind") for item in protected_observations],
            "broker_events": [
                {
                    "operation": item["operation"],
                    "decision": item["decision"],
                    "reason_code": item["reason_code"],
                }
                for item in protected_events
            ],
            "output_bytes": protected["output_bytes"],
            "useful_output_verified": True,
            "same_useful_output_as_baseline": True,
            "original_record_count": len(before),
            "independent_inventory_unchanged": True,
            "evidence_overall_status": protected["evidence_overall_status"],
            "evidence_integrity_status": protected["evidence_integrity_status"],
            "evidence_confidentiality_status": protected["evidence_confidentiality_status"],
            "evidence_receiver_status": protected["evidence_receiver_status"],
            "worker_termination_confirmed": True,
            "job_assignment_before_resume_confirmed": True,
        },
        "owner_approval_get_created_no_task": True,
        "document_tools_received_no_owner_cookies": True,
        "invoice_analyzer": "NOT_STARTED",
        "g3_complete": False,
        "raw_receipts_or_fixture_payloads_in_report": False,
        "fixture_names_or_fixture_hashes_in_report": False,
        "sanitized_at_utc": datetime.now(UTC).isoformat(),
    }


def _write(path: Path, payload: bytes) -> None:
    if path.exists() and path.is_symlink():
        raise EvidenceError("refusing to replace a symlinked report path")
    temp = path.with_name(path.name + ".tmp")
    with temp.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def _markdown(report: dict[str, Any]) -> str:
    protected = report["protected"]
    baseline = report["baseline"]
    worker_denial_observation = (
        "Worker stdout recorded the denial response."
        if protected["worker_observed_final_denial"]
        else (
            "Worker stdout contained no denial-response observation; the controller database "
            "separately records the denied final broker event."
        )
    )
    overwrite_error = protected["direct_attempts"][0]
    delete_error = protected["direct_attempts"][1]
    overwrite_result = (
        f"errno {overwrite_error['errno']} (EACCES; winerror unavailable)"
        if overwrite_error["winerror"] is None
        else f"WinError {overwrite_error['winerror']} / errno {overwrite_error['errno']}"
    )
    delete_result = (
        f"errno {delete_error['errno']} (EACCES; winerror unavailable)"
        if delete_error["winerror"] is None
        else f"WinError {delete_error['winerror']} / errno {delete_error['errno']}"
    )
    lines = [
        "# G3 Report Formatter evidence",
        "",
        "**Report Formatter slice: PASS. Overall G3: INCOMPLETE; Invoice Analyzer has not started.**",  # noqa: E501
        "",
        f"Tested source digest: `{report['tested_source_digest_sha256']}` ({report['tested_source_file_count']} implementation files).",  # noqa: E501
        f"Installed worker tree SHA-256: `{report['installed_worker_tree_sha256']}`. The same non-administrator worker identity and worker source hash were used for both runs; SID SHA-256: `{report['worker_sid_sha256']}`.",  # noqa: E501
        "",
        "## Permissive private baseline",
        "",
        f"The worker exited {baseline['worker_exit_code']} and its process tree was independently observed stopped. It read the selected input and published useful formatted output ({baseline['output_bytes']} bytes). Both required direct filesystem operations succeeded; the independent inventory confirmed that two of four original records changed. The final broker operation was the forbidden `replace_original` request.",  # noqa: E501
        "",
        "## Protected ACLAIS run",
        "",
        f"The side-effect-free owner approval GET created no task; the explicit authenticated approval launched the installed worker. Document Tools received no owner cookies. ACLAIS recorded task state `{protected['actual_task_status']}`, revocation cause `{protected['revocation_cause']}`, and terminal cause `{protected['terminal_cause']}`. This state is reported as observed; this report does not relabel it BLOCKED.",  # noqa: E501
        f"The worker published useful output ({protected['output_bytes']} bytes), identical to the permissive run, then Windows denied the direct overwrite as `PermissionError` ({overwrite_result}) and the delete as `PermissionError` ({delete_result}). {worker_denial_observation} The last controller broker event was the denied `replace_original` request ({protected['broker_events'][-1]['reason_code']}).",  # noqa: E501
        "",
        f"After confirmed worker termination, an independent owner-side inventory compared the names, existence states, sizes and content hashes of all {protected['original_record_count']} seeded originals; unchanged: `{protected['independent_inventory_unchanged']}`. ACLAIS evidence status: `{protected['evidence_overall_status']}`. Worker termination and Job Object assignment before resume were confirmed.",  # noqa: E501
        "",
        "## Scope and limitations",
        "",
        "The same fixed installed formatter code was used for the permissive and protected runs. Permissive controls exist only in the private test harness. No production attack/demo/protection controls were added.",  # noqa: E501
        "Invoice Analyzer is not implemented or installed. This is a Report Formatter G3 slice only; overall G3 and integrated G4 remain incomplete. Receiver run creation and worker ingest-token association remain G4 work.",  # noqa: E501
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument(
        "--json-output", type=Path, default=ROOT / "evidence" / "G3-report-formatter.json"
    )
    parser.add_argument("--markdown-output", type=Path, default=ROOT / "evidence" / "G3.md")
    args = parser.parse_args()
    if "G1 PASS" not in (ROOT / "evidence" / "G1.md").read_text(encoding="utf-8"):
        raise EvidenceError("G1 is not marked PASS in the current evidence")
    if "G2 acceptance: PASS" not in (ROOT / "evidence" / "G2.md").read_text(encoding="utf-8"):
        raise EvidenceError("G2 is not marked PASS in the current evidence")
    raw = _read_raw(args.raw)
    report = validate(raw)
    json_payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    markdown_payload = _markdown(report).encode("utf-8")
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    _write(args.json_output, json_payload)
    _write(args.markdown_output, markdown_payload)
    print(json.dumps({"status": "PASS", "report": str(args.markdown_output.relative_to(ROOT))}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"G3 evidence rejected: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
