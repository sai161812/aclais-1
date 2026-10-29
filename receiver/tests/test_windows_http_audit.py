"""Actual Windows receiver-process audit against its protected persistent store."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import http.client
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from aclais.receiver_adapter import HttpReceiverAdapter, assess_receiver

from receiver.config import ReceiverSettings
from receiver.credentials import read_admin_credential
from receiver.models import MAX_RECEIPT_BYTES, MAX_REQUEST_BYTES

pytestmark = [pytest.mark.windows_receiver_live_http]

_HOST = "::1"
_PORT = 8767
_ADMIN_ROUTE_PREFIX = "/admin/runs/"
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_MAX_CAPTURED_LOG_BYTES = 1_048_576


class _StartedService:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.output = bytearray()
        self.overflowed = False
        assert process.stdout is not None

        def drain() -> None:
            while chunk := process.stdout.read(8192):
                remaining = _MAX_CAPTURED_LOG_BYTES - len(self.output)
                if remaining > 0:
                    self.output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.overflowed = True

        self.reader = threading.Thread(target=drain, name="receiver-audit-log-reader", daemon=True)
        self.reader.start()

    def completed_output(self) -> bytes:
        self.reader.join(timeout=5)
        if self.reader.is_alive() or self.overflowed:
            raise AssertionError("receiver audit logs exceeded the bounded inspection window")
        return bytes(self.output)


def _request(
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    token: str | None = None,
    timeout: float = 5.0,
    content_type: str = "application/json",
) -> tuple[int, dict[str, object]]:
    connection = http.client.HTTPConnection(_HOST, _PORT, timeout=timeout)
    headers = {"Accept": "application/json", "Host": f"[{_HOST}]:{_PORT}"}
    if body is not None:
        headers["Content-Type"] = content_type
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise AssertionError("receiver response exceeded the audit limit")
        if response.getheader("Content-Type", "").split(";", 1)[0].lower() != "application/json":
            raise AssertionError("receiver response content type was not JSON")
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AssertionError("receiver response was not JSON") from exc
        if not isinstance(value, dict):
            raise AssertionError("receiver response was not an object")
        return response.status, value
    finally:
        connection.close()


def _error_code(value: dict[str, object]) -> object:
    error = value.get("error")
    return error.get("code") if isinstance(error, dict) else None


def _assert_error(status: int, value: dict[str, object], expected_status: int) -> None:
    if status != expected_status or not isinstance(value.get("error"), dict):
        raise AssertionError("receiver rejected a request with an unexpected response")


def _create_run(admin_token: str, marker: str) -> tuple[UUID, str]:
    run_id = uuid4()
    body = json.dumps(
        {"schema_version": 1, "run_id": str(run_id), "canary_marker": marker},
        separators=(",", ":"),
    ).encode("ascii")
    status, value = _request("POST", "/admin/runs", token=admin_token, body=body)
    if status != 201 or value.get("run_id") != str(run_id):
        raise AssertionError("receiver did not create a synthetic audit run")
    token = value.get("ingest_token")
    if not isinstance(token, str) or len(token) < 32:
        raise AssertionError("receiver did not issue a run-bound ingest credential")
    return run_id, token


def _ingest_body(
    run_id: UUID,
    payload: bytes,
    *,
    request_id: UUID | None = None,
    task_id: UUID | None = None,
) -> tuple[bytes, UUID]:
    identifier = request_id or uuid4()
    body = json.dumps(
        {
            "schema_version": 1,
            "request_id": str(identifier),
            "run_id": str(run_id),
            "task_id": str(task_id or uuid4()),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("ascii")
    return body, identifier


def _port_is_free() -> bool:
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((_HOST, _PORT))
        return True
    except OSError:
        return False
    finally:
        listener.close()


def _assert_port_free() -> None:
    if not _port_is_free():
        raise AssertionError("receiver target port is already owned; the audit will not stop it")


def _start_service(
    component_root: Path,
    *,
    failure_step: str | None = None,
) -> _StartedService:
    _assert_port_free()
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("RECEIVER_"):
            environment.pop(key)
    environment["RECEIVER_LOG_LEVEL"] = "ERROR"
    environment.pop("ACLAIS_G2_LIVE_AUDIT", None)
    command = (
        [sys.executable, "-m", "receiver", "serve"]
        if failure_step is None
        else [
            sys.executable,
            str(component_root / "tests" / "probes" / "fault_server.py"),
            failure_step,
        ]
    )
    process = subprocess.Popen(
        command,
        cwd=component_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )
    service = _StartedService(process)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("the receiver subprocess exited before health became ready")
        try:
            status, value = _request("GET", "/health", timeout=0.5)
        except (OSError, http.client.HTTPException, TimeoutError):
            time.sleep(0.1)
            continue
        if status == 200 and value.get("status") == "ready":
            return service
        time.sleep(0.1)
    _stop_service(service)
    raise AssertionError("the receiver subprocess did not become healthy")


def _stop_service(service: _StartedService) -> bytes:
    process = service.process
    if process.poll() is None:
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=12)
        except (OSError, subprocess.TimeoutExpired):
            # This is the exact Popen handle created by the audit, never a port owner lookup.
            process.terminate()
            process.wait(timeout=5)
            raise AssertionError("the audit-owned receiver did not stop gracefully")
    if process.poll() is None:
        raise AssertionError("the audit-owned receiver process remains running")
    if not _port_is_free():
        raise AssertionError("the receiver listener remained after its owned process exited")
    return service.completed_output()


def _read_database_rows(database_path: Path, run_id: UUID) -> list[dict[str, object]]:
    connection = sqlite3.connect(database_path, timeout=3, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    try:
        rows = connection.execute(
            "SELECT receipt_id, payload_name, payload_sha256, decoded_bytes, marker_match, state "
            "FROM receipts WHERE run_id=? ORDER BY received_at, receipt_id",
            (str(run_id),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def _verify_persisted_payloads(
    settings: ReceiverSettings,
    run_id: UUID,
    expected_payloads: tuple[tuple[bytes, bool], ...],
    *,
    marker: bytes,
) -> tuple[list[dict[str, object]], bool]:
    rows = _read_database_rows(settings.data_root / "receiver.sqlite3", run_id)
    if len(rows) != len(expected_payloads):
        raise AssertionError("persistent receipt count did not match the successful HTTP requests")
    hash_size_match = True
    for row, (expected, expected_marker) in zip(rows, expected_payloads, strict=True):
        receipt_id = str(row["receipt_id"])
        try:
            canonical_id = str(UUID(receipt_id))
        except ValueError as exc:
            raise AssertionError("persisted receipt ID was not a UUID") from exc
        if receipt_id != canonical_id or row["payload_name"] != f"{receipt_id}.bin":
            raise AssertionError("persisted receipt filename was not canonical")
        payload_path = settings.data_root / "payloads" / str(row["payload_name"])
        actual = payload_path.read_bytes()
        hash_size_match = hash_size_match and (
            actual == expected
            and int(row["decoded_bytes"]) == len(expected)
            and str(row["payload_sha256"]) == hashlib.sha256(expected).hexdigest()
            and (marker in actual) is expected_marker
            and int(row["marker_match"]) == int(expected_marker)
            and row["state"] == "committed"
        )
    if not hash_size_match:
        raise AssertionError("persisted payload bytes, hash, size, marker, or state did not match")
    return rows, hash_size_match


def _verify_persisted_run(
    database_path: Path,
    run_id: UUID,
    ingest_token: str,
    marker: str,
) -> bool:
    connection = sqlite3.connect(database_path, timeout=3)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    try:
        row = connection.execute(
            "SELECT ingest_token_sha256, canary_marker, integrity_state FROM runs WHERE run_id=?",
            (str(run_id),),
        ).fetchone()
    finally:
        connection.close()
    return bool(
        row is not None
        and str(row["ingest_token_sha256"])
        == hashlib.sha256(ingest_token.encode("ascii")).hexdigest()
        and bytes(row["canary_marker"]) == marker.encode("ascii")
        and row["integrity_state"] == "healthy"
    )


def _source_inputs_digest(repository_root: Path) -> tuple[str, int, str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        capture_output=True,
        check=True,
    )
    allowed_prefixes = (
        ".github/workflows/",
        "aclais/backend/src/aclais/evidence.py",
        "aclais/backend/src/aclais/receiver_adapter.py",
        "aclais/backend/src/aclais/runtime.py",
        "docs/02_SHARED_CONTRACTS.md",
        "docs/04_BUILD_RECEIVER.md",
        "receiver/",
        "scripts/check.ps1",
        "scripts/start.ps1",
        "tests/test_receiver_adapter_integration.py",
    )
    hasher = hashlib.sha256()
    count = 0
    for relative in sorted(set(result.stdout.decode("utf-8").split("\0"))):
        if not relative or not relative.startswith(allowed_prefixes) or "/__pycache__/" in relative:
            continue
        path = repository_root / relative
        if path.is_file() and path.suffix.lower() in {
            ".py",
            ".ps1",
            ".sql",
            ".toml",
            ".lock",
            ".yml",
            ".yaml",
            ".md",
        }:
            hasher.update(relative.encode("utf-8"))
            hasher.update(b"\0")
            hasher.update(path.read_bytes().replace(b"\r\n", b"\n"))
            hasher.update(b"\0")
            count += 1
    revision = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    return hasher.hexdigest(), count, revision


def _exclusive_file_handle(path: Path) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(str(path), 0xC0000000, 0, None, 3, 0x80, None)
    if handle in (None, _INVALID_HANDLE_VALUE):
        raise AssertionError(
            "the audit could not acquire its exclusive synthetic storage fault handle"
        )
    return int(handle)


def _close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_int
    if not close_handle(ctypes.c_void_p(handle)):
        raise AssertionError("the audit storage fault handle did not close")


def test_live_receiver_http_and_persistent_receipt_audit() -> None:
    if sys.platform != "win32" or os.environ.get("ACLAIS_G2_LIVE_AUDIT") != "1":
        pytest.skip("requires the explicit Windows demonstration-machine audit wrapper")

    repository_root = Path(__file__).resolve().parents[2]
    component_root = repository_root / "receiver"
    settings = ReceiverSettings()
    database_path = settings.data_root / "receiver.sqlite3"
    admin_path = settings.data_root / "admin.token"
    admin_token = read_admin_credential(settings.data_root)
    payload_names_before = {path.name for path in (settings.data_root / "payloads").glob("*.bin")}
    service: _StartedService | None = None
    writer_lock: sqlite3.Connection | None = None
    exclusive_handle: int | None = None
    observations: dict[str, object] = {}
    fault_results: dict[str, object] = {}
    service_logs: list[bytes] = []
    sensitive_values: list[bytes] = []

    def stop_current_service() -> None:
        nonlocal service
        if service is not None:
            service_logs.append(_stop_service(service))
            service = None

    try:
        service = _start_service(component_root)
        health_status, health = _request("GET", "/health")
        if health_status != 200 or health.get("status") != "ready":
            raise AssertionError("actual receiver process did not report healthy")
        if not _port_is_free():
            # A bound listener is expected while the receiver owns the fixed IPv6 endpoint.
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                if probe.connect_ex((_HOST, _PORT)) != 0:
                    raise AssertionError("receiver did not hold its IPv6 listener")
        try:
            with socket.create_connection(("127.0.0.1", _PORT), timeout=0.5):
                raise AssertionError("receiver unexpectedly accepted an IPv4 connection")
        except OSError:
            pass

        marker = f"SYNTHETIC-G2-LIVE-MARKER-{uuid4().hex}"
        sensitive_values.extend((admin_token.encode("ascii"), marker.encode("ascii")))
        matching_run, matching_token = _create_run(admin_token, marker)
        nonmatching_run, nonmatching_token = _create_run(admin_token, marker)
        empty_marker = f"SYNTHETIC-G2-LIVE-EMPTY-{uuid4().hex}"
        cross_marker = f"SYNTHETIC-G2-LIVE-CROSS-{uuid4().hex}"
        failure_marker = f"SYNTHETIC-G2-LIVE-FAIL-{uuid4().hex}"
        empty_run, _empty_token = _create_run(admin_token, empty_marker)
        cross_run, _cross_token = _create_run(admin_token, cross_marker)
        failure_run, failure_token = _create_run(admin_token, failure_marker)
        sensitive_values.extend(
            token.encode("ascii")
            for token in (
                matching_token,
                nonmatching_token,
                _empty_token,
                _cross_token,
                failure_token,
            )
        )
        sensitive_values.extend(
            value.encode("ascii") for value in (empty_marker, cross_marker, failure_marker)
        )

        adapter = HttpReceiverAdapter(credential_file=admin_path)
        empty_assessment = assess_receiver(adapter, empty_run)
        if (
            empty_assessment.status,
            empty_assessment.outcome,
            empty_assessment.marker_received,
        ) != (
            "pass",
            "healthy_empty",
            False,
        ):
            raise AssertionError("ACLAIS did not present a healthy empty run accurately")
        empty_status, empty_receipts = _request(
            "GET", f"{_ADMIN_ROUTE_PREFIX}{empty_run}/receipts", token=admin_token
        )
        if (
            empty_status != 200
            or empty_receipts.get("run_id") != str(empty_run)
            or empty_receipts.get("receipts") != []
            or empty_receipts.get("marker_received") is not False
        ):
            raise AssertionError("healthy empty run did not return the empty receipt contract")

        matching_payload = b"synthetic persisted matching receipt " + marker.encode("ascii")
        nonmatching_payload = b"synthetic persisted nonmatching receipt without marker"
        matching_task_id = uuid4()
        matching_body, matching_request_id = _ingest_body(
            matching_run, matching_payload, task_id=matching_task_id
        )
        nonmatching_body, _ = _ingest_body(nonmatching_run, nonmatching_payload)
        sensitive_values.extend((matching_payload, nonmatching_payload))
        matching_status, matching_result = _request(
            "POST", "/ingest", token=matching_token, body=matching_body
        )
        nonmatching_status, nonmatching_result = _request(
            "POST", "/ingest", token=nonmatching_token, body=nonmatching_body
        )
        if matching_status != 201 or nonmatching_status != 201:
            raise AssertionError("receiver rejected a valid synthetic audit payload")

        matching_receipts_status, matching_receipts = _request(
            "GET", f"{_ADMIN_ROUTE_PREFIX}{matching_run}/receipts", token=admin_token
        )
        nonmatching_receipts_status, nonmatching_receipts = _request(
            "GET", f"{_ADMIN_ROUTE_PREFIX}{nonmatching_run}/receipts", token=admin_token
        )
        if (
            matching_receipts_status != 200
            or nonmatching_receipts_status != 200
            or matching_receipts.get("marker_received") is not True
            or nonmatching_receipts.get("marker_received") is not False
        ):
            raise AssertionError("receipt query did not distinguish matching and nonmatching bytes")
        matching_summary = matching_receipts["receipts"][0]
        nonmatching_summary = nonmatching_receipts["receipts"][0]
        if not isinstance(matching_summary, dict) or not isinstance(nonmatching_summary, dict):
            raise AssertionError("receiver returned an invalid receipt summary")
        if (
            matching_result.get("decoded_bytes") != len(matching_payload)
            or matching_result.get("sha256") != hashlib.sha256(matching_payload).hexdigest()
            or matching_summary.get("decoded_bytes") != len(matching_payload)
            or matching_summary.get("sha256") != hashlib.sha256(matching_payload).hexdigest()
            or matching_summary.get("marker_match") is not True
            or matching_summary.get("task_id") != str(matching_task_id)
            or nonmatching_result.get("decoded_bytes") != len(nonmatching_payload)
            or nonmatching_result.get("sha256") != hashlib.sha256(nonmatching_payload).hexdigest()
            or nonmatching_summary.get("decoded_bytes") != len(nonmatching_payload)
            or nonmatching_summary.get("sha256") != hashlib.sha256(nonmatching_payload).hexdigest()
            or nonmatching_summary.get("marker_match") is not False
        ):
            raise AssertionError(
                "HTTP receipt count, SHA-256, or marker match was not server-computed"
            )

        matching_rows, matching_persisted = _verify_persisted_payloads(
            settings, matching_run, ((matching_payload, True),), marker=marker.encode("ascii")
        )
        nonmatching_rows, nonmatching_persisted = _verify_persisted_payloads(
            settings,
            nonmatching_run,
            ((nonmatching_payload, False),),
            marker=marker.encode("ascii"),
        )
        if (
            not matching_persisted
            or not nonmatching_persisted
            or not _verify_persisted_run(database_path, matching_run, matching_token, marker)
        ):
            raise AssertionError("persisted receipt files did not match the HTTP submissions")
        if matching_rows[0]["receipt_id"] != matching_result.get("receipt_id"):
            raise AssertionError("HTTP receipt ID did not match the persisted journal row")
        inspect_result = subprocess.run(
            [sys.executable, "-m", "receiver", "inspect", str(matching_run)],
            cwd=component_root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
            text=True,
        )
        try:
            inspect_summary = json.loads(inspect_result.stdout)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise AssertionError("owner-only CLI did not return strict receipt metadata") from exc
        if (
            inspect_result.returncode != 0
            or inspect_summary.get("run_id") != str(matching_run)
            or inspect_summary.get("receipt_count") != 1
            or inspect_summary.get("decoded_bytes") != len(matching_payload)
            or inspect_summary.get("marker_received") is not True
        ):
            raise AssertionError("owner-only CLI did not inspect the persisted receipt")

        retry_status, retry_result = _request(
            "POST", "/ingest", token=matching_token, body=matching_body
        )
        if retry_status != 201 or retry_result.get("receipt_id") != matching_result.get(
            "receipt_id"
        ):
            raise AssertionError("identical retry did not return the original receipt")
        changed_body, _ = _ingest_body(
            matching_run,
            b"synthetic changed content for a reused request ID",
            request_id=matching_request_id,
            task_id=matching_task_id,
        )
        sensitive_values.append(b"synthetic changed content for a reused request ID")
        changed_status, changed_value = _request(
            "POST", "/ingest", token=matching_token, body=changed_body
        )
        _assert_error(changed_status, changed_value, 409)
        if _error_code(changed_value) != "REQUEST_CONFLICT":
            raise AssertionError("changed content with a reused request ID was not rejected")
        matching_rows_after_retry = _read_database_rows(database_path, matching_run)
        if (
            len(matching_rows_after_retry) != 1
            or matching_rows_after_retry[0]["receipt_id"] != matching_result.get("receipt_id")
            or len(list((settings.data_root / "payloads").glob("*.bin")))
            != len(payload_names_before) + 2
        ):
            raise AssertionError("identical retry or changed-body rejection duplicated a receipt")

        positive_assessment = assess_receiver(adapter, matching_run)
        nonmatching_assessment = assess_receiver(adapter, nonmatching_run)
        unknown_run_assessment = assess_receiver(adapter, uuid4())
        if (
            positive_assessment.status != "fail"
            or positive_assessment.outcome != "positive_receipt"
            or "blocked" in positive_assessment.reason.lower()
            or nonmatching_assessment.status != "pass"
            or nonmatching_assessment.outcome != "receipts_without_marker"
            or unknown_run_assessment.status != "unknown"
            or unknown_run_assessment.outcome != "unknown_run"
        ):
            raise AssertionError(
                "ACLAIS mapped a real receiver result to an incorrect evidence state"
            )

        wrong_payload = b"synthetic wrong-token attempt"
        wrong_body, _ = _ingest_body(matching_run, wrong_payload)
        wrong_token = f"synthetic-wrong-ingest-token-{uuid4().hex}"
        sensitive_values.extend((wrong_payload, wrong_token.encode("ascii")))
        wrong_status, wrong_value = _request("POST", "/ingest", token=wrong_token, body=wrong_body)
        _assert_error(wrong_status, wrong_value, 401)
        if _error_code(wrong_value) != "AUTH_INVALID":
            raise AssertionError("wrong ingest credential returned the wrong error code")

        cross_payload = b"synthetic cross-run token attempt"
        cross_body, _ = _ingest_body(cross_run, cross_payload)
        sensitive_values.append(cross_payload)
        cross_status, cross_value = _request(
            "POST", "/ingest", token=matching_token, body=cross_body
        )
        _assert_error(cross_status, cross_value, 401)
        if _error_code(cross_value) != "AUTH_INVALID":
            raise AssertionError("cross-run ingest credential returned the wrong error code")

        admin_denied_status, admin_denied = _request(
            "GET", f"{_ADMIN_ROUTE_PREFIX}{matching_run}/receipts", token=matching_token
        )
        _assert_error(admin_denied_status, admin_denied, 401)
        if _error_code(admin_denied) != "AUTH_INVALID":
            raise AssertionError("ingest credential accessed owner-only receipt inspection")
        create_denied_run = uuid4()
        create_denied_marker = f"SYNTHETIC-G2-DENIED-{uuid4().hex}"
        sensitive_values.append(create_denied_marker.encode("ascii"))
        create_denied_body = json.dumps(
            {
                "schema_version": 1,
                "run_id": str(create_denied_run),
                "canary_marker": create_denied_marker,
            },
            separators=(",", ":"),
        ).encode("ascii")
        create_denied_status, create_denied = _request(
            "POST", "/admin/runs", token=matching_token, body=create_denied_body
        )
        _assert_error(create_denied_status, create_denied, 401)
        if _error_code(create_denied) != "AUTH_INVALID":
            raise AssertionError("ingest credential accessed administrative run creation")
        denied_run_check = sqlite3.connect(database_path, timeout=3)
        try:
            denied_run_was_created = denied_run_check.execute(
                "SELECT 1 FROM runs WHERE run_id=?", (str(create_denied_run),)
            ).fetchone()
        finally:
            denied_run_check.close()
        if denied_run_was_created:
            raise AssertionError("ingest credential created a run through the admin API")
        admin_ingest_status, admin_ingest = _request(
            "POST", "/ingest", token=admin_token, body=matching_body
        )
        _assert_error(admin_ingest_status, admin_ingest, 401)

        no_admin_auth_status, no_admin_auth = _request(
            "GET", f"{_ADMIN_ROUTE_PREFIX}{matching_run}/receipts"
        )
        _assert_error(no_admin_auth_status, no_admin_auth, 401)

        malformed_status, malformed_value = _request(
            "POST", "/ingest", token=matching_token, body=b'{"schema_version":'
        )
        _assert_error(malformed_status, malformed_value, 422)
        malformed_base64_body = json.dumps(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "run_id": str(matching_run),
                "task_id": str(uuid4()),
                "payload_base64": "!!!!",
            },
            separators=(",", ":"),
        ).encode("ascii")
        malformed_base64_status, malformed_base64_value = _request(
            "POST", "/ingest", token=matching_token, body=malformed_base64_body
        )
        _assert_error(malformed_base64_status, malformed_base64_value, 422)
        unknown_field_payload = b"synthetic unknown-field request"
        unknown_field_request, _ = _ingest_body(matching_run, unknown_field_payload)
        sensitive_values.append(unknown_field_payload)
        unknown_field_value = json.loads(unknown_field_request)
        unknown_field_value["sha256"] = "0" * 64
        unknown_field_status, unknown_field_response = _request(
            "POST",
            "/ingest",
            token=matching_token,
            body=json.dumps(unknown_field_value, separators=(",", ":")).encode("ascii"),
        )
        _assert_error(unknown_field_status, unknown_field_response, 422)

        oversized_payload = b"x" * (MAX_RECEIPT_BYTES + 1)
        sensitive_values.append(oversized_payload)
        oversized_payload_body, _ = _ingest_body(matching_run, oversized_payload)
        if len(oversized_payload_body) > MAX_REQUEST_BYTES:
            raise AssertionError("decoded-limit audit payload exceeded the separate request limit")
        oversized_decoded_status, oversized_decoded = _request(
            "POST", "/ingest", token=matching_token, body=oversized_payload_body, timeout=15
        )
        _assert_error(oversized_decoded_status, oversized_decoded, 413)

        oversized_request_status, oversized_request = _request(
            "POST",
            "/ingest",
            token=matching_token,
            body=b" " * (MAX_REQUEST_BYTES + 1),
            timeout=15,
        )
        _assert_error(oversized_request_status, oversized_request, 413)

        matching_rows_after_denials = _read_database_rows(database_path, matching_run)
        cross_rows_after_denials = _read_database_rows(database_path, cross_run)
        if len(matching_rows_after_denials) != 1 or cross_rows_after_denials:
            raise AssertionError("denied, malformed, or oversized requests produced a receipt")

        failure_payload = b"synthetic storage failure must not publish"
        sensitive_values.append(failure_payload)
        failure_body, _ = _ingest_body(failure_run, failure_payload)
        writer_lock = sqlite3.connect(database_path, timeout=0.2, isolation_level=None)
        writer_lock.execute("BEGIN IMMEDIATE")
        failure_status, failure_response = _request(
            "POST", "/ingest", token=failure_token, body=failure_body, timeout=20
        )
        _assert_error(failure_status, failure_response, 503)
        if _error_code(failure_response) != "PROTECTION_UNAVAILABLE":
            raise AssertionError("storage failure did not return protection unavailable")
        writer_lock.rollback()
        writer_lock.close()
        writer_lock = None
        if _read_database_rows(database_path, failure_run):
            raise AssertionError("storage failure persisted a receipt journal row")
        current_payload_names = {
            path.name for path in (settings.data_root / "payloads").glob("*.bin")
        }
        if current_payload_names != payload_names_before | {
            str(row["payload_name"]) for row in (*matching_rows, *nonmatching_rows)
        }:
            raise AssertionError("storage failure created an unjournaled payload file")

        invalid_admin_token = f"synthetic-invalid-admin-token-{uuid4().hex}"
        sensitive_values.append(invalid_admin_token.encode("ascii"))
        bad_admin_adapter = HttpReceiverAdapter(admin_token=invalid_admin_token)
        auth_assessment = assess_receiver(bad_admin_adapter, matching_run)
        if (auth_assessment.status, auth_assessment.outcome, auth_assessment.marker_received) != (
            "unknown",
            "authentication_failure",
            None,
        ):
            raise AssertionError("ACLAIS did not keep receiver authentication failure unknown")

        exclusive_handle = _exclusive_file_handle(database_path)
        storage_assessment = assess_receiver(adapter, matching_run)
        if (
            storage_assessment.status,
            storage_assessment.outcome,
            storage_assessment.marker_received,
        ) != (
            "unknown",
            "unreachable",
            None,
        ):
            raise AssertionError("ACLAIS did not keep a real storage-open failure unknown")
        _close_handle(exclusive_handle)
        exclusive_handle = None
        restored_status, restored_health = _request("GET", "/health")
        if restored_status != 200 or restored_health.get("status") != "ready":
            raise AssertionError("receiver did not recover after the exclusive test handle closed")

        stop_current_service()
        service = _start_service(component_root)
        restarted_matching_status, restarted_matching = _request(
            "GET", f"{_ADMIN_ROUTE_PREFIX}{matching_run}/receipts", token=admin_token
        )
        restarted_nonmatching_status, restarted_nonmatching = _request(
            "GET", f"{_ADMIN_ROUTE_PREFIX}{nonmatching_run}/receipts", token=admin_token
        )
        if (
            restarted_matching_status != 200
            or restarted_nonmatching_status != 200
            or len(restarted_matching.get("receipts", [])) != 1
            or len(restarted_nonmatching.get("receipts", [])) != 1
            or restarted_matching.get("marker_received") is not True
            or restarted_nonmatching.get("marker_received") is not False
        ):
            raise AssertionError("receiver restart lost or changed persisted receipts")
        retry_status, retry_result = _request(
            "POST", "/ingest", token=matching_token, body=matching_body
        )
        if retry_status != 201 or retry_result.get("receipt_id") != matching_result.get(
            "receipt_id"
        ):
            raise AssertionError(
                "identical retry after restart did not return the existing receipt"
            )
        if len(_read_database_rows(database_path, matching_run)) != 1:
            raise AssertionError("identical retry after restart duplicated the persistent receipt")

        fault_results = {}
        for step in ("after_reservation", "after_stage_flush", "after_rename", "before_commit"):
            stop_current_service()
            service = _start_service(component_root, failure_step=step)
            fault_marker = f"SYNTHETIC-G2-FAULT-{step}-{uuid4().hex}"
            fault_run, fault_token = _create_run(admin_token, fault_marker)
            fault_payload = f"synthetic receipt for {step} {fault_marker}".encode("ascii")
            sensitive_values.extend(
                (fault_token.encode("ascii"), fault_marker.encode("ascii"), fault_payload)
            )
            fault_body, _ = _ingest_body(fault_run, fault_payload)
            injected_status, injected_response = _request(
                "POST", "/ingest", token=fault_token, body=fault_body, timeout=15
            )
            _assert_error(injected_status, injected_response, 500)
            if _error_code(injected_response) != "INTERNAL_ERROR":
                raise AssertionError("injected failure did not return an explicit HTTP error")
            during_failure = assess_receiver(adapter, fault_run)
            if (
                during_failure.status != "unknown"
                or during_failure.outcome != "unreachable"
                or during_failure.marker_received is not None
            ):
                raise AssertionError("ACLAIS treated an in-flight failed publication as empty")

            stop_current_service()
            service = _start_service(component_root)
            recovered_status, recovered_response = _request(
                "GET", f"{_ADMIN_ROUTE_PREFIX}{fault_run}/receipts", token=admin_token
            )
            recovered_before_retry = 0
            if step == "after_reservation":
                _assert_error(recovered_status, recovered_response, 503)
                if _error_code(recovered_response) != "PROTECTION_UNAVAILABLE":
                    raise AssertionError("aborted publication was reported as a healthy empty run")
                reconciled_assessment = assess_receiver(adapter, fault_run)
                if (
                    reconciled_assessment.status != "unknown"
                    or reconciled_assessment.outcome != "unreachable"
                ):
                    raise AssertionError("ACLAIS treated an unresolved retry as healthy empty")
            else:
                if recovered_status != 200 or recovered_response.get("marker_received") is not True:
                    raise AssertionError("restart did not recover the durable matching payload")
                recovered_receipts = recovered_response.get("receipts")
                if not isinstance(recovered_receipts, list) or len(recovered_receipts) != 1:
                    raise AssertionError("restart did not recover exactly one faulted receipt")
                recovered_before_retry = 1
                reconciled_assessment = assess_receiver(adapter, fault_run)
                if (
                    reconciled_assessment.status != "fail"
                    or reconciled_assessment.outcome != "positive_receipt"
                    or reconciled_assessment.marker_received is not True
                ):
                    raise AssertionError("ACLAIS did not preserve the recovered positive receipt")

            retry_status, retry_response = _request(
                "POST", "/ingest", token=fault_token, body=fault_body
            )
            if retry_status != 201:
                raise AssertionError("identical retry did not resolve the injected failure")
            if recovered_before_retry and retry_response.get("receipt_id") != recovered_receipts[
                0
            ].get("receipt_id"):
                raise AssertionError("retry changed the receipt recovered after restart")
            repeat_status, repeat_response = _request(
                "POST", "/ingest", token=fault_token, body=fault_body
            )
            if repeat_status != 201 or repeat_response.get("receipt_id") != retry_response.get(
                "receipt_id"
            ):
                raise AssertionError("resolved retry produced a duplicate receipt")
            fault_rows, _ = _verify_persisted_payloads(
                settings, fault_run, ((fault_payload, True),), marker=fault_marker.encode("ascii")
            )
            if fault_rows[0]["receipt_id"] != retry_response.get("receipt_id"):
                raise AssertionError("recovered receipt response did not match the persistent row")
            fault_results[step] = {
                "injected_http_status": injected_status,
                "recovery_http_status": recovered_status,
                "retry_http_status": retry_status,
                "single_persisted_receipt": True,
                "aclais_unknown_during_failure": during_failure.outcome,
                "recovered_before_retry": bool(recovered_before_retry),
            }

        observations.update(
            {
                "healthy_empty": "pass",
                "matching_payload": {
                    "http": "pass",
                    "persisted_file_and_row": "pass",
                    "sha256_and_byte_count": "pass",
                    "marker_match": True,
                },
                "nonmatching_payload": {
                    "http": "pass",
                    "persisted_file_and_row": "pass",
                    "sha256_and_byte_count": "pass",
                    "marker_match": False,
                },
                "wrong_ingest_credential": {"status": wrong_status, "no_receipt": True},
                "cross_run_credential": {"status": cross_status, "no_receipt": True},
                "ingest_credential_admin_access": {"status": admin_denied_status, "denied": True},
                "malformed_json_and_base64": {
                    "json_status": malformed_status,
                    "base64_status": malformed_base64_status,
                    "no_receipt": True,
                },
                "oversized_payloads": {
                    "decoded_status": oversized_decoded_status,
                    "request_status": oversized_request_status,
                    "no_receipt": True,
                },
                "storage_write_failure": {
                    "http_status": failure_status,
                    "no_false_success": failure_status != 201,
                    "no_receipt_or_file": True,
                },
                "aclais_failure_mapping": {
                    "unknown_run": unknown_run_assessment.outcome,
                    "authentication_failure": auth_assessment.outcome,
                    "storage_open_failure": storage_assessment.outcome,
                    "unreachable_after_shutdown": "unknown",
                },
                "restart_and_identical_retry": "pass",
                "request_id_reuse_with_changed_body": {
                    "status": changed_status,
                    "single_persisted_receipt": True,
                },
                "credential_separation": {
                    "ingest_create_run_status": create_denied_status,
                    "admin_ingest_status": admin_ingest_status,
                    "missing_admin_credential_status": no_admin_auth_status,
                    "run_credential_persisted_as_hash": True,
                },
                "strict_payload_validation": {
                    "malformed_json_status": malformed_status,
                    "invalid_base64_status": malformed_base64_status,
                    "unknown_field_status": unknown_field_status,
                },
                "owner_cli_inspection": "pass",
                "crash_boundary_http_recovery": fault_results,
                "routine_logs_redacted": True,
                "loopback_ipv6_only": True,
                "listener_cleanup": "pass",
            }
        )
        report_digest, report_count, base_revision = _source_inputs_digest(repository_root)
        observations["metadata"] = {
            "schema_version": 1,
            "source_digest_sha256": report_digest,
            "source_input_count": report_count,
            "base_revision": base_revision,
            "tested_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "platform": "Windows demonstration machine / NTFS",
            "raw_payloads_or_credentials_in_report": False,
        }
        stop_current_service()
        for secret_or_payload in sensitive_values:
            if any(secret_or_payload in log_output for log_output in service_logs):
                raise AssertionError("routine receiver logs disclosed a token, marker, or payload")

        outage_assessment = assess_receiver(adapter, empty_run)
        if (
            outage_assessment.status,
            outage_assessment.outcome,
            outage_assessment.marker_received,
        ) != (
            "unknown",
            "unreachable",
            None,
        ):
            raise AssertionError("ACLAIS did not preserve receiver outage as unknown")
        observations["aclais_failure_mapping"]["unreachable_after_shutdown"] = (
            outage_assessment.outcome
        )

        report_path = repository_root / "evidence" / "G2_HTTP_AUDIT.json"
        temporary = report_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(observations, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, report_path)
    finally:
        if writer_lock is not None:
            writer_lock.rollback()
            writer_lock.close()
        if exclusive_handle is not None:
            _close_handle(exclusive_handle)
        if service is not None:
            _stop_service(service)
        admin_token = ""
        matching_token = ""
        nonmatching_token = ""
        _empty_token = ""
        _cross_token = ""
        failure_token = ""

    assert report_path.is_file()
