"""Actual Windows A6 lifecycle, broker and restart-containment checks."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from aclais.app import create_app
from aclais.config import Settings
from aclais.evidence import FixtureVerifier
from aclais.launcher.windows import RuntimeLayout, WindowsWorkerController
from aclais.lifecycle import LifecycleCoordinator, LifecycleError, TaskWorkspace
from aclais.persistence.database import Database
from aclais.persistence.models import (
    BrokerReadDocumentRequest,
    RevocationCause,
    TaskStatus,
    TerminalCause,
)
from aclais.publication import OutputPublisher

pytestmark = pytest.mark.windows_enforcement

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_ERROR_INVALID_PARAMETER = 87
_ERROR_NOT_FOUND = 1168
_CREATE_NO_WINDOW = 0x08000000
_CRASH_TOKEN = "synthetic-a6-controller-crash-token-not-a-secret"


class _Server:
    def __init__(self, coordinator: LifecycleCoordinator) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = int(listener.getsockname()[1])
        self.url = f"http://127.0.0.1:{self.port}/api/broker/operations"
        settings = Settings(port=self.port)
        self.server = uvicorn.Server(
            uvicorn.Config(
                create_app(settings, broker=coordinator.broker),
                host=settings.host,
                port=settings.port,
                log_config=None,
                access_log=False,
                lifespan="off",
                log_level="critical",
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started and time.monotonic() < deadline:
            if not self.thread.is_alive():
                raise AssertionError("private loopback broker failed to start")
            time.sleep(0.025)
        if not self.server.started:
            raise AssertionError("private loopback broker startup timed out")

    def close(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=8)
        assert not self.thread.is_alive(), "private loopback broker did not stop"


class _Runtime:
    def __init__(self, layout: RuntimeLayout, database_path: Path) -> None:
        self.layout = layout
        self.database = Database(database_path)
        self.publisher = OutputPublisher(self.database, layout.verified_output_root)
        self.launcher = WindowsWorkerController(layout)
        self.handles = {}
        original_start = self.launcher.start_a3_private_probe

        def capture_handle(**kwargs):
            handle = original_start(**kwargs)
            self.handles[kwargs["task_id"]] = handle
            return handle

        self.launcher.start_a3_private_probe = capture_handle
        self.workspace = TaskWorkspace(layout)
        self.verifier = FixtureVerifier(
            self.database,
            layout.root / "store",
            layout.raw_evidence_root,
            expected_fixtures=layout.fixture_hashes,
            source_root=Path(__file__).resolve().parents[2] / "backend" / "src" / "aclais",
            source_revision=None,
        )
        self.coordinator = LifecycleCoordinator(
            layout,
            self.database,
            self.publisher,
            launcher=self.launcher,
            workspace=self.workspace,
            verifier=self.verifier,
        )
        self.coordinator.recover_before_serving()

    def close(self) -> None:
        self.coordinator.shutdown()


def _wait_json(path: Path, timeout: float = 12.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        time.sleep(0.025)
    raise AssertionError(f"private lifecycle marker was not created: {path.name}")


def _task_marker(layout: RuntimeLayout, task_id: uuid.UUID, suffix: str) -> Path:
    return layout.task_output_root / str(task_id) / f"a3-{task_id.hex}.{suffix}.json"


def _process_running(pid: int, creation_time_100ns: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class FILETIME(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetProcessTimes.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ]
    kernel32.GetProcessTimes.restype = ctypes.c_int
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    process = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE, False, pid
    )
    if not process:
        error = ctypes.get_last_error()
        if error in {_ERROR_INVALID_PARAMETER, _ERROR_NOT_FOUND}:
            return False
        raise AssertionError(f"cannot observe worker process (winerror={error})")
    try:
        created, exited, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not kernel32.GetProcessTimes(
            process,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise AssertionError(f"cannot verify process creation identity: {pid}")
        created_at = (int(created.high) << 32) | int(created.low)
        if created_at != creation_time_100ns:
            return False  # PID was reused; the recorded process identity is gone.
        result = kernel32.WaitForSingleObject(process, 0)
        if result == _WAIT_OBJECT_0:
            return False
        if result == _WAIT_TIMEOUT:
            return True
        raise AssertionError("process wait returned an unrecognized result")
    finally:
        kernel32.CloseHandle(process)


def _assert_stopped(pid: int, created: int, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_running(pid, created):
            return
        time.sleep(0.025)
    raise AssertionError(f"recorded worker process identity {pid} remained active")


def _handle(runtime: _Runtime, task_id: uuid.UUID):
    return runtime.handles[task_id]


def _read_request() -> bytes:
    return BrokerReadDocumentRequest(
        schema_version=1,
        request_id=uuid.uuid4(),
        operation="read_document",
        document_id="doc-report",
    ).model_dump_json().encode("utf-8")


def _fixture_hashes(layout: RuntimeLayout) -> dict[str, str]:
    result = {}
    for relative, _digest in layout.fixture_hashes:
        if relative.startswith("store/originals/"):
            path = layout.root / Path(relative)
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _assert_broker_probe_startup(layout: RuntimeLayout, task_id: uuid.UUID) -> None:
    startup = _wait_json(_task_marker(layout, task_id, "worker"))
    assert startup["selected_input_read"] is True
    assert set(key.casefold() for key in startup["environment_keys"]) == {
        "systemroot",
        "windir",
        "temp",
        "tmp",
    }
    checks = {item["name"]: item["denied"] for item in startup["protected_checks"]}
    assert checks == {
        "task_config_write_denied": True,
        "task_config_delete_denied": True,
        "task_config_rename_denied": True,
        "selected_input_write_denied": True,
        "selected_input_delete_denied": True,
        "selected_input_rename_denied": True,
        "selected_parent_list_denied": True,
        "temporary_parent_list_denied": True,
    }


def test_a6_windows_completion_denial_revocation_cancel_timeout_shutdown_and_admission(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.fail("mandatory A6 enforcement was not executed on Windows")
    layout = replace(RuntimeLayout.open(), verified_output_root=tmp_path / "verified-output")
    workspace = TaskWorkspace(layout)
    workspace.prepare_roots()
    database_path = tmp_path / "a6.sqlite3"
    originals_before = _fixture_hashes(layout)
    assert originals_before, "protected original fixtures were not present for comparison"
    runtime = _Runtime(layout, database_path)
    server = _Server(runtime.coordinator)
    token_index = 0

    def next_token() -> str:
        nonlocal token_index
        token_index += 1
        return f"synthetic-a6-task-credential-{token_index:04d}-not-a-secret"

    runtime.coordinator._token_factory = next_token
    task_ids: list[uuid.UUID] = []
    try:
        # Successful completion requires broker read, committed publication,
        # normal process exit, job drain and a hash-verified output record.
        complete_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=20,
            probe_case="normal",
            broker_probe="allow_and_publish",
        )
        task_ids.append(complete_id)
        complete_handle = _handle(runtime, complete_id)
        completed = runtime.coordinator.wait(complete_id, timeout=15)
        assert completed.status == TaskStatus.COMPLETED
        assert completed.terminal_cause == TerminalCause.WORKER_EXIT_SUCCESS
        assert complete_handle.handles_closed
        assert complete_handle.worker_sid == layout.worker_sid
        assert complete_handle._result is not None
        assert complete_handle._result.worker_is_administrator is False
        _assert_stopped(complete_handle.pid, complete_handle.creation_time)
        records = runtime.database.outputs_for_task(complete_id)
        assert len(records) == 1 and records[0].state.value == "published"
        _metadata, content = runtime.publisher.read_published(records[0].output_id)
        assert content.startswith(b"# A6 private lifecycle probe")
        evidence = runtime.database.evidence_response(complete_id)
        assert evidence.status == "complete" and evidence.report is not None
        assert evidence.report.overall_status == "pass"
        assert evidence.report.integrity_status == "pass"
        assert evidence.report.worker_exit_observed is True
        assert evidence.report.worker_termination_confirmed is True
        assert evidence.report.selected_input_size_before_bytes == (
            evidence.report.selected_input_size_after_bytes
        )
        assert evidence.report.selected_input_sha256_before == (
            evidence.report.selected_input_sha256_after
        )
        process_observation = evidence.report.controller_process_observation
        assert process_observation is not None
        assert process_observation.source == "controller"
        assert process_observation.pid == complete_handle.pid
        assert process_observation.creation_time_100ns == complete_handle.creation_time
        assert process_observation.worker_sid == layout.worker_sid
        assert process_observation.assigned_to_job_before_resume is True
        assert process_observation.job_kill_on_close is True
        assert process_observation.worker_is_administrator is False
        assert evidence.report.file_inventory_before == evidence.report.file_inventory_after
        assert evidence.report.published_output_sha256 == _metadata.sha256
        assert evidence.report.published_output_size_bytes == len(content)
        event_sequences = {
            event.kind: event.seq for event in runtime.database.events(complete_id)
        }
        assert event_sequences["worker_exit_observed"] < event_sequences[
            "independent_verification_started"
        ]
        assert event_sequences["independent_verification_started"] < event_sequences[
            "independent_verification_completed"
        ]
        assert evidence.report.tested_source_sha256 == runtime.verifier.source_sha256
        assert {item.source for item in evidence.report.event_sources} >= {
            "controller",
            "broker",
            "verifier",
        }
        assert runtime.database.worker_process_creation_time(complete_id) == (
            complete_handle.creation_time
        )

        # A worker process crash with a live descendant is a failed task, and
        # the controller observes the whole job stop before terminalizing it.
        crash_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=20,
            probe_case="child_crash",
            broker_probe="none",
        )
        task_ids.append(crash_id)
        crash_handle = _handle(runtime, crash_id)
        crash_child = _wait_json(_task_marker(layout, crash_id, "child"))
        crashed = runtime.coordinator.wait(crash_id, timeout=12)
        assert crashed.status == TaskStatus.FAILED
        assert crashed.terminal_cause == TerminalCause.WORKER_EXIT_FAILURE
        assert crash_handle._result is not None and crash_handle._result.exit_code == 23
        assert crash_handle.handles_closed
        _assert_stopped(crash_handle.pid, crash_handle.creation_time)
        _assert_stopped(crash_child["pid"], crash_child["creation_time_100ns"])

        # Admission is single-worker. The child marker is read before scoped
        # workspace cleanup, and both recorded process identities are checked.
        cancel_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=20,
            probe_case="child_wait",
            broker_probe="allow_and_publish",
        )
        task_ids.append(cancel_id)
        cancel_handle = _handle(runtime, cancel_id)
        cancel_worker_marker = _wait_json(_task_marker(layout, cancel_id, "worker"))
        child = _wait_json(_task_marker(layout, cancel_id, "child"))
        _assert_broker_probe_startup(layout, cancel_id)
        with pytest.raises(LifecycleError, match="single worker slot is occupied"):
            runtime.coordinator.start_private_probe(server.url)
        cancelled = runtime.coordinator.cancel(cancel_id)
        assert cancelled.status == TaskStatus.CANCELLED
        assert cancelled.terminal_cause == TerminalCause.CANCELLED
        assert cancel_handle.handles_closed
        _assert_stopped(cancel_handle.pid, cancel_handle.creation_time)
        _assert_stopped(child["pid"], child["creation_time_100ns"])
        assert cancel_worker_marker["pid"] == cancel_handle.pid
        credential = runtime.database.credential_hash(cancel_id)
        assert credential is not None and credential.revoked_at is not None
        assert runtime.coordinator.broker.execute(
            next_token_for_task(runtime.database, cancel_id, token_index), _read_request()
        ).status_code == 401

        # An out-of-scope read durably denies and revokes before stopping the job.
        denial_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=20,
            probe_case="child_wait",
            broker_probe="policy_denial",
        )
        task_ids.append(denial_id)
        denial_token = next_token_for_task(runtime.database, denial_id, token_index)
        denial_handle = _handle(runtime, denial_id)
        denied = runtime.coordinator.wait(denial_id, timeout=15)
        assert denied.status == TaskStatus.FAILED
        assert denied.revocation_cause == RevocationCause.POLICY_DENIED
        assert denied.terminal_cause == TerminalCause.POLICY_DENIED
        assert denial_handle.handles_closed
        _assert_stopped(denial_handle.pid, denial_handle.creation_time)
        assert runtime.coordinator.broker.execute(denial_token, _read_request()).status_code == 401
        with runtime.database._connection() as connection:
            incident = connection.execute(
                "SELECT containment_status, integrity_status, confidentiality_status "
                "FROM incidents WHERE task_id=?",
                (str(denial_id),),
            ).fetchone()
        assert tuple(incident) == ("terminated", "pass", "unknown")

        # Deadline expiration terminates both the selected worker and its child.
        timeout_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=5,
            probe_case="child_wait",
            broker_probe="allow_and_publish",
        )
        task_ids.append(timeout_id)
        timeout_handle = _handle(runtime, timeout_id)
        timeout_child = _wait_json(_task_marker(layout, timeout_id, "child"), timeout=8)
        timed_out = runtime.coordinator.wait(timeout_id, timeout=12)
        assert timed_out.status == TaskStatus.FAILED
        assert timed_out.revocation_cause == RevocationCause.WORKER_TIMEOUT
        assert timed_out.terminal_cause == TerminalCause.WORKER_TIMEOUT
        assert timeout_handle.handles_closed
        _assert_stopped(timeout_handle.pid, timeout_handle.creation_time)
        _assert_stopped(timeout_child["pid"], timeout_child["creation_time_100ns"])

        # Orderly controller shutdown commits a durable cause before job cleanup.
        shutdown_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=20,
            probe_case="child_wait",
            broker_probe="allow_and_publish",
        )
        task_ids.append(shutdown_id)
        shutdown_handle = _handle(runtime, shutdown_id)
        shutdown_child = _wait_json(_task_marker(layout, shutdown_id, "child"))
        runtime.coordinator.shutdown()
        shutdown_task = runtime.database.get_task(shutdown_id)
        assert shutdown_task is not None
        assert shutdown_task.status == TaskStatus.FAILED
        assert shutdown_task.revocation_cause == RevocationCause.CONTROLLER_SHUTDOWN
        assert shutdown_task.terminal_cause == TerminalCause.CONTROLLER_SHUTDOWN
        assert shutdown_handle.handles_closed
        _assert_stopped(shutdown_handle.pid, shutdown_handle.creation_time)
        _assert_stopped(shutdown_child["pid"], shutdown_child["creation_time_100ns"])

        assert _fixture_hashes(layout) == originals_before
    finally:
        try:
            runtime.coordinator.shutdown()
        finally:
            server.close()
            for task_id in task_ids:
                workspace.cleanup(task_id)
            for suffix in ("", "-wal", "-shm"):
                Path(f"{database_path}{suffix}").unlink(missing_ok=True)
            if layout.verified_output_root.exists():
                shutil.rmtree(layout.verified_output_root)


def next_token_for_task(database: Database, task_id: uuid.UUID, token_index: int) -> str:
    # Tokens are predictable test-only values; only their hashes are persisted.
    token = f"synthetic-a6-task-credential-{token_index:04d}-not-a-secret"
    credential = database.credential_hash(task_id)
    assert credential is not None
    assert hashlib.sha256(token.encode("ascii")).hexdigest() == credential.token_sha256
    return token


def test_a6_windows_cancel_exit_and_timeout_completion_races(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.fail("mandatory A6 race checks were not executed on Windows")
    layout = replace(RuntimeLayout.open(), verified_output_root=tmp_path / "verified-output")
    TaskWorkspace(layout).prepare_roots()
    database_path = tmp_path / "a6-race.sqlite3"
    runtime = _Runtime(layout, database_path)
    server = _Server(runtime.coordinator)
    token_counter = 0

    def next_token() -> str:
        nonlocal token_counter
        token_counter += 1
        return f"synthetic-a6-race-credential-{token_counter:04d}-not-a-secret"

    runtime.coordinator._token_factory = next_token
    task_ids: list[uuid.UUID] = []
    publish_returned = threading.Event()
    release_publish_response = threading.Event()
    release_timeout_publication = threading.Event()
    try:
        original_execute = runtime.coordinator.broker.execute

        def gated_execute(token: str | None, body: bytes, **kwargs):
            result = original_execute(token, body, **kwargs)
            if b'"operation":"publish_output"' in body:
                publish_returned.set()
                if not release_publish_response.wait(8):
                    raise AssertionError("private worker response release timed out")
            return result

        runtime.coordinator.broker.execute = gated_execute  # type: ignore[method-assign]
        cancel_exit_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=20,
            probe_case="normal",
            broker_probe="allow_and_publish",
        )
        task_ids.append(cancel_exit_id)
        handle = _handle(runtime, cancel_exit_id)
        assert publish_returned.wait(8), "worker did not reach broker publication response"
        cancel_errors: list[BaseException] = []
        gate = threading.Barrier(2)

        def cancel_at_release() -> None:
            gate.wait()
            try:
                runtime.coordinator.cancel(cancel_exit_id)
            except BaseException as exc:
                cancel_errors.append(exc)

        cancel_thread = threading.Thread(target=cancel_at_release, daemon=True)
        cancel_thread.start()
        gate.wait()
        release_publish_response.set()
        cancel_thread.join(timeout=12)
        assert not cancel_thread.is_alive() and not cancel_errors
        task = runtime.coordinator.wait(cancel_exit_id, timeout=12)
        assert task.status in {TaskStatus.CANCELLED, TaskStatus.COMPLETED}
        assert task.terminal_cause in {
            TerminalCause.CANCELLED,
            TerminalCause.WORKER_EXIT_SUCCESS,
        }
        assert handle.handles_closed
        _assert_stopped(handle.pid, handle.creation_time)
        assert len(runtime.database.outputs_for_task(cancel_exit_id)) == 1

        # Hold publication inside its task lock; timeout waits behind an already
        # authorized effect, then wins at the exact deadline before completion.
        timeout_entered = threading.Event()

        def publication_barrier(label: str) -> None:
            if label == "before_final_commit":
                timeout_entered.set()
                if not release_timeout_publication.wait(8):
                    raise AssertionError("timeout publication barrier timed out")

        runtime.publisher._fault = publication_barrier

        class TestClock:
            value = 100.0
            lock = threading.Lock()

            def __call__(self) -> float:
                with self.lock:
                    return self.value

            def advance(self, value: float) -> None:
                with self.lock:
                    self.value = value

        clock = TestClock()
        # Replace the monotonic source before admission; the deadline is set
        # from the timestamp captured before the suspended worker resumes.
        runtime.coordinator._monotonic = clock
        timeout_id = runtime.coordinator.start_private_probe(
            server.url,
            deadline_seconds=2,
            probe_case="normal",
            broker_probe="allow_and_publish",
        )
        task_ids.append(timeout_id)
        timeout_handle = _handle(runtime, timeout_id)
        assert timeout_entered.wait(8), "worker publication did not reach the deadline barrier"
        clock.advance(102.0)
        release_timeout_publication.set()
        timed_out = runtime.coordinator.wait(timeout_id, timeout=12)
        assert timed_out.status == TaskStatus.FAILED
        assert timed_out.revocation_cause == RevocationCause.WORKER_TIMEOUT
        assert timed_out.terminal_cause == TerminalCause.WORKER_TIMEOUT
        assert timeout_handle.handles_closed
        _assert_stopped(timeout_handle.pid, timeout_handle.creation_time)
        assert len(runtime.database.outputs_for_task(timeout_id)) == 1
        assert runtime.database.outputs_for_task(timeout_id)[0].state.value == "published"
    finally:
        release_publish_response.set()
        release_timeout_publication.set()
        runtime.coordinator.shutdown()
        server.close()
        for task_id in task_ids:
            TaskWorkspace(layout).cleanup(task_id)
        for suffix in ("", "-wal", "-shm"):
            Path(f"{database_path}{suffix}").unlink(missing_ok=True)
        if layout.verified_output_root.exists():
            shutil.rmtree(layout.verified_output_root)


def test_a6_windows_abrupt_controller_death_and_restart_reconciliation(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.fail("mandatory A6 restart enforcement was not executed on Windows")
    layout = replace(RuntimeLayout.open(), verified_output_root=tmp_path / "verified-output")
    TaskWorkspace(layout).prepare_roots()
    database_path = tmp_path / "a6-crash.sqlite3"
    signal_file = tmp_path / "a6-controller-ready.json"
    helper_path = Path(__file__).resolve().parents[1] / "probes" / "a6_controller_crash_probe.py"
    backend_source = Path(__file__).resolve().parents[2] / "backend" / "src"
    env = {
        "SystemRoot": os.environ.get("SystemRoot") or os.environ["WINDIR"],
        "WINDIR": os.environ.get("SystemRoot") or os.environ["WINDIR"],
        "TEMP": os.environ.get("TEMP", str(layout.output_root)),
        "TMP": os.environ.get("TMP", str(layout.output_root)),
        "COMPUTERNAME": os.environ["COMPUTERNAME"],
    }
    helper = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            str(helper_path),
            "--database",
            str(database_path),
            "--signal-file",
            str(signal_file),
            "--backend-source",
            str(backend_source),
            "--verified-output-root",
            str(layout.verified_output_root),
        ],
        cwd=Path(__file__).resolve().parents[3],
        env=env,
        shell=False,
        creationflags=_CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    runtime: _Runtime | None = None
    try:
        signal = _wait_json(signal_file, timeout=25)
        assert signal["ready"] is True
        assert signal["worker_sid"] == layout.worker_sid
        assert helper.poll() is None
        helper.terminate()  # This is the exact private controller process started above.
        helper.wait(timeout=8)
        _assert_stopped(signal["worker_pid"], signal["worker_creation_time_100ns"])
        _assert_stopped(signal["child_pid"], signal["child_creation_time_100ns"])

        runtime = _Runtime(layout, database_path)
        task_id = uuid.UUID(signal["task_id"])
        reconciled = runtime.database.get_task(task_id)
        assert reconciled is not None
        assert reconciled.status == TaskStatus.FAILED
        assert reconciled.terminal_cause == TerminalCause.RECOVERY_INTERRUPTED
        assert [item.to_status for item in runtime.database.transitions(task_id)][-2:] == [
            TaskStatus.VERIFYING,
            TaskStatus.FAILED,
        ]
        credential = runtime.database.credential_hash(task_id)
        assert credential is not None and credential.revoked_at is not None
        retry = runtime.coordinator.broker.execute(_CRASH_TOKEN, _read_request())
        assert retry.status_code == 401
        assert not tuple(layout.selected_root.glob(".aclais-a3-task-*.json"))
        assert not (layout.selected_copy_root / str(task_id)).exists()
        assert not (layout.task_output_root / str(task_id)).exists()
        events = runtime.database.events(task_id)
        assert any(event.kind == "task_restart_reconciled" for event in events)
        assert any(
            event.kind == "task_restart_verification_started"
            and event.reason_code is None
            for event in events
        )
    finally:
        if helper.poll() is None:
            helper.terminate()
            helper.wait(timeout=8)
        if runtime is not None:
            runtime.close()
        signal_file.unlink(missing_ok=True)
        for suffix in ("", "-wal", "-shm"):
            Path(f"{database_path}{suffix}").unlink(missing_ok=True)
        if layout.verified_output_root.exists():
            shutil.rmtree(layout.verified_output_root)
