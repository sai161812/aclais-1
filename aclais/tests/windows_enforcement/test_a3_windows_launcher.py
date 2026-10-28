"""Actual Windows A3 checks; these require the provisioned demonstration-machine A2 identity."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from aclais.launcher.windows import (
    CredentialUnavailable,
    IdentityMismatch,
    LauncherError,
    RuntimeLayout,
    WindowsWorkerController,
    _Win32Api,
)

pytestmark = pytest.mark.windows_enforcement

_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_PROCESS_SYNCHRONIZE = 0x00100000
_CREATE_NO_WINDOW = 0x08000000


def _wait_json(path: Path, timeout: float = 12.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        time.sleep(0.025)
    raise AssertionError(f"expected private probe marker was not created: {path.name}")


def _wait_file(path: Path, timeout: float = 12.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.025)
    raise AssertionError(f"expected private probe marker was not created: {path.name}")


def _process_alive(pid: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(_PROCESS_SYNCHRONIZE, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error in (87, 1168):  # INVALID_PARAMETER / NOT_FOUND
            return False
        raise AssertionError(f"owner could not observe process completion (winerror={error})")
    try:
        status = kernel32.WaitForSingleObject(handle, 0)
        if status == _WAIT_OBJECT_0:
            return False
        if status == _WAIT_TIMEOUT:
            return True
        raise AssertionError("process completion wait failed")
    finally:
        kernel32.CloseHandle(handle)


def _assert_stopped(pid: int, timeout: float = 8.0) -> None:
    if not isinstance(pid, int) or pid <= 0:
        raise AssertionError(
            "launcher did not retain the process identity for cleanup verification"
        )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_alive(pid):
            return
        time.sleep(0.05)
    raise AssertionError(f"launched process {pid} remained active after job cleanup")


def _cleanup_marker_files(layout: RuntimeLayout, task_ids: list[str], extra: list[Path]) -> None:
    for task_id in task_ids:
        for suffix in ("worker.json", "child.json", "txt"):
            (layout.output_root / f"a3-{task_id}.{suffix}").unlink(missing_ok=True)
    for path in extra:
        path.unlink(missing_ok=True)


def _minimal_owner_env(layout: RuntimeLayout) -> dict[str, str]:
    system_root = os.environ.get("SystemRoot") or os.environ["WINDIR"]
    return {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "TEMP": str(layout.output_root),
        "TMP": str(layout.output_root),
        "COMPUTERNAME": os.environ["COMPUTERNAME"],
    }


def test_a3_real_worker_identity_job_pipes_and_cleanup() -> None:
    if os.name != "nt":
        pytest.fail("mandatory A3 Windows enforcement was not executed on Windows")
    layout = RuntimeLayout.open()
    task_ids: list[str] = []
    extra_files: list[Path] = []
    controllers: list[WindowsWorkerController] = []
    unrelated: subprocess.Popen[bytes] | None = None
    assert layout.owner_sid != layout.worker_sid

    try:
        # A successful real local-account logon proves the true token, pre-resume
        # job assignment, fixed entrypoint, protected config and safe argv handling.
        echo_arguments = (
            "two words",
            'embedded "quote"',
            "trailing slash\\",
            "shell & | < > ; ` $()",
            "authorization=Bearer synthetic-marker",
        )
        controller = WindowsWorkerController(layout)
        controllers.append(controller)
        handle = controller.start_a3_private_probe(
            deadline_seconds=30, probe_case="normal", echo_arguments=echo_arguments
        )
        task_ids.append(handle.config.task_id.hex)
        worker_pid = handle.pid
        config_path = handle.config_path
        result = handle.wait()
        startup_path = layout.output_root / f"a3-{handle.config.task_id.hex}.worker.json"
        assert result.exit_code == 0, {
            "stdout": [line.text for line in result.stdout],
            "stderr": [line.text for line in result.stderr],
        }
        startup = _wait_json(startup_path)
        task_config_hash_marker = f"a3-{handle.config.task_id.hex}.txt"

        assert result.exit_code == 0
        assert result.termination_cause == "process_exit"
        assert result.worker_sid == layout.worker_sid
        assert result.worker_is_administrator is False
        assert result.assigned_to_job_before_resume is True
        assert result.job_kill_on_close is True
        assert result.launch_sequence == (
            "created_suspended",
            "identity_verified",
            "job_configured",
            "assigned",
            "resumed",
        )
        assert result.process_tree_stopped is True and handle.handles_closed is True
        assert result.task_configuration_unchanged is True
        assert startup["pid"] == worker_pid and startup["in_job"] is True
        assert startup["working_directory"] == str(layout.output_root)
        assert startup["selected_input_read"] and startup["task_config_read"]
        assert startup["task_config_unchanged_after_attempts"]
        assert {item["name"] for item in startup["protected_checks"]} == {
            "task_config_write_denied",
            "task_config_delete_denied",
            "task_config_rename_denied",
        }
        assert all(item["denied"] for item in startup["protected_checks"]), startup[
            "protected_checks"
        ]
        assert startup["protected_checks"][0]["errno"] == 13  # EACCES from the Windows CRT
        assert all(item["winerror"] == 5 for item in startup["protected_checks"][1:])
        assert set(key.casefold() for key in startup["environment_keys"]) == {
            "systemroot",
            "windir",
            "temp",
            "tmp",
        }
        assert {key.casefold(): value for key, value in startup["environment"].items()} == {
            "systemroot": os.environ.get("SystemRoot") or os.environ["WINDIR"],
            "windir": os.environ.get("SystemRoot") or os.environ["WINDIR"],
            "temp": str(layout.output_root),
            "tmp": str(layout.output_root),
        }
        assert startup["argv"][:2] == ["--task-config", str(config_path)]
        assert startup["argv"].count("--echo-arg") == len(echo_arguments)
        observed_echo = next(
            json.loads(line.text)["echo_arguments"]
            for line in result.stdout
            if "echo_arguments" in line.text
        )
        assert tuple(observed_echo[:4]) == echo_arguments[:4]
        assert observed_echo[4] == "authorization=Bearer [REDACTED]"
        assert any("private_probe_started" in line.text for line in result.stdout)
        assert any("private_probe_diagnostic" in line.text for line in result.stderr)
        assert all(
            line.channel == "stdout" and line.provenance == "worker_reported"
            for line in result.stdout
        )
        assert all(
            line.channel == "stderr" and line.provenance == "worker_reported"
            for line in result.stderr
        )
        redacted_echo = next(line.text for line in result.stdout if "echo_arguments" in line.text)
        assert "synthetic-marker" not in redacted_echo and "[REDACTED]" in redacted_echo
        assert (layout.output_root / task_config_hash_marker).is_file()
        assert (
            (layout.output_root / task_config_hash_marker)
            .read_text(encoding="utf-8")
            .startswith("private probe read ")
        )
        assert not config_path.exists()
        _assert_stopped(worker_pid)

        # Output larger than the pipe capacity drains on both streams while the
        # retained byte count and individual lines remain bounded.
        capture_controller = WindowsWorkerController(layout)
        controllers.append(capture_controller)
        capture_handle = capture_controller.start_a3_private_probe(
            deadline_seconds=30, probe_case="capture"
        )
        task_ids.append(capture_handle.config.task_id.hex)
        capture_result = capture_handle.wait()
        assert capture_result.exit_code == 0
        assert capture_result.stdout_bytes_observed > 1_000_000
        assert capture_result.stderr_bytes_observed > 1_000_000
        assert capture_result.stdout_truncated and capture_result.stderr_truncated
        assert sum(len(line.text.encode("utf-8")) for line in capture_result.stdout) <= 256 * 1024
        assert sum(len(line.text.encode("utf-8")) for line in capture_result.stderr) <= 256 * 1024
        assert all(len(line.text.encode("utf-8")) <= 16_384 for line in capture_result.stdout)
        assert all(len(line.text.encode("utf-8")) <= 16_384 for line in capture_result.stderr)
        assert len(capture_result.stdout) <= 1024 and len(capture_result.stderr) <= 1024
        assert capture_handle.handles_closed

        # A worker that exits while its child lives triggers scoped job cleanup.
        child_controller = WindowsWorkerController(layout)
        controllers.append(child_controller)
        child_handle = child_controller.start_a3_private_probe(
            deadline_seconds=30, probe_case="child_exit"
        )
        task_ids.append(child_handle.config.task_id.hex)
        child_marker_path = layout.output_root / f"a3-{child_handle.config.task_id.hex}.child.json"
        child_info = _wait_json(child_marker_path)
        child_result = child_handle.wait()
        assert child_result.termination_cause == "process_exit"
        assert child_info["in_job"] is True
        _assert_stopped(child_info["pid"])
        _assert_stopped(child_handle.pid)
        assert child_handle.handles_closed

        # Explicit cancellation and deadline expiry both terminate the worker
        # and the child in its job, without touching a separately launched owner process.
        owner_marker = layout.output_root / f"a3-owner-sleeper-{uuid.uuid4().hex}.txt"
        extra_files.append(owner_marker)
        unrelated = subprocess.Popen(
            [
                str(layout.python_exe),
                "-I",
                "-B",
                str(layout.private_probe),
                "--owner-sleep",
                str(owner_marker),
            ],
            cwd=layout.output_root,
            env=_minimal_owner_env(layout),
            shell=False,
            creationflags=_CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_file(owner_marker)
        assert int(owner_marker.read_text(encoding="ascii")) == unrelated.pid

        cancel_controller = WindowsWorkerController(layout)
        controllers.append(cancel_controller)
        cancel_handle = cancel_controller.start_a3_private_probe(
            deadline_seconds=30, probe_case="child_wait"
        )
        task_ids.append(cancel_handle.config.task_id.hex)
        cancel_child = _wait_json(
            layout.output_root / f"a3-{cancel_handle.config.task_id.hex}.child.json"
        )
        cancel_result = cancel_handle.cancel()
        assert cancel_result.termination_cause == "cancelled"
        _assert_stopped(cancel_handle.pid)
        _assert_stopped(cancel_child["pid"])
        assert unrelated.poll() is None, "job cancellation terminated an unrelated owner process"
        assert cancel_handle.handles_closed

        timeout_controller = WindowsWorkerController(layout)
        controllers.append(timeout_controller)
        timeout_handle = timeout_controller.start_a3_private_probe(
            deadline_seconds=1, probe_case="child_wait"
        )
        task_ids.append(timeout_handle.config.task_id.hex)
        timeout_child = _wait_json(
            layout.output_root / f"a3-{timeout_handle.config.task_id.hex}.child.json"
        )
        timeout_result = timeout_handle.wait()
        assert timeout_result.termination_cause == "timeout"
        _assert_stopped(timeout_handle.pid)
        _assert_stopped(timeout_child["pid"])
        assert unrelated.poll() is None, "job timeout terminated an unrelated owner process"
        assert timeout_handle.handles_closed

        shutdown_controller = WindowsWorkerController(layout)
        controllers.append(shutdown_controller)
        shutdown_handle = shutdown_controller.start_a3_private_probe(
            deadline_seconds=30, probe_case="child_wait"
        )
        task_ids.append(shutdown_handle.config.task_id.hex)
        shutdown_child = _wait_json(
            layout.output_root / f"a3-{shutdown_handle.config.task_id.hex}.child.json"
        )
        shutdown_controller.shutdown()
        shutdown_result = shutdown_handle.wait()
        assert shutdown_result.termination_cause == "controller_shutdown"
        _assert_stopped(shutdown_handle.pid)
        _assert_stopped(shutdown_child["pid"])
        assert unrelated.poll() is None, "controller shutdown terminated an unrelated owner process"
        assert shutdown_handle.handles_closed

        class ResumeBarrierApi(_Win32Api):
            def __init__(self) -> None:
                super().__init__()
                self.resume_entered = threading.Event()
                self.allow_resume = threading.Event()

            def resume_thread(self, thread: ctypes.c_void_p) -> int:
                self.resume_entered.set()
                if not self.allow_resume.wait(10):
                    raise LauncherError("test_resume_barrier_timeout")
                return super().resume_thread(thread)

        racing_api = ResumeBarrierApi()
        racing_controller = WindowsWorkerController(layout, api=racing_api)
        controllers.append(racing_controller)
        launch_handles = []
        launch_errors: list[BaseException] = []
        launch_finished = threading.Event()
        shutdown_finished = threading.Event()

        def launch_during_shutdown() -> None:
            try:
                launch_handles.append(
                    racing_controller.start_a3_private_probe(
                        deadline_seconds=30, probe_case="child_wait"
                    )
                )
            except BaseException as exc:
                launch_errors.append(exc)
            finally:
                launch_finished.set()

        def shutdown_during_launch() -> None:
            try:
                racing_controller.shutdown()
            except BaseException as exc:
                launch_errors.append(exc)
            finally:
                shutdown_finished.set()

        launch_thread = threading.Thread(target=launch_during_shutdown, daemon=True)
        shutdown_thread = threading.Thread(target=shutdown_during_launch, daemon=True)
        launch_thread.start()
        try:
            assert racing_api.resume_entered.wait(10)
            shutdown_thread.start()
            time.sleep(0.1)
            assert not shutdown_finished.is_set()
        finally:
            racing_api.allow_resume.set()
        launch_thread.join(timeout=15)
        shutdown_thread.join(timeout=15)
        assert launch_finished.is_set() and shutdown_finished.is_set()
        assert not launch_errors, [type(error).__name__ for error in launch_errors]
        assert len(launch_handles) == 1
        racing_handle = launch_handles[0]
        task_ids.append(racing_handle.config.task_id.hex)
        racing_result = racing_handle.wait()
        assert racing_result.termination_cause == "controller_shutdown"
        _assert_stopped(racing_handle.pid)
        racing_child_path = layout.output_root / f"a3-{racing_handle.config.task_id.hex}.child.json"
        if racing_child_path.exists():
            _assert_stopped(json.loads(racing_child_path.read_text(encoding="utf-8"))["pid"])
        assert racing_handle.handles_closed
        assert unrelated.poll() is None, "launch/shutdown race terminated an unrelated owner process"

        # A forced controller-process death closes its final Job Object handle;
        # Windows must terminate the worker and child as a kernel cleanup action.
        signal_path = layout.output_root / f"a3-controller-signal-{uuid.uuid4().hex}.json"
        extra_files.append(signal_path)
        helper = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                str(
                    Path(__file__).resolve().parents[1] / "probes" / "a3_controller_crash_probe.py"
                ),
                "--signal-file",
                str(signal_path),
            ],
            cwd=Path(__file__).resolve().parents[3],
            env=_minimal_owner_env(layout),
            shell=False,
            creationflags=_CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            crash_info = _wait_json(signal_path, timeout=20)
            assert crash_info["ready"] and crash_info["child_in_job"] is True
            assert helper.poll() is None
            helper.terminate()  # exact owner-side controller process created above
            helper.wait(timeout=8)
            _assert_stopped(crash_info["worker_pid"])
            _assert_stopped(crash_info["child_pid"])
        finally:
            if helper.poll() is None:
                helper.terminate()
                helper.wait(timeout=8)
            if helper.stderr:
                helper.stderr.close()
        assert unrelated.poll() is None, (
            "controller process close terminated an unrelated owner process"
        )

        unrelated.terminate()  # exact test-owned sentinel process, not a system process
        unrelated.wait(timeout=8)

        # Incorrect expected identity and a native assignment failure both leave
        # the suspended probe unexecuted; neither path retries as the owner.
        wrong_identity_controller = WindowsWorkerController(
            replace(layout, worker_sid=layout.owner_sid)
        )
        controllers.append(wrong_identity_controller)
        before_wrong_identity = {path.name for path in layout.output_root.glob("a3-*.worker.json")}
        with pytest.raises(IdentityMismatch) as identity_error:
            wrong_identity_controller.start_a3_private_probe(
                deadline_seconds=10, probe_case="normal"
            )
        _assert_stopped(identity_error.value.process_pid)
        assert {
            path.name for path in layout.output_root.glob("a3-*.worker.json")
        } == before_wrong_identity

        class AssignmentFailureApi(_Win32Api):
            def assign_process_to_job(self, job: ctypes.c_void_p, process: ctypes.c_void_p) -> None:
                raise LauncherError("job_assign", 5)

        failed_assignment_controller = WindowsWorkerController(layout, api=AssignmentFailureApi())
        controllers.append(failed_assignment_controller)
        before_assignment_failure = {
            path.name for path in layout.output_root.glob("a3-*.worker.json")
        }
        with pytest.raises(LauncherError, match="worker_job_assign_failed") as assignment_error:
            failed_assignment_controller.start_a3_private_probe(
                deadline_seconds=10, probe_case="normal"
            )
        _assert_stopped(assignment_error.value.process_pid)
        assert {
            path.name for path in layout.output_root.glob("a3-*.worker.json")
        } == before_assignment_failure

        class MembershipFailureApi(_Win32Api):
            def is_process_in_job(
                self, process: ctypes.c_void_p, job: ctypes.c_void_p
            ) -> bool:
                return False

        membership_failure_controller = WindowsWorkerController(
            layout, api=MembershipFailureApi()
        )
        controllers.append(membership_failure_controller)
        before_membership_failure = {
            path.name for path in layout.output_root.glob("a3-*.worker.json")
        }
        with pytest.raises(LauncherError, match="worker_job_assignment_not_observed_failed") as (
            membership_error
        ):
            membership_failure_controller.start_a3_private_probe(
                deadline_seconds=10, probe_case="normal"
            )
        _assert_stopped(membership_error.value.process_pid)
        assert {
            path.name for path in layout.output_root.glob("a3-*.worker.json")
        } == before_membership_failure

        class MissingCredential:
            calls = 0

            def __call__(self) -> Any:
                self.calls += 1
                raise CredentialUnavailable("credential_read", 1168)

        missing_credential = MissingCredential()
        missing_credential_controller = WindowsWorkerController(
            layout, credential_reader=missing_credential
        )
        controllers.append(missing_credential_controller)
        before_credential_failure = {
            path.name for path in layout.output_root.glob("a3-*.worker.json")
        }
        with pytest.raises(CredentialUnavailable):
            missing_credential_controller.start_a3_private_probe(
                deadline_seconds=10, probe_case="normal"
            )
        assert missing_credential.calls == 1
        assert {
            path.name for path in layout.output_root.glob("a3-*.worker.json")
        } == before_credential_failure
    finally:
        cleanup_failures: list[str] = []
        for controller in controllers:
            try:
                controller.shutdown()
            except LauncherError as exc:
                cleanup_failures.append(exc.operation)
        if unrelated is not None and unrelated.poll() is None:
            unrelated.terminate()
            unrelated.wait(timeout=8)
        _cleanup_marker_files(layout, task_ids, extra_files)
        if cleanup_failures:
            pytest.fail(f"test-owned worker cleanup failed: {cleanup_failures}")
