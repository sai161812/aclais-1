"""Harmless private A3 worker; deployed only into the owner-protected lab code tree."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


def _in_any_job() -> bool:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.IsProcessInJob.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    kernel32.IsProcessInJob.restype = ctypes.c_int
    member = ctypes.c_int()
    if not kernel32.IsProcessInJob(kernel32.GetCurrentProcess(), None, ctypes.byref(member)):
        raise OSError(ctypes.get_last_error(), "IsProcessInJob failed")
    return bool(member.value)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")


def _read_config(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "task_id",
        "selected_input",
        "temporary_output",
        "deadline_seconds",
        "probe_case",
        "echo_arguments",
    }
    extended = expected | {
        "selected_document_id",
        "tool_id",
        "broker_url",
        "worker_credential",
        "broker_probe",
    }
    if (
        not isinstance(raw, dict)
        or frozenset(raw) not in {frozenset(expected | {"broker_probe"}), frozenset(extended)}
        or raw["schema_version"] != 1
    ):
        raise ValueError("task_config_schema_invalid")
    if raw["probe_case"] not in {
        "normal",
        "child_exit",
        "child_wait",
        "child_crash",
        "capture",
    }:
        raise ValueError("task_config_probe_case_invalid")
    if not isinstance(raw["echo_arguments"], list) or len(raw["echo_arguments"]) > 16:
        raise ValueError("task_config_arguments_invalid")
    return raw


def _post_broker(config: dict[str, Any], body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        config["broker_url"],
        data=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + config["worker_credential"],
            "Content-Type": "application/json",
            "Host": config["broker_url"].split("//", 1)[1].split("/", 1)[0],
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read(2_097_153).decode("utf-8"))
    except urllib.error.HTTPError as response:
        return response.code, json.loads(response.read(2_097_153).decode("utf-8"))


def _broker_lifecycle_probe(config: dict[str, Any]) -> None:
    mode = config.get("broker_probe", "none")
    if mode == "none":
        return
    if mode == "policy_denial":
        _post_broker(
            config,
            {
                "schema_version": 1,
                "request_id": str(uuid.uuid4()),
                "operation": "read_document",
                "document_id": "doc-private",
            },
        )
        return
    status, response = _post_broker(
        config,
        {
            "schema_version": 1,
            "request_id": str(uuid.uuid4()),
            "operation": "read_document",
            "document_id": config["selected_document_id"],
        },
    )
    if status != 200 or response.get("decision") != "allow":
        raise RuntimeError("private_broker_read_failed")
    if config["tool_id"] == "report_formatter":
        output_kind = "formatted_markdown"
        output_text = "# A6 private lifecycle probe\n\nSynthetic broker output.\n"
    else:
        output_kind = "invoice_json"
        output_text = (
            '{"vendor":"Synthetic Vendor","invoice_number":"A6-001",'
            '"date":"2026-10-29","line_total":"1.00","grand_total":"1.00"}'
        )
    status, response = _post_broker(
        config,
        {
            "schema_version": 1,
            "request_id": str(uuid.uuid4()),
            "operation": "publish_output",
            "output_kind": output_kind,
            "output_text": output_text,
        },
    )
    if status != 200 or response.get("decision") != "allow":
        raise RuntimeError("private_broker_publish_failed")


def _creation_time_100ns(pid: int) -> int:
    import ctypes

    class FILETIME(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    try:
        created, exited, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
        return (int(created.high) << 32) | int(created.low)
    finally:
        kernel32.CloseHandle(handle)


def _try_denial(name: str, operation: Any) -> dict[str, Any]:
    try:
        operation()
    except OSError as exc:
        return {
            "name": name,
            "denied": True,
            "winerror": getattr(exc, "winerror", None),
            "errno": getattr(exc, "errno", None),
        }
    return {"name": name, "denied": False, "winerror": None, "errno": None}


def _open_config_for_write(path: Path) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    os.close(descriptor)


def _launch_child(config: dict[str, Any], marker: Path) -> int:
    child = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--child-sleep",
            str(marker),
        ],
        cwd=config["temporary_output"],
        env={
            "SystemRoot": os.environ["SystemRoot"],
            "WINDIR": os.environ["WINDIR"],
            "TEMP": config["temporary_output"],
            "TMP": config["temporary_output"],
        },
        shell=False,
        close_fds=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if marker.exists():
            return child.pid
        if child.poll() is not None:
            raise RuntimeError("child_exited_before_marker")
        time.sleep(0.02)
    raise TimeoutError("child_marker_timeout")


def _child(marker: Path) -> int:
    _write_json(
        marker,
        {
            "pid": os.getpid(),
            "creation_time_100ns": _creation_time_100ns(os.getpid()),
            "in_job": _in_any_job(),
        },
    )
    time.sleep(600)
    return 0


def _capture_burst() -> None:
    import threading

    payload = (b"ACLAIS-A3-CAPTURE-" + b"x" * 1022 + b"\n") * 2048

    def write(stream: Any) -> None:
        stream.buffer.write(payload)
        stream.flush()

    stdout_writer = threading.Thread(target=write, args=(sys.stdout,))
    stderr_writer = threading.Thread(target=write, args=(sys.stderr,))
    stdout_writer.start()
    stderr_writer.start()
    stdout_writer.join()
    stderr_writer.join()


def _probe(task_config_path: Path, echo_arguments: list[str]) -> int:
    config = _read_config(task_config_path)
    task_id = config["task_id"].replace("-", "")
    output_root = Path(config["temporary_output"])
    selected_input = Path(config["selected_input"])
    task_config_bytes = task_config_path.read_bytes()
    startup_marker = output_root / f"a3-{task_id}.worker.json"
    child_marker = output_root / f"a3-{task_id}.child.json"
    output_file = output_root / f"a3-{task_id}.txt"

    fixture_text = selected_input.read_text(encoding="utf-8")
    output_file.write_text(f"private probe read {len(fixture_text)} characters\n", encoding="utf-8")

    protected_checks = [
        _try_denial("task_config_write_denied", lambda: _open_config_for_write(task_config_path)),
        _try_denial("task_config_delete_denied", lambda: task_config_path.unlink()),
        _try_denial(
            "task_config_rename_denied",
            lambda: task_config_path.rename(task_config_path.with_suffix(".renamed")),
        ),
    ]
    if config.get("broker_probe", "none") != "none":
        selected_parent = selected_input.parent
        selected_root = selected_parent.parent
        temporary_root = output_root.parent
        protected_checks.extend(
            (
                _try_denial(
                    "selected_input_write_denied",
                    lambda: _open_config_for_write(selected_input),
                ),
                _try_denial("selected_input_delete_denied", lambda: selected_input.unlink()),
                _try_denial(
                    "selected_input_rename_denied",
                    lambda: selected_input.rename(selected_input.with_suffix(".renamed")),
                ),
                _try_denial("selected_parent_list_denied", lambda: list(selected_root.iterdir())),
                _try_denial(
                    "temporary_parent_list_denied", lambda: list(temporary_root.iterdir())
                ),
            )
        )
    # If a boundary unexpectedly permits a change, the check fails and the owner
    # harness restores/deletes only this run's disposable configuration file.
    config_unchanged = (
        task_config_path.exists() and task_config_path.read_bytes() == task_config_bytes
    )

    environment_keys = sorted(os.environ, key=str.casefold)
    startup = {
        "pid": os.getpid(),
        "in_job": _in_any_job(),
        "working_directory": os.getcwd(),
        "environment_keys": environment_keys,
        "environment": dict(os.environ),
        "argv": sys.argv[1:],
        "selected_input_read": bool(fixture_text),
        "task_config_read": True,
        "task_config_unchanged_after_attempts": config_unchanged,
        "protected_checks": protected_checks,
    }
    _write_json(startup_marker, startup)
    print(json.dumps({"event": "private_probe_started", "pid": os.getpid()}), flush=True)
    print(
        json.dumps({"event": "private_probe_diagnostic", "task": task_id}),
        file=sys.stderr,
        flush=True,
    )
    print(
        json.dumps({"echo_arguments": echo_arguments}, ensure_ascii=True, separators=(",", ":")),
        flush=True,
    )

    _broker_lifecycle_probe(config)

    if config["probe_case"] == "capture":
        _capture_burst()
    elif config["probe_case"] in {"child_exit", "child_wait", "child_crash"}:
        child_pid = _launch_child(config, child_marker)
        print(json.dumps({"event": "child_started", "pid": child_pid}), flush=True)
        if config["probe_case"] == "child_wait":
            time.sleep(600)
        elif config["probe_case"] == "child_crash":
            os._exit(23)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--task-config")
    parser.add_argument("--echo-arg", action="append", default=[])
    parser.add_argument("--child-sleep")
    parser.add_argument("--owner-sleep")
    args = parser.parse_args()
    try:
        if args.child_sleep:
            return _child(Path(args.child_sleep))
        if args.owner_sleep:
            Path(args.owner_sleep).write_text(str(os.getpid()), encoding="ascii")
            time.sleep(600)
            return 0
        if not args.task_config:
            return 64
        return _probe(Path(args.task_config), args.echo_arg)
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__}), file=sys.stderr, flush=True)
        return 90


if __name__ == "__main__":
    raise SystemExit(main())
