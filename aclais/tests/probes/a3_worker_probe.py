"""Harmless private A3 worker; deployed only into the owner-protected lab code tree."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
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
    if not isinstance(raw, dict) or set(raw) != expected or raw["schema_version"] != 1:
        raise ValueError("task_config_schema_invalid")
    if raw["probe_case"] not in {"normal", "child_exit", "child_wait", "capture"}:
        raise ValueError("task_config_probe_case_invalid")
    if not isinstance(raw["echo_arguments"], list) or len(raw["echo_arguments"]) > 16:
        raise ValueError("task_config_arguments_invalid")
    return raw


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
    _write_json(marker, {"pid": os.getpid(), "in_job": _in_any_job()})
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

    if config["probe_case"] == "capture":
        _capture_burst()
    elif config["probe_case"] in {"child_exit", "child_wait"}:
        child_pid = _launch_child(config, child_marker)
        print(json.dumps({"event": "child_started", "pid": child_pid}), flush=True)
        if config["probe_case"] == "child_wait":
            time.sleep(600)
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
