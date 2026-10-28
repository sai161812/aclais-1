"""Portable, strict models shared by the Windows launcher and its private probe."""

from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class A3ProbeConfiguration(BaseModel):
    """Bounded private A3 task configuration written by the owner before launch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    task_id: UUID
    selected_input: str = Field(min_length=1, max_length=1024)
    temporary_output: str = Field(min_length=1, max_length=1024)
    deadline_seconds: int = Field(ge=1, le=600)
    probe_case: Literal["normal", "child_exit", "child_wait", "capture"]
    echo_arguments: tuple[str, ...] = Field(default=(), max_length=16)

    @field_validator("selected_input", "temporary_output")
    @classmethod
    def require_absolute_windows_path(cls, value: str) -> str:
        path = PureWindowsPath(value)
        components = value[3:].replace("/", "\\").split("\\") if len(value) >= 3 else ()
        if (
            "\x00" in value
            or not path.is_absolute()
            or len(path.drive) != 2
            or path.drive[0].upper() not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            or path.drive[1] != ":"
            or any(component in {".", ".."} or ":" in component for component in components)
        ):
            raise ValueError("managed path must be an absolute drive path")
        return value

    @field_validator("echo_arguments")
    @classmethod
    def bound_arguments(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in value or len(value) > 2048 for value in values):
            raise ValueError("probe argument is invalid or too large")
        return values


class CapturedLine(BaseModel):
    """One bounded output line with explicit channel and provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    channel: Literal["stdout", "stderr"]
    provenance: Literal["worker_reported"] = "worker_reported"
    text: str = Field(max_length=16_384)


class WorkerResult(BaseModel):
    """Trusted launcher observations plus separately attributed worker output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    pid: int = Field(gt=0)
    creation_time_100ns: int = Field(gt=0)
    worker_sid: str = Field(min_length=1, max_length=184)
    worker_is_administrator: Literal[False]
    assigned_to_job_before_resume: Literal[True]
    job_kill_on_close: Literal[True]
    task_configuration_unchanged: Literal[True]
    exit_code: int
    termination_cause: Literal["process_exit", "cancelled", "timeout", "controller_shutdown"]
    process_tree_stopped: Literal[True]
    stdout: tuple[CapturedLine, ...]
    stderr: tuple[CapturedLine, ...]
    stdout_bytes_observed: int = Field(ge=0)
    stderr_bytes_observed: int = Field(ge=0)
    stdout_truncated: bool
    stderr_truncated: bool
    launch_sequence: tuple[
        Literal["created_suspended", "identity_verified", "job_configured", "assigned", "resumed"],
        ...,
    ]


def windows_command_line(application: str, arguments: tuple[str, ...]) -> str:
    """Quote a bounded argv with the Windows C runtime rules; never invoke a shell."""

    import subprocess

    application_path = PureWindowsPath(application)
    if (
        not application
        or "\x00" in application
        or not application_path.is_absolute()
        or len(application_path.drive) != 2
        or application_path.drive[0].upper() not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        or application_path.drive[1] != ":"
    ):
        raise ValueError("absolute application path is required")
    if any(not isinstance(item, str) or "\x00" in item for item in arguments):
        raise ValueError("arguments must be NUL-free strings")
    command_line = subprocess.list2cmdline([application, *arguments])
    if len(command_line.encode("utf-16-le")) // 2 >= 32_767:
        raise ValueError("worker command line exceeds the Windows limit")
    return command_line
