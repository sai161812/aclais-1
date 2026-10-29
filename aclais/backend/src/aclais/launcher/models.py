"""Portable, strict models shared by the Windows launcher and its private probe."""

from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class A3ProbeConfiguration(BaseModel):
    """Bounded private A3 task configuration written by the owner before launch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    task_id: UUID
    selected_input: str = Field(min_length=1, max_length=1024)
    temporary_output: str = Field(min_length=1, max_length=1024)
    deadline_seconds: int = Field(ge=1, le=600)
    probe_case: Literal["normal", "child_exit", "child_wait", "child_crash", "capture"]
    echo_arguments: tuple[str, ...] = Field(default=(), max_length=16)
    selected_document_id: Literal["doc-report", "doc-invoice"] | None = None
    tool_id: Literal["report_formatter", "invoice_analyzer"] | None = None
    broker_url: str | None = Field(default=None, max_length=256, repr=False)
    worker_credential: str | None = Field(default=None, max_length=512, repr=False)
    broker_probe: Literal["none", "allow_and_publish", "policy_denial"] = "none"

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

    @field_validator("broker_url")
    @classmethod
    def require_loopback_broker_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or not 1024 <= parsed.port <= 65535
            or parsed.path != "/api/broker/operations"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("private worker broker URL must use the fixed loopback endpoint")
        return value

    @model_validator(mode="after")
    def validate_broker_probe(self) -> A3ProbeConfiguration:
        configured = (
            self.selected_document_id,
            self.tool_id,
            self.broker_url,
            self.worker_credential,
        )
        if self.broker_probe == "none":
            if any(value is not None for value in configured):
                raise ValueError("broker fields require an explicit private broker probe mode")
            return self
        if any(value is None for value in configured):
            raise ValueError("private broker probe fields are incomplete")
        if (self.tool_id, self.selected_document_id) not in {
            ("report_formatter", "doc-report"),
            ("invoice_analyzer", "doc-invoice"),
        }:
            raise ValueError("private broker probe tool and document do not match")
        if not 32 <= len(self.worker_credential or "") <= 512:
            raise ValueError("private worker credential has an invalid length")
        return self


class WorkerScopeManifest(BaseModel):
    """Controller-issued filename-only scope derived from the validated lab sentinel."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1]
    root_id: UUID
    root_path: str = Field(min_length=1, max_length=1024)
    fixture_files: tuple[str, ...] = Field(min_length=4, max_length=4)

    @field_validator("root_path")
    @classmethod
    def require_absolute_root(cls, value: str) -> str:
        return A3ProbeConfiguration.require_absolute_windows_path(value)

    @field_validator("fixture_files")
    @classmethod
    def require_fixed_document_manifest(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        expected = (
            "store/originals/Personnel_Private.csv",
            "store/originals/invoice.csv",
            "store/originals/meeting-notes.md",
            "store/originals/project-report.md",
        )
        if values != expected:
            raise ValueError("worker scope must contain exactly the four seeded documents")
        return values


class DocumentToolsWorkerConfiguration(BaseModel):
    """Strict owner-written configuration for the fixed production formatter."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    task_id: UUID
    tool_id: Literal["report_formatter"]
    selected_document_id: Literal["doc-report"]
    fixture_root: str = Field(min_length=1, max_length=1024)
    scope_manifest: WorkerScopeManifest
    temporary_output: str = Field(min_length=1, max_length=1024)
    deadline_seconds: int = Field(ge=1, le=30)
    broker_url: str = Field(min_length=1, max_length=256, repr=False)
    worker_credential: str = Field(min_length=32, max_length=512, repr=False)

    @field_validator("fixture_root", "temporary_output")
    @classmethod
    def require_absolute_paths(cls, value: str) -> str:
        return A3ProbeConfiguration.require_absolute_windows_path(value)

    @field_validator("broker_url")
    @classmethod
    def require_canonical_broker_url(cls, value: str) -> str:
        if value != "http://127.0.0.1:8765/api/broker/operations":
            raise ValueError("production worker broker URL is fixed to the ACLAIS origin")
        return value

    @field_validator("worker_credential")
    @classmethod
    def validate_credential(cls, value: str) -> str:
        if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
            raise ValueError("worker credential is invalid")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> DocumentToolsWorkerConfiguration:
        root = PureWindowsPath(self.fixture_root)
        temp = PureWindowsPath(self.temporary_output)
        try:
            temp.relative_to(root)
        except ValueError as exc:
            raise ValueError("temporary output must be under the fixture root") from exc
        if self.scope_manifest.root_path != self.fixture_root:
            raise ValueError("scope manifest root does not match the fixture root")
        return self


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
    termination_cause: Literal[
        "process_exit", "cancelled", "timeout", "controller_shutdown", "policy_denied"
    ]
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
