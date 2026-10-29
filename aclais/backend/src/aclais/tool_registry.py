"""Controller-owned allowlist for the two specified production worker entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aclais.persistence.models import CreateTaskRequest


class WorkerUnavailable(RuntimeError):
    """A fixed worker entrypoint is not installed or cannot be safely resolved."""


@dataclass(frozen=True, slots=True)
class ToolRegistration:
    tool_id: str
    document_id: str
    relative_entrypoint: Path


FIXED_TOOL_REGISTRATIONS = (
    ToolRegistration(
        "report_formatter",
        "doc-report",
        Path("workers") / "report_formatter" / "entrypoint.py",
    ),
    ToolRegistration(
        "invoice_analyzer",
        "doc-invoice",
        Path("workers") / "invoice_analyzer" / "entrypoint.py",
    ),
)


class FixedToolRegistry:
    """Resolve only controller-fixed tool/document pairs beneath the install root."""

    def __init__(self, runtime_root: Path) -> None:
        if not runtime_root.is_absolute():
            raise ValueError("runtime root must be explicit and absolute")
        self.runtime_root = runtime_root
        self.code_root = runtime_root / "code" / "document-tools"
        self._registrations = {
            (item.tool_id, item.document_id): item for item in FIXED_TOOL_REGISTRATIONS
        }

    def registration_for(self, request: CreateTaskRequest) -> ToolRegistration:
        try:
            return self._registrations[(request.tool_id, request.selected_document_id)]
        except KeyError as exc:
            raise WorkerUnavailable(
                "tool and selected document are not a fixed registration"
            ) from exc

    def resolve_installed_entrypoint(self, request: CreateTaskRequest) -> Path:
        registration = self.registration_for(request)
        unresolved = self.runtime_root
        for component in (
            "code",
            "document-tools",
            *registration.relative_entrypoint.parts,
        ):
            unresolved = unresolved / component
            if unresolved.is_symlink():
                raise WorkerUnavailable("registered worker path contains a symbolic link")
        root = self.code_root.resolve(strict=False)
        candidate = unresolved.resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise WorkerUnavailable("registered worker escaped its protected install root") from exc
        if not candidate.is_file():
            raise WorkerUnavailable("registered worker entrypoint is not installed")
        return candidate
