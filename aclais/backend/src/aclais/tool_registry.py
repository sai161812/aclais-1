"""Controller-owned allowlist for the two specified production worker entrypoints."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

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

    def __init__(self, runtime_root: Path, *, root_id: str | None = None) -> None:
        if not runtime_root.is_absolute():
            raise ValueError("runtime root must be explicit and absolute")
        self.runtime_root = runtime_root
        self.root_id = root_id
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
        record = self._installed_record(registration)
        expected_relative = registration.relative_entrypoint.as_posix()
        if record["entrypoint"] != expected_relative:
            raise WorkerUnavailable("registered worker manifest does not match the fixed allowlist")
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
        declared = {item["path"]: item for item in record["files"]}
        relative_path = candidate.relative_to(self.code_root).as_posix()
        if relative_path not in declared:
            raise WorkerUnavailable(
                "registered worker entrypoint is absent from its install manifest"
            )
        for relative, item in declared.items():
            path = self._resolve_manifest_path(relative)
            if path.stat().st_size != item["length"] or _sha256(path) != item["sha256"]:
                raise WorkerUnavailable("installed worker source failed its protected manifest")
        return candidate

    def entrypoint_sha256(self, request: CreateTaskRequest) -> str:
        candidate = self.resolve_installed_entrypoint(request)
        return _sha256(candidate)

    def _installed_record(self, registration: ToolRegistration) -> dict[str, Any]:
        manifest_path = self.code_root / "tool-manifest.json"
        try:
            metadata = manifest_path.lstat()
        except OSError:
            raise WorkerUnavailable(
                "protected worker installation manifest is unavailable"
            ) from None
        if (
            manifest_path.is_symlink()
            or getattr(metadata, "st_file_attributes", 0) & 0x0400
            or not manifest_path.is_file()
            or metadata.st_size > 65_536
        ):
            raise WorkerUnavailable("protected worker installation manifest is unavailable")
        try:
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
            )
        except (OSError, UnicodeDecodeError, ValueError):
            raise WorkerUnavailable("protected worker installation manifest is invalid") from None
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version",
            "root_id",
            "tools",
        }:
            raise WorkerUnavailable("protected worker installation manifest fields are invalid")
        try:
            UUID(manifest["root_id"])
        except (ValueError, TypeError, KeyError):
            raise WorkerUnavailable("protected worker installation root ID is invalid") from None
        if (
            type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or self.root_id is not None
            and manifest["root_id"] != self.root_id
            or not isinstance(manifest["tools"], list)
        ):
            raise WorkerUnavailable("protected worker installation manifest identity is invalid")
        matches = [
            item
            for item in manifest["tools"]
            if isinstance(item, dict) and item.get("tool_id") == registration.tool_id
        ]
        if len(matches) != 1:
            raise WorkerUnavailable("fixed worker is not installed")
        record = matches[0]
        if set(record) != {"tool_id", "document_id", "entrypoint", "files"}:
            raise WorkerUnavailable("worker installation record fields are invalid")
        if (
            record["tool_id"] != registration.tool_id
            or record["document_id"] != registration.document_id
            or not isinstance(record["entrypoint"], str)
            or not isinstance(record["files"], list)
        ):
            raise WorkerUnavailable("worker installation record does not match the registry")
        file_paths: set[str] = set()
        for item in record["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "length"}:
                raise WorkerUnavailable("worker source inventory is invalid")
            path = item["path"]
            if (
                not isinstance(path, str)
                or "\\" in path
                or ":" in path
                or path.startswith("/")
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or path
                not in {
                    *(
                        f"src/document_tools/{name}"
                        for name in ("__init__.py", "broker.py", "worker.py")
                    ),
                    "workers/report_formatter/entrypoint.py",
                }
                or path in file_paths
                or not isinstance(item["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or type(item["length"]) is not int
                or item["length"] < 0
            ):
                raise WorkerUnavailable("worker source path or digest is invalid")
            file_paths.add(path)
        expected_files = {
            "src/document_tools/__init__.py",
            "src/document_tools/broker.py",
            "src/document_tools/worker.py",
            "workers/report_formatter/entrypoint.py",
        }
        if record["entrypoint"] not in file_paths or file_paths != expected_files:
            raise WorkerUnavailable("worker source inventory is incomplete")
        return record

    def _resolve_manifest_path(self, relative: str) -> Path:
        path = self.code_root
        for part in relative.split("/"):
            path = path / part
            try:
                metadata = path.lstat()
            except OSError:
                raise WorkerUnavailable("protected worker source is unavailable") from None
            if path.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x0400:
                raise WorkerUnavailable("protected worker source contains a symbolic link")
        try:
            path.resolve(strict=True).relative_to(self.code_root.resolve(strict=True))
        except (OSError, ValueError):
            raise WorkerUnavailable(
                "protected worker source escaped its installation root"
            ) from None
        if not path.is_file():
            raise WorkerUnavailable("protected worker source is missing")
        return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate worker manifest key")
        result[key] = value
    return result
