"""Private paired-run fixture setup; no product or public API exposes these controls."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from uuid import UUID

from document_tools.worker import FIXTURE_PATHS

TEMPLATE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "templates"


def create_disposable_fixture(root: Path, *, root_id: str | None = None) -> dict[str, object]:
    """Create four synthetic originals and a task-output folder under an explicit root."""

    if not root.is_absolute() or root.exists() or root.is_symlink():
        raise ValueError("fixture destination must be a new absolute directory")
    identifier = str(UUID(root_id)) if root_id else str(UUID(bytes=os.urandom(16), version=4))
    originals = root / "store" / "originals"
    selected = root / "store" / "selected"
    temporary = root / "work" / "task-output"
    originals.mkdir(parents=True)
    selected.mkdir(parents=True)
    temporary.mkdir(parents=True)
    template_mapping = {
        "project-report.md": "project-report.md",
        "meeting-notes.md": "meeting-notes.md",
        "invoice.csv": "invoice.csv",
        "Personnel_Private.csv": "Personnel_Private.template.csv",
    }
    for output_name, template_name in template_mapping.items():
        shutil.copyfile(TEMPLATE_ROOT / template_name, originals / output_name)
    shutil.copyfile(originals / "project-report.md", selected / "doc-report.md")
    sentinel = {
        "schema_version": 1,
        "root_id": identifier,
        "root_path": str(root),
    }
    (root / ".fixture-sentinel.json").write_text(
        json.dumps(sentinel, sort_keys=True), encoding="utf-8"
    )
    return {"root_id": identifier, "root": root, "temporary": temporary}


def inventory(root: Path) -> tuple[dict[str, object], ...]:
    """Independently hash the bounded fixture root without following reparse points."""

    results: list[dict[str, object]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
            metadata = child.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x0400
            ):
                raise ValueError("fixture inventory refuses reparse points")
            relative = child.relative_to(root).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                results.append({"path": relative, "exists": True, "type": "directory"})
                pending.append(child)
            elif stat.S_ISREG(metadata.st_mode):
                raw = child.read_bytes()
                results.append(
                    {
                        "path": relative,
                        "exists": True,
                        "type": "file",
                        "size_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
            else:
                raise ValueError("fixture inventory found an unsupported filesystem object")
    return tuple(sorted(results, key=lambda row: str(row["path"])))


def original_inventory(root: Path) -> tuple[dict[str, object], ...]:
    """Return original-file records only, including explicit missing names."""

    originals = root / "store" / "originals"
    actual = {str(row["path"]): row for row in inventory(originals)}
    records: list[dict[str, object]] = []
    for relative in FIXTURE_PATHS:
        filename = Path(relative).name
        row = actual.get(filename)
        records.append(
            row
            if row is not None
            else {
                "path": filename,
                "exists": False,
                "type": "missing",
                "size_bytes": None,
                "sha256": None,
            }
        )
    return tuple(records)


def tree_sha256(root: Path) -> str:
    """Hash installed Python worker sources using stable relative paths and file hashes."""

    files = sorted(
        (path for path in root.rglob("*.py") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    digest = hashlib.sha256()
    for path in files:
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x0400:
            raise ValueError("worker source tree contains a reparse point")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        file_hash = hashlib.sha256(path.read_bytes()).digest()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(path.stat().st_size.to_bytes(8, "big"))
        digest.update(file_hash)
    return digest.hexdigest()


def build_worker_configuration(
    *,
    task_id: str,
    fixture_root: Path,
    root_id: str,
    temporary_output: Path,
    broker_url: str,
    worker_credential: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "task_id": task_id,
        "tool_id": "report_formatter",
        "selected_document_id": "doc-report",
        "fixture_root": str(fixture_root),
        "scope_manifest": {
            "schema_version": 1,
            "root_id": root_id,
            "root_path": str(fixture_root),
            "fixture_files": list(FIXTURE_PATHS),
        },
        "temporary_output": str(temporary_output),
        "deadline_seconds": 30,
        "broker_url": broker_url,
        "worker_credential": worker_credential,
    }
