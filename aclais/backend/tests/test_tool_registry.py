from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aclais.persistence.models import CreateTaskRequest
from aclais.tool_registry import FIXED_TOOL_REGISTRATIONS, FixedToolRegistry, WorkerUnavailable

pytestmark = pytest.mark.portable


def test_registry_resolves_only_fixed_absolute_worker_entrypoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_root = tmp_path / "protected-runtime"
    root_id = str(uuid4())
    registry = FixedToolRegistry(runtime_root, root_id=root_id)
    unrelated = tmp_path / "unrelated-working-directory"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)

    registration = FIXED_TOOL_REGISTRATIONS[0]
    code_root = runtime_root / "code" / "document-tools"
    source_paths = (
        Path("src/document_tools/__init__.py"),
        Path("src/document_tools/broker.py"),
        Path("src/document_tools/worker.py"),
        registration.relative_entrypoint,
    )
    files = []
    for relative in source_paths:
        path = code_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# synthetic registry target\n", encoding="utf-8")
        raw = path.read_bytes()
        files.append(
            {
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "length": len(raw),
            }
        )
    (code_root / "tool-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "root_id": root_id,
                "tools": [
                    {
                        "tool_id": "report_formatter",
                        "document_id": "doc-report",
                        "entrypoint": registration.relative_entrypoint.as_posix(),
                        "files": files,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    request = CreateTaskRequest(
        schema_version=1,
        tool_id="report_formatter",
        selected_document_id="doc-report",
        launch_source_claim="document_tools",
    )
    entrypoint = code_root / registration.relative_entrypoint
    assert registry.resolve_installed_entrypoint(request) == entrypoint.resolve()
    assert (
        registry.entrypoint_sha256(request) == hashlib.sha256(entrypoint.read_bytes()).hexdigest()
    )

    invoice_request = CreateTaskRequest(
        schema_version=1,
        tool_id="invoice_analyzer",
        selected_document_id="doc-invoice",
        launch_source_claim="document_tools",
    )
    with pytest.raises(WorkerUnavailable):
        registry.resolve_installed_entrypoint(invoice_request)


def test_registry_rejects_uninstalled_worker_and_untrusted_request_fields(tmp_path: Path) -> None:
    registry = FixedToolRegistry(tmp_path / "empty-runtime")
    request = CreateTaskRequest(
        schema_version=1,
        tool_id="report_formatter",
        selected_document_id="doc-report",
        launch_source_claim="document_tools",
    )
    with pytest.raises(WorkerUnavailable):
        registry.resolve_installed_entrypoint(request)
    with pytest.raises(ValidationError):
        CreateTaskRequest.model_validate(
            {
                "schema_version": 1,
                "tool_id": "report_formatter",
                "selected_document_id": "doc-report",
                "launch_source_claim": "document_tools",
                "executable": "calc.exe",
                "args": [],
            },
            strict=True,
        )


def test_registry_rejects_tampered_installed_worker_source(tmp_path: Path) -> None:
    runtime_root = tmp_path / "runtime"
    root_id = str(uuid4())
    code_root = runtime_root / "code" / "document-tools"
    entrypoint = code_root / "workers/report_formatter/entrypoint.py"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("print('installed')\n", encoding="utf-8")
    expected_files = []
    for relative in (
        "src/document_tools/__init__.py",
        "src/document_tools/broker.py",
        "src/document_tools/worker.py",
        "workers/report_formatter/entrypoint.py",
    ):
        path = code_root / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("# protected worker source\n", encoding="utf-8")
        raw = path.read_bytes()
        expected_files.append(
            {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "length": len(raw)}
        )
    (code_root / "tool-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "root_id": root_id,
                "tools": [
                    {
                        "tool_id": "report_formatter",
                        "document_id": "doc-report",
                        "entrypoint": "workers/report_formatter/entrypoint.py",
                        "files": expected_files,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    entrypoint.write_text("print('changed')\n", encoding="utf-8")
    request = CreateTaskRequest(
        schema_version=1,
        tool_id="report_formatter",
        selected_document_id="doc-report",
        launch_source_claim="document_tools",
    )
    with pytest.raises(WorkerUnavailable):
        FixedToolRegistry(runtime_root, root_id=root_id).resolve_installed_entrypoint(request)
