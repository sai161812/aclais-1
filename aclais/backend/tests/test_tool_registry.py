from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from aclais.persistence.models import CreateTaskRequest
from aclais.tool_registry import FIXED_TOOL_REGISTRATIONS, FixedToolRegistry, WorkerUnavailable

pytestmark = pytest.mark.portable


def test_registry_resolves_only_fixed_absolute_worker_entrypoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_root = tmp_path / "protected-runtime"
    registry = FixedToolRegistry(runtime_root)
    unrelated = tmp_path / "unrelated-working-directory"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)

    for registration in FIXED_TOOL_REGISTRATIONS:
        entrypoint = runtime_root / "code" / "document-tools" / registration.relative_entrypoint
        entrypoint.parent.mkdir(parents=True, exist_ok=True)
        entrypoint.write_text("# synthetic registry target\n", encoding="utf-8")
        request = CreateTaskRequest(
            schema_version=1,
            tool_id=registration.tool_id,
            selected_document_id=registration.document_id,
            launch_source_claim="document_tools",
        )
        assert registry.resolve_installed_entrypoint(request) == entrypoint.resolve()


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
