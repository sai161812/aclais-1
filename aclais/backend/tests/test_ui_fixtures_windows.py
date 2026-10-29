"""Visibly labeled isolated UI contract fixtures. No worker/receiver is run here."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

from aclais.persistence.database import Database, utc_now
from aclais.persistence.models import (
    ContractSummary,
    CreateTaskRequest,
    EvidenceCheck,
    EvidenceReport,
    EvidenceResponse,
    HealthCheck,
    HealthResponse,
    Incident,
    OutputMetadata,
    RevocationCause,
    TaskDetailResponse,
    TaskListResponse,
    TaskRecord,
    TaskStatus,
    TaskSummary,
    TerminalCause,
)

pytestmark = pytest.mark.windows_ui


def test_isolated_verified_and_containment_failure_ui_contract_fixtures(tmp_path: Path):
    if os.name != "nt":
        pytest.skip("the designated G1 browser machine is Windows")
    from playwright.sync_api import sync_playwright

    database = Database(tmp_path / "isolated-ui-fixture.sqlite3")
    task = database.create_task(
        CreateTaskRequest(
            schema_version=1,
            tool_id="report_formatter",
            selected_document_id="doc-report",
            launch_source_claim="document_tools",
        )
    )
    now = utc_now()
    incident_id, trigger_id, output_id = uuid4(), uuid4(), uuid4()
    content = "<img src=x onerror=alert(1)> Synthetic inert UI fixture."
    metadata = OutputMetadata(
        output_id=output_id,
        task_id=task.task_id,
        output_kind="formatted_markdown",
        file_name=f"{output_id}.md",
        decoded_bytes=len(content.encode()),
        sha256=hashlib.sha256(content.encode()).hexdigest(),
        created_at=now,
    )
    contract = ContractSummary.model_validate(
        database.get_contract(task.task_id).model_dump(exclude={"created_at"})
    )
    root = Path(__file__).resolve().parents[3]
    dist = root / "aclais/frontend/dist"
    shots = root / "evidence/g1-visuals"
    shots.mkdir(exist_ok=True, parents=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe", headless=True
        )
        try:
            for failed in (False, True):
                state = TaskStatus.FAILED if failed else TaskStatus.BLOCKED
                record = TaskRecord.model_validate(
                    {
                        **task.model_dump(),
                        "status": state,
                        "started_at": now,
                        "finished_at": now,
                        "incident_id": incident_id,
                        "revocation_cause": RevocationCause.POLICY_DENIED,
                        "terminal_cause": TerminalCause.POLICY_DENIED,
                    }
                )
                incident = Incident(
                    incident_id=incident_id,
                    task_id=task.task_id,
                    trigger_event_id=trigger_id,
                    policy_reason="DOCUMENT_OUT_OF_SCOPE",
                    containment_status="failed" if failed else "terminated",
                    integrity_status="unknown" if failed else "pass",
                    confidentiality_status="unknown" if failed else "pass",
                    evidence_refs=(),
                )
                report = EvidenceReport(
                    report_id=uuid4(),
                    task_id=task.task_id,
                    run_id=task.run_id,
                    generated_at=now,
                    verifier_version="isolated-ui-contract-fixture",
                    tested_source_revision=None,
                    tested_source_sha256="0" * 64,
                    overall_status="unknown" if failed else "pass",
                    integrity_status="unknown" if failed else "pass",
                    confidentiality_status="unknown" if failed else "pass",
                    file_inventory_before=(),
                    file_inventory_after=(),
                    selected_input_size_before_bytes=None,
                    selected_input_sha256_before=None,
                    selected_input_size_after_bytes=None,
                    selected_input_sha256_after=None,
                    published_output_size_bytes=None,
                    published_output_sha256=None,
                    added_files=(),
                    missing_files=(),
                    renamed_files=(),
                    changed_files=(),
                    differences=(),
                    receiver_status="unknown" if failed else "pass",
                    receipt_ids=(),
                    marker_received=None if failed else False,
                    controller_process_observation=None,
                    worker_exit_observed=False,
                    worker_identity_recorded=False,
                    worker_termination_confirmed=not failed,
                    worker_exit_code=None,
                    worker_observation_count=0,
                    event_sources=(),
                    checks=(
                        EvidenceCheck(
                            id="isolated_ui_fixture",
                            source="receiver",
                            status="unknown" if failed else "pass",
                            observed="Typed UI fixture. No worker or receiver was run.",
                            expected="Presentation branch only; no enforcement claim.",
                            artifact_path="isolated-ui-fixture.json",
                        ),
                    ),
                )
                detail = TaskDetailResponse(
                    schema_version=1,
                    task=record,
                    contract_summary=contract,
                    output_metadata=metadata,
                    incident_summary=incident,
                )
                summary = TaskSummary.model_validate(
                    {field: getattr(record, field) for field in TaskSummary.model_fields}
                )
                health = HealthResponse(
                    schema_version=1,
                    status="unavailable" if failed else "ready",
                    protection_ready=not failed,
                    checks=(
                        HealthCheck(
                            id="g1_protection",
                            status="fail" if failed else "pass",
                            summary="ISOLATED UI FIXTURE; not observed protection.",
                        ),
                    ),
                )
                responses = {
                    "/api/health": health,
                    "/api/documents": database.documents(),
                    "/api/tasks": TaskListResponse(schema_version=1, tasks=(summary,)),
                    f"/api/tasks/{task.task_id}": detail,
                    f"/api/tasks/{task.task_id}/evidence": EvidenceResponse(
                        schema_version=1, status="complete", report=report
                    ),
                }
                context = browser.new_context(viewport={"width": 1366, "height": 768})

                def fixture_route(route):
                    path = urlsplit(route.request.url).path
                    if path == "/owner":
                        notice = (
                            "<aside role='note' style='position:fixed;top:0;left:220px;"
                            "z-index:9999;background:#fff1b8;color:#172033;padding:12px'>"
                            "ISOLATED UI FIXTURE — NO ENFORCEMENT OR RECEIVER EVIDENCE</aside>"
                        )
                        html = (dist / "index.html").read_text(encoding="utf-8")
                        route.fulfill(
                            content_type="text/html", body=html.replace("<body>", "<body>" + notice)
                        )
                    elif path in responses:
                        route.fulfill(
                            content_type="application/json", body=responses[path].model_dump_json()
                        )
                    elif path.endswith("/events"):
                        route.fulfill(json={"schema_version": 1, "events": [], "last_seq": 0})
                    elif path == f"/api/outputs/{output_id}":
                        route.fulfill(content_type="text/plain", body=content)
                    elif path.startswith("/assets/") and Path(path).name == path.split("/")[-1]:
                        route.fulfill(path=str(dist / "assets" / Path(path).name))
                    else:
                        route.abort()

                context.route("http://127.0.0.1:8765/**", fixture_route)
                page = context.new_page()
                page.goto("http://127.0.0.1:8765/owner")
                page.get_by_role("button", name="View details").click()
                expected = "Containment failed" if failed else "Protected originals unchanged"
                page.get_by_role("dialog", name="Protection event").wait_for()
                banner = page.locator(".incident-banner strong").inner_text()
                assert banner == expected
                assert page.get_by_text(
                    "Generated by a tool that was stopped", exact=True
                ).is_visible()
                assert page.locator(".output-preview img").count() == 0
                for width, height in ((1366, 768), (1920, 1080)):
                    page.set_viewport_size({"width": width, "height": height})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    name = "containment-failed" if failed else "verified"
                    page.screenshot(
                        path=str(shots / f"ui-fixture-{name}-{width}x{height}.png"),
                        animations="disabled",
                    )
                context.close()
            assert len(database.task_summaries()) == 1
            assert database.get_task(task.task_id).status == TaskStatus.CREATED
        finally:
            browser.close()
