"""Paired baseline/protected Report Formatter run on the actual A2 target."""

# ruff: noqa: E402

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import uvicorn

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
for source_root in (
    REPOSITORY_ROOT / "aclais" / "backend" / "src",
    REPOSITORY_ROOT / "document-tools" / "src",
):
    sys.path.insert(0, str(source_root))

from document_tools.server import WebsiteServer

from aclais.config import Settings
from aclais.launcher.models import DocumentToolsWorkerConfiguration
from aclais.launcher.windows import RuntimeLayout, WindowsWorkerController
from aclais.lifecycle import TaskWorkspace
from aclais.owner_auth import OWNER_SESSION_COOKIE
from aclais.persistence.models import RevocationCause, TaskStatus
from aclais.runtime import create_a8_runtime

pytestmark = pytest.mark.windows_enforcement


def _load_private_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("private G3 test helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(os.name != "nt", reason="G3 enforcement requires the designated Windows host")
def test_report_formatter_baseline_and_protected_owner_approval() -> None:
    from playwright.sync_api import sync_playwright

    fixture_harness = _load_private_module(
        "aclais_g3_private_fixture_harness",
        REPOSITORY_ROOT / "document-tools" / "tests" / "private" / "fixture_harness.py",
    )
    broker_harness = _load_private_module(
        "aclais_g3_private_broker_harness",
        REPOSITORY_ROOT / "document-tools" / "tests" / "private" / "broker_server.py",
    )

    layout = RuntimeLayout.open()
    fixture_root = layout.output_root / f".g3-formatter-baseline-{uuid4().hex}"
    worker_root = layout.code_root / "document-tools"
    worker_tree_sha256 = fixture_harness.tree_sha256(worker_root)
    worker_source_tree_sha256 = _worker_source_tree_sha256(REPOSITORY_ROOT)
    assert worker_tree_sha256 == worker_source_tree_sha256
    controller = WindowsWorkerController(layout)
    runtime = None
    website = None
    uvicorn_server = None
    server_thread = None
    browser = None
    context = None
    raw_report: dict[str, object] | None = None
    baseline_result = None
    baseline_before: tuple[dict[str, object], ...] = ()
    baseline_after: tuple[dict[str, object], ...] = ()
    protected_before: tuple[dict[str, object], ...] = ()
    protected_after: tuple[dict[str, object], ...] = ()
    baseline_observations: list[dict[str, object]] = []
    protected_observations: list[dict[str, object]] = []
    baseline_operations: list[dict[str, object]] = []
    protected_operations: list[dict[str, object]] = []
    protected_task_id = None
    protected_task = None
    published_metadata = None
    published_content = b""
    evidence = None
    protected_worker_controller = None
    playwright = None
    baseline_output_sha256 = ""
    baseline_output_bytes = 0
    before_task_count = 0
    task_count_after_approval_get = -1
    before_tasks = ()
    tasks_after_approval_get = ()
    test_owner_session_sha256 = None
    process_creation_time = None
    source_hash_before = ""

    try:
        _require_loopback_ports_free((8765, 8766))
        TaskWorkspace(layout).prepare_roots()

        setup = fixture_harness.create_disposable_fixture(fixture_root)
        baseline_before = fixture_harness.original_inventory(fixture_root)
        selected_input = fixture_root / "store" / "selected" / "doc-report.md"
        baseline_token = _ephemeral_token()
        baseline_task_id = uuid4()
        baseline_config = _worker_configuration(
            fixture_harness,
            task_id=baseline_task_id,
            fixture_root=fixture_root,
            root_id=str(setup["root_id"]),
            temporary_output=Path(setup["temporary"]),
            worker_credential=baseline_token,
        )
        with broker_harness.PrivateBroker(selected_input, baseline_token, port=8765) as broker:
            baseline_handle = controller.start_private_document_tools_worker_for_test(
                baseline_config
            )
            try:
                baseline_result = baseline_handle.wait()
            finally:
                if not baseline_handle.handles_closed:
                    baseline_handle.cancel()
            baseline_operations = broker.operations
            assert broker.published, "baseline did not publish useful output through its broker"
            baseline_output = broker.published[0].encode("utf-8")
            assert b"## Contents" in baseline_output
            baseline_output_sha256 = hashlib.sha256(baseline_output).hexdigest()
            baseline_output_bytes = len(baseline_output)
        assert baseline_result is not None
        assert baseline_result.process_tree_stopped
        assert baseline_result.worker_sid == layout.worker_sid
        assert baseline_result.worker_is_administrator is False
        assert controller.verify_stored_process_stopped(
            baseline_result.pid,
            baseline_result.creation_time_100ns,
            baseline_result.worker_sid,
        )
        baseline_after = fixture_harness.original_inventory(fixture_root)
        baseline_observations = _worker_observations(baseline_result.stdout)
        _verify_baseline_effects(baseline_before, baseline_after, baseline_observations)
        assert [item["operation"] for item in baseline_operations] == [
            "read_document",
            "publish_output",
            "replace_original",
        ]
        assert baseline_result.exit_code == 0
        assert not baseline_result.stdout_truncated and not baseline_result.stderr_truncated
        assert fixture_harness.tree_sha256(worker_root) == worker_tree_sha256
        baseline_selected_sha256 = hashlib.sha256(selected_input.read_bytes()).hexdigest()
        assert baseline_selected_sha256 == _source_worker_selected_sha256(layout.root)
        controller.shutdown()
        _remove_disposable_fixture(fixture_root, layout.output_root)

        runtime = create_a8_runtime(Settings())
        protected_worker_controller = runtime.lifecycle.launcher
        assert isinstance(protected_worker_controller, WindowsWorkerController)
        website = WebsiteServer(REPOSITORY_ROOT / "document-tools" / "frontend" / "dist")
        website.start()
        uvicorn_server = uvicorn.Server(
            uvicorn.Config(
                runtime.app,
                host="127.0.0.1",
                port=8765,
                log_level="critical",
                access_log=False,
                lifespan="on",
            )
        )
        server_thread = threading.Thread(target=uvicorn_server.run, name="g3-aclais-owner-api")
        server_thread.start()
        _wait_for_health()
        assert runtime.bootstrap_url is not None

        protected_before = fixture_harness.original_inventory(layout.root)
        source_hash_before = fixture_harness.tree_sha256(worker_root)
        before_tasks = runtime.database.task_summaries(50)
        before_task_count = len(before_tasks)

        playwright = sync_playwright().start()
        try:
            browser = playwright.chromium.launch(
                executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                headless=True,
            )
            context = browser.new_context(viewport={"width": 1440, "height": 900})
            page = context.new_page()
            response = page.goto("http://localhost:8766/", wait_until="networkidle")
            assert response is not None and response.status == 200
            assert page.title() == "Document Tools"
            assert page.get_by_role("heading", name="Format a report").is_visible()
            assert page.get_by_role("button", name="Not available yet").is_disabled()
            website_text = page.locator("body").inner_text().casefold()
            assert "attack" not in website_text and "demo" not in website_text
            assert context.cookies("http://localhost:8766") == []
            assert page.evaluate("document.cookie") == ""
            (layout.raw_evidence_root / "g3").mkdir(parents=True, exist_ok=True)
            page.screenshot(
                path=str(layout.raw_evidence_root / "g3" / "report-formatter-website.png"),
                full_page=True,
            )
            approval_href = page.get_by_role("link", name="Continue to review").get_attribute(
                "href"
            )
            assert approval_href == (
                "http://127.0.0.1:8765/approve?tool_id=report_formatter"
                "&launch_source_claim=document_tools"
            )

            page.goto(runtime.bootstrap_url, wait_until="domcontentloaded")
            page.wait_for_url("http://127.0.0.1:8765/owner", timeout=10_000)
            owner_cookie = next(
                cookie
                for cookie in context.cookies("http://127.0.0.1:8765")
                if cookie["name"] == OWNER_SESSION_COOKIE
            )
            test_owner_session_sha256 = hashlib.sha256(
                owner_cookie["value"].encode("ascii", errors="strict")
            ).hexdigest()
            assert page.get_by_role("heading", name="Workspace").is_visible()
            invoice_action = page.get_by_role("button", name="Invoice Analyzer unavailable")
            invoice_action.wait_for(state="visible", timeout=10_000)
            assert invoice_action.is_disabled()
            page.goto("http://localhost:8766/", wait_until="networkidle")
            page.get_by_role("link", name="Continue to review").click()
            page.wait_for_url(approval_href, timeout=10_000)
            assert page.get_by_text("Nothing starts when this page opens.").is_visible()
            tasks_after_approval_get = runtime.database.task_summaries(50)
            task_count_after_approval_get = len(tasks_after_approval_get)
            assert task_count_after_approval_get == before_task_count
            assert tasks_after_approval_get == before_tasks
            assert runtime.database.tasks_in_progress() == ()
            assert page.get_by_role("button", name="Approve and open").is_enabled()
            with page.expect_response(
                lambda response: response.url == "http://127.0.0.1:8765/api/tasks"
                and response.request.method == "POST",
                timeout=120_000,
            ) as launch_response:
                page.get_by_role("button", name="Approve and open").click()
            assert launch_response.value.status == 201, (
                "the authenticated approval request did not create a task "
                f"(HTTP {launch_response.value.status})"
            )
            page.wait_for_url("http://127.0.0.1:8765/owner", timeout=10_000)
            protected_task_text = page.evaluate('sessionStorage.getItem("aclais:selectedTaskId")')
            assert type(protected_task_text) is str and protected_task_text
            protected_task_id = _parse_uuid(protected_task_text)
            protected_task = _wait_for_terminal_task(runtime, protected_task_id)

            assert protected_task.revocation_cause == RevocationCause.POLICY_DENIED
            assert protected_task.terminal_cause.value == "POLICY_DENIED"
            assert protected_task.status in {TaskStatus.BLOCKED, TaskStatus.FAILED}
            assert protected_task.worker_pid is not None
            assert protected_task.worker_sid == layout.worker_sid
            process_creation_time = runtime.database.worker_process_creation_time(protected_task_id)
            assert process_creation_time is not None
            assert protected_worker_controller.verify_stored_process_stopped(
                protected_task.worker_pid,
                process_creation_time,
                protected_task.worker_sid,
            )

            broker_events = [
                event
                for event in runtime.database.events(protected_task_id)
                if event.source == "broker"
            ]
            protected_operations = [
                {
                    "operation": event.operation,
                    "decision": event.decision,
                    "reason_code": event.reason_code,
                }
                for event in broker_events
            ]
            assert [(event["operation"], event["decision"]) for event in protected_operations] == [
                ("read_document", "allow"),
                ("publish_output", "allow"),
                ("replace_original", "deny"),
            ]
            assert protected_operations[-1]["reason_code"] == "ORIGINAL_MUTATION_FORBIDDEN"
            protected_after = fixture_harness.original_inventory(layout.root)
            assert protected_after == protected_before
            assert fixture_harness.tree_sha256(worker_root) == source_hash_before
            assert source_hash_before == worker_tree_sha256
            evidence_response = runtime.database.evidence_response(protected_task_id)
            evidence = evidence_response.report
            assert evidence_response.status == "complete" and evidence is not None
            assert evidence.integrity_status == "pass"
            assert evidence.confidentiality_status in {"pass", "unknown"}
            assert evidence.receiver_status in {"pass", "unknown"}
            assert evidence.overall_status in {"pass", "unknown"}
            assert evidence.selected_input_sha256_before == baseline_selected_sha256
            protected_observations = _load_persisted_worker_observations(
                layout.raw_evidence_root,
                protected_task_id,
                evidence.report_id,
            )
            _verify_protected_denials(protected_observations)
            assert evidence.worker_termination_confirmed
            assert evidence.worker_identity_recorded
            assert evidence.controller_process_observation is not None
            assert evidence.controller_process_observation.process_tree_stopped
            assert evidence.controller_process_observation.assigned_to_job_before_resume

            outputs = runtime.database.outputs_for_task(protected_task_id)
            assert len(outputs) == 1 and outputs[0].state == "published"
            published_metadata, published_content = runtime.output_publisher.read_published(
                outputs[0].output_id
            )
            assert published_metadata.output_kind == "formatted_markdown"
            assert b"## Contents" in published_content
            page.locator(".output-preview pre").filter(has_text="## Contents").wait_for(
                state="visible", timeout=15_000
            )
            assert page.get_by_text("Formatted report", exact=True).is_visible()

            logout_status = page.evaluate(
                """async () => {
                  const pair = document.cookie.split('; ').find(
                    x => x.startsWith('aclais_owner_csrf=')
                  );
                  if (!pair) return 0;
                  const token = pair.slice(pair.indexOf('=') + 1);
                  const response = await fetch('/api/owner/session/logout', {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'X-CSRF-Token': decodeURIComponent(token) }
                  });
                  return response.status;
                }"""
            )
            assert logout_status == 200
        finally:
            active_error = sys.exception()
            cleanup_errors = []
            context_to_close, browser_to_close = context, browser
            playwright_to_stop = playwright
            context = None
            browser = None
            playwright = None
            for resource_name, resource in (
                ("browser context", context_to_close),
                ("browser", browser_to_close),
            ):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception as error:
                        cleanup_errors.append(f"{resource_name}: {type(error).__name__}")
            try:
                playwright_to_stop.stop()
            except Exception as error:
                cleanup_errors.append(f"Playwright: {type(error).__name__}")
            if cleanup_errors:
                cleanup_message = "G3 browser cleanup failed: " + "; ".join(cleanup_errors)
                if active_error is not None:
                    active_error.add_note(cleanup_message)
                else:
                    raise AssertionError(cleanup_message)

        raw_report = {
            "schema_version": 1,
            "checkpoint": "G3_REPORT_FORMATTER",
            "created_at_utc": datetime.now(UTC).isoformat(),
            "tested_source_digest_sha256": _source_digest_sha256(REPOSITORY_ROOT),
            "worker_tree_sha256_baseline": worker_tree_sha256,
            "worker_source_tree_sha256": worker_source_tree_sha256,
            "worker_tree_sha256_protected_before": source_hash_before,
            "worker_tree_sha256_protected_after": fixture_harness.tree_sha256(worker_root),
            "worker_sid": layout.worker_sid,
            "worker_is_administrator": False,
            "baseline": {
                "task_id": str(baseline_task_id),
                "process_id": baseline_result.pid,
                "process_tree_stopped": baseline_result.process_tree_stopped,
                "worker_sid": baseline_result.worker_sid,
                "exit_code": baseline_result.exit_code,
                "operations": [item["operation"] for item in baseline_operations],
                "stdout_observations": baseline_observations,
                "original_inventory_before": baseline_before,
                "original_inventory_after": baseline_after,
                "output_sha256": baseline_output_sha256,
                "output_bytes": baseline_output_bytes,
                "selected_input_sha256": baseline_selected_sha256,
                "useful_output_content_verified": True,
            },
            "protected": {
                "task_id": str(protected_task_id),
                "status": protected_task.status.value,
                "revocation_cause": protected_task.revocation_cause.value,
                "terminal_cause": protected_task.terminal_cause.value,
                "worker_pid": protected_task.worker_pid,
                "worker_sid": protected_task.worker_sid,
                "process_creation_time_100ns": process_creation_time,
                "process_stopped_independently": True,
                "broker_events": protected_operations,
                "stdout_observations": protected_observations,
                "original_inventory_before": protected_before,
                "original_inventory_after": protected_after,
                "evidence_report_id": str(evidence.report_id),
                "evidence_overall_status": evidence.overall_status,
                "evidence_integrity_status": evidence.integrity_status,
                "evidence_confidentiality_status": evidence.confidentiality_status,
                "evidence_receiver_status": evidence.receiver_status,
                "evidence_worker_termination_confirmed": evidence.worker_termination_confirmed,
                "evidence_process_tree_stopped": (
                    evidence.controller_process_observation.process_tree_stopped
                ),
                "evidence_assigned_to_job_before_resume": (
                    evidence.controller_process_observation.assigned_to_job_before_resume
                ),
                "output_id": str(published_metadata.output_id),
                "output_bytes": len(published_content),
                "output_sha256": published_metadata.sha256,
                "useful_output_content_verified": b"## Contents" in published_content,
            },
            "approval_get_task_count_before": before_task_count,
            "approval_get_task_count_after": task_count_after_approval_get,
            "owner_approval_action_observed": True,
            "document_tools_cookie_count": 0,
        }
        raw_dir = layout.raw_evidence_root / "g3"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_path = raw_dir / f"report-formatter-{uuid4().hex}.json"
        _write_private_json(raw_path, raw_report)

    finally:
        active_error = sys.exception()
        cleanup_errors = []

        def attempt_cleanup(name: str, operation) -> None:
            try:
                operation()
            except Exception as error:
                cleanup_errors.append(f"{name}: {type(error).__name__}")

        if context is not None:
            attempt_cleanup("browser context", context.close)
        if browser is not None:
            attempt_cleanup("browser", browser.close)
        if playwright is not None:
            attempt_cleanup("Playwright", playwright.stop)
        if uvicorn_server is not None:
            attempt_cleanup(
                "owner API shutdown request",
                lambda: setattr(uvicorn_server, "should_exit", True),
            )
        if runtime is not None:
            attempt_cleanup("controller shutdown", runtime.lifecycle.shutdown)

        def revoke_test_owner_session() -> None:
            if runtime is None or test_owner_session_sha256 is None:
                return
            record = runtime.database.owner_session(test_owner_session_sha256)
            if record is not None and record.revoked_at is None:
                runtime.database.revoke_owner_session(
                    test_owner_session_sha256, now=runtime.owner_auth.now()
                )

        if test_owner_session_sha256 is not None:
            attempt_cleanup("test owner session", revoke_test_owner_session)

        def join_owner_api() -> None:
            if server_thread is not None:
                server_thread.join(timeout=20)
                if server_thread.is_alive():
                    raise AssertionError("owner API thread remained alive")

        if server_thread is not None:
            attempt_cleanup("owner API thread", join_owner_api)

        def require_no_active_task() -> None:
            if runtime is not None and runtime.database.tasks_in_progress():
                raise AssertionError("controller cleanup left a nonterminal task")

        if runtime is not None:
            attempt_cleanup("terminal task reconciliation", require_no_active_task)
        if website is not None:
            attempt_cleanup("Document Tools site", website.close)
        if not controller._shutdown:
            attempt_cleanup("private worker controller", controller.shutdown)
        if fixture_root.exists():
            attempt_cleanup(
                "disposable fixture cleanup",
                lambda: _remove_disposable_fixture(fixture_root, layout.output_root),
            )
        if cleanup_errors:
            cleanup_message = "G3 test cleanup failed: " + "; ".join(cleanup_errors)
            if active_error is not None:
                active_error.add_note(cleanup_message)
            else:
                raise AssertionError(cleanup_message)

    assert raw_report is not None


def _worker_configuration(
    harness,
    *,
    task_id,
    fixture_root,
    root_id,
    temporary_output,
    worker_credential,
):
    payload = harness.build_worker_configuration(
        task_id=str(task_id),
        fixture_root=fixture_root,
        root_id=root_id,
        temporary_output=temporary_output,
        broker_url="http://127.0.0.1:8765/api/broker/operations",
        worker_credential=worker_credential,
    )
    return DocumentToolsWorkerConfiguration.model_validate_json(json.dumps(payload))


def _source_worker_selected_sha256(root: Path) -> str:
    path = root / "store" / "originals" / "project-report.md"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _worker_source_tree_sha256(root: Path) -> str:
    relatives = (
        "src/document_tools/__init__.py",
        "src/document_tools/broker.py",
        "src/document_tools/worker.py",
        "workers/report_formatter/entrypoint.py",
    )
    digest = hashlib.sha256()
    for relative in relatives:
        path = root / "document-tools" / relative
        content = path.read_bytes()
        encoded_relative = relative.encode("utf-8")
        digest.update(len(encoded_relative).to_bytes(4, "big"))
        digest.update(encoded_relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _load_persisted_worker_observations(raw_root: Path, task_id, report_id):
    path = raw_root / str(task_id) / f"{report_id}.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise AssertionError("protected worker evidence artifact is unavailable")
    artifact = json.loads(path.read_text(encoding="utf-8"))
    lines = artifact.get("worker_observations")
    if not isinstance(lines, list):
        raise AssertionError("persisted worker observations are missing")
    return [json.loads(line["text"]) for line in lines if line.get("channel") == "stdout"]


def _ephemeral_token() -> str:
    import secrets

    return secrets.token_urlsafe(48)


def _parse_uuid(value: str):
    from uuid import UUID

    return UUID(value)


def _require_loopback_ports_free(ports: tuple[int, ...]) -> None:
    for port in ports:
        for host in ("127.0.0.1", "::1"):
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                if probe.connect_ex((host, port)) == 0:
                    raise AssertionError("a required G3 loopback port is already in use")


def _worker_observations(lines) -> list[dict[str, object]]:
    return [json.loads(line.text) for line in lines if line.channel == "stdout"]


def _verify_baseline_effects(before, after, observations) -> None:
    before_by_name = {str(item["path"]): item for item in before}
    after_by_name = {str(item["path"]): item for item in after}
    assert (
        before_by_name["project-report.md"]["sha256"]
        != after_by_name["project-report.md"]["sha256"]
    )
    assert after_by_name["meeting-notes.md"]["exists"] is False
    assert before_by_name["meeting-notes.md"]["exists"] is True
    assert before_by_name["invoice.csv"] == after_by_name["invoice.csv"]
    assert before_by_name["Personnel_Private.csv"] == after_by_name["Personnel_Private.csv"]
    direct = [item for item in observations if item.get("kind") == "direct_attempt"]
    assert [(item["operation"], item["result"]) for item in direct] == [
        ("overwrite", "succeeded"),
        ("delete", "succeeded"),
    ]
    kinds = [item.get("kind") for item in observations]
    assert kinds.index("useful_output_published") < kinds.index("direct_attempt")
    assert kinds.index("broker_denial_observed") > max(
        index for index, kind in enumerate(kinds) if kind == "direct_attempt"
    )


def _verify_protected_denials(observations) -> None:
    direct = [item for item in observations if item.get("kind") == "direct_attempt"]
    assert [(item["operation"], item["result"]) for item in direct] == [
        ("overwrite", "denied"),
        ("delete", "denied"),
    ]
    assert all(
        item.get("error_type") == "PermissionError"
        and item.get("errno") == errno.EACCES
        and (
            type(item.get("winerror")) is int and item.get("winerror") == 5
            or item.get("winerror") is None and item.get("errno") == errno.EACCES
        )
        for item in direct
    )
    kinds = [item.get("kind") for item in observations]
    assert kinds.index("useful_output_published") < kinds.index("direct_attempt")
    assert [item["target"] for item in direct] == [
        "store/originals/project-report.md",
        "store/originals/meeting-notes.md",
    ]


def _wait_for_terminal_task(runtime, task_id):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        task = runtime.database.get_task(task_id)
        if task is not None and task.status in {
            TaskStatus.COMPLETED,
            TaskStatus.BLOCKED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }:
            return task
        time.sleep(0.1)
    raise AssertionError("the approved Report Formatter task did not reach a terminal state")


def _wait_for_health() -> None:
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8765/api/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.1)
    raise AssertionError("the local ACLAIS owner API did not become ready")


def _remove_disposable_fixture(path: Path, allowed_parent: Path) -> None:
    resolved = path.resolve(strict=True)
    resolved.relative_to(allowed_parent.resolve(strict=True))
    if path.is_symlink() or not path.name.startswith(".g3-formatter-baseline-"):
        raise AssertionError("refusing to remove an unexpected G3 fixture path")
    shutil.rmtree(resolved)


def _write_private_json(path: Path, value: dict[str, object]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    temporary = path.with_suffix(".tmp")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _source_digest_sha256(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=True,
    )
    prefixes = (
        "aclais/",
        "receiver/",
        "document-tools/",
        "shared/",
        "tests/",
        "scripts/",
        ".github/workflows/",
    )
    allowed_suffixes = {
        ".py",
        ".sql",
        ".ps1",
        ".ts",
        ".tsx",
        ".css",
        ".html",
        ".json",
        ".toml",
        ".lock",
        ".yml",
        ".yaml",
        ".js",
        ".csv",
        ".md",
    }
    selected = []
    for relative in sorted(set(result.stdout.decode().split("\0"))):
        if not relative.startswith(prefixes):
            continue
        path = root / relative
        if path.is_file() and path.suffix.lower() in allowed_suffixes:
            digest = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            selected.append((relative, digest))
    manifest = "".join(f"{relative}\0{digest}\n" for relative, digest in selected).encode()
    return hashlib.sha256(manifest).hexdigest()
