from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from aclais.app import create_app
from aclais.config import Settings
from aclais.evidence import FixtureVerifier
from aclais.launcher.windows import RuntimeLayout, WindowsWorkerController
from aclais.lifecycle import LifecycleCoordinator, TaskWorkspace
from aclais.owner_auth import OWNER_SESSION_COOKIE, OwnerAuth
from aclais.persistence.database import Database
from aclais.persistence.models import CreateTaskRequest, RevocationCause, TaskStatus
from aclais.publication import OutputPublisher
from aclais.readiness import Readiness

pytestmark = pytest.mark.windows_enforcement

_COOKIE_OBSERVATIONS: list[tuple[str, str | None]] = []
_COOKIE_LOCK = threading.Lock()


class _PrivateHostHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        with _COOKIE_LOCK:
            _COOKIE_OBSERVATIONS.append((self.path, self.headers.get("Cookie")))
        if self.path == "/":
            body = (
                b"<!doctype html><a id='open' href='http://127.0.0.1:8765/approve?"
                b"tool_id=report_formatter&amp;"
                b"launch_source_claim=document_tools'>Open securely</a>"
            )
            content_type = "text/html; charset=utf-8"
        else:
            body = b"private loopback probe"
            content_type = "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _IPv6LoopbackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class _ObservedApp:
    def __init__(self, application: Any) -> None:
        self.application = application
        self.requests: list[dict[str, str]] = []
        self.lock = threading.Lock()

    async def __call__(self, scope, receive, send) -> None:
        observation = None
        if scope["type"] == "http" and scope.get("path") in {
            "/api/owner/session",
            "/api/tasks",
            "/approve",
        }:
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope.get("headers", [])
            }
            observation = {
                "path": scope["path"],
                "method": scope["method"],
                "cookie": headers.get("cookie", ""),
                "origin": headers.get("origin", ""),
                "referer": headers.get("referer", ""),
                "status": "",
            }
            with self.lock:
                self.requests.append(observation)

        async def observed_send(message) -> None:
            if observation is not None and message.get("type") == "http.response.start":
                observation["status"] = str(message["status"])
            await send(message)

        await self.application(scope, receive, observed_send)


def _start_http_server(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, name="aclais-private-host", daemon=True)
    thread.start()
    return thread


def _wait_for_server(server: uvicorn.Server, thread: threading.Thread) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and thread.is_alive() and not server.started:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("private ACLAIS test server did not start")


def _build_private_approval_runtime(
    probe_modes_by_tool: dict[str, tuple[str, str]] | None = None,
    hold_policy_verification: bool = False,
):
    settings = Settings()
    layout = RuntimeLayout.open()
    namespace = uuid.uuid4().hex
    layout = replace(
        layout, verified_output_root=(layout.root / "work" / "private-browser-output" / namespace)
    )
    layout.verified_output_root.parent.mkdir(exist_ok=True)
    workspace = TaskWorkspace(layout)
    workspace.prepare_roots()
    database = Database(layout.root / "state" / f"a9-private-{namespace}.sqlite3")
    publisher = OutputPublisher(database, layout.verified_output_root)
    launcher = WindowsWorkerController(layout)
    verifier = FixtureVerifier(
        database,
        layout.root / "store",
        layout.raw_evidence_root,
        expected_fixtures=layout.fixture_hashes,
    )
    verification_gate = threading.Event()
    if hold_policy_verification:
        verify = verifier.verify_after_termination

        def delayed_verify(*args, **kwargs):
            task = args[0] if args else kwargs.get("task")
            cause = getattr(task, "revocation_cause", None)
            if cause == RevocationCause.POLICY_DENIED:
                if not verification_gate.wait(timeout=60):
                    raise TimeoutError("private UI verification gate was not released")
            return verify(*args, **kwargs)

        verifier.verify_after_termination = delayed_verify
    lifecycle = LifecycleCoordinator(
        layout,
        database,
        publisher,
        launcher=launcher,
        workspace=workspace,
        verifier=verifier,
    )
    lifecycle._private_verification_gate = verification_gate
    lifecycle.recover_before_serving()
    auth = OwnerAuth(database, origin=settings.expected_origin)
    bootstrap_url = auth.issue_bootstrap_url()
    if bootstrap_url is None:
        raise RuntimeError("a prior owner session is still active; log out before this probe")

    def private_probe_launcher(
        request: CreateTaskRequest,
        observed_origin: str | None,
        observed_referer: str | None,
    ):
        probe_case, broker_probe = (probe_modes_by_tool or {}).get(
            request.tool_id, ("child_wait", "allow_and_publish")
        )
        try:
            return lifecycle.start_private_probe(
                "http://127.0.0.1:8765/api/broker/operations",
                request=request,
                deadline_seconds=20,
                probe_case=probe_case,
                broker_probe=broker_probe,
                use_trusted_document=True,
                observed_origin=observed_origin,
                observed_referer=observed_referer,
            )
        except Exception as exc:
            application.state.private_probe_launch_exception = type(exc).__name__
            raise

    def private_cancel(task_id):
        try:
            return lifecycle.cancel(task_id)
        except Exception as exc:
            application.state.private_cancel_exception = type(exc).__name__
            raise

    health_readiness = Readiness(layout)
    application = create_app(
        settings,
        broker=lifecycle.broker,
        output_publisher=publisher,
        owner_auth=auth,
        cancel_task=private_cancel,
        approved_task_launcher=private_probe_launcher,
        frontend_dist=Path(__file__).resolve().parents[2] / "frontend" / "dist",
        health_provider=lambda: health_readiness.health(
            controller_accepting=lifecycle.accepting_tasks
        ),
    )
    application.router.add_event_handler("shutdown", lifecycle.shutdown)
    return application, lifecycle, database, auth, bootstrap_url


@pytest.mark.parametrize(
    "browser_path",
    [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ],
    ids=["chrome", "edge"],
)
def test_real_browser_owner_isolation_and_authenticated_approval_launch(
    browser_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("A8 browser enforcement requires the Windows demonstration machine")
    if not browser_path.is_file():
        pytest.fail(f"Required installed browser is missing: {browser_path.name}")

    with _COOKIE_LOCK:
        _COOKIE_OBSERVATIONS.clear()
    app, lifecycle, database, auth, bootstrap_url = _build_private_approval_runtime()
    observed_app = _ObservedApp(app)
    config = uvicorn.Config(
        observed_app,
        host="127.0.0.1",
        port=8765,
        log_level="error",
        access_log=False,
        log_config=None,
        workers=1,
    )
    api_server = uvicorn.Server(config)
    api_thread = threading.Thread(target=api_server.run, name="aclais-a8-private-api", daemon=True)
    tools_v4 = ThreadingHTTPServer(("127.0.0.1", 8766), _PrivateHostHandler)
    tools_v6 = _IPv6LoopbackServer(("::1", 8766), _PrivateHostHandler)
    receiver_v6 = _IPv6LoopbackServer(("::1", 8767), _PrivateHostHandler)
    tool_threads = [
        _start_http_server(tools_v4),
        _start_http_server(tools_v6),
        _start_http_server(receiver_v6),
    ]
    task_id = None
    session_token = None
    from playwright.sync_api import sync_playwright

    browser: Any | None = None
    playwright = sync_playwright().start()
    try:
        api_thread.start()
        _wait_for_server(api_server, api_thread)
        before_tasks = len(database.task_summaries())
        browser = playwright.chromium.launch(executable_path=str(browser_path), headless=True)
        context = browser.new_context()
        page = context.new_page()
        try:
            page.goto(bootstrap_url, wait_until="networkidle")
        except Exception:
            pytest.fail(
                "One-time bootstrap navigation failed; URL details are withheld.", pytrace=False
            )
        page.wait_for_url("http://127.0.0.1:8765/owner", timeout=10_000)
        assert page.evaluate("window.location.hash") == ""
        assert page.get_by_role("heading", name="Workspace").is_visible()

        browser_cookies = context.cookies("http://127.0.0.1:8765")
        owner_cookie = next(
            cookie for cookie in browser_cookies if cookie["name"] == OWNER_SESSION_COOKIE
        )
        assert owner_cookie["httpOnly"] is True
        assert owner_cookie["domain"] == "127.0.0.1"
        session_token = owner_cookie["value"]
        assert all(cookie["domain"] != "localhost" for cookie in browser_cookies)

        page.goto("http://localhost:8766/", wait_until="networkidle")
        page.goto("http://localhost:8766/cookie", wait_until="networkidle")
        page.goto("http://[::1]:8767/probe", wait_until="networkidle")
        with _COOKIE_LOCK:
            tool_cookies = [
                cookie for path, cookie in _COOKIE_OBSERVATIONS if path in {"/", "/cookie"}
            ]
            receiver_cookies = [cookie for path, cookie in _COOKIE_OBSERVATIONS if path == "/probe"]
        assert tool_cookies and all(value is None for value in tool_cookies)
        assert receiver_cookies and all(value is None for value in receiver_cookies)

        page.goto("http://localhost:8766/", wait_until="networkidle")
        page.evaluate(
            """async () => await Promise.allSettled([
              fetch('http://127.0.0.1:8765/api/owner/session',
                { credentials: 'include' }),
              fetch('http://127.0.0.1:8765/api/tasks', {
                method: 'POST', credentials: 'include', mode: 'no-cors',
                headers: { 'Content-Type': 'text/plain' }, body: 'cross-origin probe'
              })
            ])"""
        )
        assert len(database.task_summaries()) == before_tasks
        with observed_app.lock:
            hostile_requests = [
                request
                for request in observed_app.requests
                if request["origin"] == "http://localhost:8766"
            ]
        assert any(item["path"] == "/api/owner/session" for item in hostile_requests)
        assert any(item["path"] == "/api/tasks" for item in hostile_requests)
        assert all(not item["cookie"] for item in hostile_requests)
        assert all(item["status"] == "401" for item in hostile_requests)

        page.goto("http://localhost:8766/", wait_until="networkidle")
        page.get_by_role("link", name="Open securely").click()
        page.wait_for_url("http://127.0.0.1:8765/approve?*", timeout=10_000)
        assert page.get_by_role("heading", name="Review and approve").is_visible()
        assert page.get_by_text("Permissions ACLAIS will enforce").is_visible()
        assert page.locator("#approval-document option").count() == 1
        assert page.locator("#approval-document").input_value() == "doc-report"
        assert "Observed referrer" in page.locator("body").inner_text()
        assert (
            "Other documents and original-file changes are prohibited."
            in page.locator("body").inner_text()
        )
        assert "http://localhost:8766" in page.locator("body").inner_text()
        assert len(database.task_summaries()) == before_tasks

        page.get_by_role("button", name="Approve and open").click()
        page.wait_for_url("http://127.0.0.1:8765/owner", timeout=10_000)
        page.wait_for_function("sessionStorage.getItem('aclais:selectedTaskId') !== null")
        task_id = page.evaluate("sessionStorage.getItem('aclais:selectedTaskId')")
        task = database.get_task(task_id)
        assert task is not None and task.status == TaskStatus.RUNNING
        assert task.launch_source_claim == "document_tools"
        assert task.selected_document_id == "doc-report"
        assert task.observed_referer == "http://localhost:8766"
        assert database.get_contract(task.task_id) is not None
        assert task.worker_sid is not None
        assert task.worker_pid is not None
        child_marker = (
            lifecycle.layout.task_output_root
            / str(task.task_id)
            / f"a3-{task.task_id.hex}.child.json"
        )
        marker_deadline = time.monotonic() + 10
        while time.monotonic() < marker_deadline and not child_marker.is_file():
            time.sleep(0.05)
        assert child_marker.is_file()
        child = json.loads(child_marker.read_text(encoding="utf-8"))
        assert child["in_job"] is True
        cancelled = lifecycle.cancel(task.task_id)
        assert cancelled.status == TaskStatus.CANCELLED
        task = lifecycle.wait(task.task_id, timeout=10)
        creation_time = database.worker_process_creation_time(task.task_id)
        assert creation_time is not None
        assert lifecycle.launcher.verify_stored_process_stopped(
            task.worker_pid, creation_time, task.worker_sid
        )
        assert lifecycle.launcher.verify_stored_process_stopped(
            child["pid"], child["creation_time_100ns"], task.worker_sid
        )
        assert database.evidence_response(task_id).status == "complete"

        csrf_cookie = next(
            cookie
            for cookie in context.cookies("http://127.0.0.1:8765")
            if cookie["name"] == "aclais_owner_csrf"
        )
        page.evaluate(
            """csrf => fetch('/api/owner/session/logout', {
              method: 'POST', credentials: 'same-origin',
              headers: { 'X-CSRF-Token': csrf }
            })""",
            csrf_cookie["value"],
        )
        page.wait_for_timeout(100)
        assert database.owner_session(auth._sha256(session_token)).revoked_at is not None
    finally:
        if session_token is not None:
            database.revoke_owner_session(auth._sha256(session_token), now=auth.now())
        for task in database.tasks_in_progress():
            if task.status == TaskStatus.RUNNING:
                lifecycle.cancel(task.task_id)
        api_server.should_exit = True
        if api_thread.is_alive():
            api_thread.join(timeout=10)
        if browser is not None and browser.is_connected():
            browser.close()
        playwright.stop()
        for server in (tools_v4, tools_v6, receiver_v6):
            server.shutdown()
            server.server_close()
        for thread in tool_threads:
            thread.join(timeout=5)


def test_a9_connected_dashboard_refresh_keyboard_and_visual_evidence() -> None:
    if os.name != "nt":
        pytest.skip("A9 visual and owner-session checks require the Windows demonstration machine")
    browser_path = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    if not browser_path.is_file():
        pytest.fail(f"Required installed browser is missing: {browser_path.name}")

    app, lifecycle, database, auth, bootstrap_url = _build_private_approval_runtime(
        {"invoice_analyzer": ("child_wait", "policy_denial")},
        hold_policy_verification=True,
    )
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=8765,
        log_level="error",
        access_log=False,
        log_config=None,
        workers=1,
    )
    api_server = uvicorn.Server(config)
    api_thread = threading.Thread(target=api_server.run, name="aclais-a9-private-api", daemon=True)
    task_ids: list[str] = []
    session_token = None
    from playwright.sync_api import sync_playwright

    browser: Any | None = None
    playwright = sync_playwright().start()
    screenshot_root = Path(__file__).resolve().parents[3] / "evidence" / "g1-visuals"
    screenshot_root.mkdir(parents=True, exist_ok=True)

    def capture(page, screen: str) -> None:
        for width, height in ((1366, 768), (1920, 1080)):
            page.set_viewport_size({"width": width, "height": height})
            page.screenshot(
                path=str(screenshot_root / f"{screen}-{width}x{height}.png"),
                full_page=False,
                animations="disabled",
            )
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    try:
        api_thread.start()
        _wait_for_server(api_server, api_thread)
        browser = playwright.chromium.launch(executable_path=str(browser_path), headless=True)
        context = browser.new_context(
            viewport={"width": 1366, "height": 768}, timezone_id="Asia/Kolkata"
        )
        page = context.new_page()
        external_requests: list[str] = []
        page_errors: list[str] = []
        console_errors: list[str] = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.on(
            "console",
            lambda message: (
                console_errors.append(message.text + str(message.location))
                if message.type == "error"
                else None
            ),
        )
        page.on(
            "request",
            lambda request: (
                external_requests.append(request.url)
                if not request.url.startswith("http://127.0.0.1:8765/")
                else None
            ),
        )
        page.goto(bootstrap_url, wait_until="networkidle")
        session_cookie = next(
            cookie
            for cookie in context.cookies("http://127.0.0.1:8765")
            if cookie["name"] == OWNER_SESSION_COOKIE
        )
        session_token = session_cookie["value"]
        page.wait_for_url("http://127.0.0.1:8765/owner", timeout=10_000)
        page.wait_for_selector(".document-card", state="visible", timeout=10_000)
        assert page.get_by_role("heading", name="Workspace").is_visible()
        assert page.get_by_text("Verification pending").first.is_visible()
        assert page.get_by_role("heading", name="Documents", exact=True).is_visible()
        capture(page, "workspace")

        report_action = page.get_by_role("button", name="Review Report Formatter approval")
        report_action.focus()
        page.keyboard.press("Enter")
        page.wait_for_url("http://127.0.0.1:8765/approve?*", timeout=10_000)
        assert page.get_by_role("heading", name="Review and approve").is_visible()
        assert page.locator("#approval-document").input_value() == "doc-report"
        assert page.locator(".approval-tool .status-badge").count() == 0
        assert "Source claim" in page.locator("body").inner_text()
        before_approval_tasks = database.task_summaries()
        capture(page, "approval")
        assert database.task_summaries() == before_approval_tasks

        approve_button = page.get_by_role("button", name="Approve and open")
        approve_button.focus()
        with page.expect_response("**/api/tasks") as approval_response:
            page.keyboard.press("Enter")
        response = approval_response.value
        launch_diagnostic = getattr(app.state, "private_probe_launch_exception", "none")
        assert response.status == 201, (
            f"approval endpoint returned {response.status}: {response.text()}; "
            f"private launch exception={launch_diagnostic}"
        )
        page.wait_for_url("http://127.0.0.1:8765/owner", timeout=10_000)
        page.wait_for_function("sessionStorage.getItem('aclais:selectedTaskId') !== null")
        task_id = page.evaluate("sessionStorage.getItem('aclais:selectedTaskId')")
        task_ids.append(task_id)
        page.wait_for_selector(".output-preview pre", state="visible", timeout=15_000)
        page.get_by_text("Synthetic broker output.", exact=False).wait_for(timeout=10_000)
        unsafe_preview_nodes = page.locator(
            ".output-preview script, .output-preview img, .output-preview iframe"
        )
        assert unsafe_preview_nodes.count() == 0
        running_task = database.get_task(task_id)
        assert running_task is not None and running_task.status == TaskStatus.RUNNING
        assert database.outputs_for_task(task_id)
        capture(page, "running")

        event_sequences = page.locator(".event-line").evaluate_all(
            "items => items.map(item => Number(item.dataset.eventSeq))"
        )
        assert event_sequences == sorted(set(event_sequences))
        assert event_sequences
        persisted_sequences = [event.seq for event in database.events(task_id)]
        assert event_sequences == persisted_sequences

        def slow_real_health(route) -> None:
            response = route.fetch()
            time.sleep(0.7)
            route.fulfill(response=response)

        page.route("**/api/health", slow_real_health)
        page.reload(wait_until="domcontentloaded")
        page.locator(".event-line").first.wait_for(state="visible", timeout=10_000)
        refreshed_sequences = page.locator(".event-line").evaluate_all(
            "items => items.map(item => Number(item.dataset.eventSeq))"
        )
        assert refreshed_sequences == persisted_sequences
        page.unroute("**/api/health")
        page.get_by_role("button", name="Activity").click()
        page.get_by_role("heading", name="Task history").wait_for(timeout=5_000)
        activity_sequences = page.locator(".event-line").evaluate_all(
            "items => items.map(item => Number(item.dataset.eventSeq))"
        )
        assert activity_sequences == persisted_sequences
        capture(page, "activity")
        assert console_errors == []
        page.get_by_role("button", name="Workspace", exact=True).click()
        page.get_by_role("heading", name="Workspace").wait_for(timeout=5_000)

        page.route("**/api/health", lambda route: route.abort())
        page.get_by_role("button", name="Refresh workspace").click()
        page.get_by_text("ACLAIS is disconnected").wait_for(timeout=5_000)
        capture(page, "disconnected")
        assert page.locator(".health-card.health-disconnected .health-tag").all_inner_texts() == [
            "OFFLINE",
            "OFFLINE",
        ], page.locator(".health-card").evaluate_all(
            "items => items.map(item => ({className: item.className, text: item.innerText}))"
        )
        assert page.locator(".live-tag").inner_text().strip() == "Connection lost"
        assert page.get_by_text("Live", exact=True).count() == 0
        page.unroute("**/api/health")
        page.get_by_role("button", name="Refresh workspace").click()
        page.get_by_text("Connected", exact=True).wait_for(timeout=5_000)
        assert page.get_by_text("Verification pending").first.is_visible()

        def failed_preflight(route) -> None:
            response = route.fetch()
            payload = response.json()
            payload["status"] = "unavailable"
            payload["protection_ready"] = False
            for check in payload["checks"]:
                if check["id"] == "g1_protection":
                    check["status"] = "fail"
                    check["summary"] = "Private UI mapping check."
            route.fulfill(response=response, json=payload)

        page.route("**/api/health", failed_preflight)
        page.get_by_role("button", name="Refresh workspace").click()
        page.get_by_text("Protection unavailable", exact=True).first.wait_for(timeout=5_000)
        assert page.locator(".health-card.health-unavailable .health-tag").all_inner_texts() == [
            "UNAVAILABLE",
            "UNAVAILABLE",
        ]
        page.unroute("**/api/health")
        page.get_by_role("button", name="Refresh workspace").click()
        page.get_by_text("Verification pending").first.wait_for(timeout=5_000)

        with page.expect_response("**/cancel") as cancellation_response:
            page.get_by_role("button", name="Stop task").click()
        cancellation = cancellation_response.value
        assert cancellation.status == 200, (
            f"cancellation endpoint returned {cancellation.status}; "
            f"private cancel exception={getattr(app.state, 'private_cancel_exception', 'none')}"
        )
        cancelled_status = cancellation.json()["status"]
        cancelled = lifecycle.wait(task_id, timeout=30)
        assert cancelled.status.value == cancelled_status
        assert cancelled.status == TaskStatus.CANCELLED
        creation_time = database.worker_process_creation_time(task_id)
        assert creation_time is not None and cancelled.worker_pid is not None
        assert lifecycle.launcher.verify_stored_process_stopped(
            cancelled.worker_pid, creation_time, cancelled.worker_sid
        )

        page.get_by_role("button", name="Workspace", exact=True).click()
        invoice_action = page.get_by_role("button", name="Review Invoice Analyzer approval")
        invoice_action.focus()
        page.keyboard.press("Enter")
        page.wait_for_url("http://127.0.0.1:8765/approve?*", timeout=10_000)
        assert page.locator("#approval-document").input_value() == "doc-invoice"
        invoice_approval = page.get_by_role("button", name="Approve and open")
        invoice_approval.focus()
        page.keyboard.press("Enter")
        page.wait_for_url("http://127.0.0.1:8765/owner", timeout=10_000)
        page.wait_for_function(
            "expected => sessionStorage.getItem('aclais:selectedTaskId') !== null && "
            "sessionStorage.getItem('aclais:selectedTaskId') !== expected",
            arg=task_id,
        )
        incident_task_id = page.evaluate("sessionStorage.getItem('aclais:selectedTaskId')")
        task_ids.append(incident_task_id)
        incident_record = database.get_task(incident_task_id)
        incident_deadline = time.monotonic() + 10
        while (
            incident_record is not None
            and incident_record.incident_id is None
            and time.monotonic() < incident_deadline
        ):
            time.sleep(0.05)
            incident_record = database.get_task(incident_task_id)
        assert incident_record is not None and incident_record.incident_id is not None
        api_incident = page.evaluate(
            "async taskId => { const response = await fetch(`/api/tasks/${taskId}`); "
            "return {status: response.status, body: await response.json()}; }",
            incident_task_id,
        )
        assert api_incident["status"] == 200, api_incident["body"].get("error", {}).get("code")
        assert api_incident["body"]["incident_summary"]["incident_id"] == str(
            incident_record.incident_id
        )
        page.reload(wait_until="domcontentloaded")
        page.wait_for_selector(".incident-callout", state="visible", timeout=10_000)
        assert any(
            event.source == "broker" and event.decision == "deny"
            for event in database.events(incident_task_id)
        )
        assert page.get_by_text("Broker denied operation", exact=True).is_visible()
        page.get_by_role("button", name="View details").click()
        dialog = page.get_by_role("dialog", name="Protection event")
        dialog.wait_for(state="visible", timeout=5_000)
        assert page.get_by_text("Independent verification", exact=True).is_visible()
        assert page.locator(".incident-banner strong").inner_text() == "Verification pending"
        assert database.evidence_response(incident_task_id).status == "pending"
        page.get_by_text(
            "The controller has not reported a completed verifier result.", exact=True
        ).wait_for(timeout=5_000)
        assert database.evidence_response(incident_task_id).status == "pending"
        capture(page, "verification-pending")

        lifecycle._private_verification_gate.set()
        incident_task = lifecycle.wait(incident_task_id, timeout=40)
        assert database.evidence_response(incident_task_id).status == "complete"
        page.locator(".evidence-check").first.wait_for(state="visible", timeout=10_000)
        evidence = database.evidence_response(incident_task_id)
        assert evidence.report is not None
        should_block = (
            evidence.report.overall_status == "pass"
            and evidence.report.integrity_status == "pass"
            and evidence.report.confidentiality_status == "pass"
        )
        expected_terminal = TaskStatus.BLOCKED if should_block else TaskStatus.FAILED
        assert incident_task.status == expected_terminal, (
            f"task status={incident_task.status.value}; overall={evidence.report.overall_status}; "
            f"integrity={evidence.report.integrity_status}; "
            f"confidentiality={evidence.report.confidentiality_status}; "
            f"containment={evidence.report.containment_status}; "
            f"termination={evidence.report.worker_termination_confirmed}; "
            f"checks={[(check.id, check.status, check.source) for check in evidence.report.checks]}"
        )
        screenshot_name = (
            "incident-verified"
            if evidence.report.overall_status == "pass"
            else "verification-incomplete"
        )
        capture(page, screenshot_name)
        context.grant_permissions(
            ["clipboard-read", "clipboard-write"], origin="http://127.0.0.1:8765"
        )
        page.get_by_role("button", name="Advanced evidence").click()
        assert "doc-private" in page.locator(".advanced-evidence").inner_text()
        page.get_by_role("button", name="Copy Task ID", exact=True).click()
        page.get_by_text("Task ID copied.", exact=True).wait_for(timeout=5_000)
        assert page.evaluate("navigator.clipboard.readText()") == incident_task_id
        page.get_by_role("button", name="Advanced evidence").click()
        page.get_by_role("button", name="Close incident details").focus()
        page.keyboard.press("Shift+Tab")
        assert page.get_by_role("button", name="Advanced evidence").evaluate(
            "element => element === document.activeElement"
        )
        page.keyboard.press("Escape")
        dialog.wait_for(state="hidden", timeout=5_000)
        page.get_by_role("button", name="View details").wait_for(state="visible")

        page.emulate_media(reduced_motion="reduce")
        page.get_by_role("button", name="View details").click()
        page.get_by_role("dialog", name="Protection event").wait_for(state="visible")
        page.set_viewport_size({"width": 1366, "height": 768})
        page.screenshot(
            path=str(screenshot_root / "incident-reduced-motion-1366x768.png"),
            full_page=False,
            animations="disabled",
        )
        assert external_requests == []
        assert page_errors == []

    finally:
        lifecycle._private_verification_gate.set()
        if session_token is not None:
            database.revoke_owner_session(auth._sha256(session_token), now=auth.now())
        for task_id in task_ids:
            try:
                task = database.get_task(task_id)
                if task and task.status == TaskStatus.RUNNING:
                    lifecycle.cancel(task.task_id)
                    lifecycle.wait(task.task_id, timeout=10)
            except Exception:
                pass
        api_server.should_exit = True
        if api_thread.is_alive():
            api_thread.join(timeout=10)
        if browser is not None and browser.is_connected():
            browser.close()
        playwright.stop()
