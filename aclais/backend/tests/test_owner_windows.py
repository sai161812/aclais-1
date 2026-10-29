from __future__ import annotations

import json
import os
import socket
import threading
import time
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
from aclais.persistence.models import CreateTaskRequest, TaskStatus
from aclais.publication import OutputPublisher

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


def _build_private_approval_runtime():
    settings = Settings()
    layout = RuntimeLayout.open()
    workspace = TaskWorkspace(layout)
    workspace.prepare_roots()
    database = Database(layout.root / "state" / "controller.sqlite3")
    publisher = OutputPublisher(database, layout.verified_output_root)
    launcher = WindowsWorkerController(layout)
    verifier = FixtureVerifier(
        database,
        layout.root / "store",
        layout.raw_evidence_root,
        expected_fixtures=layout.fixture_hashes,
    )
    lifecycle = LifecycleCoordinator(
        layout,
        database,
        publisher,
        launcher=launcher,
        workspace=workspace,
        verifier=verifier,
    )
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
        return lifecycle.start_private_probe(
            "http://127.0.0.1:8765/api/broker/operations",
            request=request,
            deadline_seconds=20,
            probe_case="child_wait",
            broker_probe="allow_and_publish",
            use_trusted_document=True,
            observed_origin=observed_origin,
            observed_referer=observed_referer,
        )

    application = create_app(
        settings,
        broker=lifecycle.broker,
        output_publisher=publisher,
        owner_auth=auth,
        cancel_task=lifecycle.cancel,
        approved_task_launcher=private_probe_launcher,
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
        assert page.get_by_text("Owner session active").is_visible()

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
        assert page.get_by_role("heading", name="Review task permissions").is_visible()
        assert page.get_by_role("heading", name="Contract to approve").is_visible()
        assert page.locator("#document option").count() == 1
        assert page.locator("#document").input_value() == "doc-report"
        assert "Observed referrer origin" in page.locator("body").inner_text()
        assert (
            "Other documents and original-file changes are not permitted."
            in page.locator("body").inner_text()
        )
        assert "http://localhost:8766" in page.locator("body").inner_text()
        assert len(database.task_summaries()) == before_tasks

        page.get_by_role("button", name="Approve and open").click()
        status_node = page.locator("#status")
        status_text = ""
        approval_deadline = time.monotonic() + 10
        while time.monotonic() < approval_deadline:
            status_text = status_node.inner_text()
            if status_text != "No task starts until you select Approve and open.":
                break
            time.sleep(0.1)
        assert status_text.startswith("Task "), status_text
        task_id = status_text.removeprefix("Task ").removesuffix(" accepted.")
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
