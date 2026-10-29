from __future__ import annotations

import asyncio
import html
import json
import secrets
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from uuid import UUID

import pytest
from starlette.types import ASGIApp, Message, Scope

from aclais.app import create_app
from aclais.config import Settings
from aclais.owner_auth import OWNER_CSRF_COOKIE, OWNER_SESSION_COOKIE, OwnerAuth
from aclais.persistence.database import Database
from aclais.persistence.models import CreateTaskRequest
from aclais.tool_registry import FixedToolRegistry

pytestmark = pytest.mark.portable
NOW = datetime(2026, 10, 29, 8, 30, tzinfo=UTC)
TOKENS = tuple(secrets.token_urlsafe(32) for _ in range(8))


class _MainDataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.value: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "main":
            self.value = dict(attrs).get("data-approval")


def _asgi_request(
    application: ASGIApp,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    sent: list[Message] = []
    consumed = False
    if isinstance(headers, list):
        request_headers = [("host", "127.0.0.1:8765"), *headers]
    else:
        request_headers = list({"host": "127.0.0.1:8765", **(headers or {})}.items())
    path_only, _, query = path.partition("?")

    async def receive() -> Message:
        nonlocal consumed
        if consumed:
            return {"type": "http.disconnect"}
        consumed = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path_only,
        "raw_path": path_only.encode("ascii"),
        "query_string": query.encode("ascii"),
        "root_path": "",
        "headers": [
            (name.encode("ascii"), value.encode("latin-1")) for name, value in request_headers
        ],
        "client": ("127.0.0.1", 45678),
        "server": ("127.0.0.1", 8765),
    }
    asyncio.run(application(scope, receive, send))
    start = next(item for item in sent if item["type"] == "http.response.start")
    response_body = b"".join(
        item.get("body", b"") for item in sent if item["type"] == "http.response.body"
    )
    response_headers = [
        (name.decode("latin-1").lower(), value.decode("latin-1"))
        for name, value in start.get("headers", [])
    ]
    return start["status"], response_headers, response_body


def _cookie(headers: list[tuple[str, str]], name: str) -> str:
    for key, value in headers:
        if key == "set-cookie" and value.startswith(f"{name}="):
            return value.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError(f"missing {name} cookie")


def _fixture(tmp_path: Path, *, task_launcher=None, tool_registry=None):
    database = Database(tmp_path / "controller.sqlite3")
    token_iter = iter(TOKENS)
    auth = OwnerAuth(
        database,
        origin="http://127.0.0.1:8765",
        token_factory=lambda _nbytes: next(token_iter),
        now_factory=lambda: NOW,
    )
    app = create_app(
        Settings(),
        owner_auth=auth,
        approved_task_launcher=task_launcher,
        tool_registry=tool_registry,
    )
    bootstrap_url = auth.issue_bootstrap_url()
    assert bootstrap_url is not None
    return app, auth, database, bootstrap_url.rsplit("#", 1)[1]


def _exchange(app: ASGIApp, token: str, *, extra_headers: dict[str, str] | None = None):
    body = json.dumps({"schema_version": 1, "bootstrap_token": token}).encode()
    return _asgi_request(
        app,
        "POST",
        "/api/owner/bootstrap/exchange",
        body=body,
        headers={
            "origin": "http://127.0.0.1:8765",
            "sec-fetch-site": "same-origin",
            "content-type": "application/json",
            **(extra_headers or {}),
        },
    )


def _owner_headers(session: str, csrf: str, **extra: str) -> dict[str, str]:
    return {
        "cookie": f"{OWNER_SESSION_COOKIE}={session}; {OWNER_CSRF_COOKIE}={csrf}",
        "origin": "http://127.0.0.1:8765",
        "sec-fetch-site": "same-origin",
        "x-csrf-token": csrf,
        **extra,
    }


def _approval_context(body: bytes) -> str:
    parser = _MainDataParser()
    parser.feed(body.decode("utf-8"))
    assert parser.value is not None
    return json.loads(html.unescape(parser.value))["approval_context"]


def test_bootstrap_is_fragment_only_one_time_and_sets_host_only_cookies(tmp_path: Path) -> None:
    app, auth, database, token = _fixture(tmp_path)
    status, headers, body = _exchange(
        app,
        token,
        extra_headers={"cookie": f"{OWNER_SESSION_COOKIE}=attacker-fixed-value"},
    )
    assert status == 200
    assert token.encode() not in body
    session = _cookie(headers, OWNER_SESSION_COOKIE)
    assert _cookie(headers, OWNER_CSRF_COOKIE)
    session_cookie_header = next(
        value
        for key, value in headers
        if key == "set-cookie" and value.startswith(OWNER_SESSION_COOKIE)
    )
    assert "HttpOnly" in session_cookie_header
    assert "Domain=" not in session_cookie_header
    assert "Path=/" in session_cookie_header
    assert "SameSite=lax" in session_cookie_header
    assert session != "attacker-fixed-value"
    assert database.owner_session(auth._sha256(session)) is not None
    with database._connection() as connection:
        stored = " ".join(
            str(row[0])
            for row in connection.execute(
                "SELECT token_sha256 FROM owner_bootstrap UNION ALL "
                "SELECT session_sha256 FROM owner_sessions UNION ALL "
                "SELECT csrf_sha256 FROM owner_sessions"
            )
        )
    assert token not in stored
    assert session not in stored
    assert _cookie(headers, OWNER_CSRF_COOKIE) not in stored
    assert _exchange(app, token)[0] == 401


def test_expired_bootstrap_cannot_create_owner_session(tmp_path: Path) -> None:
    database = Database(tmp_path / "expired-bootstrap.sqlite3")
    auth = OwnerAuth(
        database,
        origin="http://127.0.0.1:8765",
        token_factory=lambda _nbytes: secrets.token_urlsafe(32),
        now_factory=lambda: NOW,
    )
    bootstrap_url = auth.issue_bootstrap_url()
    assert bootstrap_url is not None
    token = bootstrap_url.rsplit("#", 1)[1]
    expired = OwnerAuth(
        database,
        origin="http://127.0.0.1:8765",
        now_factory=lambda: NOW + timedelta(minutes=16),
    )
    assert expired.exchange_bootstrap(token) is None
    with database._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM owner_sessions").fetchone()[0] == 0


def test_owner_routes_reject_missing_expired_or_worker_credentials(tmp_path: Path) -> None:
    app, auth, _database, token = _fixture(tmp_path)
    status, headers, _ = _exchange(app, token)
    assert status == 200
    session = _cookie(headers, OWNER_SESSION_COOKIE)
    assert _asgi_request(app, "GET", "/api/documents")[0] == 401
    status, _, page = _asgi_request(
        app,
        "GET",
        "/approve?tool_id=report_formatter&launch_source_claim=document_tools",
    )
    assert status == 401
    assert b"Owner session required" in page
    assert _database.task_summaries() == ()
    assert (
        _asgi_request(
            app,
            "GET",
            "/api/owner/session",
            headers={"authorization": f"Bearer {secrets.token_urlsafe(32)}"},
        )[0]
        == 401
    )

    expired_auth = OwnerAuth(
        auth.database,
        origin="http://127.0.0.1:8765",
        token_factory=lambda _nbytes: TOKENS[4],
        now_factory=lambda: NOW + timedelta(hours=9),
    )
    expired_app = create_app(Settings(), owner_auth=expired_auth)
    assert (
        _asgi_request(
            expired_app,
            "GET",
            "/api/owner/session",
            headers={"cookie": f"{OWNER_SESSION_COOKIE}={session}"},
        )[0]
        == 401
    )


def test_owner_routes_reject_undeclared_query_parameters(tmp_path: Path) -> None:
    app, _auth, _database, token = _fixture(tmp_path)
    status, cookies, _ = _exchange(app, token)
    assert status == 200
    headers = _owner_headers(
        _cookie(cookies, OWNER_SESSION_COOKIE), _cookie(cookies, OWNER_CSRF_COOKIE)
    )
    assert _asgi_request(app, "GET", "/api/documents?path=arbitrary", headers=headers)[0] == 400
    assert (
        _asgi_request(app, "GET", "/api/owner/session?credential=worker", headers=headers)[0]
        == 400
    )


def test_host_origin_csrf_and_strict_executable_fields_fail_closed(tmp_path: Path) -> None:
    launches: list[object] = []

    def launch(
        request: CreateTaskRequest, observed_origin: str | None, observed_referer: str | None
    ):
        launches.append((request, observed_origin, observed_referer))
        return UUID("00000000-0000-4000-8000-000000000123")

    app, auth, database, token = _fixture(tmp_path, task_launcher=launch)
    status, headers, _ = _exchange(app, token)
    assert status == 200
    session, csrf = _cookie(headers, OWNER_SESSION_COOKIE), _cookie(headers, OWNER_CSRF_COOKIE)
    assert (
        _asgi_request(
            app,
            "GET",
            "/api/owner/session",
            headers={"host": "evil.example:8765", "cookie": f"{OWNER_SESSION_COOKIE}={session}"},
        )[0]
        == 400
    )
    assert (
        _asgi_request(
            app,
            "GET",
            "/api/owner/session",
            headers=[
                ("host", "127.0.0.1:8765"),
                ("host", "evil.example:8765"),
                ("cookie", f"{OWNER_SESSION_COOKIE}={session}"),
            ],
        )[0]
        == 400
    )

    mutation_body = json.dumps(
        {
            "schema_version": 1,
            "tool_id": "report_formatter",
            "selected_document_id": "doc-report",
            "launch_source_claim": "document_tools",
        }
    ).encode()
    status, _, page = _asgi_request(
        app,
        "GET",
        "/approve?tool_id=report_formatter&launch_source_claim=document_tools",
        headers={
            "cookie": f"{OWNER_SESSION_COOKIE}={session}",
            "referer": "http://localhost:8766/launch?ticket=discard-this",
        },
    )
    assert status == 200
    assert launches == []

    context = _approval_context(page)
    headers_for_action = _owner_headers(
        session,
        csrf,
        **{"x-aclais-approval-context": context},
    )

    assert (
        _asgi_request(
            app,
            "POST",
            "/api/tasks",
            body=mutation_body,
            headers={
                **headers_for_action,
                "origin": "http://localhost:8766",
                "content-type": "application/json",
            },
        )[0]
        == 403
    )
    assert (
        _asgi_request(
            app,
            "POST",
            "/api/tasks",
            body=mutation_body,
            headers={
                key: value for key, value in headers_for_action.items() if key != "x-csrf-token"
            }
            | {"content-type": "application/json"},
        )[0]
        == 403
    )
    forged = json.dumps(
        {
            "schema_version": 1,
            "tool_id": "report_formatter",
            "selected_document_id": "doc-report",
            "launch_source_claim": "document_tools",
            "executable": "calc.exe",
            "args": ["--anything"],
        }
    ).encode()
    assert (
        _asgi_request(
            app,
            "POST",
            "/api/tasks",
            body=forged,
            headers={**headers_for_action, "content-type": "application/json"},
        )[0]
        == 422
    )
    assert launches == []


def test_missing_fixed_worker_fails_closed_without_creating_a_task(tmp_path: Path) -> None:
    launches: list[object] = []
    app, _auth, database, token = _fixture(
        tmp_path,
        task_launcher=lambda *args: launches.append(args),
        tool_registry=FixedToolRegistry(tmp_path / "protected-install"),
    )
    status, cookies, _ = _exchange(app, token)
    assert status == 200
    session = _cookie(cookies, OWNER_SESSION_COOKIE)
    csrf = _cookie(cookies, OWNER_CSRF_COOKIE)
    status, _, approval = _asgi_request(
        app,
        "GET",
        "/approve?tool_id=report_formatter&launch_source_claim=document_tools",
        headers={"cookie": f"{OWNER_SESSION_COOKIE}={session}"},
    )
    assert status == 200
    context = _approval_context(approval)
    body = json.dumps(
        {
            "schema_version": 1,
            "tool_id": "report_formatter",
            "selected_document_id": "doc-report",
            "launch_source_claim": "document_tools",
        }
    ).encode()
    status, _, _ = _asgi_request(
        app,
        "POST",
        "/api/tasks",
        body=body,
        headers={
            **_owner_headers(session, csrf, **{"x-aclais-approval-context": context}),
            "content-type": "application/json",
        },
    )
    assert status == 503
    assert database.task_summaries() == ()
    assert launches == []


def test_explicit_authenticated_approval_records_claim_separately_from_observation(
    tmp_path: Path,
) -> None:
    calls: list[tuple[CreateTaskRequest, str | None, str | None]] = []
    database = Database(tmp_path / "controller.sqlite3")

    def launch(
        request: CreateTaskRequest, observed_origin: str | None, observed_referer: str | None
    ):
        calls.append((request, observed_origin, observed_referer))
        return database.create_task(
            request,
            now=NOW,
            observed_origin=observed_origin,
            observed_referer=observed_referer,
        ).task_id

    app, auth, _database, token = _fixture(tmp_path, task_launcher=launch)
    status, headers, _ = _exchange(app, token)
    assert status == 200
    session, csrf = _cookie(headers, OWNER_SESSION_COOKIE), _cookie(headers, OWNER_CSRF_COOKIE)
    status, _, page = _asgi_request(
        app,
        "GET",
        "/approve?tool_id=report_formatter&launch_source_claim=document_tools",
        headers={
            "cookie": f"{OWNER_SESSION_COOKIE}={session}",
            "referer": "http://localhost:8766/formatter?user=ignored",
        },
    )
    assert status == 200
    assert calls == []
    context = _approval_context(page)
    request_body = json.dumps(
        {
            "schema_version": 1,
            "tool_id": "report_formatter",
            "selected_document_id": "doc-report",
            "launch_source_claim": "document_tools",
        }
    ).encode()
    status, _, response = _asgi_request(
        app,
        "POST",
        "/api/tasks",
        body=request_body,
        headers={
            **_owner_headers(session, csrf, **{"x-aclais-approval-context": context}),
            "content-type": "application/json",
        },
    )
    assert status == 201
    assert len(calls) == 1
    task = database.get_task(json.loads(response)["task_id"])
    assert task is not None
    assert task.launch_source_claim == "document_tools"
    assert task.observed_origin is None
    assert task.observed_referer == "http://localhost:8766"
    assert calls[0][2] == "http://localhost:8766"
    assert auth.authenticate(_request_with_cookie(OWNER_SESSION_COOKIE, session)) is not None
    replay_status, _, _ = _asgi_request(
        app,
        "POST",
        "/api/tasks",
        body=request_body,
        headers={
            **_owner_headers(session, csrf, **{"x-aclais-approval-context": context}),
            "content-type": "application/json",
        },
    )
    assert replay_status == 403
    assert len(calls) == 1


def test_logout_revokes_session_and_invalid_host_is_rejected(tmp_path: Path) -> None:
    app, _auth, _database, token = _fixture(tmp_path)
    status, headers, _ = _exchange(app, token)
    assert status == 200
    session, csrf = _cookie(headers, OWNER_SESSION_COOKIE), _cookie(headers, OWNER_CSRF_COOKIE)
    status, _, _ = _asgi_request(
        app,
        "POST",
        "/api/owner/session/logout",
        headers=_owner_headers(session, csrf),
    )
    assert status == 200
    assert (
        _asgi_request(
            app,
            "GET",
            "/api/owner/session",
            headers={"cookie": f"{OWNER_SESSION_COOKIE}={session}"},
        )[0]
        == 401
    )


def _request_with_cookie(name: str, value: str):
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/owner/session",
        "headers": [(b"cookie", f"{name}={value}".encode("ascii"))],
    }
    return Request(scope)
