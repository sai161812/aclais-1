from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx2 as httpx
import pytest
from fastapi import Request
from starlette.types import ASGIApp, Message, Scope

from aclais.app import create_app
from aclais.broker import BrokerService
from aclais.config import Settings
from aclais.persistence.database import Database
from aclais.persistence.models import CreateTaskRequest, TaskStatus
from aclais.publication import OutputPublisher

pytestmark = pytest.mark.portable

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "a4-create-task-request.json"


def _harness(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    database = Database(root / "state.sqlite3")
    task = database.create_task(
        CreateTaskRequest.model_validate_json(FIXTURE.read_text(encoding="utf-8")),
        run_id=uuid4(),
        now=NOW,
    )
    database.transition_task(task.task_id, TaskStatus.PREPARING, now=NOW + timedelta(seconds=1))
    database.transition_task(task.task_id, TaskStatus.RUNNING, now=NOW + timedelta(seconds=2))
    token = secrets.token_urlsafe(32)
    database.create_credential_hash(
        task.task_id,
        hashlib.sha256(token.encode("ascii")).hexdigest(),
        created_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(seconds=20),
    )
    selected_root = root / "selected"
    selected_root.mkdir()
    task_root = selected_root / str(task.task_id)
    task_root.mkdir()
    (task_root / "doc-report.md").write_bytes(b"selected input\n")
    output_root = root / "verified-output"
    output_root.mkdir()
    publisher = OutputPublisher(database, output_root)
    broker = BrokerService(database, selected_root, publisher)
    return database, task, token, publisher, broker


def _asgi_request(
    application: ASGIApp,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    sent: list[Message] = []
    request_consumed = False
    request_headers = {"host": "127.0.0.1:8765", **(headers or {})}

    async def receive() -> Message:
        nonlocal request_consumed
        if request_consumed:
            return {"type": "http.disconnect"}
        request_consumed = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (name.encode("ascii"), value.encode("latin-1"))
            for name, value in request_headers.items()
        ],
        "client": ("127.0.0.1", 45678),
        "server": ("127.0.0.1", 8765),
    }
    asyncio.run(application(scope, receive, send))
    start = next(message for message in sent if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    response_headers = {
        name.decode("latin-1").lower(): value.decode("latin-1")
        for name, value in start.get("headers", [])
    }
    return start["status"], response_headers, response_body


def test_broker_http_route_uses_bearer_token_and_bounded_json_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, token, _, broker = _harness(tmp_path)
    monkeypatch.setattr("aclais.broker.utc_now", lambda: NOW + timedelta(seconds=3))
    app = create_app(Settings(), broker=broker)
    body = json.dumps(
        {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": "read_document",
            "document_id": "doc-report",
        }
    ).encode("utf-8")

    status, _, response = _asgi_request(
        app,
        "POST",
        "/api/broker/operations",
        body=body,
        headers={"authorization": f"Bearer {token}"},
    )
    assert status == 200
    assert json.loads(response)["content_text"] == "selected input\n"

    unauthenticated, _, error = _asgi_request(app, "POST", "/api/broker/operations", body=body)
    assert unauthenticated == 401
    assert json.loads(error)["error"]["code"] == "AUTH_INVALID"

    oversized, _, error = _asgi_request(
        app,
        "POST",
        "/api/broker/operations",
        body=b" " * (2_097_153),
        headers={"authorization": f"Bearer {token}"},
    )
    assert oversized == 413
    assert json.loads(error)["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_slow_broker_execution_does_not_block_owner_health_route() -> None:
    async def exercise() -> None:
        started = threading.Event()
        release = threading.Event()
        fallback_release = threading.Timer(2, release.set)

        class BlockingBroker:
            def execute(self, _token: str, _body: bytes):
                started.set()
                if not release.wait(timeout=5):
                    raise TimeoutError("test broker was not released")

                class ResultBody:
                    def model_dump(self, *, mode: str):
                        assert mode == "json"
                        return {"schema_version": 1}

                return SimpleNamespace(status_code=200, body=ResultBody())

        app = create_app(Settings(), broker=BlockingBroker())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765"
        ) as client:
            fallback_release.start()
            broker_request = asyncio.create_task(
                client.post(
                    "/api/broker/operations",
                    content=b"{}",
                    headers={"authorization": "Bearer " + secrets.token_urlsafe(32)},
                )
            )
            try:
                assert await asyncio.to_thread(started.wait, 1)
                health = await asyncio.wait_for(client.get("/api/health"), timeout=1)
                assert health.status_code == 200
                assert not release.is_set()
            finally:
                release.set()
                fallback_release.cancel()
            broker_response = await asyncio.wait_for(broker_request, timeout=1)
            assert broker_response.status_code == 200

    asyncio.run(exercise())


def test_output_http_route_requires_injected_owner_auth_and_serves_finalized_attachment(
    tmp_path: Path,
) -> None:
    _, _, token, publisher, broker = _harness(tmp_path)
    body = json.dumps(
        {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": "publish_output",
            "output_kind": "formatted_markdown",
            "output_text": "# Download\n",
        }
    ).encode("utf-8")
    published = broker.execute(token, body, now=NOW + timedelta(seconds=3))
    assert published.status_code == 200

    app = create_app(
        Settings(),
        output_publisher=publisher,
        authorize_output=lambda request: (
            request.cookies.get("aclais_owner_session") == "test-session"
        ),
    )
    path = f"/api/outputs/{published.body.output_id}"
    unauthorized, _, _ = _asgi_request(app, "GET", path)
    assert unauthorized == 401

    def unavailable_auth(_request: Request) -> bool:
        raise RuntimeError("private failure")

    unavailable_app = create_app(
        Settings(),
        output_publisher=publisher,
        authorize_output=unavailable_auth,
    )
    unavailable, _, unavailable_body = _asgi_request(unavailable_app, "GET", path)
    assert unavailable == 503
    assert json.loads(unavailable_body)["error"]["code"] == "PROTECTION_UNAVAILABLE"
    status, headers, content = _asgi_request(
        app,
        "GET",
        path,
        headers={"cookie": "aclais_owner_session=test-session"},
    )
    assert status == 200
    assert content == b"# Download\n"
    assert headers["x-content-type-options"] == "nosniff"
    assert "attachment" in headers["content-disposition"]
    assert headers["cache-control"] == "no-store"
