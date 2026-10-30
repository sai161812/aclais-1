from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from document_tools import server as site_server
from document_tools.server import handler_for

pytestmark = pytest.mark.portable


def test_site_host_allowlist_and_no_cookie_or_cors_headers(tmp_path: Path) -> None:
    index = tmp_path / "index.html"
    index.write_text("<main>Document Tools</main>", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_port}/",
            headers={"Host": "localhost:8766"},
        )
        with urlopen(request, timeout=3) as response:
            assert response.status == 200
            assert response.read() == b"<main>Document Tools</main>"
            assert response.headers.get("Set-Cookie") is None
            assert response.headers.get("Access-Control-Allow-Origin") is None
            assert response.headers.get("Content-Security-Policy")

        blocked = Request(
            f"http://127.0.0.1:{server.server_port}/",
            headers={"Host": "127.0.0.1:8766"},
        )
        with pytest.raises(Exception):
            urlopen(blocked, timeout=3)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_normal_tool_card_links_only_to_trusted_aclais_approval() -> None:
    source = (Path(__file__).resolve().parents[1] / "frontend" / "src" / "main.tsx").read_text(
        encoding="utf-8"
    )
    assert "http://127.0.0.1:8765/approve" in source
    assert 'searchParams.set("launch_source_claim", "document_tools")' in source
    assert 'approvalUrl("report_formatter")' in source
    assert 'approvalUrl("invoice_analyzer")' in source
    for prohibited in ("attack button", "protection switch", "demo mode", "payload input"):
        assert prohibited not in source.casefold()


def test_public_availability_is_strict_and_exposes_only_installed_tool_states() -> None:
    health = {
        "schema_version": 1,
        "status": "ready",
        "protection_ready": True,
        "checks": [
            {"id": "tool_report_formatter", "status": "pass", "summary": "installed"},
            {"id": "tool_invoice_analyzer", "status": "fail", "summary": "not installed"},
        ],
    }
    assert site_server._parse_public_health(json.dumps(health).encode()) == {
        "status": "ready",
        "tools": {"report_formatter": True, "invoice_analyzer": False},
    }
    for malformed in (
        {**health, "unrecognized": True},
        {**health, "checks": health["checks"] + [health["checks"][0]]},
        {**health, "status": []},
        {**health, "checks": [{"id": "tool_report_formatter", "status": [], "summary": "bad"}]},
    ):
        assert site_server._parse_public_health(json.dumps(malformed).encode()) is None
    assert site_server._parse_public_health(b'{"schema_version":1,"schema_version":1}') is None


def test_availability_route_is_no_store_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = tmp_path / "index.html"
    index.write_text("<main>Document Tools</main>", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(
            site_server,
            "_public_tool_availability",
            lambda: {
                "status": "ready",
                "tools": {"report_formatter": True, "invoice_analyzer": False},
            },
        )
        request = Request(
            f"http://127.0.0.1:{server.server_port}/availability.json",
            headers={"Host": "localhost:8766"},
        )
        with urlopen(request, timeout=3) as response:
            assert json.loads(response.read()) == {
                "schema_version": 1,
                "status": "ready",
                "tools": {"report_formatter": True, "invoice_analyzer": False},
            }
            assert response.headers.get("Cache-Control") == "no-store"
            assert response.headers.get("Set-Cookie") is None
            assert response.headers.get("Access-Control-Allow-Origin") is None

        monkeypatch.setattr(site_server, "_public_tool_availability", lambda: None)
        unavailable = Request(
            f"http://127.0.0.1:{server.server_port}/availability.json",
            headers={"Host": "localhost:8766"},
        )
        with pytest.raises(HTTPError) as error:
            urlopen(unavailable, timeout=3)
        assert error.value.code == 503
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_public_health_client_uses_fixed_unauthenticated_loopback_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    health = {
        "schema_version": 1,
        "status": "ready",
        "protection_ready": True,
        "checks": [
            {"id": "tool_report_formatter", "status": "pass", "summary": "installed"},
            {"id": "tool_invoice_analyzer", "status": "pass", "summary": "installed"},
        ],
    }
    observed: dict[str, object] = {}

    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            observed.update(
                method="GET",
                path=self.path,
                host=self.headers.get("Host"),
                authorization=self.headers.get("Authorization"),
                cookie=self.headers.get("Cookie"),
            )
            body = json.dumps(health).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            return

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(site_server, "_ACLAIS_PORT", upstream.server_port)
        assert site_server._public_tool_availability() == {
            "status": "ready",
            "tools": {"report_formatter": True, "invoice_analyzer": True},
        }
        assert observed == {
            "method": "GET",
            "path": "/api/health",
            "host": "127.0.0.1:8765",
            "authorization": None,
            "cookie": None,
        }
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=3)
