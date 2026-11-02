"""Dual-loopback static website server with an exact Host allowlist."""

from __future__ import annotations

import argparse
import http.client
import json
import mimetypes
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

EXPECTED_HOST = "localhost:8766"
LISTENERS = ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))
_ACLAIS_HOST = "127.0.0.1"
_ACLAIS_PORT = 8765
_ACLAIS_HOST_HEADER = "127.0.0.1:8765"
_MAX_HEALTH_BYTES = 65_536
_HEALTH_CHECK_IDS = {
    "application_api",
    "g1_protection",
    "owner_and_worker_identity",
    "effective_runtime_permissions",
    "checkout_dependencies_and_commands",
    "code_and_fixture_integrity",
    "credential_retrieval",
    "job_configuration",
    "launch_preflight",
    "database_integrity",
    "owned_installation",
    "no_active_worker",
    "controller_lifecycle",
    "tool_report_formatter",
    "tool_invoice_analyzer",
}


def _parse_public_health(raw: bytes) -> dict[str, object] | None:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return None
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "status", "protection_ready", "checks"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(value["status"]) is not str
        or value["status"] not in {"ready", "unavailable"}
        or type(value["protection_ready"]) is not bool
        or type(value["checks"]) is not list
        or not 1 <= len(value["checks"]) <= 32
        or (value["status"] == "ready") != value["protection_ready"]
    ):
        return None
    checks: dict[str, str] = {}
    for check in value["checks"]:
        if (
            type(check) is not dict
            or set(check) != {"id", "status", "summary"}
            or type(check["id"]) is not str
            or check["id"] not in _HEALTH_CHECK_IDS
            or check["id"] in checks
            or type(check["status"]) is not str
            or check["status"] not in {"pass", "fail", "unknown"}
            or type(check["summary"]) is not str
            or not 1 <= len(check["summary"]) <= 256
        ):
            return None
        checks[check["id"]] = check["status"]
    ready = value["status"] == "ready" and value["protection_ready"]
    return {
        "status": "ready" if ready else "protection_unavailable",
        "tools": {
            "report_formatter": ready and checks.get("tool_report_formatter") == "pass",
            "invoice_analyzer": ready and checks.get("tool_invoice_analyzer") == "pass",
        },
    }


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate health response field")
        result[key] = value
    return result


def _public_tool_availability() -> dict[str, object] | None:
    connection = http.client.HTTPConnection(_ACLAIS_HOST, _ACLAIS_PORT, timeout=1.5)
    try:
        connection.request(
            "GET",
            "/api/health",
            headers={
                "Host": _ACLAIS_HOST_HEADER,
                "Accept": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        raw = response.read(_MAX_HEALTH_BYTES + 1)
    except (OSError, TimeoutError, http.client.HTTPException):
        return None
    finally:
        connection.close()
    if (
        response.status != 200
        or len(raw) > _MAX_HEALTH_BYTES
        or response.getheader("Content-Type", "").split(";", 1)[0].lower()
        != "application/json"
    ):
        return None
    return _parse_public_health(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], family: int
    ) -> None:
        self.address_family = family
        super().__init__(address, handler, bind_and_activate=False)
        if family == socket.AF_INET and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        if family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.server_bind()
        self.server_activate()


def handler_for(root: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "DocumentTools"
        sys_version = ""

        def do_GET(self) -> None:
            self._serve_file(send_body=True)

        def do_HEAD(self) -> None:
            self._serve_file(send_body=False)

        def _serve_file(self, *, send_body: bool) -> None:
            host_values = self.headers.get_all("Host", [])
            if len(host_values) != 1 or host_values[0].casefold() != EXPECTED_HOST:
                self.send_error(400, "Host is not allowlisted")
                return
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                self.send_error(400, "Request target is invalid")
                return
            if parsed.path == "/availability.json":
                availability = _public_tool_availability()
                if availability is None:
                    self.send_error(503, "ACLAIS tool availability is unavailable")
                    return
                data = json.dumps(
                    {"schema_version": 1, **availability},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                if send_body:
                    self.wfile.write(data)
                return
            try:
                relative = unquote(parsed.path).lstrip("/") or "index.html"
                candidate = (root / relative).resolve(strict=True)
                candidate.relative_to(root)
                if candidate.is_symlink() or not candidate.is_file():
                    raise ValueError("not a static asset")
            except (OSError, ValueError):
                self.send_error(404, "Asset not found")
                return
            data = candidate.read_bytes()
            self.send_response(200)
            self.send_header(
                "Content-Type",
                mimetypes.guess_type(candidate.name)[0] or "application/octet-stream",
            )
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                (
                    "default-src 'self'; style-src 'self'; img-src 'self' data:; "
                    "script-src 'self'; connect-src 'self'; base-uri 'none'; "
                    "frame-ancestors 'none'; form-action 'none'"
                ),
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            if send_body:
                self.wfile.write(data)

        def do_OPTIONS(self) -> None:
            self.send_error(405, "Method is not supported")

        def do_POST(self) -> None:
            self.send_error(405, "Method is not supported")

        def log_message(self, _format: str, *args: object) -> None:
            # URLs, headers and request bodies are not needed by this static service.
            return

    return Handler


class WebsiteServer:
    """Own both fixed loopback listeners without touching any unrelated process."""

    def __init__(self, root: Path) -> None:
        resolved = root.resolve(strict=True)
        if not resolved.is_dir() or not (resolved / "index.html").is_file():
            raise RuntimeError("built Document Tools frontend is unavailable")
        self.servers: list[_Server] = []
        self.threads: list[threading.Thread] = []
        try:
            for family, address in LISTENERS:
                self.servers.append(_Server((address, 8766), handler_for(resolved), family))
        except OSError:
            for server in self.servers:
                server.server_close()
            raise

    def start(self) -> None:
        for server in self.servers:
            thread = threading.Thread(
                target=server.serve_forever,
                name=f"document-tools-{server.server_address[0]}",
                daemon=True,
            )
            thread.start()
            self.threads.append(thread)

    def close(self) -> None:
        for server in self.servers[: len(self.threads)]:
            server.shutdown()
        for server in self.servers:
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)


def serve(root: Path) -> None:
    server = WebsiteServer(root)
    try:
        server.start()
        print(
            "Document Tools listening on http://localhost:8766 (IPv4 and IPv6 loopback)", flush=True
        )
        for thread in server.threads:
            thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2] / "frontend" / "dist"
    )
    args = parser.parse_args()
    serve(args.root)


if __name__ == "__main__":
    main()
