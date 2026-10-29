"""Dual-loopback static website server with an exact Host allowlist."""

from __future__ import annotations

import argparse
import mimetypes
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

EXPECTED_HOST = "localhost:8766"
LISTENERS = ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))


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
                    "script-src 'self'; connect-src 'none'; base-uri 'none'; "
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
