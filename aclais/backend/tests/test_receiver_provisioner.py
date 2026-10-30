from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest

from aclais.receiver_adapter import HttpReceiverRunProvisioner, ReceiverProtocolFailure

pytestmark = pytest.mark.portable


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True


def test_controller_provisions_a_run_and_keeps_admin_credential_out_of_context(monkeypatch) -> None:
    admin_token = "synthetic-admin-token-" + "x" * 32
    ingest_token = "synthetic-ingest-token-" + "y" * 32
    observed: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            observed["path"] = self.path
            observed["host"] = self.headers.get("Host")
            observed["authorization"] = self.headers.get("Authorization")
            observed["request"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body = json.dumps(
                {
                    "schema_version": 1,
                    "run_id": observed["request"]["run_id"],
                    "ingest_token": ingest_token,
                }
            ).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = _IPv6Server(("::1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("aclais.receiver_adapter._RECEIVER_ADMIN_PORT", port)
    monkeypatch.setattr("aclais.receiver_adapter._RECEIVER_ADMIN_HOST_HEADER", f"[::1]:{port}")
    run_id = uuid4()
    marker = "SYNTHETIC_FIXTURE_MARKER_012345"
    try:
        context = HttpReceiverRunProvisioner(admin_token=admin_token).create_run(run_id, marker)
        assert context.run_id == run_id
        assert context.ingest_token == ingest_token
        assert context.ingest_token not in repr(context)
        assert admin_token not in repr(HttpReceiverRunProvisioner(admin_token=admin_token))
        assert observed == {
            "path": "/admin/runs",
            "host": f"[::1]:{port}",
            "authorization": f"Bearer {admin_token}",
            "request": {
                "schema_version": 1,
                "run_id": str(run_id),
                "canary_marker": marker,
            },
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_controller_rejects_receiver_run_identity_mismatch(monkeypatch) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps(
                {
                    "schema_version": 1,
                    "run_id": str(uuid4()),
                    "ingest_token": "synthetic-ingest-token-" + "x" * 32,
                }
            ).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = _IPv6Server(("::1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("aclais.receiver_adapter._RECEIVER_ADMIN_PORT", port)
    monkeypatch.setattr("aclais.receiver_adapter._RECEIVER_ADMIN_HOST_HEADER", f"[::1]:{port}")
    try:
        with pytest.raises(ReceiverProtocolFailure):
            HttpReceiverRunProvisioner(admin_token="synthetic-admin-token-" + "x" * 32).create_run(
                uuid4(), "SYNTHETIC_FIXTURE_MARKER_012345"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
