from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest

from document_tools.receiver import ReceiverClient, ReceiverIngestError

pytestmark = pytest.mark.portable


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True


def test_receiver_client_retries_lost_response_with_identical_request(monkeypatch) -> None:
    requests: list[bytes] = []
    first_request = threading.Event()
    payload = b"synthetic private fixture bytes\n"
    owner = {"calls": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/ingest"
            assert self.headers.get("Host") == f"[::1]:{port}"
            assert self.headers.get("Authorization") == "Bearer synthetic-ingest-token-0123456789"
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append(raw)
            owner["calls"] += 1
            if owner["calls"] == 1:
                first_request.set()
                self.connection.close()
                return
            value = json.loads(raw)
            submitted = base64.b64decode(value["payload_base64"], validate=True)
            response = json.dumps(
                {
                    "schema_version": 1,
                    "receipt_id": str(uuid4()),
                    "received_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "decoded_bytes": len(submitted),
                    "sha256": hashlib.sha256(submitted).hexdigest(),
                }
            ).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = _IPv6Server(("::1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("document_tools.receiver._RECEIVER_PORT", port)
    monkeypatch.setattr("document_tools.receiver._RECEIVER_HOST_HEADER", f"[::1]:{port}")
    try:
        result = ReceiverClient(
            run_id=str(uuid4()),
            task_id=str(uuid4()),
            ingest_token="synthetic-ingest-token-0123456789",
        ).ingest(payload)
        assert first_request.is_set()
        assert owner["calls"] == 2
        assert requests[0] == requests[1]
        request = json.loads(requests[0])
        assert set(request) == {
            "schema_version",
            "request_id",
            "run_id",
            "task_id",
            "payload_base64",
        }
        assert base64.b64decode(request["payload_base64"], validate=True) == payload
        assert result.decoded_bytes == len(payload)
        assert result.sha256 == hashlib.sha256(payload).hexdigest()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_receiver_client_preserves_auth_failure_and_rejects_oversize(monkeypatch) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps(
                {
                    "schema_version": 1,
                    "error": {
                        "code": "AUTH_INVALID",
                        "message": "Run-bound ingest credential is invalid.",
                        "request_id": str(uuid4()),
                    },
                }
            ).encode()
            self.send_response(401)
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
    monkeypatch.setattr("document_tools.receiver._RECEIVER_PORT", port)
    monkeypatch.setattr("document_tools.receiver._RECEIVER_HOST_HEADER", f"[::1]:{port}")
    client = ReceiverClient(
        run_id=str(uuid4()),
        task_id=str(uuid4()),
        ingest_token="synthetic-ingest-token-0123456789",
    )
    try:
        with pytest.raises(ReceiverIngestError) as rejected:
            client.ingest(b"payload")
        assert rejected.value.outcome == "authentication_failure"
        assert rejected.value.status_code == 401
        assert rejected.value.code == "AUTH_INVALID"
        with pytest.raises(ReceiverIngestError) as oversized:
            client.ingest(b"x" * (1_048_576 + 1))
        assert oversized.value.outcome == "payload_too_large"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
