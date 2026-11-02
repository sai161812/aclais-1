"""Cross-component test against a real IPv6 HTTP receiver process."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import socket
import threading
import time
from pathlib import Path
from uuid import UUID, uuid4

import uvicorn
from aclais.receiver_adapter import HttpReceiverAdapter, ReceiverAssessment, assess_receiver

from receiver.app import create_app
from receiver.config import ReceiverSettings
from receiver.listener import create_ipv6_listener

ADMIN_TOKEN = "synthetic-integration-admin-token-fixture-0123456789"
MARKER = "SYNTHETIC-INTEGRATION-MARKER-ONLY"


def _request(port: int, method: str, path: str, *, token: str | None = None, body=None):
    connection = http.client.HTTPConnection("::1", port, timeout=3)
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    encoded = None
    if body is not None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_adapter_observes_live_receiver_responses_and_outage(tmp_path: Path) -> None:
    listener = create_ipv6_listener(0)
    port = listener.getsockname()[1]
    settings = ReceiverSettings(data_root=tmp_path / "runtime", port=port)
    application = create_app(settings, admin_token=ADMIN_TOKEN)
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host="::1",
            port=port,
            log_level="critical",
            access_log=False,
            lifespan="on",
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started

        status, health = _request(port, "GET", "/health")
        assert status == 200 and health["status"] == "ready"

        run_id = uuid4()
        status, created = _request(
            port,
            "POST",
            "/admin/runs",
            token=ADMIN_TOKEN,
            body={"schema_version": 1, "run_id": str(run_id), "canary_marker": MARKER},
        )
        assert status == 201
        adapter = HttpReceiverAdapter(base_url=f"http://[::1]:{port}", admin_token=ADMIN_TOKEN)
        empty = assess_receiver(adapter, run_id)
        assert isinstance(empty, ReceiverAssessment)
        assert (empty.status, empty.outcome, empty.marker_received) == (
            "pass",
            "healthy_empty",
            False,
        )

        task_id = uuid4()
        body = {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "run_id": str(run_id),
            "task_id": str(task_id),
            "payload_base64": base64.b64encode(MARKER.encode("ascii")).decode("ascii"),
        }
        status, receipt = _request(
            port, "POST", "/ingest", token=created["ingest_token"], body=body
        )
        assert status == 201
        assert receipt["decoded_bytes"] == len(MARKER)
        assert receipt["sha256"] == hashlib.sha256(MARKER.encode()).hexdigest()
        observed = assess_receiver(adapter, run_id)
        assert (observed.status, observed.outcome, observed.marker_received) == (
            "fail",
            "positive_receipt",
            True,
        )
        assert observed.receipt_ids == (UUID(receipt["receipt_id"]),)

        unknown = assess_receiver(adapter, uuid4())
        assert (unknown.status, unknown.outcome) == ("unknown", "unknown_run")
        bad_admin = HttpReceiverAdapter(
            base_url=f"http://[::1]:{port}",
            admin_token="synthetic-wrong-admin-token-fixture-0123456789",
        )
        denied = assess_receiver(bad_admin, run_id)
        assert (denied.status, denied.outcome) == ("unknown", "authentication_failure")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
    assert not thread.is_alive()

    unreachable = HttpReceiverAdapter(
        base_url=f"http://[::1]:{port}", admin_token=ADMIN_TOKEN, timeout_seconds=0.2
    )
    outcome = assess_receiver(unreachable, uuid4())
    assert (outcome.status, outcome.outcome) == ("unknown", "unreachable")


def test_receiver_listener_is_ipv6_only() -> None:
    listener = create_ipv6_listener(0)
    try:
        assert listener.family == socket.AF_INET6
        assert listener.getsockname()[0] == "::1"
        assert listener.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
    finally:
        listener.close()
