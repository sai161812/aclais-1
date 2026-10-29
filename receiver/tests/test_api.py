from __future__ import annotations

import base64
import hashlib
import sqlite3
from uuid import uuid4

import pytest

from receiver.models import MAX_RECEIPT_BYTES, MAX_RUN_BYTES
from support import ADMIN_TOKEN, CANARY_MARKER, ReceiverHarness

pytestmark = pytest.mark.portable


def _ingest_body(run_id, payload: bytes, *, request_id=None, task_id=None):
    return {
        "schema_version": 1,
        "request_id": str(request_id or uuid4()),
        "run_id": str(run_id),
        "task_id": str(task_id or uuid4()),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }


def _ingest(receiver: ReceiverHarness, token: str, body: dict[str, object]):
    return receiver.client.post("/ingest", headers={"Authorization": f"Bearer {token}"}, json=body)


def test_admin_and_ingest_credentials_are_distinct_and_hash_only(receiver: ReceiverHarness) -> None:
    run_id = uuid4()
    request = {"schema_version": 1, "run_id": str(run_id), "canary_marker": CANARY_MARKER}
    no_admin = receiver.client.post("/admin/runs", json=request)
    assert no_admin.status_code == 401
    assert no_admin.json()["error"]["code"] == "AUTH_INVALID"

    created_id, ingest_token = receiver.create_run(run_id)
    assert created_id == run_id
    db_bytes = b"".join(path.read_bytes() for path in receiver.root.glob("receiver.sqlite3*"))
    assert not bool(ingest_token.encode("ascii") in db_bytes)
    with sqlite3.connect(receiver.root / "receiver.sqlite3") as db:
        stored = db.execute(
            "SELECT ingest_token_sha256, canary_marker FROM runs WHERE run_id=?",
            (str(run_id),),
        ).fetchone()
    assert stored[0] == hashlib.sha256(ingest_token.encode("ascii")).hexdigest()
    assert bytes(stored[1]) == CANARY_MARKER.encode("ascii")

    duplicate = receiver.client.post(
        "/admin/runs",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json=request,
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "REQUEST_CONFLICT"


def test_ingest_computes_count_hash_marker_and_returns_metadata_only(
    receiver: ReceiverHarness,
) -> None:
    run_id, ingest_token = receiver.create_run()
    task_id = uuid4()
    payload = b"synthetic receipt prefix " + CANARY_MARKER.encode("ascii") + b" suffix"
    response = _ingest(receiver, ingest_token, _ingest_body(run_id, payload, task_id=task_id))
    assert response.status_code == 201
    receipt = response.json()
    assert receipt["schema_version"] == 1
    assert receipt["decoded_bytes"] == len(payload)
    assert receipt["sha256"] == hashlib.sha256(payload).hexdigest()
    assert CANARY_MARKER not in response.text
    assert base64.b64encode(payload).decode("ascii") not in response.text

    read = receiver.client.get(
        f"/admin/runs/{run_id}/receipts",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert read.status_code == 200
    data = read.json()
    assert data["run_id"] == str(run_id)
    assert data["marker_received"] is True
    assert len(data["receipts"]) == 1
    assert data["receipts"][0]["task_id"] == str(task_id)
    assert data["receipts"][0]["marker_match"] is True
    assert data["receipts"][0]["decoded_bytes"] == len(payload)
    assert data["receipts"][0]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert CANARY_MARKER not in read.text
    stored_payload = next((receiver.root / "payloads").glob("*.bin")).read_bytes()
    assert stored_payload == payload


def test_healthy_empty_and_nonmatching_payload_are_distinct_from_marker_receipt(
    receiver: ReceiverHarness,
) -> None:
    empty_run, empty_token = receiver.create_run()
    empty = receiver.client.get(
        f"/admin/runs/{empty_run}/receipts",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert empty.status_code == 200
    assert empty.json()["receipts"] == []
    assert empty.json()["marker_received"] is False

    payload = b"synthetic payload with no configured canary"
    response = _ingest(receiver, empty_token, _ingest_body(empty_run, payload))
    assert response.status_code == 201
    read = receiver.client.get(
        f"/admin/runs/{empty_run}/receipts",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert read.status_code == 200
    assert read.json()["marker_received"] is False
    assert read.json()["receipts"][0]["marker_match"] is False


def test_identical_retry_returns_same_receipt_and_different_body_conflicts(
    receiver: ReceiverHarness,
) -> None:
    run_id, token = receiver.create_run()
    request_id = uuid4()
    body = _ingest_body(run_id, b"synthetic retry body", request_id=request_id)
    first = _ingest(receiver, token, body)
    second = _ingest(receiver, token, body)
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()

    unauthenticated = receiver.client.post("/ingest", json=body)
    assert unauthenticated.status_code == 401

    changed = _ingest(receiver, token, _ingest_body(run_id, b"changed body", request_id=request_id))
    assert changed.status_code == 409
    assert changed.json()["error"]["code"] == "REQUEST_CONFLICT"
    with sqlite3.connect(receiver.root / "receiver.sqlite3") as db:
        count = db.execute(
            "SELECT count(*) FROM receipts WHERE run_id=?", (str(run_id),)
        ).fetchone()[0]
    assert count == 1
    assert len(list((receiver.root / "payloads").glob("*.bin"))) == 1


def test_ingest_and_admin_credentials_cannot_cross_runs_or_routes(
    receiver: ReceiverHarness,
) -> None:
    run_a, token_a = receiver.create_run()
    run_b, token_b = receiver.create_run()
    body = _ingest_body(run_b, b"synthetic cross-run payload")
    cross_run = _ingest(receiver, token_a, body)
    assert cross_run.status_code == 401

    admin_as_ingest = _ingest(receiver, ADMIN_TOKEN, _ingest_body(run_a, b"no effect"))
    assert admin_as_ingest.status_code == 401
    ingest_as_admin = receiver.client.get(
        f"/admin/runs/{run_a}/receipts",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert ingest_as_admin.status_code == 401

    no_run = receiver.client.get(
        f"/admin/runs/{uuid4()}/receipts",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert no_run.status_code == 404
    assert no_run.json()["error"]["code"] == "NOT_FOUND"


def test_strict_models_malformed_base64_forged_fields_and_limits_have_no_effect(
    receiver: ReceiverHarness,
) -> None:
    run_id, token = receiver.create_run()
    valid = _ingest_body(run_id, b"synthetic", request_id=uuid4())

    unknown = {**valid, "marker_match": True}
    duplicate = receiver.client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=(
            '{"schema_version":1,"request_id":"'
            + valid["request_id"]
            + '","request_id":"'
            + valid["request_id"]
            + '","run_id":"'
            + str(run_id)
            + '","task_id":"'
            + str(uuid4())
            + '","payload_base64":"c3ludGhldGlj"}'
        ),
    )
    malformed = _ingest(receiver, token, {**valid, "payload_base64": "%%%"})
    forged = _ingest(receiver, token, unknown)
    assert duplicate.status_code == malformed.status_code == forged.status_code == 422

    deeply_nested = receiver.client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=b"[" * 2000 + b"]" * 2000,
    )
    assert deeply_nested.status_code == 422

    oversize = _ingest(
        receiver,
        token,
        _ingest_body(run_id, b"x" * (MAX_RECEIPT_BYTES + 1)),
    )
    assert oversize.status_code == 413
    assert oversize.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

    too_large_body = receiver.client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=b" " * (2_097_153),
    )
    assert too_large_body.status_code == 413
    assert too_large_body.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

    with sqlite3.connect(receiver.root / "receiver.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0


def test_storage_limit_is_per_run_and_returns_specific_capacity_error(
    receiver: ReceiverHarness,
) -> None:
    run_id, token = receiver.create_run()
    full = b"x" * MAX_RECEIPT_BYTES
    for _ in range(MAX_RUN_BYTES // MAX_RECEIPT_BYTES):
        accepted = _ingest(receiver, token, _ingest_body(run_id, full))
        assert accepted.status_code == 201
    rejected = _ingest(receiver, token, _ingest_body(run_id, b"one byte"))
    assert rejected.status_code == 429
    assert rejected.json()["error"]["code"] == "RATE_LIMITED"

    another, another_token = receiver.create_run()
    accepted_other_run = _ingest(receiver, another_token, _ingest_body(another, b"still available"))
    assert accepted_other_run.status_code == 201


def test_host_query_and_invalid_identifier_checks_are_strict(receiver: ReceiverHarness) -> None:
    invalid_host = receiver.client.get("/health", headers={"host": "127.0.0.1:8767"})
    assert invalid_host.status_code == 400
    assert invalid_host.json()["error"]["code"] == "INVALID_HOST"
    unknown_query = receiver.client.get("/health?verbose=1")
    assert unknown_query.status_code == 422
    assert unknown_query.json()["error"]["code"] == "INVALID_REQUEST"
    invalid_length = receiver.client.post(
        "/ingest",
        headers={
            "Authorization": f"Bearer {ADMIN_TOKEN}",
            "Content-Type": "application/json",
            "Content-Length": "+2",
        },
        content=b"{}",
    )
    assert invalid_length.status_code == 422
    assert invalid_length.json()["error"]["code"] == "INVALID_REQUEST"
    invalid_id = receiver.client.get(
        "/admin/runs/not-a-uuid/receipts",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert invalid_id.status_code == 422
