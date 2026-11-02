"""Portable health/API checks; these do not verify Windows enforcement."""

import pytest
from fastapi.testclient import TestClient

from aclais.app import create_app
from aclais.config import Settings


@pytest.mark.portable
def test_health_is_live_and_reports_protection_unavailable() -> None:
    with TestClient(create_app(Settings()), base_url="http://127.0.0.1:8765") as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "schema_version": 1,
        "status": "unavailable",
        "protection_ready": False,
        "checks": [
            {
                "id": "application_api",
                "status": "pass",
                "summary": "The local API process is responding.",
            },
            {
                "id": "g1_protection",
                "status": "unknown",
                "summary": "Protected runtime is not enabled for this API process.",
            },
        ],
    }


@pytest.mark.portable
def test_health_rejects_an_unknown_host_with_contract_error() -> None:
    with TestClient(create_app(Settings()), base_url="http://127.0.0.1:8765") as client:
        response = client.get("/api/health", headers={"host": "attacker.example"})

    assert response.status_code == 400
    body = response.json()
    assert body["schema_version"] == 1
    assert body["error"]["code"] == "INVALID_HOST"
    assert body["error"]["request_id"]
    assert "attacker.example" not in response.text
