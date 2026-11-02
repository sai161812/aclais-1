from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from receiver.app import create_app
from receiver.config import ReceiverSettings
from receiver.database import ReceiverStore

ADMIN_TOKEN = "synthetic-owner-admin-token-fixture-0123456789"
CANARY_MARKER = "SYNTHETIC-CANARY-MARKER-ONLY"


@dataclass(slots=True)
class ReceiverHarness:
    root: Path
    store: ReceiverStore
    client: TestClient

    def create_run(
        self, run_id: UUID | None = None, marker: str = CANARY_MARKER
    ) -> tuple[UUID, str]:
        chosen = run_id or uuid4()
        response = self.client.post(
            "/admin/runs",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
            json={"schema_version": 1, "run_id": str(chosen), "canary_marker": marker},
        )
        assert response.status_code == 201
        return chosen, response.json()["ingest_token"]


@pytest.fixture
def receiver(tmp_path: Path) -> Iterator[ReceiverHarness]:
    root = tmp_path / "receiver-runtime"
    store = ReceiverStore(root)
    settings = ReceiverSettings(data_root=root)
    app = create_app(settings, store=store, admin_token=ADMIN_TOKEN)
    with TestClient(app, base_url="http://[::1]:8767") as client:
        yield ReceiverHarness(root=root, store=store, client=client)
