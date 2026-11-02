from __future__ import annotations

import base64
import json
from uuid import uuid4

import pytest

from receiver.cli import _inspect
from receiver.config import ReceiverSettings
from receiver.credentials import (
    CredentialError,
    create_admin_credential,
    read_admin_credential,
)
from receiver.database import ReceiverStore
from receiver.models import CreateRunRequest, IngestRequest
from receiver.security import audit_store_root

pytestmark = pytest.mark.portable

_MARKER = "SYNTHETIC-CLI-MARKER-ONLY"
_TOKEN = "synthetic-cli-ingest-token-fixture-0123456789"


def test_owner_receipt_cli_outputs_sanitized_metadata_only(tmp_path, capsys) -> None:
    settings = ReceiverSettings(data_root=tmp_path / "receiver-runtime")
    store = ReceiverStore(settings.data_root)
    store.initialize()
    run_id = uuid4()
    store.create_run(
        CreateRunRequest(schema_version=1, run_id=run_id, canary_marker=_MARKER),
        ingest_token=_TOKEN,
    )
    payload = b"private synthetic payload " + _MARKER.encode("ascii")
    store.ingest(
        _TOKEN,
        IngestRequest(
            schema_version=1,
            request_id=uuid4(),
            run_id=run_id,
            task_id=uuid4(),
            payload_base64=base64.b64encode(payload).decode("ascii"),
        ),
    )

    assert _inspect(settings, str(run_id)) == 0
    output = capsys.readouterr().out
    summary = json.loads(output)
    assert summary["run_id"] == str(run_id)
    assert summary["receipt_count"] == 1
    assert summary["decoded_bytes"] == len(payload)
    assert summary["marker_received"] is True
    assert set(summary) == {
        "run_id",
        "receipt_count",
        "decoded_bytes",
        "marker_received",
        "received_at",
    }
    assert payload.decode("ascii") not in output
    assert _MARKER not in output
    assert _TOKEN not in output


def test_admin_credential_is_owner_protected_and_never_overwritten(tmp_path, capsys) -> None:
    root = tmp_path / "receiver-runtime"
    create_admin_credential(root)
    token = read_admin_credential(root)
    assert len(token) >= 32
    assert _TOKEN not in token
    assert capsys.readouterr().out == ""
    audit_store_root(root)

    with pytest.raises(CredentialError):
        create_admin_credential(root)
    assert read_admin_credential(root) == token
