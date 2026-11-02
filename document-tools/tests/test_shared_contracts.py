from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.portable


def test_worker_broker_requests_match_shared_openapi_models() -> None:
    schema_path = Path(__file__).resolve().parents[2] / "shared" / "openapi.json"
    schemas = json.loads(schema_path.read_text(encoding="utf-8"))["components"]["schemas"]
    assert schemas["BrokerReadDocumentRequest"]["required"] == [
        "schema_version",
        "request_id",
        "operation",
        "document_id",
    ]
    assert schemas["BrokerPublishOutputRequest"]["required"] == [
        "schema_version",
        "request_id",
        "operation",
        "output_kind",
        "output_text",
    ]
    assert schemas["BrokerReplaceOriginalRequest"]["required"] == [
        "schema_version",
        "request_id",
        "operation",
        "document_id",
        "replacement_text",
    ]
    assert (
        "formatted_markdown"
        in schemas["BrokerPublishOutputRequest"]["properties"]["output_kind"]["enum"]
    )
    assert "doc-report" in schemas["BrokerReadDocumentRequest"]["properties"]["document_id"]["enum"]
