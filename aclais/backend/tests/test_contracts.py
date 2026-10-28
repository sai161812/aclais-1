from __future__ import annotations

import json
from uuid import uuid4

import pytest
from pydantic import TypeAdapter, ValidationError

from aclais.api_contracts import BrokerOperationRequest, build_openapi_document
from aclais.app import app
from aclais.persistence.models import (
    ApprovalQuery,
    BrokerPublishOutputRequest,
    CreateTaskRequest,
    EventsQuery,
    HealthResponse,
    InvoiceResult,
    ReceiptJournalState,
    ReceiverReceiptJournalRecord,
    TaskListQuery,
)
from aclais.strict_json import MAX_JSON_BODY_BYTES, parse_strict_json

pytestmark = pytest.mark.portable

TASK_REQUEST = {
    "schema_version": 1,
    "tool_id": "report_formatter",
    "selected_document_id": "doc-report",
    "launch_source_claim": "document_tools",
}


def test_create_request_is_strict_and_does_not_accept_paths_or_grants() -> None:
    assert CreateTaskRequest.model_validate(TASK_REQUEST).selected_document_id == "doc-report"
    for invalid in (
        {**TASK_REQUEST, "selected_path": "D:/secret.csv"},
        {**TASK_REQUEST, "grants": ["delete_document"]},
        {**TASK_REQUEST, "schema_version": "1"},
        {**TASK_REQUEST, "selected_document_id": "../../secret"},
    ):
        with pytest.raises(ValidationError):
            CreateTaskRequest.model_validate(invalid)


def test_queries_and_response_models_are_strict() -> None:
    assert TaskListQuery.model_validate({"limit": "50"}).limit == 50
    for invalid in ({"limit": "01"}, {"limit": "51"}, {"limit": True}, {"limit": "1", "path": "x"}):
        with pytest.raises(ValidationError):
            TaskListQuery.model_validate(invalid)
    with pytest.raises(ValidationError):
        EventsQuery.model_validate({"after_seq": "1000000000"})
    assert (
        ApprovalQuery.model_validate(
            {"tool_id": "report_formatter", "launch_source_claim": "document_tools"}
        ).tool_id
        == "report_formatter"
    )
    with pytest.raises(ValidationError):
        ApprovalQuery.model_validate(
            {
                "tool_id": "report_formatter",
                "launch_source_claim": "document_tools",
                "path": "D:/private.csv",
            }
        )
    with pytest.raises(ValidationError):
        HealthResponse.model_validate(
            {
                "schema_version": 1,
                "status": "ready",
                "protection_ready": False,
                "checks": [],
                "document_path": "D:/private.csv",
            }
        )


def test_broker_discriminator_and_output_size_are_operation_specific() -> None:
    adapter = TypeAdapter(BrokerOperationRequest)
    request = adapter.validate_python(
        {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": "publish_output",
            "output_kind": "formatted_markdown",
            "output_text": "synthetic",
        }
    )
    assert isinstance(request, BrokerPublishOutputRequest)
    for invalid in (
        {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": "delete_document",
            "output_text": "not a delete request",
        },
        {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": "publish_output",
            "output_kind": "formatted_markdown",
            "output_text": "🙂" * 262_145,
        },
    ):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)

    formatter_output = BrokerPublishOutputRequest.model_validate(
        {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": "publish_output",
            "output_kind": "formatted_markdown",
            "output_text": "synthetic markdown",
        }
    )
    assert formatter_output.validate_for_tool("report_formatter") is formatter_output
    with pytest.raises(ValueError, match="not allowed"):
        formatter_output.validate_for_tool("invoice_analyzer")

    with pytest.raises(ValidationError, match="invoice_json"):
        BrokerPublishOutputRequest.model_validate(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "operation": "publish_output",
                "output_kind": "invoice_json",
                "output_text": "not valid invoice JSON",
            }
        )


def test_invoice_json_contract_preserves_exact_decimal_strings() -> None:
    accepted = (
        b'{"vendor":"Example Co","invoice_number":"0007",'
        b'"date":"2026-10-29","line_total":"12.30","grand_total":"12.30"}'
    )
    invoice = parse_strict_json(accepted, InvoiceResult)
    assert invoice.invoice_number == "0007"
    invoice_request = BrokerPublishOutputRequest.model_validate(
        {
            "schema_version": 1,
            "request_id": str(uuid4()),
            "operation": "publish_output",
            "output_kind": "invoice_json",
            "output_text": accepted.decode("utf-8"),
        }
    )
    assert invoice_request.validate_for_tool("invoice_analyzer") is invoice_request
    for invalid in (
        (
            b'{"vendor":"Example Co","invoice_number":"7","date":"2026-02-30",'
            b'"line_total":"1.00","grand_total":"1.00"}'
        ),
        (
            b'{"vendor":"Example Co","invoice_number":"7","date":"2026-10-29",'
            b'"line_total":1.00,"grand_total":"1.00"}'
        ),
        (
            b'{"vendor":"Example Co","invoice_number":"7","date":"2026-10-29",'
            b'"line_total":"1.00","grand_total":"1.00","extra":true}'
        ),
    ):
        with pytest.raises(ValueError):
            parse_strict_json(invalid, InvoiceResult)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":1,"schema_version":1,"tool_id":"report_formatter","selected_document_id":"doc-report","launch_source_claim":"document_tools"}',
        b'{"schema_version":NaN,"tool_id":"report_formatter","selected_document_id":"doc-report","launch_source_claim":"document_tools"}',
        b'{"schema_version":1,"tool_id":"report_formatter","selected_document_id":"doc-report","launch_source_claim":"document_tools","x":"\\ud800"}',
        b"\xff",
    ],
)
def test_strict_json_rejects_ambiguous_or_invalid_encoding(payload: bytes) -> None:
    with pytest.raises(ValueError):
        parse_strict_json(payload, CreateTaskRequest)


def test_strict_json_body_size_is_bounded() -> None:
    with pytest.raises(ValueError, match="2 MiB"):
        parse_strict_json(b" " * (MAX_JSON_BODY_BYTES + 1), CreateTaskRequest)


def test_generated_openapi_covers_contract_and_safe_output_content() -> None:
    document = build_openapi_document(app)
    expected_paths = {
        "/api/health",
        "/api/documents",
        "/api/tasks",
        "/api/tasks/{task_id}",
        "/api/tasks/{task_id}/events",
        "/api/tasks/{task_id}/cancel",
        "/api/tasks/{task_id}/evidence",
        "/api/outputs/{output_id}",
        "/api/broker/operations",
        "/approve",
        "/health",
        "/ingest",
        "/admin/runs",
        "/admin/runs/{run_id}/receipts",
    }
    assert set(document["paths"]) == expected_paths
    schemas = document["components"]["schemas"]
    assert schemas["CreateTaskRequest"]["additionalProperties"] is False
    approval_parameters = document["paths"]["/approve"]["get"]["parameters"]
    assert [param["required"] for param in approval_parameters] == [True, True]
    assert approval_parameters[0]["schema"]["enum"] == [
        "report_formatter",
        "invoice_analyzer",
    ]
    task_id_parameter = document["paths"]["/api/tasks/{task_id}"]["parameters"][0]
    assert task_id_parameter["schema"] == {"format": "uuid", "type": "string"}
    assert schemas["BrokerOperationRequest"]["discriminator"]["propertyName"] == "operation"
    operation_schemas = schemas["BrokerOperationRequest"]["oneOf"]
    assert len(operation_schemas) == 4
    assert all(
        schemas[reference["$ref"].rsplit("/", 1)[1]]["additionalProperties"] is False
        for reference in operation_schemas
    )
    output_200 = document["paths"]["/api/outputs/{output_id}"]["get"]["responses"]["200"]
    assert set(output_200["content"]) == {"text/markdown", "application/json"}
    assert output_200["headers"]["X-Content-Type-Options"]["schema"]["const"] == "nosniff"
    assert "relative_path" not in json.dumps(schemas["TaskRecord"])


def test_receiver_receipt_journal_is_value_only_and_rejects_paths() -> None:
    receipt_id = uuid4()
    journal = ReceiverReceiptJournalRecord(
        run_id=uuid4(),
        request_id=uuid4(),
        task_id=uuid4(),
        canonical_body_sha256="a" * 64,
        receipt_id=receipt_id,
        staging_relative_path=f"staging/{receipt_id}.stage",
        payload_relative_path=f"payloads/{receipt_id}.bin",
        payload_sha256="b" * 64,
        decoded_bytes=42,
        marker_match=False,
        state=ReceiptJournalState.RESERVED,
        received_at="2026-10-29T10:00:00Z",
    )
    assert journal.decoded_bytes == 42
    with pytest.raises(ValidationError):
        ReceiverReceiptJournalRecord.model_validate(
            {
                **journal.model_dump(mode="json"),
                "payload_relative_path": "../../outside.bin",
            }
        )
