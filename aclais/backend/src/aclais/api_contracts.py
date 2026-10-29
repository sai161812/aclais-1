"""The strict model catalog and published API contract routes.

Contract paths describe the agreed ACLAIS and receiver wire surface. Only the A1 health
handler is currently mounted in the local application; A4 adds types without implementing
later checkpoint endpoints.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from aclais.persistence.models import (
    ApiError,
    ApprovalQuery,
    BrokerDeleteDocumentRequest,
    BrokerOutputAllowed,
    BrokerPublishOutputRequest,
    BrokerReadDocumentAllowed,
    BrokerReadDocumentRequest,
    BrokerReplaceOriginalRequest,
    CancelResponse,
    ContractSummary,
    CreateRunRequest,
    CreateRunResponse,
    CreateTaskRequest,
    DocumentListResponse,
    DocumentSummary,
    ErrorResponse,
    EventsQuery,
    EventsResponse,
    EvidenceCheck,
    EvidenceReport,
    EvidenceResponse,
    HealthCheck,
    HealthResponse,
    Incident,
    IngestRequest,
    InvoiceResult,
    OutputMetadata,
    OwnerBootstrapExchangeRequest,
    OwnerLogoutResponse,
    OwnerSessionResponse,
    ReceiptResponse,
    ReceiptsResponse,
    ReceiptSummary,
    ReceiverHealthResponse,
    ReceiverReceiptJournalRecord,
    TaskDetailResponse,
    TaskListQuery,
    TaskListResponse,
    TaskRecord,
    TaskSummary,
    UUIDValue,
)

BrokerOperationRequest = Annotated[
    BrokerReadDocumentRequest
    | BrokerPublishOutputRequest
    | BrokerReplaceOriginalRequest
    | BrokerDeleteDocumentRequest,
    Field(discriminator="operation"),
]
BrokerOperationResponse = BrokerReadDocumentAllowed | BrokerOutputAllowed


class ContractSchemaCatalog(BaseModel):
    """Root schema used to derive all component DTOs from the same Pydantic models."""

    model_config = ConfigDict(extra="forbid", strict=True)

    api_error: ApiError
    error_response: ErrorResponse
    health_check: HealthCheck
    health_response: HealthResponse
    document_summary: DocumentSummary
    document_list_response: DocumentListResponse
    create_task_request: CreateTaskRequest
    approval_query: ApprovalQuery
    task_record: TaskRecord
    task_summary: TaskSummary
    task_list_response: TaskListResponse
    task_list_query: TaskListQuery
    contract_summary: ContractSummary
    output_metadata: OutputMetadata
    incident: Incident
    task_detail_response: TaskDetailResponse
    cancel_response: CancelResponse
    event_query: EventsQuery
    events_response: EventsResponse
    evidence_check: EvidenceCheck
    evidence_report: EvidenceReport
    evidence_response: EvidenceResponse
    broker_read_request: BrokerReadDocumentRequest
    broker_publish_request: BrokerPublishOutputRequest
    broker_replace_request: BrokerReplaceOriginalRequest
    broker_delete_request: BrokerDeleteDocumentRequest
    broker_operation_request: BrokerOperationRequest
    broker_read_response: BrokerReadDocumentAllowed
    broker_output_response: BrokerOutputAllowed
    broker_operation_response: BrokerOperationResponse
    invoice_result: InvoiceResult
    receiver_health_response: ReceiverHealthResponse
    ingest_request: IngestRequest
    receipt_response: ReceiptResponse
    receiver_receipt_journal_record: ReceiverReceiptJournalRecord
    create_run_request: CreateRunRequest
    create_run_response: CreateRunResponse
    receipt_summary: ReceiptSummary
    receipts_response: ReceiptsResponse
    owner_bootstrap_exchange_request: OwnerBootstrapExchangeRequest
    owner_session_response: OwnerSessionResponse
    owner_logout_response: OwnerLogoutResponse


_ERROR_RESPONSES = {
    "400": "Invalid host or query",
    "401": "Authentication failed",
    "403": "Well-formed operation denied by policy",
    "404": "Identifier not found",
    "409": "Busy task, conflicting request, or duplicate run",
    "413": "Request body exceeds the documented limit",
    "422": "Strict request validation failed",
    "500": "Internal persistence or recovery failure",
    "503": "Protection unavailable",
}


def _schema_reference(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/schemas/{name}"}


def _json_content(model: str | dict[str, object]) -> dict[str, object]:
    schema = _schema_reference(model) if isinstance(model, str) else model
    return {"application/json": {"schema": schema}}


def _response(description: str, model: str | dict[str, object] | None = None) -> dict[str, object]:
    response: dict[str, object] = {"description": description}
    if model is not None:
        response["content"] = _json_content(model)
    return response


def _path_parameter(name: str, schema: dict[str, object]) -> dict[str, object]:
    return {
        "name": name,
        "in": "path",
        "required": True,
        "schema": schema,
    }


def _query_parameter(
    name: str,
    schema: dict[str, object],
    description: str,
    *,
    required: bool = False,
) -> dict[str, object]:
    return {
        "name": name,
        "in": "query",
        "required": required,
        "description": description,
        "schema": schema,
    }


def _security(name: str) -> list[dict[str, list[str]]]:
    return [{name: []}]


def _error_responses(statuses: tuple[str, ...]) -> dict[str, object]:
    return {
        status: _response(description, "ErrorResponse")
        for status, description in _ERROR_RESPONSES.items()
        if status in statuses
    }


def _operation(
    operation_id: str,
    summary: str,
    *,
    tags: list[str],
    success_status: str,
    response: str | dict[str, object] | None,
    request: str | dict[str, object] | None = None,
    security: list[dict[str, list[str]]] | None = None,
    parameters: list[dict[str, object]] | None = None,
    errors: tuple[str, ...] = (),
) -> dict[str, object]:
    result: dict[str, object] = {
        "operationId": operation_id,
        "summary": summary,
        "tags": tags,
        "responses": {
            success_status: _response("Successful Response", response),
            **_error_responses(errors),
        },
    }
    if security is not None:
        result["security"] = security
    if parameters:
        result["parameters"] = parameters
    if request is not None:
        request_schema = _schema_reference(request) if isinstance(request, str) else request
        result["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": request_schema}},
        }
    return result


def contract_paths(
    query_schemas: dict[str, dict[str, object]],
    path_id_schema: dict[str, object],
) -> dict[str, object]:
    """Build OpenAPI paths from the same strict types consumed by Pydantic and TypeScript."""

    owner = _security("OwnerSession")
    owner_mutation = [{"OwnerSession": [], "CsrfToken": []}]
    worker = _security("WorkerCredential")
    receiver_ingest = _security("ReceiverIngest")
    receiver_admin = _security("ReceiverAdmin")
    paths: dict[str, object] = {
        "/api/health": {
            "get": _operation(
                "getApiHealth",
                "Read local service health",
                tags=["health"],
                success_status="200",
                response="HealthResponse",
                errors=("400", "500"),
            )
        },
        "/api/owner/bootstrap/exchange": {
            "post": _operation(
                "exchangeOwnerBootstrap",
                "Exchange the one-time owner bootstrap secret",
                tags=["owner"],
                success_status="200",
                response="OwnerSessionResponse",
                request="OwnerBootstrapExchangeRequest",
                security=[],
                errors=("400", "401", "403", "413", "422", "500"),
            )
        },
        "/api/owner/session": {
            "get": _operation(
                "getOwnerSession",
                "Read current owner session status",
                tags=["owner"],
                success_status="200",
                response="OwnerSessionResponse",
                security=owner,
                errors=("400", "401", "500"),
            )
        },
        "/api/owner/session/logout": {
            "post": _operation(
                "logoutOwnerSession",
                "Revoke the current owner session",
                tags=["owner"],
                success_status="200",
                response="OwnerLogoutResponse",
                security=owner_mutation,
                errors=("400", "401", "403", "500"),
            )
        },
        "/api/documents": {
            "get": _operation(
                "listDocuments",
                "List registered document metadata",
                tags=["owner"],
                success_status="200",
                response="DocumentListResponse",
                security=owner,
                errors=("400", "401", "500"),
            )
        },
        "/api/tasks": {
            "get": _operation(
                "listTasks",
                "List recent tasks",
                tags=["owner"],
                success_status="200",
                response="TaskListResponse",
                security=owner,
                parameters=[
                    _query_parameter("limit", query_schemas["limit"], "Maximum rows; 1 through 50")
                ],
                errors=("400", "401", "500"),
            ),
            "post": _operation(
                "createTask",
                "Create an allowlisted task request",
                tags=["owner"],
                success_status="201",
                response="TaskRecord",
                request="CreateTaskRequest",
                security=owner_mutation,
                parameters=[
                    {
                        "name": "X-Aclais-Approval-Context",
                        "in": "header",
                        "required": True,
                        "schema": {"type": "string", "minLength": 1, "maxLength": 2048},
                        "description": "Short-lived server-signed context from the approval GET",
                    }
                ],
                errors=("400", "401", "403", "409", "413", "422", "500", "503"),
            ),
        },
        "/api/tasks/{task_id}": {
            "get": _operation(
                "getTask",
                "Read task, contract, output and incident metadata",
                tags=["owner"],
                success_status="200",
                response="TaskDetailResponse",
                security=owner,
                parameters=[_path_parameter("task_id", path_id_schema)],
                errors=("400", "401", "404", "500"),
            )
        },
        "/api/tasks/{task_id}/events": {
            "get": _operation(
                "getTaskEvents",
                "Read ordered task events",
                tags=["owner"],
                success_status="200",
                response="EventsResponse",
                security=owner,
                parameters=[
                    _path_parameter("task_id", path_id_schema),
                    _query_parameter(
                        "after_seq",
                        query_schemas["after_seq"],
                        "Return events with greater sequence numbers",
                    ),
                ],
                errors=("400", "401", "404", "500"),
            )
        },
        "/api/tasks/{task_id}/cancel": {
            "post": _operation(
                "cancelTask",
                "Request task cancellation",
                tags=["owner"],
                success_status="200",
                response="CancelResponse",
                security=owner_mutation,
                parameters=[_path_parameter("task_id", path_id_schema)],
                errors=("400", "401", "403", "404", "409", "500"),
            )
        },
        "/api/tasks/{task_id}/evidence": {
            "get": _operation(
                "getTaskEvidence",
                "Read verification report or pending state",
                tags=["owner"],
                success_status="200",
                response="EvidenceResponse",
                security=owner,
                parameters=[_path_parameter("task_id", path_id_schema)],
                errors=("400", "401", "404", "500"),
            )
        },
        "/api/outputs/{output_id}": {
            "get": _operation(
                "getOutput",
                "Download inert, committed task output",
                tags=["owner"],
                success_status="200",
                response={"type": "string", "format": "binary"},
                security=owner,
                parameters=[_path_parameter("output_id", path_id_schema)],
                errors=("400", "401", "404", "409", "500"),
            )
        },
        "/api/broker/operations": {
            "post": _operation(
                "brokerOperation",
                "Submit a strict worker operation",
                tags=["broker"],
                success_status="200",
                response="BrokerOperationResponse",
                request="BrokerOperationRequest",
                security=worker,
                errors=("400", "401", "403", "409", "413", "422", "500", "503"),
            )
        },
        "/approve": {
            "get": {
                "operationId": "getApprovalPage",
                "summary": "Render the side-effect-free owner approval page",
                "tags": ["owner"],
                "security": owner,
                "parameters": [
                    _query_parameter(
                        "tool_id",
                        query_schemas["approval_tool_id"],
                        "Tool selected by the fixed approval allowlist",
                        required=True,
                    ),
                    _query_parameter(
                        "launch_source_claim",
                        query_schemas["approval_launch_source_claim"],
                        "Fixed launch source claim",
                        required=True,
                    ),
                ],
                "responses": {
                    "200": {
                        "description": "Trusted approval page",
                        "content": {"text/html": {"schema": {"type": "string"}}},
                    },
                    **_error_responses(("400", "401", "500")),
                },
            }
        },
        "/health": {
            "get": _operation(
                "getReceiverHealth",
                "Read receiver process health",
                tags=["receiver"],
                success_status="200",
                response="ReceiverHealthResponse",
                errors=("400", "500"),
            )
        },
        "/ingest": {
            "post": _operation(
                "ingestReceipt",
                "Durably accept or replay a run receipt",
                tags=["receiver"],
                success_status="201",
                response="ReceiptResponse",
                request="IngestRequest",
                security=receiver_ingest,
                errors=("400", "401", "409", "413", "422", "500"),
            )
        },
        "/admin/runs": {
            "post": _operation(
                "createReceiverRun",
                "Create an empty receiver run",
                tags=["receiver-admin"],
                success_status="201",
                response="CreateRunResponse",
                request="CreateRunRequest",
                security=receiver_admin,
                errors=("400", "401", "409", "413", "422", "500"),
            )
        },
        "/admin/runs/{run_id}/receipts": {
            "get": _operation(
                "getReceiverReceipts",
                "Read committed receipt summaries",
                tags=["receiver-admin"],
                success_status="200",
                response="ReceiptsResponse",
                security=receiver_admin,
                parameters=[_path_parameter("run_id", path_id_schema)],
                errors=("400", "401", "404", "500"),
            )
        },
    }

    output_response = paths["/api/outputs/{output_id}"]["get"]["responses"]["200"]
    output_response["description"] = (
        "Inert attachment with nosniff; media type follows the committed output kind."
    )
    output_response["headers"] = {
        "Content-Disposition": {"schema": {"type": "string"}},
        "X-Content-Type-Options": {"schema": {"type": "string", "const": "nosniff"}},
    }
    output_response["content"] = {
        "text/markdown": {"schema": {"type": "string"}},
        "application/json": {"schema": {"type": "string"}},
    }

    for path, item in paths.items():
        path_parameters = [
            parameter
            for operation in item.values()
            if isinstance(operation, dict)
            for parameter in operation.get("parameters", [])
            if parameter.get("in") == "path"
        ]
        if path_parameters:
            item["parameters"] = path_parameters
            for operation in item.values():
                if isinstance(operation, dict) and "parameters" in operation:
                    operation["parameters"] = [
                        p for p in operation["parameters"] if p.get("in") != "path"
                    ]
    return paths


def build_openapi_document(app: object) -> dict[str, object]:
    """Combine the mounted health contract with the complete versioned wire contract."""

    document = app.openapi()
    catalog = ContractSchemaCatalog.model_json_schema(ref_template="#/components/schemas/{model}")
    schemas = catalog.pop("$defs", {})
    properties = catalog.get("properties", {})
    schemas["BrokerOperationRequest"] = properties["broker_operation_request"]
    schemas["BrokerOperationResponse"] = properties["broker_operation_response"]
    paths = contract_paths(
        {
            "limit": schemas["TaskListQuery"]["properties"]["limit"],
            "after_seq": schemas["EventsQuery"]["properties"]["after_seq"],
            "approval_tool_id": schemas["ApprovalQuery"]["properties"]["tool_id"],
            "approval_launch_source_claim": schemas["ApprovalQuery"]["properties"][
                "launch_source_claim"
            ],
        },
        TypeAdapter(UUIDValue).json_schema(),
    )
    document["info"]["description"] = (
        "Versioned ACLAIS and receiver wire contracts are generated from strict backend models. "
        "Only the A1 health route is currently implemented; later routes are contract definitions."
    )
    document["paths"] = paths
    document["components"]["schemas"].update(schemas)
    document["components"]["securitySchemes"] = {
        "OwnerSession": {"type": "apiKey", "in": "cookie", "name": "aclais_owner_session"},
        "CsrfToken": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token"},
        "WorkerCredential": {"type": "http", "scheme": "bearer"},
        "ReceiverIngest": {"type": "http", "scheme": "bearer"},
        "ReceiverAdmin": {"type": "http", "scheme": "bearer"},
    }
    document["tags"] = [
        {"name": "health"},
        {"name": "owner"},
        {"name": "broker"},
        {"name": "receiver"},
        {"name": "receiver-admin"},
    ]
    return document
