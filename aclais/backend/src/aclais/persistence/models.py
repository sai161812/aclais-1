"""Strict persistence and wire models for the ACLAIS v1 contract."""

from __future__ import annotations

import base64
import binascii
import re
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

SchemaVersion = Literal[1]
ToolId = Literal["report_formatter", "invoice_analyzer"]
DocumentId = Literal["doc-report", "doc-notes", "doc-invoice", "doc-private"]
OutputKind = Literal["formatted_markdown", "invoice_json"]
Operation = Literal["read_document", "publish_output", "replace_original", "delete_document"]
EventSource = Literal["controller", "broker", "worker_reported", "verifier"]
Sensitivity = Literal["standard", "confidential"]
ProtectionStatus = Literal["ready", "unverified", "unavailable"]
VerificationStatus = Literal["pending", "pass", "fail", "unknown", "not_applicable"]
ContainmentStatus = Literal["pending", "terminated", "failed"]
ReasonCode = Literal[
    "DOCUMENT_OUT_OF_SCOPE",
    "ORIGINAL_MUTATION_FORBIDDEN",
    "TASK_REVOKED",
    "AUTH_INVALID",
    "OUTPUT_ALREADY_PUBLISHED",
    "INVALID_REQUEST",
    "PROTECTION_UNAVAILABLE",
    "WORKER_TIMEOUT",
    "VERIFICATION_INCOMPLETE",
    "CONTROLLER_SHUTDOWN",
    "PUBLICATION_INCONSISTENT",
]


class TaskStatus(StrEnum):
    CREATED = "CREATED"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    REVOKING = "REVOKING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class RevocationCause(StrEnum):
    POLICY_DENIED = "POLICY_DENIED"
    CANCELLED = "CANCELLED"
    WORKER_TIMEOUT = "WORKER_TIMEOUT"
    CONTROLLER_SHUTDOWN = "CONTROLLER_SHUTDOWN"


class TerminalCause(StrEnum):
    POLICY_DENIED = "POLICY_DENIED"
    CANCELLED = "CANCELLED"
    WORKER_TIMEOUT = "WORKER_TIMEOUT"
    CONTROLLER_SHUTDOWN = "CONTROLLER_SHUTDOWN"
    WORKER_EXIT_SUCCESS = "WORKER_EXIT_SUCCESS"
    WORKER_EXIT_FAILURE = "WORKER_EXIT_FAILURE"
    PREPARATION_FAILED = "PREPARATION_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    RECOVERY_INTERRUPTED = "RECOVERY_INTERRUPTED"


class JournalState(StrEnum):
    RESERVED = "reserved"
    STAGED = "staged"
    FILE_COMMITTED = "file_committed"
    PUBLISHED = "published"
    ABORTED = "aborted"
    INCONSISTENT = "inconsistent"


class ReceiptJournalState(StrEnum):
    RESERVED = "reserved"
    STAGED = "staged"
    FILE_COMMITTED = "file_committed"
    COMMITTED = "committed"
    ABORTED = "aborted"
    INCONSISTENT = "inconsistent"


def _uuid_value(value: object) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ValueError("must be a UUID string")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("must be a UUID string") from exc
    if str(parsed) != value:
        raise ValueError("must use canonical UUID syntax")
    return parsed


UUIDValue = Annotated[UUID, BeforeValidator(_uuid_value)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
BoundedMessage = Annotated[str, StringConstraints(min_length=1, max_length=2048, strict=True)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=256, strict=True)]


def _datetime_value(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("must be an ISO-8601 timestamp") from exc
    else:
        raise ValueError("must be an ISO-8601 timestamp")
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed


def _utc_datetime(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamps must be UTC")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, BeforeValidator(_datetime_value), AfterValidator(_utc_datetime)]


def _supported_tool_document(tool_id: str, document_id: str) -> bool:
    return (tool_id, document_id) in {
        ("report_formatter", "doc-report"),
        ("invoice_analyzer", "doc-invoice"),
    }


def _iso_date_value(value: object) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("must be an ISO-8601 calendar date") from exc
        if parsed.isoformat() != value:
            raise ValueError("date must use YYYY-MM-DD form")
        return parsed
    raise ValueError("must be an ISO-8601 calendar date")


IsoDate = Annotated[date, BeforeValidator(_iso_date_value)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)


class HealthCheck(StrictModel):
    id: Literal["application_api", "g1_protection"]
    status: Literal["pass", "fail", "unknown"]
    summary: ShortText


class HealthResponse(StrictModel):
    schema_version: SchemaVersion
    status: Literal["ready", "unavailable"]
    protection_ready: bool
    checks: tuple[HealthCheck, ...]


class CreateTaskRequest(StrictModel):
    """Only client supplied task choices; all paths and grants remain controller-owned."""

    schema_version: SchemaVersion
    tool_id: ToolId
    selected_document_id: DocumentId
    launch_source_claim: Literal["document_tools"]

    @model_validator(mode="after")
    def validate_tool_document_pair(self) -> CreateTaskRequest:
        if not _supported_tool_document(self.tool_id, self.selected_document_id):
            raise ValueError("tool and selected document are not a supported pair")
        return self


class ApprovalQuery(StrictModel):
    tool_id: ToolId
    launch_source_claim: Literal["document_tools"]


class DocumentSummary(StrictModel):
    id: DocumentId
    display_name: ShortText
    media_type: ShortText
    size_bytes: int | None = Field(ge=0)
    sensitivity: Sensitivity
    protection_status: ProtectionStatus
    last_verified_at: UtcDateTime | None


class DocumentListResponse(StrictModel):
    schema_version: SchemaVersion
    documents: tuple[DocumentSummary, ...]


class TaskRecord(StrictModel):
    schema_version: SchemaVersion
    task_id: UUIDValue
    run_id: UUIDValue
    tool_id: ToolId
    selected_document_id: DocumentId
    contract_id: UUIDValue
    status: TaskStatus
    created_at: UtcDateTime
    started_at: UtcDateTime | None
    finished_at: UtcDateTime | None
    worker_pid: int | None = Field(default=None, gt=0)
    worker_sid: (
        Annotated[str, StringConstraints(min_length=1, max_length=184, strict=True)] | None
    ) = None
    launch_source_claim: Literal["document_tools"]
    observed_origin: Annotated[str, StringConstraints(max_length=512, strict=True)] | None = None
    observed_referer: Annotated[str, StringConstraints(max_length=2048, strict=True)] | None = None
    incident_id: UUIDValue | None
    revocation_cause: RevocationCause | None = None
    terminal_cause: TerminalCause | None = None

    @model_validator(mode="after")
    def validate_lifecycle_fields(self) -> TaskRecord:
        if (self.worker_pid is None) != (self.worker_sid is None):
            raise ValueError("worker PID and SID must be present together")
        if not _supported_tool_document(self.tool_id, self.selected_document_id):
            raise ValueError("tool and selected document are not a supported pair")
        terminal = self.status in {
            TaskStatus.COMPLETED,
            TaskStatus.BLOCKED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
        if terminal != (self.finished_at is not None):
            raise ValueError("finished_at must be present exactly for terminal tasks")
        if terminal != (self.terminal_cause is not None):
            raise ValueError("terminal_cause must be present exactly for terminal tasks")
        if (
            self.status == TaskStatus.COMPLETED
            and self.terminal_cause != TerminalCause.WORKER_EXIT_SUCCESS
        ):
            raise ValueError("COMPLETED requires a verified successful worker exit")
        if self.status == TaskStatus.BLOCKED and self.terminal_cause != TerminalCause.POLICY_DENIED:
            raise ValueError("BLOCKED requires a policy denial")
        if self.status == TaskStatus.CANCELLED and self.terminal_cause != TerminalCause.CANCELLED:
            raise ValueError("CANCELLED requires an explicit cancellation")
        if (
            self.terminal_cause == TerminalCause.WORKER_EXIT_SUCCESS
            and self.status != TaskStatus.COMPLETED
        ):
            raise ValueError("a successful worker exit can only complete a task")
        if self.revocation_cause is not None and self.terminal_cause is not None:
            if self.revocation_cause.value != self.terminal_cause.value:
                raise ValueError("terminal outcome cannot replace the committed revocation cause")
        if self.terminal_cause in {
            TerminalCause.CANCELLED,
            TerminalCause.WORKER_TIMEOUT,
            TerminalCause.CONTROLLER_SHUTDOWN,
            TerminalCause.POLICY_DENIED,
        }:
            if self.revocation_cause is None:
                raise ValueError("revocation terminal causes require a committed revocation")
        if self.status == TaskStatus.REVOKING and self.revocation_cause is None:
            raise ValueError("revocation cause is required in REVOKING")
        if self.revocation_cause is not None and self.status not in {
            TaskStatus.REVOKING,
            TaskStatus.VERIFYING,
            TaskStatus.BLOCKED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }:
            raise ValueError("revocation cause is invalid before revocation")
        if self.started_at is not None and self.started_at < self.created_at:
            raise ValueError("started_at cannot precede created_at")
        if (
            self.finished_at is not None
            and self.started_at is not None
            and self.finished_at < self.started_at
        ):
            raise ValueError("finished_at cannot precede started_at")
        return self


class TaskSummary(StrictModel):
    task_id: UUIDValue
    tool_id: ToolId
    selected_document_id: DocumentId
    status: TaskStatus
    created_at: UtcDateTime
    finished_at: UtcDateTime | None
    incident_id: UUIDValue | None

    @model_validator(mode="after")
    def validate_tool_document_pair(self) -> TaskSummary:
        if not _supported_tool_document(self.tool_id, self.selected_document_id):
            raise ValueError("tool and selected document are not a supported pair")
        return self


class TaskListResponse(StrictModel):
    schema_version: SchemaVersion
    tasks: tuple[TaskSummary, ...]


AllowedOperations = tuple[Literal["read_document"], Literal["publish_output"]]


class ContractSummary(StrictModel):
    contract_id: UUIDValue
    task_id: UUIDValue
    selected_document_id: DocumentId
    allowed_operations: AllowedOperations
    output_slot_id: UUIDValue
    expires_at: UtcDateTime
    policy_version: Literal["1"]


class ActionContractRecord(ContractSummary):
    created_at: UtcDateTime


class OutputMetadata(StrictModel):
    output_id: UUIDValue
    task_id: UUIDValue
    output_kind: OutputKind
    file_name: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}\.(md|json)$", strict=True)]
    decoded_bytes: int = Field(ge=0, le=1_048_576)
    sha256: Sha256
    created_at: UtcDateTime

    @model_validator(mode="after")
    def filename_matches_server_output_id(self) -> OutputMetadata:
        suffix = ".md" if self.output_kind == "formatted_markdown" else ".json"
        if self.file_name != f"{self.output_id}{suffix}":
            raise ValueError("output file name must be derived from its controller output ID")
        return self


class Incident(StrictModel):
    incident_id: UUIDValue
    task_id: UUIDValue
    trigger_event_id: UUIDValue
    policy_reason: Literal["DOCUMENT_OUT_OF_SCOPE", "ORIGINAL_MUTATION_FORBIDDEN"]
    containment_status: ContainmentStatus
    integrity_status: VerificationStatus
    confidentiality_status: VerificationStatus
    evidence_refs: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=512, strict=True)], ...
    ]

    @field_validator("evidence_refs")
    @classmethod
    def evidence_refs_are_trusted_relative(cls, refs: tuple[str, ...]) -> tuple[str, ...]:
        for ref in refs:
            path = PurePosixPath(ref)
            if (
                path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
                or "\\" in ref
            ):
                raise ValueError("evidence references must be trusted relative paths")
        return refs


class TaskDetailResponse(StrictModel):
    schema_version: SchemaVersion
    task: TaskRecord
    contract_summary: ContractSummary | None
    output_metadata: OutputMetadata | None
    incident_summary: Incident | None


class CancelResponse(StrictModel):
    schema_version: SchemaVersion
    task_id: UUIDValue
    status: TaskStatus


def _query_integer(value: object, *, allow_zero: bool) -> int:
    if isinstance(value, bool):
        raise ValueError("must be a decimal integer")
    if isinstance(value, int):
        return value
    if (
        not isinstance(value, str)
        or re.fullmatch(r"0|[1-9][0-9]{0,8}", value, flags=re.ASCII) is None
    ):
        raise ValueError("must be a decimal integer")
    parsed = int(value)
    if parsed == 0 and not allow_zero:
        raise ValueError("must be positive")
    return parsed


class TaskListQuery(StrictModel):
    limit: Annotated[
        int, BeforeValidator(lambda value: _query_integer(value, allow_zero=False))
    ] = Field(default=20, ge=1, le=50)


class EventsQuery(StrictModel):
    after_seq: Annotated[
        int, BeforeValidator(lambda value: _query_integer(value, allow_zero=True))
    ] = Field(default=0, ge=0, le=999_999_999)


class EventRecord(StrictModel):
    schema_version: SchemaVersion
    event_id: UUIDValue
    task_id: UUIDValue
    run_id: UUIDValue
    seq: int = Field(ge=1)
    timestamp: UtcDateTime
    source: EventSource
    kind: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$", strict=True)]
    operation: Operation | None
    target_document_id: DocumentId | None
    decision: Literal["allow", "deny"] | None
    reason_code: ReasonCode | None
    message: BoundedMessage
    evidence_refs: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=512, strict=True)], ...
    ]

    @field_validator("evidence_refs")
    @classmethod
    def evidence_refs_are_trusted_relative(cls, refs: tuple[str, ...]) -> tuple[str, ...]:
        for ref in refs:
            path = PurePosixPath(ref)
            if (
                path.is_absolute()
                or "\\" in ref
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise ValueError("evidence references must be trusted relative paths")
        return refs


class EventsResponse(StrictModel):
    schema_version: SchemaVersion
    events: tuple[EventRecord, ...]
    last_seq: int = Field(ge=0)


class TaskStateTransitionRecord(StrictModel):
    task_id: UUIDValue
    seq: int = Field(ge=1)
    from_status: TaskStatus | None
    to_status: TaskStatus
    cause: Annotated[str, StringConstraints(max_length=64, strict=True)] | None
    timestamp: UtcDateTime


class CredentialHashRecord(StrictModel):
    task_id: UUIDValue
    token_sha256: Sha256
    created_at: UtcDateTime
    expires_at: UtcDateTime
    revoked_at: UtcDateTime | None

    @model_validator(mode="after")
    def expiry_is_bounded(self) -> CredentialHashRecord:
        lifetime = (self.expires_at - self.created_at).total_seconds()
        if not 0 < lifetime <= 120:
            raise ValueError("credential lifetime must be at most 120 seconds")
        if self.revoked_at is not None and self.revoked_at < self.created_at:
            raise ValueError("revocation cannot precede credential creation")
        return self


class DeduplicationRecord(StrictModel):
    task_id: UUIDValue
    request_id: UUIDValue
    canonical_body_sha256: Sha256
    state: Literal["reserved", "completed"]
    response_json: Annotated[str, StringConstraints(max_length=2_097_152, strict=True)] | None
    created_at: UtcDateTime
    updated_at: UtcDateTime

    @model_validator(mode="after")
    def response_matches_state(self) -> DeduplicationRecord:
        if (self.state == "completed") != (self.response_json is not None):
            raise ValueError("completed requests require a stored response")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        return self


class OutputJournalRecord(StrictModel):
    task_id: UUIDValue
    request_id: UUIDValue
    output_id: UUIDValue
    output_slot_id: UUIDValue
    output_kind: OutputKind
    staging_relative_path: Annotated[
        str, StringConstraints(min_length=1, max_length=512, strict=True)
    ]
    final_relative_path: Annotated[
        str, StringConstraints(min_length=1, max_length=512, strict=True)
    ]
    content_sha256: Sha256
    decoded_bytes: int = Field(ge=0, le=1_048_576)
    state: JournalState
    created_at: UtcDateTime
    updated_at: UtcDateTime

    @field_validator("staging_relative_path", "final_relative_path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or "\\" in value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("journal paths must be trusted relative paths")
        if ":" in value:
            raise ValueError("journal paths cannot contain drive or stream syntax")
        return value

    @model_validator(mode="after")
    def output_names_are_derived(self) -> OutputJournalRecord:
        suffix = ".md" if self.output_kind == "formatted_markdown" else ".json"
        prefix = f"{self.task_id}/"
        if self.staging_relative_path != f"{prefix}{self.output_id}.staging":
            raise ValueError("staging path must be derived from controller IDs")
        if self.final_relative_path != f"{prefix}{self.output_id}{suffix}":
            raise ValueError("final path must be derived from controller IDs")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        return self


class ReceiverReceiptJournalRecord(StrictModel):
    """Receiver-owned journal schema; it is not stored in the ACLAIS database."""

    run_id: UUIDValue
    request_id: UUIDValue
    task_id: UUIDValue
    canonical_body_sha256: Sha256
    receipt_id: UUIDValue
    staging_relative_path: Annotated[
        str, StringConstraints(min_length=1, max_length=512, strict=True)
    ]
    payload_relative_path: Annotated[
        str, StringConstraints(min_length=1, max_length=512, strict=True)
    ]
    payload_sha256: Sha256
    decoded_bytes: int = Field(ge=0, le=1_048_576)
    marker_match: bool
    state: ReceiptJournalState
    received_at: UtcDateTime

    @field_validator("staging_relative_path", "payload_relative_path")
    @classmethod
    def receipt_paths_are_trusted_relative(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or "\\" in value
            or ":" in value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("receipt journal paths must be trusted relative paths")
        return value

    @model_validator(mode="after")
    def receipt_filenames_are_id_derived(self) -> ReceiverReceiptJournalRecord:
        if self.staging_relative_path != f"staging/{self.receipt_id}.stage":
            raise ValueError("staging path must be derived from the receipt ID")
        if self.payload_relative_path != f"payloads/{self.receipt_id}.bin":
            raise ValueError("payload path must be derived from the receipt ID")
        return self


class EvidenceCheck(StrictModel):
    id: ShortText
    status: VerificationStatus
    observed: Annotated[str, StringConstraints(max_length=2048, strict=True)]
    expected: Annotated[str, StringConstraints(max_length=2048, strict=True)]
    artifact_path: Annotated[str, StringConstraints(min_length=1, max_length=512, strict=True)]

    @field_validator("artifact_path")
    @classmethod
    def artifact_path_is_trusted_relative(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or "\\" in value
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("artifact paths must be trusted relative paths")
        return value


class EvidenceReport(StrictModel):
    report_id: UUIDValue
    task_id: UUIDValue
    run_id: UUIDValue
    generated_at: UtcDateTime
    verifier_version: ShortText
    file_inventory_before: tuple[ShortText, ...]
    file_inventory_after: tuple[ShortText, ...]
    differences: tuple[ShortText, ...]
    receiver_status: Literal["pass", "fail", "unknown", "not_applicable"]
    receipt_ids: tuple[UUIDValue, ...]
    marker_received: bool | None
    worker_exit_observed: bool
    checks: tuple[EvidenceCheck, ...]


class EvidenceResponse(StrictModel):
    schema_version: SchemaVersion
    status: Literal["pending", "complete"]
    report: EvidenceReport | None

    @model_validator(mode="after")
    def report_matches_status(self) -> EvidenceResponse:
        if (self.status == "complete") != (self.report is not None):
            raise ValueError("complete evidence requires a report")
        return self


class ApiError(StrictModel):
    code: Literal[
        "INVALID_HOST",
        "INVALID_REQUEST",
        "NOT_FOUND",
        "PAYLOAD_TOO_LARGE",
        "AUTH_INVALID",
        "POLICY_DENIED",
        "TASK_BUSY",
        "REQUEST_CONFLICT",
        "OUTPUT_ALREADY_PUBLISHED",
        "PROTECTION_UNAVAILABLE",
        "WORKER_TIMEOUT",
        "VERIFICATION_INCOMPLETE",
        "CONTROLLER_SHUTDOWN",
        "PUBLICATION_INCONSISTENT",
        "INTERNAL_ERROR",
    ]
    message: BoundedMessage
    request_id: UUIDValue


class ErrorResponse(StrictModel):
    schema_version: SchemaVersion
    error: ApiError


class BrokerReadDocumentRequest(StrictModel):
    schema_version: SchemaVersion
    request_id: UUIDValue
    operation: Literal["read_document"]
    document_id: DocumentId


class InvoiceResult(StrictModel):
    vendor: Annotated[str, StringConstraints(min_length=1, max_length=256, strict=True)]
    invoice_number: Annotated[str, StringConstraints(min_length=1, max_length=128, strict=True)]
    date: IsoDate
    line_total: Annotated[
        str,
        StringConstraints(
            min_length=4,
            max_length=64,
            pattern=r"^(?:0|[1-9][0-9]{0,60})\.[0-9]{2}$",
            strict=True,
        ),
    ]
    grand_total: Annotated[
        str,
        StringConstraints(
            min_length=4,
            max_length=64,
            pattern=r"^(?:0|[1-9][0-9]{0,60})\.[0-9]{2}$",
            strict=True,
        ),
    ]

    @field_validator("line_total", "grand_total")
    @classmethod
    def finite_decimal(cls, value: str) -> str:
        try:
            amount = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError("must be a finite decimal") from exc
        if not amount.is_finite() or amount < 0:
            raise ValueError("must be a non-negative finite decimal")
        return value


class BrokerPublishOutputRequest(StrictModel):
    schema_version: SchemaVersion
    request_id: UUIDValue
    operation: Literal["publish_output"]
    output_kind: OutputKind
    output_text: Annotated[str, StringConstraints(max_length=1_048_576, strict=True)]

    @field_validator("output_text")
    @classmethod
    def output_is_bounded_utf8(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("output_text must be valid Unicode") from exc
        if len(encoded) > 1_048_576:
            raise ValueError("output_text exceeds the decoded byte limit")
        return value

    @model_validator(mode="after")
    def invoice_output_matches_contract(self) -> BrokerPublishOutputRequest:
        if self.output_kind == "invoice_json":
            from aclais.strict_json import parse_strict_json

            try:
                parse_strict_json(self.output_text.encode("utf-8"), InvoiceResult)
            except ValueError as exc:
                raise ValueError(
                    "invoice_json must match the strict invoice result schema"
                ) from exc
        return self

    def validate_for_tool(self, tool_id: ToolId) -> BrokerPublishOutputRequest:
        if tool_id not in {"report_formatter", "invoice_analyzer"}:
            raise ValueError("unknown controller-selected tool")
        expected_kind: OutputKind = (
            "formatted_markdown" if tool_id == "report_formatter" else "invoice_json"
        )
        if self.output_kind != expected_kind:
            raise ValueError("output kind is not allowed for this controller-selected tool")
        return self


class BrokerReplaceOriginalRequest(StrictModel):
    schema_version: SchemaVersion
    request_id: UUIDValue
    operation: Literal["replace_original"]
    document_id: DocumentId
    replacement_text: Annotated[str, StringConstraints(max_length=1_048_576, strict=True)]

    @field_validator("replacement_text")
    @classmethod
    def replacement_is_bounded_utf8(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("replacement_text must be valid Unicode") from exc
        if len(encoded) > 1_048_576:
            raise ValueError("replacement_text exceeds the decoded byte limit")
        return value


class BrokerDeleteDocumentRequest(StrictModel):
    schema_version: SchemaVersion
    request_id: UUIDValue
    operation: Literal["delete_document"]
    document_id: DocumentId


class BrokerReadDocumentAllowed(StrictModel):
    schema_version: SchemaVersion
    decision: Literal["allow"]
    document_id: DocumentId
    content_text: Annotated[str, StringConstraints(max_length=1_048_576, strict=True)]


class BrokerOutputAllowed(StrictModel):
    schema_version: SchemaVersion
    decision: Literal["allow"]
    output_id: UUIDValue
    sha256: Sha256


class ReceiverHealthResponse(StrictModel):
    schema_version: SchemaVersion
    status: Literal["ready", "unavailable"]
    version: ShortText


class IngestRequest(StrictModel):
    schema_version: SchemaVersion
    request_id: UUIDValue
    run_id: UUIDValue
    task_id: UUIDValue
    payload_base64: Annotated[str, StringConstraints(max_length=1_398_104, strict=True)]

    @field_validator("payload_base64")
    @classmethod
    def strict_bounded_base64(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("payload_base64 must use strict RFC 4648 base64") from exc
        if len(decoded) > 1_048_576:
            raise ValueError("decoded payload exceeds 1 MiB")
        return value


class ReceiptResponse(StrictModel):
    schema_version: SchemaVersion
    receipt_id: UUIDValue
    received_at: UtcDateTime
    decoded_bytes: int = Field(ge=0, le=1_048_576)
    sha256: Sha256


class CreateRunRequest(StrictModel):
    schema_version: SchemaVersion
    run_id: UUIDValue
    canary_marker: Annotated[str, StringConstraints(min_length=16, max_length=128, strict=True)]

    @field_validator("canary_marker")
    @classmethod
    def printable_ascii_marker(cls, value: str) -> str:
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
            raise ValueError("canary marker must be printable ASCII")
        return value


class CreateRunResponse(StrictModel):
    schema_version: SchemaVersion
    run_id: UUIDValue
    ingest_token: Annotated[str, StringConstraints(min_length=32, max_length=512, strict=True)]


class ReceiptSummary(StrictModel):
    receipt_id: UUIDValue
    task_id: UUIDValue
    received_at: UtcDateTime
    decoded_bytes: int = Field(ge=0, le=1_048_576)
    sha256: Sha256
    marker_match: bool


class ReceiptsResponse(StrictModel):
    schema_version: SchemaVersion
    run_id: UUIDValue
    receipts: tuple[ReceiptSummary, ...]
    marker_received: bool

    @model_validator(mode="after")
    def marker_matches_receipts(self) -> ReceiptsResponse:
        if self.marker_received != any(receipt.marker_match for receipt in self.receipts):
            raise ValueError("marker_received must match the receipt summaries")
        return self
