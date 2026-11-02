"""Strict receiver wire and journal value models."""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime, timedelta
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

SCHEMA_VERSION = Literal[1]
MAX_RECEIPT_BYTES = 1_048_576
MAX_REQUEST_BYTES = 2_097_152
MAX_RUN_BYTES = 10 * 1_048_576
MAX_BASE64_LENGTH = MAX_REQUEST_BYTES


def _uuid_value(value: object) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ValueError("must be a canonical UUID string")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise ValueError("must be a canonical UUID string")
    return parsed


def _utc_datetime(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    return value.astimezone(UTC)


def _datetime_value(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
    raise ValueError("timestamp must be ISO-8601")


UUIDValue = Annotated[UUID, BeforeValidator(_uuid_value)]
UtcDateTime = Annotated[datetime, BeforeValidator(_datetime_value), AfterValidator(_utc_datetime)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
CanaryMarker = Annotated[str, StringConstraints(min_length=16, max_length=128, strict=True)]
Base64Payload = Annotated[str, StringConstraints(max_length=MAX_BASE64_LENGTH, strict=True)]
RequestId = UUIDValue


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class IngestRequest(StrictModel):
    schema_version: SCHEMA_VERSION
    request_id: RequestId
    run_id: UUIDValue
    task_id: UUIDValue
    payload_base64: Base64Payload

    @field_validator("payload_base64")
    @classmethod
    def validate_base64(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("payload_base64 must use strict RFC 4648 base64") from exc
        if base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("payload_base64 must use canonical RFC 4648 encoding")
        return value

    @property
    def decoded_payload(self) -> bytes:
        return base64.b64decode(self.payload_base64, validate=True)

    @model_validator(mode="after")
    def request_version_is_supported(self) -> IngestRequest:
        if self.schema_version != 1:
            raise ValueError("unsupported schema version")
        return self


class CreateRunRequest(StrictModel):
    schema_version: SCHEMA_VERSION
    run_id: UUIDValue
    canary_marker: CanaryMarker

    @field_validator("canary_marker")
    @classmethod
    def printable_ascii_marker(cls, value: str) -> str:
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
            raise ValueError("canary marker must be printable ASCII")
        return value


class ErrorDetail(StrictModel):
    code: Literal[
        "INVALID_HOST",
        "INVALID_REQUEST",
        "NOT_FOUND",
        "PAYLOAD_TOO_LARGE",
        "RATE_LIMITED",
        "AUTH_INVALID",
        "REQUEST_CONFLICT",
        "PROTECTION_UNAVAILABLE",
        "INTERNAL_ERROR",
    ]
    message: Annotated[str, StringConstraints(min_length=1, max_length=256, strict=True)]
    request_id: UUIDValue


class ErrorResponse(StrictModel):
    schema_version: SCHEMA_VERSION
    error: ErrorDetail


class ReceiverHealthResponse(StrictModel):
    schema_version: SCHEMA_VERSION
    status: Literal["ready", "unavailable"]
    version: Annotated[str, StringConstraints(min_length=1, max_length=256, strict=True)]


class CreateRunResponse(StrictModel):
    schema_version: SCHEMA_VERSION
    run_id: UUIDValue
    ingest_token: Annotated[str, StringConstraints(min_length=32, max_length=512, strict=True)]


class ReceiptResponse(StrictModel):
    schema_version: SCHEMA_VERSION
    receipt_id: UUIDValue
    received_at: UtcDateTime
    decoded_bytes: int = Field(ge=0, le=MAX_RECEIPT_BYTES, strict=True)
    sha256: Sha256


class ReceiptSummary(StrictModel):
    receipt_id: UUIDValue
    task_id: UUIDValue
    received_at: UtcDateTime
    decoded_bytes: int = Field(ge=0, le=MAX_RECEIPT_BYTES, strict=True)
    sha256: Sha256
    marker_match: bool


class ReceiptsResponse(StrictModel):
    schema_version: SCHEMA_VERSION
    run_id: UUIDValue
    receipts: tuple[ReceiptSummary, ...]
    marker_received: bool

    @model_validator(mode="after")
    def marker_matches_receipts(self) -> ReceiptsResponse:
        if self.marker_received != any(receipt.marker_match for receipt in self.receipts):
            raise ValueError("marker_received must match the receipt summaries")
        return self


def canonical_body_sha256(model: StrictModel) -> str:
    """Hash only the canonical validated request representation."""
    import hashlib
    import json

    canonical = json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")
    return hashlib.sha256(canonical).hexdigest()
