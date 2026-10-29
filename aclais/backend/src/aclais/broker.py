"""Strict worker broker using controller identity, grants, and filesystem registries."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from pydantic import TypeAdapter, ValidationError

from aclais.api_contracts import BrokerOperationRequest, BrokerOperationResponse
from aclais.concurrency import TaskLockRegistry
from aclais.persistence.database import (
    TRUSTED_DOCUMENTS,
    CredentialInvalid,
    Database,
    DatabaseError,
    RequestConflict,
    RequestDisposition,
    RequestInProgress,
    canonical_body_sha256,
    utc_now,
)
from aclais.persistence.models import (
    ApiError,
    BrokerDeleteDocumentRequest,
    BrokerOutputAllowed,
    BrokerPublishOutputRequest,
    BrokerReadDocumentAllowed,
    BrokerReadDocumentRequest,
    BrokerReplaceOriginalRequest,
    ErrorResponse,
    TaskRecord,
)
from aclais.publication import (
    MAX_OUTPUT_BYTES,
    OutputCollision,
    OutputPublisher,
    OutputUnavailable,
    PublicationError,
)
from aclais.strict_json import MAX_JSON_BODY_BYTES, decode_strict_json

_LOGGER = logging.getLogger("aclais.broker")
_REQUEST_ADAPTER = TypeAdapter(BrokerOperationRequest)
_RESPONSE_ADAPTER = TypeAdapter(BrokerReadDocumentAllowed | BrokerOutputAllowed)
_RECOGNIZED_DOCUMENTS = frozenset(document.id for document in TRUSTED_DOCUMENTS)
type BrokerResponse = BrokerOperationResponse | ErrorResponse


@dataclass(frozen=True, slots=True)
class BrokerResult:
    status_code: int
    body: BrokerResponse


def _error(
    status: int, code: str, message: str, request_id: UUID | str | None = None
) -> BrokerResult:
    response = ErrorResponse(
        schema_version=1,
        error=ApiError(
            code=code,
            message=message,
            request_id=str(request_id or uuid4()),
        ),
    )
    return BrokerResult(status, response)


def _is_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x0400
    )


def _require_plain_path(path: Path, *, include_leaf: bool = True) -> None:
    if not path.is_absolute():
        raise OSError("managed input path is not absolute")
    current = Path(path.anchor)
    parts = path.parts[1:] if include_leaf else path.parts[1:-1]
    for part in parts:
        current /= part
        if _is_reparse(current):
            raise OSError("managed input path contains a reparse point")


class BrokerService:
    """Execute only operations authorized by the task bound to a worker credential."""

    def __init__(
        self,
        database: Database,
        selected_copy_root: Path,
        output_publisher: OutputPublisher,
        *,
        task_locks: TaskLockRegistry | None = None,
        before_admission: Callable[[TaskRecord, datetime], bool] | None = None,
        on_policy_denial: Callable[[TaskRecord], None] | None = None,
        on_protection_failure: Callable[[TaskRecord], None] | None = None,
    ) -> None:
        if not selected_copy_root.is_absolute() or not selected_copy_root.is_dir():
            raise ValueError("selected-copy root must exist and be an absolute trusted path")
        _require_plain_path(selected_copy_root)
        self.database = database
        self.selected_copy_root = selected_copy_root
        self.output_publisher = output_publisher
        self._task_locks = task_locks or TaskLockRegistry()
        self._before_admission = before_admission
        self._on_policy_denial = on_policy_denial
        self._on_protection_failure = on_protection_failure
        self._failure_clock = time.monotonic
        self._failure_lock = threading.Lock()
        self._failures: OrderedDict[str, tuple[float, int]] = OrderedDict()

    def _throttled(self, key: str, *, add_failure: bool = False) -> bool:
        with self._failure_lock:
            at = self._failure_clock()
            start, count = self._failures.get(key, (at, 0))
            if at - start >= 30:
                start, count = at, 0
            if add_failure:
                count += 1
                self._failures[key] = (start, count)
                self._failures.move_to_end(key)
                while len(self._failures) > 256:
                    self._failures.popitem(last=False)
            return count > 20

    def _invalid(self, key: str, result: BrokerResult) -> BrokerResult:
        if self._throttled(key, add_failure=True):
            return _error(429, "RATE_LIMITED", "Repeated invalid requests are temporarily limited.")
        return result

    def _parse(self, body: bytes) -> tuple[BrokerOperationRequest | None, BrokerResult | None]:
        if not isinstance(body, bytes):
            return None, _error(422, "INVALID_REQUEST", "Request body must be bytes.")
        if len(body) > MAX_JSON_BODY_BYTES:
            return None, _error(413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB.")
        request_id: UUID | None = None
        try:
            decoded = decode_strict_json(body)
        except (TypeError, ValueError):
            return None, _error(422, "INVALID_REQUEST", "Request body is not strict JSON.")
        if isinstance(decoded, dict):
            candidate = decoded.get("request_id")
            try:
                request_id = UUID(candidate) if isinstance(candidate, str) else None
            except ValueError:
                pass
        try:
            request = _REQUEST_ADAPTER.validate_python(decoded, strict=True)
        except ValidationError as exc:
            if _too_large_validation_error(exc):
                return None, _error(
                    413,
                    "PAYLOAD_TOO_LARGE",
                    "Output content exceeds the 1 MiB limit.",
                    request_id,
                )
            return None, _error(
                422, "INVALID_REQUEST", "Request fields failed validation.", request_id
            )
        return request, None

    def execute(
        self, token: str | None, body: bytes, *, now: datetime | None = None
    ) -> BrokerResult:
        """Process one bounded request. Tokens and worker content are never logged."""
        failure_key = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
        if self._throttled(failure_key):
            return _error(429, "RATE_LIMITED", "Repeated invalid requests are temporarily limited.")
        request, parse_error = self._parse(body)
        if parse_error is not None:
            try:
                task = self.database.active_task_for_credential(token or "", at=now or utc_now())
            except (DatabaseError, sqlite3.Error):
                return _error(503, "PROTECTION_UNAVAILABLE", "Authorization state is unavailable.")
            return self._invalid(failure_key if task is not None else "anonymous", parse_error)
        assert request is not None
        at = now or utc_now()
        try:
            task = self.database.active_task_for_credential(token or "", at=at)
        except (DatabaseError, sqlite3.Error):
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Worker authorization state is unavailable.",
                request.request_id,
            )
        if task is None:
            return self._invalid(
                "anonymous",
                _error(
                    401,
                    "AUTH_INVALID",
                    "Worker credential is invalid or expired.",
                    request.request_id,
                ),
            )
        with self._task_locks.hold(str(task.task_id)):
            if self._before_admission is not None:
                try:
                    if not self._before_admission(task, at):
                        return _error(
                            503,
                            "PROTECTION_UNAVAILABLE",
                            "Task lifecycle admission is unavailable.",
                            request.request_id,
                        )
                except Exception:
                    self._signal_protection_failure(task)
                    return _error(
                        503,
                        "PROTECTION_UNAVAILABLE",
                        "Task lifecycle admission is unavailable.",
                        request.request_id,
                    )
            result = self._execute_validated(token, request, at)
            if result.status_code == 503:
                self._signal_protection_failure(task)
            if result.status_code in {401, 413, 422}:
                return self._invalid(failure_key, result)
            return result

    def _signal_protection_failure(self, task: TaskRecord) -> None:
        if self._on_protection_failure is None:
            return
        try:
            self._on_protection_failure(task)
        except Exception:
            _LOGGER.error("broker_fail_closed_cleanup_failed")

    def _execute_validated(
        self, token: str | None, request: BrokerOperationRequest, at: datetime
    ) -> BrokerResult:
        try:
            task = self.database.active_task_for_credential(token or "", at=at)
        except (DatabaseError, sqlite3.Error):
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Worker authorization state is unavailable.",
                request.request_id,
            )
        if task is None:
            return _error(
                401, "AUTH_INVALID", "Worker credential is invalid or expired.", request.request_id
            )
        try:
            contract = self.database.get_contract(task.task_id)
        except (DatabaseError, sqlite3.Error):
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Worker contract state is unavailable.",
                request.request_id,
            )
        if contract is None or at >= contract.expires_at:
            return _error(
                401, "AUTH_INVALID", "Worker contract is no longer active.", request.request_id
            )
        token_sha256 = hashlib.sha256((token or "").encode("ascii")).hexdigest()

        if isinstance(request, BrokerReadDocumentRequest):
            if request.document_id != contract.selected_document_id:
                return self._deny(
                    task,
                    request,
                    at,
                    token_sha256,
                    reason_code="DOCUMENT_OUT_OF_SCOPE",
                    policy_reason="DOCUMENT_OUT_OF_SCOPE",
                    message="Read request targeted a document outside the selected grant.",
                )
            if "read_document" not in contract.allowed_operations:
                return _error(
                    403,
                    "POLICY_DENIED",
                    "Read is not granted by the task contract.",
                    request.request_id,
                )
            return self._read(task, request, at, token_sha256)

        if isinstance(request, (BrokerReplaceOriginalRequest, BrokerDeleteDocumentRequest)):
            return self._deny(
                task,
                request,
                at,
                token_sha256,
                reason_code="ORIGINAL_MUTATION_FORBIDDEN",
                policy_reason="ORIGINAL_MUTATION_FORBIDDEN",
                message="Original-document mutation is never granted to workers.",
            )

        if isinstance(request, BrokerPublishOutputRequest):
            if "publish_output" not in contract.allowed_operations:
                return _error(
                    403, "POLICY_DENIED", "Output publication is not granted.", request.request_id
                )
            try:
                request.validate_for_tool(task.tool_id)
            except ValueError:
                return _error(
                    422,
                    "INVALID_REQUEST",
                    "Output kind is not valid for this task.",
                    request.request_id,
                )
            return self._publish(task, request, at, token_sha256)

        return _error(
            422,
            "INVALID_REQUEST",
            "Operation is not part of the broker contract.",
            request.request_id,
        )

    def _deny(
        self,
        task: TaskRecord,
        request: BrokerReadDocumentRequest
        | BrokerReplaceOriginalRequest
        | BrokerDeleteDocumentRequest,
        at: datetime,
        token_sha256: str,
        *,
        reason_code: str,
        policy_reason: str,
        message: str,
    ) -> BrokerResult:
        body_hash = canonical_body_sha256(request)
        try:
            response = self.database.record_policy_denial(
                task.task_id,
                request.request_id,
                body_hash,
                token_sha256=token_sha256,
                operation=request.operation,
                target_document_id=request.document_id,
                reason_code=reason_code,
                policy_reason=policy_reason,
                message=message,
                now=at,
            )
            if self._on_policy_denial is not None:
                try:
                    self._on_policy_denial(task)
                except Exception:
                    _LOGGER.error("broker_denial_containment_failed")
                    return _error(
                        503,
                        "PROTECTION_UNAVAILABLE",
                        "The denied task could not be safely contained.",
                        request.request_id,
                    )
            return BrokerResult(403, response)
        except RequestConflict:
            return _error(
                409,
                "REQUEST_CONFLICT",
                "Request ID is bound to different content.",
                request.request_id,
            )
        except CredentialInvalid:
            return _error(
                401,
                "AUTH_INVALID",
                "Worker credential is no longer active.",
                request.request_id,
            )
        except (RequestInProgress, DatabaseError):
            return _error(
                409,
                "TASK_BUSY",
                "Task state changed before the request was recorded.",
                request.request_id,
            )
        except sqlite3.Error:
            self._signal_protection_failure(task)
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Policy denial could not be recorded.",
                request.request_id,
            )

    def _selected_path(self, task: TaskRecord, document_id: str) -> Path:
        document = next((item for item in TRUSTED_DOCUMENTS if item.id == document_id), None)
        if document is None or document.id not in _RECOGNIZED_DOCUMENTS:
            raise OSError("selected document registry entry is missing")
        task_root = self.selected_copy_root / str(task.task_id)
        suffix = PurePosixPath(document.relative_path).suffix
        path = task_root / f"{document.id}{suffix}"
        _require_plain_path(self.selected_copy_root)
        _require_plain_path(task_root)
        _require_plain_path(path)
        if not path.is_file():
            raise OSError("controller-prepared selected copy is missing")
        return path

    def _read(
        self,
        task: TaskRecord,
        request: BrokerReadDocumentRequest,
        at: datetime,
        token_sha256: str,
    ) -> BrokerResult:
        digest = canonical_body_sha256(request)
        try:
            disposition, cached = self.database.begin_request(
                task.task_id,
                request.request_id,
                digest,
                now=at,
                token_sha256=token_sha256,
            )
        except CredentialInvalid:
            return _error(
                401,
                "AUTH_INVALID",
                "Worker credential is no longer active.",
                request.request_id,
            )
        except RequestConflict:
            return _error(
                409,
                "REQUEST_CONFLICT",
                "Request ID is bound to different content.",
                request.request_id,
            )
        except RequestInProgress:
            return _error(
                409,
                "TASK_BUSY",
                "The matching request is still being processed.",
                request.request_id,
            )
        except (DatabaseError, sqlite3.Error):
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Persistent request state is unavailable.",
                request.request_id,
            )
        if disposition == RequestDisposition.REPLAY:
            return self._replay(cached, request.request_id)
        try:
            path = self._selected_path(task, request.document_id)
            with path.open("rb") as stream:
                raw = stream.read(MAX_OUTPUT_BYTES + 1)
            if len(raw) > MAX_OUTPUT_BYTES:
                raise OSError("selected copy exceeds the broker response limit")
            text = raw.decode("utf-8", errors="strict")
            response = BrokerReadDocumentAllowed(
                schema_version=1,
                decision="allow",
                document_id=request.document_id,
                content_text=text,
            )
            self.database.complete_request(
                task.task_id,
                request.request_id,
                digest,
                response,
                now=at,
                token_sha256=token_sha256,
                event_kind="operation_allowed",
                event_operation="read_document",
                event_target_document_id=request.document_id,
                event_decision="allow",
                event_message="Selected document copy was read.",
            )
            return BrokerResult(200, response)
        except CredentialInvalid:
            try:
                self.database.abandon_unstarted_request(task.task_id, request.request_id, digest)
            except (DatabaseError, sqlite3.Error):
                _LOGGER.error("broker_read_reservation_cleanup_failed")
            return _error(
                401,
                "AUTH_INVALID",
                "Worker credential is no longer active.",
                request.request_id,
            )
        except (OSError, UnicodeError, ValueError, DatabaseError, sqlite3.Error):
            try:
                self.database.abandon_unstarted_request(task.task_id, request.request_id, digest)
            except (DatabaseError, sqlite3.Error):
                _LOGGER.error("broker_read_reservation_cleanup_failed")
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "The selected input copy is unavailable or inconsistent.",
                request.request_id,
            )

    def _publish(
        self,
        task: TaskRecord,
        request: BrokerPublishOutputRequest,
        at: datetime,
        token_sha256: str,
    ) -> BrokerResult:
        body_hash = canonical_body_sha256(request)
        encoded = request.output_text.encode("utf-8", errors="strict")
        content_hash = hashlib.sha256(encoded).hexdigest()
        try:
            disposition, cached = self.database.begin_request(
                task.task_id,
                request.request_id,
                body_hash,
                now=at,
                token_sha256=token_sha256,
            )
            if disposition == RequestDisposition.REPLAY:
                return self._replay(cached, request.request_id)
        except RequestConflict:
            return _error(
                409,
                "REQUEST_CONFLICT",
                "Request ID is bound to different content.",
                request.request_id,
            )
        except RequestInProgress:
            # A reserved exact retry is allowed to resume its controller-owned journal.
            pass
        except CredentialInvalid:
            return _error(
                401,
                "AUTH_INVALID",
                "Worker credential is no longer active.",
                request.request_id,
            )
        except (DatabaseError, sqlite3.Error):
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Persistent request state is unavailable.",
                request.request_id,
            )

        try:
            record = self.database.output_for_request(task.task_id, request.request_id)
        except (DatabaseError, sqlite3.Error):
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Persistent output state is unavailable.",
                request.request_id,
            )
        if record is None:
            try:
                record = self.database.reserve_output(
                    task.task_id,
                    request.request_id,
                    content_hash,
                    len(encoded),
                    now=at,
                    token_sha256=token_sha256,
                )
            except CredentialInvalid:
                return _error(
                    401,
                    "AUTH_INVALID",
                    "Worker credential is no longer active.",
                    request.request_id,
                )
            except sqlite3.IntegrityError as exc:
                if "output_slot_id" in str(exc) or "output_records.output_slot_id" in str(exc):
                    response = _error(
                        409,
                        "OUTPUT_ALREADY_PUBLISHED",
                        "The task output slot is already reserved or published.",
                        request.request_id,
                    ).body
                    try:
                        self.database.complete_request(
                            task.task_id,
                            request.request_id,
                            body_hash,
                            response,
                            now=at,
                            token_sha256=token_sha256,
                            event_kind="output_publication_denied",
                            event_operation="publish_output",
                            event_decision="deny",
                            event_reason_code="OUTPUT_ALREADY_PUBLISHED",
                            event_message="The task output slot is already reserved or published.",
                        )
                    except CredentialInvalid:
                        return _error(
                            401,
                            "AUTH_INVALID",
                            "Worker credential is no longer active.",
                            request.request_id,
                        )
                    except (DatabaseError, sqlite3.Error):
                        return _error(
                            503,
                            "PROTECTION_UNAVAILABLE",
                            "Output-slot denial could not be recorded.",
                            request.request_id,
                        )
                    return BrokerResult(409, response)
                return _error(
                    503, "PROTECTION_UNAVAILABLE", "Output reservation failed.", request.request_id
                )
            except (DatabaseError, sqlite3.Error, KeyError, ValueError):
                return _error(
                    503, "PROTECTION_UNAVAILABLE", "Output reservation failed.", request.request_id
                )

        if (
            record.content_sha256 != content_hash
            or record.decoded_bytes != len(encoded)
            or record.output_kind != request.output_kind
        ):
            return _error(
                409,
                "REQUEST_CONFLICT",
                "Output journal does not match request content.",
                request.request_id,
            )
        if record.state.value in {"inconsistent", "aborted"}:
            return _error(
                503,
                "PUBLICATION_INCONSISTENT",
                "Output publication cannot be safely resumed.",
                request.request_id,
            )
        try:
            response = self.output_publisher.publish(
                record, request, token_sha256=token_sha256, now=at
            )
            return BrokerResult(200, response)
        except CredentialInvalid:
            return _error(
                401,
                "AUTH_INVALID",
                "Worker credential is no longer active.",
                request.request_id,
            )
        except (OutputCollision, OutputUnavailable, PublicationError):
            return _error(
                503,
                "PUBLICATION_INCONSISTENT",
                "Output publication is incomplete and is withheld.",
                request.request_id,
            )
        except (DatabaseError, sqlite3.Error, OSError):
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "Output publication did not finalize.",
                request.request_id,
            )

    @staticmethod
    def _replay(cached: dict[str, object] | None, request_id: UUID) -> BrokerResult:
        if cached is None:
            return _error(
                503, "PROTECTION_UNAVAILABLE", "Stored request result is missing.", request_id
            )
        try:
            response = _RESPONSE_ADAPTER.validate_python(cached, strict=True)
        except ValidationError:
            try:
                error_response = ErrorResponse.model_validate(cached, strict=True)
            except ValidationError:
                return _error(
                    503, "PROTECTION_UNAVAILABLE", "Stored request result is invalid.", request_id
                )
            return BrokerResult(_status_for_cached_error(error_response), error_response)
        return BrokerResult(200, response)


def _too_large_validation_error(error: ValidationError) -> bool:
    for item in error.errors(include_url=False):
        location = item.get("loc", ())
        message = str(item.get("msg", ""))
        if (
            location
            and location[-1] in {"output_text", "replacement_text"}
            and (item.get("type") == "string_too_long" or "decoded byte limit" in message)
        ):
            return True
    return False


def _status_for_cached_error(response: ErrorResponse) -> int:
    if response.error.code == "POLICY_DENIED":
        return 403
    if response.error.code == "OUTPUT_ALREADY_PUBLISHED":
        return 409
    if response.error.code in {"REQUEST_CONFLICT", "TASK_BUSY"}:
        return 409
    return 503
