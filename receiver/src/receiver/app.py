"""Strict IPv6-only HTTP API for the independent receipt store."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import sqlite3
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from receiver import __version__
from receiver.config import ReceiverSettings
from receiver.database import (
    AuthenticationInvalid,
    ReceiverStore,
    ReceiverStoreError,
    RequestConflict,
    RequestInProgress,
    RunConflict,
    RunUnknown,
    StorageFull,
    StorageIntegrityUnknown,
    StorageProtectionError,
    StorageUnavailable,
)
from receiver.models import (
    MAX_RECEIPT_BYTES,
    MAX_REQUEST_BYTES,
    CreateRunRequest,
    CreateRunResponse,
    ErrorDetail,
    ErrorResponse,
    IngestRequest,
    ReceiptResponse,
    ReceiptsResponse,
    ReceiverHealthResponse,
)
from receiver.strict_json import parse_model

_logger = logging.getLogger("receiver.service")
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,512}$", re.ASCII)


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    response = ErrorResponse(
        schema_version=1,
        error=ErrorDetail(code=code, message=message, request_id=uuid4()),
    )
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def _credential_header(request: Request) -> str | None:
    headers = request.headers.getlist("authorization")
    if len(headers) != 1 or not headers[0].startswith("Bearer "):
        return None
    token = headers[0][7:]
    if not _TOKEN_PATTERN.fullmatch(token):
        return None
    return token


async def _json_body(request: Request) -> bytes | JSONResponse:
    types = request.headers.getlist("content-type")
    if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
        return _error(422, "INVALID_REQUEST", "A strict JSON request body is required.")
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1:
        return _error(422, "INVALID_REQUEST", "The request body length is invalid.")
    if lengths:
        if not lengths[0].isascii() or not lengths[0].isdecimal():
            return _error(422, "INVALID_REQUEST", "The request body length is invalid.")
        try:
            length = int(lengths[0])
        except ValueError:
            return _error(422, "INVALID_REQUEST", "The request body length is invalid.")
        if length < 0:
            return _error(422, "INVALID_REQUEST", "The request body length is invalid.")
        if length > MAX_REQUEST_BYTES:
            return _error(413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB.")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_REQUEST_BYTES:
            return _error(413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB.")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_request(body: bytes, model: type[Any]) -> Any | JSONResponse:
    try:
        return parse_model(body, model)
    except ValueError:
        return _error(422, "INVALID_REQUEST", "The request does not match the strict API contract.")


def _parse_run_id(value: str) -> UUID | JSONResponse:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return _error(422, "INVALID_REQUEST", "Run ID must be a canonical UUID.")
    if str(parsed) != value:
        return _error(422, "INVALID_REQUEST", "Run ID must be a canonical UUID.")
    return parsed


def _translate_store_error(exc: ReceiverStoreError) -> JSONResponse:
    if isinstance(exc, AuthenticationInvalid):
        return _error(401, "AUTH_INVALID", "Receiver credential is invalid.")
    if isinstance(exc, RunUnknown):
        return _error(404, "NOT_FOUND", "Receiver run was not found.")
    if isinstance(exc, (RunConflict, RequestConflict)):
        return _error(409, "REQUEST_CONFLICT", "The request conflicts with stored receiver state.")
    if isinstance(exc, StorageFull):
        return _error(429, "RATE_LIMITED", "Receiver run storage has reached its limit.")
    if isinstance(exc, RequestInProgress):
        return _error(
            503,
            "PROTECTION_UNAVAILABLE",
            "The matching receiver request is still being reconciled.",
        )
    if isinstance(exc, (StorageIntegrityUnknown, StorageUnavailable, StorageProtectionError)):
        return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage integrity is unavailable.")
    return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage is unavailable.")


def create_app(
    settings: ReceiverSettings | None = None,
    *,
    store: ReceiverStore | None = None,
    admin_token: str,
) -> FastAPI:
    """Create the receiver API from trusted local storage and admin credentials."""
    runtime = settings or ReceiverSettings.from_env()
    if not _TOKEN_PATTERN.fullmatch(admin_token):
        raise ValueError("receiver admin credential is invalid")
    receiver_store = store or ReceiverStore(runtime.data_root)
    admin_digest = hashlib.sha256(admin_token.encode("ascii")).digest()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.storage_ready = False
        try:
            await run_in_threadpool(receiver_store.initialize)
            application.state.storage_ready = True
        except (OSError, sqlite3.Error, ReceiverStoreError, StorageProtectionError):
            _logger.error("receiver_storage_unavailable")
        try:
            yield
        finally:
            application.state.storage_ready = False

    application = FastAPI(
        title="ACLAIS Local Receiver",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.storage_ready = False

    @application.middleware("http")
    async def host_and_response_headers(request: Request, call_next):
        host_values = request.headers.getlist("host")
        if host_values != [runtime.expected_host_header]:
            response = _error(400, "INVALID_HOST", "This service accepts only its fixed IPv6 host.")
        elif request.scope.get("query_string", b""):
            response = _error(422, "INVALID_REQUEST", "Query parameters are not accepted.")
        else:
            response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    @application.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return _error(404, "NOT_FOUND", "Receiver route was not found.")
        return _error(400, "INVALID_REQUEST", "The receiver request is invalid.")

    @application.exception_handler(Exception)
    async def unexpected_error(_: Request, __: Exception) -> JSONResponse:
        _logger.error("receiver_request_failed")
        return _error(500, "INTERNAL_ERROR", "The receiver could not complete the request.")

    def admin_authorized(request: Request) -> bool:
        token = _credential_header(request)
        if token is None:
            return False
        return hmac.compare_digest(hashlib.sha256(token.encode("ascii")).digest(), admin_digest)

    def storage_ready() -> bool:
        return bool(application.state.storage_ready)

    @application.get("/health", response_model=ReceiverHealthResponse)
    async def health() -> ReceiverHealthResponse:
        ready = storage_ready()
        if ready:
            try:
                await run_in_threadpool(receiver_store.health_status)
            except ReceiverStoreError:
                ready = False
        return ReceiverHealthResponse(
            schema_version=1,
            status="ready" if ready else "unavailable",
            version=__version__,
        )

    @application.post(
        "/admin/runs",
        status_code=201,
        response_model=CreateRunResponse,
        responses={401: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
    )
    async def create_run(request: Request) -> Any:
        if not admin_authorized(request):
            return _error(401, "AUTH_INVALID", "Receiver administrative credential is invalid.")
        if not storage_ready():
            return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage is unavailable.")
        raw = await _json_body(request)
        if isinstance(raw, JSONResponse):
            return raw
        parsed = _parse_request(raw, CreateRunRequest)
        if isinstance(parsed, JSONResponse):
            return parsed
        import secrets

        ingest_token = secrets.token_urlsafe(32)
        try:
            return await run_in_threadpool(
                receiver_store.create_run, parsed, ingest_token=ingest_token
            )
        except ReceiverStoreError as exc:
            return _translate_store_error(exc)
        except (sqlite3.Error, OSError):
            return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage is unavailable.")

    @application.post(
        "/ingest",
        status_code=201,
        response_model=ReceiptResponse,
        responses={
            401: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            429: {"model": ErrorResponse},
        },
    )
    async def ingest(request: Request) -> Any:
        if not storage_ready():
            return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage is unavailable.")
        token = _credential_header(request)
        if token is None:
            return _error(401, "AUTH_INVALID", "Run-bound ingest credential is required.")
        raw = await _json_body(request)
        if isinstance(raw, JSONResponse):
            return raw
        parsed = _parse_request(raw, IngestRequest)
        if isinstance(parsed, JSONResponse):
            return parsed
        if len(parsed.decoded_payload) > MAX_RECEIPT_BYTES:
            return _error(413, "PAYLOAD_TOO_LARGE", "Decoded receipt exceeds 1 MiB.")
        try:
            return await run_in_threadpool(receiver_store.ingest, token, parsed)
        except ReceiverStoreError as exc:
            return _translate_store_error(exc)
        except (sqlite3.Error, OSError):
            return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage is unavailable.")

    @application.get(
        "/admin/runs/{run_id}/receipts",
        response_model=ReceiptsResponse,
        responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    )
    async def get_receipts(run_id: str, request: Request) -> Any:
        if not admin_authorized(request):
            return _error(401, "AUTH_INVALID", "Receiver administrative credential is invalid.")
        if not storage_ready():
            return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage is unavailable.")
        parsed_run_id = _parse_run_id(run_id)
        if isinstance(parsed_run_id, JSONResponse):
            return parsed_run_id
        try:
            return await run_in_threadpool(receiver_store.get_receipts, parsed_run_id)
        except ReceiverStoreError as exc:
            return _translate_store_error(exc)
        except (sqlite3.Error, OSError):
            return _error(503, "PROTECTION_UNAVAILABLE", "Receiver storage is unavailable.")

    return application
