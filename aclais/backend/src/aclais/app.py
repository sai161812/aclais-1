"""Local API routes assembled from trusted controller services at startup."""

from __future__ import annotations

import inspect
import logging
import sqlite3
from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from aclais.broker import BrokerService
from aclais.config import Settings
from aclais.owner_api import TaskCanceller, TaskLauncher, install_owner_routes
from aclais.owner_auth import OwnerAuth
from aclais.persistence.database import DatabaseError
from aclais.publication import OutputPublisher, OutputUnavailable
from aclais.schemas import ApiError, ErrorResponse, HealthCheck, HealthResponse
from aclais.tool_registry import FixedToolRegistry

_logger = logging.getLogger("aclais.api")


def create_app(
    settings: Settings | None = None,
    *,
    broker: BrokerService | None = None,
    output_publisher: OutputPublisher | None = None,
    authorize_output: Callable[[Request], bool | Awaitable[bool]] | None = None,
    owner_auth: OwnerAuth | None = None,
    cancel_task: TaskCanceller | None = None,
    approved_task_launcher: TaskLauncher | None = None,
    tool_registry: FixedToolRegistry | None = None,
    frontend_dist: Path | None = None,
) -> FastAPI:
    runtime = settings if settings is not None else Settings()
    application = FastAPI(
        title="ACLAIS Local API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @application.middleware("http")
    async def exact_host_allowlist(request: Request, call_next):
        if request.headers.getlist("host") != [runtime.expected_host_header]:
            request_id = str(uuid4())
            body = ErrorResponse(
                schema_version=1,
                error=ApiError(
                    code="INVALID_HOST",
                    message="This local service does not accept the requested host.",
                    request_id=request_id,
                ),
            )
            return JSONResponse(
                status_code=400,
                content=body.model_dump(mode="json"),
                headers={
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
            )
        return await call_next(request)

    @application.get(
        "/api/health",
        response_model=HealthResponse,
        responses={400: {"model": ErrorResponse}},
        tags=["health"],
        operation_id="getApiHealth",
    )
    async def get_health() -> HealthResponse:
        result = HealthResponse(
            schema_version=1,
            status="unavailable",
            protection_ready=False,
            checks=(
                HealthCheck(
                    id="application_api",
                    status="pass",
                    summary="The local API process is responding.",
                ),
                HealthCheck(
                    id="g1_protection",
                    status="unknown",
                    summary="G1 verification and owner-session gates are incomplete.",
                ),
            ),
        )
        _logger.info(
            "health_response_created",
            extra={"fields": {"api_status": result.status, "protection_ready": False}},
        )
        return result

    if broker is not None:

        @application.post("/api/broker/operations", tags=["worker"], operation_id="brokerOperation")
        async def broker_operation(request: Request):
            authorization_values = request.headers.getlist("authorization")
            if len(authorization_values) != 1:
                return _error_response(401, "AUTH_INVALID", "Worker credential is required.")
            authorization = authorization_values[0]
            if not authorization.startswith("Bearer "):
                return _error_response(401, "AUTH_INVALID", "Worker credential is required.")
            token = authorization[7:]
            if not token or any(char.isspace() for char in token):
                return _error_response(401, "AUTH_INVALID", "Worker credential is invalid.")
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    if int(content_length) > 2_097_152:
                        return _error_response(
                            413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB."
                        )
                except ValueError:
                    return _error_response(400, "INVALID_REQUEST", "Content-Length is invalid.")
            chunks: list[bytes] = []
            body_size = 0
            async for chunk in request.stream():
                body_size += len(chunk)
                if body_size > 2_097_152:
                    return _error_response(413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB.")
                chunks.append(chunk)
            result = await run_in_threadpool(broker.execute, token, b"".join(chunks))
            return JSONResponse(
                status_code=result.status_code,
                content=result.body.model_dump(mode="json"),
            )

    if output_publisher is not None and authorize_output is not None and owner_auth is None:

        @application.get(
            "/api/outputs/{output_id}", tags=["owner"], operation_id="getPublishedOutput"
        )
        async def published_output(output_id: str, request: Request):
            try:
                authorized = authorize_output(request)
                if inspect.isawaitable(authorized):
                    authorized = await authorized
            except Exception:
                return _error_response(
                    503, "PROTECTION_UNAVAILABLE", "Owner authorization is unavailable."
                )
            if not authorized:
                return _error_response(401, "AUTH_INVALID", "Owner session is required.")
            try:
                metadata, content = output_publisher.read_published(output_id)
            except (OutputUnavailable, ValueError):
                return _error_response(404, "NOT_FOUND", "Published output was not found.")
            except (DatabaseError, sqlite3.Error, OSError):
                return _error_response(
                    503, "PROTECTION_UNAVAILABLE", "Output integrity state is unavailable."
                )
            media_type = (
                "text/markdown; charset=utf-8"
                if metadata.output_kind == "formatted_markdown"
                else "application/json"
            )
            return Response(
                content=content,
                status_code=200,
                media_type=media_type,
                headers={
                    "Content-Disposition": f'attachment; filename="{metadata.file_name}"',
                    "X-Content-Type-Options": "nosniff",
                    "Cache-Control": "no-store",
                },
            )

    if owner_auth is not None:
        install_owner_routes(
            application,
            owner_auth,
            output_publisher=output_publisher,
            cancel_task=cancel_task,
            task_launcher=approved_task_launcher,
            tool_registry=tool_registry,
            frontend_dist=frontend_dist,
        )

    return application


app = create_app(Settings())


def _error_response(status: int, code: str, message: str) -> JSONResponse:
    response = ErrorResponse(
        schema_version=1,
        error=ApiError(code=code, message=message, request_id=str(uuid4())),
    )
    return JSONResponse(status_code=status, content=response.model_dump(mode="json"))
