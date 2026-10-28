"""Minimal A1 HTTP application; enforcement remains explicitly unavailable."""

from __future__ import annotations

import logging
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aclais.config import Settings
from aclais.schemas import ApiError, ErrorResponse, HealthCheck, HealthResponse

_logger = logging.getLogger("aclais.api")


def create_app(settings: Settings | None = None) -> FastAPI:
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
        if request.headers.get("host") != runtime.expected_host_header:
            request_id = str(uuid4())
            body = ErrorResponse(
                schema_version=1,
                error=ApiError(
                    code="INVALID_HOST",
                    message="This local service does not accept the requested host.",
                    request_id=request_id,
                ),
            )
            return JSONResponse(status_code=400, content=body.model_dump(mode="json"))
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
                    summary="The A1 API process is responding.",
                ),
                HealthCheck(
                    id="g1_protection",
                    status="unknown",
                    summary="Worker isolation and enforcement are not implemented in A1.",
                ),
            ),
        )
        _logger.info(
            "health_response_created",
            extra={"fields": {"api_status": result.status, "protection_ready": False}},
        )
        return result

    return application


app = create_app(Settings())
