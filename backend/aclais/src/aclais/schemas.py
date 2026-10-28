"""Strict API response models used to generate the shared OpenAPI contract."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class StrictApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class HealthCheck(StrictApiModel):
    id: Literal["application_api", "g1_protection"]
    status: Literal["pass", "fail", "unknown"]
    summary: str


class HealthResponse(StrictApiModel):
    schema_version: Literal[1]
    status: Literal["ready", "unavailable"]
    protection_ready: bool
    checks: tuple[HealthCheck, ...]


class ApiError(StrictApiModel):
    code: Literal["INVALID_HOST"]
    message: str
    request_id: str


class ErrorResponse(StrictApiModel):
    schema_version: Literal[1]
    error: ApiError
