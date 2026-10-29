"""Typed ACLAIS boundary for the not-yet-implemented local receiver."""

from __future__ import annotations

import http.client
import stat
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from aclais.persistence.models import (
    ErrorResponse,
    ReceiptsResponse,
    ReceiverHealthResponse,
)
from aclais.strict_json import decode_strict_json


class ReceiverAdapterError(RuntimeError):
    """Receiver state could not be established; callers must preserve unknown."""


class ReceiverUnknownRun(ReceiverAdapterError):
    """The receiver is healthy but has no record for the requested run."""


class ReceiverUnavailable(ReceiverAdapterError):
    """The receiver could not provide a trustworthy response."""


class ReceiverAuthenticationFailed(ReceiverAdapterError):
    """The receiver rejected or could not read its owner-only admin credential."""


class ReceiverProtocolFailure(ReceiverAdapterError):
    """The receiver response did not match the strict shared contract."""


class ReceiverAdapter(Protocol):
    """Minimal read-only interface. It creates no runs and sends no canary data."""

    def health(self) -> ReceiverHealthResponse: ...

    def receipts(self, run_id: UUID) -> ReceiptsResponse: ...


class HttpReceiverAdapter:
    """Read-only HTTP adapter to the fixed local receiver protocol."""

    def __init__(
        self,
        *,
        base_url: str = "http://[::1]:8767",
        admin_token: str | None = None,
        credential_file: Path | None = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "::1"
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("receiver adapter must use the IPv6 loopback origin")
        if (admin_token is None) == (credential_file is None):
            raise ValueError("provide exactly one owner-only receiver credential source")
        if timeout_seconds <= 0 or timeout_seconds > 10:
            raise ValueError("receiver timeout must be between zero and ten seconds")
        if admin_token is not None and not _valid_admin_token(admin_token):
            raise ValueError("receiver administrative credential is invalid")
        if credential_file is not None and not credential_file.is_absolute():
            raise ValueError("receiver credential file must use an absolute path")
        self._port = parsed.port
        self._token = admin_token
        self._credential_file = credential_file
        self._timeout = timeout_seconds

    def __repr__(self) -> str:
        return f"HttpReceiverAdapter(host='::1', port={self._port}, admin_credential='redacted')"

    def health(self) -> ReceiverHealthResponse:
        response = self._request("GET", "/health", model=ReceiverHealthResponse)
        if response.status != "ready":
            raise ReceiverUnavailable("receiver_health_unavailable")
        return response

    def receipts(self, run_id: UUID) -> ReceiptsResponse:
        token = self._read_admin_token()
        path = f"/admin/runs/{run_id}/receipts"
        return self._request(
            "GET",
            path,
            model=ReceiptsResponse,
            authorization=token,
            unknown_run_is_typed=True,
        )

    def _read_admin_token(self) -> str:
        if self._token is not None:
            return self._token
        path = self._credential_file
        assert path is not None
        try:
            metadata = path.lstat()
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & reparse
            ):
                raise OSError("credential file is not a regular protected file")
            token = path.read_bytes().decode("ascii", errors="strict")
        except (OSError, UnicodeError) as exc:
            raise ReceiverAuthenticationFailed("receiver_admin_credential_unavailable") from exc
        if not _valid_admin_token(token):
            raise ReceiverAuthenticationFailed("receiver_admin_credential_unavailable")
        return token

    def _request(
        self,
        method: str,
        path: str,
        *,
        model: type[BaseModel],
        authorization: str | None = None,
        unknown_run_is_typed: bool = False,
    ):
        connection = http.client.HTTPConnection("::1", self._port, timeout=self._timeout)
        headers = {"Accept": "application/json"}
        if authorization is not None:
            headers["Authorization"] = f"Bearer {authorization}"
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower()
            payload = response.read(2_097_153)
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise ReceiverUnavailable("receiver_transport_unavailable") from exc
        finally:
            connection.close()
        if len(payload) > 2_097_152 or content_type != "application/json":
            raise ReceiverProtocolFailure("receiver_response_invalid")
        if response.status != 200:
            try:
                error = _validate_json_model(ErrorResponse, payload)
            except (ValueError, TypeError) as exc:
                raise ReceiverProtocolFailure("receiver_error_response_invalid") from exc
            if response.status == 401 and error.error.code == "AUTH_INVALID":
                raise ReceiverAuthenticationFailed("receiver_admin_authentication_failed")
            if (
                unknown_run_is_typed
                and response.status == 404
                and error.error.code == "NOT_FOUND"
            ):
                raise ReceiverUnknownRun("receiver_unknown_run")
            if response.status >= 500:
                raise ReceiverUnavailable("receiver_service_unavailable")
            raise ReceiverProtocolFailure("receiver_response_status_invalid")
        try:
            return _validate_json_model(model, payload)
        except (ValueError, TypeError) as exc:
            raise ReceiverProtocolFailure("receiver_success_response_invalid") from exc


def _validate_json_model(model: type[BaseModel], payload: bytes) -> BaseModel:
    """Apply duplicate-key checks, then Pydantic's strict JSON semantics for arrays/dates."""
    decode_strict_json(payload)
    return model.model_validate_json(payload, strict=True)


def _valid_admin_token(token: str) -> bool:
    return (
        isinstance(token, str)
        and 32 <= len(token) <= 512
        and token.isascii()
        and all(char.isalnum() or char in "-_" for char in token)
    )


class ReceiverAssessment(BaseModel):
    """A typed, content-free result suitable for an ACLAIS evidence report."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["pass", "fail", "unknown", "not_applicable"]
    outcome: Literal[
        "not_configured",
        "not_evaluated",
        "healthy_empty",
        "positive_receipt",
        "receipts_without_marker",
        "unknown_run",
        "authentication_failure",
        "unreachable",
        "invalid_response",
    ]
    receipt_ids: tuple[UUID, ...] = ()
    marker_received: bool | None = None
    reason: str


def assess_receiver(
    adapter: ReceiverAdapter | None,
    run_id: UUID,
) -> ReceiverAssessment:
    if adapter is None:
        return ReceiverAssessment(
            status="not_applicable",
            outcome="not_configured",
            reason="No receiver run was configured for this ACLAIS task.",
        )
    try:
        health = ReceiverHealthResponse.model_validate(adapter.health(), strict=True)
        if health.status != "ready":
            raise ReceiverUnavailable("receiver_health_unavailable")
        response = ReceiptsResponse.model_validate(adapter.receipts(run_id), strict=True)
        if response.run_id != run_id:
            raise ReceiverUnavailable("receiver_run_identity_mismatch")
    except ReceiverUnknownRun:
        return ReceiverAssessment(
            status="unknown",
            outcome="unknown_run",
            reason="The receiver is healthy but the requested run is unknown.",
        )
    except ReceiverAuthenticationFailed:
        return ReceiverAssessment(
            status="unknown",
            outcome="authentication_failure",
            reason="The receiver administrative authentication failed; marker status is unknown.",
        )
    except (ReceiverUnavailable, OSError, TimeoutError):
        return ReceiverAssessment(
            status="unknown",
            outcome="unreachable",
            reason="The receiver did not provide a complete trustworthy observation.",
        )
    except (ReceiverAdapterError, ValueError, TypeError):
        return ReceiverAssessment(
            status="unknown",
            outcome="invalid_response",
            reason="The receiver did not provide a complete trustworthy observation.",
        )
    except Exception:
        return ReceiverAssessment(
            status="unknown",
            outcome="invalid_response",
            reason="The receiver did not provide a complete trustworthy observation.",
        )
    outcome = (
        "positive_receipt"
        if response.marker_received
        else "healthy_empty"
        if not response.receipts
        else "receipts_without_marker"
    )
    return ReceiverAssessment(
        status="fail" if response.marker_received else "pass",
        outcome=outcome,
        receipt_ids=tuple(receipt.receipt_id for receipt in response.receipts),
        marker_received=response.marker_received,
        reason=(
            "The receiver reported a matching marker."
            if response.marker_received
            else "The healthy receiver reported no matching marker."
        ),
    )
