"""Owner-only HTTP surface and side-effect-free approval page."""

from __future__ import annotations

import html
import inspect
import json
import re
import secrets
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import TypeAdapter, ValidationError
from starlette.staticfiles import StaticFiles

from aclais.owner_auth import OWNER_CSRF_COOKIE, OWNER_SESSION_COOKIE, OwnerAuth
from aclais.persistence.database import DatabaseError, TaskAlreadyActive
from aclais.persistence.models import (
    ApprovalQuery,
    CancelResponse,
    ContractSummary,
    CreateTaskRequest,
    ErrorResponse,
    EventsQuery,
    EventsResponse,
    OwnerBootstrapExchangeRequest,
    OwnerLogoutResponse,
    OwnerSessionResponse,
    TaskDetailResponse,
    TaskListQuery,
    TaskListResponse,
    UUIDValue,
)
from aclais.publication import OutputPublisher, OutputUnavailable
from aclais.strict_json import decode_strict_json
from aclais.tool_registry import FixedToolRegistry, WorkerUnavailable

_UUID_ADAPTER = TypeAdapter(UUIDValue)
TaskLauncher = Callable[[CreateTaskRequest, str | None, str | None], Any]
TaskCanceller = Callable[[UUID], Any]


def install_owner_routes(
    application: FastAPI,
    owner_auth: OwnerAuth,
    *,
    output_publisher: OutputPublisher | None = None,
    cancel_task: TaskCanceller | None = None,
    task_launcher: TaskLauncher | None = None,
    tool_registry: FixedToolRegistry | None = None,
    frontend_dist: Path | None = None,
) -> None:
    database = owner_auth.database
    task_canceller = cancel_task
    frontend_root = _validate_frontend_dist(frontend_dist)
    if frontend_root is not None:
        application.mount(
            "/assets",
            StaticFiles(directory=str(frontend_root / "assets"), check_dir=True),
            name="owner-frontend-assets",
        )

    @application.get("/bootstrap", response_class=HTMLResponse, include_in_schema=False)
    async def bootstrap_page(request: Request) -> Response:
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Bootstrap query is invalid.")
        return _html_response(_bootstrap_html())

    @application.get("/owner", response_class=HTMLResponse, include_in_schema=False)
    async def owner_home(request: Request) -> Response:
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Owner query is invalid.")
        if owner_auth.authenticate(request) is None:
            return _html_response(_signin_html(), status_code=401)
        return _frontend_response(frontend_root)

    @application.get("/approve", response_class=HTMLResponse, include_in_schema=False)
    async def approval_page(request: Request) -> Response:
        query = _approval_query(request)
        if query is None:
            return _error(400, "INVALID_REQUEST", "Approval query is invalid.")
        session = owner_auth.authenticate(request)
        if session is None:
            return _html_response(_signin_html(), status_code=401)
        if frontend_root is None:
            return _frontend_response(None)
        provenance = _observed_provenance(request)
        context = owner_auth.create_approval_context(
            session,
            tool_id=query.tool_id,
            launch_source_claim=query.launch_source_claim,
            observed_origin=provenance[0],
            observed_referer=provenance[1],
        )
        return _frontend_response(
            frontend_root,
            approval={
                "tool_id": query.tool_id,
                "launch_source_claim": query.launch_source_claim,
                "approval_context": context,
                "observed_origin": provenance[0],
                "observed_referer": provenance[1],
            },
            referrer_policy="strict-origin-when-cross-origin",
        )

    @application.post("/api/owner/bootstrap/exchange")
    async def exchange_bootstrap(request: Request) -> Response:
        if not _same_origin_mutation(request, owner_auth.origin):
            return _error(403, "AUTH_INVALID", "Bootstrap exchange requires the ACLAIS origin.")
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Bootstrap exchange query is invalid.")
        decoded, error = await _read_json(request, OwnerBootstrapExchangeRequest)
        if error is not None:
            return error
        assert decoded is not None
        secrets_pair = owner_auth.exchange_bootstrap(decoded.bootstrap_token)
        if secrets_pair is None:
            return _error(401, "AUTH_INVALID", "Bootstrap secret is invalid or expired.")
        response = JSONResponse(
            status_code=200,
            content=OwnerSessionResponse(
                schema_version=1, authenticated=True, expires_at=secrets_pair.expires_at
            ).model_dump(mode="json"),
        )
        response.set_cookie(
            OWNER_SESSION_COOKIE,
            secrets_pair.session_token,
            max_age=28_800,
            path="/",
            httponly=True,
            samesite="lax",
        )
        response.set_cookie(
            OWNER_CSRF_COOKIE,
            secrets_pair.csrf_token,
            max_age=28_800,
            path="/",
            httponly=False,
            samesite="strict",
        )
        return _private_response(response)

    @application.get("/api/owner/session")
    async def get_owner_session(request: Request) -> Response:
        session = owner_auth.authenticate(request)
        if session is None:
            return _error(401, "AUTH_INVALID", "Owner session is required.")
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Session query is invalid.")
        return _private_response(
            JSONResponse(
                content=OwnerSessionResponse(
                    schema_version=1, authenticated=True, expires_at=session.expires_at
                ).model_dump(mode="json")
            )
        )

    @application.post("/api/owner/session/logout")
    async def logout_owner_session(request: Request) -> Response:
        session, error = _authorize_mutation(request, owner_auth)
        if error is not None:
            return error
        assert session is not None
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Logout query is invalid.")
        owner_auth.revoke(session)
        response = JSONResponse(
            content=OwnerLogoutResponse(schema_version=1, authenticated=False).model_dump(
                mode="json"
            )
        )
        response.delete_cookie(OWNER_SESSION_COOKIE, path="/", samesite="lax")
        response.delete_cookie(OWNER_CSRF_COOKIE, path="/", samesite="strict")
        return _private_response(response)

    @application.get("/api/documents")
    async def list_documents(request: Request) -> Response:
        if owner_auth.authenticate(request) is None:
            return _error(401, "AUTH_INVALID", "Owner session is required.")
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Document query is invalid.")
        try:
            return _private_response(
                JSONResponse(content=database.documents().model_dump(mode="json"))
            )
        except (DatabaseError, sqlite3.Error):
            return _error(503, "PROTECTION_UNAVAILABLE", "Document registry is unavailable.")

    @application.get("/api/tasks")
    async def list_tasks(request: Request) -> Response:
        if owner_auth.authenticate(request) is None:
            return _error(401, "AUTH_INVALID", "Owner session is required.")
        values = request.query_params.getlist("limit")
        if set(request.query_params.keys()) - {"limit"} or len(values) > 1:
            return _error(400, "INVALID_REQUEST", "Task query is invalid.")
        try:
            query = TaskListQuery.model_validate(
                {"limit": values[0] if values else "20"}, strict=True
            )
            result = TaskListResponse(schema_version=1, tasks=database.task_summaries(query.limit))
        except (ValidationError, ValueError):
            return _error(400, "INVALID_REQUEST", "Task query is invalid.")
        except (DatabaseError, sqlite3.Error):
            return _error(503, "PROTECTION_UNAVAILABLE", "Task history is unavailable.")
        return _private_response(JSONResponse(content=result.model_dump(mode="json")))

    @application.post("/api/tasks")
    async def create_task(request: Request) -> Response:
        session, error = _authorize_mutation(request, owner_auth)
        if error is not None:
            return error
        assert session is not None
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Task query is invalid.")
        body, error = await _read_json(request, CreateTaskRequest)
        if error is not None:
            return error
        assert body is not None
        approval_context = request.headers.getlist("x-aclais-approval-context")
        if len(approval_context) != 1:
            return _error(403, "AUTH_INVALID", "A fresh approval page is required.")
        provenance = owner_auth.verify_approval_context(
            approval_context[0],
            session,
            tool_id=body.tool_id,
            launch_source_claim=body.launch_source_claim,
        )
        if provenance is None:
            return _error(403, "AUTH_INVALID", "Approval context is invalid or expired.")
        if tool_registry is not None:
            try:
                tool_registry.resolve_installed_entrypoint(body)
            except WorkerUnavailable:
                return _error(
                    503,
                    "PROTECTION_UNAVAILABLE",
                    "The fixed production worker is unavailable until its component gate passes.",
                )
        if task_launcher is None:
            return _error(
                503,
                "PROTECTION_UNAVAILABLE",
                "No trusted task launcher is available.",
            )
        try:
            launched = task_launcher(body, provenance[0], provenance[1])
            if inspect.isawaitable(launched):
                launched = await launched
            task = (
                launched
                if hasattr(launched, "task_id") and hasattr(launched, "model_dump")
                else database.get_task(launched)
            )
            if task is None:
                return _error(503, "PROTECTION_UNAVAILABLE", "Task launch did not persist a task.")
            return _private_response(
                JSONResponse(status_code=201, content=task.model_dump(mode="json"))
            )
        except TaskAlreadyActive:
            return _error(409, "TASK_BUSY", "Another worker task is active.")
        except (DatabaseError, sqlite3.Error):
            return _error(503, "PROTECTION_UNAVAILABLE", "Task persistence is unavailable.")
        except Exception:
            return _error(503, "PROTECTION_UNAVAILABLE", "The approved task could not be started.")

    @application.get("/api/tasks/{task_id}")
    async def get_task(task_id: str, request: Request) -> Response:
        if owner_auth.authenticate(request) is None:
            return _error(401, "AUTH_INVALID", "Owner session is required.")
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Task query is invalid.")
        identifier = _parse_uuid(task_id)
        if identifier is None:
            return _error(400, "INVALID_REQUEST", "Task identifier is invalid.")
        try:
            task = database.get_task(identifier)
            if task is None:
                return _error(404, "NOT_FOUND", "Task was not found.")
            contract_record = database.get_contract(identifier)
            contract = (
                ContractSummary.model_validate(
                    contract_record.model_dump(exclude={"created_at"}), strict=True
                )
                if contract_record is not None
                else None
            )
            outputs = database.outputs_for_task(identifier)
            output = next(
                (
                    found
                    for record in reversed(outputs)
                    if (found := database.published_output(record.output_id)) is not None
                ),
                None,
            )
            incident = database.incident_for_task(identifier)
            detail = TaskDetailResponse(
                schema_version=1,
                task=task,
                contract_summary=contract,
                output_metadata=output,
                incident_summary=incident,
            )
            return _private_response(JSONResponse(content=detail.model_dump(mode="json")))
        except (DatabaseError, sqlite3.Error, ValidationError, ValueError):
            return _error(503, "PROTECTION_UNAVAILABLE", "Task detail is unavailable.")

    @application.get("/api/tasks/{task_id}/events")
    async def get_task_events(task_id: str, request: Request) -> Response:
        if owner_auth.authenticate(request) is None:
            return _error(401, "AUTH_INVALID", "Owner session is required.")
        identifier = _parse_uuid(task_id)
        if identifier is None:
            return _error(400, "INVALID_REQUEST", "Task identifier is invalid.")
        values = request.query_params.getlist("after_seq")
        if set(request.query_params.keys()) - {"after_seq"} or len(values) > 1:
            return _error(400, "INVALID_REQUEST", "Event query is invalid.")
        try:
            query = EventsQuery.model_validate(
                {"after_seq": values[0] if values else "0"}, strict=True
            )
            if database.get_task(identifier) is None:
                return _error(404, "NOT_FOUND", "Task was not found.")
            events = database.events(identifier, after_seq=query.after_seq)
            result = EventsResponse(
                schema_version=1,
                events=events,
                last_seq=events[-1].seq if events else query.after_seq,
            )
            return _private_response(JSONResponse(content=result.model_dump(mode="json")))
        except (ValidationError, ValueError):
            return _error(400, "INVALID_REQUEST", "Event query is invalid.")
        except (DatabaseError, sqlite3.Error):
            return _error(503, "PROTECTION_UNAVAILABLE", "Task events are unavailable.")

    @application.get("/api/tasks/{task_id}/evidence")
    async def get_task_evidence(task_id: str, request: Request) -> Response:
        if owner_auth.authenticate(request) is None:
            return _error(401, "AUTH_INVALID", "Owner session is required.")
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Evidence query is invalid.")
        identifier = _parse_uuid(task_id)
        if identifier is None:
            return _error(400, "INVALID_REQUEST", "Task identifier is invalid.")
        try:
            if database.get_task(identifier) is None:
                return _error(404, "NOT_FOUND", "Task was not found.")
            result = database.evidence_response(identifier)
            return _private_response(JSONResponse(content=result.model_dump(mode="json")))
        except (DatabaseError, sqlite3.Error):
            return _error(503, "PROTECTION_UNAVAILABLE", "Task evidence is unavailable.")

    @application.post("/api/tasks/{task_id}/cancel")
    async def cancel_task(task_id: str, request: Request) -> Response:
        session, error = _authorize_mutation(request, owner_auth)
        if error is not None:
            return error
        assert session is not None
        if not _query_allowed(request, set()):
            return _error(400, "INVALID_REQUEST", "Cancellation query is invalid.")
        identifier = _parse_uuid(task_id)
        if identifier is None:
            return _error(400, "INVALID_REQUEST", "Task identifier is invalid.")
        body_chunks = []
        async for chunk in request.stream():
            if chunk:
                body_chunks.append(chunk)
                if sum(map(len, body_chunks)) > 2_097_152:
                    return _error(413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB.")
        if body_chunks:
            return _error(400, "INVALID_REQUEST", "Cancel requests do not accept a body.")
        if task_canceller is None:
            return _error(503, "PROTECTION_UNAVAILABLE", "Task cancellation is unavailable.")
        try:
            task = task_canceller(identifier)
            result = CancelResponse(schema_version=1, task_id=task.task_id, status=task.status)
            return _private_response(JSONResponse(content=result.model_dump(mode="json")))
        except KeyError:
            return _error(404, "NOT_FOUND", "Task was not found.")
        except Exception:
            return _error(503, "PROTECTION_UNAVAILABLE", "Task cancellation is unavailable.")

    if output_publisher is not None:

        @application.get("/api/outputs/{output_id}")
        async def get_output(output_id: str, request: Request) -> Response:
            if owner_auth.authenticate(request) is None:
                return _error(401, "AUTH_INVALID", "Owner session is required.")
            if not _query_allowed(request, set()):
                return _error(400, "INVALID_REQUEST", "Output query is invalid.")
            identifier = _parse_uuid(output_id)
            if identifier is None:
                return _error(400, "INVALID_REQUEST", "Output identifier is invalid.")
            try:
                metadata, content = output_publisher.read_published(identifier)
            except (OutputUnavailable, ValueError):
                return _error(404, "NOT_FOUND", "Published output was not found.")
            except (DatabaseError, sqlite3.Error, OSError):
                return _error(
                    503, "PROTECTION_UNAVAILABLE", "Output integrity state is unavailable."
                )
            return _private_response(
                Response(
                    content=content,
                    status_code=200,
                    media_type=(
                        "text/markdown; charset=utf-8"
                        if metadata.output_kind == "formatted_markdown"
                        else "application/json"
                    ),
                    headers={
                        "Content-Disposition": f'attachment; filename="{metadata.file_name}"',
                        "X-Content-Type-Options": "nosniff",
                    },
                )
            )


async def _read_json(request: Request, model_type):
    content_types = request.headers.getlist("content-type")
    if (
        len(content_types) != 1
        or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
    ):
        return None, _error(400, "INVALID_REQUEST", "Content-Type must be application/json.")
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1:
        return None, _error(400, "INVALID_REQUEST", "Content-Length is invalid.")
    if lengths:
        try:
            if not lengths[0].isascii() or not lengths[0].isdecimal():
                raise ValueError
            if int(lengths[0]) > 2_097_152:
                return None, _error(413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB.")
        except ValueError:
            return None, _error(400, "INVALID_REQUEST", "Content-Length is invalid.")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > 2_097_152:
            return None, _error(413, "PAYLOAD_TOO_LARGE", "Request body exceeds 2 MiB.")
        chunks.append(chunk)
    try:
        decoded = decode_strict_json(b"".join(chunks))
        return model_type.model_validate(decoded, strict=True), None
    except (ValueError, ValidationError, TypeError):
        return None, _error(
            422, "INVALID_REQUEST", "Request body does not match the strict contract."
        )


def _authorize_mutation(request: Request, owner_auth: OwnerAuth):
    session = owner_auth.authenticate(request)
    if session is None:
        return None, _error(401, "AUTH_INVALID", "Owner session is required.")
    if not _same_origin_mutation(request, owner_auth.origin):
        return None, _error(403, "AUTH_INVALID", "Mutation requires the exact ACLAIS origin.")
    if not owner_auth.csrf_valid(request, session):
        return None, _error(403, "AUTH_INVALID", "Anti-CSRF validation failed.")
    return session, None


def _same_origin_mutation(request: Request, expected_origin: str) -> bool:
    origins = request.headers.getlist("origin")
    sites = request.headers.getlist("sec-fetch-site")
    return origins == [expected_origin] and (not sites or sites == ["same-origin"])


def _query_allowed(request: Request, allowed: set[str]) -> bool:
    return not (set(request.query_params.keys()) - allowed)


def _approval_query(request: Request) -> ApprovalQuery | None:
    if set(request.query_params.keys()) != {"tool_id", "launch_source_claim"}:
        return None
    if (
        len(request.query_params.getlist("tool_id")) != 1
        or len(request.query_params.getlist("launch_source_claim")) != 1
    ):
        return None
    try:
        return ApprovalQuery.model_validate(
            {
                "tool_id": request.query_params.get("tool_id"),
                "launch_source_claim": request.query_params.get("launch_source_claim"),
            },
            strict=True,
        )
    except ValidationError:
        return None


def _observed_provenance(request: Request) -> tuple[str | None, str | None]:
    origin_values = request.headers.getlist("origin")
    referer_values = request.headers.getlist("referer")
    origin = _origin_only(origin_values[0], allow_path=False) if len(origin_values) == 1 else None
    referer = _origin_only(referer_values[0], allow_path=True) if len(referer_values) == 1 else None
    return origin, referer


def _origin_only(value: str, *, allow_path: bool) -> str | None:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "http"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or (not allow_path and (parsed.query or parsed.fragment))
            or (not allow_path and parsed.path not in {"", "/"})
        ):
            return None
        hostname = parsed.hostname.lower()
        if len(hostname) > 253:
            return None
        if ":" in hostname:
            hostname = f"[{hostname}]"
        else:
            hostname = hostname.encode("idna").decode("ascii")
        port = parsed.port
        authority = f"{hostname}:{port}" if port is not None else hostname
        result = f"http://{authority}"
        return result if len(result) <= (2048 if allow_path else 512) else None
    except ValueError:
        return None


def _parse_uuid(value: str) -> UUID | None:
    try:
        return _UUID_ADAPTER.validate_python(value)
    except ValidationError:
        return None


def _error(status: int, code: str, message: str) -> JSONResponse:
    result = ErrorResponse(
        schema_version=1,
        error={"code": code, "message": message, "request_id": str(uuid4())},
    )
    return _private_response(
        JSONResponse(status_code=status, content=result.model_dump(mode="json"))
    )


def _private_response(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _validate_frontend_dist(frontend_dist: Path | None) -> Path | None:
    if frontend_dist is None:
        return None
    if not frontend_dist.is_absolute():
        raise ValueError("frontend distribution path must be absolute")
    try:
        root = frontend_dist.resolve(strict=True)
        assets = (root / "assets").resolve(strict=True)
    except OSError as exc:
        raise ValueError("frontend distribution is unavailable") from exc
    if (
        not root.is_dir()
        or not (root / "index.html").is_file()
        or not assets.is_dir()
        or not assets.is_relative_to(root)
    ):
        raise ValueError("frontend distribution is incomplete or escapes its install root")
    return root


def _frontend_response(
    frontend_root: Path | None,
    *,
    approval: dict[str, str | None] | None = None,
    referrer_policy: str = "no-referrer",
) -> HTMLResponse:
    if frontend_root is None:
        body = (
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>ACLAIS unavailable</title><main><h1>Owner interface unavailable</h1>"
            "<p>Build the ACLAIS frontend and restart the controller.</p></main></html>"
        )
        response = HTMLResponse(body, status_code=503)
    else:
        index_path = frontend_root / "index.html"
        try:
            body = index_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            body = ""
        root_pattern = re.compile(r"<div id=([\"'])root\1\s*></div>")
        if body and len(root_pattern.findall(body)) == 1:
            attribute = ""
            if approval is not None:
                encoded = json.dumps(approval, ensure_ascii=True, separators=(",", ":"))
                attribute = f' data-approval="{html.escape(encoded, quote=True)}"'
            body = root_pattern.sub(f'<div id="root"{attribute}></div>', body, count=1)
            response = HTMLResponse(body)
        else:
            body = (
                "<!doctype html><html lang='en'><meta charset='utf-8'>"
                "<title>ACLAIS unavailable</title><main><h1>Owner interface unavailable</h1>"
                "<p>The frontend distribution is incomplete. Rebuild it and restart "
                "ACLAIS.</p></main></html>"
            )
            response = HTMLResponse(body, status_code=503)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = referrer_policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "font-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; "
        "frame-ancestors 'none'; object-src 'none'"
    )
    return response


def _html_response(
    body: str, *, status_code: int = 200, referrer_policy: str = "no-referrer"
) -> HTMLResponse:
    response = HTMLResponse(body, status_code=status_code)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = referrer_policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'nonce-"
        + _extract_nonce(body)
        + "'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
    )
    return response


def _extract_nonce(body: str) -> str:
    marker = "<script nonce='"
    if marker not in body:
        return "disabled"
    return body.split(marker, 1)[1].split("'", 1)[0]


def _bootstrap_html() -> str:
    nonce = secrets.token_urlsafe(18)
    script = """
const statusNode = document.getElementById('status');
const token = window.location.hash.slice(1);
if (token) {
  window.history.replaceState(null, '', window.location.pathname);
  fetch('/api/owner/bootstrap/exchange', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ schema_version: 1, bootstrap_token: token })
  }).then(async response => {
    if (!response.ok) {
      throw new Error('The one-time link is invalid or expired. ' +
        'Restart ACLAIS to create a fresh owner link.');
    }
    window.location.replace('/owner');
  }).catch(error => { statusNode.textContent = error.message; });
} else {
  statusNode.textContent = 'Open the one-time link generated by the ACLAIS owner startup.';
}
"""
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>ACLAIS owner sign-in</title></head><body><main><h1>ACLAIS owner sign-in</h1>"
        "<p id='status' role='status'>Exchanging the one-time owner link...</p></main>"
        f"<script nonce='{nonce}'>{script}</script></body></html>"
    )


def _signin_html() -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>ACLAIS owner sign-in</title></head><body><main>"
        "<h1>Owner session required</h1>"
        "<p>Use the one-time sign-in link opened by the ACLAIS controller. "
        "If your session expired, restart the controller to create a fresh link.</p>"
        "</main></body></html>"
    )
