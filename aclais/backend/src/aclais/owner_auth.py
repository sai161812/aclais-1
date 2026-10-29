"""Hashed, host-only owner sessions for the local ACLAIS controller."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from starlette.requests import Request

from aclais.persistence.database import Database, OwnerSessionRecord

OWNER_SESSION_COOKIE = "aclais_owner_session"
OWNER_CSRF_COOKIE = "aclais_owner_csrf"
CSRF_HEADER = "x-csrf-token"
SESSION_LIFETIME = timedelta(hours=8)
BOOTSTRAP_LIFETIME = timedelta(minutes=15)


class OwnerAuthError(RuntimeError):
    """Owner authentication storage is unavailable or inconsistent."""


@dataclass(frozen=True, slots=True)
class OwnerSessionSecrets:
    session_token: str
    csrf_token: str
    expires_at: datetime


class OwnerAuth:
    """Issues one-time bootstrap links and validates hashed owner credentials."""

    def __init__(
        self,
        database: Database,
        *,
        origin: str,
        token_factory=secrets.token_urlsafe,
        now_factory=lambda: datetime.now(UTC),
    ) -> None:
        if origin != "http://127.0.0.1:8765":
            raise ValueError("owner origin must be the canonical ACLAIS origin")
        self.database = database
        self.origin = origin
        self._token_factory = token_factory
        self._now_factory = now_factory
        self._approval_context_key = secrets.token_bytes(32)
        self._approval_context_lock = threading.Lock()
        self._consumed_approval_contexts: dict[str, int] = {}

    def issue_bootstrap_url(self) -> str | None:
        """Create a fresh one-time secret in a URL fragment, never in an HTTP query."""

        now = self._now_factory().astimezone(UTC)
        token = self._new_token()
        created = self.database.issue_owner_bootstrap(
            self._sha256(token), now=now, expires_at=now + BOOTSTRAP_LIFETIME
        )
        if not created:
            return None
        return f"{self.origin}/bootstrap#{quote(token, safe='-_')}"

    def exchange_bootstrap(self, token: str) -> OwnerSessionSecrets | None:
        if not self._valid_token(token):
            return None
        now = self._now_factory().astimezone(UTC)
        bootstrap = self.database.owner_bootstrap()
        if (
            bootstrap is None
            or bootstrap.consumed_at is not None
            or bootstrap.expires_at is None
            or now >= bootstrap.expires_at
            or not secrets.compare_digest(bootstrap.token_sha256, self._sha256(token))
        ):
            return None

        session_token = self._new_token()
        csrf_token = self._new_token()
        expiry = now + SESSION_LIFETIME
        consumed = self.database.exchange_owner_bootstrap(
            self._sha256(token),
            self._sha256(session_token),
            self._sha256(csrf_token),
            now=now,
            session_expires_at=expiry,
        )
        if not consumed:
            return None
        return OwnerSessionSecrets(session_token, csrf_token, expiry)

    def authenticate(self, request: Request) -> OwnerSessionRecord | None:
        token = _single_cookie(request, OWNER_SESSION_COOKIE)
        if not self._valid_token(token):
            return None
        record = self.database.owner_session(self._sha256(token))
        now = self._now_factory().astimezone(UTC)
        if (
            record is None
            or record.revoked_at is not None
            or record.expires_at is None
            or now >= record.expires_at
        ):
            return None
        return record

    def csrf_valid(self, request: Request, session: OwnerSessionRecord) -> bool:
        cookie = _single_cookie(request, OWNER_CSRF_COOKIE)
        headers = request.headers.getlist(CSRF_HEADER)
        if (
            not self._valid_token(cookie)
            or len(headers) != 1
            or not secrets.compare_digest(headers[0], cookie)
        ):
            return False
        return secrets.compare_digest(session.csrf_sha256, self._sha256(cookie))

    def revoke(self, session: OwnerSessionRecord) -> None:
        self.database.revoke_owner_session(
            session.session_sha256, now=self._now_factory().astimezone(UTC)
        )

    def create_approval_context(
        self,
        session: OwnerSessionRecord,
        *,
        tool_id: str,
        launch_source_claim: str,
        observed_origin: str | None,
        observed_referer: str | None,
    ) -> str:
        now = int(self._now_factory().astimezone(UTC).timestamp())
        expires_at = now + 300
        nonce = secrets.token_urlsafe(32)
        with self._approval_context_lock:
            self._prune_approval_contexts(now)
            if len(self._consumed_approval_contexts) >= 4096:
                raise OwnerAuthError("too many pending approval contexts")
        payload = json.dumps(
            {
                "expires_at": expires_at,
                "nonce": nonce,
                "launch_source_claim": launch_source_claim,
                "observed_origin": observed_origin,
                "observed_referer": observed_referer,
                "session_sha256": session.session_sha256,
                "tool_id": tool_id,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        encoded = _b64url(payload)
        signature = hmac.new(self._approval_context_key, payload, hashlib.sha256).digest()
        return encoded + "." + _b64url(signature)

    def verify_approval_context(
        self,
        token: str,
        session: OwnerSessionRecord,
        *,
        tool_id: str,
        launch_source_claim: str,
    ) -> tuple[str | None, str | None] | None:
        if not isinstance(token, str) or len(token) > 2048 or token.count(".") != 1:
            return None
        payload_part, signature_part = token.split(".", 1)
        try:
            payload = _unb64url(payload_part)
            signature = _unb64url(signature_part)
            decoded = json.loads(payload.decode("ascii", errors="strict"))
        except (ValueError, UnicodeError, json.JSONDecodeError):
            return None
        expected = hmac.new(self._approval_context_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected) or not isinstance(decoded, dict):
            return None
        if set(decoded) != {
            "expires_at",
            "launch_source_claim",
            "nonce",
            "observed_origin",
            "observed_referer",
            "session_sha256",
            "tool_id",
        }:
            return None
        now = int(self._now_factory().astimezone(UTC).timestamp())
        if (
            type(decoded["expires_at"]) is not int
            or now >= decoded["expires_at"]
            or decoded["session_sha256"] != session.session_sha256
            or decoded["tool_id"] != tool_id
            or decoded["launch_source_claim"] != launch_source_claim
            or not self._valid_token(decoded["nonce"])
            or decoded["observed_origin"] is not None
            and not isinstance(decoded["observed_origin"], str)
            or decoded["observed_referer"] is not None
            and not isinstance(decoded["observed_referer"], str)
        ):
            return None
        with self._approval_context_lock:
            self._prune_approval_contexts(now)
            if decoded["nonce"] in self._consumed_approval_contexts:
                return None
            if len(self._consumed_approval_contexts) >= 4096:
                return None
            self._consumed_approval_contexts[decoded["nonce"]] = decoded["expires_at"]
        return decoded["observed_origin"], decoded["observed_referer"]

    def _prune_approval_contexts(self, now: int) -> None:
        expired = [
            nonce
            for nonce, expires_at in self._consumed_approval_contexts.items()
            if now >= expires_at
        ]
        for nonce in expired:
            del self._consumed_approval_contexts[nonce]

    def now(self) -> datetime:
        return self._now_factory().astimezone(UTC)

    def _new_token(self) -> str:
        token = self._token_factory(32)
        if not self._valid_token(token):
            raise OwnerAuthError("owner credential generator returned an invalid token")
        return token

    @staticmethod
    def _sha256(token: str) -> str:
        return hashlib.sha256(token.encode("ascii", errors="strict")).hexdigest()

    @staticmethod
    def _valid_token(token: object) -> bool:
        return (
            isinstance(token, str)
            and 32 <= len(token) <= 128
            and all(
                character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                for character in token
            )
        )


def _single_cookie(request: Request, name: str) -> str | None:
    cookies: list[str] = []
    for header in request.headers.getlist("cookie"):
        for part in header.split(";"):
            key, separator, value = part.strip().partition("=")
            if separator and key == name:
                cookies.append(value)
    return cookies[0] if len(cookies) == 1 else None


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    if not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
        for character in value
    ):
        raise ValueError("invalid base64url value")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
