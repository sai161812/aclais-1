"""Bounded HTTP client for the shared ACLAIS worker operation contract."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
from urllib.parse import urlsplit
from uuid import UUID, uuid4

MAX_BODY = 1_048_576 + 65_536


class BrokerProtocolError(RuntimeError):
    """The ACLAIS response was unavailable or did not match its strict contract."""


class BrokerDenied(BrokerProtocolError):
    def __init__(self, status_code: int, code: str) -> None:
        self.status_code = status_code
        self.code = code
        super().__init__("broker operation was denied")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


class BrokerClient:
    def __init__(self, url: str, token: str, *, timeout: float = 5.0) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or not 1024 <= parsed.port <= 65535
            or parsed.path != "/api/broker/operations"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not 32 <= len(token) <= 512
            or not re.fullmatch(r"[A-Za-z0-9_-]+", token)
        ):
            raise ValueError("broker must use the bounded loopback operation endpoint")
        self.host = parsed.hostname
        self.port = parsed.port
        self.path = parsed.path
        self.token = token
        self.timeout = timeout

    def _call(self, request: dict[str, object]) -> dict[str, object]:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            body = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            connection.request(
                "POST",
                self.path,
                body=body,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            raw = response.read(MAX_BODY + 1)
            if (
                len(raw) > MAX_BODY
                or response.getheader("Content-Type", "").split(";")[0] != "application/json"
            ):
                raise BrokerProtocolError("broker response exceeded its strict limit")
            try:
                value = json.loads(
                    raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object
                )
            except (UnicodeDecodeError, ValueError) as exc:
                raise BrokerProtocolError("broker response was not strict JSON") from exc
            if not isinstance(value, dict):
                raise BrokerProtocolError("broker response was not an object")
            if response.status >= 400:
                if (
                    set(value) != {"schema_version", "error"}
                    or type(value.get("schema_version")) is not int
                    or value["schema_version"] != 1
                ):
                    raise BrokerProtocolError("broker error response fields were invalid")
                error = value.get("error")
                if not isinstance(error, dict) or set(error) != {"code", "message", "request_id"}:
                    raise BrokerProtocolError("broker error details were invalid")
                code = error.get("code") if isinstance(error, dict) else None
                message = error.get("message")
                request_id = error.get("request_id")
                if (
                    type(code) is not str
                    or not re.fullmatch(r"[A-Z_]{3,64}", code)
                    or type(message) is not str
                    or len(message) > 512
                    or type(request_id) is not str
                ):
                    raise BrokerProtocolError("broker error response was invalid")
                try:
                    UUID(request_id)
                except ValueError as exc:
                    raise BrokerProtocolError("broker error request ID was invalid") from exc
                raise BrokerDenied(response.status, code)
            if response.status not in (200, 201):
                raise BrokerProtocolError("broker success status was invalid")
            return value
        except (OSError, http.client.HTTPException) as exc:
            raise BrokerProtocolError("broker endpoint could not be reached") from exc
        finally:
            connection.close()

    def read_document(self, task_id: str, document_id: str) -> str:
        if type(task_id) is not str:
            raise BrokerProtocolError("worker task identifier was invalid")
        try:
            UUID(task_id)
        except ValueError as exc:
            raise BrokerProtocolError("worker task identifier was invalid") from exc
        if document_id != "doc-report":
            raise BrokerProtocolError("formatter can read only its selected report")
        value = self._call(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "operation": "read_document",
                "document_id": document_id,
            }
        )
        if set(value) != {"schema_version", "decision", "document_id", "content_text"}:
            raise BrokerProtocolError("read response fields were invalid")
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["decision"]) is not str
            or value["decision"] != "allow"
            or type(value["document_id"]) is not str
            or value["document_id"] != document_id
            or type(value["content_text"]) is not str
        ):
            raise BrokerProtocolError("read response did not match the selected document")
        content = value["content_text"]
        if type(content) is not str or len(content.encode("utf-8")) > 1_048_576:
            raise BrokerProtocolError("selected input exceeded the broker read limit")
        return content

    def publish_output(self, text: str) -> dict[str, str]:
        encoded = text.encode("utf-8", errors="strict")
        if len(encoded) > 1_048_576:
            raise BrokerProtocolError("formatted output exceeds the broker limit")
        value = self._call(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "operation": "publish_output",
                "output_kind": "formatted_markdown",
                "output_text": text,
            }
        )
        if set(value) != {"schema_version", "decision", "output_id", "sha256"}:
            raise BrokerProtocolError("publish response fields were invalid")
        output_id, digest = value["output_id"], value["sha256"]
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["decision"]) is not str
            or value["decision"] != "allow"
            or type(output_id) is not str
            or type(digest) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or digest != hashlib.sha256(encoded).hexdigest()
        ):
            raise BrokerProtocolError("publish response did not match the output contract")
        try:
            UUID(output_id)
        except ValueError as exc:
            raise BrokerProtocolError("publish response output identifier was invalid") from exc
        return {"output_id": output_id, "sha256": digest}

    def replace_original(self, task_id: str, document_id: str, replacement_text: str) -> None:
        if type(task_id) is not str:
            raise BrokerProtocolError("worker task identifier was invalid")
        try:
            UUID(task_id)
        except ValueError as exc:
            raise BrokerProtocolError("worker task identifier was invalid") from exc
        if document_id != "doc-report" or type(replacement_text) is not str:
            raise BrokerProtocolError("formatter replacement request was invalid")
        if len(replacement_text.encode("utf-8", errors="strict")) > 1_048_576:
            raise BrokerProtocolError("formatter replacement request exceeded its limit")
        self._call(
            {
                "schema_version": 1,
                "request_id": str(uuid4()),
                "operation": "replace_original",
                "document_id": document_id,
                "replacement_text": replacement_text,
            }
        )
