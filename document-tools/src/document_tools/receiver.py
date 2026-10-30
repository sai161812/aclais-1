"""Fixed loopback receiver ingest client for the Invoice Analyzer worker."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

_RECEIVER_HOST = "::1"
_RECEIVER_PORT = 8767
_RECEIVER_HOST_HEADER = "[::1]:8767"
_RECEIVER_PATH = "/ingest"
_MAX_RECEIPT_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 65_536


class ReceiverIngestError(RuntimeError):
    def __init__(self, outcome: str, *, status_code: int | None = None, code: str | None = None):
        self.outcome = outcome
        self.status_code = status_code
        self.code = code
        super().__init__("receiver ingest did not return a valid receipt")


@dataclass(frozen=True, slots=True)
class ReceiverReceipt:
    decoded_bytes: int
    sha256: str


class ReceiverClient:
    def __init__(self, *, run_id: str, task_id: str, ingest_token: str, timeout: float = 3.0):
        try:
            self.run_id = str(UUID(run_id))
            self.task_id = str(UUID(task_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("receiver task or run identifier is invalid") from exc
        if (
            not isinstance(ingest_token, str)
            or not 32 <= len(ingest_token) <= 512
            or not re.fullmatch(r"[A-Za-z0-9_-]+", ingest_token)
        ):
            raise ValueError("receiver ingest credential is invalid")
        if not 0 < timeout <= 5:
            raise ValueError("receiver timeout must be bounded")
        self._token = ingest_token
        self._timeout = timeout

    def ingest(self, payload: bytes) -> ReceiverReceipt:
        if not isinstance(payload, bytes) or len(payload) > _MAX_RECEIPT_BYTES:
            raise ReceiverIngestError(
                "payload_too_large", status_code=413, code="PAYLOAD_TOO_LARGE"
            )
        request_id = str(uuid4())
        body = json.dumps(
            {
                "schema_version": 1,
                "request_id": request_id,
                "run_id": self.run_id,
                "task_id": self.task_id,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

        # The receiver deduplicates by run and request ID. A transport retry must send
        # precisely the same request ID and body so a lost response cannot duplicate data.
        for attempt in range(2):
            connection = http.client.HTTPConnection(
                _RECEIVER_HOST, _RECEIVER_PORT, timeout=self._timeout
            )
            try:
                connection.request(
                    "POST",
                    _RECEIVER_PATH,
                    body=body,
                    headers={
                        "Host": _RECEIVER_HOST_HEADER,
                        "Authorization": f"Bearer {self._token}",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
            except (OSError, TimeoutError, http.client.HTTPException) as exc:
                if attempt == 0:
                    continue
                raise ReceiverIngestError("unreachable") from exc
            finally:
                connection.close()
            if (
                len(raw) > _MAX_RESPONSE_BYTES
                or response.getheader("Content-Type", "").split(";", 1)[0].lower()
                != "application/json"
            ):
                raise ReceiverIngestError("invalid_response", status_code=response.status)
            try:
                value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ReceiverIngestError("invalid_response", status_code=response.status) from exc
            if response.status != 201:
                code = None
                if isinstance(value, dict) and set(value) == {"schema_version", "error"}:
                    error = value["error"]
                    if (
                        isinstance(error, dict)
                        and set(error) == {"code", "message", "request_id"}
                        and type(error.get("code")) is str
                        and re.fullmatch(r"[A-Z_]{3,64}", error["code"])
                        and type(error.get("message")) is str
                        and 1 <= len(error["message"]) <= 256
                        and type(error.get("request_id")) is str
                    ):
                        try:
                            request_error_id = UUID(error["request_id"])
                        except (TypeError, ValueError):
                            request_error_id = None
                        if (
                            request_error_id is not None
                            and str(request_error_id) == error["request_id"]
                        ):
                            code = error["code"]
                if (
                    type(value) is not dict
                    or set(value) != {"schema_version", "error"}
                    or type(value.get("schema_version")) is not int
                    or value["schema_version"] != 1
                    or code is None
                ):
                    raise ReceiverIngestError("invalid_response", status_code=response.status)
                outcome = (
                    "authentication_failure"
                    if response.status in (401, 403)
                    else "unavailable"
                    if response.status >= 500
                    else "rejected"
                )
                raise ReceiverIngestError(
                    outcome,
                    status_code=response.status,
                    code=code,
                )
            if not isinstance(value, dict) or set(value) != {
                "schema_version",
                "receipt_id",
                "received_at",
                "decoded_bytes",
                "sha256",
            }:
                raise ReceiverIngestError("invalid_response", status_code=response.status)
            digest = hashlib.sha256(payload).hexdigest()
            if (
                type(value["schema_version"]) is not int
                or value["schema_version"] != 1
                or type(value["decoded_bytes"]) is not int
                or value["decoded_bytes"] != len(payload)
                or type(value["sha256"]) is not str
                or value["sha256"] != digest
                or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
            ):
                raise ReceiverIngestError("invalid_response", status_code=response.status)
            try:
                receipt_id = UUID(value["receipt_id"])
            except (TypeError, ValueError) as exc:
                raise ReceiverIngestError("invalid_response", status_code=response.status) from exc
            received_at = value["received_at"]
            if type(received_at) is not str:
                raise ReceiverIngestError("invalid_response", status_code=response.status)
            try:
                parsed_timestamp = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ReceiverIngestError("invalid_response", status_code=response.status) from exc
            if (
                str(receipt_id) != value["receipt_id"]
                or parsed_timestamp.tzinfo is None
                or parsed_timestamp.utcoffset() != timedelta(0)
            ):
                raise ReceiverIngestError("invalid_response", status_code=response.status)
            return ReceiverReceipt(decoded_bytes=len(payload), sha256=digest)
        raise ReceiverIngestError("unreachable")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result
