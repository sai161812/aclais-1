"""JSON logging with bounded, explicit secret redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

_SENSITIVE_KEY = re.compile(
    r"(?i)(authorization|proxy.authorization|cookie|set.cookie|token|password|passwd|secret|"
    r"credential|canary|payload|private|api[\s_-]?key)"
)
_COOKIE_ASSIGNMENT = re.compile(r"(?i)\b(set-cookie|cookie)\b(\s*[:=]\s*)[^\r\n]*")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|access[_-]?token|token|"
    r"password|passwd|secret|credential|canary|api[\s_-]?key)\b(\s*[:=]\s*)"
    r"(bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")


def redact_text(value: str) -> str:
    """Redact common credential assignments and bearer values in log messages."""

    def replace_assignment(match: re.Match[str]) -> str:
        scheme = "Bearer " if match.group(3) else ""
        return f"{match.group(1)}{match.group(2)}{scheme}[REDACTED]"

    def replace_cookie_assignment(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}[REDACTED]"

    scrubbed = _COOKIE_ASSIGNMENT.sub(replace_cookie_assignment, value)
    scrubbed = _SENSITIVE_ASSIGNMENT.sub(replace_assignment, scrubbed)
    return _BEARER_VALUE.sub("Bearer [REDACTED]", scrubbed)


def redact_fields(value: Any) -> Any:
    """Redact sensitive structured fields recursively before serialization."""

    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact_fields(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_fields(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))


class JsonFormatter(logging.Formatter):
    """Serialize an allowlisted record shape; never include raw exception text."""

    def format(self, record: logging.LogRecord) -> str:
        message = redact_text(record.getMessage())
        document: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            document["fields"] = redact_fields(fields)
        if record.exc_info:
            document["exception_type"] = record.exc_info[0].__name__
        return json.dumps(document, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def configure_logging(level: str = "INFO") -> None:
    """Configure a single JSON console handler for the controller process."""

    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    logging.captureWarnings(True)
