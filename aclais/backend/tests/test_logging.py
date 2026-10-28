"""Portable checks for the structured log format and redaction rules."""

import json
import logging
import sys

import pytest

from aclais.logging_config import JsonFormatter, redact_text


@pytest.mark.portable
def test_json_formatter_redacts_sensitive_fields_and_message_patterns() -> None:
    record = logging.LogRecord(
        name="aclais.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="authorization=Bearer header-secret request accepted",
        args=(),
        exc_info=None,
    )
    record.fields = {
        "request_id": "safe-id",
        "nested": {"access_token": "field-secret", "status": "safe"},
        "cookie": "cookie-secret",
        "API Key": "api-key-secret",
    }

    encoded = JsonFormatter().format(record)
    parsed = json.loads(encoded)

    assert parsed["message"] == "authorization=Bearer [REDACTED] request accepted"
    assert parsed["fields"]["nested"]["access_token"] == "[REDACTED]"
    assert parsed["fields"]["cookie"] == "[REDACTED]"
    assert parsed["fields"]["API Key"] == "[REDACTED]"
    assert "header-secret" not in encoded
    assert "field-secret" not in encoded
    assert "cookie-secret" not in encoded
    assert "api-key-secret" not in encoded
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "aclais.test"


@pytest.mark.portable
def test_json_formatter_omits_exception_text() -> None:
    try:
        raise ValueError("exception-secret")
    except ValueError:
        exception_info = sys.exc_info()

    record = logging.LogRecord(
        name="aclais.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=40,
        msg="unexpected operation failure",
        args=(),
        exc_info=exception_info,
    )

    encoded = JsonFormatter().format(record)
    parsed = json.loads(encoded)

    assert parsed["exception_type"] == "ValueError"
    assert "exception-secret" not in encoded


@pytest.mark.portable
def test_cookie_header_redacts_all_cookie_pairs_and_attributes() -> None:
    message = "Cookie: session=first-secret; preference=second-secret; SameSite=Strict"

    assert redact_text(message) == "Cookie: [REDACTED]"
