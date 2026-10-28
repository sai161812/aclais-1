"""Strict JSON decoding shared by request validation and persistence contract tests."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ValidationError

MAX_JSON_BODY_BYTES = 2 * 1024 * 1024


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is invalid: {value}")


def _validate_unicode(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("JSON strings must contain valid Unicode scalar values")
    elif isinstance(value, list):
        for item in value:
            _validate_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode(key)
            _validate_unicode(item)


def parse_strict_json[TModel: BaseModel](data: bytes, model: type[TModel]) -> TModel:
    """Decode bounded strict JSON: no duplicate keys, invalid UTF-8, NaN, or coercion."""

    if not isinstance(data, bytes):
        raise TypeError("JSON body must be bytes")
    if len(data) > MAX_JSON_BODY_BYTES:
        raise ValueError("JSON body exceeds 2 MiB")
    try:
        text = data.decode("utf-8", errors="strict")
        decoded = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_unicode(decoded)
        return model.model_validate(decoded, strict=True)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError("JSON body does not match its strict request model") from exc
