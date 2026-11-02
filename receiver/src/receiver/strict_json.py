"""Strict JSON decoding for the receiver's bounded request bodies."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ValidationError


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite number")


def _validate_unicode(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("invalid Unicode scalar")
    elif isinstance(value, list):
        for item in value:
            _validate_unicode(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode(key)
            _validate_unicode(item)


def decode_strict_json(data: bytes) -> Any:
    if len(data) > 2_097_152:
        raise ValueError("request body exceeds limit")
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
        _validate_unicode(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("request is not strict UTF-8 JSON") from exc


def parse_model[TModel: BaseModel](data: bytes, model: type[TModel]) -> TModel:
    try:
        return model.model_validate(decode_strict_json(data), strict=True)
    except ValidationError as exc:
        raise ValueError("request does not match its strict model") from exc
