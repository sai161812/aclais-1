"""Validated, non-secret runtime configuration for the local API."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Settings(BaseModel):
    """Validated local API settings; the listener is always loopback-only."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: Literal["127.0.0.1"] = "127.0.0.1"
    port: int = Field(default=8765, ge=1024, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    protected_runtime: bool = False

    @property
    def expected_host_header(self) -> str:
        return f"{self.host}:{self.port}"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Load only supported ACLAIS variables; reject typos without echoing values."""

        values = os.environ if environ is None else environ
        allowed = {
            "ACLAIS_HOST",
            "ACLAIS_PORT",
            "ACLAIS_LOG_LEVEL",
            "ACLAIS_PROTECTED_RUNTIME",
        }
        unexpected = sorted(
            key for key in values if key.startswith("ACLAIS_") and key not in allowed
        )
        if unexpected:
            raise ValueError(f"Unsupported ACLAIS configuration key: {unexpected[0]}")

        host = values.get("ACLAIS_HOST", "127.0.0.1")
        raw_port = values.get("ACLAIS_PORT", "8765")
        if not raw_port.isascii() or not raw_port.isdecimal():
            raise ValueError("ACLAIS_PORT must contain decimal digits only")
        raw_runtime = values.get("ACLAIS_PROTECTED_RUNTIME", "false").casefold()
        if raw_runtime not in {"true", "false"}:
            raise ValueError("ACLAIS_PROTECTED_RUNTIME must be true or false")

        return cls.model_validate(
            {
                "host": host,
                "port": int(raw_port),
                "log_level": values.get("ACLAIS_LOG_LEVEL", "INFO"),
                "protected_runtime": raw_runtime == "true",
            }
        )
