"""Validated non-secret receiver settings with fixed network authority."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_ROOT = (
    Path(r"C:\ACLAIS-Lab\state\receiver")
    if sys.platform == "win32"
    else Path.home() / ".local" / "share" / "aclais-1" / "receiver"
)


class ReceiverSettings(BaseModel):
    """The production host and port are fixed by the shared protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    data_root: Path = _DEFAULT_ROOT
    host: Literal["::1"] = "::1"
    port: int = Field(default=8767, ge=1024, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("data_root")
    @classmethod
    def absolute_outside_checkout(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("receiver storage must use an absolute path")
        normalized = Path(os.path.abspath(value))
        try:
            normalized.relative_to(_REPOSITORY_ROOT)
        except ValueError:
            return normalized
        raise ValueError("receiver runtime storage cannot be inside the repository")

    @property
    def expected_host_header(self) -> str:
        return f"[{self.host}]:{self.port}"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ReceiverSettings:
        values = os.environ if environ is None else environ
        allowed = {"RECEIVER_LOG_LEVEL"}
        unexpected = sorted(
            key for key in values if key.startswith("RECEIVER_") and key not in allowed
        )
        if unexpected:
            raise ValueError(f"Unsupported receiver configuration key: {unexpected[0]}")
        return cls.model_validate(
            {"log_level": values.get("RECEIVER_LOG_LEVEL", "INFO")}, strict=True
        )
