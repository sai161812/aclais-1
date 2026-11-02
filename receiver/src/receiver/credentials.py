"""One-time owner-only receiver administrator credential provisioning."""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path

from receiver.security import StorageProtectionError, prepare_store_root

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,512}$", re.ASCII)
_CREDENTIAL_NAME = "admin.token"


class CredentialError(RuntimeError):
    """The local receiver administrative credential is missing or invalid."""


def credential_path(data_root: Path) -> Path:
    return data_root / _CREDENTIAL_NAME


def create_admin_credential(data_root: Path) -> None:
    """Create a random administrator secret without printing or overwriting it."""
    path = credential_path(data_root)
    if path.exists() or path.is_symlink():
        raise CredentialError("receiver administrative credential already exists")
    prepare_store_root(data_root)
    token = secrets.token_urlsafe(32)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(token.encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        prepare_store_root(data_root)
    except (OSError, StorageProtectionError) as exc:
        try:
            if path.exists() and not _is_reparse(path):
                path.unlink()
        except OSError:
            pass
        raise CredentialError("receiver administrative credential could not be protected") from exc
    finally:
        token = ""


def read_admin_credential(data_root: Path) -> str:
    path = credential_path(data_root)
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(path)
            or not stat.S_ISREG(metadata.st_mode)
        ):
            raise CredentialError("receiver administrative credential is unavailable")
        raw = path.read_bytes()
        token = raw.decode("ascii", errors="strict")
        if not _TOKEN.fullmatch(token):
            raise CredentialError("receiver administrative credential is unavailable")
        return token
    except (OSError, UnicodeError) as exc:
        raise CredentialError("receiver administrative credential is unavailable") from exc


def _is_reparse(path: Path) -> bool:
    metadata = path.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse
    )
