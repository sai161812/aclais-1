"""Owner-only receiver storage preparation and audit."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

_STORE_DIRECTORIES = ("payloads", "staging", "quarantine")


class StorageProtectionError(RuntimeError):
    """The receiver's configured data root cannot be protected safely."""


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def _validate_existing_ancestors(root: Path) -> None:
    if not root.is_absolute() or root == Path(root.anchor):
        raise StorageProtectionError("receiver storage root is not a scoped absolute directory")
    current = root
    while True:
        try:
            _is_reparse_point(current)
        except FileNotFoundError:
            pass
        else:
            if _is_reparse_point(current):
                raise StorageProtectionError("receiver storage path contains a reparse point")
        if current.parent == current:
            break
        current = current.parent


def _powershell_path() -> Path:
    script = Path(__file__).resolve().parents[2] / "scripts" / "protect_store.ps1"
    if not script.is_file() or _is_reparse_point(script):
        raise StorageProtectionError("receiver storage protection script is unavailable")
    return script


def _protect_windows_tree(root: Path, *, audit_only: bool = False) -> None:
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(_powershell_path()),
        "-StoreRoot",
        str(root),
    ]
    if audit_only:
        command.append("-AuditOnly")
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StorageProtectionError("receiver storage permissions could not be verified") from exc
    if result.returncode != 0 or result.stdout.strip() != "RECEIVER_STORE_PROTECTED":
        raise StorageProtectionError("receiver storage permissions could not be verified")


def _protect_posix_tree(root: Path) -> None:
    for directory, child_directories, files in os.walk(root, followlinks=False):
        current = Path(directory)
        if _is_reparse_point(current):
            raise StorageProtectionError("receiver storage path contains a reparse point")
        os.chmod(current, 0o700)
        for name in child_directories:
            path = current / name
            if _is_reparse_point(path):
                raise StorageProtectionError("receiver storage path contains a reparse point")
        for name in files:
            path = current / name
            if _is_reparse_point(path):
                raise StorageProtectionError("receiver storage path contains a reparse point")
            os.chmod(path, 0o600)


def prepare_store_root(root: Path) -> tuple[Path, Path, Path]:
    """Create and protect a scoped receiver tree before creating any receipt data."""
    root = Path(os.path.abspath(root))
    _validate_existing_ancestors(root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        for name in _STORE_DIRECTORIES:
            (root / name).mkdir(exist_ok=True)
    except OSError as exc:
        raise StorageProtectionError("receiver storage could not be prepared") from exc
    _validate_existing_ancestors(root)
    if sys.platform == "win32":
        _protect_windows_tree(root)
    else:
        _protect_posix_tree(root)
    return tuple(root / name for name in _STORE_DIRECTORIES)  # type: ignore[return-value]


def audit_store_root(root: Path) -> None:
    """Measure the existing owner-only ACL without changing it."""
    if not root.is_dir():
        raise StorageProtectionError("receiver storage directory is unavailable")
    root = Path(os.path.abspath(root))
    _validate_existing_ancestors(root)
    if sys.platform == "win32":
        _protect_windows_tree(root, audit_only=True)
        return
    for directory, child_directories, files in os.walk(root, followlinks=False):
        current = Path(directory)
        if _is_reparse_point(current) or stat.S_IMODE(current.stat().st_mode) != 0o700:
            raise StorageProtectionError("receiver directory permissions are not owner-only")
        for name in child_directories:
            if _is_reparse_point(current / name):
                raise StorageProtectionError("receiver storage path contains a reparse point")
        for name in files:
            path = current / name
            if _is_reparse_point(path) or stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise StorageProtectionError("receiver file permissions are not owner-only")
