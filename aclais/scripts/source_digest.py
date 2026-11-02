"""Digest versioned implementation inputs, excluding runtime and evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


def source_digest() -> dict[str, str | int]:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=True,
    )
    selected = []
    for relative in sorted(set(result.stdout.decode().split("\0"))):
        if not relative.startswith(
            (
                "aclais/",
                "receiver/",
                "document-tools/",
                "shared/",
                "tests/",
                "scripts/",
                ".github/workflows/",
            )
        ):
            continue
        path = root / relative
        if path.is_file() and path.suffix.lower() in {
            ".py",
            ".sql",
            ".ps1",
            ".ts",
            ".tsx",
            ".css",
            ".html",
            ".json",
            ".toml",
            ".lock",
            ".yml",
            ".yaml",
            ".js",
            ".csv",
            ".md",
        }:
            selected.append(
                (relative, hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest())
            )
    manifest = "".join(f"{path}\0{digest}\n" for path, digest in selected).encode()
    return {"file_count": len(selected), "sha256": hashlib.sha256(manifest).hexdigest()}


if __name__ == "__main__":
    print(json.dumps(source_digest()))
