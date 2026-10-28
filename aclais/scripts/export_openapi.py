"""Export the API schema from backend response models in a stable form."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACLAIS_ROOT = REPOSITORY_ROOT / "aclais"
OUTPUT_PATH = REPOSITORY_ROOT / "shared" / "openapi.json"


def render_openapi() -> str:
    sys.path.insert(0, str(ACLAIS_ROOT / "backend" / "src"))
    from aclais.api_contracts import build_openapi_document
    from aclais.app import app

    return json.dumps(
        build_openapi_document(app), ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the committed shared OpenAPI schema is stale",
    )
    args = parser.parse_args()
    generated = render_openapi()

    if args.check:
        if not OUTPUT_PATH.is_file() or OUTPUT_PATH.read_text(encoding="utf-8") != generated:
            print("shared/openapi.json is stale; run aclais/scripts/generate-api.ps1", file=sys.stderr)
            return 1
        print("Shared OpenAPI schema matches the backend response models.")
        return 0

    OUTPUT_PATH.write_text(generated, encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT_PATH.relative_to(REPOSITORY_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
