"""Fixed installed entrypoint for the Invoice Analyzer worker."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--task-config", required=True)
    arguments = parser.parse_args()
    entrypoint = Path(__file__).resolve(strict=True)
    component_root = entrypoint.parents[2]
    source_root = component_root / "src"
    if not source_root.is_dir() or source_root.is_symlink():
        return 10
    sys.path.insert(0, str(source_root))
    from document_tools.invoice import run_invoice_analyzer
    from document_tools.worker import WorkerConfigurationError, parse_config

    try:
        config_path = Path(arguments.task_config)
        if not config_path.is_absolute() or config_path.is_symlink():
            return 11
        config = parse_config(config_path.read_bytes())
        if (config.tool_id, config.selected_document_id) != ("invoice_analyzer", "doc-invoice"):
            return 12
        return run_invoice_analyzer(config)
    except (OSError, WorkerConfigurationError):
        return 13


if __name__ == "__main__":
    raise SystemExit(main())
