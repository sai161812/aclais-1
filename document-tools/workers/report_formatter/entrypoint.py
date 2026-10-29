"""Fixed installed entrypoint for the Report Formatter worker."""

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
    from document_tools.worker import WorkerConfigurationError, parse_config, run_report_formatter

    try:
        config_path = Path(arguments.task_config)
        if not config_path.is_absolute() or config_path.is_symlink():
            return 11
        config = parse_config(config_path.read_bytes())
        return run_report_formatter(config)
    except (OSError, WorkerConfigurationError):
        return 12


if __name__ == "__main__":
    raise SystemExit(main())
