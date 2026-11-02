"""Private owner-side harness used to test OS cleanup on controller process death."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / "aclais" / "backend" / "src"))

from aclais.launcher.windows import RuntimeLayout, WindowsWorkerController  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signal-file", required=True)
    arguments = parser.parse_args()
    controller = WindowsWorkerController(RuntimeLayout.open())
    handle = controller.start_a3_private_probe(deadline_seconds=120, probe_case="child_wait")
    child_marker = (
        Path(handle.config.temporary_output) / f"a3-{handle.config.task_id.hex}.child.json"
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not child_marker.exists():
        time.sleep(0.025)
    if not child_marker.exists():
        controller.shutdown()
        return 72
    child = json.loads(child_marker.read_text(encoding="utf-8"))
    Path(arguments.signal_file).write_text(
        json.dumps(
            {
                "ready": True,
                "worker_pid": handle.pid,
                "child_pid": child["pid"],
                "child_in_job": child["in_job"],
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    handle.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
