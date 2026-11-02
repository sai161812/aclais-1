"""Owner-side process used to exercise A6 recovery after an abrupt controller death."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--signal-file", required=True)
    parser.add_argument("--backend-source", required=True)
    parser.add_argument("--verified-output-root", required=True)
    arguments = parser.parse_args()
    sys.path.insert(0, str(Path(arguments.backend_source).resolve()))

    import uvicorn

    from aclais.app import create_app
    from aclais.config import Settings
    from aclais.evidence import FixtureVerifier
    from aclais.launcher.windows import RuntimeLayout, WindowsWorkerController
    from aclais.lifecycle import LifecycleCoordinator, TaskWorkspace
    from aclais.persistence.database import Database
    from aclais.publication import OutputPublisher

    layout = replace(RuntimeLayout.open(), verified_output_root=Path(arguments.verified_output_root))
    workspace = TaskWorkspace(layout)
    workspace.prepare_roots()
    database = Database(Path(arguments.database))
    publisher = OutputPublisher(database, layout.verified_output_root)
    launcher = WindowsWorkerController(layout)
    verifier = FixtureVerifier(
        database,
        layout.root / "store",
        layout.raw_evidence_root,
        expected_fixtures=layout.fixture_hashes,
        source_root=Path(arguments.backend_source).resolve() / "aclais",
        source_revision=None,
    )
    coordinator = LifecycleCoordinator(
        layout,
        database,
        publisher,
        launcher=launcher,
        workspace=workspace,
        verifier=verifier,
        token_factory=lambda: "synthetic-a6-controller-crash-token-not-a-secret",
    )
    coordinator.recover_before_serving()

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
    settings = Settings(port=port)
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings, broker=coordinator.broker),
            host=settings.host,
            port=settings.port,
            log_config=None,
            access_log=False,
            lifespan="off",
            log_level="critical",
        )
    )
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        if not server_thread.is_alive():
            return 71
        time.sleep(0.025)
    if not server.started:
        return 72

    task_id = coordinator.start_private_probe(
        f"http://127.0.0.1:{port}/api/broker/operations",
        deadline_seconds=20,
        probe_case="child_wait",
        broker_probe="allow_and_publish",
    )
    with coordinator._active_lock:
        context = coordinator._active[task_id]
    handle = context.handle
    child_marker = context.paths.temporary_directory / f"a3-{task_id.hex}.child.json"
    marker_deadline = time.monotonic() + 12
    while time.monotonic() < marker_deadline and not child_marker.exists():
        time.sleep(0.025)
    if not child_marker.exists():
        coordinator.shutdown()
        return 73
    child = json.loads(child_marker.read_text(encoding="utf-8"))
    Path(arguments.signal_file).write_text(
        json.dumps(
            {
                "ready": True,
                "task_id": str(task_id),
                "worker_pid": handle.pid,
                "worker_creation_time_100ns": handle.creation_time,
                "worker_sid": handle.worker_sid,
                "child_pid": child["pid"],
                "child_creation_time_100ns": child["creation_time_100ns"],
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    time.sleep(600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
