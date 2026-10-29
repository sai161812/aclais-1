"""Trusted A6 Windows runtime assembly, kept separate from public request models."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI

from aclais.app import create_app
from aclais.config import Settings
from aclais.evidence import FixtureVerifier
from aclais.launcher.windows import RuntimeLayout, WindowsWorkerController
from aclais.lifecycle import LifecycleCoordinator, TaskWorkspace
from aclais.persistence.database import Database
from aclais.publication import OutputPublisher


@dataclass(frozen=True, slots=True)
class A6Runtime:
    app: FastAPI
    lifecycle: LifecycleCoordinator
    database: Database
    output_publisher: OutputPublisher


def create_a6_runtime(settings: Settings | None = None) -> A6Runtime:
    """Create the protected runtime and reconcile persisted tasks before serving."""

    runtime_settings = settings or Settings()
    layout = RuntimeLayout.open()
    workspace = TaskWorkspace(layout)
    workspace.prepare_roots()
    database = Database(layout.root / "state" / "controller.sqlite3")
    output_publisher = OutputPublisher(database, layout.verified_output_root)
    launcher = WindowsWorkerController(layout)
    verifier = FixtureVerifier(
        database,
        layout.root / "store",
        layout.raw_evidence_root,
        expected_fixtures=layout.fixture_hashes,
        source_revision=None,
    )
    lifecycle = LifecycleCoordinator(
        layout,
        database,
        output_publisher,
        launcher=launcher,
        workspace=workspace,
        verifier=verifier,
    )
    lifecycle.recover_before_serving()
    application = create_app(
        runtime_settings,
        broker=lifecycle.broker,
        output_publisher=output_publisher,
    )
    application.add_event_handler("shutdown", lifecycle.shutdown)
    return A6Runtime(
        app=application,
        lifecycle=lifecycle,
        database=database,
        output_publisher=output_publisher,
    )
