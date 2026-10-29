"""Portable lifecycle arbitration checks; fake handles do not prove Windows containment."""

from __future__ import annotations

import hashlib
import shutil
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

import aclais.lifecycle as lifecycle_module
from aclais.concurrency import TaskLockRegistry
from aclais.evidence import FixtureVerifier
from aclais.lifecycle import LifecycleCoordinator, LifecycleError, TaskWorkspacePaths
from aclais.persistence.database import Database, DatabaseError, utc_now
from aclais.persistence.models import (
    BrokerPublishOutputRequest,
    BrokerReadDocumentRequest,
    CreateTaskRequest,
    RevocationCause,
    TaskStatus,
    TerminalCause,
)
from aclais.publication import OutputPublisher

pytestmark = pytest.mark.portable


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value
        self.lock = threading.Lock()

    def __call__(self) -> float:
        with self.lock:
            return self.value

    def set(self, value: float) -> None:
        with self.lock:
            self.value = value


class FakeWorkspace:
    def __init__(self, layout: SimpleNamespace) -> None:
        self.layout = layout
        self.selected_inputs: dict[UUID, Path] = {}

    def prepare_roots(self) -> None:
        return

    def prepare(self, task, *, source_override: Path | None = None) -> TaskWorkspacePaths:
        selected_directory = self.layout.selected_copy_root / str(task.task_id)
        temporary_directory = self.layout.task_output_root / str(task.task_id)
        selected_directory.mkdir()
        temporary_directory.mkdir()
        selected_input = selected_directory / "doc-report.md"
        shutil.copyfile(source_override or self.layout.selected_input, selected_input)
        self.selected_inputs[task.task_id] = selected_input
        return TaskWorkspacePaths(
            task_id=task.task_id,
            selected_directory=selected_directory,
            temporary_directory=temporary_directory,
            selected_input=selected_input,
        )

    def cleanup(self, task_id: UUID | str) -> None:
        self.selected_inputs.pop(UUID(str(task_id)), None)
        for root in (self.layout.selected_copy_root, self.layout.task_output_root):
            shutil.rmtree(root / str(task_id), ignore_errors=True)

    def selected_input_for_task(self, task):
        return self.selected_inputs.get(task.task_id)


class FakeResult:
    def __init__(self, cause: str, exit_code: int) -> None:
        self.termination_cause = cause
        self.exit_code = exit_code
        self.process_tree_stopped = True
        self.stdout = ()
        self.stderr = ()


class FakeWorkerHandle:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._exited = threading.Event()
        self._lock = threading.Lock()
        self._exit_code = 0
        self._result: FakeResult | None = None
        self.handles_closed = False

    @property
    def stopped(self) -> bool:
        return self._result is not None or self._exited.is_set()

    def process_exit_observed(self) -> bool:
        return self._exited.is_set()

    def wait_for_process_exit(self, milliseconds: int) -> bool:
        return self._exited.wait(milliseconds / 1000)

    def signal_exit(self, exit_code: int = 0) -> None:
        with self._lock:
            if self._result is None:
                self._exit_code = exit_code
                self._exited.set()

    def finish_process_exit(self) -> FakeResult:
        with self._lock:
            if self._result is None:
                self._result = FakeResult("process_exit", self._exit_code)
                self.handles_closed = True
            return self._result

    def terminate(self, cause: str) -> FakeResult:
        with self._lock:
            if self._result is None:
                self._result = FakeResult(cause, 0xC000013A)
                self._exited.set()
                self.handles_closed = True
            return self._result


def _read_body(document_id: str = "doc-report") -> bytes:
    return BrokerReadDocumentRequest(
        schema_version=1,
        request_id=uuid4(),
        operation="read_document",
        document_id=document_id,
    ).model_dump_json().encode("utf-8")


def _publish_body(text: str = "# A6 synthetic output\n") -> bytes:
    return BrokerPublishOutputRequest(
        schema_version=1,
        request_id=uuid4(),
        operation="publish_output",
        output_kind="formatted_markdown",
        output_text=text,
    ).model_dump_json().encode("utf-8")


class FakeLauncher:
    def __init__(self, worker_sid: str, behavior: str = "complete") -> None:
        self.worker_sid = worker_sid
        self.behavior = behavior
        self.broker = None
        self.handles: dict[UUID, FakeWorkerHandle] = {}
        self.threads: list[threading.Thread] = []
        self.responses: list[tuple[str, int]] = []
        self.publish_completed = threading.Event()

    def start_a3_private_probe(self, *, task_id, worker_credential, before_resume, **_kwargs):
        pid = 50_000 + len(self.handles)
        handle = FakeWorkerHandle(pid)
        before_resume(pid, pid * 100, self.worker_sid)
        self.handles[task_id] = handle
        behavior = self.behavior
        if behavior in {"complete", "publish_wait", "deny"}:
            thread = threading.Thread(
                target=self._run_broker_flow,
                args=(task_id, worker_credential, handle, behavior),
                daemon=True,
            )
            thread.start()
            self.threads.append(thread)
        return handle

    def _run_broker_flow(
        self, task_id: UUID, token: str, handle: FakeWorkerHandle, behavior: str
    ) -> None:
        if behavior == "deny":
            result = self.broker.execute(token, _read_body("doc-private"))
            self.responses.append(("deny", result.status_code))
            return
        result = self.broker.execute(token, _read_body())
        self.responses.append(("read", result.status_code))
        if result.status_code != 200:
            return
        result = self.broker.execute(token, _publish_body())
        self.responses.append(("publish", result.status_code))
        if result.status_code == 200:
            self.publish_completed.set()
            if behavior == "complete":
                handle.signal_exit(0)

    def shutdown(self) -> None:
        for handle in self.handles.values():
            if not handle.stopped:
                handle.terminate("controller_shutdown")


class ObservedTaskLocks(TaskLockRegistry):
    def __init__(self) -> None:
        super().__init__()
        self.denial_thread_id: int | None = None
        self.denial_contending = threading.Event()

    @contextmanager
    def hold(self, task_id: str):
        if threading.get_ident() == self.denial_thread_id:
            self.denial_contending.set()
        with super().hold(task_id):
            yield


@pytest.fixture
def harness(tmp_path: Path):
    selected_root = tmp_path / "work" / "selected-inputs"
    task_output_root = tmp_path / "work" / "task-output"
    verified_output_root = tmp_path / "work" / "verified-output"
    selected_root.mkdir(parents=True)
    task_output_root.mkdir(parents=True)
    verified_output_root.mkdir(parents=True)
    selected_source = tmp_path / "selected-input.template.md"
    selected_source.write_text("Synthetic selected input for A6.\n", encoding="utf-8")
    fixture_root = tmp_path / "store" / "selected"
    fixture_root.mkdir(parents=True)
    fixture = fixture_root / "report.md"
    shutil.copyfile(selected_source, fixture)
    layout = SimpleNamespace(
        root=tmp_path,
        owner_sid="S-1-5-21-100-200-300-1001",
        worker_sid="S-1-5-21-100-200-300-1006",
        selected_input=selected_source,
        raw_evidence_root=tmp_path / "evidence" / "raw",
        fixture_hashes=(
            ("store/selected/report.md", hashlib.sha256(fixture.read_bytes()).hexdigest()),
        ),
        selected_copy_root=selected_root,
        task_output_root=task_output_root,
    )
    database = Database(tmp_path / "state.sqlite3")
    publisher = OutputPublisher(database, verified_output_root)
    launcher = FakeLauncher(layout.worker_sid)
    workspace = FakeWorkspace(layout)
    verifier = FixtureVerifier(
        database,
        layout.root / "store",
        layout.raw_evidence_root,
        expected_fixtures=layout.fixture_hashes,
        source_root=Path(__file__).resolve().parents[1] / "src" / "aclais",
    )
    token_values = [f"synthetic-worker-token-{index:04d}-not-a-secret" for index in range(20)]
    token_index = 0
    token_lock = threading.Lock()

    def next_token() -> str:
        nonlocal token_index
        with token_lock:
            value = token_values[token_index]
            token_index += 1
            return value

    def coordinator(*, clock=None, locks=None, preflight=None) -> LifecycleCoordinator:
        instance = LifecycleCoordinator(
            layout,
            database,
            publisher,
            launcher=launcher,
            workspace=workspace,
            verifier=verifier,
            monotonic=clock or time.monotonic,
            token_factory=next_token,
            process_stopped=lambda task: launcher.handles[task.task_id].stopped,
            task_locks=locks,
            preflight=preflight,
        )
        instance.recover_before_serving()
        launcher.broker = instance.broker
        return instance

    return SimpleNamespace(
        layout=layout,
        database=database,
        publisher=publisher,
        launcher=launcher,
        workspace=workspace,
        coordinator=coordinator,
        tokens=token_values,
        source_hash=hashlib.sha256(selected_source.read_bytes()).hexdigest(),
    )


@pytest.mark.parametrize("deadline", [True, 0, 31])
def test_private_probe_rejects_deadlines_outside_the_product_bound(harness, deadline):
    coordinator = harness.coordinator()
    try:
        with pytest.raises(ValueError):
            coordinator.start_private_probe(
                "http://127.0.0.1:8765/api/broker/operations", deadline_seconds=deadline
            )
        assert harness.database.task_summaries() == ()
        assert harness.launcher.handles == {}
    finally:
        coordinator.shutdown()


def test_failed_preflight_prevents_task_and_worker_creation(harness):
    def denied():
        raise LifecycleError("private readiness failure")
    coordinator = harness.coordinator(preflight=denied)
    try:
        with pytest.raises(LifecycleError):
            coordinator.start_private_probe("http://127.0.0.1:8765/api/broker/operations")
        assert harness.database.task_summaries() == ()
        assert harness.launcher.handles == {}
    finally:
        coordinator.shutdown()


def test_publication_racing_with_denial_preserves_authorized_effect_order(harness, tmp_path):
    entered = threading.Event()
    release = threading.Event()
    paused = False

    def fault(label: str) -> None:
        nonlocal paused
        if label == "before_final_commit" and not paused:
            paused = True
            entered.set()
            assert release.wait(5)

    harness.publisher._fault = fault
    locks = ObservedTaskLocks()
    harness.launcher.behavior = "publish_wait"
    lifecycle = harness.coordinator(locks=locks)
    task_id = lifecycle.start_private_probe("http://127.0.0.1:8765/api/broker/operations")
    token = harness.tokens[0]
    assert entered.wait(5), "publisher did not reach its durable pre-finalization barrier"

    denial_result: list[int] = []
    denial_started = threading.Event()

    def deny() -> None:
        locks.denial_thread_id = threading.get_ident()
        denial_started.set()
        denial_result.append(
            harness.launcher.broker.execute(token, _read_body("doc-private")).status_code
        )

    denial_thread = threading.Thread(target=deny, daemon=True)
    denial_thread.start()
    assert denial_started.wait(2)
    assert locks.denial_contending.wait(5), "denial did not queue behind the publication lock"
    release.set()
    denial_thread.join(timeout=8)
    assert not denial_thread.is_alive()
    assert denial_result == [403]

    task = harness.database.get_task(task_id)
    assert task is not None
    assert task.status == TaskStatus.FAILED
    assert task.revocation_cause == RevocationCause.POLICY_DENIED
    assert task.terminal_cause == TerminalCause.POLICY_DENIED
    assert harness.launcher.handles[task_id].stopped
    assert harness.database.credential_hash(task_id).revoked_at is not None
    events = harness.database.events(task_id)
    output_seq = next(event.seq for event in events if event.kind == "output_published")
    denial_seq = next(event.seq for event in events if event.kind == "operation_denied")
    assert output_seq < denial_seq
    assert len(harness.database.outputs_for_task(task_id)) == 1
    assert harness.database.outputs_for_task(task_id)[0].state.value == "published"
    source_hash = hashlib.sha256(harness.layout.selected_input.read_bytes()).hexdigest()
    assert source_hash == harness.source_hash

    revoked_retry = harness.launcher.broker.execute(token, _publish_body("# must not publish\n"))
    assert revoked_retry.status_code == 401
    assert len(harness.database.outputs_for_task(task_id)) == 1

    incident = harness.database.get_task(task_id)
    assert incident is not None and incident.incident_id is not None
    with harness.database._connection() as connection:
        row = connection.execute(
            "SELECT containment_status, integrity_status, confidentiality_status "
            "FROM incidents WHERE incident_id=?",
            (str(incident.incident_id),),
        ).fetchone()
    assert tuple(row) == ("terminated", "pass", "unknown")

    harness.launcher.behavior = "complete"
    next_task = lifecycle.start_private_probe("http://127.0.0.1:8765/api/broker/operations")
    completed = lifecycle.wait(next_task)
    assert completed.status == TaskStatus.COMPLETED
    assert harness.launcher.handles[next_task].stopped
    assert next_task not in lifecycle._active
    lifecycle.shutdown()


def test_cancel_racing_with_process_exit_keeps_first_durable_outcome(harness):
    harness.launcher.behavior = "manual"
    lifecycle = harness.coordinator()
    task_id = lifecycle.start_private_probe("http://127.0.0.1:8765/api/broker/operations")
    handle = harness.launcher.handles[task_id]
    gate = threading.Barrier(3)
    cancel_errors: list[BaseException] = []

    def cancel() -> None:
        gate.wait()
        try:
            lifecycle.cancel(task_id)
        except BaseException as exc:
            cancel_errors.append(exc)

    def exit_worker() -> None:
        gate.wait()
        handle.signal_exit(0)

    cancel_thread = threading.Thread(target=cancel, daemon=True)
    exit_thread = threading.Thread(target=exit_worker, daemon=True)
    cancel_thread.start()
    exit_thread.start()
    gate.wait()
    cancel_thread.join(timeout=8)
    exit_thread.join(timeout=8)
    assert not cancel_errors
    task = lifecycle.wait(task_id)
    assert task.status in {TaskStatus.CANCELLED, TaskStatus.FAILED}
    assert handle.stopped and handle.handles_closed
    transitions = harness.database.transitions(task_id)
    revocations = [item for item in transitions if item.to_status == TaskStatus.REVOKING]
    if revocations:
        assert task.status == TaskStatus.CANCELLED
        assert revocations[0].cause == RevocationCause.CANCELLED.value
        assert task.terminal_cause == TerminalCause.CANCELLED
    else:
        assert task.status == TaskStatus.FAILED
        assert task.terminal_cause == TerminalCause.VERIFICATION_FAILED
    lifecycle.shutdown()


def test_timeout_wins_completion_at_deadline_boundary(harness):
    clock = FakeClock(100.0)
    harness.launcher.behavior = "manual"
    lifecycle = harness.coordinator(clock=clock)
    task_id = lifecycle.start_private_probe(
        "http://127.0.0.1:8765/api/broker/operations", deadline_seconds=1
    )
    handle = harness.launcher.handles[task_id]
    clock.set(101.0)
    handle.signal_exit(0)
    task = lifecycle.wait(task_id)
    assert task.status == TaskStatus.FAILED
    assert task.revocation_cause == RevocationCause.WORKER_TIMEOUT
    assert task.terminal_cause == TerminalCause.WORKER_TIMEOUT
    assert handle.stopped and handle.handles_closed
    lifecycle.shutdown()


def test_worker_exit_before_deadline_is_admitted_before_cancellation(harness):
    clock = FakeClock(200.0)
    harness.launcher.behavior = "manual"
    lifecycle = harness.coordinator(clock=clock)
    task_id = lifecycle.start_private_probe(
        "http://127.0.0.1:8765/api/broker/operations", deadline_seconds=2
    )
    handle = harness.launcher.handles[task_id]
    clock.set(201.9)
    handle.signal_exit(0)
    task = lifecycle.cancel(task_id)
    assert task.status == TaskStatus.FAILED
    assert task.revocation_cause is None
    assert task.terminal_cause == TerminalCause.VERIFICATION_FAILED
    assert handle.stopped and handle.handles_closed
    lifecycle.shutdown()


def test_controller_failure_revokes_credential_and_restart_reconciles(harness):
    token = harness.tokens[0]
    now = utc_now()
    task = harness.database.create_task(
        CreateTaskRequest(
            schema_version=1,
            tool_id="report_formatter",
            selected_document_id="doc-report",
            launch_source_claim="document_tools",
        ),
        now=now,
        require_single_worker=True,
    )
    harness.database.transition_task(task.task_id, TaskStatus.PREPARING, now=now)
    contract = harness.database.get_contract(task.task_id)
    assert contract is not None
    started_at = now
    harness.database.activate_worker(
        task.task_id,
        hashlib.sha256(token.encode("ascii")).hexdigest(),
        worker_pid=55_001,
        worker_sid=harness.layout.worker_sid,
        worker_creation_time_100ns=55_001_000,
        now=started_at,
        credential_expires_at=contract.expires_at,
    )
    task_id = task.task_id
    handle = FakeWorkerHandle(55_001)
    harness.launcher.handles[task_id] = handle
    handle.terminate("controller_shutdown")  # Simulate the old Job Object closing on owner death.
    assert handle.stopped

    restarted = harness.coordinator()
    task = harness.database.get_task(task_id)
    assert task is not None
    assert task.status == TaskStatus.FAILED
    assert task.terminal_cause == TerminalCause.RECOVERY_INTERRUPTED
    assert [item.to_status for item in harness.database.transitions(task_id)][-2:] == [
        TaskStatus.VERIFYING,
        TaskStatus.FAILED,
    ]
    assert any(
        event.kind == "task_restart_verification_started"
        and event.reason_code is None
        for event in harness.database.events(task_id)
    )
    assert harness.database.credential_hash(task_id).revoked_at is not None
    assert any(
        event.kind == "task_restart_reconciled"
        for event in harness.database.events(task_id)
    )
    assert restarted.broker.execute(token, _read_body()).status_code == 401
    restarted.shutdown()


def test_restart_preserves_a_committed_revocation_cause(harness):
    token = harness.tokens[1]
    now = utc_now()
    task = harness.database.create_task(
        CreateTaskRequest(
            schema_version=1,
            tool_id="report_formatter",
            selected_document_id="doc-report",
            launch_source_claim="document_tools",
        ),
        now=now,
        require_single_worker=True,
    )
    harness.database.transition_task(task.task_id, TaskStatus.PREPARING, now=now)
    contract = harness.database.get_contract(task.task_id)
    assert contract is not None
    harness.database.activate_worker(
        task.task_id,
        hashlib.sha256(token.encode("ascii")).hexdigest(),
        worker_pid=55_002,
        worker_sid=harness.layout.worker_sid,
        worker_creation_time_100ns=55_002_000,
        now=now,
        credential_expires_at=contract.expires_at,
    )
    handle = FakeWorkerHandle(55_002)
    harness.launcher.handles[task.task_id] = handle
    harness.database.revoke_task(
        task.task_id,
        RevocationCause.CANCELLED,
        now=now,
        event_kind="task_cancellation_requested",
        event_message="Synthetic cancellation committed before controller failure.",
    )
    handle.terminate("cancelled")

    restarted = harness.coordinator()
    recovered = harness.database.get_task(task.task_id)
    assert recovered is not None
    assert recovered.status == TaskStatus.FAILED
    assert recovered.revocation_cause == RevocationCause.CANCELLED
    assert recovered.terminal_cause == TerminalCause.CANCELLED
    assert [item.to_status for item in harness.database.transitions(task.task_id)][-2:] == [
        TaskStatus.VERIFYING,
        TaskStatus.FAILED,
    ]
    assert any(
        event.kind == "task_restart_verification_started"
        and event.reason_code is None
        for event in harness.database.events(task.task_id)
    )
    assert restarted.broker.execute(token, _read_body()).status_code == 401
    restarted.shutdown()


def test_database_revocation_failure_kills_in_memory_job_without_persisted_cause(
    harness, monkeypatch
):
    harness.launcher.behavior = "manual"
    lifecycle = harness.coordinator()
    task_id = lifecycle.start_private_probe("http://127.0.0.1:8765/api/broker/operations")
    handle = harness.launcher.handles[task_id]

    def unavailable(*_args, **_kwargs):
        raise DatabaseError("synthetic database outage")

    monkeypatch.setattr(harness.database, "revoke_task", unavailable)
    task = lifecycle.cancel(task_id)
    assert task.status == TaskStatus.RUNNING
    assert task.revocation_cause is None and task.terminal_cause is None
    assert handle.stopped and handle.handles_closed
    assert not lifecycle.accepting_tasks
    lifecycle.shutdown()


def test_monitor_start_failure_revokes_and_contains_resumed_worker(harness, monkeypatch):
    harness.launcher.behavior = "manual"

    class FailedMonitorThread:
        def __init__(self, **_kwargs) -> None:
            return

        def start(self) -> None:
            raise RuntimeError("synthetic monitor creation failure")

    monkeypatch.setattr(lifecycle_module.threading, "Thread", FailedMonitorThread)
    lifecycle = harness.coordinator()
    with pytest.raises(RuntimeError, match="synthetic monitor creation failure"):
        lifecycle.start_private_probe("http://127.0.0.1:8765/api/broker/operations")

    task_id = next(iter(harness.launcher.handles))
    task = harness.database.get_task(task_id)
    assert task is not None
    assert task.status == TaskStatus.FAILED
    assert task.revocation_cause == RevocationCause.CONTROLLER_SHUTDOWN
    assert task.terminal_cause == TerminalCause.CONTROLLER_SHUTDOWN
    handle = harness.launcher.handles[task_id]
    assert handle.stopped and handle.handles_closed
    assert task_id not in lifecycle._active
    assert not lifecycle.accepting_tasks


def test_preparation_failure_is_terminal_and_releases_single_worker_slot(harness, monkeypatch):
    original_prepare = harness.workspace.prepare

    def fail_preparation(*_args, **_kwargs):
        raise LifecycleError("synthetic preparation failure")

    monkeypatch.setattr(harness.workspace, "prepare", fail_preparation)
    lifecycle = harness.coordinator()
    with pytest.raises(LifecycleError, match="synthetic preparation failure"):
        lifecycle.start_private_probe("http://127.0.0.1:8765/api/broker/operations")
    with harness.database._connection() as connection:
        failed_id = UUID(
            connection.execute("SELECT task_id FROM tasks ORDER BY rowid DESC LIMIT 1").fetchone()[
                "task_id"
            ]
        )
    failed = harness.database.get_task(failed_id)
    assert failed is not None
    assert failed.status == TaskStatus.FAILED
    assert failed.terminal_cause == TerminalCause.PREPARATION_FAILED
    assert harness.database.credential_hash(failed_id) is None
    assert harness.launcher.handles == {}

    monkeypatch.setattr(harness.workspace, "prepare", original_prepare)
    harness.launcher.behavior = "complete"
    next_task = lifecycle.start_private_probe("http://127.0.0.1:8765/api/broker/operations")
    assert lifecycle.wait(next_task).status == TaskStatus.COMPLETED
    lifecycle.shutdown()
