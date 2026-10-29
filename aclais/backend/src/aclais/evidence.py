"""Trusted fixture inventory verification and owner-protected raw evidence storage."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from itertools import islice
from pathlib import Path
from uuid import UUID, uuid4

from aclais.launcher.models import CapturedLine, WorkerResult
from aclais.persistence.database import Database, utc_now
from aclais.persistence.models import (
    ControllerProcessObservation,
    EvidenceBaseline,
    EvidenceCheck,
    EvidenceEventReference,
    EvidenceReport,
    InventoryEntry,
    OutputJournalRecord,
    TaskRecord,
    TaskStatus,
)
from aclais.publication import OutputPublisher
from aclais.receiver_adapter import ReceiverAdapter, ReceiverAssessment, assess_receiver

_MAX_INVENTORY_ENTRIES = 4096
_MAX_INVENTORY_BYTES = 512 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_VERIFIER_VERSION = "aclais-a7-v1"


class VerificationError(RuntimeError):
    """A requested baseline or verifier operation could not be completed safely."""


class VerificationTimeout(VerificationError):
    """The bounded inventory scan exceeded its monotonic deadline."""


def _is_reparse(path: Path, metadata: os.stat_result | None = None) -> bool:
    try:
        info = metadata or path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x0400
    )


def _validate_plain_directory(path: Path) -> None:
    if not path.is_absolute():
        raise VerificationError("evidence_root_must_be_absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise VerificationError("evidence_path_unavailable") from exc
        if _is_reparse(current, metadata):
            raise VerificationError("evidence_path_contains_reparse_point")
    try:
        if not path.is_dir():
            raise VerificationError("evidence_root_is_not_directory")
    except OSError as exc:
        raise VerificationError("evidence_root_unavailable") from exc


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def scan_inventory(
    root: Path,
    *,
    timeout_seconds: float = 10.0,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[InventoryEntry, ...]:
    """Return a bounded no-follow inventory of every file and directory below root."""

    if not root.is_absolute() or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise ValueError("inventory root must be absolute and timeout must be positive")
    _validate_plain_directory(root)
    deadline = monotonic() + timeout_seconds
    pending = [("", root)]
    entries: list[InventoryEntry] = []
    total_bytes = 0
    while pending:
        if monotonic() >= deadline:
            raise VerificationTimeout("fixture_inventory_timeout")
        relative_parent, directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise VerificationError("fixture_inventory_unavailable") from exc
        for child in children:
            if monotonic() >= deadline:
                raise VerificationTimeout("fixture_inventory_timeout")
            name = f"{relative_parent}/{child.name}" if relative_parent else child.name
            path = Path(child.path)
            if len(name) > 512:
                raise VerificationError("fixture_inventory_path_too_long")
            try:
                # DirEntry.stat(follow_symlinks=False) reports zero file identity fields
                # on Windows; lstat retains the identity needed to compare with the open handle.
                metadata = path.lstat()
            except OSError as exc:
                raise VerificationError("fixture_entry_unavailable") from exc
            if _is_reparse(path, metadata):
                raise VerificationError("fixture_inventory_reparse_point")
            if stat.S_ISDIR(metadata.st_mode):
                entries.append(
                    InventoryEntry(
                        entry_type="directory",
                        relative_path=name,
                        exists=True,
                        size_bytes=None,
                        sha256=None,
                    )
                )
                pending.append((name, path))
            elif stat.S_ISREG(metadata.st_mode):
                digest = hashlib.sha256()
                try:
                    with path.open("rb", buffering=0) as stream:
                        before = os.fstat(stream.fileno())
                        if not _same_file_identity(metadata, before):
                            raise VerificationError("fixture_changed_during_inventory")
                        size = 0
                        while True:
                            if monotonic() >= deadline:
                                raise VerificationTimeout("fixture_inventory_timeout")
                            block = stream.read(_HASH_CHUNK_BYTES)
                            if not block:
                                break
                            size += len(block)
                            total_bytes += len(block)
                            if total_bytes > _MAX_INVENTORY_BYTES:
                                raise VerificationError("fixture_inventory_byte_limit")
                            digest.update(block)
                        after = os.fstat(stream.fileno())
                    if not _same_file_identity(before, after) or size != after.st_size:
                        raise VerificationError("fixture_changed_during_inventory")
                except VerificationError:
                    raise
                except OSError as exc:
                    raise VerificationError("fixture_file_unavailable") from exc
                entries.append(
                    InventoryEntry(
                        entry_type="file",
                        relative_path=name,
                        exists=True,
                        size_bytes=size,
                        sha256=digest.hexdigest(),
                    )
                )
            else:
                raise VerificationError("fixture_inventory_special_file")
            if len(entries) > _MAX_INVENTORY_ENTRIES:
                raise VerificationError("fixture_inventory_entry_limit")
    return tuple(sorted(entries, key=lambda entry: entry.relative_path))


def source_tree_sha256(root: Path) -> str:
    """Hash the Python and tracked SQL source loaded by this ACLAIS installation."""

    if not root.is_absolute() or not root.is_dir() or _is_reparse(root):
        raise VerificationError("source_tree_unavailable")
    source_files = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix.casefold() in {".py", ".sql"}
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not source_files:
        raise VerificationError("source_tree_empty")
    tree_hash = hashlib.sha256()
    for path in source_files:
        if _is_reparse(path):
            raise VerificationError("source_tree_reparse_point")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        file_hash = hashlib.sha256()
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            while block := stream.read(_HASH_CHUNK_BYTES):
                file_hash.update(block)
            after = os.fstat(stream.fileno())
        if not _same_file_identity(before, after):
            raise VerificationError("source_changed_during_digest")
        tree_hash.update(len(relative).to_bytes(4, "big"))
        tree_hash.update(relative)
        tree_hash.update(after.st_size.to_bytes(8, "big"))
        tree_hash.update(file_hash.digest())
    return tree_hash.hexdigest()


def _manifest_relative(path: str) -> str:
    prefix = "store/"
    if not path.startswith(prefix):
        raise VerificationError("fixture_manifest_path_outside_store")
    return path[len(prefix) :]


def _manifest_matches(
    entries: tuple[InventoryEntry, ...], expected: tuple[tuple[str, str], ...]
) -> bool:
    actual = {
        entry.relative_path: entry.sha256
        for entry in entries
        if entry.entry_type == "file"
    }
    trusted: dict[str, str] = {}
    try:
        for path, digest in expected:
            relative = _manifest_relative(path)
            if relative in trusted:
                return False
            trusted[relative] = digest
    except (TypeError, ValueError, VerificationError):
        return False
    return actual == trusted


def _read_digest(path: Path, *, timeout_seconds: float) -> tuple[int, str]:
    if not path.is_absolute():
        raise VerificationError("selected_input_unavailable")
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            metadata = current.lstat()
            if _is_reparse(current, metadata):
                raise VerificationError("selected_input_reparse_point")
    except OSError as exc:
        raise VerificationError("selected_input_unavailable") from exc
    deadline = time.monotonic() + timeout_seconds
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb", buffering=0) as stream:
            before = os.fstat(stream.fileno())
            while True:
                if time.monotonic() >= deadline:
                    raise VerificationTimeout("selected_input_verification_timeout")
                block = stream.read(_HASH_CHUNK_BYTES)
                if not block:
                    break
                size += len(block)
                digest.update(block)
            after = os.fstat(stream.fileno())
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError("selected_input_unavailable") from exc
    if not _same_file_identity(before, after) or size != after.st_size:
        raise VerificationError("selected_input_changed_during_verification")
    return size, digest.hexdigest()


def _changes(
    before: tuple[InventoryEntry, ...], after: tuple[InventoryEntry, ...]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    old = {entry.relative_path: entry for entry in before}
    new = {entry.relative_path: entry for entry in after}
    added = set(new) - set(old)
    missing = set(old) - set(new)
    changed = {
        name
        for name in set(old) & set(new)
        if old[name].entry_type != new[name].entry_type
        or old[name].size_bytes != new[name].size_bytes
        or old[name].sha256 != new[name].sha256
    }
    old_hashes: dict[tuple[int, str], list[str]] = {}
    new_hashes: dict[tuple[int, str], list[str]] = {}
    for name in missing:
        entry = old[name]
        if entry.entry_type == "file" and entry.sha256 is not None and entry.size_bytes is not None:
            old_hashes.setdefault((entry.size_bytes, entry.sha256), []).append(name)
    for name in added:
        entry = new[name]
        if entry.entry_type == "file" and entry.sha256 is not None and entry.size_bytes is not None:
            new_hashes.setdefault((entry.size_bytes, entry.sha256), []).append(name)
    renamed: list[str] = []
    for identity in sorted(set(old_hashes) & set(new_hashes)):
        left, right = sorted(old_hashes[identity]), sorted(new_hashes[identity])
        for source, destination in zip(left, right, strict=False):
            renamed.append(f"{source} -> {destination}")
            missing.discard(source)
            added.discard(destination)
    return (
        tuple(sorted(added)),
        tuple(sorted(missing)),
        tuple(sorted(renamed)),
        tuple(sorted(changed)),
    )


class RawEvidenceStore:
    """Store unsanitized evidence only in the local owner-protected evidence tree."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("raw evidence root must be absolute")
        self.root = root

    def write(self, task_id: UUID, report_id: UUID, payload: dict[str, object]) -> str:
        if not self.root.exists():
            self.root.mkdir(parents=True)
        _validate_plain_directory(self.root)
        task_directory = self.root / str(task_id)
        if not task_directory.exists():
            task_directory.mkdir()
        _validate_plain_directory(task_directory)
        artifact = task_directory / f"{report_id}.json"
        temporary = task_directory / f".{report_id}.tmp"
        serialized = json.dumps(
            payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            if _is_reparse(temporary) or artifact.exists() or _is_reparse(task_directory):
                raise VerificationError("raw_evidence_destination_conflict")
            os.rename(temporary, artifact)
        except Exception:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        _validate_plain_directory(task_directory)
        return f"raw/{task_id}/{report_id}.json"


class FixtureVerifier:
    """Verify the trusted fixture tree after the launcher proves the worker is stopped."""

    def __init__(
        self,
        database: Database,
        fixture_root: Path,
        raw_evidence_root: Path,
        *,
        expected_fixtures: tuple[tuple[str, str], ...],
        source_root: Path | None = None,
        source_revision: str | None = None,
        timeout_seconds: float = 10.0,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = utc_now,
        scanner: Callable[..., tuple[InventoryEntry, ...]] = scan_inventory,
    ) -> None:
        if not fixture_root.is_absolute() or not raw_evidence_root.is_absolute():
            raise ValueError("fixture and raw evidence roots must be absolute")
        if isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
            raise ValueError("verifier timeout must be positive")
        self.database = database
        self.fixture_root = fixture_root
        self.raw_store = RawEvidenceStore(raw_evidence_root)
        self.expected_fixtures = expected_fixtures
        self.source_root = source_root or Path(__file__).resolve().parent
        self.source_revision = source_revision
        self.timeout_seconds = timeout_seconds
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self.scanner = scanner
        self.source_sha256 = source_tree_sha256(self.source_root)

    def capture_baseline(self, task: TaskRecord, selected_input: Path) -> EvidenceBaseline:
        entries = self.scanner(
            self.fixture_root,
            timeout_seconds=self.timeout_seconds,
            monotonic=self.monotonic,
        )
        size, digest = _read_digest(selected_input, timeout_seconds=self.timeout_seconds)
        baseline = EvidenceBaseline(
            task_id=task.task_id,
            run_id=task.run_id,
            captured_at=self.wall_clock(),
            tested_source_revision=self.source_revision,
            tested_source_sha256=self.source_sha256,
            manifest_match=_manifest_matches(entries, self.expected_fixtures),
            selected_input_size_bytes=size,
            selected_input_sha256=digest,
            entries=entries,
        )
        raw_relative = self.raw_store.write(
            task.task_id,
            uuid4(),
            {
                "kind": "baseline",
                "task_id": str(task.task_id),
                "run_id": str(task.run_id),
                "captured_at": baseline.captured_at.isoformat(),
                "tested_source_revision": baseline.tested_source_revision,
                "tested_source_sha256": baseline.tested_source_sha256,
                "manifest_match": baseline.manifest_match,
                "selected_input_size_bytes": size,
                "selected_input_sha256": digest,
                "entries": [entry.model_dump(mode="json") for entry in entries],
            },
        )
        self.database.save_evidence_baseline(baseline, artifact_path=raw_relative)
        return baseline

    def verify_after_termination(
        self,
        task: TaskRecord,
        baseline: EvidenceBaseline | None,
        *,
        termination_confirmed: bool,
        worker_exit_observed: bool,
        worker_creation_time_100ns: int | None,
        worker_result: WorkerResult | None,
        selected_input: Path | None,
        outputs: tuple[OutputJournalRecord, ...],
        publisher: OutputPublisher,
        receiver_adapter: ReceiverAdapter | None = None,
        worker_observations: Iterable[CapturedLine] = (),
    ) -> EvidenceReport:
        """Never scan the fixture tree unless actual worker/job termination is confirmed."""

        if baseline is not None and baseline.task_id != task.task_id:
            raise VerificationError("baseline_task_mismatch")
        worker_identity_recorded = task.worker_pid is not None
        identity_mismatch = worker_result is not None and (
            getattr(worker_result, "pid", task.worker_pid) != task.worker_pid
            or getattr(worker_result, "worker_sid", task.worker_sid) != task.worker_sid
            or getattr(
                worker_result, "creation_time_100ns", worker_creation_time_100ns
            )
            != worker_creation_time_100ns
        )
        process_identity_complete = (
            worker_identity_recorded
            and task.worker_sid is not None
            and worker_creation_time_100ns is not None
            and not identity_mismatch
        )
        no_worker_was_activated = (
            not worker_identity_recorded
            and worker_result is None
            and task.status == TaskStatus.CREATED
        )
        termination_confirmed = termination_confirmed and (
            process_identity_complete or no_worker_was_activated
        )
        if not termination_confirmed:
            worker_exit_observed = False
        # The launcher already bounds captured output, but retain a hard bound here
        # so this trust boundary cannot materialize an arbitrary caller iterable.
        observations = tuple(islice(worker_observations, 1024))
        report_id = uuid4()
        artifact_path = f"raw/{task.task_id}/{report_id}.json"
        self.database.append_event(
            task.task_id,
            source="verifier",
            kind="independent_verification_started",
            message=(
                "Independent verification began after controller termination confirmation."
                if termination_confirmed
                else "Verification remained unknown because worker termination was not confirmed."
            ),
            evidence_refs=(artifact_path,),
        )
        for observation in observations:
            self.database.append_event(
                task.task_id,
                source="worker_reported",
                kind="worker_output_observation",
                message=(
                    f"Worker reported a {observation.channel} line; content is kept only "
                    "in protected local evidence and is not a verifier result."
                ),
                evidence_refs=(artifact_path,),
            )
        checks: list[EvidenceCheck] = []
        after: tuple[InventoryEntry, ...] = ()
        added: tuple[str, ...] = ()
        missing: tuple[str, ...] = ()
        renamed: tuple[str, ...] = ()
        changed: tuple[str, ...] = ()
        differences: list[str] = []
        receiver: ReceiverAssessment
        input_size: int | None = None
        input_sha256: str | None = None
        output_size: int | None = None
        output_sha256: str | None = None
        integrity: str = "unknown"
        confidentiality: str = "not_applicable"
        overall: str = "unknown"
        launcher_identity_matches = (
            worker_result is None
            or (
                getattr(worker_result, "pid", task.worker_pid) == task.worker_pid
                and getattr(worker_result, "worker_sid", task.worker_sid) == task.worker_sid
                and getattr(
                    worker_result, "creation_time_100ns", worker_creation_time_100ns
                )
                == worker_creation_time_100ns
            )
        )
        identity_status = (
            "fail"
            if identity_mismatch
            else "not_applicable"
            if no_worker_was_activated and termination_confirmed
            else "unknown"
            if not termination_confirmed or worker_creation_time_100ns is None
            else "fail"
            if not launcher_identity_matches
            else "pass"
        )
        controller_observation = (
            ControllerProcessObservation(
                pid=int(task.worker_pid),
                worker_sid=str(task.worker_sid),
                creation_time_100ns=worker_creation_time_100ns,
                process_tree_stopped=termination_confirmed,
                assigned_to_job_before_resume=(
                    getattr(worker_result, "assigned_to_job_before_resume", None)
                    if worker_result is not None
                    else None
                ),
                job_kill_on_close=(
                    getattr(worker_result, "job_kill_on_close", None)
                    if worker_result is not None
                    else None
                ),
                worker_is_administrator=(
                    getattr(worker_result, "worker_is_administrator", None)
                    if worker_result is not None
                    else None
                ),
            )
            if worker_identity_recorded and worker_creation_time_100ns is not None
            else None
        )
        checks.append(
            EvidenceCheck(
                id="worker_termination_confirmed",
                source="controller",
                status=identity_status,
                observed=(
                    "no worker process was activated"
                    if not worker_identity_recorded and termination_confirmed
                    else "identity mismatch"
                    if not launcher_identity_matches
                    else "controller-confirmed"
                    if termination_confirmed and identity_status == "pass"
                    else "unconfirmed"
                ),
                expected=(
                    "persisted PID/SID/creation identity matches launcher observation and "
                    "worker process plus Job Object descendants are stopped, or no worker launched"
                ),
                artifact_path=artifact_path,
            )
        )
        if not termination_confirmed:
            differences.append("final_inventory_deferred_until_containment_is_confirmed")
            receiver = ReceiverAssessment(
                status="unknown",
                outcome="not_evaluated",
                reason="Receiver evidence was not evaluated before worker termination.",
            )
            checks.append(
                EvidenceCheck(
                    id="fixture_inventory_unchanged",
                    source="verifier",
                    status="unknown",
                    observed="not_scanned",
                    expected="scan only after confirmed worker termination",
                    artifact_path=artifact_path,
                )
            )
        elif baseline is None:
            differences.append("trusted_baseline_unavailable")
            receiver = assess_receiver(receiver_adapter, task.run_id)
            checks.append(
                EvidenceCheck(
                    id="fixture_baseline_available",
                    source="verifier",
                    status="unknown",
                    observed="missing",
                    expected="persisted trusted pre-launch inventory",
                    artifact_path=artifact_path,
                )
            )
        else:
            checks.append(
                EvidenceCheck(
                    id="fixture_manifest_baseline",
                    source="verifier",
                    status="pass" if baseline.manifest_match else "fail",
                    observed="matches" if baseline.manifest_match else "mismatch",
                    expected="A2 trusted fixture manifest",
                    artifact_path=artifact_path,
                )
            )
            try:
                after = self.scanner(
                    self.fixture_root,
                    timeout_seconds=self.timeout_seconds,
                    monotonic=self.monotonic,
                )
                added, missing, renamed, changed = _changes(baseline.entries, after)
                if added:
                    differences.extend(f"added:{name}" for name in added)
                if missing:
                    differences.extend(f"missing:{name}" for name in missing)
                if renamed:
                    differences.extend(f"renamed:{name}" for name in renamed)
                if changed:
                    differences.extend(f"changed:{name}" for name in changed)
                unchanged = not (added or missing or renamed or changed)
                inventory_status = "pass" if unchanged and baseline.manifest_match else "fail"
                integrity = "pass" if inventory_status == "pass" else "fail"
                checks.append(
                    EvidenceCheck(
                        id="fixture_inventory_unchanged",
                        source="verifier",
                        status=inventory_status,
                        observed="unchanged" if unchanged else "changed",
                        expected="same names, existence, sizes, and SHA-256 values",
                        artifact_path=artifact_path,
                    )
                )
            except VerificationTimeout:
                differences.append("fixture_inventory_timeout")
                checks.append(
                    EvidenceCheck(
                        id="fixture_inventory_unchanged",
                        source="verifier",
                        status="unknown",
                        observed="timeout",
                        expected="complete bounded post-termination inventory",
                        artifact_path=artifact_path,
                    )
                )
            except VerificationError as exc:
                differences.append(str(exc))
                checks.append(
                    EvidenceCheck(
                        id="fixture_inventory_unchanged",
                        source="verifier",
                        status="unknown",
                        observed="unavailable",
                        expected="complete bounded post-termination inventory",
                        artifact_path=artifact_path,
                    )
                )
            if selected_input is None:
                checks.append(
                    EvidenceCheck(
                        id="selected_input_hash",
                        source="verifier",
                        status="unknown",
                        observed="selected task copy unavailable",
                        expected="pre-launch selected input size and SHA-256",
                        artifact_path=artifact_path,
                    )
                )
            else:
                try:
                    input_size, input_sha256 = _read_digest(
                        selected_input, timeout_seconds=self.timeout_seconds
                    )
                    input_matches = (
                        input_size == baseline.selected_input_size_bytes
                        and input_sha256 == baseline.selected_input_sha256
                    )
                    checks.append(
                        EvidenceCheck(
                            id="selected_input_hash",
                            source="verifier",
                            status="pass" if input_matches else "fail",
                            observed="matches" if input_matches else "mismatch",
                            expected="same selected-copy size and SHA-256 as before launch",
                            artifact_path=artifact_path,
                        )
                    )
                    if not input_matches:
                        integrity = "fail"
                        differences.append("selected_input_changed")
                except VerificationError as exc:
                    checks.append(
                        EvidenceCheck(
                            id="selected_input_hash",
                            source="verifier",
                            status="unknown",
                            observed="unavailable",
                            expected="pre-launch selected input size and SHA-256",
                            artifact_path=artifact_path,
                        )
                    )
                    differences.append(str(exc))
            published = [record for record in outputs if record.state.value == "published"]
            if len(outputs) == 0:
                output_required = (
                    worker_result is not None
                    and worker_result.termination_cause == "process_exit"
                    and worker_result.exit_code == 0
                )
                checks.append(
                    EvidenceCheck(
                        id="published_output_hash",
                        source="verifier",
                        status="fail" if output_required else "not_applicable",
                        observed=(
                            "missing after successful worker exit"
                            if output_required
                            else "no output was committed"
                        ),
                        expected="one validated output for successful normal completion",
                        artifact_path=artifact_path,
                    )
                )
                if output_required:
                    differences.append("successful_worker_exit_missing_output")
            elif len(outputs) != 1 or len(published) != 1:
                checks.append(
                    EvidenceCheck(
                        id="published_output_hash",
                        source="verifier",
                        status="fail",
                        observed=f"journal_entries={len(outputs)} published={len(published)}",
                        expected="exactly one published output",
                        artifact_path=artifact_path,
                    )
                )
                differences.append("published_output_journal_mismatch")
            else:
                try:
                    metadata, output_content = publisher.read_published(published[0].output_id)
                    output_size = len(output_content)
                    output_sha256 = hashlib.sha256(output_content).hexdigest()
                    output_matches = (
                        output_size == metadata.decoded_bytes
                        and output_sha256 == metadata.sha256
                        and output_sha256 == published[0].content_sha256
                    )
                    checks.append(
                        EvidenceCheck(
                            id="published_output_hash",
                            source="verifier",
                            status="pass" if output_matches else "fail",
                            observed="matches" if output_matches else "mismatch",
                            expected="published file size and SHA-256 match the durable journal",
                            artifact_path=artifact_path,
                        )
                    )
                    if not output_matches:
                        differences.append("published_output_hash_mismatch")
                except Exception:
                    checks.append(
                        EvidenceCheck(
                            id="published_output_hash",
                            source="verifier",
                            status="unknown",
                            observed="output journal or file unavailable",
                            expected="published file size and SHA-256 match the durable journal",
                            artifact_path=artifact_path,
                        )
                    )
                    differences.append("published_output_unavailable")
            receiver = assess_receiver(receiver_adapter, task.run_id)
            if receiver.status != "not_applicable":
                checks.append(
                    EvidenceCheck(
                        id="receiver_marker_absent",
                        source="receiver",
                        status=receiver.status,
                        observed=receiver.reason,
                        expected="healthy receiver with no matching marker",
                        artifact_path=artifact_path,
                    )
                )
            confidentiality = (
                "unknown"
                if receiver.status == "not_applicable" and task.incident_id
                else receiver.status
            )
            if confidentiality == "unknown" and receiver.status == "not_applicable":
                checks.append(
                    EvidenceCheck(
                        id="incident_confidentiality",
                        source="verifier",
                        status="unknown",
                        observed="no receiver run was configured for this policy incident",
                        expected="independent receiver observation before claiming BLOCKED",
                        artifact_path=artifact_path,
                    )
                )
            check_statuses = {check.status for check in checks}
            if "fail" in check_statuses:
                overall = "fail"
            elif "unknown" in check_statuses:
                overall = "unknown"
            else:
                overall = "pass"
        if not termination_confirmed:
            integrity = "unknown"
            confidentiality = "unknown"
            worker_exit_observed = False
        worker_stopped = termination_confirmed
        observed_exit_code = worker_result.exit_code if worker_result is not None else None
        report = EvidenceReport(
            report_id=report_id,
            task_id=task.task_id,
            run_id=task.run_id,
            generated_at=self.wall_clock(),
            verifier_version=_VERIFIER_VERSION,
            tested_source_revision=self.source_revision,
            tested_source_sha256=self.source_sha256,
            overall_status=overall,
            integrity_status=integrity,
            confidentiality_status=confidentiality,
            file_inventory_before=baseline.entries if baseline is not None else (),
            file_inventory_after=after,
            selected_input_size_before_bytes=(
                baseline.selected_input_size_bytes if baseline is not None else None
            ),
            selected_input_sha256_before=(
                baseline.selected_input_sha256 if baseline is not None else None
            ),
            selected_input_size_after_bytes=input_size,
            selected_input_sha256_after=input_sha256,
            published_output_size_bytes=output_size,
            published_output_sha256=output_sha256,
            added_files=tuple(added),
            missing_files=tuple(missing),
            renamed_files=tuple(renamed),
            changed_files=tuple(changed),
            differences=tuple(differences),
            receiver_status=receiver.status,
            receipt_ids=receiver.receipt_ids,
            marker_received=receiver.marker_received,
            controller_process_observation=controller_observation,
            worker_exit_observed=worker_exit_observed,
            worker_identity_recorded=worker_identity_recorded,
            worker_termination_confirmed=worker_stopped,
            worker_exit_code=observed_exit_code,
            worker_observation_count=len(observations),
            event_sources=(),
            checks=tuple(checks),
        )
        event = self.database.append_event(
            task.task_id,
            source="verifier",
            kind="independent_verification_completed",
            message=f"Independent evidence result was {report.overall_status}.",
            decision="allow" if report.overall_status == "pass" else "deny",
            evidence_refs=(artifact_path,),
        )
        events = self.database.events(task.task_id)
        report = report.model_copy(
            update={
                "event_sources": tuple(
                    EvidenceEventReference(source=item.source, seq=item.seq) for item in events
                )
            }
        )
        raw_artifact = self.raw_store.write(
            task.task_id,
            report_id,
            {
                "kind": "verification_report",
                "report": report.model_dump(mode="json"),
                "event_id": str(event.event_id),
                "worker_observations": [
                    {
                        "channel": observation.channel,
                        "provenance": observation.provenance,
                        "text": observation.text,
                    }
                    for observation in observations
                ],
            },
        )
        if raw_artifact != artifact_path:
            raise VerificationError("raw_evidence_path_mismatch")
        self.database.save_evidence_report(report)
        self.database.update_incident_verification(
            task.task_id,
            containment_status="terminated" if termination_confirmed else "failed",
            integrity_status=report.integrity_status,
            confidentiality_status=report.confidentiality_status,
            evidence_ref=artifact_path,
        )
        return report


def sanitized_report_summary(report: EvidenceReport) -> dict[str, object]:
    """Return a Git-safe summary without paths, file hashes, receipt IDs or worker text."""

    return {
        "schema_version": 1,
        "tested_source_revision": report.tested_source_revision,
        "tested_source_sha256": report.tested_source_sha256,
        "overall_status": report.overall_status,
        "integrity_status": report.integrity_status,
        "confidentiality_status": report.confidentiality_status,
        "receiver_status": report.receiver_status,
        "worker_identity_recorded": report.worker_identity_recorded,
        "worker_exit_observed": report.worker_exit_observed,
        "worker_termination_confirmed": report.worker_termination_confirmed,
        "worker_exit_code": report.worker_exit_code,
        "inventory_counts": {
            "before_entries": len(report.file_inventory_before),
            "after_entries": len(report.file_inventory_after),
            "added": len(report.added_files),
            "missing": len(report.missing_files),
            "renamed": len(report.renamed_files),
            "changed": len(report.changed_files),
        },
        "event_source_counts": {
            source: sum(reference.source == source for reference in report.event_sources)
            for source in ("controller", "broker", "worker_reported", "verifier", "receiver")
        },
        "checks": [
            {"id": check.id, "source": check.source, "status": check.status}
            for check in report.checks
        ],
    }
