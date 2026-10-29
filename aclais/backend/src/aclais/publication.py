"""Crash-consistent controller-owned output publication on one protected volume."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from uuid import UUID, uuid4

from aclais.persistence.database import (
    Database,
    canonical_body_sha256,
    utc_now,
)
from aclais.persistence.models import (
    ApiError,
    BrokerOutputAllowed,
    BrokerPublishOutputRequest,
    ErrorResponse,
    JournalState,
    OutputJournalRecord,
    OutputMetadata,
)

MAX_OUTPUT_BYTES = 1_048_576
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MOVEFILE_WRITE_THROUGH = 0x00000008


class PublicationError(RuntimeError):
    """An output could not be safely published or verified."""


class OutputCollision(PublicationError):
    """A controller-derived final name already belongs to another file."""


class OutputUnavailable(PublicationError):
    """An output is unfinalized or its published file no longer matches the journal."""


class SimulatedPublicationCrash(BaseException):
    """Private test-only abrupt-stop marker; production never installs fault hooks."""


def _is_reparse(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _require_plain_tree(path: Path) -> None:
    if not path.is_absolute():
        raise PublicationError("managed output paths must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if _is_reparse(current):
            raise PublicationError("reparse points are forbidden in managed output paths")
        if current != path and not stat.S_ISDIR(metadata.st_mode):
            raise PublicationError("managed output parent is not a directory")


def _exists(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            size += len(chunk)
            if size > MAX_OUTPUT_BYTES:
                raise PublicationError("managed output exceeds its recorded size limit")
            digest.update(chunk)
    return digest.hexdigest(), size


def _flush_to_disk(stream: BinaryIO) -> None:
    stream.flush()
    os.fsync(stream.fileno())
    if sys.platform == "win32":
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        flush_file_buffers = kernel32.FlushFileBuffers
        flush_file_buffers.argtypes = (ctypes.c_void_p,)
        flush_file_buffers.restype = ctypes.c_int
        if not flush_file_buffers(ctypes.c_void_p(handle)):
            raise OSError(ctypes.get_last_error(), "FlushFileBuffers failed")


def _move_without_replace(source: Path, destination: Path) -> None:
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file_ex = kernel32.MoveFileExW
        move_file_ex.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
        move_file_ex.restype = ctypes.c_int
        if not move_file_ex(str(source), str(destination), _MOVEFILE_WRITE_THROUGH):
            error = ctypes.get_last_error()
            if error in (80, 183):
                raise OutputCollision("controller-derived output name already exists")
            raise OSError(error, "MoveFileExW failed")
        return
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise OutputCollision("controller-derived output name already exists") from exc
    source.unlink()


class OutputPublisher:
    """Publishes validated output text using IDs and paths created by the controller."""

    def __init__(
        self,
        database: Database,
        output_root: Path,
        *,
        fault: Callable[[str], None] | None = None,
    ) -> None:
        if not output_root.is_absolute() or not output_root.is_dir():
            raise ValueError(
                "the protected verified-output root must already exist and be absolute"
            )
        _require_plain_tree(output_root)
        self.database = database
        self.output_root = output_root
        self._fault = fault

    def _boundary(self, label: str) -> None:
        if self._fault is not None:
            self._fault(label)

    def paths(self, record: OutputJournalRecord) -> tuple[Path, Path]:
        suffix = ".md" if record.output_kind == "formatted_markdown" else ".json"
        task_part = str(record.task_id)
        output_part = str(record.output_id)
        expected_staging = f"{task_part}/{output_part}.staging"
        expected_final = f"{task_part}/{output_part}{suffix}"
        if (
            record.staging_relative_path != expected_staging
            or record.final_relative_path != expected_final
        ):
            raise PublicationError("database output paths do not match controller-derived IDs")
        task_dir = self.output_root / task_part
        staging = task_dir / f"{output_part}.staging"
        final = task_dir / f"{output_part}{suffix}"
        _require_plain_tree(self.output_root)
        _require_plain_tree(task_dir)
        return staging, final

    def publish(
        self,
        record: OutputJournalRecord,
        request: BrokerPublishOutputRequest,
        *,
        token_sha256: str | None = None,
        now: datetime | None = None,
    ) -> BrokerOutputAllowed:
        publication_time = now or utc_now()
        content = request.output_text.encode("utf-8", errors="strict")
        if len(content) > MAX_OUTPUT_BYTES:
            raise ValueError("output exceeds the 1 MiB publication limit")
        digest = hashlib.sha256(content).hexdigest()
        if record.content_sha256 != digest or record.decoded_bytes != len(content):
            raise PublicationError("output journal content does not match the validated request")
        if request.output_kind != record.output_kind:
            raise PublicationError("output journal kind does not match the validated request")

        try:
            staging, final = self.paths(record)
        except (OSError, PublicationError):
            self._mark_inconsistent(record)
            raise
        staging.parent.mkdir(exist_ok=True)
        _require_plain_tree(staging.parent)
        current = self.database.output_journal(record.output_id)
        if current is None:
            raise PublicationError("output journal disappeared before filesystem work")
        record = current

        # A crash before the staged commit may leave a partial exclusive temp file.
        # It is controller-owned and ID-derived, so remove only that partial and retry.
        if record.state == JournalState.RESERVED:
            if _exists(final):
                self._mark_inconsistent(record)
                raise OutputCollision("unexpected final file exists for a reserved output")
            if _exists(staging):
                try:
                    _require_plain_tree(staging)
                    if _hash_file(staging) == (digest, len(content)):
                        with staging.open("r+b") as stream:
                            _flush_to_disk(stream)
                        if _hash_file(staging) != (digest, len(content)):
                            raise PublicationError("recovered staging content changed during flush")
                        record = self.database.transition_output(
                            record.output_id, JournalState.STAGED, now=publication_time
                        )
                    else:
                        staging.unlink()
                except (OSError, PublicationError) as exc:
                    self._mark_inconsistent(record)
                    raise PublicationError("could not safely recover the staging file") from exc
            if record.state == JournalState.RESERVED:
                try:
                    with staging.open("xb") as stream:
                        self._boundary("stage_created")
                        stream.write(content)
                        self._boundary("stage_written")
                        _flush_to_disk(stream)
                        self._boundary("stage_flushed")
                except FileExistsError:
                    raise PublicationError("staging file changed during publication") from None
                record = self.database.transition_output(
                    record.output_id, JournalState.STAGED, now=publication_time
                )
                self._boundary("staged_recorded")

        if record.state not in {JournalState.STAGED, JournalState.FILE_COMMITTED}:
            raise PublicationError("output journal is not recoverable for publication")

        if _exists(final):
            try:
                _require_plain_tree(final)
            except (OSError, PublicationError):
                self._mark_inconsistent(record)
                raise OutputCollision("final output path is not a plain managed file") from None
            try:
                final_matches = _hash_file(final) == (digest, len(content))
            except (OSError, PublicationError):
                final_matches = False
            if _exists(staging) or not final_matches:
                self._mark_inconsistent(record)
                raise OutputCollision("existing final file is not the sole verified output")
        else:
            if not staging.is_file():
                self._mark_inconsistent(record)
                raise OutputUnavailable("verified staging content is missing")
            try:
                _require_plain_tree(staging)
            except (OSError, PublicationError):
                self._mark_inconsistent(record)
                raise OutputUnavailable("staging path is not a plain managed file") from None
            if _hash_file(staging) != (digest, len(content)):
                self._mark_inconsistent(record)
                raise OutputUnavailable("staging content does not match its durable intent")
            self._boundary("before_move")
            try:
                _move_without_replace(staging, final)
            except OutputCollision:
                self._mark_inconsistent(record)
                raise
            self._boundary("after_move")

        _require_plain_tree(final)
        if _hash_file(final) != (digest, len(content)):
            self._mark_inconsistent(record)
            raise OutputUnavailable("final content does not match its durable intent")
        self._boundary("final_verified")

        response = BrokerOutputAllowed(
            schema_version=1,
            decision="allow",
            output_id=record.output_id,
            sha256=digest,
        )
        self._boundary("before_final_commit")
        self.database.finalize_output_publication(
            record.output_id,
            canonical_body_sha256(request),
            response,
            now=publication_time,
            token_sha256=token_sha256,
        )
        self._boundary("after_final_commit")
        return response

    def _mark_inconsistent(self, record: OutputJournalRecord) -> None:
        if record.state != JournalState.INCONSISTENT:
            self.database.transition_output(
                record.output_id, JournalState.INCONSISTENT, now=utc_now()
            )

    def reconcile_task(self, task_id: UUID | str) -> tuple[str, ...]:
        """Finish only hash-verified durable publications; abort incomplete staging."""

        recovered: list[str] = []
        for record in self.database.outputs_for_task(task_id):
            if record.state == JournalState.PUBLISHED:
                self.read_published(record.output_id)
                continue
            if record.state == JournalState.INCONSISTENT:
                raise OutputUnavailable("an inconsistent publication requires operator review")
            if record.state in {
                JournalState.PUBLISHED,
                JournalState.ABORTED,
                JournalState.INCONSISTENT,
            }:
                continue
            staging, final = self.paths(record)
            has_staging, has_final = _exists(staging), _exists(final)
            if has_staging and has_final:
                self._mark_inconsistent(record)
                raise OutputUnavailable("recovery found both staging and final output files")

            if has_final:
                _require_plain_tree(final)
                if _hash_file(final) != (record.content_sha256, record.decoded_bytes):
                    self._mark_inconsistent(record)
                    raise OutputUnavailable("recovery found mismatched final output content")
            elif has_staging:
                _require_plain_tree(staging)
                if _hash_file(staging) != (record.content_sha256, record.decoded_bytes):
                    self._remove_partial_staging(staging, record)
                    self._abort_recovered_request(record)
                    recovered.append("aborted")
                    continue
                with staging.open("r+b") as stream:
                    _flush_to_disk(stream)
                if record.state == JournalState.RESERVED:
                    record = self.database.transition_output(
                        record.output_id, JournalState.STAGED, now=utc_now()
                    )
                _move_without_replace(staging, final)
                _require_plain_tree(final)
                if _hash_file(final) != (record.content_sha256, record.decoded_bytes):
                    self._mark_inconsistent(record)
                    raise OutputUnavailable("recovered output changed during finalization")
            else:
                if record.state == JournalState.RESERVED:
                    self._abort_recovered_request(record)
                    recovered.append("aborted")
                    continue
                self._mark_inconsistent(record)
                raise OutputUnavailable(
                    "durably staged output is missing from both managed locations"
                )

            if record.state == JournalState.RESERVED:
                record = self.database.transition_output(
                    record.output_id, JournalState.STAGED, now=utc_now()
                )
            body_hash = self.database.request_body_sha256(record.task_id, record.request_id)
            if body_hash is None:
                self._mark_inconsistent(record)
                raise OutputUnavailable("recovered output has no request journal")
            response = BrokerOutputAllowed(
                schema_version=1,
                decision="allow",
                output_id=record.output_id,
                sha256=record.content_sha256,
            )
            self.database.finalize_output_publication(
                record.output_id, body_hash, response, now=utc_now()
            )
            recovered.append("published")
        return tuple(recovered)

    def reconcile_all(self, *, scan_unknown: bool = False) -> None:
        known: set[Path] = set()
        for task_id in self.database.publication_task_ids():
            self.reconcile_task(task_id)
            for record in self.database.outputs_for_task(task_id):
                known.update(self.paths(record))
        if not scan_unknown:
            return
        unknown: list[Path] = []
        for task_directory in self.output_root.iterdir():
            if task_directory.name == ".quarantine":
                _require_plain_tree(task_directory)
                continue
            _require_plain_tree(task_directory)
            if not task_directory.is_dir():
                unknown.append(task_directory)
                continue
            for file in task_directory.rglob("*"):
                _require_plain_tree(file)
                if file.is_file() and file not in known:
                    unknown.append(file)
        if unknown:
            quarantine = self.output_root / ".quarantine" / str(uuid4())
            quarantine.mkdir(parents=True)
            records = []
            for file in unknown:
                destination = quarantine / str(uuid4())
                _move_without_replace(file, destination)
                records.append({"source": file.relative_to(self.output_root).as_posix(),
                                "quarantined_as": destination.name})
            (quarantine / "findings.json").write_text(json.dumps(records), encoding="utf-8")
            raise OutputUnavailable("unknown output files were quarantined; review before restart")

    def _remove_partial_staging(self, staging: Path, record: OutputJournalRecord) -> None:
        try:
            _require_plain_tree(staging)
            expected, _ = self.paths(record)
            if staging != expected or not staging.is_file():
                raise PublicationError("recovery staging path is not controller-derived")
            staging.unlink()
        except (OSError, PublicationError):
            self._mark_inconsistent(record)
            raise OutputUnavailable(
                "recovery could not remove incomplete staging content"
            ) from None

    def _abort_recovered_request(self, record: OutputJournalRecord) -> None:
        if record.state != JournalState.ABORTED:
            self.database.transition_output(record.output_id, JournalState.ABORTED, now=utc_now())
        body_hash = self.database.request_body_sha256(record.task_id, record.request_id)
        if body_hash is None:
            return
        error = ErrorResponse(
            schema_version=1,
            error=ApiError(
                code="PUBLICATION_INCONSISTENT",
                message="Output publication did not complete before controller recovery.",
                request_id=str(record.request_id),
            ),
        )
        self.database.complete_request(
            record.task_id,
            record.request_id,
            body_hash,
            error,
            now=utc_now(),
            event_kind="publication_recovery_aborted",
            event_operation="publish_output",
            event_decision="deny",
            event_reason_code="PUBLICATION_INCONSISTENT",
            event_message="Incomplete output staging was withheld during restart recovery.",
        )

    def read_published(self, output_id: UUID | str) -> tuple[OutputMetadata, bytes]:
        metadata = self.database.published_output(output_id)
        record = self.database.output_journal(output_id)
        if metadata is None or record is None or record.state != JournalState.PUBLISHED:
            raise OutputUnavailable("output is not published")
        try:
            _, final = self.paths(record)
            _require_plain_tree(final)
            with final.open("rb") as stream:
                content = stream.read(MAX_OUTPUT_BYTES + 1)
        except (OSError, PublicationError) as exc:
            self._mark_inconsistent(record)
            raise OutputUnavailable("published output file is unavailable") from exc
        if (
            len(content) != metadata.decoded_bytes
            or hashlib.sha256(content).hexdigest() != metadata.sha256
            or len(content) > MAX_OUTPUT_BYTES
        ):
            self._mark_inconsistent(record)
            raise OutputUnavailable("published output does not match its finalized metadata")
        return metadata, content
