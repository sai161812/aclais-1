"""Independent SQLite journal and crash-consistent receipt publication."""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import stat
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from receiver.models import (
    MAX_RECEIPT_BYTES,
    MAX_RUN_BYTES,
    CreateRunRequest,
    CreateRunResponse,
    IngestRequest,
    ReceiptResponse,
    ReceiptsResponse,
    ReceiptSummary,
    canonical_body_sha256,
)
from receiver.security import StorageProtectionError, prepare_store_root

_MIGRATIONS = Path(__file__).with_name("migrations")
_FINAL_STATES = ("committed", "inconsistent")
_CAPACITY_STATES = ("reserved", "staged", "file_committed", "committed", "inconsistent")


class ReceiverStoreError(RuntimeError):
    """Base class for bounded receiver storage outcomes."""


class AuthenticationInvalid(ReceiverStoreError):
    pass


class RunConflict(ReceiverStoreError):
    pass


class RequestConflict(ReceiverStoreError):
    pass


class RunUnknown(ReceiverStoreError):
    pass


class StorageFull(ReceiverStoreError):
    pass


class RequestInProgress(ReceiverStoreError):
    pass


class StorageUnavailable(ReceiverStoreError):
    pass


class StorageIntegrityUnknown(StorageUnavailable):
    pass


class InjectedCrash(RuntimeError):
    """Private failure hook used only by receiver recovery tests."""


FaultHook = Callable[[str], None]


def _timestamp(value: datetime | None = None) -> str:
    now = value or datetime.now(UTC)
    return now.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii", errors="strict")).digest()


def _regular_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISREG(metadata.st_mode) and not (
        getattr(metadata, "st_file_attributes", 0) & reparse
    )


def _flush_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _move_no_replace(source: Path, destination: Path) -> None:
    if os.name == "nt":
        import ctypes

        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
        move.restype = ctypes.c_int
        # MOVEFILE_WRITE_THROUGH only: never request replace or cross-volume copy.
        if not move(str(source), str(destination), 0x00000008):
            code = ctypes.get_last_error()
            if code == 183:
                raise FileExistsError(code, "receipt destination already exists")
            raise OSError(code, "receipt no-replace rename failed")
    else:
        os.link(source, destination, follow_symlinks=False)
        source.unlink()
        _flush_directory(destination.parent)


class ReceiverStore:
    """Owner-protected receiver persistence, separate from the ACLAIS database."""

    def __init__(self, data_root: Path, *, fault_hook: FaultHook | None = None) -> None:
        self.data_root = Path(os.path.abspath(data_root))
        self.database_path = self.data_root / "receiver.sqlite3"
        self.payload_root = self.data_root / "payloads"
        self.staging_root = self.data_root / "staging"
        self.quarantine_root = self.data_root / "quarantine"
        self._fault_hook = fault_hook
        self._initialized = False

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if not self._initialized:
            raise StorageUnavailable("receiver store is not initialized")
        connection = sqlite3.connect(self.database_path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
        finally:
            connection.close()

    @staticmethod
    @contextmanager
    def _transaction(connection: sqlite3.Connection) -> Iterator[None]:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()

    def initialize(self) -> None:
        try:
            prepare_store_root(self.data_root)
            if self.database_path.exists() and not _regular_file(self.database_path):
                raise StorageUnavailable("receiver database is not a regular file")
            db = sqlite3.connect(self.database_path, timeout=10, isolation_level=None)
            try:
                db.execute("PRAGMA journal_mode = WAL")
                db.execute("PRAGMA synchronous = FULL")
                self._apply_migrations(db)
                check = db.execute("PRAGMA quick_check").fetchone()
                if check is None or check[0] != "ok":
                    raise StorageUnavailable("receiver database integrity is unknown")
            finally:
                db.close()
            self._initialized = True
            self.reconcile()
        except (OSError, sqlite3.Error, StorageProtectionError, StorageUnavailable):
            self._initialized = False
            raise

    def _apply_migrations(self, db: sqlite3.Connection) -> None:
        migrations = sorted(_MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.sql"))
        if not migrations:
            raise StorageUnavailable("receiver migration files are unavailable")
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            applied = {
                int(row[0]): str(row[1])
                for row in db.execute("SELECT version, sha256 FROM schema_migrations")
            }
            known_versions: set[int] = set()
            for migration in migrations:
                version = int(migration.name[:4])
                known_versions.add(version)
                content = migration.read_bytes().replace(b"\r\n", b"\n")
                digest = _sha256(content)
                if version in applied:
                    if not hmac.compare_digest(applied[version], digest):
                        raise StorageUnavailable("receiver migration checksum changed")
                    continue
                if version != max(applied, default=0) + 1:
                    raise StorageUnavailable("receiver migration sequence is inconsistent")
                for statement in content.decode("utf-8", errors="strict").split(";"):
                    if statement.strip():
                        db.execute(statement)
                db.execute(
                    "INSERT INTO schema_migrations(version, sha256, applied_at) VALUES(?, ?, ?)",
                    (version, digest, _timestamp()),
                )
                applied[version] = digest
            if set(applied) != known_versions:
                raise StorageUnavailable("receiver database has an unknown migration")
            db.commit()
        except BaseException:
            db.rollback()
            raise

    def _fault(self, step: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(step)

    def _assert_service_integrity(self, connection: sqlite3.Connection) -> None:
        row = connection.execute("SELECT 1 FROM system_incidents LIMIT 1").fetchone()
        if row is not None:
            raise StorageIntegrityUnknown("receiver storage has an unresolved integrity incident")

    def create_run(self, request: CreateRunRequest, *, ingest_token: str) -> CreateRunResponse:
        token_hash = _digest_token(ingest_token)
        try:
            with self._connection() as connection, self._transaction(connection):
                self._assert_service_integrity(connection)
                connection.execute(
                    "INSERT INTO runs(run_id, ingest_token_sha256, canary_marker, created_at) "
                    "VALUES(?, ?, ?, ?)",
                    (
                        str(request.run_id),
                        token_hash.hex(),
                        request.canary_marker.encode("ascii", errors="strict"),
                        _timestamp(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RunConflict("receiver run already exists") from exc
        return CreateRunResponse(schema_version=1, run_id=request.run_id, ingest_token=ingest_token)

    def ingest(self, token: str, request: IngestRequest) -> ReceiptResponse:
        payload = request.decoded_payload
        if len(payload) > MAX_RECEIPT_BYTES:
            raise ValueError("decoded receipt payload exceeds the per-receipt limit")
        body_digest = canonical_body_sha256(request)
        payload_digest = _sha256(payload)
        request_id = str(request.request_id)
        run_id = str(request.run_id)
        receipt_id = str(uuid.uuid4())
        stage_name = f"{receipt_id}.stage"
        payload_name = f"{receipt_id}.bin"
        received_at = _timestamp()
        marker: bytes

        replay_receipt: ReceiptResponse | None = None
        # Authenticate inside the same immediate transaction and before replay lookup.
        with self._connection() as connection, self._transaction(connection):
            self._assert_service_integrity(connection)
            run = connection.execute(
                "SELECT ingest_token_sha256, canary_marker, integrity_state "
                "FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None or not hmac.compare_digest(
                str(run["ingest_token_sha256"]), _digest_token(token).hex()
            ):
                raise AuthenticationInvalid("receiver ingest credential is invalid")
            if run["integrity_state"] != "healthy":
                raise StorageIntegrityUnknown("receiver run integrity is unknown")
            marker = bytes(run["canary_marker"])
            existing = connection.execute(
                "SELECT * FROM receipts WHERE run_id = ? AND request_id = ?",
                (run_id, request_id),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(str(existing["canonical_body_sha256"]), body_digest):
                    raise RequestConflict("request ID was reused with different content")
                if existing["state"] == "committed":
                    replay_receipt = self._committed_response(existing)
                elif existing["state"] == "inconsistent":
                    raise StorageIntegrityUnknown("receiver receipt integrity is unknown")
                elif existing["state"] != "aborted":
                    raise RequestInProgress("an identical request is being reconciled")
            if replay_receipt is not None:
                receipt_id = str(replay_receipt.receipt_id)
            else:
                stored = connection.execute(
                    "SELECT COALESCE(SUM(decoded_bytes), 0) AS total FROM receipts "
                    "WHERE run_id = ? AND state IN (?, ?, ?, ?, ?)",
                    (run_id, *_CAPACITY_STATES),
                ).fetchone()
                if int(stored["total"]) + len(payload) > MAX_RUN_BYTES:
                    raise StorageFull("receiver run storage is full")
                marker_match = marker in payload
                if existing is None:
                    connection.execute(
                        "INSERT INTO receipts(run_id, request_id, task_id, canonical_body_sha256, "
                        "receipt_id, staging_name, payload_name, payload_sha256, decoded_bytes, "
                        "marker_match, state, received_at) "
                        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            run_id,
                            request_id,
                            str(request.task_id),
                            body_digest,
                            receipt_id,
                            stage_name,
                            payload_name,
                            payload_digest,
                            len(payload),
                            int(marker_match),
                            "reserved",
                            received_at,
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE receipts SET receipt_id=?, staging_name=?, payload_name=?, "
                        "payload_sha256=?, decoded_bytes=?, marker_match=?, state='reserved', "
                        "received_at=? WHERE run_id=? AND request_id=? AND state='aborted'",
                        (
                            receipt_id,
                            stage_name,
                            payload_name,
                            payload_digest,
                            len(payload),
                            int(marker_match),
                            received_at,
                            run_id,
                            request_id,
                        ),
                    )

        if replay_receipt is not None:
            return self._read_committed_response(
                run_id, request_id, str(replay_receipt.receipt_id), expected=replay_receipt
            )

        self._fault("after_reservation")
        stage = self.staging_root / stage_name
        final = self.payload_root / payload_name
        try:
            self._write_stage(stage, payload)
            self._fault("after_stage_flush")
            with self._connection() as connection, self._transaction(connection):
                connection.execute(
                    "UPDATE receipts SET state='staged' WHERE run_id=? AND request_id=? "
                    "AND receipt_id=? AND state='reserved'",
                    (run_id, request_id, receipt_id),
                )
            self._fault("after_staged")
            _move_no_replace(stage, final)
            self._fault("after_rename")
            with self._connection() as connection, self._transaction(connection):
                connection.execute(
                    "UPDATE receipts SET state='file_committed' WHERE run_id=? AND request_id=? "
                    "AND receipt_id=? AND state='staged'",
                    (run_id, request_id, receipt_id),
                )
            self._fault("after_file_committed")
            with self._connection() as connection, self._transaction(connection):
                connection.execute(
                    "UPDATE receipts SET state='committed' WHERE run_id=? AND request_id=? "
                    "AND receipt_id=? AND state='file_committed'",
                    (run_id, request_id, receipt_id),
                )
                self._fault("before_commit")
        except BaseException:
            raise

        receipt = ReceiptResponse(
            schema_version=1,
            receipt_id=uuid.UUID(receipt_id),
            received_at=_parse_timestamp(received_at),
            decoded_bytes=len(payload),
            sha256=payload_digest,
        )
        # Reopen and validate the durable row/file before the API may return success.
        return self._read_committed_response(run_id, request_id, receipt_id, expected=receipt)

    def _write_stage(self, stage: Path, payload: bytes) -> None:
        if not stage.parent.is_dir() or _is_reparse(stage.parent):
            raise StorageUnavailable("receiver staging directory is unavailable")
        try:
            with stage.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            raise StorageIntegrityUnknown("receiver staging destination already exists") from exc

    def _committed_response(self, row: sqlite3.Row) -> ReceiptResponse:
        return ReceiptResponse(
            schema_version=1,
            receipt_id=uuid.UUID(str(row["receipt_id"])),
            received_at=_parse_timestamp(str(row["received_at"])),
            decoded_bytes=int(row["decoded_bytes"]),
            sha256=str(row["payload_sha256"]),
        )

    def _read_committed_response(
        self,
        run_id: str,
        request_id: str,
        receipt_id: str,
        *,
        expected: ReceiptResponse | None = None,
    ) -> ReceiptResponse:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM receipts WHERE run_id=? AND request_id=? AND receipt_id=?",
                (run_id, request_id, receipt_id),
            ).fetchone()
            if row is None or row["state"] != "committed":
                raise StorageUnavailable("receiver did not durably finalize the receipt")
            try:
                payload = self._read_valid_payload(row)
            except (OSError, StorageIntegrityUnknown):
                self._mark_run_unknown(run_id, receipt_id)
                raise StorageIntegrityUnknown("receiver receipt integrity is unknown") from None
            if (
                len(payload) != int(row["decoded_bytes"])
                or _sha256(payload) != row["payload_sha256"]
            ):
                self._mark_run_unknown(run_id, receipt_id)
                raise StorageIntegrityUnknown("receiver receipt integrity is unknown")
            response = self._committed_response(row)
            if expected is not None and response != expected:
                self._mark_run_unknown(run_id, receipt_id)
                raise StorageIntegrityUnknown("receiver receipt identity is inconsistent")
            return response

    def _read_valid_payload(self, row: sqlite3.Row) -> bytes:
        name = str(row["payload_name"])
        receipt_id = str(row["receipt_id"])
        if (
            Path(name).name != name
            or name != f"{receipt_id}.bin"
            or not _canonical_uuid(receipt_id)
        ):
            raise StorageIntegrityUnknown("receiver payload name is invalid")
        path = self.payload_root / name
        if not _regular_file(path):
            raise StorageIntegrityUnknown("receiver payload file is unavailable")
        if path.stat().st_size > MAX_RECEIPT_BYTES:
            raise StorageIntegrityUnknown("receiver payload file exceeds its bound")
        return path.read_bytes()

    def _mark_run_unknown(self, run_id: str, receipt_id: str) -> None:
        with self._connection() as connection, self._transaction(connection):
            connection.execute(
                "UPDATE receipts SET state='inconsistent' WHERE run_id=? AND receipt_id=?",
                (run_id, receipt_id),
            )
            connection.execute(
                "UPDATE runs SET integrity_state='unknown' WHERE run_id=?", (run_id,)
            )

    def get_receipts(self, run_id: uuid.UUID) -> ReceiptsResponse:
        text_run_id = str(run_id)
        with self._connection() as connection:
            self._assert_service_integrity(connection)
            run = connection.execute(
                "SELECT integrity_state, canary_marker FROM runs WHERE run_id=?",
                (text_run_id,),
            ).fetchone()
            if run is None:
                raise RunUnknown("receiver run is unknown")
            if run["integrity_state"] != "healthy":
                raise StorageIntegrityUnknown("receiver run integrity is unknown")
            rows = connection.execute(
                "SELECT * FROM receipts WHERE run_id=? AND state IN (?, ?) "
                "ORDER BY received_at, receipt_id",
                (text_run_id, *_FINAL_STATES),
            ).fetchall()
            summaries: list[ReceiptSummary] = []
            marker = bytes(run["canary_marker"])
            for row in rows:
                if row["state"] != "committed":
                    self._mark_run_unknown(text_run_id, str(row["receipt_id"]))
                    raise StorageIntegrityUnknown("receiver run integrity is unknown")
                try:
                    payload = self._read_valid_payload(row)
                    valid = (
                        len(payload) == int(row["decoded_bytes"])
                        and _sha256(payload) == str(row["payload_sha256"])
                        and (marker in payload) == bool(row["marker_match"])
                    )
                except (OSError, StorageIntegrityUnknown):
                    valid = False
                if not valid:
                    self._mark_run_unknown(text_run_id, str(row["receipt_id"]))
                    raise StorageIntegrityUnknown("receiver run integrity is unknown")
                summaries.append(
                    ReceiptSummary(
                        receipt_id=uuid.UUID(str(row["receipt_id"])),
                        task_id=uuid.UUID(str(row["task_id"])),
                        received_at=_parse_timestamp(str(row["received_at"])),
                        decoded_bytes=int(row["decoded_bytes"]),
                        sha256=str(row["payload_sha256"]),
                        marker_match=bool(row["marker_match"]),
                    )
                )
        return ReceiptsResponse(
            schema_version=1,
            run_id=run_id,
            receipts=tuple(summaries),
            marker_received=any(item.marker_match for item in summaries),
        )

    def inspect_summary(self, run_id: uuid.UUID) -> dict[str, object]:
        response = self.get_receipts(run_id)
        total = sum(item.decoded_bytes for item in response.receipts)
        times = tuple(
            item.received_at.isoformat().replace("+00:00", "Z") for item in response.receipts
        )
        return {
            "run_id": str(run_id),
            "receipt_count": len(response.receipts),
            "decoded_bytes": total,
            "marker_received": response.marker_received,
            "received_at": times,
        }

    def health_status(self) -> str:
        with self._connection() as connection:
            self._assert_service_integrity(connection)
            result = connection.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise StorageUnavailable("receiver database integrity is unknown")
        return "ready"

    def reconcile(self) -> None:
        """Recover receipt intent rows before serving any request."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM receipts ORDER BY received_at, receipt_id"
            ).fetchall()
            known_stages = {str(row["staging_name"]) for row in rows}
            known_payloads = {str(row["payload_name"]) for row in rows}
        for row in rows:
            state = str(row["state"])
            try:
                stage, final = self._receipt_paths(row)
            except StorageIntegrityUnknown:
                self._set_inconsistent(row)
                continue
            if state == "inconsistent":
                self._set_inconsistent(row)
                continue
            if _path_exists(final):
                if self._final_matches(row, final):
                    self._set_committed(row)
                    _safe_unlink(stage)
                else:
                    self._set_inconsistent(row)
                continue
            if state == "committed" or state == "file_committed" or state == "inconsistent":
                self._set_inconsistent(row)
                continue
            if _path_exists(stage):
                if self._final_matches(row, stage):
                    try:
                        _move_no_replace(stage, final)
                        self._set_committed(row)
                    except (FileExistsError, OSError):
                        self._set_inconsistent(row)
                else:
                    _safe_unlink(stage)
                    self._set_aborted(row)
                continue
            if state in {"reserved", "staged", "aborted"}:
                self._set_aborted(row)
            else:
                self._set_inconsistent(row)

        orphaned = self._quarantine_orphans(known_stages, known_payloads)
        if orphaned:
            self._record_system_incidents(orphaned)

        with self._connection() as connection:
            for row in connection.execute(
                "SELECT run_id FROM receipts WHERE state='inconsistent' GROUP BY run_id"
            ):
                connection.execute(
                    "UPDATE runs SET integrity_state='unknown' WHERE run_id=?", (row[0],)
                )

    def _final_matches(self, row: sqlite3.Row, path: Path) -> bool:
        if not _regular_file(path):
            return False
        try:
            size = path.stat().st_size
            if size != int(row["decoded_bytes"]) or size > MAX_RECEIPT_BYTES:
                return False
            content = path.read_bytes()
        except OSError:
            return False
        if _sha256(content) != str(row["payload_sha256"]):
            return False
        with self._connection() as connection:
            marker_row = connection.execute(
                "SELECT canary_marker FROM runs WHERE run_id=?", (str(row["run_id"]),)
            ).fetchone()
        return marker_row is not None and (bytes(marker_row[0]) in content) == bool(
            row["marker_match"]
        )

    def _receipt_paths(self, row: sqlite3.Row) -> tuple[Path, Path]:
        receipt_id = str(row["receipt_id"])
        if (
            not _canonical_uuid(receipt_id)
            or str(row["staging_name"]) != f"{receipt_id}.stage"
            or str(row["payload_name"]) != f"{receipt_id}.bin"
        ):
            raise StorageIntegrityUnknown("receiver journal path identity is invalid")
        return self.staging_root / f"{receipt_id}.stage", self.payload_root / f"{receipt_id}.bin"

    def _set_committed(self, row: sqlite3.Row) -> None:
        with self._connection() as connection, self._transaction(connection):
            connection.execute(
                "UPDATE receipts SET state='committed' WHERE run_id=? AND request_id=?",
                (str(row["run_id"]), str(row["request_id"])),
            )

    def _set_aborted(self, row: sqlite3.Row) -> None:
        with self._connection() as connection, self._transaction(connection):
            connection.execute(
                "UPDATE receipts SET state='aborted' WHERE run_id=? AND request_id=? "
                "AND state IN ('reserved', 'staged', 'aborted')",
                (str(row["run_id"]), str(row["request_id"])),
            )

    def _set_inconsistent(self, row: sqlite3.Row) -> None:
        with self._connection() as connection, self._transaction(connection):
            connection.execute(
                "UPDATE receipts SET state='inconsistent' WHERE run_id=? AND request_id=?",
                (str(row["run_id"]), str(row["request_id"])),
            )
            connection.execute(
                "UPDATE runs SET integrity_state='unknown' WHERE run_id=?",
                (str(row["run_id"]),),
            )

    def _quarantine_orphans(
        self, known_stages: set[str], known_payloads: set[str]
    ) -> list[tuple[str, str]]:
        unknown: list[tuple[str, str]] = []
        for directory, known, suffix, code in (
            (self.staging_root, known_stages, ".stage", "UNKNOWN_STAGING_FILE"),
            (self.payload_root, known_payloads, ".bin", "UNKNOWN_PAYLOAD_FILE"),
        ):
            for item in directory.iterdir():
                if _is_reparse(item):
                    raise StorageUnavailable("receiver data directory contains a reparse point")
                if not item.is_file() or item.name in known:
                    if item.is_dir():
                        destination = self.quarantine_root / f"{uuid.uuid4()}.quarantined"
                        try:
                            os.rename(item, destination)
                        except OSError as exc:
                            raise StorageUnavailable(
                                "unknown receiver directory could not be quarantined"
                            ) from exc
                        unknown.append(("UNKNOWN_PAYLOAD_FILE", destination.name))
                    continue
                if item.suffix != suffix:
                    unknown.append((code, item.name))
                destination = self.quarantine_root / f"{uuid.uuid4()}.quarantined"
                try:
                    _move_no_replace(item, destination)
                except OSError as exc:
                    raise StorageUnavailable(
                        "unknown receiver file could not be quarantined"
                    ) from exc
                unknown.append((code, destination.name))
        return unknown

    def _record_system_incidents(self, incidents: list[tuple[str, str]]) -> None:
        with self._connection() as connection, self._transaction(connection):
            for code, name in incidents:
                connection.execute(
                    "INSERT INTO system_incidents(incident_id, code, artifact_name, created_at) "
                    "VALUES(?, ?, ?, ?)",
                    (str(uuid.uuid4()), code, name, _timestamp()),
                )


def _is_reparse(path: Path) -> bool:
    metadata = path.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse
    )


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _canonical_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _safe_unlink(path: Path) -> None:
    if _path_exists(path):
        if _is_reparse(path) or not path.is_file():
            raise StorageUnavailable("receiver staged path is unsafe")
        path.unlink()
