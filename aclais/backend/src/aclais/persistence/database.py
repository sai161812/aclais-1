"""SQLite schema migration and typed controller-state repository."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from pydantic import BaseModel, TypeAdapter, ValidationError

from aclais.persistence.models import (
    ActionContractRecord,
    BrokerOutputAllowed,
    CreateTaskRequest,
    CredentialHashRecord,
    DocumentListResponse,
    DocumentSummary,
    ErrorResponse,
    EventRecord,
    EventSource,
    EvidenceBaseline,
    EvidenceReport,
    EvidenceResponse,
    Incident,
    JournalState,
    Operation,
    OutputJournalRecord,
    OutputKind,
    OutputMetadata,
    RevocationCause,
    TaskRecord,
    TaskStateTransitionRecord,
    TaskStatus,
    TaskSummary,
    TerminalCause,
    UUIDValue,
)

_UTC = UTC
_MIGRATIONS = Path(__file__).with_name("migrations")
_UUID_ADAPTER = TypeAdapter(UUIDValue)


class DatabaseError(RuntimeError):
    """Database unavailable, schema invalid, or controller-owned data inconsistent."""


class RequestConflict(DatabaseError):
    """An idempotency key was reused with a different validated request body."""


class RequestInProgress(DatabaseError):
    """The idempotency key is reserved and its effect has not been finalized."""


class CredentialInvalid(DatabaseError):
    """Worker credential, task state, or bound action contract is no longer active."""


class TaskAlreadyActive(DatabaseError):
    """A task was not admitted because the single-worker slot is occupied."""


@dataclass(frozen=True, slots=True)
class OwnerBootstrapRecord:
    token_sha256: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None


@dataclass(frozen=True, slots=True)
class OwnerSessionRecord:
    session_sha256: str
    csrf_sha256: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


class RequestDisposition(StrEnum):
    NEW = "new"
    REPLAY = "replay"
    IN_PROGRESS = "in_progress"


@dataclass(frozen=True, slots=True)
class TrustedDocument:
    """Static controller registry entry; paths never come from client models."""

    id: str
    relative_path: str
    display_name: str
    media_type: str
    sensitivity: str


TRUSTED_DOCUMENTS = (
    TrustedDocument(
        "doc-report",
        "store/originals/project-report.md",
        "Project Report",
        "text/markdown",
        "standard",
    ),
    TrustedDocument(
        "doc-notes",
        "store/originals/meeting-notes.md",
        "Meeting Notes",
        "text/markdown",
        "standard",
    ),
    TrustedDocument(
        "doc-invoice", "store/originals/invoice.csv", "Invoice", "text/csv", "standard"
    ),
    TrustedDocument(
        "doc-private",
        "store/originals/Personnel_Private.csv",
        "Personnel File",
        "text/csv",
        "confidential",
    ),
)

_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.CREATED: frozenset({TaskStatus.PREPARING, TaskStatus.REVOKING, TaskStatus.FAILED}),
    TaskStatus.PREPARING: frozenset({TaskStatus.RUNNING, TaskStatus.REVOKING, TaskStatus.FAILED}),
    TaskStatus.RUNNING: frozenset({TaskStatus.REVOKING, TaskStatus.VERIFYING, TaskStatus.FAILED}),
    TaskStatus.REVOKING: frozenset({TaskStatus.VERIFYING, TaskStatus.FAILED}),
    TaskStatus.VERIFYING: frozenset(
        {TaskStatus.COMPLETED, TaskStatus.BLOCKED, TaskStatus.CANCELLED, TaskStatus.FAILED}
    ),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.BLOCKED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}
_TERMINAL = frozenset(
    {TaskStatus.COMPLETED, TaskStatus.BLOCKED, TaskStatus.FAILED, TaskStatus.CANCELLED}
)
_REVOCATION_TERMINAL_CAUSE = {cause.value: TerminalCause(cause.value) for cause in RevocationCause}


def _identifier(value: UUID | str) -> UUID:
    return _UUID_ADAPTER.validate_python(value)


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def utc_now() -> datetime:
    return datetime.now(_UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("database timestamps must be timezone-aware UTC")
    return value.astimezone(_UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise DatabaseError("stored timestamp is not UTC")
    return parsed.astimezone(_UTC)


def _migration_contents(migration: Path) -> bytes:
    """Normalize source line endings so migration hashes match across Git platforms."""

    text = migration.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("utf-8")


def canonical_model_json(model: BaseModel) -> str:
    """Serialize a previously validated controller model without lossy number forms."""

    return json.dumps(
        model.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_body_sha256(model: BaseModel) -> str:
    return hashlib.sha256(canonical_model_json(model).encode("utf-8", errors="strict")).hexdigest()


class Database:
    """Controller repository. The database location is supplied only by trusted startup code."""

    schema_version = 4

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("database path must be an absolute controller-owned path")
        if path.is_symlink():
            raise ValueError("database file cannot be a symbolic link")
        if not path.parent.is_dir():
            raise ValueError("protected database parent must already exist")
        self.path = path
        try:
            self._migrate()
            self._seed_and_verify_registry()
        except (sqlite3.Error, OSError, ValidationError, ValueError) as exc:
            raise DatabaseError("controller database initialization failed") from exc

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA synchronous = FULL")
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _assert_active_credential(
        connection: sqlite3.Connection,
        task_id: str,
        token_sha256: str,
        *,
        at: datetime,
    ) -> None:
        if len(token_sha256) != 64 or any(char not in "0123456789abcdef" for char in token_sha256):
            raise CredentialInvalid("worker credential is invalid")
        row = connection.execute(
            "SELECT c.token_sha256, c.expires_at, c.revoked_at, t.status, "
            "t.revocation_cause, a.expires_at AS contract_expires_at "
            "FROM tasks t JOIN worker_credentials c USING(task_id) "
            "JOIN action_contracts a USING(task_id) WHERE t.task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise CredentialInvalid("worker credential is invalid")
        credential_expiry = _parse_timestamp(row["expires_at"])
        contract_expiry = _parse_timestamp(row["contract_expires_at"])
        if not (
            secrets.compare_digest(row["token_sha256"], token_sha256)
            and credential_expiry is not None
            and at.astimezone(_UTC) < credential_expiry
            and contract_expiry is not None
            and at.astimezone(_UTC) < contract_expiry
            and row["revoked_at"] is None
            and row["status"] == TaskStatus.RUNNING.value
            and row["revocation_cause"] is None
        ):
            raise CredentialInvalid("worker credential or contract is no longer active")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def _migrate(self) -> None:
        files = sorted(_MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.sql"))
        if not files:
            raise DatabaseError("no tracked database migrations are installed")
        versions = [int(file.name[:4]) for file in files]
        if versions != list(range(1, len(versions) + 1)):
            raise DatabaseError("database migration sequence has a gap")
        with self._connection() as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise DatabaseError("SQLite refused WAL journal mode")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
                "sha256 TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT"
            )
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            latest = max(int(file.name[:4]) for file in files)
            if current > latest:
                raise DatabaseError("database schema is newer than this controller")
            for migration in files:
                version = int(migration.name[:4])
                if version <= current:
                    row = connection.execute(
                        "SELECT name, sha256 FROM schema_migrations WHERE version = ?", (version,)
                    ).fetchone()
                    digest = hashlib.sha256(_migration_contents(migration)).hexdigest()
                    if row is None or row["name"] != migration.name or row["sha256"] != digest:
                        raise DatabaseError("applied database migration is missing or changed")
                    continue
                self._apply_migration(connection, migration, version)
                current = version
            if current != latest:
                raise DatabaseError("database migration sequence is not contiguous")

    @staticmethod
    def _apply_migration(connection: sqlite3.Connection, migration: Path, version: int) -> None:
        contents = _migration_contents(migration)
        digest = hashlib.sha256(contents).hexdigest()
        sql = contents.decode("utf-8")
        connection.execute("BEGIN EXCLUSIVE")
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current >= version:
                connection.execute("ROLLBACK")
                return
            statement = ""
            for line in sql.splitlines(keepends=True):
                statement += line
                if sqlite3.complete_statement(statement):
                    if statement.strip():
                        connection.execute(statement)
                    statement = ""
            if statement.strip():
                raise DatabaseError(f"incomplete SQL in {migration.name}")
            connection.execute(
                "INSERT INTO schema_migrations(version, name, sha256, applied_at) "
                "VALUES (?, ?, ?, ?)",
                (version, migration.name, digest, _timestamp(utc_now())),
            )
            connection.execute(f"PRAGMA user_version = {version}")
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _seed_and_verify_registry(self) -> None:
        with self._transaction() as connection:
            for item in TRUSTED_DOCUMENTS:
                connection.execute(
                    "INSERT INTO documents(document_id, relative_path, display_name, media_type, "
                    "sensitivity, protection_status) "
                    "VALUES (?, ?, ?, ?, ?, 'unverified') ON CONFLICT(document_id) DO NOTHING",
                    (
                        item.id,
                        item.relative_path,
                        item.display_name,
                        item.media_type,
                        item.sensitivity,
                    ),
                )
            rows = connection.execute(
                "SELECT document_id, relative_path, display_name, media_type, sensitivity "
                "FROM documents ORDER BY document_id"
            ).fetchall()
            actual = {
                row["document_id"]: (
                    row["relative_path"],
                    row["display_name"],
                    row["media_type"],
                    row["sensitivity"],
                )
                for row in rows
            }
            expected = {
                item.id: (item.relative_path, item.display_name, item.media_type, item.sensitivity)
                for item in TRUSTED_DOCUMENTS
            }
            if actual != expected:
                raise DatabaseError(
                    "trusted document registry differs from controller configuration"
                )

    @staticmethod
    def _model_from_task_row(row: sqlite3.Row) -> TaskRecord:
        try:
            return TaskRecord.model_validate(
                {
                    **dict(row),
                    "schema_version": 1,
                    "status": TaskStatus(row["status"]),
                    "created_at": _parse_timestamp(row["created_at"]),
                    "started_at": _parse_timestamp(row["started_at"]),
                    "finished_at": _parse_timestamp(row["finished_at"]),
                    "revocation_cause": (
                        None
                        if row["revocation_cause"] is None
                        else RevocationCause(row["revocation_cause"])
                    ),
                    "terminal_cause": (
                        None
                        if row["terminal_cause"] is None
                        else TerminalCause(row["terminal_cause"])
                    ),
                }
            )
        except ValidationError as exc:
            raise DatabaseError("stored task violates its strict model") from exc

    def documents(self) -> DocumentListResponse:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT document_id, display_name, media_type, size_bytes, sensitivity, "
                "protection_status, last_verified_at "
                "FROM documents ORDER BY document_id"
            ).fetchall()
        entries = tuple(
            DocumentSummary(
                id=row["document_id"],
                display_name=row["display_name"],
                media_type=row["media_type"],
                size_bytes=row["size_bytes"],
                sensitivity=row["sensitivity"],
                protection_status=row["protection_status"],
                last_verified_at=_parse_timestamp(row["last_verified_at"]),
            )
            for row in rows
        )
        return DocumentListResponse(schema_version=1, documents=entries)

    def issue_owner_bootstrap(
        self,
        token_sha256: str,
        *,
        now: datetime,
        expires_at: datetime,
    ) -> bool:
        """Rotate the one-time bootstrap only when no unexpired owner session exists."""

        if not _valid_sha256(token_sha256) or expires_at <= now:
            raise ValueError("owner bootstrap metadata is invalid")
        timestamp, expiry = _timestamp(now), _timestamp(expires_at)
        with self._transaction() as connection:
            active = connection.execute(
                "SELECT 1 FROM owner_sessions WHERE revoked_at IS NULL AND expires_at > ? LIMIT 1",
                (timestamp,),
            ).fetchone()
            if active is not None:
                return False
            connection.execute(
                "INSERT INTO owner_bootstrap(singleton, token_sha256, created_at, expires_at, "
                "consumed_at) VALUES (1, ?, ?, ?, NULL) ON CONFLICT(singleton) DO UPDATE SET "
                "token_sha256=excluded.token_sha256, created_at=excluded.created_at, "
                "expires_at=excluded.expires_at, consumed_at=NULL",
                (token_sha256, timestamp, expiry),
            )
        return True

    def owner_bootstrap(self) -> OwnerBootstrapRecord | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM owner_bootstrap WHERE singleton = 1").fetchone()
        if row is None:
            return None
        return OwnerBootstrapRecord(
            token_sha256=str(row["token_sha256"]),
            created_at=_parse_timestamp(row["created_at"]),
            expires_at=_parse_timestamp(row["expires_at"]),
            consumed_at=_parse_timestamp(row["consumed_at"]),
        )

    def exchange_owner_bootstrap(
        self,
        token_sha256: str,
        session_sha256: str,
        csrf_sha256: str,
        *,
        now: datetime,
        session_expires_at: datetime,
    ) -> bool:
        """Consume bootstrap and persist a new hashed owner session atomically."""

        if not all(_valid_sha256(value) for value in (token_sha256, session_sha256, csrf_sha256)):
            raise ValueError("owner credential hash is invalid")
        if session_expires_at <= now:
            raise ValueError("owner session expiry is invalid")
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            updated = connection.execute(
                "UPDATE owner_bootstrap SET consumed_at = ? WHERE singleton = 1 "
                "AND token_sha256 = ? AND consumed_at IS NULL AND expires_at > ?",
                (timestamp, token_sha256, timestamp),
            )
            if updated.rowcount != 1:
                return False
            connection.execute(
                "INSERT INTO owner_sessions(session_sha256, csrf_sha256, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (session_sha256, csrf_sha256, timestamp, _timestamp(session_expires_at)),
            )
        return True

    def owner_session(self, session_sha256: str) -> OwnerSessionRecord | None:
        if not _valid_sha256(session_sha256):
            return None
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM owner_sessions WHERE session_sha256 = ?", (session_sha256,)
            ).fetchone()
        if row is None:
            return None
        return OwnerSessionRecord(
            session_sha256=str(row["session_sha256"]),
            csrf_sha256=str(row["csrf_sha256"]),
            created_at=_parse_timestamp(row["created_at"]),
            expires_at=_parse_timestamp(row["expires_at"]),
            revoked_at=_parse_timestamp(row["revoked_at"]),
        )

    def revoke_owner_session(self, session_sha256: str, *, now: datetime) -> bool:
        if not _valid_sha256(session_sha256):
            return False
        with self._transaction() as connection:
            updated = connection.execute(
                "UPDATE owner_sessions SET revoked_at = ? WHERE session_sha256 = ? "
                "AND revoked_at IS NULL",
                (_timestamp(now), session_sha256),
            )
        return updated.rowcount == 1

    def create_task(
        self,
        request: CreateTaskRequest,
        *,
        run_id: UUID | str | None = None,
        now: datetime | None = None,
        require_single_worker: bool = False,
        observed_origin: str | None = None,
        observed_referer: str | None = None,
    ) -> TaskRecord:
        """Create task, fixed action contract and its two grants atomically."""

        event_time = now or utc_now()
        timestamp = _timestamp(event_time)
        task_id, contract_id, output_slot_id = uuid4(), uuid4(), uuid4()
        trusted_run_id = _identifier(run_id) if run_id is not None else uuid4()
        created_at = _parse_timestamp(timestamp)
        assert created_at is not None
        expires_at = self._contract_expiry(created_at)
        if observed_origin is not None and (
            not isinstance(observed_origin, str) or len(observed_origin) > 512
        ):
            raise ValueError("observed origin is invalid")
        if observed_referer is not None and (
            not isinstance(observed_referer, str) or len(observed_referer) > 2048
        ):
            raise ValueError("observed referer is invalid")
        with self._transaction() as connection:
            if require_single_worker:
                active = connection.execute(
                    "SELECT 1 FROM tasks WHERE status IN "
                    "('CREATED', 'PREPARING', 'RUNNING', 'REVOKING', 'VERIFYING') LIMIT 1"
                ).fetchone()
                if active is not None:
                    raise TaskAlreadyActive("the single worker slot is occupied")
            connection.execute(
                "INSERT INTO tasks(task_id, run_id, tool_id, selected_document_id, contract_id, "
                "status, created_at, launch_source_claim, observed_origin, observed_referer) "
                "VALUES (?, ?, ?, ?, ?, 'CREATED', ?, ?, ?, ?)",
                (
                    str(task_id),
                    str(trusted_run_id),
                    request.tool_id,
                    request.selected_document_id,
                    str(contract_id),
                    timestamp,
                    request.launch_source_claim,
                    observed_origin,
                    observed_referer,
                ),
            )
            connection.execute(
                "INSERT INTO action_contracts(contract_id, task_id, selected_document_id, "
                "output_slot_id, created_at, expires_at, policy_version) "
                "VALUES (?, ?, ?, ?, ?, ?, '1')",
                (
                    str(contract_id),
                    str(task_id),
                    request.selected_document_id,
                    str(output_slot_id),
                    timestamp,
                    expires_at,
                ),
            )
            connection.executemany(
                "INSERT INTO contract_grants(contract_id, operation, document_id, output_slot_id) "
                "VALUES (?, ?, ?, ?)",
                (
                    (str(contract_id), "read_document", request.selected_document_id, None),
                    (str(contract_id), "publish_output", None, str(output_slot_id)),
                ),
            )
            connection.execute(
                "INSERT INTO task_state_transitions(task_id, seq, from_status, to_status, "
                "cause, timestamp) "
                "VALUES (?, 1, NULL, 'CREATED', NULL, ?)",
                (str(task_id), timestamp),
            )
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (str(task_id),)
            ).fetchone()
        assert row is not None
        return self._model_from_task_row(row)

    def _contract_expiry(self, created_at: datetime) -> str:
        """Keep a 30-second contract within SQLite Julian-day comparison precision."""

        with self._connection() as connection:
            for correction_us in range(1001):
                candidate = created_at + timedelta(seconds=30, microseconds=-correction_us)
                candidate_text = _timestamp(candidate)
                within_bound = connection.execute(
                    "SELECT julianday(?) <= julianday(?) + (30.0 / 86400.0)",
                    (candidate_text, _timestamp(created_at)),
                ).fetchone()
                if within_bound is not None and within_bound[0]:
                    return candidate_text
        raise DatabaseError("SQLite could not represent the task contract deadline safely")

    def get_task(self, task_id: UUID | str) -> TaskRecord | None:
        identifier = _identifier(task_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (str(identifier),)
            ).fetchone()
        return None if row is None else self._model_from_task_row(row)

    def worker_process_creation_time(self, task_id: UUID | str) -> int | None:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT creation_time_100ns FROM task_process_identities WHERE task_id=?",
                (identifier,),
            ).fetchone()
        return None if row is None else int(row["creation_time_100ns"])

    def tasks_in_progress(self) -> tuple[TaskRecord, ...]:
        """Return every task whose state can still own work or credentials."""

        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks WHERE status IN "
                "('CREATED', 'PREPARING', 'RUNNING', 'REVOKING', 'VERIFYING') "
                "ORDER BY created_at, task_id"
            ).fetchall()
        return tuple(self._model_from_task_row(row) for row in rows)

    def task_summaries(self, limit: int = 20) -> tuple[TaskSummary, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
            raise ValueError("task limit must be between 1 and 50")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT task_id, tool_id, selected_document_id, status, created_at, "
                "finished_at, incident_id "
                "FROM tasks ORDER BY created_at DESC, task_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(
            TaskSummary(
                task_id=row["task_id"],
                tool_id=row["tool_id"],
                selected_document_id=row["selected_document_id"],
                status=TaskStatus(row["status"]),
                created_at=_parse_timestamp(row["created_at"]),
                finished_at=_parse_timestamp(row["finished_at"]),
                incident_id=row["incident_id"],
            )
            for row in rows
        )

    def get_contract(self, task_id: UUID | str) -> ActionContractRecord | None:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM action_contracts WHERE task_id = ?", (identifier,)
            ).fetchone()
            if row is None:
                return None
            grants = tuple(
                item[0]
                for item in connection.execute(
                    "SELECT operation FROM contract_grants "
                    "WHERE contract_id = ? ORDER BY operation",
                    (row["contract_id"],),
                ).fetchall()
            )
        if set(grants) != {"read_document", "publish_output"}:
            raise DatabaseError("action contract does not contain the controller grant set")
        return ActionContractRecord(
            contract_id=row["contract_id"],
            task_id=row["task_id"],
            selected_document_id=row["selected_document_id"],
            allowed_operations=("read_document", "publish_output"),
            output_slot_id=row["output_slot_id"],
            expires_at=_parse_timestamp(row["expires_at"]),
            policy_version=row["policy_version"],
            created_at=_parse_timestamp(row["created_at"]),
        )

    def transitions(self, task_id: UUID | str) -> tuple[TaskStateTransitionRecord, ...]:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM task_state_transitions WHERE task_id = ? ORDER BY seq", (identifier,)
            ).fetchall()
        return tuple(
            TaskStateTransitionRecord(
                task_id=row["task_id"],
                seq=row["seq"],
                from_status=(
                    None if row["from_status"] is None else TaskStatus(row["from_status"])
                ),
                to_status=TaskStatus(row["to_status"]),
                cause=row["cause"],
                timestamp=_parse_timestamp(row["timestamp"]),
            )
            for row in rows
        )

    @staticmethod
    def _validate_terminal_cause(
        from_status: TaskStatus,
        to_status: TaskStatus,
        revocation_cause: RevocationCause | None,
        terminal_cause: TerminalCause | None,
    ) -> None:
        if to_status == TaskStatus.REVOKING:
            if revocation_cause is None or terminal_cause is not None:
                raise ValueError("entering REVOKING requires exactly one durable revocation cause")
            return
        if revocation_cause is not None:
            raise ValueError("revocation cause may only be committed with the REVOKING transition")
        if to_status not in _TERMINAL:
            if terminal_cause is not None:
                raise ValueError("terminal cause is only valid on a terminal transition")
            return
        if terminal_cause is None:
            raise ValueError("terminal transitions require a cause")
        if terminal_cause in set(TerminalCause(item.value) for item in RevocationCause):
            if from_status not in {TaskStatus.REVOKING, TaskStatus.VERIFYING}:
                raise ValueError("revocation terminal cause requires revocation/verification")
            if to_status == TaskStatus.BLOCKED and terminal_cause != TerminalCause.POLICY_DENIED:
                raise ValueError("BLOCKED requires a policy denial")
            if to_status == TaskStatus.CANCELLED and terminal_cause != TerminalCause.CANCELLED:
                raise ValueError("CANCELLED requires an explicit cancellation")
            if to_status not in {TaskStatus.BLOCKED, TaskStatus.CANCELLED, TaskStatus.FAILED}:
                raise ValueError("revocation cause cannot produce this terminal status")
            return
        allowed = {
            TaskStatus.CREATED: {
                TerminalCause.PREPARATION_FAILED,
                TerminalCause.RECOVERY_INTERRUPTED,
            },
            TaskStatus.PREPARING: {
                TerminalCause.PREPARATION_FAILED,
                TerminalCause.RECOVERY_INTERRUPTED,
            },
            TaskStatus.RUNNING: {
                TerminalCause.WORKER_EXIT_FAILURE,
                TerminalCause.RECOVERY_INTERRUPTED,
            },
            TaskStatus.VERIFYING: {
                TerminalCause.WORKER_EXIT_SUCCESS,
                TerminalCause.WORKER_EXIT_FAILURE,
                TerminalCause.VERIFICATION_FAILED,
                TerminalCause.RECOVERY_INTERRUPTED,
            },
        }.get(from_status, set())
        if terminal_cause not in allowed:
            raise ValueError("terminal cause does not match the lifecycle transition")
        if (
            to_status == TaskStatus.COMPLETED
            and terminal_cause != TerminalCause.WORKER_EXIT_SUCCESS
        ):
            raise ValueError("only a verified zero exit can complete a task")
        if to_status in {TaskStatus.BLOCKED, TaskStatus.CANCELLED}:
            raise ValueError("blocked/cancelled outcomes require the matching revocation cause")

    def transition_task(
        self,
        task_id: UUID | str,
        to_status: TaskStatus,
        *,
        now: datetime | None = None,
        revocation_cause: RevocationCause | None = None,
        terminal_cause: TerminalCause | None = None,
        event_kind: str | None = None,
        event_message: str | None = None,
        revoke_worker_credential: bool = False,
        incident_containment_status: str | None = None,
    ) -> TaskRecord:
        if not isinstance(to_status, TaskStatus):
            raise ValueError("unknown task state")
        identifier = str(_identifier(task_id))
        event_time = now or utc_now()
        timestamp = _timestamp(event_time)
        with self._transaction() as connection:
            current_row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (identifier,)
            ).fetchone()
            if current_row is None:
                raise KeyError("task not found")
            current = self._model_from_task_row(current_row)
            latest_transition = connection.execute(
                "SELECT timestamp FROM task_state_transitions "
                "WHERE task_id = ? ORDER BY seq DESC LIMIT 1",
                (identifier,),
            ).fetchone()
            if latest_transition is not None:
                latest_at = _parse_timestamp(latest_transition["timestamp"])
                if latest_at is not None and timestamp < _timestamp(latest_at):
                    raise ValueError("task transition time cannot move backwards")
            if to_status not in _TRANSITIONS[current.status]:
                raise ValueError(f"invalid task state transition: {current.status} -> {to_status}")
            self._validate_terminal_cause(
                current.status, to_status, revocation_cause, terminal_cause
            )
            if current.revocation_cause is not None and to_status in _TERMINAL:
                if terminal_cause is None or terminal_cause.value != current.revocation_cause.value:
                    raise ValueError(
                        "a terminal outcome cannot replace the committed revocation cause"
                    )
            cause = (
                revocation_cause.value
                if revocation_cause
                else (terminal_cause.value if terminal_cause else None)
            )
            finished = timestamp if to_status in _TERMINAL else None
            started_sql = (
                timestamp
                if to_status == TaskStatus.RUNNING and current.started_at is None
                else None
            )
            connection.execute(
                "UPDATE tasks SET status = ?, started_at = COALESCE(started_at, ?), "
                "finished_at = ?, revocation_cause = COALESCE(revocation_cause, ?), "
                "terminal_cause = ? WHERE task_id = ?",
                (
                    to_status.value,
                    started_sql,
                    finished,
                    revocation_cause.value if revocation_cause else None,
                    terminal_cause.value if terminal_cause else None,
                    identifier,
                ),
            )
            seq = int(
                connection.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 "
                    "FROM task_state_transitions WHERE task_id = ?",
                    (identifier,),
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT INTO task_state_transitions(task_id, seq, from_status, to_status, "
                "cause, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (identifier, seq, current.status.value, to_status.value, cause, timestamp),
            )
            if revoke_worker_credential:
                connection.execute(
                    "UPDATE worker_credentials SET revoked_at=COALESCE(revoked_at, ?) "
                    "WHERE task_id=?",
                    (timestamp, identifier),
                )
            if incident_containment_status is not None:
                if incident_containment_status not in {"terminated", "failed"}:
                    raise ValueError("unknown incident containment status")
                connection.execute(
                    "UPDATE incidents SET containment_status=?, integrity_status='unknown', "
                    "confidentiality_status='unknown' WHERE task_id=?",
                    (incident_containment_status, identifier),
                )
            if (event_kind is None) != (event_message is None):
                raise ValueError("lifecycle event kind and message must be supplied together")
            if event_kind is not None and event_message is not None:
                self._insert_event_row(
                    connection,
                    identifier,
                    timestamp=event_time,
                    source="controller",
                    kind=event_kind,
                    operation=None,
                    target_document_id=None,
                    decision=None,
                    reason_code=None,
                    message=event_message,
                )
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (identifier,)
            ).fetchone()
        assert row is not None
        return self._model_from_task_row(row)

    def activate_worker(
        self,
        task_id: UUID | str,
        token_sha256: str,
        *,
        worker_pid: int,
        worker_sid: str,
        worker_creation_time_100ns: int,
        now: datetime,
        credential_expires_at: datetime,
    ) -> TaskRecord:
        """Commit the verified suspended process identity and credential before resume."""

        identifier = str(_identifier(task_id))
        timestamp = _timestamp(now)
        credential = CredentialHashRecord(
            task_id=identifier,
            token_sha256=token_sha256,
            created_at=now,
            expires_at=credential_expires_at,
            revoked_at=None,
        )
        if worker_pid <= 0 or worker_creation_time_100ns <= 0 or not worker_sid:
            raise ValueError("verified worker identity is incomplete")
        with self._transaction() as connection:
            current_row = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (identifier,)
            ).fetchone()
            if current_row is None:
                raise KeyError("task not found")
            current = self._model_from_task_row(current_row)
            if current.status != TaskStatus.PREPARING or current.revocation_cause is not None:
                raise DatabaseError("task is not prepared for worker activation")
            contract = connection.execute(
                "SELECT expires_at FROM action_contracts WHERE task_id=?", (identifier,)
            ).fetchone()
            if contract is None or credential.expires_at > _parse_timestamp(contract["expires_at"]):
                raise ValueError("worker credential expiry exceeds the action contract")
            if credential.created_at < current.created_at:
                raise ValueError("worker activation cannot precede task creation")
            seq = int(
                connection.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM task_state_transitions WHERE task_id=?",
                    (identifier,),
                ).fetchone()[0]
            )
            connection.execute(
                "UPDATE tasks SET status='RUNNING', started_at=?, worker_pid=?, worker_sid=? "
                "WHERE task_id=?",
                (timestamp, worker_pid, worker_sid, identifier),
            )
            connection.execute(
                "INSERT INTO task_process_identities(task_id, creation_time_100ns, recorded_at) "
                "VALUES (?, ?, ?)",
                (identifier, worker_creation_time_100ns, timestamp),
            )
            connection.execute(
                "INSERT INTO task_state_transitions(task_id, seq, from_status, to_status, "
                "cause, timestamp) VALUES (?, ?, 'PREPARING', 'RUNNING', NULL, ?)",
                (identifier, seq, timestamp),
            )
            connection.execute(
                "INSERT INTO worker_credentials(task_id, token_sha256, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    identifier,
                    credential.token_sha256,
                    timestamp,
                    _timestamp(credential.expires_at),
                ),
            )
            self._insert_event_row(
                connection,
                identifier,
                timestamp=now,
                source="controller",
                kind="worker_started",
                operation=None,
                target_document_id=None,
                decision="allow",
                reason_code=None,
                message="Verified worker identity was committed before process resume.",
            )
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (identifier,)
            ).fetchone()
        assert row is not None
        return self._model_from_task_row(row)

    def revoke_task(
        self,
        task_id: UUID | str,
        cause: RevocationCause,
        *,
        now: datetime,
        event_kind: str,
        event_message: str,
    ) -> tuple[TaskRecord, bool]:
        """Durably revoke one active task; an earlier cause is immutable."""

        identifier = str(_identifier(task_id))
        timestamp = _timestamp(now)
        if cause == RevocationCause.POLICY_DENIED:
            raise ValueError("broker policy denial must use record_policy_denial")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise KeyError("task not found")
            current = self._model_from_task_row(row)
            if current.revocation_cause is not None:
                return current, False
            if current.status not in {
                TaskStatus.CREATED,
                TaskStatus.PREPARING,
                TaskStatus.RUNNING,
            }:
                return current, False
            if (
                current.status == TaskStatus.CREATED
                and cause != RevocationCause.CONTROLLER_SHUTDOWN
            ):
                return current, False
            latest = connection.execute(
                "SELECT seq, timestamp FROM task_state_transitions "
                "WHERE task_id=? ORDER BY seq DESC LIMIT 1",
                (identifier,),
            ).fetchone()
            if latest is not None and timestamp < latest["timestamp"]:
                raise ValueError("revocation time cannot precede the latest task transition")
            seq = int(latest["seq"] + 1) if latest is not None else 1
            connection.execute(
                "UPDATE tasks SET status='REVOKING', revocation_cause=? WHERE task_id=?",
                (cause.value, identifier),
            )
            connection.execute(
                "UPDATE worker_credentials SET revoked_at=COALESCE(revoked_at, ?) WHERE task_id=?",
                (timestamp, identifier),
            )
            connection.execute(
                "INSERT INTO task_state_transitions(task_id, seq, from_status, to_status, "
                "cause, timestamp) VALUES (?, ?, ?, 'REVOKING', ?, ?)",
                (identifier, seq, current.status.value, cause.value, timestamp),
            )
            self._insert_event_row(
                connection,
                identifier,
                timestamp=now,
                source="controller",
                kind=event_kind,
                operation=None,
                target_document_id=None,
                decision="deny",
                reason_code=(
                    "WORKER_TIMEOUT"
                    if cause == RevocationCause.WORKER_TIMEOUT
                    else "CONTROLLER_SHUTDOWN"
                    if cause == RevocationCause.CONTROLLER_SHUTDOWN
                    else "TASK_REVOKED"
                ),
                message=event_message,
            )
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (identifier,)
            ).fetchone()
        assert row is not None
        return self._model_from_task_row(row), True

    def finish_interrupted_task(
        self,
        task_id: UUID | str,
        *,
        now: datetime,
        event_kind: str,
        event_message: str,
        worker_stopped: bool,
    ) -> TaskRecord:
        """Reconcile a startup task only after its retained process identity is stopped."""

        identifier = str(_identifier(task_id))
        if worker_stopped is not True:
            raise DatabaseError("interrupted worker process is not verified stopped")
        timestamp = _timestamp(now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise KeyError("task not found")
            current = self._model_from_task_row(row)
            if current.status in _TERMINAL:
                return current
            terminal_cause = (
                TerminalCause(current.revocation_cause.value)
                if current.revocation_cause is not None
                else TerminalCause.RECOVERY_INTERRUPTED
            )
            latest = connection.execute(
                "SELECT seq, timestamp FROM task_state_transitions "
                "WHERE task_id=? ORDER BY seq DESC LIMIT 1",
                (identifier,),
            ).fetchone()
            if latest is not None and timestamp < latest["timestamp"]:
                raise ValueError("recovery time cannot precede the latest task transition")
            sequence = int(latest["seq"] + 1) if latest is not None else 1
            verification_from = current.status
            if current.status in {TaskStatus.RUNNING, TaskStatus.REVOKING}:
                connection.execute(
                    "UPDATE tasks SET status='VERIFYING' WHERE task_id=?",
                    (identifier,),
                )
                connection.execute(
                    "INSERT INTO task_state_transitions(task_id, seq, from_status, to_status, "
                    "cause, timestamp) VALUES (?, ?, ?, 'VERIFYING', ?, ?)",
                    (
                        identifier,
                        sequence,
                        current.status.value,
                        current.revocation_cause.value
                        if current.revocation_cause is not None
                        else TerminalCause.RECOVERY_INTERRUPTED.value,
                        timestamp,
                    ),
                )
                self._insert_event_row(
                    connection,
                    identifier,
                    timestamp=now,
                    source="controller",
                    kind="task_restart_verification_started",
                    operation=None,
                    target_document_id=None,
                    decision="deny",
                    reason_code=None,
                    message=(
                        "Recorded process identity and publication recovery were checked "
                        "before terminalizing the interrupted task."
                    ),
                )
                verification_from = TaskStatus.VERIFYING
            elif current.status == TaskStatus.VERIFYING:
                verification_from = TaskStatus.VERIFYING
            self._validate_terminal_cause(
                verification_from, TaskStatus.FAILED, None, terminal_cause
            )
            connection.execute(
                "UPDATE tasks SET status='FAILED', finished_at=?, terminal_cause=? WHERE task_id=?",
                (timestamp, terminal_cause.value, identifier),
            )
            connection.execute(
                "UPDATE worker_credentials SET revoked_at=COALESCE(revoked_at, ?) WHERE task_id=?",
                (timestamp, identifier),
            )
            connection.execute(
                "INSERT INTO task_state_transitions(task_id, seq, from_status, to_status, "
                "cause, timestamp) VALUES (?, ?, ?, 'FAILED', ?, ?)",
                (
                    identifier,
                    sequence + int(verification_from != current.status),
                    verification_from.value,
                    terminal_cause.value,
                    timestamp,
                ),
            )
            self._insert_event_row(
                connection,
                identifier,
                timestamp=now,
                source="controller",
                kind=event_kind,
                operation=None,
                target_document_id=None,
                decision="deny",
                reason_code=None,
                message=event_message,
            )
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (identifier,)
            ).fetchone()
        assert row is not None
        return self._model_from_task_row(row)

    def create_credential_hash(
        self, task_id: UUID | str, token_sha256: str, *, created_at: datetime, expires_at: datetime
    ) -> CredentialHashRecord:
        record = CredentialHashRecord(
            task_id=_identifier(task_id),
            token_sha256=token_sha256,
            created_at=created_at,
            expires_at=expires_at,
            revoked_at=None,
        )
        if (record.expires_at - record.created_at).total_seconds() > 120:
            raise ValueError("credential expiry exceeds the 120-second maximum")
        with self._transaction() as connection:
            task = connection.execute(
                "SELECT status, revocation_cause FROM tasks WHERE task_id = ?",
                (str(record.task_id),),
            ).fetchone()
            if task is None:
                raise KeyError("task not found")
            if task["status"] != TaskStatus.RUNNING.value or task["revocation_cause"] is not None:
                raise ValueError("credentials can be created only for an active running task")
            connection.execute(
                "INSERT INTO worker_credentials(task_id, token_sha256, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    str(record.task_id),
                    record.token_sha256,
                    _timestamp(record.created_at),
                    _timestamp(record.expires_at),
                ),
            )
        return record

    def credential_hash(self, task_id: UUID | str) -> CredentialHashRecord | None:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM worker_credentials WHERE task_id = ?", (identifier,)
            ).fetchone()
        if row is None:
            return None
        return CredentialHashRecord(
            task_id=row["task_id"],
            token_sha256=row["token_sha256"],
            created_at=_parse_timestamp(row["created_at"]),
            expires_at=_parse_timestamp(row["expires_at"]),
            revoked_at=_parse_timestamp(row["revoked_at"]),
        )

    def active_task_for_credential(self, token: str, *, at: datetime) -> TaskRecord | None:
        """Resolve an active worker task from the bearer token without storing the token."""

        if not isinstance(token, str) or not 32 <= len(token) <= 512:
            return None
        try:
            encoded = token.encode("ascii", errors="strict")
        except UnicodeEncodeError:
            return None
        token_hash = hashlib.sha256(encoded).hexdigest()
        _timestamp(at)
        with self._connection() as connection:
            credential = connection.execute(
                "SELECT task_id, token_sha256, expires_at, revoked_at "
                "FROM worker_credentials "
                "WHERE token_sha256 = ?",
                (token_hash,),
            ).fetchone()
            if credential is None:
                return None
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (credential["task_id"],)
            ).fetchone()
        if row is None:
            return None
        expires = _parse_timestamp(credential["expires_at"])
        if not (
            secrets.compare_digest(credential["token_sha256"], token_hash)
            and expires is not None
            and at.astimezone(_UTC) < expires
            and credential["revoked_at"] is None
            and row["status"] == TaskStatus.RUNNING.value
            and row["revocation_cause"] is None
        ):
            return None
        return self._model_from_task_row(row)

    def credential_is_valid(self, task_id: UUID | str, token_sha256: str, *, at: datetime) -> bool:
        identifier = str(_identifier(task_id))
        _timestamp(at)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT c.token_sha256, c.expires_at, c.revoked_at, t.status, t.revocation_cause "
                "FROM worker_credentials c JOIN tasks t USING(task_id) WHERE c.task_id = ?",
                (identifier,),
            ).fetchone()
        if row is None:
            return False
        expires = _parse_timestamp(row["expires_at"])
        return bool(
            secrets.compare_digest(row["token_sha256"], token_sha256)
            and expires is not None
            and at.astimezone(_UTC) < expires
            and row["revoked_at"] is None
            and row["status"] == TaskStatus.RUNNING.value
            and row["revocation_cause"] is None
        )

    def revoke_credential(self, task_id: UUID | str, *, at: datetime) -> None:
        identifier = str(_identifier(task_id))
        timestamp = _timestamp(at)
        with self._transaction() as connection:
            connection.execute(
                "UPDATE worker_credentials SET revoked_at = COALESCE(revoked_at, ?) "
                "WHERE task_id = ?",
                (timestamp, identifier),
            )

    @staticmethod
    def _insert_event_row(
        connection: sqlite3.Connection,
        task_id: str,
        *,
        timestamp: datetime,
        source: EventSource,
        kind: str,
        operation: Operation | None,
        target_document_id: str | None,
        decision: str | None,
        reason_code: str | None,
        message: str,
        event_id: UUID | None = None,
    ) -> EventRecord:
        task_row = connection.execute(
            "SELECT run_id FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        if task_row is None:
            raise KeyError("task not found")
        seq = int(
            connection.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM task_events WHERE task_id = ?",
                (task_id,),
            ).fetchone()[0]
        )
        model = EventRecord(
            schema_version=1,
            event_id=event_id or uuid4(),
            task_id=task_id,
            run_id=task_row["run_id"],
            seq=seq,
            timestamp=timestamp,
            source=source,
            kind=kind,
            operation=operation,
            target_document_id=target_document_id,
            decision=decision,
            reason_code=reason_code,
            message=message,
            evidence_refs=(),
        )
        connection.execute(
            "INSERT INTO task_events(event_id, task_id, run_id, seq, timestamp, source, "
            "kind, operation, target_document_id, decision, reason_code, message, "
            "evidence_refs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')",
            (
                str(model.event_id),
                task_id,
                str(model.run_id),
                model.seq,
                _timestamp(model.timestamp),
                model.source,
                model.kind,
                model.operation,
                model.target_document_id,
                model.decision,
                model.reason_code,
                model.message,
            ),
        )
        return model

    def append_event(
        self,
        task_id: UUID | str,
        *,
        source: EventSource,
        kind: str,
        message: str,
        timestamp: datetime | None = None,
        operation: Operation | None = None,
        target_document_id: str | None = None,
        decision: str | None = None,
        reason_code: str | None = None,
        evidence_refs: tuple[str, ...] = (),
    ) -> EventRecord:
        identifier = str(_identifier(task_id))
        at = timestamp or utc_now()
        with self._transaction() as connection:
            task = connection.execute(
                "SELECT run_id FROM tasks WHERE task_id = ?", (identifier,)
            ).fetchone()
            if task is None:
                raise KeyError("task not found")
            seq = int(
                connection.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM task_events WHERE task_id = ?",
                    (identifier,),
                ).fetchone()[0]
            )
            event_id = uuid4()
            model = EventRecord(
                schema_version=1,
                event_id=event_id,
                task_id=identifier,
                run_id=task["run_id"],
                seq=seq,
                timestamp=at,
                source=source,
                kind=kind,
                operation=operation,
                target_document_id=target_document_id,
                decision=decision,
                reason_code=reason_code,
                message=message,
                evidence_refs=evidence_refs,
            )
            connection.execute(
                "INSERT INTO task_events(event_id, task_id, run_id, seq, timestamp, "
                "source, kind, operation, "
                "target_document_id, decision, reason_code, message, evidence_refs_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(event_id),
                    identifier,
                    task["run_id"],
                    seq,
                    _timestamp(at),
                    source,
                    kind,
                    operation,
                    target_document_id,
                    decision,
                    reason_code,
                    message,
                    json.dumps(list(evidence_refs), ensure_ascii=False, separators=(",", ":")),
                ),
            )
        return model

    def record_policy_denial(
        self,
        task_id: UUID | str,
        request_id: UUID | str,
        body_sha256: str,
        *,
        token_sha256: str,
        operation: Operation,
        target_document_id: str,
        reason_code: str,
        policy_reason: str,
        message: str,
        now: datetime | None = None,
    ) -> ErrorResponse:
        """Atomically persist denial, revocation, event, incident, and request response."""

        task_key, request_key = str(_identifier(task_id)), str(_identifier(request_id))
        if len(body_sha256) != 64 or any(c not in "0123456789abcdef" for c in body_sha256):
            raise ValueError("canonical body hash must be lower-case SHA-256")
        if not (
            (
                operation == "read_document"
                and reason_code == "DOCUMENT_OUT_OF_SCOPE"
                and policy_reason == "DOCUMENT_OUT_OF_SCOPE"
            )
            or (
                operation in {"replace_original", "delete_document"}
                and reason_code == "ORIGINAL_MUTATION_FORBIDDEN"
                and policy_reason == "ORIGINAL_MUTATION_FORBIDDEN"
            )
        ):
            raise ValueError("policy denial fields do not describe a supported denial")
        event_time = now or utc_now()
        timestamp = _timestamp(event_time)
        error_response = ErrorResponse(
            schema_version=1,
            error={
                "code": "POLICY_DENIED",
                "message": "The requested operation is forbidden by the task contract.",
                "request_id": request_key,
            },
        )
        response_text = canonical_model_json(error_response)
        with self._transaction() as connection:
            self._assert_active_credential(connection, task_key, token_sha256, at=event_time)
            existing = connection.execute(
                "SELECT canonical_body_sha256, state FROM request_deduplication "
                "WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            ).fetchone()
            if existing is not None:
                if existing["canonical_body_sha256"] != body_sha256:
                    raise RequestConflict("request ID was reused with a different canonical body")
                raise RequestInProgress("request ID already has a durable result or intent")
            latest = connection.execute(
                "SELECT seq, timestamp FROM task_state_transitions "
                "WHERE task_id = ? ORDER BY seq DESC LIMIT 1",
                (task_key,),
            ).fetchone()
            if latest is not None and timestamp < latest["timestamp"]:
                raise ValueError("denial time cannot precede the latest task transition")
            connection.execute(
                "INSERT INTO request_deduplication(task_id, request_id, canonical_body_sha256, "
                "state, created_at, updated_at) VALUES (?, ?, ?, 'reserved', ?, ?)",
                (task_key, request_key, body_sha256, timestamp, timestamp),
            )
            event_id, incident_id = uuid4(), uuid4()
            self._insert_event_row(
                connection,
                task_key,
                timestamp=event_time,
                source="broker",
                kind="operation_denied",
                operation=operation,
                target_document_id=target_document_id,
                decision="deny",
                reason_code=reason_code,
                message=message,
                event_id=event_id,
            )
            connection.execute(
                "UPDATE tasks SET status = 'REVOKING', revocation_cause = 'POLICY_DENIED' "
                "WHERE task_id = ?",
                (task_key,),
            )
            connection.execute(
                "UPDATE worker_credentials SET revoked_at=COALESCE(revoked_at, ?) WHERE task_id=?",
                (timestamp, task_key),
            )
            transition_seq = int(latest["seq"] + 1) if latest is not None else 1
            connection.execute(
                "INSERT INTO task_state_transitions(task_id, seq, from_status, to_status, "
                "cause, timestamp) VALUES (?, ?, 'RUNNING', 'REVOKING', 'POLICY_DENIED', ?)",
                (task_key, transition_seq, timestamp),
            )
            incident = Incident(
                incident_id=incident_id,
                task_id=task_key,
                trigger_event_id=event_id,
                policy_reason=policy_reason,
                containment_status="pending",
                integrity_status="pending",
                confidentiality_status="pending",
                evidence_refs=(),
            )
            connection.execute(
                "INSERT INTO incidents(incident_id, task_id, trigger_event_id, policy_reason, "
                "containment_status, integrity_status, confidentiality_status, evidence_refs_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, '[]')",
                (
                    str(incident.incident_id),
                    task_key,
                    str(incident.trigger_event_id),
                    incident.policy_reason,
                    incident.containment_status,
                    incident.integrity_status,
                    incident.confidentiality_status,
                ),
            )
            connection.execute(
                "UPDATE tasks SET incident_id = ? WHERE task_id = ?",
                (str(incident_id), task_key),
            )
            connection.execute(
                "UPDATE request_deduplication SET state = 'completed', response_json = ?, "
                "updated_at = ? WHERE task_id = ? AND request_id = ?",
                (response_text, timestamp, task_key, request_key),
            )
        return error_response

    def events(self, task_id: UUID | str, *, after_seq: int = 0) -> tuple[EventRecord, ...]:
        identifier = str(_identifier(task_id))
        if (
            isinstance(after_seq, bool)
            or not isinstance(after_seq, int)
            or not 0 <= after_seq <= 999_999_999
        ):
            raise ValueError("after_seq must be between 0 and 999,999,999")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM task_events WHERE task_id = ? AND seq > ? ORDER BY seq",
                (identifier, after_seq),
            ).fetchall()
        return tuple(
            EventRecord(
                schema_version=1,
                event_id=row["event_id"],
                task_id=row["task_id"],
                run_id=row["run_id"],
                seq=row["seq"],
                timestamp=_parse_timestamp(row["timestamp"]),
                source=row["source"],
                kind=row["kind"],
                operation=row["operation"],
                target_document_id=row["target_document_id"],
                decision=row["decision"],
                reason_code=row["reason_code"],
                message=row["message"],
                evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
            )
            for row in rows
        )

    def create_incident(self, incident: Incident) -> None:
        with self._transaction() as connection:
            task = connection.execute(
                "SELECT revocation_cause FROM tasks WHERE task_id = ?", (str(incident.task_id),)
            ).fetchone()
            event = connection.execute(
                "SELECT task_id, source, decision, operation, reason_code "
                "FROM task_events WHERE event_id = ?",
                (str(incident.trigger_event_id),),
            ).fetchone()
            if task is None or event is None or event["task_id"] != str(incident.task_id):
                raise ValueError("incident must refer to an event belonging to its task")
            if (
                task["revocation_cause"] != RevocationCause.POLICY_DENIED.value
                or event["source"] != "broker"
                or event["decision"] != "deny"
            ):
                raise ValueError("incidents require a committed broker policy denial")
            valid_reason = (
                incident.policy_reason == "DOCUMENT_OUT_OF_SCOPE"
                and event["operation"] == "read_document"
                and event["reason_code"] == "DOCUMENT_OUT_OF_SCOPE"
            ) or (
                incident.policy_reason == "ORIGINAL_MUTATION_FORBIDDEN"
                and event["operation"] in {"replace_original", "delete_document"}
                and event["reason_code"] == "ORIGINAL_MUTATION_FORBIDDEN"
            )
            if not valid_reason:
                raise ValueError("incident reason must match its broker denial event")
            connection.execute(
                "INSERT INTO incidents(incident_id, task_id, trigger_event_id, policy_reason, "
                "containment_status, integrity_status, confidentiality_status, "
                "evidence_refs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(incident.incident_id),
                    str(incident.task_id),
                    str(incident.trigger_event_id),
                    incident.policy_reason,
                    incident.containment_status,
                    incident.integrity_status,
                    incident.confidentiality_status,
                    json.dumps(
                        list(incident.evidence_refs), ensure_ascii=False, separators=(",", ":")
                    ),
                ),
            )
            connection.execute(
                "UPDATE tasks SET incident_id = ? WHERE task_id = ?",
                (str(incident.incident_id), str(incident.task_id)),
            )

    def incident_for_task(self, task_id: UUID | str) -> Incident | None:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT incident_id, task_id, trigger_event_id, policy_reason, "
                "containment_status, integrity_status, confidentiality_status, evidence_refs_json "
                "FROM incidents WHERE task_id = ?",
                (identifier,),
            ).fetchone()
        if row is None:
            return None
        try:
            return Incident.model_validate(
                {
                    "incident_id": row["incident_id"],
                    "task_id": row["task_id"],
                    "trigger_event_id": row["trigger_event_id"],
                    "policy_reason": row["policy_reason"],
                    "containment_status": row["containment_status"],
                    "integrity_status": row["integrity_status"],
                    "confidentiality_status": row["confidentiality_status"],
                    "evidence_refs": json.loads(row["evidence_refs_json"]),
                },
                strict=True,
            )
        except (ValueError, ValidationError) as exc:
            raise DatabaseError("stored incident violates its strict model") from exc

    def begin_request(
        self,
        task_id: UUID | str,
        request_id: UUID | str,
        body_sha256: str,
        *,
        now: datetime | None = None,
        token_sha256: str | None = None,
    ) -> tuple[RequestDisposition, dict[str, object] | None]:
        task_key, request_key = str(_identifier(task_id)), str(_identifier(request_id))
        if len(body_sha256) != 64 or any(c not in "0123456789abcdef" for c in body_sha256):
            raise ValueError("canonical body hash must be lower-case SHA-256")
        at_time = now or utc_now()
        at = _timestamp(at_time)
        with self._transaction() as connection:
            if token_sha256 is not None:
                self._assert_active_credential(
                    connection,
                    task_key,
                    token_sha256,
                    at=at_time,
                )
            existing = connection.execute(
                "SELECT canonical_body_sha256, state, response_json "
                "FROM request_deduplication WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            ).fetchone()
            if existing is not None:
                if existing["canonical_body_sha256"] != body_sha256:
                    raise RequestConflict("request ID was reused with a different canonical body")
                if existing["state"] == "reserved":
                    raise RequestInProgress("request ID has an unfinished durable intent")
                response = json.loads(existing["response_json"])
                return RequestDisposition.REPLAY, response
            connection.execute(
                "INSERT INTO request_deduplication(task_id, request_id, "
                "canonical_body_sha256, state, created_at, updated_at) "
                "VALUES (?, ?, ?, 'reserved', ?, ?)",
                (task_key, request_key, body_sha256, at, at),
            )
        return RequestDisposition.NEW, None

    def complete_request(
        self,
        task_id: UUID | str,
        request_id: UUID | str,
        body_sha256: str,
        response: BaseModel,
        *,
        now: datetime | None = None,
        token_sha256: str | None = None,
        event_kind: str | None = None,
        event_operation: Operation | None = None,
        event_target_document_id: str | None = None,
        event_decision: str | None = None,
        event_reason_code: str | None = None,
        event_message: str | None = None,
    ) -> None:
        task_key, request_key = str(_identifier(task_id)), str(_identifier(request_id))
        response_text = canonical_model_json(response)
        at_time = now or utc_now()
        at = _timestamp(at_time)
        with self._transaction() as connection:
            if token_sha256 is not None:
                self._assert_active_credential(connection, task_key, token_sha256, at=at_time)
            row = connection.execute(
                "SELECT canonical_body_sha256, state, created_at FROM request_deduplication "
                "WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            ).fetchone()
            if row is None:
                raise KeyError("request reservation not found")
            if row["canonical_body_sha256"] != body_sha256:
                raise RequestConflict("request ID was reused with a different canonical body")
            if row["state"] == "completed":
                raise RequestInProgress("request response is already finalized")
            if at < row["created_at"]:
                raise ValueError("request completion time cannot precede its reservation")
            if event_kind is not None:
                if event_operation is None or event_decision is None or event_message is None:
                    raise ValueError("broker event requires an operation, decision, and message")
                self._insert_event_row(
                    connection,
                    task_key,
                    timestamp=at_time,
                    source="broker",
                    kind=event_kind,
                    operation=event_operation,
                    target_document_id=event_target_document_id,
                    decision=event_decision,
                    reason_code=event_reason_code,
                    message=event_message,
                )
            connection.execute(
                "UPDATE request_deduplication SET state = 'completed', "
                "response_json = ?, updated_at = ? "
                "WHERE task_id = ? AND request_id = ?",
                (response_text, at, task_key, request_key),
            )

    def abandon_unstarted_request(
        self, task_id: UUID | str, request_id: UUID | str, body_sha256: str
    ) -> None:
        """Remove a read-only reservation only when no durable output intent exists."""

        task_key, request_key = str(_identifier(task_id)), str(_identifier(request_id))
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT canonical_body_sha256, state FROM request_deduplication "
                "WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            ).fetchone()
            if row is None:
                return
            if row["canonical_body_sha256"] != body_sha256 or row["state"] != "reserved":
                raise RequestConflict("only the matching unfinished request can be abandoned")
            has_output = connection.execute(
                "SELECT 1 FROM output_records WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            ).fetchone()
            if has_output is not None:
                raise DatabaseError("durable output intent cannot be abandoned")
            connection.execute(
                "DELETE FROM request_deduplication WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            )

    def reserve_output(
        self,
        task_id: UUID | str,
        request_id: UUID | str,
        content_sha256: str,
        decoded_bytes: int,
        *,
        now: datetime | None = None,
        token_sha256: str | None = None,
    ) -> OutputJournalRecord:
        task_key, request_key = str(_identifier(task_id)), str(_identifier(request_id))
        at = now or utc_now()
        with self._transaction() as connection:
            if token_sha256 is not None:
                self._assert_active_credential(connection, task_key, token_sha256, at=at)
            row = connection.execute(
                "SELECT t.tool_id, c.output_slot_id, r.state FROM tasks t "
                "JOIN action_contracts c ON c.task_id = t.task_id "
                "JOIN request_deduplication r ON r.task_id = t.task_id "
                "WHERE t.task_id = ? AND r.request_id = ?",
                (task_key, request_key),
            ).fetchone()
            if row is None or row["state"] != "reserved":
                raise ValueError(
                    "output requires an active request reservation and controller contract"
                )
            request_row = connection.execute(
                "SELECT created_at FROM request_deduplication WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            ).fetchone()
            if request_row is None or _timestamp(at) < request_row["created_at"]:
                raise ValueError("output reservation time cannot precede its request")
            kind: OutputKind = (
                "formatted_markdown" if row["tool_id"] == "report_formatter" else "invoice_json"
            )
            output_id = uuid4()
            suffix = ".md" if kind == "formatted_markdown" else ".json"
            prefix = f"{task_key}/"
            record = OutputJournalRecord(
                task_id=task_key,
                request_id=request_key,
                output_id=output_id,
                output_slot_id=row["output_slot_id"],
                output_kind=kind,
                staging_relative_path=f"{prefix}{output_id}.staging",
                final_relative_path=f"{prefix}{output_id}{suffix}",
                content_sha256=content_sha256,
                decoded_bytes=decoded_bytes,
                state=JournalState.RESERVED,
                created_at=at,
                updated_at=at,
            )
            connection.execute(
                "INSERT INTO output_records(output_id, task_id, request_id, output_slot_id, "
                "output_kind, staging_relative_path, final_relative_path, content_sha256, "
                "decoded_bytes, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)",
                (
                    str(output_id),
                    task_key,
                    request_key,
                    str(record.output_slot_id),
                    kind,
                    record.staging_relative_path,
                    record.final_relative_path,
                    content_sha256,
                    decoded_bytes,
                    _timestamp(at),
                    _timestamp(at),
                ),
            )
        return record

    def output_for_request(
        self, task_id: UUID | str, request_id: UUID | str
    ) -> OutputJournalRecord | None:
        task_key, request_key = str(_identifier(task_id)), str(_identifier(request_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM output_records WHERE task_id = ? AND request_id = ?",
                (task_key, request_key),
            ).fetchone()
        return None if row is None else self._output_model(row)

    @staticmethod
    def _output_model(row: sqlite3.Row) -> OutputJournalRecord:
        return OutputJournalRecord(
            task_id=row["task_id"],
            request_id=row["request_id"],
            output_id=row["output_id"],
            output_slot_id=row["output_slot_id"],
            output_kind=row["output_kind"],
            staging_relative_path=row["staging_relative_path"],
            final_relative_path=row["final_relative_path"],
            content_sha256=row["content_sha256"],
            decoded_bytes=row["decoded_bytes"],
            state=JournalState(row["state"]),
            created_at=_parse_timestamp(row["created_at"]),
            updated_at=_parse_timestamp(row["updated_at"]),
        )

    def finalize_output_publication(
        self,
        output_id: UUID | str,
        body_sha256: str,
        response: BrokerOutputAllowed,
        *,
        now: datetime | None = None,
        token_sha256: str | None = None,
    ) -> OutputJournalRecord:
        """Commit file-verified output state and exact replay response atomically."""

        identifier = str(_identifier(output_id))
        if response.output_id != UUID(identifier):
            raise ValueError("publication response output ID does not match its journal row")
        at_time = now or utc_now()
        at = _timestamp(at_time)
        response_text = canonical_model_json(response)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM output_records WHERE output_id = ?", (identifier,)
            ).fetchone()
            if row is None:
                raise KeyError("output journal row not found")
            if token_sha256 is not None:
                self._assert_active_credential(connection, row["task_id"], token_sha256, at=at_time)
            if response.sha256 != row["content_sha256"]:
                raise ValueError("publication response hash does not match its journal row")
            if row["state"] == JournalState.PUBLISHED.value:
                request_row = connection.execute(
                    "SELECT state, canonical_body_sha256 FROM request_deduplication "
                    "WHERE task_id = ? AND request_id = ?",
                    (row["task_id"], row["request_id"]),
                ).fetchone()
                if (
                    request_row is not None
                    and request_row["state"] == "completed"
                    and request_row["canonical_body_sha256"] == body_sha256
                ):
                    return self._output_model(row)
                raise DatabaseError("published output is missing its finalized request response")
            request_row = connection.execute(
                "SELECT state, canonical_body_sha256, created_at FROM request_deduplication "
                "WHERE task_id = ? AND request_id = ?",
                (row["task_id"], row["request_id"]),
            ).fetchone()
            if (
                request_row is None
                or request_row["state"] != "reserved"
                or request_row["canonical_body_sha256"] != body_sha256
            ):
                raise RequestConflict("output request no longer matches its reservation")
            if row["state"] not in {
                JournalState.STAGED.value,
                JournalState.FILE_COMMITTED.value,
            }:
                raise DatabaseError("output is not ready for publication finalization")
            if at < row["updated_at"] or at < request_row["created_at"]:
                raise ValueError("publication time cannot move backwards")
            if row["state"] == JournalState.STAGED.value:
                connection.execute(
                    "UPDATE output_records SET state='file_committed', updated_at=? "
                    "WHERE output_id=?",
                    (at, identifier),
                )
            connection.execute(
                "UPDATE output_records SET state='published', updated_at=? WHERE output_id=?",
                (at, identifier),
            )
            self._insert_event_row(
                connection,
                row["task_id"],
                timestamp=at_time,
                source="broker",
                kind="output_published",
                operation="publish_output",
                target_document_id=None,
                decision="allow",
                reason_code=None,
                message="Validated task output was published.",
            )
            connection.execute(
                "UPDATE request_deduplication SET state='completed', response_json=?, "
                "updated_at=? WHERE task_id=? AND request_id=?",
                (response_text, at, row["task_id"], row["request_id"]),
            )
            finalized = connection.execute(
                "SELECT * FROM output_records WHERE output_id = ?", (identifier,)
            ).fetchone()
        assert finalized is not None
        return self._output_model(finalized)

    def transition_output(
        self, output_id: UUID | str, state: JournalState, *, now: datetime | None = None
    ) -> OutputJournalRecord:
        identifier = str(_identifier(output_id))
        at = _timestamp(now or utc_now())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM output_records WHERE output_id = ?", (identifier,)
            ).fetchone()
            if row is None:
                raise KeyError("output journal row not found")
            if at < row["created_at"]:
                raise ValueError("output journal time cannot move backwards")
            updated = connection.execute(
                "UPDATE output_records SET state = ?, updated_at = ? WHERE output_id = ?",
                (state.value, at, identifier),
            )
            if updated.rowcount != 1:
                raise DatabaseError("output state transition did not update exactly one record")
            row = connection.execute(
                "SELECT * FROM output_records WHERE output_id = ?", (identifier,)
            ).fetchone()
        return OutputJournalRecord(
            task_id=row["task_id"],
            request_id=row["request_id"],
            output_id=row["output_id"],
            output_slot_id=row["output_slot_id"],
            output_kind=row["output_kind"],
            staging_relative_path=row["staging_relative_path"],
            final_relative_path=row["final_relative_path"],
            content_sha256=row["content_sha256"],
            decoded_bytes=row["decoded_bytes"],
            state=JournalState(row["state"]),
            created_at=_parse_timestamp(row["created_at"]),
            updated_at=_parse_timestamp(row["updated_at"]),
        )

    def output_journal(self, output_id: UUID | str) -> OutputJournalRecord | None:
        identifier = str(_identifier(output_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM output_records WHERE output_id = ?", (identifier,)
            ).fetchone()
        if row is None:
            return None
        return self._output_model(row)

    def outputs_for_task(self, task_id: UUID | str) -> tuple[OutputJournalRecord, ...]:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM output_records WHERE task_id=? ORDER BY created_at, output_id",
                (identifier,),
            ).fetchall()
        return tuple(self._output_model(row) for row in rows)

    def request_body_sha256(self, task_id: UUID | str, request_id: UUID | str) -> str | None:
        task_key, request_key = str(_identifier(task_id)), str(_identifier(request_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT canonical_body_sha256 FROM request_deduplication "
                "WHERE task_id=? AND request_id=?",
                (task_key, request_key),
            ).fetchone()
        return None if row is None else str(row["canonical_body_sha256"])

    def published_output(self, output_id: UUID | str) -> OutputMetadata | None:
        identifier = str(_identifier(output_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM output_records WHERE output_id = ? AND state = 'published'",
                (identifier,),
            ).fetchone()
        if row is None:
            return None
        return OutputMetadata(
            output_id=row["output_id"],
            task_id=row["task_id"],
            output_kind=row["output_kind"],
            file_name=Path(row["final_relative_path"]).name,
            decoded_bytes=row["decoded_bytes"],
            sha256=row["content_sha256"],
            created_at=_parse_timestamp(row["created_at"]),
        )

    def save_evidence_baseline(self, baseline: EvidenceBaseline, *, artifact_path: str) -> None:
        """Persist a single immutable pre-launch inventory for the controller-owned task."""

        identifier = str(_identifier(baseline.task_id))
        inventory_json = json.dumps(
            [entry.model_dump(mode="json") for entry in baseline.entries],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        inventory_sha256 = hashlib.sha256(inventory_json.encode("utf-8")).hexdigest()
        artifact = PurePosixPath(artifact_path)
        if (
            artifact.is_absolute()
            or artifact_path.startswith("/")
            or "\\" in artifact_path
            or ":" in artifact_path
            or any(part in {"", ".", ".."} for part in artifact_path.split("/"))
        ):
            raise ValueError("baseline artifact path must be trusted and relative")
        with self._transaction() as connection:
            task = connection.execute(
                "SELECT run_id FROM tasks WHERE task_id=?", (identifier,)
            ).fetchone()
            if task is None or task["run_id"] != str(baseline.run_id):
                raise ValueError("evidence baseline must match its persisted task and run")
            connection.execute(
                "INSERT INTO task_evidence_baselines(task_id, run_id, captured_at, "
                "tested_source_revision, tested_source_sha256, manifest_match, "
                "selected_input_size_bytes, selected_input_sha256, inventory_json, "
                "inventory_sha256, artifact_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    identifier,
                    str(baseline.run_id),
                    _timestamp(baseline.captured_at),
                    baseline.tested_source_revision,
                    baseline.tested_source_sha256,
                    int(baseline.manifest_match),
                    baseline.selected_input_size_bytes,
                    baseline.selected_input_sha256,
                    inventory_json,
                    inventory_sha256,
                    artifact_path,
                ),
            )

    def evidence_baseline(self, task_id: UUID | str) -> EvidenceBaseline | None:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM task_evidence_baselines WHERE task_id=?", (identifier,)
            ).fetchone()
        if row is None:
            return None
        try:
            inventory_json = str(row["inventory_json"])
            if (
                hashlib.sha256(inventory_json.encode("utf-8")).hexdigest()
                != row["inventory_sha256"]
            ):
                raise DatabaseError("stored evidence baseline digest mismatch")
            entries = tuple(json.loads(inventory_json))
            baseline = EvidenceBaseline(
                task_id=row["task_id"],
                run_id=row["run_id"],
                captured_at=_parse_timestamp(row["captured_at"]),
                tested_source_revision=row["tested_source_revision"],
                tested_source_sha256=row["tested_source_sha256"],
                manifest_match=bool(row["manifest_match"]),
                selected_input_size_bytes=row["selected_input_size_bytes"],
                selected_input_sha256=row["selected_input_sha256"],
                entries=entries,
            )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise DatabaseError("stored evidence baseline is invalid") from exc
        artifact = PurePosixPath(row["artifact_path"])
        if (
            artifact.is_absolute()
            or row["artifact_path"].startswith("/")
            or "\\" in row["artifact_path"]
            or ":" in row["artifact_path"]
            or any(part in {"", ".", ".."} for part in row["artifact_path"].split("/"))
        ):
            raise DatabaseError("stored evidence artifact path is invalid")
        return baseline

    def save_evidence_report(self, report: EvidenceReport) -> None:
        """Append a validated report; prior unknown reports remain auditable."""

        report_json = canonical_model_json(report)
        report_hash = hashlib.sha256(report_json.encode("utf-8")).hexdigest()
        with self._transaction() as connection:
            task = connection.execute(
                "SELECT run_id FROM tasks WHERE task_id=?", (str(report.task_id),)
            ).fetchone()
            if task is None or task["run_id"] != str(report.run_id):
                raise ValueError("evidence report must match its persisted task and run")
            connection.execute(
                "INSERT INTO task_evidence_reports(report_id, task_id, run_id, generated_at, "
                "report_sha256, report_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(report.report_id),
                    str(report.task_id),
                    str(report.run_id),
                    _timestamp(report.generated_at),
                    report_hash,
                    report_json,
                ),
            )

    def evidence_response(self, task_id: UUID | str) -> EvidenceResponse:
        identifier = str(_identifier(task_id))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT report_sha256, report_json FROM task_evidence_reports "
                "WHERE task_id=? ORDER BY generated_at DESC, report_id DESC LIMIT 1",
                (identifier,),
            ).fetchone()
        if row is None:
            return EvidenceResponse(schema_version=1, status="pending", report=None)
        raw = str(row["report_json"])
        if hashlib.sha256(raw.encode("utf-8")).hexdigest() != row["report_sha256"]:
            raise DatabaseError("stored evidence report digest mismatch")
        try:
            report = EvidenceReport.model_validate_json(raw, strict=True)
        except ValidationError as exc:
            raise DatabaseError("stored evidence report is invalid") from exc
        if str(report.task_id) != identifier:
            raise DatabaseError("stored evidence report task identity mismatch")
        return EvidenceResponse(schema_version=1, status="complete", report=report)

    def update_incident_verification(
        self,
        task_id: UUID | str,
        *,
        containment_status: str,
        integrity_status: str,
        confidentiality_status: str,
        evidence_ref: str,
    ) -> None:
        identifier = str(_identifier(task_id))
        if containment_status not in {"terminated", "failed"}:
            raise ValueError("incident containment status is invalid")
        if integrity_status not in {"pass", "fail", "unknown", "not_applicable"}:
            raise ValueError("incident integrity status is invalid")
        if confidentiality_status not in {"pass", "fail", "unknown", "not_applicable"}:
            raise ValueError("incident confidentiality status is invalid")
        path = Path(evidence_ref)
        if (
            path.is_absolute()
            or "\\" in evidence_ref
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("incident evidence reference must be trusted and relative")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT i.incident_id, i.evidence_refs_json FROM incidents i "
                "JOIN tasks t USING(task_id) WHERE t.task_id=?",
                (identifier,),
            ).fetchone()
            if row is None:
                return
            references = list(json.loads(row["evidence_refs_json"]))
            if evidence_ref not in references:
                references.append(evidence_ref)
            connection.execute(
                "UPDATE incidents SET containment_status=?, integrity_status=?, "
                "confidentiality_status=?, evidence_refs_json=? WHERE incident_id=?",
                (
                    containment_status,
                    integrity_status,
                    confidentiality_status,
                    json.dumps(references, ensure_ascii=False, separators=(",", ":")),
                    row["incident_id"],
                ),
            )
