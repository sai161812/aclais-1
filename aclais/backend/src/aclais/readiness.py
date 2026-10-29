"""Live owner-side preflight; the Windows gate probes remain independent evidence."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

from aclais.launcher.windows import RuntimeLayout, _NativeApi
from aclais.persistence.models import HealthCheck, HealthResponse


class ReadinessError(RuntimeError):
    """A mandatory local boundary check failed; no launch is authorized."""

    def __init__(self, message: str, checks: tuple[HealthCheck, ...] = ()) -> None:
        super().__init__(message)
        self.checks = checks


def boundary_check(
    *, skip_fixture_hashes: bool = False, require_idle: bool = False, allow_retiring: bool = False
) -> tuple[HealthCheck, ...]:
    script = Path(__file__).resolve().parents[3] / "scripts" / "check_boundary.ps1"
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    environment = {
        key: os.environ[key]
        for key in ("SystemRoot", "WINDIR", "SystemDrive", "COMPUTERNAME", "TEMP", "TMP")
        if key in os.environ
    }
    command = [str(powershell), "-NoProfile", "-NonInteractive", "-File", str(script)]
    if skip_fixture_hashes:
        command.append("-SkipFixtureHashes")
    if require_idle:
        command.append("-RequireIdle")
    if allow_retiring:
        command.append("-AllowRetiring")
    result = subprocess.run(command, capture_output=True, timeout=45, env=environment, check=False)
    if len(result.stdout) > 65536:
        raise ReadinessError("boundary response exceeded its limit")
    body = json.loads(result.stdout)
    checks = tuple(HealthCheck.model_validate(item) for item in body["checks"])
    if result.returncode or not body["passed"]:
        raise ReadinessError("effective boundary verification failed", checks)
    return checks


class Readiness:
    def __init__(self, layout: RuntimeLayout) -> None:
        self.layout = layout
        self._lock = threading.Lock()
        self._checked_at = 0.0
        self._checks: tuple[HealthCheck, ...] = ()

    def check(self, *, fresh: bool = False) -> tuple[HealthCheck, ...]:
        with self._lock:
            if not fresh and self._checks and time.monotonic() - self._checked_at < 5:
                return self._checks
            checks: list[HealthCheck] = []
            try:
                checks.extend(boundary_check())
                api = _NativeApi()
                secret = api.read_credential()
                secret.clear()
                checks.append(
                    HealthCheck(
                        id="credential_retrieval",
                        status="pass",
                        summary="Owner Credential Manager retrieval succeeded.",
                    )
                )
                job = api.create_job()
                try:
                    api.configure_kill_on_close(job)
                    if not api.verify_kill_on_close(job):
                        raise ReadinessError("job configuration was not verified")
                finally:
                    api.close_handle(job)
                checks.append(
                    HealthCheck(
                        id="job_configuration",
                        status="pass",
                        summary="Kill-on-close Job Object configuration verified.",
                    )
                )
                database = self.layout.root / "state/controller.sqlite3"
                if database.exists():
                    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
                        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                            raise ReadinessError("database integrity check failed")
                        migrations = Path(__file__).with_name("persistence") / "migrations"
                        expected = max(int(p.name[:4]) for p in migrations.glob("*.sql"))
                        if connection.execute("PRAGMA user_version").fetchone()[0] != expected:
                            raise ReadinessError("database migrations are incomplete")
                    checks.append(
                        HealthCheck(
                            id="database_integrity",
                            status="pass",
                            summary="Database integrity and migration version verified.",
                        )
                    )
            except Exception as exc:
                if isinstance(exc, ReadinessError):
                    checks.extend(exc.checks)
                checks.append(
                    HealthCheck(
                        id="launch_preflight",
                        status="fail",
                        summary="Mandatory local preflight failed; launch refused.",
                    )
                )
            self._checks = tuple(checks)
            self._checked_at = time.monotonic()
            return self._checks

    def require_core(self) -> None:
        if any(item.status != "pass" for item in self.check(fresh=True)):
            raise ReadinessError("mandatory local preflight failed")

    def health(self, *, controller_accepting: bool = True) -> HealthResponse:
        checks = self.check()
        if not controller_accepting:
            checks = (
                *checks,
                HealthCheck(
                    id="controller_lifecycle",
                    status="fail",
                    summary="The controller stopped accepting work; launch is refused.",
                ),
            )
        core_ready = bool(checks) and all(item.status == "pass" for item in checks)
        installed = all(
            (self.layout.root / "code/document-tools/workers" / tool / "entrypoint.py").is_file()
            for tool in ("report_formatter", "invoice_analyzer")
        )
        ready = core_ready and installed
        summary = (
            "Local boundary checks passed; fixed workers are installed."
            if ready
            else "Core checks passed; production workers are pending G3 installation."
            if core_ready
            else "A mandatory local boundary check failed; launch is refused."
        )
        return HealthResponse(
            schema_version=1,
            status="ready" if ready else "unavailable",
            protection_ready=ready,
            checks=(
                HealthCheck(
                    id="application_api",
                    status="pass",
                    summary="The local API process is responding.",
                ),
                *checks,
                HealthCheck(
                    id="g1_protection",
                    status="pass" if ready else "unknown" if core_ready else "fail",
                    summary=summary,
                ),
            ),
        )
