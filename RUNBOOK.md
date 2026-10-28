# ACLAIS local development runbook

## Prerequisites

- Windows 11, Python 3.12, `uv` 0.12.15 or compatible, Node.js 24, and npm 11.
- Git checkout of the repository. The Python and npm dependencies are pinned by `backend/aclais/uv.lock` and `frontend/aclais/package-lock.json`.

The environment observed for A1 has Python 3.12.10, `uv` 0.12.15, Node.js 24.19.0, and npm 11.17.0. The application development servers bind loopback only.

## Install environments

From the repository root in PowerShell:

```powershell
Push-Location backend/aclais
uv sync --locked
Pop-Location

Push-Location frontend/aclais
npm ci
Pop-Location
```

The backend virtual environment is `backend/aclais/.venv` and is ignored by Git. The frontend dependencies are installed under `frontend/aclais/node_modules`, also ignored.

## Start the A1 shell

Use two PowerShell terminals from the repository root.

Backend terminal:

```powershell
Push-Location backend/aclais
uv run --locked python -m aclais
```

Frontend terminal:

```powershell
Push-Location frontend/aclais
npm run dev
```

Open `http://127.0.0.1:5173`. Vite proxies same-origin `/api` requests to the API at `http://127.0.0.1:8765`. The direct health URL is `http://127.0.0.1:8765/api/health`. An `unavailable` protection state is expected in A1: the API is responding, while worker isolation and enforcement have not been implemented. No receiver or Document Tools service starts in this checkpoint.

## Configuration and logging

Supported environment variables are `ACLAIS_HOST`, `ACLAIS_PORT`, and `ACLAIS_LOG_LEVEL`. Defaults are `127.0.0.1`, `8765`, and `INFO`. The host is restricted to `127.0.0.1`; the port must be decimal and in the range 1024–65535; log level must be DEBUG, INFO, WARNING, or ERROR. Unknown `ACLAIS_` variable names and invalid values stop startup. A `.env` file is not loaded.

PowerShell example:

```powershell
$env:ACLAIS_HOST = '127.0.0.1'
$env:ACLAIS_PORT = '8765'
$env:ACLAIS_LOG_LEVEL = 'INFO'
```

Logs are one-line JSON records on stderr. Structured fields with names containing authorization, cookie, token, password, secret, credential, canary, payload, private, or API key are replaced with `[REDACTED]`; common bearer and `key=value`/header patterns in messages are also redacted. Exception text and tracebacks are omitted. Do not log request bodies, headers, credentials, canary values, private document contents, or arbitrary user input. The redactor is defense in depth and does not make unsafe logging of arbitrary strings acceptable.

## A2 demonstration-machine provisioning and probe

From the repository root, provision only on the designated Windows demonstration machine. This setup creates or refreshes the non-administrator account, writes a newly generated secret directly to the owner's Credential Manager, seeds synthetic files under `C:\ACLAIS-Lab`, and applies its owned NTFS permissions. It requires one-time elevation and refuses to run while an AclaisWorker process is active:

```powershell
Start-Process PowerShell -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File .\scripts\provision_a2.ps1'
```

Run the private access probe from the ordinary, non-elevated owner session after provisioning:

```powershell
.\scripts\run_a2_access_probe.ps1
```

The harness retrieves the credential from the current owner's Credential Manager and passes it through the process credential API. It records no password, passes no secret in argv/environment, and writes sanitized evidence to `evidence/A2.md` and `evidence/a2-access-summary.json`. The actual fixture data, installation manifest and raw process capture remain under the ignored owner-protected `C:\ACLAIS-Lab` tree. Review both reports; a successful provisioning command alone is not A2 evidence.

The A2 private probe is not a production tool or UI route. Its real Windows result is separate from portable CI and from future automated Windows enforcement checks.

## A3 actual Windows launcher checks

Run these commands on the provisioned demonstration machine from the ordinary, non-elevated owner session. The deployment step verifies the protected runtime inventory and refreshes the fixed private probe; it does not print or export the Credential Manager value:

```powershell
.\scripts\check_a3_windows.ps1
```

This runs the actual `AclaisWorker` logon and Job Object checks. It covers protected task configuration, safe argument passing, minimal environment, stdout/stderr draining and caps, normal exit, child cleanup, forced cancellation, deadline timeout, orderly shutdown, abrupt controller-process exit, identity mismatch and assignment failure. The harness verifies worker and child exit using process handles and confirms a separate owner process survives. Sanitized results are recorded in `evidence/A3.md` and `evidence/a3-launcher-summary.json`; no password, runtime fixture content, PID or raw worker log belongs in those files.

The portable command remains separate:

```powershell
.\scripts\check.ps1
```

It runs portable backend tests/lint plus frontend type checking/lint/build but does not run the Windows enforcement test. GitHub-hosted CI runs only the portable jobs; no self-hosted Windows runner is configured. A2 reprovisioning may replace the protected runtime manifest, so rerun `check_a3_windows.ps1` to deploy and verify the A3 probe/runtime again. Fail the checkpoint if the Windows script is skipped, run elevated against the wrong owner credential store, or cannot observe process-tree cleanup.

## Checks and verification lanes

Run the implemented portable checks from the repository root:

```powershell
.\scripts\check.ps1
```

The script syncs the locked Python environment, runs Ruff and `pytest -m portable`, checks OpenAPI generation, installs from the npm lockfile, verifies generated TypeScript, typechecks and lints the frontend, and builds the production bundle. GitHub Actions runs the same backend and frontend checks in separate portable jobs. The marker filter keeps later Windows-enforcement tests out of the portable job.

Portable checks do not run Windows enforcement tests. The A2 private demonstration-machine ACL probe passed as recorded in `evidence/A2.md`; the automated Windows enforcement lane and A3 Credential Manager/job-launcher checks remain `NOT_RUN`. Later enforcement checks must use the actual Windows account, NTFS, Credential Manager, and Job Object as required by `docs/03_BUILD_ACLAIS.md` and `docs/07_VERIFICATION_AND_HANDOFF.md`.

Regenerate API artifacts after changing backend models:

```powershell
.\scripts\generate-api.ps1
```

Review both `shared/openapi.json` and `frontend/aclais/src/generated/api.ts` in the resulting diff.

## Shutdown

Stop each development server with Ctrl+C. No background worker, receiver, or production tool is created in A1.
