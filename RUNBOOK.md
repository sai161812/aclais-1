# ACLAIS local development runbook

## Repository layout

This is one repository for all three components. ACLAIS source, tests, tools, and dependencies live in `aclais/`; the later receiver and Document Tools source roots are `receiver/` and `document-tools/`; `shared/` holds minimal shared schemas/protocols. Root `tests/` is for cross-component acceptance and root `scripts/` is for whole-system orchestration. Protected fixture data, local credentials, databases, raw logs, and installed worker code remain in their designated runtime locations outside Git.

## Prerequisites

- Windows 11, Python 3.12, `uv` 0.12.15 or compatible, Node.js 24, and npm 11.
- Git checkout of the repository. Python and npm dependencies are pinned by `aclais/backend/uv.lock` and `aclais/frontend/package-lock.json`.

The development machine has Python 3.12.10, `uv` 0.12.15, Node.js 24.19.0, and npm 11.17.0. Application development servers bind loopback only.

## Install environments

From any PowerShell working directory, use the repository-root orchestration command:

```powershell
& '<repository-root>\scripts\check.ps1'
```

For dependency installation only, from the repository root:

```powershell
uv --directory .\aclais\backend sync --locked
npm --prefix .\aclais\frontend ci
```

The backend virtual environment is `aclais/backend/.venv` and is ignored by Git. Frontend packages are installed under `aclais/frontend/node_modules`, also ignored.

## Start the ACLAIS shell

Use two PowerShell terminals. Run these repository-root commands; they resolve component locations from the scripts themselves and leave the caller's working directory unchanged.

Backend terminal:

```powershell
.\scripts\start.ps1 -Service Backend
```

Frontend terminal:

```powershell
.\scripts\start.ps1 -Service Frontend
```

From any other directory use `& '<repository-root>\scripts\start.ps1' -Service Backend` or `-Service Frontend`. Install the locked dependencies with the root check command first. Each command runs in the foreground with live output; stop it with Ctrl+C in its terminal. A startup error returns failure; an occupied port is reported without terminating its existing owner. Frontend uses strict port 5173 and does not silently choose a different port.

Open `http://127.0.0.1:5173`. Vite proxies same-origin `/api` requests to the API at `http://127.0.0.1:8765`. The direct health URL is `http://127.0.0.1:8765/api/health`. An unavailable protection state is expected until its implementation checkpoint passes. No receiver or Document Tools service starts early.

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

From the repository root on the designated Windows demonstration machine, provision only when the owned runtime is absent or needs the documented setup. This creates or refreshes the non-administrator account, writes a newly generated secret directly to the owner's Credential Manager, seeds synthetic files under `C:\ACLAIS-Lab`, and applies owned NTFS permissions. It requires one-time elevation and refuses to run while an `AclaisWorker` process is active:

```powershell
Start-Process PowerShell -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File .\aclais\scripts\provision_a2.ps1'
```

After the protected lab already exists, do not reprovision as part of routine checks. When the private probe source changes, refresh only that allowlisted probe in the protected installation from the ordinary, non-elevated owner session. Then run the access probe:

```powershell
.\aclais\scripts\deploy_a2_probe.ps1
.\aclais\scripts\run_a2_access_probe.ps1
```

The harness retrieves the credential from the current owner's Credential Manager and passes it only through the process credential API. It records no password and passes no secret in argv/environment. Sanitized evidence is written to `evidence/A2.md` and `evidence/a2-access-summary.json`; fixture contents, installation manifest, and raw process capture remain under the ignored owner-protected `C:\ACLAIS-Lab` tree. Review both reports; successful provisioning alone is not evidence.

The A2 private probe is not a production tool or UI route. Its real Windows result is separate from portable CI and automated Windows enforcement checks.

## A3 actual Windows launcher checks

Run from the ordinary, non-elevated owner session on the provisioned demonstration machine. Deployment resolves the test probe from `aclais/tests/probes/`, verifies the protected installation inventory, and refreshes the fixed private probe in the protected runtime. It does not print or export the Credential Manager value:

```powershell
.\aclais\scripts\check_a3_windows.ps1
```

This runs the actual `AclaisWorker` logon and Job Object checks. It covers protected task configuration, safe argument passing, minimal environment, stdout/stderr draining and caps, normal exit, child cleanup, forced cancellation, deadline timeout, orderly shutdown, abrupt controller-process exit, identity mismatch, and assignment failure. The harness verifies worker and child exit using process handles and confirms an unrelated owner process survives. Sanitized results are recorded in `evidence/A3.md` and `evidence/a3-launcher-summary.json`; no password, runtime fixture contents, PID, or raw worker log belongs in those files.

## Portable checks and API generation

Run implemented portable checks from any working directory:

```powershell
& '<repository-root>\scripts\check.ps1'
```

The root command delegates to the implemented ACLAIS checks by script location. Those checks sync the locked Python environment, run Ruff and portable pytest cases, check OpenAPI generation, install from the npm lockfile, verify generated TypeScript, typecheck and lint the frontend, and build its bundle. GitHub-hosted CI runs the portable backend and frontend jobs separately. No placeholder checks are used for reserved components.

A4's SQLite migration tests create disposable databases under the test runner's temporary directory. The checked-in SQL files under `aclais/backend/src/aclais/persistence/migrations/` are versioned source; do not copy generated test databases into the protected runtime state or commit any runtime database. Pydantic models are authoritative for request, response and receiver journal schemas; regenerate `shared/openapi.json` and the TypeScript API types together after changing them.

Portable checks do not run Windows enforcement. They never imply A2/A3 enforcement passed. The automated Windows tests and demonstration-machine checks must be reported separately. There is no self-hosted Windows CI runner.

Regenerate API artifacts after changing backend models:

```powershell
.\aclais\scripts\generate-api.ps1
```

Review `shared/openapi.json` and `aclais/frontend/src/generated/api.ts` in the resulting diff.

## Shutdown

Stop each development server with Ctrl+C. The development shell does not start a receiver service or production tool. The A3 harmless private worker probes run only through their explicit test scripts.
