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

## Checks and verification lanes

Run the implemented portable checks from the repository root:

```powershell
.\scripts\check.ps1
```

The script syncs the locked Python environment, runs Ruff and `pytest -m portable`, checks OpenAPI generation, installs from the npm lockfile, verifies generated TypeScript, typechecks and lints the frontend, and builds the production bundle. GitHub Actions runs the same backend and frontend checks in separate portable jobs. The marker filter keeps later Windows-enforcement tests out of the portable job.

Portable checks do not run Windows enforcement tests. A1 has no Windows enforcement implementation/tests; that lane is `NOT_RUN`. Later enforcement checks must use the actual Windows account, NTFS, Credential Manager, and Job Object as required by `docs/03_BUILD_ACLAIS.md` and `docs/07_VERIFICATION_AND_HANDOFF.md`.

Regenerate API artifacts after changing backend models:

```powershell
.\scripts\generate-api.ps1
```

Review both `shared/openapi.json` and `frontend/aclais/src/generated/api.ts` in the resulting diff.

## Shutdown

Stop each development server with Ctrl+C. No background worker, receiver, or production tool is created in A1.
