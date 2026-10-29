# ACLAIS local development runbook

## Protected G1 operator commands

From any directory, use `& '<repository-root>\scripts\aclais.ps1' -Action doctor|start|stop|reset|teardown` with exactly one action. These commands delegate to `aclais/scripts/manage.ps1`; they use the sentinel-owned `C:\ACLAIS-Lab` and ordinary owner session. `start` stays in the foreground, opens the one-time owner bootstrap locally, and stops with Ctrl+C. `stop` verifies the recorded owner PID, creation time and instance before requesting shutdown and waiting for observed process exit. It never kills a port owner or unrelated process. A duplicate controller or occupied port fails.

`doctor` measures core SID/non-admin, DACLs, fixture/code inventory, credential retrieval, database integrity/migration version, and kill-on-close Job Object configuration. Fresh core checks also precede admission; each launch separately verifies suspended-process identity and actual job assignment. A passing historical G1 gate does not make absent G3 production workers ready. Until those fixed entrypoints are installed, health remains **unavailable** with `g1_protection=unknown`, and product launch refuses without creating a task. The unprotected development health process never claims enforcement.

`reset` refuses a live controller, worker, or nonterminal task. It archives raw evidence and a consistent database backup, restores only fixed synthetic fixture templates, rotates the private canary, and retains task history. A protected reset journal permits recovery of interrupted multi-file changes; unresolved recovery blocks startup. Do not edit the manifest/baseline to turn changed files green. Raw archives, databases, credentials and fixture contents remain outside Git.

`teardown -ConfirmRootId '<exact-owned-sentinel-root-id>'` refuses an incorrect identity or active work. It restores recorded checkout DACLs, removes only the recorded owner Credential Manager entry, and archives the owned lab beside its original location rather than deleting evidence. An interrupted retirement blocks startup and can be retried. The initial installation did not record whether the local account preexisted; teardown therefore retains that account. Account deletion is a separate administrative decision. The G1 audit tests scoped retirement on disposable owned fixtures; it does not uninstall the active demonstration environment.

Run the complete local lanes separately:

```powershell
& '<repository-root>\scripts\check.ps1'
& '<repository-root>\aclais\scripts\check_g1_windows.ps1'
```

The first is portable and cannot establish Windows security. The second must run on the designated provisioned Windows/NTFS machine, refreshes fixed private probes, measures real worker access before and after tests, rejects skipped target tests, and records `evidence/g1-check-summary.json`. Raw JUnit and inventory records remain owner-protected locally. Isolated `windows_ui` contract fixtures run separately and are visibly labeled; they never establish enforcement or receiver integration. Runtime assets are local and require no font/CDN access. See `evidence/G1.md` for the requirement matrix, exact tested source digest, actual counts and limitations.

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

## Start the connected ACLAIS owner dashboard

Build the frontend bundle from the repository root. The protected controller serves the built application and its assets from its own authenticated origin; no browser API proxy is used.

```powershell
npm --prefix .\aclais\frontend run build
$env:ACLAIS_PROTECTED_RUNTIME = 'true'
.\scripts\start.ps1 -Service Backend
```

Run this connected dashboard only after the A2 protected runtime has been provisioned on the demonstration machine. The controller opens the one-time owner bootstrap link. After sign-in, open `http://127.0.0.1:8765/owner`. The direct health URL is `http://127.0.0.1:8765/api/health`. The production worker routes remain closed until their G3 entrypoints pass the required gate.

For source editing, `scripts/start.ps1 -Service Frontend` runs Vite at `http://127.0.0.2:5173` as an unauthenticated visual preview. It has no API proxy and cannot display owner data. This separate loopback host prevents the preview from receiving cookies scoped to `127.0.0.1`; browser cookies are scoped by host, not port. Use the connected dashboard at port 8765 for real task state, approval and evidence. Do not put the owner session on a same-host dev server.

From any other directory use `& '<repository-root>\scripts\start.ps1' -Service Backend` or `-Service Frontend`. Install the locked dependencies with the root check command first. Servers run in the foreground with live output and stop with Ctrl+C. Startup failures and occupied ports are reported without terminating an existing port owner. Vite uses strict port 5173 and does not silently choose another port. The receiver is a separate foreground service after its G2 checkpoint; Document Tools remains gated on G2.

## Local receiver (G2)

The receiver is independent from ACLAIS and listens only at `[::1]:8767`. It has no browser UI, CORS grant, owner-cookie access, or route that changes ACLAIS decisions. The Windows runtime is fixed at `C:\ACLAIS-Lab\state\receiver`, outside Git. From the ordinary owner session, initialize it once with `& '<repository-root>\receiver\scripts\receiver.ps1' -Action init`. The generated `admin.token`, database, raw payloads, staging files and quarantine remain owner-protected at that runtime location; initialization never prints or replaces the credential.

Start it in the foreground using `& '<repository-root>\scripts\start.ps1' -Service Receiver` and stop with Ctrl+C. A busy port fails without terminating its existing owner. Inspect only receipt metadata with `& '<repository-root>\receiver\scripts\receiver.ps1' -Action inspect -RunId '<canonical-run-uuid>'`. There is no online reset or payload-download command. Root `scripts/check.ps1` runs portable ACLAIS and receiver checks plus live local receiver/adapter integration. Run `receiver/scripts/check_windows.ps1` separately on the provisioned Windows/NTFS machine from the non-elevated owner session; it audits the actual protected receiver store against the current owner, SYSTEM, Administrators, and configured worker SID, then uses the real service for HTTP receipt, denial, restart, retry, storage-failure and recovery checks. Sanitized outcomes are recorded in `evidence/G2_HTTP_AUDIT.json`; raw payloads, receipts, credentials and captured logs stay out of Git. Portable CI does not establish Windows ACL enforcement. The ACLAIS adapter reads actual receiver health/receipt responses; production run creation and delivery of per-run ingest credentials remain pending G4.

## Configuration and logging

Supported environment variables are `ACLAIS_HOST`, `ACLAIS_PORT`, `ACLAIS_LOG_LEVEL`, and `ACLAIS_PROTECTED_RUNTIME`. Defaults are `127.0.0.1`, `8765`, `INFO`, and `false`. The host is restricted to `127.0.0.1`; the port must be decimal and in the range 1024–65535; log level must be DEBUG, INFO, WARNING, or ERROR; protected runtime accepts only `true` or `false`. Unknown `ACLAIS_` variable names and invalid values stop startup. A `.env` file is not loaded.

PowerShell example:

```powershell
$env:ACLAIS_HOST = '127.0.0.1'
$env:ACLAIS_PORT = '8765'
$env:ACLAIS_LOG_LEVEL = 'INFO'
$env:ACLAIS_PROTECTED_RUNTIME = 'false'
```

On the provisioned A2/A3 Windows machine, `ACLAIS_PROTECTED_RUNTIME=true` assembles the worker controller, broker and persistence, runs restart reconciliation before the API serves requests, and keeps the broker unavailable if recovery fails. The ACLAIS frontend bundle is resolved from the component location and served from the protected controller origin. The A2 ACL covers the generated `aclais/frontend/dist` bundle as application code; rebuilds retain its inherited worker deny rule. Production launch remains closed while the fixed G3 worker entrypoints are absent. The health response remains `unknown` for overall G1 protection until A7–A10 verification gates pass.

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

## A5 broker and publication checks

Run from any directory:

```powershell
& 'D:\Workspace\IDL\ACLAIS-1\scripts\check.ps1'
```

The portable check includes the A5 broker and publication filesystem/journal tests. It does not establish Windows containment or NTFS enforcement. Run that separate lane on the demonstration Windows machine:

```powershell
Set-Location 'D:\Workspace\IDL\ACLAIS-1\aclais\backend'
uv run --locked pytest -m windows_enforcement tests/test_publication.py --tb=short
```

The A5 broker API is mounted only by injecting a trusted `BrokerService`. In the protected runtime, output downloads and task/evidence reads use A8's persisted owner session; a browser owner cookie is never a worker credential. Portable A5 contract tests use private injected services, while A8's owner route tests exercise the real session and CSRF gates.

## A6 lifecycle and recovery checks

Run the target-machine lane from the ordinary, non-elevated owner session on the provisioned demonstration machine:

```powershell
& 'D:\Workspace\IDL\ACLAIS-1\aclais\scripts\check_a6_windows.ps1'
```

The script refreshes and reruns the fixed A3 worker probe, then runs the real A6 lifecycle tests. Those tests exercise brokered completion, denial and credential revocation, per-task selected-copy/output ACLs, single-worker admission, cancellation, deadline, a worker crash with a child, orderly shutdown, cancellation/process-exit and timeout/completion races, and abrupt controller death followed by startup reconciliation. They record worker/child PID, SID and process creation identities only in temporary owner-protected test state and verify actual process exit with Windows process handles. Test databases, task workspaces, task configuration and marker files are removed after the run; no credential values or runtime fixture contents are committed. A failure to start, stop or reconcile is a failed enforcement check. Portable CI does not run this lane.

The A6 report at `evidence/A6.md` is a historical record of that checkpoint and its then-current limitations. A7 verification status is recorded separately in `evidence/A7.md`.

## A7 verification and evidence checks

Run portable contract, inventory, receiver-adapter and persistence tests with the root command:

```powershell
& 'D:\Workspace\IDL\ACLAIS-1\scripts\check.ps1'
```

Run the target-machine evidence lane from the ordinary, non-elevated owner session:

```powershell
& 'D:\Workspace\IDL\ACLAIS-1\aclais\scripts\check_a7_windows.ps1'
```

This invokes the A3 prerequisite and actual A6 worker lifecycle suite. It inspects evidence only after confirmed worker/job cleanup, compares protected fixture inventories and output hashes, and checks controller/broker/verifier attribution. Hosted portable CI does not run these Windows enforcement checks.

Raw inventories and captured worker output stay under the protected local runtime path C:\ACLAIS-Lab\evidence\raw. Track only sanitized summaries under `evidence/`; reports identify the tested code revision or source digest and contain no raw fixture names/hashes, receipt IDs, worker text, runtime paths or credentials. Do not mark receiver-dependent incident confidentiality as pass when no run or an unknown/outage response is available.

## A8 owner authentication and approval

Protected startup creates a one-time bootstrap URL only when no owner session remains active. The token is in the URL fragment, is exchanged once at the exact ACLAIS origin, and is removed from browser history. Persisted storage contains only bootstrap/session/CSRF hashes. The owner cookie is host-only for `127.0.0.1`; the receiver must remain on `[::1]:8767` because HTTP cookies ignore ports. Never copy a bootstrap URL, cookie or worker token into an issue, log or evidence report.

Run portable route and abuse checks from any directory through the root check command:

```powershell
& 'D:\Workspace\IDL\ACLAIS-1\scripts\check.ps1'
```

On the designated Windows machine, while the protected A2 runtime is provisioned and the ACLAIS/tool/receiver ports are free, run the actual Chrome and Edge browser lane from any directory:

```powershell
& 'D:\Workspace\IDL\ACLAIS-1\aclais\scripts\check_a8_windows.ps1'
```

The private harness starts ACLAIS on `127.0.0.1:8765`, test-only hostile web origins on `localhost:8766`, and an IPv6 receiver-origin probe at `[::1]:8767`. It verifies no owner cookie reaches either other host; cross-origin API attempts have no owner credential; a cross-host top-level approval GET makes no task; and the explicit owner button launches only the existing harmless A3 probe in the test harness. The probe selects the trusted document, starts a child in the assigned Job Object, then the harness cancels and verifies the actual worker and child process identities stopped before checking persisted evidence. The harness does not add a production tool or a production receiver.

`launch_source_claim` is user-supplied attribution. Observed Origin and referrer headers are recorded separately and do not prove which site launched the task; the referrer path/query is stripped. The fixed production registry only accepts installed Document Tools entrypoints by exact tool/document pair. Since G3 workers are not installed, a production approval POST returns protection unavailable without creating a task. The demonstration test injects a private probe callback only in its test process.

## A9 connected dashboard checks

Run portable checks from any directory with `scripts/check.ps1`. On the provisioned Windows demonstration machine, run the real-backend Chrome flow from any directory:

```powershell
& '<repository-root>\aclais\scripts\check_a9_windows.ps1'
```

The private browser test uses a fresh disposable SQLite database, the protected seeded documents, the actual ACLAIS APIs, and the existing A3 private probe. It checks keyboard approval, side-effect-free approval-page loading, rendered inert output, event sequence order before and after refresh and on Activity, disconnection and reconnection, an unavailable preflight response, cancellation with verified worker termination, and a policy-denial incident with pending then completed verifier evidence. It captures sanitized screenshots at 1366x768 and 1920x1080 plus one reduced-motion screenshot. The test-only health response is used only to exercise unavailable-state rendering; production status always comes from backend responses. A9 does not claim a verified incident when the real receiver adapter leaves confidentiality unknown.

The frontend preview binds to `127.0.0.2:5173` and has no API proxy. Only the built owner UI served from `127.0.0.1:8765` is connected. During an outage, the UI clears green protection status and marks active task progress as disconnected; after refresh it rebuilds state from persisted task, event, incident and evidence responses.


Source protection includes the owned checkout root and Git metadata. Controller-held Windows directory handles prevent source-ancestor rename while workers can run; their handles are non-inheritable and close after verified shutdown. The audit changes no ACL outside the owned project. Repeated package installation can produce mixed ACL ordering; the scoped protector canonicalizes existing ACEs without dropping their rights before reapplying worker denial. Do not bypass this protection because source-file reads alone pass.


For G1 browser revalidation, distinguish native readiness-response time from browser rendering time. The private UI test awaits the real bounded health response before checking reconnection; it retains the five-second DOM-state assertion. It uses the specified 30-second worker ceiling and explicitly cancels/observes process termination before later health-state presentation checks. No worker deadline is paused or extended while the UI is disconnected, and no health or enforcement result is substituted for the real native checks. See D-049 for the reproduced failure and correction.
