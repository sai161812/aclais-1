# Component 2 — local collection server
Prerequisite: evidence/G1.md PASS. Read 01, 02 and 07. This is a separate process with its own SQLite database, not a counter inside ACLAIS.

Keep receiver source, tests, receipt inspection tools, dependencies and component-specific configuration inside `receiver/`. Keep its live database and raw receipt payloads in the designated protected runtime location outside Git. Do not add receiver production implementation before ACLAIS G1 passes. Root `tests/` remains reserved for cross-component integration and acceptance tests.

## Purpose
Receive a stolen seeded payload if a hostile utility actually obtains it. Supply independent persistent receipt evidence. It does not decide whether an attack was blocked and cannot alter ACLAIS incidents.

## Implementation
Use a small Python/FastAPI service at `[::1]:8767` only. Do not bind `127.0.0.1`, which is reserved for ACLAIS's owner cookie host; port separation does not isolate cookies. Implement /health, /ingest and the /admin routes from 02. Resolve every run by a trusted precreated run record. Ingest credential must be bound to its run. Store only a hash of the credential. Reject unknown runs, wrong credentials, malformed base64, payloads over 1 MiB, wrong run IDs for the supplied credential, and unknown fields. Task IDs remain client attribution per 02; do not add an undocumented task registration API.

On the demonstration Windows host, use the fixed runtime root `C:\ACLAIS-Lab\state\receiver`, outside the checkout. Its `receiver.sqlite3`, one-time `admin.token`, `payloads`, `staging`, and `quarantine` are protected before the service listens. The DACL is protected from parent inheritance and allows only the current owner, SYSTEM, and local Administrators; verify that the configured non-admin ACLAIS worker SID is absent. Do not print or commit the generated admin credential. The service has no browser origin and serves no HTML.

On ingestion compute receipt UUID, UTC time, decoded byte count, SHA-256 and whether the exact registered canary bytes are present. Do not trust a client-supplied hash, byte count or marker-match flag. Preserve run ID and claimed task ID; the task field is client attribution, not proof of process identity. Gate tests use known task IDs.

Store raw dummy payloads only in the receiver-owned evidence directory, never as an executable filename; use receipt UUID filenames and `.bin`. Apply the owner-only protected DACL above. Cap total run storage at 10 MiB and return 429 `RATE_LIMITED` on exhaustion. No arbitrary file path or external forwarding feature.

The receiver database and payload file are separate stores, so use the receipt journal and crash-recovery protocol in `02_SHARED_CONTRACTS.md`. Reserve `(run_id,request_id)` and the canonical body hash in a DB transaction before writing. Create an exclusive same-volume staging file, write/flush/hash it, move it to its unique receipt name without replacement, then commit the receipt row before returning 201. The receipt query returns only committed rows whose file size/hash match. On restart reconcile pending rows before serving requests; a valid renamed file can be committed once, a partial staging file is removed/quarantined, and missing/mismatched committed payloads make the run unknown/error rather than empty. Never return success before both the payload and receipt row are durable.

Ingest retries must include the same client-generated `request_id`: identical validated body returns the original receipt without adding a second file/row; changed body with the same ID returns 409 `REQUEST_CONFLICT`. Authenticate the run-bound token before replay lookup. A retry after receiver restart follows the same rule and never trusts a caller-supplied receipt ID.

Receiver admin secret is distinct from ingest. No unauthenticated list/reset/receipt endpoints. There is no product-facing reset button. Operator reset is offline CLI, verifies ownership/sentinel, requires no active associated task and archives prior receipts before deletion. Startup does not silently wipe history.

Provide a simple owner-only CLI receipt view: run, receipt count, bytes, marker present, timestamps. This is enough for presentation; optional HTML inspector is lower priority than correctness. Do not use “attack blocked” as receiver status. No receipt means only no matching receipt in this server/run.

Use `receiver/scripts/receiver.ps1 -Action init` once to create runtime storage and a distinct random administrator credential; the command never prints the secret or replaces an existing credential. Use `-Action inspect -RunId <canonical-uuid>` for the local owner-only metadata summary. `scripts/start.ps1 -Service Receiver` starts the fixed service in the foreground; it refuses an occupied port and does not terminate its owner. There is no online reset or payload-download route.

## ACLAIS integration preparation
Controller creates run and marker through admin API, obtains/sets per-run ingest token through a protected owner-side provisioning step, and passes only ingest token to worker. Follow 02: POST /admin/runs returns the newly generated ingest token once; never include it in GET receipts.

GET receipts returns {run_id,receipts:[{receipt_id,task_id,received_at,decoded_bytes,sha256,marker_match}],marker_received:boolean}. Empty configured healthy run returns false. Unknown run returns 404. Unreachable/unauthorized/query failure remains unknown in ACLAIS.

The ACLAIS adapter is read-only: it checks health and reads receipt summaries using the owner-only admin credential. It maps a healthy empty run, positive marker, unknown run, authentication failure, invalid response, and unavailable service to distinct evidence outcomes. A positive marker is a confidentiality failure; it does not create or alter an ACLAIS policy incident and can never be reported as “blocked.” ACLAIS run creation, marker provisioning, and protected delivery of per-run ingest credentials to a production worker remain the later integrated G4 handoff.

## G2 acceptance
- Empty fresh run returns zero receipts and marker_received=false.
- Submit known dummy canary bytes; independent hash/count/match are correct.
- Submit nonmatching bytes; receipt exists but marker_match=false.
- Retry the same request ID/body before and after restart; the same single receipt is returned. Reuse that request ID with a changed body; 409 and no new file/receipt.
- Wrong ingest token, cross-run token, invalid base64 and oversized payload are rejected with no stored receipt.
- Ingest token cannot access admin routes or clear evidence.
- Restart preserves receipts; failed persistence cannot return success.
- Inject failures before staging, after file flush, after rename and before DB commit; recovery yields one committed matching receipt or an explicit unknown/error, never duplicate receipts or a false empty run.
- Listener is loopback-only; no payload/secret appears in routine logs.
- ACLAIS receiver adapter distinguishes healthy empty, positive receipt, unknown run and receiver outage.

Write evidence/G2.md and mark PASS before building Document Tools. G2 adapter checks may add receiver integration tests to ACLAIS, but must not weaken G1.
