# Component 2 — local collection server
Prerequisite: evidence/G1.md PASS. Read 01, 02 and 07. This is a separate process with its own SQLite database, not a counter inside ACLAIS.

## Purpose
Receive a stolen seeded payload if a hostile utility actually obtains it. Supply independent persistent receipt evidence. It does not decide whether an attack was blocked and cannot alter ACLAIS incidents.

## Implementation
Use a small Python/FastAPI service at 127.0.0.1:8767. Implement /health, /ingest and the /admin routes from 02. Resolve every run by a trusted precreated run record. Ingest credential must be bound to its run. Store only a hash of the credential. Reject unknown runs, wrong credentials, malformed base64, payloads over 1 MiB, wrong run IDs for the supplied credential, and unknown fields. Task IDs remain client attribution per 02; do not add an undocumented task registration API.

On ingestion compute receipt UUID, UTC time, decoded byte count, SHA-256 and whether the exact registered canary bytes are present. Persist before returning 201. Do not trust a client-supplied hash, byte count or marker-match flag. Preserve run ID and claimed task ID; the task field is client attribution, not proof of process identity. Gate tests use known task IDs.

Store raw dummy payloads only in the receiver-owned evidence directory, never as an executable filename; use receipt UUID filenames and .bin. Apply owner-only access. Cap total run storage at 10 MiB and return 429 on exhaustion. No arbitrary file path or external forwarding feature.

Receiver admin secret is distinct from ingest. No unauthenticated list/reset/receipt endpoints. There is no product-facing reset button. Operator reset is offline CLI, verifies ownership/sentinel, requires no active associated task and archives prior receipts before deletion. Startup does not silently wipe history.

Provide a simple owner-only CLI receipt view: run, receipt count, bytes, marker present, timestamps. This is enough for presentation; optional HTML inspector is lower priority than correctness. Do not use “attack blocked” as receiver status. No receipt means only no matching receipt in this server/run.

## ACLAIS integration preparation
Controller creates run and marker through admin API, obtains/sets per-run ingest token through a protected owner-side provisioning step, and passes only ingest token to worker. Follow 02: POST /admin/runs returns the newly generated ingest token once; never include it in GET receipts.

GET receipts returns {run_id,receipts:[{receipt_id,task_id,received_at,decoded_bytes,sha256,marker_match}],marker_received:boolean}. Empty configured healthy run returns false. Unknown run returns 404. Unreachable/unauthorized/query failure remains unknown in ACLAIS.

## G2 acceptance
- Empty fresh run returns zero receipts and marker_received=false.
- Submit known dummy canary bytes; independent hash/count/match are correct.
- Submit nonmatching bytes; receipt exists but marker_match=false.
- Wrong ingest token, cross-run token, invalid base64 and oversized payload are rejected with no stored receipt.
- Ingest token cannot access admin routes or clear evidence.
- Restart preserves receipts; failed persistence cannot return success.
- Listener is loopback-only; no payload/secret appears in routine logs.
- ACLAIS receiver adapter distinguishes healthy empty, positive receipt, unknown run and receiver outage.

Write evidence/G2.md and mark PASS before building Document Tools. G2 adapter checks may add receiver integration tests to ACLAIS, but must not weaken G1.
