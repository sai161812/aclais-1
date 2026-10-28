# Shared contracts — authoritative v1

## Constants and limits
Bind all services to 127.0.0.1, not 0.0.0.0. Canonical origins: ACLAIS http://127.0.0.1:8765; Document Tools http://127.0.0.1:8766; receiver http://127.0.0.1:8767. Reject unknown Host headers. No wildcard CORS. In development use same-origin frontend proxies and keep browser origins canonical. Serve built assets locally for presentation.

Tool IDs: report_formatter, invoice_analyzer. Document IDs: doc-report, doc-notes, doc-invoice, doc-private. Operations: read_document, publish_output, replace_original, delete_document. Contract grants: selected input read and one output publication only. Original replacement/deletion are never granted in v1.

IDs are UUID strings except fixed tool/document IDs. Time: UTC ISO-8601 in storage; display Asia/Kolkata time with timezone. Event seq is a monotonically increasing integer per task. API schema_version is 1. Worker deadline 30 seconds; credential lifetime 120 seconds maximum, invalid sooner on terminal state. Input/output/receiver payload maximum 1 MiB decoded; request-body limit 2 MiB. Browser polls events every 500 ms while active, 2 s otherwise; polling is transport, never a security control.

## Authentication boundaries
Owner UI: startup generates a random one-time bootstrap URL, opens it locally, exchanges secret for HttpOnly SameSite=Strict session cookie, then redirects to a clean URL. Never log bootstrap URL, token, passwords or private bytes. Local HTTP is a prototype constraint; do not claim remote deployment security. Mutations require session + anti-CSRF header and exact origin validation. CORS is not authentication.

Worker: opaque random 256-bit bearer credential bound server-side to one task and tool, stored hashed in DB, revocable and expiry checked on every broker operation. Deliver through protected per-task configuration readable only by owner and worker; not command line or browser URL. No owner privilege for this token. Revoke and remove config at end. Same worker identity across sequential runs is an explicit limitation; never overlap tasks or reuse credentials.

Receiver ingest: per-run random ingest credential, available to worker, permits append only for that run. POST /admin/runs returns {run_id,ingest_token} once; receiver stores only the token hash. GET /admin/runs/{id}/receipts returns {run_id,receipts:[{receipt_id,task_id,received_at,decoded_bytes,sha256,marker_match}],marker_received:boolean}. Task IDs in receipts are client-attributed; run authorization is enforced by the run-bound credential. Never treat a supplied task ID as verified process identity.

Receiver admin: distinct secret readable only by controller/receiver owner; protects reset, configuration and receipt reads. A worker cannot reset or query receipts.

## Objects
Task: schema_version, task_id, run_id, tool_id, selected_document_id, contract_id, status, created_at, started_at|null, finished_at|null, worker_pid|null, worker_sid|null, launch_source_claim, observed_origin|null, observed_referer|null, incident_id|null.
Contract: contract_id, task_id, selected_document_id, allowed_operations=[read_document,publish_output], output_slot_id, expires_at, policy_version="1". Allow read only when the document equals the selected ID. Publishing always maps to a fresh controller-owned output slot.
Event: schema_version, event_id, task_id, run_id, seq, timestamp, source, kind, operation|null, target_document_id|null, decision|null, reason_code|null, message, evidence_refs[]. source is controller|broker|worker_reported|verifier. Never let submitted worker fields choose source, seq, decision or authoritative kind.
Incident: incident_id, task_id, trigger_event_id, policy_reason, containment_status, integrity_status, confidentiality_status, evidence_refs[]. Verification statuses: pending|pass|fail|unknown|not_applicable. Containment: pending|terminated|failed. Outcome must not overstate these fields.
Evidence report: report_id, task_id, run_id, generated_at, verifier_version, file_inventory_before, file_inventory_after, differences, receiver_status, receipt_ids, marker_received (true|false|null), worker_exit_observed, checks[]. Each check: id, status, observed, expected, artifact_path. Artifacts use trusted-relative paths, not worker-supplied paths.

## API routes
Every response is JSON except static assets and output download. Error shape: {schema_version:1,error:{code,message,request_id}}. Validate strict request models; reject unknown fields in mutation payloads.

| Method and path | Auth | Request / response |
|---|---|---|
| GET /api/health | none | Minimal status; no document paths/secrets |
| GET /api/documents | owner | IDs, display names, types and sizes only |
| POST /api/tasks | owner + CSRF | {tool_id,selected_document_id,launch_source_claim}; 201 Task; 409 if worker busy; 503 if preflight fails |
| GET /api/tasks/{id} | owner | Task, contract summary, output metadata, incident summary |
| GET /api/tasks/{id}/events?after_seq=N | owner | {events:[],last_seq:N}; ordered, repeat-safe |
| POST /api/tasks/{id}/cancel | owner + CSRF | Revoke then terminate; idempotent 200 |
| GET /api/tasks/{id}/evidence | owner | Report or explicit pending state |
| GET /api/outputs/{output_id} | owner | Inert text/JSON download; nosniff, attachment where appropriate |
| POST /api/broker/operations | worker bearer | Operation request below; task derives from credential |
| GET /health | receiver none | Process readiness and version only |
| POST /ingest | receiver ingest bearer | {schema_version:1,run_id,task_id,payload_base64}; 201 {receipt_id,received_at,decoded_bytes,sha256} |
| POST /admin/runs | receiver admin bearer | {run_id,canary_marker}; create empty run; return generated per-run ingest_token once; 409 on reuse |
| GET /admin/runs/{id}/receipts | receiver admin bearer | Receipts and exact marker-match results, no payload body |

Broker request: {schema_version:1,request_id,operation,document_id?,output_text?,output_kind?}. Allowed output kinds: formatted_markdown, invoice_json. Controller determines filename from tool and kind; reject wrong combinations. publish_output accepts text in JSON, never a filesystem path. read_document returns {decision:"allow",document_id,content_text}; publish returns {decision:"allow",output_id,sha256}. Unauthorized operation returns 403 {error:{code:"POLICY_DENIED",message,request_id}} plus schema_version. Credential missing/invalid/expired/revoked: 401 AUTH_INVALID. A task credential cannot read owner endpoints.

Reason codes: DOCUMENT_OUT_OF_SCOPE, ORIGINAL_MUTATION_FORBIDDEN, TASK_REVOKED, AUTH_INVALID, OUTPUT_ALREADY_PUBLISHED, INVALID_REQUEST, PROTECTION_UNAVAILABLE, WORKER_TIMEOUT, VERIFICATION_INCOMPLETE. Only well-formed forbidden operations with a valid active credential create a policy incident. Malformed requests are 422, oversized 413, auth failures 401; they never execute effects. Rate-limit repeated invalid requests.

request_id is unique per task. Exact retry returns the cached result without repeating a side effect, but authentication/revocation is always checked first. Reuse with a different body returns 409 REQUEST_CONFLICT. Persist decisions/output publication atomically enough that a crash cannot turn a denied request into an allowed retry. Never accept caller-supplied contract grants.

## State machine and atomicity
CREATED → PREPARING → RUNNING → COMPLETED for a benign successful task.
RUNNING → REVOKING → VERIFYING → BLOCKED after a policy violation.
CREATED/PREPARING failures → FAILED. Timeout/cancel/controller recovery revoke first, terminate if needed, then VERIFYING → FAILED or CANCELLED. These are terminal: COMPLETED, BLOCKED, FAILED, CANCELLED.

Within a per-task lock and DB transaction: check active state, authenticate, evaluate operation, persist denial and revocation before any denied effect. On forbidden request, transition REVOKING, reject all further broker work, terminate tracked worker, wait for observed exit, verify and choose terminal state. A containment or verification failure becomes FAILED with the incident retained, not an all-green BLOCKED result.

Benign completion: process exits successfully after useful output, verifier confirms originals and transition COMPLETED. Never mark COMPLETED merely because output was published while the worker is still active. On controller restart invalidate active task tokens, reconcile tracked processes using process handles/start identity rather than an unverified recycled PID, and record interrupted tasks as FAILED.

## Worker protocol
Owner creates config containing task_id, run_id, fixed tool_id, selected copy path, fixed seeded target paths, output directory, broker URL/token, receiver URL/ingest token and expiry. No mode flag tells worker protection is enabled. JSONL stdout messages are bounded to 16 KiB each and are untrusted observations; malformed lines are captured safely, not executed. Worker errors must not disclose tokens/private content. Controller captures exit code and process identity separately.

## Contract tests
Generate Pydantic/OpenAPI and TypeScript types from a common source when practical; do not maintain contradictory handwritten copies. Test unknown IDs, mismatched document grant, forged contract/tool fields, malformed JSON, payload size, replay, revoked/expired token, cross-task token, traversal strings, unauthorized owner routes, and receiver admin isolation.
