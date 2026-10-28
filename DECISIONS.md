# Decisions

This log records the workflow/specification decisions for A0 and the foundation choices for A1. G1 enforcement and later production components remain unimplemented.

## D-001 — Preserve the supplied specification pack

The nine files in `docs/` are the project authority for scope, contracts, component order, interface behavior, and verification. Keep the three components in this repository and implement only the explicitly requested checkpoint.

## D-002 — Use the explicitly supplied GitHub repository

The user supplied `https://github.com/sai161812/aclais-1.git`. Authenticated GitHub metadata verified owner `sai161812`, repository `aclais-1`, public visibility, and default branch `main` before the first push. The repository had no branches or commits, so the documentation-only baseline was created on local `main` before `aclais-prototype`. After the first push to the empty remote, GitHub reports `aclais-prototype` as the current default; no settings API was used. Do not create another repository or replace a remote.

## D-003 — Keep this checkpoint documentation-only

A0 was limited to readiness and specification reconciliation, including affected specs, decisions, build status, and the A0–A10 plan; it implemented no application code. Later checkpoints follow the sequence in `IMPLEMENTATION_CHECKPOINTS.md` and require their listed prerequisites.

## D-004 — Track safe templates and summaries; ignore sensitive runtime material

Ignore credentials, local environments, runtime databases, raw receipt payloads, generated confidential fixtures, unsanitized logs, and build/test output. Keep synthetic fixture templates and sanitized test summaries trackable.

## D-005 — Isolate browser owner cookies by host

Keep all listeners loopback-only, but serve ACLAIS at `127.0.0.1:8765` and Document Tools at `localhost:8766`. Bind Document Tools to `127.0.0.1` and `::1` only because Windows resolves `localhost` to both addresses. HTTP cookies are not scoped by port, so the distinct hostnames prevent the browser from sending ACLAIS's host-only owner cookie to Document Tools. Use `SameSite=Lax` because the approved launch is a side-effect-free cross-host top-level GET; retain exact-Origin and anti-CSRF checks for mutations. Keep the receiver server-to-server at `127.0.0.1:8767`.

## D-006 — Retrieve the worker logon secret from the owner's Credential Manager

Provision an owner-only generic credential and retrieve it with `CredReadW` at launch. Pass the local account to `CreateProcessWithLogonW` as a real user logon; do not use network-credentials-only mode, a shell, command-line password, inherited environment, or owner-identity fallback. Start suspended, verify SID/non-admin token, assign to a kill-on-close/no-breakaway Job Object, then resume. Capture stdout and stderr on separate bounded pipes.

## D-007 — Journal filesystem publication and retries

SQLite and NTFS are separate transactions. For controller outputs and receiver receipts, commit an intent/idempotency row first, write and flush an exclusive same-volume staging file, move to a unique final name without replacement, verify hash/size, and commit the published/receipt row before returning success. On restart reconcile journals fail closed; API reads expose only finalized rows with matching files. Bind retries to request ID plus canonical body hash.

## D-008 — Serialize lifecycle outcomes under one task lock

Serialize broker admission, policy denial, cancellation, timeout, process exit, shutdown and recovery under a per-task lock. A policy denial admitted while the task is active commits revocation before later contenders; an already committed cancellation/timeout/shutdown cannot be replaced. Deadline checks occur before new operations at the boundary. Normal completion waits for process exit and in-flight broker requests. Terminal cause is immutable.

## D-009 — Use strict operation-specific models

Every JSON route has strict request and response schemas with extra fields/coercion rejected. Broker requests use a discriminated union so each operation has exactly its permitted fields. Malformed requests return validation errors with no side effect; well-formed forbidden operations return policy denial and create an incident only while the task remains active. Receiver ingest also has request-ID idempotency.

## D-010 — Make the dashboard's data path explicit

Add `GET /api/tasks?limit=N` for bounded recent-task summaries. Map each dashboard screen/action to exact ACLAIS health, document, task, event, evidence, output and cancel routes in `06_UI_DESIGN.md`; render only persisted backend states.

## D-011 — Keep G1 probes private and test-only

Before receiver and Document Tools exist, G1 tests ACLAIS with small private probes and disposable fixtures under test paths. Do not register, package or expose probes as production tools or UI, and do not implement later hostile worker behavior early. Receiver-dependent G1 states use explicitly labeled injected test data only; G4 uses the real receiver.

## D-012 — Separate verification environments

Report portable CI, Windows-specific automated checks and mandatory demonstration-machine checks in separate lanes. Portable checks never prove Windows enforcement. A G1 pass requires all mandatory checks across the lanes, including real browser-origin isolation and real ACL/job behavior on the demonstration machine.

## D-013 — Keep the specification pack in its supplied folder layout

Retain all nine specifications under `docs/`. Root documentation must link to `docs/00_START_HERE.md`; do not move the pack to `docs/spec/`. Build sequence is defined in root `IMPLEMENTATION_CHECKPOINTS.md` and does not change the three-component scope or G1→G2→G3 order.

## D-014 — Use locked project-local development environments

Keep the Python controller project in `backend/aclais` with its PEP 621 `pyproject.toml` and committed `uv.lock`; keep the React/TypeScript dashboard in `frontend/aclais` with exact package versions and committed `package-lock.json`. Use Python 3.12 and the observed Node 24/npm environment. Keep virtual environments and installed packages ignored and local to their component directories.

## D-015 — Generate shared API artifacts from backend models

Backend Pydantic response models are the A1 schema source. Generate the tracked `shared/openapi.json` artifact from FastAPI OpenAPI, then generate frontend TypeScript declarations from that shared document. Check both generation steps for stale committed output. Extend this source as API contracts are implemented; do not maintain a second handwritten copy.

## D-016 — Keep A1 readiness and logs truthful

Validate only the supported `ACLAIS_` configuration keys and bind the API to `127.0.0.1` with an exact Host allowlist. The minimal health response may report that the API process responds, while G1 protection remains `unknown` and `protection_ready` is false. Emit structured JSON logs with key-based field redaction, full cookie-header and common token-pattern redaction, omit exception text, and never log request bodies or secrets.

## D-017 — Keep portable CI separate and read-only

Run real backend lint/tests and frontend API-type check, typecheck, lint and build in separate GitHub-hosted Ubuntu jobs. Grant only `contents: read`, pin each action to a verified full commit SHA, bound job timeouts, disable persisted checkout credentials, and provide no deployment credentials. Use ordinary `pull_request`, never a privileged pull-request event. These jobs establish portable checks only; Windows enforcement remains its own real-target lane.
