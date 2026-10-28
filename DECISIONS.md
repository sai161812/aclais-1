# Decisions

This log records the A0 specification decisions, A1 foundation choices, A2 protected-fixture decisions, A3 launcher choices, and repository-structure checkpoint. Later production controller components remain unimplemented.

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

## D-014 — Use locked component-local development environments

Keep the Python controller project in `aclais/backend` with its PEP 621 `pyproject.toml` and committed `uv.lock`; keep the React/TypeScript dashboard in `aclais/frontend` with exact package versions and committed `package-lock.json`. Use Python 3.12 and the observed Node 24/npm environment. Keep virtual environments and installed packages ignored and local to their component directories.

## D-015 — Generate shared API artifacts from backend models

Backend Pydantic response models are the A1 schema source. Generate the tracked `shared/openapi.json` artifact from FastAPI OpenAPI, then generate frontend TypeScript declarations from that shared document. Check both generation steps for stale committed output. Extend this source as API contracts are implemented; do not maintain a second handwritten copy.

## D-016 — Keep A1 readiness and logs truthful

Validate only the supported `ACLAIS_` configuration keys and bind the API to `127.0.0.1` with an exact Host allowlist. The minimal health response may report that the API process responds, while G1 protection remains `unknown` and `protection_ready` is false. Emit structured JSON logs with key-based field redaction, full cookie-header and common token-pattern redaction, omit exception text, and never log request bodies or secrets.

## D-017 — Keep portable CI separate and read-only

Run real backend lint/tests and frontend API-type check, typecheck, lint and build in separate GitHub-hosted Ubuntu jobs. Grant only `contents: read`, pin each action to a verified full commit SHA, bound job timeouts, disable persisted checkout credentials, and provide no deployment credentials. Use ordinary `pull_request`, never a privileged pull-request event. These jobs establish portable checks only; Windows enforcement remains its own real-target lane.

## D-018 — Protect checkout source and evidence with a worker-specific deny

The demonstration checkout is on a volume whose inherited `Authenticated Users` permissions include Modify. Apply an explicit deny only to the `AclaisWorker` SID on the backend/frontend application source and committed evidence subtrees, where the owner can still read and update files. Do not change the repository root, volume/ancestor ACLs, or a group containing the owner. Keep the separate `C:\ACLAIS-Lab` runtime code ACL allowlist as the primary worker-visible code boundary.

## D-019 — Require owner integrity evidence for path-hidden denials

Windows may return file/path-not-found when traversal to a protected parent is denied, including for reads, writes, and renames. A private probe may count Win32 2/3 as a denial only when the owner verifies the protected target exists and matches its trusted manifest hash before launch, then confirms it remains present and unchanged after the probe. Other denials require the observed access-denied result; command success or an exception alone is not proof.

## D-020 — Keep the A3 entrypoint fixed and task configuration owner-protected

A3 launches only the controller-owned private probe through a fixed absolute interpreter and script path; callers cannot select an executable, script, working directory or environment. Until production task routing arrives, the private probe is test-only and is not registered, exposed by an API or included in the dashboard. The controller writes a nonsensitive per-task configuration in the worker-read-only selected directory, verifies its hash after cleanup, and removes it. Production task entrypoints and their validated configuration schemas are later checkpoint work.

## D-021 — Use the pinned embedded Python runtime for the worker

The demo worker interpreter lives in the owner-protected `C:\ACLAIS-Lab\code\python-runtime` directory and is provisioned from the official Python 3.12.10 Windows embeddable package whose SHA-256 is pinned in the deployment script. This avoids the controller user's profile-specific interpreter path when a separate account launches the worker and keeps its code inventory under the existing A2 protection boundary. The runtime remains offline and contains no pip-installed application packages.

## D-022 — Transfer pipe and job ownership only after a successful launch

After resume, the returned worker handle owns the process, primary thread, job, read-pipe handles and concurrent drain threads. Setup cleanup joins/closes these resources only before ownership transfer; post-launch completion first terminates any remaining child processes through the scoped job, then drains pipes and closes all retained handles. This avoids blocking setup on a child that inherited stdout/stderr and prevents cleanup from touching processes outside that job.

## D-023 — Serialize launch admission with controller shutdown

Hold the controller lifecycle lock across private task configuration creation, suspended process setup and active-handle registration. Shutdown takes the same lock before snapshotting active handles. This prevents a process from being created after shutdown snapshots the job set but before a new handle is registered. The demonstration-machine harness pauses immediately before `ResumeThread` and races shutdown against launch to check this boundary.

## D-024 — Keep each component's source in its assigned folder

Use one repository with `aclais/`, `receiver/`, and `document-tools/` as the component roots, `shared/` for schemas/minimal protocol definitions, root `tests/` only for cross-component integration/acceptance, and root `scripts/` only for whole-system orchestration. Keep component implementation, component-owned test suites and private probes, assets, configuration, dependency manifests, and locks with that component. Keep later component folders as reservation notes until their prerequisite gates pass. Root orchestration must invoke component commands by resolved paths from any caller working directory. Application/runtime paths and fixed worker registration remain explicit and independent of shell CWD. This checkpoint changes source organization only; protected runtime data, credentials, and confidential fixtures stay in their existing designated runtime locations.

## D-025 — Start implemented development services through root orchestration

Use root `scripts/start.ps1 -Service Backend` or `-Service Frontend`, with component-specific commands in `aclais/scripts/start.ps1`. Resolve component locations from script paths and pass them as separate native arguments to uv/npm. Keep each server in the foreground in its own terminal, with live output and Ctrl+C shutdown; report native startup failures and preserve an existing port owner. Do not create background process registries or start reserved production components as part of the R0 follow-up. The later G1 operator startup/readiness controls remain their own deliverables.
