# ACLAIS implementation checkpoints

This sequence decomposes ACLAIS G1 into reviewable checkpoints. It preserves the product scope and component order in `docs/00_START_HERE.md`: finish ACLAIS G1 before production receiver G2, and finish G2 before Document Tools G3. A0 is readiness/specification work; A1–A10 build and audit ACLAIS. Passing A0 does not mean G1 is complete.

For each checkpoint, verify only its listed tests and acceptance criteria, update `BUILD_STATUS.md` and `DECISIONS.md`, inspect the explicit staged diff, and commit/push only the working branch under `AGENTS.md` and `GIT_WORKFLOW.md`. A failed or unavailable mandatory prerequisite stops advancement. Report `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN` accurately. Do not implement a later checkpoint while completing an earlier one.

## A0 — Readiness and specification

**Dependencies:** None.

**Deliverables:** Read all nine `docs/00_START_HERE.md` through `docs/08_CODING_AGENT_PROMPTS.md` in order; inspect the repository, Git state and remote, Windows edition/build, NTFS volumes, runtimes, browser availability, elevation and worker/lab prerequisites; reconcile the security/API/lifecycle/UI/test requirements in those specs; record decisions; create this checkpoint plan; update build status with observed facts and blockers. Preserve the supplied `docs/` layout. No application code or features.

**Tests/checks:** Specification cross-reference and stale-path audit; check consistency of origins, cookie scope, API routes, state transitions and checkpoint dependencies; inspect Git working tree and remote tracking; read-only environment inventory. No application tests are expected in A0.

**Observable acceptance:** All nine specs have one consistent contract; each requested gap has an explicit rule and planned verification; A1–A10 have deliverables/dependencies/tests/observable criteria; current environment prerequisites are recorded without claiming unrun capability; no application feature has been implemented; A0 status and G1 status are distinct.

## A1 — Project foundation

**Dependencies:** A0 PASS.

**Deliverables:** Establish only the ACLAIS project structure, Python/TypeScript package configuration, pinned dependency/lock files, common schema source and generated OpenAPI/TypeScript outputs, local scripts and portable test layout. Add test-only probe directories and portable CI checks. Keep receiver and Document Tools as future components; do not create their production services or workers.

**Tests:** Clean-install/lock consistency; portable backend import/unit/schema tests; frontend typecheck/lint/build; generated-schema diff; portable CI workflow run.

**Observable acceptance:** A clean checkout can install the pinned ACLAIS foundation and run its portable checks without manual file edits; generated types match the common source; no real Windows enforcement claim, production receiver, or production hostile tool exists yet.

## A2 — Protected fixtures and worker identity

**Dependencies:** A1 PASS; one-time explicit elevation available for provisioning.

**Deliverables:** Owner-scoped `C:\ACLAIS-Lab` sentinel and fixed owned directories; deterministic synthetic fixtures; provisioned non-administrator `AclaisWorker`; owner-only Credential Manager entry for its logon secret; exact allowlist NTFS ACLs for originals, selected copies, output, state, evidence and protected runtime code. Grant only traverse on the lab root plus `store` and `work` parents. Apply worker-SID-specific protection to checkout application source/evidence when volume inheritance grants broader rights. Keep private probes out of production tools and UI. Record SID and install manifest only.

**Tests:** On the demonstration machine, launch the private probe under the actual worker SID. Verify selected-copy read and temporary-output create/write/delete; denied original read/write/delete/rename/replace and parent child creation; denied trusted-state/evidence/code/DACL/owner changes; Credential Manager isolation; repository source/evidence denial; post-probe fixture/code/source integrity; and missing sentinel/root/ownership refusal. Record automated Windows checks separately.

**Observable acceptance:** Actual worker SID differs from the ordinary controller and is not an administrator; selected copy is readable, output scratch is writable, originals/confidential fixture/trusted state/owner credentials are inaccessible as specified, and protected code/evidence are not modifiable. Every ACL result is observed inside the worker process and confirmed by owner-side integrity checks.

## A3 — Launcher and containment

**Dependencies:** A2 PASS.

**Deliverables:** Narrow Windows adapter using `CredReadW` and `CreateProcessWithLogonW`; bounded in-memory secret handling; explicit executable/argv/environment/working directory; separate bounded stdout/stderr pipes; retained process/thread/job handles; Job Object with kill-on-close and no breakaway; create suspended, verify token, assign job, then resume. Fail closed on every setup/identity/assignment error.

**Tests:** Windows automated checks for local-account logon, true SID/non-admin token, password absent from argv/environment/logs, argument quoting, separate pipe capture and pipe-drain behavior, oversized output truncation, assignment-before-resume, assignment-failure termination, child containment, cancel/timeout/controller-close cleanup and handle closure.

**Observable acceptance:** No worker runs before verified job assignment; a harmless child is terminated with the parent/job; controller close leaves no process; stdout/stderr are attributed only as `worker_reported`; no fallback to the owner identity occurs.

## A4 — Persistence and contracts

**Dependencies:** A3 PASS.

**Deliverables:** Versioned SQLite schema/migrations with protected state directory, WAL and `synchronous=FULL`; task/event/contract/token/incident/output/request/receipt journal models; strict request and response schemas for every ACLAIS and receiver contract route; discriminated broker operations; generated OpenAPI and TypeScript types; idempotency keys bound to canonical request-body hashes. This checkpoint defines the receiver contract but does not implement its production process.

**Tests:** Portable schema tests for unknown fields, coercion, duplicate keys, enums/unions, size limits, invalid IDs, response validation, operation/tool/output mismatch, invalid invoice JSON, request-ID conflict/replay, migrations and transaction rollback. Receiver model tests use values only, not a fake production endpoint.

**Observable acceptance:** Every route has a bounded strict request/response model; malformed input cannot cause effects; valid forbidden operations remain distinguishable from malformed requests; schema/type generation has no unexplained diff; SQLite migrations preserve terminal states and request hashes.

## A5 — Broker and publication

**Dependencies:** A2–A4 PASS.

**Deliverables:** Owner-controlled document registry, selected-copy read, one output publication, policy denials for unselected read/original replacement/deletion, atomic-enough output journal protocol, secure output serving and replay handling. No worker path is accepted.

**Tests:** Portable broker policy/model tests; Windows/NTFS fault injection after DB reservation, stage creation/write/flush, no-replace rename and final DB commit; duplicate exact retry; changed-body conflict; destination collision; missing/mismatched final file; concurrent publish; output API withholding unfinalized files.

**Observable acceptance:** A valid active task can read only its selected document and publish one fresh inert output; original mutation never executes; only a hash-verified file with a finalized matching journal row is served; each injected crash recovers to one committed output or explicit fail-closed error with no overwrite/duplicate.

## A6 — Lifecycle and recovery

**Dependencies:** A3–A5 PASS.

**Deliverables:** Per-task lifecycle lock and transition implementation for policy denial, cancellation, timeout, process exit, controller shutdown/restart and DB failure; immutable terminal cause; revoke-before-terminate/recovery behavior; single-worker admission.

**Tests:** Deterministic barrier-controlled races among denial/cancel/deadline/exit/shutdown; timeout boundary and tie behavior; broker request admission/drain; DB unavailable; process crash; controller restart; cancellation idempotency; no orphan job children; subsequent task after incident; concurrent start returns 409.

**Observable acceptance:** The first durable revocation cause is retained; an active valid policy denial wins over later stop/exit events; expired deadline wins at the boundary; no new broker effect starts after revocation; normal completion waits for exit and drained broker requests; failures never become `BLOCKED` or `COMPLETED`.

## A7 — Verification and evidence

**Dependencies:** A2, A4, A5 and A6 PASS.

**Deliverables:** Trusted full-inventory verifier, input/output hashes, evidence reports, explicit `pass|fail|unknown|not_applicable` receiver status and truthful source attribution. Add a typed receiver adapter interface with test-only injected response models. Do not implement the production receiver in G1.

**Tests:** Inventory changes/missing/new/rename/hash cases; verifier timeout; event provenance; evidence persistence and retrieval; injected receiver healthy-empty/positive/unknown/outage cases; no canary in general logs; no green status when checks are unknown or fail.

**Observable acceptance:** Evidence comes from trusted controller/verifier data and real inventory; worker reports remain separate; receiver test data is visibly fixture-only; a missing receiver or unknown run never means zero receipt/leakage; failed verification cannot report protected success.

## A8 — Owner authentication and approval

**Dependencies:** A4, A6 and A7 PASS.

**Deliverables:** One-time bootstrap exchange on ACLAIS origin; host-only `aclais_owner_session` cookie; exact-Origin and CSRF checks; side-effect-free top-level approval GET; allowlisted tool/source claims; owner document selection and task creation. Keep ACLAIS at `127.0.0.1:8765`; reserve `localhost:8766` for Document Tools and bind it only to `127.0.0.1`/`::1`; reserve `127.0.0.1:8767` for server-to-server receiver traffic. No session is passed to Document Tools.

**Tests:** Windows Chrome and Edge browser checks: cookie is sent to ACLAIS but absent from Document Tools requests on the different hostname; top-level cross-host safe GET reaches approval; GET has no mutation; cross-origin POST, missing CSRF, bad Host, reused bootstrap token, cookie fixation and owner-route access failures are rejected.

**Observable acceptance:** Owner approval works after the Document Tools-origin top-level navigation; only the ACLAIS host receives the owner cookie; all task mutations require session, exact Origin and CSRF; bootstrap secret is removed from the address bar and logs.

## A9 — Connected dashboard

**Dependencies:** A5–A8 PASS.

**Deliverables:** Implement the screen-to-API mapping in `docs/06_UI_DESIGN.md`: Workspace, Activity, Approval, Running/Result, Incident drawer, Cancel and Disconnected/protection-unavailable states. Connect only to persisted ACLAIS APIs. Use private probes in the verification harness for successful/denied G1 flows; no probe is a production tool, route or screen.

**Tests:** Browser integration against the real ACLAIS backend plus test-only private probe; polling sequence/reconnect; output/evidence rendering; keyboard/focus/ARIA; reduced motion; 1366×768 and 1920×1080 screenshots; API outage/preflight failure; cookie-host isolation; no placeholder telemetry or cross-origin session sharing.

**Observable acceptance:** Every displayed status maps to an actual response/event/evidence field; refresh preserves order without duplicate events; disconnect removes green status; outputs are inert; the real approval and probe flows work without a production probe control.

## A10 — Complete G1 audit

**Dependencies:** A1–A9 PASS.

**Deliverables:** Run the complete G1 requirement matrix; produce `evidence/G1.md`, screenshots, environment/dependency versions, exact commands and exit codes, observed results, artifact paths, source/commit hash, known limitations and remaining issues; update `BUILD_STATUS.md` and traceability.

**Tests:** All required portable CI checks; all Windows-specific automated checks; every mandatory demonstration-machine check in `docs/03_BUILD_ACLAIS.md` and `docs/07_VERIFICATION_AND_HANDOFF.md`. Include direct ACL bypass probes, broker allow/deny, strict schemas, cookies, output/retry/crash recovery, lifecycle races, process containment, restart and second benign task.

**Observable acceptance:** Every mandatory G1 criterion passes in its assigned lane with real evidence; no skipped/mocked Windows enforcement is called pass; no worker/token remains; G1 is marked PASS only after the three lanes are complete. Only then may production receiver G2 begin.
