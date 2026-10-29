# ACLAIS implementation checkpoints

This sequence decomposes ACLAIS G1 into reviewable checkpoints. It preserves the product scope and component order in `docs/00_START_HERE.md`: finish ACLAIS G1 before production receiver G2, and finish G2 before Document Tools G3. A0 is readiness/specification work; A1–A10 build and audit ACLAIS. Passing A0 does not mean G1 is complete.

The repository-structure checkpoint `R0` is a source-organization prerequisite inserted after the completed A3 work and before A4 begins. It does not renumber, replace, or change the deliverables of A0–A10.

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

**Deliverables:** Narrow Windows adapter using `CredReadW` and `CreateProcessWithLogonW`; bounded in-memory secret handling; explicit fixed entrypoint, argument vector, minimal environment and controlled working directory; owner-created task configuration under the worker-read-only selected directory; separate bounded stdout/stderr pipes; retained process/thread/job handles; Job Object with kill-on-close and no breakaway; create suspended, verify token, assign job, then resume. Provide only a private harmless probe at this checkpoint; production task/tool entrypoints come later.

**Tests:** Portable strict-model and command-line construction checks. Separately, actual Windows demonstration-machine checks for Credential Manager logon, true SID/non-admin token, secret-free argv/environment/capture, quoting, protected task configuration, separate pipe drain and bounded oversized output, assignment-before-resume, identity mismatch and assignment-failure termination, a child process, normal exit, forced termination, deadline timeout, orderly controller shutdown during an active task and during launch, and abrupt controller-process closure. Check that every worker and child stops and an unrelated owner process survives. The Windows lane is not implied by portable CI.

**Observable acceptance:** No worker runs before verified job assignment; identity/assignment failure leaves no probe marker or running process; a harmless child is terminated with the parent/job after exit, cancel, timeout, shutdown and abrupt controller closure; shutdown serialized against launch admission leaves no untracked worker; the unrelated owner process remains alive; task configuration is unchanged and removed by the owner; bounded stdout/stderr are tagged only as `worker_reported`; no owner-identity fallback occurs. Record sanitized results from both lanes. A3 does not complete G1 or authorize A4 until these acceptance results are reviewed.

## R0 — Repository structure (after A3, before A4)

**Dependencies:** A0–A3 PASS; at the time R0 was accepted, no A4 work had started.

**Deliverables:** Keep one repository and the existing working branch. Put all current ACLAIS source, tests, fixtures/templates, probes, scripts, assets, and configuration under `aclais/`; keep `receiver/` and `document-tools/` as reservation notes only until their gates pass; keep only shared schemas/minimal protocols under `shared/`; reserve root `tests/` for cross-component integration/acceptance and root `scripts/` for whole-system orchestration. Retain the supplied `docs/` arrangement, runtime data and credentials in their designated runtime locations, existing root tracking files, and fixed worker allowlist. Update imports, manifests, scripts, CI, specs, and documentation together. Add no application features.

**Tests/checks:** Inspect the complete repository/Git state and all moved files; audit for stale paths and component-private cross-imports; verify root checks and foreground backend/frontend startup from outside component directories, including real health/proxy responses, Ctrl+C shutdown, occupied-port refusal and invalid service rejection; run the full implemented ACLAIS portable suite and frontend build; parse component PowerShell scripts; rerun the real A2 worker filesystem access probe and A3 launcher/child-process enforcement suite on the demonstration machine because source ACLs and launcher paths may have changed; inspect runtime fixture locations and verify they remain outside Git; validate all links and the staged diff. A path-hidden Win32 2/3 result for a protected source operation is accepted only when the owner verifies the source exists and its hash is unchanged before and after the worker probe.

**Observable acceptance:** Each component-owned file is in its assigned component folder; root tests and scripts have only their cross-component/orchestration roles; reserved components contain no production implementation; the single Git worktree and branch are unchanged; root commands need no manual component-directory change; fixed entrypoint registration resolves from explicit paths; actual A2/A3 checks pass after relocation; no protected runtime data is staged; current portable and Windows results are recorded separately. `R0 PASS` is required before A4; it does not advance or complete A4 or G1.

## A4 — Persistence and contracts

**Dependencies:** A3 PASS and R0 repository-structure PASS.

**Deliverables:** Versioned SQLite schema/migrations with protected state directory, WAL and `synchronous=FULL`; controller task/event/contract/token/incident/output/request journal models; strict receiver receipt-journal value model without a receiver-owned database or service; strict request and response schemas for every ACLAIS and receiver contract route, including approval query, bounded list/event query and UUID path parameters; discriminated broker operations; generated OpenAPI and TypeScript types; idempotency keys bound to canonical validated request-body hashes. Pydantic models are the wire-schema source of truth. This checkpoint publishes route contracts while only the existing health route remains mounted; it does not implement A5 broker behavior, A6 recovery/lifecycle arbitration, or the production receiver.

**Tests:** Portable schema tests for unknown fields, coercion, duplicate keys, enums/unions, size limits, invalid IDs, response validation, operation/tool/output mismatch, invalid invoice JSON, request-ID conflict/replay, grant and credential uniqueness/expiry, ordered append-only events, valid/invalid task transitions, output journal state rules, migration rollback/checksum and database reopen. Confirm the wheel includes its migration. Receiver contract and journal model tests use values only, not a fake production endpoint. Windows enforcement remains a separate lane and is not implied by A4's portable results.

**Observable acceptance:** Every route has a bounded strict request/response model; client task requests cannot contain paths or grants; malformed input cannot cause effects; valid forbidden operations remain distinguishable from malformed requests; generated OpenAPI and TypeScript match with no unexplained diff; SQLite migrations preserve valid transitions, terminal causes, grants and request hashes. The ACLAIS database is created only from a trusted absolute path under the pre-provisioned protected state directory. Passing A4 does not mean later routes, broker effects, filesystem publication/recovery, authentication, dashboard connection, or G1 have been implemented.

## A5 — Broker and publication

**Dependencies:** A2–A4 PASS.

**Deliverables:** Credential-derived task identity; active-state, credential/contract-expiry, and operation-specific checks; registry-derived selected-copy reads; policy denials for unselected read/original replacement/deletion; one bounded inert output publication; secure output serving behind an injected owner authorizer; exact retry replay, changed-body conflict and broker audit events. The broker accepts no worker path, task identity, contract or grant fields. Selected-copy paths follow `work/selected-inputs/<task UUID>/<document ID><registry extension>`; A6 provisions the task-scoped directory ACL and lifecycle cleanup.

**Tests:** Portable strict-request, credential/task binding, expiry, denial-before-effect, original hash, idempotency/event ordering and actual-filesystem/persisted-journal tests; bounded text and strict invoice-output checks; Windows/NTFS tests for `FlushFileBuffers`, no-replace `MoveFileExW`, crash injection after reservation, staging create/write/flush, staged-row commit, rename and atomic finalization, DB failure after rename, destination collision, missing/mismatched final file, concurrent publication and output API withholding. Run Windows-specific checks on the actual demonstration machine; portable CI does not establish that lane.

**Observable acceptance:** A valid active task can read only its selected copy and publish one fresh inert output; original mutation never executes and original hashes remain unchanged; each successful operation has one persisted broker event; exact retry returns the stored result without a duplicate event or effect; only a hash-verified file with a finalized matching journal row is served when an owner authorizer is supplied; every injected crash recovers to one committed output or an explicit fail-closed error with no overwrite/duplicate. Owner authentication, task setup/cleanup, lifecycle arbitration and restart reconciliation remain A6/A8 work.

## A6 — Lifecycle and recovery

**Dependencies:** A3–A5 PASS.

**Deliverables:** Shared reentrant per-task lifecycle lock for broker/lifecycle operations; transactionally enforced single-worker admission; task-scoped selected-copy and temporary-output ACLs; persisted worker PID/SID/process creation time and credential hash before resume; completion, denial, cancellation, timeout, process crash, shutdown and restart reconciliation; immutable terminal cause; revoke-before-terminate/recovery behavior. Private lifecycle probes remain under ACLAIS tests and are not registered or exposed as production tools.

**Tests:** Portable deterministic preparation failure/admission recovery, races for publication/denial, cancellation/process exit and timeout/completion, database failure, monitor startup failure after resume and restart recovery; actual Windows demonstration-machine probes for successful completion, policy denial, revoked-credential reuse, single-worker admission, cancellation, timeout, nonzero worker crash with a child, orderly shutdown, exact worker/child process-stop checks, interruption by an abruptly killed controller, and database-backed restart reconciliation. Reopened tasks use recorded PID/SID/creation time; evidence does not infer cleanup from UI or a recorded intention.

**Observable acceptance:** The first durable revocation cause is retained; an active valid policy denial wins over later stop/exit events; timeout wins at the exact boundary; no new broker effect starts after revocation; normal completion waits for observed exit, drained broker requests and exactly one published hash-verified output. On the demonstration machine each worker and child process identity is actually checked stopped after cancel, timeout, crash, shutdown and controller death. Restart revokes the old credential and fails the interrupted task only after verifying the recorded process identity stopped. Failure to persist or verify containment fails closed; failures do not become `BLOCKED` or `COMPLETED`.

## A7 — Verification and evidence

**Dependencies:** A2, A4, A5 and A6 PASS.

**Deliverables:** Capture a trusted full fixture inventory before launch and compare names, existence, sizes and hashes only after controller-confirmed worker/job termination. Compare selected-input and published-output hashes; persist immutable baseline/report records and a source digest. Keep controller observations, broker decisions, worker-reported output, verifier results and receiver results separately attributed. Preserve owner-protected raw local evidence separately from sanitized Git-trackable summaries. Add a typed receiver adapter interface and test-only response fixtures. Do not implement the production receiver in G1.

**Tests:** Inventory changes/missing/new/rename/hash cases; selected-input/output hashes; verifier timeout and unavailable baseline; no final scan before confirmed termination; event provenance; evidence persistence/reopen and integrity; sanitized-summary redaction; injected receiver healthy-empty/positive/unknown/outage cases; no canary or worker claims in general logs; no green status when a check is unknown or failed. Run the A6 worker lifecycle suite on the actual Windows target and inspect reports after process cleanup.

**Observable acceptance:** Final verification follows actual worker/job termination; evidence identifies its tested source revision or source digest; raw names, file hashes, receipt identifiers and worker text remain local; sanitized summaries contain only status, counts and source attribution. Worker claims cannot establish enforcement. Receiver fixtures are visibly test-only; unknown stays unknown and absent-run is not applicable; failed or incomplete verification cannot report protected success.

## A8 — Owner authentication and approval

**Dependencies:** A4, A6 and A7 PASS.

**Deliverables:** One-time bootstrap exchange from an ACLAIS URL fragment; hash-only persisted bootstrap/session/CSRF credentials; host-only `aclais_owner_session`; exact Host, Origin and CSRF checks; owner-only APIs; side-effect-free top-level approval GET; signed short-lived observed-header context; allowlisted tool/source claims; trusted document selection and explicit task action. The source claim remains distinct from observed Origin/referrer values. Keep ACLAIS at `127.0.0.1:8765`; reserve `localhost:8766` for Document Tools and bind it only to `127.0.0.1`/`::1`; bind the later receiver only to `[::1]:8767` so it cannot share the owner-cookie host. No session is passed to Document Tools. Use controller-fixed entrypoints under the explicit install root; private probes remain test-only and production workers stay gated until G3.

**Tests:** Windows Chrome and Edge browser checks: cookie is sent to ACLAIS but absent from Document Tools and IPv6 receiver requests; top-level cross-host safe GET reaches approval; GET has no task/process effect; authenticated explicit approval launches the fixed private probe in the test harness; cross-origin POST, missing/expired credentials, missing CSRF, bad Host, reused bootstrap token, cookie fixation, worker-token access to owner routes, undeclared query parameters, and caller-supplied executable arguments are rejected. Confirm the private probe process and child are stopped before final verification.

**Observable acceptance:** Owner approval works after the Document Tools-origin top-level navigation; only the ACLAIS host receives the owner cookie; GET has no launch effect; an authenticated explicit approval is the only launch path; all task mutations require session, exact Origin, CSRF and a fresh signed approval context; bootstrap secret is removed from the address bar and never appears in logs or Git. Missing production workers fail closed without creating a task.

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


A10 additionally closes audited readiness/operator gaps: measured per-admission core checks, controller failure reflected in health, dependencies/scripts protected against the actual worker, all-task publication reconciliation and orphan quarantine, bounded invalid-request throttling, sentinel-scoped start/stop/reset/retirement, and strict lane selection. Evidence includes real target checks and a separately labeled isolated UI-fixture lane for receiver-dependent presentation. G1 does not authorize any G2/G3 production code in the A10 turn; real receiver integration remains pending G4. See evidence/G1.md for the per-requirement implementation/test/evidence matrix and the owner-delegated resolution of the draft-PR base conflict (D-046).

## Component 2 — G2 local receiver

This component begins only after the verified A10/G1 PASS. It does not add another A0–A10 item or start Document Tools G3. Receiver run creation and protected ingest-token delivery from ACLAIS remain G4 integration work.

**Deliverables:** independent `receiver/` Python service and SQLite migrations; run-bound hashed ingest credentials; distinct owner-only admin credential; strict health, run creation, ingest and receipt-inspection contracts; bounded validated payload handling; server-computed receipt metadata; protected payload storage and crash recovery; metadata-only owner CLI; read-only ACLAIS HTTP adapter; component and cross-component tests; portable CI job; actual Windows runtime ACL evidence; sanitized `evidence/G2.md`.

**Dependencies:** A10/G1 PASS (`evidence/G1.md`); shared v1 receiver contracts in `docs/02_SHARED_CONTRACTS.md`; receiver scope and acceptance in `docs/04_BUILD_RECEIVER.md`; fixed `[::1]:8767` runtime and owner-protected data root.

**Tests:** receiver portable API, strict-model, authorization, limits, retry/idempotency, filesystem-effect and crash-reconciliation tests; real IPv6 service-to-ACLAIS-adapter tests for healthy-empty, positive receipt, unknown run, authentication failure and outage; actual Windows/NTFS DACL audit confirming the owner, SYSTEM and Administrators allowlist and exclusion of the non-admin worker SID. The portable job never claims the Windows ACL lane passed.

**Observable acceptance:** only IPv6 loopback accepts service requests; worker credentials can ingest only for their run and cannot inspect/administer; admin credential can inspect metadata but never retrieve raw bytes; the database stores no run token in plaintext; byte count, SHA-256 and marker match derive from decoded bytes; request and run limits are enforced; exact retries have no duplicate effect and changed-body retries conflict; recovery never turns missing/mismatched payloads into a healthy empty result; the actual receiver store ACL passes on the demonstration machine; ACLAIS outcomes distinguish healthy-empty, positive, unknown, auth failure, protocol failure and unreachable without claiming “attack blocked.” No raw receipt, payload or credential enters Git/CI artifacts.
