# Build status

As of 2026-10-29. A0–A7 and repository-structure checkpoint R0 have passed their required checks. A7 implementation commit `26e806bd51b4b8944717667474ae7269fa27ab98` is pushed and verified; its hosted portable CI passed. G1 remains incomplete, and later production components remain unimplemented.

Historical A1–A3 command paths below describe the tree when those runs occurred. Current component and orchestration paths are documented in `RUNBOOK.md` and the R0 record.

## Current state

- All nine specification files in `docs/` have been reviewed in the prescribed order and reconciled for consistent implementation.
- The supplied repository is verified as `sai161812/aclais-1` at `https://github.com/sai161812/aclais-1.git`; it is public. GitHub reported `main` as the default before the first push and now reports `aclais-prototype` after the first branch was pushed to the empty repository.
- The working branch remains `aclais-prototype`, tracking `origin/aclais-prototype`; R0 startup implementation commit `860070068607acb7004a2cc001a5b7e39854bce8` was pushed, the local and remote heads matched, and [run 9](https://github.com/sai161812/aclais-1/actions/runs/40769494744) passed for that revision. Synchronization and CI for its final documentation-only evidence commit are reported separately in the completion report.
- Current source is organized under `aclais/`, `receiver/`, and `document-tools/`; root `tests/` is cross-component only, root `scripts/` is orchestration only, and `shared/` holds schemas/minimal protocol notes. Receiver and Document Tools contain reservation notes only. The existing `docs/` arrangement and protected `C:\ACLAIS-Lab` runtime location were retained. A2/A3 Windows checks were rerun after the move; both portable CI jobs passed on the R0 implementation commit.
- A3 now provides the fixed private Windows probe launcher, Credential Manager retrieval, suspended alternate-user creation, pre-resume Job Object assignment, bounded output capture and scoped deadline/shutdown cleanup. Its real target-machine checks pass; portable checks remain a separate lane. This checkpoint does not complete G1.
- The remote was genuinely empty: GitHub reported repository size 0 and no branches, its refs endpoint reported an empty repository, and `git ls-remote --heads` returned no refs. A documentation-only baseline was committed to local `main` as `0752747004fc689e07f8e55435964bf4d267fd12`; working branch `aclais-prototype` was created from it. Only `aclais-prototype` was pushed; it tracks `origin/aclais-prototype`, and the local and GitHub branch heads matched after the final status push.
- Initial A0 environment inventory: Windows 11 Home Single Language 10.0.26200, 64-bit; C: and D: are NTFS. Python 3.12.10/pip 25.0.1, Node.js v24.19.0/npm 11.17.0, Git 2.55.0.windows.4. Chrome 156.0.8078.48 and Edge 156.0.4314.50 are installed. Globally visible Python packages: FastAPI 0.115.0, Pydantic 2.9.2 and pytest 8.3.3; pywin32 is absent. The shell is not elevated. `C:\ACLAIS-Lab` and local account `AclaisWorker` are absent. At that inventory, no project source, project virtual environment or lockfile existed; A1 now establishes the isolated backend/frontend sources, environments and locks below. Global npm package inventory failed because `%APPDATA%\npm` does not exist; `npm --version` succeeds. Provisioning capability has not been tested.
- A1 toolchain: Python 3.12.10 with `uv` 0.12.15; Node.js 24.19.0 with npm 11.17.0. Isolated locked backend versions: FastAPI 0.162.0, Pydantic 2.14.1, Uvicorn 0.54.0, pytest 9.2.0, Ruff 0.17.3 and httpx2 2.16.0. Frontend versions: React/React DOM 19.3.1, Vite 8.3.5, TypeScript 5.9.3, ESLint 10.13.0 and openapi-typescript 7.13.0. `npm ci` reported zero vulnerabilities in the installed lockfile.
- Cookie boundary is specified as ACLAIS `127.0.0.1:8765`, Document Tools `localhost:8766`, and receiver `[::1]:8767`; Windows resolves `localhost` to both `::1` and `127.0.0.1`, so the tools listener binds both loopback addresses. D-035 corrects the initial receiver host because ports do not isolate cookies.
- A0 records resolved rules for cookie-host separation; SQLite/NTFS publication and retry recovery; Windows credential/alternate-user/job/pipe lifecycle; task-event precedence; strict request/response and operation models; dashboard API mapping; pre-receiver/private probe discipline; and separate portable, Windows, and demo-machine verification lanes.

## Gates

| Gate | Status | Evidence / prerequisite |
|---|---|---|
| G0 — environment and contract review | PASS | All nine specs and the environment were reviewed; repository metadata was verified; local `main` documentation baseline created; `aclais-prototype` pushed and matched against the GitHub branch head. |
| G1 — ACLAIS | IN_PROGRESS | A1–A7 pass their current checkpoint checks; A8–A10 and the complete G1 audit remain. |
| G2 — receiver | NOT_STARTED | Requires passing G1. |
| G3 — Document Tools | NOT_STARTED | Requires passing G1 and G2. |
| G4 — integrated release audit | NOT_STARTED | Requires passing G1, G2, and G3. |

## A0–A10 checkpoints

| Checkpoint | Status | Evidence / prerequisite |
|---|---|---|
| A0 — readiness and specification | PASS | All nine specs reconciled, environment reviewed, decisions recorded, plan created; no application changes. |
| A1 — project foundation | PASS | Local portable checks passed; GitHub Actions run 1 passed for the A1 implementation commit. Windows enforcement remains `NOT_RUN`. |
| A2 — protected fixtures and worker identity | PASS | Demonstration-machine private worker probe passed 57/57 checks; sanitized evidence is tracked under `evidence/`. |
| A3 — launcher and containment | PASS | Actual Windows demonstration-machine launcher checks and local portable checks passed; sanitized evidence is in `evidence/A3.md` and `evidence/a3-launcher-summary.json`. GitHub CI is portable only. |
| A4 — persistence and contracts | PASS | Requires A3 PASS and the separate R0 repository-structure checkpoint; see `evidence/A4.md` and [GitHub Actions run 11](https://github.com/sai161812/aclais-1/actions/runs/40774065632). |
| A5 — broker and publication | PASS | A2–A4 prerequisites pass; local portable and Windows publication checks pass; [GitHub Actions run 40810541367](https://github.com/sai161812/aclais-1/actions/runs/40810541367) passed for the implementation revision. |
| A6 — lifecycle and recovery | PASS | Local portable checks, actual Windows demonstration-machine tests, push verification, and hosted portable CI passed; see `evidence/A6.md`. |
| A7 — verification and evidence | PASS | A2, A4–A6 prerequisites pass; 107 portable tests and the actual Windows A3/A6 prerequisite suite pass; implementation commit is synchronized and hosted CI passed. See `evidence/A7.md` and `evidence/a7-sanitized-summary.json`. |
| A8 — owner authentication and approval | NOT_STARTED | Requires A4, A6 and A7 PASS. |
| A9 — connected dashboard | NOT_STARTED | Requires A5–A8 PASS. |
| A10 — complete G1 audit | NOT_STARTED | Requires A1–A9 PASS; all verification lanes required. |

## R0 repository-structure checkpoint

- Status: PASS for local portable, actual Windows acceptance, and hosted portable CI on the implementation commit.
- Component files now live in their assigned folders; ACLAIS source/tests/scripts are in `aclais/`, receiver and Document Tools are reserved with structure notes only, `shared/` contains the OpenAPI contract and scope note, root `tests/` is integration-only, and root `scripts/check.ps1` resolves and runs from outside the repository.
- The moved backend virtual environment contained stale executable launchers, so it was refreshed with `uv sync --locked --reinstall` at `aclais/backend/.venv`. The frontend's moved dependencies were refreshed with `npm ci`; both paths remain ignored.
- Post-move portable acceptance: root `scripts/check.ps1`, invoked from `C:\Windows\Temp`, passed Ruff, 23 backend tests, OpenAPI and TypeScript generation checks, frontend typecheck/lint/build, and npm audit (0 vulnerabilities). Portable checks do not claim Windows enforcement.
- Post-move PowerShell parser: 31 component `.ps1` files parsed with 0 syntax errors.
- Post-move A2: `aclais/scripts/deploy_a2_probe.ps1` refreshed only the fixed private probe and protected installation inventory; actual `AclaisWorker` SID `S-1-5-21-2514999450-3486617813-2191310599-1006`, non-administrator; 57/57 actual worker checks passed. Source/evidence access denials and owner-side hash/integrity checks passed. No credential values were recorded.
- Post-move A3: `aclais/scripts/check_a3_windows.ps1` exited 0 and the actual Windows test passed (1 passed). It reran the fixed entrypoint, real worker SID, suspended/job assignment, bounded stdout/stderr, child cleanup, cancellation, timeout, controller shutdown/crash, and fail-closed identity/job/credential checks. No worker identity processes remained afterward.
- Sanitized structure record: `evidence/R0-structure.md`. A2 and A3 enforcement results ran on the demonstration machine and are separate from the portable lane.
- Implementation commit: `c86471821274697c3819dfe534ff811380874326` (`chore: organize component source structure`) was pushed to `origin/aclais-prototype`; `git ls-remote --heads origin aclais-prototype` matched the local head. [GitHub Actions run 7](https://github.com/sai161812/aclais-1/actions/runs/40765960340) passed for that exact revision; both portable jobs succeeded. Windows enforcement evidence remains separate from CI.

### R0 follow-up — root startup

- Root `scripts/start.ps1 -Service Backend` and `-Service Frontend` delegate to `aclais/scripts/start.ps1`. uv receives an explicit backend directory and npm receives an explicit frontend prefix; neither requires a manual directory change. Both servers run in the foreground and surface startup errors. Dependency-only instructions also avoid manual folder changes.
- Actual Windows development smoke from `C:\Windows\Temp`: direct API health, frontend shell and frontend-proxied API health returned HTTP 200; health retained `protection_ready:false`. Duplicate starts failed for both occupied ports without changing existing listener identities; an unimplemented service name and missing uv/npm were rejected. Ctrl+C stopped each foreground session and final process/listener checks found no development servers remaining. This is development orchestration evidence, not worker enforcement.
- Root portable checks from `C:\Windows\Temp` passed Ruff, 23 backend tests, OpenAPI/type generation consistency, frontend typecheck/lint/build and npm audit (0 vulnerabilities). The new scripts parsed successfully. The prior A2/A3 Windows evidence remains historical; this follow-up does not relocate source/runtime data or change worker entrypoints, permissions or launcher behavior, so those enforcement tests were not rerun.
- Evidence: `evidence/R0-structure.md`, follow-up section. Implementation commit `860070068607acb7004a2cc001a5b7e39854bce8` was pushed to `origin/aclais-prototype` and `git ls-remote --heads` matched the local head. [GitHub Actions run 9](https://github.com/sai161812/aclais-1/actions/runs/40769494744) completed successfully for that exact revision; both portable jobs passed. The staged implementation diff was reviewed, and the working tree was clean after push. At R0 acceptance, A4 remained `NOT_STARTED`; its status is recorded in the current A4 section below.

## Checks and evidence

- A0 checks run: all nine specs read in order; repository/working-tree/branch/remote inspection; authenticated GitHub repository metadata; OS/filesystem/runtime/browser/worker-account/elevation and installed-package inventory; current working branch and remote tracking inspected. `npm --version` succeeded; `npm list -g --depth=0` could not enumerate packages because its configured user prefix directory is absent. Cross-spec consistency reviewed; all local Markdown targets resolve; A0–A10 headings and required fields are present; obsolete-path/host/receiver-test wording search is clear; `git diff --check` passed.
- A1 local portable checks: `scripts/check.ps1` passed; Ruff passed; pytest passed (19 portable tests); generated OpenAPI matched backend models; generated TypeScript matched the schema; TypeScript typecheck, ESLint and Vite production build passed. `npm ci` installed from lockfile and reported 0 vulnerabilities. Runtime smoke check passed for direct API health, same-origin Vite proxy and frontend shell HTTP 200; health reports `protection_ready:false` and G1 protection `unknown` as intended.
- A1 GitHub Actions: [run 1](https://github.com/sai161812/aclais-1/actions/runs/40747054105) passed for implementation commit `786bdca742d0b41ed8c37bd9c82d49068dc78e3c`; both portable backend and frontend jobs completed successfully. Windows enforcement lane: NOT_RUN; no Windows enforcement tests or implementation were added in A1.
- A1 did not run Windows enforcement. A3 launcher enforcement now passes on the demonstration machine; other G1 requirements remain incomplete and are not claimed as passed.
- A2 checkpoint record: the scoped fixture, credential, runtime-code and checkout source/evidence boundary passed on the demonstration machine. At that checkpoint's completion, A3 Job Object checks and an automated Windows CI runner had not run; A3 evidence is recorded in its own section below.
- Evidence artifacts: `evidence/A2.md` and `evidence/a2-access-summary.json` contain sanitized results only; runtime fixtures, credentials, installation state and raw process capture remain outside Git under `C:\ACLAIS-Lab`.
- Baseline commit: `0752747004fc689e07f8e55435964bf4d267fd12` on local `main` and in the working-branch history.
- G0 workflow commit: `01effbdea3a55ede6d40b29bcc07003d4f0d8da2`.
- A0 checkpoint commit: `536b02cdf05fb50f6109f010fbec2507f6f9c932`.
- A1 implementation commit: `786bdca742d0b41ed8c37bd9c82d49068dc78e3c` on `aclais-prototype`; its remote head matched after push and its portable CI run passed.
- Synchronization: the A0 checkpoint commit was pushed to `origin/aclais-prototype`; `git ls-remote --heads` matched the commit and GitHub's branch API confirmed the working branch. A final status-only commit records this verification.
- CI history: the A0 commit had no workflow because `.github/workflows` did not yet exist. GitHub reported no workflow runs or commit status checks for that A0 revision. A1 adds the portable workflow; its run passed as recorded above.

## A3 checkpoint (original implementation evidence before R0)

- Status: PASS. The implementation uses the actual owner Credential Manager entry and `AclaisWorker` identity, a pinned offline Python runtime, a fixed test-only probe, owner-protected per-task configuration, a minimal environment, bounded separate output pipes, and a kill-on-close Job Object assigned before the worker is resumed.
- Windows demonstration-machine command: `scripts/check_a3_windows.ps1`, exit 0 against implementation commit `ed136604fdbd15d7a650e91941f8a188a7140453`; actual Windows test `1 passed` (3.72 seconds). It verified real worker SID/non-admin status, Job Object assignment before resume, protected task configuration, argument quoting and redaction, exact environment/cwd, >1 MB per output stream with configured capture bounds, normal/child/cancel/timeout/shutdown/crash cleanup, unrelated-process survival, and fail-closed identity/assignment/credential cases.
- Local portable command: `scripts/check.ps1`, exit 0; Ruff, 23 backend tests, OpenAPI/type generation consistency, frontend typecheck/lint/build passed; npm audit reported zero vulnerabilities. The portable script expressly does not run Windows enforcement. The two new PowerShell scripts parsed successfully.
- Sanitized demonstration-machine report: `evidence/A3.md`, `evidence/a3-launcher-summary.json`. No credential values, runtime fixture contents, process IDs or raw worker logs are tracked.
- The initial Windows execution found a pipe-reader setup cleanup bug when a child inherited the worker output handles. Ownership now transfers to the active handle, which kills remaining job processes before draining; the complete Windows test reran and passed.
- G1 remains incomplete. Broker admission, durable publication, lifecycle persistence, owner authentication, dashboard connection, receiver integration and remaining G1 audit checks are later work. A3's private probe is not a production tool.
- A3 implementation commit: `ed136604fdbd15d7a650e91941f8a188a7140453`; verification/evidence commit: `115c3489a25c59063cfcb62d6ff1442de6d783d2`. Both were pushed to `origin/aclais-prototype`, and `git ls-remote` matched the local head at `115c3489a25c59063cfcb62d6ff1442de6d783d2`. [GitHub Actions run 5](https://github.com/sai161812/aclais-1/actions/runs/40762418616) passed for that exact revision: portable backend and frontend jobs both succeeded. No Windows runner is configured; the actual Windows test above ran on the demonstration machine.

## A2 checkpoint

- Status: PASS on the designated Windows demonstration machine. Provisioning for the local worker and owner Credential Manager entry was established during the elevated setup; the private access probe ran later from the ordinary owner session.
- Provisioning evidence: the local worker/root/credential state was already established by the elevated setup. The new worker-specific repository source/evidence rules were applied to the owner-owned subtrees with the updated native DACL helper and then verified inside the actual worker probe; the A2 probe was not run elevated.
- Environment: Windows 11 Home Single Language, build 26200; C: NTFS; owner SID `S-1-5-21-2514999450-3486617813-2191310599-1001`; worker `LAPTOP-FMQ8RARQ\AclaisWorker`, SID `S-1-5-21-2514999450-3486617813-2191310599-1006`, verified non-administrator.
- Actual worker results: process exited; 57 checks, 0 failures; worker stderr 0 bytes; 8 owned-root guard checks passed; owner-side Credential Manager read passed without recording the secret; the worker could not read that credential (Win32 1168). Six owner read checks passed.
- Effective access: selected input read passed; temporary output create/write/delete passed; original read/write/delete/rename/replace denied; protected trusted state, evidence, sentinel and runtime-code modifications denied; the worker could not read/write checkout application source or read/write/create checkout evidence. The `C:\ACLAIS-Lab` parent traversal and child-creation checks passed. Path-not-found rename results were paired with intact owner-side hashes.
- Integrity: 11/11 seeded fixture hashes unchanged; 530/530 protected runtime-code files unchanged; trusted state, installation manifest, sentinel and repository source/evidence marker unchanged. Runtime ACLAIS import passed. The synthetic repository marker and worker-created-child target were absent after cleanup.
- Private probe evidence: `evidence/A2.md`, `evidence/a2-access-summary.json`. These are actual demonstration-machine results, not portable CI output.
- Portable checks rerun: `scripts/check.ps1` passed (19 backend tests, Ruff, schema/type generation checks, frontend typecheck/lint/build); all seven PowerShell scripts parsed; owned-root guard passed 8/8, including a known Windows profile junction rejection.
- A2 GitHub Actions: [run 3](https://github.com/sai161812/aclais-1/actions/runs/40757642281) passed for `854ba2159369bc2235940fd2fe19239056193d0f`; the portable backend and frontend jobs completed successfully. This CI run did not execute Windows enforcement.
- A2 synchronization: implementation commit `854ba2159369bc2235940fd2fe19239056193d0f` was pushed to `origin/aclais-prototype`; `git ls-remote --heads` matched the commit and the local working tree was clean.
- Verification lanes at A2 completion: portable CI did not establish Windows enforcement. The A3 launcher/Job Object tests had not yet run; their later result is tracked in the A3 section.
- Remaining issues: A3 launcher/job containment is next; A2 does not claim a full machine sandbox, network isolation, or A3 process containment.

## A4 checkpoint

- Status: PASS. Local acceptance, push verification, and hosted portable CI passed.
- Implemented versioned SQLite persistence models and migration `0001_initial.sql`, fixed controller-owned document/grant rules, hash-only worker credential records, append-only events/transitions, incident guards, immutable task/credential/dedup/output intent identities and output publication journal transitions. The ACLAIS database contains no receiver tables; A4 defines the strict receiver wire and receipt-journal value models only.
- Backend Pydantic models now define the complete ACLAIS and receiver request/response contract. `shared/openapi.json` and the frontend API TypeScript are regenerated from that source. Only the existing health endpoint is mounted; later routes remain schema-only.
- Local portable suite: 45 passed. Ruff, OpenAPI consistency, frontend typecheck/lint/build passed. The backend wheel includes the tracked SQL migration. The complete root portable check passed from `C:\Windows\Temp` after staging and confirmed generated OpenAPI/TypeScript consistency.
- All A4 database tests used disposable SQLite databases under pytest's temporary directory. No runtime database or credential material is tracked. Windows enforcement tests were not run for A4; this checkpoint adds no Windows enforcement behavior. Historical A2/A3 evidence remains separate; G1 is still `NOT_STARTED`.
- Implementation commit `db4c372719fba250764084800383d25859fb596f` was pushed to the verified `origin/aclais-prototype`; `git ls-remote --heads` matched the local commit.
- [GitHub Actions run 11](https://github.com/sai161812/aclais-1/actions/runs/40774065632) passed for that exact commit. Both portable backend and frontend jobs succeeded; Windows enforcement is a separate lane and was not run by this workflow.
- At A4 completion, A5 broker and publication was next. A4 contains the journal records and state machine only; it does not implement NTFS publication, crash reconciliation, or G1.

## A5 checkpoint

- Status: PASS. Local acceptance, push verification and hosted portable CI passed for the implementation revision.
- Implemented credential-derived task binding, active credential/contract checks, strict operation validation, registry-derived selected-copy reads, pre-effect policy denials, idempotent request handling, atomic broker events/replay records, one bounded output slot, and crash-consistent staging/flush/no-replace rename/finalization. Output API mount requires trusted injected owner authorization; default app remains health-only.
- Local backend checks: Ruff passed; 72 portable tests passed. The complete `scripts/check.ps1` passed from `C:\Windows\Temp`, including OpenAPI/TypeScript consistency, frontend typecheck, lint and production build.
- Demonstration Windows publication lane: 1 `windows_enforcement` test passed on Windows 11 Home Single Language build 26200. It asserted NTFS and exercised actual `MoveFileExW` no-replace behavior. This does not rerun A2/A3 identity/ACL/Job Object tests and does not establish G1.
- A5 tests used disposable databases and files. No runtime database, credential material, password or confidential fixture was staged.
- Implementation commit `4a8a12d232aa9171824f145ee1a3597250a3eebd` was pushed to `origin/aclais-prototype`; `git ls-remote --heads` matched the commit. The working tree was clean after the implementation commit.
- [GitHub Actions run 40810541367](https://github.com/sai161812/aclais-1/actions/runs/40810541367) passed for that exact commit. Both portable backend and frontend jobs succeeded; Windows publication enforcement remains a separate demonstration-machine check.
- Remaining issues: A7 trusted verification remains required before a policy denial can become `BLOCKED`; A8 must supply real owner authentication before the product output route is mounted.

## A6 checkpoint

- Status: PASS for local portable and actual Windows demonstration-machine checks, synchronized to the verified remote, and hosted portable CI.
- Connected lifecycle admission, the A5 broker/publication path and A4 persistence through one shared per-task lock and SQLite single-worker admission. Task-scoped selected input/output ACLs, persisted process PID/SID/creation time and hash-only credential are committed before resume. Completion, denial, cancellation, timeout, crash, shutdown and restart now share the persisted state machine.
- Revocation is committed before worker termination; broker authorization revalidates under the same lock. Previously authorized publication can finish before a queued denial/timeout, with event ordering preserved; no later effect can begin after revocation. Restart recovery verifies process identity by SID, PID and creation time, reconciles journals, verifies interrupted tasks through `VERIFYING`, and fails closed when process or durable output state is inconsistent.
- Local portable acceptance: root `scripts/check.ps1` passed from `C:\Windows\Temp`; Ruff, 84 portable backend tests, OpenAPI/type generation consistency, frontend typecheck/lint/build and npm audit (0 vulnerabilities) passed. Windows enforcement tests are not part of this portable check.
- Demonstration-machine acceptance: `aclais/scripts/check_a6_windows.ps1` passed from `C:\Windows\Temp`; its A3 precondition passed (1 actual Windows test), followed by 3 actual A6 tests. Worker and child process identities were checked stopped using Windows process handles and process creation times after cancellation, timeout, worker crash, orderly shutdown and abrupt controller death. Original fixture hashes were unchanged. See `evidence/A6.md` for identities, scenarios and reproduction commands.
- Implementation commit `7b387df0b9c6ca1a73d6f4f4dff6c3ed9f2f5343` was pushed to `origin/aclais-prototype`; `git ls-remote --heads origin aclais-prototype` matched this exact commit. The post-push Windows run deployed the A3 probe with this source revision and passed its prerequisite plus all 3 A6 tests.
- [GitHub Actions run 40816068549](https://github.com/sai161812/aclais-1/actions/runs/40816068549) passed for that exact commit. Both portable backend and frontend jobs succeeded. CI did not run Windows enforcement.
- A policy denial ended `FAILED` with `POLICY_DENIED`, containment `terminated`, and integrity/confidentiality `unknown`. This is fail-closed because the A7 trusted verifier has not been implemented; A6 makes no `BLOCKED` or G1 claim.
- Historical issue before A8: the demonstration fixture registry did not resolve `doc-report`; D-038 seeded the three missing permitted originals from synthetic templates, and the A2 actual worker access probe passed against the refreshed 14-fixture manifest before owner approval was exercised.

## A7 checkpoint

- Status: PASS for local portable checks, actual Windows demonstration-machine checks, remote synchronization, and hosted portable CI.
- Trusted pre-launch and post-termination inventories compare fixture names, existence, file sizes and SHA-256. Final inventory capture waits for controller-confirmed worker/job termination; incomplete containment and unavailable evidence stay unknown. Selected-input and published-output hashes are verified independently of worker-reported observations.
- Controller, broker, worker-reported, verifier and receiver evidence are attributed separately. Raw evidence is owner-protected and local. `evidence/a7-sanitized-summary.json` omits raw fixture names and hashes, task/run identifiers, receipt IDs, worker text and runtime paths; it carries the tested backend source digest.
- Portable checks from `C:\Windows\Temp`: Ruff passed; 107 portable backend tests passed; OpenAPI consistency, TypeScript generation, frontend typecheck/lint/build passed; npm audit found 0 vulnerabilities. This lane does not run Windows enforcement.
- Demonstration-machine checks: `aclais/scripts/check_a7_windows.ps1` passed its actual A3 prerequisite (1 test) and A6 lifecycle suite (3 tests). Reports were inspected only after actual worker/job cleanup. The healthy-empty, positive-receipt, unknown-run and outage adapter scenarios are test fixtures; unknown remains unknown. No production receiver or extra production probe was added.
- Tested backend source SHA-256: `3883cade8274ab394851e734ed5821a0b4fa373ccfe84279e636bdc2148a46ae`. The report revision field was null during testing; the committed backend source digest was recomputed and matched.
- Implementation commit `26e806bd51b4b8944717667474ae7269fa27ab98` was pushed to `origin/aclais-prototype`; `git ls-remote` matched this exact head. [GitHub Actions run 40822988478](https://github.com/sai161812/aclais-1/actions/runs/40822988478) passed the portable backend and frontend jobs for this revision. CI does not run Windows enforcement.
- See `evidence/A7.md` for method, limitations and remaining issues. The separate Windows demonstration-machine lane remains the enforcement evidence.

## A8 checkpoint

- Status: PASS for portable checks and actual Windows Chrome/Edge browser and worker-containment checks; hosted CI result is recorded after synchronization.
- Owner bootstrap is a random one-time URL-fragment token with a 15-minute expiry; only its hash is stored. Successful exchange creates an 8-hour session and CSRF token whose hashes are stored. Session and CSRF cookies are host-only; the session is HttpOnly and SameSite=Lax, and the CSRF cookie is SameSite=Strict. Logout revokes the session. The URL fragment is removed after exchange, and no token value is included in logs or reports.
- Owner routes require a valid session. Mutations require the exact `127.0.0.1:8765` Host and Origin, a matching CSRF cookie/header/hash, and same-origin Fetch Metadata when present. Approval is a safe GET; task creation requires a fresh single-use five-minute HMAC context and the explicit owner POST. Source claim and normalized observed Origin/referrer are persisted separately as unverified attribution.
- The controller registry contains only the fixed report formatter/doc-report and invoice analyzer/doc-invoice mappings below the protected install root. No arbitrary executable, argv, filesystem path or grant is accepted. Production launch returns unavailable without creating a task while G3 workers are absent. The actual browser test injects only the A3 private probe in its test harness.
- A2 was revalidated on the demonstration machine after synthetic permitted documents were added: 60 worker checks passed, all 14 fixtures were present and hash-verified, all originals and trusted state remained protected, and the worker identity was the existing non-administrator `AclaisWorker`. See `evidence/A2.md` and `evidence/a2-access-summary.json`.
- Actual Windows browser evidence: Chrome and Edge each completed the owner isolation/approval flow. Tools at `localhost:8766` and receiver-host probe at `[::1]:8767` received no ACLAIS cookie; cross-origin API attempts were rejected with no cookie; approval GET created no task. A single explicit owner approval started the A3 private worker under its Job Object; the private child was confirmed in-job and both worker and child were verified stopped by their recorded Windows process creation identities after cancellation. Sanitized results are in `evidence/A8.md` and `evidence/a8-sanitized-summary.json`.
- Ten portable A8 route and registry tests cover one-time bootstrap and cookie fixation, missing/expired sessions, worker credentials on owner routes, invalid Host, cross-origin Origin, missing CSRF, rejected executable arguments, undeclared query parameters, approval GET with no launch, separate source/observed attribution, single-use approval context, and logout. They do not substitute for the Windows browser evidence.
- G1 remains incomplete until A9 and A10; receiver G2 and Document Tools G3 remain gated.

## Next step

A9 connected dashboard follows A8. G1 remains incomplete; receiver G2 and Document Tools G3 remain gated.
