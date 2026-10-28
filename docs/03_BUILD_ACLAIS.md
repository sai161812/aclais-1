# Component 1 — ACLAIS
Read 00, 01, 02, 06 and 07 before implementation. Gate G1 must pass before building receiver production code. In G1, cover receiver-dependent cases only with explicitly test-only injected typed response models; real receiver integration belongs to G4.

## Purpose and deliverables
Deliver a working controller, broker, restricted launcher, protected fixture store, verifier and finished dashboard. Deliver provisioning, startup, doctor, teardown and reset scripts, automated tests, locked dependencies, RUNBOOK.md and evidence/G1.md. No stubs in this component's final gate. Only receiver integration can be explicitly pending G4.

## Step 1 — environment and provisioning
Inspect actual Windows version, NTFS, Python/Node installations, ability to provision a local standard account, and existing repository. Preserve user work. If working on Linux/macOS, implement portable modules but report Windows checks BLOCKED. Do not replace the Windows requirement with a container sandbox without revising the specification with the user.

Create a dedicated C:\ACLAIS-Lab root and ownership sentinel. Partition into store/originals, store/verified-output, state, evidence, work, and baseline. Keep source code/venv outside worker-writable directories. Install dependencies before presentation; all runtime assets must work offline.

Provision AclaisWorker as non-admin. Generate its password securely; never check it in, print it, put it on a command line, place it in an environment block, or embed it in a fixture. Store it in the controller owner's Windows Credential Manager as a versioned `CRED_TYPE_GENERIC` entry via `CredWriteW`, target `ACLAIS-1/AclaisWorker`. Runtime reads it with `CredReadW`; validate the opaque blob length/format, copy it only into a bounded mutable wide-character buffer for the launch call, zero that copy immediately afterward, and free the returned credential buffer with `CredFree`. Do not put the password in the worker's Credential Manager. Record only the worker SID and installation manifest. Account creation/ACL edits require an explicit one-time elevated setup; runtime must not silently elevate. The ordinary owner controller must be able to retrieve its own stored credential without elevation.

Configure exact allowlisted permissions: owner/SYSTEM/admins control trusted state; worker cannot read originals, write parent directories, delete children, replace/rename originals, change DACL/ownership, read controller credentials or edit code. Worker gets read-only selected copies and modify access only to its current temporary-output directory. Grant only traverse on the lab root and the `store` and `work` parents so the worker can reach those scoped children; do not grant list, create, write or delete rights there. Disable inheritance and replace each owned DACL with the explicit allowlist, removing unrelated explicit as well as inherited grants. Validate effective access, including parent `DELETE_CHILD` rights; do not infer safety from an ACL command returning zero. Do not apply a broad deny to a group that contains the owner.

Protect application source and committed evidence in the checkout with a worker-SID-specific deny on the source/evidence subtrees when the checkout volume grants broader inherited rights. Keep the denial scoped to those subtrees; do not change an ancestor or a broad group ACL. The protected runtime copy remains separately allowlisted under `C:\ACLAIS-Lab\code`.

The account is a limited workspace boundary, not a full machine sandbox. Run only the known seeded workers. It may read unrelated world-readable host files; do not claim otherwise. It has network access.

Before UI work, launch an independent private probe as the actual worker SID. It must read its selected copy and write scratch output; fail to read the confidential original, overwrite/delete/rename originals, replace the directory, modify protected DACLs/ownership, alter trusted state or evidence, read the owner's credential, or read/write application source and checkout evidence. Capture exact Windows errors and effective identity. Verify seeded fixture presence and hashes against the trusted manifest before launch. When Windows reports path-not-found for a protected rename, accept it only if the seeded target matched its manifest hash before launch and owner-side checks confirm it remains present and unchanged after the probe. This is the first mandatory checkpoint.

## Step 2 — reliable launcher
Implement one narrow Windows adapter around `CreateProcessWithLogonW` using the real local AclaisWorker account. Do not use `LOGON_NETCREDENTIALS_ONLY`, which does not provide the required different local process identity. Pass a non-null absolute `lpApplicationName`, a bounded correctly quoted argument vector, a controlled working directory, an explicit minimal Unicode environment block, and logon flags that do not load a worker profile unless a documented dependency requires it. Set `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW`; never pass a null environment block that would inherit owner variables. Do not use `shell=True`, arbitrary shell strings, PATH-based executable lookup, or inherited owner secrets. Verify the actual process token SID and that the token is non-administrator before resuming. A failed identity/verification is a launch failure; never fall back to the owner.

Capture stdout and stderr through separate redirected pipes. Mark only the intended child write handles inheritable; keep all unrelated parent handles non-inheritable and close the parent's write handles immediately after process creation. Drain both pipes concurrently so neither can deadlock the worker. Bound retained bytes and each JSONL line to 16 KiB, continue draining after truncation, identify truncation, redact secrets, and label all worker output `worker_reported`. Record process exit code and SID from trusted handles/token inspection, not from worker output.

Create a Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway flags. Create the process suspended, call `AssignProcessToJobObject`, verify assignment, then `ResumeThread`. If job creation/configuration/assignment, token verification, or resume fails, terminate the still-suspended process, wait for its exit, close all handles/pipes, and fail closed. Retain process, primary-thread, and job handles plus process creation identity while active; do not manage by PID alone. On cancel/timeout/policy denial/shutdown, revoke first, terminate the job, wait for observed exit, drain both streams, then close handles. A crash must close the final job handle and terminate all job processes. Never quietly claim job containment without the harmless child-process test on Windows and the demonstration machine.

At runtime, startup doctor checks SID, effective fixture permissions, roots, secret access, DB migration state, code paths and ability to assign the job. Disable task launch when unhealthy.

## Step 3 — controller and broker
Implement shared contracts exactly. SQLite holds tasks, contract grants, token hashes, incidents, events, published outputs and request deduplication. Protect the DB directory. Serialize task creation; never race two launches past the single-worker limit.

Document registry owns canonical paths. Requests accept opaque IDs only. No user path joins, UNC paths, alternate data streams, ../ escapes or absolute path arguments. Reject reparse points in managed roots and verify provisioned roots at startup. Since workers cannot mutate the originals directory, keep that invariant throughout execution.

Selected input is copied by controller before worker starts. Compute trusted baseline inventory/hashes before launch; record file sizes, relative names and file identity where available. Fix fixture set for a task. Revoke in DB under the operation lock before terminating. Persist evidence failures honestly.

Output broker accepts bounded text rather than moving a worker-supplied path. Follow the publication journal and crash-recovery protocol in `02_SHARED_CONTRACTS.md`: reserve request ID/body hash in SQLite, write a unique same-volume staging file, flush/verify it, perform a no-replace same-volume move, and commit published metadata/cache only after the final file is verified. The response and output API must not expose unfinalized files. A request retry must neither duplicate nor overwrite an output. Never overwrite a protected original. Keep imported Markdown/JSON inert. A formatter result is not a trusted program.

## Step 4 — verifier and evidence
Verifier runs as owner, not worker. Compare full fixture inventory and hashes after exit, not only the target filename. Record missing/new/renamed files. Controller collects broker request decisions; worker stdout is tagged worker_reported. A worker saying ACCESS_DENIED is not independently observed OS telemetry.

Independent Windows gate probes establish effective access. At runtime, the trusted broker event proves the denied broker request, inventory checks prove observed final state, and worker reports describe direct attempts. UI must keep those evidence categories distinct. No claim of continuous OS syscall monitoring.

Receiver adapter supports pass/fail/unknown and is covered by explicitly test-only injected response models in G1. Do not create a receiver process, receipt database, mock HTTP endpoint or receiver administration UI in production during G1. In G4 replace adapter assumptions with real receiver responses. Absence of connection or unknown run is unknown, not pass. Do not store canary contents in general event logs.

Persist events before presenting them. Database failure stops new operations. Logging is owner-protected, not cryptographically tamper-proof; do not market it as immutable.

## Step 5 — premium UI
Implement 06 fully: workspace, task approval, task detail, incident drawer, status/error states. Use the exact screen-to-API mappings in `06_UI_DESIGN.md` and real backend data. Before Document Tools exists, exercise approval and harmless task flows only through the private test probe harness below. Mock event fixtures may be used in isolated UI tests, never in production routes.

## G1 testing before receiver and hostile tools exist
G1 is completed before production receiver code or either Document Tools worker is built. Put small, private probe programs and fixtures under test-only paths (for example `tests/probes/`); do not register them in the production tool registry, package them as app tools, expose a “probe” or attack page/button, or reuse them as the G3 hostile workers. Probes may verify selected-copy reads, output publication, broker schema/policy denial, and actual Windows ACL behavior only against disposable sentinel-owned test fixtures. They must not implement report formatting, invoice analysis, confidential-data upload, or later hostile-tool behavior.

Use a harmless private probe for successful different-SID launch/output and focused broker probes for invalid/out-of-scope requests. Exercise direct denied read/write/delete/rename/DACL/evidence operations against disposable fixture copies with an independently verified worker SID. For receiver-dependent UI/evidence states, inject typed test data into isolated unit/UI tests; label those results as fixtures and never render them as production telemetry. G4 replaces all receiver assumptions with the real receiver. The two hostile production workers arrive only in G3 after G1 and G2 pass.

## G1 acceptance
- Private probes are test-only and are not registered, packaged, or exposed as production tools/UI. No production receiver or hostile Document Tools code is present in G1.
- Portable CI, Windows-specific automated checks, and mandatory demonstration-machine checks are reported as separate lanes; all required checks for each lane pass before G1 PASS.
- Actual Windows different-SID launch and all required direct permission tests pass.
- Runtime retrieval uses the owner's Windows Credential Manager; the actual AclaisWorker SID is verified after alternate-user launch; no password appears in argv, environment, logs, stdout or stderr.
- Separate stdout/stderr capture is bounded and drained; Job Object assignment occurs before resume; assignment failure is fail closed; parent/job closure leaves no worker or child.
- Broker allows selected read and a valid output; denies unselected read, replace and delete.
- Strict request and response models reject unknown/extra fields, coercion, invalid unions, body overflow and invalid output/tool combinations without side effects.
- Output publication/retry/crash tests show one consistent file/DB result, no overwrite, no duplicate output, and fail-closed recovery at every journal boundary.
- Deterministic race checks cover policy denial, cancellation, timeout, process exit and shutdown precedence; terminal cause is never overwritten.
- Controller restart invalidates stale tokens and reconciles interrupted tasks; deadline, cancellation, controller-close cleanup and restart recovery pass.
- Token forgery, expiry, revocation, replay, owner-route access and cross-task misuse fail correctly.
- Browser CSRF, unknown origin/Host, untrusted HTML/Markdown and path-like IDs cannot obtain extra authority.
- Evidence is independently computed, truthful on failures and persistent on refresh.
- A subsequent benign task succeeds after a denied task; no active worker/token remains.
- Keyboard-accessible premium UI works at 1366×768 and 1920×1080 with no clipping or console errors.
- Component's build/type/lint/tests pass. Windows-only tests actually run on Windows.

Write evidence/G1.md with environment, commands, exit codes, results, screenshots, known limits and commit/hash. Only then mark G1 PASS.

## Primary implementation references
- Windows file permissions: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
- Windows Credential Manager retrieval: https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw
- Alternate-user creation: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
- Job ownership/termination: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
- Process/job assignment: https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
- No-replace file publication: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
Consult current official API documentation before binding native functions. These references support the primitives; they do not validate our eventual implementation.
