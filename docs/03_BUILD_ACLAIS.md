# Component 1 — ACLAIS
Read 00, 01, 02, 06 and 07 before implementation. Gate G1 must pass before building receiver production code. Use test doubles for receiver responses in G1 and label them as such; real receiver integration belongs to G4.

## Purpose and deliverables
Deliver a working controller, broker, restricted launcher, protected fixture store, verifier and finished dashboard. Deliver provisioning, startup, doctor, teardown and reset scripts, automated tests, locked dependencies, RUNBOOK.md and evidence/G1.md. No stubs in this component's final gate. Only receiver integration can be explicitly pending G4.

## Step 1 — environment and provisioning
Inspect actual Windows version, NTFS, Python/Node installations, ability to provision a local standard account, and existing repository. Preserve user work. If working on Linux/macOS, implement portable modules but report Windows checks BLOCKED. Do not replace the Windows requirement with a container sandbox without revising the specification with the user.

Create a dedicated C:\ACLAIS-Lab root and ownership sentinel. Partition into store/originals, store/verified-output, state, evidence, work, and baseline. Keep source code/venv outside worker-writable directories. Install dependencies before presentation; all runtime assets must work offline.

Provision AclaisWorker as non-admin. Generate its password securely; never check in, print, place on a command line, or embed in a fixture. Use Windows Credential Manager or equivalent owner-only OS secret storage for the controller. Record only the account SID and installation manifest. Account creation/ACL edits may need an explicit one-time elevation; runtime must not silently elevate.

Configure allowlisted permissions: owner/SYSTEM/admins control trusted state; worker cannot read originals, write parent directories, delete children, replace/rename originals, change DACL/ownership, read controller credentials or edit code. Worker gets read-only selected copies and modify access only to its current working-output directory. Disable inherited broad grants within owned sensitive folders where necessary. Validate effective access, including parent DELETE_CHILD rights; do not infer safety from an ACL command returning zero. Do not apply a broad deny to a group that contains the owner.

The account is a limited workspace boundary, not a full machine sandbox. Run only the known seeded workers. It may read unrelated world-readable host files; do not claim otherwise. It has network access.

Before UI work, launch an independent probe as the actual worker SID. It must read its selected copy and write scratch output; fail to read the confidential original, overwrite/delete/rename originals, replace the directory, modify a DACL, or alter controller evidence. Capture exact Windows errors and effective identity. This is the first mandatory checkpoint.

## Step 2 — reliable launcher
Implement one narrow Windows adapter with explicit executable path, correctly quoted argv, controlled working directory and minimal environment. No shell=True, arbitrary shell strings, or inherited owner secrets. Launch as the dedicated identity using an appropriate documented Windows logon API. Verify actual token SID and standard-user privileges. A failed identity change is a launch failure, never a reason to fall back to the owner.

Use fixed interpreter and script paths. Worker configuration file is read-only to worker. Code directories are read/execute only. Set output size and runtime bounds. Keep process handles/start timestamps, not just PIDs.

Preferred required containment mechanism for this pack: Windows Job Object, kill-on-close, no breakaway. Create the process suspended, assign it to the job before resume, and fail closed if assignment fails. Verify on the target machine that a harmless child process is terminated with its parent/job. This is a stronger implementation detail than the earlier conversation's single-process minimum; it is required by this pack to avoid orphan workers with reused identity. Do not quietly claim job containment without the test. Closing controller must not leave workers active.

At runtime, startup doctor checks SID, effective fixture permissions, roots, secret access, DB migration state, code paths and ability to assign the job. Disable task launch when unhealthy.

## Step 3 — controller and broker
Implement shared contracts exactly. SQLite holds tasks, contract grants, token hashes, incidents, events, published outputs and request deduplication. Protect the DB directory. Serialize task creation; never race two launches past the single-worker limit.

Document registry owns canonical paths. Requests accept opaque IDs only. No user path joins, UNC paths, alternate data streams, ../ escapes or absolute path arguments. Reject reparse points in managed roots and verify provisioned roots at startup. Since workers cannot mutate the originals directory, keep that invariant throughout execution.

Selected input is copied by controller before worker starts. Compute trusted baseline inventory/hashes before launch; record file sizes, relative names and file identity where available. Fix fixture set for a task. Revoke in DB under the operation lock before terminating. Persist evidence failures honestly.

Output broker accepts bounded text rather than moving a worker-supplied path. Validate output kind and syntax; write a fresh file in controller-owned verified-output using an atomic temporary-file rename. Never overwrite a protected original. Keep imported Markdown/JSON inert. A formatter result is not a trusted program.

## Step 4 — verifier and evidence
Verifier runs as owner, not worker. Compare full fixture inventory and hashes after exit, not only the target filename. Record missing/new/renamed files. Controller collects broker request decisions; worker stdout is tagged worker_reported. A worker saying ACCESS_DENIED is not independently observed OS telemetry.

Independent Windows gate probes establish effective access. At runtime, the trusted broker event proves the denied broker request, inventory checks prove observed final state, and worker reports describe direct attempts. UI must keep those evidence categories distinct. No claim of continuous OS syscall monitoring.

Receiver adapter supports pass/fail/unknown and is covered by fake-response unit tests in G1. In G4 replace integration assumptions with real receiver responses. Absence of connection or unknown run is unknown, not pass. Do not store canary contents in general event logs.

Persist events before presenting them. Database failure stops new operations. Logging is owner-protected, not cryptographically tamper-proof; do not market it as immutable.

## Step 5 — premium UI
Implement 06 fully: workspace, task approval, task detail, incident drawer, status/error states. Use real backend data. Test approval and harmless probe workflows locally. Do not wait until the end of the project to build the core UI. Mock event fixtures may be used in isolated UI tests, never in production routes.

## G1 acceptance
- Actual Windows different-SID launch and all required direct permission tests pass.
- Broker allows selected read and a valid output; denies unselected read, replace and delete.
- Child-job containment, deadline, cancellation, controller-close cleanup and restart recovery pass.
- Token forgery, expiry, revocation, replay, owner-route access and cross-task misuse fail correctly.
- Browser CSRF, unknown origin/Host, untrusted HTML/Markdown and path-like IDs cannot obtain extra authority.
- Evidence is independently computed, truthful on failures and persistent on refresh.
- A subsequent benign task succeeds after a denied task; no active worker/token remains.
- Keyboard-accessible premium UI works at 1366×768 and 1920×1080 with no clipping or console errors.
- Component's build/type/lint/tests pass. Windows-only tests actually run on Windows.

Write evidence/G1.md with environment, commands, exit codes, results, screenshots, known limits and commit/hash. Only then mark G1 PASS.

## Primary implementation references
- Windows file permissions: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
- Alternate-user creation: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
- Job ownership/termination: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
Consult current official API documentation before binding native functions. These references support the primitives; they do not validate our eventual implementation.
