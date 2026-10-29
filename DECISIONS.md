# Decisions

This log records the A0 specification decisions, A1 foundation choices, A2 protected-fixture decisions, A3 launcher choices, repository-structure checkpoint, A6/A7 lifecycle and evidence decisions, and A8 owner-authentication decisions. Later production controller components remain gated.

## D-001 — Preserve the supplied specification pack

The nine files in `docs/` are the project authority for scope, contracts, component order, interface behavior, and verification. Keep the three components in this repository and implement only the explicitly requested checkpoint.

## D-002 — Use the explicitly supplied GitHub repository

The user supplied `https://github.com/sai161812/aclais-1.git`. Authenticated GitHub metadata verified owner `sai161812`, repository `aclais-1`, public visibility, and default branch `main` before the first push. The repository had no branches or commits, so the documentation-only baseline was created on local `main` before `aclais-prototype`. After the first push to the empty remote, GitHub reports `aclais-prototype` as the current default; no settings API was used. Do not create another repository or replace a remote.

## D-003 — Keep this checkpoint documentation-only

A0 was limited to readiness and specification reconciliation, including affected specs, decisions, build status, and the A0–A10 plan; it implemented no application code. Later checkpoints follow the sequence in `IMPLEMENTATION_CHECKPOINTS.md` and require their listed prerequisites.

## D-004 — Track safe templates and summaries; ignore sensitive runtime material

Ignore credentials, local environments, runtime databases, raw receipt payloads, generated confidential fixtures, unsanitized logs, and build/test output. Keep synthetic fixture templates and sanitized test summaries trackable.

## D-005 — Isolate browser owner cookies by host

Keep all listeners loopback-only, but serve ACLAIS at `127.0.0.1:8765` and Document Tools at `localhost:8766`. Bind Document Tools to `127.0.0.1` and `::1` only because Windows resolves `localhost` to both addresses. HTTP cookies are not scoped by port, so the distinct hostnames prevent the browser from sending ACLAIS's host-only owner cookie to Document Tools. Use `SameSite=Lax` because the approved launch is a side-effect-free cross-host top-level GET; retain exact-Origin and anti-CSRF checks for mutations. The receiver binding was later corrected to `[::1]:8767` by D-035 so it cannot share the owner-cookie host.

## D-006 — Retrieve the worker logon secret from the owner's Credential Manager

Provision an owner-only generic credential and retrieve it with `CredReadW` at launch. Pass the local account to `CreateProcessWithLogonW` as a real user logon; do not use network-credentials-only mode, a shell, command-line password, inherited environment, or owner-identity fallback. Start suspended, verify SID/non-admin token, assign to a kill-on-close/no-breakaway Job Object, then resume. Capture stdout and stderr on separate bounded pipes.

## D-007 — Journal filesystem publication and retries

SQLite and NTFS are separate transactions. For controller outputs and receiver receipts, commit an intent/idempotency row first, write and flush an exclusive same-volume staging file, move to a unique final name without replacement, verify hash/size, and commit the published/receipt row before returning success. On restart reconcile journals fail closed; API reads expose only finalized rows with matching files. Bind retries to request ID plus canonical body hash.

## D-008 — Serialize lifecycle outcomes under one task lock

Serialize broker admission, policy denial, cancellation, timeout, process exit, shutdown and recovery under a per-task lock. A policy denial admitted while the task is active commits revocation before later contenders; an already committed cancellation/timeout/shutdown cannot be replaced. Deadline checks occur before new operations at the boundary. Normal completion waits for process exit and in-flight broker requests. Terminal cause is immutable.

## D-009 — Use strict operation-specific models

Every JSON route has strict request and response schemas with extra fields/coercion rejected. Broker requests use a discriminated union so each operation has exactly its permitted fields. Malformed requests return validation errors with no side effect; a well-formed forbidden operation admitted while the task is `RUNNING` atomically records the policy incident and `RUNNING → REVOKING` cause before the 403 response and worker termination. Receiver ingest also has request-ID idempotency.

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

## D-026 — Version controller persistence with immutable intent and audit history

The ACLAIS controller stores only controller-selected document paths and grants in a protected SQLite database. Versioned SQL migrations are checksum-verified using normalized LF line endings; connections enable foreign keys, WAL, and `synchronous=FULL`. Task identity, document identity/path, contract grants, credential digest/expiry, request key/body hash, and output journal intent are immutable in SQLite; state, revocation, response finalization, and verifier metadata change only through their defined transitions. Task transitions, grants, events, incident linkage, completed replay responses, and output publication states receive database guards appropriate to their immutability. Recovery may move an output from published to inconsistent so subsequent owner reads withhold it. Receiver receipt storage remains in the later receiver-owned database; A4 supplies and tests its strict receipt journal value model without building that service or mixing its authority into the controller database.

## D-027 — Use backend Pydantic models as the contract source

Backend strict Pydantic models define ACLAIS and receiver wire records, request/response shapes, the broker operation union, query bounds, IDs, and journal record values. Generate `shared/openapi.json` and the frontend TypeScript contract from those models. Keep generated files checked in and reject unexplained generator diffs. Only the existing health endpoint is mounted during A4; schema coverage of later routes is not a claim that those routes already work.

## D-028 — Make verification a state on the success and revocation paths

Both benign and revoked task flows enter `VERIFYING`: normal completion is `RUNNING → VERIFYING → COMPLETED`, and denial/cancel/timeout/shutdown pass through `REVOKING → VERIFYING`. The first persisted revocation cause remains unchanged through termination and terminalization. `BLOCKED` requires policy denial, `CANCELLED` requires cancellation, and only verified successful exit can produce `COMPLETED`; other containment/verification outcomes fail closed as `FAILED`.

## D-029 — Resolve selected input from one active task copy

The broker reads only `work/selected-inputs/<task UUID>/<document ID><extension from the trusted registry>`. It derives the task UUID from the hashed bearer credential, validates the requested document against the immutable task contract, and never reads the original path. A6 creates the task directory with worker read/execute rights only, keeps its parent traverse-only/non-listable, provides the fixed path to the launcher, and removes the active copy after containment and verification. This avoids leaving prior task inputs available to the shared worker SID.

## D-030 — Finalize output, replay response and audit event together

`output_records` is the publication journal and source of output metadata; there is no second output file table. After the final file is hash/size-verified, one SQLite transaction advances `staged → file_committed → published`, appends the `output_published` broker event, and completes the request's exact replay response. A selected-read response and its one allow event are committed together. A replay adds no filesystem effect or duplicate event. Any failure before that transaction leaves output unserved.

## D-031 — Inject broker routes only from trusted startup assembly

`create_app` mounts the worker broker route only when a trusted `BrokerService` is injected. The output download route requires both an `OutputPublisher` and an owner-authorizer dependency; no output route is mounted by the default app, and A8 supplies the product owner session/CSRF implementation. Route tests inject a private test authorizer and do not claim owner authentication is complete. The broker's durable credential, task, contract and expiry checks remain authoritative for worker operations.

## D-032 — Persist verified worker identity before resume and reconcile only stopped identities

The lifecycle coordinator and broker share one per-task reentrant lock. Task admission checks the single-worker slot in the same SQLite transaction that creates the task. After the launcher verifies the alternate-user SID and assigns the suspended process to its kill-on-close Job Object, SQLite commits the task as `RUNNING`, the worker PID/SID/Windows creation time, and only the credential hash before `ResumeThread`. Every authorized broker operation revalidates under the shared lock. Denial, cancellation, timeout, and shutdown commit revocation and credential invalidation before Job Object termination; revoked paths then enter `VERIFYING` before terminalization. Startup revokes all nonterminal credentials, verifies PID plus creation time and SID are stopped without terminating a possibly recycled PID, reconciles output journals, moves interrupted `RUNNING` or `REVOKING` tasks through `VERIFYING`, records them as `FAILED`, removes only their task directories, then accepts broker traffic. An abrupt restart with no prior cause ends as `RECOVERY_INTERRUPTED`; an already committed revocation cause remains terminal. Missing durable staged output becomes inconsistent and keeps the controller unavailable. If a live identity cannot be verified stopped, startup remains closed.

## D-033 — Keep the persisted 30-second contract within SQLite's time comparison precision

SQLite `julianday()` uses floating-point day values, so two ISO timestamps exactly 30 seconds apart can compare a few microseconds beyond the schema's 30-second upper bound. Task creation checks the proposed expiry using the same SQLite expression and, only when needed, moves expiry backward by the smallest microsecond count that satisfies the persisted bound. The contract never exceeds 30 seconds; fixed-time tests continue to retain an exact 30-second interval where SQLite represents it safely.

## D-034 — Attribute A7 evidence and defer final inventory until containment

The owner-side verifier captures one immutable pre-launch inventory of the trusted fixture tree, then waits for controller confirmation that the recorded worker and job are stopped before scanning again. Inventory entries record names, existence, sizes and SHA-256; selected-input and published-output hashes are kept in the protected report. Incomplete termination, absent baseline, scan timeout, receiver outage and unknown run remain unknown. A policy incident can become BLOCKED only when the independent report passes integrity and confidentiality checks; no receiver run leaves incident confidentiality unknown.

Evidence records preserve source boundaries: controller observations, broker decisions, worker-reported stdout/stderr, verifier checks and typed receiver observations. Workers cannot submit an authoritative verification result. Raw inventories, identifiers and worker output stay in owner-protected local evidence; Git summaries omit fixture paths/hashes, receipt identifiers, worker text and runtime paths while identifying the tested source revision or source-tree digest. The ACLAIS receiver adapter remains an interface with test-only typed responses; it creates no receiver service, endpoint or production tool.

## D-035 â€” Give the receiver a distinct loopback host

Ports do not isolate browser cookies. A receiver bound to `127.0.0.1:8767` would share the host-only cookie host with ACLAIS at `127.0.0.1:8765`. Bind the later server-to-server receiver only to IPv6 loopback `[::1]:8767`; keep ACLAIS on `127.0.0.1:8765` and Document Tools on `localhost:8766`. The receiver remains private service-to-service traffic and is not a browser origin. Private A8 browser probes verify no owner cookie is sent to either other host.

## D-036 â€” Bootstrap owner sessions without persisting raw secrets

At protected startup, create a random 256-bit, 15-minute one-time bootstrap token in memory, persist only its SHA-256 hash in the owner database, and open its URL with the token in the fragment. The fragment is never sent in the HTTP request; the page removes it immediately after reading it, before the exchange POST. Bootstrap exchange requires exact ACLAIS Origin and atomically consumes the token while creating a session. Persist only hashes for the 8-hour absolute owner session and CSRF value. The session cookie is host-only, HttpOnly, Path=/, SameSite=Lax; the CSRF cookie is host-only, readable only by same-origin page code, Path=/, SameSite=Strict. Owner mutations require exact Host and Origin, CSRF cookie/header/hash match, and `Sec-Fetch-Site: same-origin` when available. Opening the approval page has no persistent mutation or launch effect.

Each approval GET signs the session, fixed tool claim, user source claim, and normalized observed Origin/referrer into an in-memory HMAC context with a five-minute expiry and a single-use nonce. The explicit owner POST returns that observation separately from the `launch_source_claim`; both are untrusted attribution, not verified browser provenance. Strip referrer paths, query and fragment. Require and consume the signed context once for task creation; strict body schemas reject executable paths, argv, grants and filesystem paths.

## D-037 â€” Keep the production worker allowlist fixed and gate workers until G3

The fixed controller registry maps only `report_formatter/doc-report` and `invoice_analyzer/doc-invoice` to explicit worker entrypoints beneath `C:\ACLAIS-Lab\code\document-tools`. Client requests cannot name an executable or arguments. If a fixed entrypoint or launcher is unavailable, do not create a task and return protection unavailable. A8 browser verification injects the existing harmless A3 private probe only in the test harness; the probe is never a production tool, route, package or UI option. Production Document Tools workers remain gated until G3.

## D-038 â€” Reconcile missing permitted A2 originals with synthetic templates

The demonstration runtime initially lacked the three permitted originals already named in the trusted registry. Add trackable fabricated templates for report, notes and invoice documents; update A2 provisioning to seed and hash them; use the scoped A8 prerequisite updater only when the protected lab exists, controller is stopped, sentinel/identity match and any existing bytes match their template. Apply owner-only DACLs to each file and reconcile the manifest/trusted hashes. Re-run the actual A2 worker probe before using those documents; raw runtime files remain outside Git.

## D-039 — Derive dashboard state from same-origin persisted responses

Serve the built owner dashboard and its assets from the authenticated ACLAIS origin. Keep the Vite preview on `127.0.0.2` without an API proxy so it cannot share the owner cookie. The UI treats network reachability and protection readiness as separate states: a failed request is disconnected; a reachable failed preflight is protection unavailable; pending G1 gates or evidence stay pending/unknown. Refresh reloads health, document registry, task summaries and selected task events from the backend, merges events by sequence, and never carries forward a green state after an outage. Active tasks refresh every 500 ms only while connected and otherwise back off. Worker output is size-bounded inert text. Live-backend visual/API failure tests may alter only a private health response; they do not synthesize activity, task status, broker telemetry, or evidence. Separately isolated typed UI contract fixtures are permitted by specification 03 for receiver-dependent presentation branches: label them visibly, intercept their entire API surface, and never call their screenshots enforcement or production telemetry (D-044).

## D-040 — Keep owner routes responsive during broker work and cancellation

Run synchronous broker execution in FastAPI's thread pool so slow policy work cannot starve health or owner requests on the event loop. Bind the owner cancellation route to the controller callback under a stable local name so the route handler cannot recursively shadow it. Decode persisted incident evidence lists back to the contract's immutable tuple before response validation. These fixes keep the UI connected to the existing broker/persistence authority without adding a UI-side status source.


## D-041 ? Measured readiness and complete source protection

Replace the historical static G1 health placeholder with measured core readiness. The owner-side check validates the sentinel, SID/non-admin membership, effective DACL allowlist, fixture/code inventory and source/dependency/script denials. Native checks retrieve and immediately zero the owner credential, create/configure a kill-on-close job, and inspect the actual database integrity/migration version. Cache only display checks for five seconds; admission repeats fresh checks before creating a task. Each launch still verifies its actual suspended token and job assignment. A lifecycle controller that no longer accepts work always clears protection readiness, independently of filesystem checks. Missing G3 entrypoints remain unknown/unavailable; a historical G1 PASS cannot fabricate production readiness. Protect the backend virtual environment, frontend dependencies/build, launch scripts and schemas alongside source. Canonicalize mixed dependency ACL ordering without dropping existing ACEs before repeatable denial updates. Apply DACL-only changes without requesting SACL privileges.

## D-042 ? Reconcile every publication, including terminal tasks

Restart validates published rows for all known tasks, not only interrupted workers. Missing or tampered committed content becomes inconsistent and remains withheld. Unknown output files are moved without replacement into an owner-only quarantine and that startup refuses; subsequent startup can proceed with the unserved files retained for review. The audit found 43 old private-browser test orphans, quarantined them and verified all 23 production-namespace published records independently. Private browser outputs now have separate private namespaces so tests cannot contaminate production recovery.

## D-043 ? Sentinel-scoped owner operations

Use a process-held nonblocking Windows byte lock for controller/operator admission. Owner start/stop remains foreground and identity-bound; stop uses PID plus creation time and SID, a protected instance request and observed exit. Reset refuses controllers/workers/nonterminal tasks, archives evidence and a consistent SQLite backup, restores fixed templates, rotates the canary and journals crash recovery. Retirement restores only recorded source DACLs, deletes only the fixed owner credential and archives the owned runtime. Preserve an account without recorded pre-installation provenance. The active lab is not uninstalled during acceptance; disposable retirement and wrong-confirmation tests exercise the safety boundary.

## D-044 ? Honest test lanes and isolated presentation fixtures

An NTFS-only publication test had inherited the module portable marker; give portable tests individual markers and explicitly exclude Windows enforcement in local/hosted portable selectors. G1 target checks reject missing, failed or skipped mandatory results. Live dashboard integration remains backend-driven. A separately intercepted, no-owner-session browser context uses strict typed fixtures only for verified-receiver and containment-failure presentation; its screenshots visibly say no enforcement or receiver evidence. Keep this `windows_ui` result distinct from real worker/receiver observations. The production receiver remains pending G4, and actual unavailable evidence stays unknown. Await refresh promises so slow checks do not produce overlapping polling; idle polling is two seconds and display times explicitly identify IST.

## D-045 ? Bounded invalid-request throttling

Throttle 20 invalid requests per 30 seconds using at most 256 hashed credential buckets. Unknown/forged credentials share one anonymous bucket; valid task credentials retain independent buckets. Return strict 429 RATE_LIMITED without filesystem effects or fabricated policy incidents. Expiration restores service and a forged flood cannot exhaust another valid task's bucket. Extend the shared generated OpenAPI/TypeScript error contract together with broker behavior and behavioral tests.

Implementation references checked: Microsoft SetFileSecurityW (DACL_SECURITY_INFORMATION), CredDeleteW (generic target, flags zero, ERROR_NOT_FOUND idempotence), and Python 3.12 msvcrt.locking (LK_NBLCK, process-held byte range). No credential values are recorded.


## D-046 ? Owner-delegated resolution of the PR base

GitHub initially had only aclais-prototype and selected it as default, making the requested self-PR impossible. The owner explicitly delegated the base decision during A10. Publish the unchanged original documentation baseline 0752747004fc689e07f8e55435964bf4d267fd12 as main and make main default; retain aclais-prototype and its full existing history as the working branch. Both operations succeeded, and authenticated metadata independently confirmed public sai161812/aclais-1 with default main. No repository was created, visibility/remote changed, history rewritten, merge performed or reviewers requested. This is a specific owner-authorized workflow correction; future repository settings/default pushes still require a separate instruction. The one PR remains draft and portable PR checks target main.


## D-047 ? Protect the source namespace, including writable ancestors

The workspace drive grants ordinary authenticated users Modify rights on source ancestors. Component-file denials alone therefore do not protect a source path from an ancestor rename; Git metadata also had protected inheritance. Deny the worker at the owned repository root and explicitly protect Git metadata, retaining recorded DACL snapshots. During every controller lifetime, retain non-inheritable directory handles for the source path and each non-volume ancestor with FILE_LIST_DIRECTORY, FILE_SHARE_READ|FILE_SHARE_WRITE, OPEN_EXISTING and FILE_FLAG_BACKUP_SEMANTICS. Excluding FILE_SHARE_DELETE prevents directory deletion/rename. Failure to acquire a guard fails controller construction; release only after shutdown confirms worker cleanup. Do not change permissions outside the owned repository.

The independent A2 harness holds equivalent native guards. Its worker tests request DELETE access without actually renaming any workspace path, and separately deny Git metadata read/write. A Windows regression uses the real Python controller's handles (disables the harness-owned guards), executes the full actual-SID access probe and verifies the retained handles are closed after shutdown. An initial metadata-only access-zero guard did not enforce sharing; actual worker checks caught this, and FILE_LIST_DIRECTORY fixed it. No success was recorded for that failed attempt. Final A2 count is 75 on this machine. Microsoft reference: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew .


## D-048 ? Refuse operator junctions and redact bootstrap-open failures

Operator path checks inspect lstat metadata (and Windows junction identity), not stat metadata that follows the target. A real NTFS junction under a disposable owned fixture must be refused before any external target is touched. A browser-open exception is handled with a fixed event name only; its text/traceback and bootstrap URL never reach logs. Portable synthetic-secret failure tests and the actual Windows junction test verify these behaviors. These are failure-path corrections, not new product scope.


## D-049 - Synchronize G1 reconnect evidence with real native checks

A repeat audit of 09cee7d passed 12 Windows checks but the connected-dashboard test timed out while waiting five seconds for reconnection. Its readiness request performs the real native audit with a 45-second bound; the five-second test wait began before that response. Await an actual successful health response with a bounded 50-second transport allowance, then retain the five-second rendered-state assertion. Do not fabricate readiness or omit native checks.

Cancel the actual worker through the owner UI while health transport is disconnected, and confirm process identity/termination before the subsequent health-only presentation checks. Use the existing 30-second contract ceiling for this private UI probe; the private lifecycle helper's former 20-second ceiling is aligned to 30. Production deadline, credential lifetime and grants are unchanged. Portable behavioral tests reject boolean, zero and greater-than-30 private deadlines before task/process creation. The original failing result is not called passed; the focused corrected browser run passed and all mandatory lanes must pass again before renewed G1 acceptance.


## D-050 - Bound operator startup checks and retain failure-cleanup identity

The next complete rerun passed the dashboard and 11 other Windows cases, but the operator test's 35-second startup wait expired during sequential native readiness work. Its failure cleanup then tried to read a controller record that had not yet been written, leaving that test-owned startup process running. The recorded controller was subsequently stopped with the identity-checked operator command, and listener absence was verified.

The test now allows the two startup audits and first health audit their existing 45-second bounds plus a five-second transport margin (140 seconds total). Actual failed preflight still refuses startup; no audit is omitted or relaxed. The normal passing path must use graceful identity-checked stop. Failure cleanup instead uses only the original Popen child's retained handle and waits for exit, even before its record exists; it never selects a process by port or another controller's record. The focused operator case passed before the final complete rerun.

Viewport evidence capture now waits for two actual animation frames after resizing. This removed an observed transient repaint band in the 1366x768 running capture without changing application styling, editing images or manufacturing data. The full source/test digest includes these harness corrections.


## D-051 - Keep receiver evidence independent and owner-protected

After verified G1 PASS, implement G2 as a separate FastAPI process and SQLite database bound only to `[::1]:8767`. Use the fixed Windows runtime root `C:\ACLAIS-Lab\state\receiver` outside Git. Protect the whole store tree with an explicit DACL for the current owner, SYSTEM, and local Administrators; reject reparse points and verify the actual non-administrator worker SID is not allowed. Use a DACL-only native update so protection does not require SACL privileges. Create a distinct random owner-only `admin.token` once and store only SHA-256 hashes of run-bound ingest tokens.

Bound one decoded payload to 1 MiB, one request to 2 MiB, and one run to 10 MiB. Store raw receipt bytes in UUID-named `.bin` files through the independent journal/stage/flush/no-replace/finalize recovery flow; GET returns validated metadata, never payload. Quota exhaustion uses the shared `429 RATE_LIMITED` response. The local CLI exposes metadata only and offers no online reset. Raw payloads and credentials are excluded from Git and CI artifacts.

Connect ACLAIS through its read-only HTTP adapter, with strict JSON/model validation and distinct healthy-empty, positive receipt, unknown run, authentication failure, protocol failure, and unavailable outcomes. A positive marker is independent confidentiality evidence, not an ACLAIS policy decision or a claim of blocking. Production run creation and ingest-token delivery to G3 workers remain G4 integration work.


## D-052 - Defer receiver archival until task association is trusted

The receiver specification describes an offline receipt archive/reset that must prove no associated ACLAIS task is active before deleting any history. G2 has no trusted run-to-task association because production run creation and worker-token delivery are G4 handoff work. Do not introduce a partial reset guard, ask the operator to assert quiescence, import ACLAIS private persistence into `receiver/`, or delete receiver history. G2 therefore exposes no reset route or CLI action and preserves all records. Implement the offline archive/reset only after G4 defines a trusted association and quiescence check; then archive before deletion and fail closed on unavailable proof.


## D-053 - Keep unresolved receiver publications unknown and protect SQLite sidecars

Receipt inspection must not turn a `reserved`, `staged`, `file_committed`, or `aborted` journal row into a healthy empty result. Query the run and receipt journal under one SQLite read snapshot; return the bounded `503 PROTECTION_UNAVAILABLE` response while a row is unresolved. A valid run-bound retry with the identical canonical request body may resolve that row and produce the one committed receipt; changed content remains a conflict. This keeps ACLAIS at unknown until publication is complete or retry resolves it.

SQLite may create WAL/SHM sidecar files after the receiver's first storage-protection pass. After startup migrations and recovery, apply and verify the scoped owner/SYSTEM/Administrators DACL again before the service listens. This covers database artifacts created during initialization while retaining the existing fixed runtime root and worker-SID exclusion.
