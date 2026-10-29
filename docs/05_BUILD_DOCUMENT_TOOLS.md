# Component 3 — Document Tools website and workers
Prerequisites: G1 and G2 PASS. Read 01, 02, 06 and 07. Both utilities are internal parts of this component; finish/test Report Formatter before adding Invoice Analyzer.

Keep the website, Report Formatter worker, Invoice Analyzer worker, assets, tests, dependencies and component-specific configuration inside `document-tools/`. Keep generated confidential fixtures and runtime data in their designated protected runtime locations outside Git. Do not add production Document Tools code before both G1 and G2 pass; root `tests/` remains reserved for cross-component integration and acceptance tests.

## Website
Serve a separate local website at browser origin `http://localhost:8766`, with listeners only on `127.0.0.1:8766` and `[::1]:8766` and an exact `localhost:8766` Host allowlist. This hostname differs from the ACLAIS owner-session host `127.0.0.1`; different ports alone do not isolate cookies. Do not set, proxy, copy or expose the ACLAIS session cookie/token to this origin. Brand it “Document Tools,” a credible compact utility suite. Show two clear cards: Format a report and Extract invoice details. Each explains its legitimate result; only an installed worker has an enabled action. During the Report Formatter slice, the invoice action is visibly unavailable and disabled in both Document Tools and ACLAIS until Invoice Analyzer passes its own gate. No attacks, scenarios, protection switches, payload fields, exploit logs or demo terminology in the UI.

The action performs a top-level, side-effect-free GET to the real ACLAIS approval page at `http://127.0.0.1:8765`, with only an allowlisted tool ID and bounded source claim. ACLAIS's host-only `SameSite=Lax` cookie can accompany this safe top-level navigation; only ACLAIS renders/accepts approval mutations, with exact-Origin and anti-CSRF validation. The browser cannot execute workers itself. Selection/approval happens on the trusted ACLAIS origin. Do not collect arbitrary user filesystem paths or accept confidential uploads on the tools website. Show tool-specific results within the ACLAIS task view after launch, not through cross-origin owner-token sharing.

## Worker architecture and fixture boundary
The controller allowlist contains the two specified fixed tool/document pairs, sharing a small broker client and strict config parser. Install only the Report Formatter entrypoint in this slice; implement and validate it completely before adding Invoice Analyzer. Until its own gate passes, Invoice Analyzer is unavailable in both interfaces. Each implemented worker's code must be identical in protected and baseline validation; only filesystem fixture roots/access differ. There is no protection_enabled flag, detection of ACLAIS health to suppress an attack, fake failure function, artificial success log or mock file operation.

The ACLAIS controller validates the owner sentinel, root identity, fixed fixture manifest and seeded-file hashes before creating a task. A2 deliberately denies the worker access to the owner sentinel and the originals directory. The protected task configuration therefore supplies the controller-verified root ID and the fixed four-file scope; the worker validates this strict scope and never reads sentinel bytes. On the protected root, inability to enumerate originals is recorded as a worker observation and does not suppress the two required direct attempts. In the permissive baseline, the private launcher validates the disposable sentinel and the same worker can enumerate the exact fixture names. Refuse symlinks/reparse points, path escapes and unexpected files whenever metadata is available. Never scan the computer. These scope checks bound where test code operates; they must not decide whether a required operation is attempted or succeeds.

Worker configuration never contains canary bytes. It includes confidential path, because secrecy of paths is not our defense. No credentials, production files, persistence, real encryption, remote hosts or generalized attack engine. Receiver host/port is fixed to the loopback endpoint in 02. Runtime has no internet dependency.

## Report Formatter implementation
Parse seeded Markdown; normalize heading spacing and blank lines; generate a contents list from actual headings. Test content preservation and deterministic output. Publish formatted_markdown via broker before unauthorized operations.

Attempt open+write of the exact protected project-report.md using a harmless fixed replacement string, then attempt unlink of exact meeting-notes.md. Catch and report actual errno/WinError for each bounded attempt; do not retry indefinitely. Then send a valid replace_original broker request for doc-report. Expect termination/revocation, but code must not require it to claim success. Do not swallow useful-output errors and pretend formatting completed.

On the demonstration machine, record the Python overwrite result as observed: `PermissionError`, `errno=13` (`EACCES`), with no `winerror` value; the unlink result is `PermissionError`, `errno=13`, `winerror=5`. Sanitized evidence must preserve these fields and must not invent a missing Win32 error code.

The Formatter's forbidden `replace_original` request is its final broker operation. Direct attempts happen before that request, per 01; the first forbidden request revokes its task. Broker `delete_document` remains covered by the A5/A6 fresh-task tests rather than being sent after revocation.

## Invoice Analyzer implementation
Use Python CSV parser and Decimal arithmetic. Validate expected headers, quantities and amounts; compute actual totals from rows. Seed supported invoice fields and reject malformed input with clear failure. Publish invoice_json through broker.

Attempt direct binary read of Personnel_Private.csv. If it succeeds, POST exactly those obtained bytes as base64 to /ingest with a fresh UUID `request_id`, current run/task and ingest token. If retrying because the response was lost, reuse that request ID only with the identical payload/body; the receiver returns the original receipt once. Capture HTTP success/failure without inventing a receipt. If read fails, record error without uploading an empty stand-in. Then request read_document for doc-private through broker. Catching a direct read error is allowed so this independently enforced broker request is exercised.

Useful-output preview contains only invoice fields; do not display private file contents if a baseline succeeds. The receiver's marker-match status is enough evidence.

## Baseline validation
Use disposable unprotected fixture copies under the designated temporary-output root. Give the SAME worker identity access there; change fixture-root configuration only. Maintain the same installed worker entrypoint and record SHA-256 of worker source/package in both runs. Baseline harness may provide its private HTTP broker for selected read/output and the expected policy response, but it does not expose production protection switches or controls in the product UI.

Formatter baseline must publish useful output, then change the actual disposable report and delete the actual disposable notes file before its forbidden broker operation. The protected run uses the real owner approval route, ACLAIS broker, and registered worker. Record the worker source hash, actual OS errors, broker event order, task/revocation state, confirmed worker termination and an independent before/after inventory of every original. The baseline run records successful overwrite/deletion effects and the same source hash. Do not label an outcome `BLOCKED` unless ACLAIS's complete verification criteria pass; for example, an unavailable receiver result remains unknown and may leave the task `FAILED` even when direct filesystem denials and unchanged originals are independently observed.

Invoice baseline must read actual seeded bytes and create a matching receiver receipt before its broker violation. Protected runs must deny those reads/writes and preserve all originals. Separate run IDs and independent baselines prevent stale receipts from contaminating results.

If Windows Defender or another product prevents execution, record it as external interference and investigate the harmless worker; do not disable host protections to manufacture an ACLAIS result. Attribute the observed denial accurately.

## G3 acceptance
- Website looks like a real utility page; every enabled action goes through trusted ACLAIS approval, and unimplemented tools remain visibly unavailable.
- Formatter's output is useful and derived from input; baseline modifications succeed, protected modifications fail.
- Invoice fields/totals are computed correctly; baseline marker arrives, protected marker does not.
- Same code hash for protected/baseline per tool; no protection-aware branch.
- Broker policy creates incidents; direct errors are labeled worker_reported.
- Invalid/missing sentinel, path escape, unexpected root or nonloopback receiver is rejected by the worker's scope guard.
- No process/token survives termination; evidence ties output, attempts and verification to one run/task.
- Full production frontend build works offline, with no embedded demo controls or secret values.

Write evidence/G3.md, then run the overall G4 audit in 07.
