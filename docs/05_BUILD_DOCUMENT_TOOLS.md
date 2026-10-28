# Component 3 — Document Tools website and workers
Prerequisites: G1 and G2 PASS. Read 01, 02, 06 and 07. Both utilities are internal parts of this component; finish/test Report Formatter before adding Invoice Analyzer.

## Website
Serve a separate local website at browser origin `http://localhost:8766`, with listeners only on `127.0.0.1:8766` and `[::1]:8766` and an exact `localhost:8766` Host allowlist. This hostname differs from the ACLAIS owner-session host `127.0.0.1`; different ports alone do not isolate cookies. Do not set, proxy, copy or expose the ACLAIS session cookie/token to this origin. Brand it “Document Tools,” a credible compact utility suite. Two clear cards: Format a report and Extract invoice details. Each explains the legitimate result and has a normal primary action. No attacks, scenarios, protection switches, payload fields, exploit logs or demo terminology in the UI.

The action performs a top-level, side-effect-free GET to the real ACLAIS approval page at `http://127.0.0.1:8765`, with only an allowlisted tool ID and bounded source claim. ACLAIS's host-only `SameSite=Lax` cookie can accompany this safe top-level navigation; only ACLAIS renders/accepts approval mutations, with exact-Origin and anti-CSRF validation. The browser cannot execute workers itself. Selection/approval happens on the trusted ACLAIS origin. Do not collect arbitrary user filesystem paths or accept confidential uploads on the tools website. Show tool-specific results within the ACLAIS task view after launch, not through cross-origin owner-token sharing.

## Worker architecture and fixture boundary
Two fixed worker entrypoints share a small broker client and strict config parser. Their code is identical in protected and baseline validation; only filesystem fixture roots/access differ. There is no protection_enabled flag, detection of ACLAIS health to suppress an attack, fake failure function, artificial success log or mock file operation.

Require a valid lab sentinel and fixed fixture manifest. Every destructive target must resolve inside the seeded fixture root and match its allowlisted filename. Refuse symlinks/reparse points and unexpected files. Never scan the computer. These safety bounds limit where our test code operates; they must not decide whether its malicious operation succeeds.

Worker configuration never contains canary bytes. It includes confidential path, because secrecy of paths is not our defense. No credentials, production files, persistence, real encryption, remote hosts or generalized attack engine. Receiver host/port is fixed to the loopback endpoint in 02. Runtime has no internet dependency.

## Report Formatter implementation
Parse seeded Markdown; normalize heading spacing and blank lines; generate a contents list from actual headings. Test content preservation and deterministic output. Publish formatted_markdown via broker before unauthorized operations.

Attempt open+write of the exact protected project-report.md using a harmless fixed replacement string, then attempt unlink of exact meeting-notes.md. Catch and report actual errno/WinError for each bounded attempt; do not retry indefinitely. Then send a valid replace_original broker request for doc-report. Expect termination/revocation, but code must not require it to claim success. Do not swallow useful-output errors and pretend formatting completed.

Broker deletion is tested with a separate fresh task in the harness because the first forbidden broker request revokes the current task. Direct attempts happen before that broker request, per 01.

## Invoice Analyzer implementation
Use Python CSV parser and Decimal arithmetic. Validate expected headers, quantities and amounts; compute actual totals from rows. Seed supported invoice fields and reject malformed input with clear failure. Publish invoice_json through broker.

Attempt direct binary read of Personnel_Private.csv. If it succeeds, POST exactly those obtained bytes as base64 to /ingest with a fresh UUID `request_id`, current run/task and ingest token. If retrying because the response was lost, reuse that request ID only with the identical payload/body; the receiver returns the original receipt once. Capture HTTP success/failure without inventing a receipt. If read fails, record error without uploading an empty stand-in. Then request read_document for doc-private through broker. Catching a direct read error is allowed so this independently enforced broker request is exercised.

Useful-output preview contains only invoice fields; do not display private file contents if a baseline succeeds. The receiver's marker-match status is enough evidence.

## Baseline validation
Use disposable unprotected fixture copies under the owned baseline root. Give the SAME worker identity access there; change fixture-root configuration only. Maintain the same worker entrypoint and record SHA-256 of worker source/package in both runs. Baseline harness may grant test broker output publication but does not expose production protection switches.

Formatter baseline must change/delete actual disposable files before its forbidden broker operation. Invoice baseline must read actual seeded bytes and create a matching receiver receipt before its broker violation. Protected runs must deny those reads/writes and preserve all originals. Separate run IDs and independent baselines prevent stale receipts from contaminating results.

If Windows Defender or another product prevents execution, record it as external interference and investigate the harmless worker; do not disable host protections to manufacture an ACLAIS result. Attribute the observed denial accurately.

## G3 acceptance
- Website looks like a real utility page, and both actions go through trusted ACLAIS approval.
- Formatter's output is useful and derived from input; baseline modifications succeed, protected modifications fail.
- Invoice fields/totals are computed correctly; baseline marker arrives, protected marker does not.
- Same code hash for protected/baseline per tool; no protection-aware branch.
- Broker policy creates incidents; direct errors are labeled worker_reported.
- Invalid/missing sentinel, path escape, unexpected root or nonloopback receiver is rejected by the worker's scope guard.
- No process/token survives termination; evidence ties output, attempts and verification to one run/task.
- Full production frontend build works offline, with no embedded demo controls or secret values.

Write evidence/G3.md, then run the overall G4 audit in 07.
