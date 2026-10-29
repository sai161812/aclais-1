# Verification, gates and final handoff

## Gate policy
G0: environment and contract review. G1: ACLAIS complete. G2: receiver complete. G3: Document Tools complete. G4: integrated release audit. Only G0–G1 may be underway initially. No later production component starts until the previous mandatory gate passes. Inside G1, infrastructure/security checkpoint precedes dashboard polish.

Use `IMPLEMENTATION_CHECKPOINTS.md` for the ordered A0–A10 delivery steps inside G1. A0 is readiness/specification work; A1–A10 are sequential implementation checkpoints. A0 PASS does not mean G1 PASS or authorize starting the receiver/tools ahead of their gates.

Every gate report includes: actual platform/build, dependency lock identifiers, commit/source hash, exact commands and exit codes, observed results, artifact paths, unresolved defects and final status. An unrun mandatory test means BLOCKED, not PASS. Tests must exercise behavior, not simply assert the implementation contains a chosen function name.

For A7, preserve raw inventories and captured worker output only in the owner-protected local evidence tree. Git-trackable summaries must omit fixture names/hashes, receipt IDs, worker text, credentials and runtime paths, and identify the tested source revision or source digest. Final inventory begins only after actual worker/job termination is confirmed; incomplete containment or a verifier timeout remains unknown.

## Verification lanes
Keep these results separate in `BUILD_STATUS.md`, gate evidence and CI summaries:

1. **Portable CI checks.** A1 establishes the portable CI workflow; later checkpoints extend it with implemented cross-platform contracts, strict model/schema behavior, pure logic, SQLite migration/state invariants, frontend type/lint/build, and accessibility/static checks. Filesystem publication fault injection is added with A5; receiver receipt persistence is added with G2. These checks may use injected adapters and private fixtures only in their test boundaries. They cannot establish Windows identity, NTFS, Credential Manager, or Job Object enforcement. A portable pass is never evidence of Windows security.
2. **Windows-specific automated checks.** Run real Windows adapter tests for Credential Manager retrieval, alternate-user SID/privilege, ACL effective rights (including parent `DELETE_CHILD`), stdout/stderr pipes, process token, suspended process/job assignment, job kill-on-close, NTFS no-replace publication, restart/journal reconciliation, and lifecycle races. Record Windows edition/build, filesystem, user/SIDs, exact command/exit code and artifacts. A Windows CI runner can cover only checks it actually executes with the required identity/privileges; mocks or skipped elevation are `NOT_RUN`/`BLOCKED`.
3. **Mandatory demonstration-machine checks.** Run the actual ACLAIS gate checklist on the intended Windows 11 NTFS presentation machine with the provisioned non-admin `AclaisWorker`, installed Chrome or Edge, real browser services and the private G1 probe harness. This includes confirming `localhost` reaches the Document Tools listener over the local IPv4/IPv6 loopback addresses available on that machine, browser cookie-host separation/top-level approval flow, actual direct file access probes, job/child cleanup, publication recovery/retry, task arbitration and required dashboard states. Hosted CI and another Windows machine do not replace this lane.

G1 may be PASS only when required checks in all three lanes pass. If a required lane is unavailable or a mandatory check is skipped, mark G1 BLOCKED/NOT_RUN with the missing prerequisite; do not infer a pass. Later gates keep their own portable, Windows and live-demonstration evidence separate where applicable. Hosted portable CI does not run Windows enforcement and has no self-hosted runner.

## Requirements traceability
| Requirement | Owner | Gate / evidence |
|---|---|---|
| Natural website workflows, no attack controls | Tools/UI | G3 route and screenshot review |
| Selected input and legitimate output work | ACLAIS/tools | G1 benign probe, G3 output assertions |
| Different worker identity and original protection | ACLAIS | G1 real Windows SID/ACL probes |
| Owner cookie withheld from Document Tools and receiver | ACLAIS/UI | G1 Chrome/Edge browser-origin test at 127.0.0.1, localhost and [::1] |
| Approval GET has no launch effect; owner POST is the launch action | ACLAIS | G1 owner-auth route test and actual private-probe browser run |
| Output/retry/crash consistency across SQLite and NTFS | ACLAIS/receiver | G1/G2 publication and receipt journal fault injection |
| No bypass by direct read/write/delete | ACLAIS/tools | G1 access tests, G3 paired runs |
| Unauthorized broker effect never runs | ACLAIS | G1 forbidden-operation tests + inventory |
| Accurate confidential receipt evidence | Receiver | G2 marker tests; G4 positive/negative control |
| Immediate revocation, no orphan children | ACLAIS | G1 race, replay, job termination tests |
| Premium accessible dashboard | UI | G1 and G4 screenshots/keyboard checks |
| Honest attribution and failure display | All | G4 evidence audit |
| Repeatable offline presentation | All | G4 clean-start rehearsal |

## G4 integration matrix
Run each in a fresh run namespace, record real outputs:
1. Benign formatter-style probe: permitted read/output succeeds, originals unchanged, COMPLETED.
2. Formatter protected: actual output published; direct overwrite/delete denied; broker replace denied; task BLOCKED only after verified containment/integrity.
3. Formatter baseline: same code modifies/deletes disposable copies. Record source hash, file differences and no production-root changes.
4. Analyzer protected: actual invoice output; direct private read denied; broker private read denied; receiver healthy with marker absent.
5. Analyzer baseline: same code obtains seeded bytes; receiver records exact marker, byte count and matching payload hash.
6. Unauthorized broker delete in its own fresh task: 403 and original still exists.
7. Expired/revoked/replayed token: denied after incident, no additional published file.
8. Publication/receipt crash points: reservation, stage flush, no-replace rename, and final DB commit recover to one valid committed object or an explicit fail-closed inconsistent status; exact retry never duplicates it.
9. Lifecycle races: policy denial, deadline, cancellation, normal exit and shutdown are serialized with the documented winner; no terminal cause is overwritten.
10. Containment: harmless child started by test worker; denial and controller close both leave no child. Do not infer process death from UI state.
11. Failure injection: receiver offline → unknown; ACL misconfiguration → launch refused; DB unavailable → fail closed; worker crash → FAILED; timeout → revoked/terminated; controller restart → stale tasks reconciled.
12. UI refresh/reconnect: stored events retain order/no duplicates; no stale green status; owner session required.
13. Second task after incident works. Concurrent start receives 409 without creating an untracked process.
14. Modify seeded report/invoice content before launch: real outputs change appropriately; enforcement still holds.

Security case review: malformed payload, oversized input, arbitrary executable field, traversal/UNC/ADS paths, worker credential on owner route, receiver ingest credential on admin route, cross-origin mutation and duplicate differing request body. Reject without side effects.

## Race and integrity checks
Broker denial and revocation share the per-task serialization boundary. Exercise simultaneous publish and forbidden operation: already-authorized publication may finish before revocation, but no new authorized effect starts after revocation. Preserve event order; do not retroactively claim an earlier allowed output was blocked. Verifier waits for actual job termination before final inventory. On verification timeout retain unknown/fail status.

## Operator runbook requirements
For G1, exercise ACLAIS owner commands and harmless private origin/worker probes on the demonstration machine. Full three-service clean-start rehearsals, receiver receipts, and same-worker protected/baseline pairs remain G4 requirements. G1 still requires all identity, ACL, containment, authorization, recovery, authentication and evidence checks.

Document installation/provisioning once, ordinary startup, readiness, opening the two UI URLs, creating fixtures, both user journeys, evidence inspection, shutdown, reset and removal. Provide one start script that checks ports/health and reports useful errors; one stop script using owned process identities; one doctor command; one reset command scoped to sentinel root. Do not kill arbitrary processes by name or free a port by killing an unknown owner.

All three services must start cleanly without internet after dependencies are installed. Reset must refuse active tasks and never touch user documents. Test three consecutive full rehearsals with fresh run IDs and restored fixture hashes. Record p50/maximum measured launch and incident-display times if useful; do not invent latency metrics.

## What to deliver to the user after coding
Source repository, exact install/start instructions, dependency lockfiles, updated specs/decisions, passed gate reports, screenshots, reproducible tests, known limitations and a short presentation walkthrough. Include backed-up evidence from a real successful rehearsal. A recording supplements, never replaces, a live functioning product.

## Honest presentation answers
“Windows does the blocking?” Windows supplies mandatory file permissions for the worker identity; ACLAIS provisions/checks that boundary, derives per-task grants, mediates requests, contains jobs and explains evidence.
“Can it stop all malware?” No. This prototype validates these supported workflows and boundaries.
“Can it stop any upload?” No. The confidential file is protected at its read boundary; general network egress control is outside v1.
“How do we know it is not a fake alert?” Same worker code succeeds on disposable permissive fixtures, fails in the restricted environment, with broker logs, independent file verification and receiver controls.
“Is the causal chain discovered automatically?” No. It records our instrumented browser launch and controller-started worker. General browser/endpoint correlation is future work.
