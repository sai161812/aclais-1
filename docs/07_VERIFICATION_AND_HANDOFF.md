# Verification, gates and final handoff

## Gate policy
G0: environment and contract review. G1: ACLAIS complete. G2: receiver complete. G3: Document Tools complete. G4: integrated release audit. Only G0–G1 may be underway initially. No later production component starts until the previous mandatory gate passes. Inside G1, infrastructure/security checkpoint precedes dashboard polish.

Every gate report includes: actual platform/build, dependency lock identifiers, commit/source hash, exact commands and exit codes, observed results, artifact paths, unresolved defects and final status. An unrun mandatory test means BLOCKED, not PASS. Tests must exercise behavior, not simply assert the implementation contains a chosen function name.

## Requirements traceability
| Requirement | Owner | Gate / evidence |
|---|---|---|
| Natural website workflows, no attack controls | Tools/UI | G3 route and screenshot review |
| Selected input and legitimate output work | ACLAIS/tools | G1 benign probe, G3 output assertions |
| Different worker identity and original protection | ACLAIS | G1 real Windows SID/ACL probes |
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
8. Containment: harmless child started by test worker; denial and controller close both leave no child. Do not infer process death from UI state.
9. Failure injection: receiver offline → unknown; ACL misconfiguration → launch refused; DB unavailable → fail closed; worker crash → FAILED; timeout → revoked/terminated; controller restart → stale tasks reconciled.
10. UI refresh/reconnect: stored events retain order/no duplicates; no stale green status; owner session required.
11. Second task after incident works. Concurrent start receives 409 without creating an untracked process.
12. Modify seeded report/invoice content before launch: real outputs change appropriately; enforcement still holds.

Security case review: malformed payload, oversized input, arbitrary executable field, traversal/UNC/ADS paths, worker credential on owner route, receiver ingest credential on admin route, cross-origin mutation and duplicate differing request body. Reject without side effects.

## Race and integrity checks
Broker denial and revocation share the per-task serialization boundary. Exercise simultaneous publish and forbidden operation: already-authorized publication may finish before revocation, but no new authorized effect starts after revocation. Preserve event order; do not retroactively claim an earlier allowed output was blocked. Verifier waits for actual job termination before final inventory. On verification timeout retain unknown/fail status.

## Operator runbook requirements
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
