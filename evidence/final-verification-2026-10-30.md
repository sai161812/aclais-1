# Consolidated final verification — 2026-10-30

## Scope and status

The tested base was `a9fafba9b5312f69776744d8d8a9060e05f1ff3b`. The current implementation-input digest at handoff is `81cf246c2dbf9b7ca78820b27115c1c85b7a34a711df6a156cf6b6807c6eef63` across 183 inputs. Each older gate report retains its own tested revision or digest; this report does not relabel those earlier runs as the current digest.

G1 and G2 remain verified. G3 passed its Report Formatter and Invoice Analyzer paired target checks. One complete paired browser rehearsal ran on the intended Windows 11 / NTFS machine. G4 is **PENDING**, not PASS: three consecutive fresh rehearsals and the trusted-quiescence receiver archive/reset gate remain unverified.

## Current-tree portable checks

`scripts/check.ps1` exited 0 on the current tree:

- ACLAIS Ruff passed; 142 backend tests passed and 10 Windows/UI tests were deselected.
- OpenAPI and generated TypeScript consistency passed. ACLAIS frontend typecheck, lint, production build, and npm audit passed; npm audit reported 0 vulnerabilities.
- Receiver Ruff passed; 21 portable tests passed and 2 Windows/integration cases were deselected, then 2 live receiver/adapter integration tests passed.
- Document Tools Ruff and 17 tests passed. Its frontend typecheck and build passed; npm audit reported 0 vulnerabilities.

Deselected tests are not counted as passing enforcement checks.

## Demonstration-machine checks

- A2 private probe: 75 actual access checks passed across 14 synthetic fixtures under the non-administrator `AclaisWorker` identity. Selected input read and permitted temporary output succeeded. Confidential-original reads, original overwrite/delete/rename/replacement, parent-directory bypass, trusted-state modification, and permission changes were denied. The sanitized report identifies the account and redacts its machine-specific SID.
- G1: the Windows enforcement run produced 12 passes and one stale expected-summary assertion. After updating the assertion to the observed truthful health sentence, the exact failed test passed on rerun. Thus all 13 distinct enforcement cases passed across the full run plus focused rerun; the full wrapper was not rerun. Cases covered alternate non-admin identity, effective NTFS rights and parent-directory bypass, suspended worker/job assignment and child containment, denial/revocation/cancellation/timeout/shutdown/crash/restart, second-task admission, Chrome/Edge cookie-host isolation, explicit owner approval, and source-claim versus observed-origin attribution. The separate UI fixture test passed once. Four affected readiness/operator portable tests then passed on the final source, followed by the full current-tree portable command.
- G2: 2 actual Windows receiver checks passed. The sanitized HTTP audit covers real requests and persisted receipts, malformed/oversized inputs, cross-run and cross-role credentials, identical retry, changed-body conflict, restart/recovery, storage failure, and ACLAIS unknown-outcome mapping.
- G3: the paired Report Formatter and Invoice Analyzer Windows tests passed (2 passed in 328.88 seconds). Their validated reports identify tested digest `91afd6e7252ed6f7ecc400b91e43283eb2063091193ff120422f93d1d6279971`. The natural website approval flows produced useful outputs. Identical installed worker code changed disposable permissive fixtures and encountered actual protected filesystem errors; the broker denied the final forbidden operation. The Invoice Analyzer baseline persisted a matching receiver receipt; the protected run produced a healthy-empty result. Original inventories were checked after confirmed worker/job termination. This earlier G3 digest is kept distinct from the final current-tree digest above.
- The standalone doctor reported `application_api=unknown` because it did not observe a live API request, while its core protection checks reported ready. The actual final process/listener query found no worker process and no listener on ports 8765, 8766, or 8767.

The final paired rehearsal uses real ACLAIS approval, the receiver, and the Document Tools website. Approval-page GET did not launch work; explicit authenticated approval did. Report Formatter's policy denial and unknown verifier result are reported as observed, not relabeled `BLOCKED`. Invoice Analyzer's protected receiver result was healthy-empty. Worker-reported observations, broker decisions, controller state, receiver results, and independent inventories remain separate.

## Harness incidents and evidence limits

An earlier private-harness attempt moved 43 synthetic files into quarantine; each was restored to its recorded original location and checked by hash. A later attempt created one synthetic orphan output; it was removed only after matching the raw task ID, size, and hash. Neither attempt is counted as a pass. No production receipt or payload was changed. The final paired harness isolates its database and output directory under private test state. Raw records remain in the owner-protected runtime and are not included here.

Sanitized target reports are `evidence/a2-access-summary.json`, `evidence/g1-operator-summary.json`, `evidence/G2_HTTP_AUDIT.json`, `evidence/G3.md`, `evidence/G3-report-formatter.md`, and `evidence/G3-invoice-analyzer.md`. The tracked A2 summary redacts the worker SID. User-modified screenshots were left untouched and are not part of this report.

## Remaining G4 work

- Run three consecutive full clean-start demonstrations with fresh run IDs and restored fixture hashes.
- Implement and verify the receiver archive/reset operation only after trusted ACLAIS task-quiescence proof is available.
- Re-run any affected target checks if code changes alter the tested security behavior. Do not infer enforcement from portable CI.

No current-revision GitHub CI result is claimed by this report. The verification is committed locally for handoff; G4 remains pending.
