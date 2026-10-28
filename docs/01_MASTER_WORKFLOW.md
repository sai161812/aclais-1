# Master workflow and product specification

## Outcome
ACLAIS connects an instrumented browser launch to a restricted Windows document task, enforces the task's authority, and explains blocked actions using attributable evidence. The visible experience is normal document work. The hidden hostile behavior is part of the two fixed test tools, not a user-facing mode.

The presentation proves two properties: integrity (originals cannot be overwritten/deleted) and confidentiality (an unselected confidential document cannot be read for theft). It does not prove general malware detection, universal exfiltration blocking, arbitrary browser monitoring, full host sandboxing, or ML prediction.

## Architecture and ownership
Browser Document Tools → top-level ACLAIS approval → trusted controller → restricted worker. The worker can request operations through the ACLAIS broker. The broker checks a controller-owned contract. NTFS permissions protect the originals even when the worker bypasses the broker. The receiver is a separate loopback process; it cannot modify ACLAIS state.

The protected store, contract database, credentials, application code, evidence and verified output store are writable only by trusted identities. A worker has its selected input copy and a temporary output directory. A selected input copy is readable but not writable by the worker. Workers never receive the confidential fixture contents, its marker, an owner browser session, or receiver-admin credentials.

There is one active worker at a time. Reject concurrent starts cleanly. A later legitimate task must still work after a blocked task. Cross-task concurrency and isolation are not claimed.

The website cannot execute arbitrary local code or select an arbitrary executable. The controller maps exactly two registered tool IDs to fixed, owner-controlled entrypoints. Normal browser content supplies no executable path or shell command.

## Natural launch
1. User opens Document Tools and chooses Format report or Extract invoice details.
2. Website navigates to the ACLAIS top-level approval page with an allowlisted tool ID and a claimed source tag. This GET has no side effect.
3. ACLAIS shows its own document picker and plain-language contract. The user selects a seeded document and approves.
4. Controller validates its owner session and anti-CSRF token, generates a task, captures input hashes and provenance, and prepares the working copy.
5. Controller verifies enforcement readiness, launches the tool as AclaisWorker, records SID/PID/start time, and starts the execution deadline.
6. User sees the tool's real output within the ACLAIS task view. Tool-specific progress and result cards give the normal application experience. Do not pass an owner credential to the tools origin.
7. Unauthorized broker requests create an incident, revoke the task, and trigger containment. Evidence is verified after worker termination. UI polls actual persisted events.

Origin means the instrumented launch entry and separately recorded observed HTTP origin/referer where present. The source tag is a claim, not cryptographic proof of a browser tab. Never collapse those fields into a fabricated verified provenance assertion.

## Scenario A — Report Formatter
Input: project-report.md. Useful output: formatted-report.md with normalized headings, spacing, and a generated contents list.

Worker order: generate and publish useful output; attempt direct overwrite of project-report.md; attempt direct deletion of meeting-notes.md; then request broker replace_original on doc-report. Each direct operation is bounded and catches its actual exception so the next attempt can run. The broker violation revokes the task immediately. Do not schedule another malicious step after that point and expect it to run.

Windows permissions should deny the direct operations before damage. Worker stdout describing these attempts is explicitly worker_reported telemetry. The trusted broker's denied operation is authoritative for that request. Controller verifies the complete fixture inventory, names, existence, sizes and SHA-256 values after the task exits. Only then show “Protected originals unchanged.”

Dedicated gate tests exercise broker deletion denial separately; live presentation need not squeeze every broker operation into one revoked task. No delays or weakened containment to make a scripted story finish.

## Scenario B — Invoice Analyzer
Input: invoice.csv. Useful output: invoice-analysis.json containing vendor, invoice number, date, line total and computed grand total.

Worker order: extract and publish useful output; attempt direct read of Personnel_Private.csv; if bytes were actually obtained, immediately send them to the fixed local receiver; then request broker read_document for doc-private. If direct read fails, continue to the broker request. Do not fabricate bytes, send the secret marker from a manifest, or call an empty upload “successful theft.”

The denied broker request revokes the task. The receiver may therefore see zero upload attempts in a protected run. UI must say “Confidential read denied” and “No seeded payload received,” not “Network packet blocked.” The confidentiality boundary is denial of the source read. The worker still has network access; selected input data is not covered by a general network prevention claim.

## Fixtures and reset
Use a dedicated root C:\ACLAIS-Lab, with a controller-owned sentinel and run manifest. Seed only four originals: project-report.md, meeting-notes.md, invoice.csv, Personnel_Private.csv. The private file contains a unique randomly generated per-run canary marker. Only controller, verifier and receiver admin configuration know the marker.

Private document is visible to the owner UI as metadata, never as bytes in tool launch payloads. The manifest supplied to workers may contain fixed fixture paths/IDs and run ID, never the marker. No filesystem discovery, arbitrary path CLI switches, persistence, encryption, privilege escalation, or external destinations in hostile tools.

Reset is an operator CLI command, absent from the product UI. It refuses while workers are active, verifies the sentinel/root/ownership, archives evidence, and reseeds only owned fixture directories. Never recursively change permissions on a drive, profile or Windows folder. Uninstall restores only changes recorded during provisioning.

## Claims and failure handling
If ACL setup, worker identity, contract persistence, or preflight fails, refuse to launch and show “Protection unavailable” with a useful reason. If verification fails, show “Verification incomplete,” not green success. Receiver unreachable means receipt verification unknown, never zero leakage. Hash equality alone cannot prove absence of temporary writes; combine post-run integrity with tested mandatory permissions and denied operations.

Useful output is labeled “Generated by a tool that was stopped” after an incident. Render as inert text/structured data. Do not automatically execute or open active content. Outputs are kept separately; no overwrite of originals is available in v1.

## Presentation, approximately four minutes
Open normal website; choose formatting; approve narrow permissions; observe useful output and real incident; inspect original and evidence. Repeat with invoice extraction; inspect the confidential-read incident and receiver verification. Finish with a benign probe or normal successful supported task from the private verification harness, showing ACLAIS is not simply denying everything. No baseline switch or attack controls in the product.

Unprotected runs happen only in private validation against disposable baseline fixtures. They establish that the exact hostile binary can cause the intended change/receipt when authority exists. Do not disable protection on the real protected root.
