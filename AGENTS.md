# ACLAIS-1 project instructions

Read `docs/00_START_HERE.md` and the referenced specification documents before implementation. The specifications are authoritative for product scope and security behavior. Record resolved engineering decisions in `DECISIONS.md` and keep contracts, code, tests, and documentation consistent.

## Required execution rules

- Implement only the requested checkpoint.
- Do not advance past a failed mandatory prerequisite.
- Never fake enforcement, telemetry, or test results.
- Keep specifications, contracts, code, and tests consistent.
- Preserve unrelated changes.
- Stage files explicitly and review the staged diff before committing.
- After a passing checkpoint, commit its implementation, tests, and documentation coherently, then push only the working branch to the verified remote.
- Verify push success; do not claim GitHub backup when synchronization failed.
- Never force-push, destructively reset, rewrite shared history, change repository settings, merge, or deploy without a separate instruction.
- Inspect CI results for the pushed revision when CI exists.
- Never mark skipped or unrun enforcement tests as passed.
- End each checkpoint with changes, checks, evidence, commit ID, synchronization status, and remaining issues.

## Component order

Keep ACLAIS, the local receiver, and Document Tools in this repository. Follow the specified order: ACLAIS (G1), receiver (G2), Document Tools (G3), integrated audit (G4). Do not start a later production component before its required earlier gate passes. A Windows enforcement claim requires the real target-platform checks in the specifications.
