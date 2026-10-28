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

## Repository structure

Keep one Git repository and the verified `aclais-prototype` working branch. The canonical component folders are `aclais/`, `receiver/`, and `document-tools/`; `shared/` contains only shared schemas and minimal protocol definitions. Component source, assets, tests, dependencies, and configuration stay inside the component that owns them. `aclais/tests/`, `receiver/tests/`, and `document-tools/tests/` contain component tests and private component probes. Root `tests/` is reserved for cross-component integration and acceptance tests only. Root `scripts/` contains whole-system orchestration commands; component-specific commands live under that component's `scripts/` folder and root commands must resolve their component paths without a manual directory change.

Keep only repository-wide files at the root, including these instructions and the existing tracking documents. Keep `docs/` in its supplied arrangement. Reserved later-component folders may contain structure notes only until their prerequisite gates pass; do not add production code early. Do not create nested repositories, submodules, or component histories. Keep shared code minimal: no business logic or trusted controller authority belongs in `shared/`, and components may communicate only through specified interfaces rather than importing another component's private implementation.

Keep root startup and check commands usable from any working directory. Delegate service-specific startup to the owning component; the caller must not manually enter a component folder. Development servers run in the foreground with explicit service choices and stop with Ctrl+C; failed startup must report failure without terminating an existing port owner.

Resolve worker entrypoints, runtime assets, and protected fixtures from explicit project or installation locations, never from the shell's current working directory. Preserve the controller's fixed allowlisted worker registration. Provisioned runtime data, credentials, and protected fixtures stay in their designated runtime locations and never move into Git as part of source organization. A source move that affects filesystem permissions or launch paths invalidates the corresponding prior check until that check is rerun on its required target.
