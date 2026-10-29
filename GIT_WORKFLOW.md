# Git workflow

## Repository identity

- Verified repository: `sai161812/aclais-1`
- Remote: `origin` → `https://github.com/sai161812/aclais-1.git`
- Visibility: public
- Default branch before the first push: `main`
- Current verified default branch: `main` (A10 owner-delegated correction); the first working-branch push originally made `aclais-prototype` the default
- Initial remote state: empty; no branches or commits
- Workspace before setup: `D:\Workspace\IDL\ACLAIS-1` had no `.git` directory, local branch/history, staged changes, remote, or tracking configuration. Its root contained the nine supplied specification files under `docs/`.
- Local baseline: commit `0752747004fc689e07f8e55435964bf4d267fd12` on `main`, containing the specification pack, workflow documents, agent instructions, and ignore rules.
- Current branch: `aclais-prototype`, created from that baseline; it tracks `origin/aclais-prototype`.
- First push head: `01effbdea3a55ede6d40b29bcc07003d4f0d8da2`. The final status push was verified separately by comparing local HEAD, `origin/aclais-prototype`, `git ls-remote --heads`, and the GitHub branch API.
- Local `main` retains the baseline commit and has no upstream. The baseline is present in the pushed working-branch history.
- The initial G0 tree had no `.github/workflows` directory. A1 adds `.github/workflows/portable-checks.yml`; record each pushed revision's portable CI result in `BUILD_STATUS.md`.

Initial repository facts were verified through the authenticated GitHub repository list and metadata, GitHub's branches endpoint, and `git ls-remote --heads`. The working branch and current default branch were checked again after push. No repository settings API was used, and no credentials are recorded here.

Before Git changes, inspect the root and complete working tree, current branch and history, all remotes, upstream/tracking configuration, and staged and unstaged diffs. Preserve existing changes and history. Verify the supplied remote's owner, repository name, public/private visibility, and configured default branch using authenticated GitHub tooling. Do not guess, create a repository, change visibility, or replace a remote.

## Branch selection

The verified repository was empty, so a documentation-only baseline was committed on local `main`, the configured default branch. Then `aclais-prototype` was created from that baseline. The remote default branch had no prior history to alter. Push only the working branch for this checkpoint. Keep ACLAIS, the receiver, and Document Tools together in this repository.

## Source organization

Keep one Git repository and one working branch for all components. The canonical layout is `aclais/`, `receiver/`, `document-tools/`, `shared/`, `tests/`, `scripts/`, and the existing `docs/`. Component source, tests, assets, manifests, and configuration stay in their component folder. Root `tests/` is cross-component only; root `scripts/` contains whole-system orchestration only. Shared files remain schemas and minimal protocol definitions. Keep later component folders as reservation notes until their prerequisite gate passes; receiver implementation is permitted only after the verified G1 PASS. Do not create nested repositories, submodules, or separate component histories. Never put provisioned credentials, confidential fixtures, runtime databases, or protected installation data in Git. Use the root orchestration commands without requiring a manual `cd` into a component.

## Checkpoint procedure

1. Confirm the checkpoint's mandatory prerequisites and inspect files before staging.
2. Make only the requested checkpoint changes and inspect the complete diff.
3. Stage explicit paths, then inspect the staged names and staged diff for secrets, unrelated work, and scope errors.
4. Commit a passing checkpoint coherently with its implementation, tests, and documentation.
5. Push only the working branch to the verified remote. Verify the remote branch head and push result; report synchronization failure accurately.
6. When CI exists, inspect the checks for the pushed revision. Never report skipped or unrun enforcement checks as passing.

For the repository-structure checkpoint, stage the moves and all import, script, worker-registration, frontend, CI, spec, permission-assumption, and documentation updates together. Rerun affected checks after relocation; historical PASS records do not replace checks invalidated by a source-path or ACL change.

R0 follow-up startup commands use root `scripts/start.ps1 -Service Backend|Frontend` and delegate component details to `aclais/scripts/start.ps1`. Verify startup and Ctrl+C shutdown from an unrelated directory, strict occupied-port failure without replacing an existing owner, and the implemented portable checks before committing the orchestration change. This follow-up does not start A4 or invalidate unchanged worker-runtime/ACL paths.

Never force-push, destructively reset, rewrite shared history, change repository settings, merge, or deploy without a separate instruction. Use `.gitignore` for local secrets/environments, runtime databases and raw receipts, generated confidential fixtures, unsanitized logs, and build output; retain synthetic fixture templates and sanitized summaries.

## A10 owner-delegated default/base correction

The owner explicitly delegated resolution of the self-PR conflict during A10 ("decide yourself and mention in relevant docs"). Publish only the existing local documentation baseline 0752747004fc689e07f8e55435964bf4d267fd12 as main, then set GitHub's default to main. Both actions succeeded and authenticated metadata independently verified sai161812/aclais-1, public, default main. No existing branch history or visibility was changed. This one baseline publication/default correction is the separately authorized exception to working-branch-only pushes and settings preservation; it is not continuing permission for other settings/default-branch changes.

Keep aclais-prototype tracking origin/aclais-prototype. Checkpoint commits still push only that branch. Target one draft PR from aclais-prototype to verified main; do not request reviewers, merge or deploy. Portable push CI targets the working branch; pull_request CI targets main. Verify CI against the exact current pushed head, not an older successful run or only a PR merge ref.

## Component 2 / G2 receiver checkpoint

G1 PASS was verified before receiver implementation. The receiver lives entirely under `receiver/`; only the public cross-component HTTP adapter test lives in root `tests/`. Its runtime database, `admin.token`, raw receipt files and generated ingest credentials are outside Git, with explicit ignore rules as defense in depth. The portable workflow has a receiver job for lint, component tests and a live IPv6 ACLAIS-adapter integration test. Windows ACL acceptance is a separate demonstration-machine lane and is never inferred from portable CI. Stage only explicit source, lock, migration, tests, workflow, sanitized evidence, specification, decision, and runbook paths; inspect the staged diff and verify no runtime artifacts or credentials are included. Push only `aclais-prototype`, verify the exact remote head, and inspect the exact-revision push CI run.
