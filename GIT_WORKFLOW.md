# Git workflow

## Repository identity

- Verified repository: `sai161812/aclais-1`
- Remote: `origin` → `https://github.com/sai161812/aclais-1.git`
- Visibility: public
- Default branch before the first push: `main`
- Current default branch reported by GitHub: `aclais-prototype` (after the first branch was pushed to the empty repository)
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

Keep one Git repository and one working branch for all components. The canonical layout is `aclais/`, `receiver/`, `document-tools/`, `shared/`, `tests/`, `scripts/`, and the existing `docs/`. Component source, tests, assets, manifests, and configuration stay in their component folder. Root `tests/` is cross-component only; root `scripts/` contains whole-system orchestration only. Shared files remain schemas and minimal protocol definitions. Keep later component folders as reservation notes until their prerequisite gate passes. Do not create nested repositories, submodules, or separate component histories. Never put provisioned credentials, confidential fixtures, runtime databases, or protected installation data in Git. Use the root orchestration commands without requiring a manual `cd` into a component.

## Checkpoint procedure

1. Confirm the checkpoint's mandatory prerequisites and inspect files before staging.
2. Make only the requested checkpoint changes and inspect the complete diff.
3. Stage explicit paths, then inspect the staged names and staged diff for secrets, unrelated work, and scope errors.
4. Commit a passing checkpoint coherently with its implementation, tests, and documentation.
5. Push only the working branch to the verified remote. Verify the remote branch head and push result; report synchronization failure accurately.
6. When CI exists, inspect the checks for the pushed revision. Never report skipped or unrun enforcement checks as passing.

For the repository-structure checkpoint, stage the moves and all import, script, worker-registration, frontend, CI, spec, permission-assumption, and documentation updates together. Rerun affected checks after relocation; historical PASS records do not replace checks invalidated by a source-path or ACL change.

Never force-push, destructively reset, rewrite shared history, change repository settings, merge, or deploy without a separate instruction. Use `.gitignore` for local secrets/environments, runtime databases and raw receipts, generated confidential fixtures, unsanitized logs, and build output; retain synthetic fixture templates and sanitized summaries.
