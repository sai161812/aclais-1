# Git workflow

## Repository identity

- Verified repository: `sai161812/aclais-1`
- Remote: `origin` → `https://github.com/sai161812/aclais-1.git`
- Visibility: public
- Configured default branch: `main`
- Initial remote state: empty; no branches or commits
- Workspace before setup: `D:\Workspace\IDL\ACLAIS-1` had no `.git` directory, local branch/history, staged changes, remote, or tracking configuration. Its root contained the nine supplied specification files under `docs/`.
- Local baseline: commit `0752747004fc689e07f8e55435964bf4d267fd12` on `main`, containing the specification pack, workflow documents, agent instructions, and ignore rules.
- Current branch: `aclais-prototype`, created from that baseline; upstream tracking is pending the first push.

These facts were verified through the authenticated GitHub repository list and metadata, GitHub's branches endpoint, and `git ls-remote --heads`. No credentials are recorded here.

Before Git changes, inspect the root and complete working tree, current branch and history, all remotes, upstream/tracking configuration, and staged and unstaged diffs. Preserve existing changes and history. Verify the supplied remote's owner, repository name, public/private visibility, and configured default branch using authenticated GitHub tooling. Do not guess, create a repository, change visibility, or replace a remote.

## Branch selection

The verified repository was empty, so a documentation-only baseline was committed on local `main`, the configured default branch. Then `aclais-prototype` was created from that baseline. The remote default branch had no prior history to alter. Push only the working branch for this checkpoint. Keep ACLAIS, the receiver, and Document Tools together in this repository.

## Checkpoint procedure

1. Confirm the checkpoint's mandatory prerequisites and inspect files before staging.
2. Make only the requested checkpoint changes and inspect the complete diff.
3. Stage explicit paths, then inspect the staged names and staged diff for secrets, unrelated work, and scope errors.
4. Commit a passing checkpoint coherently with its implementation, tests, and documentation.
5. Push only the working branch to the verified remote. Verify the remote branch head and push result; report synchronization failure accurately.
6. When CI exists, inspect the checks for the pushed revision. Never report skipped or unrun enforcement checks as passing.

Never force-push, destructively reset, rewrite shared history, change repository settings, merge, or deploy without a separate instruction. Use `.gitignore` for local secrets/environments, runtime databases and raw receipts, generated confidential fixtures, unsanitized logs, and build output; retain synthetic fixture templates and sanitized summaries.
