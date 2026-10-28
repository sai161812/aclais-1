# R0 repository-structure checkpoint evidence

- Result: PASS for local portable and demonstration-machine acceptance; hosted CI is pending the push for this revision.
- Date: 2026-10-29.
- Repository/branch: `sai161812/aclais-1`, `aclais-prototype`; one Git worktree with no component submodules or nested repositories.
- Remote metadata: public repository, default branch `aclais-prototype`; authenticated metadata matched `origin` at `https://github.com/sai161812/aclais-1.git`.
- Runtime data and worker credentials remain under the existing owner-protected `C:\ACLAIS-Lab` location, outside Git.

## Resulting source layout

- `aclais/backend/`: Python API, launcher/security code, Python manifest/lock, and backend tests.
- `aclais/frontend/`: dashboard shell, frontend configuration, generated API declarations, npm manifest/lock, and installed local frontend environment (ignored).
- `aclais/scripts/`: ACLAIS-specific checks, API generation, A2 provisioning/access/private-probe refresh, and A3 deployment/enforcement commands.
- `aclais/tests/`: ACLAIS component fixtures/templates, private probes, portable-test notes, and Windows enforcement tests.
- `receiver/` and `document-tools/`: reservation notes only; no production service or worker was added.
- `shared/`: generated `openapi.json` and a scope note limiting future content to schemas/minimal protocols.
- Root `tests/`: integration/acceptance scope note only. Root `scripts/`: repository-wide `check.ps1` and orchestration note.
- `docs/` remains in its supplied nine-file arrangement. Existing root tracking files remain at the repository root.

The tracked project moves preserve Git rename history where practical: the former `backend/aclais`, `frontend/aclais`, root ACLAIS `scripts/`, and component-only root `tests/` content now live under `aclais/`. No provisioned runtime files or credentials were moved into Git.

## Checks after relocation

- Root orchestration: invoked by absolute path from `C:\Windows\Temp`; passed without changing into a component directory.
- Environment: moved Python `.venv` contained stale executable launchers after relocation, so it was refreshed with `uv sync --locked --reinstall` under `aclais/backend/`; frontend packages were refreshed with `npm ci` under `aclais/frontend/`. Both environments remain ignored.
- Portable checks: Ruff passed; 23 backend tests passed; OpenAPI and generated TypeScript matched; frontend typecheck, lint, and production build passed; npm reported 0 vulnerabilities. Portable checks do not assert Windows enforcement.
- Portable workflow configuration parsed successfully; both backend/frontend jobs are present and `contents` permission remains read-only. The workflow uses no deployment credentials or self-hosted runners.
- Windows parser: all 31 component PowerShell scripts parsed with 0 syntax errors.
- A2 actual worker probe: the ordinary, non-elevated owner launched `LAPTOP-FMQ8RARQ\AclaisWorker`, SID `S-1-5-21-2514999450-3486617813-2191310599-1006`; the worker was not an administrator. All 57 checks passed. Selected-copy, temporary-output, protected originals, state, source, evidence, and integrity results were observed inside the actual worker. The owner confirmed fixture/source hashes remained unchanged, evidence was not created or modified, and cleanup completed. No credential value was recorded.
- A2 path-hiding result: application-source read/write returned Win32 3 because traversal to the protected subtree was denied. The owner verified the source file existed and its before/after SHA-256 matched; this is the documented path-hidden denial condition. The private probe source and protected installation manifest matched by SHA-256.
- A3 actual Windows launcher test: `aclais/scripts/check_a3_windows.ps1` exited 0; pytest reported 1 passed. The test verified actual worker identity, suspended creation and Job Object assignment before resume, fixed entrypoint, argument/environment/cwd controls, task configuration, bounded dual-pipe capture, normal/child/cancel/timeout/shutdown/crash cleanup, fail-closed identity/assignment/credential conditions, and survival of an unrelated owner process.
- Post-test process inspection found 0 candidate processes owned by the worker SID.
- Hosted GitHub Actions: NOT_RUN for the R0 revision pending push; inspect both portable jobs for the exact pushed commit before finalizing synchronization status.

This checkpoint changes source organization and verification-path handling only. It adds no A4 persistence/contracts, receiver service, Document Tools site, or hostile production worker.
