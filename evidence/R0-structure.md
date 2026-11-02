# R0 repository-structure checkpoint evidence

- Result: PASS for local portable checks, demonstration-machine enforcement checks, and hosted portable CI on the implementation commit.
- Date: 2026-10-29.
- Repository/branch: `sai161812/aclais-1`, `aclais-prototype`; one Git worktree with no component submodules or nested repositories.
- Remote metadata: public repository, default branch `aclais-prototype`; authenticated metadata matched `origin` at `https://github.com/sai161812/aclais-1.git`.
- Runtime data and worker credentials remain under the existing owner-protected `C:\ACLAIS-Lab` location, outside Git.
- R0 implementation commit: `c86471821274697c3819dfe534ff811380874326` (`chore: organize component source structure`), pushed to `origin/aclais-prototype`.

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
- A2 was rerun after the R0 implementation push: 57/57 actual worker checks passed, and the protected installation manifest hash remained stable through probe and repair. The sanitized access summary records this later run; runtime credential values and contents remain absent.
- A2 path-hiding result: application-source read/write returned Win32 3 because traversal to the protected subtree was denied. The owner verified the source file existed and its before/after SHA-256 matched; this is the documented path-hidden denial condition. The private probe source and protected installation manifest matched by SHA-256.
- A3 actual Windows launcher test: `aclais/scripts/check_a3_windows.ps1` exited 0; pytest reported 1 passed. The test verified actual worker identity, suspended creation and Job Object assignment before resume, fixed entrypoint, argument/environment/cwd controls, task configuration, bounded dual-pipe capture, normal/child/cancel/timeout/shutdown/crash cleanup, fail-closed identity/assignment/credential conditions, and survival of an unrelated owner process.
- Post-test process inspection found 0 candidate processes owned by the worker SID.
- Post-commit runtime deployment identified source revision `c86471821274697c3819dfe534ff811380874326`; the post-commit A3 Windows test passed (1 passed), and process inspection again found 0 worker-owned processes.
- [GitHub Actions run 7](https://github.com/sai161812/aclais-1/actions/runs/40765960340) completed successfully for exact revision `c86471821274697c3819dfe534ff811380874326`. The Portable backend job passed all steps; the Portable frontend job passed all steps. These jobs do not execute Windows enforcement.
- Synchronization: `git ls-remote --heads origin aclais-prototype` matched the local branch at `c86471821274697c3819dfe534ff811380874326`; the working tree was clean after the implementation push. CI for the documentation-only evidence commit is reported separately from implementation and Windows enforcement results.

This checkpoint changes source organization and verification-path handling only. It adds no A4 persistence/contracts, receiver service, Document Tools site, or hostile production worker.

## R0 follow-up: root startup gap (2026-10-29)

The review found that root portable checks worked but the runbook still required manual component-directory changes to start the development servers. Root `scripts/start.ps1 -Service Backend|Frontend` now delegates to component-owned `aclais/scripts/start.ps1`. It passes explicit component directories to the installed uv/npm commands, keeps each service in the foreground and reports startup failures. Dependency-only instructions use explicit uv directory/npm prefix arguments as well. No application code, worker registration, protected installation, fixture data or A4 deliverable was changed.

Actual development-machine checks, from `C:\Windows\Temp`:

- `& '<repository-root>\scripts\start.ps1' -Service Backend`: started the configured API on `127.0.0.1:8765`; direct health returned HTTP 200 and `protection_ready:false`.
- `& '<repository-root>\scripts\start.ps1' -Service Frontend`: started Vite on `127.0.0.1:5173`; shell returned HTTP 200 and the proxied `/api/health` body matched the direct API response.
- While those two listeners were active, duplicate backend and frontend starts threw failure. The original listener process identities remained unchanged, and the caller's location remained `C:\Windows\Temp`.
- A reserved `Receiver` service choice failed parameter validation before launch. With PATH temporarily empty in the validation shell, both service choices returned the documented missing-runtime error before launch; PATH was restored afterward.
- Sent Ctrl+C to each foreground terminal. The API logged completed application shutdown; both terminal sessions ended with interruption exit code 1. Final checks observed no listener on either development port and no project uv/python/node process remaining. An initial broad project-process query during concurrent portable checks was inconclusive; the server-command query and the repeated post-suite query found no remaining development process.
- Root `scripts/check.ps1`: exit 0; Ruff PASS; 23 portable backend tests PASS; OpenAPI/type generation checks PASS; frontend typecheck/lint/build PASS; npm audit 0 vulnerabilities. These portable checks do not execute Windows enforcement.
- The runbook's dependency-only commands were also run from the repository root: `uv --directory .\aclais\backend sync --locked` and `npm --prefix .\aclais\frontend ci` both exited 0; npm reported 0 vulnerabilities.
- All 15 project-owned PowerShell scripts, including both new startup scripts, parsed without errors. All local links in the 28 tracked Markdown files resolved; `git diff --check` passed. Existing worker source/runtime paths and permissions were unchanged; A2/A3 enforcement was not rerun for this startup-only follow-up, and no new enforcement PASS is claimed.

Before this follow-up, implementation/status commits `c86471821274697c3819dfe534ff811380874326` and `3e9aa5889e3285ab59ed65385016fd94a08d4ef1` were synchronized. [Run 8](https://github.com/sai161812/aclais-1/actions/runs/40766363869) passed both portable jobs for `3e9aa5889e3285ab59ed65385016fd94a08d4ef1`.

Follow-up implementation commit: `860070068607acb7004a2cc001a5b7e39854bce8` (`fix: start development services through root orchestration`). Explicitly staged scripts/docs were reviewed and `git diff --cached --check` passed before commit. Push to `origin/aclais-prototype` succeeded; `git ls-remote --heads origin aclais-prototype` matched the local head and the working tree was clean. [Run 9](https://github.com/sai161812/aclais-1/actions/runs/40769494744) completed successfully for that exact SHA: Portable backend and Portable frontend jobs both passed with no failed steps. CI for this documentation-only evidence update is reported separately. A4 remains unstarted.
