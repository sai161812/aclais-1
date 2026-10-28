# Build status

As of 2026-10-29. A0 is complete. A1 foundation code and local portable checks are implemented; the A1 workflow result is pending the required push. No Windows enforcement or later production component has been implemented.

## Current state

- All nine specification files in `docs/` have been reviewed in the prescribed order and reconciled for consistent implementation.
- The supplied repository is verified as `sai161812/aclais-1` at `https://github.com/sai161812/aclais-1.git`; it is public. GitHub reported `main` as the default before the first push and now reports `aclais-prototype` after the first branch was pushed to the empty repository.
- The remote was genuinely empty: GitHub reported repository size 0 and no branches, its refs endpoint reported an empty repository, and `git ls-remote --heads` returned no refs. A documentation-only baseline was committed to local `main` as `0752747004fc689e07f8e55435964bf4d267fd12`; working branch `aclais-prototype` was created from it. Only `aclais-prototype` was pushed; it tracks `origin/aclais-prototype`, and the local and GitHub branch heads matched after the final status push.
- Initial A0 environment inventory: Windows 11 Home Single Language 10.0.26200, 64-bit; C: and D: are NTFS. Python 3.12.10/pip 25.0.1, Node.js v24.19.0/npm 11.17.0, Git 2.55.0.windows.4. Chrome 156.0.8078.48 and Edge 156.0.4314.50 are installed. Globally visible Python packages: FastAPI 0.115.0, Pydantic 2.9.2 and pytest 8.3.3; pywin32 is absent. The shell is not elevated. `C:\ACLAIS-Lab` and local account `AclaisWorker` are absent. At that inventory, no project source, project virtual environment or lockfile existed; A1 now establishes the isolated backend/frontend sources, environments and locks below. Global npm package inventory failed because `%APPDATA%\npm` does not exist; `npm --version` succeeds. Provisioning capability has not been tested.
- A1 toolchain: Python 3.12.10 with `uv` 0.12.15; Node.js 24.19.0 with npm 11.17.0. Isolated locked backend versions: FastAPI 0.162.0, Pydantic 2.14.1, Uvicorn 0.54.0, pytest 9.2.0, Ruff 0.17.3 and httpx2 2.16.0. Frontend versions: React/React DOM 19.3.1, Vite 8.3.5, TypeScript 5.9.3, ESLint 10.13.0 and openapi-typescript 7.13.0. `npm ci` reported zero vulnerabilities in the installed lockfile.
- Cookie boundary is specified as ACLAIS `127.0.0.1:8765` and Document Tools `localhost:8766`; Windows resolves `localhost` to both `::1` and `127.0.0.1`, so its listener must bind both loopback addresses. The receiver remains server-to-server at `127.0.0.1:8767`.
- A0 records resolved rules for cookie-host separation; SQLite/NTFS publication and retry recovery; Windows credential/alternate-user/job/pipe lifecycle; task-event precedence; strict request/response and operation models; dashboard API mapping; pre-receiver/private probe discipline; and separate portable, Windows, and demo-machine verification lanes.

## Gates

| Gate | Status | Evidence / prerequisite |
|---|---|---|
| G0 — environment and contract review | PASS | All nine specs and the environment were reviewed; repository metadata was verified; local `main` documentation baseline created; `aclais-prototype` pushed and matched against the GitHub branch head. |
| G1 — ACLAIS | NOT_STARTED | Requires G0 and the Windows enforcement checks in `docs/03_BUILD_ACLAIS.md`. |
| G2 — receiver | NOT_STARTED | Requires passing G1. |
| G3 — Document Tools | NOT_STARTED | Requires passing G1 and G2. |
| G4 — integrated release audit | NOT_STARTED | Requires passing G1, G2, and G3. |

## A0–A10 checkpoints

| Checkpoint | Status | Evidence / prerequisite |
|---|---|---|
| A0 — readiness and specification | PASS | All nine specs reconciled, environment reviewed, decisions recorded, plan created; no application changes. |
| A1 — project foundation | NOT_RUN | Local checks passed; required GitHub Actions run awaits the A1 push. |
| A2 — protected fixtures and worker identity | NOT_STARTED | Requires A1 PASS and explicit one-time elevation. |
| A3 — launcher and containment | NOT_STARTED | Requires A2 PASS. |
| A4 — persistence and contracts | NOT_STARTED | Requires A3 PASS. |
| A5 — broker and publication | NOT_STARTED | Requires A2–A4 PASS. |
| A6 — lifecycle and recovery | NOT_STARTED | Requires A3–A5 PASS. |
| A7 — verification and evidence | NOT_STARTED | Requires A2, A4–A6 PASS. |
| A8 — owner authentication and approval | NOT_STARTED | Requires A4, A6 and A7 PASS. |
| A9 — connected dashboard | NOT_STARTED | Requires A5–A8 PASS. |
| A10 — complete G1 audit | NOT_STARTED | Requires A1–A9 PASS; all verification lanes required. |

## Checks and evidence

- A0 checks run: all nine specs read in order; repository/working-tree/branch/remote inspection; authenticated GitHub repository metadata; OS/filesystem/runtime/browser/worker-account/elevation and installed-package inventory; current working branch and remote tracking inspected. `npm --version` succeeded; `npm list -g --depth=0` could not enumerate packages because its configured user prefix directory is absent. Cross-spec consistency reviewed; all local Markdown targets resolve; A0–A10 headings and required fields are present; obsolete-path/host/receiver-test wording search is clear; `git diff --check` passed.
- A1 local portable checks: `scripts/check.ps1` passed; Ruff passed; pytest passed (19 portable tests); generated OpenAPI matched backend models; generated TypeScript matched the schema; TypeScript typecheck, ESLint and Vite production build passed. `npm ci` installed from lockfile and reported 0 vulnerabilities. Runtime smoke check passed for direct API health, same-origin Vite proxy and frontend shell HTTP 200; health reports `protection_ready:false` and G1 protection `unknown` as intended.
- A1 GitHub Actions: workflow added with separate portable backend/frontend jobs; run for the implementation commit is pending push. Windows enforcement lane: NOT_RUN; no Windows enforcement tests or implementation were added in A1.
- G1/Windows enforcement tests: NOT_RUN; A1 only adds portable foundation and tests. No enforcement result is claimed.
- Windows security enforcement: NOT_RUN; no enforcement implementation exists.
- Evidence artifacts: none; environment output and source review are recorded in this status/decision log.
- Baseline commit: `0752747004fc689e07f8e55435964bf4d267fd12` on local `main` and in the working-branch history.
- G0 workflow commit: `01effbdea3a55ede6d40b29bcc07003d4f0d8da2`.
- A0 checkpoint commit: `536b02cdf05fb50f6109f010fbec2507f6f9c932`.
- Synchronization: the A0 checkpoint commit was pushed to `origin/aclais-prototype`; `git ls-remote --heads` matched the commit and GitHub's branch API confirmed the working branch. A final status-only commit records this verification.
- CI history: the A0 commit had no workflow because `.github/workflows` did not yet exist. GitHub reported no workflow runs or commit status checks for that A0 revision. A1 adds the portable workflow; its A1 run is pending push.

## Next step

G0 and A0 are complete. A1 remains NOT_RUN until the pushed revision's portable CI checks are inspected. A2 setup requires explicit elevation to create the non-administrator `AclaisWorker` account and `C:\ACLAIS-Lab`; neither exists yet. Windows automation and demonstration-machine enforcement acceptance remain future work.
