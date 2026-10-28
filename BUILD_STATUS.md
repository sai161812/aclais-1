# Build status

As of 2026-10-28. A0 completes readiness and specification reconciliation only; no application features have been implemented.

## Current state

- All nine specification files in `docs/` have been reviewed in the prescribed order and reconciled for consistent implementation.
- The supplied repository is verified as `sai161812/aclais-1` at `https://github.com/sai161812/aclais-1.git`; it is public. GitHub reported `main` as the default before the first push and now reports `aclais-prototype` after the first branch was pushed to the empty repository.
- The remote was genuinely empty: GitHub reported repository size 0 and no branches, its refs endpoint reported an empty repository, and `git ls-remote --heads` returned no refs. A documentation-only baseline was committed to local `main` as `0752747004fc689e07f8e55435964bf4d267fd12`; working branch `aclais-prototype` was created from it. Only `aclais-prototype` was pushed; it tracks `origin/aclais-prototype`, and the local and GitHub branch heads matched after the final status push.
- Environment observed: Windows 11 Home Single Language 10.0.26200, 64-bit; C: and D: are NTFS. Python 3.12.10/pip 25.0.1, Node.js v24.19.0/npm 11.17.0, Git 2.55.0.windows.4. Chrome 156.0.8078.48 and Edge 156.0.4314.50 are installed. Globally visible Python packages: FastAPI 0.115.0, Pydantic 2.9.2 and pytest 8.3.3; pywin32 is absent. The current shell is not elevated. `C:\ACLAIS-Lab` and local account `AclaisWorker` are absent. There is no project source, virtual environment, or lockfile. Global npm package inventory failed because `%APPDATA%\npm` does not exist; `npm --version` succeeds. Provisioning capability has not been tested.
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
| A1 — project foundation | NOT_STARTED | Requires A0 PASS. |
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
- Application tests: NOT_RUN; A0 is specification/readiness only and no application code exists.
- Windows security enforcement: NOT_RUN; no enforcement implementation exists.
- Evidence artifacts: none; environment output and source review are recorded in this status/decision log.
- Baseline commit: `0752747004fc689e07f8e55435964bf4d267fd12` on local `main` and in the working-branch history.
- G0 workflow commit: `01effbdea3a55ede6d40b29bcc07003d4f0d8da2`.
- A0 checkpoint commit: `536b02cdf05fb50f6109f010fbec2507f6f9c932`.
- Synchronization: the A0 checkpoint commit was pushed to `origin/aclais-prototype`; `git ls-remote --heads` matched the commit and GitHub's branch API confirmed the working branch. A final status-only commit records this verification.
- CI: no `.github/workflows` directory exists; GitHub reported no workflow runs or commit status checks for the A0 checkpoint commit.

## Next step

G0 and A0 are complete. Stop after A0 for this request. A1 remains NOT_STARTED. Future A2 setup requires explicit elevation to create the non-administrator `AclaisWorker` account and `C:\ACLAIS-Lab`; neither exists yet. Portable CI, Windows automation and demonstration-machine acceptance remain future work.
