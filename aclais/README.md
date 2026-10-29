# ACLAIS component

This folder owns the ACLAIS backend (`backend/`), dashboard (`frontend/`), component-specific scripts (`scripts/`), portable and Windows enforcement tests, private probes, and sanitized fixture templates (`tests/`). The Python and frontend manifests and lockfiles are kept with their projects. Runtime fixtures, credentials, databases, installed protected code, and raw logs remain in their designated local runtime locations outside Git.

Run the implemented portable checks through the repository-root command `scripts/check.ps1`, or run component-specific commands from any working directory by their explicit paths. A Windows enforcement PASS requires the demonstration-machine checks recorded in `evidence/`; portable CI alone is not enforcement evidence.
