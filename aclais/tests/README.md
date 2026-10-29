# Test lanes

`aclais/backend/tests` contains portable checks for configuration, API contracts, and logging. Mark portable tests with `pytest.mark.portable`.

`aclais/tests/windows_enforcement` contains automated checks that exercise the real Windows worker identity, NTFS permissions, Credential Manager, or Job Objects. Such checks use `pytest.mark.windows_enforcement` and must run against the target Windows environment. A2's private PowerShell probe and A3 launcher check are demonstration-machine checks recorded in [`../../evidence/A2.md`](../../evidence/A2.md) and [`../../evidence/A3.md`](../../evidence/A3.md). Portable tests and CI do not prove Windows enforcement. A skipped or absent check is never a pass.

`aclais/tests/probes` contains only private ACLAIS verification probes. They remain outside production tools, routes, packaging, and UI; they are not the later hostile Document Tools workers. Root `tests/` is reserved for cross-component integration and acceptance tests.
