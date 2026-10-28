# Test lanes

`backend/aclais/tests` contains portable checks for configuration, API contracts, and logging. Mark portable tests with `pytest.mark.portable`.

`tests/windows_enforcement` is reserved for automated checks that must exercise the real Windows worker identity, NTFS permissions, Credential Manager, or Job Objects. Such checks use `pytest.mark.windows_enforcement` and must run against the target Windows environment. A2's private PowerShell probe is a manual demonstration-machine check recorded in `../evidence/A2.md`; it does not count as the automated Windows lane, which remains `NOT_RUN`. A skipped or absent check is never a pass.

`tests/probes` contains only private ACLAIS verification probes. They remain outside production tools, routes, packaging, and UI; they are not the later hostile Document Tools workers.
