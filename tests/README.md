# Test lanes

`backend/aclais/tests` contains portable checks for configuration, API contracts, and logging. Mark portable tests with `pytest.mark.portable`.

`tests/windows_enforcement` is reserved for checks that must exercise the real Windows worker identity, NTFS permissions, Credential Manager, or Job Objects. Such checks use `pytest.mark.windows_enforcement` and must run against the target Windows environment. There are no Windows enforcement tests in A1; that lane remains `NOT_RUN` until checks are implemented and executed. A skipped or absent check is never a pass.

`tests/probes` is reserved for small private probe programs used by later ACLAIS verification. A1 adds no probes or production tools.
