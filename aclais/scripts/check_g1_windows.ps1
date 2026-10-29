$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$backend = Join-Path $componentRoot 'backend'
& (Join-Path $PSScriptRoot 'protect_checkout.ps1') | Out-Null
& (Join-Path $PSScriptRoot 'deploy_a2_probe.ps1') | Out-Null
& (Join-Path $PSScriptRoot 'deploy_a3_probe.ps1') | Out-Null
& (Join-Path $PSScriptRoot 'run_a2_access_probe.ps1') | Out-Null
$windowsXml = 'C:\ACLAIS-Lab\evidence\g1-windows-results.xml'
$uiXml = 'C:\ACLAIS-Lab\evidence\g1-ui-fixture-results.xml'
& uv --directory $backend run --locked --group windows-enforcement pytest `
    -c (Join-Path $backend 'pyproject.toml') (Join-Path $backend 'tests') `
    (Join-Path $componentRoot 'tests\windows_enforcement') -m windows_enforcement -v --tb=short --junitxml=$windowsXml
if ($LASTEXITCODE -ne 0) { throw 'G1 Windows checks failed; no PASS report was generated.' }
& uv --directory $backend run --locked --group windows-enforcement pytest `
    (Join-Path $backend 'tests\test_ui_fixtures_windows.py') -m windows_ui -q --tb=short --junitxml=$uiXml
if ($LASTEXITCODE -ne 0) { throw 'Isolated UI fixture checks failed; no PASS report was generated.' }
$windowsResult = ([xml](Get-Content -LiteralPath $windowsXml -Raw)).testsuites.testsuite
$uiResult = ([xml](Get-Content -LiteralPath $uiXml -Raw)).testsuites.testsuite
foreach ($result in @($windowsResult, $uiResult)) {
    if ([int]$result.skipped -ne 0 -or [int]$result.failures -ne 0 -or [int]$result.errors -ne 0) {
        throw 'A mandatory target check was skipped or failed.'
    }
}
if ([int]$windowsResult.tests -lt 13 -or [int]$uiResult.tests -ne 1) { throw 'Mandatory checks were not collected.' }
# The operator test rotates the owned confidential fixture; measure final access again.
& (Join-Path $PSScriptRoot 'run_a2_access_probe.ps1') | Out-Null
& uv --directory $backend run --locked python -m aclais.operator doctor
if ($LASTEXITCODE -ne 0) { throw 'Final owner doctor failed.' }
$digest = (& uv --directory $backend run --locked python (Join-Path $PSScriptRoot 'source_digest.py')) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Unable to identify tested source inputs.' }
$a2 = Get-Content -LiteralPath (Join-Path $repoRoot 'evidence\a2-access-summary.json') -Raw | ConvertFrom-Json
$platform = Get-CimInstance Win32_OperatingSystem
$report = [ordered]@{
    checkpoint='A10'; gate='G1'; windows_checks_passed=$true
    tested_base_revision=(& git -C $repoRoot rev-parse HEAD).Trim()
    tested_input_sha256=$digest.sha256; tested_input_file_count=$digest.file_count
    windows_edition=$platform.Caption; windows_build=$platform.BuildNumber
    file_system=(Get-Volume -DriveLetter C).FileSystem
    access_probe_check_count=$a2.check_count; fixture_count=$a2.fixture_count
    worker_is_administrator=$a2.worker_is_administrator
    windows_test_count=[int]$windowsResult.tests; isolated_ui_fixture_test_count=[int]$uiResult.tests
    raw_inventory_committed=$false; receiver_production_integration='PENDING_G4'
    commands=@(
        @{command='protect_checkout.ps1'; exit_code=0},
        @{command='deploy_a2_probe.ps1'; exit_code=0},
        @{command='deploy_a3_probe.ps1'; exit_code=0},
        @{command='run_a2_access_probe.ps1 (before and after Windows suite)'; exit_code=0},
        @{command='uv run --locked --group windows-enforcement pytest -c pyproject.toml tests ../tests/windows_enforcement -m windows_enforcement -v --tb=short'; exit_code=0},
        @{command='uv run --locked --group windows-enforcement pytest tests/test_ui_fixtures_windows.py -m windows_ui -q --tb=short'; exit_code=0; enforcement_evidence=$false},
        @{command='python -m aclais.operator doctor'; exit_code=0}
    )
}
[IO.File]::WriteAllText((Join-Path $repoRoot 'evidence\g1-check-summary.json'), ($report | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
Write-Host 'G1 Windows and demonstration-machine checks passed. Portable CI remains separate.'
