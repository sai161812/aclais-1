$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$backend = Join-Path $repoRoot 'aclais\backend'
$reportPath = 'C:\ACLAIS-Lab\evidence\g3-windows-results.xml'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The G3 demonstration check must run in the ordinary ACLAIS owner session.'
}
if (-not (Test-Path -LiteralPath 'C:\ACLAIS-Lab\.owner-sentinel.json' -PathType Leaf)) {
    throw 'The provisioned A2 target-machine runtime is unavailable.'
}
if ((Get-Content -LiteralPath (Join-Path $repoRoot 'evidence\G1.md') -Raw) -notmatch 'G1 PASS') {
    throw 'G1 evidence must pass before Component 3 checks run.'
}
if ((Get-Content -LiteralPath (Join-Path $repoRoot 'evidence\G2.md') -Raw) -notmatch 'G2 acceptance: PASS') {
    throw 'G2 evidence must pass before Component 3 checks run.'
}

& (Join-Path $repoRoot 'aclais\scripts\protect_checkout.ps1') | Out-Null
if (-not $?) { throw 'The worker-accessible checkout boundary failed.' }
& (Join-Path $repoRoot 'aclais\scripts\deploy_a2_probe.ps1') | Out-Null
if (-not $?) { throw 'The protected A2 runtime could not be refreshed.' }
& (Join-Path $repoRoot 'aclais\scripts\deploy_a3_probe.ps1') | Out-Null
if (-not $?) { throw 'The protected A3 source inventory could not be refreshed.' }
& (Join-Path $repoRoot 'aclais\scripts\run_a2_access_probe.ps1') | Out-Null
if (-not $?) { throw 'The actual worker access probe failed.' }

& (Join-Path $PSScriptRoot 'install_worker.ps1') | Out-Null
if (-not $?) { throw 'The fixed Document Tools worker installation failed.' }

& uv --directory (Join-Path $repoRoot 'document-tools') sync --locked
if ($LASTEXITCODE -ne 0) { throw 'The Document Tools environment is not locked and complete.' }
& npm --prefix (Join-Path $componentRoot 'frontend') ci
if ($LASTEXITCODE -ne 0) { throw 'The locked Document Tools frontend could not be installed.' }
& npm --prefix (Join-Path $componentRoot 'frontend') run build
if ($LASTEXITCODE -ne 0) { throw 'The actual Document Tools site did not build.' }
& npm --prefix (Join-Path $repoRoot 'aclais\frontend') run build
if ($LASTEXITCODE -ne 0) { throw 'The actual ACLAIS approval workspace did not build.' }

& uv --directory $backend run --locked --group windows-enforcement pytest `
    -c (Join-Path $backend 'pyproject.toml') (Join-Path $repoRoot 'tests\test_g3_report_formatter_windows.py') `
    -m windows_enforcement -v --tb=short --junitxml=$reportPath
if ($LASTEXITCODE -ne 0) { throw 'The G3 paired target-machine worker checks failed.' }
$result = ([xml](Get-Content -LiteralPath $reportPath -Raw)).testsuites.testsuite
if ([int]$result.tests -ne 2 -or [int]$result.skipped -ne 0 -or
    [int]$result.failures -ne 0 -or [int]$result.errors -ne 0) {
    throw 'One or more mandatory G3 target-machine worker checks were skipped or failed.'
}

$rawFormatter = Get-ChildItem -LiteralPath 'C:\ACLAIS-Lab\evidence\raw\g3' -Filter 'report-formatter-*.json' -File |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -eq $rawFormatter) { throw 'The Report Formatter check did not write protected raw evidence.' }
& uv --directory $backend run --locked python (Join-Path $repoRoot 'document-tools\scripts\sanitize_g3_report_formatter.py') `
    --raw $rawFormatter.FullName
if ($LASTEXITCODE -ne 0) { throw 'The sanitized G3 report rejected the raw target evidence.' }

$rawInvoice = Get-ChildItem -LiteralPath 'C:\ACLAIS-Lab\evidence\raw\g3' -Filter 'invoice-analyzer-*.json' -File |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -eq $rawInvoice) { throw 'The Invoice Analyzer check did not write protected raw evidence.' }
& uv --directory $backend run --locked python (Join-Path $repoRoot 'document-tools\scripts\sanitize_g3_invoice_analyzer.py') `
    --raw $rawInvoice.FullName
if ($LASTEXITCODE -ne 0) { throw 'The sanitized G3 Invoice Analyzer evidence was rejected.' }
Write-Host 'The paired Report Formatter and Invoice Analyzer target-machine checks passed. G4 remains pending.'
