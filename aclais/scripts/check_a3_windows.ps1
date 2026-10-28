$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'A3 tests must run from the ordinary owner session.'
}
if (-not (Test-Path -LiteralPath 'C:\ACLAIS-Lab\.owner-sentinel.json')) {
    throw 'A3 actual Windows enforcement requires the provisioned demonstration-machine lab.'
}

Push-Location $repoRoot
try {
    & (Join-Path $PSScriptRoot 'deploy_a3_probe.ps1')
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "A3 runtime deployment failed: $LASTEXITCODE" }
    Push-Location (Join-Path $componentRoot 'backend')
    try {
        & uv run --locked pytest -c pyproject.toml ../tests/windows_enforcement/test_a3_windows_launcher.py -m windows_enforcement -v
        if ($LASTEXITCODE -ne 0) { throw "A3 Windows enforcement checks failed: $LASTEXITCODE" }
    }
    finally { Pop-Location }
}
finally { Pop-Location }

Write-Host "`nA3 actual Windows launcher checks passed. Portable CI is a separate lane."
