$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot 'check_a3_windows.ps1')
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "A3 protected worker foundation checks failed: $LASTEXITCODE"
}

Push-Location (Join-Path $componentRoot 'backend')
try {
    & uv run --locked pytest -c pyproject.toml ../tests/windows_enforcement/test_a6_lifecycle.py `
        -m windows_enforcement -v
    if ($LASTEXITCODE -ne 0) {
        throw "A6 Windows lifecycle checks failed: $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "`nA6 actual Windows lifecycle checks passed. Portable checks are a separate lane."
