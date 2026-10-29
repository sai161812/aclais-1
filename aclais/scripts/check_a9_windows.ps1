$ErrorActionPreference = 'Stop'

$componentRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $componentRoot 'backend'
Push-Location $backendDir
try {
    & uv run --locked --group windows-enforcement pytest -m windows_enforcement `
        tests/test_owner_windows.py::test_a9_connected_dashboard_refresh_keyboard_and_visual_evidence --tb=short
    if ($LASTEXITCODE -ne 0) {
        throw "A9 connected dashboard checks failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

Write-Host 'A9 connected dashboard browser checks and sanitized screenshots passed.'
