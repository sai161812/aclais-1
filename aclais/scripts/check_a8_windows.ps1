$ErrorActionPreference = 'Stop'

$componentRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $componentRoot 'backend'
Push-Location $backendDir
try {
    & uv run --locked --group windows-enforcement pytest -m windows_enforcement tests/test_owner_windows.py --tb=short
    if ($LASTEXITCODE -ne 0) {
        throw "A8 Windows owner authentication checks failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

Write-Host 'A8 Chrome/Edge owner authentication and process-containment checks passed.'
