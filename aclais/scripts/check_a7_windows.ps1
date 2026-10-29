$ErrorActionPreference = 'Stop'

# Run the real A6 launcher and lifecycle suite, which now validates A7 reports
# against independently observed process cleanup.
& (Join-Path $PSScriptRoot 'check_a6_windows.ps1')
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "A6 prerequisite and A7 Windows evidence checks failed: $LASTEXITCODE"
}

Write-Host 'A7 Windows fixture verification and evidence checks passed. Portable checks remain separate.'
