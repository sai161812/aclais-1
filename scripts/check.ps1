$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $repoRoot 'backend/aclais'
$frontendDir = Join-Path $repoRoot 'frontend/aclais'

function Invoke-Check([string]$Name, [string]$Executable, [string[]]$Arguments) {
    Write-Host "`n== $Name =="
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE." }
}

Push-Location $backendDir
try {
    Invoke-Check 'Sync locked backend environment' 'uv' @('sync', '--locked')
    Invoke-Check 'Backend lint' 'uv' @('run', '--locked', 'ruff', 'check', '.')
    Invoke-Check 'Portable backend tests' 'uv' @('run', '--locked', 'pytest', '-m', 'portable')
    Invoke-Check 'OpenAPI source consistency' 'uv' @('run', '--locked', 'python', '../../scripts/export_openapi.py', '--check')
}
finally {
    Pop-Location
}

Push-Location $frontendDir
try {
    Invoke-Check 'Install locked frontend environment' 'npm' @('ci')
    Invoke-Check 'Generate TypeScript API types' 'npm' @('run', 'api:generate')
}
finally {
    Pop-Location
}

Push-Location $repoRoot
try {
    Invoke-Check 'Generated TypeScript is current' 'git' @('diff', '--exit-code', '--', 'frontend/aclais/src/generated/api.ts')
}
finally {
    Pop-Location
}

Push-Location $frontendDir
try {
    Invoke-Check 'Frontend type checking' 'npm' @('run', 'typecheck')
    Invoke-Check 'Frontend lint' 'npm' @('run', 'lint')
    Invoke-Check 'Frontend production build' 'npm' @('run', 'build')
}
finally {
    Pop-Location
}

Write-Host "`nPortable checks passed. This script does not run Windows enforcement checks."
