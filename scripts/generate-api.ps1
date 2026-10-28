$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $repoRoot 'backend/aclais'
$frontendDir = Join-Path $repoRoot 'frontend/aclais'

Push-Location $backendDir
try {
    uv run --locked python ../../scripts/export_openapi.py
    if ($LASTEXITCODE -ne 0) { throw 'OpenAPI export failed.' }
}
finally {
    Pop-Location
}

Push-Location $frontendDir
try {
    npm run api:generate
    if ($LASTEXITCODE -ne 0) { throw 'TypeScript API generation failed.' }
}
finally {
    Pop-Location
}
