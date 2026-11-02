$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot
$backendDir = Join-Path $componentRoot 'backend'
$frontendDir = Join-Path $componentRoot 'frontend'
$openApiExporter = Join-Path $PSScriptRoot 'export_openapi.py'

Push-Location $backendDir
try {
    uv run --locked python $openApiExporter
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
