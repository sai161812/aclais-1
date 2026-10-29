$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw 'uv is required for the Document Tools Python checks.' }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'npm is required for the Document Tools frontend checks.' }

& uv --directory $componentRoot sync --locked
if ($LASTEXITCODE -ne 0) { throw 'Document Tools dependency sync failed.' }
& uv --directory $componentRoot run --locked ruff check src workers tests
if ($LASTEXITCODE -ne 0) { throw 'Document Tools lint failed.' }
& uv --directory $componentRoot run --locked pytest -m portable
if ($LASTEXITCODE -ne 0) { throw 'Document Tools portable tests failed.' }

$frontend = Join-Path $componentRoot 'frontend'
& npm --prefix $frontend ci
if ($LASTEXITCODE -ne 0) { throw 'Document Tools frontend dependency install failed.' }
& npm --prefix $frontend run typecheck
if ($LASTEXITCODE -ne 0) { throw 'Document Tools frontend type check failed.' }
& npm --prefix $frontend run build
if ($LASTEXITCODE -ne 0) { throw 'Document Tools frontend build failed.' }

Write-Host 'Document Tools portable checks passed. Windows worker enforcement remains a separate target-machine lane.'
