$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
$server = Join-Path $componentRoot 'src\document_tools\server.py'
$dist = Join-Path $componentRoot 'frontend\dist'
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw 'uv is required. Run scripts/check.ps1 first.' }
if (-not (Test-Path -LiteralPath (Join-Path $dist 'index.html') -PathType Leaf)) {
    throw 'Document Tools is not built. Run scripts/check.ps1 first.'
}
& uv --directory $componentRoot run --locked python $server --root $dist
if ($LASTEXITCODE -ne 0) { throw "Document Tools server exited with code $LASTEXITCODE." }
