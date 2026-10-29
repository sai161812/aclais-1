$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
Push-Location $componentRoot
try {
& uv --project $componentRoot sync --locked
if ($LASTEXITCODE -ne 0) { throw 'Receiver dependency synchronization failed.' }
& uv --project $componentRoot run --locked ruff check . ..\tests\test_receiver_adapter_integration.py
if ($LASTEXITCODE -ne 0) { throw 'Receiver lint failed.' }
& uv --project $componentRoot run --locked pytest -m portable
if ($LASTEXITCODE -ne 0) { throw 'Receiver portable tests failed.' }
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$oldPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $repositoryRoot 'aclais\backend\src'
    & uv --project $componentRoot run --locked python -m pytest -q (Join-Path $repositoryRoot 'tests\test_receiver_adapter_integration.py')
    if ($LASTEXITCODE -ne 0) { throw 'Receiver and ACLAIS adapter integration failed.' }
} finally {
    $env:PYTHONPATH = $oldPythonPath
}
} finally {
    Pop-Location
}
