[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
& uv --project $componentRoot run --locked aclais-receiver serve
if ($LASTEXITCODE -ne 0) {
    throw "Receiver service exited with code $LASTEXITCODE."
}
