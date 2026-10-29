[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Backend', 'Frontend', 'Receiver')]
    [string]$Service
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if ($Service -eq 'Receiver') {
    $receiverStart = Join-Path $repoRoot 'receiver\scripts\start.ps1'
    if (-not (Test-Path -LiteralPath $receiverStart -PathType Leaf)) {
        throw 'The receiver component start script is missing.'
    }
    & $receiverStart
    if ($LASTEXITCODE -ne 0) { throw "Receiver development service exited with code $LASTEXITCODE." }
    return
}
$componentStart = Join-Path $repoRoot 'aclais\scripts\start.ps1'
if (-not (Test-Path -LiteralPath $componentStart -PathType Leaf)) {
    throw 'The ACLAIS component start script is missing.'
}

& $componentStart -Service $Service
