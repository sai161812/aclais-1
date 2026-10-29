[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Backend', 'Frontend', 'Receiver', 'DocumentTools')]
    [string]$Service
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if ($Service -in @('Receiver', 'DocumentTools')) {
    $componentName = if ($Service -eq 'Receiver') { 'receiver' } else { 'document-tools' }
    $serviceName = if ($Service -eq 'Receiver') { 'Receiver' } else { 'Document Tools' }
    $componentStart = Join-Path $repoRoot "$componentName\scripts\start.ps1"
    if (-not (Test-Path -LiteralPath $componentStart -PathType Leaf)) {
        throw "The $serviceName component start script is missing."
    }
    & $componentStart
    if ($LASTEXITCODE -ne 0) { throw "$serviceName development service exited with code $LASTEXITCODE." }
    return
}
$componentStart = Join-Path $repoRoot 'aclais\scripts\start.ps1'
if (-not (Test-Path -LiteralPath $componentStart -PathType Leaf)) {
    throw 'The ACLAIS component start script is missing.'
}

& $componentStart -Service $Service
