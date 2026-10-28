[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Backend', 'Frontend')]
    [string]$Service
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$componentStart = Join-Path $repoRoot 'aclais\scripts\start.ps1'
if (-not (Test-Path -LiteralPath $componentStart -PathType Leaf)) {
    throw 'The ACLAIS component start script is missing.'
}

& $componentStart -Service $Service
