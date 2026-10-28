$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$componentCheck = Join-Path $repoRoot 'aclais\scripts\check.ps1'
if (-not (Test-Path -LiteralPath $componentCheck -PathType Leaf)) {
    throw 'The ACLAIS component check script is missing.'
}

& $componentCheck
if (-not $?) {
    throw 'The implemented ACLAIS portable checks failed.'
}
