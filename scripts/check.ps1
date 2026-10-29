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

$receiverCheck = Join-Path $repoRoot 'receiver\scripts\check.ps1'
if (-not (Test-Path -LiteralPath $receiverCheck -PathType Leaf)) {
    throw 'The receiver component check script is missing.'
}
& $receiverCheck
if (-not $?) {
    throw 'The implemented receiver portable checks failed.'
}

Write-Host "`nPortable ACLAIS and receiver checks passed. Windows enforcement checks remain separate."
