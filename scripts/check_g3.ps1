$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$targetCheck = Join-Path $repoRoot 'document-tools\scripts\check_windows.ps1'
if (-not (Test-Path -LiteralPath $targetCheck -PathType Leaf)) {
    throw 'The Document Tools Windows target-check script is missing.'
}
& $targetCheck
if (-not $?) { throw 'The Report Formatter target check failed.' }
