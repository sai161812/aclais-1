[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('init', 'inspect')]
    [string]$Action,
    [string]$RunId
)

$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot
$arguments = @('--project', $componentRoot, 'run', '--locked', 'aclais-receiver', $Action)
if ($Action -eq 'inspect') {
    if ([string]::IsNullOrWhiteSpace($RunId)) { throw 'Inspect requires -RunId.' }
    $arguments += $RunId
}
& uv @arguments
if ($LASTEXITCODE -ne 0) { throw "Receiver $Action failed with exit code $LASTEXITCODE." }
