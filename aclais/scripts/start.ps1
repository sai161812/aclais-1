[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Backend', 'Frontend')]
    [string]$Service
)

$ErrorActionPreference = 'Stop'
$componentRoot = Split-Path -Parent $PSScriptRoot

switch ($Service) {
    'Backend' {
        if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
            throw 'uv is required. Install the runbook prerequisites and run scripts/check.ps1.'
        }
        $backendDir = Join-Path $componentRoot 'backend'
        & uv --directory $backendDir run --locked python -m aclais
    }
    'Frontend' {
        if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
            throw 'npm is required. Install the runbook prerequisites and run scripts/check.ps1.'
        }
        $frontendDir = Join-Path $componentRoot 'frontend'
        $viteEntrypoint = Join-Path $frontendDir 'node_modules\vite\bin\vite.js'
        if (-not (Test-Path -LiteralPath $viteEntrypoint -PathType Leaf)) {
            throw 'Frontend dependencies are missing. Run scripts/check.ps1 before startup.'
        }
        & npm --prefix $frontendDir run dev
    }
}

if ($LASTEXITCODE -ne 0) {
    throw "$Service development server exited with code $LASTEXITCODE."
}
