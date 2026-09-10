# Compatibility entrypoint retained for central launcher ABI 1/2 manifests.
# The provider-neutral implementation lives under scripts/shared.
[CmdletBinding()]
param(
  [string]$Branch = '',
  [string]$Base = '',
  [string]$Backend = '',
  [string]$ReasoningEffort = ''
)

$sharedScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\auto-merge.ps1'
if (-not (Test-Path -LiteralPath $sharedScript -PathType Leaf)) {
  Write-Host "[auto-merge] ERROR: shared implementation is missing at '$sharedScript'."
  exit 3
}

$global:LASTEXITCODE = $null
try {
  & $sharedScript @PSBoundParameters
  $sharedExit = $global:LASTEXITCODE
} catch {
  Write-Host "[auto-merge] ERROR: shared implementation invocation failed: $($_.Exception.Message)"
  exit 3
}

if ($null -eq $sharedExit -or $sharedExit -notin @(0, 2, 3)) {
  Write-Host "[auto-merge] ERROR: shared implementation returned no valid gate exit code."
  exit 3
}
exit $sharedExit
