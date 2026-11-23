# Compatibility entrypoint retained for central launcher ABI 1/2 manifests.
# The provider-neutral implementation lives under scripts/shared.
#
# MIRROR CONTRACT (keep in lock-step): scripts/shared/auto-merge.ps1 owns the
# param() block and the gate exit codes copied here. A parameter added there
# and not here fails at parameter binding, before any exit-code mapping runs;
# an exit code added there and not to the accepted set below is rewritten to 3.
# Parameters stay plain [string], as in the shared gate: a binding-time
# validation failure would exit 1, the code its exit contract retired.
[CmdletBinding()]
param(
  [string]$Branch = '',
  [string]$Base = '',
  [string]$Backend = '',
  [string]$ReasoningEffort = ''
)

$sharedScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\auto-merge.ps1'
if (-not (Test-Path -LiteralPath $sharedScript -PathType Leaf)) {
  Write-Host "[auto-merge] ERROR: no shared implementation file was found at '$sharedScript' (the path is absent, is not a file, or could not be probed)."
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
  $observedExit = if ($null -eq $sharedExit) { 'none' } else { "$sharedExit" }
  Write-Host "[auto-merge] ERROR: shared implementation returned no valid gate exit code (observed: $observedExit)."
  exit 3
}
exit $sharedExit
