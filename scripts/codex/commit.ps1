# Cross-review commit entry for Codex-as-implementer: review routes to Claude.
# scripts/claude/commit.ps1 is the one implementation for both implementers.
# Every failure to start it refuses: an unchecked call would return whatever
# exit code the shell last held, which can read as a successful commit.
$sharedScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'claude\commit.ps1'
if (-not (Test-Path -LiteralPath $sharedScript -PathType Leaf)) {
  Write-Error "scripts/codex/commit.ps1: ABORT -- the shared commit wrapper is missing at '$sharedScript'."
  exit 1
}
$global:LASTEXITCODE = $null
try {
  & $sharedScript -CrgImplementer codex @args
  $sharedExit = $global:LASTEXITCODE
} catch {
  Write-Error "scripts/codex/commit.ps1: ABORT -- the shared commit wrapper could not run ($($_.Exception.Message))."
  exit 1
}
if ($sharedExit -isnot [int]) {
  Write-Error 'scripts/codex/commit.ps1: ABORT -- the shared commit wrapper returned no exit code.'
  exit 1
}
exit $sharedExit
