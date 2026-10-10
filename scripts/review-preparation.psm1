# Central-only preparation surface for the paired-review input contract. The
# functions it exports live in scripts/review-common.ps1, which the review
# wrappers dot-source too, so the central path and the wrappers assemble the
# same prompt from the same code. The explicit export list keeps every other
# shared function private to this module. No provider or Git I/O runs during
# import. docs/paired-review-input-v1.md owns the proposed new input ABI.

try { . (Join-Path $PSScriptRoot 'review-common.ps1') }
catch { throw "review preparation could not load the shared review functions: $($_.Exception.Message)" }

Export-ModuleMember -Function @(
  'Resolve-ConsistencyDocConfig',
  'Test-ConsistencyDocInNameStatus',
  'Test-PlanConsistencyEvidenceEnvelope',
  'New-PlanConsistencyEvidenceEnvelope',
  'Get-TouchedPlanLines',
  'Get-PlanConsistencyReport',
  'ConvertFrom-ProjectModeDeclaration',
  'Format-ProjectModeBlock',
  'Join-ReviewPromptAssembly'
)
