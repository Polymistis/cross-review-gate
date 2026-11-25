# Adversarial review wrapper for Codex CLI.
#
# ISOLATION MODEL (redesign to prevent reviewer worktree corruption):
#
# The reviewer is NEVER given the live git repo. Earlier this wrapper ran
# `codex exec --dangerously-bypass-approvals-and-sandbox` with cwd = the live
# worktree and a prompt telling Codex to fetch the diff via git. Codex (an
# autonomous agent carrying its own plugin-marketplace git scaffolding) spliced
# a foreign tree into `.git/worktrees/<wt>/index`, producing thousands of
# phantom missing blobs, failing `git fsck`, and self-blocking every commit.
#
# Now: the prepared review evidence -- the exact diff and the COMPLETE
# source tree at the reviewed revision -- is copied into a throwaway
# directory OUTSIDE any git repo and outside the ACL-restricted repo path.
# Codex is invoked there with NO bypass and sandbox/approval locked down
# via per-invocation `-s read-only -c approval_policy="never"` flags
# (NOT via global config:
# the user runs Codex outside the review process too) and NO
# git: it can read the full codebase to do integration-boundary review, but
# there is physically no `.git` to corrupt and no write capability. The
# scratch tree is deleted after the verdict is parsed.
#
# Exit codes (2026-07 severity contract: only BLOCKER aborts; QUALITY is a
# non-blocking finding):
#   0 = PASS. Sub-cases that all pass the gate:
#       (a) CLEAN - no findings, verdict line is `VERDICT: CLEAN`
#       (b) NOTE-only - one or more NOTE findings (informational), no
#           BLOCKER or QUALITY, verdict line is `VERDICT: NON-BLOCKING`.
#       (c) QUALITY-only - one or more QUALITY findings (the legacy NON-BLOCKER
#           prefix is severity-equivalent), no BLOCKER, verdict line is
#           `VERDICT: NON-BLOCKING`. QUALITY does NOT abort the gate; the
#           QUALITY and NOTE findings are shown to the submitting session,
#           grouped by what each cites, to fix as part of this change: the
#           paired session shows them from the verdict file
#           (paired-governance.psm1). Nothing records them as work for a
#           later session.
#       A consumer should treat a NOTE- or QUALITY-bearing verdict as a
#       pass WITH awareness that the verdict file still contains those entries
#       (do not relabel it CLEAN).
#   1 = RETIRED (was: QUALITY/NON-BLOCKING). The 2026-07 contract made QUALITY
#       non-blocking, so this wrapper no longer returns 1. Documented so a stray
#       exit 1 from an OLD cached wrapper is recognizable; the gates treat an
#       unexpected exit 1 as fail-closed. (A pre-rewrite verdict with no category
#       block is still malformed -> exit 3, regardless of prefix.)
#   2 = BLOCKED. One or more BLOCKER findings WITH a present `VERDICT:` line
#       (even a wrong/malformed-word one -- BLOCKER takes precedence over an
#       inconsistent line). BLOCKER findings with NO `VERDICT:` line are
#       malformed output and fail closed (exit 3), not exit 2.
#   3 = invocation failure (codex error, bundling error,
#       malformed verdict line -- INCLUDING a BLOCKER verdict with a
#       missing/duplicate `VERDICT:` line, etc.)
#   4 = TOKEN EXHAUSTION (operator fallback ruling 2026-08-22: when one backend
#       runs out of tokens, the fallback is the other). A fail-closed variant
#       of exit 3, returned ONLY when every errored pass's events NDJSON
#       carries a CLI-OWNED error record (top-level `type: "error"` /
#       `"turn.failed"`; Get-CodexCliErrorMessage) whose message matches the
#       token-exhaustion signature (Test-CodexTokenExhaustionText), no
#       produced body -- collected OR errored
#       (Resolve-CodexErroredPassEvidence) -- is malformed, AND no BLOCKER
#       verdict exists anywhere (a BLOCKER wins over exhaustion -> exit 2,
#       never 4 -- a fallback must never be able to pass a diff a reviewer
#       already blocked). The classification is durable: a `.exhaustion.json`
#       sidecar is written beside the verdict artifact, and a failed sidecar
#       write DOWNGRADES the exit to 3 (no fallback offer without evidence).
#       A parent with no fallback support treats 4 like any unexpected code
#       and fails closed, so the contract degrades safely.
#
# Fails CLOSED: any ambiguity (no verdict file, malformed verdict, bundling
# failure) is exit 3, never a silent pass.
#
# Flags the paired review session supplies besides the prepared input:
#   -ReviewPasses <1..10>  number of INDEPENDENT review passes (run CONCURRENTLY;
#                          gate blocks on the union).
#   -ReasoningEffort <minimal|low|medium|high|xhigh|max>  Codex reasoning-effort
#                          tier. The wrapper PINS every pass to it via
#                          `-c model_reasoning_effort="<tier>"` (so the pass runs
#                          at exactly the stamped REVIEW-EFFORT).
#   -OutDir <path>         the private attempt directory the paired session
#                          owns (docs/paired-review-input-v1.md); the shared
#                          input reader validates it.

[CmdletBinding(DefaultParameterSetName = 'PreparedPair')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'PreparedPair')]
  [ValidateNotNullOrEmpty()]
  [string]$PreparedPairPath,

  [Parameter(Mandatory = $true, ParameterSetName = 'PreparedPair')]
  [ValidatePattern('(?-i)\A[0-9a-f]{64}\z')]
  [string]$PreparedPairSha256,

  [Parameter(Mandatory = $true, ParameterSetName = 'PreparedPair')]
  [ValidatePattern('(?-i)\A[0-9a-f]{64}\z')]
  [string]$PreparedPublicTreeSha256,

  [Parameter(Mandatory = $true, ParameterSetName = 'PreparedPair')]
  [ValidatePattern('(?-i)\A[0-9a-f]{64}\z')]
  [string]$PreparedPrivateTreeSha256,

  [Parameter(ParameterSetName = 'PreparedPair')]
  [ValidatePattern('(?-i)\A(?:paired-v1|first-attachment-v1)\z')]
  [string]$PreparedOrigin = 'paired-v1',

  [Parameter(Mandatory = $true, ParameterSetName = 'PreparedPair')]
  [string]$OutDir,

  # Number of INDEPENDENT codex review passes to run and combine. A single
  # pass over a dense diff is non-exhaustive + non-deterministic (each run
  # surfaces a different subset of the real findings), which is why the gate
  # historically dribbled one nitpick per commit-round. Running N passes and
  # blocking on the UNION returns far more findings in a single gate run. The
  # gate fails closed if ANY pass errors or is malformed.
  [Parameter(Mandatory = $true, ParameterSetName = 'PreparedPair')]
  [ValidateRange(1, 10)]
  [int]$ReviewPasses,

  # Codex reasoning-effort tier for this review invocation, PINNED on every
  # pass via `-c model_reasoning_effort=...` and stamped as REVIEW-EFFORT.
  # An invalid value is rejected by ValidateSet (nonzero param-bind exit) or,
  # when ValidateSet's culture match let it through (U+00AD, say), by the
  # exact-spelling lookup after binding (exit 3); either fails the invocation
  # closed. The empty member stays in the set although no tier is empty: a
  # value of only U+00AD matches it by culture and so reaches the lookup and
  # its exit 3, which callers of the prepared-pair interface have seen since
  # the set was written.
  [Parameter(Mandatory = $true, ParameterSetName = 'PreparedPair')]
  [ValidateSet('', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max')]
  [string]$ReasoningEffort
)

$ErrorActionPreference = 'Stop'

# Functions shared with the other review hosts. Dot-sourced so they run in
# this script's own scope (the file's header gives the reason); every trusted
# review copy carries scripts/review-common.ps1 beside this wrapper. The load
# precedes the console code-page save and the replacement-suppression setup
# below, which use its functions, and runs no Git command itself.
try {
  . (Join-Path (Split-Path -Parent $PSScriptRoot) 'review-common.ps1')
} catch {
  Write-Host "[auto-review] ERROR: the shared review functions could not be loaded ($($_.Exception.Message)) - failing closed."
  exit 3
}

# Force UTF-8 for native command pipes. Default $OutputEncoding is ASCII on
# Windows PowerShell 5.1, which mangles multi-byte glyphs (em-dashes in the
# prompt template were corrupted to `???`).
# Only this process's cached encodings change, never the console window shared
# with the invoking shell; the finally at the end of the script puts back the
# values returned here so the script leaves the process as it found it.
$crgConsoleInputSwitched = $false
try {
  $crgSavedConsoleInputEncoding = Set-CrgProcessConsoleEncoding -ConsoleInput -Encoding ([System.Text.UTF8Encoding]::new($false))
  $crgConsoleInputSwitched = $true
  $crgSavedConsoleOutputEncoding = Set-CrgProcessConsoleEncoding -Encoding ([System.Text.UTF8Encoding]::new($false))
} catch {
  Write-Host "[auto-review] ERROR: the console encodings could not be set to UTF-8 ($($_.Exception.Message)) - failing closed."
  if ($crgConsoleInputSwitched) { try { $null = Set-CrgProcessConsoleEncoding -ConsoleInput -Encoding $crgSavedConsoleInputEncoding } catch { } }
  exit 3
}
try {
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# ValidateSet compares by culture and admits spellings such as one containing
# U+00AD; keep only an exact listed value so later ordinal comparisons hold.
$crgEffortCanonical = @(@('minimal', 'low', 'medium', 'high', 'xhigh', 'max') | Where-Object { [string]::Equals($_, $ReasoningEffort, [System.StringComparison]::OrdinalIgnoreCase) })
if ($crgEffortCanonical.Count -ne 1) {
  Write-Host "[auto-review] ERROR: -ReasoningEffort '$ReasoningEffort' is not one of minimal, low, medium, high, xhigh, max."
  exit 3
}
$ReasoningEffort = $crgEffortCanonical[0]
$pairedHostInput = $null
$pairedProviderSnapshot = $null

# Git reference-backend redirects, replacement refs, grafts, and shallow boundaries can make every
# successful HEAD/parent/tree read describe a caller-selected history. Inspect
# the raw process environment case-insensitively before the first Git probe,
# then disable ordinary refs/replace and default graft lookup for every trusted
# read below.
$crgHistoryOverrideNames = @('GIT_REPLACE_REF_BASE', 'GIT_GRAFT_FILE', 'GIT_SHALLOW_FILE', 'GIT_REFERENCE_BACKEND')
$crgAttributeOverrideNames = @('GIT_ATTR_SOURCE', 'GIT_ATTR_NOSYSTEM')
$crgHistoryOverrideSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($crgHistoryOverrideName in $crgHistoryOverrideNames) { [void]$crgHistoryOverrideSet.Add($crgHistoryOverrideName) }
$crgAttributeOverrideSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($crgAttributeOverrideName in $crgAttributeOverrideNames) { [void]$crgAttributeOverrideSet.Add($crgAttributeOverrideName) }
$crgHistoryOverridesFound = [System.Collections.Generic.List[string]]::new()
$crgAttributeOverridesFound = [System.Collections.Generic.List[string]]::new()
try {
  $crgRawProcessEnvironment = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
  foreach ($crgRawEnvironmentName in $crgRawProcessEnvironment.Keys) {
    $crgRawEnvironmentNameText = [string]$crgRawEnvironmentName
    if ($crgHistoryOverrideSet.Contains($crgRawEnvironmentNameText)) { $crgHistoryOverridesFound.Add($crgRawEnvironmentNameText) }
    if ($crgAttributeOverrideSet.Contains($crgRawEnvironmentNameText)) { $crgAttributeOverridesFound.Add($crgRawEnvironmentNameText) }
  }
} catch {
  Write-Host "[auto-review] ERROR: could not inspect the raw process environment before the first Git proof: $($_.Exception.Message)"
  exit 3
}
# Ordinal sort: Sort-Object -Unique compares by culture and case-insensitively.
# The names are distinct environment keys, so no dedupe is needed.
if ($crgHistoryOverridesFound.Count -gt 0) {
  $crgHistoryOverridesFound.Sort([System.StringComparer]::Ordinal)
  Write-Host "[auto-review] ERROR: refusing Git history-resolution override env var(s): $(@($crgHistoryOverridesFound) -join ', '). Unset every named variable and re-run."
  exit 3
}
if ($crgAttributeOverridesFound.Count -gt 0) {
  $crgAttributeOverridesFound.Sort([System.StringComparer]::Ordinal)
  Write-Host "[auto-review] ERROR: refusing Git attribute-resolution override env var(s): $(@($crgAttributeOverridesFound) -join ', '). Unset every named variable and re-run."
  exit 3
}
[Environment]::SetEnvironmentVariable('GIT_GRAFT_FILE', '\\.\NUL', [EnvironmentVariableTarget]::Process)
if (-not [string]::Equals([Environment]::GetEnvironmentVariable('GIT_GRAFT_FILE', [EnvironmentVariableTarget]::Process), '\\.\NUL', [System.StringComparison]::Ordinal)) {
  Write-Host '[auto-review] ERROR: could not establish the controlled GIT_GRAFT_FILE=\\.\NUL boundary before the first Git proof.'
  exit 3
}

# Reviewer liveness (heartbeat, stall threshold, duration stamp) is shared with
# the other review hosts. Every trusted review copy carries
# scripts/review-liveness.psm1 beside this wrapper, so the import is exact.
try {
  Import-Module -Name (Join-Path (Split-Path -Parent $PSScriptRoot) 'review-liveness.psm1') -DisableNameChecking -ErrorAction Stop
} catch {
  Write-Host "[auto-review] ERROR: the shared reviewer-liveness module could not be loaded ($($_.Exception.Message)) - failing closed."
  exit 3
}

# Combine the per-pass Get-VerdictExitCode results from an N-pass review into a
# single gate exit code via UNION semantics.
#
# Contract:
#   - Fail closed (exit 3) if any pass errored/produced no verdict ($PassErrored),
#     if fewer than $ExpectedPasses results were collected, or if ANY pass's own
#     verdict was malformed (its $Cls.ExitCode -eq 3). A pass we cannot trust
#     makes the union unreliable, so the whole gate fails closed.
#   - Otherwise the gate blocks on the UNION: exit 2 if ANY pass found a BLOCKER;
#     else exit 0 (every pass was CLEAN, NOTE-only, or QUALITY-only). Under the
#     2026-07 severity contract QUALITY is NON-BLOCKING, so it does not escalate
#     the union exit -- only a BLOCKER in any pass raises it to 2 (malformed/errored
#     passes fail closed at 3, above). QualityMax and NoteMax are still returned
#     so the caller shows the union's non-blocking findings.
function Get-CombinedReviewExit {
  param(
    [object[]]$PassResults,
    [bool]$PassErrored,
    [int]$ExpectedPasses
  )

  $res = [pscustomobject]@{
    ExitCode   = 3
    Diagnostic = ''
    BlockerMax = 0
    QualityMax = 0
    NoteMax    = 0
  }

  if ($PassErrored) {
    $res.Diagnostic = 'one or more review passes errored or produced no verdict'
    return $res
  }

  $results = @($PassResults)
  if ($results.Count -lt $ExpectedPasses) {
    $res.Diagnostic = "expected $ExpectedPasses review passes, only $($results.Count) completed"
    return $res
  }

  # Only $anyMalformed and $anyBlocker drive the union exit; QUALITY and NOTE are
  # NON-blocking (2026-07 severity contract), so the loop tracks their MAX counts
  # (QualityMax/NoteMax, for the caller's non-blocking findings notice) but the union never gates
  # on them.
  $anyMalformed = $false
  $anyBlocker = $false
  foreach ($pr in $results) {
    $c = $pr.Cls
    if ($null -eq $c) { $anyMalformed = $true; continue }
    if ($c.ExitCode -eq 3) { $anyMalformed = $true }
    if ($c.BlockerCount -gt 0) { $anyBlocker = $true }
    if ($c.BlockerCount -gt $res.BlockerMax) { $res.BlockerMax = $c.BlockerCount }
    $qWithLegacy = $c.QualityCount + $c.LegacyNbCount  # surface legacy NON-BLOCKER in the QUALITY count
    if ($qWithLegacy -gt $res.QualityMax) { $res.QualityMax = $qWithLegacy }
    if ($c.NoteCount -gt $res.NoteMax) { $res.NoteMax = $c.NoteCount }
  }

  if ($anyMalformed) {
    $res.Diagnostic = 'at least one pass produced a malformed verdict'
    $res.ExitCode = 3
    return $res
  }
  if ($anyBlocker) { $res.ExitCode = 2; return $res }
  # QUALITY no longer escalates the union exit (2026-07 severity contract): a
  # union whose worst finding is QUALITY (or legacy NON-BLOCKER) PASSES. QualityMax
  # was tracked above so the caller shows those findings as non-blocking.
  $res.ExitCode = 0
  return $res
}

# Extract CLI-OWNED error messages from the codex `--json` events NDJSON --
# the ONLY channel the exhaustion recognizer reads (stderr carries wrapped
# model text and is never consulted for this). Recognized record shapes:
# `{"type":"error","message":<string>}` and
# `{"type":"turn.failed","error":{"message":<string>}}`. Unknown well-formed
# typed objects are ignored (the CLI adds record types freely); an
# unparseable line, a non-object line, a typeless object, or a recognized
# error record with a malformed shape sets MalformedStream -- a malformed
# stream is never fallback-eligible. Forgery boundary: all model/tool text
# lives inside `item.*` records' JSON string fields, and a raw newline cannot
# exist inside a JSON string, so reviewed content can never mint a top-level
# record. Pure.
function Get-CodexCliErrorMessage {
  param([string]$EventsText)
  $msgs = @()
  $malformed = $false
  if ([string]::IsNullOrWhiteSpace($EventsText)) { return @{ Messages = $msgs; MalformedStream = $false } }
  foreach ($ln in ($EventsText -split "(?:\r\n|\n|\r)")) {
    if ([string]::IsNullOrWhiteSpace($ln)) { continue }
    $obj = $null
    try { $obj = ConvertFrom-Json -InputObject $ln -ErrorAction Stop } catch { $malformed = $true; continue }
    if ($null -eq $obj -or -not ($obj -is [System.Management.Automation.PSCustomObject])) { $malformed = $true; continue }
    # Ordinal: -ceq compares by culture and ignores characters such as U+00AD.
    $typeProps = @($obj.PSObject.Properties | Where-Object { [string]::Equals($_.Name, 'type', [System.StringComparison]::Ordinal) })
    if ($typeProps.Count -ne 1 -or -not ($typeProps[0].Value -is [string])) { $malformed = $true; continue }
    $t = [string]$typeProps[0].Value
    if ([string]::Equals($t, 'error', [System.StringComparison]::Ordinal)) {
      $mProps = @($obj.PSObject.Properties | Where-Object { [string]::Equals($_.Name, 'message', [System.StringComparison]::Ordinal) })
      if ($mProps.Count -eq 1 -and $mProps[0].Value -is [string]) { $msgs += [string]$mProps[0].Value } else { $malformed = $true }
    } elseif ([string]::Equals($t, 'turn.failed', [System.StringComparison]::Ordinal)) {
      $emOk = $false
      $eProps = @($obj.PSObject.Properties | Where-Object { [string]::Equals($_.Name, 'error', [System.StringComparison]::Ordinal) })
      if ($eProps.Count -eq 1 -and $null -ne $eProps[0].Value -and ($eProps[0].Value -is [System.Management.Automation.PSCustomObject])) {
        $emProps = @($eProps[0].Value.PSObject.Properties | Where-Object { [string]::Equals($_.Name, 'message', [System.StringComparison]::Ordinal) })
        if ($emProps.Count -eq 1 -and $emProps[0].Value -is [string]) { $msgs += [string]$emProps[0].Value; $emOk = $true }
      }
      if (-not $emOk) { $malformed = $true }
    }
  }
  return @{ Messages = $msgs; MalformedStream = $malformed }
}

# Token-exhaustion signature recognizer over a CLI-owned error message.
# Case-insensitive substring/regex semantics. TRANSIENTS ARE DELIBERATELY
# EXCLUDED -- `rate limit`, HTTP 429, overloaded, timeout, and the CLI's
# capacity message all retry-resolve and must fail closed (exit 3), never
# trigger a fallback. Pure.
function Test-CodexTokenExhaustionText {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
  $t = $Text.ToLowerInvariant()
  $limitSignatures = @(
    'hit your usage limit',
    'usage limit (reached|exceeded)',
    'usage_limit_reached',
    'insufficient_quota',
    'out of (workspace )?credits',
    '(workspace |usage )?credits? (balance )?(is |are |has been |have been )?(depleted|exhausted|used up)',
    'credit (limit|balance) (reached|exceeded|depleted|exhausted)',
    'spend (cap|limit) (reached|exceeded|hit)'
  )
  foreach ($sig in $limitSignatures) {
    if ($t -match $sig) { return $true }
  }
  return $false
}

# Classify ONE errored pass into the exit-4 guard inputs. Rule: ANY non-empty
# body on an errored pass vetoes the fallback -- a well-formed BLOCKER body
# sets BodyBlocker (BLOCKER wins over exhaustion), every other non-empty body
# sets BodyMalformed (an ambiguous fragment is never fallback-eligible). Only
# a BODYLESS errored pass whose events carry a clean exhaustion signature
# leaves both vetoes clear. Pure.
function Resolve-CodexErroredPassEvidence {
  param([string]$BodyText, [string]$EventsText)
  $bodyBlocker = $false
  $bodyMalformed = $false
  if (-not [string]::IsNullOrWhiteSpace($BodyText)) {
    $bodyCls = Get-VerdictExitCode -Verdict $BodyText
    if ($bodyCls.ExitCode -eq 2) { $bodyBlocker = $true } else { $bodyMalformed = $true }
  }
  $cem = Get-CodexCliErrorMessage -EventsText $EventsText
  $exhausted = $false
  foreach ($cliMsg in @($cem.Messages)) {
    if (Test-CodexTokenExhaustionText -Text $cliMsg) { $exhausted = $true; break }
  }
  return @{
    BodyBlocker     = $bodyBlocker
    BodyMalformed   = $bodyMalformed
    EventsMalformed = [bool]$cem.MalformedStream
    Exhausted       = $exhausted
  }
}

# Derive the authoritative gate exit from the combined union plus the
# errored-pass evidence. The whole derivation is scoped to EXHAUSTION runs
# (every errored pass positively identified, nothing malformed): only there
# does the fail-closed 3 upgrade to the fallback-eligible 4, and only there
# does a BLOCKER anywhere promote to 2 instead (a fallback must never
# re-review a blocked diff). A NON-exhaustion partial failure keeps the
# pre-existing fail-closed 3 unchanged, blocker or not -- the scoping
# preserves the pre-fallback exit contract outside the exhaustion case. The
# `ErroredPassCount -gt 0` guard keeps a vacuously-true all-exhausted flag
# (zero errored passes) from minting a 4. Pure.
function Resolve-CodexGateExit {
  param(
    [int]$CombinedExit,
    [int]$ErroredPassCount,
    [bool]$AllErroredExhausted,
    [bool]$AnyMalformedPass,
    [bool]$AnyBlockerPass
  )
  if ($CombinedExit -eq 3 -and -not $AnyMalformedPass -and
      $ErroredPassCount -gt 0 -and $AllErroredExhausted) {
    if ($AnyBlockerPass) { return 2 }
    return 4
  }
  return $CombinedExit
}

try {
  # Import after the embedded function declarations so the paired compiler
  # retains its module-qualified exports. No Git probe runs before this
  # point; the ambient override refusal above remains required.
  $pairedScriptsRoot = Split-Path -Parent $PSScriptRoot
  foreach ($pairedModule in @('private-governance', 'paired-governance', 'paired-tree', 'review-preparation',
      'project-preparation', 'paired-review-input', 'paired-diff', 'paired-preparation')) {
    Import-Module -Name (Join-Path $pairedScriptsRoot ($pairedModule + '.psm1')) -ErrorAction Stop
  }
  # The paired parent supplies one canonical raw Path; the shared input
  # boundary asserts that spelling without mutating the inherited selection.
  # PS7 preserves empty variables when a managed null call binds as an empty
  # string, so startup must not repair the inherited Path through a managed
  # setter.
  $pairedHostInput = Open-CrgPairedHostInput -HostScriptPath $PSCommandPath `
    -PreparedPairPath $PreparedPairPath -PreparedPairSha256 $PreparedPairSha256 `
    -PreparedPublicTreeSha256 $PreparedPublicTreeSha256 -PreparedPrivateTreeSha256 $PreparedPrivateTreeSha256 `
    -OutDir $OutDir -Backend 'codex' -PreparedOrigin $PreparedOrigin
  $scopeTag = $pairedHostInput.ScopeTag
  $outDirAbs = $pairedHostInput.OutDir
} catch {
  if ($null -ne $pairedHostInput) { $null = Complete-CrgPairedHostInput -HostInput $pairedHostInput -ProviderSnapshot $null }
  Write-Host "[auto-review] ERROR: paired input acquisition failed: $($_.Exception.Message)"
  exit 3
}

$srcName    = 'REVIEW_SRC'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$verdictFile = Join-Path $outDirAbs "review-$timestamp-$scopeTag.md"
$eventsFile  = Join-Path $outDirAbs "review-$timestamp-$scopeTag.jsonl"
$stderrFile  = Join-Path $outDirAbs "review-$timestamp-$scopeTag.stderr.log"

# Scratch lives under TEMP: a normal-ACL path with NO `CodexSandboxUsers`
# Deny ACE (that ACE on the repo path is what originally forced the sandbox
# bypass). Codex reads here under the read-only sandbox passed via the
# `-s read-only` flag at the codex invocation below (NOT via global
# config -- see the note there); nothing it can do here can reach a git
# repo.
#
# CRITICAL trust boundary (BLOCKER caught by the gate reviewing its own
# change): Codex auto-loads AGENTS.md (and similar) from its
# working root + ancestors as its OWN instructions. If the working root were
# the reviewed tree, a candidate commit could ship an AGENTS.md that rewrites
# the review contract and forces a CLEAN verdict. So Codex runs from a
# TRUSTED root the wrapper builds; the untrusted reviewed source goes in a
# non-instruction SUBDIR (REVIEW_SRC/, a descendant - never auto-loaded as
# instructions), and a trusted root AGENTS.md restates the contract and
# marks REVIEW_SRC/ as untrusted data.
$work = Join-Path $env:TEMP ("crg-review-" + [guid]::NewGuid().ToString('N').Substring(0,12))

try {
  New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null
  try {
    $pairedProviderSnapshot = New-CrgPairedProviderSnapshot -InputBundle $pairedHostInput.InputBundle `
      -RuntimeTemplateBytes $pairedHostInput.RuntimeTemplateBytes -TempParent $work -Backend 'codex' -PreparedOrigin $pairedHostInput.Origin
  } catch {
    $pairedHostInput.ProviderSnapshotFailure = $_.Exception
    throw
  }
  $reviewRoot = $pairedProviderSnapshot.Root
  $fullPrompt = $pairedHostInput.FullPrompt
  $checkPath = $reviewRoot
  while ($checkPath -and $checkPath.Length -gt 0) {
    $parent = Split-Path -Parent $checkPath
    if ([string]::Equals($parent, $checkPath, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::IsNullOrEmpty($parent)) { break }
    foreach ($candidate in @('AGENTS.md', 'AGENTS.override.md', 'codex.md', 'CODEX.md')) {
      if (Test-Path -LiteralPath (Join-Path $parent $candidate)) {
        throw "paired review root ancestor '$parent' contains auto-discoverable instruction file '$candidate'"
      }
    }
    $checkPath = $parent
  }
  Assert-CrgPairedReadContext -Context $pairedHostInput.ReadContext -InputBundle $pairedHostInput.InputBundle
  Assert-CrgPairedInputSnapshot -Snapshot $pairedProviderSnapshot

  Write-Host "[auto-review] scope=PreparedPair unit=$($pairedHostInput.InputBundle.Metadata.ReviewUnit.ReviewUnitSha256)"
  Write-Host "[auto-review] review root -> $reviewRoot (trusted; source in $srcName/, git-less, read-only)"
  Write-Host "[auto-review] verdict  -> $verdictFile"

  # codex exec with sandbox + approval EXPLICITLY locked down via the
  # per-invocation `-s read-only` and `-c approval_policy="never"`
  # flags below. This wrapper intentionally does NOT rely on
  # `~/.codex/config.toml` defaults: the
  # user uses Codex outside the review process (workspace-write, normal
  # approval) and globally pinning the review's read-only/never defaults
  # in the user config would neuter every general Codex session on this
  # machine. The flags carry the lockdown into THIS invocation only.
  # NO bypass flag. -C points
  # the working root at the TRUSTED scratch root (NOT the reviewed tree, so a
  # candidate AGENTS.md cannot become reviewer instructions); the prompt
  # arrives on stdin. stdout (JSONL events) is redirected by THIS wrapper
  # (regular user) to a scratch file - not a Codex action - so neither the
  # sandbox nor the repo ACL is involved.
  # --skip-git-repo-check: the root is DELIBERATELY git-less (that is the
  # whole isolation guarantee). Codex otherwise refuses to run outside a git
  # repo / trusted dir. This flag only acknowledges "not a repo, proceed" - it
  # does NOT relax the sandbox; the per-invocation `-s read-only` lockdown
  # below still applies.
  # Base codex args. Per-pass `-o <verdict>` and the `-` stdin marker are
  # appended inside the multi-pass review loop below.
  $codexArgsBase = @(
    'exec',
    '--json',
    '--skip-git-repo-check',
    # Lock down sandbox + approval per-invocation. Do NOT delegate to the
    # user's `~/.codex/config.toml`: that file is shared with the user's
    # general (non-review) Codex sessions, and setting a global default of
    # `read-only` + `never` there would neuter every interactive Codex run
    # on the machine. The review's lockdown belongs to the review, not the
    # user's global Codex defaults.
    # `-s` is a documented `codex exec` flag (`--sandbox <SANDBOX_MODE>`).
    # `approval_policy` has NO dedicated flag in the CLI; the generic
    # `-c <key=value>` config override is the documented way to set it
    # per-invocation -- the value is parsed as TOML, so the string must
    # be quoted as `"never"`.
    '-s', 'read-only',
    '-c', 'approval_policy="never"',
    '-C', $reviewRoot
  )

  # Every child is PINNED to the canonical -ReasoningEffort, and the same value
  # is the REVIEW-EFFORT stamp, so the stamp matches the tier the passes ran
  # at; no Codex configuration file is read.
  $codexArgsBase += @('-c', ('model_reasoning_effort="' + $ReasoningEffort + '"'))
  Write-Host "[auto-review] reasoning-effort pinned for all passes: model_reasoning_effort=$ReasoningEffort (stamped as REVIEW-EFFORT)"

  # ROOT CAUSE: Codex's plugin-marketplace subsystem runs its OWN `git`
  # operations (independent of -C, the sandbox, and the review prompt) that
  # INHERIT GIT_INDEX_FILE / GIT_DIR (etc.) from this process. When this
  # wrapper ran under `git commit`, which exports those vars to its hooks,
  # Codex plugin objects (`.agents/plugins/marketplace.json`, blob
  # 0cfe0c7c...) were written into the worktree's index, poisoning the commit
  # tree ("Error building trees") even though the review itself was fully
  # isolated. Scrub the git environment for the codex child so its plugin git
  # inherits no redirection to the caller's repository. Every git read the
  # review itself needs ran ABOVE this point with the proper environment. The
  # environment is restored after the reviewer exits.
  $gitEnvNames = @(
    'GIT_INDEX_FILE', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_NAMESPACE', 'GIT_REFERENCE_BACKEND',
    'GIT_PREFIX', 'GIT_CEILING_DIRECTORIES', 'GIT_CONFIG',
    'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT'
  )
  $savedGitEnv = @{}
  foreach ($n in $gitEnvNames) {
    $savedGitEnv[$n] = [Environment]::GetEnvironmentVariable($n)
    if ($null -ne $savedGitEnv[$n]) {
      # -ErrorAction Stop + post-removal verification: SilentlyContinue
      # plus no verify would let a failed scrub silently fall through,
      # leaving the codex child with inherited live-repo GIT_* vars and
      # the ability to corrupt the live index via Codex's internal
      # plugin git operations. Fail closed (exit 3) on any scrub
      # failure.
      try {
        Remove-Item -LiteralPath "Env:$n" -ErrorAction Stop
      } catch {
        Write-Host "[auto-review] ERROR: failed to scrub git env var '$n' ($($_.Exception.Message)); refusing to invoke codex with a potentially live-repo-pointing git env still active."
        exit 3
      }
      if ($null -ne [Environment]::GetEnvironmentVariable($n)) {
        Write-Host "[auto-review] ERROR: git env var '$n' persisted after Remove-Item; refusing to invoke codex with a potentially live-repo-pointing git env still active."
        exit 3
      }
    }
  }

  $prevEAP = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'

  # Heartbeat: each pass's codex CLI (now run in a concurrent child runner)
  # redirects ALL output to per-pass files (events-$pass.jsonl +
  # codex-$pass.stderr.log), so without a beat this wrapper's own output (the
  # paired session's attempt transcript) shows no progress during the
  # (multi-minute) concurrent review while the parent blocks on WaitForExit,
  # and a stalled review reads the same as a working one. The
  # heartbeat thread runs in the PARENT and keeps emitting while the children run.
  # The beats watch the per-pass events NDJSON in the run scratch dir -- the
  # codex CLI streams an event per action into them, so a working pass grows
  # its file and a stalled one goes quiet, which the beat escalates on after
  # the resolved threshold (docs/reviewer-liveness-design.md).
  $stallResolved = Resolve-StallWarnMs -Raw $env:CROSS_REVIEW_STALL_WARN_SECS
  if (-not $stallResolved.Ok) {
    Write-Host "[auto-review] ERROR: CROSS_REVIEW_STALL_WARN_SECS='$($env:CROSS_REVIEW_STALL_WARN_SECS)' is not a valid stall-warning threshold (integer seconds, 30..86400) - an invocation/config error, not a review finding. Aborting."
    exit 3
  }
  # The liveness log (timestamped samples + escalation transitions) is the
  # post-run audit's artifact; preserved under the verdict-shape name after
  # the passes join. Announced so a supervising agent can follow it live.
  $livenessRaw = Join-Path $work 'liveness.jsonl'
  Write-Host "[auto-review] liveness log -> $livenessRaw (per-pass evidence samples; preserved with forensics)"
  # The helper is created here (the finally's Stop needs the object on
  # every exit path), but the BEAT starts only after the pass children
  # launch below: escalation eligibility is process-liveness per pass, so
  # the pid map does not exist until the launches return.
  $codexHeartbeatHelper = Get-AdversarialReviewHeartbeat

  $passResults = @()
  $passErrored = $false
  # Exit-4 evidence accumulators. $allErroredExhausted starts $true and is
  # ANDed down per errored pass; the zero-errored vacuous case is guarded in
  # Resolve-CodexGateExit (ErroredPassCount -gt 0).
  $erroredPassCount = 0
  $allErroredExhausted = $true
  $erroredBodyMalformed = $false
  $erroredBodyBlocker = $false
  try {
    # Run the N review passes CONCURRENTLY. They are independent (same prompt,
    # separate -o files); the gate blocks on the deterministic UNION of their
    # findings (Get-CombinedReviewExit). Concurrency is a measured win:
    # A measured dogfood (Commit scope, gpt-5.5 xhigh) -- concurrent passes
    # delivered roughly Nx the aggregate throughput of a solo pass with no
    # rate-limit/shaping events in any stderr log. This SUPERSEDES an earlier
    # "concurrent passes each run at ~1/N speed" claim, which is
    # FALSIFIED -- no artifact of that dogfood survives in-repo and the
    # later measurement directly contradicts it.
    # CAVEAT: under sustained account-wide token saturation the backend COULD
    # still shape aggregate throughput; if that ever happens, a throttled pass
    # presents as a slow/failed child -> the per-pass error path below trips
    # $passErrored and the gate fails closed (exit 3) loudly. Concurrency never
    # weakens the gate; worst case it costs wall time or a fail-closed retry.
    #
    # Start-Process child runners (NOT Start-Job): Start-Job loses the
    # wrapper's UTF-8 native-pipe encoding pin AND its native array-arg
    # handling (both load-bearing -- the prompt + verdict carry multi-byte
    # glyphs, and the codex argv is an array). Each pass runs in a generated
    # `.ps1` runner that re-pins the exact UTF-8 console/output encodings,
    # reads the SHARED prompt file (UTF-8 no-BOM, written once below), and
    # pipes it to `& codex @args` with a per-pass `-o verdict-N.md`. The
    # runner writes $LASTEXITCODE to exit-N.txt; a missing/unparsable exit
    # file OR a missing/empty verdict means that pass errored -> fail closed.
    # All N children share the ONE read-only $reviewRoot (codex is sandboxed
    # `-s read-only`; verified safe -- the dogfood ran multiple concurrent
    # wrappers against identical content with no corruption).

    # Write the full prompt ONCE as UTF-8 no-BOM; every runner reads it.
    $promptShared = Join-Path $work 'prompt.txt'
    [System.IO.File]::WriteAllText($promptShared, $fullPrompt, $utf8NoBom)

    # Serialize the SHARED base codex args (one per line, UTF-8 no-BOM) so each
    # runner reconstructs the exact argv array the parent would have used. The
    # per-pass `-o <verdict>` and the `-` stdin marker are appended by the
    # runner (they differ per pass). Line-delimited is safe here: every base
    # arg is a CLI flag, a fixed token, the %TEMP% $reviewRoot path, or the
    # ValidateSet-constrained effort override -- none can contain a newline.
    $codexArgsFile = Join-Path $work 'codex-args.txt'
    [System.IO.File]::WriteAllLines($codexArgsFile, [string[]]$codexArgsBase, $utf8NoBom)

    # Generate the per-pass runner script. It is identical for every pass; the
    # pass index is the sole argument. ASCII-only source (the whole wrapper is
    # BOM-less UTF-8 read as ANSI by PS 5.1, so non-ASCII here would mojibake).
    $runnerPath = Join-Path $work 'pass-runner.ps1'
    $runnerBody = @'
param([Parameter(Mandatory=$true)][int]$PassIndex)
$ErrorActionPreference = 'Continue'
# Re-pin UTF-8 exactly like the parent wrapper so the native pipe to codex and
# the -o verdict output preserve multi-byte glyphs (em-dashes etc.). A
# Start-Job child would lose this; a fresh powershell.exe child must redo it,
# through the parent's process-local helper, inserted below when this file is
# written, since a runner sharing the parent's console would otherwise leave
# that console's code pages changed. A switch that fails ends the runner
# before its exit file is written, which the parent fails closed.
#CRG-PROCESS-CONSOLE-ENCODING-HELPER#
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
$null = Set-CrgProcessConsoleEncoding -ConsoleInput -Encoding $utf8NoBom
$null = Set-CrgProcessConsoleEncoding -Encoding $utf8NoBom
$work = $PSScriptRoot
$promptShared  = Join-Path $work 'prompt.txt'
$codexArgsFile = Join-Path $work 'codex-args.txt'
$verdictPath = Join-Path $work ("verdict-$PassIndex.md")
$eventsPath  = Join-Path $work ("events-$PassIndex.jsonl")
$stderrPath  = Join-Path $work ("codex-$PassIndex.stderr.log")
$exitPath    = Join-Path $work ("exit-$PassIndex.txt")
# Reconstruct the codex argv: shared base + this pass's -o verdict + stdin
# marker. ReadAllLines drops the trailing newline; no empty-arg risk because
# WriteAllLines emitted exactly one line per non-empty base arg.
$baseArgs = [System.IO.File]::ReadAllLines($codexArgsFile, $utf8NoBom)
$codexArgs = @($baseArgs) + @('-o', $verdictPath, '-')
$prompt = [System.IO.File]::ReadAllText($promptShared, [System.Text.Encoding]::UTF8)
# Default the exit file to a non-zero sentinel BEFORE invoking codex, so a
# crash that kills this child before it can write the real code still leaves a
# fail-closed marker for the parent (missing/non-zero -> pass errored).
[System.IO.File]::WriteAllText($exitPath, '999', $utf8NoBom)
$prompt | & codex @codexArgs > $eventsPath 2> $stderrPath
$realExit = $LASTEXITCODE
[System.IO.File]::WriteAllText($exitPath, ([string]$realExit), $utf8NoBom)
exit $realExit
'@
    $runnerBody = $runnerBody.Replace('#CRG-PROCESS-CONSOLE-ENCODING-HELPER#', ("function Set-CrgProcessConsoleEncoding {" + ${function:Set-CrgProcessConsoleEncoding}.ToString() + "}"))
    [System.IO.File]::WriteAllText($runnerPath, $runnerBody, $utf8NoBom)

    # Launch all N children concurrently AFTER the git-env scrub above, so each
    # inherits the scrubbed environment (their codex plugin git cannot reach
    # the repo). -PassThru gives the Process objects to WaitForExit on.
    # REVIEW-DURATION-SECS anchors HERE, at reviewer launch (the design's
    # launch-to-header interval), and monotonically, so wrapper setup time
    # and clock steps never contaminate the stamp.
    $reviewStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $procs = @{}
    $pairedProcessExits = @{}
    for ($pass = 1; $pass -le $ReviewPasses; $pass++) {
      Write-Host "[auto-review] launching review pass $pass/$ReviewPasses (concurrent; gate blocks on the union) ..."
      Set-CrgNoReplaceObjects
      $procs[$pass] = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList (Convert-ToProcArgString -ArgList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runnerPath, "$pass")) `
        -WindowStyle Hidden -PassThru
      if ($null -eq $procs[$pass]) { throw 'paired provider runner launch returned no process' }
      $null = $procs[$pass].Handle
    }

    # Start the evidence beat with each pass file mapped to its RUNNER's
    # process id: quiet + live owner is the stall shape; quiet + dead owner
    # is completion or a crash the exit handling below reports on its own.
    # A pass whose Start-Process failed has no pid and no mapping; it
    # also never writes an events file for the beat to watch, and the
    # missing exit/verdict files fail it closed regardless.
    $pidSpecParts = @()
    foreach ($pass in ($procs.Keys | Sort-Object)) {
      if ($null -ne $procs[$pass]) { $pidSpecParts += "events-$pass.jsonl=$($procs[$pass].Id)" }
    }
    $codexHeartbeatHelper.Start("codex-$scopeTag-$PID", 30000, $work, 'events-*.jsonl', $stallResolved.Ms, $livenessRaw, ([string]::Join(';', $pidSpecParts)))

    # Wait for every child. The heartbeat thread keeps emitting to stderr while
    # we block here. WaitForExit on each in turn is sufficient -- the longest
    # pass dominates and the others have already finished by the time we reach
    # them. A $null process handle (Start-Process failure) is treated as an
    # errored pass below via the missing exit/verdict files.
    foreach ($pass in ($procs.Keys | Sort-Object)) {
      $p = $procs[$pass]
      if ($null -ne $p) {
        $p.WaitForExit()
        if (-not $p.HasExited) { throw 'paired provider runner has not exited' }
        $pairedProcessExits[$pass] = $p.ExitCode
      } else {
        Write-Host "[auto-review] WARN: pass $pass process handle is null (Start-Process failed)"
      }
    }

    # Collect every pass's result. Preserve the EXACT semantics of the old
    # serial path: forensics copied with the -passN suffix,
    # missing/non-zero exit OR missing/empty verdict => that
    # pass errored ($passErrored), per-pass console verdict line. Unlike the
    # serial loop (which `break`ed on the first failure), concurrency collects
    # ALL passes -- a failure in one still records the others, and $passErrored
    # routes the union through the fail-closed path regardless.
    for ($pass = 1; $pass -le $ReviewPasses; $pass++) {
      $passVerdictRaw = Join-Path $work ("verdict-$pass.md")
      $passEventsRaw  = Join-Path $work ("events-$pass.jsonl")
      $passStderrRaw  = Join-Path $work ("codex-$pass.stderr.log")
      $passExitRaw    = Join-Path $work ("exit-$pass.txt")

      # Preserve per-pass forensics into the output dir (suffix -passN); a
      # failed copy must not be silent (the comment promises preservation).
      # -ErrorAction Stop + a SIZE check: a Test-Path-only guard would report
      # success when a stale same-name file already exists or a partial/
      # truncated copy lands, so verify the destination length equals the source
      # before treating preservation as complete (forensics is non-fatal, so a
      # mismatch WARNs rather than aborting -- but it must never falsely claim a
      # complete trail).
      if (Test-Path $passEventsRaw) {
        $dst = ($eventsFile -replace '\.jsonl$', "-pass$pass.jsonl")
        try {
          Copy-Item -Path $passEventsRaw -Destination $dst -Force -ErrorAction Stop
          $srcLenE = (Get-Item -LiteralPath $passEventsRaw).Length
          if (-not (Test-Path -LiteralPath $dst) -or (Get-Item -LiteralPath $dst).Length -ne $srcLenE) {
            Write-Host "[auto-review] WARN: pass $pass events preservation to $dst is incomplete (size mismatch or missing)"
          }
        } catch {
          Write-Host "[auto-review] WARN: failed to preserve pass $pass events to ${dst}: $($_.Exception.Message)"
        }
      }
      if (Test-Path $passStderrRaw) {
        $dst = ($stderrFile -replace '\.stderr\.log$', "-pass$pass.stderr.log")
        try {
          Copy-Item -Path $passStderrRaw -Destination $dst -Force -ErrorAction Stop
          $srcLenS = (Get-Item -LiteralPath $passStderrRaw).Length
          if (-not (Test-Path -LiteralPath $dst) -or (Get-Item -LiteralPath $dst).Length -ne $srcLenS) {
            Write-Host "[auto-review] WARN: pass $pass stderr preservation to $dst is incomplete (size mismatch or missing)"
          }
        } catch {
          Write-Host "[auto-review] WARN: failed to preserve pass $pass stderr to ${dst}: $($_.Exception.Message)"
        }
      }

      # Resolve the child exit code from exit-N.txt. Missing or unparsable =>
      # that pass errored (the runner pre-seeds '999' before invoking codex and
      # overwrites with the real code on completion, so a missing file means the
      # child died before even starting -- both fail closed).
      $passExit = $null
      if (Test-Path $passExitRaw) {
        $exitRawText = ([System.IO.File]::ReadAllText($passExitRaw, [System.Text.Encoding]::UTF8)).Trim()
        $parsedExit = 0
        if ([int]::TryParse($exitRawText, [ref]$parsedExit)) { $passExit = $parsedExit }
      }
      if (-not $pairedProcessExits.ContainsKey($pass) -or
          $null -eq $passExit -or $pairedProcessExits[$pass] -ne $passExit) {
        $passExit = $null
        $erroredBodyMalformed = $true
        Write-Host "[auto-review] ERROR: paired pass $pass exit-file evidence differs from the observed runner exit."
      }

      $passVerdictText = ''
      if (Test-Path $passVerdictRaw) {
        $passVerdictText = [System.IO.File]::ReadAllText($passVerdictRaw, [System.Text.Encoding]::UTF8)
      }

      if ($null -eq $passExit -or $passExit -ne 0 -or [string]::IsNullOrWhiteSpace($passVerdictText)) {
        $passErrored = $true
        $erroredPassCount++
        $exitDisp = if ($null -eq $passExit) { 'missing/unparsable' } else { "$passExit" }
        Write-Host "[auto-review] pass $pass FAILED: codex exit $exitDisp; verdict present = $([bool](-not [string]::IsNullOrWhiteSpace($passVerdictText)))"
        if (Test-Path $passEventsRaw) { Write-Host "[auto-review] tail of pass $pass events:"; Get-Content $passEventsRaw -Tail 15 | ForEach-Object { Write-Host "  $_" } }
        if (Test-Path $passStderrRaw) { Write-Host "[auto-review] tail of pass $pass stderr:"; Get-Content $passStderrRaw -Tail 15 | ForEach-Object { Write-Host "  $_" } }
        # Exit-4 evidence for THIS errored pass: classify the body (any
        # non-empty body vetoes the fallback -- BLOCKER wins, anything else is
        # ambiguity) and scan the CLI-owned events records for the exhaustion
        # signature. A malformed events stream is never fallback-eligible.
        $passEventsText = ''
        if (Test-Path $passEventsRaw) {
          $passEventsText = [System.IO.File]::ReadAllText($passEventsRaw, [System.Text.Encoding]::UTF8)
        }
        $evidence = Resolve-CodexErroredPassEvidence -BodyText $passVerdictText -EventsText $passEventsText
        if ($evidence.BodyBlocker) { $erroredBodyBlocker = $true }
        if ($evidence.BodyMalformed) { $erroredBodyMalformed = $true }
        if ($evidence.EventsMalformed) {
          $erroredBodyMalformed = $true
          Write-Host "[auto-review] pass $pass events stream carries malformed CLI records - never fallback-eligible (fail closed)"
        }
        if (-not $evidence.Exhausted) { $allErroredExhausted = $false }
        # Preserve a non-empty errored-pass body VERBATIM beside the verdict
        # (no generated header -- the preserved evidence must byte-match what
        # the classifier read). Exclusive creation for the same collision
        # reason as the sidecar; a failed preservation WARNs only -- the
        # classification above already stands.
        if (-not [string]::IsNullOrWhiteSpace($passVerdictText)) {
          $erroredBodyFile = ($verdictFile -replace '\.md$', "-pass$pass.errored.txt")
          try {
            $erroredBodyStream = [System.IO.File]::Open($erroredBodyFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
              $erroredBodyBytes = $utf8NoBom.GetBytes($passVerdictText)
              $erroredBodyStream.Write($erroredBodyBytes, 0, $erroredBodyBytes.Length)
            } finally {
              $erroredBodyStream.Dispose()
            }
            Write-Host "[auto-review] preserved errored pass $pass body -> $erroredBodyFile"
          } catch {
            Write-Host "[auto-review] WARN: could not preserve errored pass $pass body to '$erroredBodyFile' ($($_.Exception.Message)) - the classification above still stands; the scratch copy is lost when this run exits"
          }
        }
        continue
      }

      $cls = Get-VerdictExitCode -Verdict $passVerdictText
      $passResults += [pscustomobject]@{ Pass = $pass; Verdict = $passVerdictText; Cls = $cls }
      $passDiag = if ($cls.Diagnostic) { " [$($cls.Diagnostic)]" } else { '' }
      $qDisp = $cls.QualityCount + $cls.LegacyNbCount  # surface legacy NON-BLOCKER alongside QUALITY
      Write-Host "[auto-review] pass $pass verdict: $($cls.VerdictText)  BLOCKER=$($cls.BlockerCount) QUALITY=$qDisp NOTE=$($cls.NoteCount)$passDiag"
    }
  } finally {
    $hbQuiescent = $codexHeartbeatHelper.Stop()
    if (-not $hbQuiescent) {
      Write-Host "[auto-review] WARN: the heartbeat thread did not confirm quiescence; the preserved liveness log below may miss trailing records"
    }
    # Preserve the liveness log with the run's forensics (size-checked,
    # warn-not-abort, like the per-pass events): the post-run audit reads
    # it to reconstruct quiet intervals and escalations the console alone
    # cannot show.
    if (Test-Path -LiteralPath $livenessRaw) {
      $livenessFile = Join-Path $outDirAbs "review-$timestamp-$scopeTag-r$PID.liveness.jsonl"
      try {
        Copy-Item -Path $livenessRaw -Destination $livenessFile -Force -ErrorAction Stop
        $srcLenLive = (Get-Item -LiteralPath $livenessRaw).Length
        if (-not ((Test-Path -LiteralPath $livenessFile) -and ((Get-Item -LiteralPath $livenessFile).Length -eq $srcLenLive))) {
          Write-Host "[auto-review] WARN: liveness-log preservation to $livenessFile is incomplete (size mismatch or missing; scratch copy at $livenessRaw is lost when this run exits)"
        }
      } catch {
        Write-Host "[auto-review] WARN: failed to preserve the liveness log to ${livenessFile}: $($_.Exception.Message)"
      }
    } else {
      Write-Host "[auto-review] WARN: no liveness log exists at $livenessRaw - the start record creates it synchronously at launch, so its appends were failing; this run has no liveness artifact"
    }
    $ErrorActionPreference = $prevEAP
    foreach ($n in $gitEnvNames) {
      if ($null -ne $savedGitEnv[$n]) {
        Set-Item -LiteralPath "Env:$n" -Value $savedGitEnv[$n] -ErrorAction SilentlyContinue
      }
    }
  }

  # Authoritative gate exit = the UNION of the review passes.
  # Fails CLOSED if any pass errored or was malformed; otherwise blocks
  # on the union severity (any BLOCKER -> 2; else 0 -- QUALITY is non-blocking under
  # the 2026-07 severity contract and is shown as a non-blocking finding, not an abort).
  $combined = Get-CombinedReviewExit -PassResults $passResults -PassErrored $passErrored -ExpectedPasses $ReviewPasses

  # Artifact: a deterministic per-pass concatenation. Its framing is a
  # contract: Read-CrgSuccessfulPairArtifactBytes (paired-governance.psm1)
  # accepts a passing artifact only in exactly this shape.
  $concatParts = @($passResults | ForEach-Object {
    "===== REVIEW PASS $($_.Pass)/$ReviewPasses =====`n$($_.Verdict.TrimEnd())`n"
  })
  $artifact = if ($concatParts.Count -gt 0) { ($concatParts -join "`n") } else { "(no verdict produced)`n" }
  $artifactKind = 'per-pass concatenation (deterministic)'

  # If the gate failed closed (a pass errored / was malformed), the artifact so
  # far is the concatenation of only the SUCCESSFUL passes -- which can look
  # clean. Prepend an unambiguous fail-closed banner with a BLOCKED verdict so
  # a reader of the retained artifact never takes a fail-closed run as passing.
  if ($combined.ExitCode -eq 3) {
    $artifact = "===== GATE FAILED CLOSED =====`n$($combined.Diagnostic)`n`nVERDICT: BLOCKED`n`n" + $artifact
    $artifactKind = "$artifactKind + fail-closed banner"
  }

  $diffSha = $pairedHostInput.DiffSha256
  # REVIEW-DURATION-SECS (docs/reviewer-liveness-design.md): the review
  # invocation's wall time, forensics/metadata like the rest of the header --
  # no gate decision reads it, but it makes reviewer latency a recorded,
  # comparable quantity for the review-the-reviewers audit.
  $reviewDurationSecs = Get-ReviewDurationSecs -ElapsedSeconds $reviewStopwatch.Elapsed.TotalSeconds
  Assert-CrgPairedReadContext -Context $pairedHostInput.ReadContext -InputBundle $pairedHostInput.InputBundle
  Assert-CrgPairedInputSnapshot -Snapshot $pairedProviderSnapshot
  $pairedArtifactBytes = & $pairedHostInput.ArtifactWriter -ReviewUnitBytes $pairedHostInput.InputBundle.Buffers['review-unit.txt'] `
    -PublicObjectFormat $pairedHostInput.InputBundle.Metadata.Descriptor.Fields['public-object-format'] `
    -PrivateObjectFormat $pairedHostInput.InputBundle.Metadata.Descriptor.Fields['private-object-format'] `
    -DescriptorSha256 $pairedHostInput.InputBundle.DescriptorSha256 -DisplayDiffSha256 $diffSha `
    -Backend 'codex' -Effort $ReasoningEffort -DurationSecs $reviewDurationSecs -VerdictText $artifact
  $pairedArtifactStream = [IO.File]::Open($verdictFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $pairedArtifactStream.Write($pairedArtifactBytes, 0, $pairedArtifactBytes.Length) } finally { $pairedArtifactStream.Dispose() }

  Write-Host ""
  Write-Host "[auto-review] $ReviewPasses-pass review -> $verdictFile ($artifactKind)"
  Write-Host "[auto-review] union findings (max across passes): BLOCKER=$($combined.BlockerMax)  QUALITY=$($combined.QualityMax)  NOTE=$($combined.NoteMax)"
  if ($combined.Diagnostic) {
    Write-Host "[auto-review] $($combined.Diagnostic) - failing closed"
  }
  # Exit-4 derivation: a fail-closed union whose errored passes ALL carry the
  # positively-identified exhaustion signature (and no malformed evidence, and
  # no BLOCKER anywhere) upgrades to the fallback-eligible exit 4. The .md
  # artifact keeps the STANDARD fail-closed banner; the process exit and the
  # sidecar carry the exhaustion classification.
  $gateExit = Resolve-CodexGateExit -CombinedExit $combined.ExitCode `
    -ErroredPassCount $erroredPassCount `
    -AllErroredExhausted $allErroredExhausted `
    -AnyMalformedPass ((@($passResults | Where-Object { $null -eq $_.Cls -or $_.Cls.ExitCode -eq 3 }).Count -gt 0) -or $erroredBodyMalformed) `
    -AnyBlockerPass ((@($passResults | Where-Object { $null -ne $_.Cls -and $_.Cls.ExitCode -eq 2 }).Count -gt 0) -or $erroredBodyBlocker)
  if ($gateExit -eq 4) {
    Write-Host "[auto-review] TOKEN EXHAUSTION positively identified on every errored pass ($erroredPassCount of $ReviewPasses) - reporting exit 4 (fallback-eligible) instead of fail-closed."
    $sidecarPath = ($verdictFile -replace '\.md$', '.exhaustion.json')
    $sidecarOk = Write-CrgPairedExhaustionSidecar -HostInput $pairedHostInput -Path $sidecarPath -Backend 'codex' `
      -SignatureClass 'cli-limit-signature' -ProcessOutcome "errored-passes-$erroredPassCount-of-$ReviewPasses"
    if ($sidecarOk -isnot [bool]) { $sidecarOk = $false }
    if (-not $sidecarOk) {
      Write-Host "[auto-review] ERROR: exhaustion was classified but the durable sidecar could not be written - failing closed (exit 3) instead of offering a fallback without evidence."
      $gateExit = 3
    }
  }
  exit $gateExit
}
catch {
  # Any uncaught PowerShell terminating error inside the main review body --
  # prompt/argv/runner-script file writes, the snapshot copy, a verdict write,
  # the per-pass runner launch/collection -- would otherwise leak out with
  # PowerShell's default error exit code (1), which the consumer would misread as
  # a review verdict code rather than the documented invocation-failure code
  # (exit 3, fail-closed). (Under the 2026-07 severity contract exit 1 is retired
  # -- QUALITY passes as exit 0 -- so a leaked raw 1 is simply an unexpected code;
  # mapping to exit 3 keeps the fail-closed contract explicit.) Map all uncaught
  # failures to the documented invocation-failure code with a stable diagnostic
  # line, mirroring the claude wrapper's main-try catch. (Codex CROSS-CRATE-CONTRACT.)
  Write-Host "[auto-review] ERROR: unhandled wrapper failure: $($_.Exception.Message)"
  Write-Host "[auto-review]        $($_.InvocationInfo.PositionMessage)"
  exit 3
}
finally {
  try {
    $workCleanupAllowed = Complete-CrgPairedHostInput -HostInput $pairedHostInput -ProviderSnapshot $pairedProviderSnapshot
    if ($workCleanupAllowed -isnot [bool]) { $workCleanupAllowed = $false }
  } catch {
    $workCleanupAllowed = $false
    Write-Host "[auto-review] ERROR: paired child or snapshot cleanup could not establish quiescence: $($_.Exception.Message)"
  }
  if (-not $workCleanupAllowed) {
    Write-Host "[auto-review] ERROR: paired scratch retained because child or snapshot custody remains uncertain: $work"
  }
  # Always delete the throwaway snapshot (full source-tree copy).
  # Package cleanup policy: single-file Remove-Item is allowed; -Recurse is
  # banned (the dangerous recursive force-delete is avoided even for the gate's
  # own scratch). Walk the tree, remove files, then remove now-empty dirs
  # bottom-up. Matches scripts/claude/auto-review.ps1's cleanup.
  if ($workCleanupAllowed -and (Test-Path $work)) {
    Get-ChildItem -LiteralPath $work -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
    }
    Get-ChildItem -LiteralPath $work -Directory -Recurse -ErrorAction SilentlyContinue |
      Sort-Object { $_.FullName.Length } -Descending |
      ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue
  }
  if (-not $workCleanupAllowed) { exit 3 }
}
} finally {
  try {
    $null = Set-CrgProcessConsoleEncoding -ConsoleInput -Encoding $crgSavedConsoleInputEncoding
  } catch { Write-Warning "auto-review.ps1: could not put back the cached console input encoding ($($_.Exception.Message))." }
  try {
    $null = Set-CrgProcessConsoleEncoding -Encoding $crgSavedConsoleOutputEncoding
  } catch { Write-Warning "auto-review.ps1: could not put back the cached console output encoding ($($_.Exception.Message))." }
}
