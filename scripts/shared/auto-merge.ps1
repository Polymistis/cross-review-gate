# Merge-gate wrapper: run an adversarial branch review against the target base,
# only ff-merge the branch into the base when the review surfaces no BLOCKER
# findings (2026-07 severity contract: CLEAN, NOTE-only, and QUALITY-only
# verdicts all pass).
#
# Required for any merge to the integration base branch per the installed
# AGENTS.md. A bare `git merge` to that base is a workflow violation - the
# branch must pass an adversarial review pass first. The base defaults to the
# repo's default branch (origin/HEAD, fallback 'main') unless -Base is given.
#
# Security note: this wrapper NEVER checks out the candidate branch before
# review. The review runs from the base branch's checkout, using the base
# branch's wrapper and prompt template. The candidate branch's tip is named
# via -Tip so codex inspects branch-tip content via `git show <tip>:<path>`
# without that content ever executing. This prevents a candidate branch from
# weakening the review wrapper, prompt, or hook and having the weakened
# version decide whether the branch may merge.
#
# Exit codes (2026-07 severity contract: only BLOCKER aborts a merge; QUALITY is
# a non-blocking follow-up):
#   0 = review passed (CLEAN, NOTE-only, OR QUALITY-only; the wrappers exit 0 for
#       all three -- QUALITY findings are staged by each child wrapper and promoted
#       to logs/review-followups.md by THIS gate after the ff-merge
#       succeeds, for batch triage, not blocked), merge applied
#   1 = RETIRED (was: QUALITY findings blocked the merge). QUALITY no longer blocks
#       a merge, so this gate never returns 1; a stray exit 1 from a backend is an
#       unexpected code and fails the merge closed (exit 3).
#   2 = review surfaced BLOCKER findings WITH a present `VERDICT:` line (even a
#       wrong/malformed-word one), merge NOT applied
#   3 = invocation failure (review error, dirty tree, branch not found,
#       malformed verdict -- INCLUDING a backend verdict with BLOCKER entries but
#       a missing/duplicate `VERDICT:` line, which classifies exit 3 and aborts
#       the merge as malformed, not exit 2 -- etc.)
#
# Preferred-provider merge panels:
#   The REQUIRED -Backend parameter names the preferred provider that starts
#   this merge review, and the whole planned panel first runs on it at full coverage:
#     -Backend codex  -> the codex wrapper carries the whole pass count
#                        itself (it parallelizes its passes internally)
#     -Backend claude -> CONCURRENT tagged single-pass claude children
#                        (-ArtifactTag, the reserved p<N> panel-slot
#                        grammar; the base-extracted claude wrapper must
#                        declare -ArtifactTag or the panel refuses up
#                        front -- concurrent untagged children would
#                        collide on artifact stems)
#   The panel verdict is the worst of the children's validated exits
#   ({0,2}; exit 4 routes to the exhaustion fallback below; exit 3 and
#   any other code fail the merge closed). A claude child exit 3
#   ABORTS the merge (fail closed): exit 3 is the Claude wrapper's GENERAL
#   fail-closed code (configured consistency doc unsupported, ancestor
#   CLAUDE.md trust breach, auth failure, malformed/empty output), not only
#   quota. The replayed child transcript supplies the cause-specific remedy;
#   transport refusal needs host-network authorization and an unchanged retry,
#   while consistency-doc routing still requires the Codex backend. A branch that touches the
#   configured consistency doc REFUSES -Backend claude up front (the
#   claude wrapper fails closed on any diff touching it; the remedy the
#   refusal names is -Backend codex) -- an ineligible preferred route refuses
#   before launch; only positively identified exhaustion can substitute below.
#
#   TOKEN-EXHAUSTION FALLBACK (operator fallback ruling 2026-08-22): a child
#   exit 4 is POSITIVELY-IDENTIFIED exhaustion (the wrapper wrote a durable
#   .exhaustion.json sidecar; anything ambiguous stays exit 3). When the
#   PREFERRED provider's initial panel reports exhaustion, the gate substitutes a FULL
#   panel on the OTHER provider: codex exhausted -> a tagged single-pass
#   claude panel (refused when the branch touches the configured
#   consistency doc, and when the base's claude wrapper does not declare
#   -ArtifactTag); claude exhausted -> a codex substitute carrying the
#   whole pass count.
#   No substitute runs when a surviving child of the chosen panel already
#   decided the merge (a BLOCKER exit 2 aborts the union no matter what a
#   substitute would say; any other nonzero exit aborts on its own arm) --
#   the panel is never burned on a merge that cannot proceed
#   (Resolve-PanelOutcome's blocker-decisive arm).
#   Cross-provider substitution is transparent to the calling session on a
#   successful run. Provider identity and exhaustion remain in the durable
#   sidecars and verdict headers; both pools unavailable still fails closed.
#
# DO NOT reintroduce same-content dedup pass-reduction (crediting a prior
#   verdict artifact as a merge pass) without an UNFORGEABLE receipt
#   mechanism: verdict artifacts live in gitignored, workspace-writable
#   `logs/<backend>/reviews/`, so any local agent could plant one with the
#   computed identity headers and shave a real merge pass -- no LOCAL
#   artifact is unforgeable in this trust model, and concurrency already
#   removes dedup's wall-clock value. The gate always runs the full pass
#   count. A current run-owned artifact is mandatory corroboration of a
#   successful child exit: its identity headers and successful semantic rows
#   are validated before merge. Historical/shared artifacts remain forensics
#   only and never earn pass credit.
#
# Usage:
#   scripts\shared\auto-merge.ps1 -Branch claude-work-feature -Backend codex
#   scripts\shared\auto-merge.ps1 -Branch claude-work-feature -Backend claude
#   scripts\shared\auto-merge.ps1 -Branch claude-work-feature -Backend codex -Base main
#   scripts\shared\auto-merge.ps1 -Branch claude-work-feature -Backend codex -ReasoningEffort high

[CmdletBinding()]
param(
  # Validated at runtime below to preserve the explicit exit-code contract.
  [string]$Branch = '',

  # Project-agnostic: this package ships WITHOUT a hard-coded integration
  # branch. When -Base is omitted it is resolved at runtime from the remote
  # default branch (origin/HEAD), falling back to 'main' -- see
  # Resolve-DefaultBaseBranch below. A concrete install may pass -Base
  # explicitly or pin it in the installed AGENTS.md.
  [string]$Base = '',

  # REQUIRED (validated at runtime like -Branch): the
  # preferred provider that starts this merge review. The planned panel first
  # runs on it; only positively identified exhaustion can substitute below.
  # The operator chooses the preferred provider per merge. Positively identified
  # exhaustion substitutes a full panel on the other provider inside this
  # invocation without changing the caller's environment or successful output.
  # Deliberately a plain [string]: a [ValidateSet] here would fail
  # PARAMETER BINDING on an invalid value and terminate with exit 1 --
  # the code this gate's exit contract RETIRED -- before any in-script
  # diagnostic or the exit-code mapping could run. Validation lives in
  # Resolve-BackendSelection at the runtime usage checks (stable
  # diagnostic, exit 3).
  [string]$Backend = '',

  # Codex reasoning-effort override. The merge gate resolves its own EFFECTIVE
  # effort (Resolve-EffectiveCodexEffort: this value when non-empty, else the
  # top-level ~/.codex/config.toml model_reasoning_effort, else `unknown`) and,
  # when a known tier, forwards THAT resolved value to the branch-review codex
  # wrapper's -ReasoningEffort -- pinning the branch review to that exact tier
  # (deterministic, stamped as REVIEW-EFFORT) rather than letting the child
  # re-read config. An empty value here therefore still pins the child to the
  # config-derived tier. The Claude wrapper has no effort knob (it pins
  # CLAUDE_CODE_EFFORT_LEVEL=max internally), so this is codex-only.
  # Plain [string] for the same retired-exit-1 reason as -Backend:
  # validated at the runtime usage checks (exit 3), never by binding.
  [string]$ReasoningEffort = ''

)

$ErrorActionPreference = 'Stop'

# Functions shared with the review wrappers, dot-sourced so they run in this
# script's own scope (the file's
# header gives the reason). Every layout that carries this gate carries that
# file too: both are in the bootstrap install inventory, which the runtime
# payload list includes.
try {
  . (Join-Path (Split-Path -Parent $PSScriptRoot) 'review-common.ps1')
} catch {
  Write-Host "[auto-merge] ERROR: the shared review functions could not be loaded ($($_.Exception.Message)) - merge ABORTED (fail closed)."
  exit 3
}

# Repository-default info/grafts remains active even with replacement refs
# disabled. Route every production Git read to the immutable Windows null
# device so mutable repository metadata cannot add forged ancestry edges. The
# device-qualified spelling is required: bare NUL suppresses the file but makes
# current Git emit its graft-deprecation hint on stderr, which PowerShell 5.1
# can promote to a terminating NativeCommandError under ErrorActionPreference
# Stop.
function Set-CrgNoDefaultGrafts {
  [Environment]::SetEnvironmentVariable('GIT_GRAFT_FILE', '\\.\NUL', [EnvironmentVariableTarget]::Process)
  if (-not [string]::Equals(
      [Environment]::GetEnvironmentVariable('GIT_GRAFT_FILE', [EnvironmentVariableTarget]::Process),
      '\\.\NUL',
      [System.StringComparison]::Ordinal)) {
    throw 'the canonical GIT_GRAFT_FILE process value did not verify as exactly \\.\NUL'
  }
}

# Called only AFTER the repository's default shallow state has been proved
# complete. Subsequent graph reads then ignore a late-created .git/shallow
# boundary instead of changing semantics midway through the merge transaction.
function Set-CrgNoLateShallowBoundary {
  [Environment]::SetEnvironmentVariable('GIT_SHALLOW_FILE', '\\.\NUL', [EnvironmentVariableTarget]::Process)
  if (-not [string]::Equals(
      [Environment]::GetEnvironmentVariable('GIT_SHALLOW_FILE', [EnvironmentVariableTarget]::Process),
      '\\.\NUL',
      [System.StringComparison]::Ordinal)) {
    throw 'the canonical GIT_SHALLOW_FILE process value did not verify as exactly \\.\NUL'
  }
}

$crgGitSelectorKeys = @(Get-CrgGitSelectorEnvironmentKeys)
if ($crgGitSelectorKeys.Count -ne 0) {
  Write-Host '[auto-merge] ERROR: an ambient Git selector is set (repository/object/ref/index, GIT_CONFIG* carrier, history, or attribute family; case-insensitive); refusing before the first Git command.'
  exit 3
}
try {
  Set-CrgNoReplaceObjects
  Set-CrgNoDefaultGrafts
}
catch {
  Write-Host "[auto-merge] ERROR: could not enforce the replacement/graft history boundary before the first Git command: $($_.Exception.Message)"
  exit 3
}


# Classify the exact machine-readable output of `rev-parse
# --is-shallow-repository`. Only a successful, single `false` proves that the
# ancestry/range operations below see complete repository history.
function Resolve-CrgShallowRepositoryState {
  param([string[]]$Output, [int]$ExitCode)
  if ($ExitCode -ne 0) { return 'indeterminate' }
  $rows = @($Output | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($rows.Count -ne 1) { return 'indeterminate' }
  if ([string]::Equals($rows[0], 'false', [System.StringComparison]::Ordinal)) { return 'complete' }
  if ([string]::Equals($rows[0], 'true', [System.StringComparison]::Ordinal)) { return 'shallow' }
  return 'indeterminate'
}

# Return every exact spelling of the retired project-mode authorization name in
# a RAW process environment block. Windows can preserve case-variant duplicate
# keys in that block even though the Env: provider and the single-value
# GetEnvironmentVariable API compare names case-insensitively. Enumerating the
# raw block is therefore the complete read boundary.
function Get-RetiredProjectModeEnvironmentKeys {
  $EnvEntries = [Environment]::GetEnvironmentVariables('Process')
  $names = New-Object 'System.Collections.Generic.List[string]'
  foreach ($rawName in @($EnvEntries.Keys)) {
    $name = [string]$rawName
    if ([string]::Equals($name, 'CROSS_REVIEW_ALLOW_MODE_CHANGE', [System.StringComparison]::OrdinalIgnoreCase)) {
      [void]$names.Add($name)
    }
  }
  return $names.ToArray()
}

# Remove every exact raw spelling before any trusted base wrapper can be
# started. One provider/API removal is insufficient for a duplicate-case block:
# Windows removes one case-insensitive match and can leave the other spelling
# live. Drive one removal from every enumerated exact key, then re-read the raw
# block and fail closed if any spelling survived.
function Clear-RetiredProjectModeEnvironment {
  $before = @(Get-RetiredProjectModeEnvironmentKeys)
  foreach ($exactName in $before) {
    [Environment]::SetEnvironmentVariable(
      $exactName,
      $null,
      [EnvironmentVariableTarget]::Process
    )
  }
  $remaining = @(Get-RetiredProjectModeEnvironmentKeys)
  if ($remaining.Count -ne 0) {
    throw [System.InvalidOperationException]::new(
      "retired environment key(s) survived raw-block removal: $($remaining -join ', ')"
    )
  }
}

try {
  Clear-RetiredProjectModeEnvironment
} catch {
  Write-Host "[auto-merge] ERROR: failed to scrub retired project-mode authorization from the raw process environment before child execution: $($_.Exception.Message)"
  exit 3
}

# Force UTF-8 for native command pipes and stdin/stdout. Default
# $OutputEncoding is ASCII on Windows PowerShell 5.1; `git show` /
# `git diff` output captured via `&` is round-tripped through the
# platform default codepage, mojibake-ing UTF-8 multi-byte glyphs
# (em-dashes, smart quotes) before this script writes the trusted-
# infra copies. Same defect class as the verdict + prompt reads in
# auto-review.ps1 (fixed in a prior round). Pin explicitly here too.
# The console code pages belong to the console window this script shares with
# the invoking shell, so the finally at the end of the script puts back the
# values saved here.
try {
  $crgSavedConsoleInputEncoding = Get-CrgConsoleRestoreEncoding -ConsoleInput
  $crgSavedConsoleOutputEncoding = Get-CrgConsoleRestoreEncoding
} catch {
  Write-Host "[auto-merge] ERROR: the console code pages could not be read ($($_.Exception.Message)) - merge ABORTED (fail closed)."
  exit 3
}
try {
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding  = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

# Project-mode capability (docs/project-mode-doctrine-v1.md; token:
# crg-project-mode-capability-v1). The merge gate's project-mode duties are
# CONSUMED, not owned: the wrappers are the sole resolver -- their Branch
# scope resolves review context from the pinned base and exposes any candidate
# declaration as ordinary diff evidence. Repository-read failures still reach
# this gate as a child exit 3 that aborts the merge. The base OID this gate pins
# and passes as -Target IS the governing ref the wrappers read, so a base branch
# moving mid-run cannot split resolutions.


# PURE normalize-and-validate for the preferred initial -Backend choice. Lives
# in-script (not a param [ValidateSet]) because binding-time validation
# terminates with the RETIRED exit 1 before the exit-code contract applies;
# the runtime maps a failed selection to a stable diagnostic + exit 3. The
# explicit ToLowerInvariant is load-bearing: the match is ordinal (PS 5.1
# culture compares ignore characters such as U+00AD), and every provider
# dispatch and slot/run-dir name below consumes the canonical lowercase form.
function Resolve-BackendSelection {
  param([string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return @{ Ok = $false; Reason = 'required' } }
  $norm = $Raw.ToLowerInvariant()
  if ([Array]::IndexOf([string[]]@('codex', 'claude'), [string]$norm) -ge 0) { return @{ Ok = $true; Backend = $norm } }
  return @{ Ok = $false; Reason = 'invalid' }
}

# SINGLE AUTHORITY for the planned panel size. Every consumer -- the claude
# slot list, the fallback slot list, the codex children's -ReviewPasses, and
# the printed pass counts -- derives from this constant so the cardinality
# cannot drift between them (prose counts were already removed for the same
# reason; code-side literals could still diverge silently).
$script:PanelPassCount = 3

# The per-slot launch identity every panel and fallback child derives its
# display name, run dir, staged-follow-up path, and tag forwarding from.
# Centralized so distinct dirs, pending paths, and claude -ArtifactTag forwarding
# derive from the same slot identity.
function Resolve-PanelSlotSpec {
  param([string]$Backend, [string]$Slot, [string]$RunDir)
  $name = if ([string]::IsNullOrEmpty($Slot)) { $Backend } else { "$Backend-$Slot" }
  $dir = Join-Path $RunDir $name
  $extra = if ([string]::Equals($Backend, 'claude', [System.StringComparison]::Ordinal) -and -not [string]::IsNullOrEmpty($Slot)) { @('-ArtifactTag', $Slot) } else { @() }
  return @{ Name = $name; Dir = $dir; Pending = (Join-Path $dir 'followups.pending.md'); ExtraArgs = $extra }
}

# Resolve the full initial panel launch plan for the PREFERRED backend
# (-Backend is required; positively identified exhaustion may substitute a full
# alternate panel after this plan completes). PURE.
# Refusals fire BEFORE any child launches:
#   run                -- launch the panel. Slots = the child slot tags:
#                         the bare '' slot for codex (the wrapper carries
#                         the whole pass count itself), the reserved p<N>
#                         -ArtifactTag slots for claude (concurrent
#                         tagged single-pass children)
#   refuse-consistency -- -Backend claude while the branch touches the
#                         configured consistency doc: the claude wrapper
#                         fails closed on any diff touching it, so the
#                         panel would be burned; the remedy the runtime
#                         names is -Backend codex (a known-ineligible initial
#                         route is refused rather than launched)
#   refuse-tag         -- -Backend claude but the BASE's claude wrapper
#                         does not declare -ArtifactTag: concurrent tagged
#                         children would param-bind-fail on it (the exact
#                         hazard Get-WrapperParameterDeclaration exists to
#                         prevent)
function Resolve-MergePanelPlan {
  param(
    [string]$Backend,
    [bool]$ConsistencyDocInBranch,
    [string]$ClaudeTagDeclaration   # Get-WrapperParameterDeclaration: declared|absent|unknown
  )
  if ([string]::Equals($Backend, 'claude', [System.StringComparison]::Ordinal)) {
    if ($ConsistencyDocInBranch) { return @{ Action = 'refuse-consistency' } }
    if ($ClaudeTagDeclaration -ne 'declared') { return @{ Action = 'refuse-tag' } }
    return @{ Action = 'run'; Slots = @(1..$script:PanelPassCount | ForEach-Object { "p$_" }) }
  }
  return @{ Action = 'run'; Slots = @('') }
}

# Classify a completed panel's per-child exits into the gate's next step.
# PURE; inputs are the VALIDATED per-child exits
# (the runtime aborts on a null or file-vs-process-inconsistent readback
# before ever calling this). Under the 2026-07 severity contract a valid
# child verdict is 0 (PASS -- incl. non-blocking QUALITY/NOTE) or 2
# (BLOCKER); 4 is positively-identified token exhaustion; 3 is the child's
# own fail-closed code; anything else (the retired exit 1, crash codes) is
# NOT a verdict and must never collapse to a passing union. Action values:
#   abort-empty      -- ZERO exits reached classification (null/empty
#                       input): an accounting failure, not a reviewed
#                       merge -- zero children examined must never read
#                       as reviewed-clean, so it fails closed
#   abort-exit3      -- a child failed closed: the merge aborts on that
#                       child's own arm (the claude wording differs at the
#                       call site)
#   abort-unknown    -- a child exit outside {0,2,3,4}: fail closed
#   blocker-decisive -- exhaustion (4) present but a surviving child
#                       already reported BLOCKER (2): the union is 2 no
#                       matter what a substitute panel would say, so the
#                       substitute is SKIPPED rather than burned on a merge
#                       that cannot proceed, and the gate exits 2 (the
#                       review-blocked code -- collapsing it onto 3 would
#                       make a real BLOCKER read as a gate malfunction).
#   fallback         -- exhaustion (4) present with NO decisive sibling
#                       (every sibling passed or is itself exhausted):
#                       substitute a full panel on the other provider
#                       (Resolve-MergeFallbackPlan) -- a fully-exhausted
#                       panel routes here too, since the whole pool is
#                       the exhausted unit
#   union            -- no 3/4/unknown: Exit is the worst of {0,2}
function Resolve-PanelOutcome {
  param([int[]]$Exits)
  if ($null -eq $Exits -or @($Exits).Count -eq 0) { return @{ Action = 'abort-empty' } }
  $has3 = $false; $has4 = $false; $has2 = $false; $hasUnknown = $false
  foreach ($e in $Exits) {
    if ($e -eq 3) { $has3 = $true }
    elseif ($e -eq 4) { $has4 = $true }
    elseif ($e -eq 2) { $has2 = $true }
    elseif ($e -ne 0) { $hasUnknown = $true }
  }
  if ($has3) { return @{ Action = 'abort-exit3' } }
  if ($hasUnknown) { return @{ Action = 'abort-unknown' } }
  if ($has4 -and $has2) { return @{ Action = 'blocker-decisive' } }
  if ($has4) { return @{ Action = 'fallback' } }
  if ($has2) { return @{ Action = 'union'; Exit = 2 } }
  return @{ Action = 'union'; Exit = 0 }
}

# PURE fallback-plan resolver for the token-exhaustion substitution
# (operator fallback ruling 2026-08-22, reshaped by P4's preferred-provider
# panels): the PREFERRED provider's initial panel reported exhaustion with every other
# child passing, so a FULL panel on the OTHER provider substitutes --
# unless that provider cannot review this branch. PURE. Action values:
#   fallback-claude    -- chosen codex exhausted; a tagged single-pass
#                         claude panel substitutes
#   fallback-codex     -- chosen claude exhausted; a codex substitute
#                         carrying the whole pass count
#   refuse-consistency -- the substitute would be claude but the branch
#                         touches the configured consistency doc (the
#                         claude wrapper fails closed on any diff touching
#                         it; the attempt would be burned)
#   refuse-tag         -- the substitute would be claude but the BASE's
#                         claude wrapper does not declare -ArtifactTag
# Precedence: consistency before tag -- the more fundamental
# cannot-review-this-branch reason first, so the diagnostic names the real
# cause. (Both-exhausted is discovered at runtime when the substitute
# panel itself exits 4.)
function Resolve-MergeFallbackPlan {
  param(
    [string]$ChosenBackend,
    [bool]$ConsistencyDocInBranch,
    [string]$ClaudeTagDeclaration
  )
  if ([string]::Equals($ChosenBackend, 'codex', [System.StringComparison]::Ordinal)) {
    if ($ConsistencyDocInBranch) { return @{ Action = 'refuse-consistency' } }
    if ($ClaudeTagDeclaration -ne 'declared') { return @{ Action = 'refuse-tag' } }
    return @{ Action = 'fallback-claude' }
  }
  return @{ Action = 'fallback-codex' }
}

# Normalize a detected `origin/HEAD` short-ref (e.g. 'origin/main') to a base
# branch name, defaulting to 'main' when detection yielded nothing. PURE (no
# git); the non-pure detection lives in
# Resolve-DefaultBaseBranch. Only the leading `origin/` segment is stripped so
# a slashed default branch ('origin/release/x' -> 'release/x') survives intact.
function Get-NormalizedDefaultBase {
  param([string]$DetectedRef)
  if ([string]::IsNullOrWhiteSpace($DetectedRef)) { return 'main' }
  $name = ($DetectedRef -replace '^origin/', '').Trim()
  if ([string]::IsNullOrWhiteSpace($name)) { return 'main' }
  return $name
}

# Resolve the default base branch for a project-agnostic install: read the
# remote default branch from `origin/HEAD`. Any failure (no remote, HEAD unset,
# git error) yields '' so Get-NormalizedDefaultBase falls back to 'main'. NON-
# pure (shells out to git); callers pass an explicit -Base to bypass it.
function Resolve-DefaultBaseBranch {
  $ref = ''
  try {
    $rows = @(& git symbolic-ref --quiet refs/remotes/origin/HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $rows.Count -eq 1) {
      $fullRef = ([string]$rows[0]).Trim()
      $prefix = 'refs/remotes/origin/'
      if ($fullRef.StartsWith($prefix, [System.StringComparison]::Ordinal) -and $fullRef.Length -gt $prefix.Length) {
        $ref = 'origin/' + $fullRef.Substring($prefix.Length)
      }
    }
  } catch { $ref = '' }
  return (Get-NormalizedDefaultBase -DetectedRef $ref)
}

# Successful caller status deliberately excludes panel/provider routing detail.
# The chosen and effective providers remain in the run-owned verdict headers and
# exhaustion sidecars; callers receive the same success shape with or without
# automatic substitution. PURE.
function Get-MergePanelVerdictStatusLine {
  param([int]$ExitCode)
  return "[auto-merge] panel verdict: $ExitCode"
}

# Successful review progress is intentionally provider-neutral. These helpers
# keep the caller contract visible instead of scattering backend names
# through runtime-only literals.
function Get-MergeReviewEffortStatusLine {
  param([string]$Effort)
  return "[auto-merge] review reasoning effort: $Effort"
}
function Get-MergePanelPlanStatusLine {
  param([int]$PassCount)
  return "[auto-merge] panel: $PassCount independent review passes"
}
function Get-MergePanelLaunchStatusLine {
  param([int]$PassCount)
  return "[auto-merge] launching review panel ($PassCount passes) ..."
}

# Exit 3 identifies no single cause: an unchanged retry follows transport
# authorization, but cannot repair an ineligible consistency-doc backend.
# Preserve that cause-specific distinction without changing automatic routing.
# PURE.
function Get-ClaudePanelExit3RetryLine {
  return '[auto-merge] Follow the cited child diagnostic before retrying. Consistency-doc edits require -Backend codex; transport refusal requires host-network authorization followed by the same merge command unchanged. Exit 3 never triggers automatic provider substitution.'
}

# Resolve one local branch by its exact, case-sensitive refname. Git revision
# expressions are deliberately excluded from the untrusted branch-name
# boundary: names such as `feat~1` must never select an ancestor, and a
# case-insensitive ref filesystem must not let requested `Feat` alias stored
# `feat`. `for-each-ref` returns the stored refname and direct object OID in one
# snapshot; exactly one case-folded match with ordinal-equal spelling is
# eligible for commit peeling.
function Resolve-CrgExactLocalBranchCommit {
  param([AllowNull()][AllowEmptyString()][string]$BranchName)

  $oidPattern = '^[0-9a-f]{40}(?:[0-9a-f]{24})?$'
  if ([string]::IsNullOrWhiteSpace($BranchName)) {
    return [pscustomobject]@{ State = 'invalid-name'; RefName = ''; CommitOid = '' }
  }

  $refName = 'refs/heads/' + $BranchName
  $formatExit = -1
  try {
    & git check-ref-format $refName 2>$null | Out-Null
    $formatExit = $LASTEXITCODE
  } catch {
    $formatExit = -1
  }
  if ($formatExit -ne 0) {
    return [pscustomobject]@{ State = 'invalid-name'; RefName = $refName; CommitOid = '' }
  }

  $rows = @()
  $listExit = -1
  try {
    $rows = @(& git for-each-ref '--format=%(refname)%09%(objectname)' refs/heads/ 2>$null)
    $listExit = $LASTEXITCODE
  } catch {
    $rows = @()
    $listExit = -1
  }
  if ($listExit -ne 0) {
    return [pscustomobject]@{ State = 'indeterminate'; RefName = $refName; CommitOid = '' }
  }

  $directOid = ''
  $foldedMatchCount = 0
  $exactSpelling = $false
  foreach ($rawRow in $rows) {
    $row = [string]$rawRow
    $tab = $row.IndexOf("`t", [System.StringComparison]::Ordinal)
    if ($tab -le 0 -or $row.IndexOf([char]9, $tab + 1) -ge 0) {
      return [pscustomobject]@{ State = 'indeterminate'; RefName = $refName; CommitOid = '' }
    }
    $storedRef = $row.Substring(0, $tab)
    $storedOid = $row.Substring($tab + 1)
    if (-not $storedRef.StartsWith('refs/heads/', [System.StringComparison]::Ordinal) -or
        $storedOid -notmatch $oidPattern) {
      return [pscustomobject]@{ State = 'indeterminate'; RefName = $refName; CommitOid = '' }
    }
    if ([string]::Equals($storedRef, $refName, [System.StringComparison]::OrdinalIgnoreCase)) {
      $foldedMatchCount++
      if ([string]::Equals($storedRef, $refName, [System.StringComparison]::Ordinal)) {
        $exactSpelling = $true
        $directOid = $storedOid
      }
    }
  }
  if ($foldedMatchCount -eq 0) {
    return [pscustomobject]@{ State = 'missing'; RefName = $refName; CommitOid = '' }
  }
  if ($foldedMatchCount -ne 1 -or -not $exactSpelling) {
    return [pscustomobject]@{ State = 'case-collision'; RefName = $refName; CommitOid = '' }
  }

  $commitRows = @()
  $commitExit = -1
  try {
    $commitRows = @(& git rev-parse --verify "$directOid`^{commit}" 2>$null)
    $commitExit = $LASTEXITCODE
  } catch {
    $commitRows = @()
    $commitExit = -1
  }
  $commitOid = if ($commitRows.Count -eq 1) { ([string]$commitRows[0]).Trim() } else { '' }
  if ($commitExit -ne 0 -or $commitRows.Count -ne 1 -or $commitOid -notmatch $oidPattern) {
    return [pscustomobject]@{ State = 'not-commit'; RefName = $refName; CommitOid = '' }
  }
  return [pscustomobject]@{ State = 'valid'; RefName = $refName; CommitOid = $commitOid }
}

# Launch ONE review-wrapper child and make its exit code DETERMINISTIC to read
# back, closing the PowerShell 5.1 `Start-Process -PassThru` quirk (observed live):
# `.ExitCode` returns $null after WaitForExit() unless the process
# HANDLE was accessed before the process exited. We fix that two ways at once,
# mirroring the codex wrapper's own proven idiom (scripts/codex/auto-review.ps1
# pass-runner: pre-seed an exit file, child writes $LASTEXITCODE into it, parent
# reads the FILE):
#   (1) An exit-FILE carries the child's deterministic claimed result. We
#       pre-seed it with a non-zero
#       '999' sentinel BEFORE launch, so a child that dies before recording its
#       real code still leaves a fail-closed marker (Resolve-ReviewChildExit
#       rejects any value outside {0,1,2,3,4} as $null -> fail closed). The
#       generated runner re-issues the SAME
#       `powershell.exe -File <wrapper> <args>` invocation the parent used to make
#       directly, captures that child's $LASTEXITCODE, and writes it to the file.
#       Routing the wrapper through `powershell.exe` (an EXE) inside the runner
#       lets the runner SURVIVE the wrapper's `exit N` to record the code -- a
#       direct `& <wrapper.ps1>` would terminate the runner on the wrapper's exit
#       before it could write the file.
#   (2) `$null = $proc.Handle` is cached on the RUNNER process the instant it is
#       spawned, making the in-memory `.ExitCode` reliable. The caller USES that
#       via Test-ChildExitConsistency as a TAMPER CHECK: the exit file is a
#       mutable default-ACL input, so a readable handle .ExitCode that MISMATCHES
#       the file value means the file cannot be trusted -> the merge FAILS CLOSED
#       (the handle is NOT file-backed, so it is the tamper detector). The runner
#       is a thin shim ending in `exit $code` with the same $code it wrote, so the
#       two sources agree under normal operation. A launch failure or unreadable
#       .ExitCode has no immutable process provenance for the mutable exit file,
#       so Test-ChildExitConsistency refuses every value, including 0 and 4.
# The args are passed via a per-child args FILE (one token per line, UTF-8
# no-BOM), exactly like the codex wrapper's codex-args.txt, so the wrapper's
# multi-word -Title survives without any nested Start-Process arg-quoting. Every
# arg token here is a CLI flag, a fixed token, a %TEMP% path, the branch SHA, the
# ValidateSet effort tier, or the single multi-word -Title -- none can contain a
# newline, so line-delimited round-trips losslessly. Child stdout/stderr go to
# separate run-owned captures: no provider/routing detail reaches a successful
# caller, while a failed final outcome can replay bounded evidence. Returns a
# PSCustomObject { Proc; ExitFile; StdoutFile; StderrFile } the caller waits on,
# resolves via Resolve-ReviewChildExit, and retains for failure replay.
function Start-ReviewChild {
  param(
    [Parameter(Mandatory = $true)][string]$RunDir,
    [Parameter(Mandatory = $true)][string[]]$WrapperArgs,
    [Parameter(Mandatory = $true)][System.Text.Encoding]$Utf8NoBom
  )
  $argsFile   = Join-Path $RunDir 'child-args.txt'
  $exitFile   = Join-Path $RunDir 'child-exit.txt'
  $runnerPath = Join-Path $RunDir 'child-runner.ps1'
  $stdoutFile = Join-Path $RunDir 'child-stdout.log'
  $stderrFile = Join-Path $RunDir 'child-stderr.log'

  # Serialize the wrapper argv (one token per line) for the runner to reconstruct.
  [System.IO.File]::WriteAllLines($argsFile, [string[]]$WrapperArgs, $Utf8NoBom)
  # Pre-seed the exit file with a fail-closed sentinel BEFORE launch.
  [System.IO.File]::WriteAllText($exitFile, '999', $Utf8NoBom)
  # Create both captures before launch. A launch failure then still has an
  # explicit empty transcript rather than an ambiguous missing-file state.
  [System.IO.File]::WriteAllText($stdoutFile, '', $Utf8NoBom)
  [System.IO.File]::WriteAllText($stderrFile, '', $Utf8NoBom)

  # ASCII-only runner body (the wrapper file is BOM-less UTF-8 read as ANSI by
  # PS 5.1, so non-ASCII here would mojibake). It reads the argv array, invokes
  # the wrapper as a SEPARATE powershell.exe child (so the wrapper's `exit N`
  # becomes that child's exit code, captured in $LASTEXITCODE without killing the
  # runner), records the code to child-exit.txt, and exits with it.
  $runnerBody = @'
$ErrorActionPreference = 'Continue'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$work      = $PSScriptRoot
$argsFile  = Join-Path $work 'child-args.txt'
$exitFile  = Join-Path $work 'child-exit.txt'
$wrapperArgs = [System.IO.File]::ReadAllLines($argsFile, $utf8NoBom)
# auto-merge pins graph metadata after proving the target repository complete,
# but each base-extracted wrapper owns and re-proves its own boundary. Clear
# every raw spelling before launch so an older strict wrapper does not reject
# the parent's safe sentinels and a current wrapper observes default shallow
# state before installing its own sentinel.
$historyBoundaryNames = @('GIT_GRAFT_FILE', 'GIT_SHALLOW_FILE')
$rawEnvironment = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
foreach ($rawName in @($rawEnvironment.Keys)) {
  foreach ($boundaryName in $historyBoundaryNames) {
    if ([string]::Equals([string]$rawName, $boundaryName, [System.StringComparison]::OrdinalIgnoreCase)) {
      [Environment]::SetEnvironmentVariable([string]$rawName, $null, [EnvironmentVariableTarget]::Process)
    }
  }
}
$remainingEnvironment = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
foreach ($rawName in @($remainingEnvironment.Keys)) {
  foreach ($boundaryName in $historyBoundaryNames) {
    if ([string]::Equals([string]$rawName, $boundaryName, [System.StringComparison]::OrdinalIgnoreCase)) {
      [System.IO.File]::WriteAllText($exitFile, '999', $utf8NoBom)
      exit 999
    }
  }
}
$noReplaceName = 'GIT_NO_REPLACE_OBJECTS'
try {
  if (-not ('CrgProcessNoReplaceEnvironment.NativeV1' -as [type])) {
    Add-Type -TypeDefinition @"
namespace CrgProcessNoReplaceEnvironment {
  using System;
  using System.Collections.Generic;
  using System.ComponentModel;
  using System.Runtime.InteropServices;

  public static class NativeV1 {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetEnvironmentStringsW();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeEnvironmentStringsW(IntPtr environmentBlock);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetEnvironmentVariableW(string name, string value);

    public static string[] ReadProcessEntries() {
      IntPtr block = GetEnvironmentStringsW();
      if (block == IntPtr.Zero) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "GetEnvironmentStringsW failed");
      }
      Exception pending = null;
      try {
        List<string> entries = new List<string>();
        IntPtr cursor = block;
        while (true) {
          string entry = Marshal.PtrToStringUni(cursor);
          if (entry == null) {
            throw new InvalidOperationException("raw environment block contained an unreadable entry");
          }
          if (entry.Length == 0) { break; }
          entries.Add(entry);
          cursor = IntPtr.Add(cursor, checked((entry.Length + 1) * 2));
        }
        return entries.ToArray();
      } catch (Exception ex) {
        pending = ex;
        throw;
      } finally {
        if (!FreeEnvironmentStringsW(block) && pending == null) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "FreeEnvironmentStringsW failed");
        }
      }
    }

    private static void ValidateName(string name) {
      if (String.IsNullOrEmpty(name) || name.IndexOf('\0') >= 0 || name.IndexOf('=') >= 0) {
        throw new ArgumentException("environment variable names must be non-empty, NUL-free, and '='-free", "name");
      }
    }

    private static void ValidateValue(string value) {
      if (value == null || value.IndexOf('\0') >= 0) {
        throw new ArgumentException("environment variable values must be non-null and NUL-free", "value");
      }
    }

    public static void SetProcessVariable(string name, string value) {
      ValidateName(name);
      ValidateValue(value);
      if (!SetEnvironmentVariableW(name, value)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetEnvironmentVariableW failed for " + name);
      }
    }

    public static void RemoveProcessVariable(string name) {
      ValidateName(name);
      if (!SetEnvironmentVariableW(name, null)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetEnvironmentVariableW removal failed for " + name);
      }
    }
  }
}
"@ -Language CSharp -ErrorAction Stop
  }
  function Get-RunnerRawNoReplaceMatches {
    $runnerMatches = New-Object 'System.Collections.Generic.List[object]'
    [string[]]$runnerEntries = [CrgProcessNoReplaceEnvironment.NativeV1]::ReadProcessEntries()
    if ($null -eq $runnerEntries) { throw 'raw environment enumeration returned null' }
    foreach ($runnerEntry in $runnerEntries) {
      if ([string]::IsNullOrEmpty($runnerEntry) -or $runnerEntry.IndexOf([char]0) -ge 0) {
        throw 'raw environment entry is empty or contains NUL'
      }
      $runnerSeparator = if ($runnerEntry.StartsWith('=', [System.StringComparison]::Ordinal)) {
        $runnerEntry.IndexOf('=', 1, [System.StringComparison]::Ordinal)
      } else { $runnerEntry.IndexOf('=', [System.StringComparison]::Ordinal) }
      $runnerMinimum = if ($runnerEntry.StartsWith('=', [System.StringComparison]::Ordinal)) { 1 } else { 0 }
      if ($runnerSeparator -le $runnerMinimum) { throw 'raw environment entry does not use name=value grammar' }
      $runnerName = $runnerEntry.Substring(0, $runnerSeparator)
      if ([string]::Equals($runnerName, $noReplaceName, [System.StringComparison]::OrdinalIgnoreCase)) {
        $runnerMatches.Add([pscustomobject]@{
          Name = $runnerName
          Value = $runnerEntry.Substring($runnerSeparator + 1)
        }) | Out-Null
      }
    }
    return $runnerMatches.ToArray()
  }
  while ($true) {
    $beforeNoReplace = @(Get-RunnerRawNoReplaceMatches)
    if ($beforeNoReplace.Count -eq 0) { break }
    $removeName = [string]$beforeNoReplace[0].Name
    [CrgProcessNoReplaceEnvironment.NativeV1]::RemoveProcessVariable($removeName)
    $afterNoReplace = @(Get-RunnerRawNoReplaceMatches)
    if ($afterNoReplace.Count -ge $beforeNoReplace.Count) {
      throw "replacement-suppression removal made no progress for '$removeName'"
    }
  }
  $remainingNoReplace = @(Get-RunnerRawNoReplaceMatches)
  if ($remainingNoReplace.Count -ne 0) { throw 'replacement-suppression spelling survived raw removal' }
  [CrgProcessNoReplaceEnvironment.NativeV1]::SetProcessVariable($noReplaceName, '1')
  $finalNoReplace = @(Get-RunnerRawNoReplaceMatches)
  if ($finalNoReplace.Count -ne 1 -or
      -not [string]::Equals([string]$finalNoReplace[0].Name, $noReplaceName, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals([string]$finalNoReplace[0].Value, '1', [System.StringComparison]::Ordinal)) {
    throw 'replacement-suppression singleton postcondition failed'
  }
} catch {
  [System.IO.File]::WriteAllText($exitFile, '999', $utf8NoBom)
  exit 999
}
& powershell.exe @wrapperArgs
$code = $LASTEXITCODE
if ($null -eq $code) { $code = 999 }
[System.IO.File]::WriteAllText($exitFile, ([string]$code), $utf8NoBom)
exit $code
'@
  [System.IO.File]::WriteAllText($runnerPath, $runnerBody, $Utf8NoBom)

  $runnerArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runnerPath)
  # Catch a Start-Process LAUNCH failure explicitly (and SEPARATELY from handle
  # caching -- see below). The script runs under $ErrorActionPreference='Stop',
  # so a launch throw would otherwise abort this function BEFORE it returns -- the
  # caller's slot-child variable would never be assigned and control would
  # route to the outer catch. Catching it and returning the sentinel-backed object
  # (Proc=$null, ExitFile = the pre-seeded '999' file) keeps the contract uniform:
  # the caller ALWAYS gets an object, Resolve-ReviewChildExit reads the '999'
  # sentinel -> $null -> fail closed. So a failed launch of a REQUIRED child fails
  # the merge closed via the normal resolve path rather than an opaque outer-catch.
  $proc = $null
  # Capture the effective PATH before Normalize collapses the Path/PATH duplicate
  # surface for the Start-Process env-block build; restore it in the finally after
  # the child has inherited the collapsed block at launch, so the mutation does not
  # persist into a dot-sourced / persistent-session caller (same restore discipline
  # as the commit wrappers). The capture preserves effective lookup order first and
  # appends deterministic raw-only additions, so restoration keeps every directory
  # without changing which executable wins. Canonical restoration verifies exactly
  # one raw `Path` spelling and the expected value.
  $savedNormalizePath = (Get-UnionProcessPathParts -Spellings (Get-ProcessPathSpellings)) -join [System.IO.Path]::PathSeparator
  try {
    Set-CrgNoReplaceObjects
    Normalize-ProcessPathEnvForStartProcess
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList (Convert-ToProcArgString -ArgList $runnerArgs) -NoNewWindow -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -ErrorAction Stop
  } catch {
    Write-Host "[auto-merge] WARNING: failed to launch the review runner ($($_.Exception.Message)) - the pre-seeded '999' sentinel in '$exitFile' will drive a fail-closed resolution."
    $proc = $null
  } finally {
    if (-not [string]::IsNullOrEmpty($savedNormalizePath)) {
      # -ErrorAction Stop + inner try/catch so a provider failure is DIAGNOSED
      # (matches the commit wrappers' restore path) rather than silently leaving
      # the session PATH modified. The inner catch keeps the throw from escaping
      # this finally (which would otherwise mask any in-flight exception).
      try {
        Set-CanonicalProcessPathEnvironment -Value $savedNormalizePath
      } catch { Write-Warning "[auto-merge] failed to restore process PATH after the review launch ($($_.Exception.Message)); later commands in this session may retain the collapsed Path spelling." }
    }
  }
  # Handle caching is a SEPARATE concern with a SEPARATE catch. If the launch
  # SUCCEEDED ($proc not null) but accessing .Handle throws, the child is STILL
  # ALIVE -- it must NOT be nulled out (that would orphan a running process and
  # let the caller skip WaitForExit and let finally delete its scratch dir
  # mid-run). The handle cache is only a belt for the in-memory .ExitCode; the
  # child must still be retained and joined. A handle-cache failure is therefore
  # non-fatal at launch time, but Test-ChildExitConsistency later refuses the
  # result if .ExitCode remains unreadable: the mutable file cannot establish
  # PASS or fallback eligibility without immutable process provenance.
  if ($null -ne $proc) {
    try { $null = $proc.Handle }
    catch { Write-Host "[auto-merge] WARNING: could not cache the review runner's process handle ($($_.Exception.Message)) - the child is still live (kept), but an unreadable .ExitCode after join will fail the review closed." }
  }
  [PSCustomObject]@{ Proc = $proc; ExitFile = $exitFile; StdoutFile = $stdoutFile; StderrFile = $stderrFile }
}

# Resolve a review child's claimed exit code from its run-owned exit FILE
# after the caller has WaitForExit()'d. Missing / empty / unparsable file, OR a
# parsed value outside the readable wrapper-code set {0,1,2,3,4} (e.g. the '999' crash
# sentinel) => $null, which the caller MUST treat as fail-closed (it aborts the
# merge on a $null). $BackendName + the file path are surfaced in the loud
# diagnostic so an operator can inspect the run dir. PURE-ish (reads one file).
function Resolve-ReviewChildExit {
  param(
    [Parameter(Mandatory = $true)][string]$ExitFile,
    [Parameter(Mandatory = $true)][string]$BackendName
  )
  if (-not (Test-Path -LiteralPath $ExitFile)) {
    Write-Host "[auto-merge] $BackendName review exit file MISSING ($ExitFile) - treating as fail-closed."
    return $null
  }
  $raw = ''
  try {
    $raw = ([System.IO.File]::ReadAllText($ExitFile, [System.Text.Encoding]::UTF8)).Trim()
  } catch {
    Write-Host "[auto-merge] $BackendName review exit file UNREADABLE ($ExitFile): $($_.Exception.Message) - treating as fail-closed."
    return $null
  }
  $parsed = 0
  if (-not [int]::TryParse($raw, [ref]$parsed)) {
    Write-Host "[auto-merge] $BackendName review exit file UNPARSABLE (got '$raw' from $ExitFile) - treating as fail-closed."
    return $null
  }
  # Only {0,1,2,3,4} are readable wrapper codes (0 = PASS incl. non-blocking QUALITY,
  # 2 = BLOCKER, 3 = fail-closed; 1 is the RETIRED QUALITY code -- readback-recognized
  # but rejected as an invalid verdict by the later {0,2} union check; 4 is
  # positively-identified token exhaustion -- readback-recognized so the
  # fallback substitution can consume it, while the {0,2} union still rejects
  # any 4 that escapes substitution). Anything else
  # -- the pre-seeded '999' sentinel left when the
  # runner crashed before recording a real code, or any other garbage -- means
  # the child never produced a verdict. Fail closed loudly, naming the file. The
  # exit-3 pass-through is deliberate: it preserves the wrapper's own
  # fail-closed code so the caller's backend-specific exit-3 handling still fires.
  if ($parsed -notin @(0, 1, 2, 3, 4)) {
    Write-Host "[auto-merge] $BackendName review exit file holds non-verdict code $parsed (from $ExitFile; '999' is the runner's crash sentinel) - treating as fail-closed."
    return $null
  }
  return $parsed
}

# Tamper-resistant cross-check between the exit FILE and the handle-cached process
# .ExitCode (the reason `$null = $proc.Handle` is accessed at spawn). The runner
# is a thin shim ending in `exit $code` with the SAME $code it wrote to the file,
# so under normal operation handle.ExitCode == file value ALWAYS. The exit file
# lives under default-ACL $env:TEMP and is therefore a MUTABLE input: a same-user
# process could overwrite it. The process .ExitCode is NOT file-backed, so it is
# the tamper detector. RETURNS:
#   $true  -- one readable process exit MATCHES the file value (or FileExit is
#             already null and the caller will fail closed independently).
#   $false -- the process never launched, its exit is unreadable, or a readable
#             process exit MISMATCHES the file. The mutable file alone can never
#             mint PASS or fallback eligibility after a launch/provenance loss.
# A $null FileExit is not cross-checked (the caller already fails closed on it).
function Test-ChildExitConsistency {
  param(
    [Parameter(Mandatory = $true)][string]$BackendName,
    $FileExit,                                   # int or $null (from Resolve-ReviewChildExit)
    $Proc                                        # System.Diagnostics.Process or $null
  )
  if ($null -eq $Proc) {
    Write-Host "[auto-merge] SECURITY: $BackendName review process handle is null (Start-Process failed) - no process provenance exists for the mutable exit file (file=$(if ($null -eq $FileExit){'null'}else{$FileExit})); failing closed."
    return $false
  }
  $handleExit = $null
  try { $handleExit = $Proc.ExitCode } catch { $handleExit = $null }
  if ($null -eq $handleExit) {
    Write-Host "[auto-merge] SECURITY: $BackendName review process .ExitCode is unreadable despite the cached handle - no immutable process result can corroborate the mutable exit file (file=$(if ($null -eq $FileExit){'null'}else{$FileExit})); failing closed."
    return $false
  }
  # Only cross-check when the file produced a usable verdict code. A $null FileExit
  # already failed closed at the call site, where the raw handle value differing
  # is expected (the file was rejected) -- not a tamper signal.
  if ($null -ne $FileExit -and $handleExit -ne $FileExit) {
    Write-Host "[auto-merge] SECURITY: $BackendName review exit-code MISMATCH (file=$FileExit, handle=$handleExit) - the run-owned exit file disagrees with the live process exit code. The file is a mutable input; this divergence (tamper, or a runner that exited differently than it recorded) means the file value cannot be trusted -> failing the merge CLOSED."
    return $false
  }
  return $true
}

# ---------------------------------------------------------------------------
# Non-pure runtime helpers: Git-backed log-directory resolution, artifact
# centralization with preservation on failure, and follow-up promotion.
# ---------------------------------------------------------------------------

# Local-install shape verification (docs/local-install-v1.md): a gate
# file that is UNTRACKED and deliberately IGNORED verifies against the
# operator-written install manifest in the per-worktree git dir instead of a
# tree. Returns the verified file's BYTES -- a snapshot: the same read
# is hashed and handed to the caller, closing the verify-then-consume
# race -- or $null. Fail-closed at every step, LF-only manifest grammar
# (any CR byte refuses the whole manifest); the git probes run under an
# EAP scoped to Continue (EAP=Stop turns a native stderr line through a
# redirection into a terminating error in exactly the failure states
# probed for), and the tracked probe LISTS the path instead of using
# --error-unmatch. Local authority additionally requires the
# operator-written byte-exact authorization marker beside the manifest
# (docs/local-install-v1.md section 2): every full install writes a
# manifest (tracked installs use it for refresh-drift reporting), so
# the manifest alone must never admit local fallback -- a candidate
# commit could untrack and ignore the gate files without any operator
# act.
function Get-CrgLocalInstallVerifiedBytes {
  param([string]$RelPath)
  $lvPrevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
  # ROOT-RELATIVE semantics throughout: $RelPath is repo-root relative,
  # but a plain ls-files/check-ignore pathspec resolves against the
  # CWD -- a subdirectory invocation would probe <subdir>/$RelPath (or
  # an ignored decoy there) while the byte read below hashes the root
  # file. The top level resolves FIRST and every probe runs -C there.
  $lvTop = [string]@(& git rev-parse --show-toplevel 2>$null)[0]
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($lvTop)) { return $null }
  $lvTracked = @(& git -C $lvTop ls-files --cached -- $RelPath 2>$null)
  if ($LASTEXITCODE -ne 0 -or $lvTracked.Count -gt 0) { return $null }
  & git -C $lvTop check-ignore -q -- $RelPath 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  # PER-WORKTREE git dir (docs/local-install-v1.md section 2): the
  # verified gate files are worktree-local, so a common-dir manifest
  # would let one worktree's reseal or refresh silently invalidate
  # every sibling worktree's baseline.
  $lvGitDir = [string]@(& git -C $lvTop rev-parse --absolute-git-dir 2>$null)[0]
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($lvGitDir)) { return $null }
  $lvManifest = Join-Path $lvGitDir 'crg-install-manifest'
  if (-not (Test-Path -LiteralPath $lvManifest -PathType Leaf)) { return $null }
  try { $lvMBytes = [System.IO.File]::ReadAllBytes($lvManifest) } catch { return $null }
  # LOCAL-SHAPE AUTHORIZATION marker, EPOCH-BOUND and PER-COMPONENT:
  # line 2 pins the SHA-256 of the CURRENT manifest bytes (a marker
  # minted for an earlier local epoch dies when any install or reseal
  # republishes the manifest -- a candidate cannot replay an old
  # authorization against a new baseline), and the remaining lines are
  # the AUTHORIZED PATH SET, so a hybrid layout authorizes exactly its
  # local components. Written only by an operator bootstrap or reseal,
  # revoked in place when no local component is observed; the consumed
  # path must be listed. Same byte domain as the manifest.
  $lvAuth = Join-Path $lvGitDir 'crg-local-install'
  if (-not (Test-Path -LiteralPath $lvAuth -PathType Leaf)) { return $null }
  try { $lvABytes = [System.IO.File]::ReadAllBytes($lvAuth) } catch { return $null }
  foreach ($lvAB in $lvABytes) { if (-not (($lvAB -eq 0x0A) -or ($lvAB -ge 0x20 -and $lvAB -le 0x7E))) { return $null } }
  $lvMHash = $null
  try {
    $lvMSha = [System.Security.Cryptography.SHA256]::Create()
    try { $lvMHash = ([System.BitConverter]::ToString($lvMSha.ComputeHash($lvMBytes)) -replace '-', '').ToLowerInvariant() } finally { $lvMSha.Dispose() }
  } catch { return $null }
  $lvALines = ([System.Text.Encoding]::UTF8.GetString($lvABytes)) -split "`n"
  if ($lvALines.Count -lt 4) { return $null }
  if (-not [string]::Equals($lvALines[0], 'crg-local-install-authorization v1', [System.StringComparison]::Ordinal)) { return $null }
  if (-not [string]::Equals($lvALines[1], "manifest-sha256: $lvMHash", [System.StringComparison]::Ordinal)) { return $null }
  if ($lvALines[$lvALines.Count - 1].Length -ne 0) { return $null }
  $lvAFound = $false
  for ($lvAi = 2; $lvAi -lt $lvALines.Count - 1; $lvAi++) {
    if ($lvALines[$lvAi].Length -eq 0) { return $null }
    if ([string]::Equals($lvALines[$lvAi], $RelPath, [System.StringComparison]::Ordinal)) { $lvAFound = $true }
  }
  if (-not $lvAFound) { return $null }
  # Byte domain: printable ASCII (0x20-0x7E) plus LF only, enforced on
  # RAW BYTES before any decode -- PowerShell's UTF-8 decode substitutes
  # U+FFFD for invalid sequences, so two distinct invalid byte paths
  # could collapse to one string here while the raw-byte sh readers keep
  # them distinct, splitting the accept set. CR sits outside the domain,
  # so the LF-only rule rides on the same check.
  foreach ($lvB in $lvMBytes) { if (-not (($lvB -eq 0x0A) -or ($lvB -ge 0x20 -and $lvB -le 0x7E))) { return $null } }
  $lvLines = ([System.Text.Encoding]::UTF8.GetString($lvMBytes)) -split "`n"
  # ORDINAL string operations only: PowerShell's -ceq/-cne are
  # culture-sensitive (a culture-ignorable char like U+00AD compares
  # equal to its absence), which would accept headers and paths the
  # LC_ALL=C sh readers refuse.
  if ($lvLines.Count -lt 3 -or -not ([string]::Equals($lvLines[0], 'crg-install-manifest v1', [System.StringComparison]::Ordinal) -or [string]::Equals($lvLines[0], 'crg-install-manifest v2', [System.StringComparison]::Ordinal))) { return $null }
  if ($lvLines[1] -cnotmatch '^installed: [0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$') { return $null }
  # STRICT whole-file grammar, kept IDENTICAL to every other manifest
  # reader (sh crg_local_manifest_want, bootstrap Read-CrgInstallManifest):
  # every entry line is exactly <64-hex><two spaces><path not starting
  # with a space>; any junk line, any duplicate path, or a missing
  # `installed: ` record refuses the WHOLE manifest -- a tolerant reader
  # here would accept a manifest a stricter stage later refuses,
  # splitting one trust decision in two. ORDINAL comparer: a literal
  # @{} compares keys case-insensitively, which would call `a/b` and
  # `A/b` duplicates while awk's seen[] under LC_ALL=C keeps them
  # distinct -- paths compare byte-exact in every runtime.
  $lvWant = ''
  $lvSeen = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  for ($lvI = 2; $lvI -lt $lvLines.Count; $lvI++) {
    $lvLn = $lvLines[$lvI]
    if ($lvLn.Length -eq 0 -and $lvI -eq $lvLines.Count - 1) { continue }
    if ($lvLn -cnotmatch '^([0-9a-f]{64})  ([^ ].*)$') { return $null }
    if ($lvSeen.ContainsKey($Matches[2])) { return $null }
    $lvSeen[$Matches[2]] = $true
    if ([string]::Equals($Matches[2], $RelPath, [System.StringComparison]::Ordinal)) { $lvWant = $Matches[1] }
  }
  if ([string]::IsNullOrEmpty($lvWant)) { return $null }
  $lvFull = Join-Path $lvTop $RelPath
  if (-not (Test-Path -LiteralPath $lvFull -PathType Leaf)) { return $null }
  try { $lvFBytes = [System.IO.File]::ReadAllBytes($lvFull) } catch { return $null }
  try {
    $lvSha = [System.Security.Cryptography.SHA256]::Create()
    try { $lvGot = ([System.BitConverter]::ToString($lvSha.ComputeHash($lvFBytes)) -replace '-', '').ToLowerInvariant() }
    finally { $lvSha.Dispose() }
  } catch { return $null }
  if (-not [string]::Equals($lvGot, $lvWant, [System.StringComparison]::Ordinal)) { return $null }
  return ,$lvFBytes
  } finally { $ErrorActionPreference = $lvPrevEap }
}

# ---------------------------------------------------------------------------
# Post-merge audit quoting + summary helpers (PURE). The non-gating audit builds
# a PowerShell command to invoke the trusted worker-audit.ps1 copy and parses
# the child's console summary. Quoting or summary errors would silently degrade
# the required landing audit to a warning/no-report path.
# ---------------------------------------------------------------------------

# Wrap a value as a PowerShell SINGLE-QUOTED literal (double embedded apostrophes,
# the only metachar inside single quotes), returning the value WITH its surrounding
# quotes, so a path/arg containing an apostrophe survives intact in the `-Command`
# string built below.
function ConvertTo-PSSingleQuotedLiteral {
  param([string]$Value)
  return "'" + (([string]$Value) -replace "'", "''") + "'"
}

# Build the comma-joined single-quoted literal list for `-ReviewsDir` from a dir
# array. Each dir is its OWN quoted literal (ConvertTo-PSSingleQuotedLiteral) and
# the join comma sits OUTSIDE the quotes, so the `-Command` form binds a REAL
# array whose elements worker-audit takes VERBATIM (its array parameter never
# splits an element; the comma-splitting form is its separate -ReviewsDirCsv) --
# a run-dir PATH containing a COMMA (a valid `$env:TEMP` char on Windows)
# reaches it unshattered.
function Build-ReviewDirLiteralList {
  param([string[]]$Dirs)
  return (($Dirs | ForEach-Object { ConvertTo-PSSingleQuotedLiteral -Value ([string]$_) }) -join ',')
}

# Compose the post-merge audit's `-ReviewsDir` input: the central logs that
# EXIST (worker-audit's explicit list is strict -- a missing explicit dir
# aborts the audit -- and a single-backend install lacks one central dir, so
# absence is filtered here and named) plus the EFFECTIVE verdict panel's
# run-owned dirs. Superseded panels remain registered for later centralization,
# but must not make this caller-facing audit announce hidden routing. Duplicates
# collapse; order is preserved.
function Get-PostMergeAuditDirList {
  # The central dirs are RESOLVED to absolute paths through the same
  # git-common-dir resolution the wrappers centralize with
  # (Resolve-CentralLogDir), never tested relative to the process cwd: a
  # merge launched from a repository subdirectory would otherwise drop the
  # central history and audit the run-owned dirs alone.
  # A resolution FAILURE (the resolver throws or returns nothing) is not an
  # absence: the central history may exist yet cannot be located, so an
  # audit over the run-owned dirs alone would report an ABSENT commit-gate
  # corpus -- a false description of history that is present but
  # unreachable. The caller skips the audit loudly on ResolutionFailed;
  # only a RESOLVED path that does not exist is a confirmed absence.
  param([string[]]$CentralBackends, [string[]]$ChildDirs)
  $out = New-Object 'System.Collections.Generic.List[string]'
  $notes = New-Object 'System.Collections.Generic.List[string]'
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList @(,[System.StringComparer]::OrdinalIgnoreCase)
  $resolutionFailed = $false
  foreach ($b in @($CentralBackends)) {
    $c = $null
    $failed = $false
    try { $c = [string](Resolve-CentralLogDir -Backend $b) } catch { $failed = $true; $notes.Add('[auto-merge] (post-merge audit) a central review-log directory could not be RESOLVED (resolver error) - the audit is skipped rather than run without its history (NON-GATING).') }
    if (-not $failed -and [string]::IsNullOrWhiteSpace($c)) { $failed = $true; $notes.Add('[auto-merge] (post-merge audit) a central review-log directory could not be RESOLVED (no git common dir / top-level) - the audit is skipped rather than run without its history (NON-GATING).') }
    if ($failed) { $resolutionFailed = $true; continue }
    if (-not (Test-Path -LiteralPath $c -PathType Container)) {
      $notes.Add('[auto-merge] (post-merge audit) a central review-log directory is absent on this install - not passed to the audit (NON-GATING).')
      continue
    }
    if ($seen.Add($c)) { $out.Add($c) }
  }
  # A confirmed-absent central dir (a fresh install) does NOT withhold the
  # audit: the trusted audit runs after every successful ff-merge, and
  # worker-audit itself leads its report with the absent commit-gate corpus
  # (its counts tagged INCOMPLETE) -- a directory's presence is never the
  # test for whether history was examined.
  foreach ($d in @($ChildDirs)) {
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    if ($seen.Add($d)) { $out.Add($d) }
  }
  return [pscustomobject]@{ Dirs = $out.ToArray(); ResolutionFailed = $resolutionFailed; Notes = $notes.ToArray() }
}

# Extract the path line (`wrote report to`) and summary line (`AUTHORITATIVE:`)
# from the audit child's captured console text. Returns @{ PathLine; SumLine;
# SuspectLines; ErrorLines; UnclassifiedLines; WarningLines } with $null for an
# absent line -- both PathLine and SumLine $null is exactly what drives the
# caller's no-usable-summary WARNING path, so this parse decides whether the
# mandated audit reports or degrades to a warning. SuspectLines carries the
# audit's branch-correlated evidence-integrity errors (ErrorLines its
# operational ones): a suspect-led audit still exits 0, so its
# ERROR/UNRELIABLE stdout is the ONLY suspect signal that reaches this consumer -- dropping it
# would present suspect counts as a normal authoritative audit. WarningLines
# carries the audit's `[worker-audit] WARNING:` lines for the same reason (the
# quarantine and scan-failure warnings must reach the merge output).
function Get-AuditSummaryLines {
  param([string]$AuditText)
  $lines = @(([string]$AuditText) -split "`n")
  # ANCHORED to the producer's line grammar, never a phrase search. worker-audit
  # embeds UNTRUSTED artifact filenames in its warning payloads, and a verdict
  # name is free to contain "wrote report to" or "AUTHORITATIVE:" -- an
  # unanchored match let such a payload stand in for the real report path or
  # summary, so the consumer read diagnostic DATA as a protocol record
  # (merge-panel BLOCKER 2026-08-30). Every matcher below starts at the tag.
  $pathLine = @($lines | Where-Object { $_ -match '^\[worker-audit\] wrote report to ' }) | Select-Object -First 1
  $sumLine  = @($lines | Where-Object { $_ -match '^\[worker-audit\]\s+commits=\S+\s+.*AUTHORITATIVE:' }) | Select-Object -First 1
  # The audit's ERROR classes cross this boundary and must stay distinct: a
  # branch-correlated SUSPECT (a verdict artifact this branch owns is
  # fail-closed, malformed, unreadable, or names this tip while carrying a
  # mismatched review tree -- possible gate bypass) and an OPERATIONAL error
  # (an absent corpus, a failed enumeration, a non-monotonic history, an
  # unresolvable dir). Relabeling the second as SUSPECT would claim a suspect
  # verdict artifact that does not exist; relabeling the first as operational
  # hides a possible bypass.
  #
  # The class is read from the PRODUCER'S OWN token (worker-audit's console
  # diagnostic contract stamps `[class:suspect]` / `[class:operational]` on
  # every ERROR line). This consumer never re-derives the class from prose: a prose matcher
  # only classifies the messages it was written against, so every message it
  # does not anticipate takes the fallthrough branch -- which is exactly how
  # the tip-named/tree-mismatched merge verdict was reported here as an
  # ordinary operational error (gate BLOCKER 2026-08-30).
  #
  # An ERROR line with NO token, or an unrecognized one, is a producer-contract
  # breach -- an older audit build, or a new emission that escaped the
  # producer's scan. It is surfaced on its own channel and treated as a
  # suspect, never as operational: presenting a possible gate-bypass signal as
  # routine is the unsafe direction.
  $errAll = @($lines | Where-Object { $_ -match '^\[worker-audit\] ERROR: ' })
  $suspectLines = @($errAll | Where-Object { $_ -match '^\[worker-audit\] ERROR: \[class:suspect\] ' })
  $errorLines = @($errAll | Where-Object { $_ -match '^\[worker-audit\] ERROR: \[class:operational\] ' })
  $unclassifiedLines = @($errAll | Where-Object { $_ -notmatch '^\[worker-audit\] ERROR: \[class:(suspect|operational)\] ' })
  $warningLines = @($lines | Where-Object { $_ -match '^\[worker-audit\] WARNING: ' })
  return [pscustomobject]@{ PathLine = $pathLine; SumLine = $sumLine; SuspectLines = $suspectLines; ErrorLines = $errorLines; UnclassifiedLines = $unclassifiedLines; WarningLines = $warningLines }
}

function Get-AuditTimeoutMessage {
  # Pure message composer for the post-merge-audit timeout path. Termination is
  # only CLAIMED on a CONFIRMED exit (post-kill bounded wait returned): a Kill() call is
  # asynchronous, and claiming "terminated" for a possibly-live child would hide
  # why the report never appeared AND mask the cleanup race the caller guards
  # via $auditChildUnconfirmed.
  param([bool]$ExitConfirmed, [int]$TimeoutSec)
  if ($ExitConfirmed) { return "[auto-merge] (post-merge audit) WARNING: worker-audit.ps1 exceeded ${TimeoutSec}s and was terminated (exit confirmed; NON-GATING; the merge already completed and verdict consolidation continues)." }
  return "[auto-merge] (post-merge audit) WARNING: worker-audit.ps1 exceeded ${TimeoutSec}s; termination was ATTEMPTED but its exit is UNCONFIRMED - the run/trusted dirs will be PRESERVED at cleanup (NON-GATING; the merge already completed and verdict consolidation continues)."
}

# The post-merge audit child's lifecycle: launch
# via Start-Process (output cannot be captured inline, so stdout/stderr go to
# run-owned capture files), a BOUNDED wait so a hung audit cannot stall the
# merge script, kill-then-CONFIRM on timeout (a non-throwing Kill() is
# asynchronous, so "kill returned" is not "child exited"; termination is only
# CLAIMED on a confirmed exit), both captures read back through the pinned
# reader, and the captures deleted ONLY when the exit is confirmed (an
# unconfirmed child may still be writing them, and they are the promised
# evidence inside the preserved run dir). The caller prints the returned
# messages, parses the stdout summary unless the child was Killed (a terminated
# child's output is partial by construction, while a child that completed on
# its own before a wait failure was noticed keeps its exit code and summary),
# and folds the unconfirmed-exit and bounded-capture flags into the finally's
# preservation decision; nothing here can affect the merge outcome.
function Invoke-PostMergeAuditChild {
  param([string]$Command, [int]$TimeoutSec, [string]$RunDir)
  $messages = New-Object 'System.Collections.Generic.List[string]'
  $guid = [guid]::NewGuid().ToString('N').Substring(0, 8)
  $stdoutFile = Join-Path $RunDir "worker-audit-out-$guid.txt"
  $stderrFile = Join-Path $RunDir "worker-audit-err-$guid.txt"
  $stdoutText = ''
  $stderrText = ''
  $exit = 0
  $timedOut = $false
  $killed = $false
  $unconfirmed = $false
  $proc = $null
  try {
    Set-CrgNoReplaceObjects
    # Quoted as one argv element: an unquoted -Command text would be re-split
    # by the child's argv parser and rejoined with single spaces, collapsing
    # whitespace runs inside the quoted path literals.
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList (Convert-ToProcArgString -ArgList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $Command)) -NoNewWindow -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
      $timedOut = $true
      $killed = $true
      # Process.Kill() ends only powershell.exe; the audit's native `git`
      # descendants would outlive it and a hang inside git would survive a
      # "confirmed" exit. The whole TREE is terminated (taskkill /T /F) and
      # the root's exit is then waited for; a taskkill failure falls back to
      # Kill() and leaves the exit UNCONFIRMED (the dirs are preserved).
      $exitConfirmed = $false
      try {
        $treeKill = & taskkill.exe /PID $proc.Id /T /F 2>&1
        if ($LASTEXITCODE -ne 0) { throw "taskkill /T exited $LASTEXITCODE ($(@($treeKill) -join ' '))" }
        if ($proc.WaitForExit(10000)) { $exitConfirmed = $true }
      } catch {
        $messages.Add("[auto-merge] (post-merge audit) WARNING: process-tree kill of the timed-out worker-audit.ps1 child FAILED ('$($_.Exception.Message)') - its descendants may still be running (NON-GATING).")
        try { $proc.Kill() } catch { }
      }
      if (-not $exitConfirmed) { $unconfirmed = $true }
      $messages.Add((Get-AuditTimeoutMessage -ExitConfirmed $exitConfirmed -TimeoutSec $TimeoutSec))
    } else {
      # PS 5.1 -PassThru `.ExitCode` can read $null even on a clean exit; treat
      # $null as 0 for the NON-GATING diagnostic (the merge is unaffected).
      $exit = if ($null -ne $proc.ExitCode) { [int]$proc.ExitCode } else { 0 }
    }
  } catch {
    if ($null -ne $proc) {
      # Launch SUCCEEDED but the wait path threw (odd host state) -- the child
      # may still be RUNNING: one bounded confirmation, and on any remaining
      # uncertainty the exit is unconfirmed (the finally preserves the dirs).
      $postLaunchConfirmed = $false
      try { if ($proc.HasExited -or $proc.WaitForExit(10000)) { $postLaunchConfirmed = $true } } catch { }
      if ($postLaunchConfirmed) {
        $exit =if ($null -ne $proc.ExitCode) { [int]$proc.ExitCode } else { 0 }
      } else {
        $killed = $true
        # Still live after the bounded wait: the same process-TREE termination
        # as the timeout branch, so an unbounded audit or native git descendant
        # cannot outlive the parent; only a confirmed exit clears the flag.
        try {
          $treeKill = & taskkill.exe /PID $proc.Id /T /F 2>&1
          if ($LASTEXITCODE -ne 0) { throw "taskkill /T exited $LASTEXITCODE ($(@($treeKill) -join ' '))" }
          if ($proc.WaitForExit(10000)) { $postLaunchConfirmed = $true }
        } catch {
          $messages.Add("[auto-merge] (post-merge audit) WARNING: process-tree kill of the still-running worker-audit.ps1 child FAILED ('$($_.Exception.Message)') - its descendants may still be running (NON-GATING).")
          try { $proc.Kill() } catch { }
        }
      }
      if (-not $postLaunchConfirmed) { $unconfirmed = $true }
      $confNote = if ($postLaunchConfirmed -and -not $killed) { 'exit confirmed (the child completed on its own; its summary is parsed)' } elseif ($postLaunchConfirmed) { 'exit confirmed after a process-tree kill (its output is partial and not parsed)' } else { 'exit UNCONFIRMED after a process-tree kill attempt; run/trusted dirs will be preserved at cleanup' }
      $messages.Add("[auto-merge] (post-merge audit) WARNING: post-launch failure while waiting on worker-audit.ps1 ('$($_.Exception.Message)') - $confNote (NON-GATING).")
    } else {
      $messages.Add("[auto-merge] (post-merge audit) WARNING: could not launch worker-audit.ps1 ('$($_.Exception.Message)') - NON-GATING.")
    }
  }
  $stdoutRead = Get-AuditCaptureRead -Path $stdoutFile -Label 'stdout' -Consequence 'summary unavailable'
  if ($null -ne $stdoutRead.Text) { $stdoutText = $stdoutRead.Text }
  if ($stdoutRead.Warning) { $messages.Add($stdoutRead.Warning) }
  $stderrRead = Get-AuditCaptureRead -Path $stderrFile -Label 'stderr' -Consequence 'child errors may be lost'
  if ($null -ne $stderrRead.Text) { $stderrText = $stderrRead.Text }
  if ($stderrRead.Warning) { $messages.Add($stderrRead.Warning) }
  # A capture the read had to BOUND is retained even on a clean exit: the
  # in-memory text is then a reduction, and deleting the file would destroy the
  # only complete copy of evidence the warning has just pointed the operator at.
  $captureBounded = ($stdoutRead.Bounded -or $stderrRead.Bounded)
  if (-not $unconfirmed -and -not $captureBounded) {
    Remove-Item -LiteralPath $stdoutFile -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stderrFile -ErrorAction SilentlyContinue
  }
  $procId = if ($null -ne $proc) { $proc.Id } else { 0 }
  return [pscustomobject]@{ Exit = $exit; TimedOut = $timedOut; Killed = $killed; Unconfirmed = $unconfirmed; CaptureBounded = $captureBounded; StdoutText = $stdoutText; StderrText = $stderrText; Messages = $messages.ToArray(); StdoutFile = $stdoutFile; StderrFile = $stderrFile; ProcessId = $procId }
}

function Get-AuditCaptureRead {
  # Read a child capture file, never swallowing a failure: a missing file
  # captures nothing and says nothing, while a read failure returns no text plus
  # a warning the caller surfaces ($Consequence names what is lost). Post-merge
  # audit wording remains the default; review-failure replay supplies its own
  # context and gating consequence; failures never silently become an empty catch.
  #
  # BOUNDED IN BYTES, BEFORE any allocation. The child emits one line per
  # correlated suspect, mismatched and quarantined artifact and its scan
  # cardinality is the log corpus, so the capture has no size limit of its own.
  # Reading it whole -- with ReadAllText, or line by line to EOF, which is the
  # same unbounded work plus an unbounded allocation per line -- happens INSIDE
  # the merge process, after the merge has landed but before the `finally` that
  # consolidates verdict artifacts, so an oversized capture can take the
  # process down between those two points and lose the consolidation
  # (merge-panel BLOCKER 2026-08-30, raised again after a line-count cap that
  # still scanned and allocated without limit).
  #
  # FIXED byte regions are read instead -- a head and a tail, seeked directly --
  # so the work and every allocation are capped by construction at
  # any capture size. Both ends: the consumer's protocol lines open
  # the run, while the report path and the authoritative summary are the LAST
  # lines the child writes, and a head-only policy made a successful audit look
  # summary-less. The partial line at each region's inner edge is dropped,
  # which also discards any UTF-8 sequence the byte cut split.
  #
  # A cutoff is NAMED and never silent, and the caller keeps the capture file
  # and the run dir whenever `Bounded` is set -- the complete evidence then
  # exists only there.
  param(
    [string]$Path,
    [string]$Label,
    [string]$Consequence,
    [int]$MaxHeadBytes = 262144,
    [int]$MaxTailBytes = 262144,
    [int]$MaxLineChars = 4096,
    [string]$ContextLabel = 'post-merge audit',
    [string]$CaptureNoun = 'audit',
    [bool]$NonGating = $true
  )
  $capPrefix = "[auto-merge] ($ContextLabel)"
  $capSuffix = if ($NonGating) { ' (NON-GATING).' } else { '.' }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]@{ Text = $null; Warning = $null; Bounded = $false } }
  try {
    $capStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $capLen = $capStream.Length
      $capElided = 0L
      if ($capLen -le ([long]$MaxHeadBytes + [long]$MaxTailBytes)) {
        $capWhole = New-Object byte[] ([int]$capLen)
        $capRead = 0
        while ($capRead -lt $capWhole.Length) {
          $capGot = $capStream.Read($capWhole, $capRead, $capWhole.Length - $capRead)
          if ($capGot -le 0) { break }
          $capRead += $capGot
        }
        $capHeadText = [System.Text.Encoding]::UTF8.GetString($capWhole, 0, $capRead)
        $capTailText = ''
      } else {
        $capElided = $capLen - [long]$MaxHeadBytes - [long]$MaxTailBytes
        $capHeadBuf = New-Object byte[] $MaxHeadBytes
        $capRead = 0
        while ($capRead -lt $MaxHeadBytes) {
          $capGot = $capStream.Read($capHeadBuf, $capRead, $MaxHeadBytes - $capRead)
          if ($capGot -le 0) { break }
          $capRead += $capGot
        }
        $capHeadText = [System.Text.Encoding]::UTF8.GetString($capHeadBuf, 0, $capRead)
        [void]$capStream.Seek(-([long]$MaxTailBytes), [System.IO.SeekOrigin]::End)
        $capTailBuf = New-Object byte[] $MaxTailBytes
        $capRead = 0
        while ($capRead -lt $MaxTailBytes) {
          $capGot = $capStream.Read($capTailBuf, $capRead, $MaxTailBytes - $capRead)
          if ($capGot -le 0) { break }
          $capRead += $capGot
        }
        $capTailText = [System.Text.Encoding]::UTF8.GetString($capTailBuf, 0, $capRead)
        # The head's last line and the tail's first line are both cut mid-line
        # by the byte boundary; a truncated protocol line would parse as a
        # complete one that simply said less.
        $capHeadCut = $capHeadText.LastIndexOf([char]10)
        $capHeadText = if ($capHeadCut -ge 0) { $capHeadText.Substring(0, $capHeadCut) } else { '' }
        $capTailCut = $capTailText.IndexOf([char]10)
        $capTailText = if ($capTailCut -ge 0) { $capTailText.Substring($capTailCut + 1) } else { '' }
      }
    } finally { $capStream.Dispose() }
    $capLines = New-Object 'System.Collections.Generic.List[string]'
    $capLongLines = 0
    # Indexed, never a value comparison to pick the tail: the regions can hold
    # identical text, and the elision marker must sit between them regardless.
    $capRegions = @($capHeadText, $capTailText)
    for ($capRi = 0; $capRi -lt $capRegions.Count; $capRi++) {
      $capRegion = [string]$capRegions[$capRi]
      if ([string]::IsNullOrEmpty($capRegion)) { continue }
      if ($capRi -eq 1 -and $capElided -gt 0) {
        $capLines.Add("$capPrefix ... $capElided byte(s) ELIDED by the capture read bound; the complete capture is the file named in the warning ...") | Out-Null
      }
      foreach ($capLine in ($capRegion -split "`r?`n")) {
        if ($capLine.Length -gt $MaxLineChars) {
          $capLines.Add($capLine.Substring(0, $MaxLineChars) + ' [...line truncated by the capture bound]') | Out-Null
          $capLongLines++
        } else {
          $capLines.Add($capLine) | Out-Null
        }
      }
    }
    $capBounded = ($capElided -gt 0 -or $capLongLines -gt 0)
    $capWarn = $null
    if ($capBounded) {
      $capWarn = "$capPrefix WARNING: the $CaptureNoun $Label capture exceeded the read bounds and was reduced in memory ($capElided byte(s) elided between the first $MaxHeadBytes and last $MaxTailBytes bytes, $capLongLines line(s) truncated at $MaxLineChars chars) - the COMPLETE capture is RETAINED at $Path$capSuffix"
    }
    return [pscustomobject]@{ Text = ($capLines.ToArray() -join [Environment]::NewLine); Warning = $capWarn; Bounded = $capBounded }
  }
  catch { return [pscustomobject]@{ Text = $null; Warning = "$capPrefix WARNING: could not read the $CaptureNoun $Label capture ('$($_.Exception.Message)') - $Consequence$capSuffix"; Bounded = $false } }
}

# Select only the panel that actually supplied the final verdict for the
# immediate caller-facing post-merge audit. Every primary and substituted
# artifact is still centralized in finally; excluding a superseded exhaustion
# panel here prevents the report-only audit from announcing hidden routing.
function Select-EffectiveReviewChildDirs {
  param(
    [string[]]$PrimaryDirs,
    [string[]]$SubstituteDirs,
    [bool]$Substituted
  )
  $selected = if ($Substituted) { @($SubstituteDirs) } else { @($PrimaryDirs) }
  foreach ($dir in $selected) {
    if (-not [string]::IsNullOrWhiteSpace($dir)) { $dir }
  }
}

$script:crgSuccessfulEvidenceNativeState = $null
function Initialize-CrgSuccessfulEvidenceNative {
  if ($null -ne $script:crgSuccessfulEvidenceNativeState) { return $script:crgSuccessfulEvidenceNativeState }
  try {
    if (-not ('CrgSuccessfulEvidence.NativeV1' -as [type])) {
      Add-Type -Namespace 'CrgSuccessfulEvidence' -Name 'NativeV1' -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
private struct FileTime {
  public uint Low;
  public uint High;
}

[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
private struct ByHandleFileInformation {
  public uint FileAttributes;
  public FileTime CreationTime;
  public FileTime LastAccessTime;
  public FileTime LastWriteTime;
  public uint VolumeSerialNumber;
  public uint FileSizeHigh;
  public uint FileSizeLow;
  public uint NumberOfLinks;
  public uint FileIndexHigh;
  public uint FileIndexLow;
}

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
[return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
private static extern bool GetFileInformationByHandle(
  Microsoft.Win32.SafeHandles.SafeFileHandle file,
  out ByHandleFileInformation information);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
private static extern uint GetFinalPathNameByHandle(
  Microsoft.Win32.SafeHandles.SafeFileHandle file,
  System.Text.StringBuilder path,
  uint pathChars,
  uint flags);

public static string GetVerifiedFinalPath(Microsoft.Win32.SafeHandles.SafeFileHandle file) {
  if (file == null || file.IsInvalid || file.IsClosed) return null;
  ByHandleFileInformation information;
  if (!GetFileInformationByHandle(file, out information)) return null;
  const uint Directory = 0x10;
  const uint ReparsePoint = 0x400;
  if ((information.FileAttributes & (Directory | ReparsePoint)) != 0) return null;

  System.Text.StringBuilder path = new System.Text.StringBuilder(32768);
  uint pathChars = GetFinalPathNameByHandle(file, path, (uint)path.Capacity, 0);
  if (pathChars == 0 || pathChars >= path.Capacity) return null;
  string finalPath = path.ToString();
  if (finalPath.StartsWith(@"\\?\UNC\", System.StringComparison.OrdinalIgnoreCase)) {
    finalPath = @"\\" + finalPath.Substring(8);
  } else if (finalPath.StartsWith(@"\\?\", System.StringComparison.OrdinalIgnoreCase)) {
    finalPath = finalPath.Substring(4);
  }
  return System.IO.Path.GetFullPath(finalPath);
}
'@ -ErrorAction Stop
    }
    $script:crgSuccessfulEvidenceNativeState = $true
  } catch {
    $script:crgSuccessfulEvidenceNativeState = $false
  }
  return $script:crgSuccessfulEvidenceNativeState
}

function Test-CrgSuccessfulEvidenceHandle {
  param(
    [Parameter(Mandatory = $true)][System.IO.FileStream]$Stream,
    [Parameter(Mandatory = $true)][string]$ExpectedPath
  )
  if (-not (Initialize-CrgSuccessfulEvidenceNative)) { return $false }
  try {
    $expectedFullPath = [System.IO.Path]::GetFullPath($ExpectedPath)
    $openedFullPath = [CrgSuccessfulEvidence.NativeV1]::GetVerifiedFinalPath($Stream.SafeFileHandle)
    return (-not [string]::IsNullOrEmpty($openedFullPath) -and
      [string]::Equals($openedFullPath, $expectedFullPath, [System.StringComparison]::OrdinalIgnoreCase))
  } catch {
    return $false
  }
}

# Convert one successful-review evidence file exactly once. Successful caller
# output is derived only from this bounded snapshot of a corroborated ordinary
# file handle, never from a later pathname reopen or from the wrapper's
# provider-bearing console transcript. UTF-8 BOMs, malformed sequences, CR line
# endings, and non-LF control characters are not emitted by the wrappers and
# therefore make the evidence indeterminate.
function Read-CrgSuccessfulReviewEvidence {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [int]$MaxBytes = 67108864,
    [switch]$AllowCrlf
  )
  try {
    if ($MaxBytes -lt 0) { return @{ Ok = $false; Code = 'file-shape'; Text = '' } }
    if (-not [System.IO.File]::Exists($Path)) { return @{ Ok = $false; Code = 'missing'; Text = '' } }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      return @{ Ok = $false; Code = 'file-shape'; Text = '' }
    }
    $stream = $null
    $memory = $null
    try {
      $stream = [System.IO.FileStream]::new($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan)
      # The lstat-like classification above is only a preflight. Bind the trust
      # decision to the held handle so a path replacement or parent redirection
      # between classification and open cannot substitute another file.
      if (-not (Test-CrgSuccessfulEvidenceHandle -Stream $stream -ExpectedPath $item.FullName)) {
        return @{ Ok = $false; Code = 'file-shape'; Text = '' }
      }
      $memory = [System.IO.MemoryStream]::new()
      $chunk = [byte[]]::new(65536)
      $total = 0L
      while (($read = $stream.Read($chunk, 0, $chunk.Length)) -gt 0) {
        $total += $read
        if ($total -gt $MaxBytes) { return @{ Ok = $false; Code = 'file-shape'; Text = '' } }
        $memory.Write($chunk, 0, $read)
      }
      $bytes = $memory.ToArray()
    } finally {
      if ($null -ne $memory) { $memory.Dispose() }
      if ($null -ne $stream) { $stream.Dispose() }
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
      return @{ Ok = $false; Code = 'encoding'; Text = '' }
    }
    $strict = [System.Text.UTF8Encoding]::new($false, $true)
    try { $text = $strict.GetString($bytes) }
    catch [System.Text.DecoderFallbackException] { return @{ Ok = $false; Code = 'encoding'; Text = '' } }
    if ($AllowCrlf) {
      $text = $text.Replace("`r`n", "`n")
      if ($text.Contains("`r")) { return @{ Ok = $false; Code = 'control'; Text = '' } }
    } elseif ($text.Contains("`r")) {
      return @{ Ok = $false; Code = 'control'; Text = '' }
    }
    foreach ($ch in $text.ToCharArray()) {
      $code = [int][char]$ch
      if ($code -eq 10) { continue }
      if ($code -lt 0x20 -or $code -eq 0x7F) { return @{ Ok = $false; Code = 'control'; Text = '' } }
    }
    return @{ Ok = $true; Code = ''; Text = $text }
  } catch {
    return @{ Ok = $false; Code = 'unreadable'; Text = '' }
  }
}

function Get-CrgSuccessfulReviewProjection {
  param(
    [Parameter(Mandatory = $true)][string[]]$ReviewDirs,
    [Parameter(Mandatory = $true)][string]$ExpectedTreeOid,
    [Parameter(Mandatory = $true)][string]$ExpectedDiffSha,
    [Parameter(Mandatory = $true)][string]$ExpectedTipPrefix,
    [Parameter(Mandatory = $true)][string]$ExpectedBasePrefix
  )
  $refuse = { param([string]$Code) @{ Ok = $false; Code = $Code; Lines = @() } }
  if ($ReviewDirs.Count -lt 1 -or
      $ExpectedTreeOid -cnotmatch '\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z' -or
      $ExpectedDiffSha -cnotmatch '\A[0-9a-f]{64}\z' -or
      $ExpectedTipPrefix -cnotmatch '\A[0-9a-f]{12}\z' -or
      $ExpectedBasePrefix -cnotmatch '\A[0-9a-f]{12}\z') {
    return (& $refuse 'expected-identity')
  }

  $visibility = $null
  $warningKey = $null
  $warnings = New-Object 'System.Collections.Generic.SortedSet[string]' ([System.StringComparer]::Ordinal)
  $findings = New-Object 'System.Collections.Generic.SortedSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($dir in $ReviewDirs) {
    if ([string]::IsNullOrWhiteSpace($dir) -or -not [System.IO.Directory]::Exists($dir)) {
      return (& $refuse 'review-dir')
    }
    $dirItem = $null
    try { $dirItem = Get-Item -LiteralPath $dir -Force -ErrorAction Stop } catch { return (& $refuse 'review-dir') }
    if (($dirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return (& $refuse 'review-dir') }
    $expectedBackend = ''
    $expectedTag = ''
    if ([string]::Equals($dirItem.Name, 'codex', [System.StringComparison]::Ordinal) -or [string]::Equals($dirItem.Name, 'codex-fb1', [System.StringComparison]::Ordinal)) {
      $expectedBackend = 'codex'
    } elseif ($dirItem.Name -cmatch '\Aclaude-(p[1-3]|fb[1-3])\z') {
      $expectedBackend = 'claude'
      $expectedTag = $Matches[1]
    } else {
      return (& $refuse 'review-dir-identity')
    }
    $artifactLeafPattern = if ($expectedTag.Length -eq 0) {
      "\Areview-[0-9]{8}-[0-9]{6}-branch-$ExpectedTipPrefix-vs-$ExpectedBasePrefix\.md\z"
    } else {
      "\Areview-[0-9]{8}-[0-9]{6}-branch-$ExpectedTipPrefix-vs-$ExpectedBasePrefix-$expectedTag\.md\z"
    }

    $capture = Read-CrgSuccessfulReviewEvidence -Path (Join-Path $dirItem.FullName 'child-stdout.log') -AllowCrlf
    if (-not $capture.Ok) { return (& $refuse ('capture-' + $capture.Code)) }
    $modeLines = New-Object 'System.Collections.Generic.List[string]'
    $childWarnings = New-Object 'System.Collections.Generic.SortedSet[string]' ([System.StringComparer]::Ordinal)
    $successPaths = New-Object 'System.Collections.Generic.List[string]'
    $semanticChars = 0
    foreach ($line in ($capture.Text -split "`n")) {
      $semantic = $null
      if ($line.StartsWith('[auto-review] project-mode: ', [System.StringComparison]::Ordinal)) {
        if ($expectedBackend -cne 'codex') { return (& $refuse 'provider-conflict') }
        $semantic = $line.Substring('[auto-review] '.Length)
      } elseif ($line.StartsWith('[auto-review:claude] project-mode: ', [System.StringComparison]::Ordinal)) {
        if ($expectedBackend -cne 'claude') { return (& $refuse 'provider-conflict') }
        $semantic = $line.Substring('[auto-review:claude] '.Length)
      }
      if ($null -ne $semantic) {
        if ($semantic.Length -gt 4096 -or $semantic -cnotmatch '\Aproject-mode: (?:GOVERNING mode=(?:prototype|stabilizing|shipped) campaign=.+ ref=[0-9a-f]{12}|ABSENT - shipped defaults|FALLBACK - shipped defaults; .+|INDETERMINATE - .+)\z') {
          return (& $refuse 'mode-shape')
        }
        $semanticChars += $semantic.Length
        [void]$modeLines.Add($semantic)
        continue
      }
      $warning = $null
      if ($line.StartsWith('[auto-review] project-mode WARN: ', [System.StringComparison]::Ordinal)) {
        if ($expectedBackend -cne 'codex') { return (& $refuse 'provider-conflict') }
        $warning = $line.Substring('[auto-review] '.Length)
      } elseif ($line.StartsWith('[auto-review:claude] project-mode WARN: ', [System.StringComparison]::Ordinal)) {
        if ($expectedBackend -cne 'claude') { return (& $refuse 'provider-conflict') }
        $warning = $line.Substring('[auto-review:claude] '.Length)
      }
      if ($null -ne $warning) {
        if ($warning.Length -gt 4096 -or $warning -cnotmatch '\Aproject-mode WARN: \S(?:.*\S)?\z') { return (& $refuse 'warning-shape') }
        $semanticChars += $warning.Length
        [void]$childWarnings.Add($warning)
        continue
      }
      if ($expectedBackend -ceq 'codex' -and $line -cmatch '\A\[auto-review\] [1-9][0-9]*-pass review -> (.+) \(per-pass concatenation \(deterministic\)\)\z') {
        [void]$successPaths.Add($Matches[1])
      } elseif ($expectedBackend -ceq 'claude' -and $line -cmatch '\A\[auto-review:claude\] verdict  -> (.+)\z') {
        [void]$successPaths.Add($Matches[1])
      }
    }
    if ($modeLines.Count -ne 1 -or $childWarnings.Count -gt 64 -or $semanticChars -gt 65536) { return (& $refuse 'mode-count') }
    if ($successPaths.Count -ne 1) { return (& $refuse 'artifact-path-count') }
    if ($null -eq $visibility) { $visibility = $modeLines[0] }
    elseif (-not [string]::Equals($visibility, $modeLines[0], [System.StringComparison]::Ordinal)) { return (& $refuse 'mode-conflict') }
    $thisWarningKey = [string]::Join("`n", $childWarnings)
    if ($null -eq $warningKey) { $warningKey = $thisWarningKey; foreach ($w in $childWarnings) { [void]$warnings.Add($w) } }
    elseif (-not [string]::Equals($warningKey, $thisWarningKey, [System.StringComparison]::Ordinal)) { return (& $refuse 'warning-conflict') }

    $reportedArtifact = ''
    try { $reportedArtifact = [System.IO.Path]::GetFullPath($successPaths[0]) } catch { return (& $refuse 'artifact-path') }
    $reportedParent = [System.IO.Path]::GetDirectoryName($reportedArtifact)
    $reportedLeaf = [System.IO.Path]::GetFileName($reportedArtifact)
    if (-not [string]::Equals($reportedParent, $dirItem.FullName, [System.StringComparison]::OrdinalIgnoreCase) -or
        $reportedLeaf -cnotmatch $artifactLeafPattern) {
      return (& $refuse 'artifact-path')
    }
    $enumerationError = @()
    $artifacts = @(Get-ChildItem -LiteralPath $dirItem.FullName -File -Force -ErrorAction SilentlyContinue -ErrorVariable enumerationError |
      Where-Object { $_.Name -cmatch $artifactLeafPattern })
    if ($enumerationError.Count -ne 0 -or $artifacts.Count -ne 1 -or
        -not [string]::Equals($artifacts[0].FullName, $reportedArtifact, [System.StringComparison]::OrdinalIgnoreCase)) {
      return (& $refuse 'artifact-count')
    }
    $artifactRead = Read-CrgSuccessfulReviewEvidence -Path $artifacts[0].FullName -MaxBytes 16777216
    if (-not $artifactRead.Ok) { return (& $refuse ('artifact-' + $artifactRead.Code)) }
    $rows = @($artifactRead.Text -split "`n")
    $effortOk = if ($expectedBackend -ceq 'codex') {
      $rows.Count -ge 4 -and $rows[3] -cmatch '\AREVIEW-EFFORT: (?:unknown|minimal|low|medium|high|xhigh|max)\z'
    } else {
      $rows.Count -ge 4 -and [string]::Equals($rows[3], 'REVIEW-EFFORT: n/a', [System.StringComparison]::Ordinal)
    }
    if ($rows.Count -lt 8 -or
        -not [string]::Equals($rows[0], "DIFF-SHA256: $ExpectedDiffSha", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($rows[1], "REVIEW-TREE-OID: $ExpectedTreeOid", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($rows[2], "REVIEW-BACKEND: $expectedBackend", [System.StringComparison]::Ordinal) -or
        -not $effortOk -or
        -not [string]::Equals($rows[4], 'REVIEW-SEVERITY-CONTRACT: blocker-only', [System.StringComparison]::Ordinal) -or
        $rows[5] -cnotmatch '\AREVIEW-DURATION-SECS: (?:0|[1-9][0-9]*)\z' -or
        -not [string]::Equals($rows[6], '', [System.StringComparison]::Ordinal)) {
      return (& $refuse 'artifact-identity')
    }
    $verdictCount = 0
    $nonBlockingVerdictCount = 0
    $artifactFindingCount = 0
    for ($rowIndex = 0; $rowIndex -lt $rows.Count; $rowIndex++) {
      $row = $rows[$rowIndex]
      if ($rowIndex -gt 5 -and $row -cmatch '\A(?:DIFF-SHA256|REVIEW-TREE-OID|REVIEW-BACKEND|REVIEW-EFFORT|REVIEW-SEVERITY-CONTRACT|REVIEW-DURATION-SECS):') {
        return (& $refuse 'artifact-duplicate-identity')
      }
      if ($row -cmatch '\AVERDICT:') {
        if ([string]::Equals($row, 'VERDICT: CLEAN', [System.StringComparison]::Ordinal)) { }
        elseif ([string]::Equals($row, 'VERDICT: NON-BLOCKING', [System.StringComparison]::Ordinal)) { $nonBlockingVerdictCount++ }
        else { return (& $refuse 'artifact-verdict') }
        $verdictCount++
        continue
      }
      if ($row -cmatch '\ABLOCKER:') { return (& $refuse 'artifact-blocker') }
      if ($row -cmatch '\A(QUALITY|NON-BLOCKER|NOTE):(.*)\z') {
        $severity = $Matches[1]
        $body = $Matches[2]
        if ([string]::IsNullOrWhiteSpace($body) -or $row.Length -gt 4096) { return (& $refuse 'finding-shape') }
        if ($severity -ceq 'NON-BLOCKER') { $severity = 'QUALITY' }
        [void]$findings.Add("${severity}:$body")
        $artifactFindingCount++
      }
    }
    if ($verdictCount -lt 1 -or
        ($artifactFindingCount -gt 0 -and $nonBlockingVerdictCount -lt 1) -or
        ($artifactFindingCount -eq 0 -and $nonBlockingVerdictCount -gt 0)) {
      return (& $refuse 'artifact-verdict')
    }
  }

  $lines = New-Object 'System.Collections.Generic.List[string]'
  [void]$lines.Add($visibility)
  foreach ($warning in $warnings) { [void]$lines.Add($warning) }
  foreach ($finding in $findings) { [void]$lines.Add($finding) }
  return @{ Ok = $true; Code = ''; Lines = $lines.ToArray() }
}

# Review-feedback and housekeeping warnings (Write-ReviewFeedbackStatus in
# scripts/review-common.ps1) for a passed merge: without them a passed merge
# hid feedback work left undone (merge review, 2026-10-09) and skipped
# housekeeping. Kept apart from
# Get-CrgSuccessfulReviewProjection on purpose. It reads EVERY launched
# child, not only the panel that supplied the verdict, because a passing
# child of a replaced panel may still have written records. It never fails
# the merge: a line it cannot show becomes a fixed notice instead of a
# refusal. (Folding these lines into the strict projection was tried and
# dropped the same day: it read only the accepting panel and could refuse a
# passed merge.) A child log is whatever the wrapper and its provider tools
# printed, CRLF endings, escape codes and all, so it is read line by line
# with invalid bytes replaced and only the matched lines checked; the strict
# Read-CrgSuccessfulReviewEvidence would drop a whole child's warnings for
# one stray control character elsewhere in its log. The text is only shown,
# never acted on, so no handle identity check is needed. The writer's
# messages name no provider; the tag naming the wrapper is removed. Count
# lines are not shown: the merge PASS line counts after every child. At most
# 32 warnings, the rest counted.
function Get-CrgReviewFeedbackStatusLines {
  param([string[]]$ChildDirs)
  $found = New-Object 'System.Collections.Generic.SortedSet[string]' ([System.StringComparer]::Ordinal)
  $seenDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  foreach ($dir in @($ChildDirs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $seenDirs.Add([string]$_) })) {
    # The launcher creates the log before launch, so even a missing one is a
    # child whose warnings cannot be shown. The size limit is the strict
    # reader's.
    $stream = $null
    $reader = $null
    try {
      $stream = [System.IO.FileStream]::new((Join-Path $dir 'child-stdout.log'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite, 65536, [System.IO.FileOptions]::SequentialScan)
      $reader = [System.IO.StreamReader]::new($stream, [System.Text.UTF8Encoding]::new($false, $false), $false)
      if ($stream.Length -gt 67108864) { throw 'the log is too large' }
      while ($null -ne ($line = $reader.ReadLine())) {
        if ($line -cnotmatch '\A\[auto-review(?::claude)?\] ((review-feedback|housekeeping) WARN: .*)\z') { continue }
        $warning = $Matches[1]
        $kind = $Matches[2]
        if ([System.Text.Encoding]::UTF8.GetByteCount($warning) -gt 4096 -or $warning -cmatch '[\x00-\x1F\x7F]' -or $warning -cnotmatch '\A(?:review-feedback|housekeeping) WARN: \S(?:.*\S)?\z') {
          $warning = "$kind WARN: a $kind line was not in the expected form and is not shown"
        }
        [void]$found.Add($warning)
      }
    } catch {
      [void]$found.Add('review-feedback WARN: the review-feedback lines of one review child could not be read')
    } finally {
      if ($null -ne $reader) { $reader.Dispose() } elseif ($null -ne $stream) { $stream.Dispose() }
    }
  }
  $lines = @($found | Select-Object -First 32)
  if ($found.Count -gt 32) { $lines += "review-feedback WARN: $($found.Count - 32) further review-feedback warnings are not shown" }
  return $lines
}

function Publish-CrgSuccessfulReviewProjection {
  param([Parameter(Mandatory = $true)][string[]]$Lines)
  foreach ($line in $Lines) { Write-Host "[auto-merge] review result: $line" }
}

# Pin the exact identity stamped by both Branch-scope wrappers before any review
# child launches. A private bare Git directory and a highest-precedence `!diff`
# reset make the patch hash independent of repository info/attributes, committed
# attributes, global/system attributes, textconv, and external diff drivers.
function Get-CrgBranchReviewExpectedIdentity {
  param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$BaseSha,
    [Parameter(Mandatory = $true)][string]$TipSha,
    [Parameter(Mandatory = $true)][string]$RunDir
  )
  $bad = { param([string]$Code) @{ Ok = $false; Code = $Code; TreeOid = ''; DiffSha = '' } }
  $oidPattern = '\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z'
  if ($BaseSha -cnotmatch $oidPattern -or $TipSha -cnotmatch $oidPattern -or $BaseSha.Length -ne $TipSha.Length) {
    return (& $bad 'input')
  }
  try {
    $treeRows = @(& git --no-replace-objects -C $RepoRoot rev-parse --verify "$TipSha`^{tree}" 2>$null)
    $treeExit = $LASTEXITCODE
    $treeOid = if ($treeRows.Count -eq 1) { ([string]$treeRows[0]).Trim() } else { '' }
    if ($treeExit -ne 0 -or $treeOid -cnotmatch $oidPattern -or $treeOid.Length -ne $TipSha.Length) { return (& $bad 'tree') }

    $objectRows = @(& git -C $RepoRoot rev-parse --git-path objects 2>$null)
    $objectExit = $LASTEXITCODE
    if ($objectExit -ne 0 -or $objectRows.Count -ne 1) { return (& $bad 'objects') }
    $sourceObjectsRaw = [string]$objectRows[0]
    if ([string]::IsNullOrWhiteSpace($sourceObjectsRaw) -or $sourceObjectsRaw.IndexOfAny([char[]]@("`r", "`n")) -ge 0) { return (& $bad 'objects') }
    $sourceObjects = if ([System.IO.Path]::IsPathRooted($sourceObjectsRaw)) {
      [System.IO.Path]::GetFullPath($sourceObjectsRaw)
    } else {
      [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $sourceObjectsRaw))
    }
    if (-not [System.IO.Directory]::Exists($sourceObjects)) { return (& $bad 'objects') }

    $root = Join-Path $RunDir 'success-projection-identity'
    $gitDir = Join-Path $root 'gitdir'
    $objectDir = Join-Path $gitDir 'objects'
    $objectInfoDir = Join-Path $objectDir 'info'
    $infoDir = Join-Path $gitDir 'info'
    $refsDir = Join-Path $gitDir 'refs'
    $noHome = Join-Path $root 'no-home'
    $noXdg = Join-Path $root 'no-xdg'
    foreach ($dir in @($root, $gitDir, $objectDir, $objectInfoDir, $infoDir, $refsDir, $noHome, $noXdg)) {
      [void][System.IO.Directory]::CreateDirectory($dir)
    }
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $configText = if ($TipSha.Length -eq 64) {
      "[core]`n`trepositoryformatversion = 1`n`tbare = true`n`tcommitGraph = false`n`tmultiPackIndex = false`n[extensions]`n`tobjectFormat = sha256`n"
    } else {
      "[core]`n`trepositoryformatversion = 0`n`tbare = true`n`tcommitGraph = false`n`tmultiPackIndex = false`n"
    }
    $noGlobal = Join-Path $root 'no-global-config'
    $canary = Join-Path $root 'hostile-global-attributes'
    [System.IO.File]::WriteAllText((Join-Path $gitDir 'HEAD'), "ref: refs/heads/crg-success-projection`n", $utf8)
    [System.IO.File]::WriteAllText((Join-Path $gitDir 'config'), $configText, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $gitDir 'commondir'), ".`n", $utf8)
    [System.IO.File]::WriteAllText((Join-Path $gitDir 'shallow'), '', $utf8)
    [System.IO.File]::WriteAllText((Join-Path $infoDir 'grafts'), '', $utf8)
    [System.IO.File]::WriteAllText((Join-Path $infoDir 'attributes'), "* !diff`n", $utf8)
    [System.IO.File]::WriteAllText((Join-Path $objectInfoDir 'alternates'), (($sourceObjects -replace '\\', '/') + "`n"), $utf8)
    [System.IO.File]::WriteAllText($noGlobal, '', $utf8)
    [System.IO.File]::WriteAllText($canary, "* -diff`n", $utf8)

    $gitCommand = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $gitCommand -or [string]::IsNullOrWhiteSpace($gitCommand.Source)) { return (& $bad 'git') }
    $invokePrivate = {
      param([string[]]$Arguments)
      $psi = [System.Diagnostics.ProcessStartInfo]::new()
      $psi.FileName = $gitCommand.Source
      $psi.UseShellExecute = $false
      $psi.CreateNoWindow = $true
      $psi.RedirectStandardOutput = $true
      $psi.RedirectStandardError = $true
      $psi.WorkingDirectory = [System.IO.Path]::GetPathRoot($root)
      $psi.Arguments = Convert-ToProcArgString -ArgList (@('-c', 'core.bare=true') + $Arguments)
      # Windows PowerShell 5.1 materializes a casing-preserving
      # StringDictionaryWithComparer here; a map that cannot preserve canonical
      # spelling is intentionally refused by the child-map postcondition.
      $environmentProperty = $psi.PSObject.Properties['Environment']
      if ($null -ne $environmentProperty -and $null -ne $environmentProperty.Value) {
        $childEnvironment = $environmentProperty.Value
      } else {
        $childEnvironment = $psi.EnvironmentVariables
      }
      $childEnvironment.Clear()
      foreach ($name in @('SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'PATH')) {
        $value = [Environment]::GetEnvironmentVariable($name, [EnvironmentVariableTarget]::Process)
        if ($null -ne $value) { $childEnvironment[$name] = $value }
      }
      $childEnvironment['TEMP'] = $root
      $childEnvironment['TMP'] = $root
      $childEnvironment['HOME'] = $noHome
      $childEnvironment['XDG_CONFIG_HOME'] = $noXdg
      $childEnvironment['GIT_DIR'] = $gitDir
      $childEnvironment['GIT_COMMON_DIR'] = $gitDir
      $childEnvironment['GIT_OBJECT_DIRECTORY'] = $objectDir
      $childEnvironment['GIT_CONFIG_NOSYSTEM'] = '1'
      $childEnvironment['GIT_CONFIG_GLOBAL'] = $noGlobal
      $childEnvironment['GIT_ATTR_NOSYSTEM'] = '1'
      $childEnvironment['GIT_OPTIONAL_LOCKS'] = '0'
      $childEnvironment['LC_ALL'] = 'C'
      $childEnvironment['LANG'] = 'C'
      Set-CrgNoReplaceObjectsInChildEnvironment -EnvEntries $childEnvironment
      try { $psi.StandardOutputEncoding = $utf8; $psi.StandardErrorEncoding = $utf8 } catch { }
      $proc = [System.Diagnostics.Process]::new()
      $proc.StartInfo = $psi
      try {
        if (-not $proc.Start()) { throw 'private Git process did not start' }
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()
        return @{ Exit = $proc.ExitCode; Out = $outTask.Result; Err = $errTask.Result }
      } finally { $proc.Dispose() }
    }

    $probePath = 'nested/crg-success-projection-probe.txt'
    $probe = & $invokePrivate @('-c', "core.attributesFile=$canary", 'check-attr', '--cached', 'diff', '--', $probePath)
    if ($probe.Exit -ne 0 -or -not [string]::Equals($probe.Out.Trim(), "$probePath`: diff: unspecified", [System.StringComparison]::Ordinal)) { return (& $bad 'attribute-reset') }
    $patchPath = Join-Path $root 'DIFF.patch'
    $patch = & $invokePrivate @('-c', "core.attributesFile=$canary", '-c', 'core.quotePath=false',
      'diff', '--no-color', '--no-ext-diff', '--no-textconv', '--no-relative', '--ignore-submodules=none',
      '--src-prefix=a/', '--dst-prefix=b/', "--output=$patchPath", "$BaseSha...$TipSha")
    if ($patch.Exit -ne 0 -or -not [System.IO.File]::Exists($patchPath)) { return (& $bad 'diff') }
    $patchBytes = [System.IO.File]::ReadAllBytes($patchPath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
      $diffSha = ([System.BitConverter]::ToString($sha.ComputeHash($patchBytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return @{ Ok = $true; Code = ''; TreeOid = $treeOid; DiffSha = $diffSha }
  } catch {
    return (& $bad 'exception')
  }
}

# Successful review transcripts stay private. A final BLOCKER/fail-closed
# outcome replays every launched child's stdout/stderr once, under fixed byte
# and line bounds, in launch order. Provider identity may appear inside this
# failure evidence; successful output never carries it. A bounded/unreadable
# capture sets State.Preserve so the complete run-owned evidence survives.
function Publish-ReviewFailureTranscripts {
  param(
    [int]$FinalExitCode,
    [object[]]$Children,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$State,
    [int]$MaxHeadBytes = 262144,
    [int]$MaxTailBytes = 262144,
    [int]$MaxLineChars = 4096
  )
  if ($FinalExitCode -eq 0 -or [bool]$State['Published']) { return }
  $ordinal = 0
  foreach ($child in @($Children)) {
    if ($null -eq $child) { continue }
    $ordinal++
    foreach ($capture in @(
        @{ Label = 'stdout'; Path = [string]$child.StdoutFile },
        @{ Label = 'stderr'; Path = [string]$child.StderrFile }
      )) {
      if ([string]::IsNullOrWhiteSpace($capture.Path) -or -not (Test-Path -LiteralPath $capture.Path -PathType Leaf)) {
        Write-Host "[auto-merge] (review failure transcript) WARNING: review child $ordinal $($capture.Label) capture is missing - complete failure evidence is unavailable."
        $State['Preserve'] = $true
        continue
      }
      $read = Get-AuditCaptureRead -Path $capture.Path -Label $capture.Label `
        -Consequence 'complete failure evidence is unavailable; the run directory will be retained' `
        -MaxHeadBytes $MaxHeadBytes -MaxTailBytes $MaxTailBytes -MaxLineChars $MaxLineChars `
        -ContextLabel 'review failure transcript' -CaptureNoun 'review' -NonGating $false
      if ($read.Warning) {
        Write-Host $read.Warning
        $State['Preserve'] = $true
      }
      if ($read.Bounded) { $State['Preserve'] = $true }
      if (-not [string]::IsNullOrWhiteSpace($read.Text)) {
        Write-Host "[auto-merge] (review failure transcript) review child $ordinal $($capture.Label):"
        Write-Host $read.Text
      }
    }
  }
  $State['Published'] = $true
}

function Get-CrgGateUntrackList {
  return @('scripts/codex/auto-review.ps1', 'scripts/codex/auto-merge.ps1', 'scripts/shared/auto-merge.ps1', 'scripts/codex/commit.ps1', 'scripts/shared/analyze-blocker-trends.ps1', 'scripts/shared/author-lint.ps1', 'scripts/shared/dispatch-checklist.ps1', 'scripts/shared/worker-audit.ps1', 'scripts/codex/review-prompt-template.md', 'scripts/claude/auto-review.ps1', 'scripts/claude/commit.ps1', 'scripts/git-hooks/pre-commit', 'scripts/run-gate.sh', 'scripts/render-project-values.ps1', 'scripts/review-liveness.psm1', 'scripts/review-common.ps1', 'docs/AGENTS.md.template', 'docs/audit-protocol.md')
}
function Test-CrgGateUntrackSanctioned {
  return [string]::Equals($env:CROSS_REVIEW_ALLOW_GATE_UNTRACK, '1', [System.StringComparison]::Ordinal)
}
# Range scan for a gate-component removal (deletion or rename-away)
# across base..tip -- the aggregate diff is the landing's net effect.
# Ok=$false is the fail-closed probe-failure answer.
function Get-CrgRangeGateRemoval {
  param([string]$BaseSha, [string]$TipSha)
  $guList = Get-CrgGateUntrackList
  # --no-relative keeps the installed-file inventory rooted at the repository
  # even when the caller starts below that root or configures diff.relative.
  # quotePath=false gives the line parser one deterministic UTF-8 path spelling;
  # the fixed gate inventory is ASCII, but every name-status consumer uses the
  # same contract so a future non-ASCII inventory entry cannot fail open.
  try { $guNs = @(& git -c core.quotePath=false diff --no-color --no-ext-diff --no-textconv --no-relative --ignore-submodules=none --name-status -M "$BaseSha..$TipSha" 2>$null) } catch { return @{ Ok = $false; Removed = $null } }
  if ($LASTEXITCODE -ne 0) { return @{ Ok = $false; Removed = $null } }
  foreach ($guLine in $guNs) {
    $guCols = "$guLine" -split "`t"
    if ($guCols.Count -lt 2) { continue }
    if ((($guCols[0].StartsWith('D', [System.StringComparison]::Ordinal)) -or ($guCols[0].StartsWith('R', [System.StringComparison]::Ordinal))) -and ([Array]::IndexOf([string[]]$guList, [string]$guCols[1]) -ge 0)) { return @{ Ok = $true; Removed = $guCols[1] } }
  }
  return @{ Ok = $true; Removed = $null }
}

# The trusted-infra source decision for ONE gate file: the BASE commit's
# copy when it exists (the candidate cannot weaken the reviewer that
# decides its merge), else -- on POSITIVE absence only, ls-tree
# succeeding and listing nothing -- the manifest-verified local snapshot
# bytes (docs/local-install-v1.md). $null is the fail-closed answer for
# every other state: probe failure, present-but-unreadable, or an
# unverified local file.
function Resolve-CrgTrustedInfraSource {
  param([string]$BaseSha, [string]$RelPath)
  # The tree entry is probed FIRST and must be a BLOB before `git show`
  # is trusted: `git show <sha>:<dir>` prints a tree LISTING with exit 0,
  # which would otherwise land as trusted-infra "content".
  # --full-tree makes the pathspec ROOT-relative regardless of the
  # process CWD, matching the root-relative `git show <sha>:<path>`
  # this probe gates -- without it a subdirectory CWD would probe a
  # different path than the one extracted.
  $tiProbe = @(& git ls-tree --full-tree $BaseSha -- $RelPath 2>$null)
  if ($LASTEXITCODE -ne 0) { return $null }
  $tiEntries = @($tiProbe | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($tiEntries.Count -eq 0) {
    $tiBytes = Get-CrgLocalInstallVerifiedBytes -RelPath $RelPath
    if ($null -ne $tiBytes) { return @{ Kind = 'local'; Bytes = $tiBytes } }
    return $null
  }
  # REGULAR-FILE modes only: a symlink lists as `120000 blob`, and
  # `git show` on it prints the LINK TARGET string, which would land as
  # trusted-infra content.
  if ($tiEntries.Count -ne 1 -or $tiEntries[0] -cnotmatch '^100[0-7]{3} blob ') { return $null }
  $tiLines = & git show "${BaseSha}:$RelPath"
  if ($LASTEXITCODE -ne 0) { return $null }
  return @{ Kind = 'base'; Text = (($tiLines -join "`n") + "`n") }
}

# Does a wrapper script DECLARE a given parameter? Answered from the PARSED
# param() AST, not a lexical scan: a whole-file regex accepts commented and
# string-literal mentions and rejects the valid spaced `[string] $Name` form --
# a false positive forwards an unsupported argument and param-bind-fails a valid
# merge. Needed because this gate runs the BASE-extracted wrappers: a base
# predating a new optional parameter would param-bind-fail if the gate forwarded
# it unconditionally, turning a valid merge into a fail-closed abort.
# TRI-STATE: 'declared', 'absent', or 'unknown'. A probe that could not READ or
# parse the wrapper knows nothing about it, and treating that silence as "an old
# wrapper without the parameter" is an inference the evidence does not support --
# the caller must be able to say "I could not tell" out loud instead of quietly
# assuming the legacy shape.
#
# SCOPE: this answers PARAMETER EXISTENCE only. Whether a declared parameter
# would ACCEPT a particular VALUE is a different and much wider question --
# every validation-attribute type, fully-qualified attribute names -- and a
# partial answer to it was measured fail-open; `docs/known-debt.md` tracks that
# value-accepting probe as its own combined task. For a SWITCH parameter
# existence is the whole question; for a valued parameter this probe answers
# only the existence HALF (the `-ArtifactTag` caller leans on exactly that:
# declared-or-not gates the forward, while the value's acceptance rests on
# the wrapper's own ValidatePattern rather than on this probe).
function Get-WrapperParameterDeclaration {
  param(
    # NOT mandatory: an empty path is one of the states this answers about
    # ('unknown'), and binding-time rejection would turn it into a crash.
    [string]$WrapperPath = '',
    [Parameter(Mandatory = $true)][string]$ParamName
  )
  if ([string]::IsNullOrWhiteSpace($WrapperPath)) { return 'unknown' }
  try {
    if (-not (Test-Path -LiteralPath $WrapperPath -PathType Leaf)) { return 'unknown' }
  } catch { return 'unknown' }
  try {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($WrapperPath, [ref]$tokens, [ref]$parseErrors)
    # A MALFORMED script answers UNKNOWN, never 'absent': ParseFile recovers a
    # partial AST alongside its errors, so neither a declaration found nor one
    # missing in that AST is evidence about the real wrapper.
    if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) { return 'unknown' }
    if ($null -eq $ast) { return 'unknown' }
    if ($null -eq $ast.ParamBlock) { return 'absent' }
    foreach ($p in $ast.ParamBlock.Parameters) {
      if ([string]::Equals($p.Name.VariablePath.UserPath, $ParamName, [System.StringComparison]::OrdinalIgnoreCase)) { return 'declared' }
    }
    return 'absent'
  } catch {
    return 'unknown'
  }
}

# The argv a branch-review child is launched with. One element is a CORRECTNESS
# contract rather than a convenience:
# -CentralDestinationExpected tells the child that THIS gate will consolidate its
# run-owned -OutDir into the backend's central review logs after the run, so the
# child's QUALITY follow-up rows must name the CENTRAL artifact path. Dropping the
# flag would leave those rows naming this gate's scratch dir -- a path the cleanup
# below then deletes -- so the surviving central verdict would earn no prune
# exemption and a later provenance check would find nothing at the locator.
#
# FORWARDED ONLY WHEN THE WRAPPER DECLARES IT. The wrappers this gate launches are
# extracted from the BASE, not from the candidate diff, so a base predating the
# parameter would reject it at binding time and fail the merge closed before any
# review ran. The two degrades are told apart on purpose. ABSENT is evidence: a
# wrapper that old predates locators too, so its capture rows carry a bare
# BASENAME, which the doctrine grandfathers with global stem retention. UNKNOWN is
# evidence of nothing -- the probe could not read or parse the wrapper -- so the
# switch is withheld (never pass an argument a wrapper may not bind) and the
# uncertainty is named rather than dressed up as legacy.
# -ReviewPasses 0 means "this wrapper has no pass-count parameter" (the claude
# child runs a single pass by construction).
function Get-ReviewChildArgs {
  param(
    [string]$WrapperPath,
    [string]$PromptPath,
    [string]$Base,
    [string]$BranchSha,
    [string]$RunDir,
    [string]$Title,
    [int]$ReviewPasses
  )
  # -Base must be the PINNED base OID (40-hex SHA-1 or 64-hex SHA-256, the
  # same alternative the capture-row tree-OID validators accept), never a
  # symbolic ref. A symbolic ref would be re-resolved independently by every
  # concurrently launched child (`rev-parse "$Target^{commit}"` at child
  # start), so a base branch moving mid-run would split the reviewed range
  # AND the project-mode governing resolution across the panel while the
  # gate ff-merges against yet another base. Enforced structurally so no
  # future call site can regress it.
  if ($Base -cnotmatch '\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z') {
    throw "Get-ReviewChildArgs: -Base must be the pinned base OID (40- or 64-hex; got '$Base') - a symbolic ref would let each review child re-resolve a moving base and split the reviewed range and project-mode governing resolution across the panel."
  }
  $childArgs = @(
    '-ExecutionPolicy', 'Bypass', '-File', $WrapperPath,
    '-Scope', 'Branch', '-Target', $Base, '-Tip', $BranchSha,
    '-PromptPath', $PromptPath
  )
  if ($ReviewPasses -gt 0) { $childArgs += @('-ReviewPasses', "$ReviewPasses") }
  $childArgs += @('-OutDir', $RunDir)
  $centralDeclState = Get-WrapperParameterDeclaration -WrapperPath $WrapperPath -ParamName 'CentralDestinationExpected'
  if ($centralDeclState -eq 'declared') {
    $childArgs += @('-CentralDestinationExpected')
  } elseif ($centralDeclState -eq 'absent') {
    # P4 revisit of this P2-era inference: for CLAUDE wrappers the window is
    # now CLOSED -- every claude panel and fallback path requires a declared
    # -ArtifactTag (a later capability than this one) and refuses before
    # reaching this launch, so a claude wrapper old enough to trip this arm
    # never gets a child. The inference therefore remains reachable only for
    # a pre-locator CODEX base wrapper, where it stays an inference from the
    # declaration probe, not a proof.
    Write-Host "[auto-merge] WARN: the trusted wrapper at $WrapperPath does not declare -CentralDestinationExpected (the base predates it) - a wrapper that old LIKELY predates locators too (an inference from the declaration probe, not a proof), so its capture rows are expected to carry a bare BASENAME."
  } else {
    Write-Host "[auto-merge] WARN: could not determine whether the trusted wrapper at $WrapperPath declares -CentralDestinationExpected (unreadable or unparsable) - the switch is WITHHELD, so a capture row from this child names its RUN-DIR path, which consolidation then moves into the central review logs: such a row goes stale at its locator and is resolved there instead (absent-at-locator, ordinary duty, per the capture doctrine)."
  }
  $childArgs += @('-Title', $Title)
  return $childArgs
}

# Resolve the centralized shared-logs `logs/<backend>/reviews` dir -- the SAME
# destination the wrappers' Resolve-DefaultReviewOutDir DEFAULT picks (via the
# shared Get-ReviewLogDir: the git-common-dir parent for normal/worktree layouts,
# the submodule working-tree top-level for submodule installs) -- used ONLY as the
# destination to COPY this run's verdict artifacts into for FORENSICS (these
# artifacts are also read by the top-level trend analyzer, which scans BOTH
# logs/codex/reviews and logs/claude/reviews by default). The shared destination
# is NEVER a trust input: the branch review writes to a run-OWNED scratch
# -OutDir (created below), and no merge-decision input is read back from the
# gitignored shared logs. Child process exits establish the initial panel
# outcome; a putative success additionally requires the current run-owned
# capture and unique verdict artifact to pass identity and semantic validation.
# Returns $null
# when git cannot resolve a common dir (or a submodule with no resolvable
# top-level), in which case the forensic copy is skipped (the run-owned artifacts
# still exist in the scratch dir for the duration of the run). NON-pure (git
# probe); path SELECTION delegates to Get-ReviewLogDir.
function Resolve-CentralLogDir {
  param([string]$Backend)
  $commonDir = $null
  $absOut = & git rev-parse --path-format=absolute --git-common-dir 2>$null
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($absOut)) {
    $commonDir = ($absOut | Select-Object -First 1)
  } else {
    $plainOut = & git rev-parse --git-common-dir 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($plainOut)) {
      try { $commonDir = (Resolve-Path -LiteralPath ($plainOut | Select-Object -First 1) -ErrorAction Stop).Path }
      catch { $commonDir = $null }
    }
  }
  if ([string]::IsNullOrWhiteSpace($commonDir)) { return $null }
  $topLevel = $null
  $topOut = & git rev-parse --show-toplevel 2>$null
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($topOut)) {
    $topLevel = ($topOut | Select-Object -First 1)
  }
  return Get-ReviewLogDir -CommonDir $commonDir -TopLevel $topLevel -Backend $Backend
}

# Copy a run-owned backend artifact dir into the centralized shared logs for
# forensics and the top-level trend analyzer (which scans BOTH logs/codex/reviews
# and logs/claude/reviews by default). Called from the
# finally block BEFORE the run scratch dir is (conditionally) deleted (copy-then-
# delete, copy first, on EVERY exit path). RETURNS $true when the caller must
# PRESERVE the run dir because consolidation could not safely complete -- so a
# copy/enumerate failure NEVER results in silent artifact loss: the run dir is
# kept instead of deleted (see the finally), and the failure is reported LOUDLY.
#
# FAIL-LOUD + PRESERVE contract (hardened after a sibling session's
# abort silently lost multiple verdicts when the run dir was
# reaped with the artifacts uncopied): every failure mode is reported VISIBLY,
# names what was affected, and signals PRESERVE so nothing is lost --
#   - EMPTY/whitespace $RunBackendDir (no dir was ever named) -> return $false
#     SILENTLY (genuinely nothing to consolidate; safe to delete).
#   - NON-empty $RunBackendDir that is MISSING / not a container at cleanup (an
#     EXPECTED per-slot dir that vanished) -> LOUD WARN + return $true
#     (preserve the parent run dir; its artifacts may have been lost). This is
#     NOT "safe to delete" -- a vanished expected dir is an anomaly.
#   - unresolvable / uncreatable central dir -> LOUD skip line + return $true
#     (preserve; the artifacts stay in the run dir for manual recovery).
#   - run-dir enumeration FAILURE (-ErrorAction Stop in try/catch; a
#     SilentlyContinue here would mask the failure as "0 files" and let the dir be
#     deleted) -> LOUD line + return $true (preserve; we cannot even tell what is
#     in the dir).
#   - PER-FILE copy failure -> continue copying the rest (one bad file must not
#     abort the whole consolidation) but accumulate the failures, emit a LOUD
#     summary naming the count + the central path, and return $true (preserve the
#     run dir so the un-copied originals survive).
#   - a run dir that exists but holds ZERO VERDICT files (after the verdict-shape
#     filter -- it may still hold transient Start-ReviewChild scaffolding, which is
#     NOT centralized and goes away with the run dir) -> LOUD note + return $false
#     (nothing to lose; safe to delete -- usually the child produced no verdict).
#   - full success -> concise line + return $false (every verdict file centralized;
#     safe to delete).
# Still NON-FATAL to the merge decision (the trust read already happened against
# the run-owned dir); loudness is about forensic integrity, not gating. NON-pure.
# RETURNS $true when the caller should PRESERVE the run dir (consolidation could
# not safely complete -- a NON-empty run dir path that is missing/not a container,
# an unresolvable/uncreatable central dir, a run-dir enumeration failure, or one
# or more per-file copy failures), so the finally never silently deletes artifacts
# it could not centralize. RETURNS $false only when deletion is provably safe: the
# $RunBackendDir argument is EMPTY (no dir was ever named -- nothing to lose), OR
# enumeration succeeded and found ZERO VERDICT files after the verdict-shape filter
# (a scaffolding-only dir is safe to delete -- the scaffolding is transient), OR
# every VERDICT file copied successfully (centralized duplicates exist). On
# uncertainty it returns $true (preserve) -- a conservative default that never
# loses data.
# Atomic rename-with-replace for the centralization copy below: a direct
# Copy-Item into the central logs exposes a partially-written verdict at
# its final name for the whole copy duration -- the trend analyzer or a
# prune scanning mid-copy would read a truncated artifact with no way to
# tell. Staging beside the destination and swapping with MoveFileEx
# (REPLACE_EXISTING | WRITE_THROUGH) makes every centralized artifact
# appear complete-or-absent -- PROVIDED the source is quiescent: atomicity
# covers publication only, so the finally's consolidation loop skips any
# dir whose child was not confirmed exited (a live writer's partial
# snapshot would otherwise verify and publish). The type name is VERSIONED (a loaded type can
# never be redefined in-process, so an older definition must never shadow
# a newer method set), and initialization is LAZY and FALLIBLE: under the
# script's EAP=Stop a compiler/policy failure from a load-time Add-Type
# would terminate the gate before usage validation or the
# exit-code mapping, so failure is routed through the centralization path's
# ordinary warning-and-preserve arm rather than a raw termination.
$script:crgMergeNativeState = $null
function Initialize-CrgMergeNative {
  if ($null -ne $script:crgMergeNativeState) { return $script:crgMergeNativeState }
  try {
    if (-not ('CrgMerge.NativeV1' -as [type])) {
      Add-Type -Namespace 'CrgMerge' -Name 'NativeV1' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@ -ErrorAction Stop
    }
    $script:crgMergeNativeState = $true
  } catch {
    Write-Host "[auto-merge] WARN: the native rename-with-replace helper could not initialize ($($_.Exception.Message)) - atomic centralization is unavailable this run."
    $script:crgMergeNativeState = $false
  }
  return $script:crgMergeNativeState
}

function Copy-RunArtifactsToCentralLogs {
  param(
    [string]$RunBackendDir,
    [string]$Backend,
    [switch]$ProviderNeutralOutput,
    [switch]$QuietSuccess
  )
  $backendDisplay = if ($ProviderNeutralOutput) { 'review' } else { "'$Backend'" }
  $runDirDisplay = if ($ProviderNeutralOutput) { '<run-owned review directory>' } else { "'$RunBackendDir'" }
  # An EMPTY $RunBackendDir means there is genuinely nothing to consolidate (no
  # dir was ever named) -> safe to delete, no warning. But a NON-empty path that
  # is MISSING or not a container at consolidation time is an ANOMALY: the gate
  # creates each per-slot dir up front, so its disappearance means artifacts
  # may have been lost -> WARN and return the PRESERVE signal (never silently
  # report safe-to-delete for an expected-but-vanished slot dir). The
  # call site registers only dirs it actually created (every launched child's
  # slot dir), so a call here always expects the dir to exist.
  if ([string]::IsNullOrWhiteSpace($RunBackendDir)) { return $false }
  if (-not (Test-Path -LiteralPath $RunBackendDir -PathType Container)) {
    Write-Host "[auto-merge] forensics WARNING: expected $backendDisplay run dir $runDirDisplay is MISSING or not a directory at cleanup - cannot consolidate; PRESERVING the parent run dir (artifacts may have been lost)."
    return $true
  }
  $central = Resolve-CentralLogDir -Backend $Backend
  if ([string]::IsNullOrWhiteSpace($central)) {
    Write-Host "[auto-merge] forensics WARNING: could not resolve the central log dir for $backendDisplay artifacts - the central-log copy is SKIPPED; PRESERVING the run dir so verdict artifacts are not lost."
    return $true
  }
  try {
    if (-not (Test-Path -LiteralPath $central -PathType Container)) {
      New-Item -ItemType Directory -Path $central -Force -ErrorAction Stop | Out-Null
    }
  } catch {
    $centralDisplay = if ($ProviderNeutralOutput) { '<central review-log directory>' } else { "'$central'" }
    $createError = if ($ProviderNeutralOutput) { 'directory creation failed; inspect the preserved run directory' } else { $_.Exception.Message }
    Write-Host "[auto-merge] forensics WARNING: could not create central log dir $centralDisplay for $backendDisplay artifacts ($createError) - copy SKIPPED; PRESERVING the run dir so artifacts are not lost."
    return $true
  }
  # Enumerate with -ErrorAction Stop inside try/catch: a SilentlyContinue here
  # would convert an access/IO/enumeration failure into an empty set, which would
  # then be misreported as "NO files" and let the run dir be deleted -- silently
  # losing artifacts and defeating the fail-loud contract. On enumeration
  # failure, report it loudly and PRESERVE the run dir (we cannot even tell what
  # is in it).
  $allFiles = $null
  try {
    $allFiles = @(Get-ChildItem -LiteralPath $RunBackendDir -File -ErrorAction Stop)
  } catch {
    $enumerationError = if ($ProviderNeutralOutput) { 'enumeration failed; inspect the preserved run directory' } else { $_.Exception.Message }
    Write-Host "[auto-merge] forensics WARNING: could not enumerate $backendDisplay run dir $runDirDisplay ($enumerationError) - cannot centralize; PRESERVING the run dir so artifacts are not lost."
    return $true
  }
  # Copy ONLY verdict artifacts -- the exact `review-<YYYYMMDD>-<HHMMSS>-...`
  # {.md,.jsonl,.stderr.log,.exhaustion.json,.errored.txt} shape the
  # auto-review prune recognizes (the exhaustion sidecar and preserved
  # errored-pass bodies are DURABLE evidence -- the sidecar is what justified
  # a fallback, and deleting it with the run dir would destroy the record the
  # wrappers declare mandatory). Start-ReviewChild
  # leaves scaffolding (child-args.txt, child-exit.txt, child-runner.ps1, and the
  # child-stdout.log / child-stderr.log captures) in the run
  # dir; copying it into the gitignored central logs would orphan it -- the prune's
  # name regex never matches it, so it would never age out (slow unbounded growth).
  # The scaffolding is transient run-dir state that goes away with the run dir, so it
  # is intentionally NOT preserved. (Mirrors the prune-class name shapes in the
  # wrappers' Get-ReviewLogPruneClass.)
  $verdictNameRe = [regex]'^review-[0-9]{8}-[0-9]{6}-.+\.(md|jsonl|stderr\.log|exhaustion\.json|errored\.txt)$'
  $files = @($allFiles | Where-Object { $verdictNameRe.IsMatch($_.Name) })
  if ($files.Count -gt 0 -and -not (Initialize-CrgMergeNative)) {
    Write-Host "[auto-merge] forensics WARNING: the atomic-publish helper is unavailable, so $backendDisplay artifacts cannot be centralized safely - copy SKIPPED; PRESERVING the run dir so artifacts are not lost."
    return $true
  }
  if ($files.Count -eq 0) {
    if (-not $QuietSuccess) { Write-Host "[auto-merge] forensics NOTE: run dir for $backendDisplay ($runDirDisplay) holds NO verdict files to centralize - nothing to preserve (the child may have produced no verdict; any run scaffolding is transient and goes with the run dir)." }
    return $false
  }
  $copied = 0
  $failed = @()
  foreach ($f in $files) {
    $stagePath = $null
    try {
      # Per-file copy isolated so ONE unreadable/locked file cannot abort the
      # whole consolidation and drop the files that WOULD have copied (the
      # pre-hardening behavior aborted the loop on the first failure).
      # ATOMIC PUBLICATION: the artifact is staged BESIDE its central
      # destination, verified there, and swapped into its final name by
      # rename-with-replace -- a reader of the central logs never
      # observes a partially-written verdict at its final name. The stage
      # name is per-attempt unique, so concurrent gates cannot collide.
      $destPath = Join-Path $central $f.Name
      $stagePath = "$destPath.crg-new-$([guid]::NewGuid().ToString('N').Substring(0,8))"
      Copy-Item -LiteralPath $f.FullName -Destination $stagePath -ErrorAction Stop
      # Verify the STAGED copy is intact BEFORE it can become the published
      # name: the finally cleanup deletes the run-owned source, so a
      # truncated/partial copy mis-counted as success would lose the verdict
      # artifact. Require the stage to exist (Get-Item -Stop throws if
      # missing) and its byte length to match the source; a mismatch falls
      # to $failed and PRESERVES the run dir.
      $stageItem = Get-Item -LiteralPath $stagePath -ErrorAction Stop
      $stageLen = $stageItem.Length
      if ($stageLen -ne $f.Length) {
        throw "staged byte length $stageLen != source $($f.Length) (truncated/partial copy; the stage at '$stagePath' is retained for inspection)"
      }
      $swapOk = [CrgMerge.NativeV1]::MoveFileEx($stagePath, $destPath, 0x9)
      if (-not $swapOk) {
        throw "atomic publish failed (Win32 error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())); the verified stage at '$stagePath' is retained for inspection"
      }
      $copied++
    } catch {
      # The stage file (when one exists) is RETAINED and named in the
      # failure -- never deleted by path: its bytes may be the only intact
      # copy if the run dir is later lost, and a delete by name could race
      # a concurrent claimant.
      $failedName = if ($ProviderNeutralOutput) { '<review artifact>' } else { $f.Name }
      $failedDetail = if ($ProviderNeutralOutput) { 'publication failed; the internal stage was retained' } else { $_.Exception.Message }
      $failed += "$failedName ($failedDetail)"
    }
  }
  if ($failed.Count -gt 0) {
    $centralDisplay = if ($ProviderNeutralOutput) { '<central review-log directory>' } else { "'$central'" }
    Write-Host "[auto-merge] forensics WARNING: centralizing $backendDisplay artifacts to $centralDisplay - $copied/$($files.Count) copied, $($failed.Count) FAILED: $($failed -join '; '). PRESERVING the run dir so un-copied artifacts are not lost; the central trail is INCOMPLETE until recovery."
    return $true
  }
  if (-not $QuietSuccess) { Write-Host "[auto-merge] forensics: centralized $copied/$($files.Count) $backendDisplay artifact(s) to '$central'." }
  return $false
}


if ([string]::IsNullOrWhiteSpace($Branch)) {
  Write-Host "[auto-merge] ERROR: -Branch <branch> is required."
  exit 3
}
$backendSel = Resolve-BackendSelection -Raw $Backend
if (-not $backendSel.Ok) {
  if ($backendSel.Reason -eq 'invalid') {
    Write-Host "[auto-merge] ERROR: '-Backend $Backend' is not a supported backend (codex|claude). Choose the provider that reviews this merge."
  } else {
    Write-Host "[auto-merge] ERROR: -Backend codex|claude is required. Choose the preferred initial review provider."
  }
  exit 3
}
$Backend = $backendSel.Backend
if (-not [string]::IsNullOrWhiteSpace($ReasoningEffort)) {
  $ReasoningEffort = $ReasoningEffort.ToLowerInvariant()
  $mergeEffortTiers = Get-CodexEffortTiers -ExcludeMaxTier
  if ([Array]::IndexOf([string[]]$mergeEffortTiers, [string]$ReasoningEffort) -lt 0) {
    Write-Host "[auto-merge] ERROR: '-ReasoningEffort $ReasoningEffort' is not a supported tier ($($mergeEffortTiers -join '|'))."
    exit 3
  }
}

# Every merge-base, range, and first-parent proof below requires complete local
# ancestry. A true shallow repository can make a non-root commit appear
# parentless; a failed/malformed probe is equally unauthoritative.
$crgShallowRows = @()
$crgShallowExit = -1
try {
  $crgShallowRows = @(& git rev-parse --is-shallow-repository 2>$null)
  $crgShallowExit = $LASTEXITCODE
} catch {
  $crgShallowRows = @()
  $crgShallowExit = -1
}
$crgShallowState = Resolve-CrgShallowRepositoryState -Output $crgShallowRows -ExitCode $crgShallowExit
if ($crgShallowState -eq 'shallow') {
  Write-Host '[auto-merge] ERROR: the repository is shallow; complete ancestry is required for merge-base/range review and landing proofs. Fetch/unshallow the repository, then retry.'
  exit 3
}
if ($crgShallowState -ne 'complete') {
  Write-Host "[auto-merge] ERROR: repository shallow-state is indeterminate (git exit $crgShallowExit); refusing before ancestry or range work."
  exit 3
}
try { Set-CrgNoLateShallowBoundary }
catch {
  Write-Host "[auto-merge] ERROR: complete repository history was proved, but the late shallow-boundary sentinel could not be established: $($_.Exception.Message)"
  exit 3
}

# Project-agnostic base resolution: with no -Base, resolve the repo's default
# branch (origin/HEAD, fallback 'main'). MUST run before the preflight below --
# an unresolved empty $Base makes the HEAD/base check compare against '' and
# abort every run.
if ([string]::IsNullOrWhiteSpace($Base)) {
  $Base = Resolve-DefaultBaseBranch
  Write-Host "[auto-merge] -Base not given; resolved default base branch -> '$Base'"
}

# Pre-flight: resolve only exact, case-sensitive branch refs, prove that the
# requested base is the checked-out full symbolic ref, and pin both endpoints
# before graph work. Short revision names are forbidden here: a same-name tag
# can alter Git's short symbolic-ref spelling, while revision suffixes and
# case-folding can make an interpolated ref expression select a different ref.
$baseResolution = Resolve-CrgExactLocalBranchCommit -BranchName $Base
if ($baseResolution.State -eq 'invalid-name') {
  Write-Host "[auto-merge] ERROR: requested base '$Base' is not a valid local branch name."
  exit 3
}

$currentBranchRows = @(& git symbolic-ref --quiet HEAD 2>$null)
$currentBranchExit = $LASTEXITCODE
if ($currentBranchExit -ne 0 -or $currentBranchRows.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$currentBranchRows[0])) {
  Write-Host '[auto-merge] ERROR: HEAD is not one unambiguous symbolic branch; refusing before range work.'
  exit 3
}
$currentBranch = ([string]$currentBranchRows[0]).Trim()
if (-not [string]::Equals($currentBranch, $baseResolution.RefName, [System.StringComparison]::Ordinal)) {
  $currentBranchDisplay = if ($currentBranch.StartsWith('refs/heads/', [System.StringComparison]::Ordinal)) { $currentBranch.Substring(11) } else { $currentBranch }
  Write-Host "[auto-merge] ERROR: HEAD is on '$currentBranchDisplay', expected '$Base'"
  Write-Host "[auto-merge] Run 'git checkout $Base' first."
  exit 3
}
if ($baseResolution.State -ne 'valid') {
  Write-Host "[auto-merge] ERROR: exact base ref 'refs/heads/$Base' is missing, case-distinct, non-commit, or indeterminate."
  exit 3
}

$branchResolution = Resolve-CrgExactLocalBranchCommit -BranchName $Branch
if ($branchResolution.State -eq 'invalid-name') {
  Write-Host "[auto-merge] ERROR: requested branch '$Branch' is not a valid local branch name."
  exit 3
}
if ($branchResolution.State -ne 'valid') {
  Write-Host "[auto-merge] ERROR: exact branch ref 'refs/heads/$Branch' is missing, case-distinct, non-commit, or indeterminate."
  exit 3
}

$baseHeadRows = @(& git rev-parse --verify 'HEAD^{commit}' 2>$null)
$baseHeadExit = $LASTEXITCODE
$baseHead = if ($baseHeadRows.Count -eq 1) { ([string]$baseHeadRows[0]).Trim() } else { '' }
$baseRefHead = $baseResolution.CommitOid
$branchSha = $branchResolution.CommitOid
$oidPattern = '^[0-9a-f]{40}(?:[0-9a-f]{24})?$'
if ($baseHeadExit -ne 0 -or $baseHeadRows.Count -ne 1 -or
    $baseHead -notmatch $oidPattern -or $baseRefHead -notmatch $oidPattern -or
    -not [string]::Equals($baseHead, $baseRefHead, [System.StringComparison]::Ordinal)) {
  Write-Host "[auto-merge] ERROR: HEAD and exact base ref 'refs/heads/$Base' did not resolve to one identical canonical commit OID; refusing before range work."
  exit 3
}
if ($branchSha -notmatch $oidPattern) {
  Write-Host "[auto-merge] ERROR: exact branch ref 'refs/heads/$Branch' does not resolve to one canonical commit OID."
  exit 3
}

# Tracked-only cleanliness check (`--untracked-files=no` semantics): only
# tracked changes block the merge. Untracked build output, caches, and the
# gate's own generated artifacts (logs/) do not.
# A caller may start below the repository root and may carry hostile
# diff.relative/core.fsmonitor config. Root-relative traversal plus a fresh
# worktree stat is mandatory before declaring the base clean.
& git -c core.fsmonitor=false diff --no-ext-diff --no-textconv --no-relative --ignore-submodules=none --quiet
$unstagedDirty = ($LASTEXITCODE -ne 0)
& git -c core.fsmonitor=false diff --cached --no-ext-diff --no-textconv --no-relative --ignore-submodules=none --quiet
$stagedDirty = ($LASTEXITCODE -ne 0)
if ($unstagedDirty -or $stagedDirty) {
  Write-Host "[auto-merge] ERROR: tracked working tree on '$Base' is not clean"
  & git status --short --untracked-files=no
  exit 3
}

# Confirm ff-merge is actually possible. Capture cardinality and exit status
# explicitly: unrelated histories produce no stdout, and calling .Trim() on
# that null result used to escape through PowerShell's generic exit 1 instead
# of the gate's stable fail-closed diagnostic.
$mergeBaseRows = @(& git merge-base $baseHead $branchSha 2>$null)
$mergeBaseExit = $LASTEXITCODE
$mergeBase = if ($mergeBaseExit -eq 0 -and $mergeBaseRows.Count -eq 1) { ([string]$mergeBaseRows[0]).Trim() } else { '' }
$baseSha = $baseHead
if (-not [string]::Equals($mergeBase, $baseHead, [System.StringComparison]::Ordinal)) {
  Write-Host "[auto-merge] ERROR: '$Branch' is not a strict descendant of '$Base'."
  Write-Host "[auto-merge] merge-base=$(if ($mergeBase) { $mergeBase } else { '<none-or-indeterminate>' }), $Base HEAD=$baseHead (git exit $mergeBaseExit, rows=$($mergeBaseRows.Count))"
  Write-Host "[auto-merge] Rebase '$Branch' onto '$Base' first."
  exit 3
}

# Both endpoint OIDs came from exact refs above. The review and final merge use
# only these OIDs; exact refs are re-read immediately before the merge.
Write-Host "[auto-merge] Pinned '$Branch' to $branchSha"

# ---- gate-component untracking guard over the RANGE
# (docs/local-install-v1.md section 2) ----
# The hook enforces the untracking sanction on direct commits, but a
# branch landed HERE can carry commits created without the hook (a
# rebase continuation, low-level commit creation, another clone) --
# the ff-merge below fires no pre-commit hook. The same sanction is
# therefore enforced over base..tip before any review or merge; the
# aggregate diff is the landing's net effect, which is exactly what
# the guard exists to sanction. A rename away from a gate path is a
# removal, and a failed probe fails closed.
if (-not (Test-CrgGateUntrackSanctioned)) {
  $guScan = Get-CrgRangeGateRemoval -BaseSha $baseSha -TipSha $branchSha
  if (-not $guScan.Ok) {
    Write-Host "[auto-merge] ERROR: could not probe the base..tip name-status for the gate-untracking guard; refusing (fail closed)."
    exit 3
  }
  if ($null -ne $guScan.Removed) {
    Write-Host "[auto-merge] ERROR: the range $Base..$Branch REMOVES gate component '$($guScan.Removed)' from tracking."
    Write-Host "[auto-merge] Untracking a gate component is a shape transition; it lands only with the operator's explicit sanction: set CROSS_REVIEW_ALLOW_GATE_UNTRACK=1 for exactly this merge."
    exit 3
  }
}

# Resolve the merge gate's EFFECTIVE codex reasoning-effort (used to PIN the
# branch-review codex child below so the review runs at a deterministic, stamped
# tier rather than re-reading config). `unknown` -> do not pin (child inherits
# codex's own default).
$mergeEffort = Resolve-EffectiveCodexEffort -ExplicitEffort $ReasoningEffort -ConfigText (Get-CodexConfigText) -ExcludeMaxTier
Write-Host (Get-MergeReviewEffortStatusLine -Effort $mergeEffort)

# Consistency-doc exception (OPT-IN via CROSS_REVIEW_CONSISTENCY_DOC): the Claude
# merge wrapper fails closed (exit 3) whenever the configured consistency doc is
# in the changed-path set (its consistency precompute is not ported), and a claude
# child exit 3 ABORTS the merge. A known-ineligible preferred route is never
# launched: a doc-touching branch REFUSES -Backend claude up front (the refusal
# names -Backend codex as
# the remedy), and the detection result also gates the exhaustion fallback (a
# codex->claude substitute is refused for a doc-touching branch). A fresh install
# (env var unset) has NO special-casing: no doc forces a backend. Use NAME-STATUS
# (not raw diff text) so this script's own doc-mentioning comments do not
# false-trigger; resolve it from the already-pinned base/branch SHAs. A detection
# error fails toward LESS surprise (proceed with the requested -Backend) but is
# logged; the dominant case is a clean read.
# Normalize + validate the env value via the shared helper (trim, repo-relative,
# `\`->`/`). A whitespace-only / padded / absolute / `..`-escaping value is a
# BROKEN GATE CONFIG: it must FAIL CLOSED (abort the merge, exit 3), never
# silently skip the doc routing while the gate config is broken (the fail-OPEN
# bug -- a doc-touching branch would then burn a claude panel that itself fails
# closed, aborting opaquely, OR dodge the fallback refusal). $cfg.Doc is the
# normalized doc to match.
$cfgMergeDoc = Resolve-ConsistencyDocConfig -RawValue $env:CROSS_REVIEW_CONSISTENCY_DOC
if ($cfgMergeDoc.State -eq 'invalid') {
  Write-Host "[auto-merge] ERROR: $($cfgMergeDoc.Reason). The consistency-doc routing is a fail-closed config; refusing to merge with a broken CROSS_REVIEW_CONSISTENCY_DOC (fix or unset it). Aborting."
  exit 3
}
$consistencyDoc = $cfgMergeDoc.Doc
if ($cfgMergeDoc.State -eq 'valid') {
  # SHAPE-valid is not enough: a typo'd doc (`PLNA.md`) OR a directory (`docs/` ->
  # collapses to `docs`) is shape-valid yet is not a tracked FILE, so the branch-
  # diff test below never matches and the doc routing is silently skipped -- the
  # fail-OPEN this closes. Require the configured doc to resolve to a git BLOB in
  # the branch tree (`cat-file -t`, not `-e`, which accepts a tree); a missing/
  # tree/non-blob object is a BROKEN CONFIG -> fail closed (exit 3), never a silent
  # mis-route.
  $docKind = Get-GitObjectKind -TreeRef $branchSha -Path $consistencyDoc
  if (-not (Test-ConsistencyDocKind -Kind $docKind)) {
    Write-Host "[auto-merge] ERROR: CROSS_REVIEW_CONSISTENCY_DOC='$consistencyDoc' does not name a tracked FILE in the branch tree ($branchSha) (kind='$docKind') - a directory-valued or absent consistency doc is a broken gate config; refusing to merge (fix or unset it). Aborting."
    exit 3
  }
}
# Hoisted so the token-exhaustion fallback below can consult it: a
# codex->claude fallback is impossible when the branch touches the doc (the
# claude wrapper fails closed on any diff touching it). Detection failure
# leaves this $false -- the merge side degrades toward its ordinary routing,
# and a mis-routed claude fallback then fails closed on its own account
# (costing the attempt, never a silent pass).
$consistencyDocInBranch = $false
if ($cfgMergeDoc.State -eq 'valid') {
  try {
    # --no-ext-diff --no-textconv: this name-status drives a routing decision
    # (the -Backend claude refusal and the fallback refusal when the
    # consistency doc is in the branch), so a tree-configured external diff
    # driver / textconv filter must not be able to alter the path list and
    # flip the decision. Same trust-boundary rationale as the auto-review
    # wrappers' evidence calls. --no-relative pins repo-root paths despite the
    # process CWD and diff.relative config. core.quotePath=false makes a
    # configured non-ASCII document compare as its actual UTF-8 path instead of
    # Git's C-quoted spelling.
    $branchNameStatus = (& git -c core.quotePath=false diff --no-color --no-ext-diff --no-textconv --no-relative --ignore-submodules=none --name-status "$baseSha...$branchSha" 2>$null | Out-String)
    $diffExit = $LASTEXITCODE
    if ($diffExit -ne 0) {
      # A NONZERO git exit is swallowed by `2>$null` and would otherwise fail the
      # `-eq 0` test SILENTLY (only a TERMINATING error reaches the catch below).
      # Log it explicitly before proceeding so the "is logged" contract in the
      # comment above holds for the nonzero-exit path too. (Degrading toward the
      # requested backend costs at most a burned claude panel that fails closed
      # on its own account, never a silent pass.)
      Write-Host "[auto-merge] WARN: '$consistencyDoc' detection git diff --name-status exited $diffExit - cannot determine whether the branch touches the consistency doc; proceeding with the requested -Backend"
    } elseif (Test-ConsistencyDocInNameStatus -NameStatus $branchNameStatus -Doc $consistencyDoc) {
      $consistencyDocInBranch = $true
      if ([string]::Equals($Backend, 'claude', [System.StringComparison]::Ordinal)) {
        Write-Host "[auto-merge] $consistencyDoc is in the branch diff and -Backend claude was chosen - the claude wrapper fails closed on any diff touching it, so the panel would be burned. Merge ABORTED (fail closed); re-run with -Backend codex."
        exit 3
      }
      Write-Host "[auto-merge] $consistencyDoc in branch diff - automatic alternate-provider routing is unavailable for this branch."
    }
  } catch {
    Write-Host "[auto-merge] $consistencyDoc detection error ($($_.Exception.Message)) - proceeding with the requested -Backend"
  }
}

Write-Host (Get-MergePanelPlanStatusLine -PassCount $script:PanelPassCount)

# Snapshot the base-branch review infra to a tempdir so the running gate is
# guaranteed to come from $Base, not from the candidate branch.
#
# A SEPARATE fresh per-run scratch dir owned by THIS auto-merge invocation.
# Every launched panel/fallback child runs with an explicit -OutDir into its
# own per-slot subdir here. The gate-owned writers are the review process (its verdict
# `review-*-branch-*.md` and its staged `followups.pending.md`, promoted
# post-merge by Invoke-FollowupPromotion or discarded with the run dir on abort)
# and Start-ReviewChild (the runner scaffolding --
# child-args.txt, child-exit.txt, child-runner.ps1, child-stdout.log, and
# child-stderr.log). NOTE this dir is under
# $env:TEMP with default ACLs -- that is NOT an OS-enforced no-other-writer
# boundary (a same-user process could write here). The dir is auto-merge-CREATED
# fresh for THIS run, so no pre-existing planted file can be inside it. Child
# process exits establish the panel outcome, but an exit-zero panel does not
# authorize merge by itself: the current run-owned captures and exact unique
# `review-*-branch-*.md` artifacts must also pass the held-file, provider,
# review-identity, verdict, and semantic projection checks. After the review,
# the run's VERDICT artifacts (the
# `review-*` {.md,.jsonl,.stderr.log,.exhaustion.json,.errored.txt} shape)
# are COPIED into the centralized
# shared logs for forensics and the top-level trend analyzer (which scans BOTH
# backend log dirs by default); the Start-ReviewChild scaffolding
# (child-args.txt / child-exit.txt / child-runner.ps1 / child-stdout.log /
# child-stderr.log) is TRANSIENT and is NOT
# centralized -- it is discarded with the run dir (the wrappers do NOT
# auto-centralize when an explicit -OutDir is given). The
# finally block then deletes BOTH the trusted-infra dir AND the run dir
# CONDITIONALLY: it preserves the trusted-infra dir while any child is still
# running (a live child reads its -PromptPath from it), and preserves the run dir
# when a child is still running OR consolidation could not centralize every
# VERDICT artifact (a scaffolding-only run dir is safe to delete; see the finally
# for details).
#
# These directory paths are assigned BEFORE the main try/catch (the catch maps
# review/invocation failures to exit 3) because the finally block must reference
# them for cleanup. The New-Item creations are wrapped in their OWN fail-closed
# try/catch: a setup failure here would otherwise terminate under
# $ErrorActionPreference='Stop' with a raw exit (1), which the exit contract does
# not treat as a valid review verdict (exit 1 is retired under the 2026-07 severity
# contract -- QUALITY passes as 0). On failure, clean up whatever was created and
# exit 3 (invocation failure).
$trustedDir = Join-Path $env:TEMP "crg-auto-merge-trusted-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$runDir = Join-Path $env:TEMP "crg-auto-merge-run-$([guid]::NewGuid().ToString('N').Substring(0,8))"
try {
  New-Item -ItemType Directory -Path $trustedDir -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $trustedDir 'scripts\codex') -Force | Out-Null
  New-Item -ItemType Directory -Path $runDir -Force | Out-Null
} catch {
  Write-Host "[auto-merge] ERROR: could not create scratch directories ($($_.Exception.Message)) - merge ABORTED (fail closed)."
  Remove-TreeNoRecurse -Path $trustedDir
  Remove-TreeNoRecurse -Path $runDir
  exit 3
}

$reviewRepoRootRows = @(& git rev-parse --show-toplevel 2>$null)
$reviewRepoRootExit = $LASTEXITCODE
$reviewRepoRoot = if ($reviewRepoRootRows.Count -eq 1) { [string]$reviewRepoRootRows[0] } else { '' }
if ($reviewRepoRootExit -ne 0 -or [string]::IsNullOrWhiteSpace($reviewRepoRoot)) {
  Write-Host '[auto-merge] ERROR: the repository root could not be resolved while pinning successful-review evidence - merge ABORTED (fail closed).'
  Remove-TreeNoRecurse -Path $trustedDir
  Remove-TreeNoRecurse -Path $runDir
  exit 3
}
$reviewExpectedIdentity = Get-CrgBranchReviewExpectedIdentity -RepoRoot $reviewRepoRoot `
  -BaseSha $baseSha -TipSha $branchSha -RunDir $runDir
if (-not $reviewExpectedIdentity.Ok) {
  Write-Host '[auto-merge] ERROR: the provider-neutral successful-review identity could not be pinned before child launch - merge ABORTED (fail closed).'
  Remove-TreeNoRecurse -Path $trustedDir
  Remove-TreeNoRecurse -Path $runDir
  exit 3
}

# Extract the review infra from BASE so a candidate branch cannot weaken the
# reviewer that decides whether it may merge -- otherwise a candidate branch
# could ship a weakened wrapper and have THAT decide its own panel. Both
# providers' wrappers extract by the same `git show` mechanism.
#
# This whole extraction block runs BEFORE the main review try/catch (that try
# maps review/invocation failures to exit 3), still under
# $ErrorActionPreference='Stop'. Wrap it in its OWN fail-closed try/catch so ANY
# setup terminating error -- the scripts\claude New-Item, the per-file outDir
# New-Item, or the WriteAllText -- maps to invocation-failure exit 3, not
# PowerShell's raw exit 1 (no longer a valid review verdict -- exit 1 is retired
# under the 2026-07 severity contract). The explicit `git show` non-zero check
# below keeps its own specific exit-3 message.
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

try {
  # BOTH providers' wrappers are extracted unconditionally: the chosen
  # backend's panel needs its own, and the exhaustion fallback may need the
  # OTHER provider's mid-run -- extraction is base-pinned and cheap, and a
  # missing fallback wrapper at substitution time would turn a recoverable
  # exhaustion into an abort. The shared modules the wrappers import from
  # their scripts/ parent come from the same base, so a candidate cannot
  # change the liveness code watching its own panel. A module is required only
  # when an extracted trusted wrapper names it: wrappers from a base older than
  # the module never import it and must still review (merge-panel BLOCKER
  # 2026-10-07). Keep the module list in step with REVIEW_MODULES in
  # scripts/git-hooks/pre-commit.
  $reviewWrapperInfra = @(
    'scripts/codex/auto-review.ps1',
    'scripts/codex/review-prompt-template.md',
    'scripts/claude/auto-review.ps1'
  )
  $reviewModules = @('scripts/review-liveness.psm1', 'scripts/review-common.ps1')
  $localReviewInfraUsed = $false
  New-Item -ItemType Directory -Path (Join-Path $trustedDir 'scripts\claude') -Force | Out-Null
  $reviewInfra = New-Object 'System.Collections.Generic.List[string]'
  foreach ($f in $reviewWrapperInfra) { $reviewInfra.Add($f) }
  for ($reviewInfraIndex = 0; $reviewInfraIndex -lt $reviewInfra.Count; $reviewInfraIndex++) {
    $f = $reviewInfra[$reviewInfraIndex]
    $outPath = Join-Path $trustedDir $f.Replace('/', '\')
    $outDir = Split-Path $outPath -Parent
    if (-not (Test-Path $outDir)) {
      New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    # Resolve-CrgTrustedInfraSource holds the whole source decision:
    # base extraction (joined with LF and written UTF-8-no-BOM so the
    # extracted file actually parses as code -- a previous version
    # collapsed it to a single comment line via `Set-Content
    # -NoNewline`), the manifest-verified local snapshot on positive
    # base absence, and the fail-closed $null for everything else.
    $infraSrc = Resolve-CrgTrustedInfraSource -BaseSha $baseSha -RelPath $f
    if ($null -eq $infraSrc) {
      Write-Host "[auto-merge] ERROR: no trusted source for $f. Either the base '$Base' ($baseSha) probe failed or holds a non-regular entry there, or the path is positively absent from base and no manifest-verified local copy was admitted (the package's docs/local-install-v1.md). Diagnose the base tree first. For the LOCAL shape, run the retained package installer, immediately followed by the installed renderer check:"
      Write-Host '  powershell -NoProfile -ExecutionPolicy Bypass -File "<path-to>\cross-review-gate\bootstrap.ps1" -TargetRepo "<repo>" -Force'
      Write-Host '  powershell -NoProfile -ExecutionPolicy Bypass -File "<repo>\scripts\render-project-values.ps1" -TargetRepo "<repo>" -Check'
      Write-Host '[auto-merge] If exact LOCAL recovery is required, first complete the bounded sanctioned -SealManifest step in docs/install-values-v1.md, then run both commands above in order. Never retry this merge on sealed drift.'
      Remove-TreeNoRecurse -Path $trustedDir
      Remove-TreeNoRecurse -Path $runDir
      exit 3
    }
    if ($infraSrc.Kind -ceq 'local') {
      $localReviewInfraUsed = $true
      [System.IO.File]::WriteAllBytes($outPath, $infraSrc.Bytes)
    } else {
      [System.IO.File]::WriteAllText($outPath, $infraSrc.Text, $utf8NoBom)
    }
    if ($reviewInfraIndex -eq $reviewWrapperInfra.Count - 1) {
      # A name in a comment also counts; over-requiring can only abort.
      foreach ($reviewModule in $reviewModules) {
        $reviewModuleLeaf = $reviewModule.Substring($reviewModule.LastIndexOf('/') + 1)
        foreach ($reviewWrapper in @('scripts/codex/auto-review.ps1', 'scripts/claude/auto-review.ps1')) {
          $reviewWrapperText = [System.IO.File]::ReadAllText((Join-Path $trustedDir $reviewWrapper.Replace('/', '\')), $utf8NoBom)
          if ($reviewWrapperText.Contains($reviewModuleLeaf)) { $reviewInfra.Add($reviewModule); break }
        }
      }
    }
  }
  if ($localReviewInfraUsed) {
    Write-Host '[auto-merge] local install shape: review infrastructure manifest-verified'
  }
} catch {
  Write-Host "[auto-merge] ERROR: could not extract trusted review infra ($($_.Exception.Message)) - merge ABORTED (fail closed)."
  Remove-TreeNoRecurse -Path $trustedDir
  Remove-TreeNoRecurse -Path $runDir
  exit 3
}

$trustedWrapper = Join-Path $trustedDir 'scripts\codex\auto-review.ps1'
$trustedPrompt  = Join-Path $trustedDir 'scripts\codex\review-prompt-template.md'
$trustedClaudeWrapper = Join-Path $trustedDir 'scripts\claude\auto-review.ps1'

# TOLERANT extraction of worker-audit.ps1 for the NON-GATING post-merge process
# audit, through the SAME trust decision as the review infra above
# (Resolve-CrgTrustedInfraSource): the BASE commit's copy when it exists, else
# -- on positive absence -- the manifest-verified LOCAL snapshot, so the
# supported LOCAL install shape (gate files deliberately kept out of HEAD)
# still audits its landings. The just-merged candidate content at
# $PSScriptRoot is never executed: after `git merge --ff-only` the working
# tree is candidate content, and a candidate branch must not inject side
# effects into a script auto-merge runs during the merge. Unlike the
# fail-closed infra loop, an unresolvable worker-audit must NOT abort the
# merge (a non-gating addon; the very commit that introduces it has no base
# copy): $trustedWorkerAudit stays $null and the post-merge block skips the
# audit with a note.
$trustedWorkerAudit = $null
try {
  $waSrc = Resolve-CrgTrustedInfraSource -BaseSha $baseSha -RelPath 'scripts/shared/worker-audit.ps1'
  if ($null -ne $waSrc) {
    $waOut = Join-Path $trustedDir 'scripts\shared\worker-audit.ps1'
    $waDir = Split-Path $waOut -Parent
    if (-not (Test-Path $waDir)) { New-Item -ItemType Directory -Path $waDir -Force | Out-Null }
    if ($waSrc.Kind -eq 'local') { [System.IO.File]::WriteAllBytes($waOut, [byte[]]$waSrc.Bytes) }
    else { [System.IO.File]::WriteAllText($waOut, [string]$waSrc.Text, $utf8NoBom) }
    $trustedWorkerAudit = $waOut
  }
} catch {
  $trustedWorkerAudit = $null
}

Write-Host '[auto-merge] Running adversarial review on the pinned branch diff...'

# Panel bookkeeping, initialized OUTSIDE the try so the finally block always
# sees them: every launched child (panel and fallback alike) joins the
# defensive join, every child run dir joins the consolidation, and every
# staged follow-up path joins the post-merge promotion -- even when an
# exception lands mid-run.
$panelChildren = @()
$fbJoinList = @()
$consolidateDirs = @()
$allPendingPaths = @()
$panelExits = @()
# Every launched review child is also registered for caller-output handling.
# Successful runs never publish these captures. Review-derived BLOCKER/fail-
# closed outcomes publish them once under bounds; Preserve retains a complete
# capture whenever replay had to reduce it or could not read it.
$reviewTranscriptChildren = @()
$reviewReplayState = @{ Published = $false; Preserve = $false; Pending = $false }
$reviewPhaseActive = $false
# Set by the post-merge audit when its child's exit could not be CONFIRMED
# (kill attempted, wait threw); the finally then preserves the run and
# trusted dirs exactly as for a live review child.
$auditChildUnconfirmed = $false
# Second preservation reason from the same child: a capture the read had to
# BOUND leaves the in-memory text a reduction, so the run dir holding the
# complete capture must outlive the run for the warning to be actionable.
$auditCaptureBounded = $false

try {
  $reviewPhaseActive = $true
  # Resolve the panel plan NOW that the trusted claude wrapper file exists to
  # probe (-ArtifactTag): a claude panel runs as CONCURRENT tagged children,
  # and forwarding an undeclared parameter would param-bind-fail every child.
  # The consistency-doc arm already refused above for -Backend claude; the
  # pure resolver keeps that arm as defense in depth.
  $claudeTagDecl = Get-WrapperParameterDeclaration -WrapperPath $trustedClaudeWrapper -ParamName 'ArtifactTag'
  $panelPlan = Resolve-MergePanelPlan -Backend $Backend -ConsistencyDocInBranch $consistencyDocInBranch -ClaudeTagDeclaration $claudeTagDecl
  if ($panelPlan.Action -eq 'refuse-consistency') {
    Write-Host "[auto-merge] $consistencyDoc is in the branch diff and -Backend claude was chosen - the claude wrapper fails closed on any diff touching it, so the panel would be burned. Merge ABORTED (fail closed); re-run with -Backend codex."
    exit 3
  }
  if ($panelPlan.Action -eq 'refuse-tag') {
    Write-Host "[auto-merge] -Backend claude was chosen but the base's claude wrapper does not declare -ArtifactTag (probe: $claudeTagDecl) - concurrent tagged panel children would param-bind-fail on it. Merge ABORTED (fail closed); land the updated claude wrapper on the base first, or re-run with -Backend codex."
    exit 3
  }

  # Launch the chosen provider's panel. -Tip is the pinned SHA so review and
  # merge target the same content even if $Branch moves. Each child gets an
  # explicit -OutDir into its run-owned slot subdir (its verdict artifacts
  # feed the post-merge forensics copy) together with the
  # -CentralDestinationExpected declaration this gate owes it whenever the
  # base-extracted wrapper can bind it (see Get-ReviewChildArgs).
  #
  # Parent-directed follow-up staging (merge-gate BLOCKER 2026-07-10): each
  # child wrapper STAGES its QUALITY follow-ups at the
  # CROSS_REVIEW_FOLLOWUPS_PENDING path instead of appending them to the
  # durable index -- this gate can still abort on the panel verdict, the
  # branch-pin verification, or the ff-merge itself AFTER a child passes, and
  # follow-ups for an unmerged branch must never reach the index. Promotion
  # happens below, only after the ff-merge succeeds. A child's env is
  # captured at process creation, so the per-child path is set immediately
  # before each launch and the variable is restored right after the launches.
  #
  # Launch via Start-ReviewChild: the wrapper runs in a thin runner that
  # records its $LASTEXITCODE to a run-owned exit FILE (the deterministic
  # claimed result) and whose process handle is handle-cached at spawn. The
  # file is accepted only when the immutable process exit corroborates it;
  # both sources together close
  # the PS 5.1 `Start-Process -PassThru` null-ExitCode quirk that, observed
  # live, printed an empty exit code and forced the gate to fail closed on
  # EVERY merge.
  $savedFollowupsPending = $env:CROSS_REVIEW_FOLLOWUPS_PENDING
  Write-Host (Get-MergePanelLaunchStatusLine -PassCount $script:PanelPassCount)
  foreach ($slot in $panelPlan.Slots) {
    $slotSpec = Resolve-PanelSlotSpec -Backend $Backend -Slot $slot -RunDir $runDir
    New-Item -ItemType Directory -Path $slotSpec.Dir -Force | Out-Null
    if ([string]::Equals($Backend, 'codex', [System.StringComparison]::Ordinal)) {
      $slotArgs = Get-ReviewChildArgs -WrapperPath $trustedWrapper -PromptPath $trustedPrompt `
        -Base $baseSha -BranchSha $branchSha -RunDir $slotSpec.Dir `
        -Title "Pre-merge review (codex): $Branch ($branchSha) -> $Base" -ReviewPasses $script:PanelPassCount
      # Pin the codex child to $mergeEffort (the gate's resolved effective
      # tier) whenever it is a known tier, so the review runs at a
      # deterministic, stamped tier rather than re-reading config.
      if (-not [string]::Equals($mergeEffort, 'unknown', [System.StringComparison]::Ordinal)) { $slotArgs += @('-ReasoningEffort', $mergeEffort) }
    } else {
      $slotArgs = Get-ReviewChildArgs -WrapperPath $trustedClaudeWrapper -PromptPath $trustedPrompt `
        -Base $baseSha -BranchSha $branchSha -RunDir $slotSpec.Dir `
        -Title "Pre-merge review (claude ${slot}): $Branch ($branchSha) -> $Base" -ReviewPasses 0
    }
    $slotArgs += $slotSpec.ExtraArgs
    $env:CROSS_REVIEW_FOLLOWUPS_PENDING = $slotSpec.Pending
    $slotChild = Start-ReviewChild -RunDir $slotSpec.Dir -WrapperArgs $slotArgs -Utf8NoBom $utf8NoBom
    $script:panelChildren += ,@{ Name = $slotSpec.Name; Dir = $slotSpec.Dir; Child = $slotChild; Proc = $slotChild.Proc }
    $script:reviewTranscriptChildren += ,$slotChild
    $script:consolidateDirs += ,@{ Dir = $slotSpec.Dir; Backend = $Backend; Owner = $slotSpec.Name }
    $script:allPendingPaths += ,@{ Path = $slotSpec.Pending; Backend = $Backend }
  }
  # Every child captured its pending path at launch; restore the caller's
  # value so THIS process's later git/PS activity never runs with a stale one.
  if ($null -eq $savedFollowupsPending) { Remove-Item Env:CROSS_REVIEW_FOLLOWUPS_PENDING -ErrorAction SilentlyContinue }
  else { $env:CROSS_REVIEW_FOLLOWUPS_PENDING = $savedFollowupsPending }

  # WAIT FOR EVERY LAUNCHED CHILD BEFORE branching on any result: an early
  # `exit 3` taken between the waits would leave a sibling still running --
  # the finally block would then copy+delete the scratch dirs while that
  # child is mid-write, orphaning the process and racing its artifacts.
  # Joining all first makes cleanup and forensics deterministic on every exit
  # path. These are INTENTIONALLY unbounded waits: the gate's whole job here
  # is to wait for the review to finish, which legitimately takes many
  # minutes; an artificial timeout would abandon a still-valid review.
  # WaitForExit is idempotent and safe on an already-exited process. (A hung
  # child would block here indefinitely -- acceptable for an interactive gate
  # the operator is watching; the BOUNDED wait lives only in the finally's
  # exception-path defensive-join, where preserving the run dir on timeout
  # matters.)
  foreach ($pc in $panelChildren) { if ($null -ne $pc.Proc) { $pc.Proc.WaitForExit() } }

  # Resolve every exit code from its run-owned exit FILE (the deterministic
  # source written by each runner) now that all children have exited.
  # Cross-check each against the handle-cached process .ExitCode: the exit
  # file is a MUTABLE input (default-ACL $env:TEMP), so a readable handle
  # value that MISMATCHES the file value means the file cannot be trusted
  # (tamper, or a runner that exited differently than it recorded) ->
  # Test-ChildExitConsistency returns $false and the merge FAILS CLOSED
  # before unioning. No readable process value (launch failure / PS
  # .ExitCode quirk) also fails closed: the mutable file alone never mints
  # PASS or fallback eligibility. A $null resolution (missing/empty/
  # unparsable file, or the '999' crash sentinel a launch failure pre-seeds)
  # means that child never recorded a real verdict -> fail closed. Every
  # child is resolved by INTENT (the panelChildren entry exists), never by
  # whether its process launched -- a failed Start-Process must never be
  # silently skipped.
  foreach ($pc in $panelChildren) {
    $pcExit = Resolve-ReviewChildExit -ExitFile $pc.Child.ExitFile -BackendName $pc.Name
    if (-not (Test-ChildExitConsistency -BackendName $pc.Name -FileExit $pcExit -Proc $pc.Proc)) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] $($pc.Name) review exit-code failed the file-vs-process cross-check - merge ABORTED (fail closed)."
      exit 3
    }
    if ($null -eq $pcExit) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] $($pc.Name) review produced no readable exit code - merge ABORTED (fail closed)."
      exit 3
    }
    $script:panelExits += [int]$pcExit
  }

  # Forensics: run-owned verdict artifacts are copied into the centralized shared
  # logs in the finally block below (both backends' artifacts feed the top-level
  # trend analyzer, which scans both log dirs by default) so they are preserved on
  # EVERY exit path -- including a child exit-3, the panel-validation
  # fail-closed (a stray non-{0,2,3,4} code, e.g. a retired exit 1), and the BLOCKER
  # exits, all of which leave this try before reaching the ff-merge and would
  # otherwise have their artifacts deleted by finally uncopied. (There is no QUALITY
  # switch exit under the 2026-07 contract -- a QUALITY-only verdict exits 0 from the
  # child wrapper and proceeds through the PASS branch.) Non-fatal to
  # the MERGE DECISION (that is made below against the run-owned dirs, never the
  # shared logs), but the consolidation itself is fail-LOUD -- a copy failure is
  # reported visibly and names what was lost (see Copy-RunArtifactsToCentralLogs),
  # because a silently-missing forensic trail is the bug this hardening removed.

  $fallbackHappened = $false
  $fallbackProvider = ''
  $fallbackPendingPaths = @()
  $fallbackReviewDirs = @()
  # LOWER-BOUND check before classification: every launched child must have
  # resolved a validated exit (the loop above exits 3 on any unresolvable
  # child, so a mismatch here means the accounting itself broke -- and an
  # under-counted exit set must never be classified as if it were the panel).
  if (@($panelExits).Count -ne @($panelChildren).Count) {
    Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
    Write-Host "[auto-merge] panel accounting failure: $(@($panelExits).Count) exit(s) resolved for $(@($panelChildren).Count) launched child(ren) - merge ABORTED (fail closed)."
    exit 3
  }
  $panelOutcome = Resolve-PanelOutcome -Exits $panelExits
  switch ($panelOutcome.Action) {
    'abort-empty' {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] panel accounting failure: zero child exits reached classification - merge ABORTED (fail closed)."
      exit 3
    }
    'abort-exit3' {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      if ([string]::Equals($Backend, 'claude', [System.StringComparison]::Ordinal)) {
        # Claude exit 3 is the Claude wrapper's GENERAL fail-closed code --
        # consistency-doc, ancestor CLAUDE.md trust breach, auth failure,
        # malformed/empty output -- NOT only quota; the gate cannot tell
        # those apart from the exit code, so it never substitutes for it.
        Write-Host "[auto-merge] a claude panel child failed closed (exit 3; panel exits: $($panelExits -join ',')) - merge ABORTED."
        Write-Host (Get-ClaudePanelExit3RetryLine)
      } else {
        Write-Host "[auto-merge] codex review invocation failed (exit 3) - merge ABORTED (fail closed)."
      }
      exit 3
    }
    'abort-unknown' {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] a panel child returned an exit outside the verdict set (panel exits: $($panelExits -join ',')) - not a valid verdict (exit 1 was retired with the 2026-07 severity contract; QUALITY now passes as 0). Merge ABORTED (fail closed)."
      exit 3
    }
    'blocker-decisive' {
      Publish-ReviewFailureTranscripts -FinalExitCode 2 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] the review panel reported decisive BLOCKER findings; no additional review route was launched. Merge ABORTED. Fix the findings and re-run."
      exit 2
    }
  }
  $unionExit = if ($panelOutcome.Action -eq 'union') { $panelOutcome.Exit } else { $null }

  # --- Token-exhaustion FULL-PANEL fallback (operator fallback ruling
  # 2026-08-22, reshaped by P4): the PREFERRED provider's initial panel reported
  # positively-identified exhaustion (a child exit 4 with the durable
  # .exhaustion.json sidecar; every ambiguous failure stays exit 3 and
  # aborted above) with no decisive sibling (every sibling passed or is
  # itself exhausted), so a FULL panel on the OTHER provider substitutes
  # and its verdict becomes the merge verdict. Both pools exhausted fails
  # closed. Successful substitution remains caller-transparent; durable
  # artifacts retain the provider and exhaustion evidence.
  $fbPlan = if ($panelOutcome.Action -eq 'fallback') {
    Resolve-MergeFallbackPlan -ChosenBackend $Backend -ConsistencyDocInBranch $consistencyDocInBranch -ClaudeTagDeclaration $claudeTagDecl
  } else { @{ Action = 'none' } }
  switch ($fbPlan.Action) {
    'refuse-consistency' {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] automatic review routing cannot cover this branch while $consistencyDoc is in the diff. Merge ABORTED (fail closed); retry later or split the $consistencyDoc change onto a separately reviewable branch."
      exit 3
    }
    'refuse-tag' {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] automatic review routing requires the current tagged-child wrapper contract, but the trusted base does not provide it (probe: $claudeTagDecl). Merge ABORTED (fail closed); land the current wrapper on the base first."
      exit 3
    }
  }
  if ($fbPlan.Action -eq 'fallback-claude') {
    $fbLaunched = @()
    foreach ($fbTag in @(1..$script:PanelPassCount | ForEach-Object { "fb$_" })) {
      $fbSpec = Resolve-PanelSlotSpec -Backend 'claude' -Slot $fbTag -RunDir $runDir
      New-Item -ItemType Directory -Path $fbSpec.Dir -Force | Out-Null
      $fbArgs = Get-ReviewChildArgs -WrapperPath $trustedClaudeWrapper -PromptPath $trustedPrompt `
        -Base $baseSha -BranchSha $branchSha -RunDir $fbSpec.Dir `
        -Title "Pre-merge review (claude fallback ${fbTag}): $Branch ($branchSha) -> $Base" -ReviewPasses 0
      $fbArgs += $fbSpec.ExtraArgs
      $env:CROSS_REVIEW_FOLLOWUPS_PENDING = $fbSpec.Pending
      $fbChild = Start-ReviewChild -RunDir $fbSpec.Dir -WrapperArgs $fbArgs -Utf8NoBom $utf8NoBom
      $fbLaunched += ,@{ Child = $fbChild; Tag = $fbTag }
      $script:reviewTranscriptChildren += ,$fbChild
      $script:fbJoinList += ,@{ N = $fbSpec.Name; P = $fbChild.Proc }
      $script:consolidateDirs += ,@{ Dir = $fbSpec.Dir; Backend = 'claude'; Owner = $fbSpec.Name }
      $fallbackPendingPaths += $fbSpec.Pending
      $fallbackReviewDirs += $fbSpec.Dir
    }
    if ($null -eq $savedFollowupsPending) { Remove-Item Env:CROSS_REVIEW_FOLLOWUPS_PENDING -ErrorAction SilentlyContinue }
    else { $env:CROSS_REVIEW_FOLLOWUPS_PENDING = $savedFollowupsPending }
    foreach ($fb in $fbLaunched) { if ($null -ne $fb.Child.Proc) { $fb.Child.Proc.WaitForExit() } }
    # Classification collects EVERY child's exit first: a sibling BLOCKER
    # outranks a later-met exhaustion (the union is 2 regardless of what
    # any pool has left), so the loop must never abort on the first exit 4
    # it happens to encounter.
    $fbExits = @()
    foreach ($fb in $fbLaunched) {
      $fbExit = Resolve-ReviewChildExit -ExitFile $fb.Child.ExitFile -BackendName "claude-$($fb.Tag)"
      if (-not (Test-ChildExitConsistency -BackendName "claude-$($fb.Tag)" -FileExit $fbExit -Proc $fb.Child.Proc)) {
        Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
        Write-Host "[auto-merge] an automatically routed review child failed the exit-code cross-check - merge ABORTED (fail closed)."
        exit 3
      }
      if ($null -eq $fbExit) {
        Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
        Write-Host "[auto-merge] an automatically routed review child produced no readable exit code. Merge ABORTED (fail closed)."
        exit 3
      }
      $fbExits += [int]$fbExit
    }
    if (@($fbExits).Count -ne @($fbLaunched).Count) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] automatically routed panel accounting failure: $(@($fbExits).Count) exit(s) resolved for $(@($fbLaunched).Count) launched child(ren) - merge ABORTED (fail closed)."
      exit 3
    }
    $fbOutcome = Resolve-PanelOutcome -Exits $fbExits
    switch ($fbOutcome.Action) {
      'abort-empty' {
        Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
        Write-Host "[auto-merge] automatically routed panel accounting failure: zero child exits reached classification - merge ABORTED (fail closed)."
        exit 3
      }
      'abort-exit3' {
        Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
        Write-Host "[auto-merge] automatic review routing failed closed before producing a valid panel verdict. Merge ABORTED."
        exit 3
      }
      'abort-unknown' {
        Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
        Write-Host "[auto-merge] automatic review routing returned an invalid panel state. Merge ABORTED (fail closed)."
        exit 3
      }
      'blocker-decisive' {
        Publish-ReviewFailureTranscripts -FinalExitCode 2 -Children $reviewTranscriptChildren -State $reviewReplayState
        Write-Host "[auto-merge] the effective review panel reported BLOCKER findings. Merge ABORTED. Fix the findings and re-run."
        exit 2
      }
      'fallback' {
        Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
        Write-Host "[auto-merge] no review provider produced a verdict. Merge ABORTED (fail closed)."
        exit 3
      }
    }
    $unionExit = $fbOutcome.Exit
    $fallbackHappened = $true
    $fallbackProvider = 'claude'
  } elseif ($fbPlan.Action -eq 'fallback-codex') {
    $fbSpec = Resolve-PanelSlotSpec -Backend 'codex' -Slot 'fb1' -RunDir $runDir
    New-Item -ItemType Directory -Path $fbSpec.Dir -Force | Out-Null
    $fbArgs = Get-ReviewChildArgs -WrapperPath $trustedWrapper -PromptPath $trustedPrompt `
      -Base $baseSha -BranchSha $branchSha -RunDir $fbSpec.Dir `
      -Title "Pre-merge review (codex fallback fb1): $Branch ($branchSha) -> $Base" -ReviewPasses $script:PanelPassCount
    if (-not [string]::Equals($mergeEffort, 'unknown', [System.StringComparison]::Ordinal)) { $fbArgs += @('-ReasoningEffort', $mergeEffort) }
    $fbArgs += $fbSpec.ExtraArgs
    $env:CROSS_REVIEW_FOLLOWUPS_PENDING = $fbSpec.Pending
    $fbChild = Start-ReviewChild -RunDir $fbSpec.Dir -WrapperArgs $fbArgs -Utf8NoBom $utf8NoBom
    $script:reviewTranscriptChildren += ,$fbChild
    $script:fbJoinList += ,@{ N = $fbSpec.Name; P = $fbChild.Proc }
    $script:consolidateDirs += ,@{ Dir = $fbSpec.Dir; Backend = 'codex'; Owner = $fbSpec.Name }
    $fallbackPendingPaths += $fbSpec.Pending
    $fallbackReviewDirs += $fbSpec.Dir
    if ($null -eq $savedFollowupsPending) { Remove-Item Env:CROSS_REVIEW_FOLLOWUPS_PENDING -ErrorAction SilentlyContinue }
    else { $env:CROSS_REVIEW_FOLLOWUPS_PENDING = $savedFollowupsPending }
    if ($null -ne $fbChild.Proc) { $fbChild.Proc.WaitForExit() }
    $fbExit = Resolve-ReviewChildExit -ExitFile $fbChild.ExitFile -BackendName 'codex-fb1'
    if (-not (Test-ChildExitConsistency -BackendName 'codex-fb1' -FileExit $fbExit -Proc $fbChild.Proc)) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] an automatically routed review child failed the exit-code cross-check - merge ABORTED (fail closed)."
      exit 3
    }
    if ($null -eq $fbExit) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] an automatically routed review child produced no readable exit code. Merge ABORTED (fail closed)."
      exit 3
    }
    if ($fbExit -eq 4) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] no review provider produced a verdict. Merge ABORTED (fail closed)."
      exit 3
    }
    if ($fbExit -notin @(0, 2)) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] automatic review routing failed closed before producing a valid panel verdict. Merge ABORTED."
      exit 3
    }
    $unionExit = $fbExit
    $fallbackHappened = $true
    $fallbackProvider = 'codex'
  }

  # The merge verdict is the (substituted) panel verdict: worst severity of
  # the validated child exits {0,2}. Every 3/4/unknown code aborted through
  # the arms above (Resolve-PanelOutcome and the fallback's own validation),
  # so $unionExit here is 0 or 2 by construction -- the defensive default
  # arm below still fails closed on anything else. Under the 2026-07
  # severity contract QUALITY is NON-BLOCKING: the wrappers exit 0 for a
  # QUALITY-only verdict -- only a BLOCKER (exit 2) aborts the merge. Each
  # child wrapper STAGED its QUALITY-bearing PASS's follow-ups
  # (CROSS_REVIEW_FOLLOWUPS_PENDING); they are promoted to
  # logs/review-followups.md only after the ff-merge succeeds.
  if ($null -eq $unionExit) {
    Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
    Write-Host "[auto-merge] no panel verdict was produced (internal state error) - merge ABORTED (fail closed)."
    exit 3
  }

  # The immediate audit sees only the panel that supplied this verdict. All
  # launched panels remain registered in $consolidateDirs and are centralized
  # in finally, so transparency changes caller routing disclosure, not forensic
  # retention.
  $effectiveReviewDirs = @(Select-EffectiveReviewChildDirs `
    -PrimaryDirs @($panelChildren | ForEach-Object { $_.Dir }) `
    -SubstituteDirs $fallbackReviewDirs -Substituted $fallbackHappened)

  if ($unionExit -eq 0) {
    $successProjection = Get-CrgSuccessfulReviewProjection `
      -ReviewDirs $effectiveReviewDirs `
      -ExpectedTreeOid $reviewExpectedIdentity.TreeOid `
      -ExpectedDiffSha $reviewExpectedIdentity.DiffSha `
      -ExpectedTipPrefix $branchSha.Substring(0, 12) `
      -ExpectedBasePrefix $baseSha.Substring(0, 12)
    if (-not $successProjection.Ok) {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host '[auto-merge] successful-review semantic evidence was missing, malformed, conflicting, or identity-mismatched - merge ABORTED (fail closed).'
      exit 3
    }
    Publish-CrgSuccessfulReviewProjection -Lines $successProjection.Lines
    # Status lines must not fail the merge (Get-CrgReviewFeedbackStatusLines),
    # so neither collecting nor printing them may throw past here.
    try {
      try { $feedbackLines = @(Get-CrgReviewFeedbackStatusLines -ChildDirs (@($panelChildren | ForEach-Object { $_.Dir }) + @($fallbackReviewDirs))) }
      catch { $feedbackLines = @('review-feedback WARN: the review-feedback warnings could not be collected') }
      if ($feedbackLines.Count -gt 0) { Publish-CrgSuccessfulReviewProjection -Lines $feedbackLines }
    } catch { }
  }

  Write-Host ""
  Write-Host (Get-MergePanelVerdictStatusLine -ExitCode $unionExit)

  switch ($unionExit) {
    0 {
      Write-Host "[auto-merge] PASS - $(Get-ReviewPassCoverageText -GitContext (Resolve-FollowupGitContext)) - proceeding with ff-merge (verdicts may contain informational NOTE and/or non-blocking QUALITY findings; the wrappers exit 0 for CLEAN, NOTE-only, and QUALITY-only, and each QUALITY-bearing PASS's staged follow-ups are promoted to logs/review-followups.md after the ff-merge succeeds)."
      $reviewPhaseActive = $false
    }
    2 {
      Publish-ReviewFailureTranscripts -FinalExitCode 2 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] BLOCKER findings - merge ABORTED."
      Write-Host "[auto-merge] Fix the findings and re-run."
      exit 2
    }
    default {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
      Write-Host "[auto-merge] Unexpected panel verdict state (exit $unionExit) - merge ABORTED."
      exit 3
    }
  }

  # Re-read the exact candidate ref, exact base ref, symbolic checkout name,
  # and HEAD immediately before mutation. Short names would reintroduce DWIM
  # ambiguity; omitting the base checks would allow a long review to approve a
  # range whose checked-out base moved before the merge.
  $branchNowResolution = Resolve-CrgExactLocalBranchCommit -BranchName $Branch
  $branchShaNow = if ($branchNowResolution.State -eq 'valid') { $branchNowResolution.CommitOid } else { '' }
  if ($branchNowResolution.State -ne 'valid' -or $branchShaNow -notmatch $oidPattern -or
      -not [string]::Equals($branchShaNow, $branchSha, [System.StringComparison]::Ordinal)) {
    Write-Host "[auto-merge] ERROR: '$Branch' moved during review."
    Write-Host "[auto-merge] reviewed=$branchSha, now=$(if ($branchShaNow) { $branchShaNow } else { '<missing-or-indeterminate>' })"
    Write-Host "[auto-merge] Re-run the merge against the current branch tip."
    exit 3
  }

  $currentBranchNowRows = @(& git symbolic-ref --quiet HEAD 2>$null)
  $currentBranchNowExit = $LASTEXITCODE
  $baseHeadNowRows = @(& git rev-parse --verify 'HEAD^{commit}' 2>$null)
  $baseHeadNowExit = $LASTEXITCODE
  $baseNowResolution = Resolve-CrgExactLocalBranchCommit -BranchName $Base
  $currentBranchNow = if ($currentBranchNowRows.Count -eq 1) { ([string]$currentBranchNowRows[0]).Trim() } else { '' }
  $baseHeadNow = if ($baseHeadNowRows.Count -eq 1) { ([string]$baseHeadNowRows[0]).Trim() } else { '' }
  $baseRefNow = if ($baseNowResolution.State -eq 'valid') { $baseNowResolution.CommitOid } else { '' }
  if ($currentBranchNowExit -ne 0 -or $baseHeadNowExit -ne 0 -or $baseNowResolution.State -ne 'valid' -or
      $currentBranchNowRows.Count -ne 1 -or $baseHeadNowRows.Count -ne 1 -or
      -not [string]::Equals($currentBranchNow, $baseResolution.RefName, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($baseHeadNow, $baseSha, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($baseRefNow, $baseSha, [System.StringComparison]::Ordinal)) {
    Write-Host "[auto-merge] ERROR: checked-out base '$Base' moved or changed identity during review."
    $currentBranchNowDisplay = if ($currentBranchNow.StartsWith('refs/heads/', [System.StringComparison]::Ordinal)) { $currentBranchNow.Substring(11) } else { $currentBranchNow }
    Write-Host "[auto-merge] reviewed=$baseSha, checkout=$(if ($currentBranchNowDisplay) { $currentBranchNowDisplay } else { '<detached-or-indeterminate>' }), HEAD=$(if ($baseHeadNow) { $baseHeadNow } else { '<indeterminate>' }), ref=$(if ($baseRefNow) { $baseRefNow } else { '<missing-or-indeterminate>' })"
    Write-Host '[auto-merge] Re-run the merge from the unchanged requested base.'
    exit 3
  }

  Write-Host "[auto-merge] ff-merge $branchSha (=$Branch) -> '$Base'"
  # --no-overwrite-ignore: an ignored local file (the per-user TASKS.md the
  # review wrappers exclude, among others) is refused, not silently replaced,
  # when the incoming tree tracks the same path.
  & git merge --ff-only --no-overwrite-ignore $branchSha
  if ($LASTEXITCODE -ne 0) {
    Write-Host "[auto-merge] ERROR: ff-merge failed"
    exit 3
  }

  $newHead = (& git rev-parse --short=12 HEAD).Trim()
  Write-Host "[auto-merge] OK - '$Base' is now at $newHead"

  # The merge is applied -- NOW the children's staged QUALITY follow-ups may
  # reach the durable index (they describe content that actually landed).
  # Every launched child's staging is promoted, the superseded exhausted
  # panel's included (its completed passes' findings still describe landed
  # content) and every fallback child's. One call appends them all under one
  # lock (Invoke-FollowupPromotion, the promoter the commit gate also runs);
  # its result only words its own warnings, since the merge already stands.
  $promotionPaths = New-Object 'System.Collections.Generic.List[string]'
  foreach ($pp in @($allPendingPaths)) {
    if (-not [string]::IsNullOrWhiteSpace($pp.Path)) { $promotionPaths.Add($pp.Path) }
  }
  if ($fallbackHappened) {
    foreach ($fp in @($fallbackPendingPaths)) {
      if (-not [string]::IsNullOrWhiteSpace($fp)) { $promotionPaths.Add($fp) }
    }
  }
  [void](Invoke-FollowupPromotion -PendingPaths $promotionPaths.ToArray() -LogTag 'auto-merge' -ProviderNeutralOutput)
  # --- Non-gating post-merge process audit (REPORT-ONLY) -------------------
  # The merge has ALREADY completed and the base is updated above; nothing in
  # this block can change the merge outcome or this script's exit code (control
  # falls through to `exit 0` regardless of what happens here). It runs the
  # TRUSTED worker-audit.ps1 ($trustedWorkerAudit: the base's copy, else the
  # manifest-verified local snapshot, resolved above -- NOT the just-merged
  # candidate content at $PSScriptRoot) for the just-merged branch to record
  # how many gate rounds the landing took (a landing's PROCESS is audited
  # automatically whenever a trusted copy resolves; the audit protocol
  # consumes the reports). The whole block is wrapped in try/catch and every
  # failure path (no trusted copy -> $trustedWorkerAudit $null, audit error,
  # a child that writes to stderr) is a WARNING only. `$mergeBase` (the PRE-merge fork point
  # computed earlier) is passed as -Base so the audited range is correct even
  # now that the base has fast-forwarded onto the branch tip (merge-base of the
  # fork point and the tip is the fork point). The audit writes its report to a
  # gitignored logs/worker-audits/ path (its default -OutPath).
  #
  # ORDERING: this runs BEFORE the `finally` block consolidates THIS run's
  # verdict artifacts into the central `logs/<backend>/reviews`, so the
  # just-completed (passing) MERGE-gate verdicts are still ONLY in the run-owned
  # per-child dirs. The EFFECTIVE verdict panel's dirs are therefore passed to
  # `-ReviewsDir` ALONGSIDE the central logs (which already hold this branch's
  # commit-gate rounds + any PRIOR merge attempts) so the audit does not
  # undercount this landing's final merge round or announce a successful hidden
  # substitution from the superseded panel. Every superseded artifact still
  # reaches central logs in finally after this audit. worker-audit reads each artifact's backend from its own
  # REVIEW-BACKEND header, so the run-dir names carry no identity. CONSUMER-
  # FIRST MIGRATION CAVEAT: the copy run here is a PRE-LANDING trusted
  # worker-audit (the base's or the local snapshot's), so a landing that
  # introduces a new artifact shape is audited by the pre-shape consumer --
  # a transient NON-GATING degradation confined to the landings that
  # introduce those shapes. `-ReviewsDir` is passed as a real ARRAY via
  # `-Command` (single-quoted literals), NOT a comma-joined string: worker-
  # audit's array parameter takes each element VERBATIM (its comma-splitting
  # form is the separate -ReviewsDirCsv), so a `$env:TEMP` run-dir path that
  # contains a comma survives intact.
  try {
    if ([string]::IsNullOrWhiteSpace($trustedWorkerAudit) -or -not (Test-Path -LiteralPath $trustedWorkerAudit -PathType Leaf)) {
      Write-Host "[auto-merge] (post-merge audit) trusted worker-audit.ps1 unavailable (absent from base '$Base' with no manifest-verified local copy, or extraction failed) - skipping; NON-GATING."
    } else {
      $auditDirs = Get-PostMergeAuditDirList -CentralBackends @('codex', 'claude') -ChildDirs $effectiveReviewDirs
      foreach ($auditNote in @($auditDirs.Notes)) { Write-Host $auditNote }
      if ($auditDirs.ResolutionFailed) { throw 'central review-log resolution failed; the audit is skipped rather than run without its history' }
      $auditDirList = @($auditDirs.Dirs)
      # The quoting helpers build both the -ReviewsDir literal list and the
      # single-value literals. Each literal already carries surrounding single
      # quotes, so the command template does not re-add them.
      $auditDirLits = Build-ReviewDirLiteralList -Dirs $auditDirList
      $waLit = ConvertTo-PSSingleQuotedLiteral -Value $trustedWorkerAudit
      $brLit = ConvertTo-PSSingleQuotedLiteral -Value $branchSha
      $baLit = ConvertTo-PSSingleQuotedLiteral -Value $mergeBase
      # -Base is the PRE-merge fork SHA (the range stays right after the
      # ff-merge); -BaseRef is the base's REF NAME so the branch's legacy
      # `-vs-<ref>` merge verdicts keep their identity match (a SHA never
      # equals a ref-name token).
      $brefLit = ConvertTo-PSSingleQuotedLiteral -Value $Base
      $auditCmd = "& $waLit -Branch $brLit -Base $baLit -BaseRef $brefLit -ReviewsDir $auditDirLits"
      # BOUNDED child (NON-GATING): launch worker-audit.ps1 via Start-Process with a
      # TIMEOUT so a HUNG audit cannot stall this script. This matters because the
      # call runs BEFORE the finally block consolidates the run-owned verdict
      # artifacts into the central logs -- an UNBOUNDED synchronous child that hung
      # would delay or skip that (otherwise unconditional) consolidation. Start-
      # Process cannot capture output inline, so stdout/stderr are redirected to
      # run-owned temp files and read back. On timeout the child is killed, a WARNING
      # is emitted, and control falls through so the finally still runs.
      $auditRun = Invoke-PostMergeAuditChild -Command $auditCmd -TimeoutSec 120 -RunDir $runDir
      foreach ($auditMsg in @($auditRun.Messages)) { Write-Host $auditMsg }
      if ($auditRun.Unconfirmed) { $auditChildUnconfirmed = $true }
      if ($auditRun.CaptureBounded) { $auditCaptureBounded = $true }
      $auditStdoutText = $auditRun.StdoutText
      $auditStderrText = $auditRun.StderrText
      $auditExit = $auditRun.Exit
      $auditKilled = $auditRun.Killed
      # A child that writes to STDERR is a WARNING. Surface a non-empty stderr
      # ALWAYS -- even on a SUCCESSFUL run WITH summary lines -- so the audit
      # child's PowerShell errors/warnings are never silently dropped; a bounded
      # tail keeps it terse.
      if (-not [string]::IsNullOrWhiteSpace($auditStderrText)) {
        $errTail = @($auditStderrText -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 8) -join ' | '
        Write-Host "[auto-merge] (post-merge audit) worker-audit.ps1 wrote to stderr (NON-GATING): $errTail"
      }
      # A KILLED child (timeout, or still live behind a wait failure) has
      # partial output by construction; every other confirmed exit -- the
      # normal wait, or a child that completed on its own before a wait
      # failure was noticed -- is parsed for its summary.
      if (-not $auditKilled) {
        # worker-audit's summary console line leads with `AUTHORITATIVE:` (the
        # branch-scoped merge counts); the path line contains `wrote report to`.
        $auditSummary = Get-AuditSummaryLines -AuditText $auditStdoutText
        $pathLine = $auditSummary.PathLine
        $sumLine  = $auditSummary.SumLine
        # Suspect lines FIRST and prominently: the audit's suspect-led report
        # exits 0 with the UNRELIABLE-tagged summary as its only console signal,
        # so this consumer must surface those lines, not just the path/summary
        # pair. Still NON-GATING.
        foreach ($suspectLine in @($auditSummary.SuspectLines)) {
          Write-Host "[auto-merge] (post-merge audit) SUSPECT: $($suspectLine.Trim())"
        }
        # An error the audit did not classify is surfaced WITH the suspects and
        # named as the contract breach it is: the class is unknown here, and an
        # unknown class is read as the loud one.
        foreach ($unclassifiedLine in @($auditSummary.UnclassifiedLines)) {
          Write-Host "[auto-merge] (post-merge audit) SUSPECT (UNCLASSIFIED - the audit emitted an error carrying no recognized class token; read as a suspect because the safe reading of an unknown class is the loud one): $($unclassifiedLine.Trim())"
        }
        foreach ($errorLine in @($auditSummary.ErrorLines)) {
          Write-Host "[auto-merge] (post-merge audit) ERROR: $($errorLine.Trim())"
        }
        foreach ($warningLine in @($auditSummary.WarningLines)) {
          Write-Host "[auto-merge] (post-merge audit) WARNING: $($warningLine.Trim())"
        }
        if ($pathLine) { Write-Host "[auto-merge] (post-merge audit) $($pathLine.Trim())" }
        if ($sumLine)  { Write-Host "[auto-merge] (post-merge audit) $($sumLine.Trim())" }
        # Surface a failed / summary-less run instead of discarding the captured
        # output: on a nonzero exit OR when no recognizable summary was found, print
        # the exit code and a bounded tail of the child STDOUT so the NON-GATING
        # failure is diagnosable (it never affects the merge, which already landed).
        if ($auditExit -ne 0 -or (-not $pathLine -and -not $sumLine)) {
          $tail = @($auditStdoutText -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 8) -join ' | '
          # The diagnostic names exactly what the stdout carried: a path line
          # alone is not a summary.
          $auditWhy = if (-not $pathLine -and -not $sumLine) { "exited $auditExit with no usable stdout summary" } elseif ($sumLine -and $pathLine) { "exited $auditExit (nonzero) although its stdout carried a recognized summary and report path" } elseif ($sumLine) { "exited $auditExit (nonzero) although its stdout carried a recognized summary line but no report path" } else { "exited $auditExit (nonzero); its stdout carried a report path but NO summary line" }
          Write-Host "[auto-merge] (post-merge audit) worker-audit.ps1 $auditWhy (NON-GATING). Output tail: $tail"
        }
      }
    }
  } catch {
    Write-Host "[auto-merge] (post-merge audit) WARNING: worker-audit.ps1 raised '$($_.Exception.Message)' - NON-GATING, merge already completed."
  }
  # -------------------------------------------------------------------------

  exit 0
}
catch {
  # An exception while review routing is still active is a fail-closed review
  # outcome. Defer replay until finally has bounded-joined every launched child,
  # so the captures are as complete as their confirmed lifecycle allows.
  if ($reviewPhaseActive) { $reviewReplayState['Pending'] = $true }
  Write-Host "[auto-merge] EXCEPTION: $_"
  exit 3
}
finally {
  # This block runs on EVERY exit path (the try body returns normally, every
  # `exit N` -- PowerShell runs finally before the process exits -- AND the
  # catch). Order within it: (1) bounded defensive-join of any still-running
  # child, then (2) the consolidation copy for every dir whose writer is
  # CONFIRMED exited, then (3) a GUARDED delete. The copy always runs before
  # any Remove-Item (copy-before-delete), but it is QUIESCENCE-GATED: a dir
  # whose child could not be confirmed exited is SKIPPED, not copied -- a
  # paused-but-live writer's partial snapshot would pass the staged length
  # check and be published at its final name as if complete, so atomicity
  # alone cannot make a non-quiescent source safe. Skipped dirs ride the
  # preserved run dir instead (nothing is lost; centralization happens on a
  # later manual reap). The DELETE is conditional (skipped when a review
  # child is still running or consolidation could not centralize -- see
  # below). This is the forensic-integrity guarantee a sibling session's
  # abort lacked (its run dir was reaped with multiple verdicts uncopied).
  #
  # DEFENSIVE JOIN: the normal flow already WaitForExit()s every launched
  # child before any exit, but an exception thrown BETWEEN launching a child and joining it
  # (or before the join is reached) could land here with a child still running --
  # deleting $runDir under it would race/lose its in-flight verdict write. So
  # re-join any still-live launched child FIRST. A review pass can run many
  # minutes, so the bound is generous (matching the gate's own long-review
  # reality); an unbounded wait in finally must still be avoided. CRITICALLY, the
  # timeout RESULT is captured: if a child is STILL running after the wait, the
  # run dir is NOT deleted below (deleting under a live child is the exact race
  # this change closes) -- it is PRESERVED for forensics and to let the child
  # finish writing, with a loud stable warning. $panelChildren is empty on an
  # early exit before launch, in which case there is nothing to join.
  $childStillRunning = $false
  $liveOwners = @()
  $joinPairs = @()
  foreach ($pc in @($panelChildren)) { $joinPairs += ,@{ N = $pc.Name; P = $pc.Proc } }
  foreach ($pj in ($joinPairs + @($fbJoinList))) {
    if ($null -eq $pj.P) { continue }
    # Whole check wrapped: a HasExited/WaitForExit access on an odd host state
    # must NEVER throw out of finally (that would skip the consolidation below).
    # $observedRunning is initialized CONSERVATIVELY to $true (assume the child is
    # running until we PROVE it has exited) and flips to $false ONLY on a confirmed
    # exit -- HasExited returning true, or WaitForExit(bound) returning true. So a
    # throw from HasExited OR WaitForExit leaves it $true and the dir is PRESERVED:
    # on ANY uncertainty about the child's state we never delete under a
    # possibly-live child. (The earlier version initialized it $false and only
    # flipped true after HasExited returned false, so a HasExited throw wrongly
    # left it $false and allowed deletion -- fixed.)
    $observedRunning = $true
    try {
      if ($pj.P.HasExited) {
        $observedRunning = $false   # confirmed already exited before the wait
      } else {
        Write-Host "[auto-merge] forensics: $($pj.N) review child still running at cleanup - joining (bounded $([int](600000/60000))min) before consolidation to avoid racing its verdict write."
        if ($pj.P.WaitForExit(600000)) { $observedRunning = $false }   # confirmed done within the bound
      }
    } catch {
      # Left $observedRunning = $true: the child's state could not be verified, so
      # preserve conservatively (never delete under a possibly-live child).
    }
    if ($observedRunning) {
      Write-Host "[auto-merge] forensics WARNING: $($pj.N) review child STILL running (or its state is unverifiable) after the bounded wait - PRESERVING the run dir (NOT deleting) so its in-flight verdict is not lost; manually inspect/reap '$runDir' later."
      $childStillRunning = $true
      $liveOwners += $pj.N
    }
  }

  if ([bool]$reviewReplayState['Pending']) {
    try {
      Publish-ReviewFailureTranscripts -FinalExitCode 3 -Children $reviewTranscriptChildren -State $reviewReplayState
    } catch {
      Write-Host "[auto-merge] (review failure transcript) WARNING: transcript replay raised '$($_.Exception.Message)' - preserving the run directory because complete failure evidence could not be surfaced."
      $reviewReplayState['Preserve'] = $true
    }
  }

  # $preserveRunDir is the OR of every reason NOT to delete the run dir: a still-
  # running child (above), an UNCONFIRMED-exit post-merge-audit child
  # ($auditChildUnconfirmed -- it writes captures into the run dir and reads the
  # run-owned verdict dirs), a post-merge-audit capture the read had to BOUND
  # ($auditCaptureBounded -- the complete capture then exists ONLY as the run-dir
  # file the warning names), a bounded/unreadable review failure transcript
  # ($reviewReplayState.Preserve), AND a consolidation that could not safely complete
  # (Copy-RunArtifactsToCentralLogs returns $true when it could not centralize --
  # unresolvable central dir, enumeration failure, or a per-file copy failure).
  # On uncertainty we PRESERVE rather than silently delete artifacts.
  $preserveRunDir = $childStillRunning -or $auditChildUnconfirmed -or $auditCaptureBounded -or [bool]$reviewReplayState['Preserve']

  # Copy-RunArtifactsToCentralLogs is fail-LOUD internally (names lost files) and
  # returns whether the run dir must be preserved; this extra try/catch only
  # guarantees finally never THROWS (which would mask the script's real exit
  # code) -- and on such a throw we PRESERVE (we cannot confirm consolidation
  # succeeded). $consolidateDirs is the top-level always-in-scope list every
  # launched child (panel and fallback) registered its slot dir into at
  # launch, so an early exit consolidates exactly the dirs that exist.
  try {
    foreach ($fbc in @($consolidateDirs)) {
      # QUIESCENCE GATE: never consolidate a dir whose owning child was not
      # confirmed exited -- the staged length check verifies the STAGE against
      # the source at copy time, so a live writer paused mid-write would pass
      # it and publish a partial verdict at its final name with a success
      # report. The dir stays in the preserved run dir un-copied instead.
      if ([Array]::IndexOf([string[]]$liveOwners, [string]$fbc.Owner) -ge 0) {
        Write-Host "[auto-merge] forensics WARNING: consolidation SKIPPED for '$($fbc.Owner)' - its child could not be confirmed exited, so its artifacts may still be growing; they remain ONLY in the preserved run dir until the child is confirmed done and the dir is reaped manually."
        $preserveRunDir = $true
        continue
      }
      if (Copy-RunArtifactsToCentralLogs -RunBackendDir $fbc.Dir -Backend $fbc.Backend -ProviderNeutralOutput -QuietSuccess) { $preserveRunDir = $true }
    }
  } catch {
    Write-Host "[auto-merge] forensics WARNING: centralizing run artifacts in finally threw ($($_.Exception.Message)) - PRESERVING the run dir since consolidation could not be confirmed; artifacts for this run may be INCOMPLETE in the central logs."
    $preserveRunDir = $true
  }
  # The trusted-infra dir holds the prompt + wrapper copies a LIVE child still
  # reads (codex/claude wrappers receive -PromptPath $trustedPrompt and read it
  # mid-review), so it MUST be preserved while any child is still running --
  # deleting it under a live child would break that child's in-flight review and
  # lose its verdict. It carries no verdict artifacts, so a copy failure alone
  # (run dir preserved but child exited) does NOT require keeping it; gate it on
  # live/unconfirmed children specifically -- the post-merge audit runs the
  # trusted worker-audit.ps1 copy extracted here, so an unconfirmed audit
  # child may still be reading it.
  if ($childStillRunning -or $auditChildUnconfirmed) {
    $trustReason = if ($childStillRunning) { 'a review child was still running and may still read its -PromptPath' } else { 'the post-merge audit child''s exit is unconfirmed and it may still read its trusted script copy' }
    Write-Host "[auto-merge] forensics: trusted-infra dir '$trustedDir' PRESERVED ($trustReason); not auto-deleted this run."
  } else {
    Remove-TreeNoRecurse -Path $trustedDir
  }
  # Delete the run dir ONLY after consolidation AND only when nothing needs
  # preserving (no live child writing into it, and consolidation completed
  # cleanly). Otherwise PRESERVE it -- artifacts must never be deleted from under
  # a live child or lost when they could not be centralized.
  if ($preserveRunDir) {
    $reason = if ($childStillRunning) { 'a review child was still running at cleanup' } elseif ($auditChildUnconfirmed) { 'the post-merge audit child''s exit is unconfirmed' } elseif ($auditCaptureBounded) { 'a post-merge audit capture exceeded the read bounds and the complete copy lives only here' } elseif ([bool]$reviewReplayState['Preserve']) { 'a review failure transcript was bounded or unreadable and the complete available capture lives here' } else { 'consolidation could not centralize all verdict artifacts' }
    Write-Host "[auto-merge] forensics: run dir '$runDir' PRESERVED ($reason); it is not auto-deleted this run - inspect/reap it manually once resolved."
  } else {
    Remove-TreeNoRecurse -Path $runDir
  }
}
} finally {
  try {
    [Console]::InputEncoding = $crgSavedConsoleInputEncoding
  } catch { Write-Warning "auto-merge.ps1: could not restore the console input code page ($($_.Exception.Message)); run chcp to reset it." }
  try {
    [Console]::OutputEncoding = $crgSavedConsoleOutputEncoding
  } catch { Write-Warning "auto-merge.ps1: could not restore the console output code page ($($_.Exception.Message)); run chcp to reset it." }
}
