# Dispatch-checklist generator.
#
# Closes the analyzer-to-dispatch feedback loop: turns RECENT review-gate
# findings into a copy-paste "recurring defect-class checklist" block for
# worker dispatch prompts (structural fields and validated citations only --
# the paste crosses an agent-output -> agent-prompt boundary, so finding
# prose never enters it). The GLOBAL `~/.claude/CLAUDE.md` reviewer-iteration
# discipline (item 5, "Maintain a checklist of repeated defect classes")
# mandates: "When the same architectural class is flagged 2+ times across
# rounds ... treat it as a class to apply preemptively to new content of that
# shape." (The project CLAUDE.md adversarial-gate rule separately mandates
# sweeping the WHOLE defect class on EVERY finding -- a stricter, per-finding
# rule, NOT a 2+ threshold; do not conflate the two.) This script mechanizes
# the data side of the global repeated-class discipline so the dispatcher
# reviews the CURRENT top recurring classes interactively instead of
# recalling them from memory.
#
# RELATIONSHIP TO analyze-blocker-trends.ps1 (read that script first):
#   analyze-blocker-trends.ps1 clusters findings into its OWN review-system
#   archetypes (WORKFLOW-INFRA, PLAN-DRIFT, SILENT-FAILURE, ...) via a
#   keyword classifier over the SEVERITY-prefixed finding lines, to drive
#   review-surface improvements. This script clusters by the REVIEWER'S
#   EIGHT prompt categories (the per-category enumeration block the wrapper
#   parses), which is the axis dispatch guidance cites, and RANKS BY
#   CATEGORY (not by individual finding text -- see the ranking note in the
#   main pipeline: finding texts drift file:line by file:line between reviews
#   and effectively never repeat verbatim, so the category is the durable
#   recurring-class signal). Like the analyzer ranking by ARCHETYPE cluster,
#   this ranks by CATEGORY cluster -- same principle, different (eight-category
#   vs nine-archetype) taxonomy. Different consumer, different axis. A FURTHER
#   axis difference (it does NOT touch the mirrored primitives below): the
#   analyzer aggregates MULTIPLE backend dirs into one cross-backend report
#   (its `-ReviewsDir` takes a list); this checklist deliberately stays
#   SINGLE-DIR (one backend per run over a recent window) by design. The
#   parsing PRIMITIVES are deliberately MIRRORED from the analyzer -- the
#   verdict filename-shape guard, the UTF-8 read / UTF-8-no-BOM write, AND the
#   per-file dedupe by normalized text (keeping the highest severity) -- so the
#   two scripts agree on WHICH files are verdicts, on encoding, and on
#   collapsing a finding that repeats across passes to a single counted
#   exemplar; those primitives are IDENTICAL regardless of the analyzer's
#   dir-count. Dot-sourcing the analyzer is NOT viable (it runs its full report
#   pipeline and `exit`s on load), so those primitives are re-expressed here
#   inline with provenance comments pinning each to the analyzer's contract.
#   Any change to the analyzer's filename / dedupe conventions must be
#   mirrored here (and vice-versa); they are intentionally kept identical, not
#   forked. On top of the shared dedupe, dispatch-checklist additionally
#   resolves the eight-category axis (see Get-CategoryFindings) to surface
#   DISTINCT recurring exemplars.
#
# WHY the per-category block, not the severity lines: a Codex verdict's
# `BLOCKER:`/`QUALITY:`/`NOTE:` lines carry the finding text but NOT the
# reviewer category. The category label lives only on the per-category
# enumeration line (`DOC-VS-CODE-DRIFT: 2`) with its findings indented
# beneath it (the format `scripts/codex/review-prompt-template.md` mandates
# and `auto-review.ps1` parses). So the eight-category tally reads the
# enumeration block; the severity is recovered PER PASS BLOCK by matching each
# enumerated finding's text back to THAT BLOCK's severity-prefixed lines
# (highest wins), to dedupe consistently with the analyzer's own per-file
# normalized-text dedupe (the two are mirrored, not forked).
#
# Usage:
#   scripts\shared\dispatch-checklist.ps1                  # writes logs/dispatch-checklist.md, last 14 days
#   scripts\shared\dispatch-checklist.ps1 -SinceDays 30    # widen the window
#   scripts\shared\dispatch-checklist.ps1 -Top 12          # more exemplars per class
#   scripts\shared\dispatch-checklist.ps1 -OutPath foo.md  # custom output path
#   scripts\shared\dispatch-checklist.ps1 -ReviewsDir <path>
#
# Exit codes:
#   0 = report written. Covers: verdicts summarized; an empty window (loud
#       empty-window banner -- see "fails loud"); every scanned verdict CLEAN;
#       AND the case where one or more scanned verdict-shaped files are RECOGNIZED
#       producer-shaped FAIL-CLOSED runs (the wrapper's `===== GATE FAILED CLOSED
#       =====` banner PLUS the full producer self-declaration -- exact prefix,
#       diagnostic, and suffix framing -- validated over strict no-BOM-decoded bytes).
#       Such a run is a SELF-DECLARED failed gate that produced no trustworthy
#       complete-run outcome; it is EXCLUDED from the category
#       tally and reported LOUDLY (a console line AND a dedicated artifact section
#       naming each excluded file + its banner reason line), never silently
#       dropped. Excluding it (vs refusing outright) keeps a single transient
#       reviewer-environment failure from leaving the dispatcher with no checklist
#       for up to the whole window after any such failure.
#   1 = either (a) an INVOCATION failure (reviews dir missing / unreadable,
#       writer failure) OR (b) an EVIDENCE-QUALITY refusal for UNEXPLAINED
#       corruption: one or more scanned verdict-shaped files fail the structure
#       contract and are NOT a recognized fail-closed run -- EITHER bannerless, OR
#       carrying the banner but rejected by the recognizer (a bad header value,
#       unknown diagnostic, non-producer framing, or a BOM / invalid-UTF-8 encoding),
#       plus a block the wrapper itself would reject (missing/incomplete category
#       block, out-of-bound count, row imbalance, incoherent verdict, unknown marker,
#       etc.). Such a file is not a self-declared failure, so it is treated as
#       untrustworthy corruption and the window is not summarized. This case
#       writes NO artifact. The console message distinguishes (a) from (b)
#       (`ERROR:` text differs).
#
# Fails loud: neither an empty window NOR an excluded fail-closed run is a silent
# pass. An empty window still writes the artifact with a prominent "no verdicts
# in window -- NOT evidence of zero defect classes" banner; a fail-closed run is
# named (console + a dedicated artifact section) as excluded. Only an
# unreadable/missing reviews directory, or UNRECOGNIZED-malformed verdict evidence,
# is a hard exit 1 (the gate's hazard list bans validator-style silent passes on
# bad input; a fail-closed run is excluded LOUDLY, which is the opposite of a
# silent pass).

[CmdletBinding()]
param(
  [string]$ReviewsDir = 'logs/codex/reviews',
  # Default under logs/ -- the same gitignored tree the review wrappers write to
  # (bootstrap.ps1 adds `logs/` to the target repo's .gitignore). Keeping the
  # generated checklist there means a fresh install does not create a tracked
  # operational artifact. Override with -OutPath for a different location.
  [string]$OutPath = 'logs/dispatch-checklist.md',
  # Default 14 days: a dispatch checklist should reflect the RECENT arc, not
  # the full history (the analyzer covers full history). Negative values are
  # rejected at the binding boundary so a typo cannot silently widen scope.
  [ValidateRange(0, [int]::MaxValue)]
  [int]$SinceDays = 14,
  # Max RECENT EXEMPLARS to show under each recurring category in the
  # report. Every category that has findings is surfaced as a class (there are
  # at most eight); -Top bounds how many concrete recent instances list
  # beneath each so the report stays focused, not an exhaustive dump.
  [ValidateRange(1, [int]::MaxValue)]
  [int]$Top = 8
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# Win32 MoveFileEx for an ATOMIC same-volume replace (see Write-Artifact). The
# .NET [System.IO.File]::Replace is unreliable on Windows PowerShell 5.1 (throws
# "path is not of a legal form" for ordinary temp/destination paths), and
# Move-Item -Force / [System.IO.File]::Move do delete-then-move (a crash mid-swap
# could lose the prior artifact). MoveFileEx with MOVEFILE_REPLACE_EXISTING |
# MOVEFILE_WRITE_THROUGH is the canonical Windows atomic-replace on the same
# volume; it returns $false (not throws) on failure -- including a ReadOnly
# destination -- so the caller can fail loud and leave the prior artifact intact.
# The type name is VERSIONED: a type name, once loaded, can never be redefined
# in a PowerShell process, so an unversioned guard would accept an older
# copy's definition whenever two versions run in one process. A new method set
# gets a new suffix.
if (-not ('DispatchChecklist.NativeV1' -as [type])) {
  Add-Type -Namespace 'DispatchChecklist' -Name 'NativeV1' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
}

# ---------------------------------------------------------------------------
# The eight reviewer categories (the per-category enumeration the wrapper
# parses), in the same most-specific-to-most-general order as
# scripts/codex/review-prompt-template.md. Surface-class hints map each
# category to the code/doc surface a worker is touching when that class
# recurs, so the emitted bullet reads "When touching <surface>, preemptively
# check: <class>". Hints are derived from the template's own per-category
# descriptions; they are guidance phrasing, not an exhaustive surface list.
# ---------------------------------------------------------------------------
$categoryOrder = @(
  'PLAN-DRIFT'
  'SILENT-FAILURE'
  'TOMBSTONE-OR-SHIM'
  'CROSS-CRATE-CONTRACT'
  'LOADER-OR-ASSET-EDGE'
  'CONVENTION-ADHERENCE'
  'TEST-QUALITY'
  'DOC-VS-CODE-DRIFT'
)
# Category rank (most-specific = lowest index). Used as the deterministic tie-
# break when one finding TEXT appears under two categories across passes and the
# severities tie: the most-specific category wins.
# Ordinal tables: culture-keyed `@{}` ignores characters such as U+00AD in parsed keys.
$script:CatOrderRank = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
for ($ci = 0; $ci -lt $categoryOrder.Count; $ci++) { $script:CatOrderRank[$categoryOrder[$ci]] = $ci }
$categorySurface = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
$categorySurface['PLAN-DRIFT']           = 'PLAN.md milestones, cross-refs, range/status claims'
$categorySurface['SILENT-FAILURE']       = 'mutation/validation/asset-write miss branches, Option/Result handling, validators that exit 0'
$categorySurface['TOMBSTONE-OR-SHIM']    = 'removed-code comments, renamed-to-underscore params, empty-quarantine functions'
$categorySurface['CROSS-CRATE-CONTRACT'] = 'cross-crate function/type signatures, re-exports, request-shape validators, system-set ordering'
$categorySurface['LOADER-OR-ASSET-EDGE'] = 'binary-format header/length checks, identity-fallback on invalid input, asset-root env-var fall-through, format-invariant drops'
$categorySurface['CONVENTION-ADHERENCE'] = 'comments/error-handling/shims/unwraps against CLAUDE.md + AGENTS.md conventions'
$categorySurface['TEST-QUALITY']         = 'code unit tests are banned: never write, add, expand, rewrite, maintain, restore, or run code unit tests, and renaming one as a probe, check, experiment, diagnostic, or verification script creates no exception; unit-test deletion is not a defect and missing code unit tests are not findings; live testing, manual checks, ordinary program runs, and functional validation remain permitted, so do not misclassify permitted testing; preserve production input validation, error handling, runtime assertions, and safety checks'
$categorySurface['DOC-VS-CODE-DRIFT']    = 'comments, docstrings, READMEs still describing pre-change (stale, not current) behavior; magnitude-not-measurement for transient quantities in narrative prose (handles + frozen-snapshot-marked-doc line numbers exempt); an exact inventory/count in comment or doc prose is itself the defect regardless of accuracy (fix: magnitude or delete, never a corrected number; a source-comment count echoing an adjacent code literal, machine-derived output/contract counts, and counts inside dated entry bodies of the root History.md log — the drift-only History exemption; a count there mis-stating a live contract the same diff changes stays a finding — are exempt); no local-only/untracked paths cited as evidence in tracked docs'

# Severity rank (BLOCKER > QUALITY == NON-BLOCKER > NOTE). Used by the per-file
# dedupe to keep the HIGHEST severity when one finding text repeats across passes
# within a single verdict file -- the same keep-highest rule the analyzer
# (analyze-blocker-trends.ps1) applies; the two dedupes are mirrored, not forked.
function Get-SeverityRank {
  param([string]$Sev)
  # Ordinal, not `switch` (culture compare); same ranks as the analyzer's inline mirror.
  if ([string]::Equals($Sev, 'BLOCKER', [System.StringComparison]::Ordinal)) { 3 } elseif ([string]::Equals($Sev, 'QUALITY', [System.StringComparison]::Ordinal) -or [string]::Equals($Sev, 'NON-BLOCKER', [System.StringComparison]::Ordinal)) { 2 } elseif ([string]::Equals($Sev, 'NOTE', [System.StringComparison]::Ordinal)) { 1 } else { 0 }
}

# Normalize finding text for dedupe keys: collapse runs of whitespace to a single
# space, trim, and lower-invariant. This normalization is MIRRORED from
# analyze-blocker-trends.ps1, which normalizes finding text the same way (collapse
# whitespace, lower-invariant) before deduping per file -- so the two scripts
# collapse the same whitespace/case variants of a finding into one and count a
# finding that repeats across passes once. The two dedupes are intentionally kept
# identical, not forked.
function Get-NormalizedText {
  param([string]$Text)
  return ($Text -replace '\s+', ' ').Trim().ToLowerInvariant()
}

# Extract ONLY a validated structural `path:line[:col]` citation from a finding
# line, discarding the free-text prose entirely. Returns the citation string or
# $null if the line does not START with a strict path:line shape.
#
# WHY structural-only (Codex BLOCKER): the paste block is
# COPIED INTO WORKER PROMPTS, and the finding text originates from review
# artifacts = AGENT OUTPUT = untrusted across the agent-output -> agent-prompt
# boundary (project CLAUDE.md: "all data crossing a boundary is untrusted").
# Markdown inline code is NOT a prompt-isolation boundary -- a planted or
# prompt-influenced finding could carry natural-language INSTRUCTIONS into a
# future worker prompt. Earlier this code emitted the agent-authored finding
# PROSE (merely stripping markers/backticks via a now-removed Get-SafeExemplar);
# that still let directive-like prose through. The checklist's value is the
# category ranking + WHERE-TO-LOOK citations, so the prose was decoration with an
# attack surface. The paste block now emits ONLY validated structural fields:
# category, severity, count, recency date, and -- per entry -- either a
# strict-shape citation or an explicit no-citation marker (never finding prose).
#
# Strict shape (ALLOWLIST, anchored at the START of the trimmed finding line):
#   <path>:<line>[:<col>]
# where <path> is one or more chars from [A-Za-z0-9._/\-] and a backslash, and
# <line>/<col> are digit runs. Anything not matching this prefix -> $null (the
# finding still counts toward the category, it just contributes no citation).
# The matched substring is returned VERBATIM but is, by construction, only path
# characters + digits + colons -- no spaces, no prose, no markup.
function Get-SafeCitation {
  param([string]$Text)
  if ($null -eq $Text) { return $null }
  $t = $Text.Trim()
  # Path chars: letters, digits, '.', '_', '/', '\', '-'. Then :digits, opt :digits,
  # ended as review-common.ps1's Get-ReviewFindingCitationEnd ends it, so
  # `a.ps1:12abc` is no citation.
  $m = [regex]::Match($t, '^(?<cite>[A-Za-z0-9._/\\-]+:[0-9]+(?::[0-9]+)?)(?![0-9A-Za-z_]|:[0-9])')
  if ($m.Success) { return $m.Groups['cite'].Value }
  return $null
}

# ---------------------------------------------------------------------------
# Parse ONE verdict file's text into deduped category findings.
#
# Returns a list of @{ Category; Severity; Text; Citation } -- one entry per
# DISTINCT normalized-TEXT within the file (the dedupe key is text ALONE, NOT
# category+text, mirroring analyze-blocker-trends.ps1's own per-file dedupe -- see
# the dedupe note in the body), at the highest severity that text was seen at across
# passes. When
# the same text appears under different categories the highest-severity (then
# most-specific-category) occurrence wins. Citation is the VALIDATED structural
# `path:line[:col]` extracted from the finding line (Get-SafeCitation), or $null
# if the line has no strict-shape citation -- the raw finding PROSE is discarded
# at parse time and never reaches the emitted block. Text (normalized)
# is the dedupe/count key only and is never emitted.
#
# The per-category enumeration block format (review-prompt-template.md):
#   <CATEGORY>: none
#   <CATEGORY>: <count>
#     <file:line> - <one-line description>      # exactly <count> indented lines
# A multi-pass artifact repeats the whole block once per pass; the per-file dedupe
# by normalized text collapses the repeats so the finding counts once -- the same
# collapse analyze-blocker-trends.ps1 applies (mirrored, not forked).
#
# Severity is recovered PER PASS BLOCK (NOT file-wide): each block's category-
# enumeration findings are matched against THAT BLOCK's own severity-prefixed
# lines (a category-block finding line and its severity-prefixed twin share the
# same leading "<file:line> - <phrase>" text, so the normalized keys match). A
# file-wide map would give every occurrence of a text the highest severity seen
# ANYWHERE, corrupting the cross-pass category tiebreak -- see the CRITICAL note
# in Get-CategoryFindings (Codex BLOCKER). If no severity
# line matches in the block (older/edge artifacts), the finding still counts;
# its severity falls back to 'UNKNOWN' (rank 0) so it never outranks a real one.
# ---------------------------------------------------------------------------

# Upper bound on a category count, mirroring Get-VerdictExitCode in
# scripts/review-common.ps1 EXACTLY (it uses `[int]::TryParse` + reject `> 10000`). Category counts come from verdict files
# = agent output read from disk = UNTRUSTED, so a raw `[int]` cast on a value
# like `999999999999999999` would THROW (with $ErrorActionPreference='Stop',
# aborting the whole run) instead of being handled. TryParse + this bound is the
# trusted path. (Codex BLOCKER.)
$script:CategoryCountMax = 10000

# Upper bound on a REVIEW PASS marker number/total, mirroring auto-review.ps1's
# producer contract EXACTLY: `-ReviewPasses` is `[ValidateRange(1, 10)]` and
# CROSS_REVIEW_PASSES is clamped 1-10 (auto-review.ps1), so the wrapper can only
# emit `===== REVIEW PASS n/N =====` for n, N in 1..10. Accepting a larger N (the
# old code reused the 10000 category ceiling) would validate a shape the producer
# cannot make as trustworthy evidence. (Codex BLOCKER.)
$script:ReviewPassMax = 10

# A line folded so that every spelling a reader could take for a
# verdict-structure name (VERDICT, a severity prefix, a header name, the
# fail-closed banner) reads as that name in every culture. A culture `(?i)`
# match does not do this: under tr-TR it does not fold ASCII `i` onto `I`, and
# the invariant culture folds neither U+212A nor U+0130 (both checked
# 2026-10-10). Compatibility decomposition turns full-width forms and U+212A
# into ASCII and splits U+0130 into I plus a combining dot. After it, only
# printable ASCII, tab, LF and CR survive, upper-cased: dash punctuation
# reads as `-`, U+0131 reads as `I` (invariant upper-casing keeps it), and
# every other character -- ASCII control characters such as U+0000 and every
# other non-ASCII character -- is dropped. Space, tab, LF and CR are kept,
# including the spaces decomposition maps to U+0020 (U+00A0, U+2009), so a
# name split by one stays split, as it reads; other whitespace (U+0085,
# U+1680, U+2028, U+2029) is non-ASCII after decomposition, so it is dropped
# and joins what it separated. Letters of other scripts that merely look
# Latin (Cyrillic А) have no such mapping and are dropped like any other.
# Callers only widen what they refuse with the fold; acceptance stays exact.
# $null means the line could not be normalized (an unpaired surrogate) and
# must be refused.
# The WHOLE line is folded. Folding only a bounded head was tried and dropped
# (staged review, 2026-10-10): padding before the colon (`BLOCKER`, a hundred
# spaces, `:`) or before a header name pushed the delimiter past the cut, and
# the line escaped recognition. Dropping only nonspacing marks and format
# characters was also tried and dropped (merge review, 2026-10-10): a
# per-UTF-16-unit loop classified the halves of U+E0100 as surrogates and kept
# them, and invisible characters of other categories (the Hangul fillers are
# letters; unassigned code points) pass any category list. Characters are
# classified whole, a surrogate pair at once, through CharUnicodeInfo, not
# regex `\p{...}` classes: the regex engine's tables put U+00AD under dash
# punctuation, not format, so a regex-based fold read `BLOC<U+00AD>KER:` as
# `BLOC-KER:` and missed it (checked 2026-10-10).
# scripts/review-common.ps1 and the log readers
# (scripts/shared/analyze-blocker-trends.ps1, dispatch-checklist.ps1,
# worker-audit.ps1) carry byte-identical copies of this function.
function ConvertTo-CrgStructureFold {
  param([string]$Line)
  if ($Line -cnotmatch '[^\x09\x0A\x0D\x20-\x7E]') { return $Line.ToUpperInvariant() }
  try { $decomposed = $Line.Normalize([System.Text.NormalizationForm]::FormKD) } catch { return $null }
  $fold = New-Object System.Text.StringBuilder ($decomposed.Length)
  for ($i = 0; $i -lt $decomposed.Length; $i++) {
    $c = $decomposed[$i]
    $code = [int]$c
    if ($code -lt 0x80) {
      if (($code -ge 0x20 -and $code -lt 0x7F) -or $code -eq 9 -or $code -eq 10 -or $code -eq 13) { [void]$fold.Append([char]::ToUpperInvariant($c)) }
      continue
    }
    if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($decomposed, $i) -eq [System.Globalization.UnicodeCategory]::DashPunctuation) { [void]$fold.Append('-') }
    elseif ($code -eq 0x131) { [void]$fold.Append('I') }
    if ([char]::IsHighSurrogate($c) -and $i + 1 -lt $decomposed.Length -and [char]::IsLowSurrogate($decomposed[$i + 1])) { $i++ }
  }
  return $fold.ToString()
}

# Classify a single category-count tail the SAME WAY the wrapper's category
# regex matches it: the wrapper accepts ONLY `none` or a bounded digit run
# (`(?<v>none|\d+)` with `[int]::TryParse` + `<= 10000`). Returns @{ Kind; Value }
# -- 'none' / 'count' / 'invalid' for any other tail. The log consumers must
# classify tails identically, or they disagree on which verdict files are
# trustworthy evidence:
#   Kind = 'none'    -> the tail is exactly `none` (no findings under it).
#   Kind = 'count'   -> a valid in-bound digit count (Value = the integer).
#   Kind = 'invalid' -> anything else: an EMPTY tail (the wrapper requires a
#                       value), a non-numeric tail, OR a digit run that fails
#                       TryParse / exceeds 10000. (Codex BLOCKER: an
#                       empty tail was previously treated as valid.)
function Get-CategoryTailKind {
  param([string]$Tail)
  $t = $Tail.Trim()
  # CASE-SENSITIVE `none` compare (ordinal): the wrapper's category grammar is
  # case-sensitive and refuses `None` / `NONE`, so a case-insensitive compare
  # would admit a wrong-case tail as clean evidence.
  if ([string]::Equals($t, 'none', [System.StringComparison]::Ordinal)) { return @{ Kind = 'none'; Value = 0 } }
  # Digits-only shape before TryParse: TryParse alone accepts tails the wrapper
  # refuses, such as a signed `+1` or a trailing NUL character.
  $parsed = 0
  if ($t -match '^\d+$' -and [int]::TryParse($t, [ref]$parsed) -and $parsed -le $script:CategoryCountMax) {
    return @{ Kind = 'count'; Value = $parsed }
  }
  return @{ Kind = 'invalid'; Value = 0 }
}

# ---------------------------------------------------------------------------
# Fail-closed banner recognizer + reason extractor.
#
# Returns the wrapper's own fail-closed REASON line iff $Content is a genuine
# codex-wrapper fail-closed artifact, else $null. A non-null result marks a
# SELF-DECLARED failed gate run: the caller EXCLUDES the file from the tally
# LOUDLY (never silently) rather than refusing the whole window.
#
# PRODUCER-SHAPE VALIDATION (recognize ONLY the wrapper's own top-of-file emission
# SHAPE -- a producer-shaped SELF-DECLARATION, NOT an authenticated receipt: the
# header values are checked for the producer's exact lexical FORM (a 64-hex SHA256,
# a 40/64-hex OID, ...), not a signature, object existence, or a match against a real
# diff, so an all-zero header is a valid shape. What it buys is that model-authored /
# wrong-backend / reviewer-body-forged content cannot be misclassified as a
# fail-closed run and hide genuine findings). The banner is
# emitted ONLY by scripts/codex/auto-review.ps1: when a run fails closed it PREPENDS
# `===== GATE FAILED CLOSED =====\n<diagnostic>\n\nVERDICT: BLOCKED\n\n` to the
# pass concatenation; the provenance header + blank is prepended in a separate
# step. So the FINAL artifact begins with the header block, a blank, the banner,
# the diagnostic, a blank, then `VERDICT: BLOCKED`. Three producer ERAS of the header
# exist (the 2026-07 severity-contract change added REVIEW-SEVERITY-CONTRACT; the
# 4-line era predates it; the duration stamp made the 6-line era) -- ALL are recognized, else the full-history analyzer regresses
# to aborting on historical four-line-era fail-closed evidence:
#   4-line era: DIFF-SHA256 / REVIEW-TREE-OID / REVIEW-BACKEND: codex / REVIEW-EFFORT
#   5-line era: ... + REVIEW-SEVERITY-CONTRACT: blocker-only
#   6-line era: ... + REVIEW-DURATION-SECS: <secs>
# This function validates ONLY the producer-owned, reviewer-content-free portions
# (the header block by line index + exact value -- a 64-hex SHA256, a 40/64-hex git
# OID, codex backend, a known reasoning tier or 'unknown', the blocker-only
# contract -- the exact full-line banner, a known diagnostic with pass counts
# bounded to the producer's 1..10 range, `VERDICT: BLOCKED`, the FIRST suffix line's
# producer shape, and the exact terminal LF framing) and treats the multi-section
# MIDDLE as OPAQUE salvaged reviewer content. See the function-body PHASE CONTRACT
# for why pass bodies cannot be section-parsed (they are embedded UNESCAPED, so a
# body may legally contain a literal pass-marker line) and how the producer-migration
# follow-up unit will lift that limit; the fail-closed DETERMINATION rests on the
# producer-owned prefix + the first-suffix-line shape + terminal framing, ALL over
# strict no-BOM-decoded bytes -- never on the opaque middle. Why exact header values,
# not a tolerant scan: the
# Claude wrapper (scripts/claude/auto-review.ps1) writes RAW reviewer text (model
# output) immediately after its own trusted `REVIEW-BACKEND: claude` header, so a
# tolerant scan could be defeated by reviewer text forging a codex header + banner
# in the body -- excluding a genuine Claude BLOCKER verdict. Anchoring the real
# line-3 backend + validating exact values leaves no room for a body forgery or a
# non-producer shape. (Open item: these checks are pinned to the producer
# values so a producer change is the only thing that can require a recognizer change.)
#
# SHARED with scripts/shared/analyze-blocker-trends.ps1 (byte-identical there):
# the banner recognizer is a cross-script contract, same lock-step discipline as
# the mirrored filename-shape / dedupe / UTF-8 primitives. Any change to the
# wrapper's header block, value formats, or diagnostic grammar must be mirrored in
# BOTH copies. The exclusion logic that USES this sits in each script's parse loop.
function Get-FailClosedBannerReason {
  param([string]$Content)
  # PHASE CONTRACT (Option A/C): validate ONLY the producer-owned, reviewer-content-
  # free portions -- the header block, the banner line, the diagnostic line, the
  # blank separators, `VERDICT: BLOCKED`, the FIRST suffix line's producer SHAPE, and
  # exact terminal framing. The multi-section MIDDLE (the pass concatenation past the
  # first marker) is treated as OPAQUE salvaged reviewer content: it is NEVER scanned
  # for markers and its bodies are NEVER parsed. The diagnostic IS cross-checked
  # against the producer-owned FIRST suffix line (a malformed/expected diagnostic
  # constrains whether that line is the no-verdict remainder or a marker, and an
  # expected-N diagnostic constrains the first marker's total) -- but NEVER against
  # the opaque-middle bodies. WHY: auto-review.ps1's verdict-concatenation site embeds each pass
  # body UNESCAPED after its marker, so a body may legally contain a literal
  # `===== REVIEW PASS n/N =====` line -- body boundaries are ambiguous BY
  # CONSTRUCTION, making any body-level validation (marker counting, body malformed-
  # ness) unsound. The fail-closed DETERMINATION rests on the producer-owned PREFIX
  # (header + banner + diagnostic + VERDICT: BLOCKED) PLUS the first-suffix-line shape
  # and terminal framing, all validated over strict no-BOM-decoded bytes -- NEVER on
  # the opaque middle. Unambiguous body framing + body-level validation are
  # the planned producer-migration follow-up unit; until it lands, deeper suffix
  # validation is deliberately out of scope here.
  # LF framing is validated PER-LINE (not by a blanket CR scan): the producer emits
  # every framing line -- header, banner, diagnostic, VERDICT, blanks, the first
  # marker, terminal -- with LF, so a CR-converted framing line carries a trailing
  # \r that fails its exact check below. The opaque MIDDLE (reviewer body) may hold
  # any bytes, so a blanket CR reject would wrongly refuse a valid artifact whose
  # reviewer body legitimately contains CRLF.
  $lines = $Content -split "`n"
  $n = $lines.Count
  if ($n -lt 12) { return $null }   # cheap lower bound; the per-index checks below are authoritative
  # HEADER BLOCK. CASE-SENSITIVE (-c* / ordinal): PowerShell's default operators are case-
  # INSENSITIVE, which would wrongly accept REVIEW-BACKEND: CODEX or uppercase hex
  # the producer never emits. Values pinned to auto-review.ps1's exact emission.
  # Ordinal literal compares: culture compares ignore characters such as U+00AD.
  if ($lines[0] -cnotmatch '^DIFF-SHA256: [0-9a-f]{64}$')                              { return $null }
  if ($lines[1] -cnotmatch '^REVIEW-TREE-OID: [0-9a-f]{40}([0-9a-f]{24})?$')           { return $null }   # 40 (SHA1) or 64 (SHA256) hex
  if (-not [string]::Equals($lines[2], 'REVIEW-BACKEND: codex', [System.StringComparison]::Ordinal)) { return $null }
  if ($lines[3] -cnotmatch '^REVIEW-EFFORT: (minimal|low|medium|high|xhigh|max|unknown)$') { return $null }   # auto-review.ps1 $validTiers or 'unknown'
  # Line 4 selects the era: the 5-line contract stamp -- then OPTIONALLY the
  # 6-line REVIEW-DURATION-SECS stamp on line 5, value-shape validated (the
  # reviewer stamps it on EVERY artifact, fail-closed ones included, so a
  # recognizer blind to it would abort every current fail-closed run as
  # unrecognized instead of excluding it loudly) -- OR the blank ending the
  # 4-line header.
  if ([string]::Equals($lines[4], 'REVIEW-SEVERITY-CONTRACT: blocker-only', [System.StringComparison]::Ordinal)) {
    if     ($lines[5] -cmatch '^REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$') { $blankIdx = 6 }
    elseif ($lines[5].Length -eq 0)                                      { $blankIdx = 5 }
    else                                                                 { return $null }
  }
  elseif ($lines[4].Length -eq 0)                                 { $blankIdx = 4 }
  else                                                            { return $null }
  $bannerIdx = $blankIdx + 1
  if (($bannerIdx + 5) -ge $n)                              { return $null }   # need banner+diag+blank+VERDICT+blank+>=1 suffix line
  if ($lines[$blankIdx].Length -ne 0)                       { return $null }
  if (-not [string]::Equals($lines[$bannerIdx], '===== GATE FAILED CLOSED =====', [System.StringComparison]::Ordinal)) { return $null }
  # DIAGNOSTIC (Get-CombinedReviewExit): the fixed malformed/errored strings, or the `expected N ...
  # only M ...` form with CANONICAL decimal counts (no leading zeros -- the producer
  # formats ints canonically). TryParse (not [int], which THROWS on overflow under
  # Stop) bounds N to the producer 1..10 range and M to 0..N-1. N/M are producer-
  # owned and cross-checked against the FIRST suffix line below (never the middle).
  $diag = $lines[$bannerIdx + 1]
  $diagKind = ''; $diagN = 0; $diagM = 0
  if ([string]::Equals($diag, 'at least one pass produced a malformed verdict', [System.StringComparison]::Ordinal)) { $diagKind = 'malformed' }
  elseif ([string]::Equals($diag, 'one or more review passes errored or produced no verdict', [System.StringComparison]::Ordinal)) { $diagKind = 'errored' }
  else {
    $dm = [regex]::Match($diag, '^expected (?<n>0|[1-9][0-9]*) review passes, only (?<m>0|[1-9][0-9]*) completed$')
    if ($dm.Success) {
      $pn = 0; $pm = 0
      if ([int]::TryParse($dm.Groups['n'].Value, [ref]$pn) -and [int]::TryParse($dm.Groups['m'].Value, [ref]$pm) -and `
          $pn -ge 1 -and $pn -le 10 -and $pm -ge 0 -and $pm -lt $pn) {
        $diagKind = 'expected'; $diagN = $pn; $diagM = $pm
      }
    }
  }
  if ($diagKind -eq '')                                     { return $null }   # unknown / unbounded / non-canonical diagnostic
  if ($lines[$bannerIdx + 2].Length -ne 0)                  { return $null }
  if (-not [string]::Equals($lines[$bannerIdx + 3], 'VERDICT: BLOCKED', [System.StringComparison]::Ordinal)) { return $null }
  if ($lines[$bannerIdx + 4].Length -ne 0)                  { return $null }
  # TERMINAL FRAMING (validated, not normalized): the producer ends the artifact with
  # exactly ONE trailing LF, and each final pass body is `Verdict.TrimEnd()` (or the
  # exact `(no verdict produced)` remainder), so the split yields exactly one trailing
  # empty element AND the last CONTENT line ends in a NON-whitespace char. Reject a
  # missing terminal LF (last element non-empty), extra trailing blank line(s)
  # (second-to-last empty), or a whitespace-ENDING final content line -- a terminal CR
  # from CRLF, trailing spaces/tabs, or a whitespace-only final body are all producer-
  # impossible because TrimEnd strips them.
  if ($lines[$n - 1].Length -ne 0)                          { return $null }   # missing terminal newline
  if ($lines[$n - 2].Length -eq 0)                          { return $null }   # extra trailing blank line(s)
  $lastContent = $n - 2
  if ($lines[$lastContent] -cmatch '\s$')                   { return $null }   # trailing whitespace on the final content line (TrimEnd => never)
  $suffixStart = $bannerIdx + 5
  if ($lastContent -lt $suffixStart)                        { return $null }   # empty suffix
  # FIRST SUFFIX LINE (producer-owned): exactly `(no verdict produced)` (then nothing
  # else -- this remainder is fully producer-owned) XOR a producer-shaped pass marker
  # (CANONICAL decimals, n in 1..total, total in 1..10) followed by an OPAQUE, non-
  # empty middle. The multi-section MIDDLE past this line is never inspected.
  $suffixIsNoVerdict = $false; $firstMarkerN = 0; $firstMarkerTotal = 0
  if ([string]::Equals($lines[$suffixStart], '(no verdict produced)', [System.StringComparison]::Ordinal)) {
    if ($lastContent -ne $suffixStart)                      { return $null }   # trailing data after the no-verdict remainder
    $suffixIsNoVerdict = $true
  }
  else {
    $mm = [regex]::Match($lines[$suffixStart], '^===== REVIEW PASS (?<n>0|[1-9][0-9]*)/(?<total>0|[1-9][0-9]*) =====$')
    if (-not $mm.Success)                                   { return $null }   # first suffix line is not a producer shape
    $pnv = 0; $ptv = 0
    if (-not ([int]::TryParse($mm.Groups['n'].Value, [ref]$pnv) -and [int]::TryParse($mm.Groups['total'].Value, [ref]$ptv))) { return $null }
    if ($ptv -lt 1 -or $ptv -gt 10 -or $pnv -lt 1 -or $pnv -gt $ptv) { return $null }   # first-marker counts out of producer range
    if ($suffixStart -ge $lastContent)                     { return $null }   # marker-only: the opaque middle (>=1 body line) must follow
    $firstMarkerN = $pnv; $firstMarkerTotal = $ptv
  }
  # LEXICAL-AXIS CLOSURE (every character-level axis of the producer emission is either
  # validated exactly here, or classified as producer-invariant; audited once, completely,
  # parallel to the marker matrix below):
  #   line splitting         -> producer emits LF; we split on `\n`.
  #   CR anywhere            -> framing lines are LF, so the exact per-line matches reject a
  #                             trailing \r on any producer-owned line, and the terminal
  #                             whitespace check rejects a \r on the last content line; a CR
  #                             INSIDE the opaque middle is reviewer content, allowed.
  #   terminal newline count -> exactly one trailing LF (last elem empty, penultimate not).
  #   trailing whitespace    -> Verdict.TrimEnd() => the last content char is never whitespace.
  #   leading whitespace/BOM -> a UTF-8/UTF-16/UTF-32 BOM (byte 0) is rejected UPSTREAM at the
  #                             decode boundary: Read-VerdictArtifactText reads raw bytes and
  #                             refuses any preamble before this string exists, so a BOM never
  #                             reaches the recognizer. Any OTHER leading whitespace is caught
  #                             here because every producer-owned line is exact-matched
  #                             (`^...$` / ordinal).
  #   interior tabs/spaces   -> the producer emits single spaces; the exact matches pin them.
  #   blank-line counts      -> the one/zero blanks between each producer-owned pair are pinned
  #                             by fixed line index (an extra/missing blank shifts a required
  #                             line off its exact match).
  #   whitespace-only blanks -> every producer blank is checked for zero length (a "  " blank fails).
  #   unicode whitespace     -> `\s` (terminal check) + the exact ASCII matches cover it.
  #   case on every literal  -> all comparisons are case-sensitive (ordinal / `-c*` / [regex]::Match).
  # The opaque MIDDLE's interior bytes are the ONLY unvalidated axis (reviewer content by
  # construction -- see the PHASE CONTRACT); its FRAMING (first marker + terminal) is pinned.
  # DIAGNOSTIC <-> FIRST-MARKER matrix (CLOSED; all PRODUCER-OWNED, prefix-level; the
  # opaque middle is never consulted). Get-CombinedReviewExit picks the diagnostic by
  # PRECEDENCE -- $PassErrored -> errored; else results.Count < N -> expected N/M; else
  # anyMalformed -> malformed -- over successful passes collected in ASCENDING order, so
  # the first marker's n is the FIRST successful pass number and its total is N (=ReviewPasses):
  #   malformed => NO pass errored => all N passes present, contiguous 1..N => the first
  #                marker is 1/N: a marker (not no-verdict) AND n == 1.
  #   errored   => at least one pass errored => K < N: no-verdict (K==0) OR a marker; a
  #                marker means at least one succeeded AND at least one errored, so total (=N) >= 2.
  #   expected N/M, M==0 => zero completed => the no-verdict remainder.
  #   expected N/M, M>=1 => M ascending successes out of N => a marker, total == N, and
  #                the first index n <= N-M+1.
  # The table is CLOSED: every relationship between (diagnostic form, its N/M) and (first
  # marker n/total, marker-vs-no-verdict) is pinned. The only values left open are the two
  # that would need K (the section count in the OPAQUE middle): n's upper bound under
  # errored, and total under malformed -- those stay at n<=total / total in 1..10. A
  # mismatch is producer-impossible -> $null so the caller's UNRECOGNIZED-malformed abort
  # fires (never a silent exclusion of corrupted evidence).
  if ($diagKind -eq 'malformed') {
    if ($suffixIsNoVerdict)                                 { return $null }
    if ($firstMarkerN -ne 1)                                { return $null }
  }
  elseif ($diagKind -eq 'errored') {
    if (-not $suffixIsNoVerdict) {
      if ($firstMarkerTotal -lt 2)                          { return $null }
    }
  }
  elseif ($diagKind -eq 'expected') {
    if ($diagM -eq 0) {
      if (-not $suffixIsNoVerdict)                          { return $null }
    }
    else {
      if ($suffixIsNoVerdict)                               { return $null }
      if ($firstMarkerTotal -ne $diagN)                     { return $null }
      if ($firstMarkerN -gt ($diagN - $diagM + 1))          { return $null }
    }
  }
  return $diag
}

function Read-VerdictArtifactText {
  # DECODE-BOUNDARY byte-0 guarantee for Get-FailClosedBannerReason: read the
  # artifact as raw BYTES and strict-decode through a no-BOM UTF-8 decoder, so the
  # recognizer receives EXACTLY the producer's bytes from byte 0 -- never a
  # preamble-stripped string.
  #
  # WHY bytes, not [System.IO.File]::ReadAllText(..., UTF8): the framework UTF-8
  # decoder silently CONSUMES a leading BOM/preamble, so a BOM-bearing file --
  # impossible for the UTF-8-no-BOM producer (auto-review.ps1 writes via a no-BOM
  # UTF8Encoding) -- would reach the recognizer BOM-less, pass the exact-shape
  # checks, and be EXCLUDED as a genuine fail-closed run instead of taking the
  # malformed-evidence abort. The recognizer's own leading-BOM string check (see
  # LEXICAL-AXIS CLOSURE) cannot fire once the byte is gone before the string
  # exists; enforcing the guarantee HERE, at the decode boundary, is what makes it
  # real. (Reading bytes also sidesteps the Get-Content -Raw WinPS 5.1 ANSI-codepage
  # mojibake on em-dash / smart-quote glyphs the old UTF-8 ReadAllText avoided.)
  #
  # Returns @{ Ok = $true; Text = <decoded> } on a clean UTF-8-no-BOM read, else
  # @{ Ok = $false; Reason = <why> }; a reject is malformed evidence -- the caller
  # routes it to the suspect/abort path, NEVER the fail-closed exclude path.
  param([string]$Path)

  $bytes = [System.IO.File]::ReadAllBytes($Path)

  # Reject ANY encoding preamble: the producer emits UTF-8 with NO BOM, so a
  # leading BOM of any width proves the file is not producer-shaped. Test the
  # 4-byte UTF-32 preambles BEFORE the 2-byte UTF-16 prefixes they overlap.
  if ($bytes.Length -ge 4 -and $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) {
    return @{ Ok = $false; Reason = 'UTF-32 BE byte-order mark (producer emits UTF-8 without a BOM)' }
  }
  if ($bytes.Length -ge 4 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00) {
    return @{ Ok = $false; Reason = 'UTF-32 LE byte-order mark (producer emits UTF-8 without a BOM)' }
  }
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    return @{ Ok = $false; Reason = 'UTF-8 byte-order mark (producer emits UTF-8 without a BOM)' }
  }
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
    return @{ Ok = $false; Reason = 'UTF-16 BE byte-order mark (producer emits UTF-8 without a BOM)' }
  }
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
    return @{ Ok = $false; Reason = 'UTF-16 LE byte-order mark (producer emits UTF-8 without a BOM)' }
  }

  # Strict UTF-8 decode: emit no BOM, THROW on any invalid byte sequence (the
  # constructor's throwOnInvalidBytes drives the decoder's exception fallback, so
  # GetString rejects malformed UTF-8 rather than substituting U+FFFD).
  try {
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $text = $strictUtf8.GetString($bytes)
  } catch {
    return @{ Ok = $false; Reason = 'invalid UTF-8 (strict no-BOM decode threw)' }
  }
  return @{ Ok = $true; Text = $text }
}

# ---------------------------------------------------------------------------
# Classify ONE verdict file's STRUCTURE and decide whether it is TRUSTWORTHY
# review evidence. A file that is not trustworthy must make the run fail loud,
# never be summarized as clean.
#
# IsCleanEvidence is a SUPERSET of the wrapper's own malformed-output contract
# (`Get-VerdictExitCode` in scripts/review-common.ps1): it rejects everything the wrapper
# would fail closed on (exit 3), including non-canonical severity prefixes (the
# $hasWrongCaseSeverity scan), AND additionally rejects over/underfilled
# category row blocks and malformed category tails outside any review-pass block
# (which would misparse here -- see Test-VerdictBlock's row-balance note and the
# $hasInvalidCount scan). So this generator
# never accepts a wrapper-rejected verdict, and may reject a few well-formed-to-
# the-wrapper-but-row-malformed ones on purpose. Because the artifact
# is a per-pass CONCATENATION, the file is split into PASS BLOCKS on the
# `===== ... =====` separators and EACH REVIEW PASS block is validated
# independently by Test-VerdictBlock against the wrapper's per-verdict rules
# (exactly one VERDICT line; each category exactly once as `none|<digits>`;
# count sum == severity-line count; no underfilled category; verdict<->finding
# coherence with BLOCKER precedence). A file is trustworthy ONLY when:
#   1. ANY `^VERDICT:` line is present (the wrapper captures `^VERDICT:` into
#      VerdictText; only ZERO such lines is "missing verdict"). (Codex BLOCKERs.)
#   2. NO `===== GATE FAILED CLOSED =====` banner -- the authoritative
#      fail-closed signal even when a clean-pass block is also present (a
#      multi-pass fail-closed run prepends the banner to the successful passes).
#      (Codex BLOCKER.)
#   3. Every one of the eight category lines is present somewhere (a quick
#      completeness signal; exact per-block cardinality is enforced in 4).
#   4. EVERY REVIEW PASS block validates against Test-VerdictBlock (a pass
#      block with no VERDICT line fails -- the P10 regression pin).
#      This subsumes the earlier whole-file checks and adds exact per-block
#      category CARDINALITY (each category EXACTLY once -- catches duplicate
#      category lines, the wrapper's V18 case) and a DIGITS-ONLY count shape
#      (`none|\d+`; rejects `+1`). (Codex BLOCKER; also covers
#      invalid-count, incoherent-verdict, underfill +
#      malformed-word-with-BLOCKER.)
#   5. NO malformed category tail ANYWHERE in the file (the whole-file
#      $hasInvalidCount scan). Within a review-pass block the wrapper's
#      Get-VerdictExitCode now refuses the same row (it counts every `^<CAT>:`
#      row toward cardinality); this scan also covers header fragments outside
#      any block, because a malformed category line makes the artifact an
#      untrustworthy DATA SOURCE for the dispatch summary (Get-CategoryFindings
#      could misparse it).
# (Codex BLOCKER: HasInvalidCount was computed but
#      omitted from IsCleanEvidence.)
# Returns the individual signals plus IsCleanEvidence so callers agree.
# ---------------------------------------------------------------------------
$script:CatNamesAll = @('PLAN-DRIFT','SILENT-FAILURE','TOMBSTONE-OR-SHIM','CROSS-CRATE-CONTRACT','LOADER-OR-ASSET-EDGE','CONVENTION-ADHERENCE','TEST-QUALITY','DOC-VS-CODE-DRIFT')

# Validate ONE verdict BLOCK (the text of a single review pass). The first four
# checks below are exactly the wrapper's Get-VerdictExitCode malformed-output
# contract (so a block the wrapper would have failed closed on, exit 3, is
# rejected here too). The row-balance check is a DELIBERATE SUPERSET, STRICTER
# than the wrapper: Get-VerdictExitCode validates category cardinality + count
# totals but does NOT inspect the indented finding rows, whereas THIS script's
# Get-CategoryFindings consumes exactly the declared number of rows -- so an
# over/underfilled block would silently drop or misparse findings here. The
# extra rejection protects this generator's parsing; it is NOT pure wrapper
# parity. (Codex QUALITY: the comment used to over-claim pure parity.)
# Returns $true iff the block is well-formed under all of:
#   [wrapper] EXACTLY ONE `^VERDICT:` line (the wrapper rejects 0 or >1). Any
#     tail after the colon counts as present (mirrors `^VERDICT:` capture); the
#     WORD is validated only via the coherence rule below.
#   [wrapper] Each of the eight categories has EXACTLY ONE `^<CATEGORY>:` row,
#     whatever its tail, and that row has a `none|<digits>` value on the row
#     itself. A duplicate category line, a malformed tail like `+1`, or a value
#     on the following line fails.
#   [wrapper] per-category count sum == per-severity finding-line count.
#   [STRICTER-than-wrapper] each `<CATEGORY>: <n>` is followed by EXACTLY `n`
#     indented rows (no underfill AND no overfill); a `none`/`0` category has
#     ZERO indented rows. See the rationale above.
#   [wrapper] verdict<->finding coherence (BLOCKER precedence; else exact word).
function Test-VerdictBlock {
  param([string]$Block)

  # The VERDICT word is exact, as the wrappers compare the line, less trailing
  # whitespace, ordinally (`verdict: clean` is wrapper-rejected). Severity/category regexes are exact too.
  $verdictWordRe = [regex]'(?m)^VERDICT: (?<v>CLEAN|NON-BLOCKING|BLOCKED)\s*$'
  $catExactRe = [regex]'(?m)^(?<cat>PLAN-DRIFT|SILENT-FAILURE|TOMBSTONE-OR-SHIM|CROSS-CRATE-CONTRACT|LOADER-OR-ASSET-EDGE|CONVENTION-ADHERENCE|TEST-QUALITY|DOC-VS-CODE-DRIFT):[^\S\r\n]*(?<rest>.*)$'
  # Severity-prefix counting MIRRORS Get-VerdictExitCode EXACTLY
  # (it counts `(?m)^BLOCKER:`, `^QUALITY:`, `^NON-BLOCKER:`, `^NOTE:` with NO
  # content requirement). An EARLIER `\s*\S` form here required non-empty text,
  # so an empty `BLOCKER:` line was counted 0 by this script but 1 by the wrapper
  # -> the wrapper would fail closed on the sum mismatch while this script passed
  # the block as clean evidence. Counting any `^<PREFIX>:` here keeps the
  # count-sum parity exact, so the same sum-mismatch the wrapper fails closed on
  # makes Test-VerdictBlock return $false. (Codex BLOCKER.)
  $blockerPrefixRe = [regex]'(?m)^BLOCKER:'
  $qualityPrefixRe = [regex]'(?m)^QUALITY:'
  $legacyNbPrefixRe = [regex]'(?m)^NON-BLOCKER:'
  $notePrefixRe = [regex]'(?m)^NOTE:'

  # Exactly one VERDICT line in any spelling (mirrors the wrapper's capture
  # through ConvertTo-CrgStructureFold + its 0-or->1 rejection; a line that
  # cannot be normalized counts). The WORD validity is handled by the
  # coherence rule.
  $verdictLines = @($Block -split "`n" | Where-Object { $verdictFold = ConvertTo-CrgStructureFold -Line $_; $null -eq $verdictFold -or $verdictFold -cmatch '\AVERDICT\s*:' })
  if ($verdictLines.Count -ne 1) { return $false }
  $verdictWord = $null
  $vw = $verdictWordRe.Match($Block)
  if ($vw.Success) { $verdictWord = $vw.Groups['v'].Value }

  $categoryTotal = 0
  foreach ($c in $script:CatNamesAll) {
    $perCatRe = [regex]('(?m)^' + [regex]::Escape($c) + ':[^\S\r\n]*(?<v>none|\d+)[^\S\r\n]*\r?$')
    $ms = $perCatRe.Matches($Block)
    if ($ms.Count -ne 1) { return $false }                    # cardinality + shape
    if (([regex]::Matches($Block, '(?m)^' + [regex]::Escape($c) + ':')).Count -ne 1) { return $false }
    $v = $ms[0].Groups['v'].Value
    if (-not [string]::Equals($v, 'none', [System.StringComparison]::Ordinal)) {
      $parsed = 0
      if (-not [int]::TryParse($v, [ref]$parsed) -or $parsed -gt $script:CategoryCountMax) { return $false }
      $categoryTotal += $parsed
    }
  }

  $blockerN = $blockerPrefixRe.Matches($Block).Count
  $nbLikeN  = $qualityPrefixRe.Matches($Block).Count + $legacyNbPrefixRe.Matches($Block).Count + $notePrefixRe.Matches($Block).Count
  if ($categoryTotal -ne ($blockerN + $nbLikeN)) { return $false }

  # Row balance: each `<CATEGORY>: <n>` must have EXACTLY n indented finding
  # rows -- neither fewer (UNDERFILL) nor more (OVERFILL). A `<CATEGORY>: none`
  # (or `0`) must have ZERO indented rows. $inCatBlock tracks that a category
  # line is currently active (set for `none` blocks too, with remaining 0, so an
  # unexpected indented row under a `none` category is caught as overfill).
  # (Codex BLOCKER: the old loop only checked while remaining > 0, so an
  # extra row after the count was satisfied bypassed validation and
  # Get-CategoryFindings silently dropped it.)
  $inCatBlock = $false
  $declRemaining = 0
  foreach ($line in ($Block -split "`r?`n")) {
    $cm = $catExactRe.Match($line)
    if ($cm.Success) {
      if ($inCatBlock -and $declRemaining -gt 0) { return $false }   # prior block UNDERFILLED
      $k = Get-CategoryTailKind -Tail $cm.Groups['rest'].Value
      $inCatBlock = $true
      $declRemaining = if ($k.Kind -eq 'count') { $k.Value } else { 0 }   # 'none' -> 0 rows expected
      continue
    }
    if ($inCatBlock) {
      if ($line -match '^\s+\S') {
        if ($declRemaining -le 0) { return $false }   # OVERFILL: more rows than declared
        $declRemaining--
      } elseif (-not [string]::IsNullOrWhiteSpace($line)) {
        # Non-indented non-blank line ends the active block.
        if ($declRemaining -gt 0) { return $false }   # UNDERFILL: ended with rows owed
        $inCatBlock = $false
      }
      # A blank line is tolerated inside an active block (does not end it).
    }
  }
  if ($inCatBlock -and $declRemaining -gt 0) { return $false }   # EOF with rows owed (underfill)

  # Coherence (wrapper precedence): BLOCKER present -> valid (any word); else
  # QUALITY/NON-BLOCKER/NOTE -> word must be NON-BLOCKING; else zero findings -> word CLEAN.
  if ($blockerN -ge 1) { return $true }
  if ($nbLikeN -ge 1) { return [string]::Equals($verdictWord, 'NON-BLOCKING', [System.StringComparison]::Ordinal) }
  return [string]::Equals($verdictWord, 'CLEAN', [System.StringComparison]::Ordinal)
}

# ---------------------------------------------------------------------------
function Get-VerdictStructure {
  param([string]$Content)
  $verdictRe = [regex]'(?m)^VERDICT: (?<v>CLEAN|NON-BLOCKING|BLOCKED)\s*$'
  # Wrapper-exact severity-prefix form (NO content requirement) so an empty
  # `BLOCKER:` line is recognized as a finding signal, matching auto-review.ps1.
  # (Class-sweep with Test-VerdictBlock, Codex BLOCKER.)
  $sevRe     = [regex]'(?m)^(BLOCKER|QUALITY|NON-BLOCKER|NOTE):'
  $catNames  = $script:CatNamesAll

  # Loose line recognition goes through ConvertTo-CrgStructureFold, never a
  # culture `(?i)` match, which under tr-TR does not fold ASCII `i` onto `I`.
  # A line that cannot be normalized makes the file untrustworthy
  # ($hasWrongCaseSeverity below).
  $structureLines = @($Content -split "`n")
  $structureFolds = @(foreach ($structureLine in $structureLines) { ConvertTo-CrgStructureFold -Line $structureLine })
  # ANY VERDICT line in any spelling (presence), mirroring the wrapper's
  # capture; the exact word check above decides acceptance.
  $hasVerdict = (@($structureFolds | Where-Object { $_ -cmatch '\AVERDICT\s*:' }).Count -gt 0)
  $verdictWords = @($verdictRe.Matches($Content) | ForEach-Object { $_.Groups['v'].Value })
  $hasBlockedOrNb = @($verdictWords | Where-Object { [string]::Equals([string]$_, 'BLOCKED', [System.StringComparison]::Ordinal) -or [string]::Equals([string]$_, 'NON-BLOCKING', [System.StringComparison]::Ordinal) })

  # Fail-closed banner is the AUTHORITATIVE fail-closed signal.
  $hasFailClosed = (@($structureFolds | Where-Object { $_ -cmatch '\A=====\s*GATE FAILED CLOSED\s*=====' }).Count -gt 0)

  # Complete category block: every one of the eight category lines is present
  # somewhere (a quick signal; per-block cardinality is enforced below).
  $allCats = $true
  foreach ($c in $catNames) {
    $cre = [regex]('(?m)^' + [regex]::Escape($c) + ':\s*')
    if (-not $cre.IsMatch($Content)) { $allCats = $false; break }
  }

  # Split the artifact into segments on the `=====` markers, capturing each
  # marker so we know whether the segment that FOLLOWS it is a REVIEW PASS block
  # (which must validate) or a header/banner fragment (exempt). A single-pass
  # artifact has NO markers and is ONE review-pass block.
  #
  # Contract (Codex BLOCKER): EVERY non-empty REVIEW-PASS block
  # must pass Test-VerdictBlock (exactly one VERDICT line + the full per-verdict
  # rules). Validating only blocks that HAPPEN to contain `^VERDICT:` was the
  # hole: a `===== REVIEW PASS =====` block with categories but NO VERDICT
  # line would be silently skipped while a later clean block kept AllBlocksValid
  # true. Now a review-pass block with no VERDICT fails Test-VerdictBlock (its
  # "exactly one VERDICT line" check), so it can no longer slip through. Only
  # true header fragments (the leading text before the first marker, and the
  # GATE FAILED CLOSED banner's own text) are exempt -- and the banner already
  # forces fail-closed via $hasFailClosed regardless.
  # Marker handling is STRICT (Codex BLOCKER):
  #   - The ONLY exempt non-pass marker is `===== GATE FAILED CLOSED =====`
  #     (which independently forces fail-closed via $hasFailClosed). ANY OTHER
  #     `=====` marker (e.g. a planted `===== EXTRA =====`) is malformed evidence
  # -> reject. (unknown-marker blocker: unknown markers were silently exempted, so
  #     severity lines hidden after an unknown marker escaped validation.)
  #   - REVIEW PASS markers are SEQUENCE-validated: auto-review.ps1 emits exactly
  #     `===== REVIEW PASS n/N =====` for n in 1..N, one block each, where N is
  #     itself bounded to the producer's 1..$ReviewPassMax (=10) range. Require
  #     every pass number 1..N present exactly once with ONE agreed total N (and
  #     n,N in 1..10), each block passing Test-VerdictBlock. A truncated artifact
  #     (only pass 1 of N), a duplicate/total-mismatch, or an N the producer
  #     cannot emit (e.g. 11) is malformed. (marker-sequence blocker; range bound Codex
  #     BLOCKER.)
  # EXACT match to auto-review.ps1's emitted marker string (its writer at
  # auto-review.ps1: "===== REVIEW PASS $($_.Pass)/$ReviewPasses ====="): literal
  # single spaces around `REVIEW PASS`, NO spaces around the `/`, and CASE-
  # SENSITIVE (no `(?i)`). Only the trailing whitespace the line-split may leave
  # is tolerated (`\s*$`). A variant like `===== review pass 1 / 1 =====` is NOT
  # what the producer emits and is rejected as malformed evidence. (Codex BLOCKER:
  # the old `(?im)` + `\s*` form accepted producer-
  # impossible spellings.) The fail-closed banner is matched the same exact way.
  $passMarkerRe = [regex]'(?m)^===== REVIEW PASS (?<n>\d+)/(?<total>\d+) =====\s*$'
  $failClosedMarkerRe = [regex]'(?m)^===== GATE FAILED CLOSED =====\s*$'
  # A leading pre-pass fragment (before the first `=====` marker) may contain
  # ONLY the known provenance header lines + blanks. ANY verdict / category
  # / severity / indented-finding line there is malformed evidence -- otherwise a
  # finding could hide in the exempt header while a clean pass follows. (Codex
  # BLOCKER.)
  # REVIEW-DURATION-SECS is validated to its FULL declared shape (one
  # non-negative base-10 integer, no padding - trailing whitespace
  # included) rather than prefix-only: the value is new schema this slice
  # introduces, so a malformed value must classify as malformed evidence
  # instead of reading as trustworthy metadata. The pre-existing header
  # alternatives keep their historical prefix-only acceptance. MIRRORED
  # with analyze-blocker-trends.ps1.
  $headerLineRe = [regex]'^(DIFF-SHA256:|REVIEW-TREE-OID:|REVIEW-BACKEND:|REVIEW-EFFORT:|REVIEW-SEVERITY-CONTRACT:|REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$)'
  $tokens = [regex]::Split($Content, '(?m)(^=====.*=====\s*$)')
  $allBlocksValid = $true
  # Duration metadata is ALSO validated marker-independently over the
  # LEADING identity-header region only (consecutive non-blank lines
  # from the top -- the wrappers always emit a blank line after the
  # header block): the Claude wrapper's markerless artifact never
  # produces a leading fragment for the whitelist, while verdict BODY
  # prose that merely mentions the header name must never classify an
  # artifact malformed. Within the region the CANDIDATE guard is
  # deliberately loose (leading whitespace, whitespace or a missing
  # colon after the name, any case) while the accepted shape is
  # byte-exact -- a mutation the candidate guard cannot see would read
  # as clean free text. At most one stamp may appear (absence is the
  # legacy unstamped shape); duplicates with conflicting values would
  # both read as trustworthy. MIRRORED with analyze-blocker-trends.ps1.
  # Past the separator only an UNINDENTED exact-case stamp-shaped line
  # is header-shaped (a post-separator stamp would otherwise read as
  # trusted body prose); indented or mutated body mentions stay exempt
  # as prose.
  $durStamps = 0
  $durLeading = $true
  foreach ($durLn in ($Content -split "`r?`n")) {
    if ($durLeading -and [string]::IsNullOrWhiteSpace($durLn)) { $durLeading = $false; continue }
    if ($durLeading) {
      if ((ConvertTo-CrgStructureFold -Line $durLn) -cmatch '\A\s*REVIEW-DURATION-SECS\b') {
        if ($durLn -cnotmatch '^REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$') { $allBlocksValid = $false; break }
        $durStamps++
      }
    } elseif ($durLn -cmatch '^REVIEW-DURATION-SECS:') {
      if ($durLn -cnotmatch '^REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$') { $allBlocksValid = $false; break }
      $durStamps++
    }
  }
  if ($durStamps -gt 1) { $allBlocksValid = $false }
  $reviewPassBlockCount = 0
  if ($tokens.Count -eq 1) {
    # No markers: the whole artifact is a single review-pass block. The
    # AND keeps the marker-independent duration verdict: a plain
    # assignment here would clobber it.
    if ($Content.Trim().Length -ne 0) { $reviewPassBlockCount = 1; $allBlocksValid = ($allBlocksValid -and (Test-VerdictBlock -Block $Content)) }
  } else {
    # tokens alternate: [leadingFragment, marker1, seg1, marker2, seg2, ...].
    # Validate the leading fragment: every non-blank line must be a known header
    # line; no verdict/category/severity/indented content may hide there.
    $leadFrag = $tokens[0]
    foreach ($hl in ($leadFrag -split "`r?`n")) {
      if ([string]::IsNullOrWhiteSpace($hl)) { continue }
      if (-not $headerLineRe.IsMatch($hl)) { $allBlocksValid = $false; break }
    }
    $passNums = @{}              # pass number -> seen count
    $passTotals = New-Object 'System.Collections.Generic.HashSet[int]'
    for ($ti = 1; $ti -lt $tokens.Count -and $allBlocksValid; $ti += 2) {
      $marker = $tokens[$ti]
      $seg = if (($ti + 1) -lt $tokens.Count) { $tokens[$ti + 1] } else { '' }
      $pm = $passMarkerRe.Match($marker)
      if ($pm.Success) {
        # REVIEW PASS marker: segment MUST be a valid verdict block.
        if ($seg.Trim().Length -eq 0 -or -not (Test-VerdictBlock -Block $seg)) { $allBlocksValid = $false; break }
        $reviewPassBlockCount++
        # Bounded TryParse on the (untrusted) pass numbers, clamped to the
        # PRODUCER's 1..$ReviewPassMax (=10) range: auto-review.ps1's -ReviewPasses
        # is [ValidateRange(1, 10)] (CROSS_REVIEW_PASSES clamped 1-10), so it can only
        # emit n,N in 1..10. A value outside that range -- or a non-digit / overflow
        # a raw [int] cast would throw on -- is malformed evidence. (Codex BLOCKER:
        # the earlier fix used TryParse but reused the
        # 10000 category ceiling instead of the producer pass range.)
        $n = 0; $tot = 0
        if (-not [int]::TryParse($pm.Groups['n'].Value, [ref]$n) -or $n -lt 1 -or $n -gt $script:ReviewPassMax -or `
            -not [int]::TryParse($pm.Groups['total'].Value, [ref]$tot) -or $tot -lt 1 -or $tot -gt $script:ReviewPassMax) {
          $allBlocksValid = $false; break
        }
        if ($n -gt $tot) { $allBlocksValid = $false; break }   # pass number exceeds total
        if ($passNums.ContainsKey($n)) { $allBlocksValid = $false; break }   # duplicate pass number
        $passNums[$n] = 1
        [void]$passTotals.Add($tot)
      } elseif ($failClosedMarkerRe.IsMatch($marker)) {
        # GATE FAILED CLOSED banner: exempt here ($hasFailClosed forces untrust).
      } else {
        # Any OTHER `=====` marker is malformed evidence.
        $allBlocksValid = $false; break
      }
    }
    if ($allBlocksValid -and $reviewPassBlockCount -gt 0) {
      # Sequence integrity: exactly one agreed total N, and pass numbers == 1..N.
      if ($passTotals.Count -ne 1) {
        $allBlocksValid = $false                                   # mismatched totals
      } else {
        $declaredTotal = @($passTotals)[0]
        if ($passNums.Count -ne $declaredTotal) { $allBlocksValid = $false }   # missing pass(es)
        else {
          for ($p = 1; $p -le $declaredTotal; $p++) {
            if (-not $passNums.ContainsKey($p)) { $allBlocksValid = $false; break }
          }
        }
      }
    }
  }
  # A file with markers but ZERO review-pass blocks (e.g. only a banner) is not
  # trustworthy clean evidence on its own.
  if ($reviewPassBlockCount -eq 0) { $allBlocksValid = $false }

  # Reject a file with a malformed category tail ANYWHERE (e.g. `PLAN-DRIFT: +1`:
  # a tail that is neither `none` nor a valid in-bound digit count). Test-VerdictBlock
  # and the wrapper refuse such a row inside a review-pass block; this whole-file
  # scan also covers text outside any block, because a malformed category line
  # means the artifact is an untrustworthy DATA SOURCE for the dispatch summary
  # (and Get-CategoryFindings could misparse it). $hasInvalidCount must stay part
  # of IsCleanEvidence, or the scan decides nothing.
  $hasInvalidCount = $false
  foreach ($m in ([regex]'(?m)^(?<cat>PLAN-DRIFT|SILENT-FAILURE|TOMBSTONE-OR-SHIM|CROSS-CRATE-CONTRACT|LOADER-OR-ASSET-EDGE|CONVENTION-ADHERENCE|TEST-QUALITY|DOC-VS-CODE-DRIFT):[^\S\r\n]*(?<rest>.*)$').Matches($Content)) {
    if ((Get-CategoryTailKind -Tail $m.Groups['rest'].Value).Kind -eq 'invalid') { $hasInvalidCount = $true; break }
  }

  # Wrapper parity (Get-VerdictExitCode refuses the same lines, as does
  # analyze-blocker-trends.ps1's Get-VerdictSuspectReason): reject a near-miss
  # severity prefix ANYWHERE. A column-0 line like `blocker:` / `Quality:` /
  # `NOTE :` folds to a severity NAME but is NOT the exact
  # `^(BLOCKER|QUALITY|NON-BLOCKER|NOTE):` that $sevRe counts with, so it is
  # INVISIBLE to finding-counting -- a real finding hidden that way would leave a
  # `VERDICT: CLEAN` verdict falsely clean. A line that cannot be normalized
  # cannot be cleared of that and is refused with them.
  $hasWrongCaseSeverity = $false
  for ($i = 0; $i -lt $structureLines.Count; $i++) {
    if ($null -eq $structureFolds[$i]) { $hasWrongCaseSeverity = $true; break }
    $sm = [regex]::Match($structureFolds[$i], '\A(BLOCKER|QUALITY|NON-BLOCKER|NOTE)\s*:')
    if ($sm.Success -and -not $structureLines[$i].StartsWith("$($sm.Groups[1].Value):", [System.StringComparison]::Ordinal)) { $hasWrongCaseSeverity = $true; break }
  }

  $isClean = $hasVerdict -and (-not $hasFailClosed) -and $allCats -and $allBlocksValid -and (-not $hasInvalidCount) -and (-not $hasWrongCaseSeverity)

  return @{
    HasVerdictLine           = $hasVerdict
    HasCompleteCategoryBlock = $allCats
    HasFindingSignal         = ($sevRe.IsMatch($Content) -or @($hasBlockedOrNb).Count -gt 0)
    HasFailClosedBanner      = $hasFailClosed
    HasInvalidCount          = $hasInvalidCount
    HasWrongCaseSeverity     = $hasWrongCaseSeverity
    AllBlocksValid           = $allBlocksValid
    IsCleanEvidence          = $isClean
  }
}

# Parse the category-enumeration findings out of ONE pass block, pairing each
# with the severity it has WITHIN THAT BLOCK. Returns a hashtable keyed by
# normalized text -> @{ Category; Severity; Text; Citation }. The severity map
# is built from THIS BLOCK's severity-prefixed lines only -- see the file-wide
# bug note in Get-CategoryFindings. Citation = the validated path:line (or $null);
# the raw prose is never stored.
function Get-BlockFindings {
  param([string]$Block)
  $catLineRe = [regex]'(?m)^(?<cat>PLAN-DRIFT|SILENT-FAILURE|TOMBSTONE-OR-SHIM|CROSS-CRATE-CONTRACT|LOADER-OR-ASSET-EDGE|CONVENTION-ADHERENCE|TEST-QUALITY|DOC-VS-CODE-DRIFT):[^\S\r\n]*(?<rest>.*)$'
  $sevLineRe = [regex]'(?m)^(?<sev>BLOCKER|QUALITY|NON-BLOCKER|NOTE):\s*(?<text>.*)$'

  # BLOCK-LOCAL normalized-text -> highest-severity map.
  $sevByText = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  foreach ($sm in $sevLineRe.Matches($Block)) {
    $sevText = $sm.Groups['text'].Value.Trim()
    if ([string]::IsNullOrWhiteSpace($sevText)) { continue }
    $k = Get-NormalizedText -Text $sevText
    $sev = $sm.Groups['sev'].Value
    if (-not $sevByText.ContainsKey($k) -or (Get-SeverityRank $sevByText[$k]) -lt (Get-SeverityRank $sev)) {
      $sevByText[$k] = $sev
    }
  }

  $perBlock = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)   # key "<normtext>" -> @{Category;Severity;Text;Citation}
  $activeCat = $null
  $remaining = 0
  foreach ($line in ($Block -split "`r?`n")) {
    $cm = $catLineRe.Match($line)
    if ($cm.Success) {
      $kind = Get-CategoryTailKind -Tail $cm.Groups['rest'].Value
      if ($kind.Kind -eq 'count' -and $kind.Value -gt 0) {
        $activeCat = $cm.Groups['cat'].Value
        $remaining = $kind.Value
      } else {
        $activeCat = $null
        $remaining = 0
      }
      continue
    }
    if ($activeCat -and $remaining -gt 0) {
      if ($line -match '^\s+\S') {
        $text = $line.Trim()
        $norm = Get-NormalizedText -Text $text
        $sev = if ($sevByText.ContainsKey($norm)) { $sevByText[$norm] } else { 'UNKNOWN' }
        # Store ONLY the validated structural citation (path:line) -- the raw
        # finding PROSE never leaves the parser, so it can never reach the worker-
        # prompt paste block. (Codex BLOCKER.) $norm is
        # still dispatch-checklist's own dedupe key (text-alone, analyzer-
        # compatible) but is used only
        # for counting, never emitted.
        $cite = Get-SafeCitation -Text $text
        # Within a single block a text appears under one category once; if a
        # malformed block lists it twice, keep the higher severity / more-
        # specific category (same tiebreak as the cross-block merge).
        if (-not $perBlock.ContainsKey($norm)) {
          $perBlock[$norm] = @{ Category = $activeCat; Severity = $sev; Text = $norm; Citation = $cite }
        } else {
          $prev = $perBlock[$norm]
          if ((Get-SeverityRank $sev) -gt (Get-SeverityRank $prev.Severity)) {
            $perBlock[$norm] = @{ Category = $activeCat; Severity = $sev; Text = $norm; Citation = $cite }
          }
        }
        $remaining--
      } elseif (-not [string]::IsNullOrWhiteSpace($line)) {
        $activeCat = $null
        $remaining = 0
      }
    }
  }
  return $perBlock
}

function Get-CategoryFindings {
  param([string]$Content)

  # DEDUPE KEY = normalized TEXT ALONE (NOT category+text), mirroring
  # analyze-blocker-trends.ps1's own per-file dedupe (same key, keep highest
  # severity); dispatch-checklist layers the eight-category tiebreak on top: one
  # issue repeated across passes counts ONCE at the highest severity, even when two
  # passes file it under DIFFERENT
  # categories. When the severities tie across differing categories, the
  # most-specific category (lowest CatOrderRank) wins.
  #
  # CRITICAL (Codex BLOCKER): severity MUST be associated
  # with category rows WITHIN EACH PASS BLOCK, not via one file-wide text->max
  # map. A file-wide map gives EVERY occurrence of a text the highest severity
  # seen ANYWHERE in the file, so when pass 1 files a text under CROSS-CRATE-
  # CONTRACT (QUALITY) and pass 2 files it under DOC-VS-CODE-DRIFT (BLOCKER),
  # BOTH inherit BLOCKER -> a severity TIE -> the most-specific-category tiebreak
  # keeps the WRONG (lower-actual-severity) category. Processing block-by-block
  # (Get-BlockFindings builds a block-local severity map) means each occurrence
  # carries the severity it actually had in its pass, so the category that truly
  # had the higher severity wins the cross-block merge below.
  #
  # Split into pass blocks the same way Get-VerdictStructure does (on `=====`
  # markers). A single-pass artifact (no markers) is one block -- identical
  # result to the old code, so real single-pass verdicts are unaffected.
  $segments = [regex]::Split($Content, '(?m)^=====.*=====\s*$')

  $perFile = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)   # key "<normtext>" -> @{Category;Severity;Text;Citation}
  foreach ($seg in $segments) {
    if ([string]::IsNullOrWhiteSpace($seg)) { continue }
    foreach ($entry in (Get-BlockFindings -Block $seg).Values) {
      $norm = $entry.Text
      if (-not $perFile.ContainsKey($norm)) {
        $perFile[$norm] = $entry
      } else {
        $prev = $perFile[$norm]
        $prevRank = Get-SeverityRank $prev.Severity
        $thisRank = Get-SeverityRank $entry.Severity
        $take = $false
        if ($thisRank -gt $prevRank) {
          $take = $true                                  # higher actual severity wins
        } elseif ($thisRank -eq $prevRank) {
          # Genuine severity tie (same severity in both passes): most-specific
          # category (lowest rank) wins -- deterministic.
          $prevCatRank = if ($script:CatOrderRank.ContainsKey($prev.Category)) { $script:CatOrderRank[$prev.Category] } else { 999 }
          $thisCatRank = if ($script:CatOrderRank.ContainsKey($entry.Category)) { $script:CatOrderRank[$entry.Category] } else { 999 }
          if ($thisCatRank -lt $prevCatRank) { $take = $true }
        }
        if ($take) { $perFile[$norm] = $entry }
      }
    }
  }

  return $perFile.Values
}


# ---------------------------------------------------------------------------
# Resolve + validate the reviews directory (hard fail on bad input).
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ReviewsDir -PathType Container)) {
  Write-Host "[dispatch-checklist] ERROR: reviews directory not found: $ReviewsDir"
  exit 1
}
try {
  $reviewsDirAbs = (Resolve-Path -LiteralPath $ReviewsDir).Path
} catch {
  Write-Host "[dispatch-checklist] ERROR: reviews directory not resolvable: $ReviewsDir : $_"
  exit 1
}

# Verdict filename shape -- IDENTICAL to analyze-blocker-trends.ps1's
# $verdictNameRe. auto-review.ps1 composes `review-<YYYYMMDD>-<HHMMSS>-<scope>.md`;
# filtering by this shape (not bare *.md) excludes prompt-template examples and
# other stray markdown that would otherwise masquerade as verdicts.
$verdictNameRe = [regex]'^review-[0-9]{8}-[0-9]{6}-.+\.md$'
# Compute the mtime cutoff. $SinceDays is a nonnegative int by parameter
# binding, but `(Get-Date).AddDays(-$SinceDays)` THROWS an ArgumentOutOfRange
# DateTime exception for values large enough to underflow DateTime.MinValue
# (before the documented stable [dispatch-checklist] ERROR exit paths). Clamp:
# if subtracting $SinceDays would go below DateTime.MinValue, use MinValue (the
# whole history is then in scope -- the same effect as -SinceDays 0). (Codex
# QUALITY.)
$nowForCutoff = Get-Date
$maxSafeDays = ($nowForCutoff - [DateTime]::MinValue).TotalDays
# $cutoffIsFullHistory records whether the window is effectively full-history
# (either -SinceDays <= 0, or a value large enough that subtracting it would
# underflow DateTime -> clamped to MinValue). $windowNote uses this so the
# emitted Source/Methodology lines say "full history" rather than the literal
# "last <huge> days" when clamped. (Codex/Claude DOC-VS-CODE.)
$cutoffIsFullHistory = ($SinceDays -le 0) -or ($SinceDays -ge $maxSafeDays)
$cutoff = if ($cutoffIsFullHistory) {
  [DateTime]::MinValue
} else {
  $nowForCutoff.AddDays(-$SinceDays)
}

try {
  $reviewFiles = @(Get-ChildItem -LiteralPath $reviewsDirAbs -Filter '*.md' -File -ErrorAction Stop |
    Where-Object { $verdictNameRe.IsMatch($_.Name) -and $_.LastWriteTime -ge $cutoff })
} catch {
  Write-Host "[dispatch-checklist] ERROR: failed to enumerate reviews directory $reviewsDirAbs : $_"
  exit 1
}

# ---------------------------------------------------------------------------
# Resolve the output path. Directory creation is deliberately DEFERRED into
# Write-Artifact (the success path): the AGENTS.md row promises that the
# exit-1 evidence-rejection paths "write nothing", and an eagerly-created
# output directory would be a filesystem side effect on those paths (a bad
# input window would leave a fresh output directory behind). (Codex QUALITY.)
# ---------------------------------------------------------------------------
$outAbs = if ([System.IO.Path]::IsPathRooted($OutPath)) {
  $OutPath
} else {
  Join-Path (Get-Location) $OutPath
}

function Write-Artifact {
  param([string]$Body)
  # ATOMIC write to honor the documented preservation guarantee: a writer
  # failure must leave ANY prior dispatch-checklist artifact untouched
  # (the AGENTS.md row + this script's header promise exit-1 paths preserve the
  # previous artifact). A direct WriteAllText to the final path truncates/creates
  # it FIRST, so a failure mid-write would leave a partial file. Instead: write
  # the full body to a sibling temp file in the SAME directory (same volume ->
  # the final move is atomic), then swap it onto $outAbs only AFTER the write
  # fully succeeds. On ANY failure, delete the temp and leave the prior artifact
  # intact, then fail loud. (Codex QUALITY.)
  $tmp = $null
  try {
    $dir = Split-Path -Parent -Path $outAbs
    $leaf = Split-Path -Leaf -Path $outAbs
    # Ensure the output directory HERE (success path only): exit-1
    # evidence-rejection paths never reach Write-Artifact, so they leave no
    # directory behind (the AGENTS.md "write nothing" contract; E15c pins it).
    # A creation failure flows into the catch below -- fail loud, prior
    # artifact (if any) untouched.
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    # A GUID-suffixed sibling so concurrent runs cannot collide on the temp name.
    $tmp = Join-Path $dir (".${leaf}.tmp-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
    [System.IO.File]::WriteAllText($tmp, $Body, $utf8NoBom)
    # Atomic same-volume swap via MoveFileEx (REPLACE_EXISTING | WRITE_THROUGH =
    # 0x9). The prior artifact is untouched until this single call replaces it
    # with the fully-written temp; on failure (e.g. ReadOnly destination)
    # MoveFileEx returns $false WITHOUT touching the prior file, and we fall
    # through to the catch/cleanup below. Resolve both to full paths first
    # (MoveFileEx wants absolute paths).
    $tmpFull = [System.IO.Path]::GetFullPath($tmp)
    $outFull = [System.IO.Path]::GetFullPath($outAbs)
    $moved = [DispatchChecklist.NativeV1]::MoveFileEx($tmpFull, $outFull, 0x9)
    if (-not $moved) {
      $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw "MoveFileEx failed (Win32 error $err) replacing '$outFull'"
    }
    $tmp = $null   # consumed by the move; nothing left to clean up
  } catch {
    Write-Host "[dispatch-checklist] ERROR: failed to write artifact to $outAbs : $_"
    if ($tmp -and (Test-Path -LiteralPath $tmp)) {
      Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
    exit 1
  }
}

function Write-ExcludedFailClosedSection {
  # Append the LOUD excluded-fail-closed section to $Sb. Lists the excluded count,
  # each filename, and each file's own banner reason line, so the exclusion is
  # visible in the WRITTEN artifact (the console notice is the other channel);
  # never a silent drop. No-op when nothing was excluded, so the truly-empty
  # window (zero scanned files, hence zero exclusions) simply does not call it.
  # Sorted by filename for deterministic output (reruns diff cleanly). The reason
  # is the wrapper's own single-line diagnostic (control text
  # authored by auto-review.ps1, NOT model finding prose), so no
  # Get-SafeCitation structural-only stripping is needed here; the section
  # also sits OUTSIDE the recurring-classes block, keeping that block
  # structural-fields-only.
  param(
    [System.Text.StringBuilder]$Sb,
    [System.Collections.Generic.List[object]]$Excluded
  )
  if ($Excluded.Count -eq 0) { return }
  [void]$Sb.AppendLine("## Excluded fail-closed runs ($($Excluded.Count))")
  [void]$Sb.AppendLine('')
  [void]$Sb.AppendLine("> $($Excluded.Count) verdict-shaped file(s) in this window carried the wrapper's own")
  [void]$Sb.AppendLine('> `===== GATE FAILED CLOSED =====` banner -- a SELF-DECLARED failed gate run that')
  [void]$Sb.AppendLine('> produced no trustworthy complete-run outcome (typically a transient reviewer-')
  [void]$Sb.AppendLine('> environment failure, normally retried successfully). Each is EXCLUDED from the')
  [void]$Sb.AppendLine('> category tally; excluding them loudly summarizes the window honestly. This is')
  [void]$Sb.AppendLine('> NOT a silent drop and NOT evidence of a clean codebase for those runs.')
  [void]$Sb.AppendLine('')
  # Ordinal file-name order: culture sorts ignore characters such as U+00AD.
  # An index array is sorted with the names: Windows PowerShell passes an
  # object[] items array to [Array]::Sort as a converted copy, so the items
  # themselves would stay unsorted.
  $excludedItems = $Excluded.ToArray()
  [string[]]$excludedNames = @($excludedItems | ForEach-Object { [string]$_.Name })
  [int[]]$excludedIndex = if ($excludedItems.Length -gt 0) { 0..($excludedItems.Length - 1) } else { @() }
  [Array]::Sort($excludedNames, $excludedIndex, [System.StringComparer]::Ordinal)
  foreach ($ex in @($excludedIndex | ForEach-Object { $excludedItems[$_] })) {
    [void]$Sb.AppendLine("- ``$($ex.Name)`` -- $($ex.Reason)")
  }
  [void]$Sb.AppendLine('')
}

$timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
# Describe the ACTUAL window: "full history" whenever the cutoff was clamped to
# MinValue (incl. a clamped huge -SinceDays), else the literal day count.
$windowNote = if ($cutoffIsFullHistory) { 'full history (no mtime cutoff)' } else { "last $SinceDays days" }

# ---------------------------------------------------------------------------
# Empty window: write the artifact WITH a loud banner, then exit 0. NOT silent
# success-on-empty -- an empty window is explicitly NOT evidence of a clean
# codebase, and the dispatcher must see that.
# ---------------------------------------------------------------------------
if ($reviewFiles.Count -eq 0) {
  $eb = [System.Text.StringBuilder]::new()
  [void]$eb.AppendLine('# Worker dispatch checklist -- recurring gate-finding classes')
  [void]$eb.AppendLine('')
  [void]$eb.AppendLine('PASTE BLOCK for worker dispatch prompts (see AGENTS.md): structural fields and')
  [void]$eb.AppendLine('validated file:line citations only -- never finding prose (untrusted agent output).')
  [void]$eb.AppendLine('')
  [void]$eb.AppendLine("Generated: $timestamp")
  [void]$eb.AppendLine("Source: verdicts under ``$ReviewsDir`` within $windowNote (matched 0)")
  [void]$eb.AppendLine('')
  # Emit the paste-block markers even in the empty case so a dispatcher who
  # always pastes the `<!-- BEGIN ... -->` section gets the explanatory banner
  # (not nothing) -- the workflow AGENTS.md documents is uniform across all
  # outputs, and readers key on the markers. (Codex QUALITY.)
  [void]$eb.AppendLine('<!-- BEGIN dispatch-checklist paste block -->')
  [void]$eb.AppendLine('')
  [void]$eb.AppendLine('> NO VERDICTS IN WINDOW.')
  [void]$eb.AppendLine('> Checklist empty -- this is NOT evidence of zero defect classes. Either no')
  [void]$eb.AppendLine('> review verdicts landed in this window, or the window is too narrow. Widen')
  [void]$eb.AppendLine('> with `-SinceDays <N>` (or `-SinceDays 0` for full history) before treating')
  [void]$eb.AppendLine('> this as "no recurring classes to watch."')
  [void]$eb.AppendLine('')
  [void]$eb.AppendLine('<!-- END dispatch-checklist paste block -->')
  [void]$eb.AppendLine('')
  Write-Artifact -Body $eb.ToString()
  Write-Host "[dispatch-checklist] no verdict-shaped .md files in $reviewsDirAbs within $windowNote."
  Write-Host "[dispatch-checklist]   wrote empty-window artifact (loud banner) to $outAbs"
  exit 0
}

# ---------------------------------------------------------------------------
# Parse every verdict in the window. The recurring-class axis is the CATEGORY,
# not the individual finding text.
#
# WHY category, not finding text (load-bearing design decision, evidenced):
# every Codex finding line carries a `<file:line> - <phrase>` head whose line
# numbers and milestone tags DRIFT between reviews, so two reviews of the same
# underlying defect almost never produce byte-identical normalized text. A
# measurement over the live window found effectively ALL distinct
# finding texts appearing in exactly ONE file (exact-text cross-file recurrence
# was essentially absent). Ranking individual texts by occurrence would therefore
# surface an arbitrary all-singletons slice, defeating the checklist's purpose (the
# global `~/.claude/CLAUDE.md` repeated-class discipline's "a class flagged 2+
# times across rounds"). The CATEGORY is the durable
# recurring-class signal: DOC-VS-CODE-DRIFT raised across hundreds of findings
# IS the class a dispatcher must warn against. This mirrors
# analyze-blocker-trends.ps1, which ranks by ARCHETYPE cluster, not by text.
#
# Two dedupe layers, do not conflate them:
#   - WITHIN a file: Get-CategoryFindings dedupes by normalized TEXT ALONE
#     (highest severity, most-specific category on a tie), so one issue across
#     passes counts once even if filed under different categories.
#   - ACROSS files (here): the per-category exemplar map is keyed by
#     (category, normalized-text) so the SAME text surfacing in two separate
#     reviews collapses to one exemplar per category (FileCount tracks how many
#     files), keeping the most-recent cite phrasing. The category OCCURRENCE
#     count is a FILE-LEVEL tally -- incremented once per parsed finding per
#     file -- so a text raised in two files adds 2; it is NOT the distinct-text
#     count (that is $Exemplars.Count).
# ---------------------------------------------------------------------------
$catRank = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
for ($i = 0; $i -lt $categoryOrder.Count; $i++) { $catRank[$categoryOrder[$i]] = $i }

# catAgg: category -> @{ Category; Occurrences; Exemplars = @{ normtext -> entry } }
#   Occurrences = FILE-LEVEL occurrence count: incremented once per category
#     finding parsed PER FILE (each file's findings are already text-deduped by
#     Get-CategoryFindings, so a file contributes at most once per text, but the
#     SAME text in two files counts twice here). This is "how often the gate
#     raised this category in the window", which is the ranking signal -- NOT a
#     distinct-text count (that is $Exemplars.Count).
#   Exemplars[normtext] = @{ Citation; NewestDate; Severity; FileCount }
#     keyed by distinct text; Citation = validated path:line (or $null); FileCount
#     = how many separate files raised it. NO finding prose is stored.
$catAgg = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
$oldestMtime = [DateTime]::MaxValue
$newestMtime = [DateTime]::MinValue
$totalFindings = 0
# Structure tallies (see Get-VerdictStructure + Get-FailClosedBannerReason). The
# distinct untrustworthy classes, handled differently:
#   $excludedFailClosed -- files carrying the wrapper's own GATE FAILED CLOSED
#     banner (a SELF-DECLARED failed gate run). EXCLUDED from the tally and
#     reported LOUDLY (console + a dedicated artifact section); they do NOT abort
#     the run. Excluding-loud (vs refusing) keeps one transient reviewer-
#     environment failure from starving the dispatcher of a checklist. Each entry
#     is @{ Name; Reason } (Reason = the banner's own diagnostic line).
#   $suspectFiles -- files that fail the structure contract and are NOT a recognized
#     producer-shaped fail-closed run (UNEXPLAINED corruption: incomplete block,
#     out-of-bound count, row imbalance, incoherent verdict, unknown marker, ... --
#     bannerless, OR a banner with an invalid header/diagnostic/suffix/framing). A
#     non-empty list makes the run FAIL LOUD (exit 1, no artifact) regardless of how
#     many valid findings the other files produced -- unrecognized-malformed corruption
#     is not a self-declared failure and cannot be trusted or silently dropped. This
#     check fires BEFORE any report branch.
# $trustworthyCount counts files that passed BOTH gates and were tallied, so the
# report paths can tell a genuinely-clean window (some trustworthy, zero findings)
# from an only-fail-closed window (zero trustworthy, all excluded).
$excludedFailClosed = New-Object 'System.Collections.Generic.List[object]'
$suspectFiles = New-Object 'System.Collections.Generic.List[string]'
$trustworthyCount = 0
# GLOBAL normalized-text -> set of file names that raised it (ACROSS categories),
# for the cross-file-repeat statistic. Keyed by text ALONE so the same text filed
# under two categories in two files counts as a cross-file repeat (the per-
# category exemplar map would split it into two FileCount=1 entries and
# under-report). (Codex QUALITY.)
$globalTextFiles = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)

foreach ($file in $reviewFiles) {
  # Read the raw BYTES and strict-decode (no-BOM, throw-on-invalid) via
  # Read-VerdictArtifactText so the fail-closed recognizer sees byte 0: a
  # preamble-stripping [System.IO.File]::ReadAllText(..., UTF8) silently consumes a
  # BOM and would let a non-producer-encoded file reach the EXCLUDE path. A BOM /
  # invalid-UTF-8 reject is malformed evidence -- it FAILS LOUD via the suspect
  # abort below, never the fail-closed exclude. (Reading bytes also avoids the
  # Get-Content -Raw WinPS 5.1 ANSI-codepage em-dash mojibake.)
  $decoded = Read-VerdictArtifactText -Path $file.FullName
  if (-not $decoded.Ok) {
    $suspectFiles.Add($file.Name) | Out-Null
    continue
  }
  $content = $decoded.Text

  # (1) FAIL-CLOSED self-declaration: a RECOGNIZED producer-shaped fail-closed run
  # (Get-FailClosedBannerReason validates the WHOLE producer self-declaration over the
  # strict-decoded bytes -- header + banner + diagnostic + first-suffix/terminal framing
  # -- not the banner alone). EXCLUDE from the tally and record for LOUD reporting -- a
  # fail-closed run produced no trustworthy complete-run outcome, but excluding it (vs
  # refusing the whole window) keeps one transient reviewer-environment failure from
  # starving the checklist. Its successful-pass findings are NOT tallied: the file as a
  # whole is untrustworthy. Checked FIRST so a RECOGNIZED fail-closed run is excluded
  # here; a banner file that FAILS recognition falls through to the refusal below.
  $fcReason = Get-FailClosedBannerReason -Content $content
  if ($null -ne $fcReason) {
    # Producer identity is the artifact's own validated header (the
    # recognizer pins the wrapper's exact emission), never the directory the
    # file sits in -- a directory name is caller spelling, not provenance.
    $excludedFailClosed.Add(@{ Name = $file.Name; Reason = $fcReason }) | Out-Null
    continue
  }

  # (2) UNEXPLAINED corruption: a file that fails the structure contract and is NOT a
  # recognized producer-shaped fail-closed run (either bannerless, OR carrying the
  # banner but with an invalid header/diagnostic/suffix/framing that
  # Get-FailClosedBannerReason above rejected) is untrustworthy evidence of unknown
  # cause (missing/incomplete block, CLEAN-verdict-without-block, invalid count, row
  # imbalance, incoherent verdict, unknown marker). It cannot be summarized or silently
  # dropped, so it FAILS LOUD (exit 1, no artifact) below -- regardless of how many
  # valid findings other files produced.
  $struct = Get-VerdictStructure -Content $content
  if (-not $struct.IsCleanEvidence) {
    $suspectFiles.Add($file.Name) | Out-Null
    continue
  }

  # (3) TRUSTWORTHY evidence: tally it. The date range reflects tallied files
  # only (excluded/suspect files are reported/refused separately, not summarized).
  $trustworthyCount++
  if ($file.LastWriteTime -lt $oldestMtime) { $oldestMtime = $file.LastWriteTime }
  if ($file.LastWriteTime -gt $newestMtime) { $newestMtime = $file.LastWriteTime }

  foreach ($ff in (Get-CategoryFindings -Content $content)) {
    $totalFindings++
    # Global text->files map (text alone, across categories) for the cross-file
    # statistic.
    if (-not $globalTextFiles.ContainsKey($ff.Text)) {
      $globalTextFiles[$ff.Text] = New-Object 'System.Collections.Generic.HashSet[string]'
    }
    [void]$globalTextFiles[$ff.Text].Add($file.Name)
    if (-not $catAgg.ContainsKey($ff.Category)) {
      $catAgg[$ff.Category] = @{
        Category    = $ff.Category
        Occurrences = 0
        Exemplars   = (New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal))
      }
    }
    $ca = $catAgg[$ff.Category]
    $ca.Occurrences++
    $ex = $ca.Exemplars
    if (-not $ex.ContainsKey($ff.Text)) {
      $ex[$ff.Text] = @{
        Citation   = $ff.Citation
        NewestDate = $file.LastWriteTime
        Severity   = $ff.Severity
        FileCount  = 1
      }
    } else {
      $e = $ex[$ff.Text]
      $e.FileCount++
      if ($file.LastWriteTime -gt $e.NewestDate) {
        # Keep the MOST RECENT occurrence's citation + severity so the exemplar
        # shows the freshest where-to-look pointer for a recurring finding.
        $e.NewestDate = $file.LastWriteTime
        $e.Citation = $ff.Citation
        $e.Severity = $ff.Severity
      }
    }
  }
}

$dateRange = "{0:yyyy-MM-dd} to {1:yyyy-MM-dd}" -f $oldestMtime, $newestMtime

# ---------------------------------------------------------------------------
# LOUD console notice for EXCLUDED fail-closed runs (self-declared GATE FAILED
# CLOSED banners) -- emitted BEFORE the bannerless-malformed abort below, so a
# MIXED window (a fail-closed file AND a bannerless-malformed file) still NAMES
# the excluded fail-closed runs even though the run then aborts on the bannerless
# file. (An abort before this notice silently lost the recognized
# fail-closed runs.) On the exit-0 paths the excluded set is ALSO written into the
# artifact's dedicated section (Write-ExcludedFailClosedSection), so the exclusion
# is visible in BOTH channels, never a silent drop.
# ---------------------------------------------------------------------------
if ($excludedFailClosed.Count -gt 0) {
  Write-Host "[dispatch-checklist] EXCLUDED $($excludedFailClosed.Count) fail-closed run(s) from the tally (self-declared GATE FAILED CLOSED -- a failed gate run with no trustworthy complete-run outcome, typically a transient reviewer-environment failure):"
  foreach ($ex in $excludedFailClosed) {
    Write-Host "[dispatch-checklist]   - $($ex.Name) -- $($ex.Reason)"
  }
}

# ---------------------------------------------------------------------------
# FAIL LOUD on ANY UNRECOGNIZED-malformed evidence -- BEFORE any report branch, and
# REGARDLESS of how many valid findings other files produced.
#
# This class is UNEXPLAINED corruption: a file that fails the structure contract and
# is NOT a recognized fail-closed run -- EITHER bannerless, OR bannered but rejected
# by the recognizer (a missing/incomplete eight-category block including a pre-rewrite
# `VERDICT: CLEAN` with no block, an out-of-bound/non-numeric category count, a row
# imbalance, an incoherent verdict, an unknown marker, or a BOM / invalid-UTF-8
# encoding). It is not a self-declared failure, so its review outcome cannot be
# trusted and the WINDOW cannot be summarized honestly -- the checklist would
# silently drop it. Exit 1 without writing the artifact. Only a RECOGNIZED
# producer-shaped fail-closed run is handled separately ($excludedFailClosed) --
# EXCLUDED loudly (named above), not refused.
# (Codex BLOCKERs: the refusal used to live only inside the zero-findings
# branch, so a window with one malformed verdict plus one valid finding
# produced a successful checklist.)
# ---------------------------------------------------------------------------
if ($suspectFiles.Count -gt 0) {
  $sample = @($suspectFiles | Select-Object -First 5)
  Write-Host "[dispatch-checklist] ERROR: scanned $($reviewFiles.Count) verdict-shaped file(s) in $reviewsDirAbs but $($suspectFiles.Count) is/are UNRECOGNIZED-malformed (fail the structure contract and are not a recognized fail-closed run: no complete eight-category block, an out-of-bound category count, a row imbalance, an incoherent verdict, a byte-order mark or invalid UTF-8 encoding, or a GATE FAILED CLOSED banner that does not match the wrapper's exact emission)."
  Write-Host "[dispatch-checklist]        Such files are untrustworthy review evidence of unknown cause -- summarizing the window would silently drop them. This is NOT a clean codebase."
  Write-Host "[dispatch-checklist]        Refusing to write '$outAbs'."
  Write-Host "[dispatch-checklist]        Example malformed file(s): $($sample -join ', ')"
  exit 1
}

# ---------------------------------------------------------------------------
# Zero category findings extracted (bannerless-malformed files already aborted
# above). Two sub-cases, distinguished by $trustworthyCount:
#   trustworthyCount > 0 -> GENUINELY CLEAN: every TRUSTWORTHY scanned verdict
#     carried a complete eight-category block that yielded zero findings (each category
#     `none` OR a `0` count -- Test-VerdictBlock accepts both, so catAgg stays empty).
#     Any fail-closed files were excluded and are listed in the excluded section. A
#     real "no recurring classes" outcome.
#   trustworthyCount == 0 -> ONLY FAIL-CLOSED: every verdict-shaped file in the
#     window was fail-closed and excluded, so there is nothing trustworthy to
#     summarize. Use the loud empty-window banner style PLUS the excluded section
#     (an all-fail-closed window still writes an artifact, exit 0, not a refusal).
# Either way, write loudly so it is never mistaken for the script silently doing
# nothing, and append the excluded section so exclusions stay visible.
# ---------------------------------------------------------------------------
if ($catAgg.Count -eq 0) {
  $cb = [System.Text.StringBuilder]::new()
  [void]$cb.AppendLine('# Worker dispatch checklist -- recurring gate-finding classes')
  [void]$cb.AppendLine('')
  [void]$cb.AppendLine('PASTE BLOCK for worker dispatch prompts (see AGENTS.md): structural fields and')
  [void]$cb.AppendLine('validated file:line citations only -- never finding prose (untrusted agent output).')
  [void]$cb.AppendLine('')
  [void]$cb.AppendLine("Generated: $timestamp")
  [void]$cb.AppendLine("Source: $($reviewFiles.Count) verdict files in ``$ReviewsDir`` within $windowNote")
  if ($trustworthyCount -gt 0) {
    [void]$cb.AppendLine("Date range (tallied file mtime): $dateRange")
    [void]$cb.AppendLine('')
    [void]$cb.AppendLine('<!-- BEGIN dispatch-checklist paste block -->')
    [void]$cb.AppendLine('')
    [void]$cb.AppendLine('> All trustworthy scanned verdicts carried complete category blocks and were CLEAN')
    [void]$cb.AppendLine('> (zero category findings in window). No recurring defect classes to surface this')
    [void]$cb.AppendLine('> window. This reflects the scanned reviews only -- widen with `-SinceDays <N>`')
    [void]$cb.AppendLine('> for a longer arc.')
    [void]$cb.AppendLine('')
    [void]$cb.AppendLine('<!-- END dispatch-checklist paste block -->')
    [void]$cb.AppendLine('')
  } else {
    [void]$cb.AppendLine('')
    [void]$cb.AppendLine('<!-- BEGIN dispatch-checklist paste block -->')
    [void]$cb.AppendLine('')
    [void]$cb.AppendLine('> NO TRUSTWORTHY VERDICTS IN WINDOW.')
    [void]$cb.AppendLine("> All $($reviewFiles.Count) verdict-shaped file(s) in this window were fail-closed and")
    [void]$cb.AppendLine('> excluded. Checklist empty -- this is NOT evidence of zero defect classes, and NOT')
    [void]$cb.AppendLine('> evidence of a clean codebase. Re-run after the fail-closed runs are retried, or')
    [void]$cb.AppendLine('> widen with `-SinceDays <N>`.')
    [void]$cb.AppendLine('')
    [void]$cb.AppendLine('<!-- END dispatch-checklist paste block -->')
    [void]$cb.AppendLine('')
  }
  Write-ExcludedFailClosedSection -Sb $cb -Excluded $excludedFailClosed
  Write-Artifact -Body $cb.ToString()
  if ($trustworthyCount -gt 0) {
    Write-Host "[dispatch-checklist] scanned $($reviewFiles.Count) verdict-shaped file(s); $trustworthyCount trustworthy, all with complete clean category blocks (0 findings); $($excludedFailClosed.Count) excluded fail-closed."
  } else {
    Write-Host "[dispatch-checklist] scanned $($reviewFiles.Count) verdict-shaped file(s); ALL were fail-closed and excluded (0 trustworthy verdicts)."
  }
  Write-Host "[dispatch-checklist]   wrote artifact to $outAbs"
  exit 0
}

# ---------------------------------------------------------------------------
# Rank categories by occurrence count desc, then category order (most-specific
# first) for ties. Deterministic so reruns diff cleanly.
# ---------------------------------------------------------------------------
$rankedCats = @($catAgg.Values | Sort-Object `
  @{ Expression = { $_.Occurrences }; Descending = $true }, `
  @{ Expression = { if ($catRank.ContainsKey($_.Category)) { $catRank[$_.Category] } else { 999 } }; Descending = $false })

# Re-derive the cross-file-repeat statistic from THIS window (NOT a hard-coded
# historical number) so the methodology claim is always true for the actual
# input. Computed from the GLOBAL text->files map (text alone, across
# categories), so a text raised under two DIFFERENT categories in two files
# correctly counts as a cross-file repeat. (Codex QUALITY: hard-coded
# zero-repeat count; per-category exemplars under-reported cross-category
# repeats -- use the global map.)
$distinctTextTotal = $globalTextFiles.Count
$crossFileRepeatTexts = @($globalTextFiles.Values | Where-Object { $_.Count -gt 1 }).Count

# ---------------------------------------------------------------------------
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('# Worker dispatch checklist -- recurring gate-finding classes')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("Generated: $timestamp")
[void]$sb.AppendLine("Source: $($reviewFiles.Count) verdict files in ``$ReviewsDir`` within $windowNote")
[void]$sb.AppendLine("Date range (tallied file mtime): $dateRange")
[void]$sb.AppendLine("Recurring categories with findings: $($catAgg.Count) of 8 (up to $Top recent exemplars each)")
[void]$sb.AppendLine('')
# LOUD excluded-fail-closed section (no-op when none): sits ABOVE the recurring-classes section
# so the dispatcher sees the excluded runs before the checklist, and so any forged
# marker in a reason line cannot corrupt the (later) section.
Write-ExcludedFailClosedSection -Sb $sb -Excluded $excludedFailClosed
[void]$sb.AppendLine('## How to use')
[void]$sb.AppendLine('')
# The same usage banner every artifact shape carries (empty window,
# clean window, only-fail-closed window, populated window): readers key on the
# banner, so the artifact shape stays uniform across all outputs.
[void]$sb.AppendLine('PASTE BLOCK for worker dispatch prompts (see AGENTS.md): structural fields and')
[void]$sb.AppendLine('validated file:line citations only -- never finding prose (untrusted agent output).')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Paste the block below into a worker dispatch prompt. Each bullet is a')
[void]$sb.AppendLine('reviewer-category defect class the review gate raised in the window; the')
[void]$sb.AppendLine('per-bullet "N finding(s)" is how often (focus on the higher-count classes,')
[void]$sb.AppendLine('which dominate -- a count of 1 is a single recent instance, not a trend).')
[void]$sb.AppendLine('Calling these out preemptively (per the global ~/.claude/CLAUDE.md')
[void]$sb.AppendLine('repeated-class discipline and the AGENTS.md Author Pre-Commit Self-Sweep')
[void]$sb.AppendLine('item 4) lets the')
[void]$sb.AppendLine('worker catch them before the gate does. Each nested entry shows a recent')
[void]$sb.AppendLine('validated file:line citation when one is present (WHERE to look), otherwise an')
[void]$sb.AppendLine('explicit no-citation marker -- never finding prose, which is untrusted agent')
[void]$sb.AppendLine('output and is deliberately omitted from this prompt block.')
[void]$sb.AppendLine('Finding texts drift file:line by file:line, so the CATEGORY, not the exact')
[void]$sb.AppendLine('text, is the durable recurring signal. This')
[void]$sb.AppendLine('artifact is gitignored execution-state, NOT a tracked doc; regenerate it')
[void]$sb.AppendLine('before each dispatch wave.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('<!-- BEGIN dispatch-checklist paste block -->')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Recurring gate-finding classes to preemptively self-check (most frequent first):')
[void]$sb.AppendLine('')
foreach ($cat in $rankedCats) {
  $surface = if ($categorySurface.ContainsKey($cat.Category)) { $categorySurface[$cat.Category] } else { 'the relevant surface' }
  $distinct = $cat.Exemplars.Count
  [void]$sb.AppendLine("- **[$($cat.Category)]** $($cat.Occurrences) finding(s) ($distinct distinct text(s)) in window. When touching $surface, preemptively check this class.")
  # Exemplars: most-recent first, then text asc for stable ties. Take -Top.
  # The text tiebreak is an ordinal rank: Sort-Object compares strings by culture.
  [string[]]$exTexts = @($cat.Exemplars.Keys | ForEach-Object { [string]$_ })
  [Array]::Sort($exTexts, [System.StringComparer]::Ordinal)
  $exTextRank = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  for ($xi = 0; $xi -lt $exTexts.Length; $xi++) { $exTextRank[$exTexts[$xi]] = $xi }
  $exemplars = @($cat.Exemplars.GetEnumerator() | Sort-Object `
    @{ Expression = { $_.Value.NewestDate }; Descending = $true }, `
    @{ Expression = { $exTextRank[$_.Key] }; Descending = $false } | Select-Object -First $Top)
  foreach ($ex in $exemplars) {
    $dateStr = $ex.Value.NewestDate.ToString('yyyy-MM-dd')
    $sevTag = if ($ex.Value.Severity -and -not [string]::Equals([string]$ex.Value.Severity, 'UNKNOWN', [System.StringComparison]::Ordinal)) { $ex.Value.Severity } else { 'finding' }
    $seenNote = if ($ex.Value.FileCount -gt 1) { ", seen $($ex.Value.FileCount)x" } else { '' }
    # Emit ONLY structural fields: date, severity, seen-count, and -- when present
    # and matching the strict shape -- the validated path:line citation; a
    # citation-less or non-conforming row gets an explicit no-citation marker
    # instead. NO agent-authored finding prose ever reaches this worker-prompt
    # paste block. (Codex BLOCKER.)
    $cite = if ($ex.Value.Citation) { "``$($ex.Value.Citation)``" } else { '(no file:line citation)' }
    [void]$sb.AppendLine("  - [$dateStr, $sevTag$seenNote] $cite")
  }
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('<!-- END dispatch-checklist paste block -->')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Per-category breakdown (all eight categories, occurrence count desc)')
[void]$sb.AppendLine('')
# Show all eight in ranked order; categories with zero findings list as 0 so the
# breakdown is a complete inventory (a 0 row is a positive signal, not a gap).
$rankedCatNames = @($rankedCats | ForEach-Object { $_.Category })
$zeroCats = @($categoryOrder | Where-Object { $zeroCand = [string]$_; @($rankedCatNames | Where-Object { [string]::Equals([string]$_, $zeroCand, [System.StringComparison]::Ordinal) }).Count -eq 0 })
foreach ($cat in $rankedCats) {
  [void]$sb.AppendLine("- ``$($cat.Category)``: $($cat.Occurrences) occurrence(s), $($cat.Exemplars.Count) distinct finding text(s)")
}
foreach ($c in $zeroCats) {
  [void]$sb.AppendLine("- ``$c``: 0 occurrence(s), 0 distinct finding text(s)")
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Methodology')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Source: ``*.md`` files under ``' + $ReviewsDir + '`` whose name matches the')
[void]$sb.AppendLine('verdict-shape pattern `review-<YYYYMMDD>-<HHMMSS>-<scope>.md` (the exact')
[void]$sb.AppendLine("prefix ``auto-review.ps1`` emits), with file mtime within $windowNote.")
[void]$sb.AppendLine('Findings are read from each verdict''s per-category enumeration block (the')
[void]$sb.AppendLine('eight reviewer categories the gate parses), deduped within each file by')
[void]$sb.AppendLine('normalized finding text (keeping the highest severity) so a finding that')
[void]$sb.AppendLine('repeats across review passes counts once. The verdict filename-shape guard')
[void]$sb.AppendLine('AND this per-file text dedupe both mirror `scripts/shared/analyze-blocker-trends.ps1`')
[void]$sb.AppendLine('(which dedupes the same way); this generator additionally ranks by the eight')
[void]$sb.AppendLine('reviewer categories to surface distinct recurring exemplars.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('The RECURRING-CLASS axis is the reviewer CATEGORY, not the individual')
[void]$sb.AppendLine('finding text: finding texts carry file:line + milestone tails that drift')
[void]$sb.AppendLine('between reviews, so exact texts almost never repeat verbatim across files')
[void]$sb.AppendLine("(re-derived from THIS window: $crossFileRepeatTexts of $distinctTextTotal distinct finding texts appeared in more than one file). Categories are")
[void]$sb.AppendLine('ranked by total occurrence count (desc), then category order (most-specific')
[void]$sb.AppendLine('first); the entries under a category are distinct findings, most-recent')
[void]$sb.AppendLine('first -- deterministic so reruns diff cleanly. Each shows a validated')
[void]$sb.AppendLine('path:line citation when present, otherwise an explicit no-citation marker;')
[void]$sb.AppendLine('finding prose is never written to the paste block.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Codex-backend verdicts (`logs/codex/reviews`) by default; pass')
[void]$sb.AppendLine('`-ReviewsDir <dir>` to point at one different directory instead (e.g.')
[void]$sb.AppendLine('`logs/claude/reviews`). THIS checklist takes a single directory, so it')
[void]$sb.AppendLine('scans one backend per run by design; cross-backend aggregation is the')
[void]$sb.AppendLine('analyzer''s job (`analyze-blocker-trends.ps1` merges multiple backend dirs')
[void]$sb.AppendLine('in one pass).')

Write-Artifact -Body $sb.ToString()

Write-Host "[dispatch-checklist] wrote checklist to $outAbs"
Write-Host "[dispatch-checklist]   verdicts scanned: $($reviewFiles.Count) ($windowNote)"
Write-Host "[dispatch-checklist]   categories with findings: $($catAgg.Count)/8; total findings: $totalFindings"
exit 0
