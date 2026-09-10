# Cross-backend review-verdict trend analyzer.
#
# Reads verdict markdown files from one or more reviews directories
# (default: BOTH logs/codex/reviews AND logs/claude/reviews, so the
# report aggregates findings across both reviewer backends), clusters
# BLOCKER (and QUALITY / legacy NON-BLOCKER / NOTE) findings by
# archetype keyword, and emits a single markdown report enumerating the
# most-frequent classes with example cites. When MORE THAN ONE backend
# dir is scanned it produces ONE cross-backend report with per-backend
# provenance -- each verdict-count and exemplar is tagged with the
# backend it came from -- plus UNION totals.
#
# PURPOSE (read this before reading the report):
# The report exists to reduce REPEAT-CLASS BLOCKERs by improving worker
# discipline upstream. It is NOT a review-throughput metric. Use it to
# identify archetypes worth folding into worker dispatch templates,
# AGENTS.md, the review prompt's hazards section, or an anti-pattern
# guide. The output does not contain any cycle-count or time-to-merge
# statistics by design.
#
# Cross-backend aggregation: the DEFAULT scans both backend log dirs because
# defect-class archetypes are properties of the codebase, not of which
# reviewer caught them; aggregating across both reviewer backends gives
# the most complete picture for the worker-discipline-improvement goal.
# Pass -ReviewsDir to slice per-backend, or to name an explicit dir set.
#
# MIRROR CONTRACT (keep in lock-step): scripts/shared/dispatch-checklist.ps1
# deliberately RE-EXPRESSES this analyzer's verdict filename-shape guard (the
# `$verdictNameRe` review-<YYYYMMDD>-<HHMMSS>-<scope>.md pattern) and its
# per-file dedupe primitive (normalize finding text via `($text -replace
# '\s+',' ').ToLowerInvariant()`, keeping the HIGHEST severity across passes).
# The `$verdictNameRe` regex is byte-identical in both files; the dedupe yields
# identical keys + ranks (inline here; `Get-NormalizedText` / `Get-SeverityRank`
# in the checklist). Neither may drift without updating the other. The checklist
# stays SINGLE-DIR (one backend per run, over a recent window) by design; THIS
# analyzer is the cross-backend aggregator. Any change to the filename or
# dedupe conventions here must be mirrored there (and vice-versa).
#
# FAIL-CLOSED (never silently narrow coverage):
#   - An EXPLICITLY configured -ReviewsDir that is MISSING, or that holds ZERO
#     in-window verdict-shaped files, aborts the run (a mispointed, empty, or
#     missing dir must not masquerade as a covered backend). The IMPLICIT
#     default list is the one exception: a DEFAULTED backend dir that is absent
#     or empty is SKIPPED with a loud note (a single-backend install
#     legitimately has only one of the two dirs), and the run fails closed only
#     when NO defaulted dir yields verdicts. Explicit configuration is strict;
#     the default degrades loudly, never silently.
#   - A verdict-shaped file RECOGNIZED as a producer-shaped fail-closed run is a
#     SELF-DECLARED failed gate run (a transient reviewer-environment failure,
#     normally retried). Recognition is the WHOLE producer self-declaration, not
#     the banner alone: the exact provenance prefix (the 4-, 5-, or 6-line
#     header era -- the REVIEW-DURATION-SECS stamp included), the `===== GATE
#     FAILED CLOSED =====` banner, the diagnostic grammar, and the first-suffix-
#     line + terminal framing, ALL validated over bytes read with a strict no-BOM
#     decode (Read-VerdictArtifactText -> Get-FailClosedBannerReason). It is
#     EXCLUDED from the counts and reported LOUDLY -- a console line AND an
#     "Excluded fail-closed runs" report section naming each excluded file + its
#     banner reason line. The run does NOT abort AS LONG AS at least one
#     trustworthy verdict remains. Excluding it loudly (vs aborting) keeps ONE
#     such file from permanently breaking a no-cutoff (full-history) scan, in
#     which a fail-closed file never ages out. If EVERY scanned file is a
#     recognized fail-closed run, the report is STILL written (exit 0) as an
#     explicit NO-TRUSTWORTHY-VERDICTS report naming the exclusions, with every
#     count zero by construction; only a window with no recognized exclusions
#     and no parseable evidence (a mispointed input) refuses.
#   - A verdict-shaped file that is UNRECOGNIZED-malformed -- it is NOT a
#     recognized producer-shaped fail-closed run (EITHER no banner, OR the banner
#     present but the producer-shape/decode validation above rejected it: a bad
#     header value, an unknown diagnostic, a non-producer suffix/framing, or a
#     BOM / invalid-UTF-8 encoding) AND it fails the structure contract (no
#     `VERDICT:` line at all, an unrecognized `=====` marker, an incomplete
#     `REVIEW PASS n/N` sequence, a non-header leading fragment, a malformed
#     REVIEW-DURATION-SECS stamp, a wrong-case severity prefix, a review-pass
#     block with != 1 `VERDICT:` line, a review-pass block whose verdict word is
#     incoherent with its findings, or a review-pass block with a malformed or
#     missing eight-category block -- validated UNCONDITIONALLY, since this
#     package shipped with the eight-category format and has no pre-category
#     exemption) -- is UNEXPLAINED corruption. It ABORTS the run and names the
#     offender(s), in ANY scanned dir.
#     This mirrors the wrapper's per-pass Get-VerdictExitCode contract in full
#     (BLOCKER precedence; else NON-BLOCKING for QUALITY/NON-BLOCKER/NOTE; else
#     CLEAN for zero findings) plus the dispatch-checklist's marker-sequence,
#     block-structure, invalid-tail, and per-category row-balance checks.
#     Such evidence is never silently counted or dropped -- quarantine (move out
#     of the scanned dir) or repair the file, then re-run.
#
# Usage:
#   scripts\shared\analyze-blocker-trends.ps1                                                     # both backends by default -> docs/blocker-trends.md
#   scripts\shared\analyze-blocker-trends.ps1 -OutPath foo.md                                     # custom output path
#   scripts\shared\analyze-blocker-trends.ps1 -SinceDays 30                                       # only verdicts whose mtime is within N days
#   scripts\shared\analyze-blocker-trends.ps1 -ReviewsDir logs/codex/reviews                      # codex-only slice (explicit: strict)
#   scripts\shared\analyze-blocker-trends.ps1 -ReviewsDir logs/claude/reviews                     # claude-only slice
#   scripts\shared\analyze-blocker-trends.ps1 -ReviewsDir logs/codex/reviews,logs/claude/reviews  # explicit cross-backend (in-process array literal)
#   powershell -File scripts\shared\analyze-blocker-trends.ps1 -ReviewsDirCsv logs/codex/reviews,logs/claude/reviews   # the same from a native shell
#
#   -ReviewsDir takes ONE OR MORE dirs as a real array (each element verbatim,
#   never split -- a directory name may contain a comma); -ReviewsDirCsv takes
#   the same input as ONE comma-separated string, always split on every comma
#   (the `-File` binder cannot express an array). Pass exactly one of the two.
#   Whenever more than one backend is scanned the output carries a `Backends:`
#   provenance line and `[backend]`-tagged exemplars. Backend identity is each
#   ARTIFACT'S OWN `REVIEW-BACKEND:` header (headerless historical artifacts
#   count as `legacy`), never the directory spelling -- a directory name is
#   caller spelling, not provenance.
#
# Exit codes:
#   0 = success, report written (recognized producer-shaped fail-closed runs are
#       EXCLUDED loudly, not a failure -- see FAIL-CLOSED above).
#   1 = invocation failure (an explicit reviews dir missing, blank, or holding
#       no in-window verdicts, no defaulted dir yielding verdicts, both
#       -ReviewsDir and -ReviewsDirCsv passed, an UNRECOGNIZED-malformed
#       verdict file, a mispointed input with no parseable evidence and no
#       recognized exclusion, writer failure, etc.)

[CmdletBinding()]
param(
  # One OR MORE review dirs as a real array, each element verbatim (the
  # comma-separated native-shell form is -ReviewsDirCsv). The DEFAULT scans both backend
  # log dirs so the aggregated report covers the full cross-review picture; a
  # defaulted dir that is absent or empty is skipped with a note (a single-
  # backend install has only one of them) and the run fails closed only when
  # no defaulted dir yields verdicts. An EXPLICIT list is strict: every named
  # dir must exist and hold in-window verdicts. Multiple dirs produce ONE
  # cross-backend report with per-backend provenance + union totals; backend
  # identity is each artifact's own REVIEW-BACKEND header (Get-ArtifactBackend),
  # never the dir spelling. Duplicate dir paths are scanned once.
  [string[]]$ReviewsDir = @('logs/codex/reviews', 'logs/claude/reviews'),
  # The native-shell (`-File`) representation of the same input: ONE
  # comma-separated string, always split on every comma (see the
  # normalization note below). Mutually exclusive with -ReviewsDir.
  [string]$ReviewsDirCsv = '',
  [string]$OutPath = 'docs/blocker-trends.md',
  # 0 = no cutoff (full history). Negative values are rejected at the
  # parameter binding boundary so a typo like `-SinceDays -1` cannot
  # silently fall through to full-history mode.
  [ValidateRange(0, [int]::MaxValue)]
  [int]$SinceDays = 0
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# ---------------------------------------------------------------------------
# Multi-directory input has TWO representations, each unambiguous BY GRAMMAR
# and independent of filesystem state:
#   -ReviewsDir     a real array; every element is one path taken VERBATIM
#                   (a directory name may legally contain a comma on Windows,
#                   so an array element is never split).
#   -ReviewsDirCsv  ONE comma-separated string, ALWAYS split on every comma --
#                   the native-shell form (`powershell -File ... -ReviewsDirCsv
#                   a,b`), since the -File binder cannot express an array. A
#                   comma-bearing directory cannot be named through this form;
#                   the array form exists for it.
# The two never combine (an ambiguous invocation refuses), and NO entry is
# discarded here: a blank element or fragment reaches the strict per-entry
# validation below and is refused there by name, never silently dropped.
if ($PSBoundParameters.ContainsKey('ReviewsDirCsv')) {
  if ($PSBoundParameters.ContainsKey('ReviewsDir')) {
    Write-Host '[trends] ERROR: -ReviewsDir and -ReviewsDirCsv are two representations of the same input; pass exactly one.'
    exit 1
  }
  $ReviewsDir = @(([string]$ReviewsDirCsv) -split ',' | ForEach-Object { $_.Trim() })
}

# ---------------------------------------------------------------------------
# Backend provenance: producer identity from the artifact's OWN validated header.
# ---------------------------------------------------------------------------
# Identity comes from the `REVIEW-BACKEND:` header the wrappers stamp -- never
# from the directory the file happens to sit in: a directory name is caller
# spelling (`C:\archive`, `logs/codex/reviews/.`), not provenance, and inferring
# identity from it tags valid evidence falsely and misroutes recognized
# fail-closed runs. The COMPLETE leading identity region is parsed (consecutive
# non-blank lines from the top, the same region the suspect check whitelists),
# never the first matching line: a duplicated header name is conflicting
# provenance, and a block carrying SOME recognized header names but not the
# producer's mandatory four (DIFF-SHA256, REVIEW-TREE-OID, REVIEW-BACKEND,
# REVIEW-EFFORT -- the first era's whole block; the later stamps are optional)
# is a torn or forged block, not a headerless artifact -- both are malformed
# evidence (Reason set; the caller quarantines). `legacy` is reserved for an
# artifact whose leading region carries NO recognized header name at all (the
# wrappers predating the header): reported as its own backend, never guessed
# from a path. The leading region (consecutive non-blank lines from the top)
# is graded the way the fail-closed recognizer grades its header: a LOOSE
# candidate guard (any case, leading whitespace, a missing colon) decides
# that the region is header-bearing at all, and then the region must BE one
# of the wrappers' exact ORDERED header eras, line by line, values
# byte-exact: DIFF-SHA256 (64 hex), REVIEW-TREE-OID (40/64 hex),
# REVIEW-BACKEND from the closed producer set, REVIEW-EFFORT in the
# BACKEND'S OWN value set (the codex wrapper stamps a reasoning tier or
# `unknown`; the Claude wrapper stamps exactly `n/a`), then the era tail --
# nothing (4-line era), `REVIEW-SEVERITY-CONTRACT: blocker-only` (5-line),
# or that plus `REVIEW-DURATION-SECS: <int>` (6-line; the duration stamp
# never appears without the contract stamp) -- followed by the EXACTLY
# EMPTY separator line every wrapper emits. Framing is byte-exact like the
# recognizer's: the split is on LF alone, so a CR-framed header fails its
# line grammar and a whitespace-only separator is a seventh region line,
# not a separator (the wrappers write LF and a bare blank; the shipped logs
# carry no CR byte). Anything else header-bearing -- a mutated name or
# value, a cross-backend effort, a reordered or duplicated line, a tail
# combination no wrapper emits, a header cut off before its separator -- is
# malformed provenance: never prose, never `legacy` (it would contaminate
# the legacy bucket), never the first plausible value. `legacy` is reserved
# for a region with NO header-shaped line at all (the wrappers predating
# the header).
$abCandidateRe = [regex]'(?i)^\s*(DIFF-SHA256|REVIEW-TREE-OID|REVIEW-BACKEND|REVIEW-EFFORT|REVIEW-SEVERITY-CONTRACT|REVIEW-DURATION-SECS)\b'
$abEffortByBackend = @{
  'codex'  = '^REVIEW-EFFORT: (minimal|low|medium|high|xhigh|max|unknown)$'
  'claude' = '^REVIEW-EFFORT: n/a$'
}
function Get-ArtifactBackend {
  param([string]$Content)
  $abLines = $Content -split "`n"
  $abRegion = New-Object 'System.Collections.Generic.List[string]'
  $abHeaderShaped = $false
  foreach ($abLine in $abLines) {
    if ($abLine -ceq '') { break }
    $abRegion.Add($abLine)
    if ($abCandidateRe.IsMatch($abLine)) { $abHeaderShaped = $true }
  }
  if (-not $abHeaderShaped) { return @{ Backend = 'legacy'; Reason = $null } }
  $abBad = { param($abWhat) return @{ Backend = $null; Reason = "a header-bearing identity region that is not a producer header era ($abWhat) -- malformed provenance cannot be trusted (and is never legacy)" } }
  if ($abRegion.Count -lt 4 -or $abRegion.Count -gt 6) { return (& $abBad "$($abRegion.Count) leading lines; the wrappers emit 4, 5, or 6") }
  if ($abRegion[0] -cnotmatch '^DIFF-SHA256: [0-9a-f]{64}$')                      { return (& $abBad 'line 1 is not the DIFF-SHA256 stamp') }
  if ($abRegion[1] -cnotmatch '^REVIEW-TREE-OID: [0-9a-f]{40}([0-9a-f]{24})?$')   { return (& $abBad 'line 2 is not the REVIEW-TREE-OID stamp') }
  if ($abRegion[2] -cnotmatch '^REVIEW-BACKEND: (?<b>codex|claude)$')             { return (& $abBad 'line 3 is not a producer REVIEW-BACKEND stamp') }
  $abBackend = $Matches['b']
  if ($abRegion[3] -cnotmatch $abEffortByBackend[$abBackend])                      { return (& $abBad "line 4 is not the $abBackend wrapper's REVIEW-EFFORT stamp") }
  if ($abRegion.Count -ge 5 -and $abRegion[4] -cne 'REVIEW-SEVERITY-CONTRACT: blocker-only') { return (& $abBad 'line 5 is not the REVIEW-SEVERITY-CONTRACT stamp') }
  if ($abRegion.Count -eq 6 -and $abRegion[5] -cnotmatch '^REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$') { return (& $abBad 'line 6 is not the REVIEW-DURATION-SECS stamp') }
  if ($abLines.Count -le $abRegion.Count) { return (& $abBad 'the header is cut off before its empty separator line') }
  return @{ Backend = $abBackend; Reason = $null }
}

# ---------------------------------------------------------------------------
# Fail-closed banner recognizer + reason extractor.
#
# Returns the wrapper's own fail-closed REASON line iff $Content is a genuine
# codex-wrapper fail-closed artifact, else $null. A non-null result marks a
# SELF-DECLARED failed gate run: the caller EXCLUDES the file from the report
# LOUDLY (never silently) rather than aborting the whole run.
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
# 4-line era predates it; the duration stamp made the 6-line era) -- ALL are recognized, else this full-history analyzer regresses
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
# SHARED with scripts/shared/dispatch-checklist.ps1 (byte-identical there): the
# banner recognizer is a cross-script contract, same lock-step discipline as the
# mirrored filename-shape / dedupe / UTF-8 primitives. Any change to the wrapper's
# header block, value formats, or diagnostic grammar must be mirrored in BOTH
# copies. The exclusion logic that USES this sits in each script's parse loop,
# ABOVE Get-VerdictSuspectReason.
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
  # HEADER BLOCK. CASE-SENSITIVE (-c*): PowerShell's default operators are case-
  # INSENSITIVE, which would wrongly accept REVIEW-BACKEND: CODEX or uppercase hex
  # the producer never emits. Values pinned to auto-review.ps1's exact emission.
  if ($lines[0] -cnotmatch '^DIFF-SHA256: [0-9a-f]{64}$')                              { return $null }
  if ($lines[1] -cnotmatch '^REVIEW-TREE-OID: [0-9a-f]{40}([0-9a-f]{24})?$')           { return $null }   # 40 (SHA1) or 64 (SHA256) hex
  if ($lines[2] -cne 'REVIEW-BACKEND: codex')                                          { return $null }
  if ($lines[3] -cnotmatch '^REVIEW-EFFORT: (minimal|low|medium|high|xhigh|max|unknown)$') { return $null }   # auto-review.ps1 $validTiers or 'unknown'
  # Line 4 selects the era: the 5-line contract stamp -- then OPTIONALLY the
  # 6-line REVIEW-DURATION-SECS stamp on line 5, value-shape validated (the
  # reviewer stamps it on EVERY artifact, fail-closed ones included, so a
  # recognizer blind to it would abort every current fail-closed run as
  # unrecognized instead of excluding it loudly) -- OR the blank ending the
  # 4-line header.
  if ($lines[4] -ceq 'REVIEW-SEVERITY-CONTRACT: blocker-only') {
    if     ($lines[5] -cmatch '^REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$') { $blankIdx = 6 }
    elseif ($lines[5] -ceq '')                                           { $blankIdx = 5 }
    else                                                                 { return $null }
  }
  elseif ($lines[4] -ceq '')                                      { $blankIdx = 4 }
  else                                                            { return $null }
  $bannerIdx = $blankIdx + 1
  if (($bannerIdx + 5) -ge $n)                              { return $null }   # need banner+diag+blank+VERDICT+blank+>=1 suffix line
  if ($lines[$blankIdx] -cne '')                            { return $null }
  if ($lines[$bannerIdx] -cne '===== GATE FAILED CLOSED =====') { return $null }
  # DIAGNOSTIC (Get-CombinedReviewExit): the fixed malformed/errored strings, or the `expected N ...
  # only M ...` form with CANONICAL decimal counts (no leading zeros -- the producer
  # formats ints canonically). TryParse (not [int], which THROWS on overflow under
  # Stop) bounds N to the producer 1..10 range and M to 0..N-1. N/M are producer-
  # owned and cross-checked against the FIRST suffix line below (never the middle).
  $diag = $lines[$bannerIdx + 1]
  $diagKind = ''; $diagN = 0; $diagM = 0
  if ($diag -ceq 'at least one pass produced a malformed verdict') { $diagKind = 'malformed' }
  elseif ($diag -ceq 'one or more review passes errored or produced no verdict') { $diagKind = 'errored' }
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
  if ($lines[$bannerIdx + 2] -cne '')                       { return $null }
  if ($lines[$bannerIdx + 3] -cne 'VERDICT: BLOCKED')       { return $null }
  if ($lines[$bannerIdx + 4] -cne '')                       { return $null }
  # TERMINAL FRAMING (validated, not normalized): the producer ends the artifact with
  # exactly ONE trailing LF, and each final pass body is `Verdict.TrimEnd()` (or the
  # exact `(no verdict produced)` remainder), so the split yields exactly one trailing
  # empty element AND the last CONTENT line ends in a NON-whitespace char. Reject a
  # missing terminal LF (last element non-empty), extra trailing blank line(s)
  # (second-to-last empty), or a whitespace-ENDING final content line -- a terminal CR
  # from CRLF, trailing spaces/tabs, or a whitespace-only final body are all producer-
  # impossible because TrimEnd strips them.
  if ($lines[$n - 1] -cne '')                               { return $null }   # missing terminal newline
  if ($lines[$n - 2] -ceq '')                               { return $null }   # extra trailing blank line(s)
  $lastContent = $n - 2
  if ($lines[$lastContent] -cmatch '\s$')                   { return $null }   # trailing whitespace on the final content line (TrimEnd => never)
  $suffixStart = $bannerIdx + 5
  if ($lastContent -lt $suffixStart)                        { return $null }   # empty suffix
  # FIRST SUFFIX LINE (producer-owned): exactly `(no verdict produced)` (then nothing
  # else -- this remainder is fully producer-owned) XOR a producer-shaped pass marker
  # (CANONICAL decimals, n in 1..total, total in 1..10) followed by an OPAQUE, non-
  # empty middle. The multi-section MIDDLE past this line is never inspected.
  $suffixIsNoVerdict = $false; $firstMarkerN = 0; $firstMarkerTotal = 0
  if ($lines[$suffixStart] -ceq '(no verdict produced)') {
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
  #                             (`^...$` / -ceq).
  #   interior tabs/spaces   -> the producer emits single spaces; the exact matches pin them.
  #   blank-line counts      -> the one/zero blanks between each producer-owned pair are pinned
  #                             by fixed line index (an extra/missing blank shifts a required
  #                             line off its exact match).
  #   whitespace-only blanks -> every producer blank is checked `-ceq ''` (a "  " blank fails).
  #   unicode whitespace     -> `\s` (terminal check) + the exact ASCII matches cover it.
  #   case on every literal  -> all comparisons are case-sensitive (`-c*` / [regex]::Match).
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
# Archetype classifier.
# ---------------------------------------------------------------------------
# Each archetype has a friendly name + a list of keyword/regex patterns.
# A finding is classified by walking the archetype list IN ORDER and
# assigning it to the FIRST one whose pattern set matches. Order is
# most-specific to least-specific so the more-targeted archetype wins
# when multiple patterns hit (this mirrors the prompt template's
# "one primary category per finding" rule -- the analyzer uses the same
# discipline so the trend report is comparable across review periods).
#
# Patterns are case-insensitive regex. A finding line is the one-line
# summary text the reviewer emitted (the line starting with the
# severity prefix, e.g. "BLOCKER: foo.rs:10 - dropped Option").
# Either backend (codex or claude) produces this same shape per the
# shared verdict format.
#
# UNCLASSIFIED is the catch-all. A populated UNCLASSIFIED bucket in the
# report is a signal that the keyword list needs to grow.

$archetypes = @(
  # WORKFLOW-INFRA first: a finding citing `scripts/codex/...`,
  # `auto-review`, `auto-merge`, or `AGENTS.md` is ABOUT the review
  # system itself, even if the broken behavior happens to involve PLAN
  # text or asset paths. Putting this before PLAN-DRIFT keeps
  # "review-wrapper bug that misclassifies PLAN checkboxes" categorized
  # as a workflow-infra defect rather than as PLAN drift -- the actual
  # PLAN.md is fine; the wrapper is the broken artifact.
  @{
    Name = 'WORKFLOW-INFRA'
    Patterns = @(
      'scripts/codex/',
      'scripts/claude/',
      'scripts/git-hooks/',
      'bootstrap\.ps1',
      'auto-review',
      'auto-merge',
      'pre-commit',
      '\bcore\.hooksPath\b',
      '\bhooksPath\b',
      # Gate dispatcher ONLY -- qualified so a generic application "event
      # dispatcher" finding does not land in WORKFLOW-INFRA (which is first-match).
      # "pre-commit dispatcher" also matches 'pre-commit' above; "per-clone
      # dispatcher" is the non-redundant gate phrasing. A bare `\bdispatcher\b`
      # over-matched ordinary dispatcher findings.
      '(?:pre-commit|per-clone)\s+dispatcher',
      'commit wrapper',
      'commit-wrapper',
      'git-config',
      'review-prompt-template',
      'AGENTS\.md',
      # Named review-system documentation files. NOT a wildcard `docs/`
      # prefix -- that would over-match unrelated project docs. Each
      # entry pins one specific known review-infra doc. Add your own
      # project's review-system doc filenames here as they are produced;
      # the UNCLASSIFIED bucket surfaces unmapped ones (fail-loud).
      'docs/audit-protocol',
      'docs/blocker-trends'
    )
  },
  @{
    Name = 'PLAN-DRIFT'
    Patterns = @(
      'PLAN\.md',
      '\bmilestone\b',
      '\bcheckbox\b',
      'range claim',
      'status[ -]table',
      'sequencing',
      '\bM\d+\.\d+'
    )
  },
  @{
    Name = 'SILENT-FAILURE'
    Patterns = @(
      '\bdropped\b',
      '\bsilently\b',
      '\bsuppressed\b',
      '\bignored\b',
      'exits\s+0',
      'exits successfully',     # real verdict phrasing for --check returning 0 on bad input
      'false[- ]green',
      '\bno-op\b',
      'accepted\b.*\binvalid\b',
      'silently receives',
      'silently load',
      'missing diagnostic',
      'unwrap_or_default',
      # Audit-added patterns (UNCLASSIFIED reduction):
      'broken fallback',
      'fallback cannot',         # "fallback cannot classify ..."
      'lost.*playback',          # cues that silently lost audible fallback
      'reports?.*\bPASS\b',      # test instrumentation reporting false PASS
      'warning-only'             # "warning-only and skipped"
    )
  },
  @{
    Name = 'TOMBSTONE-OR-SHIM'
    Patterns = @(
      '\btombstone\b',
      'removed[- ]code',
      'renamed[- ]to[- ]underscore',
      'empty quarantine',
      '\bformerly\b',
      'keep for compat',
      '\bdead\s+code\b'
    )
  },
  # Audit-added archetype: STALE-DOC.
  # Distinct from TOMBSTONE-OR-SHIM (which is residue of removed code) --
  # STALE-DOC is documentation/comments/help-text describing OLD behavior
  # of code that has since changed. Ordering in the $archetypes array:
  # WORKFLOW-INFRA -> PLAN-DRIFT -> SILENT-FAILURE -> TOMBSTONE-OR-SHIM ->
  # STALE-DOC -> CROSS-CRATE-CONTRACT -> LOADER-OR-ASSET-EDGE -> CONVENTION.
  # STALE-DOC sits AFTER TOMBSTONE-OR-SHIM so a finding that
  # names both stays as TOMBSTONE (closer to the real defect), and AFTER
  # SILENT-FAILURE so a finding that mentions both stays as SILENT-FAILURE
  # (the silent behavior is the load-bearing defect, not the stale wording).
  # Placed BEFORE CROSS-CRATE-CONTRACT and the loader/asset/convention
  # buckets so the "still describes/says/claims" markers win over generic
  # validator/loader keywords when the finding is fundamentally a stale-doc.
  @{
    Name = 'STALE-DOC'
    Patterns = @(
      'still describes',
      'still says',
      'still claim',
      'still claims',
      'still names',
      'still documents',
      'documentation says',
      'docs still',
      'comment still',
      'comments still',
      'help still',
      '\bStale\b.*\b(documentation|doc|comment|docstring)\b'
    )
  },
  @{
    Name = 'CROSS-CRATE-CONTRACT'
    Patterns = @(
      'accepts\b.*\bdocument',
      'no longer re-exports?',
      '\bvalidator\b',
      'request shape',
      'cross[- ]crate',
      'docstring.*reject',
      'system[- ]set ordering'
    )
  },
  @{
    Name = 'LOADER-OR-ASSET-EDGE'
    Patterns = @(
      # Keep these aligned with the LOADER-OR-ASSET-EDGE surface vocabulary in
      # review-prompt-template.md and dispatch-checklist.ps1 (binary-format
      # header/length checks, identity-fallback on invalid input, asset-root
      # env-var fall-through, format-invariant drops) so a finding worded from
      # the prompt does not fall into UNCLASSIFIED.
      '\bbinary[- ]asset\b',
      '\bbinary[- ]format\b',
      'header[- ]length',
      'header-declared',
      'format[- ]invariant',
      'identity[- ]fallback',
      'fallback to identity',
      '\bbind[- ]matrix\b',
      'ASSET_ROOT',
      'asset[- ]root',
      '\bloader\b',
      'asset_repair',
      'asset.*texture',
      '\bjoint\b',
      'singular.*matrix',
      # Audit-added patterns (UNCLASSIFIED reduction):
      'nonexistent.*clip',       # animation/audio clip referenced but absent
      'nonexistent.*asset',
      'missing.*clip',
      'missing.*asset reference'
    )
  },
  @{
    Name = 'CONVENTION'
    Patterns = @(
      'CLAUDE\.md',
      'backwards[- ]compat',
      'comment.*explains',
      'mechanic[- ]explaining',
      'error handling.*impossible',
      'unwrap at boundary',
      # Audit-added patterns (UNCLASSIFIED reduction):
      '\blint gate\b',           # "trips the lint gate"
      'static[- ]analysis'
    )
  }
)

function Get-FindingArchetype {
  param([string]$Text)
  $lower = $Text  # patterns are case-insensitive; no need to lower
  foreach ($a in $archetypes) {
    foreach ($p in $a.Patterns) {
      if ($lower -match "(?i)$p") {
        return $a.Name
      }
    }
  }
  return 'UNCLASSIFIED'
}

# Max category-count the wrapper's `\d+` tail tolerates. Mirror of the same
# constant in scripts/shared/dispatch-checklist.ps1 -- both scripts consume the
# same verdict logs and must apply the same category-tail bound so they agree on
# which verdicts are trustworthy evidence.
$script:CategoryCountMax = 10000

# Classify a category line's tail as none|count|invalid, the SAME way the
# wrapper's `:\s*(?<v>none|\d+)\s*$` regex matches it. BYTE-IDENTICAL to the
# helper in scripts/shared/dispatch-checklist.ps1 -- keep the two copies in sync
# (the analyzer's suspect check and the checklist's trustworthiness gate must
# classify tails identically).
function Get-CategoryTailKind {
  param([string]$Tail)
  $t = $Tail.Trim()
  # CASE-SENSITIVE `none` compare (-ceq): the wrapper's contract regex is
  # `:\s*(?<v>none|\d+)\s*$` (case-sensitive), so `None` / `NONE` are NOT the
  # `none` sentinel -- they fall through to 'invalid', matching how the wrapper
  # treats a non-`none|\d+` tail. A case-insensitive -eq would wrongly accept
  # `None` as a zero-count category and admit a wrong-case tail as clean evidence.
  if ($t -ceq 'none') { return @{ Kind = 'none'; Value = 0 } }
  # Require a DIGITS-ONLY shape (on the already-trimmed tail) before TryParse,
  # classifying a tail the same way the wrapper's `:\s*(?<v>none|\d+)\s*$` regex
  # matches it. NOTE leading/trailing WHITESPACE is NOT a difference: the wrapper
  # allows `\s*` around the value and trims, and $t is `$Tail.Trim()`, so ` 1 `
  # is a valid count to BOTH. Only a SIGNED or otherwise non-`\d+` tail (e.g.
  # `+1`, `1.0`, `1a`) fails `^\d+$` here AND fails `(?<v>none|\d+)` in the
  # wrapper -- the wrapper then treats the line as a non-matching category line
  # (counts toward neither `none` nor a digit count).
  $parsed = 0
  if ($t -match '^\d+$' -and [int]::TryParse($t, [ref]$parsed) -and $parsed -le $script:CategoryCountMax) {
    return @{ Kind = 'count'; Value = $parsed }
  }
  return @{ Kind = 'invalid'; Value = 0 }
}

# ---------------------------------------------------------------------------
# Fail-closed per-file suspect check: returns a human-readable REASON string
# when the verdict file is NOT trustworthy review evidence, else $null. The
# analyzer calls this on each verdict file AFTER Get-FailClosedBannerReason has
# taken the RECOGNIZED producer-shaped fail-closed runs to the loud-exclude
# path, so what reaches here -- a truncated, malformed, or bannered-but-
# unrecognized verdict -- is quarantined and NAMED, never silently counted or
# dropped into the trend report. This is the SUPERSET bar
# dispatch-checklist (Get-VerdictStructure / Test-VerdictBlock) applies, not just
# the wrapper's (Get-VerdictExitCode): it rejects everything the wrapper fails
# closed on (exit 3, possibly banner-less) AND the STRICTER-than-wrapper shapes
# dispatch-checklist rejects -- over/underfilled category ROW blocks, malformed
# category TAILS (`+1`, `1.0`), and WRONG-CASE severity prefixes (`blocker:`) --
# because both scripts consume the same
# verdict logs and must agree on which files are trustworthy evidence (a file one
# rejects but the other counts would desync the corpus). $VerdictWordRe is the
# parse loop's own
# verdict-line regex (its `(?<v>)` group yields the well-formed verdict WORD);
# the coherence check extracts the word through it, so the suspect check and the
# parse loop share ONE regex and cannot drift.
# ---------------------------------------------------------------------------
function Get-VerdictSuspectReason {
  param([string]$Content, [regex]$VerdictWordRe)
  # Case policy MIRRORS the wrappers (and dispatch-checklist), which is ASYMMETRIC:
  #  - The VERDICT line + word and the GATE FAILED CLOSED banner are matched CASE-
  #    INSENSITIVELY. The wrappers detect the verdict with `-match '^VERDICT:'` and
  #    compare the word with case-insensitive `-ne` (auto-review.ps1
  #    Get-VerdictExitCode), so `verdict: clean` is an ACCEPTED clean verdict --
  #    quarantining it here would wrongly diverge from a wrapper-accepted log.
  #  - SEVERITY prefixes and CATEGORY lines / `none` are matched CASE-SENSITIVELY
  #    (the wrapper counts `^BLOCKER:` and `^<CAT>:\s*(none|\d+)` case-sensitively);
  #    a WRONG-CASE severity prefix is quarantined by the scan below as a finding
  #    the case-sensitive parser would silently under-count.
  if ($Content -match '(?m)^=====\s*GATE FAILED CLOSED\s*=====') {
    return 'GATE FAILED CLOSED banner (fail-closed evidence)'
  }
  if ($Content -notmatch '(?m)^VERDICT:') {
    return 'no VERDICT: line (truncated / missing verdict -- the wrapper and dispatch-checklist fail closed)'
  }
  # Reject WRONG-CASE severity prefixes anywhere: a column-0 line like `blocker:` /
  # `Quality:` matches a severity NAME case-insensitively but NOT the exact-case
  # `^(BLOCKER|QUALITY|NON-BLOCKER|NOTE):` that the wrapper and this analyzer's
  # $severityRe count with, so it is INVISIBLE to finding-counting -- a real finding
  # written (or corrupted) in the wrong case would leave a `VERDICT: CLEAN` verdict
  # falsely clean AND pollute the corpus with an uncounted finding. Fail closed on
  # any such line rather than trust a block the case-sensitive parser under-counts.
  foreach ($sm in ([regex]'(?im)^(?<sev>BLOCKER|QUALITY|NON-BLOCKER|NOTE):').Matches($Content)) {
    $sev = $sm.Groups['sev'].Value
    if ($sev -cne $sev.ToUpperInvariant()) {
      return "a severity-prefix line uses non-uppercase '$sev`:' -- the wrapper's case-sensitive parser under-counts it, so a real finding could hide under a falsely-clean verdict (untrustworthy)"
    }
  }
  # Every `=====` marker must be a well-formed REVIEW PASS marker (the banner is
  # handled above), AND the pass SEQUENCE must be complete: each n/N within the
  # producer's 1..10 range, n <= N, unique pass numbers, one agreed total N, and
  # exact 1..N coverage. An unknown marker (which could hide findings after it),
  # or a truncated / duplicate / mismatched-total sequence, is malformed evidence
  # (dispatch-checklist Get-VerdictStructure enforces the same; a lone
  # `REVIEW PASS 1/2` block is a silently dropped pass).
  $passMarkerRe = [regex]'^===== REVIEW PASS (?<n>\d+)/(?<total>\d+) =====\s*$'
  $passNums = @{}
  $passTotals = New-Object 'System.Collections.Generic.HashSet[int]'
  $passMarkerCount = 0
  foreach ($mk in [regex]::Matches($Content, '(?m)^=====.*=====\s*$')) {
    $pm = $passMarkerRe.Match($mk.Value)
    if (-not $pm.Success) {
      return 'an unrecognized `===== ... =====` marker (not a REVIEW PASS marker) -- malformed evidence'
    }
    $passMarkerCount++
    $n = 0; $tot = 0
    if (-not [int]::TryParse($pm.Groups['n'].Value, [ref]$n) -or $n -lt 1 -or $n -gt 10 -or `
        -not [int]::TryParse($pm.Groups['total'].Value, [ref]$tot) -or $tot -lt 1 -or $tot -gt 10) {
      return 'a REVIEW PASS marker n/N is outside the producer 1..10 range -- malformed evidence'
    }
    if ($n -gt $tot) { return 'a REVIEW PASS marker has n > N -- malformed evidence' }
    if ($passNums.ContainsKey($n)) { return 'a REVIEW PASS marker number is duplicated -- malformed evidence' }
    $passNums[$n] = 1
    [void]$passTotals.Add($tot)
  }
  if ($passMarkerCount -gt 0) {
    if ($passTotals.Count -ne 1) { return 'REVIEW PASS markers disagree on the total N -- malformed evidence' }
    $declaredTotal = @($passTotals)[0]
    if ($passNums.Count -ne $declaredTotal) { return "REVIEW PASS sequence is truncated ($($passNums.Count) of $declaredTotal passes present) -- malformed evidence" }
    for ($p = 1; $p -le $declaredTotal; $p++) {
      if (-not $passNums.ContainsKey($p)) { return "REVIEW PASS $p of $declaredTotal is missing -- malformed evidence" }
    }
  }
  # Split on the pass markers (as the wrapper / dispatch-checklist do). When
  # markers are present the FIRST segment is the leading provenance-header
  # fragment (DIFF-SHA256/REVIEW-* lines, no VERDICT): it must contain ONLY those
  # header lines + blanks. A NO-marker artifact (the Claude single-verdict shape)
  # is ONE pass block. Each non-header block must have EXACTLY ONE VERDICT line,
  # and if that word is malformed the block must carry a BLOCKER (precedence).
  # REVIEW-DURATION-SECS is validated to its FULL declared shape (one
  # non-negative base-10 integer, no padding - trailing whitespace
  # included) rather than prefix-only: the value is new schema this slice
  # introduces, so a malformed value must quarantine the artifact instead
  # of reading as trustworthy metadata. The pre-existing header
  # alternatives keep their historical prefix-only acceptance.
  $headerLineRe = [regex]'^(DIFF-SHA256:|REVIEW-TREE-OID:|REVIEW-BACKEND:|REVIEW-EFFORT:|REVIEW-SEVERITY-CONTRACT:|REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$)'
  # Duration metadata is ALSO validated marker-independently over the
  # LEADING identity-header region only (consecutive non-blank lines
  # from the top -- the wrappers always emit a blank line after the
  # header block): the Claude wrapper's markerless artifact never
  # produces a leading fragment for the whitelist, while verdict BODY
  # prose that merely mentions the header name must never quarantine an
  # artifact. Within the region the CANDIDATE guard is deliberately
  # loose (leading whitespace, whitespace or a missing colon after the
  # name, any case) while the accepted shape is byte-exact -- a
  # mutation the candidate guard cannot see would read as clean free
  # text. At most one stamp may appear (absence is the legacy unstamped
  # shape); duplicates with conflicting values would both read as
  # trustworthy.
  # Past the separator only an UNINDENTED exact-case stamp-shaped line
  # is header-shaped (a post-separator stamp would otherwise read as
  # trusted body prose); indented or mutated body mentions stay exempt
  # as prose.
  $durStamps = 0
  $durLeading = $true
  foreach ($durLn in ($Content -split "`r?`n")) {
    if ($durLeading -and [string]::IsNullOrWhiteSpace($durLn)) { $durLeading = $false; continue }
    if ($durLeading) {
      if ($durLn -match '^\s*REVIEW-DURATION-SECS\b') {
        if ($durLn -cnotmatch '^REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$') {
          return 'a leading-region REVIEW-DURATION-SECS line violates its declared shape (exact-case name, one non-negative unpadded base-10 integer) -- malformed duration metadata, regardless of artifact shape'
        }
        $durStamps++
      }
    } elseif ($durLn -cmatch '^REVIEW-DURATION-SECS:') {
      if ($durLn -cnotmatch '^REVIEW-DURATION-SECS: (0|[1-9][0-9]*)$') {
        return 'a header-shaped REVIEW-DURATION-SECS line outside the leading region violates the stamp grammar -- malformed duration metadata'
      }
      $durStamps++
    }
  }
  if ($durStamps -gt 1) {
    return 'more than one REVIEW-DURATION-SECS stamp -- conflicting duration metadata is malformed evidence'
  }
  $lineVerdictRe = [regex]'(?im)^VERDICT:[^\r\n]*'   # case-INSENSITIVE, mirroring the wrappers' `-match '^VERDICT:'`
  # Category-block validation is UNCONDITIONAL: EVERY verdict-shaped artifact the
  # analyzer counts MUST carry the complete eight-category block, because the
  # wrapper (Get-VerdictExitCode) and dispatch-checklist (Test-VerdictBlock) both
  # reject a categoryless verdict (exit 3 / not-clean-evidence). There is NO
  # pre-category legacy exemption: this package shipped WITH the eight-category
  # format, so a categoryless `VERDICT: CLEAN` / `NON-BLOCKING` / `BLOCKER`
  # artifact is malformed (truncated or corrupt), NOT a legit historical log the
  # wrapper never saw, and must be quarantined -- admitting it would let evidence
  # the other two log-consumers reject enter the trends corpus. (An earlier port
  # carried a `$categoryEra` header/category-presence exemption; the gate flagged
  # it as admitting current malformed logs, so it was removed.)
  $catNames = @('PLAN-DRIFT','SILENT-FAILURE','TOMBSTONE-OR-SHIM','CROSS-CRATE-CONTRACT','LOADER-OR-ASSET-EDGE','CONVENTION-ADHERENCE','TEST-QUALITY','DOC-VS-CODE-DRIFT')
  # Loose category-header regex (ANY tail) shared by the invalid-tail scan below
  # and the per-block row-balance check further down. The per-category cardinality
  # check inside the segment loop uses the STRICT `none|\d+` form instead.
  $catExactRe = [regex]'(?m)^(?<cat>PLAN-DRIFT|SILENT-FAILURE|TOMBSTONE-OR-SHIM|CROSS-CRATE-CONTRACT|LOADER-OR-ASSET-EDGE|CONVENTION-ADHERENCE|TEST-QUALITY|DOC-VS-CODE-DRIFT):\s*(?<rest>.*)$'
  # [STRICTER-than-wrapper, matches dispatch-checklist Get-VerdictStructure]: NO
  # category line may carry a malformed tail (a signed / non-`\d+` value like `+1`,
  # `1.0`, `1a`, or an over-max count). The wrapper's `none|\d+` count regex is
  # BLIND to such a tail (it sees no valid count line and can return CLEAN, not
  # exit 3), but a malformed tail means the artifact is an untrustworthy DATA
  # SOURCE -- dispatch-checklist rejects it (Get-CategoryFindings would misparse
  # it), so the analyzer must reject it too or the two log-consumers disagree on
  # the corpus. Caught here as a whole-content scan (an EXTRA malformed tail
  # alongside a valid `<cat>: none` line passes the per-category cardinality check,
  # which counts only the strict-form line).
  foreach ($ctm in $catExactRe.Matches($Content)) {
    if ((Get-CategoryTailKind -Tail $ctm.Groups['rest'].Value).Kind -eq 'invalid') {
      return "a category line has a malformed tail (not none|<digits<=$($script:CategoryCountMax)>) -- untrustworthy evidence (dispatch-checklist rejects it as a misparseable data source)"
    }
  }
  $segments = [regex]::Split($Content, '(?m)^=====.*=====\s*$')
  for ($i = 0; $i -lt $segments.Count; $i++) {
    $blk = $segments[$i]
    if ($segments.Count -gt 1 -and $i -eq 0) {
      foreach ($ln in ($blk -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($ln)) { continue }
        if (-not $headerLineRe.IsMatch($ln)) {
          return 'the leading header fragment (before the first REVIEW PASS marker) has a non-header line -- a finding/verdict hidden there is malformed evidence'
        }
      }
      continue
    }
    $verdictLines = $lineVerdictRe.Matches($blk)
    if ($verdictLines.Count -ne 1) {
      return "a review-pass block has $($verdictLines.Count) VERDICT: line(s) (exactly one required -- the wrapper and dispatch-checklist fail closed on zero or duplicate)"
    }
    # Per-block verdict-word / severity COHERENCE (mirrors Get-VerdictExitCode):
    # BLOCKER present -> BLOCKED (precedence; any word, incl. malformed, is kept);
    # else QUALITY/NON-BLOCKER/NOTE present -> the word must be NON-BLOCKING; else
    # zero findings -> the word must be CLEAN. A VALID word inconsistent with the
    # findings is wrapper exit-3 evidence -- and the Claude wrapper writes it
    # banner-less (claude/auto-review.ps1 write-then-exit-3), so coherence is the
    # ONLY thing that catches a claude reject.
    # CASE-SENSITIVE severity-prefix checks (-cmatch): a lowercase `blocker:` /
    # `quality:` is NOT a finding to the wrapper's case-sensitive severity parser,
    # so it must not count as one here -- otherwise a lowercase-prefix verdict
    # passes coherence but the downstream case-sensitive extractor records zero
    # findings, and a malformed file is miscounted instead of quarantined.
    $blkHasBlocker = ($blk -cmatch '(?m)^BLOCKER:')
    if (-not $blkHasBlocker) {
      $vw = $null
      $vwm = $VerdictWordRe.Match($blk)
      if ($vwm.Success) { $vw = $vwm.Groups['v'].Value }
      if (($blk -cmatch '(?m)^QUALITY:') -or ($blk -cmatch '(?m)^NON-BLOCKER:') -or ($blk -cmatch '(?m)^NOTE:')) {
        if ($vw -ne 'NON-BLOCKING') {
          return 'a review-pass block has QUALITY/NON-BLOCKER/NOTE findings but its VERDICT is not NON-BLOCKING (wrapper-rejected incoherence)'
        }
      } elseif ($vw -ne 'CLEAN') {
        return 'a review-pass block has zero findings but its VERDICT is not CLEAN (wrapper-rejected incoherence)'
      }
    }
    # Eight-category block (mirrors Get-VerdictExitCode / Test-VerdictBlock),
    # required of EVERY non-header review-pass block (UNCONDITIONAL -- see the note
    # above the segment loop): the wrapper rejects any categoryless pass, so a
    # zero-category pass inside a multi-pass artifact, OR a bare categoryless single
    # verdict, is malformed. Each category exactly once as `none|<digits<=
    # CategoryCountMax>`, the category-count sum == this block's severity-finding-
    # line count, AND (below) each category's declared count == its indented
    # finding-row count.
    $catTotal = 0
    foreach ($cat in $catNames) {
      $cms = [regex]::Matches($blk, ('(?m)^' + [regex]::Escape($cat) + ':\s*(?<v>none|\d+)\s*$'))
      if ($cms.Count -ne 1) {
        return "a review-pass block has $($cms.Count) '$cat' category line(s) (exactly one required; the wrapper exits 3 on a missing or duplicate category -- a categoryless verdict is malformed, not legacy-exempt)"
      }
      $cv = $cms[0].Groups['v'].Value
      if ($cv -ne 'none') {
        $cparsed = 0
        if (-not [int]::TryParse($cv, [ref]$cparsed) -or $cparsed -gt $script:CategoryCountMax) {
          return "a review-pass block has an out-of-range '$cat' count (the wrapper exits 3)"
        }
        $catTotal += $cparsed
      }
    }
    $bN = ([regex]::Matches($blk, '(?m)^BLOCKER:')).Count
    $nbN = ([regex]::Matches($blk, '(?m)^QUALITY:')).Count + ([regex]::Matches($blk, '(?m)^NON-BLOCKER:')).Count + ([regex]::Matches($blk, '(?m)^NOTE:')).Count
    if ($catTotal -ne ($bN + $nbN)) {
      return "a review-pass block's category-count sum ($catTotal) != its severity-finding-line count ($($bN + $nbN)) (the wrapper exits 3 on the mismatch)"
    }
    # Row balance (mirrors Test-VerdictBlock): each `<CATEGORY>: <n>` must have
    # EXACTLY n indented finding rows -- neither fewer (UNDERFILL) nor more
    # (OVERFILL); a `none`/`0` category must have ZERO indented rows. The count-
    # sum check above catches a whole-block miscount, but NOT a per-category
    # imbalance another category compensates (e.g. `PLAN-DRIFT: 2` with 1 row
    # while a sibling over-rows to keep the sum). dispatch-checklist's
    # Get-CategoryFindings would misparse THAT, so both log-consumers reject it.
    # $inCatBlock stays set across a `none` block (declRemaining 0) so an
    # unexpected indented row under `none` is caught as overfill.
    $inCatBlock = $false
    $declRemaining = 0
    foreach ($line in ($blk -split "`r?`n")) {
      $cm = $catExactRe.Match($line)
      if ($cm.Success) {
        if ($inCatBlock -and $declRemaining -gt 0) {
          return 'a review-pass block UNDERFILLS a category (fewer indented finding rows than its declared count) -- dispatch-checklist rejects it as misparseable'
        }
        $k = Get-CategoryTailKind -Tail $cm.Groups['rest'].Value
        $inCatBlock = $true
        $declRemaining = if ($k.Kind -eq 'count') { $k.Value } else { 0 }
        continue
      }
      if ($inCatBlock) {
        if ($line -match '^\s+\S') {
          if ($declRemaining -le 0) {
            return 'a review-pass block OVERFILLS a category (more indented finding rows than its declared count) -- dispatch-checklist rejects it as misparseable'
          }
          $declRemaining--
        } elseif (-not [string]::IsNullOrWhiteSpace($line)) {
          if ($declRemaining -gt 0) {
            return 'a review-pass block UNDERFILLS a category (fewer indented finding rows than its declared count) -- dispatch-checklist rejects it as misparseable'
          }
          $inCatBlock = $false
        }
        # A blank line is tolerated inside an active block (does not end it).
      }
    }
    if ($inCatBlock -and $declRemaining -gt 0) {
      return 'a review-pass block UNDERFILLS a category at end-of-block (fewer indented finding rows than its declared count) -- dispatch-checklist rejects it as misparseable'
    }
  }
  return $null
}


# ---------------------------------------------------------------------------
# Resolve + validate EVERY configured reviews dir (fail-closed on bad input).
# ---------------------------------------------------------------------------
# Each -ReviewsDir entry becomes a scanned SOURCE (display name + files; backend
# identity is per artifact, from its own header, never from the dir).
# EXPLICIT configuration is strict: a MISSING dir, or a dir with ZERO in-window
# verdict-shaped files, aborts the run so a mispointed/empty/missing dir can
# never silently narrow coverage (drop a backend from a report that claims to
# cover it). The IMPLICIT default list degrades LOUDLY instead: a defaulted
# backend dir that is absent or empty is skipped with a note (a single-backend
# install legitimately has only one of the two), and the run fails closed only
# when no defaulted dir yields verdicts. All dir-level problems are collected
# and reported together. Duplicate dir paths are scanned once.
# EITHER representation is explicit configuration -- the CSV form must be as
# strict as the array form, or a bad CSV entry would be skipped as a default.
$reviewsDirExplicit = ($PSBoundParameters.ContainsKey('ReviewsDir') -or $PSBoundParameters.ContainsKey('ReviewsDirCsv'))
$skippedDefaultDirs = New-Object 'System.Collections.Generic.List[string]'
$cutoff = if ($SinceDays -gt 0) { (Get-Date).AddDays(-$SinceDays) } else { [DateTime]::MinValue }
# Restrict to the actual verdict naming pattern emitted by auto-review.ps1:
# `review-<YYYYMMDD>-<HHMMSS>-<scope>.md`. The wrapper composes the timestamp
# via `Get-Date -Format 'yyyyMMdd-HHmmss'` and the scope tag (commit-<sha>,
# branch-<sha>-vs-<base>, staged, uncommitted) into that exact prefix; grep
# `auto-review.ps1` for the `$verdictFile = Join-Path` site to verify the
# contract if it ever changes. Filtering by pattern (not just *.md)
# closes the silent-success-on-mispointed-dir gap that even a verdict-line
# lower bound cannot: the prompt template at scripts/codex/review-prompt-
# template.md contains literal example `BLOCKER:`, `QUALITY:`, `NOTE:`, and
# `VERDICT: CLEAN` lines, so a `-ReviewsDir scripts/codex` run would
# otherwise overwrite the trend report with prompt examples masquerading as
# verdicts. (Historical regression.) IDENTICAL to
# scripts/shared/dispatch-checklist.ps1's $verdictNameRe (mirror contract).
$verdictNameRe = [regex]'^review-\d{8}-\d{6}-.+\.md$'

$sources = New-Object 'System.Collections.Generic.List[object]'   # @{ Display; Abs; Files }
# Path identity is case-INSENSITIVE on Windows (and Resolve-Path preserves the
# caller's casing), so the dedup set compares with an OS-appropriate comparer:
# a casing-only alias must not scan the same dir twice and double every count.
$rdPathComparer = if ($env:OS -match 'Windows') { [System.StringComparer]::OrdinalIgnoreCase } else { [System.StringComparer]::Ordinal }
$seenAbs = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList @(,$rdPathComparer)
$dirErrors = New-Object 'System.Collections.Generic.List[string]'

foreach ($dirRaw in $ReviewsDir) {
  $dir = [string]$dirRaw
  if ([string]::IsNullOrWhiteSpace($dir)) {
    $dirErrors.Add('empty/blank -ReviewsDir entry') | Out-Null
    continue
  }
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
    if ($reviewsDirExplicit) {
      $dirErrors.Add("reviews directory not found: $dir") | Out-Null
    } else {
      $skippedDefaultDirs.Add("$dir (not present)") | Out-Null
    }
    continue
  }
  $abs = (Resolve-Path -LiteralPath $dir).Path
  if (-not $seenAbs.Add($abs)) { continue }   # same dir passed twice -> scan once, no error
  $files = @(Get-ChildItem -LiteralPath $abs -Filter '*.md' -File |
    Where-Object { $verdictNameRe.IsMatch($_.Name) -and $_.LastWriteTime -ge $cutoff })
  if ($files.Count -eq 0) {
    if ($reviewsDirExplicit) {
      $dirErrors.Add("no in-window verdict-shaped .md files in ${dir} (expected review-<YYYYMMDD>-<HHMMSS>-<scope>.md; cutoff $cutoff)") | Out-Null
    } else {
      $skippedDefaultDirs.Add("$dir (no in-window verdicts)") | Out-Null
    }
    continue
  }
  $sources.Add([pscustomobject]@{
    Display = $dir
    Abs     = $abs
    Files   = $files
  }) | Out-Null
}

if ($dirErrors.Count -gt 0) {
  Write-Host "[trends] ERROR: one or more configured reviews dirs are unusable (aborting rather than silently narrow coverage):"
  foreach ($e in $dirErrors) { Write-Host "[trends]   - $e" }
  exit 1
}
foreach ($sk in $skippedDefaultDirs) {
  Write-Host "[trends] note: skipping defaulted reviews dir $sk -- pass -ReviewsDir explicitly to make its absence an error"
}
if ($sources.Count -eq 0) {
  Write-Host '[trends] ERROR: no usable reviews dirs after validation (no defaulted backend dir yielded in-window verdicts):'
  foreach ($d in $ReviewsDir) { Write-Host "[trends]          $d" }
  Write-Host "[trends]        Expected pattern: review-<YYYYMMDD>-<HHMMSS>-<scope>.md; cutoff: $cutoff"
  exit 1
}

# ---------------------------------------------------------------------------
# Parse each verdict file: capture VERDICT line + per-severity findings.
# ---------------------------------------------------------------------------
# Storage shape:
#   $findings = array of @{
#     File       = <verdict shortname>
#     FileDate   = <DateTime>
#     Severity   = 'BLOCKER' | 'QUALITY' | 'NON-BLOCKER' | 'NOTE'
#     Text       = <single-line finding summary>
#     Archetype  = <classifier output>
#   }

$findings = New-Object 'System.Collections.Generic.List[object]'
# Union verdict distribution + per-backend breakdown (keyed by the header-derived backend).
# Only the three recognized verdict values -- Get-VerdictSuspectReason upstream
# rejects a file with no VERDICT line and any verdict/finding incoherence, while a
# BLOCKER gives BLOCKED precedence even over a malformed word, so every counted
# file resolves to exactly one of these three (there is no "OTHER" bucket).
$verdictCounts = @{ CLEAN = 0; 'NON-BLOCKING' = 0; BLOCKED = 0 }
$verdictCountsByBackend = @{}
# Scanned-file count per backend (header-derived; recognized fail-closed runs
# and trustworthy verdicts alike), for the report's `Backends:` provenance line.
$filesByBackend = @{}
# Recognized fail-closed exclusions per backend, so the excluded aggregate
# carries the same per-backend split the report promises for every aggregate.
$excludedByBackend = @{}
# Union file list (its .Count is the "verdicts scanned" total) + the distinct
# untrustworthy classes:
#   $excludedFailClosed -- files carrying the wrapper's own GATE FAILED CLOSED
#     banner (a SELF-DECLARED failed gate run). EXCLUDED from the report and
#     reported LOUDLY (console + a report section); they never abort the run --
#     with zero trustworthy verdicts left the report is still written as an
#     explicit no-trustworthy-verdicts report.
#     Excluding-loud (vs aborting) keeps one transient reviewer-environment
#     failure from permanently breaking full-history aggregation (a fail-closed
#     file never ages out of a no-cutoff scan).
#   $suspectFiles -- UNRECOGNIZED-malformed files (unexplained corruption). These
#     still ABORT the whole run BELOW, AFTER every dir is scanned, so one message
#     names every offender across all backends.
$reviewFiles = New-Object 'System.Collections.Generic.List[object]'
$excludedFailClosed = New-Object 'System.Collections.Generic.List[string]'
$suspectFiles = New-Object 'System.Collections.Generic.List[string]'
$oldestMtime = [DateTime]::MaxValue
$newestMtime = [DateTime]::MinValue

# Severity prefixes the analyzer recognizes. Both QUALITY (post-rewrite) and
# legacy NON-BLOCKER are parsed because the verdict log spans the rename;
# the report buckets them separately so the rename is visible in trends.
$severityRe = [regex]'(?m)^(?<sev>BLOCKER|QUALITY|NON-BLOCKER|NOTE):\s*(?<text>.*)$'
# The VERDICT regex is case-INSENSITIVE (mirroring the wrappers' `-match '^VERDICT:'`
# + case-insensitive word compare in Get-VerdictExitCode), while $severityRe above
# stays case-SENSITIVE -- the wrapper counts `^BLOCKER:` etc. case-sensitively. This
# asymmetry is the wrapper's; see Get-VerdictSuspectReason's case-policy note.
$verdictLineRe = [regex]'(?im)^VERDICT:\s*(?<v>CLEAN|NON-BLOCKING|BLOCKED)\s*$'

foreach ($src in $sources) {
  foreach ($file in $src.Files) {
    $reviewFiles.Add($file) | Out-Null
    $shortName = $file.Name
    $fileFindings = @{}  # reset per file: dedupe by normalized text, keep highest severity
    if ($file.LastWriteTime -lt $oldestMtime) { $oldestMtime = $file.LastWriteTime }
    if ($file.LastWriteTime -gt $newestMtime) { $newestMtime = $file.LastWriteTime }

    # Verdict files are written by auto-review.ps1 as UTF-8 NO BOM. Read the raw
    # BYTES and strict-decode (no-BOM, throw-on-invalid) via Read-VerdictArtifactText
    # so the fail-closed recognizer sees byte 0: a preamble-stripping
    # [System.IO.File]::ReadAllText(..., UTF8) silently consumes a BOM and would let
    # a non-producer-encoded file reach the EXCLUDE path. A BOM / invalid-UTF-8
    # reject is malformed evidence -- it takes the abort path below (suspect list),
    # never the fail-closed exclude. (Reading bytes also avoids the Get-Content -Raw
    # WinPS 5.1 ANSI-codepage mojibake on em-dash / smart-quote glyphs.)
    $decoded = Read-VerdictArtifactText -Path $file.FullName
    if (-not $decoded.Ok) {
      $suspectFiles.Add("$($src.Display)/$shortName -- encoding: $($decoded.Reason)") | Out-Null
      continue
    }
    $content = $decoded.Text
    # Producer identity from the artifact's OWN validated header
    # (Get-ArtifactBackend): a malformed value is malformed evidence, a
    # headerless historical artifact is the canonical `legacy`. The source
    # dir contributes only its display name -- never identity.
    $abInfo = Get-ArtifactBackend -Content $content
    if ($null -ne $abInfo.Reason) {
      $suspectFiles.Add("$($src.Display)/$shortName -- $($abInfo.Reason)") | Out-Null
      continue
    }
    $backend = $abInfo.Backend
    if (-not $verdictCountsByBackend.ContainsKey($backend)) {
      $verdictCountsByBackend[$backend] = @{ CLEAN = 0; 'NON-BLOCKING' = 0; BLOCKED = 0 }
    }
    if (-not $filesByBackend.ContainsKey($backend)) { $filesByBackend[$backend] = 0 }
    $filesByBackend[$backend]++

    # (1) FAIL-CLOSED self-declaration: a RECOGNIZED producer-shaped fail-closed run
    # -- Get-FailClosedBannerReason validates the WHOLE producer self-declaration over
    # the strict-decoded bytes (header + banner + diagnostic + first-suffix/terminal
    # framing), not the banner alone. EXCLUDE the file from the report and record it
    # (tagged with backend + dir + the banner's own reason line) for LOUD reporting --
    # a fail-closed run produced no trustworthy complete-run outcome, but excluding it
    # (vs aborting the WHOLE run) keeps a single transient reviewer-environment failure
    # from permanently breaking the analyzer (it scans full history by default, so a
    # fail-closed file never ages out). Checked FIRST, ABOVE Get-VerdictSuspectReason
    # (which also flags the banner, standalone, in the worker-audit inline mirror),
    # so a RECOGNIZED fail-closed run
    # takes the exclude path here; a banner file that FAILS recognition falls through
    # to the abort path below.
    $fcReason = Get-FailClosedBannerReason -Content $content
    if ($null -ne $fcReason) {
      # Tagged with the artifact's OWN header identity (the recognizer pins
      # the wrapper's exact emission), whatever directory it sits in.
      $excludedFailClosed.Add("[$backend] $($src.Display)/$shortName -- $fcReason") | Out-Null
      if (-not $excludedByBackend.ContainsKey($backend)) { $excludedByBackend[$backend] = 0 }
      $excludedByBackend[$backend]++
      continue
    }

    # (2) UNEXPLAINED corruption: a file that fails the structure contract and is NOT a
    # recognized producer-shaped fail-closed run (either bannerless -- no VERDICT line,
    # an unknown marker, a truncated pass sequence, an incoherent verdict, a malformed
    # category block, a malformed duration stamp, a wrong-case severity prefix -- OR
    # carrying the banner but with an invalid header/diagnostic/suffix/framing that
    # Get-FailClosedBannerReason above rejected). It is not a self-declared failure, so
    # it cannot be trusted or silently dropped -- the abort below names EVERY offender
    # across ALL dirs before any report is written. Applies dispatch-checklist's
    # SUPERSET trustworthiness bar (everything the wrapper's Get-VerdictExitCode
    # rejects PLUS row-balance / invalid-tail / wrong-case severity), so any verdict
    # EITHER log-consumer would reject cannot pollute the trends corpus.
    $suspectReason = Get-VerdictSuspectReason -Content $content -VerdictWordRe $verdictLineRe
    if ($null -ne $suspectReason) {
      $suspectFiles.Add("[$backend] $($src.Display)/$shortName -- $suspectReason") | Out-Null
      continue
    }

    # A verdict file may carry MULTIPLE VERDICT: lines -- auto-review.ps1's .md
    # artifact is the per-pass concatenation of every review pass (one VERDICT
    # block per pass). Take the UNION (worst) verdict for the distribution, NOT
    # the first match: a pass1-CLEAN / pass2-BLOCKED file is a BLOCKED outcome,
    # not CLEAN. A single-pass artifact has exactly one VERDICT: line and reduces
    # to the same answer. (Per-pass finding lines below are deduped per file by
    # normalized text, keeping the highest severity, so a finding that repeats
    # across passes counts once -- otherwise the multi-pass concatenation
    # inflates archetype counts and thresholds.)
    # Union (worst) verdict with wrapper BLOCKER-PRECEDENCE (Get-VerdictExitCode):
    # a BLOCKER finding forces BLOCKED even when the VERDICT word is CLEAN or
    # malformed. Every file here passed Get-VerdictSuspectReason, so it has EITHER
    # a valid-word VERDICT ($vAll non-empty) OR a BLOCKER finding -- the branches
    # are exhaustive and no unparseable "OTHER" bucket is reachable. The `^BLOCKER:`
    # test is CASE-SENSITIVE (-cmatch), matching the wrapper and the $severityRe
    # extraction below (a lowercase `blocker:` is not a finding to either).
    $vAll = @($verdictLineRe.Matches($content) | ForEach-Object { $_.Groups['v'].Value })
    if (($content -cmatch '(?m)^BLOCKER:') -or ($vAll -contains 'BLOCKED')) {
      $vbucket = 'BLOCKED'
    } elseif ($vAll -contains 'NON-BLOCKING') {
      $vbucket = 'NON-BLOCKING'
    } else {
      $vbucket = 'CLEAN'
    }
    $verdictCounts[$vbucket]++
    $verdictCountsByBackend[$backend][$vbucket]++

    foreach ($m in $severityRe.Matches($content)) {
      $sev = $m.Groups['sev'].Value
      $text = $m.Groups['text'].Value.Trim()
      if ([string]::IsNullOrWhiteSpace($text)) { continue }
      # Dedupe repeated pass findings per file by NORMALIZED finding text
      # (severity excluded from the key), keeping the HIGHEST severity seen for
      # that text across the per-pass concatenation -- so one issue surfacing in
      # multiple passes counts ONCE, and the same finding reported as BLOCKER in
      # one pass and QUALITY in another counts once at BLOCKER. Counting once per
      # pass, or once per (severity,text) pair, inflates archetype counts and
      # thresholds. IDENTICAL normalize+rank to dispatch-checklist.ps1 (mirror).
      $textKey = ($text -replace '\s+', ' ').ToLowerInvariant()
      $rank = switch ($sev) { 'BLOCKER' { 3 } 'QUALITY' { 2 } 'NON-BLOCKER' { 2 } 'NOTE' { 1 } default { 0 } }
      if (-not $fileFindings.ContainsKey($textKey) -or $fileFindings[$textKey].Rank -lt $rank) {
        $fileFindings[$textKey] = @{ Sev = $sev; Text = $text; Rank = $rank }
      }
    }

    foreach ($ff in $fileFindings.Values) {
      $arch = Get-FindingArchetype -Text $ff.Text
      $findings.Add([pscustomobject]@{
        File      = $shortName
        FileDate  = $file.LastWriteTime
        Severity  = $ff.Sev
        Text      = $ff.Text
        Archetype = $arch
        Backend   = $backend
      }) | Out-Null
    }
  }
}

# ---------------------------------------------------------------------------
# LOUD console notice for EXCLUDED fail-closed runs (self-declared GATE FAILED
# CLOSED banners) -- emitted BEFORE the unrecognized-malformed abort below, so a
# MIXED input (a fail-closed file AND an unrecognized-malformed file) still NAMES
# the excluded fail-closed runs even though the run then aborts on the malformed
# file (an abort before this notice silently lost the recognized fail-closed
# runs). On the success path the excluded set is ALSO written into a dedicated
# report section (below), so the exclusion is visible in BOTH channels.
# ---------------------------------------------------------------------------
if ($excludedFailClosed.Count -gt 0) {
  Write-Host "[trends] EXCLUDED $($excludedFailClosed.Count) fail-closed run(s) from the report (self-declared GATE FAILED CLOSED -- a failed gate run with no trustworthy complete-run outcome, typically a transient reviewer-environment failure):"
  foreach ($e in $excludedFailClosed) { Write-Host "[trends]   - $e" }
}

# ---------------------------------------------------------------------------
# Fail-closed abort on ANY UNRECOGNIZED-malformed evidence, across ALL scanned
# dirs -- BEFORE emitting a report. Names every offender so it can be quarantined
# (moved out of the scanned dir) or repaired. UNRECOGNIZED-malformed evidence is not
# a self-declared failure, so it is neither counted nor silently dropped: it aborts
# the whole run. (Get-VerdictSuspectReason.) Only a RECOGNIZED producer-shaped
# fail-closed run is handled separately ($excludedFailClosed) -- EXCLUDED loudly
# (named above), not aborted; a bannered file the recognizer REJECTED lands here.
# ---------------------------------------------------------------------------
if ($suspectFiles.Count -gt 0) {
  Write-Host "[trends] ERROR: $($suspectFiles.Count) scanned verdict file(s) are UNRECOGNIZED-malformed (fail the structure contract and are not a recognized fail-closed run -- e.g. no VERDICT line, an unknown marker, an incoherent verdict, a malformed duration stamp, a wrong-case severity prefix, a byte-order mark or invalid UTF-8 encoding, or a GATE FAILED CLOSED banner that does not match the wrapper's exact emission); refusing to write a report that would silently drop or miscount them:"
  foreach ($s in $suspectFiles) { Write-Host "[trends]   - $s" }
  Write-Host "[trends]        Quarantine (move out of the scanned dir) or repair the file(s), then re-run."
  exit 1
}

# ---------------------------------------------------------------------------
# Fail-closed lower bound on parseable verdicts (final backstop).
# ---------------------------------------------------------------------------
# Even with every file individually non-suspect, require at least one recognized
# `VERDICT:` line OR at least one severity prefix across the ENTIRE input set. A
# mispointed dir full of non-verdict markdown that somehow slipped the filename
# filter would otherwise produce a zero-finding "trend report" that overwrites
# the docs/blocker-trends.md output. If neither is present, fail closed instead of
# writing a silently-empty report. (Historical regression.)
$sourceDisplays = ($sources | ForEach-Object { $_.Display }) -join ', '
$parseableVerdicts = $verdictCounts.CLEAN + $verdictCounts['NON-BLOCKING'] + $verdictCounts.BLOCKED
$noTrustworthy = $false
if ($parseableVerdicts -eq 0 -and $findings.Count -eq 0) {
  if ($excludedFailClosed.Count -gt 0) {
    # Every selected verdict was a RECOGNIZED fail-closed run. Under the
    # campaign's cutover a recognized run never aborts the run, so the report
    # is still written -- as an explicit NO-TRUSTWORTHY-VERDICTS report (exit
    # 0) that names every exclusion and carries zero counts by construction,
    # the same shape dispatch-checklist emits. Only a window with NO recognized
    # exclusions and no parseable evidence is a mispointed input and refuses.
    $noTrustworthy = $true
    Write-Host "[trends] NO TRUSTWORTHY VERDICTS in ${sourceDisplays}: every scanned file was a recognized fail-closed run ($($excludedFailClosed.Count) excluded, named above); writing the explicit no-trustworthy-verdicts report."
  } else {
    Write-Host "[trends] ERROR: scanned $($reviewFiles.Count) verdict-shaped file(s) in $sourceDisplays but found zero recognized VERDICT: lines and zero severity-prefixed findings."
    Write-Host "[trends]        The input does not appear to contain review verdicts (codex or claude backend)."
    Write-Host "[trends]        Refusing to overwrite '$OutPath' with an empty trend report."
    exit 1
  }
}

# ---------------------------------------------------------------------------
# Emit the markdown report.
# ---------------------------------------------------------------------------

$timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
$dateRange = "{0:yyyy-MM-dd} to {1:yyyy-MM-dd}" -f $oldestMtime, $newestMtime

# Distinct backend identities (header-derived, exact producer values), sorted for
# deterministic output. When more than one, the report carries per-backend
# provenance -- a per-backend split on every aggregate count + a [backend] tag
# on every exemplar -- ALONGSIDE the union totals. With a single backend the
# union lines keep their legacy labels (no '(union...)' suffix, no split).
$backends = @($filesByBackend.Keys | Sort-Object)
$multiBackend = $backends.Count -gt 1

# Wrap each Where-Object result in @() so an empty result is an empty
# array (whose .Count is 0) rather than $null (whose .Count evaluates to
# nothing and prints as blank in the wrapper log line).
$blockerCount = @($findings | Where-Object { $_.Severity -eq 'BLOCKER' }).Count
$qualityCount = @($findings | Where-Object { $_.Severity -eq 'QUALITY' }).Count
$legacyNbCount = @($findings | Where-Object { $_.Severity -eq 'NON-BLOCKER' }).Count
$noteCount = @($findings | Where-Object { $_.Severity -eq 'NOTE' }).Count

# Per-backend severity tallies for the per-backend provenance sub-lines.
$sevByBackend = @{}
foreach ($b in $backends) { $sevByBackend[$b] = @{ BLOCKER = 0; QUALITY = 0; 'NON-BLOCKER' = 0; NOTE = 0 } }
foreach ($f in $findings) {
  if ($sevByBackend.ContainsKey($f.Backend) -and $sevByBackend[$f.Backend].ContainsKey($f.Severity)) {
    $sevByBackend[$f.Backend][$f.Severity]++
  }
}

$sb = [System.Text.StringBuilder]::new()
# ONE stable title across single- and cross-backend runs: author-lint.ps1 keys
# its generated-report exemption on the `# Cross-review BLOCKER Trends Report`
# title AND on a `^Source:\s.*verdict` head line (so LINE-ANCHOR/DEAD-REF do NOT
# run against this machine-emitted report's file:line exemplar text). Keep both
# signatures byte-stable; the per-backend split lives in the body lines below,
# never in the title.
[void]$sb.AppendLine('# Cross-review BLOCKER Trends Report')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("Generated: $timestamp")
[void]$sb.AppendLine("Source: $($reviewFiles.Count) verdict files across $($sources.Count) reviews dir(s): $(($sources | ForEach-Object { '`' + $_.Display + '`' }) -join ', ')")
# Backend identity is each artifact's own REVIEW-BACKEND header (headerless
# historical artifacts count as `legacy`), never the directory spelling.
$backendParts = $backends | ForEach-Object { "$_ = $($filesByBackend[$_])" }
[void]$sb.AppendLine("Backends (from each artifact's REVIEW-BACKEND header; headerless = legacy): $($backendParts -join ', ')")
if ($skippedDefaultDirs.Count -gt 0) {
  [void]$sb.AppendLine("(skipped defaulted dir(s): $($skippedDefaultDirs -join ', '))")
}
[void]$sb.AppendLine("Date range (file mtime): $dateRange")
$unionNote = if ($multiBackend) { ' (union across backends)' } else { '' }
[void]$sb.AppendLine("Verdict distribution: CLEAN=$($verdictCounts.CLEAN), NON-BLOCKING=$($verdictCounts['NON-BLOCKING']), BLOCKED=$($verdictCounts.BLOCKED)$unionNote")
if ($multiBackend) {
  foreach ($b in $backends) {
    $vb = $verdictCountsByBackend[$b]
    [void]$sb.AppendLine("  - ${b}: CLEAN=$($vb.CLEAN), NON-BLOCKING=$($vb['NON-BLOCKING']), BLOCKED=$($vb.BLOCKED)")
  }
}
[void]$sb.AppendLine("Total findings: BLOCKER=$blockerCount, QUALITY=$qualityCount, legacy NON-BLOCKER=$legacyNbCount, NOTE=$noteCount$unionNote")
if ($multiBackend) {
  foreach ($b in $backends) {
    $sbk = $sevByBackend[$b]
    [void]$sb.AppendLine("  - ${b}: BLOCKER=$($sbk.BLOCKER), QUALITY=$($sbk.QUALITY), legacy NON-BLOCKER=$($sbk['NON-BLOCKER']), NOTE=$($sbk.NOTE)")
  }
}
if ($noTrustworthy) {
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('> NO TRUSTWORTHY VERDICTS IN WINDOW.')
  [void]$sb.AppendLine("> All $($reviewFiles.Count) verdict-shaped file(s) were recognized fail-closed runs and were")
  [void]$sb.AppendLine('> excluded (see the excluded section below). Every VERDICT and FINDING count in this')
  [void]$sb.AppendLine('> report is zero by construction (the scanned-file, backend-source, and excluded-run')
  [void]$sb.AppendLine('> counts above are not) -- this is NOT evidence of zero defect classes and NOT a clean')
  [void]$sb.AppendLine('> codebase.')
  [void]$sb.AppendLine('> Re-run after the failed gate runs are retried, or widen the window.')
}
[void]$sb.AppendLine('')
# LOUD excluded-fail-closed section (self-declared GATE FAILED CLOSED banners).
# Sorted for deterministic output. The reason is the wrapper's own single-line
# diagnostic (control text from auto-review.ps1, not model finding prose).
if ($excludedFailClosed.Count -gt 0) {
  [void]$sb.AppendLine("## Excluded fail-closed runs ($($excludedFailClosed.Count))")
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($excludedFailClosed.Count) scanned verdict-shaped file(s) carried the wrapper's own")
  [void]$sb.AppendLine('`===== GATE FAILED CLOSED =====` banner -- a SELF-DECLARED failed gate run that')
  [void]$sb.AppendLine('produced no trustworthy complete-run outcome (typically a transient reviewer-')
  [void]$sb.AppendLine('environment failure, normally retried successfully). Each is EXCLUDED from the')
  [void]$sb.AppendLine('trend counts; excluding them loudly (vs aborting the whole run) keeps one such')
  [void]$sb.AppendLine('failure from permanently breaking full-history aggregation. This is NOT a silent')
  [void]$sb.AppendLine('drop.')
  [void]$sb.AppendLine('')
  if ($multiBackend) {
    $exParts = $backends | ForEach-Object { $exN = if ($excludedByBackend.ContainsKey($_)) { $excludedByBackend[$_] } else { 0 }; "$_ = $exN" }
    [void]$sb.AppendLine("Per backend: $($exParts -join ', ')")
    [void]$sb.AppendLine('')
  }
  foreach ($e in ($excludedFailClosed | Sort-Object)) {
    [void]$sb.AppendLine("- $e")
  }
  [void]$sb.AppendLine('')
}
[void]$sb.AppendLine('## Purpose')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('This report exists to reduce REPEAT-CLASS BLOCKERs by improving worker')
[void]$sb.AppendLine('discipline upstream. It is NOT a review-throughput metric. Use it to')
[void]$sb.AppendLine('identify archetypes worth folding into worker dispatch templates,')
[void]$sb.AppendLine('AGENTS.md, the review prompt''s hazards section, or an anti-pattern')
[void]$sb.AppendLine('guide. The classifier follows the same "one primary category per')
[void]$sb.AppendLine('finding" discipline as the review prompt template, so archetypes here')
[void]$sb.AppendLine('are directly comparable to the prompt''s category enumeration.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('This archetype report does not measure token cost or time-to-merge; use existing usage and operation records for those measures.')
[void]$sb.AppendLine('Quality and correctness take priority; eliminate low-value repetition without weakening mandatory cross-review or necessary coverage.')
[void]$sb.AppendLine('')

function Write-ArchetypeSection {
  param(
    [string]$Title,
    [string]$Severity,
    [System.Collections.Generic.List[object]]$All,
    [string[]]$Backends,
    [bool]$MultiBackend
  )
  # @() wrap so a single-result bucket stays an array; without it
  # PowerShell 5.1 returns a scalar PSObject whose .Count evaluates to
  # the wrong value (blank in the section header). Same defect pattern
  # as the top-level severity counts above. (Historical regression.)
  $bucket = @($All | Where-Object { $_.Severity -eq $Severity })
  [void]$sb.AppendLine("---")
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("## $Title ($($bucket.Count) findings)")
  [void]$sb.AppendLine('')
  if ($bucket.Count -eq 0) {
    [void]$sb.AppendLine('_(none)_')
    [void]$sb.AppendLine('')
    return
  }
  # Group by archetype, sort by count desc, then by archetype name asc
  # so equal-count groups have a stable order (without the secondary
  # key, group order depends on PowerShell/filesystem ordering and the
  # generated report churns across runs). The hashtable-expression
  # form is the PowerShell idiom for multi-key sort.
  $byArch = $bucket | Group-Object -Property Archetype | Sort-Object `
    @{ Expression = 'Count'; Descending = $true }, `
    @{ Expression = 'Name';  Descending = $false }
  foreach ($g in $byArch) {
    $arch = $g.Name
    $entries = $g.Group | Sort-Object -Property FileDate -Descending
    $newest = $entries[0].FileDate.ToString('yyyy-MM-dd')
    $oldest = $entries[-1].FileDate.ToString('yyyy-MM-dd')
    # Per-backend split on the archetype count (multi-backend only): which
    # backend contributed how many of this archetype's findings -- provenance
    # alongside the union $($g.Count).
    $split = ''
    if ($MultiBackend) {
      $splitParts = foreach ($b in $Backends) {
        $bc = @($g.Group | Where-Object { $_.Backend -eq $b }).Count
        "${b}=$bc"
      }
      $split = " ($($splitParts -join ', '))"
    }
    [void]$sb.AppendLine("### $arch -- $($g.Count) findings$split")
    [void]$sb.AppendLine("Newest: $newest. Oldest: $oldest.")
    [void]$sb.AppendLine('')
    $examples = $entries | Select-Object -First 5
    [void]$sb.AppendLine('Top examples (most recent first):')
    foreach ($e in $examples) {
      $dateStr = $e.FileDate.ToString('yyyy-MM-dd')
      # [backend] provenance tag: which backend's verdict this exemplar came from.
      [void]$sb.AppendLine("- [$($e.Backend)] ``$($e.File)`` [$dateStr]: $($e.Text)")
    }
    if ($g.Count -gt 5) {
      [void]$sb.AppendLine("_(+$($g.Count - 5) more)_")
    }
    [void]$sb.AppendLine('')
  }
}

Write-ArchetypeSection -Title 'BLOCKER archetype clusters (most frequent first)' -Severity 'BLOCKER' -All $findings -Backends $backends -MultiBackend $multiBackend
Write-ArchetypeSection -Title 'QUALITY findings (post-rewrite severity tier)' -Severity 'QUALITY' -All $findings -Backends $backends -MultiBackend $multiBackend
Write-ArchetypeSection -Title 'Legacy NON-BLOCKER findings (pre-rewrite)' -Severity 'NON-BLOCKER' -All $findings -Backends $backends -MultiBackend $multiBackend
Write-ArchetypeSection -Title 'NOTE findings (informational, non-gating)' -Severity 'NOTE' -All $findings -Backends $backends -MultiBackend $multiBackend

[void]$sb.AppendLine("---")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Methodology')
[void]$sb.AppendLine('')
$cutoffNote = if ($SinceDays -gt 0) {
  " whose file mtime is within the last $SinceDays days (``-SinceDays $SinceDays``)"
} else {
  ' (no mtime cutoff; the full history is in scope)'
}
$methodSources = ($sources | ForEach-Object { '`' + $_.Display + '`' }) -join ', '
[void]$sb.AppendLine("Source: ``*.md`` files under $methodSources whose name matches")
[void]$sb.AppendLine('the verdict-shape pattern `review-<YYYYMMDD>-<HHMMSS>-<scope>.md` (this is')
[void]$sb.AppendLine('the exact prefix the review wrappers emit, so the filter excludes')
[void]$sb.AppendLine("non-verdict markdown that may happen to live in a directory)$cutoffNote.")
[void]$sb.AppendLine('Each selected file is a Codex or Claude review verdict (the analyzer treats')
[void]$sb.AppendLine('both backends identically; the verdict format is shared) and its backend is')
[void]$sb.AppendLine('read from its own REVIEW-BACKEND header (a headerless historical artifact')
[void]$sb.AppendLine('counts as `legacy`; the directory name is never identity). The analyzer')
[void]$sb.AppendLine('extracts finding lines matched by the regex')
[void]$sb.AppendLine('`^(BLOCKER|QUALITY|NON-BLOCKER|NOTE):` and classifies the one-line summary')
[void]$sb.AppendLine('into an archetype via a most-specific-first keyword list (see')
[void]$sb.AppendLine('`scripts/shared/analyze-blocker-trends.ps1` for the keyword sets). Findings')
[void]$sb.AppendLine('repeated across review passes within one file are deduped by normalized')
[void]$sb.AppendLine('text (highest severity kept) -- the same filename-shape and per-file dedupe')
[void]$sb.AppendLine('primitives as `scripts/shared/dispatch-checklist.ps1` (mirror contract).')
[void]$sb.AppendLine('')
if ($multiBackend) {
  [void]$sb.AppendLine('Cross-backend: every aggregate count carries a per-backend split and every')
  [void]$sb.AppendLine('exemplar a `[backend]` tag, alongside the UNION totals (the union is the')
  [void]$sb.AppendLine('sum across all scanned backends, aggregated into this one report).')
  [void]$sb.AppendLine('')
}
[void]$sb.AppendLine('Fail-closed: an explicitly configured reviews dir that is missing, or has no')
[void]$sb.AppendLine('in-window verdicts, aborts the run (a missing/empty dir must not silently')
[void]$sb.AppendLine('narrow coverage); a DEFAULTED backend dir that is absent or empty is skipped')
[void]$sb.AppendLine('with a note instead, and the run aborts only when no defaulted dir yields')
[void]$sb.AppendLine('verdicts. A verdict carrying the wrapper''s own `GATE FAILED CLOSED` banner is')
[void]$sb.AppendLine('a self-declared failed gate run; it is EXCLUDED from the counts and, when any are')
[void]$sb.AppendLine('present, listed in an "Excluded fail-closed runs" section (excluding it loudly')
[void]$sb.AppendLine('keeps one transient failure from permanently breaking full-history aggregation);')
[void]$sb.AppendLine('if EVERY selected verdict is excluded, the report is still written with an explicit')
[void]$sb.AppendLine('NO-TRUSTWORTHY-VERDICTS banner (exit 0), never as clean evidence.')
[void]$sb.AppendLine('An UNRECOGNIZED-malformed verdict (unexplained corruption) in ANY scanned dir still')
[void]$sb.AppendLine('aborts and names the offender rather than counting or dropping it.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('A populated `UNCLASSIFIED` bucket is a signal that the keyword list')
[void]$sb.AppendLine('needs to grow. Treat that section as "next archetypes to name."')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Re-run with `-SinceDays <N>` to scope to a recent window, or pass multiple')
[void]$sb.AppendLine('dirs for a cross-backend report (`-ReviewsDir` as an in-process array, or')
[void]$sb.AppendLine('`-ReviewsDirCsv a,b` from a native `-File` invocation).')

# Ensure output directory exists.
$outDir = Split-Path -Parent -Path $OutPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir -PathType Container)) {
  New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$outAbs = if ([System.IO.Path]::IsPathRooted($OutPath)) {
  $OutPath
} else {
  Join-Path (Get-Location) $OutPath
}

try {
  [System.IO.File]::WriteAllText($outAbs, $sb.ToString(), $utf8NoBom)
} catch {
  Write-Host "[trends] ERROR: failed to write report to $outAbs : $_"
  exit 1
}

Write-Host "[trends] wrote report to $outAbs"
Write-Host "[trends]   verdicts scanned: $($reviewFiles.Count)"
Write-Host "[trends]   total findings:   BLOCKER=$blockerCount  QUALITY=$qualityCount  legacy NON-BLOCKER=$legacyNbCount  NOTE=$noteCount"
exit 0
