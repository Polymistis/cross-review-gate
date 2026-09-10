# Per-worker process audit for ONE branch landing.
#
# The operator mandate (2026-07): workers burn too many gate rounds, so every
# agent's LANDING PROCESS must be audited automatically. This script turns the
# review-verdict artifacts a branch produced (commit-gate + merge-gate) into a
# per-worker process report: how many gate rounds each landed commit took, which
# reviewer categories recurred across consecutive blocking rounds (the single-
# instance-fix signal), the first-attempt-CLEAN rate, the batching shape (commits
# / files-per-commit), the merge-gate round count, and (when a status.json is
# provided) the escalations recorded. It is ARTIFACT-BASED ONLY -- it reads git
# history and the verdict logs; it has NO dependency on the orchestrator harness,
# a plugin, or a live worker.
#
# CORRELATION MODEL (read this before reading a report -- the precision differs
# per row and the report states it honestly):
#   The branch's commits are `git rev-list <mergeBase>..<tip>`. Each verdict
#   artifact carries a `REVIEW-TREE-OID:` header (auto-review.ps1 stamps the
#   reviewed tree OID as header line 2; for a Staged commit-gate review it is the
#   `git write-tree` of the index, which EQUALS the resulting commit's tree, and
#   for a Branch merge-gate review it is `<tip>^{tree}`). Correlation uses that
#   OID as the PRIMARY key -- EXACT on tree identity, but a git tree is NOT
#   branch-scoped, so its AUTHORITY differs per row (see below):
#     * COMMIT-GATE PASSING ROUND (TREE-MATCHED -- exact tree, NOT branch-scoped):
#       a `staged`-scope verdict (the pre-commit gate's ONLY scope) whose
#       REVIEW-TREE-OID equals a branch commit's tree OID AND whose union outcome
#       is a PASS (CLEAN, NOTE-only, or contract-stamped QUALITY -- the era-aware
#       class) is that commit's passing round. The match is
#       EXACT on TREE identity, but a git tree is NOT branch-scoped: an unrelated
#       branch that produced the SAME tree (an identical change, a revert, a rebase)
#       whose `staged` PASS verdict landed in the shared central logs is
#       INDISTINGUISHABLE and would be credited to this commit. A concurrent branch
#       USUALLY has a different tree, but identical trees across branches ARE
#       possible, so this is a TREE match, not branch provenance. Git trees are also
#       NOT unique per commit (a revert/rebase can duplicate a tree), so a
#       shared-tree PASS verdict is assigned ONCE to the closest-in-time commit; a
#       duplicate-tree sibling stays unmatched unless it has its own distinct
#       verdict. (`uncommitted` / `commit-<sha>` verdicts are MANUAL spot-checks --
#       not the gate -- and are excluded from gate-round counts.)
#     * MERGE-GATE ROUND: a `branch-<tip>-vs-<base>` verdict whose filename <tip>
#       prefixes a branch commit SHA AND whose <base> matches the audited base
#       (Test-BaseMatch: a 12-hex base token prefixes $facts.BaseSha, or a legacy
#       ref-name base equals $facts.BaseRef) is a merge round for this branch. The
#       base match is REQUIRED: a same-tip verdict reviewed against a DIFFERENT base
#       (stale pre-rebase, or a manual spot-check against another base) reviewed a
#       different diff and is NOT this landing's round -- tip-only matching would
#       inflate the count. (The review artifacts still carry no gate-vs-manual
#       provenance, so a MANUAL `-Scope Branch` spot-check of the SAME tip AND base
#       is indistinguishable from a real merge round and would also count -- a known
#       limit absent a stamped gate marker; such same-tip-and-base manual
#       spot-checks are rare.) When the
#       verdict carries a `REVIEW-TREE-OID` header (every MODERN verdict does) that
#       OID is CROSS-CHECKED against the matched commit's tree, so the match is
#       exact; a LEGACY headerless merge verdict is matched on the 12+-hex filename
#       tip + the filename base (Test-BaseMatch), WITHOUT the tree-OID cross-check (a
#       prefix collision with an unrelated branch SHA is astronomically unlikely but
#       the tree is NOT OID-verified). Every wrapper child
#       stamps its OWN `Get-Date` timestamp, so one attempt's artifacts
#       can differ by seconds; rounds are therefore grouped by (matched tip,
#       base) then CLUSTERED
#       by launch time -- NOT keyed on the filename stem -- so one attempt's
#       concurrently-launched artifacts merge (worst class wins) while a same-tip
#       RE-RUN (a separate auto-merge invocation) stays a distinct round: it trips
#       either the launch-time gap (a re-run minutes later) OR a repeated
#       (backend, child) MEMBER identity (a second SAME-member artifact for
#       this tip/base reads as a new attempt, catching a same-member fast
#       rerun inside the launch window). Any cross-backend fold is
#       UNDECIDABLE (one historical both-provider attempt vs two single-
#       provider reruns, no gate-run identifier) and is MARKED ambiguous-
#       clustering, non-authoritative, instead of counted. Single-provider
#       panel support (2026-07-22 gate): a claude panel emits one artifact PER
#       child with a reserved `-p<n>`/`-fb<n>` -ArtifactTag suffix. Whether a
#       trailing child-shaped token IS a child tag is resolved against GROUND
#       TRUTH, not metadata (Get-VerdictScope + the consumer selection): the
#       whole-suffix reading wins when it matches the audited tip+base, the
#       split reading only when the whole does not match and the split does
#       -- so a hex-shaped legacy ref like `deadbeef-p2` that names the
#       audited base stays one ref, and a tagged modern name still
#       split-matches. The member-identity
#       repeat-split keeps tagged same-backend siblings one attempt (an
#       UNTAGGED panel from a base wrapper predating the tag still
#       over-splits -- accepted degradation for the migration landings).
#       A run that exhausted its token pool writes a same-stem
#       `.exhaustion.json` sidecar -- a FORENSIC record ONLY (split-on-
#       subsystem ruling 2026-07-23): it grants no authority, so a
#       fail-closed exhaustion artifact stays SUSPECT
#       evidence handled by the FAIL-LOUD REPORT contract (the report is
#       emitted, led by the suspect section, statistics marked UNRELIABLE --
#       see the suspect handling below). The one decision a sidecar drives
#       is NEGATIVE (gate BLOCKER 2026-07-24): a filename matching the
#       audited tip/base identity -- same-stem `.md` or not, pairing being
#       unverifiable without run identity -- WITHHOLDS round authority
#       from every same-identity merge artifact, whatever its backend label
#       (headerless legacy included), launched within the
#       sidecar's panel clustering window (a later retry outside the window
#       keeps authority), listed in the report lead; it can demote, never
#       grant, and its presence proves NOTHING positive -- neither that
#       exhaustion occurred nor that any fallback panel ran (the quarantine
#       contract at the $exhaustedPanelSidecars declaration). Audit-side supersession is owned by
#       the verdict-artifact framing migration follow-up -- its
#       parent-generated run IDs and
#       producer-owned terminal panel receipt are the infrastructure that
#       makes supersession sound; nothing here may re-add it without them.
#       Consumer-first migration caveat: the post-merge audit
#       auto-merge runs is a TRUSTED pre-landing copy (the merge base's,
#       else the manifest-verified local snapshot), so the landing that
#       introduces these shapes is itself audited by the pre-shape
#       consumer -- a transient NON-GATING degradation.
#     * COMMIT-GATE ABORTED ROUND (the documented FALLBACK -- window-attributed,
#       NOT OID-verifiable): a pre-CLEAN blocking commit-gate verdict (union
#       outcome BLOCKER or QUALITY) was reviewing a staged tree that NEVER became
#       a commit (the worker fixed the finding and re-staged), so it has NO landed
#       commit tree to OID-match. These are attributed to the landed commit whose
#       commit-time window they fall in: for the i-th branch commit (oldest
#       first), the window is OPEN at both ends, (C_{i-1}.committerTime,
#       C_i.committerTime), with C_0's lower bound = the merge-base commit
#       time; an artifact stamped in the same second as either edge is a
#       BOUNDARY-SECOND artifact (whole-second clocks leave its order against
#       that commit unknowable) -- attributed to no window, listed on the
#       adjacent rows, and marking the counts INCOMPLETE. The BLOCKED/QUALITY class
#       filter alone excludes passing rounds (a PASS verdict is never blocking), so
#       NO tree-match exclusion is applied: a blocking verdict whose tree LATER
#       lands via a hook bypass is kept as bypass evidence, not dropped. Because the
#       attribution is purely by time window, a
#       CONCURRENT worker's blocking commit-gate review that landed in the same
#       window is indistinguishable and may be counted. Each commit's row is
#       therefore tagged with a CONFIDENCE: `tight` when the window is flanked by
#       an OID-matched passing round on BOTH ends (this commit AND its predecessor
#       landed with an OID-matched commit-gate verdict on this branch), else
#       `loose` (a window endpoint is not OID-anchored -- the first branch commit,
#       or any commit following a commit that has no OID-matched verdict, e.g. a
#       REBASED commit whose tree the commit hook never saw -- so concurrent
#       verdicts may inflate the count). ABORTED rounds carry the WEAKEST evidence:
#       they are ALWAYS window-attributed by time and the artifacts carry NO
#       gate/branch provenance, so even a `tight` (OID-flanked) interval CAN hold a
#       concurrent worker's blocked staged review. Tight aborted rounds are the
#       NARROWER upper bound, loose ones the WIDER upper bound -- bounds only
#       while every in-window artifact was readable and well-formed; with
#       unreadable or malformed in-window evidence present the counts may be
#       UNDERSTATED and the report labels them INCOMPLETE, not bounds. Of the correlated
#       counts, ONLY the tip-matched merge rounds are branch-scoped AUTHORITATIVE
#       (their `<tip>-vs-<base>` filename names a branch commit + the audited base);
#       the OID-matched passing rounds are TREE-MATCHED -- exact tree, but NOT
#       branch-scoped (a same-tree PASS from another branch in the shared logs is
#       indistinguishable). First-attempt-CLEAN and repeat-category, derived from
#       aborted rounds, are BEST-EFFORT (tight = narrower estimate). The report
#       prints the confidence per row and a global precision note. OID-matched
#       passing rounds are EXACT on tree identity, and merge rounds whose verdict
#       carries the tree-OID header (all modern verdicts) are tree-cross-checked too
#       -- a legacy headerless merge round rests on the tip + filename-base match,
#       without the tree-OID cross-check.
#     * ATTEMPT GROUPING: a REVIEW_BACKEND=both gate run writes one artifact PER
#       BACKEND (codex + claude) for the SAME reviewed tree. The pre-commit hook
#       runs the backends in SERIES (Codex first, Claude only after Codex passes),
#       so the two same-tree artifacts can be MINUTES apart -- commit-gate artifacts
#       are therefore bucketed by their shared REVIEW-TREE-OID (NOT a launch-time
#       cluster). WITHIN a tree bucket, artifacts fold (in time order) into the
#       current attempt until a backend REPEATS OR the current attempt is already
#       BLOCKED/QUALITY. The fold decision is PRODUCER-CONTRACT CARDINALITY,
#       never elapsed time (one pre-commit invocation emits at most TWO
#       valid same-tree artifacts; the derivation lives at the
#       Group-CommitGateAttempts fold predicate): a same-backend repeat onto
#       a ONE-artifact PASS attempt is inside the one-invocation fallback
#       space -> UNDECIDABLE -> folded and MARKED ambiguous, then EXCLUDED
#       from correlation entirely (signal-only listing; the category union
#       keeps every same-tree pass). Any artifact onto a TWO-artifact
#       attempt, or after a BLOCKED/QUALITY attempt (the short-circuit --
#       Claude never follows a failed Codex), is a DEFINITE rerun ->
#       authoritative split; a re-run's later PASS is never collapsed into
#       an earlier BLOCKED. MERGE rounds, whose panel children ARE launched
#       concurrently, group by (matched tip, base) + a launch-time cluster
#       with a SAME-member repeat split AND a same-backend ROLE-change split
#       (p*/fb*/untagged -- one merge invocation applies one uniform role
#       per backend and always switches backend on fallback); any
#       cross-backend fold is marked ambiguous-clustering (see above).
#
# MIRROR CONTRACT (keep in lock-step; dot-sourcing is deliberately NOT used):
#   This script RE-EXPRESSES several primitives from
#   scripts/shared/analyze-blocker-trends.ps1 (and, transitively, the wrapper
#   contract in scripts/codex/auto-review.ps1 / scripts/shared/auto-merge.ps1), with a provenance comment
#   pinning each to its source:
#     * $verdictNameRe -- the `review-<YYYYMMDD>-<HHMMSS>-<scope>.md` filename
#       shape guard, BYTE-IDENTICAL to analyze-blocker-trends.ps1 / dispatch-
#       checklist.ps1.
#     * Get-ArtifactBackend (+ its $abCandidateRe / $abEffortByBackend) -- the
#       producer identity reader: the artifact's OWN validated header block,
#       graded as the wrappers' exact ordered header eras, BYTE-IDENTICAL to the
#       analyzer's. A directory name is caller spelling, never provenance.
#     * Read-VerdictArtifactText -- the strict no-BOM UTF-8 decode boundary,
#       BYTE-IDENTICAL to the analyzer's; a rejected decode is unreadable
#       evidence, never a silently laundered string.
#     * Get-VerdictSuspectReason -- the fail-closed per-file suspect check,
#       BYTE-IDENTICAL to the analyzer's (the analyzer in turn mirrors the
#       wrapper's Get-VerdictExitCode per-pass
#       contract + the dispatch-checklist marker-sequence / block-structure
#       checks). Fail-closed / malformed / unreadable-branch-scope verdict
#       evidence that this audit would otherwise MISCOUNT leads the report as
#       a correlated suspect (fail-loud report contract), never counted.
#     * The severity-prefix + VERDICT-line regexes and the per-file union
#       (BLOCKER-precedence) verdict classification, from the analyzer's parse
#       loop and auto-merge.ps1's Get-VerdictExitCode.
#   Dot-sourcing analyze-blocker-trends.ps1 is NOT viable (it runs its full report
#   pipeline and `exit`s on load), so the primitives are inlined here. A shared
#   library is a recorded FUTURE refactor -- deliberately NOT done here. Any change
#   to the filename / suspect / classification conventions in the analyzer must be
#   mirrored here (and vice-versa); they are kept identical, not forked.
#
# FAIL-LOUD (never silently miscount evidence this audit relies on):
#   A fail-closed (`===== GATE FAILED CLOSED =====` banner) or otherwise MALFORMED
#   (per Get-VerdictSuspectReason) verdict that RELIABLY belongs to this branch --
#   its REVIEW-TREE-OID matches a branch commit tree (NOT the fork-point base tree --
#   the base's own staged verdict gated the base commit, outside merge-base..branch),
#   OR it is a merge verdict
#   whose filename tip NAMES a branch commit SHA *and* whose reviewed base matches
#   the audited base (Test-BaseMatch) -- is a CORRELATED SUSPECT: the report is
#   still EMITTED, but it is LED by a prominent suspect section naming each
#   offender (possible gate bypass or failed gate run -- verify manually) and
#   every count/statistic section is marked UNRELIABLE while any suspect
#   exists. Suspects stay excluded from the counts (they are not valid
#   verdicts); the alarm lives in the report's lead, not in the report's
#   absence (2026-07-23, replacing the earlier abort-before-report).
#   An UNREADABLE (locked) branch-scope verdict matching the audited tip/base
#   joins the same suspect handling -- its filename alone proves branch
#   provenance and its
#   merge evidence cannot be assessed (any other unreadable file is a named
#   advisory).
#   A same-tip merge verdict for a DIFFERENT base reviewed a different diff, so it is
#   NOT this landing's and is skipped. A malformed verdict that is only in the commit-time
#   WINDOW but does NOT OID-match (it could be a concurrent branch's) is
#   surfaced as an advisory in the report instead (neither counted
#   nor silently dropped) -- an UNRELATED
#   concurrent branch's malformed verdict sharing the directory never
#   implicates a per-branch audit. The scan is
#   NON-RECURSIVE, so the `failclosed-quarantine/` subdir (where the gate parks
#   fail-closed artifacts) is excluded by construction.
#
# NOT-CORRELATED windows fail LOUD, never as silent zeros: if zero verdicts
# correlate to the branch, the report is still written but with a prominent
# banner ("NO VERDICTS CORRELATED -- this is NOT evidence of a clean process")
# so a reader cannot mistake an empty correlation for a zero-round landing.
#
# Usage:
#   scripts\shared\worker-audit.ps1 -Branch <branch-or-tip-sha>
#   scripts\shared\worker-audit.ps1 -Branch <sha> -Base <merge-base-or-base-ref>
#   scripts\shared\worker-audit.ps1 -Branch <sha> -Base <fork-sha> -BaseRef <base-ref-name>
#   scripts\shared\worker-audit.ps1 -Branch <sha> -ReviewsDirCsv logs/codex/reviews,logs/claude/reviews
#   scripts\shared\worker-audit.ps1 -Branch <sha> -StatusFile <path-to-.worker/status.json>
#   scripts\shared\worker-audit.ps1 -Branch <sha> -OutPath <report.md>
#
#   -Base accepts a base REF (e.g. `master`) OR an explicit fork SHA. The commit
#   range is `git merge-base <Base> <Branch>`..`<Branch>`, so passing the fork SHA
#   directly (as auto-merge does, from the merge-base it computed BEFORE the
#   ff-merge) yields the same range AFTER the branch has been fast-forwarded into
#   the base -- the merge-base of an ancestor SHA and the tip is that ancestor.
#   -BaseRef carries the base's REF NAME beside a SHA -Base so legacy
#   `-vs-<ref>` merge verdicts still correlate (auto-merge passes both).
#
#   Filename timestamps are the producer's LOCAL wall clock (the wrappers
#   name artifacts with a local Get-Date, no offset). The audit resolves
#   them under the AUDIT HOST'S current zone rules, states that zone in the
#   report, and treats a wall-clock value that zone cannot resolve
#   unambiguously (a DST-gap time that never happened, a repeated fall-back
#   hour) as evidence it cannot place -- a suspect verdict, an unevaluable
#   sidecar -- never a silently chosen instant. A zone change between
#   producing and auditing is outside this contract (the report's stated
#   zone is the reader's check); an offset-bearing producer contract is
#   deferred (migration plan, P7c).
#
# CONSOLE DIAGNOSTIC CONTRACT (the PRODUCER owns the classification):
#   Every `[worker-audit] ERROR:` line carries a class token immediately after
#   the tag -- `[class:suspect]` or `[class:operational]`. The non-gating
#   consumers (auto-merge's post-merge audit) must tell an evidence-integrity
#   signal from an operational one, and a consumer that re-derives the class by
#   matching PROSE mis-routes every line whose wording it does not anticipate --
#   which is how a tip-named/tree-mismatched merge verdict was reported as an
#   ordinary operational error (gate BLOCKER 2026-08-30).
#     * `[class:suspect]` -- evidence THIS BRANCH owns is untrustworthy: a
#       correlated verdict artifact is fail-closed, malformed, or unreadable, or
#       a tip-named merge verdict carries a mismatched REVIEW-TREE-OID. A gate
#       bypass is possible, so a consumer must surface it as a SUSPECT.
#     * `[class:operational]` -- the audit could not run, or could not see
#       everything: bad arguments, unresolvable git facts, an absent or
#       unscannable corpus, a non-monotonic history, a writer failure. No
#       suspect artifact is being claimed.
#   The token is the ONLY classification channel. An unclassified or unknown-class line
#   reaching a consumer is a producer-contract breach, and every consumer routes
#   it to the LOUD side, because understating evidence integrity is the unsafe
#   direction.
#
# Exit codes:
#   0 = report written (INCLUDING the loud zero-correlation banner case AND
#       the suspect-led fail-loud report -- a correlated fail-closed/
#       malformed/unreadable artifact no longer aborts; it leads the report).
#       DELIBERATELY no distinct nonzero suspect status: to the non-gating
#       consumers a nonzero here is indistinguishable from an invocation
#       failure, so suspect visibility travels through the CONSOLE lines
#       instead -- the summary lines carry the UNRELIABLE marker and an
#       ERROR suspect line precedes them, which the post-merge consumer
#       surfaces (gate BLOCKER 2026-07-24).
#   1 = invocation failure (branch/base unresolvable, empty commit range, a
#       tip-named merge verdict with a mismatched REVIEW-TREE-OID, or a
#       writer failure)

[CmdletBinding()]
param(
  # The branch ref OR tip SHA that landed. auto-merge passes the branch tip SHA it
  # just merged. Validated below to retain the operational error diagnostic.
  [string]$Branch = '',
  # The base the branch merged into -- a ref (`master`) or an explicit fork SHA.
  # The audited range is merge-base(Base, Branch)..Branch (see the -Base note in
  # the usage header). Default `main`.
  [string]$Base = 'main',
  # The reviewed base's REF NAME for legacy `-vs-<ref>` filename identity
  # (`...-vs-main`, `...-vs-master`), SEPARATE from the range base: auto-merge
  # passes the PRE-merge fork SHA as -Base so the range stays correct after
  # the ff-merge, and a SHA can never equal a ref-name token -- without this
  # the branch's own legacy merge verdicts silently stopped correlating.
  # Empty (the default) = -Base itself is the identity (a ref passed as
  # -Base matches by name; a SHA passed as -Base matches by prefix only).
  [string]$BaseRef = '',
  # One OR MORE review dirs as a real array. Default is BOTH backends:
  # commit-gate routing, the single-provider merge panel's `-Backend` choice,
  # and the exhaustion fallback can each land a branch's verdicts in either
  # dir, so both carry correlatable evidence. Dir policy is the analyzer's
  # hybrid: an EXPLICIT list is strict (a missing or blank entry aborts --
  # coverage never narrows silently), the implicit default list degrades
  # loudly (an absent defaulted dir is skipped with a note). Unlike the
  # analyzer, a dir with ZERO in-window verdicts never aborts (a per-branch
  # audit legitimately finds a backend with no verdicts for this window). Each
  # element is one path taken verbatim; the comma-separated native-shell form
  # is -ReviewsDirCsv.
  # Backend identity is never the dir's: it is each artifact's own validated
  # REVIEW-BACKEND header (Get-ArtifactBackend, mirrored from the analyzer).
  [string[]]$ReviewsDir = @('logs/codex/reviews', 'logs/claude/reviews'),
  # The native-shell (`-File`) representation of the same input: ONE
  # comma-separated string, always split on every comma. Mutually exclusive
  # with -ReviewsDir.
  [string]$ReviewsDirCsv = '',
  # Optional path to the worker's `.worker/status.json`. When provided AND
  # readable AND valid JSON, its `escalations[]` array is summarized. Absence /
  # unreadability / malformed JSON is TOLERATED (a warning, no abort) -- the
  # escalation section then reports "status.json not provided / unreadable".
  [string]$StatusFile = '',
  # Output report path. Empty (the default) => a gitignored default is computed
  # under `logs/worker-audits/` from the branch tip + a timestamp. A
  # relative path is resolved against the current directory.
  [string]$OutPath = ''
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
# Force UTF-8 for native `git` output captured via `&` (default $OutputEncoding is
# ASCII on Windows PowerShell 5.1, which mojibakes multi-byte glyphs in commit
# subjects). Same defect class fixed in auto-merge.ps1 / auto-review.ps1.
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }

# ---------------------------------------------------------------------------
# Multi-directory input has TWO representations, each unambiguous BY GRAMMAR and
# independent of filesystem state (the same contract as analyze-blocker-trends.ps1):
#   -ReviewsDir     a real array; every element is one path taken VERBATIM (a
#                   `$env:TEMP` run-dir path may legally contain a comma on
#                   Windows, and auto-merge passes such dirs as an array via
#                   `-Command`, so an array element is never split).
#   -ReviewsDirCsv  ONE comma-separated string, ALWAYS split on every comma -- the
#                   native-shell form (`powershell -File ... -ReviewsDirCsv a,b`),
#                   since the -File binder cannot express an array.
# The two never combine (an ambiguous invocation refuses). No entry is
# discarded here: a blank element or fragment reaches the per-entry policy
# below (an explicit blank aborts by name, a defaulted blank is named and
# skipped), never silently dropped.
$reviewsDirExplicit = ($PSBoundParameters.ContainsKey('ReviewsDir') -or $PSBoundParameters.ContainsKey('ReviewsDirCsv'))
if ($PSBoundParameters.ContainsKey('ReviewsDirCsv')) {
  if ($PSBoundParameters.ContainsKey('ReviewsDir')) {
    Write-Host '[worker-audit] ERROR: [class:operational] -ReviewsDir and -ReviewsDirCsv are two representations of the same input; pass exactly one.'
    exit 1
  }
  $ReviewsDir = @(([string]$ReviewsDirCsv) -split ',' | ForEach-Object { $_.Trim() })
} else {
  # Array elements are NOT trimmed: the contract is byte-verbatim, and a
  # whitespace-bearing relative path trimmed here would scan a different
  # directory than the one named.
  $ReviewsDir = @($ReviewsDir | ForEach-Object { [string]$_ })
}
# The explicit forms promise ONE OR MORE dirs: an explicit EMPTY array (or a
# CSV that splits to nothing) would scan nothing and still publish a
# zero-correlation report as if coverage had been examined.
if ($reviewsDirExplicit -and @($ReviewsDir).Count -eq 0) {
  Write-Host '[worker-audit] ERROR: [class:operational] the explicit reviews-dir list is EMPTY; one or more directories are required (coverage never narrows silently).'
  exit 1
}

# The reviewer categories (the per-category enumeration block the wrapper
# parses), same order + names as scripts/codex/review-prompt-template.md and the
# analyzer / dispatch-checklist $catNames. Used for repeat-category detection and
# for the category-block validation inside Get-VerdictSuspectReason.
$script:CatNamesAll = @('PLAN-DRIFT', 'SILENT-FAILURE', 'TOMBSTONE-OR-SHIM', 'CROSS-CRATE-CONTRACT', 'LOADER-OR-ASSET-EDGE', 'CONVENTION-ADHERENCE', 'TEST-QUALITY', 'DOC-VS-CODE-DRIFT')

# Verdict filename shape -- IDENTICAL to analyze-blocker-trends.ps1 /
# dispatch-checklist.ps1's $verdictNameRe. auto-review.ps1 composes
# `review-<YYYYMMDD>-<HHMMSS>-<scope>.md`; filtering by this shape (not bare *.md)
# excludes prompt-template examples and other stray markdown. (Mirror contract.)
$script:VerdictNameRe = [regex]'^review-\d{8}-\d{6}-.+\.md$'
# The VERDICT line regex, IDENTICAL to the analyzer's $verdictLineRe -- its
# `(?<v>)` group yields the well-formed verdict WORD. Case-INSENSITIVE like the
# wrappers' own `-match '^VERDICT:'` + case-insensitive word compare (a
# wrapper-accepted `verdict: clean` is a valid artifact, never suspect).
# Shared by the suspect check and the union classifier so they cannot drift.
$script:VerdictLineRe = [regex]'(?im)^VERDICT:\s*(?<v>CLEAN|NON-BLOCKING|BLOCKED)\s*$'
# Filename-tip resolutions that matched MORE THAN ONE branch commit (an
# abbreviated tip that is a prefix of several full SHAs): never resolved by
# enumeration order -- quarantined as ambiguous and listed in the report.
$script:AmbiguousTipMatches = New-Object 'System.Collections.Generic.List[string]'
# Severity-prefix regex, IDENTICAL to the analyzer's $severityRe.
$script:SeverityRe = [regex]'(?m)^(?<sev>BLOCKER|QUALITY|NON-BLOCKER|NOTE):\s*(?<text>.*)$'
# Category-count ceiling read by the mirrored Get-CategoryTailKind, IDENTICAL
# to the analyzer's / checklist's $script:CategoryCountMax.
$script:CategoryCountMax = 10000
# Read envelopes for the untrusted files the audit opens whole: the producers
# write verdicts and status files in kilobytes, so a file past these sizes is
# not evidence and is never read into memory (named as unreadable /
# unavailable instead). The sidecar envelope lives in Test-ExhaustionSidecar.
$script:VerdictReadMaxBytes = 4MB
$script:StatusReadMaxBytes = 1MB

# Directory identity is the FINAL path behind a directory handle
# (GetFinalPathNameByHandle): a lexical full path keeps a junction or symlink
# alias distinct from its target, and a reviews dir supplied twice through
# an alias would be scanned twice (duplicate merge rounds; same-tree passing
# evidence folded into ambiguous attempts). The handle is opened with backup
# semantics (directories) and no access rights (identity only).
if (-not ('CrgWorkerAudit.FinalPath' -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace CrgWorkerAudit {
  public static class FinalPath {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder buffer, uint length, uint flags);
    public static string Resolve(string path, out int error) {
      error = 0;
      using (SafeFileHandle h = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
        if (h == null || h.IsInvalid) { error = Marshal.GetLastWin32Error(); return null; }
        StringBuilder sb = new StringBuilder(32768);
        uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
        if (n == 0 || n >= sb.Capacity) { error = Marshal.GetLastWin32Error(); return null; }
        string s = sb.ToString(0, (int)n);
        if (s.StartsWith(@"\\?\UNC\")) { return @"\\" + s.Substring(8); }
        if (s.StartsWith(@"\\?\")) { return s.Substring(4); }
        return s;
      }
    }
  }
}
"@
}

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
# Fail-closed per-file suspect check -- BYTE-IDENTICAL to
# analyze-blocker-trends.ps1's Get-VerdictSuspectReason (mirror contract; the
# analyzer's function header carries the per-check rationale). Returns a human-readable
# REASON string if the verdict file is NOT trustworthy review evidence, else
# $null. It mirrors the wrapper's per-pass Get-VerdictExitCode contract (BLOCKER
# precedence; else NON-BLOCKING for QUALITY/NON-BLOCKER/NOTE; else CLEAN for zero
# findings) plus the dispatch-checklist marker-sequence + block-structure checks.
# Kept identical to the analyzer, NOT forked -- any change there must be mirrored
# here. $VerdictWordRe is the parse loop's own verdict-line regex so the suspect
# check and the classifier share ONE regex.
# ---------------------------------------------------------------------------

# Classify a category line's tail as none|count|invalid, the SAME way the
# wrapper's `:\s*(?<v>none|\d+)\s*$` regex matches it. BYTE-IDENTICAL to the
# helper in scripts/shared/dispatch-checklist.ps1 -- keep every mirrored copy in sync
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
# Union (worst) outcome of a whole verdict artifact: 'BLOCKED' | 'QUALITY' |
# 'PASS'. Mirrors the analyzer's per-file vbucket union (BLOCKER precedence over a
# malformed/CLEAN word) AND the wrapper's NOTE-only == exit-0 (PASS) rule
# (auto-merge.ps1 Get-VerdictExitCode: NOTE-only -> exit 0). Because Get-Verdict-
# SuspectReason has already REJECTED any fail-closed / incoherent / malformed
# artifact before a file reaches here, whole-file severity-prefix + verdict-word
# counting yields the correct union:
#   BLOCKED  <- any `^BLOCKER:` finding, OR any pass VERDICT word BLOCKED.
#   QUALITY  <- else any `^QUALITY:` or legacy `^NON-BLOCKER:` finding, OR any pass
#               VERDICT word NON-BLOCKING WITH a blocking finding (a NON-BLOCKING
#               word with ONLY NOTE findings is a PASS).
#   PASS     <- else (CLEAN, or NOTE-only -- the gate exits 0 for both).
# This is the era-NEUTRAL severity class of the verdict. Whether a QUALITY-class
# verdict represents an ABORTED round is ERA-DEPENDENT: under the OLD contract the
# gate aborted on QUALITY (exit 1), so a QUALITY verdict == an aborted round; the
# 2026-07 severity contract made QUALITY NON-BLOCKING (exit 0, routed to
# logs/review-followups.md), so a QUALITY verdict produced by a
# post-contract wrapper is a PASSING round. BLOCKED always == a gate-BLOCKING
# (aborted) round in every era; PASS always == a landing round.
# Get-EraAwareRoundClass applies the era at RECORD CREATION using the artifact's
# REVIEW-SEVERITY-CONTRACT header stamp (Test-VerdictContractStamp), so the class
# stored on each record is already era-aware -- the attempt grouping +
# aborted-round correlation below see a stamped QUALITY as PASS, and only an
# UNSTAMPED QUALITY survives as a blocking round. The report methodology carries
# the matching caveat.
# ---------------------------------------------------------------------------
function Get-VerdictUnionClass {
  param([string]$Content)
  $vAll = @($script:VerdictLineRe.Matches($Content) | ForEach-Object { $_.Groups['v'].Value })
  if (($Content -match '(?m)^BLOCKER:') -or ($vAll -contains 'BLOCKED')) { return 'BLOCKED' }
  if (($Content -match '(?m)^QUALITY:') -or ($Content -match '(?m)^NON-BLOCKER:')) { return 'QUALITY' }
  return 'PASS'
}

# The 2026-07 severity contract made QUALITY-only verdicts NON-BLOCKING (exit 0):
# a QUALITY verdict from a POST-CONTRACT wrapper is a PASSING gate round; one from
# a PRE-CONTRACT wrapper aborted the round (the gate exited 1). The era signal is
# the artifact's REVIEW-SEVERITY-CONTRACT header stamp, which post-contract
# wrappers write UNCONDITIONALLY and pre-contract wrappers never wrote. A DATE
# cutover is deliberately NOT used: the commit dispatcher runs the BRANCH HEAD's
# gate copy, so a branch/worktree that has not yet incorporated the contract can
# emit old-contract exit-1 QUALITY artifacts at ANY date -- a date cutover would
# misclassify those genuine aborted rounds as PASS and inflate first-attempt-clean
# metrics (merge-gate BLOCKER 2026-07-10 on the date-cutover design). Conservative
# direction: an UNSTAMPED QUALITY artifact is always counted as an ABORTED round
# (the audit over-reports process friction rather than hiding it).
# Scans ONLY the contiguous leading header block (from line 1 to the first blank
# or non-header line) -- a stamp-shaped line in the verdict BODY (e.g. a finding
# QUOTING the stamp) must not spoof era detection. Rejection is the safe
# direction: a missed stamp only over-reports an aborted round.
# PURE.
function Test-VerdictContractStamp {
  param([string]$Content)
  if ([string]::IsNullOrEmpty($Content)) { return $false }
  $headerish = [regex]'^(DIFF-SHA256:|REVIEW-TREE-OID:|REVIEW-BACKEND:|REVIEW-EFFORT:|REVIEW-SEVERITY-CONTRACT:)'
  foreach ($ln in ($Content -split "`r?`n")) {
    if ($ln.Trim().Length -eq 0) { break }
    if ($ln -match '^REVIEW-SEVERITY-CONTRACT:\s*blocker-only\s*$') { return $true }
    if (-not $headerish.IsMatch($ln)) { return $false }
  }
  return $false
}

# Map a raw severity class (Get-VerdictUnionClass) to its ERA-AWARE round class:
# BLOCKED always aborts a round; QUALITY aborts only when the artifact carries NO
# REVIEW-SEVERITY-CONTRACT stamp (a stamped QUALITY exited 0 -- a PASS round);
# PASS stays PASS. Applied once at record creation so the downstream attempt
# grouping + aborted-round attribution see an era-aware class.
# PURE.
function Get-EraAwareRoundClass {
  param([string]$Class, [bool]$HasContractStamp)
  if ($Class -eq 'QUALITY' -and $HasContractStamp) { return 'PASS' }
  return $Class
}

# The reviewer categories that have >=1 finding in an artifact (union across
# passes): a category is present iff any `^<CAT>: <n>` line has a numeric n >= 1
# (not `none`). This is the repeat-category axis (same category taxonomy the
# dispatch-checklist ranks on). Returns a string[] of category names.
function Get-VerdictCategories {
  param([string]$Content)
  $present = New-Object 'System.Collections.Generic.List[string]'
  foreach ($cat in $script:CatNamesAll) {
    $rx = [regex]('(?m)^' + [regex]::Escape($cat) + ':\s*(?<v>none|\d+)\s*$')
    $hit = $false
    foreach ($m in $rx.Matches($Content)) {
      $v = $m.Groups['v'].Value
      if ($v -ne 'none') {
        $parsed = 0
        if ([int]::TryParse($v, [ref]$parsed) -and $parsed -ge 1) { $hit = $true; break }
      }
    }
    if ($hit) { $present.Add($cat) | Out-Null }
  }
  return $present.ToArray()
}

# ---------------------------------------------------------------------------
# Parse a verdict FILENAME's scope tag into @{ Kind; Tip; Base }. auto-review.ps1
# composes `review-<YYYYMMDD>-<HHMMSS>-<scopeTag>.md` where scopeTag is one of
# `staged`, `uncommitted`, `commit-<sha>`, or `branch-<tip>-vs-<base>`.
#   Kind = 'commit-gate'  for `staged` ONLY (the pre-commit gate's scope; Tip/Base $null).
#   Kind = 'merge-gate'   for branch-<tip>-vs-<base> (Tip = <tip>, Base = <base>).
#   Kind = 'manual'       for `uncommitted` / `commit-<sha>` -- MANUAL spot-checks
#          (`-Scope Uncommitted` / `-Scope Commit`), NOT gate rounds (for
#          commit-<sha>, Tip = <sha>). Counted separately, excluded from gate rounds.
#   Kind = 'other'        for a name that matches $VerdictNameRe but no known tag.
# ---------------------------------------------------------------------------
function Get-VerdictScope {
  param([string]$Name)
  # Strip the fixed `review-<8>-<6>-` prefix and the `.md` suffix to get the tag.
  $m = [regex]::Match($Name, '^review-\d{8}-\d{6}-(?<tag>.+)\.md$')
  if (-not $m.Success) { return [pscustomobject]@{ Kind = 'other'; Tip = $null; Base = $null; Child = $null } }
  $tag = $m.Groups['tag'].Value
  # The optional trailing child token is the merge gate's per-child
  # -ArtifactTag (the claude wrapper's ValidatePattern reserves the
  # `p<n>`/`fb<n>` grammar for it), appended AFTER the base so N concurrent
  # single-provider panel children cannot compute colliding filenames. NO
  # metadata proves whether a trailing child-shaped token IS a child tag: a
  # legacy REF may be hex-shaped and end in one (`deadbeef-p2` is a single
  # base ref), and no artifact header predates or postdates the tag grammar
  # reliably (gate BLOCKER 2026-07-23 falsified header-era gating). So BOTH
  # interpretations are returned: Base/Child hold the WHOLE-suffix
  # (legacy-safe) reading -- Child always $null -- and SplitBase/SplitChild
  # hold the split reading when the name supports it (12-hex-style base +
  # reserved-grammar tag), else $null. The consumer resolves the ambiguity
  # against GROUND TRUTH (the audited tip+base via Test-BaseMatch): the
  # whole-suffix reading wins when it matches; the split reading is used only
  # when the whole does not match and the split does.
  $bm = [regex]::Match($tag, '^branch-(?<tip>[0-9a-fA-F]{7,40})-vs-(?<base>.+)$')
  if ($bm.Success) {
    $splitBase = $null
    $splitChild = $null
    $sm = [regex]::Match($tag, '^branch-[0-9a-fA-F]{7,40}-vs-(?<base>[0-9a-fA-F]{7,40})-(?<child>(?:p|fb)\d{1,2})$')
    if ($sm.Success) {
      $splitBase = $sm.Groups['base'].Value
      $splitChild = $sm.Groups['child'].Value
    }
    return [pscustomobject]@{
      Kind = 'merge-gate'; Tip = $bm.Groups['tip'].Value.ToLowerInvariant()
      Base = $bm.Groups['base'].Value; Child = $null
      SplitBase = $splitBase; SplitChild = $splitChild
    }
  }
  # ONLY `staged` is a COMMIT-GATE round: scripts/git-hooks/pre-commit invokes the
  # wrapper with `-Scope Staged` exclusively. `uncommitted` (a `-Scope Uncommitted`
  # run) and `commit-<sha>` (a `-Scope Commit` run) are MANUAL spot-checks that land
  # in the same log namespace but never GATED a landing -- counting them as gate
  # rounds (or as a passing round via OID match) would inflate the audit. They are
  # classified 'manual' and excluded from the gate-round counts.
  if ($tag -eq 'staged') {
    return [pscustomobject]@{ Kind = 'commit-gate'; Tip = $null; Base = $null; Child = $null }
  }
  if ($tag -eq 'uncommitted') {
    return [pscustomobject]@{ Kind = 'manual'; Tip = $null; Base = $null; Child = $null }
  }
  $cm = [regex]::Match($tag, '^commit-(?<sha>[0-9a-fA-F]{7,40})$')
  if ($cm.Success) {
    return [pscustomobject]@{ Kind = 'manual'; Tip = $cm.Groups['sha'].Value.ToLowerInvariant(); Base = $null; Child = $null }
  }
  return [pscustomobject]@{ Kind = 'other'; Tip = $null; Base = $null; Child = $null }
}

# Parse the `review-<YYYYMMDD>-<HHMMSS>-...` FILENAME prefix into a unix epoch.
# This is the timestamp each wrapper stamps at REVIEW START (its own `Get-Date`),
# so the two backend artifacts of ONE concurrent merge attempt are within seconds
# -- UNLIKE the file MTIME (LastWriteTime), which reflects write/consolidation time
# and can differ by MINUTES between backends whose reviews took different
# durations. Merge-round clustering MUST use this (not the mtime) so one attempt's
# two backend copies stay one round. Interpreted as LOCAL time (the wrappers write
# a local Get-Date). Returns $null when the name has no parseable prefix.
#
# The wall-clock value is resolved under an explicit zone (the audit host's
# local zone by default; the suite pins a DST zone). A value the zone cannot
# resolve to ONE instant -- a spring-forward gap time that never occurred,
# a fall-back hour that occurred twice -- yields no epoch and a named
# reason: choosing either instant silently would merge or split attempt
# clusters and time-scope quarantines on a guess. Consumers that need the
# reason call Get-VerdictFileNameEpochState; Get-VerdictFileNameEpoch keeps
# the epoch-or-null shape.
function Get-VerdictFileNameEpochState {
  param([string]$Name, [System.TimeZoneInfo]$Zone = [System.TimeZoneInfo]::Local)
  $m = [regex]::Match($Name, '^review-(?<d>\d{8})-(?<t>\d{6})-')
  if (-not $m.Success) { return @{ Epoch = $null; State = 'no-prefix'; Reason = 'name carries no producer timestamp prefix' } }
  $stamp = $m.Groups['d'].Value + '-' + $m.Groups['t'].Value
  $dt = [DateTime]::MinValue
  if (-not [DateTime]::TryParseExact(($m.Groups['d'].Value + $m.Groups['t'].Value), 'yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
    return @{ Epoch = $null; State = 'unparseable'; Reason = "filename timestamp prefix $stamp does not parse as a calendar time (malformed producer name)" }
  }
  $dt = [DateTime]::SpecifyKind($dt, [System.DateTimeKind]::Unspecified)
  if ($Zone.IsInvalidTime($dt)) {
    return @{ Epoch = $null; State = 'invalid'; Reason = "filename timestamp prefix $stamp names a wall-clock time that never occurred under zone '$($Zone.Id)' (DST gap); its instant cannot be resolved" }
  }
  if ($Zone.IsAmbiguousTime($dt)) {
    return @{ Epoch = $null; State = 'ambiguous'; Reason = "filename timestamp prefix $stamp names a wall-clock time that occurred twice under zone '$($Zone.Id)' (repeated DST hour); its instant cannot be resolved" }
  }
  $epoch = [long]([DateTimeOffset]::new($dt, $Zone.GetUtcOffset($dt))).ToUnixTimeSeconds()
  return @{ Epoch = $epoch; State = 'ok'; Reason = '' }
}
function Get-VerdictFileNameEpoch {
  param([string]$Name)
  return (Get-VerdictFileNameEpochState -Name $Name).Epoch
}

# Is a producer-shaped artifact NAME inside the audited window?
#
# The window is bounded by PRODUCER time -- the timestamp the producer wrote
# into the filename -- never by the filesystem's `LastWriteTime`. An mtime is a
# mutable property of a copy operation, not of the evidence: consolidating a
# run dir, restoring a backup, or unpacking an archive rewrites it, so an
# mtime window silently drops in-window evidence (undercounted rounds, a
# quarantine that never fires) and admits out-of-window evidence under a fresh
# mtime. Every downstream decision -- attribution windows, quarantine
# identity, boundary-second handling -- already reads the filename epoch, so
# filtering on anything else made the scan disagree with its own consumers
# (merge-panel BLOCKER 2026-08-30).
#
# An artifact whose name carries NO resolvable instant (a malformed stamp, a
# DST gap, a repeated hour) is IN, never out: it cannot be placed, and a
# silent drop is the one outcome the suspect/incompleteness paths downstream
# exist to prevent. They classify it; this predicate must not pre-empt them.
function Test-VerdictNameInWindow {
  param([string]$Name, [long]$StartEpoch, [long]$EndEpoch)
  $st = Get-VerdictFileNameEpochState -Name $Name
  if ($null -eq $st.Epoch) { return $true }
  return ([long]$st.Epoch -ge $StartEpoch -and [long]$st.Epoch -le $EndEpoch)
}

# Does a merge-gate filename <tip> (7..40 hex, lowercased) identify EXACTLY one
# branch commit? A filename tip is an ABBREVIATED SHA, so match by prefix
# against each full commit SHA -- and the match must be UNIQUE: several branch
# commits can share a permitted prefix, and resolving by enumeration order
# would credit evidence to the wrong commit or raise a false tree-mismatch
# abort. An ambiguous tip is recorded ($script:AmbiguousTipMatches, listed in
# the report) and resolves to $null. Returns the matched full SHA or $null.
function Resolve-TipToCommit {
  param([string]$Tip, [string[]]$CommitShas)
  if ([string]::IsNullOrWhiteSpace($Tip)) { return $null }
  $t = $Tip.ToLowerInvariant()
  $matches = @()
  foreach ($sha in $CommitShas) {
    $s = $sha.ToLowerInvariant()
    if ($s.StartsWith($t) -or $t.StartsWith($s)) { $matches += ,$sha }
  }
  if ($matches.Count -eq 1) { return $matches[0] }
  if ($matches.Count -gt 1) {
    $script:AmbiguousTipMatches.Add("filename tip '$t' matches $($matches.Count) branch commits ($(($matches | ForEach-Object { $_.Substring(0, [Math]::Min(12, $_.Length)) }) -join ', ')) -- not correlated") | Out-Null
  }
  return $null
}

# Does a merge-gate filename <base> identify the AUDITED base? A `branch-<tip>-vs-
# <base>` verdict correlates to this landing only when BOTH the tip AND the reviewed
# base match -- matching on <tip> alone would let a same-tip verdict reviewed
# against a DIFFERENT base (a stale pre-rebase artifact, or a manual `-Scope Branch`
# spot-check against another base -- it reviewed a different diff) inflate the merge
# round count or false-abort. auto-review encodes the base as a 12-hex prefix of the
# reviewed base SHA (`branch-<tip12>-vs-<base12>`, see auto-review.ps1's Branch scope
# tag); a LEGACY verdict encoded the raw ref name (e.g. `-vs-master`). So:
#   * SHA-prefix base (7..40 hex): bidirectional prefix match against the audited
#     full base SHA (the 12-hex token is a prefix of the 40-hex $facts.BaseSha).
#   * ref-name base (non-hex, e.g. `master`): match the audited base REF verbatim
#     (case-insensitive) -- a ref name cannot be tied to a fork SHA from the artifact
#     alone, so it correlates only when the audit's ref identity is that ref
#     (-Base given as the ref, or -BaseRef supplied beside a fork-SHA -Base,
#     the form auto-merge uses).
# PURE.
# Only a VERIFIED producer header (a Get-ArtifactBackend backend that owns an
# effort stamp) fixes an artifact's era as modern; every other label -- a
# headerless legacy artifact AND malformed provenance, which yields no
# trustworthy era -- takes the wider legacy match. Those records only demote
# or mark suspect, so the wider match is the conservative direction (a
# narrow match would let a suspect vanish from the fail-loud report).
function Test-EraUnknownForBaseMatch {
  param([string]$Backend)
  return (-not $abEffortByBackend.ContainsKey([string]$Backend))
}

function Test-BaseMatch {
  param([string]$FilenameBase, [string]$AuditBaseSha, [string]$AuditBaseRef, [switch]$Legacy)
  if ([string]::IsNullOrWhiteSpace($FilenameBase)) { return $false }
  $fb = $FilenameBase.ToLowerInvariant()
  if ($fb -match '^[0-9a-f]{7,40}$') {
    # A hex-shaped token's meaning comes from the artifact's ERA, never from
    # the token: a MODERN producer (identity header present) encodes a SHA
    # prefix, so only the SHA truth applies -- a modern `-vs-deadbeef`
    # reviewed against another base must not correlate through a ref that
    # happens to spell `deadbeef`. A LEGACY artifact (no header) encoded the
    # raw ref, which git accepts in hex spellings, so the ref truth applies
    # too. Callers without an era (unreadable artifacts, sidecars) pass
    # -Legacy: those paths only demote or mark suspect, so the wider match
    # is the conservative direction.
    $sha = ([string]$AuditBaseSha).ToLowerInvariant()
    $shaHit = ($sha -ne '') -and ($sha.StartsWith($fb) -or $fb.StartsWith($sha))
    if (-not $Legacy) { return $shaHit }
    $refHit = (-not [string]::IsNullOrWhiteSpace($AuditBaseRef)) -and ($fb -eq ([string]$AuditBaseRef).ToLowerInvariant())
    return ($shaHit -or $refHit)
  }
  if (-not [string]::IsNullOrWhiteSpace($AuditBaseRef)) {
    return ($fb -eq ([string]$AuditBaseRef).ToLowerInvariant())
  }
  return $false
}

# ---------------------------------------------------------------------------
# Exhaustion-sidecar SYNTAX-ONLY classification (split-on-subsystem ruling
# 2026-07-23). A sidecar grants NO authority -- a fail-closed exhaustion
# artifact stays suspect evidence under the fail-loud report contract
# regardless of any sidecar beside it, and the one decision a sidecar
# drives is NEGATIVE: the sidecar quarantine (demote-only,
# keyed on the sidecar's FILENAME identity at $exhaustedPanelSidecars -- never on
# this function's result). Audit-side
# SUPERSESSION of such artifacts was removed from this consumer: without a
# parent-generated run identity on every artifact plus a producer-owned
# terminal panel receipt, no correlation can prove the fallback panel
# actually passed for the SAME invocation (planted or unrelated later
# verdicts qualify); supersession is owned by the verdict-artifact framing
# migration follow-up. This function classifies a sidecar for REPORT
# LABELING only, and the check is SYNTAX-ONLY: a readable leaf file whose
# JSON record carries the producer's field set as non-empty strings with
# `kind: token-exhaustion` -- field VALUES are NOT validated (no domain,
# identity, or binding checks; nothing consumes them). Returns
# @{ Valid; Reason; Record }. NON-pure (reads the file).
# ---------------------------------------------------------------------------
# Bounded read of an UNTRUSTED file through ONE handle: the length is taken
# from the opened stream and the bytes are read from that same stream, so a
# writer cannot grow or replace the file between the check and the read (a
# pathname length probe followed by a fresh ReadAll* reopens a file that may
# no longer be the one measured). The handle denies concurrent writers for
# its lifetime (FileShare.Read). Returns @{ Ok; Bytes; Reason }.
function Read-BoundedFileBytes {
  param([string]$Path, [long]$MaxBytes)
  $fs = $null
  try {
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $len = $fs.Length
    if ($len -gt $MaxBytes) { return @{ Ok = $false; Bytes = $null; Reason = "exceeds the read envelope ($len bytes > $MaxBytes)" } }
    $buf = New-Object byte[] ([int]$len)
    $off = 0
    while ($off -lt $len) {
      $n = $fs.Read($buf, $off, [int]($len - $off))
      if ($n -le 0) { return @{ Ok = $false; Bytes = $null; Reason = "short read ($off of $len bytes)" } }
      $off += $n
    }
    return @{ Ok = $true; Bytes = $buf; Reason = '' }
  } catch {
    return @{ Ok = $false; Bytes = $null; Reason = $_.Exception.Message }
  } finally {
    if ($null -ne $fs) { $fs.Dispose() }
  }
}

function Test-ExhaustionSidecar {
  param([string]$SidecarPath)
  $res = @{ Valid = $false; Reason = ''; Record = $null }
  if (-not (Test-Path -LiteralPath $SidecarPath -PathType Leaf)) {
    $res.Reason = 'sidecar path is not a leaf file'
    return $res
  }
  $raw = $null
  try {
    $bounded = Read-BoundedFileBytes -Path $SidecarPath -MaxBytes 8192
    if (-not $bounded.Ok) {
      $res.Reason = $(if ($bounded.Reason -match 'read envelope') { 'sidecar exceeds the producer size envelope' } else { "sidecar unreadable ($($bounded.Reason))" })
      return $res
    }
    $raw = [System.Text.Encoding]::UTF8.GetString($bounded.Bytes)
  } catch {
    $res.Reason = "sidecar unreadable ($($_.Exception.Message))"
    return $res
  }
  $obj = $null
  try { $obj = ConvertFrom-Json -InputObject $raw -ErrorAction Stop } catch {
    $res.Reason = 'sidecar is not valid JSON'
    return $res
  }
  if ($null -eq $obj -or -not ($obj -is [System.Management.Automation.PSCustomObject])) {
    $res.Reason = 'sidecar JSON is not an object'
    return $res
  }
  foreach ($field in @('kind', 'backend', 'scope', 'reviewTreeOid', 'diffSha256', 'signatureClass', 'processOutcome', 'timestamp')) {
    $p = $obj.PSObject.Properties[$field]
    if ($null -eq $p -or -not ($p.Value -is [string]) -or [string]::IsNullOrWhiteSpace([string]$p.Value)) {
      $res.Reason = "sidecar field '$field' missing or not a non-empty string"
      return $res
    }
  }
  if ([string]$obj.kind -ne 'token-exhaustion') { $res.Reason = "sidecar kind is '$($obj.kind)', not 'token-exhaustion'"; return $res }
  $res.Valid = $true
  $res.Record = $obj
  return $res
}

# ---------------------------------------------------------------------------
# PURE correlation engine. Given the branch commits (oldest
# first, each with Tree + Epoch), the merge-base epoch, and the parsed
# COMMIT-GATE verdict records, produce one row per commit:
#   @{ Sha; Short; Tree; Epoch; Subject; FileCount;
#      PassingRound  = <verdict record or $null>   # OID-matched, PASS outcome
#      AbortedRounds = @(<verdict record>, ...)     # window-attributed, ordered
#      RepeatCategories = @(<category name>, ...)   # consecutive-round repeats
#      Confidence    = 'tight' | 'loose'
#      TotalRounds   = AbortedRounds.Count + (PassingRound ? 1 : 0)
#      FirstAttemptClean = PassingRound present AND AbortedRounds empty AND the
#        PassingRound is a TRUE CLEAN (empty Categories) -- a QUALITY-bearing or
#        NOTE-only PASS is a non-aborted passing round but is NOT counted clean }
#
# A verdict record is a [pscustomobject] with at least: Name, TreeOid, Epoch,
# Class ('BLOCKED'|'QUALITY'|'PASS'), Categories (string[]), Backend.
#
# Passing round = a PASS-class commit-gate verdict whose TreeOid == the commit's
# Tree, ASSIGNED ONCE to the closest-in-time such commit (git trees are not unique
# per commit, so a shared-tree verdict goes to the commit it created, not all of
# them); a redundant same-tree attempt whose nearest commit already claimed a
# passing round (a gate RE-RUN of the same tree) is DROPPED, not spilled to a
# farther duplicate-tree commit. Aborted rounds = commit-gate verdicts with Class in
# {BLOCKED, QUALITY} whose Epoch is strictly inside (prevBoundary, thisEpoch);
# an Epoch equal to either edge is a boundary-second artifact (see the row's
# BoundaryArtifacts), attributed to no window. The Class filter
# ALONE excludes passing rounds (a PASS verdict, incl. the base's CLEAN review, is
# never BLOCKED/QUALITY), so NO tree-match exclusion is applied -- a blocking
# verdict whose tree later lands via a hook bypass is real bypass evidence and is
# kept, not dropped. prevBoundary = the previous commit's Epoch (or BaseEpoch for
# the first commit). Confidence is
# 'tight' iff this commit AND its predecessor both have an OID-matched passing
# round (the window is flanked by OID-anchored landings on this branch), else
# 'loose'. See the CORRELATION MODEL header for why aborted attribution is
# window-based and its concurrency limit.
# ---------------------------------------------------------------------------
function Invoke-CommitGateCorrelation {
  param(
    [object[]]$Commits,          # ordered oldest-first; each @{ Sha; Short; Tree; Epoch; Subject; FileCount }
    [long]$BaseEpoch,
    [object[]]$CommitGateAttempts, # gate ATTEMPTS (per-backend artifacts pre-grouped); each with TreeOid; Epoch; Class; Categories; Name
    # Trees that ALSO carry an AMBIGUOUS attempt the caller filtered out
    # before correlation: an ambiguous attempt is still evidence that the
    # tree was reviewed before, so a later definite rerun on it can never
    # be first-attempt-CLEAN.
    [string[]]$TreesWithAmbiguousAttempts = @()
  )
  $ambiguousTreeSet = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($t in @($TreesWithAmbiguousAttempts)) { if (-not [string]::IsNullOrWhiteSpace($t)) { [void]$ambiguousTreeSet.Add(([string]$t).ToLowerInvariant()) } }
  # Pass 1: assign each PASS verdict to at most ONE commit -- the tree-matching
  # commit CLOSEST in time to the verdict -- and CONSUME it once. Git tree OIDs are
  # NOT unique per commit (a revert or two commits with identical content share a
  # tree; the pre-commit hook skips empty commits, but rebases/reverts still
  # produce duplicate trees), so a naive "every commit whose tree matches a PASS
  # verdict" would let ONE staged verdict mark MULTIPLE commits HasPass -- inflating
  # passingTotal and wrongly making confidence `tight`. Time-disambiguation
  # attributes a shared-tree verdict to the commit it actually created (the staged
  # review's mtime ~ that commit's committer time); a duplicate-tree sibling stays
  # UNMATCHED unless it has its OWN distinct PASS verdict in range. Parallel arrays
  # (sized up front) so a $null passing round stores cleanly and the pass-2
  # confidence flag can read the predecessor's HasPass. (Codex BLOCKER: tree-only
  # matching double-counted a verdict across duplicate-tree commits.)
  $passingByIndex = [object[]]::new($Commits.Count)   # all $null
  $hasPassArr = [bool[]]::new($Commits.Count)         # all $false
  # Each PASS attempt claims its NEAREST same-tree commit (min |Δepoch|), and ONLY if
  # that nearest commit is still unclaimed. A PASS attempt belongs to the one commit
  # closest in time whose tree it carries; if that commit ALREADY claimed a passing
  # round, this attempt is a REDUNDANT same-tree attempt (a gate RE-RUN on the same
  # staged tree) and is DROPPED -- it must NOT spill to a farther same-tree commit,
  # which would backfill an OLDER duplicate-tree commit that never independently
  # passed. Using the attempt's true (nearest) home -- NOT "closest UNCLAIMED" --
  # avoids that spill without assuming a review-vs-commit timing sign (empirically a
  # passing staged review's filename epoch can be a few seconds AFTER its commit's
  # committer time, so a strict pre-commit window would drop real passing rounds).
  # (Codex BLOCKER: tree-only matching double-counted a verdict across duplicate-tree
  # commits. Codex QUALITY: the rerun-split could then let a 2nd same-tree PASS
  # attempt backfill a duplicate-tree sibling, inflating passing/tight/first-attempt.)
  # "Nearest" must be UNIQUE to be a home. Two duplicate-tree commits equidistant
  # from one PASS artifact (epochs 100 and 200, artifact at 150) make the strict
  # `<` update keep whichever the commit array happened to list first -- an
  # ARRAY-ORDER answer to a question the evidence does not answer, and it decides
  # passing totals, tight-window classification and first-attempt-CLEAN for a
  # commit chosen arbitrarily (merge-panel BLOCKER 2026-08-30). A tied attempt
  # claims NOTHING and every tied commit is flagged, matching this audit's
  # standing doctrine: an undecidable correlation is excluded and named, never
  # resolved by an accident of iteration.
  # The tied ARTIFACTS are retained per row, not a bare boolean: excluded
  # evidence carries its identity everywhere else in this audit (the ambiguous
  # and order-unstable attempt sections list names), because a count with no
  # names cannot be checked and a boolean cannot be rendered.
  $passMatchAmbiguousNames = [object[]]::new($Commits.Count)
  for ($pmi = 0; $pmi -lt $Commits.Count; $pmi++) { $passMatchAmbiguousNames[$pmi] = New-Object 'System.Collections.Generic.List[string]' }
  $passVerdicts = @($CommitGateAttempts | Where-Object { $_.Class -eq 'PASS' } | Sort-Object -Property Epoch)
  foreach ($v in $passVerdicts) {
    $vTree = ([string]$v.TreeOid).ToLowerInvariant()
    $vEpoch = [long]$v.Epoch
    $nearestIdx = -1
    $nearestDelta = [long]::MaxValue
    $nearestTied = New-Object 'System.Collections.Generic.List[int]'
    for ($i = 0; $i -lt $Commits.Count; $i++) {
      if (([string]$Commits[$i].Tree).ToLowerInvariant() -ne $vTree) { continue }
      $delta = [Math]::Abs([long]$Commits[$i].Epoch - $vEpoch)
      if ($delta -lt $nearestDelta) {
        $nearestDelta = $delta
        $nearestIdx = $i
        $nearestTied.Clear()
        $nearestTied.Add($i) | Out-Null
      } elseif ($delta -eq $nearestDelta -and $nearestIdx -ge 0) {
        $nearestTied.Add($i) | Out-Null
      }
    }
    if ($nearestTied.Count -gt 1) {
      foreach ($ti in $nearestTied.ToArray()) { $passMatchAmbiguousNames[$ti].Add([string]$v.Name) | Out-Null }
      continue
    }
    if ($nearestIdx -ge 0 -and -not $hasPassArr[$nearestIdx]) {
      $passingByIndex[$nearestIdx] = $v
      $hasPassArr[$nearestIdx] = $true
    }
  }

  # Pass 2: window-attribute aborted rounds + emit each row with confidence inline.
  $rows = New-Object 'System.Collections.Generic.List[object]'
  $prevEpoch = $BaseEpoch
  for ($i = 0; $i -lt $Commits.Count; $i++) {
    $c = $Commits[$i]
    $thisEpoch = [long]$c.Epoch
    $passing = $passingByIndex[$i]

    # Aborted = BLOCKING commit-gate verdicts (union outcome BLOCKED or QUALITY)
    # strictly inside (prevEpoch, thisEpoch) -- the edges are boundary-second
    # artifacts above -- ordered by Epoch for consecutive-round repeat-category
    # detection. Class here is ERA-AWARE (set via Get-EraAwareRoundClass at record
    # creation): a contract-STAMPED QUALITY verdict exited 0 and is already class
    # PASS, so `Class -eq 'QUALITY'` matches only UNSTAMPED old-contract QUALITY (a
    # genuine aborted round). The Class filter ALONE excludes passing rounds (a PASS
    # verdict -- incl. the base's own CLEAN review and any stamped QUALITY -- is never
    # BLOCKED/QUALITY), so NO tree exclusion is applied: a BLOCKED/QUALITY verdict
    # whose tree LATER lands (a hook-bypassed / logged-skip commit that shipped a tree
    # the gate had blocked) is real bypass evidence and MUST be counted, not dropped.
    # (Codex BLOCKER: the earlier tree exclusion silently dropped such a blocking round.)
    # Both clocks resolve to WHOLE SECONDS (filename stamps and git committer
    # times), so an artifact stamped in the SAME second as a window edge (this
    # commit's time, or the predecessor's / the base's) has no knowable order
    # against that commit: it is attributed to NO window, listed on the row as
    # a BOUNDARY-SECOND artifact, and the row's window-derived results are
    # incomplete (no first-attempt-CLEAN credit, the caller marks the bounds).
    $boundary = @($CommitGateAttempts | Where-Object {
        ($_.Class -eq 'BLOCKED' -or $_.Class -eq 'QUALITY') -and
        (([long]$_.Epoch -eq $prevEpoch) -or ([long]$_.Epoch -eq $thisEpoch))
      } | Sort-Object -Property Epoch)
    $aborted = @($CommitGateAttempts | Where-Object {
        ($_.Class -eq 'BLOCKED' -or $_.Class -eq 'QUALITY') -and
        ([long]$_.Epoch -gt $prevEpoch) -and ([long]$_.Epoch -lt $thisEpoch)
      } | Sort-Object -Property Epoch)

    # Confidence: tight iff this commit AND its predecessor both have an OID-
    # matched passing round (the window is flanked by OID-anchored landings on this
    # branch). The first commit is always loose (its predecessor is the base).
    $prevHasPass = if ($i -eq 0) { $false } else { [bool]$hasPassArr[$i - 1] }
    $tight = ([bool]$hasPassArr[$i]) -and $prevHasPass
    $repeatSplit = Resolve-RepeatCategories -OrderedRounds $aborted

    $rows.Add([pscustomobject]@{
        Sha               = $c.Sha
        Short             = $c.Short
        Tree              = $c.Tree
        Epoch             = $thisEpoch
        Subject           = $c.Subject
        FileCount         = $c.FileCount
        PassingRound      = $passing
        HasPass           = [bool]$hasPassArr[$i]
        PassMatchAmbiguous = ($passMatchAmbiguousNames[$i].Count -gt 0)
        PassMatchAmbiguousNames = $passMatchAmbiguousNames[$i].ToArray()
        AbortedRounds     = $aborted
        BoundaryArtifacts = $boundary
        # CONSECUTIVE-repeat detection reads ADJACENCY, so it is only as sound
        # as the order it is handed. These attempts come from several tree
        # buckets ordered by epoch alone, and producer stamps resolve to whole
        # seconds: two same-second attempts from DIFFERENT trees have no
        # knowable order, and A/B/A arriving as A/A/B invents a repeat that
        # never happened (merge-panel BLOCKER 2026-08-30). The per-bucket
        # permutation pass upstream cannot see this -- it permutes inside one
        # tree. Resolve-RepeatCategories runs the analysis under every ordering
        # the ties admit and splits the result: categories that repeat under ALL
        # of them are evidence, the rest are enumeration artifacts reported on
        # their own field.
        RepeatCategories  = @($repeatSplit.Invariant)
        RepeatOrderSuppressed = @($repeatSplit.Suppressed)
        TotalRounds       = ($aborted.Count + $(if ($null -ne $passing) { 1 } else { 0 }))
        # A passing round exists, NO aborted round, AND that passing round is a TRUE
        # CLEAN (empty categories). A contract-stamped QUALITY verdict era-maps to a
        # non-aborted PASS (Class 'PASS') but KEEPS its finding categories, so it is NOT
        # counted first-attempt-clean -- it carries a non-blocking follow-up entry, and
        # counting that landing clean would hide the quality debt (a NOTE-only pass
        # likewise carries categories and is not a genuine CLEAN).
        # A tied PASS artifact on this row is UNDECIDED evidence about this very
        # commit's gate history, so the row cannot be credited clean even when a
        # different, definite PASS claimed it -- the same reason a boundary-second
        # artifact or an ambiguous tree withholds the credit.
        FirstAttemptClean = (($null -ne $passing) -and ($aborted.Count -eq 0) -and ($boundary.Count -eq 0) -and ($passMatchAmbiguousNames[$i].Count -eq 0) -and (@($passing.Categories).Count -eq 0) -and -not $ambiguousTreeSet.Contains(([string]$c.Tree).ToLowerInvariant()))
        Confidence        = $(if ($tight) { 'tight' } else { 'loose' })
      }) | Out-Null
    $prevEpoch = $thisEpoch
  }
  # `.ToArray()` NOT `@($rows)`: the unary array operator `@()` applied DIRECTLY to
  # a System.Collections.Generic.List[object] whose elements carry nested-array
  # properties (AbortedRounds) throws "Argument types do not match" under Windows
  # PowerShell 5.1. List.ToArray() is the reliable materialization; the caller's
  # own `@(...)` re-collects the enumerated result. (Applies to every direct
  # `@(<List>)` return in this script -- all use .ToArray().)
  return $rows.ToArray()
}

# From an ORDERED (chronological) list of aborted-round verdict records, the
# reviewer categories that appear in >=2 CONSECUTIVE blocking rounds -- the
# single-instance-fix signal (the worker fixed one instance of a category but the
# next round raised the same category again). Returns the distinct repeating
# category names (in $CatNamesAll order). A category raised in rounds 1 and 3 but
# NOT 2 is NOT consecutive and is not reported here (a genuinely re-opened class,
# not a same-round persistence). One or zero rounds -> no repeats.
# Consecutive-repeat categories, split by whether the ORDER decides them.
#
# Consecutive detection reads ADJACENCY, and attempts stamped in one second
# carry no order evidence, so each category is judged against EVERY ordering
# those ties admit -- decided by counting, never by enumerating them. A
# category that repeats under all of them is a property of the evidence and is
# KEPT; one that repeats under some ordering and not others is an artifact of
# enumeration and is SUPPRESSED -- reported separately, never as a repeat and
# never as a silent zero. Suppressing per CATEGORY matters: an earlier definite
# X/X repeat must survive an unrelated later tie, which a whole-row verdict
# would have erased.
# Returns @{ Invariant = @(...); Suppressed = @(...) }. PURE.
function Resolve-RepeatCategories {
  param([object[]]$OrderedRounds)
  # Two QUANTIFIERS over the admissible arrangements, decided EXACTLY and per
  # category -- no enumeration, so no budget and no cap that could erase
  # evidence:
  #   PROVEN    category X is adjacent to itself under EVERY arrangement
  #   POSSIBLE  ... under AT LEAST ONE
  # A proven X is a property of the evidence and is kept; possible-but-not-proven
  # is an artifact of enumeration and is withheld. Per category, because an
  # earlier definite X/X repeat must survive an unrelated later tie.
  #
  # The admissible arrangements are exactly: permute each equal-second BLOCK
  # freely, block order fixed. Pair-shape reasoning cannot answer either
  # quantifier -- a three-member block whose members all carry X has SOME pair
  # adjacent in every arrangement while no PARTICULAR pair is, so reading pairs
  # independently reports "possible" for a repeat that is forced (merge-panel
  # BLOCKER 2026-08-30). Both quantifiers are therefore decided over the whole
  # block-and-boundary structure at once, by counting:
  #
  #   POSSIBLE(X): some block holds two X-bearers, or two ADJACENT blocks each
  #     hold one. Nothing else can meet -- block order is fixed.
  #   PROVEN(X): no arrangement AVOIDS an X/X adjacency. Model each block as
  #     b non-bearers laying out b+1 gaps, at most one X-bearer per gap (two in
  #     one gap would touch); the incoming boundary forbids the leading gap when
  #     the previous block ended on a bearer, and ending on a non-bearer forbids
  #     the trailing gap. A left-to-right walk over the end-state (bearer /
  #     non-bearer) then decides feasibility for the whole sequence: NO
  #     reachable end state means every arrangement is forced into a repeat.
  $seq = @($OrderedRounds)
  if ($seq.Count -lt 2) { return @{ Invariant = @(); Suppressed = @() } }
  $blocks = New-Object 'System.Collections.Generic.List[object]'
  $bi = 0
  while ($bi -lt $seq.Count) {
    $bj = $bi
    while ($bj + 1 -lt $seq.Count -and [long]$seq[$bj + 1].Epoch -eq [long]$seq[$bi].Epoch) { $bj++ }
    $blocks.Add([pscustomobject]@{ Start = $bi; End = $bj }) | Out-Null
    $bi = $bj + 1
  }
  $universe = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($r in $seq) { foreach ($c in @($r.Categories)) { [void]$universe.Add([string]$c) } }
  $invariantSet = New-Object 'System.Collections.Generic.HashSet[string]'
  $possibleSet = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($cat in $universe) {
    # Per block: how many members carry this category, and how many do not.
    $bear = New-Object 'System.Collections.Generic.List[int]'
    $free = New-Object 'System.Collections.Generic.List[int]'
    foreach ($b in $blocks) {
      $nb = 0
      for ($x = $b.Start; $x -le $b.End; $x++) { if (@($seq[$x].Categories) -contains $cat) { $nb++ } }
      $bear.Add($nb) | Out-Null
      $free.Add(($b.End - $b.Start + 1) - $nb) | Out-Null
    }
    $isPossible = $false
    for ($k = 0; $k -lt $blocks.Count; $k++) {
      if ($bear[$k] -ge 2) { $isPossible = $true; break }
      if ($k -lt ($blocks.Count - 1) -and $bear[$k] -ge 1 -and $bear[$k + 1] -ge 1) { $isPossible = $true; break }
    }
    if (-not $isPossible) { continue }
    # Feasibility walk. States: 0 = the arranged prefix ends on a NON-bearer (or
    # is empty, where the leading gap is unconstrained), 1 = it ends on a bearer.
    $canEndFree = $true
    $canEndBear = $false
    for ($k = 0; $k -lt $blocks.Count; $k++) {
      $a = [int]$bear[$k]
      $f = [int]$free[$k]
      $nextFree = $false
      $nextBear = $false
      foreach ($inBear in @($false, $true)) {
        if ($inBear -and -not $canEndBear) { continue }
        if ((-not $inBear) -and -not $canEndFree) { continue }
        # Usable gaps: b+1, less the leading one when the previous block ended
        # on a bearer. With f = 0 the leading and trailing gap are the SAME gap.
        $usable = $f + 1
        if ($inBear) { $usable-- }
        $trailingUsable = if ($inBear -and $f -eq 0) { $false } else { $true }
        # End on a bearer: the trailing gap holds one, the rest go elsewhere.
        if ($a -ge 1 -and $trailingUsable -and $a -le $usable) { $nextBear = $true }
        # End on a non-bearer: the trailing gap stays empty (needs one to exist).
        $usableNoTrail = $usable - $(if ($trailingUsable) { 1 } else { 0 })
        if ($f -ge 1 -and $a -le $usableNoTrail) { $nextFree = $true }
      }
      $canEndFree = $nextFree
      $canEndBear = $nextBear
      if (-not ($canEndFree -or $canEndBear)) { break }
    }
    if (-not ($canEndFree -or $canEndBear)) { [void]$invariantSet.Add([string]$cat) } else { [void]$possibleSet.Add([string]$cat) }
  }
  # Sets are ENUMERATED, never `@(...)`-wrapped: array-wrapping a generic
  # HashSet/List throws "Argument types do not match" under PS 5.1.
  $suppressed = New-Object 'System.Collections.Generic.List[string]'
  $invariant = New-Object 'System.Collections.Generic.List[string]'
  foreach ($c in $invariantSet) { $invariant.Add([string]$c) | Out-Null }
  foreach ($c in $possibleSet) { if (-not $invariantSet.Contains([string]$c)) { $suppressed.Add([string]$c) | Out-Null } }
  return @{ Invariant = @($invariant.ToArray() | Sort-Object); Suppressed = @($suppressed.ToArray() | Sort-Object) }
}


# Group tip-matched merge ARTIFACTS into merge-gate ROUNDS. A round is one
# merge-gate ATTEMPT spanning every panel-child verdict for the same
# (matched commit, base) launched CONCURRENTLY (a single-provider panel's
# tagged same-backend children, or a historical pre-2026-07-22 cross-provider
# codex+claude pair). Artifacts are grouped by
# (MatchedSha, BaseKey -- the canonical audited base identity, so every
# spelling of one base lands in one bucket) and then CLUSTERED by timestamp
# -- NOT keyed on the filename stem -- for two reasons the stem key gets wrong:
#   (a) FALSE SPLIT: every wrapper child stamps its OWN
#       `Get-Date -Format 'yyyyMMdd-HHmmss'`,
#       so one attempt's artifacts can differ by a second -> different
#       stems -> the stem key would report one attempt as several rounds. The (tip,
#       base) scope tag is identical across an attempt's children, and their
#       starts are within seconds (launched concurrently), so the timestamp
#       cluster keeps them together.
#   (b) FALSE MERGE: a SEPARATE auto-merge invocation that re-reviews the SAME tip
#       and base (e.g. a BLOCKED attempt then a same-tip re-run after the fix, or a
#       re-run of a flaky/failed-child pass) is a distinct round, but shares the
#       (tip, base) key. The split signals keeping
#       reruns distinct: a re-run MINUTES+ later trips a gap > $AttemptGapSec; a
#       re-run that REPEATS a (backend, child) member identity already in the
#       current cluster starts a NEW cluster regardless of the gap; and a
#       same-backend ROLE change (p*/fb*/untagged) splits regardless of the
#       gap too (one merge invocation applies ONE uniform -ArtifactTag role
#       per backend and always switches backend on an exhaustion fallback,
#       so a same-backend role mix is provably cross-invocation) -- auto-merge
#       emits at most ONE artifact per member per merge invocation, so a second
#       same-member artifact for this tip/base is necessarily a new attempt; this
#       catches a SAME-member fast rerun that starts within $AttemptGapSec,
#       which the gap signal alone would fold in. A DISJOINT-member fast
#       rerun across backends carries no repeat to trip -- every cross-
#       backend fold is UNDECIDABLE (one attempt vs two single-provider
#       reruns, no gate-run identifier) and the cluster is MARKED Ambiguous
#       (non-authoritative) instead of counted. The
#       member-repeat split mirrors Group-CommitGateAttempts' backend-repeat
#       split. Note the ASYMMETRY:
#       Group-CommitGateAttempts ALSO splits when the current attempt is already
#       BLOCKED/QUALITY (the commit gate runs its backends in SERIES and short-
#       circuits after a failure, so a second backend never joins a blocked run).
#       The MERGE gate does NOT: it launches its panel children CONCURRENTLY with
#       no short-circuit, so a BLOCKED child beside PASS siblings IS one attempt
#       (folded to the worst class) -- applying a non-PASS split here would wrongly
#       break that single attempt into two.
# Each round's outcome is the WORST class across its cluster's backend artifacts;
# its Epoch is the EARLIEST cluster-artifact epoch; its Ambiguous flag marks
# every multi-backend fold (non-authoritative, see the in-loop rationale). Each input artifact is a [pscustomobject] with
# MatchedSha, MatchedShort, Base (display token), BaseKey (canonical base
# identity; absent = Base is already canonical), Backend, Class, Epoch, Child.
# PURE.
# The panel launch-clustering window (seconds). ONE definition shared by
# every launch-window consumer so they stay one contract: Group-MergeRounds'
# attempt clustering and the sidecar quarantine's time scope (a sidecar only
# quarantines siblings launched within this window of it). The COMMIT-gate
# fold decision deliberately does NOT consume it -- elapsed time proves
# nothing about a rerun there (gate BLOCKER 2026-07-24); see
# Group-CommitGateAttempts' cardinality predicate.
$script:PanelAttemptGapSec = 120
# ---------------------------------------------------------------------------
# ORDER STABILITY, shared by both grouping functions.
#
# Producer timestamps resolve to WHOLE SECONDS. Artifacts stamped in the same
# second therefore carry NO evidence of their order, while both fold predicates
# are order-sensitive: which artifact opens a cluster decides whether a later
# one joins it or splits from it, and the answer differs. A partition that
# depends on an order the evidence does not contain is not a finding -- it is
# an artifact of directory enumeration (merge-panel BLOCKER 2026-08-30).
#
# So the grouping is evaluated under EVERY ordering the evidence permits: the
# epoch order is fixed, and the artifacts inside each equal-second run are
# permuted. An attempt that comes out IDENTICAL under every one of those
# orderings is order-independent and stays authoritative; an attempt that does
# not is marked OrderAmbiguous -- its OWN state, never the legacy Ambiguous.
# The judgement is per ATTEMPT, never per bucket: an
# independent round separated by a gap appears identically in every ordering,
# so an unrelated same-second ambiguity elsewhere in the bucket cannot suppress
# it. Comparing whole orderings (not just the members of one second) is what
# catches an equal-second artifact whose effect depends on the cluster ALREADY
# open when it arrives.
#
# The enumeration is the FULL CARTESIAN product of the tie blocks' permutations,
# and must stay that way. Permuting one block while every other stays canonical
# is unsound here: a cluster key can survive each block varied alone and still
# move when two vary together (a first block ordered `[none, none, p1]` and a
# second `[none, p2]` keep the canonical key that `[none, p1, none]` with
# `[p2, none]` displaces), which publishes an order-dependent grouping as
# authoritative (merge-panel BLOCKER 2026-08-30). Grouping is a WHOLE-SEQUENCE
# reading -- a cluster's boundaries depend on its neighbours -- so nothing
# cheaper than the product answers it, and a block too large to enumerate
# withholds authority from the entire grouping rather than part of it.
#
# The repeat analysis, which used to share this budget and lose evidence to it,
# no longer calls here at all: its question is per category and is decided
# exactly by counting (Resolve-RepeatCategories).
function Get-EvidenceOrderings {
  param([object[]]$Canonical, [int]$MaxOrderings = 720)
  $runs = New-Object 'System.Collections.Generic.List[object]'
  $i = 0
  while ($i -lt $Canonical.Count) {
    $j = $i
    while ($j + 1 -lt $Canonical.Count -and [long]$Canonical[$j + 1].Epoch -eq [long]$Canonical[$i].Epoch) { $j++ }
    $runs.Add(@($Canonical[$i..$j])) | Out-Null
    $i = $j + 1
  }
  # Counted BEFORE anything is built: the product is what would be materialized,
  # so a bucket past the bound must refuse before paying for it.
  $total = 1
  foreach ($r in $runs) {
    $f = 1
    for ($n = 2; $n -le $r.Count; $n++) { $f = $f * $n }
    $total = $total * $f
    if ($total -gt $MaxOrderings) { return $null }
  }
  $orderings = New-Object 'System.Collections.Generic.List[object]'
  $orderings.Add(@()) | Out-Null
  foreach ($r in $runs) {
    $perms = Get-Permutations -Items $r
    $next = New-Object 'System.Collections.Generic.List[object]'
    foreach ($prefix in $orderings) {
      foreach ($p in $perms) { $next.Add(@($prefix) + @($p)) | Out-Null }
    }
    $orderings = $next
  }
  return , $orderings.ToArray()
}

function Get-Permutations {
  param([object[]]$Items)
  if ($Items.Count -le 1) { return , @($Items) }
  $out = New-Object 'System.Collections.Generic.List[object]'
  for ($i = 0; $i -lt $Items.Count; $i++) {
    $rest = @()
    for ($j = 0; $j -lt $Items.Count; $j++) { if ($j -ne $i) { $rest += , $Items[$j] } }
    foreach ($p in (Get-Permutations -Items $rest)) { $out.Add(@(, $Items[$i]) + @($p)) | Out-Null }
  }
  return , $out.ToArray()
}

# Group one bucket under the canonical order, then mark every produced cluster
# that any evidence-consistent ordering would have produced differently.
# $Grouper takes an ordered artifact array and returns clusters; $KeyOf renders
# a cluster as the identity that must survive reordering (its member set and
# its outcome).
# A cluster's comparison key: its EPOCH, its ordinal AMONG CLUSTERS OF THAT
# EPOCH, and its content. Position matters -- two orderings that publish the
# same clusters in a different sequence still make different statements ("the
# first round blocked, the second passed" and its reverse) -- but position must
# be measured WITHIN the second it is unknowable in. A whole-list index made a
# later, order-independent round's key depend on how many clusters the earlier
# permutation happened to produce, which reported that untouched round as
# ambiguous.
function Get-ClusterStabilityKeys {
  param([object[]]$Clusters, [string]$KeyOf)
  $keys = New-Object 'System.Collections.Generic.List[string]'
  $seen = @{}
  foreach ($c in $Clusters) {
    $e = [string]([long]$c.Epoch)
    $n = if ($seen.ContainsKey($e)) { [int]$seen[$e] } else { 0 }
    $seen[$e] = $n + 1
    $keys.Add("$e|$n|" + [string](& $KeyOf $c)) | Out-Null
  }
  # Unwrapped: the elements are STRINGS, so nothing nests and `@(...)` at the
  # call site re-wraps a single one. (Wrapping here collapsed the whole list
  # into one joined string, and every cluster then failed to match.)
  return $keys.ToArray()
}

function Resolve-OrderStableGrouping {
  param([object[]]$Canonical, [string]$Grouper, [string]$KeyOf, [int]$MaxOrderings = 720)
  $canonicalClusters = @(& $Grouper $Canonical)
  $orderings = Get-EvidenceOrderings -Canonical $Canonical -MaxOrderings $MaxOrderings
  if ($null -eq $orderings) {
    # A bucket past the enumeration bound is an UNRESOLVED ORDERING, not the
    # legacy one-vs-two-invocation uncertainty: it sets this mechanism's own
    # flag and leaves any independently established legacy flag exactly as the
    # grouper left it. EVERY cluster loses authority, deliberately -- grouping
    # is a whole-sequence reading, so an unenumerated interaction can move any
    # cluster's key, and a partial exemption would be the same unsound
    # isolation the bound exists to avoid.
    foreach ($c in $canonicalClusters) { $c.OrderAmbiguous = $true }
    return $canonicalClusters
  }
  $common = $null
  foreach ($o in $orderings) {
    $keys = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($kk in @(Get-ClusterStabilityKeys -Clusters @(& $Grouper @($o)) -KeyOf $KeyOf)) { [void]$keys.Add([string]$kk) }
    if ($null -eq $common) { $common = $keys } else { $common.IntersectWith($keys) }
  }
  $canonicalKeys = @(Get-ClusterStabilityKeys -Clusters $canonicalClusters -KeyOf $KeyOf)
  for ($ci = 0; $ci -lt $canonicalClusters.Count; $ci++) {
    if ($null -eq $common -or -not $common.Contains([string]$canonicalKeys[$ci])) { $canonicalClusters[$ci].OrderAmbiguous = $true }
  }
  return $canonicalClusters
}

function Group-MergeRounds {
  param([object[]]$Artifacts, [int]$AttemptGapSec = $script:PanelAttemptGapSec)
  $rank = @{ 'PASS' = 0; 'QUALITY' = 1; 'BLOCKED' = 2 }
  # Bucket by (matched tip, base). Base is the artifact's DISPLAY token (the
  # filename spelling that matched); BaseKey is the CANONICAL audited base
  # identity every post-match consumer keys on, so a SHA-spelled and a
  # ref-spelled artifact for one audited base land in ONE bucket. A record
  # without BaseKey keys on its Base token.
  $byKey = @{}
  foreach ($a in $Artifacts) {
    $aBaseKey = if ($null -ne $a.PSObject.Properties['BaseKey'] -and -not [string]::IsNullOrEmpty([string]$a.BaseKey)) { [string]$a.BaseKey } else { [string]$a.Base }
    $k = "$($a.MatchedSha)|$aBaseKey"
    if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object 'System.Collections.Generic.List[object]' }
    $byKey[$k].Add($a) | Out-Null
  }
  $rounds = New-Object 'System.Collections.Generic.List[object]'
  foreach ($k in $byKey.Keys) {
    # Within a (tip, base) bucket, walk artifacts in time order and start a NEW
    # round whenever EITHER the gap from the previous artifact exceeds
    # $AttemptGapSec (a re-run minutes later) OR the current cluster ALREADY
    # holds this artifact's MEMBER identity -- the (backend, child) pair, not
    # the backend alone. A single-provider claude panel emits one artifact PER
    # child with a DISTINCT `-p<n>`/`-fb<n>` -ArtifactTag, so same-backend
    # siblings with different child ids are ONE attempt; a repeated identity
    # (same backend AND same child token, incl. both untagged) is necessarily a
    # NEW attempt -- that repeat-split catches a SAME-member fast rerun that
    # STARTS within the gap, which the timestamp split alone would fold in
    # and mis-count (a QUALITY/BLOCKED first attempt + a quick PASS rerun
    # would collapse to one non-passing round, undercounting the landing).
    # A DISJOINT-member cross-backend fold has no repeat to trip and is
    # instead MARKED Ambiguous below (every multi-backend cluster). Mirrors
    # Group-CommitGateAttempts' backend-repeat split; else fold into the
    # current round. (Codex BLOCKER lineage: timestamp-only splitting collapsed
    # quick reruns; backend-only splitting over-split tagged panel siblings.)
    # The PUBLISHED partition is unchanged -- the same epoch order this grouping
    # always used. What the permutation pass adds is the judgement about which of
    # its rounds may be called AUTHORITATIVE (Resolve-OrderStableGrouping); it
    # never rewrites the partition, so a reordering cannot silently republish a
    # different set of rounds.
    $canonical = @($byKey[$k] | Sort-Object -Property Epoch)
    $script:MergeRoundGapSec = $AttemptGapSec
    foreach ($r in @(Resolve-OrderStableGrouping -Canonical $canonical -Grouper 'New-MergeRoundsForBucket' -KeyOf 'Get-MergeRoundKey')) { $rounds.Add($r) | Out-Null }
  }
  return @($rounds.ToArray() | Sort-Object -Property Epoch)
}

# A round's identity for the order-stability comparison: the members it holds
# and the outcome it publishes.
function Get-MergeRoundKey {
  param($Round)
  return ((@($Round.Members | Sort-Object) -join '+') + '|' + [string]$Round.Class)
}

function New-MergeRoundsForBucket {
  param([object[]]$Ordered)
  $rank = @{ 'PASS' = 0; 'QUALITY' = 1; 'BLOCKED' = 2 }
  $AttemptGapSec = $script:MergeRoundGapSec
  $rounds = New-Object 'System.Collections.Generic.List[object]'
  $cluster = $null
  $prevEpoch = $null
  foreach ($a in $Ordered) {
      $member = "$($a.Backend)|$($a.Child)"
      # Role of the child token: 'p' (primary panel child), 'fb' (fallback
      # panel child), 'none' (untagged). PRODUCER CONTRACT (gate BLOCKER
      # 2026-07-24): auto-merge routes an exhaustion fallback to the OTHER
      # backend (Resolve-MergeFallbackDecision) and applies ONE uniform
      # -ArtifactTag role to every child of a panel, so a SAME-backend role
      # mix (p*->fb*, or tagged->untagged) cannot come from one merge
      # invocation -- a DEFINITE rerun, split authoritatively.
      $aRole = if ([string]::IsNullOrEmpty([string]$a.Child)) { 'none' } elseif (([string]$a.Child) -match '^fb') { 'fb' } else { 'p' }
      $roleChange = ($null -ne $cluster -and $cluster.BackendRoles.ContainsKey([string]$a.Backend) -and $cluster.BackendRoles[[string]$a.Backend] -ne $aRole)
      $startNew = ($null -eq $cluster -or ([long]$a.Epoch - [long]$prevEpoch) -gt $AttemptGapSec -or $cluster.Members.Contains($member) -or $roleChange)
      if ($startNew) {
        $cluster = [pscustomobject]@{
          MatchedSha      = $a.MatchedSha
          MatchedShort    = $a.MatchedShort
          Base            = $a.Base
          Epoch           = [long]$a.Epoch
          Class           = $a.Class
          Backends        = (New-Object 'System.Collections.Generic.List[string]')
          Members         = (New-Object 'System.Collections.Generic.List[string]')
          BackendRoles    = @{}
          Ambiguous       = $false
          OrderAmbiguous  = $false
        }
        $rounds.Add($cluster) | Out-Null
      }
      if (-not $cluster.Backends.Contains([string]$a.Backend)) { $cluster.Backends.Add([string]$a.Backend) | Out-Null }
      if (-not $cluster.Members.Contains($member)) { $cluster.Members.Add($member) | Out-Null }
      if (-not $cluster.BackendRoles.ContainsKey([string]$a.Backend)) { $cluster.BackendRoles[[string]$a.Backend] = $aRole }
      if ($rank[[string]$a.Class] -gt $rank[[string]$cluster.Class]) { $cluster.Class = $a.Class }
      # CROSS-BACKEND FOLD AMBIGUITY. Under the single-provider panel
      # contract one merge invocation never emits artifacts from two
      # backends, and the historical both-provider attempt shape is
      # INDISTINGUISHABLE from two single-provider reruns that chose
      # different backends (the same artifacts, no run identity). Counting
      # such a fold as one round would undercount rounds; guessing two would
      # overcount the historical shape. Every multi-backend cluster is
      # therefore MARKED ambiguous and excluded from authoritative
      # statistics (listed, not counted) until producer-stamped run identity
      # exists (framing migration follow-up).
    if ($cluster.Backends.Count -gt 1) { $cluster.Ambiguous = $true }
    $prevEpoch = [long]$a.Epoch
  }
  return $rounds.ToArray()
}

# Group commit-gate ARTIFACTS into gate ATTEMPTS. A single pre-commit gate run can
# emit one artifact PER BACKEND for the SAME reviewed staged tree
# (REVIEW_BACKEND=both), and scripts/git-hooks/pre-commit runs the backends in
# SERIES (Codex first, Claude only after Codex passes) -- so the codex + claude
# `-staged.md` of ONE run share a tree but can be a full Codex-review duration
# (minutes) apart. A launch-time cluster would wrongly split one run into two, so
# artifacts are bucketed by the shared reviewed TREE. But within a tree, a worker
# can RE-RUN the gate on UNCHANGED staged content (after a false positive or a
# nondeterministic review), producing another artifact from the SAME backend -- a
# DISTINCT attempt (e.g. run 1 BLOCKED, run 2 PASS: keeping only the worst class
# would drop the passing round and mislabel the commit as hook-bypassed). So within
# a tree bucket, artifacts (in time order) fold into the CURRENT attempt UNLESS the
# artifact's backend is ALREADY in it OR the current attempt is already
# BLOCKED/QUALITY -- either starts a NEW attempt, EXCEPT the undecidable
# both-mode-fallback shape, decided by PRODUCER-CONTRACT CARDINALITY and
# never by elapsed time (gate BLOCKERs 2026-07-24; the full derivation from
# pre-commit's dispatch lives at the fold predicate in the loop below): a
# same-backend repeat onto a ONE-artifact PASS attempt is inside the
# one-invocation fallback space -> folded and MARKED Ambiguous (the caller
# excludes marked attempts before correlation; the category union keeps
# every same-tree pass); any artifact onto a TWO-artifact attempt is outside
# the space -> a DEFINITE rerun, split authoritatively. The non-PASS split
# follows from the SHORT-CIRCUIT: a both-mode run only reaches its SECOND
# leg when the first produced a PASS artifact or exhausted (no valid
# artifact), so once an attempt is BLOCKED/QUALITY it cannot legitimately
# acquire another artifact -- a later same-tree artifact (even a DIFFERENT
# backend, e.g. a Claude PASS after a Codex BLOCKED) is a NEW run whose PASS
# must be its own attempt; folding it into the blocked attempt would sink
# its PASS and mislabel the landed commit as missing a passing gate round.
# A LEGACY artifact with NO tree header is keyed by
# its filename so each is its own attempt. Each returned attempt exposes:
# TreeOid, Epoch (earliest = review start), Class (worst), Categories (union),
# Backends, Name (earliest artifact's), Names, Ambiguous, OrderAmbiguous.
# PURE.
function Group-CommitGateAttempts {
  param([object[]]$Artifacts)
  $byTree = @{}
  foreach ($a in $Artifacts) {
    $treeKey = if ([string]::IsNullOrWhiteSpace([string]$a.TreeOid)) { "NAME:$($a.Name)" } else { ([string]$a.TreeOid).ToLowerInvariant() }
    if (-not $byTree.ContainsKey($treeKey)) { $byTree[$treeKey] = New-Object 'System.Collections.Generic.List[object]' }
    $byTree[$treeKey].Add($a) | Out-Null
  }
  $out = New-Object 'System.Collections.Generic.List[object]'
  foreach ($k in $byTree.Keys) {
    # The PUBLISHED partition is unchanged -- the same epoch order this grouping
    # always used. The permutation pass only decides which attempts may be called
    # AUTHORITATIVE (Resolve-OrderStableGrouping); it never rewrites the
    # partition.
    $canonical = @($byTree[$k] | Sort-Object -Property Epoch)
    foreach ($att in @(Resolve-OrderStableGrouping -Canonical $canonical -Grouper 'New-CommitGateAttemptsForBucket' -KeyOf 'Get-CommitGateAttemptKey')) { $out.Add($att) | Out-Null }
  }
  return @($out.ToArray() | Sort-Object -Property Epoch)
}

# An attempt's identity for the order-stability comparison: the artifacts it
# holds and the outcome it publishes. Two orderings agree about an attempt only
# when both of those match.
function Get-CommitGateAttemptKey {
  param($Attempt)
  return ((@($Attempt.Names | Sort-Object) -join '+') + '|' + [string]$Attempt.Class)
}

function New-CommitGateAttemptsForBucket {
  param([object[]]$Ordered)
  $rank = @{ 'PASS' = 0; 'QUALITY' = 1; 'BLOCKED' = 2 }
  $out = New-Object 'System.Collections.Generic.List[object]'
  $current = $null
  foreach ($a in $Ordered) {
      # PRODUCER-CONTRACT CARDINALITY, never elapsed time (gate BLOCKERs
      # 2026-07-24: a fallback pair can straddle any wall-clock gap, and a
      # window folded definite reruns). The per-invocation valid-artifact
      # space, derived from scripts/git-hooks/pre-commit's own dispatch: one
      # invocation runs AT MOST TWO legs (`run_leg codex` then -- only after
      # leg 1 returned 0 -- `run_leg claude` in `both` mode; one leg
      # otherwise), and each leg calls run_backend_for at most twice (the
      # primary, plus the OTHER backend once on primary exit 4), yielding AT
      # MOST ONE valid staged artifact per leg (an exhausted codex primary
      # leaves only a fail-closed SUSPECT banner, an exhausted claude primary
      # leaves no .md at all). Therefore one invocation emits at most TWO
      # valid same-tree artifacts, a same-backend pair only as
      # (fallback leg + own leg) where the earlier artifact PASSED, and a
      # THIRD same-tree artifact never. Decision table:
      #   - same-backend repeat onto a ONE-artifact PASS attempt: inside the
      #     space -> UNDECIDABLE (fallback pair vs rerun) -> fold, MARK
      #     Ambiguous (signal-only downstream, excluded before correlation);
      #   - ANY artifact onto a TWO-artifact attempt: outside the space ->
      #     DEFINITE rerun -> authoritative split;
      #   - any artifact after a BLOCKED/QUALITY attempt: the short-circuit
      #     (leg 2 requires leg 1 pass; a failed primary never gains a
      #     fallback sibling artifact) makes it a rerun -> split.
      $backendRepeat = ($null -ne $current -and $current.Backends.Contains([string]$a.Backend))
      $atCapacity = ($null -ne $current -and $current.Names.Count -ge 2)
      $ambiguousFold = ($backendRepeat -and -not $atCapacity -and $null -ne $current -and $current.Class -eq 'PASS')
      if ($null -eq $current -or $atCapacity -or ((-not $ambiguousFold) -and ($backendRepeat -or $current.Class -ne 'PASS'))) {
        $current = [pscustomobject]@{
          TreeOid    = [string]$a.TreeOid
          Epoch      = [long]$a.Epoch
          Class      = 'PASS'
          Categories = (New-Object 'System.Collections.Generic.List[string]')
          Backends   = (New-Object 'System.Collections.Generic.List[string]')
          Name       = [string]$a.Name
          Names      = (New-Object 'System.Collections.Generic.List[string]')
          Ambiguous      = $false
          OrderAmbiguous = $false
        }
        $out.Add($current) | Out-Null
      } elseif ($ambiguousFold) {
        $current.Ambiguous = $true
      } elseif (-not $backendRepeat) {
        # A DIFFERENT backend joining a one-artifact PASS attempt is the
        # both-mode shape -- and also exactly what two single-backend reruns
        # of the same tree with different REVIEW_BACKEND selections leave
        # behind. Without run identity the fold is UNDECIDABLE (one
        # invocation vs two), so it is kept as one attempt for evidence
        # (worst class, category union) but MARKED ambiguous: never an
        # authoritative round, never first-attempt-CLEAN credit.
        $current.Ambiguous = $true
      }
      if ($rank[[string]$a.Class] -gt $rank[[string]$current.Class]) { $current.Class = $a.Class }
      foreach ($cat in @($a.Categories)) { if (-not $current.Categories.Contains([string]$cat)) { $current.Categories.Add([string]$cat) | Out-Null } }
      if (-not $current.Backends.Contains([string]$a.Backend)) { $current.Backends.Add([string]$a.Backend) | Out-Null }
    $current.Names.Add([string]$a.Name) | Out-Null
    if ([long]$a.Epoch -lt [long]$current.Epoch) { $current.Epoch = [long]$a.Epoch; $current.Name = [string]$a.Name }
  }
  return $out.ToArray()
}

# ---------------------------------------------------------------------------
# Git-facts resolution: Resolve-GitFacts returns
#   @{ TipSha; TipShort; BaseRef; BaseSha; BaseTree; BaseEpoch;
#      ParentEpochs = @{ <parent sha outside the range> = epoch };
#      Commits = @(@{ Sha; Short; Tree; Epoch; Subject; FileCount; Parents; TopoIndex }, ...) }  # chronological (oldest first), TopoIndex = parent-order position
# Resolve-GitFacts is NON-pure (git probe).
# ---------------------------------------------------------------------------
function Invoke-GitOrNull {
  # Run git, return trimmed stdout on success, $null on non-zero exit (so callers
  # fail loud with a clear message rather than an opaque git error).
  param([string[]]$GitArgs)
  $out = & git @GitArgs 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return (($out | Out-String).TrimEnd("`r", "`n"))
}

# Chronological order, oldest first, stable on the parent-order index for equal seconds.
function Sort-GitFactsChronological {
  param([object[]]$Commits)
  $sorted = New-Object 'System.Collections.Generic.List[object]'
  foreach ($cc in @(@($Commits) | Sort-Object -Property @{ Expression = { [long]$_.Epoch } }, @{ Expression = { [int]$_.TopoIndex } })) { $sorted.Add($cc) | Out-Null }
  # The unary comma keeps the List whole through the pipeline (a bare return
  # would enumerate it into an array and drop the callers' List surface).
  return ,$sorted
}

function Resolve-GitFacts {
  param([string]$Branch, [string]$Base, [string]$BaseRef = '')
  $tipSha = Invoke-GitOrNull @('rev-parse', '--verify', "$Branch^{commit}")
  if ([string]::IsNullOrWhiteSpace($tipSha)) {
    Write-Host "[worker-audit] ERROR: [class:operational] branch/tip '$Branch' does not resolve to a commit."
    return $null
  }
  # merge-base(Base, Branch) is the fork point. Passing an explicit fork SHA as
  # -Base yields that SHA (its merge-base with a descendant tip is itself), so the
  # range is correct both PRE-merge (Base=master) and POST-merge (Base=fork SHA).
  $baseSha = Invoke-GitOrNull @('merge-base', $Base, $tipSha)
  if ([string]::IsNullOrWhiteSpace($baseSha)) {
    Write-Host "[worker-audit] ERROR: [class:operational] could not compute merge-base of '$Base' and '$Branch' (unrelated histories or bad base)."
    return $null
  }
  $baseTree = Invoke-GitOrNull @('rev-parse', '--verify', "$baseSha^{tree}")
  if ([string]::IsNullOrWhiteSpace($baseTree)) {
    Write-Host "[worker-audit] ERROR: [class:operational] could not resolve the tree of merge-base $baseSha."
    return $null
  }
  # Every git fact is VALIDATED, never defaulted: a failed numeric parse, a
  # malformed record, or a failed native call would otherwise become a zero
  # epoch, a dropped commit, or a zero file count -- fabricated metrics in a
  # report that carries no unreliable marker. Invalid facts fail the run.
  $baseEpochStr = Invoke-GitOrNull @('show', '-s', '--format=%ct', $baseSha)
  $baseEpoch = 0L
  if (-not [long]::TryParse(([string]($baseEpochStr | Select-Object -First 1)).Trim(), [ref]$baseEpoch)) {
    Write-Host "[worker-audit] ERROR: [class:operational] the merge-base commit time did not parse as an integer ('$baseEpochStr')."
    return $null
  }

  # Commit list oldest-first. Fields are delimited by the ASCII Unit Separator
  # (0x1F) which git emits via `%x1f`. The SUBJECT is the LAST field and the
  # split is bounded to the fixed field count, so a subject that itself
  # carries 0x1F (git permits any byte but NUL and newline in a subject)
  # stays whole instead of shattering the record; the fixed fields (ids,
  # epoch, parents) cannot contain 0x1F. Records are newline-separated. The
  # PS-side split uses String.Split([char]0x1F, n) -- NOT a `` `u{1f} ``
  # escape, which does not exist in Windows PowerShell 5.1 (that escape was
  # added in PowerShell 6; in 5.1 it would be the literal text `u{1f}` and the
  # split would silently fail to 1 field).
  $usSep = [char]0x1F
  # --topo-order: the branch order is the PARENT order, never git's default
  # date order -- a child dated earlier than its parent would otherwise sort
  # ahead of it and hide the very inversion the non-monotonic check exists
  # to catch (window attribution would then misassign blocking artifacts
  # without the UNRELIABLE marker).
  $logOut = & git log --reverse --topo-order --format='%H%x1f%h%x1f%T%x1f%ct%x1f%P%x1f%s' "$baseSha..$tipSha" 2>$null
  if ($LASTEXITCODE -ne 0) {
    Write-Host "[worker-audit] ERROR: [class:operational] git log for range $baseSha..$tipSha failed."
    return $null
  }
  $commits = New-Object 'System.Collections.Generic.List[object]'
  foreach ($line in @($logOut)) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    # The separator is an explicit [char[]] so .NET Framework binds
    # Split(char[], int): with a bare [char] PowerShell 5.1 resolves to
    # Split(string[], StringSplitOptions) -- the count coerces to the enum --
    # and the split runs UNBOUNDED (RG2 caught exactly that: 7 fields).
    $f = $line.Split([char[]]@($usSep), 6)
    # Exactly the six producer fields: a torn record splits into fewer -- an
    # invalid fact (more is impossible under the bounded split).
    if ($f.Count -ne 6) {
      Write-Host "[worker-audit] ERROR: [class:operational] a git log record did not split into exactly six fields (got $($f.Count)); refusing to audit on malformed facts."
      return $null
    }
    $sha = $f[0].Trim()
    if ($sha -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$' -or ($f[2].Trim()) -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$' -or [string]::IsNullOrWhiteSpace($f[1].Trim())) {
      Write-Host "[worker-audit] ERROR: [class:operational] a git log record carries a malformed commit/tree id ('$sha' / '$($f[2].Trim())'); refusing to audit on malformed facts."
      return $null
    }
    $ep = 0L
    if (-not [long]::TryParse($f[3].Trim(), [ref]$ep)) {
      Write-Host "[worker-audit] ERROR: [class:operational] the committer time of $sha did not parse as an integer ('$($f[3])'); refusing to audit on malformed facts."
      return $null
    }
    $parents = @(($f[4].Trim()) -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($parentSha in $parents) {
      if ($parentSha -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
        Write-Host "[worker-audit] ERROR: [class:operational] a git log record carries a malformed parent id ('$parentSha') for $sha; refusing to audit on malformed facts."
        return $null
      }
    }
    # Files changed by THIS commit against its FIRST PARENT, as an explicit
    # two-tree comparison: the single-commit `diff-tree <merge>` form prints
    # NOTHING for a merge commit (no per-parent diff without -m), which would
    # publish a zero file count for every merge a branch carries. A root
    # commit (no parent) lists all its files via --root. Count distinct paths;
    # the native status decides, never a defaulted zero.
    if ($parents.Count -gt 0) {
      $names = & git diff-tree --no-commit-id --name-only -r $parents[0] $sha 2>$null
    } else {
      $names = & git diff-tree --no-commit-id --name-only -r --root $sha 2>$null
    }
    if ($LASTEXITCODE -ne 0) {
      Write-Host "[worker-audit] ERROR: [class:operational] git diff-tree failed for $sha; refusing to audit on incomplete facts."
      return $null
    }
    $fileCount = @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    $commits.Add([pscustomobject]@{
        Sha       = $sha
        Short     = $f[1].Trim()
        Tree      = $f[2].Trim()
        Epoch     = $ep
        Subject   = $f[5]
        FileCount = $fileCount
        Parents   = @($parents)
        TopoIndex = $commits.Count
      }) | Out-Null
  }
  # The correlation engine's windows need CHRONOLOGICAL order (oldest first,
  # stable on the topological index for equal seconds): a merge DAG's
  # --topo-order groups one side history before another and would produce
  # decreasing timestamps between UNRELATED commits. True parent-child
  # inversions are detected separately from the Parents field (the
  # non-monotonic check in the pipeline).
  $commits = Sort-GitFactsChronological -Commits $commits.ToArray()
  # Parents OUTSIDE the audited range (the base itself, or a side history
  # already reachable from the base) still bound their children: a child
  # dated after the base yet before such a parent is a true inversion the
  # in-range map alone would miss. Every out-of-range parent's epoch is
  # resolved (validated, never defaulted) so the pipeline's check sees
  # every recorded parent edge.
  $inRange = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($cc in $commits) { [void]$inRange.Add(([string]$cc.Sha).ToLowerInvariant()) }
  $parentEpochs = @{}
  foreach ($cc in $commits) {
    foreach ($pSha in @($cc.Parents)) {
      $pk = ([string]$pSha).ToLowerInvariant()
      if ($inRange.Contains($pk) -or $parentEpochs.ContainsKey($pk)) { continue }
      $pEpochStr = Invoke-GitOrNull @('show', '-s', '--format=%ct', $pk)
      $pEpoch = 0L
      if (-not [long]::TryParse(([string]($pEpochStr | Select-Object -First 1)).Trim(), [ref]$pEpoch)) {
        Write-Host "[worker-audit] ERROR: [class:operational] the committer time of parent $pk (outside the audited range) did not parse ('$pEpochStr'); refusing to audit on malformed facts."
        return $null
      }
      $parentEpochs[$pk] = $pEpoch
    }
  }
  return [pscustomobject]@{
    ParentEpochs = $parentEpochs
    TipSha    = $tipSha
    TipShort  = $tipSha.Substring(0, [Math]::Min(12, $tipSha.Length))
    BaseRef   = $(if (-not [string]::IsNullOrWhiteSpace($BaseRef)) { $BaseRef } else { $Base })
    BaseSha   = $baseSha
    BaseTree  = $baseTree
    BaseEpoch = $baseEpoch
    Commits   = $commits.ToArray()
  }
}


# Parse the escalations[] out of a worker status.json. Returns @{ Available;
# Reason; Count; Escalations } -- tolerant of absence / unreadability / malformed
# JSON (Available=$false + a Reason), never throwing. The status file is
# WORKER-CONTROLLED input that lands in the audit's Markdown: every summary is
# rendered as ONE bounded line -- control characters (CR/LF included) become
# spaces, `<` is entity-escaped so no HTML comment can open and hide the
# sections that follow, the text is truncated -- and an entry without a
# string `reason` is named as schema-invalid rather than stringified (the
# multi-line Out-String rendering was the injection vector). An
# `escalations` value that is not an array is a schema failure (Available
# false), never coerced into one entry.
#
# The same encoder guards EVERY external string the report interpolates --
# commit subjects (git permits `<!--` and backticks in a subject), artifact
# and sidecar file names, directory paths, the base ref, and error text:
# a raw `<!--` would hide the rest of the report and a stray backtick
# would swallow the following text into a code span. Backticks become
# `&#96;`, so a name the report deliberately wraps in backticks keeps its
# wrapper intact.
function ConvertTo-BoundedMarkdownLine {
  param([string]$Text, [int]$MaxChars = 400)
  $t = [string]$Text
  $t = $t -replace '[\p{Cc}\p{Zl}\p{Zp}]+', ' '
  $t = ($t -replace '\s+', ' ').Trim()
  $t = $t -replace '<', '&lt;'
  $t = $t -replace '`', '&#96;'
  # The `](` JOINT, not the brackets: a commit subject or status reason carrying
  # `[text](url)` or `![alt](src)` otherwise renders as a live link or an image
  # fetch instead of the report DATA it is (merge-panel QUALITY 2026-08-30).
  # Breaking the joint makes both inert while leaving every bracket readable --
  # and this report composes its own bracketed labels (`[codex] name -- reason`)
  # through this same boundary, so escaping `[` wholesale would mangle the
  # structure it is meant to protect.
  $t = $t -replace '\]\(', ']&#40;'
  if ($t.Length -gt $MaxChars) { $t = $t.Substring(0, $MaxChars) + '...' }
  return $t
}
function Get-StatusEscalations {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) {
    return [pscustomobject]@{ Available = $false; Reason = 'no -StatusFile provided'; Count = 0; Escalations = @() }
  }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return [pscustomobject]@{ Available = $false; Reason = "status file not found: $Path"; Count = 0; Escalations = @() }
  }
  try {
    $bounded = Read-BoundedFileBytes -Path $Path -MaxBytes $script:StatusReadMaxBytes
    if (-not $bounded.Ok) {
      return [pscustomobject]@{ Available = $false; Reason = "status file unreadable: $($bounded.Reason)"; Count = 0; Escalations = @() }
    }
    $raw = [System.Text.Encoding]::UTF8.GetString($bounded.Bytes)
    $j = $raw | ConvertFrom-Json
  } catch {
    return [pscustomobject]@{ Available = $false; Reason = "status file unreadable / not valid JSON: $($_.Exception.Message)"; Count = 0; Escalations = @() }
  }
  if ($null -eq $j -or -not ($j -is [System.Management.Automation.PSCustomObject])) {
    return [pscustomobject]@{ Available = $false; Reason = 'status file JSON is not an object'; Count = 0; Escalations = @() }
  }
  $escProp = $j.PSObject.Properties['escalations']
  $esc = @()
  if ($null -ne $escProp -and $null -ne $escProp.Value) {
    if (-not ($escProp.Value -is [System.Array])) {
      return [pscustomobject]@{ Available = $false; Reason = 'status file `escalations` is not an array (schema-invalid)'; Count = 0; Escalations = @() }
    }
    $esc = @($escProp.Value)
  }
  $summaries = foreach ($e in $esc) {
    $reasonProp = if ($null -ne $e -and $e -is [System.Management.Automation.PSCustomObject]) { $e.PSObject.Properties['reason'] } else { $null }
    if ($null -ne $reasonProp -and ($reasonProp.Value -is [string]) -and -not [string]::IsNullOrWhiteSpace([string]$reasonProp.Value)) {
      ConvertTo-BoundedMarkdownLine -Text ([string]$reasonProp.Value) -MaxChars 200
    } else {
      '(schema-invalid escalation entry: no string `reason`)'
    }
  }
  return [pscustomobject]@{ Available = $true; Reason = 'ok'; Count = @($esc).Count; Escalations = @($summaries) }
}

# Convert a DateTime (local) to absolute unix seconds, comparable with git %ct.
function ConvertTo-UnixSeconds {
  param([DateTime]$Dt)
  return [long]([DateTimeOffset]::new($Dt)).ToUnixTimeSeconds()
}

# Extract the REVIEW-TREE-OID stamp from the LEADING identity region only (the
# same region Get-ArtifactBackend grades: consecutive lines from the top up to
# the producer's empty separator), in the producer's exact shape -- never from
# the body, where a column-zero quotation of the header name would otherwise
# fabricate a commit correlation or a false tree-mismatch abort. Returns '' for
# a headerless (legacy prose) verdict.
function Get-TreeOidFromContent {
  param([string]$Content)
  foreach ($toLine in ($Content -split "`n")) {
    if ($toLine -ceq '') { break }
    if ($toLine -cmatch '^REVIEW-TREE-OID: (?<oid>[0-9a-f]{40}([0-9a-f]{24})?)$') { return $Matches['oid'] }
  }
  return ''
}

# Resolve a RELATIVE path against the MAIN repo root (the git common-dir parent),
# returning an absolute path; an ABSOLUTE path is returned unchanged. Used for BOTH
# a relative reviews-dir entry (the review wrappers centralize verdicts to the MAIN
# repo's `logs/<backend>/reviews` via the git COMMON-DIR -- auto-merge.ps1
# Resolve-CentralLogDir / the wrappers' Resolve-DefaultReviewOutDir) AND the DEFAULT
# report path (`logs/worker-audits/...`, which the gate's `logs/` ignore rule
# covers, kept beside the centralized verdict logs at the main root). Resolving
# against the main root -- NOT the current directory,
# which for a linked worktree is the worktree's own (empty) `logs/`, and for a
# subdirectory invocation would land OUTSIDE the root-anchored ignore -- is the
# point. When git cannot resolve a common dir (not a repo / no git), the relative
# path is returned as-is for a cwd-relative fallback. NON-pure (git probe).
function Resolve-RelativeToMainRoot {
  param([string]$Dir)
  if ([string]::IsNullOrWhiteSpace($Dir)) { return $Dir }
  if ([System.IO.Path]::IsPathRooted($Dir)) { return $Dir }
  # Resolve the git common dir, mirroring auto-merge.ps1 Resolve-CentralLogDir's
  # TWO-STEP probe: try `--path-format=absolute --git-common-dir` (modern git),
  # then fall back to plain `--git-common-dir` + Resolve-Path for OLDER git that
  # lacks `--path-format` (where the plain form can return a relative `.git`).
  $commonDir = $null
  $absOut = & git rev-parse --path-format=absolute --git-common-dir 2>$null
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($absOut)) {
    $commonDir = ($absOut | Select-Object -First 1).Trim()
  } else {
    $plainOut = & git rev-parse --git-common-dir 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($plainOut)) {
      try { $commonDir = (Resolve-Path -LiteralPath (($plainOut | Select-Object -First 1).Trim()) -ErrorAction Stop).Path }
      catch { $commonDir = $null }
    }
  }
  if (-not [string]::IsNullOrWhiteSpace($commonDir)) {
    # The SAME submodule-aware root selection as the wrappers' / auto-merge's
    # Get-ReviewLogDir: a SUBMODULE's common dir sits under
    # `<superproject>/.git/modules/<name>`, whose parent is git metadata, not
    # the submodule's working tree -- there the working-tree TOP-LEVEL is the
    # root (and an unknown top-level falls back to the cwd-relative path,
    # never the wrong parent). A normal repo or linked worktree uses
    # `<common-dir>/..`, the MAIN repo root.
    if (($commonDir -replace '\\', '/') -match '(?i)/\.git/modules/') {
      $topOut = & git rev-parse --show-toplevel 2>$null
      if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($topOut)) {
        return [System.IO.Path]::GetFullPath((Join-Path (($topOut | Select-Object -First 1).Trim()) $Dir))
      }
      return $Dir
    }
    $mainRoot = Split-Path -Parent $commonDir
    if (-not [string]::IsNullOrWhiteSpace($mainRoot)) {
      return [System.IO.Path]::GetFullPath((Join-Path $mainRoot $Dir))
    }
  }
  return $Dir
}


# ===========================================================================
# MAIN PIPELINE
# ===========================================================================

if ([string]::IsNullOrWhiteSpace($Branch)) {
  Write-Host '[worker-audit] ERROR: [class:operational] -Branch is required (a branch ref or the landed tip SHA).'
  exit 1
}
$facts = Resolve-GitFacts -Branch $Branch -Base $Base -BaseRef $BaseRef
if ($null -eq $facts) { exit 1 }
if (@($facts.Commits).Count -eq 0) {
  Write-Host "[worker-audit] ERROR: [class:operational] empty commit range for merge-base($($facts.BaseRef), $Branch)..$Branch."
  Write-Host '[worker-audit]        Nothing to audit -- the branch has no commits ahead of its base (wrong -Base, or already fully merged with the fork point passed as -Base).'
  exit 1
}
$commits = @($facts.Commits)
$commitShas = @($commits | ForEach-Object { $_.Sha })
$commitTreeSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($c in $commits) { [void]$commitTreeSet.Add(([string]$c.Tree).ToLowerInvariant()) }
$firstCommitEpoch = [long]$commits[0].Epoch
$lastCommitEpoch = [long]$commits[-1].Epoch
# Window attribution walks the commits in CHRONOLOGICAL order (each commit's
# window is open at both ends: (previous commit time, this commit time), with
# same-second artifacts classified as boundary-second). Histories that break
# that: a commit sharing a whole second with the base or its chronological
# predecessor (an empty window), and a TRUE parent-child inversion -- a child
# committed before its own parent (rebases, clock skew, amended dates), which
# the chronological sort hides while the windows it yields attribute
# artifacts to the wrong commit. Both are CHECKED, never trusted: either
# marks every window-attributed statistic UNRELIABLE through the same
# lead/tag machinery as the suspect path, with the offending commits named.
$attributionNonMonotonic = New-Object 'System.Collections.Generic.List[string]'
if ($firstCommitEpoch -le [long]$facts.BaseEpoch) {
  $attributionNonMonotonic.Add("$($commits[0].Short) (committed at or before its merge-base's second)") | Out-Null
}
# Every recorded parent edge is checked: in-range parents from the commit
# list, out-of-range parents (the base, a side history reachable from it)
# from the facts' resolved ParentEpochs. A parent with no epoch on record
# is an unverified edge and marks attribution unreliable rather than pass.
$commitEpochBySha = @{}
foreach ($c in $commits) { $commitEpochBySha[([string]$c.Sha).ToLowerInvariant()] = [long]$c.Epoch }
$outsideParentEpochs = if ($null -ne $facts.PSObject.Properties['ParentEpochs'] -and $null -ne $facts.ParentEpochs) { $facts.ParentEpochs } else { @{} }
foreach ($c in $commits) {
  foreach ($parentSha in @($c.Parents)) {
    $pk = ([string]$parentSha).ToLowerInvariant()
    $parentEpoch = $null
    if ($commitEpochBySha.ContainsKey($pk)) { $parentEpoch = $commitEpochBySha[$pk] }
    elseif ($outsideParentEpochs.ContainsKey($pk)) { $parentEpoch = [long]$outsideParentEpochs[$pk] }
    if ($null -eq $parentEpoch) {
      $attributionNonMonotonic.Add("$($c.Short) (its parent $($pk.Substring(0, [Math]::Min(12, $pk.Length))) has no recorded committer time; the edge is unverified)") | Out-Null
    } elseif ([long]$c.Epoch -lt $parentEpoch) {
      $attributionNonMonotonic.Add("$($c.Short) (committed BEFORE its parent $($pk.Substring(0, [Math]::Min(12, $pk.Length))))") | Out-Null
    }
  }
}
for ($ci = 1; $ci -lt $commits.Count; $ci++) {
  if ([long]$commits[$ci].Epoch -le [long]$commits[$ci - 1].Epoch) {
    $attributionNonMonotonic.Add("$($commits[$ci].Short) (committed in the same second as its predecessor $($commits[$ci - 1].Short))") | Out-Null
  }
}

# Scan window: from the merge-base commit time (aborted rounds for the first
# commit fall after the fork) to now + 1h slack (merge-gate reviews land shortly
# after the last commit; the audit runs right after the merge). The per-commit
# aborted attribution INSIDE Invoke-CommitGateCorrelation re-bounds each commit's
# window tightly by committer times; this outer window only limits which files
# are READ. Both bounds are PRODUCER epochs, compared against the epoch each
# artifact's own NAME carries (Test-VerdictNameInWindow) -- the same clock every
# consumer downstream reads.
$windowStartEpoch = [long]$facts.BaseEpoch
# Every attribution-window EDGE second: the base's, and each commit's own. The
# windows are OPEN at both ends, so a second listed here belongs to no window at
# all: it bounds the one before it and the one after it, and attributes to
# neither commit.
$windowEdgeEpochs = New-Object 'System.Collections.Generic.HashSet[long]'
[void]$windowEdgeEpochs.Add([long]$facts.BaseEpoch)
foreach ($weC in $commits) { [void]$windowEdgeEpochs.Add([long]$weC.Epoch) }
$windowEndEpoch = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) + 3600

# ---------------------------------------------------------------------------
# Scan each reviews dir (NON-RECURSIVE -> the failclosed-quarantine/ subdir is
# excluded by construction). Dir policy is the analyzer's hybrid (the governing
# campaign disposes the skip of an explicit missing dir): an EXPLICIT list is
# strict -- a missing or blank entry aborts, so coverage never narrows
# silently (auto-merge names only dirs that exist) -- while the IMPLICIT
# default list degrades loudly (a defaulted backend dir that is absent is
# skipped with a note; a single-backend install has only one of them). A dir
# with ZERO in-window verdicts never aborts either way: a per-branch audit
# legitimately finds a backend with nothing for this window. Each in-window
# verdict-shaped file is parsed into a record.
# ---------------------------------------------------------------------------
# ONE producer event can be enumerated from SEVERAL scanned dirs: the merge
# gate passes its run-owned dirs beside the central logs, and consolidation
# copies each artifact between them under the SAME producer name. Identity is
# therefore the producer NAME plus the evidence the file carries, not the path
# it was found at.
$seenArtifactByName = @{}
$duplicateArtifactCopies = New-Object 'System.Collections.Generic.List[string]'
$commitGateAll = New-Object 'System.Collections.Generic.List[object]'
$mergeAll = New-Object 'System.Collections.Generic.List[object]'
$manualAll = New-Object 'System.Collections.Generic.List[object]'   # -Scope Uncommitted/Commit spot-checks (NOT gate rounds)
$otherAll = New-Object 'System.Collections.Generic.List[object]'    # producer-shaped names of unrecognized scope (always suspect)
$dirsScanned = New-Object 'System.Collections.Generic.List[string]'
$dirsSkipped = New-Object 'System.Collections.Generic.List[string]'
# Per-FILE read failures (a locked/unreadable artifact in the SHARED mutable
# logs): a file whose FILENAME alone proves branch provenance (a branch-scope
# verdict whose tip names a branch commit and whose base matches the audited
# base) joins the correlated-suspect handling (suspect-led exit-0 report,
# statistics marked UNRELIABLE) -- its AUTHORITATIVE merge evidence cannot be
# assessed. Every OTHER unreadable file (staged/manual with no name-level
# provenance at all, or a NON-MATCHING branch-scope name -- a foreign tip, or
# the audited tip with a DIFFERENT base) is a named advisory, never a raw exception and never
# counted -- the same not-this-branch's-evidence scoping as the window suspects.
# (Codex BLOCKER review-20260710: an undifferentiated advisory could hide a
# branch-correlated merge round.)
$unreadableSuspects = New-Object 'System.Collections.Generic.List[string]'
$unreadableCorrelated = New-Object 'System.Collections.Generic.List[string]'
# Standalone `.exhaustion.json` sidecars (no paired verdict .md): the claude
# wrapper's exit-4 paths return before any Markdown exists, so their
# exhaustion record is ONLY the sidecar (gate BLOCKER 2026-07-23: an
# *.md-only enumeration made these invisible). FORENSIC advisory rows --
# never rounds, never POSITIVE authority (split-on-subsystem ruling
# 2026-07-23); the one decision they drive is the NEGATIVE quarantine below.
$standaloneSidecars = New-Object 'System.Collections.Generic.List[string]'
$unknownScopeSidecars = New-Object 'System.Collections.Generic.List[string]'
# QUARANTINE BY SIDECAR IDENTITY (gate BLOCKER 2026-07-24) -- the quarantine
# CONTRACT site. An exhaustion-DECLARATION sidecar whose FILENAME carries
# merge-scope identity matching the audited tip/base -- with or without a
# same-stem `.md` (pairing is unverifiable without run identity; gate
# BLOCKER 2026-07-24) -- WITHHOLDS round
# authority from every same-identity merge artifact, whatever its backend
# label (the sidecar carries no authenticated producer, so its own field
# cannot narrow the demotion; a headerless legacy artifact demotes too):
# they are
# excluded from round grouping and listed in the report lead instead. The
# evidence proves ONLY the negative -- an untrusted same-identity declaration
# file exists, so those artifacts cannot be trusted as a complete
# authoritative panel. It does NOT prove exhaustion occurred, that a panel
# was abandoned, or that any fallback panel ran or holds authority: sidecar
# content is SYNTAX-ONLY forensic data (a planted file demotes identically,
# by design), and POSITIVE exhaustion/fallback provenance claims are
# RESERVED for the verdict-artifact framing migration's producer-owned
# terminal evidence (parent-generated run IDs + terminal panel receipt) --
# nothing in this consumer may assert them. Identity comes from the FILENAME
# (the same name-level provenance basis every artifact record uses). The key
# is the FULL matched identity -- resolved tip commit SHA + the CANONICAL
# audited base SHA once the filename's base token (whole or split reading)
# has matched ground truth, so every spelling of one base meets on one key --
# with NO backend component (a sidecar
# carries no authenticated producer, so its own field cannot narrow the
# demotion, and every record label -- producer headers and headerless
# legacy alike -- demotes) -- so only SAME-LANDING artifacts quarantine; a tip-less key
# would demote valid rounds for other tips (gate BLOCKER 2026-07-24). The quarantine is
# additionally TIME-SCOPED to $script:PanelAttemptGapSec around the sidecar's
# own filename timestamp -- same-window siblings launched together, so a
# LATER independent retry of the same identity lands outside it and keeps
# round authority (gate BLOCKER 2026-07-24: an identity-only key let a stale
# sidecar erase later successful retries). This window reuses the panel
# clustering constant, no new metadata. Conservative direction preserved: a
# retry improbably launched INSIDE the window quarantines (a visible
# advisory), never the reverse.
# DELIBERATE ASYMMETRY (keeps the forensic-only sidecar principle): this is a
# NEGATIVE authority decision only. A sidecar -- even a planted one -- can
# DEMOTE same-identity rounds (every backend) to a loudly-listed advisory
# (conservative: authority is withheld, the evidence stays listed), but can
# never GRANT authority, mint a round, or erase evidence.
$exhaustedPanelSidecars = New-Object 'System.Collections.Generic.List[object]'
$quarantinedPanelArtifacts = New-Object 'System.Collections.Generic.List[string]'
# Separate completeness flags, one per scan, so each report label names the
# failure that happened. $verdictScanIncomplete: a reviews dir's verdict
# .md scan failed or the dir could not be identified -- a verdict-scan
# failure also skips that dir's sidecar scan (gate BLOCKERs 2026-07-24), so
# it sets BOTH flags. $sidecarScanIncomplete: only the sidecar scan failed,
# or a this-landing sidecar could not be time-scoped -- the verdict corpus
# was scanned whole, so corpus-absence stays KNOWABLE, while the quarantine
# (negative-authority) inputs are INCOMPLETE. Either marks the whole report
# UNRELIABLE through the same machinery as the suspect path.
$verdictScanIncomplete = $false
$sidecarScanIncomplete = $false
$commitGateEvidenceIncomplete = $false
$stagedNamesObserved = 0
$seenDirAbs =New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList @(,[System.StringComparer]::OrdinalIgnoreCase)

foreach ($dirRaw in $ReviewsDir) {
  $dirIn = [string]$dirRaw
  if ([string]::IsNullOrWhiteSpace($dirIn)) {
    if ($reviewsDirExplicit) {
      Write-Host '[worker-audit] ERROR: [class:operational] an explicit reviews-dir entry is empty/blank; aborting rather than silently narrow coverage.'
      exit 1
    }
    $dirsSkipped.Add('(blank defaulted entry)') | Out-Null
    continue
  }
  # Resolve a relative entry to the MAIN repo's central logs (git-common-dir), so
  # verdicts are found even when this runs from a linked worktree; an absolute
  # entry (e.g. a run-owned scratch dir) passes through unchanged.
  $dir = Resolve-RelativeToMainRoot -Dir $dirIn
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
    if ($reviewsDirExplicit) {
      Write-Host "[worker-audit] ERROR: [class:operational] explicit reviews directory not found: $dir -- aborting rather than silently narrow coverage (name only dirs that exist; the caller decides what to scan)."
      exit 1
    }
    Write-Host "[worker-audit] WARNING: defaulted reviews directory not found (skipping with a note; a single-backend install has only one of the defaults): $dir"
    $dirsSkipped.Add($dir) | Out-Null
    continue
  }
  $abs = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $dir).Path)
  # Identity is the FINAL path behind a directory handle: a junction or
  # symlink alias of a dir already scanned is the SAME dir (see the
  # CrgWorkerAudit.FinalPath rationale). An unresolvable final path is an
  # indeterminate identity: an explicit entry refuses by name, a default is
  # skipped by name.
  $absFinalErr = 0
  $absFinal = [CrgWorkerAudit.FinalPath]::Resolve($abs, [ref]$absFinalErr)
  if ([string]::IsNullOrWhiteSpace($absFinal)) {
    if ($reviewsDirExplicit) {
      Write-Host "[worker-audit] ERROR: [class:operational] could not resolve the final path of explicit reviews directory $dir (Win32 error $absFinalErr) -- its identity is indeterminate; aborting rather than risk scanning one directory twice."
      exit 1
    }
    # A PRESENT default dir left unscanned is missing evidence, not a
    # tolerated absence: the report is UNRELIABLE through the enumeration-
    # incomplete path.
    Write-Host "[worker-audit] WARNING: could not resolve the final path of defaulted reviews directory $dir (Win32 error $absFinalErr) -- skipped (identity indeterminate); evidence INCOMPLETE."
    $dirsSkipped.Add($dir) | Out-Null
    $verdictScanIncomplete = $true
    $sidecarScanIncomplete = $true
    continue
  }
  if (-not $seenDirAbs.Add($absFinal)) { continue }   # same dir twice (any spelling or alias) -> scan once
  $files = @()
  try {
    $files = @(Get-ChildItem -LiteralPath $abs -Filter '*.md' -File -ErrorAction Stop |
      Where-Object { $script:VerdictNameRe.IsMatch($_.Name) -and (Test-VerdictNameInWindow -Name $_.Name -StartEpoch $windowStartEpoch -EndEpoch $windowEndEpoch) })
  } catch {
    # ONE failure boundary with the sidecar scan (gate BLOCKER 2026-07-24:
    # this catch's `continue` also skips the sidecar scan below, so an
    # I/O/permission failure on an EXISTING dir hides quarantine evidence --
    # unlike the tolerated missing-dir skip above, which is a documented
    # absent-backend deviation, not a failed enumeration).
    $verdictScanIncomplete = $true
    $sidecarScanIncomplete = $true
    Write-Host "[worker-audit] WARNING: failed to enumerate ${dir} (skipping; evidence INCOMPLETE): $($_.Exception.Message)"
    $dirsSkipped.Add($dir) | Out-Null
    continue
  }
  $dirsScanned.Add("``$dir`` = $($files.Count) in-window") | Out-Null
  foreach ($file in $files) {
    $content = $null
    # Every commit-gate-shaped NAME counts as observed corpus before any read:
    # an unreadable staged artifact is present evidence, so the absent-corpus
    # lead must never fire over files that merely could not be read.
    if ((Get-VerdictScope -Name $file.Name).Kind -eq 'commit-gate') { $stagedNamesObserved++ }
    # Strict no-BOM decode through the mirrored boundary: a rejected decode
    # (BOM, invalid UTF-8) is UNREADABLE evidence and takes the same path as a
    # locked file -- never a laundered string.
    $readFail = $null
    $readHold = $null
    try {
      # Size envelope enforced UNDER A HELD HANDLE: the file is opened with
      # FileShare.Read for the whole check-then-read, so no writer can grow
      # or replace it between the length taken from this handle and the
      # mirrored reader's own open (Read-VerdictArtifactText keeps the
      # analyzer's byte-identical signature, so it reopens the path; the
      # hold is what makes that reopen the SAME bytes). A planted
      # multi-gigabyte verdict-shaped file is unreadable evidence (named),
      # never read whole. A file already held by a writer fails the open
      # here and takes the locked/unreadable path.
      $readHold = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
      if ($readHold.Length -gt $script:VerdictReadMaxBytes) {
        $readFail = "exceeds the verdict read envelope ($($readHold.Length) bytes > $($script:VerdictReadMaxBytes))"
      } else {
        $decoded = Read-VerdictArtifactText -Path $file.FullName
        if ($decoded.Ok) { $content = $decoded.Text } else { $readFail = "decode rejected: $($decoded.Reason)" }
      }
    } catch { $readFail = $_.Exception.Message } finally { if ($null -ne $readHold) { $readHold.Dispose() } }
    if ($null -ne $readFail) {
      # A locked/unreadable file must not raise a raw exception -- but it is only
      # ADVISORY when the filename carries no provenance FOR THE AUDITED BRANCH
      # (staged/manual: the OID inside is unknowable; a NON-MATCHING branch-scope
      # name -- foreign tip, or audited tip with a different base -- is another
      # branch's or another diff's evidence). A BRANCH-SCOPE filename
      # matching the audited tip/base is proven branch evidence by NAME alone,
      # so an unreadable one joins the correlated-suspect handling instead of
      # being silently
      # downgraded. (Codex QUALITY + BLOCKER review-20260710.) The name's
      # base ambiguity is resolved against ground truth: the whole-suffix
      # reading first, the split reading only when the whole does not match
      # (Get-VerdictScope's rationale).
      $unreadableScope = Get-VerdictScope -Name $file.Name
      $unreadableMatched = $false
      if (($unreadableScope.Kind -eq 'merge-gate') -and
          ($null -ne (Resolve-TipToCommit -Tip $unreadableScope.Tip -CommitShas $commitShas))) {
        if (Test-BaseMatch -FilenameBase $unreadableScope.Base -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy) {
          $unreadableMatched = $true
        } elseif ($null -ne $unreadableScope.SplitBase -and
                  (Test-BaseMatch -FilenameBase $unreadableScope.SplitBase -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy)) {
          $unreadableMatched = $true
        }
      }
      if ($unreadableMatched) {
        [void]$unreadableCorrelated.Add("[unreadable, in ``$dir``] $($file.Name) -- unreadable branch-scope verdict for the audited tip/base: $readFail")
      } else {
        Write-Host "[worker-audit] WARNING: could not read verdict file $($file.Name) (recorded as unreadable-suspect): $readFail"
        [void]$unreadableSuspects.Add("``$($file.Name)`` (in ``$dir``) -- unreadable: $readFail")
        # An unreadable COMMIT-GATE (staged) artifact may hold the OID-matched
        # PASS a branch commit is missing, and an unreadable UNRECOGNIZED-scope
        # artifact could be anything at all: every commit-gate statistic is
        # then INCOMPLETE, not merely advisory-annotated. (The scope is
        # classified from the FILENAME, so the read failure cannot hide it.)
        if ($unreadableScope.Kind -eq 'commit-gate' -or $unreadableScope.Kind -eq 'other') { $commitGateEvidenceIncomplete = $true }
      }
      continue
    }
    $suspect = Get-VerdictSuspectReason -Content $content -VerdictWordRe $script:VerdictLineRe
    # Producer identity from the artifact's OWN validated header (the mirrored
    # Get-ArtifactBackend): malformed provenance is suspect evidence in its own
    # right (it joins the suspect handling when the structural check passed),
    # and a headerless historical artifact is `legacy`. The directory the
    # file sits in contributes only its display name, never identity.
    $abInfo = Get-ArtifactBackend -Content $content
    $backend = if ($null -ne $abInfo.Backend) { $abInfo.Backend } else { 'malformed-provenance' }
    if ($null -eq $suspect -and $null -ne $abInfo.Reason) { $suspect = $abInfo.Reason }
    $scope = Get-VerdictScope -Name $file.Name
    # A producer-shaped name whose scope is none the wrappers emit is
    # MALFORMED evidence, never a silent drop: it joins the suspect handling
    # (correlated by tree when the body carries one, else an in-window
    # advisory) so a corrupted or foreign producer name cannot leave the
    # counts reading authoritative.
    if ($scope.Kind -eq 'other' -and $null -eq $suspect) { $suspect = 'unrecognized verdict scope suffix (a producer-shaped name whose scope is neither staged, branch, commit, nor uncommitted) -- malformed evidence' }
    $nameEpoch = Get-VerdictFileNameEpoch -Name $file.Name
    # Epoch = the FILENAME timestamp (review start), NOT the file MTIME
    # (write/consolidation time, which can lag by minutes). Used for attempt
    # grouping + window attribution. Every selected name carries a
    # producer-shaped timestamp prefix, so a prefix that does not parse as a
    # calendar time (an impossible date) is MALFORMED evidence, not missing
    # metadata: it joins the suspect handling (correlated -> the fail-loud
    # report; otherwise a named advisory).
    if ($null -eq $nameEpoch -and $null -eq $suspect) { $suspect = (Get-VerdictFileNameEpochState -Name $file.Name).Reason }
    # An unplaceable producer time stays UNPLACEABLE. Substituting
    # `LastWriteTime` handed the record a mutable instant: copying or restoring
    # the same malformed artifact moved it between the commit window, the
    # post-commit window, and no window at all -- and in the last case it
    # reached NO advisory branch, left the commit-gate evidence marked
    # complete, and the counts read authoritative over evidence that was
    # silently dropped (merge-panel BLOCKER 2026-08-30). The mtime is kept as
    # a FORENSIC field for the report; it is never an identity or a position.
    $recEpoch = $nameEpoch
    $rec = [pscustomobject]@{
      Name          = $file.Name
      Backend       = $backend
      Dir           = $dir
      TreeOid       = (Get-TreeOidFromContent -Content $content)
      Mtime         = $file.LastWriteTime
      Epoch         = $recEpoch
      # A same-stem `.exhaustion.json` sidecar is the PRODUCER'S own
      # exhaustion declaration -- a FORENSIC record only. It carries no
      # authority: the suspect handling classifies it for the report line and
      # nothing else (supersession is deferred; see the header).
      SidecarPath   = ($file.FullName -replace '\.md$', '.exhaustion.json')
      HasExhaustionSidecar = (Test-Path -LiteralPath ($file.FullName -replace '\.md$', '.exhaustion.json') -PathType Leaf)
      Scope         = $scope
      SuspectReason = $suspect
      # Class is ERA-AWARE: Get-VerdictUnionClass gives the raw severity class, then
      # Get-EraAwareRoundClass maps a QUALITY verdict whose artifact carries the
      # REVIEW-SEVERITY-CONTRACT stamp to PASS (it exited 0 -- a passing round), so
      # the downstream attempt grouping + aborted-round attribution treat it as a
      # PASS. An UNSTAMPED QUALITY (old-contract wrapper, which exited 1 -- possible
      # at any date from a stale branch's HEAD gate) stays QUALITY = a blocking round.
      Class         = $(if ($null -eq $suspect) { Get-EraAwareRoundClass -Class (Get-VerdictUnionClass -Content $content) -HasContractStamp (Test-VerdictContractStamp -Content $content) } else { $null })
      Categories    = $(if ($null -eq $suspect) { Get-VerdictCategories -Content $content } else { @() })
    }
    # One producer NAME enumerated from several dirs is NOT resolvable into "one
    # event copied" versus "two events that collided". Producer filenames carry
    # second resolution and NO run identifier, so byte-identical artifacts under
    # one name can be a consolidation copy OR two distinct reviews of the same
    # tree in the same second -- folding them would undercount gate rounds, and
    # counting them separately would inflate them (merge-panel BLOCKER
    # 2026-08-30). Neither reading is evidence, so the set is PRESERVED WHOLE
    # and every member of it is marked, exactly like the other unresolvable
    # multiplicities in this audit. Nothing is dropped; nothing is credited.
    # Resolving this needs producer-stamped run identity (the verdict-artifact
    # framing migration follow-up), not a better guess here.
    $copyKey = "$([string]$rec.Backend)|$([string]$rec.Name)"
    if (-not $seenArtifactByName.ContainsKey($copyKey)) { $seenArtifactByName[$copyKey] = New-Object 'System.Collections.Generic.List[object]' }
    $seenArtifactByName[$copyKey].Add([pscustomobject]@{ Rec = $rec; Dir = $dir }) | Out-Null
    if ($scope.Kind -eq 'commit-gate') { $commitGateAll.Add($rec) | Out-Null }
    elseif ($scope.Kind -eq 'merge-gate') { $mergeAll.Add($rec) | Out-Null }
    elseif ($scope.Kind -eq 'manual') { $manualAll.Add($rec) | Out-Null }
    else { $otherAll.Add($rec) | Out-Null }
  }
  # Sidecar enumeration for this dir (rationale on the $standaloneSidecars
  # declaration above). A failure here means the NEGATIVE-authority evidence
  # is INCOMPLETE (quarantine decisions cannot be evaluated for this dir), so
  # it propagates through the same UNRELIABLE machinery the suspect path uses
  # (gate BLOCKER 2026-07-24: a warn-and-continue left the statistics
  # labeled authoritative on missing evidence).
  $sidecarFiles = @()
  try {
    $sidecarFiles = @(Get-ChildItem -LiteralPath $abs -Filter '*.exhaustion.json' -File -ErrorAction Stop |
      Where-Object { $_.Name -match '^review-\d{8}-\d{6}-.+\.exhaustion\.json$' -and (Test-VerdictNameInWindow -Name $_.Name -StartEpoch $windowStartEpoch -EndEpoch $windowEndEpoch) })
  } catch {
    $sidecarScanIncomplete = $true
    Write-Host "[worker-audit] WARNING: failed to enumerate exhaustion sidecars in ${dir}: $($_.Exception.Message)"
  }
  # A sidecar's scope is read up front: an unrecognized scope is reported
  # whether or not a same-stem `.md` exists (it can quarantine nothing and
  # must never vanish behind the pairing label).
  foreach ($sf in $sidecarFiles) {
    # PAIRING IS UNPROVEN (gate BLOCKER 2026-07-24): a same-stem `.md` does
    # NOT prove this sidecar belongs to that artifact's run -- second-
    # resolution stems can collide across concurrent same-scope invocations
    # and separate centralization copies, and no run identity exists to bind
    # them (framing migration). The same-stem observation is ONLY a reporting
    # label (marked unverified below); it never cancels the negative
    # quarantine. Conservative direction: over-quarantine is a visible
    # advisory, under-quarantine is silent false authority.
    $hasSameStemMd = (Test-Path -LiteralPath ($sf.FullName -replace '\.exhaustion\.json$', '.md') -PathType Leaf)
    # Every read of a sidecar goes through Test-ExhaustionSidecar's bounded
    # single-handle read (the producer's size envelope is enforced before any
    # parse); an untrusted file is never read unbounded.
    $sv = Test-ExhaustionSidecar -SidecarPath $sf.FullName
    $sidecarScope = Get-VerdictScope -Name ($sf.Name -replace '\.exhaustion\.json$', '.md')
    if ($sidecarScope.Kind -eq 'other') {
      # Its own collection and section: the standalone section claims every
      # row lacks a paired verdict, which a same-stem unknown-scope sidecar
      # contradicts. Scope, pairing state, and the syntax classification
      # (with the bounded reader's failure reason) are all retained.
      $sidecarSyntax = if ($sv.Valid) { 'syntax: well-formed (SYNTAX-ONLY check, values unvalidated)' } else { "syntax: UNRECOGNIZED ($($sv.Reason))" }
      $unknownScopeSidecars.Add("[unrecognized-scope sidecar in ``$dir``] $($sf.Name) -- UNRECOGNIZED SCOPE (a producer-shaped name whose scope is none the wrappers emit); same-stem verdict $(if ($hasSameStemMd) { 'PRESENT (pairing unverified)' } else { 'absent' }); $sidecarSyntax; it quarantines nothing") | Out-Null
    } elseif (-not $hasSameStemMd) {
      if ($sv.Valid) {
        $standaloneSidecars.Add("[$([string]$sv.Record.backend)] $($sf.Name) -- syntactically well-formed exhaustion sidecar (SYNTAX-ONLY check; no verdict artifact shares its stem)") | Out-Null
      } else {
        $standaloneSidecars.Add("[unrecognized sidecar in ``$dir``] $($sf.Name) -- UNRECOGNIZED ($($sv.Reason))") | Out-Null
      }
    }
    # The quarantine identity carries NO backend: a sidecar is a SYNTAX-ONLY
    # record with no authenticated producer identity, so its `backend`
    # field cannot narrow the demotion -- a corrupted or planted
    # same-identity sidecar naming the OTHER backend would otherwise leave
    # the actually exhausted backend's siblings eligible for authoritative
    # counting -- and an enumerated producer list would miss the labels a
    # record can carry beyond the producer headers (a headerless legacy
    # artifact is `legacy`). Over-quarantine is a visible advisory;
    # under-quarantine is silent false authority.
    # Quarantine trigger (rationale at the $exhaustedPanelSidecars
    # declaration): the FILENAME identity decides -- syntax validity does not
    # gate it, since the demotion direction is safe for a planted/corrupt
    # sidecar too and a validity gate would let a truncated real sidecar
    # silently re-grant round authority. It fires for EVERY sidecar,
    # same-stem `.md` or not (pairing unproven, above). The same
    # whole-first/split-second base resolution as the artifact records, so
    # sidecar/sibling names normalize to the same key; the filename epoch
    # time-scopes the quarantine to the sidecar's own panel launch window.
    if ($sidecarScope.Kind -eq 'merge-gate') {
      $sidecarTipSha = Resolve-TipToCommit -Tip $sidecarScope.Tip -CommitShas $commitShas
      $sidecarEffBase = $null
      if (Test-BaseMatch -FilenameBase $sidecarScope.Base -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy) {
        $sidecarEffBase = $sidecarScope.Base
      } elseif ($null -ne $sidecarScope.SplitBase -and
                (Test-BaseMatch -FilenameBase $sidecarScope.SplitBase -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy)) {
        $sidecarEffBase = $sidecarScope.SplitBase
      }
      $sidecarEpoch = Get-VerdictFileNameEpoch -Name ($sf.Name -replace '\.exhaustion\.json$', '.md')
      if ($null -ne $sidecarTipSha -and $null -ne $sidecarEffBase -and $null -ne $sidecarEpoch) {
        # The key carries the CANONICAL audited base SHA, never the matched
        # filename token: a SHA-spelled sidecar and a ref-spelled legacy
        # verdict name one identity and must meet on one key.
        $exhaustedPanelSidecars.Add([pscustomobject]@{
          Key   = "$sidecarTipSha|$(([string]$facts.BaseSha).ToLowerInvariant())"
          Epoch = [long]$sidecarEpoch
        }) | Out-Null
      } elseif ($null -ne $sidecarTipSha -and $null -ne $sidecarEffBase) {
        # A THIS-landing sidecar whose timestamp prefix does not parse as a
        # calendar time cannot be time-scoped, so its quarantine cannot be
        # evaluated: that is incomplete negative-authority evidence, the
        # same state as a failed enumeration -- never a silent omission
        # that re-grants round authority.
        $sidecarScanIncomplete = $true
        Write-Host "[worker-audit] WARNING: exhaustion sidecar $($sf.Name) in ${dir} names this landing but its $((Get-VerdictFileNameEpochState -Name ($sf.Name -replace '\.exhaustion\.json$', '.md')).Reason); its quarantine cannot be evaluated."
      }
    }
  }
}

# ---------------------------------------------------------------------------
# FAIL-LOUD, scoped to evidence RELIABLY this branch's. A malformed verdict is
# split two ways so an unrelated concurrent branch's malformed verdict cannot
# implicate a per-branch audit:
#   * DEFINITELY this branch's (=> CORRELATED SUSPECT): a commit-gate suspect
#     whose REVIEW-TREE-OID matches a branch commit tree (NOT the fork-point
#     base tree), OR a merge suspect whose
#     filename tip (which NAMES a branch commit SHA -- a strong, non-time-window
#     correlation) resolves to a branch commit. This audit would MISCOUNT such
#     evidence, so it LEADS the exit-0 report as a suspect with every
#     statistic marked UNRELIABLE (the fail-loud report contract -- the
#     alarm lives in the report's lead and the console summary, never in a
#     withheld report).
#   * ONLY window-region (=> WARN advisory): a commit-gate suspect that does NOT
#     OID-match but falls in the branch commit-time window. It CANNOT be reliably
#     attributed (a concurrent branch's malformed verdict lands in the same window
#     too), so treating it as this branch's suspect would false-implicate the
#     audit. It is surfaced as a report warning instead -- neither counted nor
#     silently dropped. (Codex
#     BLOCKER: the earlier over-broad base-to-branch window folded arbitrary
#     shared-log verdicts into the branch's evidence.)
# ---------------------------------------------------------------------------
# COLLIDING PRODUCER NAMES, resolved once the whole corpus is enumerated (a
# collision is only visible after every dir has been read). Each member of a
# colliding set is marked so none of them can reach an authoritative count,
# and all of them stay listed: whether the set is one event copied between
# dirs or several events that shared a name is not decidable from artifacts
# that carry no run identity.
foreach ($copyKey in @($seenArtifactByName.Keys)) {
  # .ToArray() on the hashtable's List value, never `@(...)`: array-wrapping a
  # generic List read out of a hashtable throws "Argument types do not match"
  # under PS 5.1 -- and this branch only runs when a collision EXISTS, so no
  # unit arm reached it. The end-to-end arm did, on its first run.
  $copySet = $seenArtifactByName[$copyKey].ToArray()
  if ($copySet.Count -lt 2) { continue }
  $copyDirs = @($copySet | ForEach-Object { "``$($_.Dir)``" }) -join ', '
  $copyWhy = "the producer name was enumerated $($copySet.Count) times (in $copyDirs); with no run identifier in the artifact, one copied event and several same-second events are indistinguishable, so none of them is counted"
  foreach ($copyEntry in $copySet) {
    if ($null -eq $copyEntry.Rec.SuspectReason) { $copyEntry.Rec.SuspectReason = $copyWhy }
  }
  $duplicateArtifactCopies.Add("$copyKey -- $copyWhy") | Out-Null
}
$suspectCorrelated = New-Object 'System.Collections.Generic.List[string]'
$suspectWindowWarn = New-Object 'System.Collections.Generic.List[string]'
# Records that no window can place -- an unresolvable producer instant, or a
# stamp on a window edge. Kept OUT of $suspectWindowWarn: that collection's
# report prose states its members are inside the commit-time window, which is
# exactly what is unknown here.
$suspectUnplaceableWarn = New-Object 'System.Collections.Generic.List[string]'
# A same-stem exhaustion sidecar is a FORENSIC RECORD ONLY (split-on-subsystem
# ruling 2026-07-23): it never suppresses, downgrades, or supersedes the
# suspect artifact -- the artifact stays suspect evidence, and the sidecar's
# SYNTAX-ONLY classification is merely
# appended to the suspect line so the operator can see the producer's
# own exhaustion declaration beside it. Supersession is deferred to
# the verdict-artifact framing migration follow-up (see the header).
function Get-SuspectSidecarNote {
  param($Rec)
  if (-not $Rec.HasExhaustionSidecar) { return '' }
  $sv = Test-ExhaustionSidecar -SidecarPath $Rec.SidecarPath
  if ($sv.Valid) {
    return '; a syntactically well-formed exhaustion sidecar accompanies this artifact (SYNTAX-ONLY shape check, values unvalidated; forensic record with no authority - supersession is deferred to the verdict-artifact framing migration)'
  }
  return "; an unrecognized exhaustion sidecar accompanies this artifact ($($sv.Reason)) - forensic record only"
}
# SUSPECT TAXONOMY for the tree-bearing (non-merge) collections -- one
# route per record class, so no malformed artifact vanishes and none is
# routed into a state it cannot legitimately affect:
#   * GATE-shaped records (commit-gate, and unrecognized-scope names, which
#     could be anything): OID-hit -> CORRELATED suspect (possible gate
#     bypass, the fail-loud lead); inside the commit-ATTRIBUTION window ->
#     advisory that marks the commit-gate statistics INCOMPLETE (its tree
#     is unknowable, so it may be a missing round); after the last commit
#     but inside the SCAN window -> a post-commit scan advisory (listed;
#     nothing past the last commit attributes to a landed commit, so no
#     count is understated).
#   * MANUAL spot-checks (`uncommitted`, `commit-<sha>`): they never gated a
#     landing, so a malformed one is listed in its own advisory section and
#     dropped from the valid-manual count -- it is neither a gate-bypass
#     alarm nor a missing aborted round, whatever tree it carries.
$suspectScanWarn = New-Object 'System.Collections.Generic.List[string]'
$manualSuspects = New-Object 'System.Collections.Generic.List[string]'
foreach ($rec in $manualAll) {
  if ($null -eq $rec.SuspectReason) { continue }
  $manualSuspects.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason)$(Get-SuspectSidecarNote -Rec $rec)") | Out-Null
}
foreach ($rec in @($commitGateAll.ToArray() + $otherAll.ToArray())) {
  if ($null -eq $rec.SuspectReason) { continue }
  $sidecarNote = Get-SuspectSidecarNote -Rec $rec
  $oid = ([string]$rec.TreeOid).ToLowerInvariant()
  # OID-match against BRANCH commit trees ONLY -- NOT the fork-point base tree: the
  # base's own staged verdict gated the BASE commit (outside merge-base..branch), so a
  # malformed base-tree verdict is NOT this branch's evidence and must NOT abort the
  # branch audit -- it falls through to the window advisory below. (Codex BLOCKER: the
  # base-tree correlation path false-aborted on a stray malformed base-tree verdict.)
  $oidHit = ($oid -ne '' -and $commitTreeSet.Contains($oid))
  if ($oidHit) {
    $suspectCorrelated.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason)$sidecarNote") | Out-Null
  } elseif ($null -eq $rec.Epoch) {
    # UNPLACEABLE: the producer's own name carries no resolvable instant, so no
    # window can include or exclude it.
    $suspectUnplaceableWarn.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason) (its producer timestamp resolves to NO instant)$sidecarNote") | Out-Null
    $commitGateEvidenceIncomplete = $true
  } elseif ($windowEdgeEpochs.Contains([long]$rec.Epoch)) {
    # EDGE FIRST, before the broad interval test: attribution windows are OPEN
    # at both ends, so an artifact stamped in an INTERNAL commit's own second
    # bounds the windows on either side of it and belongs to neither -- the
    # same undecidability the correlation reports as a BoundaryArtifact. The
    # interval test alone swallowed those into the general in-window advisory,
    # which reads as "somewhere in the attribution range" and contradicts the
    # edge taxonomy this report states everywhere else (merge-panel QUALITY
    # 2026-08-30). The base second and the last commit's second are edges too;
    # they reach this branch by the same rule rather than by their own cases.
    $suspectUnplaceableWarn.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason) (stamped in a window-edge second -- a commit's own second or the base's -- so it attributes to no commit)$sidecarNote") | Out-Null
    $commitGateEvidenceIncomplete = $true
  } elseif ([long]$rec.Epoch -gt $windowStartEpoch -and [long]$rec.Epoch -le $lastCommitEpoch) {
    $suspectWindowWarn.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason)$sidecarNote") | Out-Null
    $commitGateEvidenceIncomplete = $true
  } elseif ([long]$rec.Epoch -gt $lastCommitEpoch -and [long]$rec.Epoch -le $windowEndEpoch) {
    $suspectScanWarn.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason)$sidecarNote") | Out-Null
  } else {
    # CATCH-ALL, and deliberately not a fourth window test: the two scan-range
    # branches above both EXCLUDE their lower bound, so a record stamped exactly
    # at the range's start second -- the base commit's own second -- matched
    # neither and fell out of the taxonomy entirely, leaving the counts and the
    # completeness flags untouched while blocking evidence went unreported
    # (gate BLOCKER 2026-08-30). No suspect record may leave this loop
    # unaccounted for, so every remaining epoch lands here: named, and marking
    # the commit-gate evidence incomplete because it cannot attribute to a
    # commit window.
    $suspectUnplaceableWarn.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason) (stamped on a window EDGE or outside the attribution windows, so it attributes to no commit)$sidecarNote") | Out-Null
    $commitGateEvidenceIncomplete = $true
  }
}
foreach ($rec in $mergeAll) {
  if ($null -eq $rec.SuspectReason) { continue }
  $sidecarNote = Get-SuspectSidecarNote -Rec $rec
  $recLegacyMatch = Test-EraUnknownForBaseMatch -Backend $rec.Backend
  # RELIABLY this branch's ONLY when BOTH the filename tip resolves to a branch
  # commit AND the reviewed base matches the audited base (either name
  # interpretation -- whole-suffix first, split second, per Get-VerdictScope's
  # rationale). A same-tip verdict for a
  # DIFFERENT base reviewed a different diff (a stale pre-rebase artifact, or a
  # manual `-Scope Branch` spot-check against another base) and would
  # false-implicate this per-branch audit -- it is skipped. (Codex BLOCKER:
  # tip-only correlation let a wrong-base malformed verdict implicate the audit.)
  if (($null -ne (Resolve-TipToCommit -Tip $rec.Scope.Tip -CommitShas $commitShas)) -and
      ((Test-BaseMatch -FilenameBase $rec.Scope.Base -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy:$recLegacyMatch) -or
       ($null -ne $rec.Scope.SplitBase -and (Test-BaseMatch -FilenameBase $rec.Scope.SplitBase -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy:$recLegacyMatch)))) {
    $suspectCorrelated.Add("[$($rec.Backend)] $($rec.Name) -- $($rec.SuspectReason)$sidecarNote") | Out-Null
  }
}
# Unreadable BRANCH-SCOPE verdicts for the audited tip/base join the same
# correlated-suspect handling -- their filename proves branch provenance and
# their merge evidence cannot be assessed. (Codex BLOCKER review-20260710.)
foreach ($u in @($unreadableCorrelated)) { $suspectCorrelated.Add($u) | Out-Null }
# Computed HERE -- immediately after $suspectCorrelated is final and BEFORE any
# report or console line interpolates it (gate BLOCKER 2026-07-24: assigned
# mid-report-construction, the Source line above the assignment silently
# interpolated an empty string -- PS 5.1 without StrictMode reads an unassigned
# variable as $null -- so a suspect-mode report opened with unmarked statistics).
# An incomplete sidecar scan marks through the SAME machinery: missing
# negative-authority evidence makes every count untrustworthy too.
$unreliableTag = ''
if ($suspectCorrelated.Count -gt 0) {
  $unreliableTag = ' (UNRELIABLE -- suspect artifacts present, see the lead section)'
} elseif ($verdictScanIncomplete) {
  $unreliableTag = ' (UNRELIABLE -- evidence enumeration incomplete, see the lead section)'
} elseif ($sidecarScanIncomplete) {
  $unreliableTag = ' (UNRELIABLE -- quarantine evidence incomplete, see the lead section)'
} elseif ($attributionNonMonotonic.Count -gt 0) {
  $unreliableTag = ' (UNRELIABLE -- commit times are not monotonic, window attribution cannot be trusted; see the lead section)'
}
# Commit-gate statistics (passing rounds, window tightness, first-attempt-
# CLEAN, repeat categories) are INCOMPLETE whenever a staged or
# unrecognized-scope artifact inside the commit-attribution window could
# not be read or parsed: its tree is unknowable, so it may be the
# OID-matched PASS a branch commit is credited as missing. Merge rounds
# match on filename identity and are unaffected; manual, post-commit, or
# foreign-branch records stay advisory-only.
# NO commit-gate artifact at all in the scanned dirs' window is the loudest
# incompleteness: this run's own merge verdicts alone would still register
# as correlation signal, so the zero-correlation banner cannot expose an
# absent commit-gate CORPUS (a fresh install, a wrong -ReviewsDir set). It
# leads the report and the console, and every commit-gate statistic is
# INCOMPLETE.
# The absence claim is made only when it is KNOWN: no commit-gate-shaped name
# was observed at all AND every scanned dir enumerated cleanly. Unreadable
# staged files or a failed enumeration leave corpus presence unknowable and
# take the incomplete/unreliable paths instead.
$noCommitGateCorpus = ($commitGateAll.Count -eq 0) -and ($stagedNamesObserved -eq 0) -and (-not $verdictScanIncomplete)
if ($noCommitGateCorpus) { $commitGateEvidenceIncomplete = $true }
# FAIL-LOUD REPORT CONTRACT (2026-07-23, replacing the earlier
# abort-before-report): correlated suspect artifacts no longer suppress the
# report -- the report is EMITTED, LED by a prominent suspect section naming
# each correlated fail-closed/malformed/unreadable artifact (possible gate
# bypass or failed gate run -- verify manually), and every count/statistic
# section is marked UNRELIABLE while any suspect exists. No suppression and
# no trust decision is made: the suspects stay excluded from the counts (they
# are not valid verdicts), and the alarm the abort used to provide lives in
# the report's lead instead of in the report's absence. The audit stays
# non-gating. NOTE for a FALLBACK-merged landing: the codex-primary -> claude
# fallback direction leaves the exhausted codex panel's fail-closed banner
# artifact for the landed tip/base, so that landing's audit report is
# suspect-led with unreliable-marked statistics until the verdict-artifact
# framing migration follow-up lands audit-side supersession (its
# run-identity + terminal-receipt infrastructure); the claude-primary
# direction writes no verdict artifact at exit 4 (sidecar only), so it does
# not produce this state -- instead its surviving passing sibling artifacts
# are demoted by the sidecar quarantine (the standalone-sidecar
# identity-and-window match at $exhaustedPanelSidecars), so they cannot form
# an authoritative PASS round on that evidence alone.
if ($suspectCorrelated.Count -gt 0) {
  Write-Host "[worker-audit] ERROR: [class:suspect] $($suspectCorrelated.Count) verdict artifact(s) reliably correlated to this branch (OID/tip-matched) are fail-closed, malformed, or unreadable; the report LEADS with them and every statistic below them is marked UNRELIABLE:"
  foreach ($s in $suspectCorrelated) { Write-Host "[worker-audit]   - $s" }
  Write-Host '[worker-audit]        Verify the artifact(s) manually (possible gate bypass or failed gate run); the report is still emitted.'
}
if ($attributionNonMonotonic.Count -gt 0) {
  Write-Host "[worker-audit] ERROR: [class:operational] commit times are NOT monotonic along the branch ($($attributionNonMonotonic -join '; ')) - window attribution cannot be trusted; every window-attributed count below is UNRELIABLE (see the report lead)."
}
foreach ($am in @($script:AmbiguousTipMatches | Sort-Object -Unique)) {
  Write-Host "[worker-audit] WARNING: $am (see the report's advisory section)"
}
if ($verdictScanIncomplete) {
  Write-Host "[worker-audit] ERROR: [class:operational] evidence enumeration FAILED in at least one reviews dir (verdict scan, which also skips that dir's sidecar scan) - quarantine/correlation evidence is INCOMPLETE; every count below is UNRELIABLE (see the report lead)"
} elseif ($sidecarScanIncomplete) {
  Write-Host "[worker-audit] ERROR: [class:operational] exhaustion-sidecar evidence is INCOMPLETE in at least one reviews dir (the sidecar scan failed, or a this-landing sidecar could not be time-scoped) - quarantine decisions could not all be evaluated; every count below is UNRELIABLE (see the report lead)"
}

$commitGateValid =@($commitGateAll | Where-Object { $null -eq $_.SuspectReason })
# Group per-backend artifacts of one gate run into ATTEMPTS first (a REVIEW_BACKEND
# =both run emits a codex + claude `-staged.md` for the same tree), so a both-
# backend run is ONE round, not two.
$commitGateAttemptsAll = @(Group-CommitGateAttempts -Artifacts $commitGateValid)
# Ambiguous attempts are excluded BEFORE correlation (gate BLOCKER
# 2026-07-24: a marked fold that still correlated set HasPass, fed aborted /
# first-attempt / tight / repeat totals, and suppressed the banner while the
# prose called it non-authoritative). They live in a SIGNAL-ONLY collection:
# listed in their own report section and counted only toward the
# zero-correlation banner decision, never toward any statistic.
# ORDER-INSTABILITY is its OWN state, never folded into the flag above: the
# legacy Ambiguous flag means "a shape one invocation can produce and two
# produce identically", and every consumer's prose says exactly that. An
# attempt whose partition depends on an unknowable within-second order is a
# DIFFERENT statement, so it carries its own flag, its own console line, and
# its own report section -- while sharing the same consequence, exclusion from
# every authoritative statistic.
$commitGateAttempts = @($commitGateAttemptsAll | Where-Object { -not $_.Ambiguous -and -not $_.OrderAmbiguous })
$ambiguousCommitAttempts = @($commitGateAttemptsAll | Where-Object { $_.Ambiguous })
# An attempt can hold BOTH states at once (a cross-backend fold whose partition
# also depends on a same-second order). Each is a separate true statement about
# it, so it is listed under each -- suppressing one because the other is set
# made identical evidence report differently depending on which order the
# directory happened to enumerate.
$orderAmbiguousCommitAttempts = @($commitGateAttemptsAll | Where-Object { $_.OrderAmbiguous })
if ($ambiguousCommitAttempts.Count -gt 0) {
  Write-Host "[worker-audit] WARNING: $($ambiguousCommitAttempts.Count) same-tree commit-gate artifact set(s) have a shape one gate invocation can produce but two produce identically (a same-backend pair after a PASS, or a cross-backend pair) - undecidable without a gate-run identifier; excluded from ALL correlation statistics (signal-only, see the report)"
}
if ($orderAmbiguousCommitAttempts.Count -gt 0) {
  Write-Host "[worker-audit] WARNING: $($orderAmbiguousCommitAttempts.Count) commit-gate attempt(s) group differently depending on the order of artifacts stamped in the SAME SECOND - the producer's clock cannot separate them; excluded from ALL correlation statistics (signal-only, see the report)"
}
# The filtered-out attempts still name the trees they reviewed, under either
# flag: a later definite rerun on such a tree is not a first attempt.
$ambiguousTrees = @(@($ambiguousCommitAttempts) + @($orderAmbiguousCommitAttempts) | ForEach-Object { [string]$_.TreeOid } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$rows = @(Invoke-CommitGateCorrelation -Commits $commits -BaseEpoch $facts.BaseEpoch -CommitGateAttempts $commitGateAttempts -TreesWithAmbiguousAttempts $ambiguousTrees)
# Emitted HERE, immediately AFTER the correlation fills $rows -- beside the
# other console warnings it would have read an unassigned variable (PS 5.1
# without StrictMode yields $null), counted zero, and dropped the warning on
# every affected run, including the stdout the post-merge consumer reads.
$repeatWithheldRows = @($rows | Where-Object { @($_.RepeatOrderSuppressed).Count -gt 0 })
if ($repeatWithheldRows.Count -gt 0) {
  Write-Host "[worker-audit] WARNING: repeat categories were WITHHELD on $($repeatWithheldRows.Count) commit row(s) - same-second aborted attempts admit more than one adjacency, so those repeats are not decidable from the artifacts (named per row in the report)"
}
# A withheld passing round is a HOLE in the passing totals, so it joins the
# incomplete signal -- which is why $incompleteTag is built BELOW this block
# rather than beside the other scan-state variables: the tag is what labels
# every total the hole affects, and a tag built before the correlation ran
# would omit the only signal the correlation can raise.
$passAmbiguousRows = @($rows | Where-Object { $_.PassMatchAmbiguous })
# The tied ARTIFACTS, deduplicated across the rows that share them: this is the
# evidence collection, on the same footing as the ambiguous and order-unstable
# attempt collections -- it carries no authority, but something DID correlate,
# so it must count as correlation SIGNAL and be listed by name.
$passAmbiguousArtifacts = @(@($rows | ForEach-Object { @($_.PassMatchAmbiguousNames) }) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
if ($passAmbiguousRows.Count -gt 0) {
  $commitGateEvidenceIncomplete = $true
  Write-Host "[worker-audit] WARNING: $($passAmbiguousRows.Count) commit row(s) sit equidistant from a same-tree PASS artifact - which commit that verdict reviewed is not decidable from the artifacts, so the round is claimed by NEITHER (named per row in the report)"
}
$incompleteTag = if ($noCommitGateCorpus) { ' (INCOMPLETE -- NO commit-gate artifacts were scanned; see the lead section)' } elseif ($commitGateEvidenceIncomplete) { ' (INCOMPLETE -- unreadable or malformed staged or unrecognized-scope evidence in the commit-attribution window, or a passing round no commit can claim; see the advisory sections)' } else { '' }

# ---------------------------------------------------------------------------
# Merge-gate rounds: tip-matched to a branch commit, then grouped into ROUNDS by
# (matched commit, base) via Group-MergeRounds -- NOT the filename stem, since
# each panel child stamps its own timestamp for one attempt (see that
# function's header). A round's outcome is the WORST class across its
# artifacts (the merge gate unions its panel children).
# ---------------------------------------------------------------------------
$matchedMerge = New-Object 'System.Collections.Generic.List[object]'
$mergeTreeMismatch = New-Object 'System.Collections.Generic.List[string]'
foreach ($rec in $mergeAll) {
  if ($null -ne $rec.SuspectReason) { continue }
  $matchedCommit = Resolve-TipToCommit -Tip $rec.Scope.Tip -CommitShas $commitShas
  if ($null -eq $matchedCommit) { continue }
  # Require the reviewed base to match the audited base too (BEFORE the tree
  # cross-check below): a same-tip verdict for a DIFFERENT base (a stale pre-rebase
  # artifact, or a manual `-Scope Branch` spot-check against another base) reviewed a
  # different diff and is NOT this landing's merge round -- counting it would inflate
  # $mergeRounds. Placed ahead of the tree-mismatch abort so a wrong-base verdict is
  # skipped outright, never mistaken for a tree-mismatched branch artifact. (Codex
  # BLOCKER: tip-only match ignored the reviewed base.) The name's base
  # ambiguity resolves against GROUND TRUTH (Get-VerdictScope's rationale):
  # the whole-suffix (legacy-safe) reading wins when it matches the audited
  # identity; the split reading (12-hex base + reserved child tag) is used
  # only when the whole does not match and the split does -- which is also
  # what assigns the Child member identity the round grouping keys on.
  $effBase = $rec.Scope.Base
  $effChild = $null
  $recLegacyMatch = Test-EraUnknownForBaseMatch -Backend $rec.Backend
  if (-not (Test-BaseMatch -FilenameBase $effBase -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy:$recLegacyMatch)) {
    if ($null -ne $rec.Scope.SplitBase -and
        (Test-BaseMatch -FilenameBase $rec.Scope.SplitBase -AuditBaseSha $facts.BaseSha -AuditBaseRef $facts.BaseRef -Legacy:$recLegacyMatch)) {
      $effBase = $rec.Scope.SplitBase
      $effChild = $rec.Scope.SplitChild
    } else {
      continue
    }
  }
  # Cross-check: a HEADER-BEARING merge verdict whose filename tip resolves to a
  # branch commit MUST carry that commit's tree OID (the merge gate reviews
  # `<tip>^{tree}`). A MISMATCH is untrustworthy branch-correlated evidence (the
  # artifact names this branch's tip but reviewed a different tree), so it FAILS
  # CLOSED rather than being silently dropped (which would undercount merge rounds
  # in a passing report). A legacy prose verdict (no tree header) is accepted on the
  # tip + base match (checked just above) WITHOUT this tree-OID cross-check. (Codex
  # BLOCKER: the mismatch was silently `continue`d.)
  $recOid = ([string]$rec.TreeOid).ToLowerInvariant()
  $matchedRow = @($commits | Where-Object { $_.Sha -eq $matchedCommit })[0]
  $matchedTree = ([string]$matchedRow.Tree).ToLowerInvariant()
  if ($recOid -ne '' -and $recOid -ne $matchedTree) {
    $mergeTreeMismatch.Add("[$($rec.Backend)] $($rec.Name) -- tip resolves to commit $($matchedRow.Short) but REVIEW-TREE-OID $recOid != that commit's tree $matchedTree") | Out-Null
    continue
  }
  # SIDECAR QUARANTINE (the contract lives at the $exhaustedPanelSidecars
  # declaration): placed AFTER the tree-mismatch fail-closed check so a
  # mismatched artifact keeps its stronger abort signal. Keyed on the FULL
  # matched identity (resolved tip SHA + the CANONICAL audited base SHA --
  # never the filename's spelling, so SHA-spelled and ref-spelled names
  # meet on one key; the record's backend label is NOT part of the key, so
  # every label -- producer headers and headerless legacy alike -- demotes)
  # AND time-scoped to the panel clustering window around the sidecar's own
  # timestamp, so a valid round for a DIFFERENT tip survives and a LATER
  # same-identity retry outside the window keeps its authority.
  $canonBaseKey = ([string]$facts.BaseSha).ToLowerInvariant()
  $quarKey = "$matchedCommit|$canonBaseKey"
  $quarHit = $false
  foreach ($panelSc in $exhaustedPanelSidecars) {
    if ($panelSc.Key -eq $quarKey -and [Math]::Abs([long]$rec.Epoch - $panelSc.Epoch) -le $script:PanelAttemptGapSec) {
      $quarHit = $true
      break
    }
  }
  if ($quarHit) {
    $quarantinedPanelArtifacts.Add("[$($rec.Backend)] $($rec.Name) -- quarantined from round authority: an exhaustion-declaration sidecar shares its tip/base identity and panel launch window (every producer backend is demoted -- the sidecar carries no authenticated producer; authority withheld; any same-stem pairing unverified; no exhaustion or fallback provenance asserted)") | Out-Null
    continue
  }
  # $rec.Epoch is the FILENAME timestamp (review start), NOT the file mtime,
  # so Group-MergeRounds clusters one attempt's concurrently-launched
  # children together, separates a later same-tip re-run, and marks a
  # disjoint-member cross-backend fold Ambiguous.
  $matchedMerge.Add([pscustomobject]@{
    MatchedSha = $matchedCommit; MatchedShort = $matchedRow.Short; Base = $effBase; BaseKey = $canonBaseKey
    Backend = $rec.Backend; Class = $rec.Class; Epoch = [long]$rec.Epoch; Child = $effChild
  }) | Out-Null
}
if ($mergeTreeMismatch.Count -gt 0) {
  Write-Host "[worker-audit] ERROR: [class:suspect] $($mergeTreeMismatch.Count) merge verdict(s) name a branch commit tip but carry a mismatched REVIEW-TREE-OID -- untrustworthy branch-correlated evidence; refusing to emit an undercounted report:"
  foreach ($m in $mergeTreeMismatch) { Write-Host "[worker-audit]   - $m" }
  Write-Host '[worker-audit]        Quarantine (move out of the scanned dir) or repair the file(s), then re-run.'
  exit 1
}
$mergeRoundsAll = @(Group-MergeRounds -Artifacts $matchedMerge.ToArray())
# Ambiguous-clustering rounds (any cross-backend fold; rationale inside
# Group-MergeRounds) carry NO authority: they are listed and counted only as
# correlation SIGNAL, never in the authoritative statistics.
$mergeRounds = @($mergeRoundsAll | Where-Object { -not $_.Ambiguous -and -not $_.OrderAmbiguous })
$ambiguousMergeRounds = @($mergeRoundsAll | Where-Object { $_.Ambiguous })
# Order-instability is its own state beside the cross-backend fold: same
# consequence (no authority), different statement, so it never borrows the
# other's prose.
$orderAmbiguousMergeRounds = @($mergeRoundsAll | Where-Object { $_.OrderAmbiguous })
if ($ambiguousMergeRounds.Count -gt 0) {
  Write-Host "[worker-audit] WARNING: $($ambiguousMergeRounds.Count) merge launch-window cluster(s) fold artifacts from more than one backend - one attempt or two single-provider reruns is undecidable without a gate-run identifier; marked AMBIGUOUS-CLUSTERING and excluded from authoritative counts (see the report)"
}
if ($orderAmbiguousMergeRounds.Count -gt 0) {
  Write-Host "[worker-audit] WARNING: $($orderAmbiguousMergeRounds.Count) merge round(s) group differently depending on the order of artifacts stamped in the SAME SECOND - the producer's clock cannot separate them; excluded from authoritative counts (see the report)"
}
if ($quarantinedPanelArtifacts.Count -gt 0) {
  # WARNING, deliberately NOT the ERROR channel auto-merge's post-merge
  # consumer surfaces: quarantine is an EXPECTED state on fallback-merged
  # landings, and after the demotion the printed counts are RELIABLE (the
  # remaining rounds carry their own authority). The ERROR/SUSPECT channel
  # stays reserved for states where the statistics themselves cannot be
  # trusted.
  Write-Host "[worker-audit] WARNING: $($quarantinedPanelArtifacts.Count) merge artifact(s) are QUARANTINED from round authority -- a same-identity exhaustion-declaration sidecar is present (see the report lead):"
  foreach ($q in $quarantinedPanelArtifacts) { Write-Host "[worker-audit]   - $q" }
}

# ---------------------------------------------------------------------------
# Escalations (optional, tolerant).
# ---------------------------------------------------------------------------
$esc = Get-StatusEscalations -Path $StatusFile

$oidMatchedRows =@($rows | Where-Object { $_.HasPass })
# Aborted rounds split by window confidence into a NARROWER estimate (TIGHT: the
# window is OID-flanked on both ends) and a WIDER upper bound (LOOSE: not
# OID-bounded) -- bounds only while the in-window evidence is complete (see
# $evidenceIncomplete below). Aborted rounds carry the WEAKEST evidence: they are ALWAYS window-
# attributed by time, and the verdict artifacts carry NO gate/branch provenance, so
# even a tight interval can contain a concurrent worker's blocked staged review. Of
# the correlated counts, only the tip-matched merge rounds are branch-scoped
# AUTHORITATIVE; the OID-matched passing rounds are TREE-MATCHED (exact tree, not
# branch-scoped -- a same-tree PASS from another branch in the shared logs is
# indistinguishable). (Codex BLOCKER: window-attributed data must not be declared
# authoritative; tree-OID matches are not branch provenance.)
$tightAbortedTotal = (@($rows | Where-Object { $_.Confidence -eq 'tight' } | ForEach-Object { @($_.AbortedRounds).Count }) | Measure-Object -Sum).Sum
if ($null -eq $tightAbortedTotal) { $tightAbortedTotal = 0 }
$looseAbortedTotal = (@($rows | Where-Object { $_.Confidence -eq 'loose' } | ForEach-Object { @($_.AbortedRounds).Count }) | Measure-Object -Sum).Sum
if ($null -eq $looseAbortedTotal) { $looseAbortedTotal = 0 }
$passingTotal = $oidMatchedRows.Count
$mergeBlocked = @($mergeRounds | Where-Object { $_.Class -eq 'BLOCKED' }).Count
$mergeQuality = @($mergeRounds | Where-Object { $_.Class -eq 'QUALITY' }).Count
# PASS = the record's ERA-AWARE class (Get-EraAwareRoundClass over the raw
# Get-VerdictUnionClass): a CLEAN or NOTE-only outcome in any era, PLUS a
# contract-STAMPED QUALITY verdict (non-blocking under the 2026-07 contract --
# the normal case for a QUALITY-bearing branch merge). Labeled PASS -- NOT
# CLEAN -- since NOTE-only and stamped-QUALITY rounds are not strictly clean.
$mergePass = @($mergeRounds | Where-Object { $_.Class -eq 'PASS' }).Count
# FirstAttemptClean + RepeatCategories are BEST-EFFORT (both are derived from
# window-attributed aborted rounds, which have no gate provenance). TIGHT rows give
# the NARROWER estimate (their window is OID-flanked, so less likely to hold
# concurrent noise) and LOOSE rows the WIDER upper bound (while the in-window
# evidence is complete) -- but NEITHER is authoritative. (Codex BLOCKER:
# window-attributed derived metrics are not exact.)
$tightRows = @($rows | Where-Object { $_.Confidence -eq 'tight' })
$looseHasPassRows = @($rows | Where-Object { $_.Confidence -eq 'loose' -and $_.HasPass })
$firstAttemptCleanTight = @($tightRows | Where-Object { $_.FirstAttemptClean }).Count
# Best-effort (narrower) repeat categories = union over TIGHT rows.
$branchRepeatSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($r in $tightRows) { foreach ($cat in @($r.RepeatCategories)) { [void]$branchRepeatSet.Add($cat) } }
$branchRepeatCats = @($script:CatNamesAll | Where-Object { $branchRepeatSet.Contains($_) })
# Wider upper-bound repeat categories = union over LOOSE rows (may include noise).
$looseRepeatSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($r in @($rows | Where-Object { $_.Confidence -eq 'loose' })) { foreach ($cat in @($r.RepeatCategories)) { [void]$looseRepeatSet.Add($cat) } }
$looseRepeatCats = @($script:CatNamesAll | Where-Object { $looseRepeatSet.Contains($_) })
# CORRELATED total = the tip-matched merge rounds (branch-scoped AUTHORITATIVE) +
# the OID-matched passing rounds (TREE-MATCHED -- exact tree, not branch-scoped).
# These are the NON-window-attributed counts; aborted rounds are window-
# attributed upper bounds, NOT included. $anyCorrelationSignal additionally counts
# the aborted upper-bound rounds -- but NOT window-region suspects: those are
# explicitly not-this-branch's-by-OID advisories, so an UNRELATED malformed
# artifact in the window must not suppress the loud zero-correlation banner
# (suspects are reported in their own advisory section either way). (Codex
# BLOCKER review-20260710.)
$correlatedTotal = $passingTotal + $mergeRounds.Count
# Ambiguous clusters/attempts, CORRELATED suspects (OID/tip-matched fail-closed
# artifacts), and quarantined same-identity merge artifacts are correlated
# EVIDENCE (they suppress the zero-correlation banner) without being
# authoritative COUNTS: a report that leads with "SUSPECT ARTIFACTS
# CORRELATED" or lists audited-tip quarantine evidence has correlated
# something and must never also claim nothing correlated.
# Order-unstable clusters are correlated evidence on exactly the same footing:
# they carry no authority, but something DID correlate, so they suppress the
# banner too.
$anyCorrelationSignal = $correlatedTotal + $tightAbortedTotal + $looseAbortedTotal + $ambiguousMergeRounds.Count + $ambiguousCommitAttempts.Count + $orderAmbiguousMergeRounds.Count + $orderAmbiguousCommitAttempts.Count + $suspectCorrelated.Count + $quarantinedPanelArtifacts.Count + $passAmbiguousArtifacts.Count
# The window-attributed aborted counts are UPPER BOUNDS only while nothing
# excluded from them could be this branch's round and every window is
# trustworthy. An unreadable or malformed in-window artifact, a correlated
# suspect, or an ambiguous attempt (all excluded from the counts) may be an
# aborted round this branch owns, so the counts can be UNDERSTATED; a
# non-monotonic history misattributes the windows themselves. An understated
# or misattributed value is not a bound, and the report says so at every
# site that would otherwise call it one.
# Only evidence that COULD be this branch's commit-gate rounds counts here:
# unreadable or malformed STAGED artifacts in the window (the flag above),
# an incomplete enumeration, and boundary-second artifacts (whole-second
# clocks leave their window undecidable). Foreign-tip or wrong-base
# unreadables are confirmed not this landing's and stay advisory-only.
# Distinct artifacts: an artifact on the edge shared by two adjacent windows
# is listed on both rows.
$boundaryNames = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($r in $rows) { foreach ($ba in @($r.BoundaryArtifacts)) { [void]$boundaryNames.Add([string]$ba.Name) } }
$boundaryTotal = $boundaryNames.Count
# EVERY state that can understate or misattribute a window-derived count
# revokes the bound label: unreadable/malformed staged or unrecognized-scope
# evidence in the commit-attribution window,
# an incomplete verdict or sidecar scan, boundary-second artifacts,
# correlated suspects (excluded from the counts, so the counts understate),
# ambiguous commit-gate attempts (excluded likewise), and non-monotonic
# commit times (the windows themselves misattribute).
$evidenceIncomplete = $commitGateEvidenceIncomplete -or $verdictScanIncomplete -or $sidecarScanIncomplete -or ($boundaryTotal -gt 0) -or ($suspectCorrelated.Count -gt 0) -or ($ambiguousCommitAttempts.Count -gt 0) -or ($orderAmbiguousCommitAttempts.Count -gt 0) -or ($attributionNonMonotonic.Count -gt 0)
$abortedBoundWord = if ($evidenceIncomplete) { 'INCOMPLETE -- NOT a bound' } else { 'UPPER BOUND' }
$abortedBoundNote = if ($noCommitGateCorpus) { ' No commit-gate artifacts were scanned at all (see the lead section), so these counts are empty, not bounds.' } elseif ($evidenceIncomplete) { " Evidence that can understate or misattribute these counts exists -- unreadable or malformed staged or unrecognized-scope artifacts in the commit-attribution window, an incomplete verdict or sidecar scan, boundary-second artifacts ($boundaryTotal stamped in the same second as a window edge), correlated suspects, ambiguous attempts, or non-monotonic commit times (see the lead, advisory, and per-commit sections) -- so the aborted counts are neither a bound nor a count until that evidence is verified by hand." } else { '' }

# ---------------------------------------------------------------------------
# Resolve output path. The DEFAULT lands under the repo-root `logs/
# worker-audits/`, which the gate's `.gitignore` `logs/` rule ignores, resolved
# against the MAIN repo root (git common-dir parent), NOT the current directory:
# a subdirectory or linked-worktree invocation joining to Get-Location would
# scatter reports into a `logs/` tree away from the centralized verdict logs the
# report describes (a linked worktree's own `logs/` is empty). An explicit
# -OutPath (absolute or relative) is honored as given. (Codex QUALITY: the default
# report path was cwd-relative despite the gitignored-root claim.)
# ---------------------------------------------------------------------------
$reportTs = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
$reportTsFile = (Get-Date).ToString('yyyyMMdd-HHmmss')
if ([string]::IsNullOrWhiteSpace($OutPath)) {
  # Unique per run: the tip and a second-resolution stamp alone collide for a
  # rapid or concurrent same-tip re-run (the writer replaces an existing
  # destination), so a run-random suffix joins the name.
  $defaultRel = Join-Path 'logs' (Join-Path 'worker-audits' "worker-audit-$($facts.TipShort)-$reportTsFile-$([guid]::NewGuid().ToString('N').Substring(0, 8)).md")
  # Resolve-RelativeToMainRoot returns an absolute repo-root path (cwd fallback only
  # when git cannot resolve a repo), so the default is always the gitignored root.
  $OutPath = Resolve-RelativeToMainRoot -Dir $defaultRel
}
$outAbs = if ([System.IO.Path]::IsPathRooted($OutPath)) { $OutPath } else { Join-Path (Get-Location) $OutPath }

# Write the report: temp file then move, so a mid-write failure leaves no partial
# report at $outAbs. Unlike dispatch-checklist.ps1 this does NOT use MoveFileEx and
# makes NO prior-artifact preservation promise -- worker-audit reports are
# EPHEMERAL (the default -OutPath carries a timestamp AND a run-random suffix,
# so it never overwrites a prior report; an explicitly-reused -OutPath is
# regenerated). A
# writer failure exits 1 loudly. Uses single-file Remove-Item / Move-Item only (no
# -Recurse), per the deletion-safety rule.
function Write-AuditReport {
  param([string]$Body)
  # An -OutPath naming an existing DIRECTORY is REJECTED up front: Move-Item into a
  # directory would silently drop the temp file at <dir>/<tempname> while the caller
  # prints "wrote report to <dir>" -- a false success (Remove-Item without -Recurse
  # cannot clear a non-empty dir, so it is left in place and Move-Item targets it as
  # a container). A report path must be a (new or existing) FILE. (Codex QUALITY.)
  if (Test-Path -LiteralPath $outAbs -PathType Container) {
    Write-Host "[worker-audit] ERROR: [class:operational] -OutPath '$outAbs' is an existing directory; a report path must be a file."
    exit 1
  }
  $tmp = "$outAbs.tmp-" + [guid]::NewGuid().ToString('N').Substring(0, 12)
  try {
    # Parent-dir creation is INSIDE the try (with -ErrorAction Stop) so a bad parent
    # path or a permission failure routes through the stable writer diagnostic in the
    # catch below, NOT a raw PowerShell error -- the function header promises a stable
    # "[worker-audit] ERROR: [class:operational] failed to write report..." on ANY writer failure. (Codex
    # QUALITY: New-Item ran before the try and could escape the handler.)
    $dir = Split-Path -Parent -Path $outAbs
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
      New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
    }
    [System.IO.File]::WriteAllText($tmp, $Body, $utf8NoBom)
    # Remove only an existing LEAF (a prior report) and fail LOUD (-ErrorAction Stop)
    # so a failed removal aborts rather than letting Move-Item mis-place the temp
    # file. An existing directory was already rejected above.
    if (Test-Path -LiteralPath $outAbs -PathType Leaf) { Remove-Item -LiteralPath $outAbs -ErrorAction Stop }
    Move-Item -LiteralPath $tmp -Destination $outAbs -ErrorAction Stop
  } catch {
    Write-Host "[worker-audit] ERROR: [class:operational] failed to write report to $outAbs : $($_.Exception.Message)"
    if (Test-Path -LiteralPath $tmp -PathType Leaf) { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    exit 1
  }
}

$baseShort = if ($facts.BaseSha) { ([string]$facts.BaseSha).Substring(0, [Math]::Min(12, ([string]$facts.BaseSha).Length)) } else { ConvertTo-BoundedMarkdownLine -Text $facts.BaseRef }
$dirsScannedList = if ($dirsScanned.Count -gt 0) { ($dirsScanned -join '; ') } else { '(none)' }
# Backend identity is per artifact (its own validated header; headerless =
# legacy), so the scanned-backend list is the union over every record, never a
# directory-name derivation.
# `.ToArray()` on each List (the PS 5.1 `@(<List>)` hazard documented at the
# correlation engine's return).
$backendsSeen = @(($commitGateAll.ToArray() + $mergeAll.ToArray() + $manualAll.ToArray() + $otherAll.ToArray()) | ForEach-Object { [string]$_.Backend } | Sort-Object -Unique)
$backendsScannedList = if ($backendsSeen.Count -gt 0) { ($backendsSeen -join ', ') } else { '(none)' }

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# Worker Process Audit -- $($facts.TipShort) vs $baseShort")
[void]$sb.AppendLine('')
[void]$sb.AppendLine("Generated: $reportTs")
# The zone the producer-local filename timestamps were resolved under (the
# reader's check against a zone change between producing and auditing).
[void]$sb.AppendLine("Filename timestamps resolved as local wall clock under zone: $([System.TimeZoneInfo]::Local.Id)")
[void]$sb.AppendLine('')

# FAIL-LOUD LEAD SECTION (see the fail-loud report contract at the suspect
# handling): emitted BEFORE the Source line and every other statistic-bearing
# line (gate BLOCKER 2026-07-24 -- the suspect alarm must precede the first
# statistic, not follow the preamble), and every statistic section below
# carries the UNRELIABLE tag while any suspect exists.
if ($suspectCorrelated.Count -gt 0) {
  [void]$sb.AppendLine('## !! SUSPECT ARTIFACTS CORRELATED TO THIS BRANCH -- VERIFY MANUALLY !!')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($suspectCorrelated.Count) verdict artifact(s) reliably correlated to this branch")
  [void]$sb.AppendLine('(OID/tip-matched) are fail-closed, malformed, or unreadable -- a possible')
  [void]$sb.AppendLine('gate bypass or failed gate run. They are EXCLUDED from every count below,')
  [void]$sb.AppendLine('and because their gate outcome cannot be assessed, EVERY count and')
  [void]$sb.AppendLine('statistic in this report is UNRELIABLE until each is verified manually.')
  [void]$sb.AppendLine('(A landing merged via the codex->claude exhaustion fallback leaves the')
  [void]$sb.AppendLine('exhausted codex panel''s fail-closed artifact in exactly this state; its')
  [void]$sb.AppendLine('audit-side resolution is owned by the verdict-artifact framing migration')
  [void]$sb.AppendLine('follow-up.)')
  foreach ($s in @($suspectCorrelated)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}
if ($verdictScanIncomplete) {
  [void]$sb.AppendLine('## !! EVIDENCE ENUMERATION INCOMPLETE -- VERIFY THE REVIEWS DIRS MANUALLY !!')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('The verdict scan failed (or a dir could not be identified) in at least one')
  [void]$sb.AppendLine('reviews dir, which also skips that dir''s sidecar scan, so correlation')
  [void]$sb.AppendLine('evidence and the quarantine (the negative check that withholds round')
  [void]$sb.AppendLine('authority from artifacts beside a same-identity exhaustion declaration)')
  [void]$sb.AppendLine('could NOT be fully evaluated. Rounds below may be missing or may carry')
  [void]$sb.AppendLine('authority they would have been denied, so EVERY count and statistic in')
  [void]$sb.AppendLine('this report is UNRELIABLE until the dir state is inspected manually.')
  [void]$sb.AppendLine('')
} elseif ($sidecarScanIncomplete) {
  [void]$sb.AppendLine('## !! QUARANTINE EVIDENCE INCOMPLETE -- VERIFY THE REVIEWS DIRS MANUALLY !!')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('The verdict corpus was scanned whole, but the exhaustion-sidecar scan')
  [void]$sb.AppendLine('failed in at least one reviews dir or a this-landing sidecar could not be')
  [void]$sb.AppendLine('time-scoped (see the console warning), so the quarantine (the negative')
  [void]$sb.AppendLine('check that withholds round authority from artifacts beside a same-identity')
  [void]$sb.AppendLine('exhaustion declaration) could NOT be fully evaluated. Rounds below may')
  [void]$sb.AppendLine('carry authority they would have been denied, so EVERY count and statistic')
  [void]$sb.AppendLine('in this report is UNRELIABLE until the dir state is inspected manually.')
  [void]$sb.AppendLine('')
}
if ($noCommitGateCorpus) {
  [void]$sb.AppendLine('## !! NO COMMIT-GATE ARTIFACTS IN THE SCANNED DIRS -- COMMIT-GATE STATISTICS INCOMPLETE !!')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('Not one commit-gate (`staged`) verdict fell inside the scan window across')
  [void]$sb.AppendLine('the scanned dirs. The commit-gate corpus is ABSENT from this scan (a fresh')
  [void]$sb.AppendLine('install with no central history yet, or a `-ReviewsDir` set that misses the')
  [void]$sb.AppendLine('central logs), so every passing-round, aborted-round, first-attempt, and')
  [void]$sb.AppendLine('repeat-category figure below is INCOMPLETE -- merge rounds alone are not a')
  [void]$sb.AppendLine('process record. Verify the `-ReviewsDir` set before reading any commit-gate')
  [void]$sb.AppendLine('figure.')
  [void]$sb.AppendLine('')
}
if ($quarantinedPanelArtifacts.Count -gt 0) {
  [void]$sb.AppendLine('## Merge artifacts quarantined from round authority')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($quarantinedPanelArtifacts.Count) merge artifact(s) for the audited tip/base are excluded from round")
  [void]$sb.AppendLine('authority: an exhaustion-DECLARATION sidecar (`.exhaustion.json`, any')
  [void]$sb.AppendLine('same-stem pairing unverified)')
  [void]$sb.AppendLine('sharing their tip/base identity and panel launch window is present, so')
  [void]$sb.AppendLine('they cannot be trusted as a complete authoritative panel (every producer')
  [void]$sb.AppendLine('backend is demoted: the sidecar carries no authenticated producer, so its')
  [void]$sb.AppendLine('own `backend` field cannot narrow the demotion).')
  [void]$sb.AppendLine('This is a NEGATIVE finding only -- the sidecar is untrusted content')
  [void]$sb.AppendLine('(syntax-only check; a planted file demotes identically): its presence')
  [void]$sb.AppendLine('does NOT prove exhaustion occurred, nor that any fallback panel ran or')
  [void]$sb.AppendLine('holds authority. Rounds outside the quarantine (another tip, another')
  [void]$sb.AppendLine('launch window -- e.g. a later retry) keep their own')
  [void]$sb.AppendLine('authority on their own evidence. A sidecar can demote, but never grant')
  [void]$sb.AppendLine('authority, mint a round, or erase evidence:')
  foreach ($q in @($quarantinedPanelArtifacts)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $q)") }
  [void]$sb.AppendLine('')
}

# The `Source:` line reports the CORRELATED (non-window-attributed) round
# counts DISTINCTLY -- the tip-matched branch-scope merge rounds (AUTHORITATIVE: the
# `<tip>-vs-<base>` filename names a branch commit + the audited base) and the
# OID-matched commit-gate passing rounds (TREE-MATCHED: exact on tree identity, but a
# tree is NOT branch-scoped, so a same-tree PASS from another branch/commit in the
# shared logs is indistinguishable) -- plus the window-attributed aborted count (an
# upper bound only while the in-window evidence is complete) separately.
# It is a ROUND count, NOT a raw verdict-file count: a merge round (or a
# both-backend commit-gate attempt) with BOTH a codex and a claude artifact is
# grouped into ONE round. (The DEFAULT report path is the repo-root gitignored
# `logs/worker-audits/`, and in any case is NOT at author-lint.ps1's sole
# allowlisted generated-report path, docs/blocker-trends.md, so author-lint
# never scans it; no generated-doc exemption is needed.)
# $incompleteTag rides here too, not only on the later summaries: malformed or
# unreadable staged evidence sets it WITHOUT setting $unreliableTag, and the
# lead line would then publish $passingTotal as a complete count while every
# restatement of it below carried the label.
[void]$sb.AppendLine("Source: $($mergeRounds.Count) AUTHORITATIVE branch-scope merge round(s) [tip+base provenance] + $passingTotal TREE-MATCHED commit-gate passing round(s) [exact tree identity, NOT branch-scoped -- shared-log same-tree ambiguity] + $($tightAbortedTotal + $looseAbortedTotal) window-attributed aborted ($abortedBoundWord) (branch $($facts.TipShort) vs base $baseShort)$unreliableTag$incompleteTag")
[void]$sb.AppendLine("Branch tip: $($facts.TipSha)")
[void]$sb.AppendLine("Base: $($facts.BaseSha) (ref ``$(ConvertTo-BoundedMarkdownLine -Text $facts.BaseRef)``)")
[void]$sb.AppendLine("Range: $baseShort..$($facts.TipShort)")
[void]$sb.AppendLine("Dirs scanned: $(ConvertTo-BoundedMarkdownLine -Text $dirsScannedList -MaxChars 2000)")
[void]$sb.AppendLine("Backends (from each artifact's REVIEW-BACKEND header; headerless = legacy): $(ConvertTo-BoundedMarkdownLine -Text $backendsScannedList)")
if ($dirsSkipped.Count -gt 0) { [void]$sb.AppendLine("Dirs skipped (missing/unreadable): $(ConvertTo-BoundedMarkdownLine -Text ($dirsSkipped -join ', ') -MaxChars 2000)") }
# Compute the window string into a variable FIRST: `AppendLine("..." -f $a, $b)`
# would parse the comma as a SECOND method argument (binding -f to $a alone), so
# the {1} placeholder would have no argument. Parenthesizing via a variable avoids
# the precedence trap.
$firstDt = [DateTimeOffset]::FromUnixTimeSeconds($firstCommitEpoch).LocalDateTime
$lastDt = [DateTimeOffset]::FromUnixTimeSeconds($lastCommitEpoch).LocalDateTime
$windowStr = "Commit-time window: {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}" -f $firstDt, $lastDt
[void]$sb.AppendLine($windowStr)
[void]$sb.AppendLine('')

# Loud zero-correlation banner (NOT silent zeros) -- still a written report. Fires
# when NO round was correlated or window-attributed (no merge round, no commit-gate
# round, no tight/loose upper-bound round). Window-region SUSPECTS do NOT suppress
# it -- they are explicitly not this branch's evidence, and they get their own
# warning section either way (Codex BLOCKER review-20260710); loose-only evidence
# takes the normal report path.
if ($anyCorrelationSignal -eq 0) {
  [void]$sb.AppendLine('> **NO VERDICTS CORRELATED to this branch.**')
  [void]$sb.AppendLine('> This is NOT evidence of a clean, zero-round landing. Either the gate')
  [void]$sb.AppendLine('> verdicts live in a directory not passed via `-ReviewsDir`, the branch')
  [void]$sb.AppendLine('> commits predate/postdate the scan window, or the landing bypassed the')
  [void]$sb.AppendLine('> gate. Verify the `-ReviewsDir` set and the branch/base before reading')
  [void]$sb.AppendLine('> this as "no gate rounds."')
  [void]$sb.AppendLine('')
}

if ($script:AmbiguousTipMatches.Count -gt 0) {
  [void]$sb.AppendLine('## Ambiguous filename tips (advisory -- not correlated)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('These abbreviated filename tips are a prefix of MORE THAN ONE branch commit,')
  [void]$sb.AppendLine('so the artifacts carrying them are not credited to any commit (enumeration')
  [void]$sb.AppendLine('order never decides identity); verify them by hand.')
  [void]$sb.AppendLine('')
  foreach ($am in @($script:AmbiguousTipMatches | Sort-Object -Unique)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $am)") }
  [void]$sb.AppendLine('')
}
if ($attributionNonMonotonic.Count -gt 0) {
  [void]$sb.AppendLine('## NON-MONOTONIC COMMIT TIMES -- window attribution UNRELIABLE')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('The commits below break the time order the per-commit windows rely on: a')
  [void]$sb.AppendLine('child committed BEFORE its own parent (its chronological window then sits')
  [void]$sb.AppendLine('where artifacts of the wrong commit fall), a parent edge with no recorded')
  [void]$sb.AppendLine('time, or a commit sharing a whole second with the base or its predecessor')
  [void]$sb.AppendLine('(an empty window). Aborted rounds and first-attempt-CLEAN derive from those')
  [void]$sb.AppendLine('windows and are unreliable for them. OID-matched passing rounds and tip-matched')
  [void]$sb.AppendLine('merge rounds are unaffected (they match on identity, not time).')
  [void]$sb.AppendLine('')
  foreach ($nm in $attributionNonMonotonic) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $nm)") }
  [void]$sb.AppendLine('')
}
[void]$sb.AppendLine("## Process summary$unreliableTag")
[void]$sb.AppendLine('')
[void]$sb.AppendLine("- Commits on branch: $($commits.Count)")
[void]$sb.AppendLine("- Merge rounds (AUTHORITATIVE tip-match, branch-scope -- the merge gate under normal operation, though a manual ``-Scope Branch`` review of the same tip is indistinguishable): $($mergeRounds.Count) (PASS=$mergePass, QUALITY=$mergeQuality, BLOCKED=$mergeBlocked)")
if ($ambiguousMergeRounds.Count -gt 0) {
  [void]$sb.AppendLine("- Ambiguous-clustering merge attempts (NON-authoritative -- excluded from every count above; see their section below): $($ambiguousMergeRounds.Count)")
}
# Its OWN predicate, never nested under the legacy one: order-instability can
# occur with no cross-backend fold anywhere, and nesting would have dropped the
# line exactly then.
if ($orderAmbiguousMergeRounds.Count -gt 0) {
  [void]$sb.AppendLine("- Same-second ORDER-UNSTABLE merge rounds (NON-authoritative -- excluded from every count above; see their section below): $($orderAmbiguousMergeRounds.Count)")
}
if ($ambiguousCommitAttempts.Count -gt 0) {
  [void]$sb.AppendLine("- Ambiguous commit-gate attempt(s) (NON-authoritative -- excluded from EVERY correlation statistic in this report; see their section below): $($ambiguousCommitAttempts.Count)")
}
if ($orderAmbiguousCommitAttempts.Count -gt 0) {
  [void]$sb.AppendLine("- Same-second ORDER-UNSTABLE commit-gate attempt(s) (NON-authoritative -- excluded from EVERY correlation statistic in this report; see their section below): $($orderAmbiguousCommitAttempts.Count)")
}
if ($duplicateArtifactCopies.Count -gt 0) {
  [void]$sb.AppendLine("- COLLIDING producer names (one name enumerated from several scanned dirs -- a consolidation copy and several same-second events are indistinguishable without run identity, so every member is listed and NONE is counted): $($duplicateArtifactCopies.Count)")
  foreach ($dc in @($duplicateArtifactCopies)) { [void]$sb.AppendLine("  - $(ConvertTo-BoundedMarkdownLine -Text $dc)") }
}
[void]$sb.AppendLine("- Commit-gate PASSING rounds (TREE-MATCHED -- exact tree identity, but a tree is NOT branch-scoped, so a same-tree PASS from another branch/commit in the shared logs is indistinguishable): $passingTotal$incompleteTag")
if ($passAmbiguousRows.Count -gt 0) {
  [void]$sb.AppendLine("- Commit row(s) whose passing round is WITHHELD as EQUIDISTANT (a same-tree PASS artifact sits the same distance from more than one duplicate-tree commit; claimed by none of them, so the passing total above is INCOMPLETE): $($passAmbiguousRows.Count) row(s) over $($passAmbiguousArtifacts.Count) artifact(s) -- NON-authoritative, excluded from EVERY correlation statistic in this report; see their section below")
}
[void]$sb.AppendLine("- Commit-gate ABORTED rounds ($abortedBoundWord -- window-attributed by time, no gate provenance in the artifacts, so even a tight interval MAY hold a concurrent worker's blocked review): $tightAbortedTotal in OID-flanked (narrower) intervals + $looseAbortedTotal in loose (wider) intervals.$abortedBoundNote")
if ($suspectWindowWarn.Count -gt 0) {
  [void]$sb.AppendLine("- Uncorrelated malformed verdict(s) in the commit-time window (NOT counted, NOT this branch's by OID): $($suspectWindowWarn.Count) -- see the warning section below")
}
if ($suspectUnplaceableWarn.Count -gt 0) {
  [void]$sb.AppendLine("- Malformed verdict(s) NO window can place (an unresolvable producer instant, or a stamp on a window edge; NOT counted, and the commit-gate statistics are INCOMPLETE because of them): $($suspectUnplaceableWarn.Count) -- see the advisory section below")
}
if ($suspectScanWarn.Count -gt 0) {
  [void]$sb.AppendLine("- Malformed verdict(s) after the last commit, inside the scan window (NOT counted; nothing there attributes to a landed commit): $($suspectScanWarn.Count) -- see the advisory section below")
}
if ($manualSuspects.Count -gt 0) {
  [void]$sb.AppendLine("- Malformed manual spot-check verdict(s) (NOT gate rounds, NOT counted as spot-checks): $($manualSuspects.Count) -- see the advisory section below")
}
$manualInWindow =@($manualAll | Where-Object { ($null -eq $_.SuspectReason) -and [long]$_.Epoch -gt $windowStartEpoch -and [long]$_.Epoch -le $windowEndEpoch }).Count
if ($manualInWindow -gt 0) {
  [void]$sb.AppendLine("- Manual spot-check verdicts (`-Scope Uncommitted`/`-Scope Commit`) in the scan window: $manualInWindow (NOT gate rounds -- excluded from the counts above)")
}
# First-attempt-CLEAN is BEST-EFFORT (aborted rounds are window-attributed, not
# authoritative); TIGHT rows give the narrower estimate, loose rows an uncertain
# status reported separately.
$tightDenom = $tightRows.Count
$facPct = if ($tightDenom -gt 0) { [Math]::Round(100.0 * $firstAttemptCleanTight / $tightDenom, 1) } else { 0 }
# An absent verdict gets no CAUSAL diagnosis: a fresh install, an unscanned
# corpus, a rebase and a bypassed hook all produce the same absence, and the
# artifacts cannot tell them apart. A row whose verdict was WITHHELD as
# equidistant is not even an absence -- that row has commit-gate evidence, the
# audit simply cannot say whose -- so it is reported on its own line.
$passAmbiguousUnmatched = @($rows | Where-Object { $_.PassMatchAmbiguous -and -not $_.HasPass }).Count
$unmatchedCount = $commits.Count - $oidMatchedRows.Count - $passAmbiguousUnmatched
[void]$sb.AppendLine("- First-attempt-CLEAN (BEST-EFFORT: a commit whose passing round is a TRUE CLEAN -- empty categories, NOT a QUALITY-bearing or NOTE-only PASS -- and has NO window-attributed aborted round; not authoritative, since aborted attribution is time-based; narrower estimate over TIGHT commits): $firstAttemptCleanTight of $tightDenom tight OID-matched commit(s) ($facPct%); $($looseHasPassRows.Count) loose OID-matched commit(s) have UNCERTAIN first-attempt status; $unmatchedCount commit(s) have no OID-matched commit-gate verdict; $passAmbiguousUnmatched commit(s) have their passing evidence WITHHELD as equidistant (it exists; its owner does not resolve)$incompleteTag")
$fileCountList = ($commits | ForEach-Object { "$($_.Short)=$($_.FileCount)" }) -join ', '
$fileSum = (@($commits | ForEach-Object { [int]$_.FileCount }) | Measure-Object -Sum).Sum
[void]$sb.AppendLine("- Batching shape (files changed per commit): $fileCountList (sum $fileSum; a file touched by >1 commit is counted per commit)")
$repeatNote = if ($branchRepeatCats.Count -gt 0) { $branchRepeatCats -join ', ' } else { '(none)' }
$looseRepeatNote = if ($looseRepeatCats.Count -gt 0) { $looseRepeatCats -join ', ' } else { '(none)' }
[void]$sb.AppendLine("- Repeat-category rounds (same reviewer category in consecutive blocking rounds for one commit -- BEST-EFFORT, window-attributed) -- narrower estimate (tight windows): $repeatNote; wider $abortedBoundWord (loose, may include concurrent noise): $looseRepeatNote$incompleteTag")
$repeatSuppressedRows = @($rows | Where-Object { @($_.RepeatOrderSuppressed).Count -gt 0 })
if ($repeatSuppressedRows.Count -gt 0) {
  [void]$sb.AppendLine("- Repeat categories WITHHELD as order-dependent on $($repeatSuppressedRows.Count) commit row(s): same-second attempts admit more than one adjacency, so the repeat counts above are NOT a complete reading of the repeats (see each row)")
}
[void]$sb.AppendLine('')

[void]$sb.AppendLine("## Per-commit gate rounds$unreliableTag$incompleteTag")
[void]$sb.AppendLine('')
foreach ($r in $rows) {
  [void]$sb.AppendLine("### ``$($r.Short)`` [$($r.Confidence)] -- $(ConvertTo-BoundedMarkdownLine -Text $r.Subject)")
  [void]$sb.AppendLine("- Files changed: $($r.FileCount)")
  # Aborted rounds are window-attributed UPPER BOUNDS while the in-window
  # evidence is complete (INCOMPLETE otherwise; weakest evidence). A loose
  # window (not OID-flanked on both ends) is the WIDER upper bound -- more likely to
  # hold a concurrent worker's blocked review; the merge rounds (branch-scoped) +
  # passing round (TREE-MATCHED) are the correlated counts.
  $aCount = @($r.AbortedRounds).Count
  $boundNote = if ($aCount -gt 0) { $(if ($r.Confidence -eq 'loose') { " [aborted = LOOSE/wider $abortedBoundWord]" } else { " [aborted = tight/narrower $abortedBoundWord]" }) } else { '' }
  if ($r.HasPass) {
    [void]$sb.AppendLine("- Commit-gate: 1 OID-matched passing round (``$(ConvertTo-BoundedMarkdownLine -Text $r.PassingRound.Name)``, TREE-MATCHED -- exact tree, not branch-scoped) + $aCount window-attributed aborted round(s)$boundNote")
  } else {
    [void]$sb.AppendLine("- Commit-gate: NO OID-matched passing verdict + $aCount window-attributed aborted round(s)$boundNote")
  }
  # OUTSIDE that branch on purpose: a row can hold a definite passing round AND
  # a separate tied artifact, and hanging this on the no-pass case would hide
  # the withheld evidence on exactly the rows that look most settled. Rendered
  # with names, because a withheld round and a genuinely absent one are
  # different findings and the absence alone reads as a measured zero.
  $rPma = @($r.PassMatchAmbiguousNames)
  if ($rPma.Count -gt 0) {
    [void]$sb.AppendLine("- Commit-gate passing round(s) WITHHELD as EQUIDISTANT -- each artifact below sits the same distance from this commit as from at least one duplicate-tree sibling, so which of them it reviewed is undecidable at whole-second resolution and it is claimed by NONE of them: $(ConvertTo-BoundedMarkdownLine -Text ($rPma -join ', ') -MaxChars 2000)")
  }
  if (@($r.AbortedRounds).Count -gt 0) {
    foreach ($a in @($r.AbortedRounds)) {
      $catStr = if (@($a.Categories).Count -gt 0) { @($a.Categories) -join ', ' } else { '(no category)' }
      [void]$sb.AppendLine("    - aborted [$($a.Class)] ``$(ConvertTo-BoundedMarkdownLine -Text $a.Name)`` -- categories: $(ConvertTo-BoundedMarkdownLine -Text $catStr)")
    }
  }
  if (@($r.BoundaryArtifacts).Count -gt 0) {
    [void]$sb.AppendLine("- Boundary-second blocking artifact(s) -- stamped in the SAME second as a window edge, so their commit is UNDECIDABLE at whole-second resolution (attributed to no window; this row's window results are incomplete): $(ConvertTo-BoundedMarkdownLine -Text (@($r.BoundaryArtifacts | ForEach-Object { $_.Name }) -join ', ') -MaxChars 2000)")
  }
  $rc = @($r.RepeatCategories)
  if ($rc.Count -gt 0) {
    $rcTag = if ($r.Confidence -eq 'tight') { '<- single-instance-fix signal (best-effort, narrower)' } else { "<- best-effort $abortedBoundWord (loose window; may include concurrent noise)" }
    [void]$sb.AppendLine("- Repeat categories (consecutive blocking rounds): $(ConvertTo-BoundedMarkdownLine -Text ($rc -join ', '))  $rcTag")
  }
  # The suppressed set is RENDERED, never merely recorded: a category dropped
  # for order-dependence would otherwise read as a plain absence, presenting
  # excluded evidence as a measured zero.
  $rcSup = @($r.RepeatOrderSuppressed)
  if ($rcSup.Count -gt 0) {
    [void]$sb.AppendLine("- Repeat categories WITHHELD as order-dependent (attempts stamped in the same second have no knowable order; these repeat under some orderings and not others, so neither answer is evidence): $(ConvertTo-BoundedMarkdownLine -Text ($rcSup -join ', '))")
  }
  [void]$sb.AppendLine('')
}

[void]$sb.AppendLine("## Merge rounds (branch-scope, tip-matched)$unreliableTag")
[void]$sb.AppendLine('')
if ($mergeRounds.Count -eq 0) {
  [void]$sb.AppendLine('_(no branch-scope merge rounds correlated -- the branch may have merged via a superseded tip, or the merge verdicts are outside the scanned dirs)_')
} else {
  foreach ($mr in $mergeRounds) {
    $bk = if ($mr.Backends.Count -gt 0) { @($mr.Backends) -join '+' } else { 'unknown' }
    [void]$sb.AppendLine("- [$($mr.Class)] tip ``$(ConvertTo-BoundedMarkdownLine -Text $mr.MatchedShort)`` vs ``$(ConvertTo-BoundedMarkdownLine -Text $mr.Base)`` (backends: $(ConvertTo-BoundedMarkdownLine -Text $bk))")
  }
}
[void]$sb.AppendLine('')

if ($ambiguousMergeRounds.Count -gt 0) {
  [void]$sb.AppendLine('## Ambiguous-clustering merge attempts (NON-authoritative)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($ambiguousMergeRounds.Count) launch-window cluster(s) fold artifacts from MULTIPLE backends.")
  [void]$sb.AppendLine('Under the single-provider contract one merge invocation never emits two')
  [void]$sb.AppendLine('backends, and the historical both-provider shape is indistinguishable from')
  [void]$sb.AppendLine('two single-provider reruns; whether a cluster is one attempt, a fast rerun,')
  [void]$sb.AppendLine('or an exhaustion fallback is UNDECIDABLE without a')
  [void]$sb.AppendLine('gate-run identifier, so nothing here is counted in any authoritative')
  [void]$sb.AppendLine('statistic -- the evidence is listed, not interpreted:')
  foreach ($amr in @($ambiguousMergeRounds)) {
    $ambk = if ($amr.Backends.Count -gt 0) { @($amr.Backends) -join '+' } else { 'unknown' }
    [void]$sb.AppendLine("- [worst class $($amr.Class)] tip ``$(ConvertTo-BoundedMarkdownLine -Text $amr.MatchedShort)`` vs ``$(ConvertTo-BoundedMarkdownLine -Text $amr.Base)`` (backends: $(ConvertTo-BoundedMarkdownLine -Text $ambk); members: $(ConvertTo-BoundedMarkdownLine -Text (@($amr.Members) -join ', ') -MaxChars 2000))")
  }
  [void]$sb.AppendLine('')
}

if ($orderAmbiguousMergeRounds.Count -gt 0) {
  [void]$sb.AppendLine('## Same-second ORDER-UNSTABLE merge rounds (NON-authoritative)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($orderAmbiguousMergeRounds.Count) round(s) come out differently depending on the order of artifacts")
  [void]$sb.AppendLine('the producers stamped in the SAME SECOND. Those stamps resolve to whole')
  [void]$sb.AppendLine('seconds, so their order is not recorded anywhere: grouping them under every')
  [void]$sb.AppendLine('order the evidence permits yields more than one answer, and no evidence')
  [void]$sb.AppendLine('chooses between them. They are listed, never counted:')
  foreach ($omr in @($orderAmbiguousMergeRounds)) {
    $ombk = if ($omr.Backends.Count -gt 0) { @($omr.Backends) -join '+' } else { 'unknown' }
    [void]$sb.AppendLine("- [worst class $($omr.Class)] tip ``$(ConvertTo-BoundedMarkdownLine -Text $omr.MatchedShort)`` vs ``$(ConvertTo-BoundedMarkdownLine -Text $omr.Base)`` (backends: $(ConvertTo-BoundedMarkdownLine -Text $ombk); members: $(ConvertTo-BoundedMarkdownLine -Text (@($omr.Members) -join ', ') -MaxChars 2000))")
  }
  [void]$sb.AppendLine('')
}

if ($orderAmbiguousCommitAttempts.Count -gt 0) {
  [void]$sb.AppendLine('## Same-second ORDER-UNSTABLE commit-gate attempts (NON-authoritative)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($orderAmbiguousCommitAttempts.Count) attempt(s) come out differently depending on the order of artifacts")
  [void]$sb.AppendLine('the producers stamped in the SAME SECOND -- an order nothing records. Under')
  [void]$sb.AppendLine('one reading these artifacts are one attempt, under another they are two, and')
  [void]$sb.AppendLine('the difference changes the outcome, so they are EXCLUDED from every')
  [void]$sb.AppendLine('correlation statistic and listed here instead:')
  foreach ($oca in @($orderAmbiguousCommitAttempts)) {
    $ocaCats = if (@($oca.Categories).Count -gt 0) { @($oca.Categories) -join ', ' } else { '(none)' }
    [void]$sb.AppendLine("- [worst class $($oca.Class)] tree ``$(ConvertTo-BoundedMarkdownLine -Text $oca.TreeOid)`` (backends: $(ConvertTo-BoundedMarkdownLine -Text (@($oca.Backends) -join '+')); artifacts: $(ConvertTo-BoundedMarkdownLine -Text (@($oca.Names) -join ', ') -MaxChars 2000); categories: $(ConvertTo-BoundedMarkdownLine -Text $ocaCats))")
  }
  [void]$sb.AppendLine('')
}

if ($passAmbiguousArtifacts.Count -gt 0) {
  [void]$sb.AppendLine('## Equidistant passing artifacts (NON-authoritative)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($passAmbiguousArtifacts.Count) PASS artifact(s) sit the SAME distance from more than one commit carrying")
  [void]$sb.AppendLine('the same tree. Producer stamps resolve to whole seconds, so which of those')
  [void]$sb.AppendLine('commits the verdict reviewed is UNDECIDABLE from the artifacts -- and')
  [void]$sb.AppendLine('answering it by the order the commits happen to be listed would assign a')
  [void]$sb.AppendLine('passing round, a tight-window classification and a first-attempt-CLEAN')
  [void]$sb.AppendLine('credit to an arbitrary commit. Each is therefore claimed by NONE of them and')
  [void]$sb.AppendLine('EXCLUDED from every correlation statistic; the rows they touch are named')
  [void]$sb.AppendLine('in the per-commit section and are counted in no absence total either:')
  foreach ($paa in @($passAmbiguousArtifacts)) {
    [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $paa)")
  }
  [void]$sb.AppendLine('')
}

if ($ambiguousCommitAttempts.Count -gt 0) {
  [void]$sb.AppendLine('## Ambiguous commit-gate attempts (NON-authoritative)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($ambiguousCommitAttempts.Count) same-tree artifact set(s) have a shape one gate invocation CAN produce")
  [void]$sb.AppendLine('but two invocations produce identically: a same-backend pair whose earlier')
  [void]$sb.AppendLine('artifact passed (a both-mode leg that exhausted and fell back), or a')
  [void]$sb.AppendLine('cross-backend pair (one both-mode run, or two single-backend reruns that')
  [void]$sb.AppendLine('chose different backends).')
  [void]$sb.AppendLine('Whether each is one gate invocation or a rerun is UNDECIDABLE without a')
  [void]$sb.AppendLine('gate-run identifier, so these attempts are EXCLUDED from every')
  [void]$sb.AppendLine('correlation statistic (passing/aborted/first-attempt/repeat) and only')
  [void]$sb.AppendLine('listed here; the category union preserves the evidence:')
  foreach ($aca in @($ambiguousCommitAttempts)) {
    $acaCats = if (@($aca.Categories).Count -gt 0) { @($aca.Categories) -join ', ' } else { '(none)' }
    [void]$sb.AppendLine("- [worst class $($aca.Class)] tree ``$(ConvertTo-BoundedMarkdownLine -Text $aca.TreeOid)`` (backends: $(ConvertTo-BoundedMarkdownLine -Text (@($aca.Backends) -join '+')); artifacts: $(ConvertTo-BoundedMarkdownLine -Text (@($aca.Names) -join ', ') -MaxChars 2000); categories: $(ConvertTo-BoundedMarkdownLine -Text $acaCats))")
  }
  [void]$sb.AppendLine('')
}

[void]$sb.AppendLine('## Escalations (worker status.json)')
[void]$sb.AppendLine('')
if (-not $esc.Available) {
  [void]$sb.AppendLine("_$(ConvertTo-BoundedMarkdownLine -Text $esc.Reason)_")
} elseif ($esc.Count -eq 0) {
  [void]$sb.AppendLine('None recorded (status.json present, `escalations[]` empty).')
} else {
  [void]$sb.AppendLine("$($esc.Count) escalation(s) recorded:")
  # Bounded listing: the entries are worker-controlled, so the report never
  # grows without limit on their count either.
  $escShown = 0
  foreach ($e in @($esc.Escalations)) {
    if ($escShown -ge 100) { [void]$sb.AppendLine("- ... and $(@($esc.Escalations).Count - $escShown) more (listing capped)"); break }
    [void]$sb.AppendLine("- $e")
    $escShown++
  }
}
[void]$sb.AppendLine('')

# Window-region malformed verdicts: fail-closed evidence in the commit-time window
# that does NOT OID-match this branch (so it may belong to a concurrent branch).
# Surfaced here rather than aborting or being silently dropped.
if ($suspectWindowWarn.Count -gt 0) {
  [void]$sb.AppendLine('## Uncorrelated malformed verdicts in window (advisory)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($suspectWindowWarn.Count) verdict artifact(s) in the commit-time window are")
  [void]$sb.AppendLine('fail-closed or malformed but do NOT OID-match this branch, so they are NOT')
  [void]$sb.AppendLine('attributed to it (they may belong to a concurrent branch). They are neither')
  [void]$sb.AppendLine('counted nor silently dropped; if any actually belong to this branch, its')
  [void]$sb.AppendLine('aborted counts may be understated:')
  foreach ($s in @($suspectWindowWarn)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}
if ($suspectUnplaceableWarn.Count -gt 0) {
  [void]$sb.AppendLine('## Malformed verdicts that NO window can place (advisory)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($suspectUnplaceableWarn.Count) verdict artifact(s) are fail-closed or malformed AND cannot be")
  [void]$sb.AppendLine('placed in any attribution window: either the producer timestamp in the name')
  [void]$sb.AppendLine('resolves to no instant, or the stamp sits on a window EDGE (the base or a')
  [void]$sb.AppendLine('commit second), where no ordering against that commit is knowable. Whether')
  [void]$sb.AppendLine('they belong to this landing is therefore unknown -- which is why the')
  [void]$sb.AppendLine('commit-gate statistics above are marked INCOMPLETE rather than bounded:')
  foreach ($s in @($suspectUnplaceableWarn)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}
if ($suspectScanWarn.Count -gt 0) {
  [void]$sb.AppendLine('## Malformed verdicts after the last commit (scan window, advisory)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($suspectScanWarn.Count) gate-shaped verdict artifact(s) dated AFTER this branch's last commit")
  [void]$sb.AppendLine('(inside the scan window) are fail-closed or malformed and do NOT OID-match')
  [void]$sb.AppendLine('this branch. Nothing past the last commit attributes to a landed commit,')
  [void]$sb.AppendLine('so they understate no count; they are listed so malformed evidence never')
  [void]$sb.AppendLine('vanishes from the audit:')
  foreach ($s in @($suspectScanWarn)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}
if ($manualSuspects.Count -gt 0) {
  [void]$sb.AppendLine('## Malformed manual spot-check verdicts (advisory)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($manualSuspects.Count) manual spot-check verdict(s) (`-Scope Uncommitted`/`-Scope Commit`)")
  [void]$sb.AppendLine('are fail-closed or malformed. A spot-check never gated a landing, so a')
  [void]$sb.AppendLine('malformed one is neither a possible gate bypass nor a missing gate round,')
  [void]$sb.AppendLine('whatever tree it carries; it is dropped from the spot-check count and')
  [void]$sb.AppendLine('listed here so it never vanishes:')
  foreach ($s in @($manualSuspects)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}
if ($unknownScopeSidecars.Count -gt 0) {
  [void]$sb.AppendLine('## Unrecognized-scope exhaustion sidecars (forensic, advisory)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($unknownScopeSidecars.Count) `.exhaustion.json` sidecar(s) carry a producer-shaped name whose scope")
  [void]$sb.AppendLine('is none the wrappers emit. Each row names its pairing state (a same-stem')
  [void]$sb.AppendLine('verdict, when present, is an unverified pairing) and its SYNTAX-ONLY')
  [void]$sb.AppendLine('classification. Such a sidecar quarantines nothing (no tip/base identity)')
  [void]$sb.AppendLine('and grants nothing; it is listed so it cannot vanish:')
  foreach ($s in @($unknownScopeSidecars)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}
if ($standaloneSidecars.Count -gt 0) {
  [void]$sb.AppendLine('## Standalone exhaustion sidecars (forensic, advisory)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($standaloneSidecars.Count) `.exhaustion.json` sidecar(s) have NO paired verdict")
  [void]$sb.AppendLine('artifact (the claude wrapper''s exit-4 paths produce only the sidecar).')
  [void]$sb.AppendLine('Rows are classified by a SYNTAX-ONLY shape check (producer field set')
  [void]$sb.AppendLine('present as strings -- field VALUES are unvalidated). Forensic records:')
  [void]$sb.AppendLine('never counted as rounds, never a grant of authority; the ONLY decision a')
  [void]$sb.AppendLine('sidecar drives is NEGATIVE -- one whose filename matches the')
  [void]$sb.AppendLine('audited tip/base identity quarantines every backend''s same-identity merge')
  [void]$sb.AppendLine('artifacts launched within its panel window from round authority (see the')
  [void]$sb.AppendLine('quarantine lead section). An')
  [void]$sb.AppendLine('UNRECOGNIZED row fails even the shape check (planted/corrupt, not')
  [void]$sb.AppendLine('evidence):')
  foreach ($s in @($standaloneSidecars)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}
if ($unreadableSuspects.Count -gt 0) {
  [void]$sb.AppendLine('## Unreadable verdict files (advisory)')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("$($unreadableSuspects.Count) verdict file(s) could not be read (locked or")
  [void]$sb.AppendLine('unreadable in the shared logs). None carries name-level provenance FOR THE')
  [void]$sb.AppendLine('AUDITED branch (an unreadable BRANCH-SCOPE verdict matching the audited')
  [void]$sb.AppendLine('tip/base joins the suspect-led fail-loud section instead; a NON-MATCHING branch-scope name -- foreign')
  [void]$sb.AppendLine('tip, or the audited tip with a different base -- is not this landing''s), and')
  [void]$sb.AppendLine('their content OIDs are unknowable, so they are neither')
  [void]$sb.AppendLine('counted nor attributed; if any actually belong to this branch, its counts')
  [void]$sb.AppendLine('may be understated:')
  foreach ($s in @($unreadableSuspects)) { [void]$sb.AppendLine("- $(ConvertTo-BoundedMarkdownLine -Text $s)") }
  [void]$sb.AppendLine('')
}

[void]$sb.AppendLine('## Correlation precision (read before trusting the aborted counts)')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('OID-matched commit-gate passing rounds are TREE-MATCHED: the match is EXACT on')
[void]$sb.AppendLine('tree identity (a verdict''s `REVIEW-TREE-OID` = a Staged review''s `git')
[void]$sb.AppendLine('write-tree`, which equals the resulting commit''s tree), but a git tree is NOT')
[void]$sb.AppendLine('branch-scoped -- an unrelated branch that produced the SAME tree (an identical')
[void]$sb.AppendLine('change, a revert, a rebase) whose `staged` PASS verdict sits in the shared')
[void]$sb.AppendLine('central logs is INDISTINGUISHABLE and would be credited here. A concurrent')
[void]$sb.AppendLine('branch USUALLY differs in tree, but identical trees across branches are')
[void]$sb.AppendLine('possible, so this is a TREE match, not branch provenance. Tip-matched MERGE')
[void]$sb.AppendLine('rounds ARE branch-scoped (the `<tip>-vs-<base>` filename names a branch commit +')
[void]$sb.AppendLine('the audited base), additionally tree-OID cross-checked when the verdict carries')
[void]$sb.AppendLine('the header (every MODERN verdict); a LEGACY headerless merge verdict is matched')
[void]$sb.AppendLine('on the filename tip + base, without the tree-OID cross-check (the 12+-hex tip is')
[void]$sb.AppendLine('effectively unique but the tree is not OID-verified). ABORTED')
[void]$sb.AppendLine('rounds are WINDOW-ATTRIBUTED (the FALLBACK): a pre-CLEAN')
[void]$sb.AppendLine('blocking commit-gate review was reviewing a staged tree that never became a')
[void]$sb.AppendLine('commit, so it has no landed commit tree to OID-match. It is attributed to')
[void]$sb.AppendLine('the landed commit whose commit-time window it falls in (the BLOCKED/QUALITY')
[void]$sb.AppendLine('class alone excludes passing rounds; a blocking verdict whose tree later')
[void]$sb.AppendLine('lands via a hook bypass is kept as bypass evidence). A commit row is tagged `tight` when')
[void]$sb.AppendLine('its window is flanked by an OID-matched passing round on BOTH ends (this')
[void]$sb.AppendLine('commit AND its predecessor landed with an OID-matched verdict on this')
[void]$sb.AppendLine('branch), else `loose` (the first branch commit, or a commit following a')
[void]$sb.AppendLine('commit with no OID-matched verdict, e.g. a rebased commit whose tree the')
[void]$sb.AppendLine('commit hook never saw). ABORTED rounds carry the WEAKEST evidence: they are')
[void]$sb.AppendLine('window-attributed by time and the artifacts carry no gate provenance, so even')
[void]$sb.AppendLine('a tight (OID-flanked) interval MAY hold a concurrent worker''s blocked review.')
[void]$sb.AppendLine('The CORRELATED (non-window) counts differ in authority: tip-matched merge')
[void]$sb.AppendLine('rounds are branch-scoped AUTHORITATIVE, while OID-matched passing rounds are')
[void]$sb.AppendLine('TREE-MATCHED -- exact on tree identity but NOT branch-scoped (a same-tree PASS')
[void]$sb.AppendLine('from another branch in the shared central logs is indistinguishable and would be')
[void]$sb.AppendLine("credited here); tight aborted rounds are the narrower $abortedBoundWord, loose the")
[void]$sb.AppendLine("wider (bounds only while nothing excluded from them could be this branch's")
[void]$sb.AppendLine("round and every window is trustworthy: unreadable or malformed evidence in the")
[void]$sb.AppendLine("commit-attribution window, an incomplete verdict or sidecar scan, boundary-second")
[void]$sb.AppendLine("artifacts, correlated suspects, ambiguous attempts, or a non-monotonic history")
[void]$sb.AppendLine("each make the counts INCOMPLETE -- understated or misattributed, not bounds).")
[void]$sb.AppendLine('Both clocks resolve to whole seconds, so a blocking artifact stamped in the')
[void]$sb.AppendLine('same second as a window edge is attributed to NO commit (listed on its rows')
[void]$sb.AppendLine('as boundary-second) and makes the window-derived counts INCOMPLETE.')
[void]$sb.AppendLine('AUTHORITATIVE here is branch provenance -- a merge round''s `<tip>-vs-<base>`')
[void]$sb.AppendLine('filename names a branch commit + the audited base -- but does NOT prove the round')
[void]$sb.AppendLine('was the merge GATE vs a manual `-Scope Branch` review of the same tip+base')
[void]$sb.AppendLine('(indistinguishable; see Methodology), while `staged` scope is the commit gate by')
[void]$sb.AppendLine('convention. First-attempt-CLEAN and repeat-category are likewise BEST-EFFORT (tight')
[void]$sb.AppendLine('= narrower estimate; a loose commit''s first-attempt status is uncertain and its')
[void]$sb.AppendLine("repeat categories are $(if ($evidenceIncomplete) { 'INCOMPLETE -- not a bound' } else { 'an upper bound' })). Per-backend staged artifacts of one")
[void]$sb.AppendLine('gate run (the backends run in series, Codex first) are grouped into ONE attempt')
[void]$sb.AppendLine('by their shared tree OID -- and that cross-backend fold is MARKED ambiguous,')
[void]$sb.AppendLine('never counted: without producer-stamped run identity it is indistinguishable')
[void]$sb.AppendLine('from two single-backend reruns that chose different backends (under the')
[void]$sb.AppendLine('single-provider contract a multi-backend merge cluster is marked the same')
[void]$sb.AppendLine('way). Fold decisions use producer-contract CARDINALITY,')
[void]$sb.AppendLine('never elapsed time: one gate invocation emits at most two valid same-tree')
[void]$sb.AppendLine('artifacts, so a same-backend repeat onto a one-artifact PASS attempt is')
[void]$sb.AppendLine('undecidable (a both-mode exhaustion fallback emits exactly that pair) and')
[void]$sb.AppendLine('is EXCLUDED from every correlation statistic (listed in its own section,')
[void]$sb.AppendLine('category union kept), while any artifact beyond a two-artifact attempt,')
[void]$sb.AppendLine('or after a BLOCKED/QUALITY attempt (the short-circuit means Claude never')
[void]$sb.AppendLine('follows a failed Codex), is a definite rerun and splits into a distinct')
[void]$sb.AppendLine('attempt so its later PASS is preserved, not dropped.')
[void]$sb.AppendLine('A malformed verdict in the window')
[void]$sb.AppendLine('that does not OID-match this branch is advisory-only (it does not abort). Git')
[void]$sb.AppendLine('trees are not unique per commit, so a shared-tree PASS verdict is assigned')
[void]$sb.AppendLine('once to the closest-in-time commit; a duplicate-tree sibling stays unmatched.')
[void]$sb.AppendLine('')

[void]$sb.AppendLine('## Methodology')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Verdict artifacts are the `review-<YYYYMMDD>-<HHMMSS>-<scope>.md` files')
[void]$sb.AppendLine('`auto-review.ps1` writes under `logs/<backend>/reviews` (scanned NON-')
[void]$sb.AppendLine('recursively, so `failclosed-quarantine/` is excluded). The filename-shape')
[void]$sb.AppendLine('guard, backend-label derivation, and fail-closed suspect check are mirrored')
[void]$sb.AppendLine('inline from `scripts/shared/analyze-blocker-trends.ps1` (dot-sourcing is not')
[void]$sb.AppendLine('viable -- the analyzer runs its pipeline and exits on load -- so the')
[void]$sb.AppendLine('primitives are inlined; a shared library is a recorded future refactor).')
[void]$sb.AppendLine('SCOPE classification: only `staged` verdicts are')
[void]$sb.AppendLine('commit-gate rounds (the pre-commit gate uses `-Scope Staged`);')
[void]$sb.AppendLine('`uncommitted` and `commit-<sha>` are manual `-Scope Uncommitted`/`-Scope')
[void]$sb.AppendLine('Commit` spot-checks and are excluded. Merge rounds are `branch-<tip>-vs-<base>`')
[void]$sb.AppendLine('verdicts; the review artifacts carry no gate-vs-manual provenance, so a')
[void]$sb.AppendLine('manual `-Scope Branch` spot-check of the SAME tip AND base would also count as')
[void]$sb.AppendLine('a merge round (a known limit absent a stamped gate marker; a same-tip verdict')
[void]$sb.AppendLine('for a DIFFERENT base reviewed a different diff and is NOT counted). The')
[void]$sb.AppendLine('suspect/advisory matrix: a MALFORMED verdict that RELIABLY belongs to this')
[void]$sb.AppendLine('branch (OID-matched, or a merge verdict whose filename tip names a branch')
[void]$sb.AppendLine('commit AND whose base matches the audited base) LEADS the report as a')
[void]$sb.AppendLine('correlated suspect with every statistic marked UNRELIABLE (the fail-loud')
[void]$sb.AppendLine('report contract -- the report is emitted, never withheld); an UNREADABLE')
[void]$sb.AppendLine('verdict joins that suspect handling only via its FILENAME (branch-scope')
[void]$sb.AppendLine('matching the audited tip/base --')
[void]$sb.AppendLine('unreadable content has no OID to match); unreadable staged/manual files,')
[void]$sb.AppendLine('unreadable NON-matching branch-scope files (a foreign tip, or the audited tip')
[void]$sb.AppendLine('with a DIFFERENT base), malformed verdicts that only fall in the')
[void]$sb.AppendLine('commit-time window (not OID-matched), malformed verdicts dated after the last')
[void]$sb.AppendLine('commit, and malformed manual spot-checks (never gate rounds, whatever tree')
[void]$sb.AppendLine('they carry) are advisory-only, so an unrelated concurrent')
[void]$sb.AppendLine('branch''s malformed or locked verdict never implicates this audit. A')
[void]$sb.AppendLine('exhaustion-declaration sidecar whose filename matches the audited tip/base')
[void]$sb.AppendLine('identity -- same-stem `.md` or not (pairing is unverifiable without run')
[void]$sb.AppendLine('identity) -- WITHHOLDS round authority from every backend''s same-identity merge')
[void]$sb.AppendLine('artifacts launched within its panel window (a later retry outside the')
[void]$sb.AppendLine('window keeps authority; negative authority only -- the untrusted')
[void]$sb.AppendLine('declaration proves neither exhaustion nor any fallback, and a sidecar')
[void]$sb.AppendLine('never grants, counts, or erases). Aborted rounds are the')
[void]$sb.AppendLine('blocking commit-gate reviews: BLOCKER always aborts; QUALITY aborts only for an')
[void]$sb.AppendLine('artifact WITHOUT the REVIEW-SEVERITY-CONTRACT header stamp -- the 2026-07 severity')
[void]$sb.AppendLine('contract made QUALITY NON-BLOCKING (exit 0, recorded as a follow-up) and its')
[void]$sb.AppendLine('wrappers stamp every artifact, so a stamped QUALITY verdict is a PASS, not an')
[void]$sb.AppendLine('aborted round. An unstamped QUALITY artifact is conservatively an aborted round')
[void]$sb.AppendLine('regardless of date: a stale branch running its pre-contract HEAD gate can emit')
[void]$sb.AppendLine('old-contract exit-1 QUALITY artifacts at any time, so the stamp -- not the date --')
[void]$sb.AppendLine('is the era signal.')
[void]$sb.AppendLine('A NOTE-only verdict is a PASS (the gate exits 0). Cycle-count is not a')
[void]$sb.AppendLine('quality metric; this audit surfaces process friction to reduce repeat-class')
[void]$sb.AppendLine('gate rounds, not to rank workers.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Generated by `scripts/shared/worker-audit.ps1` (artifact-based, no harness')
[void]$sb.AppendLine('dependency; gitignored execution-state, not a tracked doc).')

Write-AuditReport -Body $sb.ToString()

# The console summary carries the suspect marker too (gate BLOCKER
# 2026-07-24): the automatic post-merge consumer surfaces only these stdout
# lines, so a marker that lived solely inside the report file would let a
# suspect-led audit read as a normal authoritative summary.
if ($suspectCorrelated.Count -gt 0) {
  Write-Host "[worker-audit] ERROR: [class:suspect] SUSPECT ARTIFACTS CORRELATED to this branch ($($suspectCorrelated.Count)) - every count below is UNRELIABLE; see the report's lead section and verify manually"
}
if ($noCommitGateCorpus) {
  Write-Host "[worker-audit] ERROR: [class:operational] NO COMMIT-GATE artifacts were scanned in the window - the commit-gate corpus is absent from the scanned dirs (a fresh install, or a -ReviewsDir set that misses the central logs); every commit-gate statistic is INCOMPLETE. Verify the -ReviewsDir set."
}
Write-Host "[worker-audit] wrote report to $outAbs$unreliableTag"
Write-Host "[worker-audit]   commits=$($commits.Count)  AUTHORITATIVE: $($mergeRounds.Count) tip-matched branch-scope merge rounds (branch provenance; gate under normal op, see report caveat); TREE-MATCHED: $passingTotal commit-gate passing (exact tree, not branch-scoped -- shared-log same-tree ambiguity)$incompleteTag; aborted ($abortedBoundWord): $tightAbortedTotal tight + $looseAbortedTotal loose$unreliableTag"
Write-Host "[worker-audit]   first-attempt-CLEAN (best-effort)=$firstAttemptCleanTight/$tightDenom tight OID-matched; repeat categories (best-effort, tight): $repeatNote$unreliableTag$incompleteTag"
exit 0
