#Requires -Version 5.1
<#
.SYNOPSIS
  Author-side mechanical linter for narrative / PLAN / doc content, plus the
  count-drift classes (inventory-count + magnitude) over staged source-file COMMENT
  lines and the magic-count-assert class over staged Rust CODE lines.

.DESCRIPTION
  Catches, BEFORE the review gate runs, the small set of mechanical defect
  classes the Codex/Claude gate repeatedly raises on authored Markdown and
  PLAN content -- and, in staged mode, the count-drift classes (inventory-count +
  magnitude) over the COMMENT lines of staged .rs/.ps1/.toml/.sh source files
  (their code lines are never scanned for a count) plus MAGIC-COUNT-ASSERT over the
  CODE lines of staged .rs files. These classes are script-detectable at ~0 token cost, so running
  this pre-pass keeps the gate a FAILSAFE rather than a debugger. The gate stays
  authoritative for everything this linter does not encode.

  Run it before the first gate commit and paste its report into the
  completion report. It ALSO runs mechanically: scripts/git-hooks/pre-commit
  invokes it in staged mode as a fail-fast pre-pass before the AI backend --
  ERROR-tier findings abort the commit there; CROSS_REVIEW_SKIP_AUTHOR_LINT=1 skips
  ONLY that pre-pass (the AI review still runs; the escape for a linter
  false positive). The hook executes HEAD's copy of this file (tempdir
  extraction, never the working tree), so an edit here takes effect on the
  NEXT commit after it lands. Manual runs remain the author-side default
  before the first gate commit of a round.

  Check classes (v1). Tiers were set by CALIBRATION against the real doc tree
  (`-Tree`), not a priori: an error-tier check must fire ZERO false positives
  on the current (gate-clean) tree; one that cannot is downgraded to advisory.
    ERROR-tier (any finding -> exit 3; exit 1 is deliberately NOT used for
    findings -- an uncaught crash under $ErrorActionPreference='Stop' makes
    `powershell -File` exit 1, so the pre-commit pre-pass reads 3 as
    "findings, abort" and 1/anything-else as "linter broke, warn and fail
    open to the AI gate"):
      LINE-ANCHOR  bare `<name>.<ext>:<line>` source citations in tracked
                   narrative docs (both `/` and `\` separators). Violates the
                   symbol-anchor rule (name the grep-able symbol, not the
                   drifting line number). ERROR-tier, EXCEPT a doc carrying the
                   EXPLICIT frozen-snapshot MARKER -- an HTML comment on its own
                   line near the top, matched by the regex
                   `^\s*<!--\s*frozen-snapshot\s*-->\s*$` (case-insensitive) within
                   the doc's first ~30 lines (Test-HasFrozenSnapshotMarker) -- which
                   DOWNGRADES to advisory, honoring the rule's exemption for frozen
                   snapshot line numbers. FILENAME AND DATE NO LONGER MATTER: a
                   dated-in-name doc WITHOUT the marker stays ERROR (it may be live
                   authority), and a NON-dated doc WITH the marker is exempt. The
                   author declares frozen status explicitly; there is no filename
                   inference and no env-var denylist. A machine-GENERATED report is
                   skipped entirely (machine-emitted format, not authored prose) but
                   ONLY when it BOTH sits at a known generated-report path
                   (docs/blocker-trends.md; $script:GeneratedDocPathPattern)
                   AND carries a generator signature -- a `Generated:` stamp alone
                   is NOT enough, so an authored doc cannot self-exempt
                   (Test-IsGeneratedContent). The full-tree audit surfaces all real
                   bare anchors, including any pre-existing debt elsewhere in the doc tree.
      SELF-NARR    narration of the PENDING change's OWN landing -- the deictic
                   "this/here + landing-event" form (Get-SelfNarrationFindings):
                   "this merge" / "this landing", "as of this entry" /
                   "add(s|ing) this entry", and "landed ... here" (a deictic
                   "here" within a short word window of "landed"). ERROR when the
                   doc is History.md (the retrospective landing log, where a
                   not-yet-landed self-reference is a factual defect -- the merge
                   SHA is unknowable while the entry rides the branch); ADVISORY in
                   any other narrative doc. CALIBRATED so the ERROR tier fires only
                   on genuine self-narration: retrospective prose about an
                   already-landed merge ("the merge landed at <sha>", "merged
                   cleanly") has no this/here pointer and stays clean, and a bare
                   "this entry" is NOT matched (legitimate timestamping like "at
                   the time of this entry" would false-positive). History.md is the
                   package's illustrative landing-log convention; a consumer without
                   one simply never trips the ERROR tier (all forms stay advisory).
      LOCAL-PROOF  a proof/verification CLAIM co-located with a LOCAL-ONLY evidence
                   reference (Get-LocalEvidenceFindings). ERROR only in the TIGHT
                   form -- a word-bounded proof word (prove/proves/proved/proven/
                   proving | verify/verifies/verified/verifying/verification/
                   verifiable; word-bounded so "approve"
                   never matches) on the same line as the gitignored review-artifact
                   PATH `logs/(codex|claude)/reviews` (either `/` or `\` separator,
                   Windows-first), OR a `proof`/`evidence` NOUN within a short
                   window of that path (so "Proof: <path>" flags while a distant
                   "evidence snapshot ... <path>" description does not). That path
                   is THE local evidence store, and the full-tree calibration found
                   the pairing does not arise in legitimate prose, so the tight form is
                   high-precision ERROR. The looser marker variants are ADVISORY
                   (see below) by the same calibration.
      INVENTORY    an EXACT INVENTORY/COUNT of repo/project state asserted in
                   prose (Get-InventoryAssertionFindings) -- a cardinal number
                   the moment the inventory changes goes stale and no reader can
                   trust it. Noun-AGNOSTIC, verb-gated shapes: "there
                   is|are N <word>", "N <word> is|are defined|tracked|supported|
                   registered|covered|available|in place", "covers|contains|
                   includes|names|totals N <word>". N is a DIGIT run OR a spelled
                   cardinal ($script:SpelledCardinalAlternation -- "one" is
                   deliberately outside it; see that constant). A further,
                   determiner-gated shape carries its own ADVISORY tier: "the|these|
                   those <spelled-N> <modifiers> <plural count-noun>" ("the two
                   consecutive landings"), noun-gated on
                   $script:CountNounPluralAlternation, with function words barred
                   from the modifier slot, and ONE OR TWO modifier words required --
                   with none the MAGNITUDE digit-first form already reports the
                   occurrence, and past two the noun is out of reach.
                   The VERB-GATED shapes with a DIGIT cardinal are ERROR in .md prose,
                   the mapping the Self-Sweep's error-tier list documents -- EXCEPT a
                   count inside a DATED entry body of the ROOT History.md log, which is
                   SKIPPED (a dated entry is a static, append-only snapshot whose
                   counts cannot drift). A SPELLED cardinal and the `names` verb are
                   ADVISORY, as is the determiner-gated shape above: the pre-pass may
                   not be STRICTER than the gate it front-runs, and the reviewer
                   contract scores an exact-count-in-prose QUALITY, so a class the gate
                   declines to block must not abort a commit. (Re-tiering the documented
                   digit shapes to match is an OPERATOR decision, not a linter change.)
                   The History exemption is CALLER-applied by
                   Invoke-FileChecks and narrow on TWO axes -- root-path (NOT a
                   nested History.md) + a dated-entry-body mask (the preamble and
                   undated `## ` sections stay in class) -- not inside this detector
                   (2026-07-09 operator decision). A CARDINAL-LEADING match at the
                   START OF THE LINE'S TEXT -- column zero, or preceded only by
                   whitespace and the Markdown marks that open a line -- is ADVISORY
                   rather than ERROR: a hard wrap can leave a comparative bound
                   ("at least") on the line above, beyond the one-line lookbehind's
                   reach, and a bounded claim is not an inventory. NO frozen-snapshot downgrade
                   otherwise -- the marker exemption is line-anchor-scoped (the digit lookbehind
                   excludes identifier/version/date/SHA digits; a FULL illustrative
                   inline-code example -- the whole claim in one backtick span --
                   is exempt so a doc can NAME the class, while a claim whose
                   number ALONE is backticked still flags). This SAME detector ALSO runs over the
                   COMMENT lines of staged .rs/.ps1/.toml/.sh source files
                   ($script:SourceExtPattern; Get-StagedSourceFindings), one tier
                   SOFTER (ADVISORY) there since comment extraction has edge cases,
                   with a code-echo exemption (a comment count equal to a code
                   literal on a NEARBY line -- within a small window -- is
                   describing that adjacent constant, not asserting an inventory;
                   an unrelated same number elsewhere in the file does NOT
                   exempt). Fix direction: magnitude phrasing or delete the
                   sentence -- never a "corrected" number, which just re-seeds the
                   drift. (Operator escalation 2026-07: exact counts recur in prose
                   and always drift; the reviewer-side contract is in
                   review-prompt-template.md.)
    ADVISORY-tier (reported; does NOT by itself set the findings exit):
      UNSUPPORTED-SYNTAX
                   a GOVERNED file whose line-oriented classes could not run over
                   it, and why. The ways a file reaches it:
                     * its text falls outside the comment/code splitter's POSITIVELY
                       SUPPORTED grammar -- line comments, non-nested block comments,
                       plain strings with the one escape the model applies (`\` in
                       rs, a backtick in a DOUBLE-quoted ps1 string -- single-quoted
                       PowerShell has no BACKTICK escape, and its own quote-doubling
                       escape is refused), a Rust string spanning records, a
                       single-level `${...}` in ps1/sh -- opaque NAME text in ps1,
                       and in sh a body PARSED against the parameter-expansion
                       productions, so a body matching none of them refuses by
                       default. Both apply in code position and inside an
                       EXPANDABLE string alike (a single-quoted string
                       interpolates in neither language, so there the braces are
                       literal text) -- and the
                       CLOSED Rust `'` shapes -- a `'ident` lifetime expecting no
                       closing quote, and a char literal whose body is bounded by the
                       escape grammar. A `#` counts as a line comment only where the
                       language's own rule settles it FOR THE RECORD IN HAND -- an
                       ESCAPED separator before it keeps it inside the word, so that
                       shape refuses rather than certifying an invented comment. A
                       trailing escape is a LINE CONTINUATION, admitted only where a
                       separator at the seam PROVES the join leaves the record-wise
                       reading unchanged, and refused otherwise -- a joined pair can
                       otherwise build a here-document or an ansi-C string opener out
                       of two records, whose body text then reads as comments.
                       Everything else
                       refuses, including forms nobody enumerated: the check LISTS
                       WHAT IS HANDLED rather than what is not, because the second
                       list is unbounded and each miss is silent. A quote glued to a
                       preceding token fails one rule that covers raw / byte / c
                       strings, here-strings, `$'...'` and triple quotes alike, and a
                       `$(...)` or backtick SUBSTITUTION inside a quoted string
                       refuses because it opens a nested expression that can hold the
                       very characters the split keys on.
                       A quote left OPEN at end of record in a non-Rust file is the
                       net under the rest -- not because those languages lack
                       multi-line strings (TOML triple-quoted and PowerShell
                       here-strings are perfectly legal) but because this model does
                       not carry them, so the state can only be a misread.
                     * git emitted no TEXT diff for it (gitattributes or content
                       heuristic), so no line-oriented class could run at all.
                     * the staged object is not a REGULAR FILE blob (a symlink or a
                       gitlink), so its bytes are not that path's text.
                     * the staged blob's RAW BYTES do not decode strictly as UTF-8,
                       or carry a NUL anywhere. The SAME strict reader answers that
                       for every status, so a metadata-only change -- which renders no
                       binary marker for the diff test to find -- cannot reach a
                       line class over replacement text.
                     * the staged blob terminates lines with a LONE CR and its added
                       lines come from HUNKS: git writes such a record as ONE patch
                       line while the native record pipeline splits it, so the two
                       readings disagree about which line an addition belongs to.
                       The CRLF twin, a terminator both agree on, is still scanned.
                     * the record is a RENAME: the lines it did not change are
                       attributed to no line of this commit, so the destination
                       path's line-oriented classes never read them (lines the
                       rename DID edit are scanned normally, and a staged PLAN.md
                       still gets its whole-file tag closure).
                   A wrong carry is not a local miss: it reclassifies every LATER
                   line of that file, which can hide a real count OR invent one from
                   string text. So the scan says so and stops, per file, rather than
                   reporting a result it cannot stand behind. ADVISORY DELIBERATELY:
                   one such file anywhere in the tree must not become a hard stop,
                   and only the count classes depend on that splitter --
                   MAGIC-COUNT-ASSERT reads its own Rust lexer and is unaffected.
      DEAD-REF     a repo-relative path (first segment a real repo top-level
                   DIRECTORY) that is ABSENT FROM THE TRACKED INDEX -- a typo or
                   a dead/local-only reference a fresh clone cannot resolve (e.g.
                   a deleted or gitignored-only
                   logs/codex/probe-pack-45ff). Machine-local operational targets
                   (~/, drive-absolute, $env:, <placeholder>, globs, URLs) are
                   exempt; dated docs are NOT (a dead path there is still
                   surfaced as advisory). ADVISORY in v1 BY
                   CALIBRATION: the full-tree run surfaced irreducible false
                   positives that no mechanical rule separates from real dead
                   refs -- a gitignored OPERATIONAL target
                   (.orchestrator/dispatch-checklist.md) is indistinguishable
                   from a gitignored EVIDENCE path (probe-pack) by ignore
                   status; plus intentional "this path does not exist"
                   references and doc-relative paths in package docs. Surfaces
                   candidates for author review; the gate stays the failsafe.
                   (Promoting to error-tier needs doc-relative resolution +
                   an evidence-vs-instruction signal -- a future extension.)
      TAG          a milestone tag `M<n>...` referenced in PLAN.md whose
                   top-level milestone `M<n>` has no defining header. Advisory
                   in v1: PLAN's suffix scheme is rich, so only a wholly
                   unknown top-level milestone is surfaced (zero false
                   positives over finer suffixes). Promote to a finer
                   closure check once calibrated against the full tag scheme.
      MAGNITUDE    an exact transient count in narrative prose where a magnitude
                   statement ("many rounds") carries the same information.
                   Implemented subset: round/iteration/attempt/pass/retry/try
                   counts in digit-first ("6 rounds") and unit-first ("round 6")
                   forms, PLUS the UNIT-AGNOSTIC verb form `took N` -- the count
                   after "took" regardless of the trailing noun, so "took 6
                   minutes" / "took 6 files" also match. The digit-first form
                   ADDITIONALLY covers the aggregate/duration nouns
                   (task/commit/file/row/site/entry/follow-up/finding/fixture/
                   assertion/instance/wave/stream/landing + minute/hour/second/day),
                   so a
                   bare duration "6 minutes", an assertion total "47 assertions",
                   and an "18-task chain" all match; "landing" enters PLURAL-ONLY,
                   unlike its neighbours here, because its singular is
                   overwhelmingly a noun MODIFIER in this prose ("Wave 2 landing",
                   "the landing gate") where admitting it would flag a stable NAME
                   plus the following word. Those nouns stay OUT of the
                   unit-first form because their unit-first shape is usually a
                   stable NAME ("Wave 2", "day 3", "row 7"), not a count.
                   ENUMERATED-CASE totals extend this family: a spelled-out "all
                   <N> <enumeration-noun>" / "both <noun>" ("all three cases"),
                   and a `(1) ... (2) ...` inline enumeration paired with an "all
                   N" total, both restate an exact count a magnitude phrasing
                   ("all cases" / "every case") carries. SPELLED cardinals ride the
                   digit-first and "took N" forms ("<spelled-N> rounds", "took
                   <spelled-N>") but
                   NOT the unit-first one, which stays DIGIT-ONLY: several of these
                   nouns double as third-person verbs, where the cardinal quantifies
                   the NEXT noun ("passes <spelled-N> tests" is not a count of
                   passes). The
                   digit-first spelled branch additionally needs WHITESPACE before a
                   PLURAL noun, so a compound-adjective NAME ("two-stream design")
                   and a verb ("all four pass") stay clean. Advisory: some counts are
                   load-bearing; the author judges. EXEMPT (like INVENTORY) for a
                   count inside a DATED entry body of the ROOT History.md log: a
                   dated entry is a static append-only snapshot, so the caller
                   Invoke-FileChecks DROPS both count classes on those lines
                   (root-path + dated-entry-body mask; the preamble, undated
                   sections, and nested History.md stay in class). (2026-07-09.)
      LOCAL-PROOF  (advisory forms; the ERROR tight form is above) a proof word
                   with a BARE local marker gitignored | local-only | untracked,
                   OR the loose "operator-side"/"local" + "evidence". These are
                   ADVISORY by CALIBRATION: the current tree co-locates these
                   markers with proof words in ordinary git prose ("verify ...
                   --untracked-files") and in META-DISCUSSION of the rule itself
                   ("gitignored logs ... cannot prove provenance"), neither of
                   which is the defect -- so the class is surfaced, not blocked
                   (mirrors the DEAD-REF advisory-by-calibration outcome).
      MAGIC-COUNT-ASSERT
                   an exact integer-literal EQUALITY assertion against a
                   collection's CARDINALITY
                   (Get-MagicCountAssertFindings) -- `assert_eq!(x.len(), 4)`,
                   its `.count()` sibling, either argument order, and the
                   `assert!(x.len() == 4)` comparison form, `debug_` variants
                   included. The literal pins a SIZE while naming nothing about
                   WHICH elements are expected, so it goes stale on any membership
                   change and, when it fails, reports only that the size moved --
                   the element that appeared or vanished is exactly what it does
                   not say; the
                   fix is set-equality/membership against the expected elements or
                   a count derived from the input data. STAGED scope, ADDED lines of
                   .rs files. The scanned SURFACE is code alone (a count in a comment
                   belongs to the INVENTORY/MAGNITUDE classes; an assertion quoted
                   inside a STRING literal or a comment is an example, not a claim,
                   and the stateful Rust lexical pass -- Get-RustLexedCodeRecords --
                   removes both), while the added-line TEST is the whole invocation
                   span: any added physical line in it reports, comment reflow
                   included.
                   An ADVISORY HINT, not a sound analyzer: it carries NO exemption
                   for a "provably anchored" count. One was tried and withdrawn --
                   it exempted nothing across the tree while resting on unsound
                   cardinality reasoning -- so the rare genuinely anchored assertion
                   drawing an advisory is the cheaper error.
                   DEFAULT-UNPARSED -- silence requires POSITIVE RECOGNITION, and
                   failure is always loud. A matched site emits UNPARSED unless every
                   part of it is positively classified, so an unhandled Rust form --
                   an unbalanced region, an unclosed generic, unevaluated
                   arithmetic, syntax that does not exist yet -- reports rather than
                   vanishes. A comma-bearing GENERIC is not among them: angles are
                   classified where the characters are lexed (Get-OpenerCloser), by an
                   operand/operator POSITION predicate rather than a list of
                   spellings, so a generic's commas are structurally nested rather
                   than feared.
                   The recognizers, each an explicit predicate:
                     FINDING       a parsed comparison pinning a parsed BARE literal
                                   above one. Judged PER COMPARISON, so a recognized
                                   one cannot mask its sibling.
                     OUT OF CLASS  no cardinality call in the REGION at all, or none
                                   in the COMPARISON text (the failure-message
                                   arguments are discarded first, so nothing in a
                                   message steers the classification); a conjunct
                                   with no cardinality call; a conjunct that IS a
                                   cardinality inequality, which is a BOUND and stays
                                   out of class even carrying a literal; a conjunct
                                   with no depth-0 `==` AND no integer
                                   literal (a literal-free predicate makes no
                                   exact-count claim -- a
                                   literal-BEARING one is UNPARSED, since an equality
                                   can hide at any depth); neither
                                   side a cardinality expression AND no cardinality
                                   call paired with a literal anywhere in the
                                   comparison (that pairing is UNPARSED instead, for
                                   the same reason: the equality may sit at a depth
                                   the sides do not expose -- and a side whose
                                   OUTERMOST operation is arithmetic is NOT a
                                   cardinality expression, so `a + b.len()` lands
                                   here rather than showing a literal pinning a count
                                   it does not pin); both sides
                                   cardinality expressions; a comparand that is a
                                   parsed symbol/path; a comparand carrying NO integer
                                   literal, which therefore cannot be pinning one; a
                                   parsed bare literal of VALUE 0 or 1.
                     UNPARSED      everything else, carrying the COMPLETE region span
                                   and its EndLine -- including an `assert_eq!`
                                   with fewer than two arguments, which has no
                                   comparison to judge and is NOT thereby out of
                                   class (the exit table in Get-MagicCountAssertFindings
                                   names every such path). The EndLine is the region's
                                   true end EXCEPT when the scan CAP fired: there the
                                   true end was never read, so the range runs to EOF
                                   rather than to the truncation point, and an edit
                                   past the cap still surfaces the truncation.
                   PRECEDENCE, one site to one documented outcome per part: every
                   classified comparison emits its FINDING, and if ANY part of the
                   site went unrecognized the site adds exactly one UNPARSED.
                   Argument lists are delimited by a BALANCED scan over every legal
                   macro delimiter and split at depth 0, redundant grouping
                   parens are stripped, and the bracket scan, cardinality search,
                   reported span and EndLine all derive from ONE absolute endpoint,
                   so the region examined and the region reported cannot differ.
                   ADVISORY
                   DELIBERATELY: `-Tree` audits Markdown, so this class's tier
                   cannot be calibrated by the same full-tree run that set the
                   Markdown classes' tiers; promoting it needs a code-surface
                   audit mode this script does not yet have.
      LOCAL-STATE  a machine-local install/wiring state asserted as repo fact
                   (Get-MachineLocalStateFindings): an "installed and wired" /
                   "is wired via" / "wired via" claim on the same line as a
                   MACHINE-LOCAL config path (~/.claude ... or
                   .claude/settings.local.json; either `/` or `\` separator) -- state a fresh clone cannot
                   confirm. EXEMPT when the line already flags it "machine-local" /
                   "local-only" (how the hook docs correctly caveat it), so only
                   UN-caveated assertions surface. Advisory: many legitimate
                   operational instructions name these paths; the author confirms.

  DEFERRED (NOT built in v1 -- documented so a later session knows the
  boundary; building fragile heuristics for these now would add false
  positives, so they are left to the gate):
    - canonical-field presence on touched PLAN milestones (needs a declared
      PLAN field schema),
    - enumeration-vs-source diff (needs machine-readable enumeration
      declarations in the doc),
    - quantitative-claim re-derivation against a named source list.

.PARAMETER Staged
  Default scope. Scan the ADDED lines of the staged diff
  (`git diff --cached --unified=0`) across tracked narrative docs, PLUS the
  ADDED COMMENT lines of staged .rs/.ps1/.toml/.sh source files (the
  inventory-count + magnitude classes), PLUS the ADDED lines of staged .rs
  files (MAGIC-COUNT-ASSERT only -- no count class ever reports a finding from a
  code line; the count classes read code solely to resolve their echo exemption). This
  is the author-side pre-commit use, keyed on what THIS commit ADDS -- though the
  added-line SET is the trigger, not a bound on the reported TEXT: the prose classes
  report the added line itself, while MAGIC-COUNT-ASSERT reports the whole assertion
  SPAN once any physical line in it is added, so an untouched assertion resurfaces
  when a line is added anywhere inside it.
  Milestone-tag closure runs over the full staged PLAN.md content when PLAN.md
  is staged (closure is a whole-file property).

.PARAMETER Paths
  Scan the full current content of the named files instead of the staged diff.
  Narrative docs only -- source-file comment scanning is staged-mode-specific
  (it needs the added-line diff and its nearby-code context).

.PARAMETER Tree
  Scan the full content of every tracked narrative doc. Used for calibration
  and full audits.

.PARAMETER OutPath
  Optional. Also write the report to this path (best-effort sibling-temp + move;
  the report always prints to stdout regardless).

.NOTES
  PowerShell 5.1 compatible. Sibling of scripts/shared/dispatch-checklist.ps1;
  mirrors its UTF-8 (read UTF-8 / write UTF-8-no-BOM) conventions. Unlike its
  MoveFileEx atomic write, the optional -OutPath report uses a best-effort move
  (the report always prints to stdout, so the file copy is a convenience).
#>
[CmdletBinding()]
param(
  [switch]$Staged,
  [string[]]$Paths,
  [switch]$Tree,
  [string]$OutPath,
  # Internal retained-runtime caller only; captured bytes are data, not approval.
  [System.Collections.IDictionary]$PairedInput,
  [System.Collections.IDictionary]$FirstAttachmentInput
)

$ErrorActionPreference = 'Stop'
# Every status that leaves GOVERNED CONTENT in the pending commit. D (deletion) is the
# only one deliberately outside it: a deleted file has no staged content to scan.
#   A add   C copy   M modify   R rename   T type change (e.g. symlink <-> regular)
# C and T were missing, and each went unscanned with no diagnostic. A copied file's
# every line is new to the index, so its content is governed exactly like a plain add.
# A type change REPLACES the object, so what its content is governed as depends on the
# destination MODE: a regular blob is add-like, while a symlink or gitlink destination
# holds no file text at all and reports the object-kind diagnostic instead.
# R's NEW path is the governed one, which is why the listing has to carry the status
# and the modes rather than paths alone.
$script:StagedDiffFilter = '--diff-filter=ACMRT'
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
# STRICT decoder for git's `-z` pathname bytes -- throwOnInvalidBytes, no replacement
# fallback. The lenient encoder maps every invalid byte to U+FFFD, so two pathnames
# differing only in bytes it cannot decode COLLAPSE into one string: the scan then
# reads one file twice and never reads the other, reporting clean on a file it never
# opened. A pathname this tool cannot represent faithfully is a STOP, not a guess.
$script:Utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)

# Pin UTF-8 for native command pipes BEFORE any git read. Windows PowerShell 5.1
# defaults $OutputEncoding to ASCII, so `git ls-files` / `git show` / `git diff`
# output is decoded lossily and UTF-8 Markdown can mojibake before scanning --
# masking or inventing a finding. auto-review.ps1 / auto-merge.ps1 pin the same
# trio so the documented UTF-8 read contract holds for the default staged scope.
# Set BARE (no try/catch swallow) like those siblings: a host that cannot apply
# the pin must FAIL LOUD via $ErrorActionPreference='Stop' -- swallowing the
# failure and continuing would run the scan under a lossy decoder and risk a
# FALSE-CLEAN lint, the one outcome this linter exists to prevent. (Codex BLOCKER
#: swallowed encoding setup defeated the UTF-8 contract.)
if (-not $PSBoundParameters.ContainsKey('PairedInput') -and -not $PSBoundParameters.ContainsKey('FirstAttachmentInput')) {
  $OutputEncoding = $script:Utf8NoBom
  [Console]::InputEncoding = $script:Utf8NoBom
  [Console]::OutputEncoding = $script:Utf8NoBom
}

# Narrative docs this linter governs (full-content scan). Source files legitimately
# contain paths and line references in CODE, so only Markdown is scanned this way.
# `\z`, never `$`, on every PATH-classification anchor in this file: git's
# NUL-delimited listings preserve control characters in index paths, and a
# PowerShell `$` matches BEFORE a final LF -- so an entry staged as
# "docs/blocker-trends.md<LF>" would pass a `$`-anchored generated-report
# allowlist (skipping authored content) and "foo.rs<LF>" would enter source
# selection whose later extension comparison then bypasses the scan. `\z`
# matches only the absolute end, so an LF-tailed path classifies as what it
# is: not that file.
$script:NarrativeDocPattern = '\.md\z'

# Source files whose COMMENT lines carry prose claims (staged mode only): the
# count-drift classes (inventory-assertion SHAPE + MAGNITUDE) run over the extracted
# comment text of added lines, never the code (a numeric literal in code is correct
# where it lives). The comment syntax is resolved per extension (Get-SourceLineParts).
$script:SourceExtPattern = '\.(rs|ps1|toml|sh)\z'

# Repo-relative PATHS of KNOWN machine-generated reports whose body is intended
# FORMAT (file:line cites, counts), not authored prose -- the ONLY files eligible
# for the generated-doc skip. This is the security boundary: an authored doc at
# any other path can never self-exempt by typing a `Generated:` stamp (see
# Test-IsGeneratedContent). The tracked generator output this pattern names is
# analyze-blocker-trends.ps1 -> docs/blocker-trends.md (its default -OutPath);
# dispatch-checklist's default OutPath is gitignored, and author-lint's own reports are
# conventionally written to gitignored logs/. -OutPath is an UNRESTRICTED string,
# so this PATH gate -- not the destination convention -- is what guarantees a
# report written to ANY tracked path is still scanned unless it is this exact
# leaf. Anchored to the exact leaf so a future docs/codex-<other>.md is not
# blanket-exempt. (Codex BLOCKER: a content-only signature was
# spoofable.)
# CASE-SENSITIVE (no `(?i)`; matched with `-cnotmatch`): this is the spoof
# boundary, so a case-variant authored path like `docs/Blocker-Trends.md`
# must NOT match and must NOT be skipped. (Codex BLOCKER: a
# case-insensitive gate let a wrong-cased authored doc self-exempt.)
# Path matches the analyzer's default -OutPath (docs/blocker-trends.md) and the
# install docs' generate-this-file instruction, so a generated trend report is
# skipped rather than scanned as authored prose and flagged on its machine-
# emitted citations. If you configure a different -OutPath, update this pattern.
$script:GeneratedDocPathPattern = '^docs/blocker-trends\.md\z'

# Extensions a bare line-anchor can name -- the TEXT file types cited with a
# `:line` in this repo's docs. Used only inside the LINE-ANCHOR regex. Includes
# text shader/markup formats (wgsl/glsl/xml) that legitimately carry line refs.
# BINARY assets (glb -- the binary glTF container -- png, etc.) are intentionally
# absent: a `:NNN` after a binary name is not a line citation. The list is a
# CALIBRATED subset of text exts actually cited in this repo's docs, not an
# exhaustive enumeration -- other text formats (gltf JSON, html, css) are simply
# not commonly cited here and stay out until they are. (Claude NOTE review-
# 20260613: shader/asset exts; Codex: gltf is text, not binary.)
$script:AnchorExtAlternation = 'rs|ps1|py|toml|ron|sh|md|txt|json|lock|yaml|yml|cfg|ini|bat|cmd|js|ts|cs|wgsl|glsl|xml'

# Spelled cardinals the count classes recognize alongside their digit forms.
# `one` is DELIBERATELY ABSENT and must stay absent: every idiom the calibration
# constraint requires to stay clean is built on it ("one of", "no one", "at least
# one", "in one pass", "one file per pass", "one-at-a-time", "step one"), and a
# singular is the weakest possible drift signal -- the same reasoning that exempts
# the 0/1 literals in MAGIC-COUNT-ASSERT. A bare sentence-initial "One <noun>"
# inventory claim is therefore left to the AI gate; no mechanical rule separates it
# from that idiom set. Compound cardinals ("twenty-three") stay out too: the
# `(?<![\w.-])` guard every consumer applies rejects a hyphen-preceded token.
# CONTRACT: the tokens are ASCENDING and start at two, so a token's position is its
# numeric value. Get-SpelledCardinalMap derives the spelled->numeral map from that
# ordering rather than restating it. Inserts or reorders change the numeric
# meaning of every following token, so the ascending order is authoritative.
$script:SpelledCardinalAlternation = 'two|three|four|five|six|seven|eight|nine|ten|eleven|twelve'

# The PROCESS-EVENT nouns (a repeated attempt at the same work). These are the only
# nouns whose UNIT-FIRST shape ("round N") is a count rather than a stable NAME.
$script:ProcessEventNounAlternation = 'rounds?|iterations?|attempts?|pass(?:es)?|retr(?:y|ies)|tr(?:y|ies)'

# The full count-noun set: process events PLUS the aggregate/duration nouns whose
# DIGIT-FIRST shape is a count ("N rows", "N minutes"). `landings` is a first-class
# process-event noun in this project's prose (a landing is a merge to master, the
# same class as a round or a wave), so a counted landing is the same drift bait as a
# counted round -- but it enters PLURAL-ONLY, unlike its neighbours here: the
# singular is overwhelmingly a noun MODIFIER in this prose ("Wave 2 landing", "the
# landing gate"), where admitting it flags a stable NAME plus the following word.
$script:CountNounAlternation = "$script:ProcessEventNounAlternation|tasks?|commits?|files?|rows?|sites?|entr(?:y|ies)|follow-ups?|findings?|fixtures?|assertions?|instances?|waves?|streams?|landings|minutes?|hours?|seconds?|days?"

# The PLURAL forms of that same noun family, for the shapes whose cardinal is
# ALWAYS >= two (the spelled branch of the digit-first form, and the determiner
# shape). A spelled cardinal followed by a SINGULAR count noun is not an
# enumeration: it is a verb ("only after all four pass") or a compound modifier
# ("the four lettered commit-tracked steps"). The digit-first branch keeps the
# optional singulars, because a count of one is still a count the existing contract
# flags. These lists describe ONE noun family.
$script:CountNounPluralAlternation = 'rounds|iterations|attempts|passes|retries|tries|tasks|commits|files|rows|sites|entries|follow-ups|findings|fixtures|assertions|instances|waves|streams|landings|minutes|hours|seconds|days'

# English FUNCTION words, shared so the gates that need them cannot drift apart:
# the determiner shape's modifier slot bars them, because a function word must not
# bridge a cardinal to a distant noun ("One of the passes" would otherwise reach
# `passes`).
$script:FunctionWordAlternation = 'of|the|a|an|per|or|and|to|for|in|on|at|by|with|from|is|was|are|were|that|which|but|not'

# A Rust INTEGER literal: decimal with `_` digit separators, the lowercase radix
# prefixes, and an optional integer type suffix. Consumers compare literal
# VALUES through ConvertFrom-RustIntLiteral, never spellings, so `4`, `0x4`, `0b100`
# and `4usize` are one cardinality. Float literals are deliberately outside the
# grammar: a cardinality is never a float, and admitting one would let `4.0` read as
# the integer 4.
# The shell parameter-expansion productions, as ONE anchored alternation.
# Written with `\uXXXX` escapes for the quote/backtick/backslash class members: the
# pattern is stored in a SINGLE-quoted string, where an apostrophe would have to be
# doubled, and one escape vocabulary for the whole class beats a per-character rule.
$script:ShellParamExpansionPattern = [regex]('^(?:#(?<lenparam>(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-]))|(?<name>(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-]))(?<sub>(?:\[(?:@|\*|[0-9]+|[A-Za-z_][A-Za-z0-9_]*)\]))?(?::?(?<wordop>[-=?+])(?<word>[^\u0024\u0060\u0027\u0022\u005C{}<>]*)|#{1,2}(?<pre>[^\u0024\u0060\u0027\u0022\u005C{}<>]*)|%{1,2}(?<suf>[^\u0024\u0060\u0027\u0022\u005C{}<>]*)|/[/#%]?(?<pat>[^\u0024\u0060\u0027\u0022\u005C{}<>]*)(?:/(?<rep>[^\u0024\u0060\u0027\u0022\u005C{}<>]*))?|:(?<off>[+-]?[0-9]+)(?::(?<len>[+-]?[0-9]+))?)?)$')

$script:RustIntLiteralPattern = '(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*)(?:[iu](?:8|16|32|64|128|size))?'

# Comparative QUALIFIERS that turn a following cardinal into a BOUND rather than an
# exact count. "at least three rounds" already carries the magnitude the count
# classes ask for, so flagging it would tell an author to rewrite prose that is
# already correct. Applied to the digit and spelled branches alike: the digit form
# ("at least 3 rounds") shares the defect, and one alternation keeps them from
# drifting apart. Kept to the comparative bounds; approximators ("roughly",
# "about") are a separate judgement and stay in class.
# Each gap is `\s+`, not a literal space, because prose indents and double-spaces
# WITHIN a line. It does not reach across records: the detectors scan one line at a
# time, so a bound a hard wrap separated from its cardinal is out of reach and the
# count still advises -- which is exactly what the start-of-text tier demotion in the
# INVENTORY class exists to soften.
$script:CountQualifierAlternation = 'at\s+least|at\s+most|more\s+than|less\s+than|fewer\s+than|no\s+more\s+than|no\s+fewer\s+than|up\s+to'

# THE OPENER INVENTORY, declared ONCE. Each grammar below answers "what may stand
# between the author's words and the cardinal", and they were maintained as separate
# literals -- so each acquired the openers the other lacked and a bounded claim's TIER
# came out different depending on which side of the cardinal the markup fell. A shared
# inventory each grammar derives from is what keeps them from drifting again.
# The openers each lacked -- the quote family, `!`, and the link, image, checkbox and
# parenthesis marks -- produced false ERROR findings on correctly-bounded prose, and a
# false ERROR aborts the commit of whatever session is running the gate.
#
# SINGLE-quoted so the backtick reaches the regex: inside a double-quoted PowerShell
# string a lone backtick is the escape character and is swallowed, which silently
# dropped inline code from the class. Smart quotes are written as `\uXXXX` regex
# escapes rather than literal characters so the pattern is independent of how
# PowerShell decodes this (BOM-less) file; the STRAIGHT apostrophe is written the
# same way so this string needs no doubled-quote escape, a construct the source
# support checker cannot model and would refuse the whole file over.
#
# What earns a place here: a mark that can stand between an author's comparative
# bound and the cardinal it bounds, or open a line ahead of one. `!` and `[` are the
# image/link openers (`at least ![three rounds](url)`), `(` and the quote family the
# ordinary bracketing of a phrase (`at least "3 rounds"`, `at least '3 rounds'`).
# Only OPENERS: a closing `]` or `)` can FOLLOW a cardinal but can never separate it
# from its qualifier, so admitting one would widen the lookbehind for nothing.
$script:MarkupOpenerClassBody = '\*_`~\[\(!"\u0027\u2018\u2019\u201C\u201D'

# Whitespace plus those openers: the run that may sit between a qualifier and the
# cardinal it bounds.
$script:MarkupGapClass = "[\s$script:MarkupOpenerClassBody]"

# The run a line may carry BEFORE its first word: indentation, the Markdown marks that
# open a line (blockquote, bullet or numbered list, heading, emphasis, inline code,
# table cell), the same opener inventory, and the task-checkbox marker. The checkbox
# needs its own alternative because its body is a LETTER (`[x]`) and no letter may
# enter the character class -- a word before the match means the line carries its own
# context, so no hard wrap put a comparative bound out of the detectors' reach.
#
# An APPROXIMATION of "markup", deliberately, and safe to leave one: it decides a
# TIER, never whether a finding exists, so a miscall costs a tier and never a miss.
# The `-` is ESCAPED because the interpolated opener body follows it, and an
# unescaped `-` between two class members is a RANGE.
$script:LineLeadMarkupPattern = "(?:\[[ xX]\]|[\s>#+|\-$script:MarkupOpenerClassBody]|\d+[.)])*"

# ---------------------------------------------------------------------------
# Pure helpers (no I/O).
# ---------------------------------------------------------------------------

function Get-ContainedRelPath {
  # Canonicalize a caller-supplied path and enforce that it is INSIDE the repo
  # root, returning the repo-relative path (forward-slash) iff contained, else
  # $null. The caller turns $null into a stable ERROR + nonzero exit.
  # PURE (string and path math only; no filesystem probe).
  #
  # Containment BEFORE repo-relative derivation is the whole point (BLOCKER
  #): the old `-Paths` code sliced `.Substring($repoRoot.Length)`
  # off a rooted path with NO containment check (an outside abs path became an
  # unrelated in-repo SUFFIX) and joined a relative `..\outside.md` directly under
  # the root (escaping the repo while using repo-index resolution) -- either way a
  # mispointed invocation could exit CLEAN against the WRONG file.
  #   - ROOTED requested path -> GetFullPath as-is.
  #   - RELATIVE requested path -> resolved against the REPO ROOT (preserving the
  #     repo-relative -Paths semantics), then GetFullPath (collapses `..`).
  # Inside iff the canonical path IS the root or starts with `<root><sep>`.
  # Comparison is ORDINAL (case-SENSITIVE) -- git's index is case-sensitive, so a
  # path differing from the root only by case (e.g. `C:\repo\PROJ\...` vs
  # `C:\repo\proj`) is a DIFFERENT location on a case-sensitive checkout and MUST be
  # rejected (BLOCKER: OrdinalIgnoreCase here accepted the case-only
  # outside path, then sliced it against $repoRoot -> a false-clean WRONG-file scan).
  # On a case-insensitive FS the only cost is an over-reject of a case-variant in-repo
  # path, which fails LOUD (exit 2) -- never a silent wrong-file scan.
  param([string]$RequestedPath, [string]$RepoRootFull)
  if ([string]::IsNullOrWhiteSpace($RequestedPath) -or [string]::IsNullOrWhiteSpace($RepoRootFull)) { return $null }
  # Drive-relative Windows paths (`C:foo.md` -- a drive letter + colon NOT followed by a
  # separator) are "rooted" per IsPathRooted() yet GetFullPath() resolves them from the
  # process cwd on that drive, NOT from the repo root -- so a mispointed `-Paths
  # C:docs/foo.md` could pass containment against the WRONG in-repo file. Reject them; a
  # fully qualified `C:\...` (separator after the colon) is unaffected. (Codex BLOCKER.)
  if ($RequestedPath -match '^[A-Za-z]:[^\\/]') { return $null }
  $rootFull = [System.IO.Path]::GetFullPath($RepoRootFull)
  $rootPrefix = $rootFull.TrimEnd('\','/') + [System.IO.Path]::DirectorySeparatorChar
  $candidateFull = $null
  try {
    if ([System.IO.Path]::IsPathRooted($RequestedPath)) {
      $candidateFull = [System.IO.Path]::GetFullPath($RequestedPath)
    } else {
      $candidateFull = [System.IO.Path]::GetFullPath((Join-Path $rootFull $RequestedPath))
    }
  } catch { return $null }
  $isInside = $candidateFull.Equals($rootFull, [System.StringComparison]::Ordinal) -or
              $candidateFull.StartsWith($rootPrefix, [System.StringComparison]::Ordinal)
  if (-not $isInside) { return $null }
  return $candidateFull.Substring($rootFull.Length).TrimStart('\','/') -replace '\\','/'
}

function Test-HasFrozenSnapshotMarker {
  # A doc is a FROZEN snapshot (its line-anchors downgrade to advisory) IFF it
  # carries the EXPLICIT in-file marker -- an HTML comment on its own line, near the
  # top:
  #     <!-- frozen-snapshot -->
  # Detection: a line matches the regex
  #     ^\s*<!--\s*frozen-snapshot\s*-->\s*$
  # (case-insensitive on the token) within the doc's FIRST $HeadLines lines (~30).
  # FILENAME AND DATE NO LONGER MATTER -- the doc declares its own frozen status.
  #
  # Why a positive marker, not the old filename guess: the prior
  # Test-IsDatedSnapshotDoc inferred "frozen" from a dated filename + a category
  # token (audit/handoff/...). That was a WEAK proxy in two directions -- a doc can
  # be dated-in-name yet still actively maintained (m19-networking-audit's §6 was
  # live authority), and a fresh install with an empty live-doc denylist exempted
  # ALL dated docs by default. An explicit marker the AUTHOR places is unambiguous:
  # absent -> error-tier (the symbol-anchor rule applies), present -> advisory (the
  # author has declared this a frozen historical record). The marker is an HTML
  # comment so it is INVISIBLE in rendered Markdown. (User-directed design.)
  #
  # The marker must be a REAL HTML comment in NORMAL Markdown context -- invisible in
  # rendered Markdown. A marker token sitting INSIDE a ``` / ~~~ fenced code block, or
  # on a CommonMark indented-code line (>=4 leading spaces, or 0-3 spaces then a tab), RENDERS
  # as visible code, NOT an invisible comment, so it must NOT grant the exemption:
  # accepting it would let a top-of-file fenced/indented code SAMPLE of the marker
  # falsely demote a doc's LINE-ANCHOR findings to advisory (a false-clean). So the
  # head window is fence-tracked (the SAME Get-FencedLineFlags the anchor/dead-ref
  # checks use), and an indented-code marker line is rejected -- the accept-set is
  # exactly the documented marker shape. (Codex CROSS-CRATE-CONTRACT.)
  #
  # PURE: -Content is authoritative. -Path remains accepted but does not
  # participate in the decision.
  param(
    [string]$Path,
    [string]$Content,
    [int]$HeadLines = 30
  )
  if ([string]::IsNullOrEmpty($Content)) { return $false }
  $head = @($Content -split "`n" | Select-Object -First $HeadLines | ForEach-Object { $_ -replace "`r$", '' })
  $fenced = Get-FencedLineFlags -Lines $head
  for ($i = 0; $i -lt $head.Count; $i++) {
    if ($fenced[$i]) { continue }                                  # inside a code fence -> visible code, not a comment
    if ($head[$i] -match '^(?: {4,}| {0,3}\t)') { continue }       # CommonMark indented code (4+ spaces, OR 0-3 spaces then a tab that expands to col 4) -> visible code, not a comment
    if ($head[$i] -match '^\s*<!--\s*frozen-snapshot\s*-->\s*$') { return $true }
  }
  return $false
}

function Test-IsGeneratedContent {
  # A generated report has a machine-emitted body where file:line and counts are
  # intended FORMAT, not hand-authored prose -- so it is skipped. Two INDEPENDENT
  # gates must BOTH pass, the PATH gate first:
  #   1. PATH (the security boundary): the repo-relative path must match a KNOWN
  #      generated-report location ($script:GeneratedDocPathPattern). An authored
  #      doc at any other path can NEVER self-exempt, no matter what text it
  #      carries -- an author cannot relocate PLAN.md/AGENTS.md/docs/foo.md to the
  #      trends path. This is what closes the spoof.
  #   2. CONTENT (a secondary sanity check): a `Generated:` head line TOGETHER with
  #      a specific generator signature, so a hand-edited / half-written file even
  #      AT the generated path is still scanned rather than skipped.
  # (Codex BLOCKER: the earlier content-only signature was
  # spoofable -- any staged Markdown placing `Generated: ... by author-lint.ps1`
  # in its first 12 lines skipped LINE-ANCHOR/DEAD-REF/MAGNITUDE/TAG validation.)
  param([string]$Path, [string]$Content)
  if ([string]::IsNullOrEmpty($Path)) { return $false }
  $rel = ([string]$Path -replace '\\', '/')
  $rel = $rel -replace '^\./', ''
  if ($rel -cnotmatch $script:GeneratedDocPathPattern) { return $false }
  if ([string]::IsNullOrEmpty($Content)) { return $false }
  $head = ($Content -split "`n" | Select-Object -First 12) -join "`n"
  if ($head -notmatch '(?im)^\s*Generated:\s') { return $false }
  return ($head -match '(?im)\bby author-lint\.ps1\b' -or
          $head -match '(?im)^\s*Source:\s.*\bverdict' -or
          $head -match '(?im)^#\s*Cross-review\s+BLOCKER\s+Trends')
}

function Build-PathSetFromFileList {
  # Given a list of repo file paths (e.g. `git ls-files` -- the INDEX), return a
  # hashtable of every file path PLUS all its ancestor directory prefixes, all
  # normalized to `/`. The DEAD-REF staged resolver keys on this so both a file
  # token (`scripts/codex/x.ps1`) and a directory token (`scripts/codex`)
  # resolve against the pending commit.
  param([string[]]$Files)
  # ORDINAL (case-sensitive) comparer -- see Get-TopLevelDirSet: git paths are
  # case-sensitive, so a default case-insensitive `@{}` would resolve a
  # wrong-cased reference against a tracked path and miss a real DEAD-REF.
  # (Codex QUALITY.)
  $set = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
  if (-not $Files) { return $set }
  foreach ($raw in $Files) {
    $f = ([string]$raw -replace '\\', '/').Trim()
    if ([string]::IsNullOrWhiteSpace($f)) { continue }
    $set[$f] = $true
    $parts = $f -split '/'
    $acc = ''
    for ($k = 0; $k -lt $parts.Count - 1; $k++) {
      $acc = if ($acc) { "$acc/$($parts[$k])" } else { $parts[$k] }
      if ($acc) { $set[$acc] = $true }
    }
  }
  return $set
}

function Get-TopLevelDirSet {
  # The set of repo top-level DIRECTORY names for the DEAD-REF first-segment
  # gate -- built DETERMINISTICALLY from the index + .gitignore, NOT a worktree
  # listing. A clean clone or review snapshot lacks gitignored roots like
  # `logs/` on disk, so keying the gate on local presence would let the
  # canonical dead/local-only evidence path (`logs/codex/probe-pack-45ff`) pass as
  # prose depending on environment. Tracked dirs come from the index; gitignored
  # evidence/build roots come from .gitignore. Pure (no I/O). (Codex BLOCKER.)
  param([string[]]$IndexFiles, [string]$GitignoreText)
  # CASE-INSENSITIVE on purpose (default `@{}`), in deliberate ASYMMETRY with the
  # ORDINAL index resolver (Build-PathSetFromFileList). This set is only the
  # first-segment INTENT gate in Get-DeadRefFindings: "does this token even look
  # like a repo-relative path?". A wrong-cased top-level segment (`Scripts/...`)
  # must still pass the intent gate so the token PROCEEDS to the ordinal resolver,
  # which then fails to resolve `Scripts/...` against tracked `scripts/...` and
  # flags the DEAD-REF. If THIS set were ordinal, `Scripts` would miss the gate and
  # be dropped as prose -- silently skipping the exact wrong-case class the ordinal
  # resolver exists to catch. (Codex BLOCKER: ordinal-here defeated
  # the case-sensitivity fix.)
  $set = @{}
  if ($IndexFiles) {
    foreach ($f in $IndexFiles) {
      $n = ([string]$f -replace '\\', '/').Trim()
      if ($n -match '^([^/]+)/') { $set[$Matches[1]] = $true }   # first seg of a tracked path
    }
  }
  if ($GitignoreText) {
    foreach ($line in ($GitignoreText -split "`n")) {
      $l = ($line -replace '\\', '/').Trim()
      if (-not $l -or $l.StartsWith('#') -or $l.StartsWith('!')) { continue }
      $l = $l.TrimStart('/')
      if ($l -match '^([^/*?]+)/') { $set[$Matches[1]] = $true }   # dir pattern with a slash (logs/, target/build)
      elseif ($l -match '^([^/*?]+)$' -and $l -notmatch '\.[A-Za-z0-9]+$') { $set[$l] = $true }   # bare root dir, e.g. /target
    }
  }
  return $set
}

function Get-FencedLineFlags {
  # Return a bool[] parallel to $Lines: $true where the line sits INSIDE a
  # ``` or ~~~ fenced code block (the fence delimiter lines themselves count as
  # inside, so an anchor written on the fence line is also skipped). Illustrative
  # citations inside fences are examples, not live references. Both CommonMark
  # fence chars are honored so an anchor inside a ~~~ block is not an error-tier
  # false positive. (Claude NOTE.)
  # The opener CHARACTER and LENGTH are tracked so a block closes only on the SAME
  # fence char with a run AT LEAST as long (CommonMark: a closing fence must match
  # the opener char and be >= its length). So a `~~~` inside a ``` block (different
  # char) and a ``` inside a ```` block (shorter run) are both CONTENT, not a close
  # -- otherwise they would prematurely end the fence and surface later in-block
  # anchors as live findings. (Codex QUALITY: mixed delimiters; then
  # shorter same-char fence.)
  param([string[]]$Lines)
  $flags = New-Object 'bool[]' $Lines.Count
  $inFence = $false
  $fenceChar = ''
  $fenceLen = 0
  for ($i = 0; $i -lt $Lines.Count; $i++) {
    # Capture the fence run AND any trailing content. An OPENING fence may carry an
    # info string (```rust); a CLOSING fence may NOT -- only trailing whitespace
    # (CommonMark). So `~~~text` / ```rust seen INSIDE a block is content, not a
    # close. (Codex QUALITY: trailing-content close.)
    # At most 3 leading SPACES (CommonMark): 4+ spaces or a leading tab is an
    # indented code block, NOT a fence delimiter -- accepting arbitrary `\s*` would
    # let `    ~~~` open a synthetic fence and suppress live error-tier findings.
    # (Codex BLOCKER.)
    $mm = [regex]::Match($Lines[$i], '^ {0,3}(```+|~~~+)(.*)$')
    if ($mm.Success) {
      $run = $mm.Groups[1].Value
      $delim = $run.Substring(0, 1)                   # '`' or '~'
      $runLen = $run.Length
      $bare = ($mm.Groups[2].Value -match '^\s*$')    # only whitespace after the run
      if (-not $inFence) {
        $inFence = $true; $fenceChar = $delim; $fenceLen = $runLen   # open (info string allowed)
        $flags[$i] = $true
      } elseif ($delim -eq $fenceChar -and $runLen -ge $fenceLen -and $bare) {
        $inFence = $false; $fenceChar = ''; $fenceLen = 0            # valid close: same char, >= len, no trailing content
        $flags[$i] = $true
      } else {
        $flags[$i] = $true                            # different char / shorter run / trailing-content -> content
      }
    } else {
      $flags[$i] = $inFence
    }
  }
  return ,$flags
}

function Get-LineAnchorFindings {
  # $Records: array of @{ Line = <int>; Text = <string> }. ERROR-tier by default.
  # A doc carrying the EXPLICIT frozen-snapshot marker ($IsFrozenSnapshot, from
  # Test-HasFrozenSnapshotMarker) DOWNGRADES to advisory -- the symbol-anchor rule
  # leaves frozen snapshot line numbers as-is, so a hard ERROR would reject
  # convention-exempt content; advisory (not skip) keeps it surfaced, never
  # silently suppressed. A doc WITHOUT the marker stays ERROR regardless of its
  # filename or date. (Marker model -- user-directed design; supersedes the
  # filename+date+category inference of the prior Test-IsDatedSnapshotDoc.)
  param(
    [object[]]$Records,
    [bool]$IsFrozenSnapshot
  )
  $out = @()
  if (-not $Records) { return $out }
  $tier = if ($IsFrozenSnapshot) { 'ADVISORY' } else { 'ERROR' }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  # Accept BOTH `/` and `\` separators -- this Windows-first repo writes
  # `scripts\codex\foo.ps1:NNN` in tracked docs. (Codex BLOCKER.)
  $rx = [regex]("[A-Za-z0-9_./\\-]+\.(?:$script:AnchorExtAlternation):\d+")
  for ($i = 0; $i -lt $Records.Count; $i++) {
    if ($fenced[$i]) { continue }
    $text = [string]$Records[$i].Text
    foreach ($m in $rx.Matches($text)) {
      # Skip ONLY a URL-EMBEDDED token, never a path citation. `file.ext:NNN` is a
      # line-anchor violation whether the path is bare (`foo.rs:5`), repo-relative
      # (`scripts/x.ps1:42`), or absolute (`/scripts/x.ps1:42`, `C:\...:5`) -- all
      # are line citations the symbol-anchor rule discourages, so all stay
      # error-tier. The exemption is exactly a token that sits INSIDE a URL --
      # identified by a `scheme://` immediately before the match with no intervening
      # whitespace -- where the `:digits` is part of the URL (a port OR a path-
      # position number, e.g. `:8080` in `https://host/app.js:8080`), never a source
      # line. An earlier broad leading-`/`/`:` guard wrongly skipped real repo-root
      # and label-prefixed anchors. (Codex BLOCKER: /scripts/...:NNN
      # must flag; the URL-embedded exemption is the correct narrow one.)
      if (($text.Substring(0, $m.Index) + $m.Value) -match '[A-Za-z][A-Za-z0-9+.\-]*://\S*$') { continue }
      $out += @{
        Class = 'LINE-ANCHOR'
        Tier  = $tier
        Line  = [int]$Records[$i].Line
        Match = $m.Value
        Hint  = 'cite the grep-able symbol, not the drifting line number'
      }
    }
  }
  return $out
}

function Get-DeadRefFindings {
  # Flag a repo-relative path token whose first segment is a real repo top-level
  # DIRECTORY (per $IsTopLevel) and that does NOT resolve (per $Resolver). Keying
  # on "first segment is a known top-level DIRECTORY AND unresolved" makes the
  # check precise: prose slash-phrases ("client/server", "read/write") and
  # root-FILE slash-lists ("PLAN.md/CLAUDE.md/auth") are not flagged because
  # their first segment is not a top-level directory, and machine-local targets
  # (~/, drive-abs, $env:, <ph>, globs, URLs) are filtered first. Whole class is
  # ADVISORY tier (see header rationale). NOT exempt on dated docs: a dead path
  # there is still surfaced (advisory), since suppressing the class would leave a
  # newly added local-only evidence path false-clean. (Codex BLOCKER.)
  #   $Resolver:   scriptblock { param($relPath) -> [bool] exists in the index/tree }
  #   $IsTopLevel: scriptblock { param($segment) -> [bool] is a repo top-level DIRECTORY }
  param(
    [object[]]$Records,
    [scriptblock]$Resolver,
    [scriptblock]$IsTopLevel
  )
  $out = @()
  if (-not $Records) { return $out }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  # A candidate path token: a run of path-ish chars containing at least one
  # separator (`/` OR `\` -- this Windows-first repo writes both). Punctuation
  # that commonly trails a path in prose (.,;:)`'"]) is trimmed after capture.
  # The START class excludes `_` (kept mid-token for names like check_registry.py)
  # so Markdown UNDERSCORE emphasis -- `_docs/x.md_` / `__docs/x.md__` -- does not
  # tokenize the wrapper into the first segment (`_docs`) and silently drop a real
  # dead path; the match then starts at `docs` and is flagged. (Codex SILENT-FAILURE
  #: `\`-separated refs were invisible; underscore-wrapped dropped.)
  $rx = [regex]('[A-Za-z0-9.$~<][A-Za-z0-9_./\\-]*[/\\][A-Za-z0-9_./\\-]+')
  for ($i = 0; $i -lt $Records.Count; $i++) {
    if ($fenced[$i]) { continue }
    $lineText = [string]$Records[$i].Text
    foreach ($m in $rx.Matches($lineText)) {
      # Suffix of a larger absolute / drive / URL path: the regex cannot capture
      # a `:` (drive), a leading `/`, or a URL scheme, so those leave the repo-
      # looking tail starting right after a separator. If the char before the
      # match is a separator or colon, the token is not a standalone repo path.
      # (Codex QUALITY.)
      # Walk back over any leading `_` emphasis chars to the first NON-underscore
      # char before the match. The token start-class excludes `_`, so an absolute /
      # drive / URL path whose segment begins with `_` (`/_docs/x`, `C:\_docs\x`,
      # `https://h/_docs/x`) starts the match AFTER the `_`, leaving `_` as the
      # immediate prev char -- the effective prev char (past the `_` run) is the real
      # separator/colon to test. (Codex QUALITY: separator+underscore
      # bypassed the absolute guard.)
      $j = $m.Index - 1
      while ($j -ge 0 -and $lineText[$j] -eq '_') { $j-- }
      $effPrev = if ($j -ge 0) { $lineText[$j] } else { '' }
      if ($effPrev -eq '/' -or $effPrev -eq '\' -or $effPrev -eq ':') { continue }
      $tok = $m.Value -replace '[.,;:`''")\]\}>]+$', ''
      # Strip a leading angle wrapper BEFORE the dot-relative strip (order matters):
      # `<./logs/...>` must become `logs/...`, so the `<` is removed first, then the
      # `./`. The trailing `>` is already trimmed above. The firstSeg-is-top-level
      # gate then separates a REAL bracketed repo path (`<logs/codex/probe-pack>` ->
      # firstSeg `logs` -> flagged) from a generic `<path/to/file>` placeholder
      # (firstSeg `path` -> prose). A blanket `^<` exemption wrongly suppressed real
      # bracketed dead refs. (Codex BLOCKER; ordering fix same round.)
      $tok = $tok -replace '^<+', ''         # strip leading angle wrapper(s) FIRST
      $tok = $tok -replace '^\.[\\/]+', ''   # then strip a leading ./ or .\ (dot-relative)
      # Markdown UNDERSCORE emphasis close: strip the trailing `_`/`__` ONLY for a
      # genuine balanced wrap -- there was a leading `_` run AND its predecessor is
      # start-of-line or a NON-WORD char (Markdown emphasis needs a left flank). A
      # word-char predecessor (`prefix_docs/...`) is an intra-identifier underscore,
      # not emphasis, so its trailing `_` is left alone (and the `/\:` absolute guard
      # above is separate). This lets `_scripts/x.ps1_` resolve while leaving a real
      # filename underscore intact. (Codex QUALITY.)
      $hadLeadUnderscore = ($j -lt ($m.Index - 1))
      $emphasisLeftFlank = ($j -lt 0 -or $effPrev -notmatch '[A-Za-z0-9]')
      if ($hadLeadUnderscore -and $emphasisLeftFlank) { $tok = $tok -replace '_+$', '' }
      if ([string]::IsNullOrWhiteSpace($tok)) { continue }
      # Glob base vs Markdown punctuation: a wildcard immediately follows the
      # captured token (the wildcard is not in the path char class, so it falls
      # just past the match -- e.g. `logs/codex/reviews/*.md` captures
      # `logs/codex/reviews`). EXEMPT a real glob: a SINGLE `*` (`dir/*`, `*.md`,
      # `prefix-*`) or a `?` that opens a glob single-char (`name?.txt`). Do NOT
      # exempt doubled `**` (Markdown bold close, e.g. `**docs/x.md**`) or a bare
      # trailing `?` (rhetorical punctuation, e.g. `docs/x.md?`) -- those wrap a
      # REAL path that must still be dead-ref checked. (Codex SILENT-FAILURE review-
      # 20260613: the prior `[/\\]?[\*\?]` swallowed Markdown emphasis/punctuation.)
      $endIdx = $m.Index + $m.Length
      $afterCtx = ''
      if ($endIdx -lt $lineText.Length) { $afterCtx = $lineText.Substring($endIdx, [Math]::Min(3, $lineText.Length - $endIdx)) }
      # Glob vs Markdown. The token regex's final `[mid]+` INCLUDES separators and is
      # greedy, so it ALWAYS consumes the separator preceding a wildcard: a globstar
      # `docs/art/**` captures `docs/art/` (trailing sep) + afterCtx `**`, while a
      # Markdown bold close `**docs/x.md**` captures `docs/x.md` (no sep) + afterCtx
      # `**`. afterCtx therefore always BEGINS with the wildcard, never `/<wildcard>`
      # (so no `[/\\]?` alternative is needed), and the captured token's trailing
      # separator is the signal that a following `**` is a real globstar segment, not
      # emphasis. (Codex/Claude: distinguish recursive ** globs from
      # Markdown bold/italic/punctuation; dropped the unreachable `/<wildcard>` arm.)
      $rawEndsSep = ($m.Value -match '[/\\]$')
      $prevChar = if ($m.Index -gt 0) { $lineText[$m.Index - 1] } else { '' }
      if ($afterCtx -match '^\*\*') { if ($rawEndsSep) { continue } }   # `dir/` + `**` globstar (sep eaten); bare ** is Markdown -> flag
      elseif ($afterCtx -match '^\*') {                                # single `*`
        # Markdown ITALIC close (`*path*`) when the match opens with a leading `*`;
        # otherwise a glob (`dir/*`, `*.md`, `prefix-*`). (Codex SILENT-FAILURE
        #: single-* emphasis around a dead path must still flag.)
        if ($prevChar -ne '*') { continue }
      }
      elseif ($afterCtx -match '^\?[\w.]') { continue }                # ?-glob single char (name?.txt), not a bare trailing ?
      # Machine-local / non-repo-relative starts the token char-class CAN produce
      # (the start class `[...$~<]` admits ~ / $ / <). Drive-absolute (`C:/`),
      # posix/UNC-absolute (`/`, `\`), URL (`scheme://`), and inline globs (`*`/`?`)
      # need NO guard here: the token regex char-class excludes `:`, a leading
      # `/`/`\`, and `*`/`?`, so such forms are already handled upstream -- the
      # prev-char `:`/`/`/`\` guard (above) drops absolute/drive/URL tails, and the
      # afterCtx wildcard check (above) drops glob bases. Guards for those were dead
      # branches over structurally-impossible tokens (DR5/DR6/DR14 pass via the
      # upstream guards) and were removed. (Claude QUALITY.)
      if ($tok -match '^~') { continue }                 # home-relative
      if ($tok -match '^\$') { continue }                 # $env:/$var
      # (A leading `<` is STRIPPED above, not exempted here, so a real `<repo/path>`
      # reaches the firstSeg/resolver check; a `<placeholder/...>` falls out via the
      # firstSeg-not-a-repo-dir gate.)
      # Normalize separators for the repo lookups; report the original token.
      $normTok = $tok -replace '\\', '/'
      $firstSeg = ($normTok -split '/')[0]
      if (-not (& $IsTopLevel $firstSeg)) { continue }    # not a repo dir -> prose
      if (& $Resolver $normTok) { continue }              # resolves -> fine
      $out += @{
        Class = 'DEAD-REF'
        Tier  = 'ADVISORY'
        Line  = [int]$Records[$i].Line
        Match = $tok
        Hint  = 'repo-relative path absent from the tracked index (typo or dead/local-only reference a fresh clone cannot resolve)'
      }
    }
  }
  return $out
}

function Get-DefinedMilestoneTags {
  # Milestone-defining headers look like `### M1: ...` / `#### M19.X3a: ...` /
  # `#### M1 Acceptance Criteria`. Return the set of top-level milestone tokens
  # (M<n>) that have at least one defining header.
  param([string]$PlanContent)
  $defined = @{}
  foreach ($line in ($PlanContent -split "`n")) {
    if ($line -match '^#{2,4}\s+(M\d+)(?:[.:\s]|$)') {
      $defined[$Matches[1]] = $true
    }
  }
  return $defined
}

function Get-MilestoneTagFindings {
  # ADVISORY. Flag a referenced milestone tag whose TOP-LEVEL milestone has no
  # defining header anywhere in PLAN.md (a wholly-unknown milestone -- usually
  # a renamed/deleted tag). Conservative by design: finer suffix closure is a
  # documented future extension.
  param([string]$PlanContent)
  $out = @()
  if ([string]::IsNullOrEmpty($PlanContent)) { return $out }
  $defined = Get-DefinedMilestoneTags -PlanContent $PlanContent
  $lines = $PlanContent -split "`n"
  $fenced = Get-FencedLineFlags -Lines $lines
  $rx = [regex]('\bM\d+(?:\.[A-Za-z0-9]+)*\b')
  $seen = @{}
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($fenced[$i]) { continue }
    foreach ($m in $rx.Matches($lines[$i])) {
      $tag = $m.Value
      $top = ([regex]::Match($tag, '^M\d+')).Value
      if ($defined.ContainsKey($top)) { continue }
      $key = "$top"
      if ($seen.ContainsKey($key)) { continue }   # report each unknown milestone once
      $seen[$key] = $true
      $out += @{
        Class = 'TAG'
        Tier  = 'ADVISORY'
        Line  = ($i + 1)
        Match = $tag
        Hint  = "milestone $top has no defining header in PLAN.md (renamed/deleted?)"
      }
    }
  }
  return $out
}

function Get-MagnitudeFindings {
  # ADVISORY. Exact transient quantities in narrative prose where a magnitude
  # statement suffices, in DIGIT and SPELLED forms alike. The unit forms
  # ($rxUnit / $rxUnitFirst) require a
  # process-event unit word adjacent to the number, so stable lookup handles
  # (file:line / dates / SHAs / task ids / versions) carry no such unit and do not
  # match. The verb form ($rxTook) is deliberately UNIT-AGNOSTIC -- it anchors on
  # "took N" instead, so it also catches "took 6 minutes"; the leading `\btook\s`
  # is what keeps it off bare numbers. Lookbehind guards per form: $rxUnit uses
  # `(?<![\w.-])` (digit-start guard incl. the dot, so dotted handles/decimal
  # fractions never shed a prefix -- see the detailed note below); $rxUnitFirst
  # uses `(?<![\w-])` (it guards the unit WORD); $rxTook needs none (the literal
  # `took ` anchor is the guard).
  # This detector is doc-agnostic; the History.md count-drift exemption (a dated
  # entry is a static snapshot whose counts cannot drift) is CALLER-applied by
  # Invoke-FileChecks, which DROPS findings on lines inside a dated entry body of the
  # ROOT History.md log. Every other line and doc is scanned normally.
  param([object[]]$Records)
  $out = @()
  if (-not $Records) { return $out }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  # The count class's surface forms are EACH matched so the documented
  # round/iteration/attempt/pass/retry/try coverage actually holds:
  #   digit-first  "6 rounds"   -- $rxUnit
  #   unit-first   "round 6"    -- $rxUnitFirst
  #   verb form    "took 6"     -- $rxTook
  # The digit-first lookbehind (?<![\w.-]) rejects a MATCH STARTING mid-token:
  # inside an identifier/version/dotted handle (task-0004, v2, M19-9, M19.9's
  # trailing 9) or at a decimal's fraction part. A FREE-STANDING decimal is
  # matched IN FULL from its first digit via the optional (\.\d+)? --
  # "0.25 seconds" is one finding ("0.25 seconds", still an exact transient
  # duration), never the fragment "25 seconds"; "M19.9 tasks" matches nothing
  # (the 19 is word-preceded, the 9 dot-preceded). The unit-first form keeps
  # the narrower (?<![\w-]) (its lookbehind guards the unit WORD, not a digit).
  #
  # The DIGIT-FIRST alternation is WIDER than the unit-first one. It adds the
  # unit-agnostic aggregate/duration nouns that leaked past the original
  # process-event list ("18-task chain", "2 rows", "47 assertions",
  # "6 minutes" -- the extension the older docs called "documented, not yet
  # caught"). These nouns are deliberately NOT in $rxUnitFirst: the unit-first
  # shape for them is usually a stable NAME, not a count ("Wave 2", "day 3",
  # "row 7" as a table coordinate), and MAGNITUDE must stay off stable
  # handles. Digit-first "2 waves"/"3 days" is a count; unit-first "Wave 2"
  # is a name.
  #
  # SPELLED cardinals ($script:SpelledCardinalAlternation) ride the digit-first and
  # verb forms -- NOT the unit-first one, which stays digit-only for the
  # part-of-speech reason given at that pattern. A spelled total drifts exactly as a
  # digit one does, so admitting it alongside the digits is what closes the gap.
  # The restrictions that separate the spelled branch from the digit branch, each
  # measured against the tree:
  #   SEPARATOR -- the digit branch keeps its `\s*-?\s*` (an "N-task chain" IS a
  #     count), while the spelled branch requires WHITESPACE. A hyphenated spelled
  #     cardinal is English compound-ADJECTIVE formation -- a NAME ("two-stream
  #     design", "three-pass pipeline"), not an enumeration.
  #   NUMBER -- the spelled branch requires a PLURAL noun not followed by a hyphen,
  #     because its cardinal is always >= two. A spelled cardinal before a SINGULAR
  #     count noun is a verb ("only after all four pass") or a compound modifier.
  # The QUALIFIER lookbehind ($script:CountQualifierAlternation) drops a comparative
  # BOUND: "at least three rounds" is already magnitude phrasing, so telling its
  # author to rewrite it would be advice against correct prose. Variable-length
  # lookbehind is a .NET regex feature, which is what lets one alternation cover
  # qualifiers of differing word counts.
  $rxUnit = [regex]("(?i)(?<!\b(?:$script:CountQualifierAlternation)$script:MarkupGapClass+)(?<![\w.-])(?:\d+(?:\.\d+)?\s*-?\s*(?:$script:CountNounAlternation)|(?:$script:SpelledCardinalAlternation)\s+(?:$script:CountNounPluralAlternation)(?!-))\b")
  # Unit-first: the unit word then a free-standing count ("round 1", "attempt 3").
  # `(?<![\w-])` before the unit keeps "subround"/"bypass 2" from matching; the
  # trailing `\b` ends the count run. (Codex DOC-VS-CODE-DRIFT.)
  # Kept to the PROCESS-EVENT nouns only -- see the digit-first note above for
  # why the aggregate/duration nouns are excluded here.
  # DIGIT-ONLY, unlike every other form here. Several of these nouns are also
  # third-person VERBS, and in that reading the following cardinal quantifies the
  # NEXT noun rather than the unit -- "passes three tests" is not three passes, nor
  # "tries three times" three tries. A digit rarely sits in that position, but a
  # spelled cardinal routinely does, and the two readings differ only by part of
  # speech, which no mechanical rule here can settle. The inverted order is
  # therefore left to the AI gate; the natural order still carries it, since
  # "three rounds" is caught by the digit-first form above.
  $rxUnitFirst = [regex]("(?i)(?<![\w-])(?:$script:ProcessEventNounAlternation)\s+\d+\b")
  # The optional (\.\d+)? consumes a decimal in full so "took 0.25 seconds"
  # is matched as "took 0.25" (still an exact transient measurement, still
  # advisory) rather than as the fragment "took 0".
  #
  # HYPHEN CONTINUATION, on BOTH flanks -- the shape `(?<![\w-]) ... (?![\w-])` that
  # this pattern, $rxAllCases and $rxAllTotal all now carry. `\b` succeeds against a
  # hyphen, so a bare `\b` around a cardinal matched INSIDE a compound: "took 3-way"
  # reported "took 3" and "all three-way" reported "all three", where the hyphenated
  # form is English compound-ADJECTIVE formation -- a NAME, not an enumeration, the
  # same distinction $rxUnit's spelled branch already drew with its whitespace
  # separator. Both spellings of the cardinal leaked it, so the digit alternative is
  # covered by the same guards rather than by a spelled-only fix. `.` stays OUT of the
  # TRAILING class: a sentence-final "took 3." is still a count.
  $rxTook = [regex]("(?i)(?<![\w-])took\s+(?:\d+(?:\.\d+)?|$script:SpelledCardinalAlternation)(?![\w-])")
  # ENUMERATED-CASE COUNTING -- the SPELLED-OUT sibling of the digit-first count
  # forms, in the same MAGNITUDE family (Class 'MAGNITUDE', ADVISORY), added
  # because "all three cases" restates an exact total a magnitude phrasing ("all
  # cases" / "every case") carries just as the digit forms do. $rxUnit is gated on the
  # COUNT-NOUN set, which the enumeration nouns sit outside, so a total like "all three
  # cases" or "both cases" slips past it -- $rxAllCases closes exactly that gap, and
  # the shared span dedupe below settles the nouns the two sets have in common.
  # The surface forms:
  #   (a) $rxAllCases: "all <spelled-N> <enumeration-noun>" / "both <noun>".
  #   (b) the paren-enumeration pairing: a line with >=2 inline `(N)` markers
  #       ($rxEnumParen) TOGETHER WITH an "all <N>" total ($rxAllTotal), i.e.
  #       the "(1) ... (2) ... (3) ... all three" enumerate-then-total shape,
  #       caught even when the total carries no enumeration noun.
  # Both feed the SHARED span dedupe below, not a pass of their own -- several
  # enumeration nouns are also count nouns, so the spelled unit form matches the
  # same phrase and only one row may survive it.
  # Stable-handle safety is inherited: neither pattern matches a bare digit run
  # (so SHAs / task-ids / dates are untouched), and the unit-first NAME shape
  # ("Wave 2", "day 3") never begins with "all"/"both", so it cannot false-match.
  $rxAllCases = [regex]("(?i)(?<![\w-])(?:all\s+(?:$script:SpelledCardinalAlternation)|both)\s+(?:cases?|instances?|forms?|variants?|scenarios?|places?|sites?|call-?sites?|classes|categories|paths?|branches|reasons?|points?|ways?)(?![\w-])")
  $rxEnumParen = [regex]('\(\d+\)')
  $rxAllTotal = [regex]("(?i)(?<![\w-])all\s+(?:\d+|$script:SpelledCardinalAlternation)(?![\w-])")
  for ($i = 0; $i -lt $Records.Count; $i++) {
    if ($fenced[$i]) { continue }
    $text = [string]$Records[$i].Text
    # Dedupe on CHARACTER SPANS, never on the number: a match is suppressed only when
    # its span OVERLAPS a kept one, so "took 6 rounds" (the "took 6" and "6 rounds"
    # spans share the "6") yields ONE finding, while the independent "6 rounds ...
    # took 6" (disjoint spans, same number) keeps BOTH. Number-based dedup wrongly
    # dropped the latter's verb-form count. (Codex QUALITY;
    # supersedes the earlier same-number dedup.)
    # ONE dedupe over EVERY form in the class, not a special case for the verb form
    # and a second pass for the enumerated totals: the widened patterns overlap each
    # other ("3 passes 4" is matched by both unit orders; "all three instances" by
    # both the enumerated-total and the spelled unit form), and one occurrence of
    # text is one count however many patterns see it. A separate pass could not see
    # the other's spans, so the shared nouns yielded two rows for one phrase.
    # Ties break by RANK first and only then by span length. Rank orders what the
    # match NAMES: rank 0 forms name what is counted ("6 rounds", "all three cases"),
    # rank 1 forms only that something was counted ("took 6", a nounless "all three"),
    # so where they overlap the naming form is the more useful thing to show.
    # Hint travels WITH the candidate, so the surviving row tells the author which
    # magnitude rewrite applies to the phrase actually reported.
    $transientHint = 'prefer magnitude over an exact transient count ("many rounds")'
    $enumHint = 'prefer "all cases"/"every case" over an exact enumerated total'
    $candidates = @()
    foreach ($ranked in @(
        @{ Rx = $rxUnit;      Rank = 0; Hint = $transientHint },
        @{ Rx = $rxUnitFirst; Rank = 0; Hint = $transientHint },
        @{ Rx = $rxAllCases;  Rank = 0; Hint = $enumHint },
        @{ Rx = $rxTook;      Rank = 1; Hint = $transientHint })) {
      foreach ($m in $ranked.Rx.Matches($text)) { $candidates += @{ Start = $m.Index; End = ($m.Index + $m.Length); Value = $m.Value; Rank = $ranked.Rank; Hint = $ranked.Hint } }
    }
    # Form (b) -- the nounless "(1) ... (2) ... all three" total. Its candidates are
    # emitted unconditionally and the SHARED SPAN DEDUPE settles them: where form (a)
    # also matched, its span CONTAINS this one and outranks it, so the noun-bearing
    # phrase wins and the line reports once.
    #
    # The guard this replaces asked whether form (a) matched ANYWHERE on the line,
    # which suppressed a DISJOINT nounless total elsewhere on the same line -- a
    # second, unrelated claim silently dropped because a first one existed. Overlap is
    # a SPAN question, and the dedupe already answers it. (Codex QUALITY.)
    if (($rxEnumParen.Matches($text).Count -ge 2) -and $rxAllTotal.IsMatch($text)) {
      foreach ($m in $rxAllTotal.Matches($text)) { $candidates += @{ Start = $m.Index; End = ($m.Index + $m.Length); Value = $m.Value; Rank = 1; Hint = $enumHint } }
    }
    $keptSpans = @()
    # POSITION is the identity, and the span filter below already enforces it: every
    # kept candidate is pairwise disjoint, so each one is a DISTINCT occurrence.
    # A second, text-keyed dedupe used to sit here and could only ever suppress the
    # thing the span filter had just proven separate -- `took 6 rounds ... 6 rounds
    # again` reported once, dropping a real second claim. Do not reintroduce it.
    foreach ($cand in ($candidates | Sort-Object @{e={ $_.Rank }}, @{e={ $_.End - $_.Start }; Descending=$true}, @{e={ $_.Start }})) {
      $overlaps = $false
      foreach ($s in $keptSpans) {
        if ($cand.Start -lt $s.End -and $s.Start -lt $cand.End) { $overlaps = $true; break }
      }
      if ($overlaps) { continue }
      $keptSpans += $cand
      $val = ([string]$cand.Value).Trim()
      $out += @{
        Class = 'MAGNITUDE'
        Tier  = 'ADVISORY'
        Line  = [int]$Records[$i].Line
        Match = $val
        Hint  = $cand.Hint
      }
    }
  }
  return $out
}

function Get-SelfNarrationFindings {
  # Narration of the PENDING change's OWN landing -- the deictic "this/here" +
  # a landing-event noun (merge/landing/entry) form. ERROR when the doc is
  # History.md ($IsHistoryDoc), ADVISORY in any other narrative doc: History
  # entries are retrospective records of what ALREADY landed, so an entry that
  # narrates its own not-yet-landed merge is a factual defect (the merge SHA is
  # not knowable while the entry rides the branch through the gate); elsewhere
  # the same phrasing is a softer smell, so it only advises.
  #
  # The signature is the DEICTIC pointer at the current change, NOT the bare
  # word "merge"/"landed" -- legitimate RETROSPECTIVE prose about an
  # already-landed merge ("the merge landed at <sha>", "the batch merged
  # cleanly") carries no "this/here" pointer and must stay clean. The phrase set
  # was CALIBRATED against the current History.md so the ERROR tier fires only on
  # genuine self-narration:
  #   - "this merge" / "this landing"  -- deictic + landing EVENT (covers
  #     "after this merge", "immediately after this merge", "this landing's").
  #     These are the highest-precision forms; the current tree's matches are all
  #     true-positive debt (high-precision -- legitimate prose is not caught).
  #   - "as of this entry" / "add(s|ing) this entry" -- the two documented
  #     entry-deixis incidents (a state-as-of-the-entry claim; a commit narrating
  #     that it adds the entry). Deliberately NARROW: a bare "this entry" is NOT
  #     matched, because legitimate timestamping ("at the time of this entry")
  #     uses it and would false-positive at ERROR tier.
  #   - "landed ... here" -- the deictic "here" (this doc/point) within a short
  #     word window of "landed" (covers "landed here" and "landed through the
  #     gate here"). Word-bounded window (<=6 words) so it cannot cross a clause.
  # Lower-precision self-narration (a bare "this entry rides ...", "recordable
  # here") is left to the AI gate on purpose -- under-flagging a borderline form
  # beats an ERROR false positive that blocks a legitimate commit (the same
  # calibration doctrine the LINE-ANCHOR tier note records).
  param(
    [object[]]$Records,
    [bool]$IsHistoryDoc
  )
  $out = @()
  if (-not $Records) { return $out }
  $tier = if ($IsHistoryDoc) { 'ERROR' } else { 'ADVISORY' }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  $patterns = @(
    [regex]('(?i)\bthis\s+merge\b'),
    [regex]('(?i)\bthis\s+landing\b'),
    [regex]('(?i)\bas\s+of\s+this\s+entry\b'),
    [regex]('(?i)\b(?:add|adds|adding)\s+this\s+entry\b'),
    # "landed" then, within up to 6 intervening words, a deictic "here".
    [regex]("(?i)\blanded\b(?:\s+[\w'-]+){0,6}?\s+here\b")
  )
  for ($i = 0; $i -lt $Records.Count; $i++) {
    if ($fenced[$i]) { continue }
    $text = [string]$Records[$i].Text
    $hits = @()
    foreach ($rx in $patterns) {
      foreach ($m in $rx.Matches($text)) { $hits += $m.Value }
    }
    foreach ($h in ($hits | Select-Object -Unique)) {
      $out += @{
        Class = 'SELF-NARR'
        Tier  = $tier
        Line  = [int]$Records[$i].Line
        Match = ($h -replace '\s+', ' ').Trim()
        Hint  = 'do not narrate the pending change''s own landing; state already-landed facts (a merge SHA is unknowable while the entry rides the branch)'
      }
    }
  }
  return $out
}

function Get-LocalEvidenceFindings {
  # A proof/verification CLAIM co-located with a LOCAL-ONLY evidence reference --
  # citing something a fresh clone cannot resolve as if it were shareable proof.
  # Tiers set by CALIBRATION against the current doc tree (the header doctrine:
  # ERROR only where the signature fires ZERO false positives):
  #   ERROR (tight): a proof word (prove/proves/proved/proven/proving | verify/
  #     verifies/verified/verifying/verification/verifiable) on the same line as the gitignored review-artifact
  #     PATH `logs/(codex|claude)/reviews` (either `/` or `\` separator), OR a
  #     `proof`/`evidence` NOUN within $NounWindow chars of that path (proximity so
  #     "Proof: <path>" flags but a distant "evidence snapshot ... <path>" does not).
  #     That path is THE local evidence store;
  #     a proof claim next to it is the exact anti-pattern, and the full-tree
  #     calibration found the pairing does not arise in legitimate prose -- so it is high-precision ERROR.
  #   ADVISORY (adjective): a proof word with one of the bare markers
  #     gitignored | local-only | untracked. These are demonstrably lower
  #     precision -- the current tree co-locates them with proof words in
  #     ordinary git prose ("verify ... --untracked-files", cleanup notes) and in
  #     META-DISCUSSION of this very rule ("gitignored logs ... cannot prove
  #     provenance"), which are NOT the defect. So the class is surfaced, not
  #     blocked, and the author judges (mirrors the DEAD-REF advisory-by-
  #     calibration outcome).
  #   ADVISORY (loose): "operator-side"/"local" together with "evidence" -- the
  #     softest form, always advisory.
  # Word-boundaried proof words so "approve"/"approved" (which merely CONTAIN
  # "prove") never match. One finding per line: ERROR outranks the adjective
  # advisory, which outranks the loose advisory.
  param([object[]]$Records)
  $out = @()
  if (-not $Records) { return $out }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  # Word-bounded proof/verification words INCLUDING the common inflections
  # (proved/proven past forms, verifying/verifiable) so `verifying via
  # logs/.../reviews` is not a false-clean. (Codex BLOCKER: the
  # original set omitted verifying/proven.)
  $rxProof    = [regex]('(?i)\b(?:prove|proves|proved|proven|proving|verify|verifies|verified|verifying|verification|verifiable)\b')
  # Accept BOTH separators -- this Windows-first repo writes `logs\codex\reviews`
  # as readily as `logs/codex/reviews` (LINE-ANCHOR/DEAD-REF honor both too).
  # (Codex BLOCKER: a `\`-separated review path bypassed the gate.)
  $rxPathMark = [regex]('logs[\\/](?:codex|claude)[\\/]reviews')
  $rxAdjMark  = [regex]('(?i)\b(?:gitignored|local-only|untracked)\b')
  $rxLooseQ   = [regex]('(?i)(?:\boperator-side\b|\blocal\b)')
  $rxEvidence = [regex]('(?i)\bevidence\b')
  # NOUN forms of the claim (proof/evidence). Caught in the tight ERROR only when
  # WITHIN $NounWindow chars of the review path -- a proximity gate so `Proof:
  # logs/.../reviews` (a citation) flags while `builds the evidence snapshot ...
  # logs/.../reviews` (the noun far from the path, a description) does not. (Codex
  # BLOCKER: noun-form path claims like "Proof: <path>".)
  $rxProofNoun = [regex]('(?i)\b(?:proof|evidence)\b')
  $NounWindow = 30
  for ($i = 0; $i -lt $Records.Count; $i++) {
    if ($fenced[$i]) { continue }
    $text = [string]$Records[$i].Text
    $proof = $rxProof.Match($text)
    $pathM = $rxPathMark.Match($text)
    # TIGHT ERROR: a verb proof-word ANYWHERE on the line with the review path, OR a
    # proof/evidence NOUN within $NounWindow chars of the path.
    $tightMatch = $null
    if ($proof.Success -and $pathM.Success) {
      $tightMatch = "$($proof.Value) + $($pathM.Value)"
    } elseif ($pathM.Success) {
      foreach ($pm in $rxPathMark.Matches($text)) {
        foreach ($nm in $rxProofNoun.Matches($text)) {
          $gap = [Math]::Max($nm.Index - ($pm.Index + $pm.Length), $pm.Index - ($nm.Index + $nm.Length))
          if ($gap -le $NounWindow) { $tightMatch = "$($nm.Value) + $($pm.Value)"; break }
        }
        if ($tightMatch) { break }
      }
    }
    if ($tightMatch) {
      $out += @{
        Class = 'LOCAL-PROOF'
        Tier  = 'ERROR'
        Line  = [int]$Records[$i].Line
        Match = $tightMatch
        Hint  = 'do not cite a gitignored review-artifact path as proof; a fresh clone cannot resolve it'
      }
      continue
    }
    if ($proof.Success) {
      $adjM = $rxAdjMark.Match($text)
      if ($adjM.Success) {
        $out += @{
          Class = 'LOCAL-PROOF'
          Tier  = 'ADVISORY'
          Line  = [int]$Records[$i].Line
          Match = "$($proof.Value) + $($adjM.Value)"
          Hint  = 'a proof claim beside a local-only marker -- confirm it is not offered as clone-resolvable evidence'
        }
        continue
      }
    }
    $q = $rxLooseQ.Match($text)
    if ($q.Success -and $rxEvidence.IsMatch($text)) {
      $out += @{
        Class = 'LOCAL-PROOF'
        Tier  = 'ADVISORY'
        Line  = [int]$Records[$i].Line
        Match = "$($q.Value) + evidence"
        Hint  = 'operator-side/local evidence is not tracked-tree evidence; state it as such or drop the claim'
      }
    }
  }
  return $out
}

function Get-MachineLocalStateFindings {
  # ADVISORY. A machine-local install/wiring state asserted as repo fact: an
  # "installed and wired" / "is wired via" / "wired via" claim on the same line
  # as a MACHINE-LOCAL config path (~/.claude ... or .claude/settings.local.json;
  # either `/` or `\` separator, Windows-first)
  # -- state that lives on one operator's machine, not in the tracked tree, so a
  # fresh clone cannot confirm it. EXEMPT when the line already flags the state
  # as machine-local (a "machine-local" / "local-only" qualifier present), which
  # is exactly how the existing hook docs correctly caveat it -- so the detector
  # surfaces only UN-caveated assertions. Advisory only: many legitimate
  # operational instructions name these paths, so the author confirms the caveat.
  param([object[]]$Records)
  $out = @()
  if (-not $Records) { return $out }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  $rxWired  = [regex]('(?i)\b(?:installed(?:\s+and\s+wired)?|is\s+wired(?:\s+via)?|wired\s+(?:via|through|in|into)|installed\s+via)\b')
  # Both separators (Windows-first): `~\.claude` / `.claude\settings.local.json`
  # are as common as the `/` forms. (Codex BLOCKER.)
  $rxMLPath = [regex]('(?i)(?:~[\\/]\.claude|\.claude[\\/]settings\.local\.json)')
  $rxCaveat = [regex]('(?i)\b(?:machine-local|machine\slocal|local-only)\b')
  for ($i = 0; $i -lt $Records.Count; $i++) {
    if ($fenced[$i]) { continue }
    $text = [string]$Records[$i].Text
    if ($rxCaveat.IsMatch($text)) { continue }
    $w = $rxWired.Match($text)
    $p = $rxMLPath.Match($text)
    if ($w.Success -and $p.Success) {
      $out += @{
        Class = 'LOCAL-STATE'
        Tier  = 'ADVISORY'
        Line  = [int]$Records[$i].Line
        Match = "$($w.Value) + $($p.Value)"
        Hint  = 'machine-local wiring asserted as repo fact; mark it machine-local or verify it in the tracked tree'
      }
    }
  }
  return $out
}

function Get-InventoryAssertionFindings {
  # An EXACT INVENTORY/COUNT of repo/project state asserted in prose -- the
  # durable, NOUN-AGNOSTIC signature of the drift-prone count (the count is wrong
  # the instant the inventory changes, and no reader can trust it). The
  # high-precision SHAPE families gate on the surrounding VERB, not a noun list,
  # so an unforeseen noun ("223 icons", "7 biomes", "96 task JSONs") is still caught,
  # and <N> is a DIGIT run or a spelled cardinal alike:
  #   1. "there is|are  <N>  <word>"
  #   2. "<N> <word>  is|are  (defined|tracked|supported|registered|covered|available|in place)"
  #   3. "(covers|contains|includes|names|totals?)  <N>  <word>"
  # A further, DETERMINER-gated shape carries its own (ADVISORY) tier:
  #   4. "(the|these|those) <spelled-N> <modifiers> <plural count-noun>"
  # The VERB-GATED shapes are ERROR-tier (calibrated: the full-tree .md run surfaces only
  # genuine inventory claims -- true-positive debt, like LINE-ANCHOR/SELF-NARR --
  # not legitimate prose, because the digit lookbehind excludes
  # identifier/version/date/SHA digits). NO frozen-snapshot downgrade: the
  # marker exemption is scoped to LINE ANCHORS (the symbol-anchor rule), so an
  # exact count stays ERROR even in a frozen-marked doc and a staged .md
  # inventory claim can never bypass the error-tier pre-pass. (Codex BLOCKER
  #: the prior ADVISORY downgrade contradicted the exact-count
  # contract.)
  # EXEMPTIONS:
  #   - the stable-handle lookbehind (?<![\w.-]) on the digit: an identifier /
  #     version / date / SHA / task-id digit ("M19.9", "task-0003", "v2", "P1") is
  #     never read as a count. Exit codes / tier / protocol values naturally fall
  #     out: none carry a shape VERB ("exit 3" has no "there are"/"covers"/"are
  #     defined"), so the shape never matches them.
  #   - INLINE CODE: a FULL illustrative example -- the WHOLE claim inside one
  #     backtick span (`there are 223 icons`) -- is exempt so a doc can name the
  #     class; but a claim whose NUMBER ALONE is backticked (there are `223`
  #     icons) is a real prose claim and still flags (matching runs on the text
  #     with backtick delimiters removed, exempting only a match wholly inside a
  #     single span). Fenced blocks are skipped as elsewhere.
  # (The source-comment code-echo exemption is applied by the caller
  # Get-StagedSourceFindings, which alone knows the nearby code lines. The
  # History.md count-drift exemption is likewise CALLER-applied by
  # Invoke-FileChecks -- which alone knows the doc identity + line layout -- so
  # this detector stays doc-agnostic and still fires when called directly on
  # History content; the caller then DROPS findings on lines inside a dated entry
  # body of the ROOT History.md log, a static snapshot whose counts cannot drift.)
  param(
    [object[]]$Records
  )
  $out = @()
  if (-not $Records) { return $out }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  # A cardinal is a DIGIT run or a SPELLED cardinal
  # ($script:SpelledCardinalAlternation): "covers three biomes" asserts and drifts
  # exactly as "covers 3 biomes" does, so admitting both spellings is what keeps the
  # claim's FORM from deciding its tier. The shared `(?<![\w.-])` guard applies to whichever branch
  # matches, so identifier/version/date/SHA digits and hyphen-compounded cardinals
  # stay excluded either way.
  $cardinal = "(?:\d+|$script:SpelledCardinalAlternation)"
  $rxThereAre = [regex]("(?i)\bthere\s+(?:is|are)\s+(?<![\w.-])$cardinal\s+[A-Za-z][A-Za-z-]*")
  # Shape 2 is the one INVENTORY shape a qualifier can precede ("at least three
  # mutators are registered"); the others place their verb before the cardinal, so a
  # qualifier there breaks the match on its own.
  $rxAreState = [regex]("(?i)(?<!\b(?:$script:CountQualifierAlternation)$script:MarkupGapClass+)(?<![\w.-])$cardinal\s+[A-Za-z][A-Za-z-]*\s+(?:are|is)\s+(?:defined|tracked|supported|registered|covered|available|in\s+place)\b")
  # `names` joins the enumerating verbs: "names three record families" is the same
  # claim shape as "contains three record families".
  $rxCovers   = [regex]("(?i)\b(?:covers|contains|includes|names|totals?)\s+(?<![\w.-])$cardinal\s+[A-Za-z][A-Za-z-]*")
  # DETERMINER-COUNT-NOUN: "the/these/those <spelled-N> [modifier]{1,2} <plural count-noun>"
  # ("the two consecutive landings", "the three arc landings"). The determiner is
  # the load-bearing gate, not decoration: it is what separates a definite
  # enumeration from the idioms that must stay clean ("in one pass", "one file per
  # pass") -- dropping it would flag those. Up to two MODIFIER words may sit between
  # the cardinal and the noun (adjectives and noun-adjuncts are the norm in this
  # prose), but a FUNCTION word may not: without that exclusion "One of the passes"
  # would reach `passes` through "of the". The noun is gated on the shared PLURAL
  # noun set ($script:CountNounPluralAlternation) and may not be hyphen-continued,
  # so an unbounded noun phrase is never matched and a compound modifier ("the four
  # lettered commit-tracked steps") is not read as an enumeration of commits.
  # AT LEAST ONE modifier is REQUIRED: with none, the cardinal sits directly on the
  # noun, which the MAGNITUDE digit-first form already reports -- admitting it here
  # too made a single occurrence yield a duplicate finding. This shape covers
  # exactly what adjacency cannot reach.
  # ADVISORY, unlike the verb-gated shapes above: the modifier slack makes this the
  # loosest shape here, and the calibration doctrine reserves ERROR for signatures
  # with zero false positives on the current tree.
  $modifier = "(?:(?!(?:$script:FunctionWordAlternation)\b)[A-Za-z][A-Za-z-]*\s+){1,2}"
  $rxDetCount = [regex]("(?i)\b(?:the|these|those)\s+(?<![\w.-])(?:$script:SpelledCardinalAlternation)\s+$modifier(?:$script:CountNounPluralAlternation)(?!-)\b")
  # Ordered ERROR-first so a shape listed earlier wins an OVERLAPPING span and an
  # ERROR claim can never be shadowed by an ADVISORY one.
  # CardinalLeads marks the one shape whose match OPENS with the cardinal. The
  # others put their verb first, so a comparative qualifier would have to sit
  # between verb and cardinal -- on the same line, where the lookbehind sees it.
  $patterns = @(
    @{ Rx = $rxThereAre; Tier = 'ERROR';    CardinalLeads = $false },
    @{ Rx = $rxAreState; Tier = 'ERROR';    CardinalLeads = $true  },
    @{ Rx = $rxCovers;   Tier = 'ERROR';    CardinalLeads = $false },
    @{ Rx = $rxDetCount; Tier = 'ADVISORY'; CardinalLeads = $false }
  )
  for ($i = 0; $i -lt $Records.Count; $i++) {
    if ($fenced[$i]) { continue }
    $text = [string]$Records[$i].Text
    # Inline-code handling. A backtick `...` span that wraps a WHOLE illustrative
    # claim (`there are 223 icons`) is exempt so a doc can NAME the class; but a
    # claim whose NUMBER ALONE is backticked (there are `223` icons) is a real
    # prose claim and MUST still flag. (Codex BLOCKER: blanking
    # every span dropped the number-only-backticked form's only digit and
    # false-cleaned a real claim.) So match on the text with backtick DELIMITERS
    # removed (adjacency restored across an inline `N`), then EXEMPT a match ONLY
    # when its ENTIRE original span lies inside a SINGLE inline-code span. $map
    # carries each flat-string index back to its original offset for that test.
    $spans = @()
    foreach ($cm in ([regex]::Matches($text, '`[^`]*`'))) { $spans += @{ Start = $cm.Index; End = ($cm.Index + $cm.Length) } }
    $flatSb = New-Object System.Text.StringBuilder
    $map = New-Object 'System.Collections.Generic.List[int]'
    for ($k = 0; $k -lt $text.Length; $k++) {
      if ($text[$k] -eq '`') { continue }
      [void]$flatSb.Append($text[$k]); $map.Add($k)
    }
    $flat = $flatSb.ToString()
    # TIER FIRST, then dedupe on overlapping SPANS -- never on matched TEXT. The tier
    # depends on WHERE a match sits (the start-of-text demotion), so the same claim can
    # be ADVISORY at the head of a line and ERROR later on it. A text key let the
    # leading, demoted occurrence claim the text and DROP the later ERROR one, which
    # silently downgraded the line. Position is the identity; disjoint occurrences all
    # survive, and where spans overlap the ERROR-first pattern order keeps the
    # strictest reading.
    $keptSpans = @()
    foreach ($p in $patterns) {
      foreach ($m in $p.Rx.Matches($flat)) {
        # Map the flat match back to original offsets; exempt only a FULL example.
        $origStart = $map[$m.Index]
        $origEnd = $map[$m.Index + $m.Length - 1]
        $insideOneSpan = $false
        foreach ($sp in $spans) { if ($origStart -ge $sp.Start -and $origEnd -lt $sp.End) { $insideOneSpan = $true; break } }
        if ($insideOneSpan) { continue }
        $overlaps = $false
        foreach ($ks in $keptSpans) { if ($origStart -le $ks.End -and $ks.Start -le $origEnd) { $overlaps = $true; break } }
        if ($overlaps) { continue }
        $keptSpans += @{ Start = $origStart; End = $origEnd }
        $val = ($m.Value -replace '\s+', ' ').Trim()
        # RESIDUAL, stated precisely: these detectors scan ONE LINE at a time, so a
        # comparative qualifier ("at least", "up to") that a hard wrap put on the
        # PREVIOUS line is invisible to the lookbehind, and a bounded claim is not an
        # inventory. A CARDINAL-LEADING match at the START OF THE LINE'S TEXT is
        # exactly the shape a wrap produces, so it is ADVISORY unconditionally -- the
        # author still sees it, and an unqualified claim there is the rarer case.
        # START OF TEXT, not column zero: a wrapped line inside an indented list item
        # or a blockquote carries its markers first, and keying on offset 0 left every
        # such wrap at ERROR while demoting only the unindented ones.
        #
        # SUPERSEDES a demotion that tried to PROVE the wrap from
        # the preceding record's qualifier tail: one-line lookback cannot see a
        # qualifier two lines up or one inside a preceding list marker, so proving it
        # only relocated the guess. Do not resurrect the proof.
        $tier = $p.Tier
        # THE PRE-PASS MUST NEVER BE STRICTER THAN THE GATE IT FRONT-RUNS. The reviewer
        # contract scores an exact-count-in-prose QUALITY -- non-blocking -- so a class
        # that exits 3 and ABORTS the commit is enforcing a severity the gate itself
        # declines to enforce. The digit shapes keep ERROR because that mapping is
        # operator-documented policy (the Self-Sweep's error-tier list names `there are
        # N X` / `covers N X`), and re-tiering documented policy is a decision for the
        # operator, not for the change that happens to touch the file. A shape the
        # error-tier list does NOT name carries no such mandate, so it stays at the
        # softer tier: a SPELLED cardinal (the shapes' only spelled position, so a
        # match with no digit run is exactly one) and the `names` verb.
        if ($tier -eq 'ERROR' -and (($val -notmatch '\d') -or ($val -match '(?i)^names\b'))) { $tier = 'ADVISORY' }
        if ($tier -eq 'ERROR' -and $p.CardinalLeads -and
            ($text.Substring(0, $origStart) -match "^$script:LineLeadMarkupPattern$")) { $tier = 'ADVISORY' }
        $out += @{
          Class = 'INVENTORY'
          Tier  = $tier
          Line  = [int]$Records[$i].Line
          Match = $val
          Hint  = 'exact inventory count in prose drifts; use magnitude phrasing or delete if the count is the only content (do not "correct" the number)'
        }
      }
    }
  }
  return $out
}

function Get-SourceLineParts {
  # Split ONE source line into its COMMENT text and its CODE text, given the
  # incoming block-comment state. Comment syntax per $Ext (rs: `//` line + `/* */`
  # block; ps1: `#` line + `<# #>` block; sh/toml: `#` line, no block). String
  # literals are honored so a `//`/`#` INSIDE a string ("http://..." , a toml
  # value with `#`) counts as code, not a comment.
  #
  # KNOWN LIMITATION, bounded and deliberate -- stated as the code actually behaves.
  # ESCAPED quotes ARE modelled: inside a string the Rust `\` and the PowerShell
  # backtick -- the latter in a DOUBLE-quoted string only, single-quoted PowerShell
  # having no escape at all -- each consume the following character, so `"a\"b"` does
  # not terminate early. What is NOT modelled, measured form by form:
  #   Rust RAW strings (`r#"..."#`) -- an interior quote closes the string early.
  #   Rust NESTED block comments -- $InBlock is a boolean, not a depth, so
  #     `/* a /* b */ c */` ends at the FIRST `*/` and its tail ` c */` is code.
  #   Rust CHAR literals holding a quote (`'"'`) -- only `"` delimits here (a bare
  #     `'` is a lifetime), so the quote opens a string that runs on across lines.
  #   PowerShell HERE-strings (`@" ... "@`) and TOML TRIPLE-QUOTED strings -- neither
  #     multi-line form is recognized, so their bodies lex by the single-quote rules.
  # BOTH directions occur, which is why the cost is not a one-sided miss:
  #   comment -> CODE. The nested-comment tail above never reaches the comment scan,
  #     AND its numbers enter the code-echo map, where they can exempt a count on a
  #     DIFFERENT nearby line. A miss here can therefore travel.
  #   string -> COMMENT. `r#"a "b // n icons" c"#` closes early at the interior
  #     quote, then meets `//` in the remainder and reads the rest of the RAW STRING
  #     as a comment -- a finding INVENTED from string content, not merely one lost.
  # ADVISORY tier is the answer to that two-sidedness: a class whose splitter can
  # both lose and invent must not abort a commit, which is why the source-comment
  # finding sits one tier under the .md ERROR. The MAGIC-COUNT-ASSERT surface does
  # NOT share these gaps -- Get-RustLexedCodeRecords lexes raw strings, char
  # literals and DEPTH-COUNTED block comments across records.
  # DO NOT re-state this as a one-sided miss: the raw-string case above INVENTS, and
  # a note that says otherwise licenses the very simplification that hid it.
  # $InString / $StrChar carry STRING state across lines the way $InBlock carries
  # block-comment state. A Rust string may span lines, and without the carry its
  # continuation lines lex as code -- so a number inside a multi-line string entered
  # the echo map and could exempt an unrelated comment count.
  param([string]$Line, [string]$Ext, [bool]$InBlock, [bool]$InString = $false, [string]$StrChar = '')
  $s = [string]$Line
  $n = $s.Length
  $comment = New-Object System.Text.StringBuilder
  $code = New-Object System.Text.StringBuilder
  # A parallel code rendering with STRING INTERIORS blanked, length-preserving.
  # Numeric extraction reads this one: a quoted `"0x3"` or `"1_000"` is text, not an
  # adjacent constant, and quote-adjacency guards on the number regex cannot see far
  # enough to tell. Blanking once here fixes every numeric consumer at the source
  # rather than per-regex.
  $codeNoStr = New-Object System.Text.StringBuilder
  $hasBlock = ($Ext -eq 'rs' -or $Ext -eq 'ps1')
  $blkOpen = switch ($Ext) { 'rs' { '/*' } 'ps1' { '<#' } default { '' } }
  $blkClose = switch ($Ext) { 'rs' { '*/' } 'ps1' { '#>' } default { '' } }
  # Rust: only `"` is a string delim here (a bare `'` is a lifetime, not a string).
  $strChars = if ($Ext -eq 'rs') { @('"') } else { @('"', "'") }
  $inStr = $InString; $strCh = $StrChar
  # PER-FRAGMENT comment emission for the staged-source segmenter. A line can
  # hold several comment FRAGMENTS with code between them (`*/ let x = 1; //
  # note` is a block tail, code, then a fresh line comment), and every
  # line-merged model measured before this one lost that structure a
  # different way: a presence flag split block continuations from their
  # openers, and a first/last positional pair could not see code between a
  # SAME-LINE close and a later same-line comment -- each time re-reading a
  # fence closer as an opener or hiding the code that separates fragments,
  # and silently suppressing a live claim either way. So the split emits the
  # structure itself: Fragments = ordered records, each with its own Text,
  # WasInBlock (a carry-in continuation of the previous line's block), and
  # CodeBefore (non-whitespace code between the previous fragment on this
  # line -- or line start -- and this fragment); the line's LAST fragment
  # additionally carries CodeAfter when it CLOSED on this line and
  # non-whitespace code followed (a line comment runs to EOL and an unclosed
  # block continues, so neither can). The aggregate Comment string remains
  # for whole-line consumers.
  $frags = New-Object 'System.Collections.Generic.List[object]'
  $fragSb = $null; $fragWasInBlock = $false; $fragCodeBefore = $false
  $fragMark = 0
  $lastCloseFragIndex = -1
  if ([bool]$InBlock) { $fragSb = New-Object System.Text.StringBuilder; $fragWasInBlock = $true; $fragCodeBefore = $false }
  $i = 0
  while ($i -lt $n) {
    $ch = [string]$s[$i]
    if ($InBlock) {
      if ($hasBlock -and ($i + 1 -lt $n) -and $s.Substring($i, 2) -eq $blkClose) {
        $InBlock = $false
        $frags.Add(@{ Text = $fragSb.ToString(); WasInBlock = $fragWasInBlock; CodeBefore = $fragCodeBefore; CodeAfter = $false })
        [void]$comment.Append($fragSb.ToString())
        $fragSb = $null; $fragMark = $code.Length; $lastCloseFragIndex = $frags.Count - 1
        $i += 2; continue
      }
      [void]$fragSb.Append($ch); $i++; continue
    }
    if ($inStr) {
      # ESCAPE FIRST, then the braced dispatch, then the terminator: an escaped `$`
      # opens no name, so reordering these silently changes which characters the
      # string is held to contain. The ordering answers for the escapes this model
      # applies -- rs `\` and ps1 backtick -- and for nothing else: an sh or toml
      # backslash inside a double-quoted string is refused outright by the support
      # checker, so no order here could be right or wrong for it. (P6 port
      # adjudication: the package's older escape MODELING for those forms is
      # superseded by the refusal -- a loud per-file degrade beats a silent
      # model of a grammar this scanner does not otherwise hold.)
      #
      # The ps1 escape is scoped to the EXPANDABLE string: PowerShell gives a
      # single-quoted string no escapes at all, so consuming a backtick there ate the
      # closing quote, ran the string on past its real end, and could put a following
      # quoted value on the string side while a `#` after it read as string text.
      if ($Ext -eq 'rs' -and $ch -eq '\') { [void]$code.Append($ch); [void]$codeNoStr.Append(' '); if ($i + 1 -lt $n) { [void]$code.Append($s[$i + 1]); [void]$codeNoStr.Append(' ') }; $i += 2; continue }
      if ($Ext -eq 'ps1' -and $strCh -eq '"' -and $ch -eq '`') { [void]$code.Append($ch); [void]$codeNoStr.Append(' '); if ($i + 1 -lt $n) { [void]$code.Append($s[$i + 1]); [void]$codeNoStr.Append(' ') }; $i += 2; continue }
      # A `${...}` inside an EXPANDABLE string is a NAME, and its body is not string
      # text: MEASURED against the PowerShell tokenizer, `"${a" 3 "b}"` lexes as ONE
      # StringExpandable whose nested token is the single variable `${a" 3 "b}` -- the
      # quotes inside the braces are name characters, not delimiters. Scanned
      # character by character the model closed the string at the first inner quote,
      # exposed the name's middle as CODE, and a digit there forged a code-echo
      # exemption that erased a real count finding with no diagnostic.
      #
      # SINGLE-quoted strings are excluded, and that is a decision rather than an
      # omission: neither language interpolates in them (MEASURED: `'${a" 3 "b}'`
      # lexes as one StringLiteral), so there the braces are ordinary literal text.
      if ($strCh -eq '"' -and ($Ext -eq 'ps1' -or $Ext -eq 'sh') -and $ch -eq '$' -and ($i + 1 -lt $n) -and [string]$s[$i + 1] -eq '{') {
        $inStrBraced = Get-BracedVariableTokenLength -Text $s -Index $i -Ext $Ext
        $inStrTake = if ($inStrBraced -gt 0) { $inStrBraced } else { $n - $i }
        [void]$code.Append($s.Substring($i, $inStrTake))
        [void]$codeNoStr.Append((Get-BracedTokenCodeProjection -Text $s -Index $i -Length $inStrTake -Ext $Ext))
        $i += $inStrTake; continue
      }
      [void]$code.Append($ch)
      [void]$codeNoStr.Append($(if ($ch -eq $strCh) { $ch } else { ' ' }))
      if ($ch -eq $strCh) { $inStr = $false; $strCh = '' }
      $i++; continue
    }
    if ($hasBlock -and ($i + 1 -lt $n) -and $s.Substring($i, 2) -eq $blkOpen) {
      $fragSb = New-Object System.Text.StringBuilder
      $fragWasInBlock = $false
      $fragCodeBefore = ($code.ToString().Substring($fragMark).Trim().Length -gt 0)
      $lastCloseFragIndex = -1
      $InBlock = $true; $i += 2; continue
    }
    # A code-position ESCAPE is consumed with the character it escapes, BEFORE any
    # dispatch below can read that character as an opener. MEASURED against the
    # PowerShell tokenizer: `` `$ `` lexes as a Generic literal dollar, so
    # `` echo `${# note `` is a literal dollar, a plain `{`, and a REAL comment -- while
    # dispatching the braced-token branch on that escaped `$` consumed the comment as a
    # name and let the file certify as fully scanned. The support checker already
    # consumed the escape this way, so this is also what keeps them in agreement.
    if (($Ext -eq 'ps1' -and $ch -eq '`') -or ($Ext -eq 'sh' -and $ch -eq '\')) {
      $escTake = if ($i + 1 -lt $n) { 2 } else { 1 }
      $escSeg = $s.Substring($i, $escTake)
      [void]$code.Append($escSeg); [void]$codeNoStr.Append($escSeg)
      $i += $escTake; continue
    }
    # A `${...}` NAME is consumed whole, in ps1 and sh alike. Its body can hold the
    # comment marker (`${#x}` -- a legal PowerShell variable name, and the shell's
    # length expansion) or a quote (`${a"b}`), and reading those characters one at a
    # time opened a comment or a string the language does not. An UNCLOSED `${` takes
    # the rest of the record as code: whatever follows is inside a name, and it
    # certainly does not start a comment. The support checker refuses that record, so
    # nothing is ever scanned on the strength of this fallback.
    if (($Ext -eq 'ps1' -or $Ext -eq 'sh') -and $ch -eq '$' -and ($i + 1 -lt $n) -and [string]$s[$i + 1] -eq '{') {
      $bracedLen = Get-BracedVariableTokenLength -Text $s -Index $i -Ext $Ext
      $take = if ($bracedLen -gt 0) { $bracedLen } else { $n - $i }
      [void]$code.Append($s.Substring($i, $take))
      # The NUMERIC surface sees only a parsed literal operand -- see
      # Get-BracedTokenCodeProjection for why a parameter name is not a literal.
      [void]$codeNoStr.Append((Get-BracedTokenCodeProjection -Text $s -Index $i -Length $take -Ext $Ext))
      $i += $take; continue
    }
    if ($Ext -eq 'rs') {
      if (($i + 1 -lt $n) -and $s.Substring($i, 2) -eq '//') {
        $frags.Add(@{ Text = $s.Substring($i); WasInBlock = $false; CodeBefore = ($code.ToString().Substring($fragMark).Trim().Length -gt 0); CodeAfter = $false })
        $lastCloseFragIndex = -1
        [void]$comment.Append($s.Substring($i)); break
      }
    } else {
      if ($ch -eq '#') {
        $prev = if ($i -gt 0) { [string]$s[$i - 1] } else { '' }
        # toml: `#` anywhere outside a string is a comment; sh/ps1 accept line
        # start, whitespace, or a command separator before `#` (`cmd;# note` is
        # a real comment -- a separator starts a new word), while `$#` and a
        # word-embedded `a#b` stay code. (Codex BLOCKER: the
        # whitespace-only rule dropped separator-adjacent comments.) The
        # separator set is PER-LANGUAGE: sh gets only `;&|` because `(){}`
        # appear before `#` in WORD-INTERNAL expansion syntax (`${name}#suffix`,
        # `$(cmd)#suffix` -- code, not comments), while ps1 keeps `(){}` too
        # (`${x}#c` / `$(cmd)#c` / `(1+2)#c` all lex a Comment there, VERIFIED
        # against the PowerShell tokenizer); a shared class false-split the sh
        # expansions. `${#name}` reaches neither language's test -- the braced-name
        # consumption above takes it first, since it is a legal NAME in each. Read as a
        # ps1 comment here, it invented one inside a variable.
        # DELIBERATE tradeoff, and now a BOUNDED one: a real sh grouping-adjacent
        # comment (`(cmd)# n`) is still sacrificed to code here, because a word
        # suffix is the far more common shape and a false split would invent
        # findings from code -- but the support checker no longer CERTIFIES that
        # guess. It refuses the record, so the miss degrades the file loudly
        # instead of silently under-reporting it.
        # The ps1 side carries a parallel bounded miss, ADJUDICATED at the P6
        # port: a token-adjacent `$x=1# note` lexes as a Comment in PowerShell
        # but stays CODE here, because the boundary-character rule is what keeps
        # a word-embedded `a#b` (argument text) from becoming an invented
        # comment -- the package's prior any-position rule traded that invention
        # risk for the adjacency miss, and the port keeps this model's
        # asymmetry: a missed comment under-reports an ADVISORY scan, a false
        # split invents findings from code.
        # EACH LANGUAGE'S OWN SEPARATOR SET, MEASURED, never one class shared by both.
        # Under bash `echo a<U+00A0># text` prints the no-break space and the `#` alike:
        # the space is word content there, so the `#` continues the word. The PowerShell
        # tokenizer lexes that same shape as Identifier + Comment. A shared `\s` matches
        # U+00A0 and so certified a shell comment the language does not have, inventing
        # count claims out of ordinary word text.
        $sepClass = if ($Ext -eq 'sh') { '[ \t;&|]' } else { '[\s;&|(){}]' }
        $atCommentPos = ($i -eq 0 -or $prev -match $sepClass)
        if (($Ext -eq 'toml') -or $atCommentPos) {
          $frags.Add(@{ Text = $s.Substring($i); WasInBlock = $false; CodeBefore = ($code.ToString().Substring($fragMark).Trim().Length -gt 0); CodeAfter = $false })
          $lastCloseFragIndex = -1
          [void]$comment.Append($s.Substring($i)); break
        }
      }
    }
    if ($strChars -contains $ch) { $inStr = $true; $strCh = $ch; [void]$code.Append($ch); [void]$codeNoStr.Append($ch); $i++; continue }
    [void]$code.Append($ch); [void]$codeNoStr.Append($ch); $i++
  }
  # A block fragment still OPEN at EOL is emitted for THIS line (its
  # continuation on the next line arrives as a fresh carry-in fragment
  # there); it closed nothing, so it can carry no CodeAfter, and a later
  # fragment's open already cleared $lastCloseFragIndex for the same reason
  # -- trailing code became THAT fragment's CodeBefore.
  if ($null -ne $fragSb) {
    $frags.Add(@{ Text = $fragSb.ToString(); WasInBlock = $fragWasInBlock; CodeBefore = $fragCodeBefore; CodeAfter = $false })
    [void]$comment.Append($fragSb.ToString())
    $fragSb = $null
  }
  if ($lastCloseFragIndex -ge 0 -and $code.Length -gt $fragMark -and $code.ToString().Substring($fragMark).Trim().Length -gt 0) {
    $frags[$lastCloseFragIndex].CodeAfter = $true
  }
  return @{ Comment = $comment.ToString(); Code = $code.ToString(); CodeNoStrings = $codeNoStr.ToString(); InBlock = $InBlock; InString = $inStr; StrChar = $strCh; Fragments = $frags.ToArray() }
}

function Get-SourceSupportDiagnostic {
  # Is Get-SourceLineParts' comment/code split TRUSTWORTHY for this whole file?
  # $null when every record parses inside the POSITIVELY SUPPORTED grammar;
  # @{ Line; Construct } naming the first thing outside it.
  #
  # POSITIVE SUPPORT, not an unsupported table -- the same closure the assertion
  # class uses. An enumerated list of bad constructs is unbounded and was already
  # incomplete (nested block comments and the `cr`/`c` string prefixes were not on
  # it), and each miss is SILENT: a wrong cross-line carry reclassifies every LATER
  # record, so a comment can be read as code (its count never scanned) or a string
  # body read as a comment (a count INVENTED from string text). Listing what the
  # splitter provably handles and rejecting everything else cannot be silently
  # wrong -- an unforeseen construct fails the positive check by not being in it.
  #
  # What the splitter models, and therefore all this admits:
  #   * line comments -- `//` (rs), and a `#` at a comment position each language's own
  #     rule PROVES: line start or a separator in ps1, the start of a WORD in sh, and
  #     anywhere outside a string in toml. A `#` the rule cannot place is refused, not
  #     assumed to be code -- see the per-language note at that test.
  #   * block comments -- `/* */` (rs), `<# #>` (ps1), NON-NESTED: the model's state
  #     is a boolean, so a nested opener ends the comment early at the inner close.
  #   * plain strings with the ONE escape the model applies: `\` in rs, and a backtick
  #     in a DOUBLE-quoted ps1 string only -- single-quoted PowerShell has no BACKTICK
  #     escape, so a backtick is ordinary text there. It does escape a quote by
  #     DOUBLING it, which is a different rule the model does not apply and therefore
  #     refuses rather than mis-reading as close-then-reopen. A string form with any
  #     other escape rule is outside support.
  #   * a Rust string spanning records -- the one carry the model does implement. A
  #     line CONTINUATION is NOT carried, so a joined pair is admitted only where a
  #     SEPARATOR at the seam proves no token can cross it and no position predicate
  #     changes; every other join is REFUSED rather than guessed at. See the escape
  #     handler for why a list of dangerous joins could not close.
  #   * Rust char literals and lifetimes in the shapes that cannot open a string.
  #   * a single-level `${...}` NAME in ps1 and sh, consumed whole by this scan
  #     and the splitter, so a `#` or a quote INSIDE a name opens nothing.
  #
  # THE PREFIX RULE is what closes the set against forms nobody has enumerated: a
  # quote glued to a preceding identifier/`#`/`@`/`$`/quote character is a PREFIXED
  # string literal of some kind, and the splitter models exactly one string form.
  # `r"`, `b"`, `c"`, `br#"`, `cr#"`, `@"`, `@'`, `$'`, `"""` all fail by that one
  # rule, as would a prefix a future language version adds.
  #
  # This scan reads the RAW record text and keeps its own state, deliberately NOT
  # Get-SourceLineParts' output: consulting the split to decide whether the split is
  # trustworthy is the circularity that let a mis-lexed construct hide from its own
  # check. Where the two would disagree is exactly where this one refuses.
  param([object[]]$Records, [string]$Ext)
  if (-not $Records) { return $null }
  $hasBlock = ($Ext -eq 'rs' -or $Ext -eq 'ps1')
  $blkOpen = switch ($Ext) { 'rs' { '/*' } 'ps1' { '<#' } default { '' } }
  $blkClose = switch ($Ext) { 'rs' { '*/' } 'ps1' { '#>' } default { '' } }
  $strChars = if ($Ext -eq 'rs') { @('"') } else { @('"', "'") }
  $inBlock = $false; $inStr = $false; $strCh = ''
  # INDEXED, not foreach: the trailing-continuation test below has to read the NEXT
  # record's first character, which is one of the two seam characters its join proof
  # rests on.
  $recArr = @($Records)
  for ($ri = 0; $ri -lt $recArr.Count; $ri++) {
    $r = $recArr[$ri]
    $s = [string]$r.Text
    $n = $s.Length
    $i = 0
    # Where a consumed `${...}` ended on THIS record. Per-record because it is only
    # ever read at the character immediately after that token; any other consumption
    # moves past it, and a stale value from the previous record would answer for text
    # that never held one.
    $afterBraced = -1
    # The index of the character the LAST code-position escape consumed, per record for
    # the same reason. The continuation proof below reads the character before the
    # trailing escape, and an escaped character is WORD CONTENT rather than the
    # separator it looks like -- `echo a\ \` + newline keeps the escaped space inside
    # the word, so a following `#` stays word-internal while a raw-character seam test
    # would call the join proven. Nothing else consults it, and a stale value from the
    # previous record would answer for text that never held an escape.
    $escapedCharIndex = -1
    while ($i -lt $n) {
      $ch = [string]$s[$i]
      if ($inBlock) {
        if ($hasBlock -and ($i + 1) -lt $n) {
          $pair = $s.Substring($i, 2)
          if ($pair -eq $blkOpen) { return @{ Line = [int]$r.Line; Construct = 'a NESTED block comment' } }
          if ($pair -eq $blkClose) { $inBlock = $false; $i += 2; continue }
        }
        $i++; continue
      }
      if ($inStr) {
        # A SUBSTITUTION inside a double-quoted string opens a nested EXPRESSION
        # whose own text the model treats as opaque string body. That expression can
        # hold quotes, a `#`, or another string, any of which moves the boundary the
        # split depends on -- and modelling it means modelling the whole embedded
        # grammar, which is the fork this check exists to avoid. Refuse instead.
        # A ps1 backtick is the string ESCAPE (consumed below); an sh backtick in a
        # double-quoted string is command substitution, so only sh refuses on it.
        if ($strCh -eq '"' -and ($Ext -eq 'ps1' -or $Ext -eq 'sh')) {
          if ($ch -eq '$' -and ($i + 1) -lt $n -and [string]$s[$i + 1] -eq '(') {
            return @{ Line = [int]$r.Line; Construct = 'a `$(...)` substitution inside a quoted string' }
          }
          if ($Ext -eq 'sh' -and $ch -eq '`') {
            return @{ Line = [int]$r.Line; Construct = 'a backtick substitution inside a quoted string' }
          }
        }
        if ($Ext -eq 'rs' -and $ch -eq '\') { $i += 2; continue }
        # EXPANDABLE only, exactly as the splitter consumes it: a single-quoted
        # PowerShell string has no backtick escape, and consuming one there would
        # certify a split that had already run the string past its closing quote.
        if ($Ext -eq 'ps1' -and $strCh -eq '"' -and $ch -eq '`') { $i += 2; continue }
        # The braced NAME inside an EXPANDABLE string, consumed exactly as the
        # splitter consumes it -- its body is name text whose quotes are not
        # delimiters, so scanning it characterwise closes the string in the wrong
        # place and certifies a split that put name text on the code side. A
        # SINGLE-quoted string interpolates in neither language, so it is excluded.
        if ($strCh -eq '"' -and ($Ext -eq 'ps1' -or $Ext -eq 'sh') -and $ch -eq '$' -and ($i + 1) -lt $n -and [string]$s[$i + 1] -eq '{') {
          $inStrBraced = Get-BracedVariableTokenLength -Text $s -Index $i -Ext $Ext
          if ($inStrBraced -le 0) { return @{ Line = [int]$r.Line; Construct = 'a braced variable name inside a string that this model cannot read' } }
          $i += $inStrBraced; continue
        }
        # An escape the model does NOT apply ends the string in the wrong place.
        if ($ch -eq '\' -and ($Ext -eq 'toml' -or $Ext -eq 'sh') -and $strCh -eq '"') {
          return @{ Line = [int]$r.Line; Construct = 'a backslash escape inside a quoted string' }
        }
        if ($ch -eq $strCh) {
          # PowerShell escapes a quote by DOUBLING it; the model reads the pair as
          # close-then-reopen.
          if ($Ext -eq 'ps1' -and ($i + 1) -lt $n -and [string]$s[$i + 1] -eq $strCh) {
            return @{ Line = [int]$r.Line; Construct = 'a doubled-quote escape inside a string' }
          }
          $inStr = $false; $strCh = ''
        }
        $i++; continue
      }
      if ([char]::IsWhiteSpace($s[$i])) { $i++; continue }
      if ($hasBlock -and ($i + 1) -lt $n -and $s.Substring($i, 2) -eq $blkOpen) { $inBlock = $true; $i += 2; continue }
      if ($Ext -eq 'rs') {
        if (($i + 1) -lt $n -and $s.Substring($i, 2) -eq '//') { break }
        if ($ch -eq "'") {
          $lit = Get-RustQuoteTokenLength -Text $s -Index $i
          if ($lit -le 0) { return @{ Line = [int]$r.Line; Construct = 'a char literal this model cannot read' } }
          $i += $lit; continue
        }
      } else {
        if ($Ext -eq 'sh' -and ($i + 1) -lt $n -and $s.Substring($i, 2) -eq '<<') {
          return @{ Line = [int]$r.Line; Construct = 'a shell here-document' }
        }
        # An escape in CODE position matters when it suppresses a character the SPLIT
        # keys on, and INVENTING a comment is not the safe direction it was once
        # recorded as: the splitter's comment records feed a shared FENCE matcher, so a
        # fence-shaped invention (`#` + a backtick run) opens a code fence that
        # suppresses every genuine count finding after it, silently and with no
        # diagnostic. Both divergent shapes are therefore REFUSED rather than traded
        # away. Each is the exact case where the language keeps the `#` inside the
        # active word while this scan would place it at a comment position -- narrower
        # than refusing every escape, which would degrade tracked scripts for a defect
        # they do not have (MEASURED against the tree).
        #   IN-RECORD: an escaped SEPARATOR immediately before `#`. MEASURED --
        #     `printf '%s' a\ #b` prints `a #b` under sh, and the PowerShell tokenizer
        #     lexes `` echo a` #b `` as ONE CommandArgument `a #b`; a SECOND unescaped
        #     separator ends the word in both, and there the `#` really is a comment.
        #   CROSS-RECORD: a TRAILING escape, which is a LINE CONTINUATION. Its own rule
        #     is below, because that one is not a `#` question at all.
        if (($Ext -eq 'sh' -and $ch -eq '\') -or ($Ext -eq 'ps1' -and $ch -eq '`')) {
          # ABSENCE IS AN INDEX QUESTION, never an equality one. MEASURED: PowerShell
          # collates zero-weight code points away on BOTH `-eq` and `-ceq`, so
          # `([string][char]0xFEFF) -eq ''` and its `-ceq` twin are each True. A
          # `$nx -eq ''` test therefore read a record whose next character is U+FEFF or
          # a soft hyphen as having NO next character -- taking the trailing-escape
          # branch for text that continues, which is the one branch that certifies a
          # cross-record join. Character IDENTITY likewise goes through a regex class,
          # whose matching is by code point (MEASURED alongside the separator classes).
          $hasNext = (($i + 1) -lt $n)
          $nx = if ($hasNext) { [string]$s[$i + 1] } else { '' }
          if ($hasNext -and ($nx -cmatch '^[#"'']$')) {
            return @{ Line = [int]$r.Line; Construct = 'an escaped quote or comment marker in code position' }
          }
          if (-not $hasNext) {
            # A TRAILING escape is a LINE CONTINUATION: the language deletes the escape
            # and the newline and reads the two records as ONE logical line, while this
            # model reads each record on its own. The join is therefore a place where
            # the two readings can differ, and CERTIFYING it needs a PROOF that they do
            # not -- not a list of the joins known to be dangerous.
            #
            # A reject list was tried here and could not be closed. It named the one
            # shape then in hand (a next record opening with `#`) and admitted every
            # other token the seam can build: `<` + `<` becomes a here-document whose
            # body lines then read as comments, `$` + `'` becomes ansi-C quoting whose
            # backslash escapes this model does not apply, `<` + `#` becomes a
            # PowerShell block comment, and a quote glued to the previous word bypasses
            # the prefix rule entirely. Each of those turns string or here-document text
            # into a comment record, and a comment record shaped like a fence
            # (`# ~~~`) suppresses every later count finding in the file -- silently,
            # with the support scan reporting the file as fully supported.
            #
            # THE PROOF needs BOTH halves, and an earlier round shipped only the second.
            # A seam is safe when (1) the LANGUAGE guarantees a token boundary there, so
            # nothing can span the seam, AND (2) the MODEL reads the two sides at the
            # same position it would read them joined. Keying on the `#` classifier's
            # own class satisfied (2) and merely LOOKED like (1): that class is built
            # from `\s`, which matches code points the shell treats as ordinary word
            # content, so a seam could be certified where the language had no boundary
            # at all. An UNESCAPED separator drawn from the language's own set gives
            # both -- it terminates any word from the left and starts a fresh one on the
            # right, so the joined token stream from the next record's first character
            # is exactly the stream this model reads from that record's start, a `#`
            # there classifies identically either way, and a quote there fails the
            # prefix rule identically either way. An EMPTY next record (including end of
            # file) joins nothing and is inert for the same reason.
            #
            # Anything else -- a word character, a quote, `$`, `<`, `}` in sh, an
            # ESCAPED separator, or whitespace outside the language's own set -- leaves
            # a token able to cross, so the join is REFUSED. That refuses some joins
            # that would have read the same either way; the file's default is
            # UNPARSED-unless-proven, and an over-refusal costs one advisory row while
            # an over-acceptance costs a silently suppressed scan.
            $nextText = if (($ri + 1) -lt $recArr.Count) { [string]$recArr[$ri + 1].Text } else { '' }
            # THE SEPARATOR CLASS IS THE LANGUAGE'S, NOT THE `#` CLASSIFIER'S, and it is
            # deliberately NARROWER than that classifier's `\s`-based one. The proof
            # needs two things at once: a character that the LANGUAGE treats as a token
            # boundary (so no token can cross the seam) and one the MODEL reads as a
            # proven comment position (so the position predicate agrees). `\s` satisfies
            # only the second. MEASURED: .NET `\s` matches U+00A0, `[ \t]` does not --
            # and a no-break space is ordinary WORD content to the shell, whose blanks
            # are space and tab. A seam of U+00A0 was therefore certified while the join
            # kept a following `#` word-internal, which is the false-fence suppression
            # this whole branch exists to stop. The ASCII set below is a SUBSET of the
            # classifier's class, so agreement on the position predicate still holds by
            # construction, and anything outside it refuses rather than being judged.
            # PowerShell's own whitespace set is wider than ASCII; the narrow set is
            # used for both languages because over-refusal costs one advisory row.
            $joinSepClass = if ($Ext -eq 'sh') { '[ \t;&|]' } else { '[ \t;&|(){}]' }
            # An ESCAPED separator is not a separator: the escape pulls it into the
            # active word, so the join leaves a following `#` word-internal while a raw
            # look at the character says the seam is safe. Parity is read from the scan
            # that consumed the escape rather than re-derived here, so the two cannot
            # disagree. Absence is an INDEX test for the reason recorded above.
            $joinSeamEscaped = (($i - 1) -eq $escapedCharIndex)
            $joinSeamProven = ($i -eq 0) -or ((-not $joinSeamEscaped) -and (([string]$s[$i - 1]) -match $joinSepClass))
            $joinProven = ($nextText.Length -eq 0) -or $joinSeamProven -or (([string]$nextText[0]) -match $joinSepClass)
            if (-not $joinProven) {
              return @{ Line = [int]$r.Line; Construct = 'a line continuation whose join this model cannot prove leaves the record-wise reading unchanged' }
            }
          } elseif ((($i + 2) -lt $n) -and ([string]$s[$i + 2] -eq '#')) {
            # THE REFUSAL CLASS MIRRORS THE CLASSIFIER'S, character for character, and
            # the two ask opposite questions of it. A refusal keys on where the MODEL
            # would read a comment the language does not have: an ESCAPE pulls the
            # separator into the word, so the language continues the word while the
            # classifier -- which sees the separator itself and not the escape before
            # it -- calls the following `#` a comment. That record must degrade. The
            # proof class above keys on where the LANGUAGE guarantees a boundary, and
            # so requires the seam separator to be UNESCAPED; that, not a different
            # character set, is what separates the two.
            $escSep = if ($Ext -eq 'sh') { '[ \t;&|]' } else { '[\s;&|(){}]' }
            if ($nx -match $escSep) {
              return @{ Line = [int]$r.Line; Construct = 'a `#` after an ESCAPED separator, which the escape keeps inside the word' }
            }
          }
          # The character this escape consumed, for the seam-parity test above.
          $escapedCharIndex = $i + 1
          $i += 2; continue
        }
        # The `${...}` NAME, consumed whole exactly as the splitter consumes it, so the
        # `#` and quote characters a name may legally hold never reach the tests below.
        if (($Ext -eq 'ps1' -or $Ext -eq 'sh') -and $ch -eq '$' -and ($i + 1) -lt $n -and [string]$s[$i + 1] -eq '{') {
          $bracedLen = Get-BracedVariableTokenLength -Text $s -Index $i -Ext $Ext
          if ($bracedLen -le 0) { return @{ Line = [int]$r.Line; Construct = 'a braced variable name this model cannot read' } }
          $i += $bracedLen; $afterBraced = $i; continue
        }
        if ($ch -eq '#') {
          # THE COMMENT POSITION IS RECOGNIZED, NOT ASSUMED, and per language -- because
          # the splitter's shared preceding-character test is not either language's rule
          # and was wrong in each direction.
          #
          # PowerShell (VERIFIED against its own tokenizer): a `#` opens a comment
          # unless it CONTINUES an in-progress bareword, parameter or path token --
          # `$x=1#c`, `$x.y#c`, `$h[0]#c` and `"s"#c` all lex a Comment, while
          # `hi#there`, `-bar#c` and `.\s.ps1#c` lex one Generic/Parameter token. Which
          # of those applies depends on the token being scanned, not on one character
          # of lookbehind, so only the positions this model can PROVE are accepted --
          # line start and the separators, every one of which the tokenizer confirms
          # opens a comment -- and every other `#` is refused rather than read as code.
          # Reading it as code is precisely what let a staged claim vanish: the split
          # put the comment's text on the code side, the file then reported no added
          # comment lines, and the no-content path skipped it in silence.
          #
          # Shell: POSIX starts a comment only where the `#` begins a WORD, so a `#`
          # after an ordinary word character is provably word text (`x=1#c`,
          # `hi#there`) and needs no refusal. The ambiguity is confined to the
          # characters that OPEN a fresh command context in one reading and continue a
          # word in the other, and this model tracks neither nesting nor which of the
          # two a given character is:
          #   `(`/`)` -- MEASURED: `$(echo a)#b` prints `a#b` (word suffix) while
          #     `(echo a)# note` prints `a` (comment).
          #   backtick -- MEASURED: an OPENING one starts a command list, so
          #     ``x=`# note`` + newline + ``echo inner` `` runs `echo inner` with the
          #     `# note` swallowed as a comment, while a CLOSING one ends a word, so
          #     ``echo `echo a`#b`` prints `a#b`. Both spellings put the same
          #     character before the `#`.
          #   `<`/`>` -- the process-substitution openers, whose `(` this same rule
          #     already covers.
          # A `#` immediately after a consumed `${...}` is the one such position that
          # IS decidable: the expansion is part of the word, so the `#` continues it.
          if ($Ext -eq 'toml') { break }
          $prev = if ($i -gt 0) { [string]$s[$i - 1] } else { '' }
          $sepClass = if ($Ext -eq 'sh') { '[ \t;&|]' } else { '[\s;&|(){}]' }
          if (($i -eq 0) -or ($prev -match $sepClass)) { break }
          if ($Ext -eq 'sh') {
            if ($i -eq $afterBraced) { $i++; continue }
            if ($prev -notmatch '[(){}<>`]') { $i++; continue }
            return @{ Line = [int]$r.Line; Construct = 'a `#` after a shell grouping or substitution character, where a comment and a word suffix are indistinguishable' }
          }
          return @{ Line = [int]$r.Line; Construct = 'a `#` in a position this model cannot classify as comment or code' }
        }
      }
      if ($strChars -contains $ch) {
        $prev = if ($i -gt 0) { [string]$s[$i - 1] } else { '' }
        if ($prev -cmatch '[\w#@$"'']') {
          # A PREFIX is admitted only when it leaves the string's own rules alone.
          # Rust's `b"..."` and `c"..."` terminate at `"` and escape with `\` exactly
          # as a plain string does, so the model reads them correctly. `r`/`br`/`cr`
          # do NOT (raw strings have no escapes and `#`-delimited ends), `@`/`$`
          # introduce here-strings and ansi-C quoting, a quote after a quote is a
          # triple-quote or doubled-quote form, and an UNKNOWN prefix is refused
          # because nothing here can know its rules -- which is what keeps the accept
          # list bounded and the refusal open-ended.
          $why = if ($prev -ceq '@' -or $prev -ceq '$') { 'a here-string or ansi-C string opener' }
                 elseif ($prev -ceq '"' -or $prev -ceq "'") { 'a triple-quoted or doubled-quote string form' }
                 else { 'a quote glued to the preceding token (a prefixed literal, or an apostrophe inside a word)' }
          if ($Ext -eq 'rs' -and $prev -cmatch '\w') {
            $j = $i - 1
            while ($j -ge 0 -and ([char]::IsLetterOrDigit($s[$j]) -or $s[$j] -eq '_')) { $j-- }
            $pfx = $s.Substring($j + 1, $i - $j - 1)
            $before = if ($j -ge 0) { [string]$s[$j] } else { '' }
            if (($pfx -ceq 'b' -or $pfx -ceq 'c') -and $before -notmatch '[\w#@$"'']') {
              $inStr = $true; $strCh = $ch; $i++; continue
            }
          }
          return @{ Line = [int]$r.Line; Construct = $why }
        }
        $inStr = $true; $strCh = $ch; $i++; continue
      }
      $i++
    }
    # A string still open at end of record: the model CARRIES that state, and only a
    # Rust string is a form it carries correctly. Elsewhere the carry is the symptom
    # of a construct read wrong -- not a claim that those languages lack multi-line
    # strings (TOML triple-quoted and PowerShell here-strings are perfectly legal;
    # this model simply does not implement them, which is why they are refused above).
    if ($inStr -and $Ext -ne 'rs') { return @{ Line = [int]$r.Line; Construct = 'a quote left open at end of line' } }
  }
  return $null
}

function Get-ShellParameterExpansionMatch {
  # Parse a shell `${...}` POSITIVELY against the parameter-expansion productions,
  # returning @{ Length; WordStart; WordLength } or $null when no production matches.
  #
  # THIS REPLACES A BLACKLIST, and the replacement is the point. The previous rule
  # named the openers it knew were hazardous and accepted everything else, so every
  # round either removed an entry to stop a false positive or added one to stop a
  # false negative, and the next unmodelled construct arrived on schedule --
  # `<(`/`>(` process substitution being the one that finally landed. A blacklist
  # cannot be enumerated, and deciding by exclusion also contradicted this file's own
  # default-UNPARSED architecture, where silence requires POSITIVE recognition.
  #
  # The productions, which are the whole accept space:
  #   ${name} ${1} ${@} ${*} ${#} ${?} ${-} ${$} ${!}   parameter, positional, special
  #   ${#name}                                          length
  #   ${name-w} ${name=w} ${name?w} ${name+w}           default/assign/error/alternate
  #   ${name:-w} ${name:=w} ${name:?w} ${name:+w}       the colon-null variants
  #   ${name#p} ${name##p} ${name%p} ${name%%p}         prefix/suffix removal
  #   ${name/p/r} ${name//p/r} ${name/#p/r} ${name/%p/r} replacement
  #   ${name:off} ${name:off:len}                       substring
  #   ${name[@]} ${name[*]} ${name[i]}                  array subscript
  # An OPERAND (word, pattern, replacement) is a run of characters that can open
  # nothing: no `$`, backtick, quote, backslash, brace, `<` or `>`. A bare
  # parenthesis stays admissible because it opens nothing on its own -- process
  # substitution needs `<(`/`>(`, whose `<`/`>` the operand class already excludes,
  # and command substitution needs `$(`, whose `$` it excludes.
  #
  # Anything else -- `${x@Q}`, `$'...'`, an arithmetic body, a construct no one has
  # thought of yet -- matches no production and is refused BY DEFAULT rather than by
  # enumeration. That is the property the blacklist could never have.
  #
  # WordStart/WordLength locate the one operand whose text is a literal VALUE -- the
  # default/assign/alternate word. Patterns, offsets, subscripts and the parameter name
  # are not values, so callers that read code literals must not see them: `${3}` names
  # positional parameter 3 and is not the number 3. The ERROR word is excluded one step
  # further along the same rule: it is never the expansion's value at all.
  param([string]$Text, [int]$Index)
  $s = [string]$Text
  $n = $s.Length
  if ($Index -lt 0 -or ($Index + 1) -ge $n) { return $null }
  if ([string]$s[$Index] -ne '$' -or [string]$s[$Index + 1] -ne '{') { return $null }
  # THE FIRST `}` IS THE ONLY CANDIDATE TERMINATOR, and that follows from the grammar
  # rather than from convenience: every operand class excludes `{}`, and no literal
  # part of a production holds one, so a body reaching a LATER `}` necessarily
  # contains the earlier one and can match nothing. A retry scan over the later
  # braces was written and REMOVED (2026-08-03): a body containing an earlier
  # terminator cannot match the grammar. Reintroducing a retry requires a
  # brace-bearing production first; otherwise the retry is unreachable.
  $close = $s.IndexOf('}', $Index + 2)
  if ($close -lt 0) { return $null }
  $body = $s.Substring($Index + 2, $close - ($Index + 2))
  $m = $script:ShellParamExpansionPattern.Match($body)
  if (-not $m.Success) { return $null }
  $wordStart = -1
  $wordLength = 0
  # THE ERROR OPERAND IS NOT A VALUE. POSIX `${name:?word}` never expands to `word`: the
  # shell writes it to stderr and exits, so that operand is a DIAGNOSTIC MESSAGE, while
  # `-`, `=` and `+` each really do yield theirs. One capture shared across all four put
  # prose on the numeric surface, where `: "${ICONS:?expected 3 icons}"` minted the
  # constant 3 and let the code-echo exemption suppress an adjacent count finding.
  if ($m.Groups['word'].Success -and ([string]$m.Groups['wordop'].Value -ne '?')) {
    $wordStart = $Index + 2 + $m.Groups['word'].Index
    $wordLength = $m.Groups['word'].Length
  }
  return @{ Length = ($close - $Index + 1); WordStart = $wordStart; WordLength = $wordLength }
}

function Get-BracedTokenCodeProjection {
  # The length-preserving rendering of a `${...}` token for the NUMERIC surface.
  #
  # Only a value operand that is ITSELF a whole numeric literal survives; the parameter
  # name, patterns, offsets, subscripts and every mixed word are blanked. The
  # distinction is the whole point: `${3}` names positional parameter 3 and is not the
  # literal 3, so leaving it visible let the code-echo exemption suppress an adjacent
  # `# there are 3 icons` claim -- while `${x:-3}` really does carry the constant 3 that
  # such a comment may describe.
  # A ps1 braced variable is opaque NAME text throughout, so it blanks entirely.
  param([string]$Text, [int]$Index, [int]$Length, [string]$Ext)
  $keepStart = -1
  $keepLength = 0
  if ($Ext -eq 'sh') {
    $m = Get-ShellParameterExpansionMatch -Text $Text -Index $Index
    if ($null -ne $m -and [int]$m.Length -eq $Length -and [int]$m.WordStart -ge 0) {
      # THE WHOLE OPERAND MUST BE THE NUMBER, not merely contain one. A default word is
      # an arbitrary shell word, so `${name:-3-icons}` carries the STRING `3-icons`;
      # preserving it verbatim let the numeric extractor lift the `3` out of the middle
      # and mint a literal the file does not contain, which is enough to exempt an
      # adjacent count comment from its finding. The accepted shape is anchored to the
      # one the numeric surface itself recognizes, so what survives here is exactly what
      # a bare literal would have been.
      $keepWord = $Text.Substring([int]$m.WordStart, [int]$m.WordLength)
      if ($keepWord -match '^\d+(?:\.\d+)?$') {
        $keepStart = [int]$m.WordStart
        $keepLength = [int]$m.WordLength
      }
    }
  }
  $sb = New-Object System.Text.StringBuilder
  for ($k = 0; $k -lt $Length; $k++) {
    $abs = $Index + $k
    $inWord = ($keepStart -ge 0 -and $abs -ge $keepStart -and $abs -lt ($keepStart + $keepLength))
    if ($inWord) { [void]$sb.Append($Text[$abs]) } else { [void]$sb.Append(' ') }
  }
  return $sb.ToString()
}

function Get-BracedVariableTokenLength {
  # Length of the `${...}` token at $Index, or 0 when this model cannot read it.
  #
  # `${...}` holds characters that steer the comment/string split from inside a token
  # that is neither a comment nor a string -- `${#x}` holds the comment marker, `${a"b}`
  # a quote -- so consuming the whole token is what keeps a name from being read as the
  # construct one of its characters would otherwise open.
  #
  # THE LANGUAGES ARE DIFFERENT GRAMMARS AND ARE MODELLED SEPARATELY. Treating them
  # as one was wrong for the shell in a way that certified a false split:
  #
  #   ps1 -- a braced variable NAME is OPAQUE text terminated by the first unescaped
  #     `}`, with a backtick escape. MEASURED against the PowerShell tokenizer:
  #     `${a$(b)}`, `${a"b}`, `${env:PATH}` and `${a`}b}` each lex as ONE Variable token,
  #     so nothing inside a name opens a nested construct and scanning to that `}` is
  #     exact. `${a${b}}` is a PARSE ERROR there (one Variable plus a stray closer), so
  #     a nested opener is refused rather than guessed at.
  #
  #   sh -- a parameter expansion is a WORD, and its operands can carry the very
  #     characters a hazard list would key on, so the body is PARSED against the
  #     productions rather than scanned for hazards: see
  #     Get-ShellParameterExpansionMatch, which owns that grammar and refuses
  #     everything it does not match.
  #
  # ZERO for everything outside those models, never a guess -- including a token
  # that does not close on this record, since the model carries no multi-record name.
  # The caller turns zero into a refusal or into an end-of-record code run, per its own
  # contract.
  param([string]$Text, [int]$Index, [string]$Ext)
  $s = [string]$Text
  $n = $s.Length
  if ($Index -lt 0 -or ($Index + 1) -ge $n) { return 0 }
  if ([string]$s[$Index] -ne '$' -or [string]$s[$Index + 1] -ne '{') { return 0 }
  if ($Ext -ne 'ps1' -and $Ext -ne 'sh') { return 0 }
  if ($Ext -eq 'sh') {
    $shMatch = Get-ShellParameterExpansionMatch -Text $s -Index $Index
    if ($null -eq $shMatch) { return 0 }
    return [int]$shMatch.Length
  }
  $j = $Index + 2
  while ($j -lt $n) {
    $c = [string]$s[$j]
    if ($c -eq '`') { $j += 2; continue }
    if ($c -eq '$' -and ($j + 1) -lt $n -and [string]$s[$j + 1] -eq '{') { return 0 }
    if ($c -eq '}') { return ($j - $Index + 1) }
    $j++
  }
  return 0
}

function Get-RustQuoteTokenLength {
  # Length of the `'`-introduced token at $Index when the comment splitter can pass
  # over it safely, or 0 when it cannot.
  #
  # CLOSED SHAPES, and a refusal for everything else. Each job Rust gives `'`
  # has a bounded form:
  #   LIFETIME / label -- `'ident`, with NO closing quote expected.
  #   CHAR literal     -- `'x'`, or `'\<escape>'` whose body is bounded by the escape
  #                       grammar (`\n`, `\\`, `\'`, `\xNN`, `\u{...}`).
  # Scanning forward to the NEXT apostrophe instead was the defect: with a lifetime
  # and a later char literal on one line, `&'a T` + `'x'` bridged into one token and
  # the scan resumed in the middle of the source, past whatever lay between. A form
  # outside both shapes is refused rather than spanned -- the same closure the rest
  # of this check uses.
  # `"` inside the literal is what actually breaks the splitter (`'` is not a string
  # delimiter in its Rust half, so the quote reaches code position and opens a string
  # that never closes), which is why the accepted bodies exclude it.
  param([string]$Text, [int]$Index)
  $n = $Text.Length
  $c1 = if (($Index + 1) -lt $n) { $Text[$Index + 1] } else { [char]0 }
  # LIFETIME: `'` + identifier NOT followed by a closing quote.
  if ([char]::IsLetter($c1) -or $c1 -eq '_') {
    $k = $Index + 1
    while ($k -lt $n -and ([char]::IsLetterOrDigit($Text[$k]) -or $Text[$k] -eq '_')) { $k++ }
    if ($k -ge $n -or $Text[$k] -ne "'") { return $k - $Index }
  }
  # CHAR literal, plain body: one character that is neither a quote nor an escape.
  if ($c1 -ne [char]0 -and $c1 -ne '"' -and $c1 -ne "'" -and $c1 -ne '\') {
    if (($Index + 2) -lt $n -and $Text[$Index + 2] -eq "'") { return 3 }
    return 0
  }
  # CHAR literal, ESCAPED body -- bounded by the escape's own grammar.
  if ($c1 -eq '\') {
    $c2 = if (($Index + 2) -lt $n) { $Text[$Index + 2] } else { [char]0 }
    if ($c2 -eq '"') { return 0 }
    if ($c2 -eq 'x') {
      if (($Index + 5) -lt $n -and ([string]$Text.Substring($Index + 3, 2)) -match '^[0-9A-Fa-f]{2}$' -and $Text[$Index + 5] -eq "'") { return 6 }
      return 0
    }
    if ($c2 -eq 'u') {
      $m = [regex]::Match($Text.Substring($Index + 2), "^u\{[0-9A-Fa-f_]{1,6}\}'")
      if ($m.Success) { return 2 + $m.Length }
      return 0
    }
    if ($c2 -ne [char]0 -and ($Index + 3) -lt $n -and $Text[$Index + 3] -eq "'") { return 4 }
    return 0
  }
  return 0
}

function Get-SourceCommentRecords {
  # Block-aware pass over a source file's line records -> comment-text records
  # @{ Line; Text=<NORMALIZED comment portion> } (only lines with non-blank
  # comment text). The block state carries across lines so a multi-line `/* */` /
  # `<# #>` body is scanned. The leading LINE-comment marker (`//`/`///`/`//!` or
  # `#`/`##`) is stripped from each record so (a) the shared fence matcher can see
  # a comment-prefixed code fence (`// ```` -> `` ``` ``) and (b) the reported
  # match is the prose, not the delimiter. (Codex TEST-QUALITY:
  # the un-normalized `//` prefix hid comment fences from Get-FencedLineFlags.)
  param([object[]]$Records, [string]$Ext)
  $out = @()
  if (-not $Records) { return $out }
  $inBlock = $false; $inStr = $false; $strCh = ''
  # A BLANK fragment (`/**/`, `<##>`, an empty block tail) is never emitted,
  # but it can OWN a boundary: its code flags say code lay between its
  # emitted neighbors, and dropping them with the fragment retained a later
  # claim under an earlier fence. The carry folds a discarded fragment's
  # flags into the NEXT emitted record's CodeBefore -- across lines too,
  # since a line may end on a blank code-flanked fragment.
  $carryCode = $false
  foreach ($r in $Records) {
    $parts = Get-SourceLineParts -Line ([string]$r.Text) -Ext $Ext -InBlock $inBlock -InString $inStr -StrChar $strCh
    $inBlock = [bool]$parts.InBlock
    $inStr = [bool]$parts.InString; $strCh = [string]$parts.StrChar
    # ONE record per comment FRAGMENT, not per line: a line can hold a block
    # tail, code, and a fresh comment (`*/ let x = 1; // note`), and merging
    # them lost both the fragment boundary and the code between -- the
    # segmenter then rode fence state across real code. Each fragment carries
    # WasInBlock (carry-in continuation -- no code can precede it on its
    # line) and CodeBefore/CodeAfter (non-whitespace code positioned between
    # this fragment and its same-line neighbors); see Get-StagedSourceFindings
    # for the boundary rule they feed.
    foreach ($frag in @($parts.Fragments)) {
      if ([string]::IsNullOrWhiteSpace([string]$frag.Text)) {
        $carryCode = $carryCode -or [bool]$frag.CodeBefore -or [bool]$frag.CodeAfter
        continue
      }
      # Strip a leading line-comment marker (+ one space) so a `// ```` fence line
      # normalizes to `` ``` `` and the fence matcher recognizes it. A block-comment
      # fragment carries no per-line MARKER, but the conventional doc-block
      # continuation `*` (` * text` inside `/** */`) plays the same role --
      # normalize it on carry-in fragments (never `*/`, which the splitter
      # consumes) so a ` * ```` fence line is recognized too. (Codex QUALITY: the
      # leading `*` hid block-doc fences from Get-FencedLineFlags.)
      $txt = [string]$frag.Text -replace '^\s*(?://+!?|#+)\s?', ''
      if ([bool]$frag.WasInBlock) { $txt = $txt -replace '^\s*\*+(?!/)\s?', '' }
      $out += @{ Line = [int]$r.Line; Text = $txt; WasInBlock = [bool]$frag.WasInBlock; CodeBefore = ([bool]$frag.CodeBefore -or $carryCode); CodeAfter = [bool]$frag.CodeAfter }
      $carryCode = $false
    }
  }
  # Return the plain array; every caller wraps with @() so a 0/1-element result
  # normalizes correctly (a `,$out` wrapper double-nests under the caller's @()).
  return $out
}

function Get-SourceCodeNumbersByLine {
  # Per-LINE standalone numeric literals -- integer or decimal, keyed by the FULL
  # token string ("223", "0.25") -- on the CODE portions of a source file
  # (block-aware): a hashtable Line -> { token-string -> $true }. The source-comment code-echo
  # exemption keys on this so it can require the echoing literal to be NEARBY the
  # comment (see Get-StagedSourceFindings), not merely present somewhere in the
  # file. (Codex QUALITY: a whole-file digit set let an UNRELATED
  # constant/string/identifier elsewhere in the file silently exempt a stale
  # comment -- the exemption must be local, "same line or nearby changed hunk".)
  param([object[]]$Records, [string]$Ext)
  $byLine = @{}
  if (-not $Records) { return $byLine }
  $inBlock = $false; $inStr = $false; $strCh = ''
  foreach ($r in $Records) {
    $parts = Get-SourceLineParts -Line ([string]$r.Text) -Ext $Ext -InBlock $inBlock -InString $inStr -StrChar $strCh
    $inBlock = [bool]$parts.InBlock
    $inStr = [bool]$parts.InString; $strCh = [string]$parts.StrChar
    $s = @{}
    # STANDALONE numeric literals -- integer OR decimal, keyed by the NUMERIC
    # token ("223", "0.25"): a digit run adjacent to a word char or a QUOTE is
    # part of an identifier / string (`ICON_223_NAME`, `"223"`, `"v223"`,
    # `v1.2`), and a `$`-, brace-, or sign-prefixed run (`$2`/`${2}` shell
    # positional / ps1 variable, `-2`/`+2` signed) is not the adjacent POSITIVE
    # literal the exemption describes -- none of those populate the echo set
    # (a rare brace-adjacent real literal only leaves the advisory STANDING --
    # the safe direction -- while a false echo would silently drop findings). A Rust TYPE
    # SUFFIX (`3usize`, `0.25f32`) is stripped so the literal enters under its
    # numeric key. Full-token keys mean a "223" comment claim never matches a
    # `0.223` code literal (or vice versa), while `// took 0.25` beside
    # `= 0.25` CAN exempt, per the documented adjacent-literal exemption.
    # (Codex QUALITY findings, layered: identifier digits, then
    # quoted-string digits, then decimal support, then `$`/sign
    # false-echo + suffixed-literal misses.)
    # Extraction reads the STRING-BLANKED rendering, so a quoted number is text.
    # RADIX and `_`-separated spellings are RUST-ONLY, and the reason is the CONSUMER,
    # not the grammar: only the `rs` path normalizes a token to a VALUE
    # (ConvertFrom-RustIntLiteral), so only there can `0x3` exempt a comment saying
    # three. Every other extension compares the token as a STRING against the plain
    # decimal a comment yields, and no radix or `_`-bearing token can ever equal one
    # -- capturing it would add a key nothing can look up. (A `0x`/`_` spelling is
    # legal TOML and PowerShell; per-language token regexes shipped for that reason
    # and were removed on measuring that nothing consumes them.) So the value rule
    # stays Rust-only, and no language's text is reinterpreted through another's.
    $numRx = if ($Ext -eq 'rs') {
      '(?<![\w."''$+{-])(0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d+)?)(?:[iu](?:8|16|32|64|128|size)|f32|f64)?(?![\w."''])'
    } else {
      '(?<![\w."''$+{-])(\d+(?:\.\d+)?)(?![\w."''])'
    }
    foreach ($m in ([regex]::Matches([string]$parts.CodeNoStrings, $numRx))) { $s[$m.Groups[1].Value] = $true }
    $byLine[[int]$r.Line] = $s
  }
  return $byLine
}

function Split-NulSeparatedList {
  # Split git's `-z` output into a RECORD:
  # @{ Valid = [bool]; Paths = [string[]]; Fields = [string[]] }.
  # `-z` is what makes the list trustworthy: the default `--name-only` C-QUOTES a path
  # carrying non-ASCII or control bytes (`"a\303\251.md"`), and a quoted name matches
  # neither the narrative-doc nor the source extension pattern, so such a file was
  # dropped from the scan without a word. NUL separation carries the bytes verbatim,
  # so no unquoting is needed and none is guessed at.
  #
  # $Text is ONE raw string, never a line-record array: a NUL record may itself
  # contain CR or LF (both are legal in a POSIX filename), and any reader that splits
  # git's stdout into lines first has already cut such a name into two paths that
  # neither exist. NOTHING here trims -- a leading or trailing whitespace character is
  # part of the pathname, not framing.
  #
  # `-z` TERMINATES every record, so a nonempty payload MUST end in NUL. One that does
  # not was truncated in transit, and its final record is a PREFIX of a real pathname
  # -- silently accepting it scans a path that does not exist while the real one goes
  # unscanned. (Codex BLOCKER.)
  #
  # A RECORD rather than a bare array or $null, because PowerShell UNROLLS an empty
  # array on return: a legitimately EMPTY listing -- a deletion-only staged commit
  # selects no governed-status file -- came back as $null and was indistinguishable from the
  # truncated-framing signal, so the fail-loud guard aborted a commit that had nothing
  # to scan. Validity and content are separate fields precisely so no value can carry
  # both meanings. (Codex BLOCKER.)
  # `Fields` carries EVERY field the payload actually held, with exactly the ONE
  # terminator-produced trailing empty removed -- so an interior or doubled NUL survives
  # to the consumer that must reject it. `Paths` keeps its filtered shape for the plain
  # listing consumers, which want pathnames rather than framing evidence; a reader that
  # validates framing takes `Fields`, since dropping every empty NORMALIZES a corrupted
  # payload into a well-formed-looking one and resynchronizes the walk on the next field.
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return @{ Valid = $true; Paths = @(); Fields = @() } }
  if ($Text[$Text.Length - 1] -ne [char]0) { return @{ Valid = $false; Paths = @(); Fields = @() } }
  $parts = @($Text -split "`0")
  $fields = @($parts[0..($parts.Count - 2)])
  return @{ Valid = $true; Paths = @($parts | Where-Object { $_ -ne '' }); Fields = $fields }
}

function ConvertTo-ProcessArgumentList {
  # Quote the arguments Start-Process will JOIN with spaces.
  #
  # Start-Process quotes nothing, so an argument holding whitespace -- a repo path
  # with a space, which git does NOT C-quote and so arrives bare -- would reach the
  # child as two arguments. A trailing backslash run is DOUBLED inside the quotes, or
  # the last one would escape the closing quote and swallow the argument boundary.
  # An embedded double quote is out of scope: every argument here is a literal git
  # flag or a filesystem path, and a Windows pathname cannot contain one. A git INDEX
  # path is the one shape that can, and those are refused before they reach any argv
  # -- see Test-IsArgvRepresentablePath.
  param([string[]]$Arguments)
  return @(@($Arguments) | ForEach-Object {
    $a = [string]$_
    if ($a -match '\s') { '"' + ($a -replace '(\\+)$', '$1$1') + '"' } else { $a }
  })
}

# Start-Process on Windows PowerShell 5.1 rejects a raw process environment
# carrying both Path and PATH. Preserve effective lookup order first,
# append raw-only directories, then collapse to one verified canonical entry.
function Get-PrependedToolPathParts {
  param([string[]]$CandidateDirs, [string]$CurrentPath)
  $parts = New-Object 'System.Collections.Generic.List[string]'
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  if ($CandidateDirs) {
    foreach ($c in $CandidateDirs) {
      if (-not [string]::IsNullOrWhiteSpace($c) -and $seen.Add($c)) { [void]$parts.Add($c) }
    }
  }
  foreach ($p in (($CurrentPath -split [System.IO.Path]::PathSeparator))) {
    if (-not [string]::IsNullOrWhiteSpace($p) -and $seen.Add($p)) { [void]$parts.Add($p) }
  }
  return ,$parts.ToArray()
}

function Get-ProcessPathSpellings {
  $EnvEntries = [Environment]::GetEnvironmentVariables('Process')
  $EffectivePath = [Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::Process)
  $out = New-Object 'System.Collections.Generic.List[string]'
  $seenValues = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  if (-not [string]::IsNullOrEmpty($EffectivePath) -and $seenValues.Add($EffectivePath)) {
    [void]$out.Add($EffectivePath)
  }
  $rawMatches = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([System.StringComparer]::Ordinal)
  foreach ($k in @($EnvEntries.Keys)) {
    $name = [string]$k
    if ([string]::Equals($name, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)) {
      $rawMatches[$name] = [string]$EnvEntries[$k]
    }
  }
  foreach ($entry in $rawMatches.GetEnumerator()) {
    $v = [string]$entry.Value
    if (-not [string]::IsNullOrEmpty($v) -and $seenValues.Add($v)) { [void]$out.Add($v) }
  }
  return ,$out.ToArray()
}

function Get-UnionProcessPathParts {
  param([string[]]$Spellings, [string[]]$CandidateDirs = @())
  $joined = (@($Spellings) | Where-Object { -not [string]::IsNullOrEmpty($_) }) -join [System.IO.Path]::PathSeparator
  return Get-PrependedToolPathParts -CandidateDirs $CandidateDirs -CurrentPath $joined
}

function Set-CanonicalProcessPathEnvironment {
  param([Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Value)
  while ($true) {
    $before = [Environment]::GetEnvironmentVariables('Process')
    $beforeKeys = @($before.Keys | Where-Object {
      [string]::Equals([string]$_, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($beforeKeys.Count -eq 0) { break }
    $removeName = [string]$beforeKeys[0]
    [Environment]::SetEnvironmentVariable($removeName, $null, [EnvironmentVariableTarget]::Process)
    $afterRemoval = [Environment]::GetEnvironmentVariables('Process')
    $afterCount = @($afterRemoval.Keys | Where-Object {
      [string]::Equals([string]$_, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)
    }).Count
    if ($afterCount -ge $beforeKeys.Count) {
      throw [System.InvalidOperationException]::new("could not remove inherited PATH spelling '$removeName'")
    }
  }
  [Environment]::SetEnvironmentVariable('Path', $Value, [EnvironmentVariableTarget]::Process)
  $final = [Environment]::GetEnvironmentVariables('Process')
  $finalKeys = @($final.Keys | Where-Object {
    [string]::Equals([string]$_, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)
  })
  if ($finalKeys.Count -ne 1 -or [string]$finalKeys[0] -cne 'Path' -or
      -not [string]::Equals([string]$final['Path'], $Value, [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new("canonical Path postcondition failed (raw spelling count=$($finalKeys.Count))")
  }
}

function Normalize-ProcessPathEnvForStartProcess {
  $pathParts = Get-UnionProcessPathParts -Spellings (Get-ProcessPathSpellings)
  if ($pathParts.Count -eq 0) { throw [System.InvalidOperationException]::new('no non-empty process PATH value is available to normalize') }
  Set-CanonicalProcessPathEnvironment -Value ([string]::Join([System.IO.Path]::PathSeparator, $pathParts))
}

function Test-IsArgvRepresentablePath {
  # Can this pathname cross the NATIVE ARGV boundary every git child here crosses?
  #
  # The precondition above rests on "a Windows pathname cannot contain a double quote".
  # That is true of a Windows FILESYSTEM path and false of a git INDEX path: git stores
  # a byte string, a quote is legal in it, and such an entry reaches this script from a
  # clone or from `update-index` without ever being checked out. Windows argv parsing
  # then reads that quote as a quoting toggle, so a selector built from the path names a
  # DIFFERENT entry -- a clean scan over the wrong blob, while every diagnostic still
  # prints the original path.
  #
  # REFUSAL, not a cleverer encoder. Lossless Windows quoting is a second escaping
  # grammar to get right, and the cost of getting it wrong is precisely the silent
  # wrong-blob scan this predicate exists to stop; a path that cannot even be checked
  # out on the platform this linter runs on does not earn that surface.
  param([string]$Path)
  return (-not ([string]$Path).Contains('"'))
}

function Select-UniqueOrdinalPaths {
  # De-duplicate and sort a path list by ORDINAL comparison.
  #
  # UNIQUENESS is the correctness half. A git pathname is a byte string, so ANY
  # culture-aware comparison can merge two tracked files and drop one from the scan
  # without a word. `Sort-Object -Unique` is case-insensitive, and `-CaseSensitive`
  # fixes only the case axis -- the comparison stays CULTURE-aware, so a composed
  # `café` and its decomposed `cafe` + combining accent still compare equal even
  # though git holds two distinct byte sequences. Ordinal equality is exactly
  # sequence equality, so it answers the question git asks.
  #
  # ORDER is only DETERMINISM, and the claim must not be overstated: ordinal compares
  # UTF-16 CODE UNITS, which is NOT git's byte order. The two agree across the BMP but
  # diverge above it -- a supplementary character encodes as a surrogate pair in the
  # D800-DFFF range and so sorts BELOW U+E000-U+FFFF here, while its UTF-8 bytes sort
  # above. Nothing downstream depends on matching git's order; what it depends on is
  # the same input yielding the same scan order every run, which ordinal gives.
  param([string[]]$Paths)
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $kept = New-Object 'System.Collections.Generic.List[string]'
  foreach ($p in @($Paths)) {
    $s = [string]$p
    if ($seen.Add($s)) { [void]$kept.Add($s) }
  }
  $kept.Sort([System.StringComparer]::Ordinal)
  return ,@($kept.ToArray())
}

function Read-NulTextFile {
  # A `-z` payload file read into @{ Present; Valid; Text }. The answers the caller
  # must keep apart, which is why this is a record and not a string:
  #   Present=$false          -- the file is ABSENT: the redirection produced nothing
  #                              despite a zero exit. Reading that as '' let a failed
  #                              redirect scan nothing and report clean, the exact
  #                              false-clean the fail-loud git wrapper exists to
  #                              prevent. (Codex BLOCKER.)
  #   Present, Valid, Text='' -- an EMPTY file, a real git answer (nothing staged).
  #   Valid=$false            -- the bytes are not valid UTF-8. Text is $null: there
  #                              is no faithful string to hand on, and substituting a
  #                              replacement-character one would silently merge
  #                              distinct pathnames.
  #
  # DECODE THE BYTES, never ReadAllText: this file holds git's `-z` output, which is
  # raw pathname bytes in a format that is git's, not ours. ReadAllText detects and
  # STRIPS a leading byte-order mark, so a pathname legitimately beginning with
  # EF BB BF arrived three bytes short and named a file that does not exist. BOM
  # handling belongs only to readers of files whose format WE define.
  # (Codex BLOCKER.)
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return @{ Present = $false; Valid = $true; Text = $null } }
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  try {
    return @{ Present = $true; Valid = $true; Text = $script:Utf8Strict.GetString($bytes) }
  } catch [System.Text.DecoderFallbackException] {
    return @{ Present = $true; Valid = $false; Text = $null }
  }
}

function Get-SpelledCardinalMap {
  # Spelled cardinal -> decimal-string value, DERIVED from
  # $script:SpelledCardinalAlternation's documented ascending-from-two ordering, so
  # the map itself never needs editing. "both" is the one entry with no position.
  $tokens = @($script:SpelledCardinalAlternation -split '\|')
  $map = @{ both = '2' }
  for ($k = 0; $k -lt $tokens.Count; $k++) { $map[$tokens[$k]] = [string]($k + 2) }
  return $map
}

function ConvertFrom-RustIntLiteral {
  # A Rust integer literal -> its VALUE as a canonical decimal string, or $null when
  # the token is not one. Every consumer compares VALUES, never spellings, so `4`,
  # `0x4`, `0b100`, `004` and `4usize` are one cardinality while `1_000` is a
  # thousand rather than a one.
  param([string]$Literal)
  if ([string]::IsNullOrWhiteSpace($Literal)) { return $null }
  $t = ([string]$Literal).Trim()
  # CASE-SENSITIVE suffix strip: Rust admits only the lowercase suffixes, so `4USIZE`
  # is not a literal and must not be read as 4 by a case-insensitive replace.
  $t = $t -creplace '(?:[iu](?:8|16|32|64|128|size))$', ''
  $t = $t -replace '_', ''
  # Radix prefixes are matched CASE-SENSITIVELY: the Rust grammar admits only the
  # lowercase forms, so `0X10` is not a literal and must not silently read as 16.
  # Every radix accumulates through BigInteger rather than a fixed-width integer:
  # a WIDE literal is still a literal, and is by construction greater than one, so
  # converting it must never fail into a null the caller would read as "not a
  # literal" and suppress.
  $digits = $null; $radix = 0
  if ($t -cmatch '^0x([0-9a-fA-F]+)$')  { $digits = $Matches[1]; $radix = 16 }
  elseif ($t -cmatch '^0o([0-7]+)$')    { $digits = $Matches[1]; $radix = 8 }
  elseif ($t -cmatch '^0b([01]+)$')     { $digits = $Matches[1]; $radix = 2 }
  elseif ($t -match  '^[0-9]+$')        { $digits = $t;          $radix = 10 }
  if ($null -eq $digits) { return $null }
  $acc = [System.Numerics.BigInteger]::Zero
  $bigRadix = [System.Numerics.BigInteger]$radix
  foreach ($ch in $digits.ToCharArray()) {
    $d = if ($ch -ge '0' -and $ch -le '9') { [int]$ch - [int][char]'0' }
         elseif ($ch -ge 'a' -and $ch -le 'f') { 10 + [int]$ch - [int][char]'a' }
         else { 10 + [int]$ch - [int][char]'A' }
    $acc = $acc * $bigRadix + [System.Numerics.BigInteger]$d
  }
  return $acc.ToString()
}

function Get-RecordIndexForOffset {
  # Index of the record owning $Offset in a flat buffer: the largest i with
  # $Starts[i] <= $Offset. $Starts must be non-decreasing and begin at 0, which the
  # flat-buffer builder guarantees (every record contributes at least its joiner).
  # Explicit Floor: PowerShell's int cast of a double rounds half-to-EVEN, so the
  # midpoint would drift upward on ties.
  param([int[]]$Starts, [int]$Offset)
  if (-not $Starts -or $Starts.Length -eq 0) { return 0 }
  $lo = 0; $hi = $Starts.Length - 1; $rec = 0
  while ($lo -le $hi) {
    $mid = [int][Math]::Floor(($lo + $hi) / 2)
    if ($Starts[$mid] -le $Offset) { $rec = $mid; $lo = $mid + 1 } else { $hi = $mid - 1 }
  }
  return $rec
}

function Get-RustLexedCodeRecords {
  # A stateful Rust lexical pass over a file's line records -> CODE records with
  # comment text REMOVED and string/char literal CONTENT blanked, length-preserving
  # so caller offset math is untouched and delimiters retained so expression
  # structure survives.
  #
  # State carries ACROSS records, which is the whole point: a `"..."` string, a
  # `r#"..."#` raw string and a `/* */` block comment may each span lines, and Rust
  # block comments NEST (`/* /* */ */` closes once, not twice). Handling them in
  # separate per-line passes let a nested comment's inner `*/` reopen code, so an
  # assertion inside a commented-out block was scanned as live.
  #
  # The lexed set is closed and bounded -- line comments, nested block comments,
  # normal strings, raw strings, char literals -- and deliberately not a Rust
  # parser: nothing here needs token types, only the regions where code is not.
  #
  # A `'` opens a CHAR literal only when a closing `'` follows within one
  # escape-or-character; otherwise it is a lifetime (`'a`), left alone, since
  # treating one as an open literal would blank the rest of the file.
  param([object[]]$Records)
  $out = New-Object 'System.Collections.Generic.List[object]'
  if (-not $Records) { return @() }
  $mode = 'code'        # code | str | raw | block
  $rawHashes = 0
  $blockDepth = 0
  foreach ($r in $Records) {
    $s = [string]$r.Text
    $chars = $s.ToCharArray()
    $i = 0
    while ($i -lt $chars.Length) {
      if ($mode -eq 'block') {
        if (($i + 1) -lt $chars.Length -and $chars[$i] -eq '/' -and $chars[$i + 1] -eq '*') {
          $blockDepth++; $chars[$i] = ' '; $chars[$i + 1] = ' '; $i += 2; continue
        }
        if (($i + 1) -lt $chars.Length -and $chars[$i] -eq '*' -and $chars[$i + 1] -eq '/') {
          $blockDepth--; $chars[$i] = ' '; $chars[$i + 1] = ' '; $i += 2
          if ($blockDepth -le 0) { $blockDepth = 0; $mode = 'code' }
          continue
        }
        $chars[$i] = ' '; $i++; continue
      }
      if ($mode -eq 'str') {
        if ($chars[$i] -eq '\') {
          $chars[$i] = ' '
          if ($i + 1 -lt $chars.Length) { $chars[$i + 1] = ' ' }
          $i += 2; continue
        }
        if ($chars[$i] -eq '"') { $mode = 'code'; $i++; continue }
        $chars[$i] = ' '; $i++; continue
      }
      if ($mode -eq 'raw') {
        if ($chars[$i] -eq '"') {
          $k = 0
          while (($i + 1 + $k) -lt $chars.Length -and $chars[$i + 1 + $k] -eq '#' -and $k -lt $rawHashes) { $k++ }
          if ($k -eq $rawHashes) { $mode = 'code'; $i += 1 + $k; continue }
        }
        $chars[$i] = ' '; $i++; continue
      }
      $ch = $chars[$i]
      if (($i + 1) -lt $chars.Length -and $ch -eq '/' -and $chars[$i + 1] -eq '/') {
        for ($k = $i; $k -lt $chars.Length; $k++) { $chars[$k] = ' ' }
        break
      }
      if (($i + 1) -lt $chars.Length -and $ch -eq '/' -and $chars[$i + 1] -eq '*') {
        $mode = 'block'; $blockDepth = 1; $chars[$i] = ' '; $chars[$i + 1] = ' '; $i += 2; continue
      }
      if ($ch -eq '"') { $mode = 'str'; $i++; continue }
      if ($ch -eq 'r' -or $ch -eq 'b' -or $ch -eq 'c') {
        # String prefixes: byte (`b`), C (`c`, Rust 2021) and raw (`r`), including
        # the `br`/`cr` combinations. A prefix counts only when it opens a token,
        # never as the tail of an identifier (`arr"` is not a raw string).
        $prevOk = ($i -eq 0) -or ($s[$i - 1] -notmatch '[A-Za-z0-9_]')
        if ($prevOk) {
          $j = $i
          if ($chars[$j] -eq 'b' -or $chars[$j] -eq 'c') { $j++ }
          if ($j -lt $chars.Length -and $chars[$j] -eq 'r') {
            $j++
            $h = 0
            while ($j -lt $chars.Length -and $chars[$j] -eq '#') { $h++; $j++ }
            if ($j -lt $chars.Length -and $chars[$j] -eq '"') { $mode = 'raw'; $rawHashes = $h; $i = $j + 1; continue }
          } elseif ($j -gt $i -and $j -lt $chars.Length -and $chars[$j] -eq '"') {
            $mode = 'str'; $i = $j + 1; continue
          }
        }
      }
      if ($ch -eq "'") {
        # Every Rust char-literal escape form, longest first: unicode `\u{...}`,
        # hex `\xNN`, then the single-character escapes and a bare character.
        $cm = [regex]::Match($s.Substring($i), "^'(?:\\u\{[0-9a-fA-F]{1,6}\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'])'")
        if ($cm.Success) {
          for ($k = $i + 1; $k -lt ($i + $cm.Length - 1); $k++) { $chars[$k] = ' ' }
          $i += $cm.Length; continue
        }
      }
      $i++
    }
    $out.Add(@{ Line = [int]$r.Line; Text = (-join $chars) })
  }
  return $out.ToArray()
}

function Test-TokenEndsExpression {
  # Can the character at $Index END an expression? That is the standard
  # operand/operator disambiguation: what precedes a `<` decides whether the `<` can
  # be a binary operator at all.
  #
  # The expression-ENDING set is the CLOSED one, which is why it is the side
  # enumerated; everything else -- an opener, a separator, any operator character, the
  # start of the text -- leaves the grammar expecting an OPERAND, where a binary `<`
  # cannot appear. Defaulting an unknown character to operand position is the loud
  # direction: it reads a following `<` as a generic opener, and a generic that never
  # closes fails the region scan rather than shearing a split.
  # A string or char delimiter counts as ending one because the lexer blanks their
  # CONTENT and keeps the delimiters.
  #
  # A word character is where the character alone is not enough: a KEYWORD is
  # identifier-SHAPED yet cannot end an expression, so `items.len() as <Pair<A, B> as
  # Trait>::Count` read its `<` as a comparison and let the generic's comma shear the
  # split. The token is therefore matched WHOLE, never by its last letter.
  # (Codex BLOCKER; `break` added.)
  #
  # The set, audited once against Rust's expression grammar rather than grown one
  # citation at a time. INCLUDED, each because a `<` may legally follow it and must
  # then open a type: `as` (cast target, incl. a qualified type), and the operand
  # introducers `return`, `break`, `if`, `else`, `match`, `in`, `where`.
  # DELIBERATELY EXCLUDED, with the reason, so the next reader need not re-derive it:
  #   `yield` / `become` -- not stable Rust; adding them would widen the accept set
  #     for syntax no tracked crate can contain.
  #   `await` -- POSTFIX (`expr.await`), so it ENDS an expression; including it would
  #     turn `x.await < y` from a comparison into an unclosed generic.
  #   `move` / `let` / `mut` / `ref` / `unsafe` -- no `<` can directly follow any of
  #     them in valid Rust (a closure pipe, a pattern, or a block always intervenes).
  #   `dyn` / `impl` -- type-position keywords, and every context where one can precede
  #     a `<` is already inside an open generic, which the type-position clause covers.
  # A LIFETIME/LABEL token (`'outer`) is not in the set because it is not a keyword: it
  # is handled below as its own shape, since `break 'outer <T as Tr>::N` puts the label
  # -- not `break` -- immediately before the angle.
  param([string]$Text, [int]$Index)
  $c = $Text[$Index]
  if ([char]::IsLetterOrDigit($c) -or $c -eq '_') {
    # MID-identifier there is no token yet, so no keyword judgement is possible and the
    # name simply continues; the real answer arrives at the identifier's last character.
    $word = Get-IdentifierEndingAt -Text $Text -Index $Index
    if (-not $word) { return $true }
    # A LIFETIME or LABEL (`'outer`) is a name, never a value, so it cannot end an
    # expression -- and `break 'outer <T as Tr>::N` puts it, not `break`, immediately
    # before the angle. The lexer blanks char-literal CONTENT, so the only identifier
    # a bare `'` can precede here is a lifetime.
    $wordStart = $Index - $word.Length + 1
    if ($wordStart -gt 0 -and $Text[$wordStart - 1] -eq "'") { return $false }
    return (-not ($word -cmatch '^(?:as|return|break|if|else|match|in|where)$'))
  }
  if ($c -eq ')' -or $c -eq ']' -or $c -eq '}') { return $true }
  if ($c -eq '"' -or $c -eq "'") { return $true }
  if ($c -eq '?') { return $true }
  return $false
}

function Get-IdentifierEndingAt {
  # The identifier token ENDING at $Index, or '' when no identifier ends there.
  #
  # ENDING is load-bearing: a caller that walks character by character asks this at
  # every position, and a backward-only scan answers with a PREFIX of the name it is
  # standing inside -- `assertions` reported `as` at its second character, which put
  # the cast-type tracker into type context in the middle of a word. Requiring the NEXT
  # character to be a non-identifier one is what makes the answer a whole token.
  # Shared so the token tests and the type-context tracker read the same tokens.
  param([string]$Text, [int]$Index)
  $c = $Text[$Index]
  if (-not ([char]::IsLetterOrDigit($c) -or $c -eq '_')) { return '' }
  if (($Index + 1) -lt $Text.Length) {
    $nx = $Text[$Index + 1]
    if ([char]::IsLetterOrDigit($nx) -or $nx -eq '_') { return '' }
  }
  $start = $Index
  while ($start -gt 0) {
    $p = $Text[$start - 1]
    if ([char]::IsLetterOrDigit($p) -or $p -eq '_') { $start-- } else { break }
  }
  return $Text.Substring($start, $Index - $start + 1)
}

function Get-AngleOperatorLength {
  # Length of the COMPLETE comparison/shift operator token starting at $Index, or 0
  # when the character is not an angle.
  #
  # The token must be consumed whole, because what follows an operator is an OPERAND:
  # `items.len() < <Marker<A, B> as Trait>::N` puts a qualified path immediately after
  # a comparison, and a scanner that stepped one character at a time carried the
  # pre-operator expression state into that `<` and read it as a second comparison --
  # shearing the generic's comma. Consuming `<`/`<<`/`<=` (and the `>` duals) as one
  # token is what lets the caller set operand state exactly once, at the right place.
  # (Codex BLOCKER.)
  param([string]$Text, [int]$Index)
  $c = $Text[$Index]
  if ($c -ne '<' -and $c -ne '>') { return 0 }
  $n1 = if (($Index + 1) -lt $Text.Length) { $Text[$Index + 1] } else { [char]0 }
  $n2 = if (($Index + 2) -lt $Text.Length) { $Text[$Index + 2] } else { [char]0 }
  if ($n1 -eq $c -and $n2 -eq '=') { return 3 }
  if ($n1 -eq $c -or $n1 -eq '=') { return 2 }
  return 1
}

function Get-TypeContextDisposition {
  # Within an `as` cast TARGET, what does the character at $Index do to that target?
  #   'continue' -- it can appear in a type
  #   'end'      -- it provably CANNOT, and terminates the target
  #   'unknown'  -- neither; the caller must report the site UNPARSED
  #
  # The default is INVERTED from the earlier terminator list, and that inversion is the
  # whole point. Enumerating what ENDS a type meant every unlisted token silently
  # continued it, and every LISTED one silently ended it -- so `ptr as *const Pair<A,
  # B>` ended at the pointer sigil and the generic's comma sheared the operand pair.
  # Rust's type grammar is larger than any such list (raw pointers, fn pointers,
  # projections, arrays, bounds), so the safe shape is to recognize what CONTINUES a
  # type, end only at tokens no type can contain, and treat everything else as
  # UNPARSED. That trades a guessed termination for a loud one, which is the only
  # trade this class permits.
  #
  # $AtEntryDepth is the caller's answer to "is the scan back at the depth the target
  # opened at?" -- a `,` is an argument separator INSIDE a fn-pointer list or a generic
  # and the target's end only at entry depth, and `;` is an array length the same way.
  param([string]$Text, [int]$Index, [bool]$AtEntryDepth)
  $c = $Text[$Index]
  $n = if (($Index + 1) -lt $Text.Length) { $Text[$Index + 1] } else { [char]0 }
  if ([char]::IsWhiteSpace($c)) { return 'continue' }
  # Identifiers carry every type keyword (`const`, `mut`, `dyn`, `impl`, `fn`) and an
  # array length; `'` opens a lifetime.
  if ([char]::IsLetterOrDigit($c) -or $c -eq '_' -or $c -eq "'") { return 'continue' }
  if ($c -eq '&') { if ($n -eq '&') { return 'end' } return 'continue' }
  if ($c -eq '|') { if ($n -eq '|') { return 'end' } return 'unknown' }
  if ($c -eq '=') { if ($n -eq '=') { return 'end' } return 'unknown' }
  if ($c -eq '!') { if ($n -eq '=') { return 'end' } return 'unknown' }
  if ($c -eq '-') { if ($n -eq '>') { return 'continue' } return 'unknown' }
  if ($c -eq ',') { if ($AtEntryDepth) { return 'end' } return 'continue' }
  if ($c -eq ';') { if ($AtEntryDepth) { return 'unknown' } return 'continue' }
  # Path separator, pointer sigil, trait-bound `+`, and the delimiters a type nests:
  # fn-pointer argument lists, array/slice brackets, generic angles.
  if ($c -eq ':' -or $c -eq '*' -or $c -eq '+' -or
      $c -eq '(' -or $c -eq ')' -or $c -eq '[' -or $c -eq ']' -or
      $c -eq '<' -or $c -eq '>') { return 'continue' }
  return 'unknown'
}

function Get-OpenerCloser {
  # The closer the character at $Index opens, or NUL when it opens nothing.
  # $InnermostCloser is the closer already expected by the enclosing delimiter (NUL
  # at top level); $PrevEndsExpression is the caller's running answer to
  # Test-TokenEndsExpression for the last non-trivia character before $Index.
  #
  # ANGLES ARE CLASSIFIED WHERE THE CHARACTERS ARE LEXED, NOT INFERRED FROM SPLIT
  # PRODUCTS. One predicate, in the positions Rust makes decidable:
  #   TYPE position -- the innermost open delimiter is itself a generic. The grammar
  #     admits no comparison there, so `Ident<` opens. This clause is what keeps a
  #     nested type argument's comma nested: without it `foo::<HashMap<K, V>, Other>()`
  #     closes its turbofish at the inner `>` and the following comma shears the split.
  #   OPERAND position -- the preceding non-trivia TOKEN cannot END an expression,
  #     so a binary `<` is grammatically impossible and the `<` must open a generic.
  #     This covers the turbofish (`::` cannot end an expression, and trivia between
  #     `::` and `<` is skipped by the caller's running flag), the qualified path
  #     `<Foo<A, B> as Trait>::ITEMS` whose leading `<` sits at operand start, and any
  #     other operand-start angle without enumerating spellings.
  #   TYPE CONTEXT -- the scan is inside a cast target opened by `as`. The target is a
  #     TYPE for its whole extent, not just its first identifier, and no comparison is
  #     grammatical anywhere in a type; without this, `items.len() as Count<A, B>` read
  #     its `<` as a comparison (the preceding `Count` ends an expression) and the
  #     generic's comma sheared the operand pair. The caller owns the state because
  #     only it knows where the target began and at what depth.
  # Everywhere else the preceding token ends an expression, so `<` is a comparison or
  # the first half of a shift. `<<` needs no rule of its own: the caller consumes a
  # comparison/shift as a COMPLETE token and sets operand state after it, so
  # `1 << 3` never re-reads its second `<` and `<<T as Trait>::A>` sees operand
  # position for both.
  #
  # SUPERSEDES Get-UnclearableAngleIndex, which guessed from flat
  # text whether a split had ALREADY been sheared and then compared that guess against
  # offsets derived from the same suspect split -- two facts proving each other. Do
  # not reintroduce a positional heuristic; classify at the characters. SUPERSEDES
  # the `::`-only and `<<`/`<=` spelling special cases this
  # predicate replaces -- they missed the qualified path and a trivia-separated
  # turbofish, which the position rule decides without naming either shape.
  param([string]$Text, [int]$Index, [char]$InnermostCloser, [bool]$PrevEndsExpression, [bool]$InTypeContext = $false)
  $c = $Text[$Index]
  if ($c -eq '(') { return [char]')' }
  if ($c -eq '[') { return [char]']' }
  if ($c -eq '{') { return [char]'}' }
  if ($c -ne '<') { return [char]0 }
  if ($InnermostCloser -eq [char]'>') { return [char]'>' }
  if ($InTypeContext) { return [char]'>' }
  if (-not $PrevEndsExpression) { return [char]'>' }
  return [char]0
}

function Test-IsGenericClose {
  # Does the `>` at $Index close an open generic, rather than act as an operator?
  param([string]$Text, [int]$Index, [char]$InnermostCloser)
  if ($InnermostCloser -ne [char]'>') { return $false }
  # `->` and `=>` carry a `>` that closes nothing, and both occur INSIDE generics
  # (`Box<dyn Fn(u8) -> u8>`, a closure's match arm); `>=` is a comparison.
  if ($Index -gt 0 -and ($Text[$Index - 1] -eq '-' -or $Text[$Index - 1] -eq '=')) { return $false }
  if (($Index + 1) -lt $Text.Length -and $Text[$Index + 1] -eq '=') { return $false }
  return $true
}

function Get-BalancedCloseIndex {
  # Index of the bracket closing the one at $OpenIndex, or -1 when the region is
  # unbalanced or reaches $Limit. The index-only view, for callers with no use for
  # the reason.
  param([string]$Text, [int]$OpenIndex, [int]$Limit)
  return ([int](Get-BalancedCloseResult -Text $Text -OpenIndex $OpenIndex -Limit $Limit).Close)
}

function Get-BalancedCloseResult {
  # Where the bracket at $OpenIndex closes, and WHY the scan stopped:
  #   @{ Close; Reason; GaveUpAt }
  # Close is the closing index, or -1 when the region was never proven closed; $Limit
  # is an ABSOLUTE, EXCLUSIVE end offset. The caller passes the same $Limit it uses to
  # derive the region span and EndLine, so the scanned region and the reported region
  # are one thing rather than two that can disagree.
  #
  # Reason separates the failures a bare -1 conflated:
  #   'unbalanced'             -- a closer MISMATCHED or a stray closer appeared. The
  #                               region provably does not close, wherever it stopped.
  #   'exhausted'              -- the walk reached $Limit with delimiters still open.
  #                               Only the CALLER knows whether $Limit was its scan cap
  #                               or the end of the text, and those are different
  #                               diagnoses; conflating them reported an early mismatch
  #                               in a long file as cap exhaustion, sending the reader
  #                               to look for a truncated region that does not exist.
  #   'unsupported-type-token' -- a cast target held a token this type grammar cannot
  #                               read, so the scan REFUSED to guess. Reporting it as
  #                               'unbalanced' named a defect the source does not have.
  # GaveUpAt is where the scan stopped, so the caller can bound what it SHOWS to text
  # the scan actually read.
  #
  # -DelimitersOnly drops angle handling entirely: `<` and `>` become ordinary
  # characters. Only the ANGLES are in doubt after an unreadable type token, and no
  # Rust type leaves a round/square/curly bracket unbalanced, so this pass still proves
  # where the macro's own delimiter closes. It is used ONLY to bound what an
  # already-decided UNPARSED site REPORTS -- never to classify one, where guessing at
  # angles is exactly what the default-unparsed inversion forbids.
  #
  # The stack holds EXPECTED CLOSERS, not a shared count: a `(` closed by a `]` is
  # not Rust, and a counting depth calls it balanced and hands the caller a region
  # whose boundaries were never proven. Failing routes it to the region's UNPARSED
  # outcome instead, which is also what protects every SUBSEQUENT split -- the callers
  # slice only regions this scan has already accepted. A generic that never closes
  # within the region reaches the same failure by the same route.
  # Assumes comments and string content are already blanked.
  param([string]$Text, [int]$OpenIndex, [int]$Limit, [switch]$DelimitersOnly)
  if ([string]::IsNullOrEmpty($Text) -or $OpenIndex -lt 0 -or $OpenIndex -ge $Text.Length) {
    return @{ Close = -1; Reason = 'unbalanced'; GaveUpAt = -1 }
  }
  $expect = New-Object 'System.Collections.Generic.Stack[char]'
  # Operand position at the start. $typeCtxDepth is the delimiter depth at which an
  # `as` cast target opened, or -1 when no target is open: the target is a TYPE until
  # a token that cannot continue one appears at that same depth.
  $prevEndsExpr = $false
  $typeCtxDepth = -1
  $end = [Math]::Min($Text.Length, $Limit)
  $i = $OpenIndex
  while ($i -lt $end) {
    $c = $Text[$i]
    $top = if ($expect.Count -gt 0) { $expect.Peek() } else { [char]0 }
    if (-not $DelimitersOnly -and $typeCtxDepth -ge 0) {
      $disp = Get-TypeContextDisposition -Text $Text -Index $i -AtEntryDepth ($expect.Count -le $typeCtxDepth)
      if ($disp -eq 'unknown') { return @{ Close = -1; Reason = 'unsupported-type-token'; GaveUpAt = $i } }
      if ($disp -eq 'end') { $typeCtxDepth = -1 }
    }
    $opens = if ($DelimitersOnly) {
      switch ($c) { '(' { [char]')' } '[' { [char]']' } '{' { [char]'}' } default { [char]0 } }
    } else {
      Get-OpenerCloser -Text $Text -Index $i -InnermostCloser $top -PrevEndsExpression $prevEndsExpr -InTypeContext ($typeCtxDepth -ge 0)
    }
    if ($opens -ne [char]0) {
      $expect.Push($opens); $prevEndsExpr = $false; $i++; continue
    }
    if (-not $DelimitersOnly -and $c -eq '>' -and (Test-IsGenericClose -Text $Text -Index $i -InnermostCloser $top)) {
      [void]$expect.Pop()
      $prevEndsExpr = $true
      if ($typeCtxDepth -ge 0 -and $expect.Count -lt $typeCtxDepth) { $typeCtxDepth = -1 }
      if ($expect.Count -eq 0) { return @{ Close = $i; Reason = 'balanced'; GaveUpAt = -1 } }
      $i++; continue
    }
    if ($c -eq ')' -or $c -eq ']' -or $c -eq '}') {
      if ($expect.Count -eq 0) { return @{ Close = -1; Reason = 'unbalanced'; GaveUpAt = $i } }
      if ($expect.Pop() -ne $c) { return @{ Close = -1; Reason = 'unbalanced'; GaveUpAt = $i } }
      $prevEndsExpr = $true
      if ($typeCtxDepth -ge 0 -and $expect.Count -lt $typeCtxDepth) { $typeCtxDepth = -1 }
      if ($expect.Count -eq 0) { return @{ Close = $i; Reason = 'balanced'; GaveUpAt = -1 } }
      $i++; continue
    }
    if (-not $DelimitersOnly) {
      $opLen = Get-AngleOperatorLength -Text $Text -Index $i
      if ($opLen -gt 0) {
        $prevEndsExpr = $false
        $i += $opLen; continue
      }
      if (-not [char]::IsWhiteSpace($c)) {
        $prevEndsExpr = Test-TokenEndsExpression -Text $Text -Index $i
        # The OUTERMOST cast owns the state: a nested `as` (a qualified path's own
        # `<T as Trait>`) must not re-base the entry depth, or the outer target ends at
        # the inner angle's close.
        if ($typeCtxDepth -lt 0 -and (Get-IdentifierEndingAt -Text $Text -Index $i) -ceq 'as') { $typeCtxDepth = $expect.Count }
      }
    }
    $i++
  }
  return @{ Close = -1; Reason = 'exhausted'; GaveUpAt = $end }
}

function Split-TopLevelOn {
  # Split $Text on each occurrence of $Token that sits at bracket depth 0.
  # $RejectFlank is a character class that must NOT sit immediately before or after
  # the token, so a comparison caller can keep `==` out of `!=`, `<=`, `>=`, `=>`
  # and `===`, and `<` out of `<<` and `<-`.
  #
  # Depth is a stack of EXPECTED CLOSERS for the same reason Get-BalancedCloseIndex
  # uses one, and it counts GENERIC angles through the same shared classifier, so a
  # turbofish's commas are nested rather than depth-0 and cannot shear an argument
  # list. On a mismatched or unmatched closer the whole text comes back as ONE
  # part: a text whose nesting cannot be read has no trustworthy depth-0 position, so
  # refusing to split is the only answer that cannot be WRONG. The pipeline never
  # relies on that fallback for its loud outcome -- it slices only regions the
  # region scan already accepted -- so this is the second line, not the first.
  param([string]$Text, [string]$Token, [string]$RejectFlank = '')
  $parts = New-Object 'System.Collections.Generic.List[string]'
  if ($null -eq $Text) { $Text = '' }
  $expect = New-Object 'System.Collections.Generic.Stack[char]'
  $prevEndsExpr = $false
  $typeCtxDepth = -1
  $start = 0; $i = 0
  $n = $Text.Length; $tl = $Token.Length
  while ($i -lt $n) {
    $c = $Text[$i]
    $top = if ($expect.Count -gt 0) { $expect.Peek() } else { [char]0 }
    if ($typeCtxDepth -ge 0) {
      $disp = Get-TypeContextDisposition -Text $Text -Index $i -AtEntryDepth ($expect.Count -le $typeCtxDepth)
      if ($disp -eq 'unknown') { return ,@([string]$Text) }
      if ($disp -eq 'end') { $typeCtxDepth = -1 }
    }
    $opens = Get-OpenerCloser -Text $Text -Index $i -InnermostCloser $top -PrevEndsExpression $prevEndsExpr -InTypeContext ($typeCtxDepth -ge 0)
    if ($opens -ne [char]0) {
      $expect.Push($opens); $prevEndsExpr = $false; $i++; continue
    }
    if ($c -eq '>' -and (Test-IsGenericClose -Text $Text -Index $i -InnermostCloser $top)) {
      [void]$expect.Pop(); $prevEndsExpr = $true
      if ($typeCtxDepth -ge 0 -and $expect.Count -lt $typeCtxDepth) { $typeCtxDepth = -1 }
      $i++; continue
    }
    if ($c -eq ')' -or $c -eq ']' -or $c -eq '}') {
      if ($expect.Count -eq 0 -or $expect.Pop() -ne $c) { return ,@([string]$Text) }
      $prevEndsExpr = $true
      if ($typeCtxDepth -ge 0 -and $expect.Count -lt $typeCtxDepth) { $typeCtxDepth = -1 }
      $i++; continue
    }
    if ($expect.Count -eq 0 -and ($i + $tl) -le $n -and $Text.Substring($i, $tl) -ceq $Token) {
      $flankOk = $true
      if ($RejectFlank) {
        $prev = if ($i -gt 0) { [string]$Text[$i - 1] } else { '' }
        $next = if (($i + $tl) -lt $n) { [string]$Text[$i + $tl] } else { '' }
        if (($prev -and $prev -match $RejectFlank) -or ($next -and $next -match $RejectFlank)) { $flankOk = $false }
      }
      if ($flankOk) {
        $parts.Add($Text.Substring($start, $i - $start))
        $prevEndsExpr = $false
        $typeCtxDepth = -1
        $i += $tl; $start = $i; continue
      }
    }
    $opLen = Get-AngleOperatorLength -Text $Text -Index $i
    if ($opLen -gt 0) {
      $prevEndsExpr = $false
      $i += $opLen; continue
    }
    if (-not [char]::IsWhiteSpace($c)) {
      $prevEndsExpr = Test-TokenEndsExpression -Text $Text -Index $i
      if ($typeCtxDepth -lt 0 -and (Get-IdentifierEndingAt -Text $Text -Index $i) -ceq 'as') { $typeCtxDepth = $expect.Count }
    }
    $i++
  }
  $parts.Add($Text.Substring($start))
  return $parts.ToArray()
}

function Remove-RedundantGrouping {
  # Strip parentheses that wrap an ENTIRE expression, repeatedly. Rust writes these
  # around macro operands and conditions often enough that leaving them in place put
  # real assertions behind a grouping layer. A pair that does not span the whole
  # trimmed text is left alone, so `(a) == (b)` survives.
  param([string]$Text)
  $t = ([string]$Text).Trim()
  while ($t.Length -ge 2 -and $t[0] -eq '(' -and (Get-BalancedCloseIndex -Text $t -OpenIndex 0 -Limit $t.Length) -eq ($t.Length - 1)) {
    $t = $t.Substring(1, $t.Length - 2).Trim()
  }
  return $t
}

function Test-IsCardinalityExpression {
  # A parsed expression whose VALUE IS a collection's cardinality: a `.len()` /
  # `.count()` call as the expression's OUTERMOST operation, optionally cast. The cast
  # is admitted because measuring the tree found `expr as usize` common enough that
  # leaving it unrecognized buried real counts in unparsed reports.
  # CASE-SENSITIVE, like Rust identifiers: `.LEN()` is a different method, and
  # reading it as this one would classify an unrelated call as a cardinality.
  #
  # OUTERMOST, not merely trailing: `a + b.len()` ENDS in the call but its value is
  # the SUM, so treating it as a cardinality let the class claim a literal was pinning
  # a count when it was pinning an arithmetic result. Such a side is not out of class
  # by that alone -- with a cardinality call and a literal still sharing the
  # comparison, the region reaches the UNPARSED pairing outcome, which is the honest
  # answer: the literal may well pin something, and nothing here can attribute it.
  # (Codex QUALITY; disqualifier widened past arithmetic 20260801.)
  #
  # EVERY depth-0 operator disqualifies, not just the arithmetic ones: a mask
  # (`flags | v.len()`), a shift (`1 << v.len()`), a unary `!` and a range endpoint
  # each make the call an INNER node exactly as `+` does, and admitting them let the
  # same wrong claim through by another spelling.
  #
  # The cast is checked on BOTH sides of the split: the pre-cast part must be an
  # outermost cardinality, and the tail must be a BARE TYPE. `v.len() as usize + 1`
  # casts and THEN adds, so its value is not the count either -- reading only the part
  # before ` as ` would have called it one.
  #
  # The cast tail is split STRUCTURALLY rather than matched as a name, so a type's own
  # `as` -- the qualified path in `x.len() as <Pair<A, B> as Trait>::Count` -- stays
  # inside its angle instead of being read as the cast boundary.
  param([string]$Text)
  $t = ([string]$Text).Trim()
  if (-not $t) { return $false }
  $asParts = @(Split-TopLevelOn -Text $t -Token ' as ')
  if ($asParts.Count -gt 2) { return $false }
  if ($asParts.Count -eq 2 -and -not (Test-IsBareTypeText -Text ([string]$asParts[1]))) { return $false }
  $core = ([string]$asParts[0]).Trim()
  # Comparison and logical operators are in the disqualifier set alongside the
  # arithmetic/bitwise ones: `a == b.len()` ends in the call but its VALUE is a
  # bool, the same inner-node shape as `a + b.len()`. Only the MULTI-char
  # spellings are listed -- a bare `<`/`>` token cannot be split on soundly
  # from a token list alone (turbofish and generic angles carry them inside a
  # type), so text carrying one at depth 0 can still read as a cardinality
  # here. That is a BOUNDED acceptance local to this predicate: its cost is a
  # rare over-claimed ADVISORY row on a bool-valued operand, never a hard
  # stop, and any caller needing sound bare-relational handling must split
  # with flank guards before calling.
  foreach ($op in @('+', '-', '*', '/', '%', '|', '&', '^', '<<', '>>', '!', '..', '==', '!=', '<=', '>=', '&&', '||')) {
    if ((@(Split-TopLevelOn -Text $core -Token $op)).Count -gt 1) { return $false }
  }
  return ($core -cmatch '\.\s*(?:len|count)\s*\(\s*\)$')
}

function Test-IsBareTypeText {
  # Is this text a TYPE and nothing more -- no operator applied to it?
  #
  # Only the characters no type can contain are rejected, so the delimiters a real cast
  # target carries (`::`, angles, array brackets, fn-pointer parens and `->`,
  # lifetimes) all pass. A tail failing this is a cast the expression then operates on,
  # which makes the cast an inner node.
  #
  # `&` and `*` are POSITIONAL, not blanket-legal: they are a reference and a pointer
  # sigil only in PREFIX position -- at the start of a type, or right after another
  # sigil or an opening delimiter -- and are the bitwise-and and multiply operators
  # once a type name precedes them. Admitting them anywhere let `usize * 2` and
  # `T & mask` read as cast targets, so the cast they follow was called the outermost
  # operation when the arithmetic was.
  #
  # `+` needs the same kind of gate: it is a trait BOUND only in a trait-object or
  # `impl` type, and an ADDITION anywhere else, so `dyn A + Send` is a type while
  # `usize + offset` is a cast the caller then adds to.
  param([string]$Text)
  $t = ([string]$Text).Trim()
  if (-not $t) { return $false }
  if ($t -match '[=!%/^|?.~]') { return $false }
  if ($t -match '<<|>>') { return $false }
  if ($t -match '\+' -and $t -cnotmatch '^(?:&\s*)*(?:dyn|impl)\b') { return $false }
  for ($i = 0; $i -lt $t.Length; $i++) {
    $c = $t[$i]
    if ($c -ne '&' -and $c -ne '*') { continue }
    $j = $i - 1
    while ($j -ge 0 -and [char]::IsWhiteSpace($t[$j])) { $j-- }
    if ($j -lt 0) { continue }                                  # start of the type
    $p = $t[$j]
    if ($p -eq '&' -or $p -eq '*' -or $p -eq '(' -or $p -eq '[' -or
        $p -eq '<' -or $p -eq ',' -or $p -eq ':') { continue }   # still prefix position
    if ($p -eq '>' -and $j -ge 1 -and $t[$j - 1] -eq '-') { continue }   # fn-pointer `->`
    $kw = Get-IdentifierEndingAt -Text $t -Index $j
    if ($kw -ceq 'mut' -or $kw -ceq 'const' -or $kw -ceq 'dyn' -or $kw -ceq 'impl') { continue }
    return $false                                               # a type name precedes it: an operator
  }
  return $true
}

function Test-IsSymbolPathExpression {
  # A parsed expression that NAMES something -- a bare identifier or a `::` path.
  # Comparing a cardinality against a name is the fix direction this class asks for,
  # so recognizing it is what lets the site stay silent.
  param([string]$Text)
  return ([string]$Text).Trim() -cmatch '^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$'
}

function Test-CarriesIntegerLiteral {
  # Does the expression contain an integer literal ANYWHERE? An expression carrying
  # none cannot be pinning one, which is what makes its recognition sound: a
  # cardinality compared against a call, a cast or a sum of names is some other
  # assertion, not a count pinned to a literal.
  #
  # A DOT is only disqualifying when it forms a FLOAT. `4usize.into()` and `0..4`
  # both carry an integer literal -- the dot there is a method call and a range --
  # while `4.0` carries a float and no integer. So the guards reject a digit-dot
  # pair specifically, not any adjacent dot: an over-broad dot guard silenced the
  # method-call form entirely.
  param([string]$Text)
  return [regex]::IsMatch([string]$Text, "(?<!\w)(?<!\d\.)$script:RustIntLiteralPattern(?!\w)(?!\.\d)")
}

function Test-IsCardinalityInequality {
  # A depth-0 inequality one of whose sides IS a cardinality expression: a BOUND,
  # not an exact-count claim. Tying the recognizer to the class -- rather than to
  # any stray angle bracket -- is what keeps a generic parameter from silencing a
  # site by looking like a `<`; the depth-0 split it rests on treats a generic angle
  # as a delimiter, so a generic never reaches these operators at all.
  param([string]$Text)
  $ops = @(
    @{ Token = '!='; Flank = '[=]' },
    @{ Token = '>='; Flank = '[=>]' },
    @{ Token = '<='; Flank = '[=<]' },
    @{ Token = '>';  Flank = '[=>-]' },
    @{ Token = '<';  Flank = '[=<-]' }
  )
  foreach ($op in $ops) {
    $sides = @(Split-TopLevelOn -Text $Text -Token $op.Token -RejectFlank $op.Flank)
    if ($sides.Count -ne 2) { continue }
    foreach ($s in $sides) { if (Test-IsCardinalityExpression -Text (Remove-RedundantGrouping -Text $s)) { return $true } }
  }
  return $false
}

function Get-MagicCountAssertFindings {
  # ADVISORY. An exact integer-literal EQUALITY assertion against a collection's
  # CARDINALITY -- `assert_eq!(x.len(), 4)`. The literal pins a SIZE while naming
  # nothing about WHICH elements are expected, so it goes stale on any membership
  # change and, when it fails, reports only that the size moved. The fix is
  # asserting MEMBERSHIP or set-equality against the expected elements, or deriving
  # the expected count from the input data that produced the collection.
  #
  # An ADVISORY HINT, not a sound analyzer. It carries no exemption for a "provably
  # anchored" count, and DO NOT ADD ONE: such an exemption was built and measured over
  # every tracked .rs file, where it fired on nothing at all -- the whole cost was
  # unsound cardinality reasoning (`take(n)` yields AT MOST n, `slice::repeat(n)`
  # yields n*len, a range endpoint bounds an iterator any adaptor may shorten). The
  # rare genuinely anchored assertion drawing an advisory is the cheaper error.
  #
  # $Records are LEXED CODE records (Get-RustLexedCodeRecords), so a count in a
  # comment stays the INVENTORY/MAGNITUDE classes' business and an assertion quoted
  # inside a string literal is an example rather than a live claim.
  #
  # TOTAL DEFAULT-UNPARSED. Silence requires POSITIVE RECOGNITION at EVERY exit of
  # this pipeline; failure is always loud. Each exit below is labelled, and an exit
  # that cannot cite a predicate is UNPARSED by construction -- which is what makes
  # an unhandled Rust form report rather than vanish. The pipeline:
  #
  #   SITE       X1 no macro-name token          -> not a site (upstream of the
  #                                                 pipeline; the recognizer itself
  #                                                 admits trivia around the `!`)
  #   REGION     X2 balanced close within cap    -> continue
  #              X3 region cap reached           -> UNPARSED (truncated)
  #              X4 brackets never balanced      -> UNPARSED (unbalanced; a generic
  #                                                 that never closes lands here, so
  #                                                 an undecidable angle is loud)
  #              X25 unsupported cast-target token
  #                                              -> UNPARSED (the scan refused to guess
  #                                                 where a type ends; distinct from X4
  #                                                 because the delimiters may close
  #                                                 perfectly. EndLine then covers that
  #                                                 proven region, while the SHOWN text
  #                                                 stops at the token -- the failure
  #                                                 message stays out of the quote)
  #   SPLIT      X6 depth-0 split, GENERIC angles counted as delimiters by
  #                 Get-OpenerCloser             -> continue (a generic's commas are
  #                                                 nested, so no exit is needed for
  #                                                 them; the retired X5 guessed at
  #                                                 that structurally instead)
  #   MESSAGE    X8 arguments past the compared pair (`assert_eq!`) or past the
  #                 condition (`assert!`)        -> out of class, DISCARDED BEFORE
  #                                                 any test that reads the operands,
  #                                                 so nothing in a failure message
  #                                                 can steer one
  #   EXTRACT    X7 `assert_eq!` with < 2 args   -> UNPARSED (no comparison)
  #              X9 conjunct without a cardinality call
  #                                              -> out of class
  #              X10 conjunct is a cardinality inequality
  #                                              -> out of class (a bound)
  #              X11 conjunct with a depth-0 `==`-> comparison
  #              X12 conjunct otherwise, carrying a cardinality call AND a literal
  #                                              -> UNPARSED (a pairing may hide at
  #                                                 any depth -- braces, closures)
  #              X13 conjunct otherwise, no literal
  #                                              -> out of class
  #   PRESENCE   X14 no cardinality call in the region
  #                                              -> out of class (tested FIRST: it
  #                                                 needs no split, so no boundary
  #                                                 question can change it)
  #              X16 no cardinality call in the comparison text
  #                                              -> out of class
  #   CLASSIFY   X17 neither side a cardinality expression, cardinality call AND
  #                  literal present             -> UNPARSED
  #              X18 neither side a cardinality expression, otherwise
  #                                              -> out of class
  #              X19 both sides cardinality expressions
  #                                              -> out of class
  #              X20 comparand is a symbol/path  -> out of class
  #              X21 comparand carries no literal-> out of class
  #              X22 comparand is a bare literal of value 0 or 1
  #                                              -> out of class
  #              X23 comparand is a bare literal above one
  #                                              -> FINDING
  #              X24 comparand carries a literal but is not one
  #                                              -> UNPARSED (unevaluated)
  #
  # PRECEDENCE, one site to one documented outcome per part: every classified
  # comparison emits its FINDING, and if ANY part went unrecognized the site adds
  # exactly one UNPARSED beside them.
  #
  # The bracket scan, cardinality search, reported span and EndLine all derive from
  # ONE absolute endpoint, so the region examined and the region reported cannot
  # differ.
  param([object[]]$Records)
  $out = @()
  if (-not $Records) { return $out }
  $sb = New-Object System.Text.StringBuilder
  $starts = New-Object 'int[]' $Records.Count
  for ($i = 0; $i -lt $Records.Count; $i++) {
    $starts[$i] = $sb.Length
    [void]$sb.Append([string]$Records[$i].Text)
    [void]$sb.Append(' ')   # a NON-word joiner, so no token spans a line break
  }
  $flat = $sb.ToString()
  $RegionCap = 4000
  # Trivia is admitted around the `!` and before the delimiter: rustfmt and hand
  # formatting both put whitespace or a newline there, and the lexer has already
  # blanked comments to spaces. A site missed here never enters the pipeline at all,
  # so the recognizer is the one place the inversion cannot cover for.
  $rxSite = [regex]('\b(?<name>(?:debug_)?assert(?:_eq)?)\s*!\s*[\(\[\{]')
  # PRESENCE, not classification. A method call is the common spelling, but the same
  # call written UFCS -- `Vec::len(&v)`, `ExactSizeIterator::len(it)`, a bare
  # `len(x)` -- is the same cardinality, and matching only the dot form routed those
  # regions to the SILENT out-of-class exit (X14/X16) instead of into classification.
  # Presence is deliberately generous because it decides only whether the region is
  # LOOKED AT: everything past it is the positive recognizer set, so a UFCS call the
  # classifier cannot pair reaches UNPARSED rather than vanishing.
  #
  # THE PREFIX IS NOT ENUMERATED, and must not be: an enumerated path grammar
  # (`(?:ident::)*`) reads only the spellings someone listed, so the qualified forms
  # Rust also accepts -- a QSelf `<I as ExactSizeIterator>::len(x)`, a turbofish
  # segment `Vec::<u8>::len(x)`, an absolute `::std::vec::Vec::len(x)` -- each failed
  # the match and took the silent exit the inversion exists to remove. What actually
  # decides the class is the IDENTIFIER, so the guard is a word boundary on it and
  # nothing else: `length(` and `token_len_count(` stay out because `len`/`count` is
  # not a whole word there, while every prefix -- listed or not -- reaches
  # classification.
  #
  # The identifier must still be ADJACENT to the call delimiter, so a parenthesized
  # function item (`(Vec::len)(&items)`) stays outside the class -- an unchanged shape,
  # named here so the coverage claim is not read as universal.
  $rxCardCall = [regex]('(?<!\w)(?:len|count)\s*\(')
  $rxLitOnly = [regex]("^\s*(?<lit>$script:RustIntLiteralPattern)\s*$")
  foreach ($site in $rxSite.Matches($flat)) {
    $openIdx = $site.Index + $site.Length - 1
    $capEnd = $site.Index + $RegionCap
    $scanEnd = [Math]::Min($flat.Length, $capEnd)
    $scanRes = Get-BalancedCloseResult -Text $flat -OpenIndex $openIdx -Limit $scanEnd
    $close = [int]$scanRes.Close
    # The scan cap is the diagnosis ONLY when the walk ran out of WINDOW -- reason
    # 'exhausted' with $scanEnd short of the text. An early mismatch in a long file
    # reaches neither, and calling it cap exhaustion sent the reader hunting a
    # truncation that never happened.
    $capFired = (($scanRes.Reason -eq 'exhausted') -and ($scanEnd -lt $flat.Length))
    # An unreadable TYPE token leaves the ANGLES in doubt and nothing else, so the
    # macro's own delimiter can still be proven by a delimiter-only pass. Attributing
    # the report to that proven region is the difference between naming one assertion
    # and covering every line to EOF. Only when the delimiters ALSO fail to close is
    # the region genuinely unbounded.
    $boundClose = if ($scanRes.Reason -eq 'unsupported-type-token') {
      [int](Get-BalancedCloseResult -Text $flat -OpenIndex $openIdx -Limit $scanEnd -DelimitersOnly).Close
    } else { -1 }
    $startLine = [int]$Records[(Get-RecordIndexForOffset -Starts $starts -Offset $site.Index)].Line
    # A GENUINELY UNBOUNDED region's extent is UNKNOWN -- the failure is exactly the
    # admission that the assertion was not read to its end -- so its EndLine runs to EOF
    # rather than to the point the scan stopped. The staged filter reports a span when
    # any line INSIDE it is added, and a truncated EndLine hid every addition past that
    # point: the truncation went unreported precisely on the edits most likely to be
    # inside the unread remainder. Over-covering is the conservative direction for a
    # class whose whole contract is that an unread region reports.
    # (Codex BLOCKER.)
    $coverEnd = if ($close -ge 0) { $close } elseif ($boundClose -ge 0) { $boundClose } else { -1 }
    $endLine = if ($coverEnd -lt 0) {
      [int]$Records[$Records.Count - 1].Line
    } else {
      [int]$Records[(Get-RecordIndexForOffset -Starts $starts -Offset $coverEnd)].Line
    }
    # What the report SHOWS is bounded by what the scan actually READ. With no proven
    # region, that is the give-up point: running the shown text to the scan limit quoted
    # the failure message and whatever followed the assertion back at the author as
    # though they were part of the undecidable expression.
    # COVERAGE and SHOWN TEXT answer different questions, and the smaller answer wins
    # for the text: EndLine must cover the whole proven region so a later added line
    # still surfaces the site, while the span only has to point the reader at what
    # the scan could not read. Where the scan gave up INSIDE the region, stopping the
    # shown text there keeps the failure message and the rest of the assertion out of
    # a quote the author is meant to act on.
    $gaveUp = [int]$scanRes.GaveUpAt
    $spanEnd = if ($gaveUp -ge $site.Index -and $gaveUp -lt $flat.Length -and ($coverEnd -lt 0 -or $gaveUp -le $coverEnd)) {
      $gaveUp
    } elseif ($coverEnd -ge 0) {
      $coverEnd
    } else {
      $scanEnd - 1
    }
    $span = ($flat.Substring($site.Index, ($spanEnd - $site.Index) + 1) -replace '\s+', ' ').Trim()
    if ($span.Length -gt 90) { $span = $span.Substring(0, 87) + '...' }
    $isEq = $site.Groups['name'].Value.EndsWith('_eq')
    $siteFindings = @()
    $unparsedReason = $null
    $comparisons = @()
    if ($close -lt 0) {
      $unparsedReason = if ($scanRes.Reason -eq 'unsupported-type-token') {
        'X25 a cast target holds a token this type grammar cannot read'
      } elseif ($capFired) {
        'X3 the region reached the scan cap before its brackets closed'
      } elseif ($scanRes.Reason -eq 'exhausted') {
        'X4 the region brackets never balanced (the text ended first)'
      } else {
        'X4 the region brackets never balanced (a closer mismatched)'
      }
    } else {
      $argText = $flat.Substring($openIdx + 1, $close - $openIdx - 1)
      # X14 FIRST, and deliberately so: a region with no cardinality call anywhere is
      # out of class no matter where its argument boundaries fall, and the test is
      # flat text that no split can affect.
      if (-not $rxCardCall.IsMatch($argText)) { continue }
      # The split needs no angle guard: Get-OpenerCloser classifies generics where the
      # characters are lexed, so a generic's commas are already nested here, and a
      # generic that never closes fails the region scan above as unbalanced.
      $argv = @(Split-TopLevelOn -Text $argText -Token ',')
      # The FAILURE MESSAGE is discarded before anything is classified. Its arguments
      # are recognized by the macro signature -- everything past the compared pair
      # for `assert_eq!`, everything past the condition for `assert!` -- so a count,
      # a generic or a literal inside a message describes the failure rather than
      # asserting anything, and must not steer the classification of the comparison.
      $comparisonText = if ($isEq) { (@($argv | Select-Object -First 2) -join ' , ') } else { [string]$argv[0] }
      if ($isEq -and $argv.Count -lt 2) {
        $unparsedReason = 'X7 assert_eq! carries no second argument to compare against'
      } elseif (-not $rxCardCall.IsMatch($comparisonText)) {
        continue                                                                                # X16
      } else {
        if ($isEq) {
          $comparisons += ,@((Remove-RedundantGrouping -Text $argv[0]), (Remove-RedundantGrouping -Text $argv[1]))   # X8 drops args 3+
        } else {
          foreach ($conj in @(Split-TopLevelOn -Text (Remove-RedundantGrouping -Text $comparisonText) -Token '&&')) {
            foreach ($alt in @(Split-TopLevelOn -Text (Remove-RedundantGrouping -Text $conj) -Token '||')) {
              $part = Remove-RedundantGrouping -Text $alt
              if (-not $rxCardCall.IsMatch($part)) { continue }                                  # X9
              if (Test-IsCardinalityInequality -Text $part) { continue }                         # X10
              $sides = @(Split-TopLevelOn -Text $part -Token '==' -RejectFlank '[!<>=]')
              if ($sides.Count -eq 2) {
                $comparisons += ,@((Remove-RedundantGrouping -Text $sides[0]), (Remove-RedundantGrouping -Text $sides[1]))   # X11
              } elseif (Test-CarriesIntegerLiteral -Text $part) {
                $unparsedReason = 'X12 a cardinality call and an integer literal share a conjunct with no depth-0 equality'
              }                                                                                 # X13
            }
          }
        }
      }
    }
    foreach ($c in $comparisons) {
      $a = [string]$c[0]; $b = [string]$c[1]
      $aCard = Test-IsCardinalityExpression -Text $a
      $bCard = Test-IsCardinalityExpression -Text $b
      if (-not $aCard -and -not $bCard) {
        if ($rxCardCall.IsMatch("$a $b") -and (Test-CarriesIntegerLiteral -Text "$a $b")) {
          $unparsedReason = 'X17 a cardinality call and an integer literal share a comparison whose sides are neither'
        }
        continue                                                                                # X18
      }
      if ($aCard -and $bCard) { continue }                                                      # X19
      $other = if ($aCard) { $b } else { $a }
      if (Test-IsSymbolPathExpression -Text $other) { continue }                                # X20
      if (-not (Test-CarriesIntegerLiteral -Text $other)) { continue }                          # X21
      $m = $rxLitOnly.Match($other)
      if (-not $m.Success) { $unparsedReason = 'X24 the comparand carries an integer literal but is not one'; continue }
      $lit = ConvertFrom-RustIntLiteral -Literal $m.Groups['lit'].Value
      if ($null -eq $lit) { $unparsedReason = 'X24 the comparand carries an integer literal but is not one'; continue }
      if ($lit -eq '0' -or $lit -eq '1') { continue }                                           # X22
      # The comparison, not the whole invocation, is the Match: two findings from one
      # site would otherwise be indistinguishable in the report.
      $cmp = (("$(if ($aCard) { $a } else { $b }) == $($m.Groups['lit'].Value)") -replace '\s+', ' ').Trim()
      if ($cmp.Length -gt 90) { $cmp = $cmp.Substring(0, 87) + '...' }
      $siteFindings += @{                                                                       # X23
        Class   = 'MAGIC-COUNT-ASSERT'
        Tier    = 'ADVISORY'
        Outcome = 'FINDING'
        Line    = $startLine
        EndLine = $endLine
        Match   = $cmp
        Num     = $lit
        Hint    = 'assert membership/set-equality against the expected elements, or derive the expected count from the input data -- not a bare literal'
      }
    }
    foreach ($f in $siteFindings) { $out += $f }
    if ($unparsedReason) {
      $out += @{
        Class   = 'MAGIC-COUNT-ASSERT'
        Tier    = 'ADVISORY'
        Outcome = 'UNPARSED'
        Line    = $startLine
        EndLine = $endLine
        Match   = $span
        Hint    = "UNPARSED -- $unparsedReason; check by hand whether the count should be membership/set-equality"
      }
    }
  }
  return $out
}

function Get-StagedSourceFindings {
  # Staged per-source-file DECISION logic over the INDEPENDENT comment and code
  # surfaces of the same file:
  #   COMMENT lines -> the count-drift classes (inventory-assertion SHAPE +
  #     MAGNITUDE). Code lines are never scanned for these: a numeric literal in
  #     code is correct where it lives.
  #   CODE lines (Rust only) -> MAGIC-COUNT-ASSERT.
  # Each surface's detectors run over the FULL set of records -- so the comment
  # classes' shared fence matcher sees an UNCHANGED comment-fence opener/closer
  # around an added line, and a multi-line assert's unchanged macro opener still
  # parses -- and the findings are filtered to ADDED lines only AFTERWARD. (Codex
  # TEST-QUALITY: filtering before the detector lost fence
  # context.) The COMMENT surface carries a code-echo exemption within $EchoWindow
  # (`// there are 3 icons` above `const ICONS = 3`) -- adjacent code is the lookup
  # key, an unrelated same number elsewhere in the file is not. The CODE surface
  # carries no exemption beyond the detector's own 0/1 value rule. Source-comment
  # inventory findings are DOWNGRADED to ADVISORY (one tier softer than the .md
  # ERROR, per the comment-extraction precision note).
  param([string]$Path, [string]$StagedText, [hashtable]$AddedSet, [string]$Ext)
  $EchoWindow = 2
  $lines = $StagedText -split "`n"
  # A List, not `$out +=`: one record per line of a whole source file, and array
  # append reallocates (quadratic on the multi-thousand-line files this repo stages).
  $allRecsList = New-Object 'System.Collections.Generic.List[object]'
  for ($i = 0; $i -lt $lines.Count; $i++) { $allRecsList.Add(@{ Line = ($i + 1); Text = ($lines[$i] -replace "`r$", '') }) }
  $allRecs = $allRecsList.ToArray()
  # SUPPORT FIRST, before anything derived from the split. The trust question has to
  # be answered by a scan that does NOT consult the split -- and it has to be answered
  # BEFORE `$hasAddedComments`, which does: an untrusted split can put an added COMMENT
  # line on the code side, and gating the diagnostic on that answer meant the very
  # files whose comments were hidden reported nothing at all.
  $support = Get-SourceSupportDiagnostic -Records $allRecs -Ext $Ext
  # MAGIC-COUNT-ASSERT is RUST-ONLY: its shapes are Rust assertion macros, and
  # `.len()`/`.count()` mean something else in the other scanned extensions. A .rs
  # file therefore has scannable content whenever the commit adds ANY line (code or
  # comment); every other extension still needs added COMMENT lines.
  $scanAsserts = ($Ext -eq 'rs')
  $commentRecs = if ($support) { @() } else { @(Get-SourceCommentRecords -Records $allRecs -Ext $Ext) }
  $hasAddedComments = (@($commentRecs | Where-Object { $AddedSet.ContainsKey([int]$_.Line) }).Count -gt 0)
  if (-not $support -and -not $hasAddedComments -and -not $scanAsserts) { return @() }
  $out = @()
  # DEGRADE LOUDLY, PER FILE. A construct outside the supported grammar poisons the
  # comment/code split for every LATER record, so the count classes are dropped for
  # this file and one diagnostic says so. Scoped to this file and to those classes:
  # MAGIC-COUNT-ASSERT reads its own Rust lexer (raw strings, char literals,
  # depth-counted block comments) and is unaffected, every other file scans normally,
  # and the diagnostic is ADVISORY so a degraded scan never aborts a commit -- an
  # abort would make one unsupported construct anywhere in the tree a hard stop.
  if ($support) {
    $out += @{
      Class = 'UNSUPPORTED-SYNTAX'
      Tier  = 'ADVISORY'
      File  = $Path
      Line  = [int]$support.Line
      Match = [string]$support.Construct
      Hint  = 'outside the comment/code splitter''s supported grammar, so the count classes were SKIPPED for this file -- check its added comments by hand'
    }
  }
  if ($hasAddedComments) {
    $codeByLine = Get-SourceCodeNumbersByLine -Records $allRecs -Ext $Ext
    $spelledToNumber = Get-SpelledCardinalMap
    # SEGMENT the comment records so a `// ``` ` fence opened in one line-comment
    # block does NOT carry its fence state across intervening CODE into a later
    # disjoint comment (which would silently suppress a real finding). A new segment
    # starts at a comment record that is NOT contiguous with the previous one AND did
    # not START inside a block comment: a code line between two line-comment blocks
    # resets the fence, while a block comment's interior stays one segment (code
    # cannot appear between block-comment lines, and a dropped blank interior line is
    # fence content, not a code separator). Fence context still spans UNCHANGED
    # comment lines WITHIN a segment. (Codex SILENT-FAILURE: the un-segmented
    # comment stream leaked fence state across code -- a package hardening
    # restored over the incoming capability per the port contract, which an
    # earlier merge draft had silently dropped.)
    $segments = @()
    $curSeg = @()
    $prevSegLine = $null
    $prevCodeAfter = $false
    foreach ($segCr in $commentRecs) {
      # A boundary falls exactly where CODE LIES BETWEEN COMMENT FRAGMENTS,
      # in any of its spellings: a line-number GAP (a pure code line between
      # comment blocks), code BEFORE this fragment on its own line
      # (`let x = 1; // note`, or the line comment in `*/ x = 1; // note` --
      # same-line records, so only the positional flag can see it), or code
      # AFTER the previous fragment's close (`/* c */ x = 1` followed by
      # another comment). Records are PER FRAGMENT, so two can share a line
      # (contiguous means same line or the next); a block-comment
      # continuation is exempt from the gap test (no code can hide in a
      # dropped blank interior line), and code that merely PRECEDES a block
      # opener never splits that block's own lines apart -- the line-merged
      # models this replaces failed one way or the other, each re-reading a
      # fence closer as an opener and silently suppressing a live claim.
      $segGap = (($null -ne $prevSegLine) -and ([int]$segCr.Line -ne $prevSegLine) -and ([int]$segCr.Line -ne ($prevSegLine + 1)) -and (-not $segCr.WasInBlock))
      if (($segGap -or [bool]$segCr.CodeBefore -or $prevCodeAfter) -and ($curSeg.Count -gt 0)) {
        $segments += ,@($curSeg)
        $curSeg = @()
      }
      $curSeg += $segCr
      $prevCodeAfter = [bool]$segCr.CodeAfter
      $prevSegLine = [int]$segCr.Line
    }
    if ($curSeg.Count -gt 0) { $segments += ,@($curSeg) }
    $inv = @()
    $mag = @()
    foreach ($seg in $segments) {
      $inv += @(Get-InventoryAssertionFindings -Records @($seg))
      $mag += @(Get-MagnitudeFindings -Records @($seg))
    }
    foreach ($f in (@($inv) + @($mag))) {
      if (-not $AddedSet.ContainsKey([int]$f.Line)) { continue }   # keep only findings on ADDED comment lines
      # NEARBY code-echo exemption: the finding's number must appear on the code of
      # a line within +/-$EchoWindow of the comment line to be exempted. Extract the
      # FULL numeric token INCLUDING any decimal (`\d+(?:\.\d+)?`): a decimal magnitude
      # like "took 0.25" compares as "0.25", never the fragment "0", and the code map
      # stores full decimal tokens too, so `// took 0.25` beside `= 0.25` exempts
      # while an unrelated integer `0` nearby cannot suppress it. (Codex BLOCKER
      #; QUALITY: decimal map support.) A SPELLED
      # enumerated total ("all three cases", "both cases") carries no digit -- map
      # the spelled word to its numeral so those can use the documented exemption
      # too (`// covers all three cases` beside `const CASES: usize = 3`). (Codex
      # QUALITY.)
      $num = $null
      $numM = [regex]::Match([string]$f.Match, '\d+(?:\.\d+)?')
      if ($numM.Success) { $num = $numM.Value }
      else {
        $spelledM = [regex]::Match([string]$f.Match, "(?i)\b(both|$script:SpelledCardinalAlternation)\b")
        if ($spelledM.Success) { $num = $spelledToNumber[$spelledM.Value.ToLowerInvariant()] }
      }
      if ($num) {
        $echoed = $false
        for ($ln = ([int]$f.Line - $EchoWindow); $ln -le ([int]$f.Line + $EchoWindow); $ln++) {
          if (-not $codeByLine.ContainsKey($ln)) { continue }
          if ($codeByLine[$ln].ContainsKey($num)) { $echoed = $true; break }
          # By-VALUE comparison is RUST-ONLY: `= 0x3` is the same constant a comment
          # calls three, but only Rust's grammar says so. Applying it to a shell or
          # TOML token would reinterpret text that has no such meaning there, so
          # those extensions match the decimal token as a string and nothing else.
          if ($Ext -eq 'rs') {
            foreach ($tok in @($codeByLine[$ln].Keys)) {
              if ((ConvertFrom-RustIntLiteral -Literal $tok) -eq $num) { $echoed = $true; break }
            }
          }
          if ($echoed) { break }
        }
        if ($echoed) { continue }
      }
      if ($f.Class -eq 'INVENTORY') { $f['Tier'] = 'ADVISORY' }   # one tier softer than the .md ERROR
      $f['File'] = $Path
      $out += $f
    }
  }
  if ($scanAsserts) {
    $lexedRecs = @(Get-RustLexedCodeRecords -Records $allRecs)
    # CONTRACT: any added PHYSICAL line anywhere in the assertion's span reports it,
    # comment reflow included. The whole INVOCATION span decides, not the literal's
    # line alone, so an edit that adds the `.len()` call or rewrites only the macro
    # line of a multi-line assertion still surfaces.
    #
    # FAILED APPROACH (removed, do not resurrect): successive
    # attempts to exempt lines that changed no CODE -- first "lexed code is blank",
    # then "lexed code equals a removed line's lexed code" -- each drew a BLOCKER for
    # unsound content classification, because the diff's removed set is a bag of
    # strings with no positional link to the added line being judged, and identical
    # code text recurs across a file. The asymmetry decides it: the class is ADVISORY,
    # so a reflow surfacing an untouched assertion costs the author one glance, while
    # a wrong exemption silently drops a real magic count. Suppression machinery here
    # is not worth another round.
    foreach ($f in (Get-MagicCountAssertFindings -Records $lexedRecs)) {
      $touched = $false
      for ($ln = [int]$f.Line; $ln -le [int]$f.EndLine; $ln++) {
        if ($AddedSet.ContainsKey($ln)) { $touched = $true; break }
      }
      if (-not $touched) { continue }
      $f['File'] = $Path
      $out += $f
    }
  }
  return $out
}

function Get-AddedRecordsFromDiff {
  # Parse `git diff --cached --unified=0` text into per-file added-line records.
  # Returns @{ '<path>' = @( @{Line=<int>; Text=<string>} , ... ) }. New-line
  # numbers come from the `@@ -a,b +c,d @@` hunk headers.
  #
  # $AttributeTo names the file the caller already knows this diff is FOR, and when
  # given, every hunk is attributed to it and the `+++` header is not consulted at
  # all. That is what keeps the decoded path list and the hunk parse in agreement:
  # git C-QUOTES a `+++ b/"caf\303\251.md"` header for a path needing escaping, so a
  # header-derived key never matches the decoded path the caller selected, the added
  # set comes back empty, and the fail-loud guard aborts the whole run. Attributing
  # directly makes the header form irrelevant rather than something to decode.
  param([string]$DiffText, [string]$AttributeTo = '')
  $byFile = @{}
  if ([string]::IsNullOrEmpty($DiffText)) { return $byFile }
  $curFile = $null
  $newLine = 0
  # HUNK STATE is essential: the `--- a/` / `+++ b/` file headers appear only in the
  # PRE-HUNK zone of each file section. Once inside a hunk (after `@@`), a line like
  # `+++ b/scripts/foo.rs:42` is ADDED CONTENT (a Markdown line literally adding
  # `++ b/...`), NOT a header -- matching the header regex unconditionally would drop
  # that added line and silently mask a lint violation on it. A `diff --git` line
  # starts a new file section and resets the zone. (Codex BLOCKER.)
  $inHunk = $false
  foreach ($raw in ($DiffText -split "`n")) {
    $line = $raw -replace "`r$", ''
    if ($line -match '^diff --git ') { $inHunk = $false; if (-not $AttributeTo) { $curFile = $null }; continue }
    if ($line -match '^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@') {
      $newLine = [int]$Matches[1]; $inHunk = $true
      if ($AttributeTo) {
        $curFile = $AttributeTo
        if (-not $byFile.ContainsKey($curFile)) { $byFile[$curFile] = @() }
      }
      continue
    }
    if (-not $inHunk) {
      # Pre-hunk header zone: these are real file headers.
      if (-not $AttributeTo -and $line -match '^\+\+\+\s+b/(.+)$') {
        $curFile = $Matches[1]
        if (-not $byFile.ContainsKey($curFile)) { $byFile[$curFile] = @() }
      }
      # `--- a/` and any other pre-hunk metadata: ignored.
      continue
    }
    if ($null -eq $curFile) { continue }
    # Inside a hunk: classify by the FIRST char only (so `+++ b/...` content counts).
    if ($line.StartsWith('+')) {
      $byFile[$curFile] += @{ Line = $newLine; Text = $line.Substring(1) }
      $newLine++
    } elseif ($line.StartsWith('-')) {
      # deleted line: does not advance the new-file counter
    } elseif ($line.StartsWith('\')) {
      # "\ No newline at end of file": ignore
    } else {
      # context line (rare at unified=0): advances new counter
      $newLine++
    }
  }
  return $byFile
}

function Get-AddedLineSetForPath {
  # Build the hashtable-set of ADDED line numbers for $Path from a
  # Get-AddedRecordsFromDiff result. ContainsKey + a per-record null guard so a
  # MISSING key yields a genuinely EMPTY set -- NOT a one-element @($null) whose
  # `[int]$null.Line` is 0. The staged-mode fail-loud guard ("parsed 0 added lines")
  # depends on the set being empty on a parse miss.
  # (Codex BLOCKER: synthetic line-0 false-clean.)
  param([hashtable]$AddedByFile, [string]$Path)
  $set = @{}
  if ($AddedByFile -and $AddedByFile.ContainsKey($Path)) {
    foreach ($r in @($AddedByFile[$Path])) {
      if ($null -ne $r) { $set[[int]$r.Line] = $true }
    }
  }
  return $set
}

function ConvertFrom-RawDiffFields {
  # `--raw -z` fields -> @{ Status; Path; Source; DstMode } records, Path being the
  # GOVERNED side (the destination for a rename or copy).
  #
  # RAW rather than `--name-status`, and the reason is the MODES alone. Each framing
  # emits a rename's source and destination paths; what the earlier parser lost was the
  # Source field it chose not to keep, not a field `--name-status` withheld. Only the
  # object MODES are absent there, and they are what say whether a `T` destination is
  # a blob this scan can read as text and whether a status agrees with the kinds on
  # either side of it.
  # The STATUS still has to survive selection, not be discarded by `--name-only`: C
  # and T need different added-line treatment from M, and a loop given only paths
  # cannot tell them apart. Returns @{ Valid; Records } -- a truncated entry (a status
  # with no path, or a rename missing its destination) is malformed FRAMING, the same
  # class the `-z` terminator check refuses, and must not half-parse into a scan.
  #
  # Field shapes git emits: a META field `:<srcmode> <dstmode> <srcobj> <dstobj>
  # <status>[<score>]`, then `<path>` for a single-path status or `<src>` `<dst>` for
  # C/R -- so the arity is decided by the status LETTER, never by counting.
  #
  # THE MATRIX IS VALIDATED, not just the field shape. A permissive `[A-Z]` plus
  # optional digits accepted statuses outside the governed set, a scoreless C or R, and
  # non-hexadecimal object ids -- so a malformed listing returned Valid and entered
  # status-specific scanning, where the wrong branch produces an AUTHORITATIVE clean
  # result.
  #
  # THE SCORE SHAPE IS MEASURED, NOT CITED, and the probe is recorded here in full
  # because this row has been asserted in incompatible ways from documentation across
  # rounds. git-diff(1) says a score follows C and R always and MAY follow M; it does
  # not mention T. The bundled git emits one on T anyway, so the DOC is the thing that
  # is incomplete, and the accept set below follows the probe.
  #
  # THE PROBE. A throwaway repository whose index carries every governed status at
  # once (a brand-new add; an edit; an exact copy of an UNMODIFIED tracked file; a
  # near-identical rename; a total rewrite; and a tracked path whose index entry was
  # turned into a symlink with `update-index --cacheinfo 120000,<blob>,<path>`, which
  # needs no filesystem symlink). git version 2.55.0.windows.3. Each listing is the
  # same index read under a different detection setting:
  #
  #   P1  $ git diff --cached --no-color --raw
  #       :000000 100644 0000000 f2ba493 A     added.txt
  #       :100644 100644 16efb08 16efb08 R100  ren.txt  copy_of_base.txt
  #       :000000 100644 0000000 bb3e1e4 A     copy_of_mod.txt
  #       :100644 100644 16efb08 bb3e1e4 M     mod.txt
  #       :100644 100644 82d6d62 5a55688 M     rw.txt
  #       :100644 120000 639d660 ade8230 T     type.txt
  #   P2  $ git diff --cached --no-color --raw --find-copies-harder
  #       :100644 100644 16efb08 bb3e1e4 C099  base.txt  copy_of_mod.txt
  #       (plus P1's A / M / T rows, and the same R100)
  #   P4  $ git diff --cached --no-color --raw -C --find-copies-harder      -- as P2
  #   P6  $ git diff --cached --no-color --raw -M -C --find-copies-harder   -- as P2
  #   P7  $ git diff --cached --no-color --raw -B
  #       :100644 100644 82d6d62 5a55688 M100  rw.txt        <- the rows -B changes;
  #       :100644 120000 639d660 ade8230 T100  type.txt         the rest are P1's
  #   P10 $ git -c diff.renames=false diff --cached --no-color --raw --find-copies-harder
  #       -- as P2: the config does not turn detection back off
  #   P15 $ git diff --cached --no-color --raw -B -C --find-copies-harder --diff-filter=ACMRT
  #       :100644 120000 639d660 ade8230 T100  type.txt      <- a scored T survives the
  #       (the broken-rewrite M100 does NOT survive that filter)   GOVERNED filter
  #
  # The doc's own examples also SPELL the score unpadded (`C68`, `R86`) where this git
  # emits it padded, which is why the width is not validated and the VALUE bound is.
  #
  # What the accept set therefore encodes:
  #   STATUS -- exactly the governed `ACMRT` set the `--diff-filter` selects. Anything
  #     else, D included, is a listing this caller did not ask for.
  #   SCORE -- one to three digits whose VALUE is 0..100. The probe's form is padded,
  #     and the unpadded form is accepted too: the value bound is what carries the
  #     validation, while a width rule would buy nothing and would abort every real
  #     commit carrying a copy or rename if some git spelled it the other way.
  #     PRESENCE is per status, and taken from the probe: REQUIRED on C and R, which
  #     every listing scores; OPTIONAL on M and T, since P7 emits `M098`-class and
  #     `T100` records and P15 shows a scored T reaching the GOVERNED filter; and
  #     FORBIDDEN on A, which no listing scored -- consistent with an add having no
  #     source to be similar to, and with `-B`'s split halves surfacing as C/R or
  #     re-merging into a scored M rather than as a scored A.
  #   OBJECT IDS -- hexadecimal runs of NO pinned width HERE, plus the ZERO-SENTINEL
  #     relationship below. The width rule lives at the PRODUCER instead: a SHA-256
  #     repository uses 64 hex digits where SHA-1 uses 40, so this parser cannot name
  #     one width, while Get-CheckedStagedStatus pins `--no-abbrev` so every listing it
  #     is fed in production carries the full id. That pin is what keeps the sentinel
  #     test decidable -- under an abbreviating listing (git abbreviates by default,
  #     and `core.abbrev` shortens it further) a real object beginning `0000` is
  # spelled exactly like the absent-object sentinel. Production emits full IDs.
  #   OBJECT-ID SENTINELS -- an id is all-zero EXACTLY where its own side's mode is
  #     `000000`, checked in Test-IsRawObjectIdSentinelPair. Both halves come from the
  #     bundled git's own raw-format documentation, which states the sentinel on the
  #     MODE and the ID together: a source is `000000`/`0{40}` for a creation or an
  #     unmerged index entry, and a destination is `000000`/`0{40}` for a deletion or
  #     an unmerged entry -- so for an INDEX-vs-HEAD listing the two axes always agree.
  #     The doc's ONE exception is a destination "from the work tree and out of sync
  #     with the index", which is a listing this caller never issues; probed, that and
  #     intent-to-add are exactly the shapes a spelling-only check let through:
  #       $ git diff --no-color --raw               (worktree, NOT --cached)
  #       :100644 100644 4cb29ea 0000000 M    c.txt        <- unwritten destination
  #       $ git add -N ita.txt ; git diff --no-color --raw
  #       :000000 100644 0000000 0000000 A    ita.txt      <- intent-to-add
  #     Each names a destination object the repository does not hold, so routing it
  #     into add or whole-blob scanning reads bytes that are not there. The width is
  #     deliberately unconstrained on BOTH sides of the rule: the doc spells the
  #     sentinel `0{40}` while the same listing abbreviates it to seven digits. The
  #     EMPTY blob is not the sentinel and must keep parsing -- it hashes to
  #     e69de29..., an ordinary id.
  #   MODES -- six octal digits, checked as OBJECT KINDS against the measured
  #     status/kind table in Test-IsGitStatusKindPair rather than as zero-vs-nonzero
  #     sides. That weaker check accepted a `T` whose kinds never changed and an `M`
  #     across regular-to-symlink alike, and each selects a whole-blob or added-hunk
  #     policy the modes contradict. A record outside the table is metadata this scan
  #     would otherwise route on the strength of a letter the rest of it disagrees
  #     with.
  # A field failing any of that is malformed framing rather than a value read out of
  # position -- including an EMPTY one, which is not a token any of these shapes can be.
  param([string[]]$Fields)
  $recs = New-Object 'System.Collections.Generic.List[object]'
  $f = @($Fields)
  $rxMeta = [regex]('^:(?<srcmode>[0-7]{6}) (?<dstmode>[0-7]{6}) (?<srcobj>[0-9a-fA-F]+) (?<dstobj>[0-9a-fA-F]+) (?<status>[ACMRT])(?<score>[0-9]{1,3})?$')
  $i = 0
  while ($i -lt $f.Count) {
    $tok = [string]$f[$i]
    $meta = $rxMeta.Match($tok)
    if (-not $meta.Success) { return @{ Valid = $false; Records = @() } }
    $letter = $meta.Groups['status'].Value
    $isPair = ($letter -eq 'C' -or $letter -eq 'R')
    $hasScore = $meta.Groups['score'].Success
    # PRESENCE PER STATUS, not merely a requirement on C/R. Leaving the others
    # unconstrained let `A050` validate and enter add-specific scanning, since an
    # optional group placed after every letter permits a score the status cannot
    # have. Per the probe above: C and R always carry one; `-B` produces the scored M
    # and T; no listing scored an A, and an add has no source to be similar to.
    if ($isPair -and -not $hasScore) { return @{ Valid = $false; Records = @() } }
    if ($hasScore -and $letter -ceq 'A') { return @{ Valid = $false; Records = @() } }
    if ($hasScore -and ([int]$meta.Groups['score'].Value) -gt 100) { return @{ Valid = $false; Records = @() } }
    if (-not (Test-IsRawObjectIdSentinelPair -Mode $meta.Groups['srcmode'].Value -ObjectId $meta.Groups['srcobj'].Value)) { return @{ Valid = $false; Records = @() } }
    if (-not (Test-IsRawObjectIdSentinelPair -Mode $meta.Groups['dstmode'].Value -ObjectId $meta.Groups['dstobj'].Value)) { return @{ Valid = $false; Records = @() } }
    $srcKind = Get-GitObjectKind -Mode $meta.Groups['srcmode'].Value
    $dstKind = Get-GitObjectKind -Mode $meta.Groups['dstmode'].Value
    if (-not (Test-IsGitStatusKindPair -Status $letter -SourceKind $srcKind -DestinationKind $dstKind)) { return @{ Valid = $false; Records = @() } }
    $need = if ($isPair) { 2 } else { 1 }
    if (($i + $need) -ge $f.Count) { return @{ Valid = $false; Records = @() } }
    $path = [string]$f[$i + $need]
    if ([string]::IsNullOrEmpty($path)) { return @{ Valid = $false; Records = @() } }
    $source = if ($isPair) { [string]$f[$i + 1] } else { '' }
    if ($isPair -and [string]::IsNullOrEmpty($source)) { return @{ Valid = $false; Records = @() } }
    $recs.Add(@{ Status = $letter; Path = $path; Source = $source; SrcMode = $meta.Groups['srcmode'].Value; DstMode = $meta.Groups['dstmode'].Value })
    $i += $need + 1
  }
  return @{ Valid = $true; Records = $recs.ToArray() }
}

function Get-GitObjectKind {
  # The OBJECT KIND a raw-diff mode names: 'absent', 'regular', 'symlink', 'gitlink',
  # or 'unknown' for a mode outside git's set.
  #
  # KIND, not the raw mode, is what the status letter is a function of -- an
  # executable bit is a mode change WITHIN the regular kind, while regular-to-symlink
  # is a kind change. Comparing modes for equality would call the first a type change;
  # comparing only zero-vs-nonzero, as this validator did, calls neither one.
  param([string]$Mode)
  switch ($Mode) {
    '000000' { return 'absent' }
    '100644' { return 'regular' }
    '100755' { return 'regular' }
    '120000' { return 'symlink' }
    '160000' { return 'gitlink' }
    default  { return 'unknown' }
  }
}

function Test-IsRawObjectIdSentinelPair {
  # Does ONE side of a raw meta field agree with itself -- is its object id all-zero
  # exactly where its mode says the object is absent?
  #
  # The zero id is git's ABSENT-OBJECT sentinel, and its raw-format documentation
  # states the sentinel on the MODE and the ID together for every case an INDEX-vs-HEAD
  # listing produces, so the two axes agree there by construction. A
  # hexadecimal-spelling check reads each field alone and so accepts every crossed
  # pairing -- an add whose absent source carries a real id, or a present side whose
  # object is the sentinel. The second one is the dangerous direction: it names an
  # object the repository does not hold, and the scan then reads that side as though
  # it did. Both crossings are refused. WIDTH is not part of THIS rule and cannot be --
  # the id width is a repository configuration -- so what keeps the all-zero test
  # decidable is the producer's `--no-abbrev` pin in Get-CheckedStagedStatus. Without
  # it a real object beginning `0000` is spelled exactly like the sentinel, and this
  # predicate refuses a perfectly valid record.
  #
  # This is a PER-SIDE invariant on purpose. Which side may be absent for a given
  # status is Test-IsGitStatusKindPair's question, and answering it in two places
  # would let the two answers drift.
  param([string]$Mode, [string]$ObjectId)
  # An ABSENT field is not a side, and answering the biconditional over one would
  # return TRUE for it: neither an empty mode nor an empty id is the sentinel, so
  # "both are not the sentinel" reads as agreement. That is the one direction this
  # predicate must never take -- it is called to decide whether a field is safe to
  # act on. The caller only reaches here through a successful match on the meta
  # regex, so an empty field cannot arrive from it, but a predicate whose failure
  # mode is a silent PASS is one refactor away from being wrong.
  if ([string]::IsNullOrEmpty($Mode) -or [string]::IsNullOrEmpty($ObjectId)) { return $false }
  $absentMode = ([string]$Mode -ceq '000000')
  $zeroId = ([string]$ObjectId -match '^0+$')
  return ($absentMode -eq $zeroId)
}

function Test-IsGitStatusKindPair {
  # Is this (status, source kind, destination kind) triple one git actually emits?
  #
  # DERIVED FROM MEASUREMENT, not from the documentation. Every stageable pair was
  # constructed against a real index with git 2.55.0 and its raw record read back:
  #     :100644 100644 ... M   (content change)
  #     :100644 100755 ... M   (mode-only, SAME blob -- an exec bit is not a T)
  #     :100644 120000 ... T   (regular -> symlink)
  #     :100644 160000 ... T   (regular -> gitlink)
  #     :000000 100644 ... A   (and the same A for 100755 / 120000 / 160000)
  #     :100644 000000 ... D   (the only absent DESTINATION, and the filter drops it)
  #     :100644 100644 ... R100 <src> <dst>
  # A rename and a copy whose destination changed KIND were each staged as their own
  # probe -- the source blob re-added as a symlink at a new path -- and git paired
  # NEITHER, reporting a plain `A` each time. So R and C never cross kinds either.
  #
  # The rule the table yields: A has an absent source and a present destination; every
  # other governed status has each side present, and T is EXACTLY the kind-changing
  # one while M, R and C are exactly the kind-preserving ones. A record outside that
  # set is not a state git produced, and acting on its letter would select a
  # whole-blob or added-hunk policy the modes contradict.
  param([string]$Status, [string]$SourceKind, [string]$DestinationKind)
  if ($DestinationKind -eq 'absent' -or $DestinationKind -eq 'unknown') { return $false }
  if ($SourceKind -eq 'unknown') { return $false }
  if ($Status -ceq 'A') { return ($SourceKind -eq 'absent') }
  if ($SourceKind -eq 'absent') { return $false }
  if ($Status -ceq 'T') { return ($SourceKind -ne $DestinationKind) }
  if ($Status -ceq 'M' -or $Status -ceq 'R' -or $Status -ceq 'C') { return ($SourceKind -eq $DestinationKind) }
  return $false
}

function Test-IsRegularBlobMode {
  # Is the index entry a REGULAR FILE blob -- the only object kind whose bytes are the
  # file's own text?
  #
  # The governed DESTINATION modes are regular (100644) and executable (100755); a
  # symlink (120000) and a gitlink (160000) are the other kinds a governed entry can
  # name, and the absent side of an add or delete carries `000000`. What disqualifies
  # the others is the same property: their object's bytes are NOT the file's text.
  # A symlink's blob is its TARGET PATH; a gitlink names a COMMIT, which resolves to a
  # commit display where its object is present and fails outright where it is not,
  # since a submodule's objects commonly live only in that submodule's own database.
  # Either outcome is a scan over something the repository does not hold as that file,
  # so the gate is on the mode and never on what a read of the object returns.
  param([string]$Mode)
  return ((Get-GitObjectKind -Mode $Mode) -eq 'regular')
}

function Get-ObjectKindLabel {
  param([string]$Mode)
  switch ($Mode) {
    '120000' { return 'a symlink entry (its staged blob is the link target, not file text)' }
    '160000' { return 'a gitlink entry (a submodule commit, not file text)' }
    default  { return "an index entry of mode $Mode, which is not a regular file" }
  }
}

function Get-PerFileDiffSelector {
  # The rename-detection flags and the pathspec a per-file staged diff needs for one
  # selection record: @{ Flags; Pathspec }.
  #
  # A RENAME must name its SOURCE too. Detection compares the destination against the other
  # side of the diff, so a pathspec naming only the destination leaves git nothing to
  # pair and it renders the rename as a whole-file ADDITION -- every line of an
  # unchanged file attributed to this commit, which is how untouched historical text
  # reached an ERROR-tier class and aborted a commit that had not edited a word of it.
  # MEASURED, both directions, against a true rename staged with its source removed:
  #     $ git diff --cached --raw -M -C --find-copies-harder -- old.md new.md
  #     :100644 100644 b18aad5 19364c5 R098   old.md  new.md
  #     $ git diff --cached --raw -M -C --find-copies-harder -- new.md
  #     :000000 100644 0000000 19364c5 A      new.md
  # The detection FLAGS travel with the pathspec because the listing that produced this
  # record asked for detection: a per-file diff without them, under a
  # `diff.renames=false` config, splits the same change back into an add and a delete.
  # `-M` is stated rather than left to `--find-copies-harder`'s internal promotion --
  # rename pairing is what this selector needs, and asking for it by name keeps the
  # requirement in the flags rather than in one git's implementation of another flag.
  #
  # Only R needs the pair. A COPY's destination content is governed as a whole blob
  # regardless of how git renders its diff, so naming its source would change nothing
  # the scan reads.
  #
  # A SOURCELESS R THROWS rather than degrading to the destination alone. The parser
  # refuses that record shape, so reaching here means a caller built the record by
  # hand -- and the quiet degradation is exactly the whole-file-add attribution this
  # function exists to prevent, restored without a word of diagnostic.
  param([object]$Record)
  $path = [string]$Record.Path
  $source = [string]$Record.Source
  if ([string]$Record.Status -ceq 'R') {
    if ([string]::IsNullOrEmpty($source)) {
      throw "author-lint: rename record for '$path' carries no source path; ConvertFrom-RawDiffFields rejects that shape, so a hand-built record reached the selector."
    }
    # The SOURCE half of the same argv boundary the blob reader guards for the
    # destination, and the ONLY place a source becomes a git argument: a copy's source
    # is never named, so it is never checked.
    if (-not (Test-IsArgvRepresentablePath -Path $source)) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: the rename source '$source' contains a double quote, which this script cannot hand to git as a native argument without changing which entry is read -- refusing to report clean on a rename it cannot address.")
      exit 2
    }
    # `-l0` travels with the detection flags for the reason Get-CheckedStagedStatus
    # records: past `diff.renameLimit` git SKIPS the exhaustive fallback, exits 0, and
    # says so only on a stderr this script drops. This diff is what separates a
    # rename's edited lines from its moved ones, so a skip here restores exactly the
    # whole-file-add attribution the pair pathspec exists to prevent.
    return @{ Flags = @('-M', '-C', '--find-copies-harder', '-l0'); Pathspec = @($source, $path) }
  }
  return @{ Flags = @(); Pathspec = @($path) }
}

function New-StagedRecordMap {
  # Path -> selection record, keyed ORDINALLY.
  #
  # PowerShell's default hashtable compares string keys case-INSENSITIVELY while git
  # pathnames are case-SENSITIVE, so `Docs/a.md` and `docs/a.md` collided here and one
  # record silently overwrote the other -- immediately after Select-UniqueOrdinalPaths
  # had deliberately kept them as the distinct files they are. Each loop then read the
  # survivor's status and mode for each of them, which under-scans one file or whole-blob
  # over-scans the other.
  #
  # The whole RECORD is the value, not a status string: the status, the rename source
  # and the destination mode a path was SELECTED under travel together rather than as
  # parallel maps that can disagree.
  #
  # A DUPLICATE destination is REJECTED rather than overwritten. Index assignment made
  # the last record win, so records naming one path -- with different statuses,
  # sources or modes -- left only one driving the object-kind and whole-blob decisions,
  # and the branch that got dropped was as likely to be the STRICTER one. Git does not
  # emit a duplicate destination for a single index diff, so a listing that carries one
  # is not describing a state this scan can act on. Returns @{ Valid; Map; Duplicate }
  # so the caller can fail loud with the offending path rather than swallowing it here.
  param([object[]]$Records)
  $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
  foreach ($rec in @($Records)) {
    $key = [string]$rec.Path
    if ($map.ContainsKey($key)) { return @{ Valid = $false; Map = $null; Duplicate = $key } }
    $map[$key] = $rec
  }
  return @{ Valid = $true; Map = $map; Duplicate = '' }
}

function Test-IsWholeBlobAddedStatus {
  # Does this status make the WHOLE staged blob added content?
  #
  # A COPY's every line is new to the index, and a TYPE CHANGE replaces the blob
  # wholesale -- git's diff for either can be empty or partial (a pure copy has NO
  # hunks at all), so the added-line set derived from hunks under-reports the content
  # this commit actually introduces. Provenance does not exempt content: the
  # added-line contract is about what the pending commit puts in the tree.
  #
  # A RENAME is deliberately NOT here. Its bytes already existed under the source
  # name, so nothing about them is new to the tree, and re-scanning an unchanged blob
  # would put historical text through the ERROR-tier classes and abort a commit that
  # edited none of it. That the destination path may carry validations the source did
  # not is reported as a DIAGNOSTIC instead -- see the rename note in each staged
  # loop. A comparison of source and destination policy was tried and REMOVED
  # (2026-08-02): it has to answer directionally (a policy-REMOVING rename adds none),
  # it has to agree with every path-sensitive gate including one that reads the blob
  # body, and it puts unchanged bytes back through a text scan. Do not reintroduce it.
  #
  # The object-kind gate runs BEFORE this, so the only T that lands here is one whose
  # destination IS readable file text.
  param([string]$Status)
  return ($Status -ceq 'C' -or $Status -ceq 'T')
}

function New-WholeBlobAddedSet {
  # An EMPTY blob has NO lines, and the empty string must therefore yield an EMPTY set.
  # PowerShell's split returns one (empty) element for it, so marking every element
  # added invented a line-1 claim in a file that holds no line 1 -- and the no-content
  # callers key on a zero count, so that phantom line was exactly what kept an empty
  # staged blob out of the path written for it.
  param([string]$Text)
  $set = @{}
  if ([string]::IsNullOrEmpty($Text)) { return $set }
  $n = @($Text -split "`n").Count
  for ($i = 1; $i -le $n; $i++) { $set[$i] = $true }
  return $set
}

function ConvertFrom-StagedBlobBytes {
  # Shared decoding boundary for Git reads and already captured paired blobs.
  # One BOM is framing. Lone CR cannot be normalized under hunk attribution:
  # Git counts that content as one physical line, unlike the normalized scanner.
  param([byte[]]$Bytes, [string]$Status = '')
  try { $text = $script:Utf8Strict.GetString($Bytes) }
  catch [System.Text.DecoderFallbackException] { return @{ Ok = $false; Text = $null; Reason = 'decode' } }
  if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
  $text = $text -replace "`r`n", "`n"
  if (($text.IndexOf([char]13) -ge 0) -and -not (Test-IsWholeBlobAddedStatus -Status $Status)) {
    return @{ Ok = $false; Text = $null; Reason = 'lone-cr' }
  }
  $text = $text -replace "`r", "`n"
  if ($text.IndexOf([char]0) -ge 0) { return @{ Ok = $false; Text = $null; Reason = 'nul' } }
  return @{ Ok = $true; Text = $text; Reason = '' }
}

function Read-StagedBlobText {
  # The staged blob's bytes, decoded ONCE and strictly: @{ Ok; Text; Reason }.
  #
  # `& git show` hands stdout to PowerShell's native-output decoding, which replaces
  # every undecodable byte with U+FFFD and joins records by line. A scan over that
  # string is a scan over REPLACEMENT TEXT: the file's real bytes were never seen,
  # and a whole-blob status would attribute all of it and report clean. Reading the
  # raw bytes and decoding them under the strict decoder is what makes 'this is text'
  # an answer rather than an assumption.
  #
  # THIS REPLACES a decoded-window NUL probe (removed 2026-08-02, do not restore):
  # that predicate asked its question AFTER the lenient decode and only within a
  # leading window, so invalid UTF-8 carrying no NUL passed, and so did a NUL past
  # the window. Each answer is unbounded here: a decode failure is a refusal, and
  # NUL is searched over the WHOLE blob.
  #
  # NUL is the text/binary boundary git itself keys on, and it is checked on the
  # DECODED string only because a NUL byte and a U+0000 char are the same codepoint
  # either way -- unlike the decode, that test cannot be moved by an encoding.
  #
  # $Status decides ONE question: whether this blob's added lines are attributed from
  # diff hunks (see the lone-CR note below). An unset value is treated as the
  # hunk-attributed case, which is the refusing one.
  param([string]$RepoRoot, [string]$Path, [string]$Status = '')
  # THE REFUSAL SITS AT THE BOUNDARY, not at the selection. Both staged loops reach
  # here only after the extension filter and the object-kind gate, so this is the
  # narrowest point that still covers every destination path becoming a git argument.
  # Refusing earlier -- over the whole raw listing -- aborted the run for an entry no
  # scanner would ever read, which contradicts the no-content contract: a selection
  # holding nothing this linter scans must report no content, not exit.
  if (-not (Test-IsArgvRepresentablePath -Path $Path)) {
    Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: the staged path '$Path' contains a double quote, which this script cannot hand to git as a native argument without changing which entry is read -- refusing to report clean on a file it cannot address.")
    exit 2
  }
  $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "author-lint-blob-$([guid]::NewGuid().ToString('N')).bin")
  $tmpErr = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "author-lint-bloberr-$([guid]::NewGuid().ToString('N')).bin")
  # `:0:` NAMES THE STAGE EXPLICITLY. Bare `:<path>` shares its grammar with
  # `:<stage>:<path>`, so an index path that itself begins `0:` parses as a stage
  # selector and resolves a DIFFERENT entry -- a clean scan over the wrong blob. Every
  # record reaching here is stage 0 (the governed status set excludes unmerged entries),
  # so naming the stage costs nothing and removes the ambiguity for every path rather
  # than for the ones that happen not to collide.
  $quotedArgs = @(ConvertTo-ProcessArgumentList -Arguments @('-C', $RepoRoot, 'show', ":0:$Path"))
  try {
    # STDERR IS REDIRECTED TOO, and that is an output-integrity boundary rather than
    # tidiness: this child is launched with a repository-controlled `:<path>` argument
    # that a failing `git show` echoes back, and a console-inherited stderr bypasses
    # every sanitized sink in this script -- CR, ESC, bidi controls and Unicode
    # separators in that payload can erase, reorder or split the diagnostics printed
    # around it. The payload is DROPPED rather than reported: the caller's own message
    # already names the file and the failure, and `Invoke-GitChecked` keeps git's
    # stderr off the console on the same reasoning.
    try {
      $proc = Start-Process -FilePath 'git' -ArgumentList $quotedArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $tmpErr
    } catch {
      # SANITIZED, for the same reason: a launch failure's message can carry the
      # argument text that provoked it.
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] WARNING: could not launch git to read the staged blob for '$Path' -- $($_.Exception.Message)")
      return @{ Ok = $false; Text = $null; Reason = 'read' }
    }
    if ($proc.ExitCode -ne 0) { return @{ Ok = $false; Text = $null; Reason = 'read' } }
    if (-not (Test-Path -LiteralPath $tmp)) { return @{ Ok = $false; Text = $null; Reason = 'read' } }
    $bytes = [System.IO.File]::ReadAllBytes($tmp)
    # ONE leading preamble, then EVERY line terminator, BEFORE any grammar reads the
    # text. The strict decoder does neither for us, and each omission was a real
    # miscall rather than a tidiness point:
    #   * U+FEFF survives the decode as a CHARACTER, and it is not `\s` (MEASURED), so
    #     an anchored first-line regex cannot match through it -- a BOM-first
    #     frozen-snapshot marker missed its own anchored pattern and promoted that
    #     doc's line anchors from advisory to commit-blocking ERROR. Worktree mode
    #     never saw this: `Get-Content -Raw -Encoding UTF8` consumes the preamble
    #     (MEASURED: first char `<`, not U+FEFF), so the two modes disagreed about the
    #     file's own first character. Exactly one is consumed -- a SECOND U+FEFF is a
    #     zero-width no-break space belonging to the text, not framing.
    #   * A lone CR is a line terminator this scan must honour, and replacing only
    #     CRLF left it inside a record: every consumer splits on LF alone, so a
    #     CR-only blob arrives as ONE record and each line after the first is
    #     unreachable by the anchored per-line classes -- content hidden from the scan
    #     while the file reports clean.
    #     NORMALIZING IT HERE IS NOT ENOUGH FOR A HUNK-ATTRIBUTED BLOB, and the second
    #     half of that is what the refusal below answers. MEASURED against real git and
    #     PowerShell: git writes an added record `+a<CR>b` as ONE patch line, while
    #     `& git`'s native record pipeline hands the diff reader `+a` and a
    #     prefix-less `b` -- so only the first normalized line enters the added set,
    #     the in-hunk added count agrees at one, and the parity guard stays dormant
    #     while every later normalized line escapes the per-line classes. The two
    #     pipelines disagree in the DIFF reader, which this function cannot reach, so
    #     the blob is REFUSED: mapping normalized subrecords back to originating git
    #     records means reconciling two pipelines, and the degradation contract already
    #     has a loud answer for a blob this scan cannot stand behind.
    #     A WHOLE-BLOB status derives its added set from this text alone
    #     (New-WholeBlobAddedSet), so no attribution disagreement exists for it and the
    #     normalization is what makes its later lines reachable.
    return (ConvertFrom-StagedBlobBytes -Bytes $bytes -Status $Status)
  } finally {
    foreach ($scratch in @($tmp, $tmpErr)) {
      if (-not (Test-Path -LiteralPath $scratch)) { continue }
      Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue -ErrorVariable rmErr
      if ($rmErr) { Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] WARNING: could not remove scratch file '$scratch' -- $($rmErr[0].Exception.Message)") }
    }
  }
}

function Get-StagedBlobReadLabel {
  # The diagnostic text a non-Ok read reports, so each loop names the same reason
  # for the same refusal.
  param([string]$Reason)
  switch ($Reason) {
    'decode'  { return 'a staged blob whose bytes are not valid UTF-8' }
    'nul'     { return 'a staged blob carrying a NUL byte, so it is not text' }
    'lone-cr' { return 'a staged blob terminating lines with a lone CR, which this commit' + [char]0x27 + 's added lines cannot be attributed against' }
    default   { return 'a staged blob this run could not read' }
  }
}

function Test-IsBinaryAttributedDiff {
  # Did git decline to emit a TEXT diff for this file?
  #
  # `diff=binary` in .gitattributes, `-text`, or git's own content heuristic all
  # produce a diff with no hunks -- so the added-line parse yields an empty set, the
  # non-empty-diff cross-check ALSO yields zero, and the file was skipped in silence.
  # A governed file the scan cannot read is exactly the case the loud-degradation
  # contract exists for, so it must reach a diagnostic rather than a `continue`.
  #
  # Both spellings: the default summary line, and the `--binary` patch form a caller
  # or a config could turn on.
  param([string]$DiffText)
  if ([string]::IsNullOrEmpty($DiffText)) { return $false }
  foreach ($raw in ($DiffText -split "`n")) {
    $l = ($raw -replace "`r$", '')
    # ORDINAL for the whole-line marker: `-ceq` collates by culture, so a
    # zero-weight character (MEASURED with U+FEFF) makes an ordinary content line
    # compare EQUAL to the marker and degrade a file the scan could have read.
    if ($l -cmatch '^Binary files .* differ$') { return $true }
    if ([string]::Equals($l, 'GIT binary patch', [System.StringComparison]::Ordinal)) { return $true }
  }
  return $false
}

function Measure-InHunkAddedLines {
  # Count ADDED lines that sit INSIDE a hunk (after `@@`), with the SAME hunk
  # awareness as Get-AddedRecordsFromDiff. The staged fail-loud guard uses this as a
  # cross-check ("the diff has added content but the parser produced 0 records ->
  # fail"). Counting by first-char-inside-hunk means a content `+++ b/...` line (a
  # `+` line in a hunk) IS counted -- the prior `-notmatch '^\+\+\+'` filter wrongly
  # dropped it, so a violation on such a line could exit clean.
  # (Codex BLOCKER.)
  param([string]$DiffText)
  if ([string]::IsNullOrEmpty($DiffText)) { return 0 }
  $n = 0
  $inHunk = $false
  foreach ($raw in ($DiffText -split "`n")) {
    $line = $raw -replace "`r$", ''
    if ($line -match '^diff --git ') { $inHunk = $false; continue }
    if ($line -match '^@@') { $inHunk = $true; continue }
    if ($inHunk -and $line.StartsWith('+')) { $n++ }
  }
  return $n
}

function Test-IsSingleFileDiff {
  # Does this diff cover EXACTLY one file? The accept set is {1}: zero sections means
  # the request did not select the file it named, and more than one means it selected
  # siblings -- neither is data the per-file attribution may interpret.
  param([string]$DiffText)
  return ((Measure-DiffFileHeaders -DiffText $DiffText) -eq 1)
}

function Measure-DiffFileHeaders {
  # Count the FILE SECTIONS in a diff.
  #
  # The per-file callers attribute every hunk to the path they asked for, which is
  # sound ONLY while the request really selected one file. A pathspec is a GLOB by
  # default, so a path holding `*`, `?` or `[` can select siblings and hand their
  # hunks the wrong path -- lines reported against a file that does not contain them.
  # Counting sections is what turns that from silent mislabelling into a loud abort.
  # (Codex BLOCKER.)
  #
  # No hunk state, unlike the `+++`-sensitive readers: every line INSIDE a hunk
  # carries a `+`/`-`/space/`\` prefix, so a bare `diff --git ` at column zero cannot
  # be content and needs no disambiguation.
  param([string]$DiffText)
  if ([string]::IsNullOrEmpty($DiffText)) { return 0 }
  $n = 0
  foreach ($raw in ($DiffText -split "`n")) {
    if (($raw -replace "`r$", '') -match '^diff --git ') { $n++ }
  }
  return $n
}

function Get-HistoryEntryBodyLineSet {
  # For the root History.md log ONLY: return the hashtable-set of line numbers that
  # fall inside a DATED entry BODY -- the lines AFTER a `## YYYY-MM-DD ...` heading
  # (incl. the established slash day-range form `## YYYY-MM-DD/NN ...`)
  # through the line before the NEXT `## ` heading (dated or not) or EOF. The dated
  # heading line itself is EXCLUDED (the waiver is body-only per every contract
  # site; a count-bearing dated title stays in class -- Codex BLOCKER
  #). The count-drift exemption applies ONLY to these lines, matching the
  # review contract's "a dated History.md ENTRY BODY": the file PREAMBLE (before the
  # first dated heading) and any UNDATED `## ` section (e.g. `## Notes`) are a static
  # snapshot too, but the contract scopes the waiver to DATED entries, so their
  # counts stay in class. The whole-file gate the first cut used (leaf name ==
  # History.md) over-exempted the lot -- preamble, undated sections, and a nested
  # file named History.md -- past the contract; the caller now pairs this mask with a
  # ROOT-path gate. (Codex CROSS-CRATE-CONTRACT.)
  # `## ` boundaries are detected only OUTSIDE code fences (shared Get-FencedLineFlags),
  # so a `## ...` line inside a ``` block is not mistaken for a heading. An H3 (`### `)
  # is NOT an H2 boundary (a subsection stays inside its dated entry).
  param([object[]]$Records)
  $set = @{}
  if (-not $Records) { return $set }
  $texts = @($Records | ForEach-Object { [string]$_.Text })
  $fenced = Get-FencedLineFlags -Lines $texts
  $inDatedEntry = $false
  for ($i = 0; $i -lt $Records.Count; $i++) {
    $text = [string]$Records[$i].Text
    # A level-2 ATX heading (`## `, not `### `) OUTSIDE a fence is an entry boundary:
    # a dated heading opens a dated entry; ANY other `## ` heading closes the dated
    # region (an undated section is not part of a dated entry).
    if (-not $fenced[$i] -and $text -match '^##\s') {
      # The date must END at a boundary: whitespace, EOL, or the established
      # slash day-range form `/NN` itself ending at whitespace/EOL
      # (`## 2026-05-01/02 ...` exists in the root log). A looser tail would
      # accept `## 2026-07-090 notes`, `## 2026-07-09foo`, or `## 2026-07-09/9foo`
      # and open the exempt region for a non-dated section. (Codex BLOCKER
      #: prefix leak, range-form exclusion, then malformed
      # range suffixes -- each direction is pinned by HEB7/HEB8.)
      $inDatedEntry = ($text -match '^##\s+\d{4}-\d{2}-\d{2}(\s|$|/\d{2}(\s|$))')
      # The HEADING itself is NOT in the mask -- every contract site scopes the
      # waiver to the entry BODY, so a count-bearing dated title stays in class.
      # (Codex BLOCKER: the heading leaked into the exempt set.)
      continue
    }
    if ($inDatedEntry) { $set[[int]$Records[$i].Line] = $true }
  }
  return $set
}

# ---------------------------------------------------------------------------
# Check runner: given a file path, its records (line/text), and the repo
# resolver seams, run every check and return findings tagged with the file.
# ---------------------------------------------------------------------------
function Invoke-FileChecks {
  param(
    [string]$Path,
    [object[]]$Records,
    [string]$PlanContentForClosure,   # full PLAN.md content if this file IS PLAN.md, else $null
    [scriptblock]$Resolver,
    [scriptblock]$IsTopLevel
  )
  $findings = @()
  # Frozen-snapshot status comes from the doc's OWN content (the explicit marker),
  # not its filename. $Records carry the full doc text (one record per line), so
  # reconstruct the head and probe for the marker. (Marker model.)
  $headText = (@($Records | Select-Object -First 30 | ForEach-Object { [string]$_.Text }) -join "`n")
  $isFrozen = Test-HasFrozenSnapshotMarker -Path $Path -Content $headText
  # $isHistory (LEAF name) drives the SELF-NARR tier: History.md (the retrospective
  # landing log) is ERROR, every other narrative doc ADVISORY -- an entry narrating
  # its OWN not-yet-landed merge is a factual defect (the merge SHA is unknowable
  # while the entry rides the branch), so it stays ERROR here. LEAF-based (nested
  # History.md included) since SELF-NARR is a STRICTER treatment -- over-applying it
  # only adds flagging, the safe direction.
  $isHistory = ([System.IO.Path]::GetFileName($Path) -eq 'History.md')
  # Count-drift EXEMPTION (INVENTORY + MAGNITUDE): a dated History entry is a static,
  # append-only snapshot -- once written its counts cannot drift the way live-doc
  # prose does -- so the operator ruled an exact count inside a dated entry is NOT a
  # review finding (2026-07-09). The waiver is NARROWER than SELF-NARR on BOTH axes,
  # matching the review-prompt-template contract ("a dated History.md ENTRY BODY"):
  #   - FILE: only the ROOT History.md log, NOT a nested file named History.md, and
  #     compared ORDINALLY -- `-eq` would exempt a root `history.md` case variant, and
  #     `-ceq` is case-sensitive but still COLLATES BY CULTURE, which gives zero-weight
  #     characters no value at all (MEASURED: a U+FEFF-prefixed `History.md` and a
  #     soft-hyphen-bearing one both compare EQUAL under it). A waiver OVER-applied is
  #     the risk here (opposite to SELF-NARR's strictness, whose -eq leaf match errs
  #     STRICTER on a case variant), so the gate is a code-unit match on the exact root
  #     path, not the leaf and not a collation.
  #   - LINE: only lines inside a DATED entry body (Get-HistoryEntryBodyLineSet); the
  #     file PREAMBLE and any UNDATED `## ` section stay in class.
  # The detectors still RUN; a finding whose line is exempt is dropped below. DRIFT-
  # staleness waiver ONLY: a History count that mis-states a LIVE contract the SAME
  # diff changes is a factual doc-vs-code defect, but this mechanical SHAPE detector
  # cannot tell drift-bait from a factual mismatch, so it defers that class to the AI
  # gate for the exempt lines (the gate stays the failsafe; the reviewer-side contract
  # is in review-prompt-template.md). LINE-ANCHOR and SELF-NARR are deliberately NOT
  # count-exempted: a `file.ext:NNN` anchor drifts because the cited SOURCE moves (its
  # exemption is the frozen-snapshot marker), and self-narration is a factual defect,
  # not a count. (Codex CROSS-CRATE-CONTRACT: the first cut skipped
  # both detectors for the WHOLE file off the leaf name, over-exempting the preamble,
  # undated sections, and nested History.md past the contract.)
  $relPath = ([string]$Path -replace '\\', '/')
  $countExemptLines = if ([string]::Equals($relPath, 'History.md', [System.StringComparison]::Ordinal)) { Get-HistoryEntryBodyLineSet -Records $Records } else { @{} }
  foreach ($f in (Get-LineAnchorFindings -Records $Records -IsFrozenSnapshot $isFrozen)) { $f['File'] = $Path; $findings += $f }
  foreach ($f in (Get-DeadRefFindings -Records $Records -Resolver $Resolver -IsTopLevel $IsTopLevel)) { $f['File'] = $Path; $findings += $f }
  foreach ($f in (Get-MagnitudeFindings -Records $Records)) {
    if ($countExemptLines.ContainsKey([int]$f.Line)) { continue }   # inside a dated History entry body -> count-drift exempt
    $f['File'] = $Path; $findings += $f
  }
  foreach ($f in (Get-SelfNarrationFindings -Records $Records -IsHistoryDoc $isHistory)) { $f['File'] = $Path; $findings += $f }
  foreach ($f in (Get-LocalEvidenceFindings -Records $Records)) { $f['File'] = $Path; $findings += $f }
  foreach ($f in (Get-MachineLocalStateFindings -Records $Records)) { $f['File'] = $Path; $findings += $f }
  # Inventory-assertion SHAPE detector: ERROR in .md prose, with NO frozen-snapshot
  # downgrade (the marker exemption is line-anchor-scoped -- see the detector).
  # No code-echo exemption in a .md doc (there is no code). Source-file
  # COMMENT scanning runs on its own staged path (Get-StagedSourceFindings). A finding
  # on a dated-History-entry-body line is dropped per $countExemptLines above.
  foreach ($f in (Get-InventoryAssertionFindings -Records $Records)) {
    if ($countExemptLines.ContainsKey([int]$f.Line)) { continue }
    $f['File'] = $Path; $findings += $f
  }
  if ($PlanContentForClosure) {
    foreach ($f in (Get-MilestoneTagFindings -PlanContent $PlanContentForClosure)) { $f['File'] = $Path; $findings += $f }
  }
  return $findings
}

function Get-StagedFileFindings {
  # Pure staged per-file DECISION logic (no git): given a staged file's full
  # text, the set of ADDED line numbers, and the resolver seams, return the
  # findings that apply to THIS commit. Full-file records give fence / PLAN
  # tag-closure context; PLAN TAG closure (a WHOLE-FILE property -- a dangling
  # ref can come from DELETING a header, never an added line) then BYPASSES the
  # added-line filter, while line-oriented classes keep it (only NEW instances).
  param([string]$Path, [string]$StagedText, [hashtable]$AddedSet, [scriptblock]$Resolver, [scriptblock]$IsTopLevel)
  $lines = $StagedText -split "`n"
  $allRecs = @()
  for ($i = 0; $i -lt $lines.Count; $i++) { $allRecs += @{ Line = ($i + 1); Text = ($lines[$i] -replace "`r$", '') } }
  $isPlan = ([System.IO.Path]::GetFileName($Path) -eq 'PLAN.md')
  $planContent = if ($isPlan) { $StagedText } else { $null }
  $fileFindings = Invoke-FileChecks -Path $Path -Records $allRecs -PlanContentForClosure $planContent -Resolver $Resolver -IsTopLevel $IsTopLevel
  $out = @()
  foreach ($f in $fileFindings) {
    if ($f.Class -eq 'TAG' -or $AddedSet.ContainsKey([int]$f.Line)) { $out += $f }
  }
  return $out
}

function ConvertTo-SafeDisplayText {
  # Text rendered for a HUMAN -- report line or console message -- with every
  # display-corrupting codepoint replaced by its `\uXXXX` escape.
  #
  # A pathname may legally hold any byte but NUL and `/`, so a staged name can carry
  # CR, ESC or BEL. Writing those raw to a terminal is not a cosmetic problem: CR
  # rewrites the line just printed, so a name ending in one HIDES the finding that
  # names it, and ESC introduces a control sequence the terminal obeys. The report
  # file inherits the same bytes and misleads its next reader in the same way.
  # Escaping is applied at the OUTPUT boundary only, never to the values the scan
  # compares, so path matching still sees git's exact bytes.
  #
  # The escaped set is decided by UNICODE CATEGORY, not by an enumerated range. An
  # enumerated C0-plus-DEL subset left the C1 block (U+0080-U+009F) raw, and a terminal
  # in an 8-bit mode reads C1 as control sequences -- the same hazard the escape exists
  # to remove, reached by the codepoints the enumeration forgot. Asking the category
  # closes it for every codepoint of that class, including any an enumeration misses.
  #
  # CONTROL IS NOT THE WHOLE HAZARD. Format defeats the same guarantee without being
  # Control: the bidirectional overrides and isolates (U+202A-U+202E, U+2066-U+2069)
  # REORDER the glyphs around them, so a repository-controlled pathname can make a
  # finding read as though it named a different file. LineSeparator and
  # ParagraphSeparator (U+2028 / U+2029) are line breaks to many renderers, so a name
  # carrying one SPLITS the report row that names it -- the erasure a raw CR performs.
  # The sibling gate scripts' `ConvertTo-SafeProcessDiagnostic` escapes the same
  # categories, so the gate's diagnostics keep one vocabulary.
  #
  # THE UNIT OF CLASSIFICATION IS THE SCALAR, NOT THE UTF-16 CODE UNIT, and the
  # distinction is the whole correctness of the guard. `GetUnicodeCategory(Char)` over
  # `ToCharArray()` sees each half of a supplementary scalar as `Surrogate`, so a
  # SUPPLEMENTARY Format scalar -- U+1BCA0, U+E0001 and U+1D173 are all category Cf,
  # MEASURED against the runtime -- classified as Surrogate and passed through raw,
  # keeping exactly the invisible layout control this escape exists to remove. The
  # string/index overload returns the SCALAR's category, so a pair is judged once.
  #
  # A valid pair whose scalar is SAFE stays intact -- escaping every non-BMP character
  # would render legitimate names unreadable for no gain (an emoji is category So). An
  # UNPAIRED surrogate is escaped: it is not a character at all, no renderer can show
  # it, and leaving malformed UTF-16 in a display path is the ambiguity this boundary
  # is meant to close.
  #
  # ONE escape vocabulary, `\uXXXX` per CODE UNIT even when the DECISION was made per
  # scalar, so a supplementary escape is a run of `\uXXXX` units rather than a wider
  # second form a reader has to recognize. Escaping the backslash too would make every
  # Windows path unreadable, so a name holding that escape text literally is
  # indistinguishable from an escaped CR -- the cheaper ambiguity, and the one that
  # cannot corrupt a terminal.
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return [string]$Text }
  $escaped = @(
    [System.Globalization.UnicodeCategory]::Control,
    [System.Globalization.UnicodeCategory]::Format,
    [System.Globalization.UnicodeCategory]::LineSeparator,
    [System.Globalization.UnicodeCategory]::ParagraphSeparator
  )
  $sb = New-Object System.Text.StringBuilder
  $i = 0
  while ($i -lt $Text.Length) {
    $paired = ([char]::IsHighSurrogate($Text[$i]) -and ($i + 1) -lt $Text.Length -and [char]::IsLowSurrogate($Text[$i + 1]))
    $width = if ($paired) { 2 } else { 1 }
    $unpairedSurrogate = ((-not $paired) -and [char]::IsSurrogate($Text[$i]))
    if ($unpairedSurrogate -or ($escaped -contains [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($Text, $i))) {
      for ($u = 0; $u -lt $width; $u++) { [void]$sb.Append('\u' + ('{0:x4}' -f [int]$Text[$i + $u])) }
    } else {
      [void]$sb.Append($Text.Substring($i, $width))
    }
    $i += $width
  }
  return $sb.ToString()
}

function Format-Report {
  param([object[]]$Findings, [string]$ScopeLabel, [int]$FileCount)
  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.AppendLine("[author-lint] scope: $ScopeLabel ($FileCount file(s) examined)")
  # Provenance stamp. The generated-doc skip is PATH-gated (Test-IsGeneratedContent
  # requires $script:GeneratedDocPathPattern), so this stamp self-skips a report
  # ONLY if it is written to the allowlisted generated path. -OutPath is an
  # unrestricted string and author-lint reports are conventionally written to
  # gitignored logs/; a report sent to any other tracked path is NOT auto-skipped,
  # which is the intended fail-safe. The `by author-lint.ps1` signature is retained
  # for the OR-branch and provenance. (Codex BLOCKER: content-only
  # skip was spoofable.)
  [void]$sb.AppendLine("Generated: $((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')) by author-lint.ps1")
  $errors = @($Findings | Where-Object { $_.Tier -eq 'ERROR' })
  $advis  = @($Findings | Where-Object { $_.Tier -eq 'ADVISORY' })
  if ($Findings.Count -eq 0) {
    [void]$sb.AppendLine('[author-lint] no findings.')
  } else {
    foreach ($f in ($Findings | Sort-Object @{e={$_.Tier}}, @{e={$_.File}}, @{e={[int]$_.Line}})) {
      # Class column widened to the longest class name (MAGIC-COUNT-ASSERT) so the
      # report's columns still line up; -f pads but never truncates.
      # A finding spanning several lines prints its whole span, and one carrying an
      # OUTCOME prints it beside the class: an author triaging the report needs to
      # tell a classified count from one the parser could not read, and needs the
      # span to find a multi-line assertion whose first line is not where the count is.
      $file = ConvertTo-SafeDisplayText -Text ([string]$f.File)
      $loc = if ($f.ContainsKey('EndLine') -and ([int]$f.EndLine -gt [int]$f.Line)) { "${file}:$($f.Line)-$($f.EndLine)" } else { "${file}:$($f.Line)" }
      $cls = if ($f.ContainsKey('Outcome')) { "$($f.Class)/$($f.Outcome)" } else { [string]$f.Class }
      # Width holds the longest class-plus-outcome label with a separating space, so
      # the location column starts at a fixed offset on every row.
      [void]$sb.AppendLine(('{0,-8} {1,-28} {2}  {3}  -> {4}' -f $f.Tier, $cls, $loc, (ConvertTo-SafeDisplayText -Text ([string]$f.Match)), $f.Hint))
    }
  }
  $verdict = if ($errors.Count -gt 0) { 'FAIL (error-tier findings present)' } else { 'OK (no error-tier findings)' }
  [void]$sb.AppendLine("[author-lint] $($errors.Count) error(s), $($advis.Count) advisory. $verdict")
  return $sb.ToString()
}

function Write-ReportFile {
  param([string]$Body, [string]$Path)
  # Best-effort write: full body to a sibling temp, then replace the target, so a
  # mid-write failure does not truncate an existing report. NOTE this is NOT the
  # MoveFileEx atomic-replace the sibling dispatch-checklist.ps1 uses for its
  # GATE artifact -- `Move-Item -Force` is adequate here because -OutPath is an
  # optional convenience copy (the report also always prints to stdout), not a
  # consumed artifact. Do not claim atomic-replacement semantics for it.
  $dir = Split-Path -Parent -Path $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $leaf = Split-Path -Leaf -Path $Path
  $targetDir = if ($dir) { $dir } else { '.' }
  $tmp = Join-Path $targetDir (".$leaf.tmp-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
  [System.IO.File]::WriteAllText($tmp, $Body, $script:Utf8NoBom)
  Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Get-PairedLintChangeRecords {
  # Name-status supplies exact endpoints; never split a diff header on spaces or
  # merge two Git indexes to invent a public attribution surface. The captured
  # attribute-neutral producer uses core.quotePath=false and a/ and b/ prefixes.
  param([string]$Domain, [string]$NameStatus, [string]$Patch, [System.Collections.IDictionary]$Entries,
    [switch]$ConservativeCandidate)
  $records = New-Object 'System.Collections.Generic.List[object]'
  $headers = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  $destinations = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($line in @($NameStatus -split "`n")) {
    if ($line.Length -eq 0) { continue }
    $columns = $line -split "`t"
    if ($columns[0] -cnotmatch '\A(?:[ADT]|M(?:[0-9]{1,3})?|[RC][0-9]{1,3})\z') { throw 'paired author-lint cannot attribute this captured change status' }
    $status = $columns[0].Substring(0, 1)
    $renamed = $status -cin @('R', 'C')
    $columnCount = if ($renamed) { 3 } else { 2 }
    if ($columns.Count -ne $columnCount) { throw 'paired author-lint change endpoints have invalid framing' }
    $source = [string]$columns[1]; $path = [string]$columns[$columns.Count - 1]
    foreach ($endpoint in @($source, $path)) {
      if ([string]::IsNullOrEmpty($endpoint) -or $endpoint -cmatch '[\x00-\x1f"\\]') { throw 'paired author-lint cannot attribute a quoted or malformed change endpoint' }
    }
    if (-not $destinations.Add($path)) { throw 'paired author-lint change destinations are duplicated' }
    $entry = $null
    if ($Entries.Contains($path) -and $Entries[$path].Domain -ceq $Domain) { $entry = $Entries[$path] }
    if (($status -ceq 'D' -and $null -ne $entry) -or ($status -cne 'D' -and $null -eq $entry)) { throw 'paired author-lint change destination differs from the validated domain tree' }
    $header = 'diff --git a/' + $source + ' b/' + $path
    if ($headers.ContainsKey($header)) { throw 'paired author-lint change headers are ambiguous' }
    $record = @{ Domain = $Domain; Path = $path; Source = $source; Status = $status; Entry = $entry
      ConservativeCandidate = [bool]$ConservativeCandidate; Sections = (New-Object 'System.Collections.Generic.List[string]') }
    $headers.Add($header, $record); $records.Add($record)
  }
  if ($ConservativeCandidate) {
    # Historical blob bytes may use an encoding rejected for candidate content.
    # Exact endpoints still exclude unchanged paths; surviving changed paths are
    # conservatively attributed as whole validated candidate blobs.
    foreach ($record in $records) { $record.Patch = '' }
    return ,$records.ToArray()
  }
  $sections = [regex]::Matches($Patch, '(?m)^diff --git [^\r\n]+')
  if ($sections.Count -eq 0) {
    if ($Patch.Length -ne 0 -or $records.Count -ne 0) { throw 'paired author-lint patch lacks the captured change sections' }
  } else {
    if ($sections[0].Index -ne 0) { throw 'paired author-lint patch has unattributed leading content' }
    for ($i = 0; $i -lt $sections.Count; $i++) {
      $header = $sections[$i].Value
      if (-not $headers.ContainsKey($header)) { throw 'paired author-lint patch section differs from the captured change endpoints' }
      $end = if ($i + 1 -lt $sections.Count) { $sections[$i + 1].Index } else { $Patch.Length }
      $headers[$header].Sections.Add($Patch.Substring($sections[$i].Index, $end - $sections[$i].Index))
    }
  }
  foreach ($record in $records) {
    # A type change can be emitted as same-path deletion plus addition. Whole-blob
    # attribution below is independent of either section's hunk line numbering.
    if ($record.Sections.Count -ne 1 -and -not ($record.Status -ceq 'T' -and $record.Sections.Count -eq 2)) { throw 'paired author-lint change lacks an unambiguous file section' }
    $record.Patch = [string]::Join('', $record.Sections.ToArray())
  }
  return ,$records.ToArray()
}

function Test-PairedLintExactDeletedBlob {
  # First attachment reviews the complete private tree against empty history, so
  # a same-path public deletion/private addition can be a domain transfer rather
  # than newly authored content. The diff producer does not use --full-index;
  # abbreviated object names cannot prove identity. Reconstruct the complete raw
  # deleted text instead, preserving BOM, CRLF and final-newline state, and require
  # the regular-file mode to survive the transfer unchanged.
  param([object]$Record, [byte[]]$CandidateBytes, [string]$CandidateMode)
  if ($null -eq $Record -or $Record.Domain -cne 'public' -or $Record.Status -cne 'D' -or
      $Record.Path -isnot [string] -or $Record.Source -cne $Record.Path -or
      $Record.Patch -isnot [string] -or $CandidateBytes -isnot [byte[]] -or
      $CandidateMode -cnotin @('100644', '100755') -or -not $Record.Patch.EndsWith("`n", [StringComparison]::Ordinal)) { return $false }
  $lines = $Record.Patch.Split([char[]]@([char]10), [StringSplitOptions]::None)
  if ($lines.Count -lt 7 -or $lines[$lines.Count - 1].Length -ne 0 -or
      $lines[0] -cne ('diff --git a/' + $Record.Path + ' b/' + $Record.Path) -or
      $lines[1] -cne ('deleted file mode ' + $CandidateMode) -or
      $lines[2] -cnotmatch '\Aindex [0-9a-f]+\.\.0+\z' -or
      $lines[3] -cne ('--- a/' + $Record.Path) -or $lines[4] -cne '+++ /dev/null' -or
      $lines[5] -cnotmatch '\A@@ -1(?:,([0-9]+))? \+0,0 @@(?: .*)?\z') { return $false }
  [int]$expectedLines = 1
  if ($Matches[1] -and -not [int]::TryParse($Matches[1], [ref]$expectedLines)) { return $false }
  if ($expectedLines -lt 1) { return $false }
  $output = New-Object IO.MemoryStream
  try {
    [int]$seen = 0
    for ($i = 6; $i -lt $lines.Count - 1; $i++) {
      $line = $lines[$i]
      if ($line.Length -eq 0 -or $line[0] -cne '-') { return $false }
      $content = $line.Substring(1)
      $bytes = $script:Utf8Strict.GetBytes($content)
      $output.Write($bytes, 0, $bytes.Length)
      $seen++
      if ($i + 1 -lt $lines.Count - 1 -and $lines[$i + 1] -ceq '\ No newline at end of file') {
        if ($i + 2 -ne $lines.Count - 1) { return $false }
        $i++
      } else { $output.WriteByte(10) }
    }
    if ($seen -ne $expectedLines -or $output.Length -ne $CandidateBytes.Length) { return $false }
    $deletedBytes = $output.GetBuffer()
    for ($i = 0; $i -lt $CandidateBytes.Length; $i++) {
      if ($deletedBytes[$i] -ne $CandidateBytes[$i]) { return $false }
    }
    return $true
  } finally { $output.Dispose() }
}

function Get-PairedLintUnchangedFirstAttachmentTransfers {
  param([object[]]$Changes, [System.Collections.IDictionary]$ContextBlobBuffers)
  $publicDeletions = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  foreach ($record in $Changes) {
    if ($record.Domain -ceq 'public' -and $record.Status -ceq 'D') { $publicDeletions.Add([string]$record.Path, $record) }
  }
  $unchanged = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($record in $Changes) {
    $path = [string]$record.Path
    if ($record.Domain -cne 'private' -or $record.Status -cne 'A' -or -not $publicDeletions.ContainsKey($path) -or
        -not (Test-IsRegularBlobMode -Mode $record.Entry.Mode) -or $ContextBlobBuffers[$path] -isnot [byte[]]) { continue }
    if (Test-PairedLintExactDeletedBlob -Record $publicDeletions[$path] -CandidateBytes $ContextBlobBuffers[$path] -CandidateMode $record.Entry.Mode) {
      $null = $unchanged.Add($path)
    }
  }
  return ,$unchanged
}

function Get-PairedLintAddedSet {
  param([string]$Path, [string]$Patch, [string]$Text)
  # Validate physical hunk attribution before reusing the ordinary added-line
  # parser. Context-bearing paired patches must not acquire a shifted candidate
  # line number from a malformed hunk or an overridden output indicator.
  $candidateLines = @($Text -split "`n")
  $oldRemaining = 0; $newRemaining = 0; $newLine = 0
  foreach ($raw in @($Patch -split "`n")) {
    $line = $raw -replace "`r$", ''
    if ($line -cmatch '^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?$') {
      if ($oldRemaining -ne 0 -or $newRemaining -ne 0) { throw 'paired author-lint patch has an incomplete hunk' }
      $oldRemaining = if ($Matches[2]) { [int]$Matches[2] } else { 1 }
      $newLine = [int]$Matches[3]
      $newRemaining = if ($Matches[4]) { [int]$Matches[4] } else { 1 }
      continue
    }
    if ($line.StartsWith('@@')) { throw 'paired author-lint patch has an unsupported hunk header' }
    if ($oldRemaining -eq 0 -and $newRemaining -eq 0) { continue }
    if ($line -ceq '\ No newline at end of file') { continue }
    if ($line.Length -eq 0 -or $line[0] -cnotin @([char]'+', [char]'-', [char]' ')) { throw 'paired author-lint patch has an invalid hunk record' }
    if ($line[0] -ne '+') { $oldRemaining-- }
    if ($line[0] -ne '-') {
      $content = $line.Substring(1)
      if ($newLine -eq 1 -and $content.Length -gt 0 -and $content[0] -eq [char]0xFEFF) { $content = $content.Substring(1) }
      if ($newLine -lt 1 -or $newLine -gt $candidateLines.Count -or
          -not [string]::Equals($content, $candidateLines[$newLine - 1], [StringComparison]::Ordinal)) { throw 'paired author-lint hunk differs from the validated candidate blob' }
      $newRemaining--; $newLine++
    }
    if ($oldRemaining -lt 0 -or $newRemaining -lt 0) { throw 'paired author-lint patch overruns a hunk range' }
  }
  if ($oldRemaining -ne 0 -or $newRemaining -ne 0) { throw 'paired author-lint patch ends inside a hunk' }
  $addedByFile = Get-AddedRecordsFromDiff -DiffText $Patch -AttributeTo $Path
  $addedSet = Get-AddedLineSetForPath -AddedByFile $addedByFile -Path $Path
  if ((Measure-InHunkAddedLines -DiffText $Patch) -ne $addedSet.Count) { throw 'paired author-lint added-line attribution is incomplete or duplicated' }
  return $addedSet
}

function New-PairedLintReferenceContext {
  # Both domains are one validated candidate namespace, not one Git index.
  param([System.Collections.IDictionary]$Entries, [System.Collections.IDictionary]$ContextBlobBuffers)
  $pathSet = [System.Collections.Hashtable]::new([StringComparer]::Ordinal)
  foreach ($path in $Entries.Keys) {
    # Already canonical tree names stay exact, including leading spaces. The
    # legacy file-list normalizer trims input and is not a candidate-tree reader.
    $pathSet[$path] = $true
    $parent = [string]$path
    while ($parent.Contains('/')) { $parent = $parent.Substring(0, $parent.LastIndexOf('/')); $pathSet[$parent] = $true }
  }
  $gitignoreText = ''
  if ($Entries.Contains('.gitignore')) {
    if (-not (Test-IsRegularBlobMode -Mode $Entries['.gitignore'].Mode)) { throw 'paired author-lint cannot read candidate .gitignore intent from a non-file object' }
    $ignoreRead = ConvertFrom-StagedBlobBytes -Bytes $ContextBlobBuffers['.gitignore'] -Status 'C'
    if (-not $ignoreRead.Ok) { throw 'paired author-lint cannot decode candidate .gitignore intent' }
    $gitignoreText = $ignoreRead.Text
  }
  $topLevels = Get-TopLevelDirSet -IndexFiles @($Entries.Keys) -GitignoreText $gitignoreText
  return @{
    Resolver = { param($candidatePath) return $pathSet.ContainsKey(([string]$candidatePath -replace '\\', '/').TrimEnd('/')) }.GetNewClosure()
    IsTopLevel = { param($name) return $topLevels.ContainsKey($name) }.GetNewClosure()
  }
}

function Invoke-PairedAuthorLint {
  # Internal in-process adapter. Retained-runtime approval and actual capture
  # custody remain operation-owner obligations, never authority supplied by this
  # object. No Git, worktree reads, environment repair, reports on disk, or exit.
  param([System.Collections.IDictionary]$InputData, [string]$ExecutingPath, [switch]$FirstAttachment)
  $expectedCount = if ($FirstAttachment -and $null -ne $InputData -and 'PrivateAttribution' -cin @($InputData.Keys)) { 3 } else { 2 }
  if ($null -eq $InputData -or $InputData.Count -ne $expectedCount -or 'Runtime' -cnotin @($InputData.Keys) -or 'CapturedInput' -cnotin @($InputData.Keys) -or
      (-not $FirstAttachment -and 'PrivateAttribution' -cin @($InputData.Keys))) { throw 'paired author-lint requires exact origin-bound input fields' }
  $runtime = $InputData['Runtime']; $captured = $InputData['CapturedInput']
  if ($null -eq $runtime -or $runtime.Id -isnot [string] -or $runtime.Id -cnotmatch '\A[0-9a-f]{64}\z' -or
      $runtime.Root -isnot [string] -or -not [IO.Path]::IsPathRooted($runtime.Root) -or $runtime.Payloads -isnot [System.Collections.IDictionary] -or
      $null -eq $captured -or $captured.Schema -ne 1 -or $captured.HasChanges -isnot [bool] -or
      (-not $FirstAttachment -and -not $captured.HasChanges)) { throw 'paired author-lint requires a retained runtime and captured changed pair' }
  $modules = @('private-governance', 'paired-governance', 'paired-tree', 'review-preparation', 'project-preparation', 'paired-review-input')
  $payloadNames = @('scripts/shared/author-lint.ps1', 'scripts/codex/review-prompt-template.md') + @($modules | ForEach-Object { 'scripts/' + $_ + '.psm1' })
  foreach ($relative in $payloadNames) {
    if ($relative -cnotin @($runtime.Payloads.Keys) -or $runtime.Payloads[$relative].Bytes -isnot [byte[]] -or
        $runtime.Payloads[$relative].Path -cne (Join-Path $runtime.Root $relative.Replace('/', '\'))) { throw 'paired author-lint requires exact retained payload paths and byte buffers' }
  }
  if (-not [string]::Equals($ExecutingPath, $runtime.Payloads['scripts/shared/author-lint.ps1'].Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'paired author-lint must execute the selected runtime payload' }
  foreach ($module in $modules) {
    $loaded = @(Get-Module -Name $module)
    if ($loaded.Count -ne 1 -or -not [string]::Equals($loaded[0].Path, $runtime.Payloads['scripts/' + $module + '.psm1'].Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'paired author-lint requires the selected runtime dependency modules' }
  }
  # Origin is selected by the explicit caller parameter, never inferred from
  # candidate bytes. Initial review uses the full private empty-tree diff even
  # when adopted ancestry and public history require no new result commits.
  $readerName = if ($FirstAttachment) { 'Read-CrgPreparedFirstAttachmentBundleBytes' } else { 'Read-CrgPreparedPairBundleBytes' }
  $readers = @(Get-Command -Name $readerName -Module 'paired-review-input' -CommandType Function -ListImported)
  if ($readers.Count -ne 1) { throw 'paired author-lint requires one retained paired input reader' }
  $metadata = & $readers[0] -DescriptorBytes $captured.Bundle.DescriptorBytes -ExpectedDescriptorSha256 $captured.Bundle.DescriptorSha256 -Buffers $captured.Bundle.Buffers -GoverningConfigBytes $captured.PreparationSources.governing.ConfigBytes -CandidateConfigBytes $captured.PreparationSources.candidate.ConfigBytes -PublicTreeBytes $captured.Indexes.public.TreeBytes -PrivateTreeBytes $captured.Indexes.private.TreeBytes -RuntimeTemplateBytes $runtime.Payloads['scripts/codex/review-prompt-template.md'].Bytes -ContextBlobBuffers $captured.ContextBlobBuffers
  if ($FirstAttachment -and ($metadata.ReviewUnit.RequiresReview -isnot [bool] -or -not $metadata.ReviewUnit.RequiresReview)) { throw 'first-attachment author-lint requires mandatory initial review input' }
  if ($metadata.ReviewUnit.Fields['runtime-manifest-sha256'] -cne $runtime.Id) { throw 'paired author-lint input differs from the selected runtime' }
  foreach ($domain in @('public', 'private')) {
    if ($captured.Indexes[$domain].TreeOid -isnot [string] -or $captured.Indexes[$domain].TreeOid -cne $metadata.ReviewUnit.Fields[$domain + '-tree']) { throw 'paired author-lint captured index tree differs from the review unit' }
  }
  $privateAttribution = $null
  $hasAdoptedPrivateParent = $FirstAttachment -and $metadata.ReviewUnit.Fields['private-parent'] -cne 'absent'
  if ($hasAdoptedPrivateParent) {
    $privateAttribution = $InputData['PrivateAttribution']
    $candidateTree = $captured.Indexes.private.TreeOid
    $oidWidth = $candidateTree.Length
    $keys = @('Domain', 'Parent', 'ParentTree', 'CandidateTree', 'PatchBytes', 'NameStatusBytes')
    if ($privateAttribution -isnot [System.Collections.IDictionary] -or $privateAttribution.Count -ne $keys.Count -or
        @($keys | Where-Object { $_ -cnotin @($privateAttribution.Keys) }).Count -ne 0 -or
        $privateAttribution.Domain -cne 'private' -or $privateAttribution.Parent -cne $metadata.ReviewUnit.Fields['private-parent'] -or
        $privateAttribution.ParentTree -isnot [string] -or $privateAttribution.ParentTree -cnotmatch ("\A[0-9a-f]{$oidWidth}\z") -or
        $privateAttribution.CandidateTree -cne $candidateTree -or $privateAttribution.PatchBytes -isnot [byte[]] -or
        $privateAttribution.NameStatusBytes -isnot [byte[]]) { throw 'first-attachment private lint attribution is not bound to the adopted parent and captured candidate' }
    try {
      $privateAttribution = @{
        Patch = $script:Utf8Strict.GetString($privateAttribution.PatchBytes)
        NameStatus = $script:Utf8Strict.GetString($privateAttribution.NameStatusBytes)
        ConservativeCandidate = $false
      }
    } catch [System.Text.DecoderFallbackException] {
      try { $nameStatus = $script:Utf8Strict.GetString($InputData['PrivateAttribution'].NameStatusBytes) }
      catch [System.Text.DecoderFallbackException] { throw 'first-attachment private lint change endpoints are not strict UTF-8' }
      $privateAttribution = @{ Patch = ''; NameStatus = $nameStatus; ConservativeCandidate = $true }
    }
  } elseif ($FirstAttachment -and 'PrivateAttribution' -cin @($InputData.Keys)) { throw 'absent private ancestry cannot supply adopted-parent lint attribution' }
  $entries = [System.Collections.Hashtable]::new([StringComparer]::Ordinal)
  foreach ($entry in $metadata.ContextEntries) { $entries.Add($entry.Path, $entry) }
  $references = New-PairedLintReferenceContext -Entries $entries -ContextBlobBuffers $captured.ContextBlobBuffers
  $resolver = $references.Resolver; $isTopLevel = $references.IsTopLevel
  $changes = New-Object 'System.Collections.Generic.List[object]'
  foreach ($domain in @('public', 'private')) {
    if ($domain -ceq 'private' -and $null -ne $privateAttribution) {
      $changeArguments = @{ Domain = $domain; NameStatus = $privateAttribution.NameStatus; Patch = $privateAttribution.Patch; Entries = $entries }
      if ($privateAttribution.ConservativeCandidate) { $changeArguments.ConservativeCandidate = $true }
      foreach ($record in (Get-PairedLintChangeRecords @changeArguments)) { $changes.Add($record) }
    } else {
      foreach ($record in (Get-PairedLintChangeRecords -Domain $domain -NameStatus $metadata.Texts[$domain + '.name-status'] -Patch $metadata.Texts[$domain + '.patch'] -Entries $entries)) { $changes.Add($record) }
    }
  }
  $unchangedTransfers = if ($FirstAttachment) { Get-PairedLintUnchangedFirstAttachmentTransfers -Changes $changes.ToArray() -ContextBlobBuffers $captured.ContextBlobBuffers } else { $null }
  $findings = New-Object 'System.Collections.Generic.List[object]'; $fileCount = 0
  foreach ($record in $changes) {
    $path = [string]$record.Path
    $narrative = $path -match $script:NarrativeDocPattern
    if ($record.Status -ceq 'D' -or (-not $narrative -and $path -notmatch $script:SourceExtPattern)) { continue }
    $fileFindings = @(); $counted = $false; $skip = $false
    if (-not (Test-IsRegularBlobMode -Mode $record.Entry.Mode)) {
      $fileFindings += @{ Class = 'UNSUPPORTED-SYNTAX'; Tier = 'ADVISORY'; File = $path; Line = 1; Match = (Get-ObjectKindLabel -Mode $record.Entry.Mode); Hint = 'the staged object is not a regular file, so its bytes are not this file''s text and no line-oriented class can run over them -- check the entry by hand' }
      $counted = $true; $skip = $true
    }
    if (-not $skip -and $record.Status -ceq 'R' -and -not $record.ConservativeCandidate) {
      $fileFindings += @{ Class = 'UNSUPPORTED-SYNTAX'; Tier = 'ADVISORY'; File = $path; Line = 1; Match = "a rename of $($record.Source)"; Hint = 'the lines this rename did not change are attributed to no line of this commit, so this path' + [char]0x27 + 's line-oriented classes never read them (any line the rename DID edit is scanned normally) -- review the moved file by hand, or touch a line to bring it into scope' }
      $counted = $true
    }
    if (-not $skip) {
      $blobRead = ConvertFrom-StagedBlobBytes -Bytes $captured.ContextBlobBuffers[$path] -Status $record.Status
      if (-not $blobRead.Ok) {
        $fileFindings += @{ Class = 'UNSUPPORTED-SYNTAX'; Tier = 'ADVISORY'; File = $path; Line = 1; Match = (Get-StagedBlobReadLabel -Reason $blobRead.Reason); Hint = 'no line-oriented class can read this blob, so none ran over it -- check it by hand, correct its attributes, or normalize its line terminators' }
        $counted = $true; $skip = $true
      }
    }
    if (-not $skip -and $narrative -and (Test-IsGeneratedContent -Path $path -Content $blobRead.Text)) { $skip = $true }
    if (-not $skip -and (Test-IsBinaryAttributedDiff -DiffText $record.Patch)) {
      $fileFindings += @{ Class = 'UNSUPPORTED-SYNTAX'; Tier = 'ADVISORY'; File = $path; Line = 1; Match = 'a binary-attributed diff'; Hint = 'git emitted no text diff for this governed file (gitattributes or content heuristic), so no line-oriented class could run -- check it by hand or correct its attributes' }
      $counted = $true; $skip = $true
    }
    if (-not $skip) {
      $addedSet = if ($record.ConservativeCandidate -or (Test-IsWholeBlobAddedStatus -Status $record.Status)) { New-WholeBlobAddedSet -Text $blobRead.Text } else { Get-PairedLintAddedSet -Path $path -Patch $record.Patch -Text $blobRead.Text }
      if ($FirstAttachment -and $record.Domain -ceq 'private' -and $record.Status -ceq 'A' -and $unchangedTransfers.Contains($path)) { $addedSet = @{} }
      if ($narrative) {
        if ($addedSet.Count -gt 0 -or [IO.Path]::GetFileName($path) -eq 'PLAN.md') {
          $counted = $true
          $fileFindings += @(Get-StagedFileFindings -Path $path -StagedText $blobRead.Text -AddedSet $addedSet -Resolver $resolver -IsTopLevel $isTopLevel)
        }
      } elseif ($addedSet.Count -gt 0) {
        $ext = [IO.Path]::GetExtension($path).TrimStart('.').ToLowerInvariant()
        $sourceInScope = $true
        if ($ext -cne 'rs') {
          $sourceLines = @($blobRead.Text -split "`n")
          $sourceRecords = New-Object 'System.Collections.Generic.List[object]'
          for ($j = 0; $j -lt $sourceLines.Count; $j++) { $sourceRecords.Add(@{ Line = $j + 1; Text = $sourceLines[$j] }) }
          if (-not (Get-SourceSupportDiagnostic -Records $sourceRecords.ToArray() -Ext $ext)) {
            $comments = @(Get-SourceCommentRecords -Records $sourceRecords.ToArray() -Ext $ext | Where-Object { $addedSet.ContainsKey([int]$_.Line) })
            $sourceInScope = $comments.Count -gt 0
          }
        }
        if ($sourceInScope) {
          $counted = $true
          $fileFindings += @(Get-StagedSourceFindings -Path $path -StagedText $blobRead.Text -AddedSet $addedSet -Ext $ext)
        }
      }
    }
    if ($counted) { $fileCount++ }
    foreach ($finding in $fileFindings) {
      $finding['Domain'] = $record.Domain; $finding['ObjectOid'] = $record.Entry.Oid
      $findings.Add($finding)
    }
  }
  $allFindings = $findings.ToArray()
  $errors = @($allFindings | Where-Object { $_.Tier -eq 'ERROR' })
  return [pscustomobject]@{
    Schema = 1; ValidationState = $(if ($FirstAttachment) { 'first-attachment-mechanical-findings-only' } else { 'paired-mechanical-findings-only' }); ReadyForPublication = $false
    ReviewUnitSha256 = $metadata.ReviewUnit.ReviewUnitSha256; FileCount = $fileCount
    ExitCode = $(if ($errors.Count -gt 0) { 3 } else { 0 }); Findings = $allFindings
    Report = (Format-Report -Findings $allFindings -ScopeLabel ($(if ($FirstAttachment) { 'first-attachment ' } else { 'paired ' }) + $metadata.ReviewUnit.ReviewUnitSha256) -FileCount $fileCount)
    PendingBindings = @('retained-runtime-approval-and-custody', 'actual-paired-capture-provenance-and-custody', 'mandatory-current-review-and-publication-guards')
  }
}

if ($PSBoundParameters.ContainsKey('PairedInput') -or $PSBoundParameters.ContainsKey('FirstAttachmentInput')) {
  if ($PSBoundParameters.ContainsKey('PairedInput') -and $PSBoundParameters.ContainsKey('FirstAttachmentInput')) { throw 'ordinary paired and first-attachment author-lint inputs are mutually exclusive' }
  foreach ($legacyParameter in @('Staged', 'Paths', 'Tree', 'OutPath')) {
    if ($PSBoundParameters.ContainsKey($legacyParameter)) { throw 'paired author-lint input cannot be combined with legacy scope or output parameters' }
  }
  if ($PSBoundParameters.ContainsKey('FirstAttachmentInput')) {
    Invoke-PairedAuthorLint -InputData $FirstAttachmentInput -ExecutingPath $PSCommandPath -FirstAttachment
  } else {
    Invoke-PairedAuthorLint -InputData $PairedInput -ExecutingPath $PSCommandPath
  }
  return
}

# ===========================================================================
# Process environment
# ===========================================================================
try {
  Normalize-ProcessPathEnvForStartProcess
} catch {
  Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: could not normalize the inherited Path/PATH environment before child launch -- $($_.Exception.Message); refusing to report clean.")
  exit 2
}


# ===========================================================================
# Main
# ===========================================================================

# Resolve repo root from git so the linter works from any cwd (incl. a linked
# worktree). Fail loud if not in a work tree.
try {
  $repoRoot = (& git rev-parse --show-toplevel 2>$null)
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRoot)) {
    throw 'not inside a git work tree'
  }
  $repoRoot = $repoRoot.Trim()
} catch {
  Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: cannot resolve repo root: $_")
  exit 2
}

# Every git read that feeds validation MUST fail loud: a suppressed git failure
# treated as empty output would silently classify real findings as clean, the
# whole point of the linter. (Codex BLOCKER class.)
function Invoke-GitChecked {
  param([string[]]$GitArgs, [string]$What)
  $out = (& git @GitArgs 2>$null)
  if ($LASTEXITCODE -ne 0) {
    Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: 'git $($GitArgs -join ' ')' failed (exit $LASTEXITCODE) -- $What; refusing to report clean.")
    exit 2
  }
  return $out
}

function Assert-SingleFileDiff {
  # Abort unless a per-file diff covers EXACTLY one file, so `-AttributeTo` can label
  # every hunk with the requested path.
  #
  # `--literal-pathspecs` is the primary defense and this is the proof: a glob that
  # slipped through would be a BUG in the request, not data to interpret, and
  # attributing a sibling's hunks to this path would report added lines against a
  # file that never held them. (Codex BLOCKER.)
  #
  # ZERO sections is equally a bug, not an empty answer. The callers reached this path
  # from the governed-status selection, so the file HAS a staged change and its
  # diff must have a section; none means the request did not select the file it named,
  # and treating that as "no added lines" reports the file clean without reading it.
  # (Codex BLOCKER.)
  #
  # VERSION FLOOR: `--literal-pathspecs` needs git >= 1.9. An older git rejects the
  # unknown option and exits non-zero into the fail-loud wrapper, so the floor cannot
  # degrade into a silent glob -- but it is a real dependency, recorded here because
  # nothing else in this script declares one.
  param([string]$DiffText, [string]$Path)
  if (-not (Test-IsSingleFileDiff -DiffText $DiffText)) {
    $sections = Measure-DiffFileHeaders -DiffText $DiffText
    Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: the per-file staged diff for '$Path' covers $sections files, not exactly one -- refusing to attribute lines from a request that did not select it alone.")
    exit 2
  }
}


function Invoke-GitCheckedNulText {
  # Same fail-loud contract as Invoke-GitChecked, but returns ONE raw string for the
  # `-z` readers instead of PowerShell's line records.
  #
  # `& git ...` hands stdout to PowerShell's LINE-RECORD pipeline, which splits on CR
  # and LF and drops the terminators. Both bytes are legal in a POSIX pathname, so a
  # `-z` record containing either arrives as two records that git never emitted --
  # and rejoining them cannot restore which terminator (or how many) was there.
  # Redirecting to a file and reading the whole text back is what keeps the bytes
  # git wrote; the caller then splits on NUL, the one separator no pathname holds.
  # UTF-8: git writes `-z` pathnames as raw bytes, and this repo's paths are UTF-8.
  # The scratch file goes to the OS temp dir, never inside the repo: this linter runs
  # from the pre-commit hook, and a scratch file in the tree would dirty the very
  # worktree the gate checks for cleanliness.
  param([string[]]$GitArgs, [string]$What)
  $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "author-lint-z-$([guid]::NewGuid().ToString('N')).bin")
  $tmpErr = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "author-lint-zerr-$([guid]::NewGuid().ToString('N')).bin")
  $quotedArgs = @(ConvertTo-ProcessArgumentList -Arguments $GitArgs)
  try {
    # Stderr is redirected and dropped for the output-integrity reason
    # Read-StagedBlobText states: a console-inherited child stream carries
    # repository-controlled text past every sanitized sink here.
    try {
      $proc = Start-Process -FilePath 'git' -ArgumentList $quotedArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $tmpErr
    } catch {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: could not launch 'git $($GitArgs -join ' ')' -- $What; $($_.Exception.Message); refusing to report clean.")
      exit 2
    }
    if ($proc.ExitCode -ne 0) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: 'git $($GitArgs -join ' ')' failed (exit $($proc.ExitCode)) -- $What; refusing to report clean.")
      exit 2
    }
    $payload = Read-NulTextFile -Path $tmp
    if (-not $payload.Present) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: 'git $($GitArgs -join ' ')' exited 0 but wrote no output file -- $What; refusing to report clean.")
      exit 2
    }
    if (-not $payload.Valid) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: 'git $($GitArgs -join ' ')' returned a -z payload that is not valid UTF-8 -- $What; a pathname this tool cannot represent faithfully is a stop, not a guess.")
      exit 2
    }
    return [string]$payload.Text
  } finally {
    # A leaked scratch file is not worth aborting a passed scan over, but silence
    # would hide a temp directory that has stopped accepting deletions.
    foreach ($scratch in @($tmp, $tmpErr)) {
      if (-not (Test-Path -LiteralPath $scratch)) { continue }
      Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue -ErrorVariable rmErr
      if ($rmErr) { Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] WARNING: could not remove scratch file '$scratch' -- $($rmErr[0].Exception.Message)") }
    }
  }
}

function Get-CheckedNulPaths {
  # EVERY `-z` path list is read here and only here: run git fail-loud, then require the
  # payload to be `-z` FRAMED before any consumer sees a path.
  #
  # Every consumer selects files to scan, so a truncated payload's trailing PREFIX
  # would send the scan to a path that does not exist while the real file went
  # unscanned -- a false-clean with no diagnostic. Collapsing the read here keeps that
  # check from being one a future call site can forget.
  #
  # The comma wrapper on the return is load-bearing: without it PowerShell unrolls an
  # EMPTY result to $null, handing every caller the same ambiguity the record was
  # introduced to kill.
  param([string[]]$GitArgs, [string]$What)
  $listing = Split-NulSeparatedList -Text (Invoke-GitCheckedNulText -GitArgs $GitArgs -What $What)
  if (-not $listing.Valid) {
    Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: 'git $($GitArgs -join ' ')' returned an unterminated -z payload -- $What; refusing to report clean.")
    exit 2
  }
  return ,@($listing.Paths)
}

function Get-CheckedStagedStatus {
  # The staged selection WITH its per-path status, read once through the same
  # fail-loud `-z` path as the plain listing.
  param([string]$RepoRoot)
  # The FLAT field list, read straight off the split record rather than through
  # Get-CheckedNulPaths' comma-wrapped return: that wrapper survives parameter
  # binding, and coercing a nested array to [string[]] space-joins each inner array
  # into one string -- which turned a rename's source and destination into a single
  # unusable pathname. Same framing check, applied here.
  #
  # DETECTION IS REQUESTED EXPLICITLY -- `-M -C --find-copies-harder`, never
  # `--find-copies-harder` alone. On the bundled git the lone flag DOES detect both
  # (probe P2 in ConvertFrom-RawDiffFields' record emits `C099` and `R100`, and P10
  # keeps emitting them under `diff.renames=false`), but only because git promotes
  # that flag to copy detection internally -- a coupling git-diff(1) does not state,
  # so resting the `C` and `R` records on it makes this listing's contract a property
  # of one implementation rather than of the flags asked for. What that would cost is
  # not hypothetical: with detection genuinely off, a rename lands as a bare `A` and
  # its whole unchanged blob is attributed to this commit.
  #     $ git -c diff.renames=false diff --cached --raw --find-copies-harder --diff-filter=ACMRT
  #     :100644 100644 b18aad5 19364c5 R098   old.md  new.md      <- detected anyway
  #     $ git -c diff.renames=false diff --cached --raw --diff-filter=ACMRT
  #     :000000 100644 0000000 19364c5 A      new.md              <- the failure mode
  # `-M` and `-C` are inert beside the lone flag on this git (probes P4 and P6 are
  # byte-identical to P2), so naming them costs nothing and removes the dependency.
  #
  # THE REST OF THIS ARGV PINS CONFIGURATION THIS LISTING'S CORRECTNESS DEPENDS ON.
  # Each names a git behaviour a repository config can otherwise move under the scan
  # while git still exits 0.
  #
  #   `-l0` -- rename/copy detection has an exhaustive fallback git SKIPS once the
  #     candidate count passes `diff.renameLimit`, warning on a stderr this script
  #     drops and exiting 0 regardless. `--find-copies-harder` widens the candidate
  #     set, which makes this listing the most exposed caller in the file. A skipped
  #     pair degrades to `A` plus `D`; the filter removes the `D`, and the whole
  #     unchanged blob behind the `A` is then attributed to this commit -- the false
  #     attribution Get-PerFileDiffSelector exists to prevent, and enough for an
  #     ERROR-tier class to abort a commit that edited none of it. Unlimited detection
  #     removes the condition rather than trying to detect it. (RL1)
  #   `--ignore-submodules=none` -- `diff.ignoreSubmodules=all`, or a per-submodule
  #     `ignore`, drops a staged gitlink from this listing entirely at exit 0. The
  #     entry then never reaches the object-kind diagnostic, so a governed staged path
  #     is neither scanned nor reported and the run still reports clean. (SUB1)
  #   `--no-abbrev` -- object ids follow `core.abbrev`. Under a short setting a REAL
  #     object whose id begins `0000` is spelled exactly like the absent-object
  #     sentinel, and Test-IsRawObjectIdSentinelPair then reads a present side as
  #     absent and refuses a valid record. Full width makes the sentinel unambiguous,
  #     since no real object is all-zero across a full id. (NS2l)
  #
  # STDERR STAYS DROPPED. The rename warning is the one completeness signal this
  # listing could have read from it, and `-l0` removes the condition that raises it;
  # reading that stream back would reintroduce the repository-controlled-text sink
  # Invoke-GitCheckedNulText documents, to recover a warning that can no longer fire.
  $gitArgs = @('-C', $RepoRoot, 'diff', '--cached', '--no-color', '--no-ext-diff', '--no-textconv', '--raw', '--no-abbrev', '-l0', '--ignore-submodules=none', '-M', '-C', '--find-copies-harder', '-z', $script:StagedDiffFilter)
  $listing = Split-NulSeparatedList -Text (Invoke-GitCheckedNulText -GitArgs $gitArgs -What 'staged raw diff list')
  if (-not $listing.Valid) {
    Write-Host (ConvertTo-SafeDisplayText -Text '[author-lint] ERROR: the staged --raw -z payload was unterminated -- refusing to report clean.')
    exit 2
  }
  # `Fields`, not `Paths`: the parser validates FRAMING, and the filtered view has
  # already normalized away the interior empty a corrupted payload would show.
  $parsed = ConvertFrom-RawDiffFields -Fields ([string[]]$listing.Fields)
  if (-not $parsed.Valid) {
    Write-Host (ConvertTo-SafeDisplayText -Text '[author-lint] ERROR: the staged --raw -z payload ended mid-entry or carried a meta field this parser does not recognize -- refusing to report clean on a selection it could not parse.')
    exit 2
  }
  return ,@($parsed.Records)
}

function Get-StagedSelectionRecord {
  # The selection record a staged path was chosen under, from the ORDINAL map.
  #
  # A miss is impossible by construction -- every path the loops iterate comes from the
  # record list that built the map -- and therefore a BUG rather than an absent value.
  # A null record would let the loop scan the file under a status and mode nobody
  # parsed, which is the false-clean this lookup exists to prevent, so it fails loud.
  # `Dictionary` (not a hashtable) is also what makes the miss detectable at all: it
  # reports absence instead of returning $null for a key that was never present.
  param([string]$Path)
  $rec = $null
  if (-not $script:stagedRecordByPath.TryGetValue($Path, [ref]$rec)) {
    Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: no staged selection record for '$Path' -- refusing to scan a file under a status this run did not parse.")
    exit 2
  }
  return $rec
}

# Tracked file list (the INDEX), read ONCE and checked. Drives both the DEAD-REF
# top-level set and the index path resolver.
# NOT wrapped in `@(...)`: the helper already returns a flat array through a comma
# wrapper, and `@()` around a single array-valued object NESTS it -- which handed the
# DEAD-REF resolver one bogus path in place of the whole index.
$indexFiles = Get-CheckedNulPaths -GitArgs @('-C', $repoRoot, 'ls-files', '-z') -What 'tracked file list (git ls-files)'

# .gitignore from the INDEX only (the pending commit), never the worktree, so an
# unstaged .gitignore cannot change DEAD-REF classification. DISTINGUISH absent
# from failure: only read when .gitignore is TRACKED (in the index) -- then read
# through the checked helper so a real git failure fails loud rather than
# silently dropping ignored roots like `logs`. Untracked/staged-deleted ->
# genuinely empty. (Codex BLOCKER.)
$giText = ''
if ($indexFiles -contains '.gitignore') {
  $giText = (@(Invoke-GitChecked -GitArgs @('-C', $repoRoot, 'show', ':.gitignore') -What '.gitignore index blob') -join "`n")
}

# Repo top-level DIRECTORY set for the DEAD-REF first-segment anchor -- built
# deterministically from the index + index .gitignore (Get-TopLevelDirSet), NOT
# a worktree listing. Directories only: a slash-list seeded by a root FILE
# ("PLAN.md/CLAUDE.md") is never a path.
$script:TopLevelDirs = Get-TopLevelDirSet -IndexFiles $indexFiles -GitignoreText $giText
$isTopLevel = {
  param($seg)
  return $script:TopLevelDirs.ContainsKey($seg)
}.GetNewClosure()

# DEAD-REF resolves against the INDEX (tracked files) for ALL modes, never the
# local filesystem: a `Test-Path` resolver would let a gitignored / untracked
# local-only artifact (e.g. a retained `logs/codex/probe-pack-45ff`) pass even
# though a fresh clone could not resolve it. The index path set is every tracked
# file plus its ancestor dir prefixes. (Codex BLOCKER.)
$script:IndexPathSet = Build-PathSetFromFileList -Files $indexFiles
$indexResolver = {
  param($relPath)
  $norm = ([string]$relPath -replace '\\', '/').TrimEnd('/')
  return $script:IndexPathSet.ContainsKey($norm)
}.GetNewClosure()

# Decide scope.
$mode = 'staged'
if ($Tree) { $mode = 'tree' }
elseif ($Paths -and $Paths.Count -gt 0) { $mode = 'paths' }
elseif ($Staged) { $mode = 'staged' }

$allFindings = @()
$fileCount = 0

if ($mode -eq 'staged') {
  # Validate the PENDING COMMIT (the index), not the worktree: read each staged
  # file's index blob, resolve referenced paths against the index, and compute
  # fence context from the FULL staged file -- then keep only findings on the
  # lines this commit ADDS. (Codex BLOCKERs: worktree headers/
  # paths could mask or invent a staged finding, and fence context from added
  # lines alone misreads a line added inside a pre-existing fenced block.)
  # The selection is read WITH its statuses and both loops share it, so the status a
  # file was selected under is still known when its added-line set is built.
  # NOT wrapped in `@(...)`: the helper returns a flat array through a comma wrapper,
  # and `@()` around a single array-valued object nests it -- which then member-
  # enumerates into one space-joined pathname.
  $script:stagedStatusRecords = Get-CheckedStagedStatus -RepoRoot $repoRoot
  $stagedMapResult = New-StagedRecordMap -Records $script:stagedStatusRecords
  if (-not $stagedMapResult.Valid) {
    Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: the staged selection names '$($stagedMapResult.Duplicate)' more than once -- refusing to scan under one of two contradictory records for the same path.")
    exit 2
  }
  $script:stagedRecordByPath = $stagedMapResult.Map
  $stagedFiles = @($script:stagedStatusRecords | ForEach-Object { [string]$_.Path } |
                   Where-Object { $_ -match $script:NarrativeDocPattern })
  foreach ($path in (Select-UniqueOrdinalPaths -Paths $stagedFiles)) {
    $selection = Get-StagedSelectionRecord -Path $path
    if (-not (Test-IsRegularBlobMode -Mode ([string]$selection.DstMode))) {
      $fileCount++
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = (Get-ObjectKindLabel -Mode ([string]$selection.DstMode))
        Hint  = 'the staged object is not a regular file, so its bytes are not this file''s text and no line-oriented class can run over them -- check the entry by hand'
      }
      continue
    }
    # A RENAME carries UNCHANGED bytes to a path whose line-oriented classes never ran
    # over them. Re-scanning the whole blob would put historical text through the
    # ERROR-tier classes and abort a commit that edited none of it -- but saying
    # nothing reports a clean scan over content the destination's own checks never
    # saw. The honest answer is the one this file already gives for an unreadable
    # object or a non-text diff: DEGRADE LOUDLY and name what was not done. Advisory,
    # so it informs without aborting.
    #
    # SCOPED TO THE UNCHANGED LINES, deliberately. A rename that also EDITS its file
    # still has those added lines attributed and scanned normally, and a staged
    # `PLAN.md` still gets its whole-file tag closure either way -- so the wording
    # claims only what is true of every rename: the lines it did not touch were not
    # re-read under this path's classes. The record is REPORTED and counted, so a
    # rename never reaches the no-content path even when it adds no line.
    #
    # A comparison of source-path policy against destination-path policy was built and
    # REMOVED (2026-08-02). Do not reintroduce it: it must answer DIRECTIONALLY, since a
    # policy-removing rename activates nothing; it must agree with every path-sensitive
    # gate, one of which reads the blob BODY and not just the path; and acting on it
    # means text-scanning a blob whose readability nothing has established.
    $renameNoted = $false
    if ([string]$selection.Status -ceq 'R') {
      $fileCount++
      $renameNoted = $true
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = "a rename of $([string]$selection.Source)"
        Hint  = 'the lines this rename did not change are attributed to no line of this commit, so this path' + [char]0x27 + 's line-oriented classes never read them (any line the rename DID edit is scanned normally) -- review the moved file by hand, or touch a line to bring it into scope'
      }
    }
    # The SAME strict read for every status. A failed index read is UNEXPECTED
    # here -- the governed-status filter already excluded deletions -- so it fails
    # loud rather than silently omitting the file; bytes that are not text degrade
    # instead, because an unreadable blob is a file this scan cannot stand behind,
    # not a broken run.
    $blobRead = Read-StagedBlobText -RepoRoot $repoRoot -Path $path -Status ([string]$selection.Status)
    if (-not $blobRead.Ok -and $blobRead.Reason -eq 'read') {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: cannot read staged blob for '$path' (git show failed)")
      exit 2
    }
    if (-not $blobRead.Ok) {
      if (-not $renameNoted) { $fileCount++ }
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = (Get-StagedBlobReadLabel -Reason ([string]$blobRead.Reason))
        Hint  = 'no line-oriented class can read this blob, so none ran over it -- check it by hand, correct its attributes, or normalize its line terminators'
      }
      continue
    }
    $stagedText = [string]$blobRead.Text
    if (Test-IsGeneratedContent -Path $path -Content $stagedText) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] skipped generated doc (not scanned): $path")
      continue
    }
    # Lines this commit adds (new-file line numbers). PIN the diff flags so user
    # `diff.noprefix` / color config cannot break the `+++ b/<path>` + hunk
    # parser (auto-review.ps1 documents that exact prior failure mode). (Codex
    # BLOCKER.)
    #
    # THE PATCH INDICATORS ARE PINNED ON THE SAME PRINCIPLE, one layer down: the
    # added-line reader and the in-hunk counter that cross-checks it both classify a
    # line by its FIRST CHARACTER, so any other rendering makes BOTH answer zero and
    # the parity guard between them agrees that nothing was added. It is the one guard
    # here blind to its own failure, because both sides read the same character.
    # Honestly, no `diff.outputIndicator*` config exists on the bundled git -- every
    # spelling probed leaves `+`/`-`/space untouched -- so this states a CLI-settable
    # rendering rather than closing a live config hole, which is the same reason the
    # prefix and color flags sit beside it. (DIFFIND1)
    #
    # `--ignore-submodules=none`: a gitlink dropped by config is a governed path
    # neither scanned nor reported. Get-CheckedStagedStatus records the measurement.
    $docSelector = Get-PerFileDiffSelector -Record $selection
    $diffText = (Invoke-GitChecked -GitArgs (@('-C', $repoRoot, '--literal-pathspecs', 'diff', '--cached', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0', '--src-prefix=a/', '--dst-prefix=b/', '--ignore-submodules=none', '--output-indicator-new=+', '--output-indicator-old=-', '--output-indicator-context= ') + @($docSelector.Flags) + @('--') + @($docSelector.Pathspec)) -What "staged diff for $path") -join "`n"
    Assert-SingleFileDiff -DiffText $diffText -Path $path
    $addedByFile = Get-AddedRecordsFromDiff -DiffText $diffText -AttributeTo $path
    # A MISSING parse key must yield an EMPTY set
    # (never a synthetic line 0) so the fail-loud guard below fires. (Codex BLOCKER.)
    $addedSet = Get-AddedLineSetForPath -AddedByFile $addedByFile -Path $path
    # Fail loud on a parse mismatch: the diff has IN-HUNK added lines but the parser
    # found none (an unexpected format) -> never report false-clean. A deletion-only
    # hunk legitimately has 0 added lines. Hunk-aware count (shared helper) so a
    # content `+++ b/...` line is included, not mistaken for a header.
    $rawAddedCount = Measure-InHunkAddedLines -DiffText $diffText
    if ($rawAddedCount -gt 0 -and $addedSet.Count -eq 0) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: parsed 0 added lines from a non-empty diff for '$path' (unexpected git diff format) -- refusing to report clean.")
      exit 2
    }
    # A COPY or TYPE CHANGE puts the whole blob into the index as new content, and
    # git's hunks describe NOT ALL of it -- a pure copy has no hunks at all, and a
    # copy-plus-edit has only the edit -- so an added-line set derived from hunks
    # alone scanned part of the content, or none of it, while the file counted as
    # handled. A RENAME is deliberately NOT here; see the rename diagnostic above.
    if (Test-IsWholeBlobAddedStatus -Status ([string]$selection.Status)) {
      $addedSet = New-WholeBlobAddedSet -Text $stagedText
    }
    # A governed file whose diff came back BINARY-ATTRIBUTED yields no hunks, so the
    # added-line set is empty and the `continue` below would drop it in silence --
    # the same silent-skip the degradation contract forbids. Report it and move on.
    if (Test-IsBinaryAttributedDiff -DiffText $diffText) {
      if (-not $renameNoted) { $fileCount++ }
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = 'a binary-attributed diff'
        Hint  = 'git emitted no text diff for this governed file (gitattributes or content heuristic), so no line-oriented class could run -- check it by hand or correct its attributes'
      }
      continue
    }
    # A staged PLAN.md still needs whole-file TAG closure even with ZERO added
    # lines: a DELETION-only change that removes a defining `M<n>` header leaves
    # dangling references the closure must catch. Other docs with no added lines
    # have nothing to check. (Codex BLOCKER.)
    $isPlan = ([System.IO.Path]::GetFileName($path) -eq 'PLAN.md')
    if ($addedSet.Count -eq 0 -and -not $isPlan) { continue }
    if (-not $renameNoted) { $fileCount++ }
    $allFindings += Get-StagedFileFindings -Path $path -StagedText $stagedText -AddedSet $addedSet -Resolver $indexResolver -IsTopLevel $isTopLevel
  }
  # SOURCE-FILE scanning (staged only), over both surfaces: the count-drift classes
  # on the COMMENT lines a commit ADDS to .rs/.ps1/.toml/.sh files, and
  # MAGIC-COUNT-ASSERT on the CODE lines it adds to .rs files (Get-StagedSourceFindings).
  # Same index-read + fail-loud git-read pattern as the .md loop. Selection is the
  # only source-specific step (pinned by SEL1-3); the whole loop is exercised
  # end-to-end by the E2E staged-source cases, which use an ALTERNATE index
  # (GIT_INDEX_FILE) so the shared worktree index is never mutated.
  $stagedSourceFiles = @($script:stagedStatusRecords | ForEach-Object { [string]$_.Path } |
                         Where-Object { $_ -match $script:SourceExtPattern })
  foreach ($path in (Select-UniqueOrdinalPaths -Paths $stagedSourceFiles)) {
    $selection = Get-StagedSelectionRecord -Path $path
    # Same object-kind gate as the doc loop, and BEFORE the blob read for the same
    # reason: `git show` succeeds on a symlink or gitlink entry and hands back the link
    # target or a whole commit, which the source classes would then scan as code.
    if (-not (Test-IsRegularBlobMode -Mode ([string]$selection.DstMode))) {
      $fileCount++
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = (Get-ObjectKindLabel -Mode ([string]$selection.DstMode))
        Hint  = 'the staged object is not a regular file, so its bytes are not this file''s text and no line-oriented class can run over them -- check the entry by hand'
      }
      continue
    }
    # A RENAME carries UNCHANGED bytes to a path whose line-oriented classes never ran
    # over them. Re-scanning the whole blob would put historical text through the
    # ERROR-tier classes and abort a commit that edited none of it -- but saying
    # nothing reports a clean scan over content the destination's own checks never
    # saw. The honest answer is the one this file already gives for an unreadable
    # object or a non-text diff: DEGRADE LOUDLY and name what was not done. Advisory,
    # so it informs without aborting.
    #
    # SCOPED TO THE UNCHANGED LINES, deliberately. A rename that also EDITS its file
    # still has those added lines attributed and scanned normally, and a staged
    # `PLAN.md` still gets its whole-file tag closure either way -- so the wording
    # claims only what is true of every rename: the lines it did not touch were not
    # re-read under this path's classes. The record is REPORTED and counted, so a
    # rename never reaches the no-content path even when it adds no line.
    #
    # A comparison of source-path policy against destination-path policy was built and
    # REMOVED (2026-08-02). Do not reintroduce it: it must answer DIRECTIONALLY, since a
    # policy-removing rename activates nothing; it must agree with every path-sensitive
    # gate, one of which reads the blob BODY and not just the path; and acting on it
    # means text-scanning a blob whose readability nothing has established.
    $renameNoted = $false
    if ([string]$selection.Status -ceq 'R') {
      $fileCount++
      $renameNoted = $true
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = "a rename of $([string]$selection.Source)"
        Hint  = 'the lines this rename did not change are attributed to no line of this commit, so this path' + [char]0x27 + 's line-oriented classes never read them (any line the rename DID edit is scanned normally) -- review the moved file by hand, or touch a line to bring it into scope'
      }
    }
    # The SAME strict read for every status. A failed index read is UNEXPECTED
    # here -- the governed-status filter already excluded deletions -- so it fails
    # loud rather than silently omitting the file; bytes that are not text degrade
    # instead, because an unreadable blob is a file this scan cannot stand behind,
    # not a broken run.
    $blobRead = Read-StagedBlobText -RepoRoot $repoRoot -Path $path -Status ([string]$selection.Status)
    if (-not $blobRead.Ok -and $blobRead.Reason -eq 'read') {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: cannot read staged blob for '$path' (git show failed)")
      exit 2
    }
    if (-not $blobRead.Ok) {
      if (-not $renameNoted) { $fileCount++ }
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = (Get-StagedBlobReadLabel -Reason ([string]$blobRead.Reason))
        Hint  = 'no line-oriented class can read this blob, so none ran over it -- check it by hand, correct its attributes, or normalize its line terminators'
      }
      continue
    }
    $stagedText = [string]$blobRead.Text
    $srcSelector = Get-PerFileDiffSelector -Record $selection
    $diffText = (Invoke-GitChecked -GitArgs (@('-C', $repoRoot, '--literal-pathspecs', 'diff', '--cached', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0', '--src-prefix=a/', '--dst-prefix=b/', '--ignore-submodules=none', '--output-indicator-new=+', '--output-indicator-old=-', '--output-indicator-context= ') + @($srcSelector.Flags) + @('--') + @($srcSelector.Pathspec)) -What "staged diff for $path") -join "`n"
    Assert-SingleFileDiff -DiffText $diffText -Path $path
    $addedByFile = Get-AddedRecordsFromDiff -DiffText $diffText -AttributeTo $path
    $addedSet = Get-AddedLineSetForPath -AddedByFile $addedByFile -Path $path
    $rawAddedCount = Measure-InHunkAddedLines -DiffText $diffText
    if ($rawAddedCount -gt 0 -and $addedSet.Count -eq 0) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: parsed 0 added lines from a non-empty diff for '$path' (unexpected git diff format) -- refusing to report clean.")
      exit 2
    }
    # A COPY or TYPE CHANGE puts the whole blob into the index as new content, and
    # git's hunks describe NOT ALL of it -- a pure copy has no hunks at all, and a
    # copy-plus-edit has only the edit -- so an added-line set derived from hunks
    # alone scanned part of the content, or none of it, while the file counted as
    # handled. A RENAME is deliberately NOT here; see the rename diagnostic above.
    if (Test-IsWholeBlobAddedStatus -Status ([string]$selection.Status)) {
      $addedSet = New-WholeBlobAddedSet -Text $stagedText
    }
    # Same silent-skip guard as the doc loop: a governed SOURCE file git will not
    # diff as text reports rather than vanishing.
    if (Test-IsBinaryAttributedDiff -DiffText $diffText) {
      if (-not $renameNoted) { $fileCount++ }
      $allFindings += @{
        Class = 'UNSUPPORTED-SYNTAX'
        Tier  = 'ADVISORY'
        File  = $path
        Line  = 1
        Match = 'a binary-attributed diff'
        Hint  = 'git emitted no text diff for this governed file (gitattributes or content heuristic), so no line-oriented class could run -- check it by hand or correct its attributes'
      }
      continue
    }
    # ZERO ADDED LINES IS A LEGITIMATE ANSWER, and reporting it as an unsupported
    # construct said the opposite. A deletion-only or mode-only M, a pure rename, and
    # an empty A/C/T blob each add no line at all; every one of them is a change the
    # parse read CORRECTLY. What the degradation contract forbids is a file whose
    # content the scan could not READ, and that case is caught above and never
    # reaches here: a diff that does hold added lines while the parse attributes none
    # exits loud on the cross-check, a non-text diff reports the binary diagnostic,
    # and a non-regular object reports the object-kind one. So no zero-added-line
    # selection reaches UNSUPPORTED-SYNTAX by being empty, and a legitimately empty
    # one takes the same silent no-content path the doc loop takes. The class covers
    # more than parser and object failures -- a RENAME emits it above over a perfectly
    # readable blob -- but every emitter names work that was NOT done, which is the
    # property the degradation contract is about.
    if ($addedSet.Count -eq 0) { continue }
    $ext = ([System.IO.Path]::GetExtension($path)).TrimStart('.').ToLowerInvariant()
    # Count this source file as SCANNED only when the commit adds content the source
    # classes actually examine. For a RUST file that is any added line -- comment
    # text feeds the count classes, code feeds MAGIC-COUNT-ASSERT -- so no extra
    # gate is needed beyond the added-line check above. For every other extension
    # only COMMENT lines are examined, so a code-only change there must fall through
    # to the "no content" report rather than inflate the scanned-file count (which
    # would mask the no-content path). (Codex QUALITY.)
    #
    # THE SUPPORT CHECK GATES THAT QUESTION. Asking the split "are any added lines
    # comments?" is only meaningful once the split is known trustworthy; asking it
    # first let an untrusted split answer "no" and skip the file it had mis-read.
    # An unsupported file is always in scope -- it has a diagnostic to report.
    if ($ext -ne 'rs') {
      $srcSplit = $stagedText -split "`n"
      $srcRecs = New-Object 'System.Collections.Generic.List[object]'
      for ($j = 0; $j -lt $srcSplit.Count; $j++) { $srcRecs.Add(@{ Line = ($j + 1); Text = ($srcSplit[$j] -replace "`r$", '') }) }
      $srcRecArr = $srcRecs.ToArray()
      if (-not (Get-SourceSupportDiagnostic -Records $srcRecArr -Ext $ext)) {
        $addedSrcComments = @(Get-SourceCommentRecords -Records $srcRecArr -Ext $ext | Where-Object { $addedSet.ContainsKey([int]$_.Line) })
        if ($addedSrcComments.Count -eq 0) { continue }
      }
    }
    if (-not $renameNoted) { $fileCount++ }
    $allFindings += @(Get-StagedSourceFindings -Path $path -StagedText $stagedText -AddedSet $addedSet -Ext $ext)
  }
}
elseif ($mode -eq 'paths' -or $mode -eq 'tree') {
  if ($mode -eq 'tree') {
    $tracked = Get-CheckedNulPaths -GitArgs @('-C', $repoRoot, 'ls-files', '-z', '*.md') -What 'tracked markdown list'
    $targetList = @($tracked | Where-Object { $_ -match $script:NarrativeDocPattern })
  } else {
    $targetList = @($Paths)
  }
  # Canonicalize the repo root ONCE for the containment checks below (git emits a
  # forward-slash absolute path; GetFullPath normalizes separators).
  $repoRootFull = [System.IO.Path]::GetFullPath($repoRoot)
  foreach ($path in (Select-UniqueOrdinalPaths -Paths $targetList)) {
    # CONTAINMENT (BLOCKER): prove a caller-supplied -Paths value is
    # INSIDE the repo root BEFORE deriving its repo-relative form -- otherwise an
    # outside abs path becomes an unrelated in-repo SUFFIX, or a relative
    # `..\outside.md` escapes the repo under repo-index resolution, and a mispointed
    # invocation exits CLEAN against the WRONG file. Get-ContainedRelPath
    # canonicalizes (rooted as-is; relative resolved against the repo root,
    # preserving the repo-relative -Paths semantics), enforces containment, and
    # returns the repo-relative path or $null. (-Tree feeds git ls-files output,
    # already repo-relative + tracked, so it is contained; running it through the
    # same check is harmless belt-and-suspenders.)
    $rel = Get-ContainedRelPath -RequestedPath $path -RepoRootFull $repoRootFull
    if ($null -eq $rel) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: requested path '$path' is OUTSIDE the repo root '$repoRootFull' (or unresolvable) -- refusing to scan (a path outside the repo cannot be validated against the repo index, and silently scanning the wrong file would be a false-clean).")
      exit 2
    }
    if ($rel -notmatch $script:NarrativeDocPattern) { continue }
    $full = Join-Path $repoRoot $rel
    if (-not (Test-Path -LiteralPath $full)) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: target not found: $rel")
      exit 2
    }
    $content = Get-Content -LiteralPath $full -Raw -Encoding UTF8
    # LONE CR is NORMALIZED here where the staged reader REFUSES it, and the asymmetry
    # follows from what each scope has to attribute: this audit reads whole files, so
    # every normalized line is in scope and normalizing makes them all reachable, while
    # a staged scan has to line up its text against a diff reader that splits the same
    # record differently (see Read-StagedBlobText). `-Raw` returns lone CRs intact
    # (MEASURED -- unlike record-mode Get-Content, which ends a record at one), and the
    # split below is on LF alone, so without this a CR-only file is a single record
    # whose later lines no per-line class can reach. The preamble needs no handling
    # here: `-Raw -Encoding UTF8` already consumes it.
    if ($null -ne $content) { $content = ($content -replace "`r`n", "`n") -replace "`r", "`n" }
    if (Test-IsGeneratedContent -Path $rel -Content $content) {
      Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] skipped generated doc (not scanned): $rel")
      continue
    }
    $fileCount++
    $lines = $content -split "`n"
    $records = @()
    for ($i = 0; $i -lt $lines.Count; $i++) { $records += @{ Line = ($i + 1); Text = ($lines[$i] -replace "`r$", '') } }
    $planContent = if ([System.IO.Path]::GetFileName($rel) -eq 'PLAN.md') { $content } else { $null }
    $allFindings += Invoke-FileChecks -Path $rel -Records $records -PlanContentForClosure $planContent -Resolver $indexResolver -IsTopLevel $isTopLevel
  }
}

# An explicit audit (-Tree / -Paths) that examined NOTHING cannot claim "clean":
# a git-listing failure or a mispointed / non-Markdown selection would otherwise
# produce a false-clean exit 0. Staged mode with no narrative docs is a
# legitimate "nothing to check". (Codex BLOCKER.)
if (($mode -eq 'tree' -or $mode -eq 'paths') -and $fileCount -eq 0) {
  Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: $mode mode examined 0 files (git-listing failure, empty, or non-Markdown selection) -- cannot report clean.")
  exit 2
}
if ($mode -eq 'staged' -and $fileCount -eq 0) {
  Write-Host '[author-lint] no staged narrative-doc or source content to check.'
  exit 0
}

$report = Format-Report -Findings $allFindings -ScopeLabel $mode -FileCount $fileCount
# sanitized-by-construction: Format-Report escapes each finding FIELD; the newlines
# left here are the report's own line structure, and escaping them would render the
# whole report as one line.
Write-Host $report
if ($OutPath) {
  # sanitized-by-construction: the same field-escaped body Write-Host emits above; the
  # file copy must keep the report's line structure for the same reason.
  try { Write-ReportFile -Body $report -Path $OutPath }
  catch { Write-Host (ConvertTo-SafeDisplayText -Text "[author-lint] ERROR: failed to write report to ${OutPath}: $_"); exit 2 }
}

# Error-tier findings exit 3, NOT 1: an uncaught crash under
# $ErrorActionPreference='Stop' makes `powershell -File` exit 1, so exit 1
# is effectively reserved as the crash signal. Using a distinct findings
# code lets the pre-commit pre-pass distinguish "real findings -> abort
# the commit" (3) from "the linter itself broke -> warn and fail open to
# the still-running AI gate" (1, or any other unexpected exit).
$errorCount = @($allFindings | Where-Object { $_.Tier -eq 'ERROR' }).Count
if ($errorCount -gt 0) { exit 3 } else { exit 0 }
