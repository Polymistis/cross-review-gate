# Cross-review surface audit protocol

Audit protocol for a **periodic task** that keeps the adversarial review
system from drifting. Run this manually from whatever session normally
edits the review surface; the audit is small enough that it does not
warrant its own automation layer.

Code unit tests are banned. This audit uses source inspection, mandatory code
review, builds, records from ordinary program operation, and functional
validation. Do not create or run code unit tests under another name. Live
testing, manual checks, ordinary program runs, and functional validation remain
permitted. Preserve production input validation, error handling, runtime
assertions, and safety checks.

> **Package scope note.** This document ships inside the
> `cross-review-gate/` package and describes the behavior of the
> **packaged** scripts under `cross-review-gate/scripts/`. The packaged
> scripts carry the full dual-provider feature set: the paired verdict
> identity header block (`paired-review-input-v1.md`), the per-run
> run-owned `-OutDir` layout, the `-ReasoningEffort` passthrough, and the
> author-side linter (`author-lint.ps1`). Audit the packaged scripts
> directly.

## Why this exists

The review system is implemented as a small set of trusted artifacts.
The system supports two backends (Codex and Claude) that cross-review
each other's work. The audit covers both backends.

Codex backend:
- `scripts/codex/review-prompt-template.md` (the stock prompt for every
  reviewer; `scripts/project-preparation.psm1` renders it with the governing
  project values into the shared prompt body, to which
  `Open-CrgPairedHostInput` (`scripts/paired-preparation.psm1`) adds each
  backend's own tool rules)
- `scripts/codex/auto-review.ps1` (Codex wrapper)

Claude backend:
- `scripts/claude/auto-review.ps1` (Claude wrapper; receives the same rendered
  prompt body with Claude's own tool rules)

Shared:
- `scripts/review-liveness.psm1` (the one reviewer heartbeat, stall threshold
  and duration stamp both wrappers and the Grok adapter import; review
  infrastructure, so the release payload carries it beside the wrappers)
- `scripts/review-common.ps1` (the shared review-feedback,
  verdict-classifier, consistency-document,
  project-mode, prompt-assembly, argument-quoting,
  replacement-suppression, attribute-neutral Git and console code-page
  implementation; the deliberate local copies outside it are listed under the
  shared production contracts in criterion 4, except the copies of
  `Set-CrgProcessConsoleEncoding`, `Initialize-CrgBoundedSinkNative` and
  `Test-CrgGitChildQuiescent` that other files carry, which a search for
  each function name finds; both wrappers dot-source it
  so it runs in
  their own script scope, and `scripts/paired-governance.psm1`,
  `scripts/review-preparation.psm1` and `scripts/paired-diff.psm1` dot-source
  it for the functions they use; review infrastructure like the
  liveness module)
- `scripts/shared/author-lint.ps1` (author-side MECHANICAL pre-pass, NOT a review
  wrapper -- it runs no Codex/Claude review, but the launcher runs it as a
  fail-fast pre-pass (`docs/central-publication-v1.md`); it encodes the
  script-detectable defect classes the gate repeatedly raises; its
  implementation is audited against the same convention sources as the
  wrappers)

The review system is itself code that drifts. Without periodic audit, the
convention sections drift out of sync with your project's convention docs,
and the wrapper's behavior diverges from the prompt's documented contract.

The audit closes that feedback loop: periodically read the current surface,
then edit the surface in place. All edits go through ordinary launcher
review (`docs/central-publication-v1.md`).

## Goal

This protocol must improve defect detection within the available time and
token capacity. Quality and correctness take priority; mandatory cross-review
remains intact. Remove repeated work with little additional defect-finding
value, not necessary coverage. Neither a fast incomplete review nor an
unbounded review/rework cycle is success. Measure review rounds, context and
token usage, coordination overhead, and time-to-merge from existing records.
Separate measured spending from avoidable waste and local execution time
from model-token usage. When excessive cost or duration is reported, reuse existing evidence to identify
the cause and correct the waste-producing path before another expensive attempt.
Complete in-flight mutations safely; preserve mandatory review coverage,
authorization, candidate identity and safety checks. An explanation alone is
not resolution, and unmeasured savings must not be claimed.

## Actor and cadence

**Actor:** whichever session edits review-system files.

**Cadence:** on demand. Reasonable triggers are (a) a recent review
caught a class of finding that suggests prompt/wrapper drift; (b) the
user explicitly asks for a review-surface audit; (c) the consuming
project's planning document crossed its size
ceiling, or a stretch of recent commits touched it repeatedly — the
plan-lifecycle trigger for criterion 4b, whose defect accumulates
gradually and so has no single event to notice.

The audit is **not** a per-commit step. It runs occasionally — likely
once per multi-week stretch of review activity, or after a significant
review-system change has bedded in.

## Inputs

Each audit run consumes:

1. **`scripts/codex/review-prompt-template.md`** — the current prompt
   (SHARED between both backends; format drift here affects both).
2. **`scripts/codex/auto-review.ps1`** — Codex wrapper (header docs,
   helper docstrings, exit-code contract). Neither wrapper extracts a patch:
   both read the evidence the launcher captured. Patch, stat and name-status
   extraction is `Get-CrgPairedGitDiffEvidence` in `scripts/paired-diff.psm1`,
   through `Invoke-CrgAttributeNeutralDiffRuns`; confirm there that every
   extraction runs from concrete object IDs in the
   owned attribute-neutral Git context: the real common object directory is
   referenced only through a private alternates file by non-mutating evidence
   commands, the primary object store and Git dir are temporary, a private
   highest-precedence `info/attributes` rule resets `diff` to Unspecified for
   every path, local/global/system attribute sources and config carriers are
   isolated or absent, replacement objects are disabled, and
   `--ignore-submodules=none` is explicit. Candidate `.gitattributes`, local
   `info/attributes`, ambient configuration, and diff submodule settings must
   not suppress review evidence; Git's built-in binary classification must
   remain intact.
3. **`scripts/claude/auto-review.ps1`** — Claude wrapper (parallel
   shape; verdict-format contract must match the Codex wrapper exactly
   since the shared prompt assumes identical exit codes). Specifically check: the wrapper still classifies through the
   shared `Get-VerdictExitCode` in `scripts/review-common.ps1` rather than
   a local copy, and the Claude
   Code 2.1.248-or-later restricted-mode boundary remains intact: built-in
   availability and pre-approval are both `Read,Grep,Glob`, MCP is excluded,
   and `dontAsk` rejects every unmatched tool request.
4. **`scripts/shared/author-lint.ps1`** — the author-side mechanical
   pre-pass. Runs no AI review (the AI gate stays authoritative), but the
   launcher runs it as a fail-fast pre-pass
   (`docs/central-publication-v1.md`): `Invoke-CrgCentralAuthorLint`
   (`scripts/central-publication.psm1`) calls it in-process on the captured
   review input, requires one result whose review-unit identity matches that
   input and whose `ExitCode` field is 0 or 3, and stops the operation before
   review on 3 (error-tier findings). Run standalone with `powershell -File`,
   author-lint EXITS 3 on error-tier findings (exit 1 is reserved as its crash
   signal). It encodes the
   script-detectable defect classes the gate repeatedly raises: at ERROR tier,
   line-anchor citations, local-only review-artifact paths cited as
   proof (`logs/(codex|claude)/reviews` beside a proof/verification word), and
   exact inventory/count claims in `.md` prose (the verb-gated `there are <N>
   <word>` / `covers <N> <word>` shapes — magnitude-or-delete, never a corrected
   number); at ADVISORY
   tier, dead repo-relative references, dangling milestone
   tags, exact-magnitude transients (incl. spelled enumerated-case totals),
   self-narration of the pending change's own landing
   (`this merge`/`this landing`/`landed ... here`),
   machine-local install/wiring state, the looser local-evidence forms,
   MAGIC-COUNT-ASSERT (Rust EQUALITY assertions — `assert_eq!` /
   `debug_assert_eq!`, or `assert!` / `debug_assert!` with `==` — pinning a
   collection cardinality to a bare integer literal of
   two or more, over staged `.rs` CODE lines via its own lexer; the `0`/`1`
   literals are out of class BY VALUE (emptiness/singleton pins are usually
   intentional), and inequalities and `assert_ne!` are not sites at all —
   the class is an equality claim), and
   UNSUPPORTED-SYNTAX (the per-file refusal diagnostics: a construct outside
   the comment/code splitter's positively-supported grammar skips that file's
   count classes loudly, and the pure-rename / type-change / binary
   degradations report what was not line-scanned). The
   INVENTORY + MAGNITUDE classes ALSO run one tier softer over the COMMENT lines
   of staged `.rs`/`.ps1`/`.toml`/`.sh` files, with a code-echo exemption for a
   count that matches an adjacent code literal. The LINE-ANCHOR class downgrades to advisory
   ONLY for a doc carrying the explicit frozen-snapshot MARKER — an HTML
   comment `<!-- frozen-snapshot -->` on its own line near the top, matched
   by `^\s*<!--\s*frozen-snapshot\s*-->\s*$` (case-insensitive) within the
   first ~30 lines, in normal Markdown context only — a marker inside a
   fenced code block or on a CommonMark indented-code line (>=4 leading
   spaces, or 0-3 spaces then a tab) renders as visible code and does NOT
   grant the exemption. Filename and date do NOT grant the exemption (no
   filename inference, no env-var denylist): a dated-in-name doc without the
   marker stays error-tier, and a non-dated doc with the marker is exempt.
   On any check-class change, inspect the implementation.
5. **REVIEW THE REVIEWERS (liveness and effectiveness;
   `docs/reviewer-liveness-design.md`)** — the reviewers themselves are a
   surface: a stalled or hollow reviewer silently converts the gate into a
   rubber stamp, and an unmonitored waiter dies with it. Periodically:
   - Sample recent verdicts' `REVIEW-DURATION-SECS` stamps per backend.
     Durations drifting far from that backend's norm — in either
     direction — are findings: a stall-prone reviewer starves the
     pipeline, and a reviewer finishing implausibly fast on large diffs
     is not reviewing.
   - Check recent run consoles/logs for `STALL-SUSPECT` heartbeat
     escalations and confirm each was investigated rather than waited
     out; the escalation names the evidence files that went quiet.
   - Spot-read a preserved claude activity stream
     (`review-*.stream.jsonl`) and a codex per-pass events file against
     their verdicts: the transcript should show the reviewer actually
     traversing the diff the verdict claims to cover, and finding volume
     should be commensurate with diff size.
   - Confirm the liveness plumbing itself is intact: each wrapper
     announces its liveness-log path at launch (the claude wrapper also
     announces its stream path), the artifacts are preserved with
     forensics, and the heartbeat prints evidence sizes (a regression
     to timer-only beats re-opens the blind wait).
6. **The tracked registers**, where the audited repository has them —
   whatever tracked backlog or debt register the project
   records deferrals in (these files are not installed, so resolve the
   path the same way criterion 4b resolves the plan). Read them for
   entries whose stated reason has EXPIRED: a deferral justified by "the
   enabling condition does not occur here" when the tree now makes it
   occur, or accepted debt whose cost has grown since. That staleness is
   invisible from the entry itself, which is why it is audited rather than
   left to whoever next opens the file.
   ABSENT or EMPTY registers are valid states, not findings: a project that
   has deferred nothing has nothing to record. Note which state was
   observed, so a later audit can tell "nothing deferred" from "register
   not found".
7. **The consuming project's PLANNING DOCUMENT**, consumed by criterion
   4b. There is no fixed path: the file is whatever that project treats as
   its plan (`PLAN.md` and `docs/PLAN.md` are the common spellings, but the
   authority is the project's own convention doc or `AGENTS.md`). Resolve it there rather than guessing, and record the
   resolved path in the audit output so a later audit compares the same
   file. Read it WHOLE: criterion 4b is a judgement about the document's
   shape, which a partial read cannot make.
   If the project has NO planning document, criterion 4b is NOT APPLICABLE
   and the audit records that explicitly — a criterion silently skipped is
   indistinguishable from one that passed, and this one is skipped legitimately
   by most consumers of a review gate.

## Audit criteria (priority order)

Work through these in order. Items at the top have the highest
impact-per-effort.

### 2. "What is NOT a finding" reflects false-positive history

The prompt template's `## What is NOT a finding` section lists observations
a reviewer should not report. It should cover the false-positive patterns
the project has found.

**Audit:** compare the findings in retained verdicts (the private review
state, `crg-review-state` in the private Git directory) with later commits
that reverted or corrected the change made for them. A pattern that recurs
needs a guard line in the section.

### 3. Evidence-bundle components are consumed by Codex

The paired provider snapshot (`New-CrgPairedProviderSnapshot` in
`scripts/paired-diff.psm1`) carries evidence files that contract with the
prompt framing (`Open-CrgPairedHostInput` in `scripts/paired-preparation.psm1`):

- `DIFF.patch` and `SCOPE.md` — the framing tells the reviewer to **start**
  with these files.
- The per-domain patch, stat and name-status files, `COMMIT-LOG.txt`,
  `COMMIT-MESSAGE.txt` and `CODEX_REVIEW_EVIDENCE/PLAN-CONSISTENCY.txt` —
  supporting evidence the framing names. `COMMIT-MESSAGE.txt` holds the
  proposed message, which is part of the change; `COMMIT-LOG.txt` lists
  earlier commits, none of which is the change under review.
  `CARRIED-FINDINGS.txt` and `FIX-ON-FIX.txt` were removed (2026-11-23):
  a passing review's findings are not shown to any later review, and
  content a change leaves as it was is never the subject of a finding
  (`docs/review-feedback-v1.md` section 2); do not add them back.

Tool-backed reviewers receive the scope's policy-authority statements inline
in the prompt and read the complete validated `SCOPE.md` from the snapshot
(`docs/paired-review-input-v1.md`).

**Audit:** for each evidence file in the
"prompt-reads-it" set above, the framing should
mention it AND name what the reviewer should do with it. Its
`PLAN-CONSISTENCY.txt` line is the model. Its canonical envelope starts at
byte-zero with exactly one `PLAN-CONSISTENCY-STATE: v1 <state>` line, using only
`produced`, `skipped-not-configured`, `skipped-not-in-diff`, or
`indeterminate`, and ends with `PLAN-CONSISTENCY-END: v1` as the final line.
When the consistency check is enabled (a configured `consistency-document`), the
Project-hazards section should instruct the reviewer to read the file first and
apply one severity mapping: a `PLAN-CONSISTENCY-FINDING:` row in a well-formed
`produced` envelope is `QUALITY:` under `PLAN-DRIFT` when the change adds or
causes the drift it names, and context otherwise; either valid skip state is
a non-finding; and, when the configured document is in the reviewed diff, an
`indeterminate` state or absent, unreadable, malformed, or unterminated
evidence is a fail-closed `BLOCKER:` under `SILENT-FAILURE`.
Independent planning defects retain any BLOCKER severity assigned elsewhere.
This project-supplied hazard text cannot make content the change leaves as
it was a finding (the prompt's "Scope of a finding"), so a retained hazard
that asks for such findings has no effect on that content.

**Drift signals:**
- An evidence file in the prompt-reads-it set is not
  mentioned anywhere in the prompt → add a prompt mention.
- A prompt mention references a file the snapshot does not carry →
  either remove the prompt reference or implement the evidence file.
- The framing stops separating the proposed message (`COMMIT-MESSAGE.txt`)
  from earlier history (`COMMIT-LOG.txt`) → restore the distinction.
- A PLAN evidence state falls outside the finite grammar, lacks the terminal
  marker, or maps documentary producer findings to BLOCKER → align the producer,
  prompt, and installed contract together.

### 4. Verdict format contract adherence

The prompt requires a specific output structure: per-category
enumeration (8 categories, exactly once each), `VERDICT:` line (one of
three values), per-severity entries. The shared `Get-VerdictExitCode` in
`scripts/review-common.ps1` (used by both wrappers and
`scripts/paired-governance.psm1`) parses this structure and fails closed on
mismatches.

**Audit:** confirm the prompt and the classifier agree on the contract.
Inspect the shared classifier and compare existing actual verdicts with the
prompt contract. Code unit-test authoring and execution are prohibited;
synthetic inputs are not prohibited merely by category, and live testing,
manual checks, ordinary program runs, and functional validation remain
permitted.
Preserve the following shared production contracts:

- `Resolve-ConsistencyDocConfig` has one implementation, in
  `scripts/review-common.ps1`;
  `author-lint.ps1` keeps its own mode-based `Get-GitObjectKind` because it runs
  as a standalone single-file copy.
- PATH helpers live in `author-lint.ps1`, a standalone single-file copy.
  The effective case-insensitive lookup value leads the
  search order; deterministic raw-block-only values follow. Normalization must
  remove every case-variant spelling, set exactly one canonical `Path`, and
  verify the raw key count, spelling, and value or fail closed.
- Child-process argument quoting: `Convert-ToProcArgString` in
  `scripts/review-common.ps1` serves the Codex wrapper and the
  shared attribute-neutral Git child. These other implementations of the same
  CommandLineToArgvW rule must change with it: `scripts/paired-process.psm1` (the C# `QuoteArgument` that builds the
  review-process command line); `scripts/central-context.psm1`
  (`Invoke-CrgStatusGit`, `Read-CrgCentralObjectBatch`) and
  `scripts/paired-retention.psm1` (`Invoke-CrgRetentionGit`), which quote
  every argument and refuse NUL; and `Convert-CrgWindowsProcessArgument` in
  the standalone `bootstrap.ps1`.
  `author-lint.ps1` keeps a narrower quoter that quotes only arguments holding
  whitespace and relies on refusing any path that contains a double quote.
- Raw-environment replacement suppression (`Set-CrgNoReplaceObjects` for the
  live process, `Set-CrgNoReplaceObjectsInChildEnvironment` for a child map)
  and the attribute-neutral Git helpers (the `CrgAttributeNeutral.NativeV1`
  handle-custody type, the owned-context functions,
  `Invoke-CrgAttributeNeutralGitChild` and
  `Invoke-CrgAttributeNeutralDiffRuns`) have one implementation in
  `scripts/review-common.ps1`: the wrappers call the replacement suppression,
  and `scripts/paired-diff.psm1` runs the attribute-neutral Git helpers for
  evidence extraction. One shared definition means the custody type
  that loads first in a process is always the complete one. Replacement
  suppression must remove every case-variant spelling from the raw native
  environment block, set exactly one canonical `GIT_NO_REPLACE_OBJECTS=1`, and
  fail closed on a malformed raw entry. A local copy remains only where the
  shared file cannot be loaded: `bootstrap.ps1` runs standalone.
- Inspect keyword-list changes against actual findings and classification logic;
  changed classifications must not silently mislabel existing artifact evidence.

**Drift signals:**
- Prompt template lists severity tiers that the shared classifier
  does not recognize, or vice versa → align them.

### 4a. Project-mode surface and the machine-injected review-context blocks

The project-mode doctrine (`docs/project-mode-doctrine-v1.md` in the
package) adds a governing-mode resolution layer, machine-injected
data-bounded review context, and
a labeled evidence channel. Audit that the pieces still agree:

- **Resolution parity.** The declaration grammar parser and the injected
  block formatter have one implementation in
  `scripts/review-common.ps1`. A review consumes the
  `PROJECT-MODE.txt` that `scripts/paired-review-input.psm1` prepares through
  `scripts/project-preparation.psm1`; audit that producer for the
  governing-state and fallback rules.
- **Configuration, never authorization.** The governing declaration is
  always read from the trusted state preceding the change. A candidate
  declaration never governs that same run, but remains ordinary diff
  content and may land beside other work. No operator sanction,
  declaration isolation, activation-provenance gate, component-token
  gate, or declaration-specific skip rule may reappear.
- **Fallback direction.** Verified absence and a grammar-invalid governing
  regular file of at most 16 MiB both select `shipped` defaults; the injected
  block's `pm-state` line reports the fallback, and a grammar-invalid file
  adds a `pm-diagnostic` line (no console warning is printed). Acquisition
  refusal is separate: `Read-CrgCentralPreparationSource`
  (`scripts/central-context.psm1`) refuses a non-regular entry at the path or
  a larger regular file before the grammar parser runs, and a failed
  repository/object read also refuses, because none of these is verified
  absence or a parsed declaration.
- **Review-context boundary.** The injected `PROJECT-MODE` block (the
  `pm-authority:` boundary line included) and the `COMMIT-LOG.txt`
  authority header both declare their free text DATA, never
  reviewer-facing instruction. The template's `## Project mode` and
  `## Verification evidence` sections must keep matching what the
  review preparation injects (mode semantics, the code unit-test policy, evidence tiers,
  citation metadata); a paired review's configured unit-test scope replaces
  the template's marked ban body and the `pm-authority` sentence together. The block must also say that campaign text is
  context, not a work allowlist.
- **Commit-log channel framing.** A review's `COMMIT-LOG.txt` comes
  from `scripts/paired-review-input.psm1`, which frames commit-message
  content by injective `\xNN` escaping (the backslash included) plus the
  `> ` quote prefix per domain under its own authority header and
  prepared history bounds.
- **Ordinary landing paths.** A `PROJECT-MODE.md` edit uses the normal
  reviewed path. The audit must flag any declaration-specific sanction, isolation, or skip
  refusal as a reintroduced authorization boundary.

**Drift signals:** a grammar-invalid governing declaration of at most 16 MiB
blocking ordinary work instead of falling back; a candidate declaration
governing its own diff; a
non-advancing but otherwise valid change receiving a campaign-based
finding; template mode sections disagreeing with the injected block's
semantics.

### 4b. Plan-document role collision

The WHOLE-DOCUMENT half of the plan-role check. The shared prompt carries
the other half — a diff-anchored per-run criterion that catches added
content belonging to another owner as it arrives. Both are needed and
neither substitutes: a diff-scoped reviewer sees each addition as
justified, which is exactly how the accumulation happens, so the shape of
the document over time is only visible from here.

Every role below has exactly ONE owner. Role collision is a role appearing
in a document that does NOT own it — most often another owner's content
accumulating inside the plan. It is not a count: the plan legitimately owns
several of these rows.

| role | sole owner |
|---|---|
| purpose, current baseline, future roadmap, ONE active package, current decisions and directives | the plan |
| durable protocol / safety / architecture / configuration / product contracts | domain documents |
| evidence, alternatives, measurements, selected designs | research dossiers |
| completed packages, commit identities, exact history | git |
| review pass lines and verdict evidence | the gate's own review records |

Finding shapes to raise, in priority order:

- **More than one ACTIVE package in the plan.** A closed package retained
  "for context" is a completion log living in a scheduling document.
- **Validation-result prose, gate receipts, or embedded validation
  scripts.** These have owners above; in the plan they are unreviewable
  and unrunnable.
- **A "reset" that retained the old plan.** A reset means REMOVAL.
  Retaining the prior document as a `<details>` block or a historical
  appendix while its contracts stay binding is not a reset — the
  scheduling becomes non-authoritative while the obligations do not, which
  is strictly worse than before. `<details>` hides nothing from model
  context, search, lint, or a reviewer.
- **Broken document anchors**, which are the mechanical symptom of prose
  that moved without its references.

Churn signals worth measuring when the shapes above are present — these
are EVIDENCE for the role inventory, never a metric in themselves:

- File size and line count against the project's own stated ceiling.
- The proportion of recent commits that touch the plan. A plan touched by
  most commits is being used as a work log.

Recommended ceiling where a project has none: 500 lines and 30 KiB.

The asymmetry that drives the accumulation is worth naming in the finding,
because it is a governance defect rather than an authoring one: where
APPENDING requires no proof and DELETING requires demonstrating that every
clause was extracted or superseded, addition is always the locally safer
act. A directive never to delete specification content, combined with a
plan that declares itself centrally authoritative, makes growth unbounded
by construction. Recording that interaction is part of the finding.

The mechanical subset of this criterion — the rejections that can be
detected without judgement — is specified for the authoring side rather
than assumed to exist: more than one active package, closed-package
dossiers, validation/receipt prose, historical `<details>` appendices,
embedded scripts, broken anchors, and growth past a fixed ceiling. Where
that check should live (author-lint is the natural home) and how a project
declares its own ceiling are planning-review decisions, not assumptions
this criterion makes.

### 5. Cross-review the wrappers themselves (on-demand, not routine)

Each backend is best-positioned to catch drift in the OTHER backend's
wrapper, because the trade-offs each design makes are visible from
across the boundary in a way they aren't from inside. The cross-review
build-out of this package is the working existence proof: Codex's
adversarial review of the Claude wrapper caught structural defects
across many iterations (sandbox/auth trade-offs, missing deny-list
entries, env-leak patterns, clustered-short-option bypasses, ancestor-
chain assumptions, etc.) that the wrapper's author kept missing from
inside. The wrappers run only inside a launcher review
(`docs/central-launcher-v1.md`). For an ordinary change the first reviewer
is the backend opposite the declared `-AuthoringAgent`; a change to
`scripts/paired-review-session.psm1`, which holds these rules, runs two
review legs, the first preferring Codex and the second Claude, and each leg
needs its own passing review; positively identified exhaustion moves a leg's
review to the other backend and then, where configured, to Grok.

**Cadence: ON-DEMAND, not routine.** The Claude backend consumes
subscription tokens noticeably, and the audit is supposed to be
lightweight. Run cross-wrapper review when:
- A wrapper has just landed a substantive change and you want a
  cross-backend pass before relying on it in production
- A complex / high-stakes commit warrants a second opinion (use the
  OTHER backend, not the same one that already gated)
- A periodic audit run has surfaced wrapper drift and you want
  detailed file:line citations on the affected wrapper

The Codex side has its own token pool (separate billing from Claude
subscription), so Codex-reviews-Claude is the lighter side of the
trade -- prefer that direction when the wrapper under audit is the
Claude wrapper. When the wrapper under audit is the CODEX wrapper,
Claude-reviews-Codex is the right direction (the OTHER backend
rule); use it sparingly given subscription token pressure. Both
directions are valid; neither should be set up on a schedule.

### 6. Scoped-authority registries are part of the reviewed surface

Each configured scoped-authority registry is prompt-consumed: a reviewer
resolves a `SCOPED:`
slug against its entries, and the marker tells the reader of the verdict that
a live declaration owns the gap; no wrapper routes it anywhere. A weak registry
contract therefore weakens review even though no wrapper code reads the
marker.

The marker's effect is ADDITIVE. A SCOPED finding keeps its severity, its
categories, and its place in the verdict enumeration; the marker records that a
live declaration owns the gap so the reader of the verdict can re-audit the
claim first-hand. It clears nothing by itself. An audit finding this package treating
capture as clearance has found a contract change, not a documentation gap.

**Audit:** the review prompt's numbered CANONICAL DECLARATION AUDIT is the
canonical accept-set. The register's `Entry format` section states the
ENTRY-SHAPE subset of the package floor: slug grammar plus slug, gap, authority,
and separability fields. Gap match, authority-predating-the-diff, and
separability remain prompt checks because no entry can grant those conclusions
about itself. Slug UNIQUENESS spans both: a register forbids reuse inside
itself, but only the prompt can require exactly one entry across the COMPLETE
authority set, preventing a favourable duplicate from clearing a row another
entry would refuse.

The package checks are a universal floor, never the complete schema. After
unique resolution, apply every stricter validation and pairing rule declared by
the resolved authority document. Such rules include additional required fields,
accepted authority shapes, split-specific scope, field pairings, and
authority-delivery pairings. Project specialization may only narrow capture;
no project rule may weaken a package check or alter severity, category, or
output requirements. Walk both layers. A marker off the first
indented body line, a slug outside the grammar, a gap mismatch, or any failed
package or project-specific rule falls back to ordinary uncaptured duty, never
to a partial or silent clearance.

Check the register against the prompt's CURRENT step list rather than against
this criterion's memory of it — a check added to the audit without a line here
is how the parity drifts.

**Drift signals:**
- One document states a weaker subset than the others → restate them together
  in one pass. This is the failure mode that produced the mechanism's early
  BLOCKER rounds.
- A reviewer stops after the package field floor even though the uniquely
  resolved authority document declares stricter validation or pairing rules →
  capture was admitted against an incomplete schema.
- An entry whose deferred work has landed → stale; removal is the delivering
  commit's duty, not a later sweep's.
- An entry citing an authority the same commit introduced → the self-granted
  shape the audit exists to reject. Verify the audit still names it, and that
  such an entry is refused rather than merely noted.
- The rendered authority set contains exactly
  `- No authority documents. SCOPED capture is dormant.` → capture is DORMANT
  and every row is ordinary repair duty. That is a valid project choice, not a
  defect. A legacy or unresolved customization token on this surface is an
  installation defect and never a dormancy signal.

## How the audit ships

Edits to the review surface go through ordinary launcher review
(`docs/central-publication-v1.md`).

Apply full-sweep discipline: every contract-touching edit must update
every cross-reference in one commit. Reactive single-spot patching
tends to ship at least one drift per iteration; sweep every reference
in one pass.

## Before redistributing this package

If you re-package this gate for another project, scrub the packaged scripts
and docs of YOUR project's identifiers FIRST, and search for each identifier in
ALL case and separator variants in one pass. A scrub keyed on a single form
(e.g. an uppercase `<PREFIX>_`) silently misses its lowercase and hyphenated
siblings (`<prefix>_`, `<prefix>-`), which then ship into the next consumer's
tree. Sweep, at minimum:

- **Crate / module / package prefix** — one case-insensitive tracked-tree
  match catches every variant: `git grep -niE '<prefix>[_-]'`.
- **Project name** — the bare word plus any CamelCase / kebab / snake forms.
- **Milestone- or release-tag scheme** — whatever tag shape your planning
  docs use (e.g. an `M<n>.<n>`-style scheme).
- **Internal task / worker / ticket IDs** — the id prefix in every form it
  appears (`<id>-0000`, worker/branch handles, etc.).

The package cannot know a consumer's tokens, so this stays a maintainer step.
Files under `examples/` are intentionally project-flavored and are exempt —
they ship as illustrations, not as the gate surface.

## Out of scope (do not do these in the audit)

- Changing the gate's exit-code semantics or severity tier definitions.
  Those are the user's authority; the audit surfaces drift but does not
  rewrite the contract.
- Reducing required review coverage merely to report a faster verdict.
  Removing measured redundant work is in scope; longer duration is not
  evidence of better review. Preserve the prompt's complete-review contract.
- Weakening any fail-closed path. Every documented fail-closed exit
  (malformed verdict, missing categories, etc.) stays.
