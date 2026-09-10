# Cross-review surface audit protocol

Audit protocol for a **periodic task** that keeps the adversarial review
system from drifting. Run this manually from whatever session normally
edits the review surface; the audit is small enough that it does not
warrant its own automation layer.

Code unit tests are banned. This audit uses source inspection, mandatory code
review, builds, records from ordinary program operation, and applicable
functional testing. Do not create or run code unit tests under another name.
Integration, end-to-end, smoke, performance, manual, live, and other functional
testing are not prohibited merely by category. Preserve production validation,
runtime assertions, and safety checks.

> **Package scope note.** This document ships inside the
> `cross-review-gate/` package and describes the behavior of the
> **packaged** scripts under `cross-review-gate/scripts/`. The packaged
> scripts carry the full dual-provider feature set: single-provider merge
> panels on a required `-Backend` (the `Resolve-MergePanelPlan` /
> `Resolve-PanelOutcome` resolvers, with the cross-provider exhaustion
> fallback), the verdict identity header block (`DIFF-SHA256`
> + `REVIEW-TREE-OID` + `REVIEW-BACKEND` + `REVIEW-EFFORT` +
> `REVIEW-SEVERITY-CONTRACT` + `REVIEW-DURATION-SECS`, stamped via
> `Get-DiffSha256` / `Resolve-EffectiveCodexEffort` -- provenance/forensics
> metadata; the exit-1 branch-QUALITY corroboration that had read these
> headers was removed with the 2026-07 severity contract), the per-run
> run-owned `-OutDir` layout, the `-ReasoningEffort` passthrough, and the
> author-side tools (`author-lint.ps1`, `dispatch-checklist.ps1`). Audit the packaged scripts
> directly.

## Why this exists

The review system is implemented as a small set of trusted artifacts.
The system supports two backends (Codex and Claude) that cross-review
each other's work, routed by the `REVIEW_BACKEND` env var read by the
pre-commit hook. The audit covers both backends.

Codex backend:
- `scripts/codex/review-prompt-template.md` (shared with Claude; what each backend reads)
- `scripts/codex/auto-review.ps1` (Codex wrapper)

Claude backend:
- `scripts/claude/auto-review.ps1` (Claude wrapper; reuses the prompt template above)

Shared:
- `scripts/shared/auto-merge.ps1` (shared ff-merge gate; required `-Backend`
  names the preferred initial provider, and the gate owns any automatic
  whole-panel substitution)
- `scripts/codex/auto-merge.ps1` (compatibility entrypoint for installed
  launcher ABIs; forwards to the shared implementation without changing review)
- `scripts/git-hooks/pre-commit` (the trigger; routes by `REVIEW_BACKEND`)
- `scripts/run-gate.sh` (the gate-FIRING entry point: exports `REVIEW_BACKEND`
  and invokes `git commit`, so it is a review-routing driver under the same
  divergence/untracking guards as the commit wrappers -- step 5d)
- `scripts/codex/commit.ps1` (cross-review wrapper used by Codex-as-implementer; sets `REVIEW_BACKEND=claude`)
- `scripts/claude/commit.ps1` (cross-review wrapper used by Claude-as-implementer; sets `REVIEW_BACKEND=codex`)
- `AGENTS.md` (the human-facing contract description)
- `scripts/shared/author-lint.ps1` (author-side MECHANICAL pre-pass, NOT a review
  wrapper -- it runs no Codex/Claude review, but the pre-commit hook runs it as a
  fail-fast pre-pass: author-lint EXITS 3 on error-tier findings, which the hook
  reads to ABORT the commit before the AI review; it encodes the
  script-detectable defect classes the gate repeatedly raises; implementation
  and the AGENTS.md Review-Infrastructure row are audited against the same convention
  sources as the wrappers)
- `scripts/shared/dispatch-checklist.ps1` (recurrence-ranked dispatch checklist
  generator over the verdict logs -- it shares `analyze-blocker-trends.ps1`'s
  verdict filename-shape guard, UTF-8 I/O, AND per-file normalized-text dedupe,
  but ranks by the eight reviewer CATEGORIES (the analyzer dedupes the same way --
  mirrored, not forked); implementation and the AGENTS.md row are audited here too)
- `scripts/shared/worker-audit.ps1` (the per-landing PROCESS audit over the
  verdict logs that `auto-merge.ps1` runs after a successful ff-merge as a
  NON-GATING child; it mirrors the analyzer's artifact primitives byte-
  identically, so the AGENTS.md row and each mirrored copy are audited here -- step 5e)

The review system is itself code that drifts. Without periodic audit, the
hazards list grows stale (new BLOCKER archetypes accumulate in the verdict
log without being folded into the prompt), the convention sections drift
out of sync with your project's convention docs, and the wrapper's
behavior diverges from the prompt's documented contract. User-facing
observation: "the review keeps catching the same class of issue and the
prompt isn't learning from it."

The audit closes that feedback loop: periodically read the trend report
and the current surface, then edit the surface in place to fold in new
patterns. All edits go through the regular pre-commit gate.

## Goal

This protocol must improve defect detection within the available time and
token capacity. Quality and correctness take priority; mandatory cross-review
remains intact. Remove repeated work with little additional defect-finding
value, not necessary coverage. Neither a fast incomplete review nor an
unbounded review/rework cycle is success. Measure review rounds, context and
token usage, coordination overhead, and time-to-merge from existing records.
Separate measured spending from avoidable waste and local execution time
from model-token usage. `worker-audit.ps1` supplies process-friction evidence,
not a substitute for cost accounting or permission to ignore repeated delays.
When excessive cost or duration is reported, reuse existing evidence to identify
the cause and correct the waste-producing path before another expensive attempt.
Complete in-flight mutations safely; preserve mandatory review coverage,
authorization, candidate identity and safety checks. An explanation alone is
not resolution, and unmeasured savings must not be claimed.

## Actor and cadence

**Actor:** whichever session edits review-system files.

**Cadence:** on demand. Reasonable triggers are (a) the trend report
shows a recurring BLOCKER archetype without a corresponding named hazard;
(b) a recent merge gate caught a class of finding that suggests
prompt/wrapper drift; (c) the user explicitly asks for a review-surface
audit; (d) the consuming project's planning document crossed its size
ceiling, or a stretch of recent commits touched it repeatedly — the
plan-lifecycle trigger for criterion 4b, whose defect accumulates
gradually and so has no single event to notice.

The audit is **not** a per-commit step. It runs occasionally — likely
once per multi-week stretch of review activity, or after a significant
review-system change has bedded in.

## Inputs

Each audit run consumes:

1. **`docs/blocker-trends.md`** (or whatever output path you configure
   via `-OutPath`) — the trend report generated by
   `scripts/shared/analyze-blocker-trends.ps1`. Re-run the analyzer at the
   start of each audit with **`-SinceDays 30`** so the report's recency
   window matches the audit-criteria thresholds below. The committed
   copy may be stale by days, and the analyzer's default is
   no-mtime-cutoff (full history) which would conflate old archetypes
   with current ones at threshold-check time:
   `powershell scripts\shared\analyze-blocker-trends.ps1 -SinceDays 30`
2. **`scripts/codex/review-prompt-template.md`** — the current prompt
   (SHARED between both backends; format drift here affects both).
3. **`scripts/codex/auto-review.ps1`** — Codex wrapper (header docs,
   helper docstrings, exit-code contract). Confirm every
   patch/stat/name-status extraction runs from concrete object IDs in the
   owned attribute-neutral Git context: the real common object directory is
   referenced only through a private alternates file by non-mutating evidence
   commands, the primary object store and Git dir are temporary, a private
   highest-precedence `info/attributes` rule resets `diff` to Unspecified for
   every path, local/global/system attribute sources and config carriers are
   isolated or absent, replacement objects are disabled, and
   `--ignore-submodules=none` is explicit. Candidate `.gitattributes`, local
   `info/attributes`, ambient configuration, and diff submodule settings must
   not suppress review evidence; Git's built-in binary classification must
   remain intact. Audit the history-depth boundary too: Commit and Branch
   scopes require `git rev-parse --is-shallow-repository` to return exactly
   `false`, while Staged and Uncommitted scopes remain usable in a shallow
   repository. Shallow or indeterminate Commit/Branch state must fail closed
   before parent or range evidence is derived.
4. **`scripts/claude/auto-review.ps1`** — Claude wrapper (parallel
   shape; verdict-format contract must match the Codex wrapper exactly
   since the shared prompt and hook routing assume identical exit
   codes). Specifically check: `Get-VerdictExitCode` classifier
   behaviour stays in sync with the Codex copy, the consistency-doc
   fail-closed gate is still in place (gated on
   `CROSS_REVIEW_CONSISTENCY_DOC`; the precompute is not ported to this
   wrapper), the same attribute-neutral evidence-extraction contract as the
   Codex wrapper, the same complete-history refusal for Commit and Branch
   scopes while Staged remains usable in a shallow repository, and the Claude
   Code 2.1.248-or-later restricted-mode boundary remains intact: built-in
   availability and pre-approval are both `Read,Grep,Glob`, MCP is excluded,
   and `dontAsk` rejects every unmatched tool request.
5. **`scripts/shared/auto-merge.ps1`** — exit-code mapping (2026-07 severity
   contract: only BLOCKER blocks; `Resolve-PanelOutcome` validates and
   classifies the per-child exits — {0,2} unions, exit 4 routes to the
   token-exhaustion fallback, and exit 3, an empty exit set, or anything
   outside the verdict set fails closed, incl. the RETIRED exit 1), the
   direct-entry Git-selector boundary (raw case-insensitive environment-name
   discovery must refuse repository/object/ref/index selectors (including
   `GIT_REFERENCE_BACKEND`), every
   supported `GIT_CONFIG*` carrier, history selectors, and attribute selectors
   before the first Git command; ordinary `HOME`/`XDG_CONFIG_HOME` remain
   admissible), the forced `GIT_NO_REPLACE_OBJECTS=1` boundary, the complete-
   history preflight (`--is-shallow-repository` must resolve to exactly
   `false`; shallow or indeterminate state refuses before merge-base, range,
   or landing proofs, with fetch/unshallow as the remedy), the
   staged follow-up promotion
   (children stage QUALITY follow-ups via `CROSS_REVIEW_FOLLOWUPS_PENDING`;
   `Publish-ReviewFollowups` promotes to `logs/review-followups.md` only
   after the ff-merge succeeds), console messages, and the trusted-infra
   snapshot extracted from base. This is the single merge gate for BOTH
   providers (the required `-Backend` names the preferred initial provider,
   and positively identified exhaustion can substitute the whole panel); there is no separate
   `scripts/claude/auto-merge.ps1`. Audit its panel plan
   (`Resolve-MergePanelPlan`), the exhaustion fallback
   (`Resolve-MergeFallbackPlan`), the per-run run-owned `-OutDir` layout,
   the `-ReasoningEffort` passthrough, the atomic centralization
   publication, and the consistency-doc `-Backend claude` refusal (gated
   on `CROSS_REVIEW_CONSISTENCY_DOC`). A successful direct panel and a
   successful automatically substituted panel must expose the same
   provider-neutral caller status: no child exit 4, fallback provider, slot,
   exhaustion, or substitution banner reaches stdout/stderr. Exact provider
   provenance remains mandatory in verdict headers and `.exhaustion.json`
   sidecars, and failed routing remains fail-loud.
5a. **`scripts/codex/commit.ps1`** AND **`scripts/claude/commit.ps1`** —
   cross-review routing wrappers. These run BEFORE the pre-commit hook
   and set `REVIEW_BACKEND` to the OTHER backend (Codex implementer →
   Claude reviewer, and vice versa). Check the bypass-flag parser
   (`Test-Bypass-Args`) for parity between the Codex and Claude wrapper copies.
   Check the direct-entry Git-selector boundary before the first Git command: raw,
   case-insensitive environment-name discovery must refuse history and
   attribute selectors, repository/object/ref/index selectors (including
   `GIT_REFERENCE_BACKEND`), every exact
   `GIT_CONFIG*` carrier, and digit-suffixed `GIT_CONFIG_KEY_n` /
   `GIT_CONFIG_VALUE_n` carriers, including empty values. Ordinary
   `HOME` / `XDG_CONFIG_HOME` remain admissible. Also check the
   `core.hooksPath` config-redirect guard (`Resolve-HooksPathGuard`
   classifier) for parity across every hand-kept copy -- both commit
   wrappers AND `bootstrap.ps1` (the installer classifies `core.hooksPath`
   the same way so it never reports success under a state the wrappers
   abort on). After that unset proof, each wrapper must resolve and attest
   the default dispatcher before `git commit`: ordinary non-reparse bytes,
   leading shebang, the gate-untracking capability marker, and the exact
   adjacent bootstrap-written v1 digest record matching those bytes. Inspect
   refusal of NON-empty and empty `core.hooksPath=` values and missing, foreign,
   or digest-mismatched default dispatchers. Verify `REVIEW_BACKEND`,
   `GIT_NO_REPLACE_OBJECTS`, and PATH save/restore error handling are not
   regressed, and confirm the `core.hooksPath` guard still runs INSIDE the
   commit `try/finally` so an abort restores the controlled environment. The pre-
   commit hook forces `REVIEW_BACKEND=both` when a staged change
   touches either commit wrapper, defending against a malicious
   wrapper edit that would otherwise route its own review to itself;
   verify that defense is intact.
5b. **`scripts/shared/author-lint.ps1`** — the author-side mechanical
   pre-pass. Runs no AI review (the AI gate stays authoritative), but the
   pre-commit hook runs it as a fail-fast pre-pass: author-lint EXITS 3 on
   error-tier findings, which the hook reads to ABORT the commit (exit 1 is
   reserved as author-lint's crash signal, so a crashed linter fails open to the
   AI gate). It encodes the
   script-detectable defect classes the gate repeatedly raises: at ERROR tier,
   line-anchor citations, self-narration of the pending change's own landing
   (`this merge`/`this landing`/`landed ... here` — ERROR only in `History.md`,
   the retrospective landing log), local-only review-artifact paths cited as
   proof (`logs/(codex|claude)/reviews` beside a proof/verification word), and
   exact inventory/count claims in `.md` prose (the verb-gated `there are <N>
   <word>` / `covers <N> <word>` shapes — magnitude-or-delete, never a corrected
   number; a count inside a dated entry body of the root `History.md` log is
   EXEMPT — the drift-only History exemption, though a count there mis-stating
   a live contract the same diff changes stays a factual finding); at ADVISORY
   tier, dead repo-relative references, dangling milestone
   tags, exact-magnitude transients (incl. spelled enumerated-case totals),
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
   On any check-class change, inspect the implementation and confirm the
   AGENTS.md Review-Infrastructure row still matches.
5b2. **REVIEW THE REVIEWERS (liveness and effectiveness;
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
5c. **`scripts/shared/dispatch-checklist.ps1`** — the recurrence-ranked
   dispatch-checklist generator over the verdict logs (it shares
   `analyze-blocker-trends.ps1`'s verdict filename-shape guard, UTF-8 I/O, AND
   per-file normalized-text dedupe (mirrored -- the analyzer dedupes the same way),
   but ranks by reviewer CATEGORY and emits structural-fields-
   only output, dropping agent-authored prose as untrusted input). Both
   scripts share the fail-closed posture: a verdict RECOGNIZED as the
   wrapper's own producer-shaped fail-closed run (any header era, the
   `REVIEW-DURATION-SECS`-stamped one included) is EXCLUDED loudly and
   named, never counted; an UNRECOGNIZED-malformed verdict aborts the run
   naming the offender. Confirm both recognizers still accept the header
   era the wrapper currently emits (a recognizer lagging a new header line
   silently turns every fail-closed run into an abort). Confirm the AGENTS.md
   row and validation-surface assumptions remain intact.
5d. **`scripts/run-gate.sh`** — the tracked gate-firing entry point, a
   review-routing driver (it exports `REVIEW_BACKEND` ahead of the
   hook). Confirm its first-Git boundary rejects the same raw,
   case-insensitive history/attribute, repository/object/ref/index, exact
   `GIT_CONFIG*`, and digit-suffixed config carriers as both direct commit
   wrappers, including empty values; `HOME` / `XDG_CONFIG_HOME` remain
   admissible for the effective `core.hooksPath` check. Before that first Git
   command, confirm every raw case variant of `GIT_NO_REPLACE_OBJECTS` is
   replaced by exactly one canonical `GIT_NO_REPLACE_OBJECTS=1` and every case
   variant of retired `CROSS_REVIEW_ALLOW_MODE_CHANGE` is removed. Confirm the
   staged-set producer's exit status is checked independently of its strict
   NUL-framed `--name-only -z` output: producer failure, an empty record, or an
   unterminated record must refuse, while zero records must reach the named
   empty-stage refusal. Inspect dispatcher digest validation for the adjacent
   `pre-commit.crg-sha256` record and the empty-stage refusal path. Confirm the
   hook's routing-driver inventory still covers the entrypoint:
   a dirty or untracked-and-unverified copy refuses (a
   manifest-verified local-shape copy stands), a staged edit forces
   `REVIEW_BACKEND=both`, only regular files are admissible anywhere
   in the inventory (a symlink hides its executed target bytes from
   every divergence probe; a FIFO or device occupant reads as absent
   to `-f` while still able to supply executable bytes, so the shape
   refusal runs before anything opens the path) and the audited skip
   also refuses a non-regular STAGED MODE for the tracked hook itself
   (the dispatcher accepts only HEAD's regular hook blob and evaluates
   an OID-verified shell buffer, so a symlink-mode entry must never
   land), and the audited skip
   walks the driver's baseline states exhaustively — a HEAD-divergent
   edit refuses, an unborn HEAD classifies against the empty baseline
   instead of falling open, and worktree-vs-index equality is graded
   in the RAW byte domain (`git hash-object --stdin` against the
   staged blob oid — `git diff` applies clean filters and EOL
   normalization, which would read a transformed executed copy as
   clean), so a staged initial add is admissible only when the raw
   worktree bytes ARE the staged blob (the commit wrappers keep their
   documented broken-wrapper skip recovery). Inspect the production attribute
   validator for `run-gate.sh` and the tracked hook: the full LF conversion
   contract is behavioral: CRLF bytes must
   normalize to LF through the path's clean conversion, an LF blob
   checks out as LF bytes under `core.autocrlf=true`, and `git
   check-attr --all` lists no filter or working-tree-encoding
   attribute — rendered `set`/`unspecified` strings cannot tell a
   state from the literal values `text=set` / `filter=unspecified`,
   which git treats as not set; `eol` alone is defeated by a later
   `-text` or filter rule. A CRLF checkout
   breaks `sh` parsing of the entry point before any guard runs. The
   classification is PER PATH (a hybrid layout's ignored local-shape
   path is legitimately ruleless while every tracked sh path must
   hold the contract), and the audited skip validates the STAGED
   contract before every unreviewed landing (the staged attribute
   files resolved in an isolated context under an allowlisted
   environment with the temporary repository pinned explicitly, so an
   ambient `info/attributes` or global/system rule, or git
   configuration carried in the environment, cannot mask a violation),
   in the tracked hook and the dispatcher mirror alike — a skip cannot
   delete or override the rules out from under a still-tracked sh
   surface. Verify that resolution stays isolated: an in-repo
   probe would consult ambient sources a fresh clone lacks. The dispatcher checks (shebang, marker,
   digest) are DETECTIVE drift guards, not a boundary against a
   hooks-path writer — treat a digest mismatch as an incident to
   investigate before any `bootstrap.ps1 -DispatcherOnly` repair, never
   as noise to re-bless.
5e. **`scripts/shared/worker-audit.ps1`** — the per-landing process audit
   `auto-merge.ps1` runs after a successful ff-merge whenever a TRUSTED
   copy resolves (NON-GATING, time-bounded, report under gitignored
   `logs/worker-audits/`): the merge base's copy first, else -- in the
   LOCAL install shape, where the gate files are kept out of HEAD -- the
   manifest-verified local snapshot (the same `Resolve-CrgTrustedInfraSource`
   decision the review infra uses); neither resolving, a failed extraction,
   or a failure to resolve the central review-log dirs the audit reads its
   history from, skips the audit with a note. It re-expresses the analyzer's primitives
   BYTE-IDENTICALLY (the verdict filename shape, `Get-ArtifactBackend`,
   `Read-VerdictArtifactText`, `Get-VerdictSuspectReason`,
   `Get-CategoryTailKind`): confirm each mirrored copy still matches the
   analyzer's (a drift silently changes which artifacts the audit trusts),
   that backend identity stays the artifact's own header (never a directory
   name), that the merge gate still surfaces the audit's SUSPECT, ERROR, and
   WARNING lines under their own classes -- the class travels as the
   PRODUCER'S OWN token (`[class:suspect]` / `[class:operational]`), never
   re-derived by the consumer from the message text, so neither direction can
   be mislabeled and an untokened error is surfaced loudly as a
   producer-contract breach. Inspect producer diagnostics and consumer routing,
   the audit child's lifecycle (launch, capture, timeout kill-and-confirm,
   unconfirmed-exit preservation), and directory-list composition. Run the
   ordinary audit against a recently landed branch and inspect the report's
   correlation of actual commit-gate and merge-gate records.
6. **`scripts/git-hooks/pre-commit`** — the trigger hook. It is the
   `REVIEW_BACKEND` router and must keep both backends' trusted-copy
   bootstrap branches working (Codex backend's `REVIEW_INFRA` set and
   Claude backend's `REVIEW_INFRA` set are independent; one author-lint
   tempdir plus up to four reviewer tempdirs occupy quoted fixed
   per-invocation slots, and the shared cleanup runs from the EXIT trap on
   early failure or explicitly before terminal success).
   Audit the provider-transparency boundary: each wrapper invocation is
   captured in a same-process, per-invocation transcript; a successful direct
   review and a successful automatic alternate-provider review print the same
   generic start/PASS pair; provider, exhaustion, and substitution text remains
   absent from successful caller output. The transcript slots must be cleaned,
   `REVIEW_BACKEND` must remain unchanged by routing, and no skip-provider
   argument or persistent fallback state may exist. Durable verdict headers and
   exhaustion sidecars remain the forensic authority.
   Audit the immutable effective-index boundary as one composed contract. Before
   any review child launches, the hook pins the exact `git write-tree` identity
   and canonical staged-diff digest; every accepted successful artifact must
   bind both identities. The hook must re-read the same effective-index tree
   across review completion, private success preparation, the single durable
   follow-up append, caller-visible semantic projection, successful-path
   cleanup, and the displayed candidate PASS. Only an overall hook/process exit
   0 authorizes Git to continue. A terminal identity refusal may retain an
   already-appended candidate-review follow-up transaction, but those rows
   describe reviewed candidate content and never prove that a commit landed.
   **Trust chain for hook edits:** the per-clone dispatcher installed
   by `bootstrap.ps1` at `.git/hooks/pre-commit` captures the exact
   `HEAD:scripts/git-hooks/pre-commit` blob in a shell-owned buffer,
   verifies its byte length and blob OID, and evaluates THAT buffer in
   a fixed `/bin/sh` subshell — not the working-tree candidate or an
   executable temp file. So a staged hook edit is executed under
   HEAD's last-good logic AND adversarially
   reviewed against HEAD's wrapper + prompt (the hook is in each
   backend's `REVIEW_INFRA`). The dispatcher itself lives per-clone
   outside the working tree; a commit cannot edit or remove it
   through the review flow. Candidate hook logic must receive source inspection
   and mandatory independent review; the committing operation exercises HEAD's
   hook, not the candidate hook. Do not substitute a smoke commit or fixture.
7. **`AGENTS.md`** — verdict severity contract, Codex Reviewer
   Operations section, Review Infrastructure table (now covers both
   backends).
7c. **The tracked registers**, where the audited repository has them —
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
7b. **The consuming project's PLANNING DOCUMENT**, consumed by criterion
   4b. There is no fixed path: the file is whatever that project treats as
   its plan (`PLAN.md` and `docs/PLAN.md` are the common spellings, but the
   authority is the project's own convention doc or `AGENTS.md`, which is
   already input 7). Resolve it there rather than guessing, and record the
   resolved path in the audit output so a later audit compares the same
   file. Read it WHOLE: criterion 4b is a judgement about the document's
   shape, which a partial read cannot make.
   If the project has NO planning document, criterion 4b is NOT APPLICABLE
   and the audit records that explicitly — a criterion silently skipped is
   indistinguishable from one that passed, and this one is skipped legitimately
   by most consumers of a review gate.
7a. **`bootstrap.ps1`** — the installer, consumed by criterion 4a:
   audit the installed dispatcher for normal audited-skip behavior,
   the gate-untracking guard, and trusted hook routing. Project-mode
   configuration adds no declaration-specific dispatcher guard.
8. **Recent verdict logs** — `logs/codex/reviews/*.md` AND
   `logs/claude/reviews/*.md` from the last ~14 days, for spot-checks
   across both backends (the audit does not re-parse them itself; the
   trend report is the aggregate signal). The analyzer's default
   `-ReviewsDir` is an array of both backend log directories -- the
   `param()` block declares `[string[]]$ReviewsDir =
   @('logs/codex/reviews', 'logs/claude/reviews')` (NOT a single codex-only
   string; the codex-only and claude-only forms shown in the usage examples are
   explicit per-backend slices, not the default) -- so the trend report
   aggregates findings across both reviewer backends by default; passing a single
   directory remains supported for per-backend slicing when needed (a
   non-existent path in the default list is skipped, so a single-backend install
   still works on the default).

The trend report's `UNCLASSIFIED` cluster is a specific input: a
populated `UNCLASSIFIED` bucket signals the analyzer's keyword list
needs growth.

## Audit criteria (priority order)

Work through these in order. Items at the top have the highest
impact-per-effort.

### 1. Hazards list reflects the trend report

The prompt template's fixed
`## Project hazards that have repeatedly affected this codebase` section
enumerates archetypes
Codex must scrutinize. Each hazard should correspond to at least one
BLOCKER cluster in the trend report.

**Audit:** for each BLOCKER archetype cluster in the trend report with
≥ 3 findings in the last 30 days, verify that the prompt template has a
named hazard for that archetype, with a real SYMBOL-ANCHOR example (the
function / type / system name involved) drawn from a verdict log -- NOT
a bare `file.ext:NNN` line number, which `author-lint.ps1` flags
error-tier in authored docs and which goes stale on the next edit.

**Drift signals:**
- A trend-report cluster with ≥ 3 recent findings has no corresponding
  named hazard in the prompt → add a hazard.
- A named hazard's symbol-anchor example no longer resolves (the cited
  function / type was renamed or removed) → refresh with a current
  symbol from a recent verdict.
- A populated `UNCLASSIFIED` cluster ≥ 5 findings → extend
  `analyze-blocker-trends.ps1`'s keyword list AND, if a new pattern is
  named, add a corresponding hazard.

### 2. "What is NOT a finding" section reflects false-positive history

The prompt template's `## What is NOT a finding` section enumerates
classes of observations Codex should NOT emit as findings. This section
should reflect false-positive patterns the project has discovered the
hard way.

**Audit:** scan the verdict log for findings that were later judged
not-defects (manual override, follow-up commit reverting the "fix",
etc.). For recurring false-positive patterns, the section should have a
guard line.

**Drift signals:**
- A specific false-positive pattern has recurred ≥ 2 times in the trend
  report's recent QUALITY/NOTE buckets without a corresponding "NOT a
  finding" guard line → add the guard.

### 3. Evidence-bundle components are consumed by Codex

`auto-review.ps1` builds `CODEX_REVIEW_EVIDENCE/` with several files
that contract with the prompt:

- `DIFF.patch`, `STAT.txt`, `NAME-STATUS.txt`, `COMMIT-LOG.txt`,
  `PLAN-CONSISTENCY.txt` — Codex is instructed by the prompt's
  scope-doc and/or hazards section to **read** these files.
- `SCOPE.txt` — wrapper-produced, but the wrapper also **injects** the
  same scope text directly into the prompt sent to Codex. Codex reads
  the injected text in its prompt, not the file. This is the
  established convention; do not flag SCOPE.txt as missing-from-prompt
  drift.

**Audit:** for each wrapper-produced evidence file in the
"prompt-reads-it" set above, the prompt's scope-doc section should
mention it AND name what Codex should do with it. The scope-doc's
`PLAN-CONSISTENCY.txt` line is the model. Its canonical envelope starts at
byte-zero with exactly one `PLAN-CONSISTENCY-STATE: v1 <state>` line, using only
`produced`, `skipped-not-configured`, `skipped-not-in-diff`, or
`indeterminate`, and ends with `PLAN-CONSISTENCY-END: v1` as the final line.
When the consistency check is enabled (`CROSS_REVIEW_CONSISTENCY_DOC` set), the
Project-hazards section should instruct the reviewer to read the file first and
apply one severity mapping: a `PLAN-CONSISTENCY-FINDING:` row in a well-formed
`produced` envelope is `QUALITY:` under `PLAN-DRIFT`; either valid skip state is
a non-finding; and, when the configured document is in the reviewed diff, an
`indeterminate` state or absent, unreadable, malformed, or unterminated
evidence is a fail-closed `BLOCKER:` under `SILENT-FAILURE`.
Independent planning defects retain any BLOCKER severity assigned elsewhere.

**Drift signals:**
- A wrapper-produced evidence file in the prompt-reads-it set is not
  mentioned anywhere in the prompt → add a prompt mention.
- A prompt mention references a file the wrapper does not produce →
  either remove the prompt reference or implement the evidence file.
- A PLAN evidence state falls outside the finite grammar, lacks the terminal
  marker, or maps documentary producer findings to BLOCKER → align the producer,
  prompt, and installed contract together.

### 4. Verdict format contract adherence

The prompt requires a specific output structure: per-category
enumeration (8 categories, exactly once each), `VERDICT:` line (one of
three values), per-severity entries. The wrapper's `Get-VerdictExitCode`
parses this structure and fails closed on mismatches.

**Audit:** confirm the prompt and the wrapper agree on the contract.
Inspect both wrapper classifiers and compare existing actual verdicts with the
prompt contract. Code unit-test authoring and execution are prohibited;
synthetic inputs are not prohibited merely by category, and applicable
non-unit functional testing remains allowed.
Preserve the following shared production contracts:

- `Resolve-ConsistencyDocConfig`, `Test-ConsistencyDocKind`, `Get-GitObjectKind`,
  and `Remove-TreeNoRecurse` retain equivalent behavior across applicable copies.
  Runtime consistency-doc routing remains opt-in through
  `CROSS_REVIEW_CONSISTENCY_DOC`.
- PATH helpers retain equivalent behavior across the review, merge, author-lint,
  and commit entrypoints. The effective case-insensitive lookup value leads the
  search order; deterministic raw-block-only values follow. Normalization must
  remove every case-variant spelling, set exactly one canonical `Path`, and
  verify the raw key count, spelling, and value or fail closed.
- Inspect keyword-list changes against actual findings and classification logic;
  changed classifications must not silently mislabel existing artifact evidence.

**Drift signals:**
- Prompt template lists severity tiers that the wrapper's classifier
  does not recognize, or vice versa → align them.
- `AGENTS.md` Verdict Severity Contract describes exit-code routing
  different from `auto-review.ps1`'s implementation → align them.

### 4a. Project-mode surface and the machine-injected review-context blocks

The project-mode doctrine (`docs/project-mode-doctrine-v1.md` in the
package) adds a resolution layer both wrappers run on every
prompt-producing scope, machine-injected data-bounded review context, and
a labeled evidence channel. Audit that the pieces still agree:

- **Resolution parity.** The project-mode module (declaration grammar
  parser, governing-ref resolution, safe fallback, and candidate
  authority boundary) is mirrored across
  `scripts/codex/auto-review.ps1` and `scripts/claude/auto-review.ps1`.
  Compare the implementations directly; divergence is drift → re-mirror.
- **Configuration, never authorization.** The governing declaration is
  always read from the trusted state preceding the change. A candidate
  declaration never governs that same run, but remains ordinary diff
  content and may land beside other work. No operator sanction,
  declaration isolation, activation-provenance gate, component-token
  gate, or declaration-specific skip rule may reappear.
- **Fallback direction.** Verified absence and a positively malformed
  governing declaration both select `shipped` defaults; malformation
  also prints a loud warning. A failed repository/object read remains a
  tooling refusal because failure is not verified absence or verified
  malformation.
- **Review-context boundary.** The injected `PROJECT-MODE` block (the
  `pm-authority:` boundary line included) and the `COMMIT-LOG.txt`
  authority header both declare their free text DATA, never
  reviewer-facing instruction. The template's `## Project mode` and
  `## Verification evidence` sections must keep matching what the
  wrappers inject (mode semantics, the code unit-test ban, evidence tiers,
  citation metadata). The block must also say that campaign text is
  context, not a work allowlist. Exactly one governing-state visibility line
  prints per invocation that reaches project-mode resolution; a scope
  preflight failure before that boundary may exit without one.
- **Commit-log channel framing.** Both wrappers frame commit-message
  content by injective escaping (backslash first, then `\xNN`) plus
  the `> ` quote prefix, with the per-message and aggregate byte caps
  refusing (never truncating) on overflow. Inspect both copies when caps or
  framing change; mismatched boundaries are drift.
- **Ordinary landing paths.** A `PROJECT-MODE.md` edit uses the normal
  reviewed path or the normal audited `CROSS_REVIEW_SKIP=1` path. The
  audit must flag any declaration-specific sanction, isolation, or skip
  refusal as a reintroduced authorization boundary.

**Drift signals:** a project-mode run proceeding without the visibility
line; a malformed governing declaration blocking ordinary work instead
of falling back; a candidate declaration governing its own diff; a
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
| review pass lines and verdict evidence | the gate's own receipts under `logs/` |
| concise pointers only — NEVER startup context | a history index |

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
inside. Use the standard wrapper invocation against a specific commit:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\claude\auto-review.ps1 -Scope Commit -Target <sha>
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\codex\auto-review.ps1  -Scope Commit -Target <sha>
```

(Same `-Scope Branch -Target <base> -Tip <branch>` shape works for
branch-scope spot-checks without going through `auto-merge.ps1`.)

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
resolves a `SCOPED:` slug against its entries, and the wrappers carry a passing
claim into
`logs/review-followups.md` as a
`[scoped: <slug> tree: <oid> diff: <sha256> find: <sha256>]` tag written ALL
PARTS OR NONE. A weak registry contract is therefore a gate weakening even
though the only wrapper code involved is the serializer that writes that tag.

The tag's effect here is ADDITIVE. A SCOPED finding keeps its severity, its
categories, and its place in the verdict enumeration; the marker records that a
live declaration owns the gap so a later batch pass can re-audit the claim
first-hand. It clears nothing by itself. An audit finding this package treating
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
output requirements. Walk both layers, then confirm the `SCOPED capture` section of
`docs/AGENTS.md.template` states the same fallbacks: a marker off the first
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

Edits to the review surface go through the regular pre-commit gate.
The gate's trusted-copy bootstrap is specifically narrow and applied
**per physical wrapper invocation**: every initial or automatic fallback
invocation uses its effective provider's `REVIEW_INFRA` set — that provider's
wrapper plus the shared
prompt template plus this hook (Codex backend: `scripts/codex/auto-review.ps1`
+ `scripts/codex/review-prompt-template.md` + `scripts/git-hooks/pre-commit`;
Claude backend: `scripts/claude/auto-review.ps1` + the same shared
prompt + the same hook). When any file in the effective provider's
`REVIEW_INFRA` is staged, trusted sourcing is decided per component: each
component present in HEAD is extracted from HEAD, while a component positively
absent from HEAD is admitted only as a manifest-verified LOCAL snapshot. This
preserves supported hybrid layouts while ensuring that a staged wrapper,
prompt, or hook edit cannot supply the bytes that review itself.

**`AGENTS.md`, `scripts/shared/auto-merge.ps1`,
`scripts/shared/analyze-blocker-trends.ps1`, `scripts/shared/dispatch-checklist.ps1`,
`scripts/shared/worker-audit.ps1`, and `scripts/shared/author-lint.ps1`** are reviewed by the normal gate path
(no trusted-copy bootstrap, since no backend's `REVIEW_INFRA` list includes
them). Every invoked provider follows the same trusted-source decision in this
case; because neither wrapper was staged, normal review applies.

**`scripts/git-hooks/pre-commit` edits run under HEAD's logic, not
the candidate's.** Pre-commit is in `REVIEW_INFRA`, and the dispatcher
at `.git/hooks/pre-commit` (installed by `bootstrap.ps1`) captures the
exact `HEAD:scripts/git-hooks/pre-commit` blob, verifies the resulting
shell-owned buffer against the blob OID, and evaluates that buffer in
a fixed `/bin/sh` subshell — not the working-tree candidate or an
executable temp file. So a staged hook edit is BOTH (a) executed
under HEAD's last-good logic (which catches drift the same way it
catches wrapper/prompt drift) AND (b) reviewed by HEAD's wrapper +
prompt. The candidate logic does not run as the gate until it
becomes HEAD on a subsequent commit. Inspect candidate logic and obtain the
mandatory independent reviews before landing; do not create a separate smoke
commit or fixture to execute candidate hook code.

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
- Suggesting `CROSS_REVIEW_SKIP=1` as a workaround
  for clusters the audit surfaces. That switch exists for specific
  narrow cases documented in your project's `AGENTS.md`; it is not an
  audit prerogative. (`-AllowNonBlocker` was REMOVED with the 2026-07
  severity contract — QUALITY no longer blocks a merge at all.)
