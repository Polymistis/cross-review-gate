# cross-review-gate

**Version 2.6.6** (Windows / PowerShell) — the authoritative value is the
`VERSION` file at the package root; this line restates it for readers.

Version 2.4 moves the Grok model choice into the central runtime: a project
enables Grok fallback and names at most a profile (`recommended`, `strong` or
`fast`), and one central release plus activation changes what every profile
runs, with no per-project edits. Once any project's retained history holds a
Grok review run under 2.4 or a 2.4 configuration shape, rollback below 2.4 is
unsupported (see `docs/private-governance-v1.md`). A reviewed `grok-fallback`
enablement is itself the authorization for Grok to receive review material.
Version 2.4.1 fixes pushes from attached projects under Git for Windows.
Version 2.4.2 states the code unit-test ban to reviewers in the operator's
global wording. Version 2.4.3 fixes Stage, Open and Commit refusals when the
gate starts from a project subfolder. Version 2.4.4 runs Grok reviews like
Codex and Claude reviews: no turn cap or one-hour deadline, and the same
warn-only stall heartbeat, now one shared `scripts/review-liveness.psm1`
module that trusted review copies carry beside the wrappers. Per-project
installs gain that module; a LOCAL install must ignore it like the other gate
files. Portable archives now ship an explicit operator document list.

Version 2.5 keeps the code unit-test ban as the default and lets a centrally
attached project loosen it through reviewed `unit-tests` records in
`.crg-project/project.conf`: while the project is in prototype mode, or under
named folders. Reviews apply the scope the preceding approved configuration
selects. Once any project's retained history holds such a record, rollback
below 2.5 is unsupported (see `docs/private-governance-v1.md`).

Version 2.6 keeps review findings. These features belong to the ordinary
(not paired) Codex and Claude reviews: a passing review adds its QUALITY
and NOTE findings as tasks in the per-user `TASKS.md` and shows them to the
next review of the same files, and the retry of a blocked staged review
needs a remediation record first (both described below and in
`docs/review-feedback-v1.md`). Ordinary reviews other than Branch reviews
also show a fix-on-fix advisory when a change rewrites recently added
lines. Identity decisions and comparisons of outside field values (verdict
and record fields, Git output, paths) are ordinal rather than by culture;
the review wrappers' `-Scope`, the Codex wrapper's `-ReasoningEffort` and
the launcher's `-AuthoringAgent` keep `ValidateSet` binding (a culture
match) and are then mapped ordinally to the exact listed spelling, and
2.6.0 still found verdict lines with culture matches. The
bootstrap changed; take its hash from the release record.
Version 2.6.1 accepts a verdict line only in its exact form at the start of
its line, in the review hosts as in the log readers, and refuses near-miss
severity prefixes in any culture; reaches the follow-up index, its lock and
the seal records only through the held logs folder Git names, with one
PowerShell promoter for the commit and merge gates; shows skipped
housekeeping on a passing gate; and reads non-ASCII Git paths and reference
names as Git reports them. Its PowerShell entry points put back the console
code pages they change; the hook's promoter child leaves that to the commit
wrapper. The bootstrap changed again; take its hash from the release record.
Version 2.6.2 has the hook's promoter child put back the console code pages
itself, so a commit through `run-gate.sh` or a plain `git commit` no longer
leaves the console on UTF-8; has bootstrap raise a console code-page
failure around a Git call to its caller, whose recovery puts back a gate
file moved aside during install, instead of ending the run; has the
isolated Git helpers of bootstrap and the project-values renderer confirm a
Git child's exit after any failure before releasing it, and raise a failed
console input code-page restore only after that exit; stops the worker
audit on a failed UTF-8
switch instead of reporting misdecoded commit subjects; names the author
lint's console failures; makes every inline native-type compile stop on
failure; and drops an uncalled bootstrap function. The bootstrap changed
again; take its hash from the release record.
Version 2.6.3 has bootstrap's blob reader enforce its byte bound while
reading, confirm its Git child's exit after any failure, and return an
empty blob as bytes, so an empty tracked `.gitattributes` is verified
rather than refused; gives the central runtime's Git cleanup its bounded
wait even when stopping the child fails; refuses an install whose
custody-artifact exclude file cannot be located instead of continuing
without its patterns; and has every copy of the console code-page helper
refuse a loaded helper type that lacks a member it calls. The bootstrap
changed again; take its hash from the release record.
Version 2.6.4 has bootstrap's and the commit wrapper's path and reference
captures read Git output as bytes and decode it as UTF-8 instead of
switching the shared console's output code page for each call, so a run
killed during one of them no longer leaves that code page changed (Git
input setup and the review wrappers still switch console encodings and put
them back in a `finally`); holds the default pre-commit dispatcher open with
shared reads from its hash check until `git commit` returns; bounds the
captures of bootstrap's Git output helpers (the path and reference capture,
the blob readers and the isolated Git process, whose every caller now has a
stdout limit), the commit wrapper and the central status, object batch,
retention and renderer Git helpers, refusing one that
overflowed, and keeps the namespace pins of retention and the related
owners when a Git child's exit cannot be confirmed; and runs the follow-up
promoter in a hidden console of its own, showing its output as Unicode on a
console without changing the committer's code pages. The bootstrap changed
again; take its hash from the release record.
Version 2.6.5 switches console encodings only inside the running process,
never on the console window it shares with the invoking shell, so a killed
run leaves that console as it was (Git input setup, the review wrappers,
author-lint, auto-merge and worker-audit); in the central status,
object-batch and retention runners, the attribute-neutral diff runner and
auto-merge's identity runner, confirms that a failed Git child
has exited and every holder of its output pipes has closed them before
anything it uses is released, keeping the index copy, history control file, admission owners,
private initialization pins, attribute-neutral context and the launcher's runtime
owners when that cannot be shown; and bounds the remaining Git captures (the
project-mode declaration, the reviewed tree listing, the attribute-neutral
runner's errors, auto-merge's identity runner and the claude version probe)
and the waits for the attribute-neutral and identity runners to exit.
The bootstrap changed again; take its hash from the release record.
Version 2.6.6 extends that confirmation to bootstrap's identifier capture,
blob reader and isolated helper, the renderer's Git helper and the commit
wrapper's path capture. A failed Git child that cannot be confirmed ended is
raised as uncertain instead of being released; from then on the process
keeps, until it ends, the private attribute contexts, the renderer's
scratch and pins, and everything the bootstrap and renderer top-level
cleanups would otherwise release, and a refused cleanup reports the
original failure. `Read-CrgGitBytes` and the claude version probe bound
their waits for the process to exit and keep, rather than dispose, a
process still running after them, together with the checkout folder holds
and TASKS.md index guard released after it; `Read-CrgGitBytes` still
decides a failed read from the root's exit alone. The bootstrap changed
again; take its hash from the release record.

Version 2.3 made `grok-4.7` the Grok provider record for new and updated
project configuration (in 2.3, unmigrated `grok-4.6` records kept running
`grok-4.6`; from 2.4 they run the central `recommended` profile on their own
transport), and the legacy review-log prune never deletes files without an
operator-configured safe-delete tool.

Version 2.2 adds a shared machine-local runtime with project configuration and
separate private governance history. One central activation upgrades all attached
projects. Software and local LLM work remain subject to mandatory combined review;
private instructions, plans and review records stay outside public software history.
The Grok fallback reviewer supports API keys or an existing Grok Build CLI login
and is enabled by reviewed project configuration. Existing per-project
TRACKED/LOCAL installations remain available; central deployment is documented in
[INSTALL.md](INSTALL.md) and [central deployment](docs/central-deployment-v1.md).

A git pre-commit / pre-merge gate that runs **two independent AI agents
in cross-review**: when one agent authors a commit, the OTHER reviews
it. Every commit and every merge gates on the review's verdict;
findings are categorized into BLOCKER / QUALITY / NOTE tiers with
strict fail-closed semantics. Only BLOCKER findings block (2026-07
severity contract): QUALITY findings pass the gate as non-blocking
follow-ups, printed prominently and recorded (best-effort) to an
append-only `logs/review-followups.md` index for batch triage; NOTE
is informational. A passing ordinary (not paired) Codex or Claude review also adds tasks for its QUALITY and
NOTE findings (one per severity and citation) to the main checkout's
per-user `TASKS.md` (QUALITY first,
never committed) and shows its findings to the next review of the same
files; PASS lines state that a review covers the source diff only, not
target execution or deployment readiness. In an ordinary staged review, a
retry of a blocked commit is
refused before review until a remediation record names, for each earlier
BLOCKER it is asked to cover (from the blocked rounds of the last 14 days,
the newest 20 rounds, up to 256 findings newest first), the invariant
broken, the sweep made and the sites fixed, and the
reviewer is shown those findings and the record; when the earlier rounds
cannot be looked up, the review runs without them and says so
(`docs/review-feedback-v1.md`).

This package contains the Codex and Claude backend wrappers, the optional
central Grok fallback reviewer adapter, the shared review
prompt template, the pre-commit hook with backend routing, commit
wrappers that handle the cross-review env-var convention, a backend-neutral
project-value renderer, a trend analyzer, an author-side mechanical pre-pass
linter, a recurrence-ranked dispatch checklist generator, an audit protocol
for the review surface itself, and a bootstrap script that drops the whole
thing into a new git repo.

## Why

Adversarial review of every commit catches real defects that single-
author iteration misses. Cross-review (one agent reviews the other's
work) preserves the adversarial property even when the project's
work is itself agent-driven — neither agent is reviewing its own
output, which tends to produce friendly self-reviews. The verdict
format pins the contract so any tool that produces compliant output
can be slotted in as a backend.

## Concepts

- **Backends**: `codex` (Codex CLI / the model set in
  `~/.codex/config.toml`, e.g. GPT-6 Sol) and `claude`
  (Claude Code CLI / the `opus` alias). Either can act as IMPLEMENTER
  (the committer) or REVIEWER (the gate). Attached central projects may
  also enable the optional `grok` fallback REVIEWER (the model and effort
  of the central profile the project names, `recommended` by default),
  which reviews only after two positively identified exhaustions.
- **`REVIEW_BACKEND` names the preferred REVIEWER** (not the committer). The
  pre-commit hook reads `REVIEW_BACKEND` and starts with THAT backend's
  wrapper. To get cross-review, the committer sets it to the OTHER
  backend: Claude commits set `REVIEW_BACKEND=codex` so Codex
  reviews; Codex commits set `REVIEW_BACKEND=claude` so Claude
  reviews. The commit-wrapper scripts
  (`scripts/codex/commit.ps1`, `scripts/claude/commit.ps1`) handle
  this convention for you (each sets the env var to the OPPOSITE of
  its own identity, saved/restored around the call; the Codex entry
  runs the one implementation in `scripts/claude/commit.ps1`) so
  you don't forget. Both direct wrappers and `scripts/run-gate.sh` bind the
  current worktree by refusing ambient Git
  repository/history/attribute/config selectors before the first Git command;
  ordinary HOME/XDG configuration remains supported. Each direct commit entry
  also establishes exactly one canonical `GIT_NO_REPLACE_OBJECTS=1` raw
  environment entry before launching Git.
  Set `REVIEW_BACKEND=both` for defense-in-depth on high-stakes commits:
  two logical review legs run in series, and each independently makes one
  automatic alternate-provider attempt only after positively identified
  token exhaustion. A non-exhaustion first-leg failure short-circuits the
  second leg. Effective providers may collapse onto one, including for
  commit-wrapper edits; each leg still requires a separate complete passing
  review of the same candidate. Automatic substitution requires neither a
  Claude verdict nor distinct effective providers.
- **Token-exhaustion fallback**: a wrapper exit 4 means
  POSITIVELY-IDENTIFIED token exhaustion (the wrapper recognized a
  CLI-owned limit signature and wrote a durable `.exhaustion.json`
  sidecar; anything ambiguous stays exit 3, fail-closed, never
  fallback-eligible). The commit gate then re-runs the same review
  once on the other backend, and the merge gate substitutes a FULL
  panel on the other provider for its chosen panel's exhaustion —
  unless a surviving panel child already decided the merge (a
  BLOCKER keeps exit 2 instead of burning a substitute panel; any
  fail-closed or unknown child exit aborts on its own arm), and a
  codex-to-claude substitute is additionally refused when the branch
  touches the configured consistency doc or the base's claude
  wrapper predates `-ArtifactTag` (the refusal names the remedy).
  Cross-review is preferred; a fallback landing on the author's own
  provider is an internally recorded self-review accepted over a stalled
  gate. Routing is automatic, per invocation, and never changes caller
  environment state. A successful caller sees the same provider-neutral
  PASS shape whether substitution occurred or not; provider identity and
  exhaustion remain in the durable verdict headers and sidecars. Provider
  availability is not a caller option, and no skip-provider switch exists.
  When no provider can produce a verdict, the gate fails closed.
- **Verdict contract**: every review emits per-category enumeration
  (8 categories: PLAN-DRIFT, SILENT-FAILURE, TOMBSTONE-OR-SHIM,
  CROSS-CRATE-CONTRACT, LOADER-OR-ASSET-EDGE, CONVENTION-ADHERENCE,
  TEST-QUALITY, DOC-VS-CODE-DRIFT) + a `VERDICT:` line
  (CLEAN / NON-BLOCKING / BLOCKED) + per-severity entries. Wrapper
  parses this and exits 0 (clean / NOTE-only / QUALITY-only — QUALITY
  is a non-blocking follow-up under the 2026-07 severity contract,
  recorded best-effort to `logs/review-followups.md`; exit 1 is
  RETIRED and treated as fail-closed by the gates), 2 (BLOCKER),
  3 (malformed / fail-closed), or 4 (positively-identified token
  exhaustion — fallback-eligible, see the token-exhaustion fallback
  above; a parent with no fallback support treats it like any
  unexpected code and fails closed). Verdict artifacts carry a
  `REVIEW-SEVERITY-CONTRACT: blocker-only` header line as the
  contract-era stamp.
- **Project mode (`PROJECT-MODE.md`)**: a repo MAY declare its
  lifecycle phase in a root `PROJECT-MODE.md` (`mode:
  prototype|stabilizing|shipped`, an optional campaign line required for
  `prototype`, and optional declared invariant surfaces — grammar in the
  prompt template's `## Project mode` section; full doctrine in
  `docs/project-mode-doctrine-v1.md`).
  The declared mode governs behavior-preservation duties only, plus the code
  unit-test scope when a project configures a prototype allowance. Code quality
  is mode-invariant and the gate reviews at full strength in every mode.
  Code unit tests are banned by default, including on declared invariant
  surfaces; agent and reviewer instructions prohibit authoring, restoring,
  maintaining, or running code unit tests. Existing code unit tests and
  unit-test-only assets are removed through the applicable reviewed workflow.
  A centrally attached project's reviewed configuration can loosen the ban
  for prototype mode or named folders (`docs/private-governance-v1.md`). Live testing, manual
  checks, ordinary program runs, and functional validation remain permitted
  and important. Preserve production validation and verify through source
  inspection, builds, ordinary program operation, and functional validation.
  The campaign is review
  context and priority, never a work allowlist: unrelated work is judged
  against its own stated intent and cannot fail merely for not advancing
  the campaign. A declaration edit is ordinary reviewed configuration and
  may land beside other work; the declaration from the trusted state before
  the change governs that review, so the candidate never selects the rules
  used to judge itself. A malformed governing declaration produces a loud
  warning and `shipped` fallback rather than blocking project work.
  Clones upgrading from a pre-redesign per-clone dispatcher must run
  `bootstrap.ps1 -TargetRepo . -DispatcherOnly`; tracked-file updates cannot
  remove retired project-mode enforcement from `.git/hooks/pre-commit`.
  When trusted `HEAD` also contains the retired enforcement, dispatcher refresh
  alone is not the package upgrade; follow INSTALL's bounded
  kernel-and-completion TRACKED-upgrade procedure.
  Completion is argued with
  the evidence contract (date + command + observed output + named
  revision per citation; build output, captured ordinary operation, and
  functional validation), not with test volume or banned code
  unit-test execution.
- **Trust boundary**: the wrappers materialize a read-only snapshot
  of the reviewed source into `REVIEW_SRC/` under a fresh per-run scratch
  root under `%TEMP%` (`crg-review-<random>/reviewroot/REVIEW_SRC/` for the
  Codex wrapper, `crg-claude-review-<random>/reviewroot/REVIEW_SRC/` for the
  Claude wrapper) and run the reviewer with locked-down tool access.
  Reviewed-tree CLAUDE.md / AGENTS.md cannot influence the reviewer.

## Prerequisites

- Windows + Windows PowerShell 5.1 (`powershell.exe`).
  The wrappers are PowerShell; porting to bash is not in this package.
- Git 2.41 or later — bootstrap's identity-bound attribute proof requires
  both `check-attr --source` and the global `--attr-source` option on
  `hash-object --path --stdin`. Bootstrap runs behavioral probes for both
  forms and refuses before target mutation when either capability is absent.
  The wrappers also pin `--no-relative` on every project-mode evidence diff
  (available since Git 2.28)
- complete, unshallowed repository history for `-Scope Commit`,
  `-Scope Branch`, and `scripts/shared/auto-merge.ps1`. A shallow clone
  must be converted with `git fetch --unshallow` (or replaced by a full
  clone) before those operations. `-Scope Staged` remains available on
  both backends in a shallow clone; Codex `-Scope Uncommitted` remains
  available too (Claude does not support Uncommitted scope)
- a SHA-256 utility (`sha256sum` or `shasum`) on the
  pre-commit hook's PATH — shipped with Git for Windows; the hook
  digests the reviewed diff before any review starts and refuses the
  commit without one
- [Codex CLI](https://github.com/openai/codex) installed and
  authenticated, OR
- [Claude Code CLI](https://claude.com/claude-code) 2.1.248 or later
  with an active subscription, OR (recommended) both. The Claude wrapper
  requires the restricted-mode boundary introduced in 2.1.248 and refuses
  missing, malformed, or older version output before launching a review
- Either or both backend can run review; the trend analyzer scans
  both backends' verdict logs by default (missing dirs are skipped, so
  single-backend installs work); the audit protocol references both
  backends' wrappers and the shared prompt template

## Quick install

From the root of your git repo:

```powershell
# 1. Extract the zip somewhere (e.g., a tools/ dir)
Expand-Archive -Path cross-review-gate-X.Y.Z.zip -DestinationPath tools/

# 2. Create CROSS-REVIEW-VALUES.md at the target root using the v1 grammar in
#    INSTALL.md Step 2 and fill all three blocks with actual project content.
#    TRACKED shape: git add -- CROSS-REVIEW-VALUES.md
#    LOCAL shape: ignore that file and every incoming gate destination first.

# 3. Run the bootstrap script targeting your repo root
powershell -NoProfile -ExecutionPolicy Bypass -File tools/cross-review-gate/bootstrap.ps1 -TargetRepo .

# 4. The bootstrap will:
#    - Copy scripts/{codex,claude,git-hooks}/, scripts/run-gate.sh, and
#      scripts/render-project-values.ps1 into your repo
#    - Copy docs/audit-protocol.md and the rendered docs/AGENTS.md.template
#      into your repo's docs/
#    - Render project context, hazards, and SCOPED authority inline from the
#      retained target-root values source before any destination mutation
#      (package self-install checks matching stock slots without rewriting)
#    - Ignore the gate's generated artifacts: `logs/` is appended to
#      your repo's root .gitignore -- or to the git common dir's
#      info/exclude instead when the gate hook path is already ignored
#      (the LOCAL shape below leaves project files untouched). Each
#      append is idempotent; the append is skipped only when one of
#      the literal forms `logs/`, `/logs/`, `logs`, or `/logs` is
#      already present -- a glob like `logs/**` still gets the
#      explicit `logs/` added
#    - Append the required named checkout rules for the sh-parsed gate surfaces
#      and TRACKED render inputs/outputs to your
#      repo's root .gitattributes -- through a handle-pinned write on
#      a validated regular single-link file, never through a symlink
#      -- and verify the EFFECTIVE conversion contract by behavior
#      (CRLF probe bytes normalize to LF on checkin, an LF blob
#      checks out as LF under core.autocrlf=true, and check-attr
#      --all lists no filter/working-tree-encoding attribute; eol
#      alone is defeated by a later -text or filter rule), resolved in
#      an isolated context of the repo's own attribute files under an
#      allowlisted environment (an ambient info/attributes or global
#      rule, or environment-carried git configuration, cannot mask
#      a violation a fresh clone would suffer); without
#      the rules a core.autocrlf=true checkout rewrites the entry
#      point to CRLF and sh fails parsing it. The values source, review prompt,
#      and AGENTS merge template additionally require strict UTF-8/LF bytes
#      with filter, ident, and working-tree encoding disabled. Each path is
#      classified independently (hybrid layouts: an ignored
#      local-shape path gets no rule, a tracked one always gets
#      its rule), and the audited skip refuses any unreviewed
#      landing whose staged attribute state breaks the contract
#    - Install a per-clone dispatcher at .git/hooks/pre-commit
#      (closes the `git rm gate` bypass that a versioned core.hooksPath
#      install would leave open)
#    - Record an install manifest (per-file SHA-256) and package-version
#      record in the repo's PER-WORKTREE git dir (each linked worktree
#      seals its own baseline). A copied install also stamps package
#      version/source provenance into each installed file; a self-install
#      deliberately leaves the package's tracked source bytes unstamped
#      while still publishing the manifest and version record
#    - On a version upgrade, compare tracked files with trusted HEAD first
#      and use the manifest only after HEAD positively proves the path
#      absent. Refuse to overwrite a local edit, back up EVERY
#      pre-existing file before replacement, and report every replaced
#      upgrade file. A same-version -Force refresh still backs up every
#      replacement and reports baseline or late-copy divergence
#    - Print a checklist of remaining setup steps you must do manually
```

See `INSTALL.md` for the detailed install + customization flow.

**Install shapes.** The default (preferred) shape TRACKS the gate files
in your repo — the checklist's bootstrap commit puts them in HEAD, which
is the gate's trusted baseline. A project whose scope cannot admit
tooling into its history can instead run the LOCAL shape: leave the gate
files untracked and deliberately ignored (list the gate paths in
the repository's `info/exclude` — resolve it with
`git rev-parse --git-path info/exclude`; `.git/info/exclude` in a
plain checkout — BEFORE running bootstrap, which then also routes
the `logs/` rule there instead of touching the tracked `.gitignore`),
and the trust chain verifies them against the install manifest instead
of HEAD (bootstrap also records a local-shape authorization marker
beside the manifest, listing exactly the components it observed
untracked and ignored and epoch-bound to that manifest — the manifest
alone never admits local authority, so a commit that merely untracks
and ignores the gate files buys a refusal, not a shape change; the
hook additionally refuses any staged untracking of a gate component
without the operator's CROSS_REVIEW_ALLOW_GATE_UNTRACK=1 sanction).
`CROSS-REVIEW-VALUES.md` follows the same selected authority family but remains
project-owned and outside the install manifest. Project context is changed in
that source, never by hand-editing the installed prompt or merge template. A
TRACKED source update is staged before rendering; an existing TRACKED install
can run `scripts/render-project-values.ps1 -TargetRepo <root>`, while install
and upgrade use package `bootstrap.ps1 -TargetRepo <root> -Force`. A LOCAL
source update uses full package bootstrap because standalone Apply never
changes executable LOCAL gate bytes. `-SealManifest` is reserved for the
bounded legacy/current LOCAL recovery cases in `docs/install-values-v1.md`, not
routine customization. An unrecognized local gate edit is preserved and
refused until the applicable recovery sequence establishes a trusted baseline.
The
advisory author-lint pre-pass is the exception: an unverifiable local
copy skips fail-open with a WARN, and the review gate itself still
runs.
`docs/local-install-v1.md` defines the shape; nothing else in the
setup differs.

## What you MUST configure before relying on the gate

1. **Project values in root `CROSS-REVIEW-VALUES.md`** — create the v1
   source before bootstrap and supply actual `project-context`,
   `project-hazards`, and `scoped-authority` bodies. Bootstrap validates the
   retained source and renders those bodies inline into the installed prompt
   and AGENTS merge template before any destination mutation. No review process
   reads the values file at runtime. Hazard examples use SYMBOL ANCHORS (the
   function / type / system name), not bare `file.ext:NNN` line numbers. Use
   the exact no-authority sentinel when SCOPED capture is intentionally
   dormant. `INSTALL.md` Step 2 and `docs/install-values-v1.md` define the
   grammar, authority, update, and recovery rules.
2. **Agent-instruction file merge** — `docs/AGENTS.md.template`
   contains the role / convergence-loop / operational sections. The
   two backends auto-discover different files: **Codex CLI** auto-loads
   `AGENTS.md` from the working root + ancestors; **Claude Code CLI**
   does NOT auto-load `AGENTS.md` — it auto-loads `CLAUDE.md` (project
   + walk-up) and `~/.claude/CLAUDE.md` (user-global). So merge the
   template sections into BOTH `AGENTS.md` AND `CLAUDE.md` if you
   want both backends to see the contract as authoritative
   instructions, or rely on a pre-existing user-global CLAUDE.md to
   cover the Claude side. INSTALL.md Step 4 has the full guidance.
3. **`~/.codex/config.toml`** (Codex backend only) — see INSTALL.md
   for the minimum config; sandbox + approval are passed per-
   invocation by the wrapper, so global config stays unmolested.
4. **Claude auth** (Claude backend only) — interactive `claude` login
   once on the machine is enough; the wrapper picks up credentials
   via keychain. See INSTALL.md for the API-key fallback path if
   keychain isn't an option.

### Optional

- **Consistency-doc precompute** — set `$env:CROSS_REVIEW_CONSISTENCY_DOC`
  to the repo-relative path of a planning/spec doc (e.g. `PLAN.md`) to
  enable the milestone cross-reference / range / missing-field precheck on
  that doc. Default OFF: a fresh install runs no special-casing. When set,
  the codex wrapper writes a `PLAN-CONSISTENCY.txt` report, the merge gate
  refuses `-Backend claude` for branches that touch the doc (naming
  `-Backend codex` as the remedy), and the Claude wrapper fails closed
  (routes such edits to the Codex backend, which has the precompute). The value is trimmed + canonicalized to git path
  form; a SET-but-invalid value — empty/whitespace-only, absolute, a `..`
  escape, a path containing an internal control character, DEL, or a double
  quote (spellings Git would C-quote), OR a path that does not resolve to a
  tracked FILE (a git blob) in the reviewed tree (a typo, a directory, or any
  non-blob object) — FAILS CLOSED
  (the wrappers exit 3 / the merge aborts) rather than silently disabling the
  gate — only an UNSET variable means "off". See INSTALL.md for details.
- **Prune tool** — set `$env:CROSS_REVIEW_PRUNE_TOOL` to a delete tool
  (e.g. a Recycle-Bin script) to enable log housekeeping; unset means
  review logs are never deleted. See INSTALL.md.
- **Legacy-index seal (capture doctrine v6)** — on an install whose
  follow-up index carries pre-v6 content (content no reader can verify),
  the review-log auto-prune stays QUARANTINED until the operator
  inspects that legacy region and runs the seal mode
  (`auto-review.ps1 -Scope SealLegacy`). Fresh v6 installs — and installs
  whose index is absent or empty — have no legacy region and need no
  seal. See INSTALL.md's "Legacy-index seal" section.

## Layout

```
cross-review-gate/
├── README.md              (this file)
├── INSTALL.md             (detailed setup)
├── VERSION                (authoritative package version consumed by bootstrap)
├── bootstrap.ps1          (copies files into a target repo; self-install aware)
├── .gitignore             (ignores the gate's generated logs/ tree; bootstrap creates this in a target repo, and it is present here so this package self-gates)
├── .gitattributes         (named checkout contracts for sh and rendered-value surfaces)
├── scripts/
│   ├── codex/
│   │   ├── auto-review.ps1            (Codex backend review wrapper)
│   │   ├── auto-merge.ps1             (legacy launcher entrypoint; forwards to shared)
│   │   ├── commit.ps1                 (Codex-implementer entry; runs the claude/ wrapper)
│   │   └── review-prompt-template.md  (shared prompt with rendered project values)
│   ├── shared/
│   │   ├── auto-merge.ps1             (shared ff-merge gate; Codex or Claude review)
│   │   ├── analyze-blocker-trends.ps1 (trend report over verdict logs)
│   │   ├── author-lint.ps1            (author-side mechanical pre-pass linter)
│   │   ├── dispatch-checklist.ps1     (recurrence-ranked dispatch checklist from verdict logs)
│   │   └── worker-audit.ps1           (per-landing process audit over the verdict logs;
│   │                                   auto-merge runs a TRUSTED copy after a merge --
│   │                                   the base's, else the manifest-verified local
│   │                                   snapshot -- non-gating; skipped with a note when
│   │                                   no trusted source holds it or the central
│   │                                   review-log dirs do not resolve)
│   ├── claude/
│   │   ├── auto-review.ps1            (Claude backend review wrapper)
│   │   └── commit.ps1                 (the one commit wrapper; Claude implementer when run directly)
│   ├── git-hooks/
│   │   └── pre-commit                 (REVIEW_BACKEND-routed pre-commit hook)
│   ├── render-project-values.ps1      (backend-neutral values renderer/checker)
│   └── run-gate.sh                    (stable gate-firing entry point: worktree,
│                                       message file, reviewer backend, pass count
│                                       (codex-side) as arguments; refuses to commit
│                                       un-gated on repository-identity mismatch or
│                                       malformed NUL-framed staged-set evidence;
│                                       normalizes replacement suppression, clears
│                                       retired project-mode authorization, rejects
│                                       raw history/attribute/repository/config
│                                       Git-selector environment names, when
│                                       core.hooksPath is
│                                       configured -- classified by git's exit
│                                       status, so a set-but-empty value counts --
│                                       or when the dispatcher is absent, disarmed,
│                                       or fails its bootstrap-recorded digest
│                                       attestation)
├── docs/
│   ├── audit-protocol.md              (periodic review-surface audit)
│   ├── AGENTS.md.template             (rendered merge source for AGENTS.md/CLAUDE.md)
│   └── ...                            (additional product contracts and design
│                                       documents, not installed and not exhaustively
│                                       listed here)
└── examples/
    └── project-hazards-example.md     (sample hazards section from a real project)
```

## Status / scope

This package was extracted from a working install in a Rust/Bevy game
project. The wrappers are battle-tested in that environment; the
project-agnostic scrubbing has been done but consumer projects may
hit edge cases. File issues against the canonical source if anything
is wrong or unclear. Re-packaging this gate for another project? See
the **Before redistributing this package** checklist in
`docs/audit-protocol.md` — search for your identifiers in all
case/separator variants before shipping.

Sub-features documented in `docs/audit-protocol.md` reference some
project-specific paths (PLAN.md, History.md) as illustrative
examples; the audit protocol is the section most likely to need
adaptation to your project's actual documentation structure.
