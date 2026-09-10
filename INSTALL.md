# INSTALL — cross-review-gate

This document covers the full install + customization flow for the
package. The quick-install in `README.md` shows the abbreviated path;
this file is the detailed reference.

## Central installation and portable rollout (v2.2)

Use [Central deployment v1](docs/central-deployment-v1.md) for the centralized
runtime: publish or import one approved release, install the stable launcher once,
activate centrally, and attach each project through private configuration and
mandatory combined review. Later compatible upgrades change the central selection,
not every project's installed runtime or configuration. Portable import requires
the approved bootstrap and manifest-owned release payload, not a source `.git`.

The numbered steps below describe the legacy TRACKED/LOCAL per-project shapes.
Do not combine those bootstrap commands with central attachment or use a legacy
`-Force` reinstall as a central upgrade. Existing legacy installations remain
governed by the unchanged instructions below until explicitly migrated.

Installation requires Git 2.41 or later. Bootstrap behaviorally verifies the
required `check-attr --source` and global `--attr-source`/`hash-object --stdin`
capabilities before any target mutation and refuses when either probe fails.
The Claude review backend additionally requires Claude Code 2.1.248 or later;
the wrapper verifies the exact CLI version before every review launch because
older releases do not provide the required restricted-mode boundary.

## Step 1 — extract the package

Extract the zip into a path of your choice. A `tools/` subdirectory of
your target repo is a reasonable convention but not required:

```powershell
Expand-Archive -Path cross-review-gate-X.Y.Z.zip -DestinationPath tools/
```

After extraction you should have `tools/cross-review-gate/` containing
`README.md`, `INSTALL.md`, `VERSION`, `bootstrap.ps1`, `.gitignore`,
`.gitattributes`, `scripts/`, `docs/`, `examples/`.

The archive deliberately excludes `CROSS-REVIEW-VALUES.md`; target project
configuration is supplied separately at the target repository root and never
falls back to package content.

## Step 2 — run the bootstrap

**If the repo already carries a root `PROJECT-MODE.md`**, leave it in
place. The file is ordinary review configuration, not install authority.
After the gate lands, a valid declaration at the governing ref supplies
the review lens; a verified-absent or positively malformed declaration uses
`shipped` defaults, with a loud warning for the malformed case. A legacy file can
therefore be normalized in an ordinary reviewed change without wedging
the bootstrap or unrelated project work.

**Create `<target-root>/CROSS-REVIEW-VALUES.md` before bootstrap.** Use the
exact v1 outer form in `docs/install-values-v1.md` section 2 and replace every
metasyntactic body with actual project content. The three required blocks are
`project-context`, `project-hazards`, and `scoped-authority`. The authority body
contains canonical repository-relative authority-document records, or the
exact `- No authority documents. SCOPED capture is dormant.` sentinel. The
file must be strict UTF-8 without a BOM, LF-only, and final-LF terminated.

For the TRACKED shape, stage the source before running bootstrap so the index
blob is the reviewed authority and the working bytes can be matched exactly:

```powershell
git add -- CROSS-REVIEW-VALUES.md
```

For the LOCAL shape, leave the source untracked and add
`/CROSS-REVIEW-VALUES.md` to the effective ignore file together with every
incoming gate destination before running bootstrap. The `Dst` column of
`Get-CrgCurrentFileList` in the extracted `bootstrap.ps1` is the authoritative
destination set; use those exact repository-relative paths rather than a broad
directory glob. The values source follows
the selected TRACKED or LOCAL authority family but remains project-owned: the
package never copies, overwrites, manifests, or archives that file.

**Decide the install shape now** — before the bootstrap runs.
The default is the TRACKED shape (the gate files are committed in Step
8). A project whose scope cannot admit tooling into its history runs
the LOCAL shape instead (`docs/local-install-v1.md`): put the gate
paths in the repository's `info/exclude` NOW — resolve its real path
with `git rev-parse --git-path info/exclude` (that is
`.git/info/exclude` in a plain checkout; in a linked worktree `.git`
is a FILE and the exclude lives in the shared common dir) — so this
bootstrap run routes the
`logs/` artifact rule there too instead of touching the tracked
`.gitignore`, and follow Step 8's local-shape alternative when you
reach it.

From the root of your git repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/cross-review-gate/bootstrap.ps1 -TargetRepo .
```

The bootstrap does the following:
- Verifies `-TargetRepo` is a git working tree
- Copies `scripts/codex/`, `scripts/claude/`, `scripts/git-hooks/`,
  `scripts/run-gate.sh`, and the backend-neutral
  `scripts/render-project-values.ps1` into the target repo's `scripts/`
  directory
- Copies `docs/audit-protocol.md` and the rendered
  `docs/AGENTS.md.template` into the target repo's `docs/` directory
  (creating `docs/` if missing)
- Retains and validates the selected values source and raw package templates,
  renders all project-context slots in memory, and validates every complete
  output before entering destination mutation. Installed prompt and AGENTS
  template bytes contain final inline text; review and hook paths perform no
  runtime values lookup. A package self-install performs the same check but
  never rewrites a render-bearing package template
- Appends `logs/` to the target repo's root `.gitignore` (creating it
  if missing) — or, when the gate hook path is already ignored (the
  LOCAL shape's Step-2 excludes), to the repository's `info/exclude`
  instead, leaving project files untouched — so the gate's generated
  artifacts — verdict logs under
  `logs/<backend>/reviews/`, the dispatch-checklist report (default
  `logs/dispatch-checklist.md`) — are not tracked. (The blocker-trends report is
  the deliberate exception: it defaults to `docs/blocker-trends.md`, a
  TRACKED location under `docs/` rather than gitignored `logs/`, because it
  is a durable historical record rather than a transient operational
  artifact — generate it in Step 11.) Idempotent: it skips the append when an existing `.gitignore`
  line already ignores the root `logs/` tree in any of the four common
  forms — `logs/`, `/logs/`, `logs`, or `/logs`. (A deeper-path or
  `**/`-prefixed pattern is not treated as covering the root tree, so the
  explicit `logs/` is still added.) Remember to `git add .gitignore` in
  the bootstrap commit (Step 8) so the rule is committed for later clones.
- Appends named checkout rules for the sh-parsed gate surfaces and TRACKED
  render surfaces to the target repo's
  root `.gitattributes`, creating it if missing: under
  `core.autocrlf=true` a fresh tracked checkout would otherwise rewrite
  them to CRLF and `sh` would fail parsing the gate-firing entry point
  before any guard runs. Append-if-absent like the `.gitignore` rule —
  written through an exclusively held handle on a validated regular
  single-link file, so a symlinked or hard-linked `.gitattributes`
  refuses instead of mutating a target outside the repository — and
  the EFFECTIVE conversion contract is then verified by exercising
  git's own conversion (CRLF probe bytes must normalize to LF through
  the path's clean conversion, an LF blob must check out as LF bytes
  under `core.autocrlf=true`, and `git check-attr --all` must list no
  filter or working-tree-encoding attribute — rendered `set` /
  `unspecified` strings cannot tell a state from the literal values
  `text=set` / `filter=unspecified`, which git treats as not set; and
  `eol` alone is defeated by a later `-text` or filter rule), in an ISOLATED context
  that holds only the repository's own attribute files, under an
  allowlisted environment with the temporary repository pinned
  explicitly — an ambient `info/attributes` or global/system rule, or
  git configuration carried in the environment
  (`GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n`),
  cannot mask a violation that a fresh clone would suffer. The values source,
  review prompt, and AGENTS merge template require `text eol=lf` plus unset
  `filter`, `ident`, and `working-tree-encoding`; behavioral probes also
  preserve literal `$Id$` and non-ASCII UTF-8 bytes. A consumer rule that still
  overrides these lines fails the bootstrap loudly instead of leaving
  checkout conversion live. Every named path is classified INDEPENDENTLY
  against its ignore state — hybrid layouts are supported, so an
  ignored (local-shape) hook beside a tracked `run-gate.sh` still
  gets the tracked path's rule — and a deliberately ignored path gets
  none (untracked files are never checkout-rewritten). The audited
  skip additionally validates the STAGED contract before every
  unreviewed landing: a skip that deletes or overrides the rules
  while a sh surface stays tracked refuses.
  Remember to `git add .gitattributes` in the bootstrap commit (Step 8).
- Installs a per-clone dispatcher at `.git/hooks/pre-commit` that
  delegates to the in-tree gate. The dispatcher lives OUTSIDE the
  working tree (in `.git/hooks/`, which is per-clone and not
  versioned), so a commit cannot edit or remove it through the
  review flow — closing the `git rm scripts/git-hooks/pre-commit`
  bypass that a versioned `core.hooksPath` install would leave open.
- Reconciles a prior `core.hooksPath`: unsets the legacy
  `scripts/git-hooks` value (superseded by the dispatcher), but ABORTS
  without `-Force` on any OTHER set value — a custom hooks dir or an
  empty `core.hooksPath=` — because the commit wrappers require
  `core.hooksPath` unset and abort on any set value. It also fails
  closed on a `git config` error, and refuses to run when a masking
  `GIT_CONFIG_*` env var is set (so it classifies `core.hooksPath`
  against the same effective config the wrappers will)
- Stamps package-version and source-commit provenance into every copied
  gate file, then records the exact installed-file hashes in
  `crg-install-manifest` and the package version in `crg-install-version`
  under the target's per-worktree Git directory. A self-install is the
  deliberate exception to stamping: package source and target are the same
  files, so bootstrap copies and stamps nothing, but still publishes the
  manifest and version record for the source bytes already present
- On `-Force`, recognizes a complete current install and the frozen released
  v1.7 inventory even when install metadata is absent. A version upgrade
  compares a tracked path with trusted `HEAD` first and consults the manifest
  only after `HEAD` positively proves that path absent. An edited path whose
  trusted baseline cannot be proved is preserved and the upgrade refuses;
  every successful replacement is backed up, every replaced upgrade path is
  reported, and a same-version refresh reports baseline or late-copy
  divergence
- Prints a setup checklist of remaining manual steps

The bootstrap installs a rendered `docs/AGENTS.md.template` but does NOT open,
create, or edit root `AGENTS.md` or `CLAUDE.md`; merging the installed template
remains a manual step (see Step 4 below).

**Legacy and metadata-free existing installs.** Every render-bearing upgrade
requires the explicit values source described above; bootstrap never scrapes a
legacy prompt or synthesizes project facts. A complete TRACKED legacy inventory
can upgrade with `-Force` after the source has staged TRACKED authority because
each existing path is compared with trusted `HEAD`. For a LOCAL install, a
still-valid v2.0 manifest and authorization marker already provide the trusted
replacement baseline. A metadata-free or deliberately divergent LOCAL legacy
inventory has no such baseline and uses the bounded seal sequence below.

To retain and migrate inspected metadata-free LOCAL bytes, install the current
dispatcher, create and validate the LOCAL values source, add every new v2.1
destination to the effective ignore rules, seal the recognized inventory under
operator custody, then retry the upgrade:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/cross-review-gate/bootstrap.ps1 -TargetRepo . -DispatcherOnly
$env:CROSS_REVIEW_ALLOW_SEAL = '1'
try {
  powershell -NoProfile -ExecutionPolicy Bypass -File tools/cross-review-gate/bootstrap.ps1 -TargetRepo . -SealManifest
} finally {
  Remove-Item Env:CROSS_REVIEW_ALLOW_SEAL -ErrorAction SilentlyContinue
}
powershell -NoProfile -ExecutionPolicy Bypass -File tools/cross-review-gate/bootstrap.ps1 -TargetRepo . -Force
```

The legacy seal accepts the complete frozen v2.0 inventory or the exact frozen
v1.7 core plus any present, recognized v2.0 additions. The current-v2.1 recovery
arm accepts only the complete current inventory, a valid LOCAL values source,
successful shared-core rendering, absent renderer transaction state, and the
documented metadata mismatch or absence. Arbitrary partial or mixed inventories
refuse. Inspect every installed file before applying the sanction; sealing
defines only the trusted replacement baseline and does not prove source
agreement or package provenance. Run the full `-Force` install immediately
afterward, then run renderer `-Check`.

**Dispatcher-only refresh (`-DispatcherOnly`)**: on a clone that is
ALREADY installed, run

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/cross-review-gate/bootstrap.ps1 -TargetRepo . -DispatcherOnly
```

to install or replace ONLY the per-clone dispatcher at
`.git/hooks/pre-commit`. No tracked file is touched. A full `-Force` run
validates project values, renders the complete destination set, and refreshes
install metadata, so dispatcher-only refresh remains the correct operation
when no in-tree install change is intended. Use it for: a FRESH CLONE
of a TRACKED-shape installed repo (per-clone hooks do not clone, so
every new clone needs it; a fresh clone of a LOCAL-shape repo instead
needs a full bootstrap — it has neither gate files nor a per-worktree
manifest, and the dispatcher alone would refuse every commit), and a
LEGACY or stale dispatcher that lacks the current audited-skip and
gate-untracking guards. Also run this refresh after upgrading from a
pre-redesign dispatcher that still contains `PROJECT-MODE.md` enforcement;
such a dispatcher can carry both generic guards and still impose the retired
declaration sanction, skip refusal, or rollback checks. Tracked-file upgrades
cannot rewrite this per-clone hook. `-DispatcherOnly` overwrites an existing
dispatcher without `-Force` — replacement is its purpose.

If you'd rather copy files manually, see the bootstrap script's
source for the exact dispatcher content (it has to be installed
in `.git/hooks/pre-commit` per-clone; copying is not enough).

### Upgrade a TRACKED pre-redesign project-mode install

This subsection applies only when the tracked `HEAD` gate still enforces
`PROJECT-MODE.md` as a work authorization, declaration sanction, or campaign
gate. The upgrade retires that behavior through a kernel landing followed by a
completion landing.
`PROJECT-MODE.md` itself is not changed: the file remains tracked review
context that tells reviewers how to evaluate work, never whether work may
proceed. The bounded procedure below exists only because the old trusted gate
cannot review the commit that removes the old gate's own enforcement. No
equivalent transition applies after the review-context kernel lands.

Start on a dedicated upgrade branch based directly on the intended target
branch. A normal consumer target requires an empty index plus no unrelated
tracked or install-destination changes before bootstrap copies the candidate
package. An untracked extracted package directory inside the target is allowed:
that directory supplies source bytes rather than destination state. A self-host
target instead requires an empty index and the intended candidate package diff
already present in the worktree: package source and target are the same files,
so a clean self-host worktree would contain nothing for bootstrap to publish as
the replacement kernel. Keep unrelated worktree changes out and keep each
infrastructure landing free of unrelated staged paths so the replacement
identity can be proved exactly.

First refresh the machine-local dispatcher, then run a complete package
install. For a consumer whose extracted package is rooted at
`tools\cross-review-gate`, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\cross-review-gate\bootstrap.ps1 -TargetRepo . -DispatcherOnly
powershell -NoProfile -ExecutionPolicy Bypass -File tools\cross-review-gate\bootstrap.ps1 -TargetRepo . -Force
```

For this package's self-host transition, run from the package root instead:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -TargetRepo . -DispatcherOnly
powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -TargetRepo . -Force
```

`-DispatcherOnly` touches no tracked file. The refreshed dispatcher preserves
the generic gate-untracking and audited-skip guards, clears the retired
`CROSS_REVIEW_ALLOW_MODE_CHANGE` variable before child execution, and delegates
ordinary non-skip commits to the old trusted `HEAD` hook. A generic audited skip
delegates only when trusted `HEAD` carries exactly one
`# crg-dispatch-tree-handoff-v1` capability marker. The earliest supported
legacy hook predates that capability, so generic skips fail closed until the
bounded review-kernel transition lands. `-DispatcherOnly` deliberately creates
no transition record.

Only a successful full install publishes the per-worktree
`crg-review-kernel-transition` identity record. The record is bound to the
current `HEAD` OID and contains the exact staged mode and filter-aware blob OID
for every changed path among:

- `.gitattributes`, when the candidate LF checkout contract changes;
- `scripts/git-hooks/pre-commit`;
- `scripts/codex/auto-review.ps1`;
- `scripts/claude/auto-review.ps1`; and
- `scripts/codex/review-prompt-template.md`.

The set is derived from the installed bytes and the target repository's Git
attributes; no fixed path-list assumption applies. A self-host install also
preserves the candidate raw routing drivers in
base-bound, digest-verified custody under the per-worktree Git directory before
attempting identity-record publication. That ordering makes custody a
recoverable write-ahead phase, not permission to land an unrecorded kernel.

Follow the full bootstrap's printed section A to restore each raw routing
driver to the state preceding hook execution. A path present in `HEAD` is
restored in the index and worktree. A path positively absent from `HEAD`, such
as `scripts/run-gate.sh` in the earliest supported layout, is removed from the
target worktree. For a normal consumer install, the separate package source
retains the candidate bytes. For a self-host install, verified custody retains
those bytes for the second landing.

Follow printed section B exactly: stage only the paths named by the published
identity record, then inspect the staged set:

```powershell
git add -- <paths printed by bootstrap section B>
git diff --cached --name-only
git -c core.whitespace=cr-at-eol diff --cached --check
```

Commit through raw Git with the ordinary audited skip so no candidate routing
driver executes:

```powershell
$env:CROSS_REVIEW_SKIP = '1'
try {
  git commit -m "cross-review-gate: transition review context"
} finally {
  Remove-Item Env:CROSS_REVIEW_SKIP -ErrorAction SilentlyContinue
}
```

This is the existing audited skip, not a project-mode authorization. The
dispatcher first confirms that trusted `HEAD` carries a recognized retired
kernel, then verifies the record's base OID, every recorded mode and blob OID,
every omitted protected path, the absence of extra staged paths, the routing
driver state, and the staged LF contract. The staged tree is written to the
local `refs/crg-review-skips` immutable audit chain before success. Neither the old project-mode policy nor candidate
hook, wrapper, or prompt bytes execute for this one identity-attested landing.
Outside that record-bound transition, a pre-handoff legacy `HEAD` refuses every
generic audited skip. Once trusted `HEAD` carries the exact handoff capability,
generic audited skips can delegate with the dispatcher-owned staged tree.

Land that review-kernel commit by itself so the target branch contains it
before preparing the second landing. In a feature-branch workflow, having the
kernel earlier only on the candidate branch is insufficient: branch review
executes the target base's trusted wrapper and prompt. Use the target project's
existing operator promotion path for this bounded self-replacement when the
old merge gate cannot admit its own replacement. A fast-forward of the exact
kernel commit leaves the upgrade branch on the same updated base. Do not set
`CROSS_REVIEW_ALLOW_MODE_CHANGE`, edit `PROJECT-MODE.md`, or weaken a hook to
make the transition pass.

After the target base contains the kernel commit, prepare the remaining package
change for a normal consumer install by re-running the full package bootstrap
with `-Force`. For a self-host install, the remaining candidate package bytes
were necessarily present before the first bootstrap and have stayed
uncommitted; first restore the raw routing drivers from durable custody through
the operation printed in section E:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -TargetRepo . -RestoreLegacyRoutingCustody
```

That operation accepts either the exact recorded legacy base (pre-kernel
interruption recovery) or the exact base-to-kernel landing. It verifies the
expected phase-A `HEAD`, index, and worktree state, freezes existing
destinations, verifies each custody digest, restores only the recorded
candidate routing drivers, and verifies each restored digest. No manual `Copy-Item`
recipe is a supported restore path. Then re-run the full self-bootstrap under
the applicable trusted `HEAD`; the pre-kernel arm republishes the same bounded
custody epoch before phase A repeats, while the post-kernel arm enables the
normal second landing. A stale base or post-kernel routing-driver edit stops
recovery before any overwrite.

For a customized legacy prompt, use the verified backup path printed by the
first bootstrap run, or the legacy parent of the kernel commit, as a reference
while authoring `CROSS-REVIEW-VALUES.md`. Transfer only the intended semantic
content from the legacy Project context and Project hazards sections into the
corresponding values blocks, and transfer the intended authority-document set
into `scoped-authority`. Never restore or copy the whole legacy prompt: doing
so would restore retired campaign and declaration rules. Establish TRACKED or
LOCAL source authority before the full bootstrap; the current package headings,
slot markers, and contract sections come only from retained package templates.

On a normal consumer target, stage the remaining installed package inventory
printed by bootstrap. On a self-host target at the exact recorded kernel
landing, use the separate source-completion recipe printed by bootstrap:
`git add -u -- :/` stages every already-tracked package-source modification or
deletion, including release documents outside the consumer install payload,
without admitting arbitrary untracked files. Add each intentional new source
path explicitly. Inspect the complete index and confirm that no intended
tracked delta remains unstaged:

```powershell
git add -u -- :/
# git add -- <intentional-new-source-path>  # repeat only for deliberate additions
git status --short
git diff --cached --name-only
git -c core.whitespace=cr-at-eol diff --cached --check
```

Commit through raw Git with both reviewers. Raw Git is required here because
the candidate commit wrappers and `run-gate.sh` are part of the change; the
installed dispatcher selects the trusted `HEAD` hook and that hook selects the
trusted `HEAD` wrappers and prompt.

```powershell
$env:REVIEW_BACKEND = 'both'
try {
  git commit -m "cross-review-gate: complete review-context upgrade"
} finally {
  Remove-Item Env:REVIEW_BACKEND -ErrorAction SilentlyContinue
}
```

Interruption recovery is state-based:

- After only `-DispatcherOnly`, tracked `HEAD` remains legacy; resume the
  full bootstrap. No identity record or self-host custody exists yet.
- If a self-host full bootstrap activates verified custody but identity-record
  publication fails, remain at the exact recorded legacy base. An unchanged
  checkout whose routing sources still match custody may retry the full
  bootstrap directly. If phase A, absence, or an edit changed a routing source,
  run `-RestoreLegacyRoutingCustody` first; exact-base restoration accepts the
  positively absent identity record, restores only verified candidate bytes,
  and publishes no post-kernel completion marker. Then retry the full
  bootstrap. An external package source cannot retry against that active
  worktree. A malformed or non-file identity occupant, moved `HEAD`, foreign
  custody, or divergent source refuses before package or repository mutation.
- After the first full bootstrap but before the kernel commit, run the printed
  section-A routing restoration and rebuild the exact record-named stage.
  `HEAD` is unchanged. If candidate self-host routing-driver bytes must be
  recovered before repeating the full bootstrap, run
  `-RestoreLegacyRoutingCustody` while `HEAD` is still that exact recorded base.
- A transition identity and its self-host custody epoch are bound to the
  recorded legacy base and that worktree's Git directory. The dispatcher
  refuses a staged identity after `HEAD` moves. Any full bootstrap targeting
  the same per-worktree Git directory refuses before package or repository
  mutation when an active epoch is pending, blocked, or otherwise cannot be
  admitted as the exact recorded recovery state. That invariant also covers a
  target `HEAD` with no review-kernel surface. A complete external package
  source does not make the stale target safe because the active epoch belongs
  to the target's Git directory.
  Preserve every custody record. Either return the worktree to the recorded
  base and continue there, or use a fresh linked worktree at the intended
  legacy base as the target; only the fresh target has independent
  per-worktree Git metadata. If phase A already left the candidate routing
  drivers in their legacy or absent state, first return the candidate checkout
  to the recorded base and run `-RestoreLegacyRoutingCustody` there. That
  restore makes the checkout a complete candidate payload again. The complete
  checkout may then serve as the external package source for the fresh target:

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File <complete-candidate-checkout>\bootstrap.ps1 -TargetRepo <fresh-linked-worktree> -Force
  ```

  Follow the same bounded kernel-and-completion procedure in that fresh target.
- After the kernel reaches the target branch, the review-context core is live.
  Run `-RestoreLegacyRoutingCustody` for a self-host install, re-run the full
  bootstrap, and complete the second landing. No manual copy recipe participates
  in recovery.
- A later `-Force` re-renders project content from the retained values source;
  no prompt-section recovery or manual port participates.
- After a second-landing review failure, fix the candidate and retry through
  `REVIEW_BACKEND=both`; never return to the audited skip.

## Step 3 — verify and maintain project values

Bootstrap has already rendered the three blocks from
`CROSS-REVIEW-VALUES.md` into the installed prompt and AGENTS merge template.
Verify exact agreement without writing:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\render-project-values.ps1 -TargetRepo . -Check
```

On a fresh TRACKED install, defer this command until Step 8's bootstrap commit
has established `HEAD` and index authority for the new outputs and attribute
records. Before that commit, either the attribute graph is unstaged or the new
outputs are index-only, and standalone `-Check` refuses both indeterminate
shapes. A LOCAL install or an existing TRACKED install with an unchanged valid
attribute graph can run the command immediately.

Project hazards remain the main project-specific quality input. Use
`examples/project-hazards-example.md` as a structural example, then maintain
actual hazards in the source's `project-hazards` block. Each hazard should name
the defect class, recurring forms, a concrete diff-level red flag, and the
runtime consequence. Cite symbols or types instead of bare line numbers.
Maintain stack, dependency direction, source-of-truth documents, status terms,
and convention documents in `project-context`. Maintain only the authority
document path set, or the exact no-authority sentinel, in `scoped-authority`.

For a later TRACKED update, stage `CROSS-REVIEW-VALUES.md` first and run the
standalone renderer Apply command above without `-Check`; both rendered outputs
publish as one recoverable transaction. For a LOCAL update, edit the ignored
source and run the extracted package's full
`bootstrap.ps1 -TargetRepo . -Force`; standalone Apply refuses LOCAL authority
because only bootstrap owns
manifest and authorization publication. Re-run `-Check` after either path.
Never edit slot bodies directly and never add a runtime values lookup.

## Step 4 — merge the contract sections into your agent-instruction files

Open the installed `docs/AGENTS.md.template`. Bootstrap copied and rendered
that merge source from the package template and the retained project values;
bootstrap did not edit either root agent-instruction file.

**The two backends auto-discover different files** — you need the
contract sections in the file each backend reads, which is not the
same file for both:

- **Codex CLI** auto-loads `AGENTS.md` from the working root + ancestors.
- **Claude Code CLI** does NOT auto-load `AGENTS.md`. It auto-loads
  `CLAUDE.md` (project + walk-up) and the user-global
  `~/.claude/CLAUDE.md`.

If your project already has both files: merge the `##` sections of
`docs/AGENTS.md.template` into both `AGENTS.md` and `CLAUDE.md`, then
adjust example paths and branch names to match your project's
conventions. One rule decides what to take:

- A section naming a BACKEND applies only if you install that backend —
  `## Claude reviewer auth setup` is the case today, and a Codex-only
  install skips it.
- Every OTHER section applies. They are contracts the gate enforces or
  disciplines its findings depend on, so none is optional on the grounds
  of project size or preference.

The merge list is the template's own heading list, deliberately not an
inventory repeated here: this document previously named eight sections
while the template carried fourteen, so consumers following it omitted
every discipline added after that list was written.

If your project does NOT have either file: at minimum create
`AGENTS.md` at your repo root with the contract sections (so Codex
implementer sessions see them). Optionally also create `CLAUDE.md`
with the same sections (so Claude implementer sessions see them
too); without it, Claude relies on the user-global
`~/.claude/CLAUDE.md` for any session-wide policy.

The Claude review wrapper runs Claude Code 2.1.248 or later in restricted mode
from the isolated review root. Restricted mode confines file tools to that
root and ignores user/project/local settings files. The explicit
`--setting-sources user` selection retains trusted host user-global
instructions while excluding project/local instruction sources, so
reviewed-tree `CLAUDE.md` or `.claude/` content cannot become session
configuration. The wrapper also restricts built-in availability to
`Read,Grep,Glob`, denies MCP tools, and uses `dontAsk` so every unmatched tool
request is refused.

## Step 5 — configure Codex (if using the Codex backend)

The wrapper passes `-s read-only -c approval_policy="never"` to Codex
PER-INVOCATION. That means you do NOT need to lock down sandbox or
approval in your global `~/.codex/config.toml` — the wrapper handles
it for the review session only, and your interactive Codex sessions
keep their normal capabilities.

Minimum required `~/.codex/config.toml` contents (configure once on
the machine):

```toml
model = "gpt-5.5"
model_reasoning_effort = "xhigh"
```

(Adjust `model` / effort as needed; `gpt-5.5` is the model the gate
was tuned against, `xhigh` is the recommended effort for adversarial
review.)

Do NOT add sandbox or approval pinning here — the wrapper supplies
those per-invocation.

## Step 6 — configure Claude auth (if using the Claude backend)

Install Claude Code 2.1.248 or later. The wrapper parses `claude --version`
and fails closed before review launch when the executable is absent, older, or
does not return the supported version format.

**Default path (recommended)**: log in to Claude Code interactively
once on the machine:

```powershell
claude
```

Complete the login flow. The wrapper then picks up your credentials
via keychain on subsequent runs. No further configuration needed.

**API-key fallback (NOT recommended — significantly more expensive)**:
see the "Claude reviewer auth setup" section in
`docs/AGENTS.md.template` for the env-var and apiKeyHelper options.

## Step 7 — verify the install

Code unit tests are banned. Do not create temporary code-unit-test commits or
run a historical SelfTest command when that command executes code unit tests.
Integration, end-to-end, smoke, performance, manual, live, and other functional
testing remain permitted and important. Merge the code-unit-test-ban policy from `docs/AGENTS.md.template`
into both project `AGENTS.md` and `CLAUDE.md` so future sessions and agents
receive the same instruction.

Inspect the actual bootstrap outcome, installed paths, project values, and
reported dispatcher/manifest state. Use the production renderer's `-Check`
mode against the actual target to verify rendered values without publication:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\render-project-values.ps1 -TargetRepo . -Check
```

Investigate actual installation failures before relying on the gate. No test
suite or fabricated repository substitutes for the installed target's state.

## Step 8 — initial bootstrap commit (REQUIRED before the gate can fire)

The gate refuses to run untracked executable review infrastructure (no trusted
baseline exists). Right after bootstrap copies and renders the files into
your working tree, they are UNTRACKED — so the very first commit
that touches anything needs to bootstrap-commit the complete installed set and
the staged TRACKED values source with `CROSS_REVIEW_SKIP=1` (the documented bootstrap
escape: there is no HEAD copy of the gate to verify against yet).

**Pre-existing `PROJECT-MODE.md`**: leave the file in place. Project-mode
configuration neither authorizes the bootstrap nor changes the initial
install escape. A valid governing declaration supplies review context
after the gate becomes available; a malformed one warns and falls back to
`shipped` defaults until an ordinary reviewed edit fixes it.

Stage the components your shape actually TRACKS. This step is the TRACKED
shape's, and the bootstrap decides which shape it just installed: with every
gate component exposed it prints the exact `git add` line for that repository,
which is the line to prefer over anything written here. A layout that ignores
only SOME components gets the MIXED INSTALL SHAPE item instead — that item
names each ignored and each exposed path and gives the two ways to unify the
shape, so no bootstrap-commit command is printed for it and this step does not
apply until it is unified. A fully ignored layout is the LOCAL shape, covered
by the alternative at the end of this step.

The printed line is still not a fixed list. `.gitignore` is absent from it when
the ignore rule was routed to the git common dir's `info/exclude` instead, and
`.gitattributes` is absent when no tracked sh surface needed an LF rule; naming
an absent or ignored path makes `git add` exit nonzero before anything is
staged. The commands below show the FULL-tracked shape, abbreviated to
directory arguments; the bootstrap's own line names each component
individually, because both ignore state and tracked state are decided per file
(a tracked component under an ignored parent still belongs in the command).
Drop any path the bootstrap's line omits.

PowerShell:

```powershell
git add CROSS-REVIEW-VALUES.md scripts/codex scripts/claude scripts/git-hooks scripts/run-gate.sh scripts/render-project-values.ps1 docs/audit-protocol.md docs/AGENTS.md.template .gitignore .gitattributes
$env:CROSS_REVIEW_SKIP = '1'
try { git commit -m "cross-review-gate: install" }
finally { Remove-Item Env:CROSS_REVIEW_SKIP -ErrorAction SilentlyContinue }
```

bash / sh:

```sh
git add CROSS-REVIEW-VALUES.md scripts/codex scripts/claude scripts/git-hooks scripts/run-gate.sh scripts/render-project-values.ps1 docs/audit-protocol.md docs/AGENTS.md.template .gitignore .gitattributes
CROSS_REVIEW_SKIP=1 git commit -m "cross-review-gate: install"
```

After the TRACKED bootstrap commit succeeds, run
`scripts/render-project-values.ps1 -TargetRepo . -Check`. At that point the
source, both rendered outputs, and named attribute records have stable `HEAD`
and index authority.

After this commit lands, HEAD has the gate files and every subsequent
commit is reviewed normally (no `CROSS_REVIEW_SKIP=1` needed). The
bootstrap commit is recorded as an immutable commit in the local
`refs/crg-review-skips` audit chain. The audit commit names the exact staged
tree; compare-and-swap publication preserves concurrent skip records or fails
closed.

If you skip this step, every subsequent commit will abort with
`ERROR: in-tree gate at <path> is not tracked in HEAD` (from the
dispatcher) because there is no committed gate to verify against.

**LOCAL install shape (alternative to this step).** A project whose
scope cannot admit tooling into its history skips the bootstrap commit
entirely: list the gate paths in the repository's `info/exclude` —
resolve the real path with `git rev-parse --git-path info/exclude`,
since in a linked worktree `.git` is a file — (preferably BEFORE
running the bootstrap, so it also routes the `logs/` artifact rule to
`info/exclude` instead of the tracked `.gitignore`) so they are
untracked AND ignored, and the trust chain verifies them against the
install manifest bootstrap recorded in the per-worktree git dir instead of
HEAD (`docs/local-install-v1.md`; bootstrap also records the
local-shape authorization marker beside the manifest, listing exactly
the components it observed untracked and ignored — without that
operator-custody marker a valid manifest never admits local
authority, and a staged untracking of a gate component refuses
without the operator's CROSS_REVIEW_ALLOW_GATE_UNTRACK=1 sanction).
`CROSS-REVIEW-VALUES.md` must also remain untracked and ignored, but stays
outside the manifest and marker. A routine values update uses the package's
full `bootstrap.ps1 -TargetRepo . -Force` path, followed by renderer `-Check`;
standalone Apply refuses LOCAL authority. A hand edit to an installed
component still mismatches the manifest and refuses. `-SealManifest` is not a
routine customization step: Step 2's bounded legacy/current recovery sequence
is the only v2.1 use. The advisory author-lint pre-pass instead skips fail-open
with a WARN while the review gate still runs. `PROJECT-MODE.md`, when
declared, stays a TRACKED file in every shape.

## Step 9 — confirm the next ordinary gated change

After the trusted baseline exists (HEAD for the tracked shape or the install
manifest for the local shape), use the normal commit wrapper for the next
actual project change. Do not create a synthetic install-check file or a
throwaway commit. The wrapper directory names the author; the opposite backend
reviews. Mandatory review remains active.

Launch the direct wrapper without ambient Git history, attribute,
repository/object/ref/index, or `GIT_CONFIG*` selector variables. Presence
alone, including an empty value or mixed-case spelling, refuses before the
first Git command. Ordinary `HOME` / `XDG_CONFIG_HOME` configuration remains
supported and still participates in the effective `core.hooksPath` check.

The commit hook reviews Staged scope, which remains available in
a shallow clone. Direct `-Scope Commit` and `-Scope Branch` review, plus
`scripts/shared/auto-merge.ps1`, require complete, unshallowed repository
history. A shallow or indeterminate history check fails closed before ancestry
or range work. Run `git fetch --unshallow` (or use a full clone) before those
operations. Codex `-Scope Uncommitted` also remains available in a shallow
clone; the Claude wrapper does not support Uncommitted scope.

Use `scripts/shared/auto-merge.ps1` for new merge commands. The legacy
`scripts/codex/auto-merge.ps1` entrypoint remains a forwarding wrapper because
installed launcher ABIs require that path. The forwarding entrypoint does not
select a reviewer or change the shared implementation's review requirements.

Confirm the ordinary commit's final process exit and the gate's own PASS
outcome before reporting a successful landing. A review finding or tooling
failure remains a real outcome to resolve through the normal workflow; a
wrapper launch alone does not prove successful installation or commit.

## Declare a project mode (OPTIONAL)

A repo may declare its lifecycle phase in a root `PROJECT-MODE.md`
(grammar and semantics: the prompt template's `## Project mode`
section; full doctrine: the package's
`docs/project-mode-doctrine-v1.md`). Without one, the gate reviews
under `shipped` behavior-preservation defaults. The code unit-test ban applies in
every mode; the declaration does not create a code-unit-test-authoring exception.

The declaration is ordinary reviewed configuration. No operator-only
environment variable, declaration-only commit, parent commit, or special
activation sequence is required. The trusted declaration that PRECEDES
the change under review supplies that change's lens; a candidate edit
never governs its own diff. A declaration edit may therefore land beside
other work, with that whole change reviewed under the prior declaration
or `shipped` defaults when the prior declaration is verified absent or
positively malformed. An indeterminate repository read still fails closed.

Author and commit it through the normal gate:

```powershell
# author PROJECT-MODE.md at the repo root, then:
git add PROJECT-MODE.md
scripts/claude/commit.ps1 -m "declare project mode"   # or scripts/codex/commit.ps1
```

Review rules:

- The campaign is lifecycle context and priority, never a work allowlist.
  A change cannot fail merely because the change does not advance the
  campaign.
- Candidate declaration text is part of the ordinary diff. Grammar,
  resolvability, and instruction-like free text are reviewed there, but
  candidate text never selects the rules for that same run.
- `CROSS_REVIEW_SKIP=1` keeps the ordinary audited-skip behavior. A
  declaration has no special authorization status and adds no separate
  skip prohibition.

## Completion evidence (what the reviewer credits)

The gate weighs EXECUTION evidence, not authored artifacts — test files being
added counts for nothing by itself toward a completion claim. Every cited run
(build, ordinary operation through the launched interface, or applicable
functional-test execution) carries,
at minimum: the DATE, the COMMAND or script exercised, the OBSERVED
OUTPUT (pasted, or pointing at content the reviewer can actually read
during the review), and the REVISION the run was performed on, named as
precisely as the channel allows (HEAD's SHA before staging, the branch
tip, or the commit under review). A citation missing its metadata weighs
nothing. The channels the reviewer reads: the commit message in Commit
and Branch scope (the wrappers deliver full message bodies as a labeled
evidence channel), or an in-diff entry (a History/doc line) in
Staged/Uncommitted scope, which sees no commit log. The AGENTS.md
sections merged in Step 4 carry the full author-facing contract; this
summary exists so an operator following INSTALL alone knows what the
reviewer will credit.

## Step 10 — optional environment variables

The wrappers respect these env vars:

- `CROSS_REVIEW_ALLOW_GATE_UNTRACK` — the OPERATOR sanction for a
  change that removes a gate component from tracking (a deletion or a
  rename away from its path). Untracking is a shape transition — it
  re-arms or retires the local-authority machinery
  (`docs/local-install-v1.md`) — so the hook and the installed
  dispatcher refuse it outright, before the audited skip, and the
  merge gate refuses it over the whole base..tip range, unless this is
  set to `1` for exactly that commit or merge. A guard-bearing
  dispatcher declares the `crg-gate-untrack-guard-v1` capability;
  marker publication refuses to arm the local shape beside a
  dispatcher missing the capability — the dispatcher install and the
  arming transaction run under the repo's install locks (the shared
  dispatcher's own lock is keyed to the git COMMON dir, covering
  every linked worktree), and each arming path (the seal included)
  validates the installed dispatcher through a handle held until the
  marker lands (see `docs/local-install-v1.md`).
  This remains an operator act by design — agents must never set it.

- `CROSS_REVIEW_ALLOW_SEAL` — the OPERATOR sanction for
  `bootstrap.ps1 -SealManifest` in the exact legacy or current-v2.1 LOCAL
  recovery shapes defined by `docs/install-values-v1.md`. The seal mints a
  trusted replacement baseline from inspected installed bytes; the subsequent
  full `-Force` run still performs rendering and ordinary publication. Without
  the sanction the seal refuses. Set the value to `1` for exactly that recovery
  run and remove the value afterward. This remains an operator act by design —
  an agent must never set the sanction.

- `CROSS_REVIEW_PRUNE_TOOL` — path to a custom delete tool used for
  auto-pruning old review log files. Receives file paths as positional
  arguments. If unset, the wrappers fall back to `Remove-Item -Force`.
  If SET but the path does not exist, auto-prune is SKIPPED for that
  run with a WARN line (instead of silently falling back to direct
  deletion, which would defeat the audit policy the variable exists
  to enforce). Set this if your project has its own safe-delete script
  (e.g., one that routes through the Recycle Bin):
  ```powershell
  $env:CROSS_REVIEW_PRUNE_TOOL = 'C:\path\to\safe-delete.sh'
  ```

- `CROSS_REVIEW_CONSISTENCY_DOC` — OPT-IN. Repo-relative path of a
  planning/spec doc (e.g. `PLAN.md`) to enable the consistency precheck
  (milestone cross-reference / range-vs-item-set / missing-field) on that
  doc. DEFAULT OFF: when unset, NO special-casing runs — the codex wrapper
  writes a `PLAN-CONSISTENCY-STATE: v1 skipped-not-configured` envelope into
  `PLAN-CONSISTENCY.txt`, the merge gate imposes no doc-based backend routing,
  and the Claude wrapper reviews planning-doc edits normally. Every envelope
  begins with exactly one byte-zero `PLAN-CONSISTENCY-STATE: v1 <state>` line,
  where the finite states are `produced`, `skipped-not-configured`,
  `skipped-not-in-diff`, and `indeterminate`, and ends with
  `PLAN-CONSISTENCY-END: v1`. In a well-formed `produced` envelope,
  `PLAN-CONSISTENCY-FINDING:` rows are documentary `QUALITY:` findings under
  `PLAN-DRIFT`; both valid skip states are non-findings. When the configured
  document is in the reviewed diff, indeterminate, absent, unreadable,
  malformed, or unterminated report evidence is a fail-closed
  `BLOCKER:` under `SILENT-FAILURE`. Independent planning blockers retain
  BLOCKER severity. When SET, the following behaviors
  activate together: (1) the codex `auto-review.ps1` runs `Get-PlanConsistencyReport`
  against the doc whenever it is in the reviewed diff; (2) `auto-merge.ps1`
  REFUSES `-Backend claude` for any branch whose diff touches the doc
  (because the Claude wrapper has not ported the precompute; the refusal
  names `-Backend codex` as the remedy); (3) the claude `auto-review.ps1`
  FAILS CLOSED (exit 3) when the doc is in the changed-path set, routing
  those edits to the Codex backend. The
  automatic availability routing honors the same contract: an alternate
  route to the Claude wrapper (commit gate and merge gate alike) is REFUSED
  when the change touches the doc, so the gate fails closed without burning
  an ineligible attempt. Set it with:
  ```powershell
  $env:CROSS_REVIEW_CONSISTENCY_DOC = 'PLAN.md'
  ```
  The value is normalized before use: surrounding whitespace is trimmed,
  backslashes become `/`, and `.`/redundant-separator segments are collapsed
  to the canonical git path form, so `'PLAN.md '`, `'docs\PLAN.md'`, and
  `'./PLAN.md'` all work. A value that is SET but INVALID — empty /
  whitespace-only, an absolute path, one containing a `..` escape, one containing
  an internal control character, DEL, or a double quote (spellings Git would
  C-quote), or one that does not resolve to a tracked FILE (a git blob) in the
  reviewed tree (a typo, a directory, or any non-blob object) — is a broken gate
  config and FAILS
  CLOSED: the review wrappers exit 3 and the merge gate aborts, with a
  diagnostic, rather than silently disabling the gate. Only an UNSET variable
  means "off".

- `CROSS_REVIEW_PASSES` — number of INDEPENDENT review passes for the
  CODEX backend (a coverage knob; the gate blocks on the union of all
  passes). Read by `scripts/codex/auto-review.ps1` ONLY — the Claude
  wrapper always runs a single pass and ignores this var. Clamped to 1-10.
  UNSET defaults to a single pass; in the codex wrapper a value that is SET
  but not a valid integer FAILS CLOSED (exit 3) rather than silently running
  one pass. An explicit `-ReviewPasses` always wins over this var — the merge
  gate (`auto-merge.ps1`) sets its own count: the full planned coverage on
  the provider its required `-Backend` names (the codex wrapper carries
  the whole count itself; a claude panel spreads it across tagged
  single-pass children).

- `CROSS_REVIEW_COMMIT_EFFORT` — codex reasoning-effort tier for the
  commit gate (`minimal|low|medium|high|xhigh|max`, case-insensitive; codex
  backend only — the Claude wrapper has no effort knob). UNSET inherits
  `~/.codex/config.toml`. A value that is SET but invalid is an
  invocation/config error that ABORTS the commit (not a review finding).
  The `max` tier is COMMIT-GATE vocabulary only: the merge gate's own
  effort resolution deliberately treats `max` as `unknown` (do-not-pin)
  until the capability-probe task in `docs/known-debt.md` lands, since it
  forwards the resolved tier to a base-extracted wrapper that may predate
  the tier.

- `CROSS_REVIEW_STALL_WARN_SECS` — the reviewer-liveness stall threshold
  (default 300; integer seconds, 30..86400). Heartbeat lines sample
  evidence files that grow only under real reviewer work (codex per-pass
  events; the claude activity stream) PER FILE and escalate to a
  self-clearing `STALL-SUSPECT` warning after this much quiet on a file
  whose pass is still active — warn only, the review is never killed.
  Samples and escalation transitions are recorded, timestamped, to a
  run-owned `review-*.liveness.jsonl` preserved with the run's
  forensics — best-effort with loud failure reporting: a denied append
  retries briefly then warns, and a preservation failure warns, never
  silently. A value that is SET but invalid ABORTS the review as an
  invocation/config error (fail closed, like the other knobs).

- `CLAUDE_REVIEW_SETTINGS` — default path to a Claude Code settings
  JSON file. Primarily used for API-key auth via `apiKeyHelper`.

- `CROSS_REVIEW_SKIP=1` — bypass the gate for a single commit. Recorded
  in the local `refs/crg-review-skips` immutable commit chain, with the exact
  staged tree in both the audit commit tree and its canonical message. Use only
  for the narrow bootstrap, HEAD-wrapper-broken repair, and identity-record-
  attested pre-redesign review-kernel transition cases documented in the
  AGENTS.md template and this guide.

- `CROSS_REVIEW_SKIP_AUTHOR_LINT=1` — skip ONLY the mechanical author-lint
  pre-pass (the fast line-anchor / dead-ref / magnitude checks the pre-commit
  hook runs before the AI review); the AI review still runs. Unlike
  `CROSS_REVIEW_SKIP`, it does NOT bypass the adversarial gate — use it only
  for an author-lint FALSE POSITIVE, where the AI gate remains authoritative.

- `REVIEW_BACKEND` — REQUIRED for every commit. Valid values:
  `codex`, `claude`, or `both`. The pre-commit hook REJECTS bare
  `git commit` when this is unset (no implicit default; an unset
  value cannot silently route to self-review). The commit wrappers
  (`scripts/{codex,claude}/commit.ps1`) set this for you; you only
  need to set it manually if you're invoking `git commit` directly.
  This value selects the preferred reviewer, not a provider-availability
  policy. Positively identified exhaustion is handled once per logical leg
  inside the gate, within the current invocation; successful caller output remains
  provider-neutral, no environment state persists, and no provider-skip
  switch is part of the interface.

## Legacy-index seal (capture doctrine v6) — REQUIRED before pruning resumes

Under capture doctrine v6 the follow-up index (`logs/review-followups.md`)
records every append as a bracketed, digest-vouched transaction. Content
written BEFORE v6 — the "legacy region" at the top of an existing index —
cannot be verified retroactively, so on an install whose index carries such
a region the review-log auto-prune is QUARANTINED: nothing is deleted until
an operator inspects that region and seals it. A fresh install (index
created under v6) has no legacy region and needs no seal.

To seal, inspect the legacy region by hand — everything above the REGION
START: the first `<!-- review-followups: transaction v1 OPEN -->` line or,
when it comes earlier, the first
`<!-- review-followups: capture-doctrine v6 BEGIN -->` line of a
byte-valid current frame; the ENTIRE file when neither exists yet (a
not-yet-migrated index, the primary upgrade path) — then capture its byte
length and SHA-256 and run the seal mode with those values:

```powershell
# from the repo root; derive <len> (the region start's byte offset), e.g.
# in git bash — grep -b prints each marker line's byte offset; take the
# SMALLER of the two, and a file printing neither uses its full length:
#   grep -a -b -m 1 -x -F '<!-- review-followups: transaction v1 OPEN -->' logs/review-followups.md | cut -d: -f1
#   grep -a -b -m 1 -x -F '<!-- review-followups: capture-doctrine v6 BEGIN -->' logs/review-followups.md | cut -d: -f1
#   wc -c < logs/review-followups.md          # when neither grep printed
# then hash exactly those bytes:
#   head -c <len> logs/review-followups.md | sha256sum
# (A BEGIN line whose frame is not byte-valid does not start the region;
# if the operation refuses with a mismatch, re-inspect against the
# refusal's measured values.)
scripts/codex/auto-review.ps1 -Scope SealLegacy `
  -SealExpectedBytes '<len>' -SealExpectedSha '<sha256>'
```

The operation recomputes both under the writer lock and REFUSES on any
mismatch (a write landed after the inspection — re-inspect and re-run), on
a damaged tail (repair it by hand first), and when there is nothing to
seal. On success it appends a seal transaction, writes a `seal-*`
provenance record beside the verdict logs, and the legacy QUARANTINE lifts
for as long as the legacy bytes keep matching the seal — the prune's other
guards (unresolved capture claims, doctrine-state checks) still apply, and
a later edit to the legacy region makes the seal inert and the quarantine
returns.

The v6 verification also requires a SHA-256 utility on the pre-commit
hook's PATH (`sha256sum`, shipped with Git for Windows, or `shasum`). On
a host without one, staged follow-ups
are DROPPED with a warning rather than appended unverified — permanently,
not transiently — so treat the utility as a production dependency of
the gate.

## Step 11 — generate a trend report (after some review history exists)

After accumulating a few weeks of review verdicts in `logs/codex/reviews/`
and/or `logs/claude/reviews/`, generate the trend report:

```powershell
powershell scripts\shared\analyze-blocker-trends.ps1 -SinceDays 30 -OutPath docs/blocker-trends.md
```

The default scans BOTH backend log directories so the report aggregates
findings across both reviewers (a single-backend install works too —
missing directories are skipped). To slice per-backend, pass an explicit
single `-ReviewsDir` (e.g. `-ReviewsDir logs/codex/reviews`).

The report clusters recurring BLOCKER archetypes — use it to identify defect
patterns worth adding to the `project-hazards` block in
`CROSS-REVIEW-VALUES.md` (see Step 3). The audit protocol at
`docs/audit-protocol.md` describes the full feedback-loop discipline.

## Troubleshooting

**`[pre-commit] ERROR: REVIEW_BACKEND='...' is not valid`** — you set
`REVIEW_BACKEND` to something other than `codex`, `claude`, or
`both`. Unset it or fix the value.

**`[auto-review:claude] ERROR: Claude is not authenticated`** —
keychain has no valid credentials. Run interactive `claude` once,
complete login, retry. Or set up an API-key fallback per the AGENTS.md
template.

**`[auto-review] ERROR: codex invocation exited with N`** — check
the stderr file mentioned in the wrapper output. Common causes:
Codex not on PATH, `~/.codex/config.toml` missing or malformed, model
name unknown.

**`[pre-commit] ERROR: commit-wrapper script has unstaged changes`** —
you edited `scripts/codex/commit.ps1` or `scripts/claude/commit.ps1`
but didn't stage the change. Stage it (or revert it) and retry; the
hook refuses unstaged wrapper changes so the working-tree version
cannot diverge from the committed version (which would subvert
cross-review).

**The consistency-doc fail-closed error** — this fires ONLY when you
have opted in by setting `$env:CROSS_REVIEW_CONSISTENCY_DOC` to a doc
name (e.g. `PLAN.md`). When set, the Claude wrapper fails closed if
that doc is in the staged changeset, because the
`Get-PlanConsistencyReport` precompute is not ported to the Claude
backend; route those edits through the Codex backend
(`REVIEW_BACKEND=codex`), which runs the precompute. A FRESH install
(env var unset) has NO such gate — the Claude backend reviews planning
docs normally. To enable the precheck for a milestone document, set
the env var to its repo-relative path (see "Optional" in README and
the env-var list above). A SEPARATE fail-closed cause: if the configured
`$env:CROSS_REVIEW_CONSISTENCY_DOC` does not resolve to a tracked FILE (a git
blob) in the reviewed tree — a typo, a directory, an absolute / `..`-escaping
path, a path containing an internal control character, DEL, or a double quote,
or any non-blob object — ALL wrappers and the merge gate exit 3 with a
diagnostic (a broken gate config must not silently disable the check); fix the
value or unset it.

**A commit landed without a review firing** — `git rebase --continue` and
`git revert` do NOT fire the pre-commit hook — only a direct `git commit`
does. For rebased landings, `git checkout <sha> -- <files>` then a direct
`git commit`. `git merge --ff-only` creates no commit, so it does not fire the
pre-commit hook — but base-branch landings still require the merge gate via
`scripts/shared/auto-merge.ps1`. The sole exception is the identity-record-
attested pre-redesign review-kernel promotion described in “Upgrade a TRACKED
pre-redesign project-mode install,” when the old merge gate cannot admit its
own replacement. That exception covers only the exact kernel commit; the
completion branch still lands through `auto-merge.ps1`.

**`Commit and Branch review require a complete repository history` or
`the repository is shallow`** — Commit/Branch evidence and merge-base/range
landing proofs require unshallowed ancestry. Run `git fetch --unshallow`, or
repeat the operation from a full clone. Staged review remains usable on both
backends; Codex Uncommitted review remains usable too.
