# Local-install shape v1 — untracked gate consumption

Operator ruling 2026-08-26: the gate is tooling for building a project
with an LLM, not part of the project. Tracking the gate files in the
consuming repo is PREFERRED where the project allows it, but some
projects cannot admit out-of-scope content into their history, and the
gate must support that deployment without local forks. This document
is the NORMATIVE definition of the shipped support (the same slice
carries the implementation); its text was authored ahead of the implementing code
inside a single slice — the operator's 2026-08-26 direction ran the
design and implementation without an intervening review round, a
sanctioned departure from the separate-design-round default — and the
implementing code cites it per stage.

The ruling was proven urgent the day it was made: a consuming robotics
project ran the gate as untracked local files behind hand-modified
copies of the dispatcher and hook, and a package refresh overwrote
those modifications with no backup — the modified files were
unrecoverable. The fork's necessity and the refresh's data loss are
each closed here.

## 1. Install shapes

- **Tracked install** (preferred): every gate file is
  committed in the consuming repo. HEAD is the trusted baseline; the
  dispatcher evaluates an exact, OID-verified buffer captured from
  HEAD's hook, the hook runs HEAD's wrappers when infra is staged, and
  project-mode configuration resolves from the
  trusted declaration preceding the reviewed change. Nothing in this
  document alters the tracked shape's REVIEW behavior; the refresh
  backups of §4 apply to every shape, and every occupied destination enters
  custody before baseline classification and replacement.
- **Local install** (shipped): the gate files sit in the working tree,
  UNTRACKED and deliberately IGNORED (via `.gitignore` or
  the repository's `info/exclude`, whose real path is
  `git rev-parse --git-path info/exclude` — `.git/info/exclude` in a
  plain checkout, the shared common dir's file in a linked worktree,
  where `.git` is a file). HEAD carries no baseline, so the trusted
  baseline is the INSTALL MANIFEST of §2 — machine state under
  `.git/`, in the same custody class as the per-clone dispatcher: a
  commit cannot alter it, and only the operator's own bootstrap run
  writes it.

`docs/install-values-v1.md` adds one project-owned input without making that
input a gate component: root `CROSS-REVIEW-VALUES.md` must have TRACKED index
authority for a uniformly TRACKED render surface, or positive untracked-and-
ignored LOCAL authority for a uniformly LOCAL render surface. The source never
enters this document's manifest or authorization marker. The installed prompt
and `docs/AGENTS.md.template` remain ordinary gate components whose exact
rendered bytes do enter both metadata records in the LOCAL shape. A mixed
TRACKED/LOCAL render surface refuses rather than falling back between families.

The discriminator is always "untracked AND ignored" together, and it
is decided PER FILE: every stage's local branch is taken component by
component, so a hybrid layout (some gate files tracked, some ignored)
resolves each component against its own baseline — tracked against
HEAD, ignored against the manifest — and commits succeed when every
component has one. The uniform shapes above are the SUPPORTED
configurations (a hybrid splits the maintenance surface across tracked landing
and manifest-refresh duties, and the install checklist flags it
loudly for unification), but a hybrid is not a trust hole: no
component ever runs unverified. A gate file that is untracked but NOT
ignored is an accidental drop in every shape and keeps today's
refusal. The ignore state is a ROUTING
discriminator, not a trust anchor: ignore rules may live in the
tracked `.gitignore`, which a candidate can reach — which is exactly
why LOCAL authority additionally requires the operator-custody
AUTHORIZATION MARKER (§2). The manifest hash-pin decides which BYTES
are trusted; the marker decides that local authority was
operator-declared at all. The strongest an ignore-rule flip plus an
untracking commit can achieve without the marker is a fail-closed
refusal over byte-identical, operator-installed files.

## 2. The install manifest

Written by `bootstrap.ps1` on every full install (the
self-install included) to
`<git-dir>/crg-install-manifest` — the PER-WORKTREE git dir
(`git rev-parse --absolute-git-dir`; `.git/worktrees/<name>` in a
linked worktree), NOT the common dir: the verified gate files are
worktree-local, so a shared manifest would let one worktree's recovery seal
or refresh silently invalidate every sibling worktree's baseline.
Each worktree that runs the local shape gets its own bootstrap run
and any required recovery seal; the backup area (§4) stays in the common dir, since
recovery copies are safe to share and every backup path is
collision-checked. There is NO legacy-location migration and NO
compatibility read: pre-release revisions of this development line
briefly placed the manifest in the common dir, but at the 2026-08-27
operator audit no released package or deployed install had written one and
every existing consumer predated manifests. No released common-dir field state
therefore existed to migrate. A migration was tried and
reverted the same day: in the main worktree the git dir IS the common
dir, so a current main-worktree manifest is indistinguishable from a
"legacy" shared one, and any migration therefore silently seeds
sibling worktrees' trust baselines forever — defeating the isolation
this location provides. A worktree without a private manifest gets a
full bootstrap run, the standard install path. Format, line-oriented
LF text:

```
crg-install-manifest v2
installed: <UTC timestamp>
<sha256-hex>  <repo-relative-path>
...a line per installed in-tree gate file...
```

Each `<sha256-hex>` is the digest of the INSTALLED file as it sits in the
repository — the artifact every verifier hashes when it asks whether a gate
file is still the one that was installed.

Manifest headers `v1` and `v2` are accepted, and entries under either describe
the same artifact: exact installed-file bytes. `v1` is the pre-stamp manifest
format used during prerelease P9 development; it is not the package v1.7
release format. Released v1.7 wrote no manifest and is recognized separately
from its frozen installed-file inventory. Current writers emit manifest `v2`.
On an ordinary copy install, bootstrap stamps provenance into each destination
before hashing that installed result. On a self-install, package source and
target are the same files, so bootstrap deliberately copies and stamps nothing
and hashes the tracked source bytes already present while still emitting a `v2`
manifest. The manifest header is therefore a record-format/writer-era marker,
not a package-version label or a universal claim that every listed file carries
a provenance stamp. Readers accept either header and always verify the file on
disk.

**Install-version record.** Every successful full install also publishes
`<git-dir>/crg-install-version` in the same per-worktree custody:

```
crg-install-version v1
version: <SemVer from VERSION>
source-commit: <canonical Git object ID or unknown>
installed: <UTC timestamp>
```

The record is printable-ASCII/LF-only and strict whole-file. The package
version is read once from the package-root `VERSION` file before repository
mutation; source provenance is resolved from the package repository itself,
never by walking upward into a consuming repository that happens to contain an
extracted package. Only a valid record naming the current package version
proves a same-version refresh. A valid different version is an upgrade. When a
complete current or recognized frozen legacy inventory exists, an absent, malformed, or
non-file version record is also treated as upgrade evidence rather than as
permission to overwrite unknown bytes. Released v1.7 has that absent-record
shape by design. An ordinary `-Force` collision with neither install metadata
nor a recognized complete inventory remains ordinary replacement handling,
not an inferred historical install.

**Local-shape authorization.** The manifest alone never admits local
authority: every full install writes one (the tracked shape uses it
for refresh-drift reporting), so a candidate commit could
`git rm --cached` the gate files and add tracked ignore rules to
satisfy untracked+ignored+manifest-match with no operator act. Local
admission therefore additionally requires the marker file
`<git-dir>/crg-local-install` beside the per-worktree manifest, an
LF-terminated record in the same byte domain as the manifest:

```
crg-local-install-authorization v1
manifest-sha256: <sha256-hex of the manifest's exact bytes>
<repo-relative-path>
...one line per authorized local component...
```

The second line EPOCH-BINDS the authorization to the manifest it was
minted with: any later install or recovery seal republishes the manifest, so
a marker from an earlier local epoch stops matching and cannot be
replayed against a new baseline. The remaining lines are the
AUTHORIZED PATH SET — issuance is PER COMPONENT, so a hybrid layout
(§1) authorizes exactly the components bootstrap observed untracked
and ignored, and a reader admits a path only when the marker lists
it. bootstrap — the full install and `-SealManifest` alike — writes
the marker from its per-component observation (the operator's
standing declaration, made before the run); a FAILED probe refuses
the whole decision and aborts, never revokes — a transient git
failure must not strip a valid install of its authorization — and a
run observing ZERO local components publishes the durable revoked
fixed-name record every reader refuses, whether the prior marker was
present or absent. The authority name is never deleted or left vacant.
Every local-branch reader verifies the marker byte-exactly — digest
and path membership included — and treats absence or any mismatch as
no-local-shape, failing closed.

The remaining replay window — re-tracking the gate files without a
bootstrap run and later untracking them unchanged, leaving a dormant
marker that still matches its manifest — is closed at every landing
gateway: the hook AND the installed dispatcher each refuse a staged
change that REMOVES any gate component from tracking (a deletion or a
rename away), ahead of their own exit paths and BEFORE the audited
skip, and the merge gate refuses the same removal over the whole
base..tip range (commits created without the hook — a rebase
continuation, low-level commit creation, another clone — land only
through it). Each guard fails closed on a failed probe of its own
surface — the staged state at the hook and dispatcher, the base..tip
range at the merge gate — and lifts only for the operator's
`CROSS_REVIEW_ALLOW_GATE_UNTRACK=1`,
set for exactly that commit or merge. The guard-bearing dispatcher
declares the `crg-gate-untrack-guard-v1` capability. A pre-guard
dispatcher — which honors the audited skip before the tracked hook
runs — cannot arm local trust; `-DispatcherOnly` upgrades the
dispatcher before bootstrap publishes a local authorization marker.
That closes every locally authorized install and (via the range guard)
every merge landing. The surface new code cannot reach retroactively —
a pre-guard
dispatcher's own audited-skip exit on a DIRECT, ungoverned commit —
is closed at the ARMING step instead of by any deployment claim: the
skip exit only matters where local trust is armed, local trust is
armed only by marker publication, and every arming code path fails
closed unless the ON-DISK dispatcher carries the generic gate-untracking
guard marker and no retired project-mode enforcement signature. The inert
project-mode compatibility token is neither required nor consumed by this
decision. Bootstrap installs the dispatcher and runs the arming transaction
under the install locks of §2 (the shared dispatcher's own lock is
keyed to the git COMMON dir, so sibling worktrees serialize too),
and each arming path validates the installed dispatcher through a
handle that denies writes, deletion, and renames, held from the
validation until the marker lands (`-SealManifest` included) — so no
code path, no crash window, and no concurrent writer ever arms a
marker beside a pre-guard dispatcher. What remains
for a host running only outdated hook code is the boundary every
hook-based gate shares: a direct, ungoverned commit there is the
same act as `--no-verify`, and where no marker is armed the readers
already treat the repo as having no local shape at all. The seal is
gated the same way:
Within the exact recovery eligibility contract, `-SealManifest` mints local
trust from the installed bytes and
refuses without the operator's `CROSS_REVIEW_ALLOW_SEAL=1` — an
author agent must not be able to stub a component and bless the
replacement.

The digest is SHA-256 over the installed file's exact bytes. On the ordinary
copy path, the digest is taken after copy and provenance stamping have verified
the expected result. A self-install skips that rewrite and hashes the package's
existing source bytes instead. For a render-bearing destination, the digest
covers the final stamped and rendered installed bytes, never the raw package
template or `CROSS-REVIEW-VALUES.md`. The grammar is LF-only and STRICT
whole-file, enforced identically by every reader in every runtime (sh
and PowerShell alike): any CR byte anywhere, an unknown leading version line,
a missing or malformed `installed:` record (its value is exactly the
writer's UTC form `YYYY-MM-DDTHH:MM:SSZ` with calendar-plausible
fields — month 01–12, day 01–31, hour 00–23, minute and second
00–59 — enforced identically by every reader), an entry line that is not exactly
`<64-hex><two spaces><path>` (path non-empty, not starting with a
space), or a duplicate path treats the manifest as ABSENT (into the
refusal paths below) rather than parsing by guess — a tolerant reader
at one stage would accept a manifest a stricter stage later refuses,
splitting one trust decision in two. Paths compare BYTE-EXACT
(case-sensitive) in every runtime: a case-variant pair is two distinct
entries, never a duplicate — the PowerShell readers use ordinal
string equality and an ordinal hashtable comparer throughout,
precisely because the language defaults (a case-folding hashtable;
culture-sensitive `-ceq`, which ignores characters like U+00AD)
would each accept manifests the sh readers refuse. The byte DOMAIN of
the whole file is printable ASCII (0x20–0x7E) plus the LF record
separator, checked on raw bytes before any decode in every runtime: an
out-of-domain byte anywhere reads the manifest as absent. That rule is
what makes the runtimes comparable at all — PowerShell's UTF-8
decode substitutes U+FFFD for invalid sequences, which would collapse
distinct invalid byte paths into one string while the raw-byte sh
readers keep them distinct. Only IN-TREE gate files get entries: the
dispatcher needs none, because the dispatcher IS a verifier and already
sits in `.git` custody. Bootstrap records a separate per-clone dispatcher
digest. `scripts/run-gate.sh` and both commit wrappers require the ordinary
default dispatcher, the generic gate-untracking marker, and that adjacent
bootstrap-written digest attestation to match before `git commit`; missing,
foreign, disarmed, or tampered dispatcher state refuses. These checks are
detective install-integrity guards; the dispatcher's own chain remains the
enforcement boundary after Git opens it. `-DispatcherOnly` therefore
touches no manifest (its restore scenario has no safe basis to derive
one); a local-shape install always begins with a full bootstrap run,
and PER WORKTREE: a fresh linked worktree that will run the local
shape needs its own full bootstrap into that worktree — its manifest
lives in its own git dir, so `-DispatcherOnly` (or a sibling's
install) never satisfies it, and until that run its commits refuse
fail-closed.

**Rendered project values and recovery sealing.** A LOCAL
`CROSS-REVIEW-VALUES.md` is untracked and positively ignored but remains
project-owned and outside the manifest and authorization marker. Bootstrap
retains that source, renders the prompt and AGENTS merge template through the
shared core, validates every final output before target mutation, then hashes
the exact rendered installed bytes into the manifest. Hook, review, and merge
paths never consult the values source at runtime.

A routine LOCAL values update runs the full package
`bootstrap.ps1 -TargetRepo <root> -Force` transaction and then renderer
`-Check`; standalone renderer Apply refuses LOCAL authority because no
standalone path owns manifest and marker publication. Direct slot-body edits
remain ordinary installed-file drift and refuse verification.
`-SealManifest` is solely an operator-sanctioned recovery step for the exact
frozen-v1.7, frozen-v2.0, or current-v2.1 shapes defined by
`docs/install-values-v1.md`. Current-v2.1 sealing requires a valid LOCAL source
and successful shared-core render; the bounded recovery arm may seal held bytes
that differ from the candidate only as the trusted replacement baseline for an
immediately following full `-Force` run. An arbitrary partial or mixed
inventory refuses. Manifest publication
is VERIFIED-THEN-IDENTITY-BOUND under WRITE EXCLUSION: every listed gate file
is opened no-follow as one ordinary single-link object and held by a
read handle that denies writers, renames, and deletion from before
verification through authorization-marker commit. The installed
dispatcher is validated and retained under the same object-shape and
sharing rules. Each digest is therefore bound to the exact held bytes
that remain live when LOCAL authority commits. The manifest record
stages under a create-new, no-follow handle and is parsed and verified
through that handle. At transaction entry, an existing manifest is
classified once as a held ordinary single-link record, positive
absence, or a foreign/unowned occupant; later publication cannot
reclassify or adopt a new pathname occupant.

Before the manifest namespace moves, the marker transaction establishes
a fail-closed reservation at the fixed `crg-local-install` name. For
positive prior absence, a create-new, no-follow stage containing the
planned final marker with a deliberately invalid first byte moves to
the fixed name without replacement. For a held prior marker, the exact
prior bytes first enter a held create-new recovery object; the fixed
held marker object is then rewritten in place to the invalid planned
record. The fixed marker name therefore never becomes vacant beside a
live manifest. A foreign marker occupant aborts before manifest
publication.

Under that invalid reservation, a held prior manifest moves through its
own handle, without replacement, to a create-new supersession name. The
held manifest stage then moves through its own handle, again without
replacement, to the final name. Interruption before that move leaves the
final name absent and the exact prior record recoverable; interruption
afterward leaves the new manifest beside an invalid marker. A process
that wins the manifest final name is preserved and turns publication
into a loud fail-closed result rather than being overwritten.

Final marker publication revalidates the held manifest, every installed
payload object, the dispatcher object, and all single-link constraints.
The complete marker body is already durable while its first byte is
invalid. One byte commits the valid header last through the same fixed-name
handle, followed by a durable flush and exact readback. Process
termination before that commit leaves an invalid marker; termination
after that commit is the completed metadata commit point. A zero-local-component
transaction publishes the durable revoked marker instead of
creating a vacant authority name.

Rollback runs in the reverse authority order. The fixed marker is first
rewritten and proven invalid; the exact new manifest is then deleted
through its retained handle; the prior manifest is restored while the
marker remains invalid; and the exact prior marker bytes commit last
through the fixed reservation handle only after that exact held prior
manifest has been restored. Positive prior-manifest absence leaves the
fixed marker invalid and preserves prior-marker recovery bytes, because
absence cannot exclude a foreign manifest winner. Any missing owner, unexpected
hard link, foreign winner, byte mismatch, or failed exact restoration
suppresses the remaining restoration and preserves recovery objects for
fail-closed hand repair. No pathname hash or released read authorizes
destructive rollback. Drift after the retained handles release is
ordinary live state and is refused by consumers on the next
verification.

The transaction additionally runs under interprocess
locks split the way the state itself is split (exclusivity comes
from each held handle, so the persistent lock files need no
deletion): the per-worktree `<git-dir>/crg-install-lock` serializes
each worktree's own manifest-plus-marker baseline, and the
common-dir `<git-common-dir>/crg-dispatcher-lock` serializes every
mutation and every arming validation of the dispatcher — which
every linked worktree of a repo shares at the common hooks path, so
a per-worktree lock alone could never serialize it. Bootstrap
acquires the dispatcher lock BEFORE any dispatcher mutation and
holds it through the transaction in every operation that touches the
dispatcher — full installs, `-DispatcherOnly` refreshes, and seals
alike — and an operation that also publishes a baseline takes its
worktree's install lock after it, in that fixed order
(`-DispatcherOnly` publishes none and takes the dispatcher lock
alone). The locks serialize cooperating bootstrap runs; retained
object handles and no-replace publication preserve foreign namespace
occupants from non-cooperating writers.

Standalone renderer Apply and `-Check` take only the per-worktree install lock;
Apply owns the fixed `<git-dir>/crg-render-project-values-transaction` record
and its recovery, while `-Check` writes nothing and refuses any state occupant.
After acquiring the install lock, every full bootstrap, refresh, upgrade, and
seal classifies that fixed name before mutation and refuses any occupant with a
direction to run standalone TRACKED Apply recovery. Such bootstrap operations
never adopt or delete renderer state. `-DispatcherOnly` remains exempt because
no per-worktree render or install state changes.

Bootstrap's retained rooted-namespace registry grades an operation against the
most-specific registered path, including an exact path match, before resolving
the parent handle used for relative I/O. A read-only result explicitly denies
creation, writing, replacement, rename, or deletion; a writable ancestor is
never an alternate mutation authority for that name. Read operations retain
read-only resolution. Private Git proof construction creates each fixed work
file under mutation authority, changes the work root to read-only through
same-identity retained-handle handoff before Git runs, and returns through the
same identity-checked handoff to mutation-and-delete custody only after Git has
finished and before exact cleanup.

**Trust argument.** The tracked shape's guarantee is not "the operator
cannot tamper" — the whole gate is operator-custody machine state, and
the doctrine already concedes that boundary. Its guarantee is that a
CANDIDATE (a staged change, a worker's edit) cannot swap the gate out
from under the review that judges it, because the executed copies come
from HEAD. The manifest and the authorization marker give the local
shape the same guarantee
through the same custody boundary: the verified copies must hash to
what the operator's bootstrap installed, the manifest and marker live
under `.git/` where no commit reaches — so a candidate that untracks
and ignores the gate files buys only a fail-closed refusal, never a
shape transition — and a working-tree edit to any gate
file — staged or not — mismatches and refuses WHEREVER A TRUSTED
COMPONENT CONSUMES THOSE BYTES: the dispatcher's verified-buffer
evaluation, the hook's snapshots, the wrappers' trusted snapshot
consumption, and the merge
gate's extraction. Directly invoking a working-tree program (a commit
wrapper, the merge gate itself) is operator custody in EVERY shape —
the tracked shape equally executes its working-tree wrappers, with
the same detective guard in the hook and the same operator boundary
the doctrine already concedes — so the local shape neither adds nor
removes that surface. What the local shape
gives up is history: no commit records which gate version reviewed
which change. That loss is real, disclosed here, and bounded by the
verdict artifacts, which stamp their producing wrapper's identity
headers per run.

### LOCAL verifier diagnostics

The tracked hook and installed dispatcher report existing LOCAL verification
failures on stderr as `[CRG-LOCAL:CODE] <component>: <cause and remedy>`.
The code vocabulary is stable across both shell surfaces; helper boundaries
and detailed messages need not be identical. Successful digest and payload
stdout remain unchanged.

| Code | Cause | Operator action |
|---|---|---|
| `TRACKED-STATE` | The selected index/tree cannot be inspected, or the component is tracked rather than LOCAL. | Restore Git metadata access for a failed probe; use the reviewed TRACKED workflow for an established tracked component. |
| `IGNORE-STATE` | The component is not ignored, or effective-ignore inspection failed. | Configure the intended LOCAL excludes or use the TRACKED workflow; restore ignore-file/Git access for a failed probe. |
| `MANIFEST-READ` | The per-worktree manifest cannot be located, captured, read, or parsed by the available utility. | Restore metadata/snapshot access and shell utilities; a missing manifest requires the full package bootstrap for this worktree. |
| `MANIFEST-GRAMMAR` | Existing manifest byte or record checks reject the manifest. | Restore the manifest through the full package bootstrap. |
| `MANIFEST-ENTRY` | The otherwise accepted manifest supplies no entry for the component. | Run the full package bootstrap for this worktree. |
| `AUTH-READ` | The LOCAL authorization marker cannot be captured/read, or parser execution fails. | Restore metadata/snapshot access and shell utilities; a missing marker requires the full package bootstrap. |
| `AUTH-GRAMMAR` | Existing marker byte or record checks reject the authorization marker. | Restore LOCAL metadata through the full package bootstrap. |
| `AUTH-HASH` | The manifest digest cannot be computed, or a syntactically valid marker digest differs from the manifest snapshot. | Restore snapshot access and a supported SHA-256 utility for a failed hash; restore matching LOCAL metadata through the full package bootstrap for a mismatch. |
| `AUTH-PATH` | The matching-epoch authorization marker does not list the component. | Run the full package bootstrap with the intended LOCAL configuration. |
| `SNAPSHOT-CREATE` | Existing snapshot allocation, cleanup registration, copy, or buffer capture fails. | Restore component-read and temporary-storage access/capacity, then retry. |
| `SNAPSHOT-HASH` | The captured component cannot be hashed, or the digest differs from the manifest entry. | Restore snapshot access/SHA-256 utilities for a failed hash; preserve local edits and restore the component through the full package bootstrap for a mismatch. |

The first existing failed decision determines the classification. Authorization
is checked before manifest grammar, so a corrupt manifest beside a stale marker
reports `AUTH-HASH` first. Diagnostics do not add authority or change acceptance,
fallback, or successful routing. Mandatory review infrastructure continues to
refuse without a verified baseline. Optional author-lint continues to warn and
skip the mechanical pre-pass when verification fails; the AI review still runs.
The recovery-seal eligibility and authorization requirements remain unchanged;
these messages do not authorize a new seal or an unreviewed edit to LOCAL files.

## 3. The trust chain under the local shape

Every stage keeps its current tracked-shape behavior and gains a
local branch, taken only when the file in question is untracked AND
ignored AND the authorization marker stands AND the manifest verifies
it:

- **Dispatcher** (`.git/hooks/pre-commit`, installed by bootstrap):
  when the gate path is POSITIVELY absent from HEAD (a readable HEAD
  listing no gate path, or an unborn branch) and the working-tree hook
  is untracked+ignored, capture its exact bytes once into a shell-owned
  base64 buffer, hash the captured bytes against the manifest, decode
  once into a shell-owned text buffer, reverify its exact byte length
  and SHA-256, and evaluate that buffer in a fixed `/bin/sh` subshell,
  announcing the local shape in the output. No authority pathname is
  reopened after verification and no executable temp file exists for a
  same-user process to replace. A failed probe,
  mismatch, unreadable manifest, absent manifest, or absent entry →
  refuse with a phase-appropriate remedy. A same-version `-Force` refresh backs
  up and replaces a drifted file. During a version upgrade, an unrecognized
  LOCAL edit is preserved. Only a complete recovery inventory satisfying
  `docs/install-values-v1.md` can be operator-sealed before retrying `-Force`;
  a locally modified hook is the exact state the refusal exists to catch. The dispatcher carries
  its own minimal sh SHA-256 discovery (sha256sum, then shasum -a
  256), refusing when no tool answers — hash-tool absence must never
  fail open.
- **Hook untracked-infra guards** (commit wrappers; per-backend
  wrapper + prompt + the shared `scripts/review-liveness.psm1` and
  `scripts/review-common.ps1` the wrappers load): the same local branch
  replaces today's unconditional refusal, running verified SNAPSHOTS of the
  wrapper, prompt and shared files and announcing it. A wrapper loads the
  shared files from beside itself, so the hook always captures the whole set into one
  directory, TRACKED components from HEAD and LOCAL ones as verified
  snapshots, and runs it from there. A module is required only when the
  captured wrapper bytes that run name it, so a wrapper from before the
  module existed runs without it (the
  commit-wrapper guard is detective-only
  in every shape — the wrappers run before the hook, so the guard
  grades persistent divergence, never pre-execution state). The
  author-lint pre-pass follows the same rule instead of skipping: a
  verified snapshot runs; an unverifiable file skips with today's WARN
  (the pre-pass is fail-open by contract; the review gate is not).
- **Wrappers and merge gate — trusted components**: the tracked shape
  consumes gate components sourced from HEAD. The local shape verifies
  each untracked+ignored component's WORKING-TREE bytes against the
  manifest before consumption. The dispatcher remains machine state in
  every shape.
- **Merge gate — trusted-infra extraction**: the gate extracts the
  wrappers, prompt and shared review files from the BASE commit so a
  candidate branch cannot
  weaken the reviewer that decides its merge. A base tree with no gate
  in it (the local shape) extracts nothing; the gate then copies each
  manifest-verified working-tree file into its trusted dir instead —
  the manifest is custody a candidate branch cannot reach, so the
  property the base extraction exists for is preserved. An unverified
  file keeps the fail-closed abort. The gate executable itself remains
  operator-invoked from the working tree in every shape; project-mode
  configuration does not add a second trust or attestation layer.
- **Ignore-rule routing**: bootstrap appends the `logs/` artifact rule
  to the git common dir's `info/exclude` — never the tracked
  `.gitignore` — when the target's gate hook path is already ignored
  at install time (the operator sets the excludes first, then runs
  bootstrap), so a local-shape install leaves project content
  untouched.
- **Project values**: bootstrap and renderer checks classify the fixed root
  values source independently of runtime gate verification. LOCAL authority
  requires positive HEAD and index absence, positive effective-ignore status,
  and retained ordinary-file custody. Bootstrap never adds the source's ignore
  rule, and no runtime gate path opens that source.
- **Project-mode configuration** (`PROJECT-MODE.md` STAYS TRACKED in
  every shape — the declaration is project metadata; only the gate
  machinery may be local): resolution is identical in TRACKED and LOCAL
  installs. The trusted declaration preceding the reviewed change
  supplies the review lens; a candidate edit never governs itself. A
  malformed governing declaration warns and selects `shipped` defaults.
  No activation walk, token attestation, parent-commit requirement,
  declaration isolation, operator sanction, or declaration-specific skip
  rule applies. Generic LOCAL-shape verification still protects the gate
  files consumed to run the review.

## 4. Refresh, drift, and backups (the loss-prevention half)

A blind `-Force` overwrite is the behavior that destroyed the consuming
project's local modifications; under this contract `-Force` overwrites
only behind a verified backup, in every shape:

- Every pre-existing gate file is first RENAMED to a sibling custody
  name (same directory, so same filesystem — atomic even when a linked
  worktree puts the git common dir on another volume), then a
  hash-verified COPY of the custody file lands in
  `<git-common-dir>/crg-backups/<UTC stamp>-<random suffix>/<path>`.
  The custody file is RETAINED until the replacement itself lands and
  verifies: a failed replacement attempts a LAYERED, BEST-EFFORT
  restoration — the custody original first, then the verified backup;
  a set-aside destination occupant is never returned to the path.
  Unverified live bytes are the worst outcome (a truncated hook can
  exit before enforcing), while an EMPTY path fail-closes for gate
  files and is covered by the dispatcher's sentinel — so the restorer
  aims the FINAL state at VERIFIED or EMPTY: the primary custody move
  is verified immediately after placement and demoted to a set-aside
  on any mismatch (the transient window between an in-place move and
  its verification is inherent), and any unverified bytes found at the
  path on entering the fallback are set aside before the refill.
  Best-effort has a stated bound: when even the
  set-aside itself fails, the bytes are left where they are and loudly
  disclaimed, never trusted or silently kept. A hostile race can still
  defeat every layer, but never
  silently: each restoration-path abort names every location that
  still holds bytes, the backup included. A destination occupant found at the path
  during that rollback — origin unverified: a concurrent writer's
  file or the installer's own partial replacement — is SET
  ASIDE under its own collision-checked name, never deleted, and a
  non-file occupant refuses the restore outright rather than nesting
  the original inside it. The backup-refill layer reports success
  only after the refilled bytes verify against the backup digest; the
  refill STAGES through a
  collision-checked sibling, verifies there, moves into place, and
  re-verifies at the path — a post-move mismatch is demoted to a
  set-aside the same way as the primary's.
  Custody is never
  deleted — path-based deletion is never automated anywhere in this
  protocol, because a deletion by name can race a concurrent
  replacement of that name and destroy bytes that have no backup. Once
  the replacement verifies,
  the custody file is ARCHIVED into the backup area beside the
  verified copy by HARDLINK — the link can only be created on the same
  filesystem (the proof of volume identity that lexical path
  comparison cannot give: mount points and junctions lie) and names
  the same data, so bytes a pre-rename writable handle wrote after the
  backup hash land in both names — and the custody name is RETAINED
  beside the installed file, named for hand cleanup once reconciled.
  Archival is BEST-EFFORT: where
  the hardlink cannot be created, the archive is a verified-readable
  copy and the custody file is retained beside the installed file,
  named for hand cleanup — and a failed archive copy leaves the
  custody file in place, reported as holding post-hash writes that are
  not archived anywhere, or as already-archived when a matching
  archive copy exists.
  For the DISPATCHER specifically the rename protocol above does NOT
  apply: the dispatcher is the live pre-commit hook, git takes no
  bootstrap lock, and any unguarded interval where the hooks path is
  EMPTY is an interval where a concurrent commit runs UNGATED —
  silently, the one outcome worse than unverified bytes. So the
  dispatcher is replaced IN PLACE, through ONE exclusive handle that
  no namespace operation ever touches: the handle (read-and-write
  access, sharing nothing) is opened on the live file — a reparse
  point is refused before mutation — and from that moment every
  other open fails, so a concurrent commit during the rewrite FAILS
  CLOSED (git cannot spawn an unopenable hook) instead of passing
  ungated. The backup and its archive twin are read from and
  verified through that same handle, land through create-new handles
  (an occupied recovery name aborts, never overwrites), and stay
  held until the stage ends so the verified identities cannot be
  swapped behind the report; the late-write divergence class is
  structurally impossible. The rewrite itself is DISARM-FIRST,
  leaning on a measured git behavior: git refuses to SPAWN a hook
  with no shebang ("cannot spawn" — the commit aborts). The first
  mutation flips the shebang's second byte to a comment marker
  ('#X/bin/sh'), the whole new body is written and read back through
  the same handle with that byte still disarmed, and the LAST
  mutation is the atomic single-byte re-arm — so every observable
  state of the file either keeps the pre-existing hook's bytes
  (whatever behavior they carried, before the disarm), refuses every
  commit at spawn (between the mutations), or is the verified new
  dispatcher (after the arm), with no interleaved-content analysis
  needed — the lone diagnosed exception
  being a disarm whose own confirmation fails, which is reported as
  possibly armed and never claimed safe. A rewrite that does not
  verify falls back to writing the SENTINEL through the same held
  handle, and a failed fallback whose disarm confirmed leaves only
  shebang-less torn states git refuses to spawn, reported loudly
  with the backup named. Every failure before the first written byte
  aborts with the pre-existing hook bytes untouched.
  The sentinel keeps the same in-place discipline: an occupant is
  exclusively opened (reparse points refused), its bytes are
  preserved from the held stream — preservation is MANDATORY: an
  occupant that cannot be preserved verified is refused, never
  destroyed — and the sentinel is written and read back through that
  same handle, while an EMPTY path takes a create-new write,
  re-hashed. A landed sentinel
  makes later commits refuse loudly instead of executing a truncated
  hook that could exit before enforcing. The sentinel is a brace-wrapped
  sh command with no shebang, so every proper nonempty prefix of it
  FAILS CLOSED under sh — almost all as syntax errors from the
  unclosed brace or quote, and the prefix that only loses the trailing
  newline still runs the refusal and exits nonzero; on
  the empty path a collision or unverified write is reclassified
  through a bounded retry — an occupant is never moved off the live
  hook name, since the move itself would open the ungated interval —
  and the residual past the final attempt — a zero-byte file, an
  occupant that could not be exclusively opened, preserved, or
  rewritten verified — is reported explicitly while the run aborts
  naming the path as unsafe to commit through.
  Diagnostics claim only positively observed locations — a vanished
  custody file is reported GONE, never "preserved". For the RENAMED
  gate files, a copy-based backup of the live path would race a
  concurrent editor save between verification and overwrite, while
  the rename preserves whichever bytes were last written; the
  dispatcher's held handle achieves the same fidelity without the
  rename, by denying the concurrent save instead. The per-run suffix
  keeps concurrent refreshes off each other's paths, a pre-existing
  backup or custody path refuses outright, and the replacement is
  created with CREATE-NEW semantics (the copy call itself throws on an
  existing destination), so a file reappearing at the destination
  mid-run fails loudly instead of being clobbered. The run
  REPORTS every replaced file during a version upgrade so every named
  version-transition backup is discoverable. The trusted baseline is a regular
  `HEAD` blob when the path is tracked; the manifest is consulted only after a
  successful repository read positively proves the path absent from `HEAD`.
  An unreadable, indeterminate, or non-regular `HEAD` entry never falls back to
  mutable manifest state. During a same-version refresh, the report names files
  that no longer matched that trusted baseline and any whose recovery copy
  diverged from the backup hash afterwards; files unmodified on both counts
  ride into the backup area unlisted. `-Force` authorizes replacement only
  after the upgrade preflight accepts every occupied path; it never bypasses a
  failed trusted-baseline check. No gate file's bytes are destroyed unbacked
  any more (recovery
  is a copy out of the backup dir), and the dispatcher transition
  never overwrites bytes whose identity was not pinned.
- Manifest entries record the exact installed-file bytes. On the ordinary copy
  path, that is the provenance-stamped result after verification against
  package-derived expected bytes. On the self-install path, no copy or stamp
  occurs and the entry records the package source bytes already present. A
  corrupted or concurrently edited copy can never become the blessed baseline
  through the COPY path. The operator-sanctioned `-SealManifest` recovery act
  (§2) re-baselines installed bytes only after exact inventory, values-source,
  renderer-state, and shared-core eligibility checks. The seal hashes the held
  installed inventory, so inspection remains part of the operator duty the
  sanction gates; the seal does not prove semantic correctness or source
  agreement.
- The backup dir is machine state under `.git/`, invisible to the
  repo; bootstrap never prunes it (disk-cheap; deletion is the
  operator's).
- P9 is delivered in v2.0.0. The package now carries an authoritative
  `VERSION`, copied installs receive package/source provenance stamps,
  bootstrap publishes a strict per-worktree version record, and a version
  upgrade compares every occupied destination with the trusted baseline before
  replacement. A locally modified upgrade path is restored from custody and
  the run refuses; a successful upgrade reports every replaced path and leaves
  every prior file recoverable from the backup area.

## 5. What this deliberately does not do

- No env var and no switch DECLARES the shape: it is declared by
  ignoring the gate paths BEFORE the bootstrap run, which then records
  that declaration as the authorization marker (§2); everything else
  follows from the manifest plus the marker.
  `CROSS_REVIEW_ALLOW_GATE_UNTRACK` (§2) sanctions a
  SHAPE TRANSITION (an operator act) — it selects nothing. The added
  switch, `-SealManifest` (§2), is a
  maintenance operation on machine state, not a shape selector.
- Metadata-free migration is inventory-bounded. Released v1.7 wrote neither a
  manifest nor a version record; v2.0 metadata can also be lost. A complete
  TRACKED legacy inventory upgrades with `-Force` through trusted `HEAD`
  baselines after the explicit values source gains staged TRACKED authority. A
  LOCAL legacy inventory has no `HEAD` baseline. After creating the valid
  ignored values source and inspecting the installed bytes, run the current
  `-DispatcherOnly`, sanction `-SealManifest` with
  `CROSS_REVIEW_ALLOW_SEAL=1`, then retry the full `-Force` install and renderer
  `-Check`. The legacy seal accepts only the complete frozen-v2.0 inventory or
  the exact frozen-v1.7 core plus any recognized v2.0 additions. The separate
  current-v2.1 recovery arm requires the exact complete current inventory and
  all source/render/state predicates in `docs/install-values-v1.md`. Arbitrary
  partial or mixed inventories refuse. Until that trusted LOCAL baseline
  exists, the local-shape refusals stand.
- No weakening of the tracked shape: every local branch is gated on
  untracked+ignored, which tracked installs never satisfy.
- Any hand-patched interim fork of an untracked install (the consuming
  robotics project carried one, marked in-file, dated 2026-08-26) is
  RETIRED through the same bounded LOCAL migration: create the explicit values
  source, install the current dispatcher, inspect the fork, sanction
  `-SealManifest` only when the exact legacy recovery shape admits those bytes,
  then run `-Force` against a package carrying this shape. Section 4 backs the
  fork's files up, reports every replaced upgrade path, and installs package
  files rendered from the explicit project values.
