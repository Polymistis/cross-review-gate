# Central deployment v1

This is the operator procedure for the Windows central runtime and privately
tracked project governance. Source integration is not a release or deployment
record. Actual source OID, manifest ID, archive/bootstrap hashes, review evidence
and consumer results must be recorded by the release operation; no example below
supplies an approval or fabricated release identity.

One activation updates every attached project's next invocation. Existing
invocations retain the selected release through completion. Routine compatible
upgrades retain launcher ABI 2 and project configuration schema 1, with no
per-project release pin, copied runtime update or configuration rewrite.
Existing ABI 1 stores require one explicit store-wide launcher migration before
activating ABI 2; fresh stores install ABI 2 directly.

## Prerequisites and input approval

Use Windows PowerShell 5.1 (`powershell.exe`), Git for Windows, and the
configured reviewer CLIs. The Claude route requires Claude Code 2.1.248 or later.
Mandatory review and automatic positive-exhaustion fallback remain active; no
manual reviewer-suppression flag is part of this procedure. Installing or
attaching a project supplies no new provider or data-transmission authorization.
An attachment using `reviewer-policy default` does not enable xAI.
Code unit tests remain banned. Live, manual, integration, end-to-end, smoke,
performance, and other functional testing remain allowed and important alongside
normal operation, builds, and review.

Choose an ordinary absolute machine-local store outside source repositories,
project Git metadata and extracted release input. The store's parent must exist.
The approved bootstrap is an independently trusted operator executable, not a
script executed merely because an imported manifest mentions an archive.

The following PowerShell variable is operator input, not an environment switch:

```powershell
$CrgStore = Read-Host 'Absolute machine-local central runtime store'
```

Run either source publication or package import, not both for the same input.
Publication/import does not activate a release or change a consumer.

## Publish a normally reviewed source revision

The source must be an actual Git worktree rooted at `CrgSource`, with HEAD equal
to the full source OID from the completed normal source review/landing record.
Every shipped payload must match that revision; uncommitted or untracked payloads
cannot be published as reviewed content.

```powershell
$CrgBootstrap = Read-Host 'Absolute path to the approved source bootstrap.ps1'
$CrgApprovedBootstrapSha256 = Read-Host 'Approved bootstrap SHA256 from the release record'
$CrgBootstrapSha256 = (Get-FileHash -LiteralPath $CrgBootstrap -Algorithm SHA256).Hash.ToLowerInvariant()
if ($CrgApprovedBootstrapSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $CrgBootstrapSha256 -cne $CrgApprovedBootstrapSha256) { throw 'Bootstrap approval/hash mismatch' }
$CrgSource = Read-Host 'Absolute root of the reviewed cross-review-gate source worktree'
$CrgApprovedSource = Read-Host 'Full approved source commit OID'
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -PublishRuntime -RuntimeStore $CrgStore -SourceRoot $CrgSource -ApprovedSourceCommit $CrgApprovedSource
if ($LASTEXITCODE -ne 0) { throw 'Central source publication failed; no activation requested' }
$CrgReleaseId = Read-Host 'Exact 64-character release ID reported by successful publication'
```

Publication reports release ID, version and source OID. The release ID is the
SHA-256 of the complete `runtime-manifest`, not the source OID or version string.
The published directory is `releases/<release-id>` inside the store. Existing
matching releases are revalidated; conflicting contents are preserved and refused.

## Import a portable package without source Git metadata

The portable archive separates executable bootstrap approval from release data:

```text
extracted-package/
  bootstrap.ps1                separately approved operator bootstrap
  INSTALL.md                   operator documentation, outside release data
  release/
    runtime-manifest
    VERSION
    scripts/...                exactly the manifest inventory
    docs/...                   exactly the manifest inventory
```

The release producer copies the already published release bytes without changing
encoding or inventory. `release/` contains no extra bootstrap, archive, source
`.git`, project values/configuration, review logs, private repository or credentials.
Operator documentation remains outside `release/`. A legacy ZIP without the
approved runtime manifest is not a central package.

Obtain archive, bootstrap and manifest hashes from the approved release record
through the established distribution channel. A digest read only from the
untrusted archive does not establish approval. Verify the archive before
extraction, then independently verify the extracted bootstrap before execution:

```powershell
$CrgArchive = Read-Host 'Absolute path to the portable archive'
$CrgApprovedArchiveSha256 = Read-Host 'Approved archive SHA256 from the release record'
$CrgArchiveSha256 = (Get-FileHash -LiteralPath $CrgArchive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($CrgApprovedArchiveSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $CrgArchiveSha256 -cne $CrgApprovedArchiveSha256) { throw 'Archive approval/hash mismatch' }
$CrgExtractRoot = Read-Host 'New absolute extraction directory outside the runtime store'
Expand-Archive -LiteralPath $CrgArchive -DestinationPath $CrgExtractRoot
$CrgBootstrap = Join-Path $CrgExtractRoot 'bootstrap.ps1'
$CrgApprovedBootstrapSha256 = Read-Host 'Approved bootstrap SHA256 from the release record'
$CrgBootstrapSha256 = (Get-FileHash -LiteralPath $CrgBootstrap -Algorithm SHA256).Hash.ToLowerInvariant()
if ($CrgApprovedBootstrapSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $CrgBootstrapSha256 -cne $CrgApprovedBootstrapSha256) { throw 'Bootstrap approval/hash mismatch' }
$CrgReleasePackage = Join-Path $CrgExtractRoot 'release'
$CrgApprovedManifestSha256 = Read-Host 'Approved runtime-manifest SHA256 from the release record'
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -PublishRuntime -RuntimeStore $CrgStore -ReleasePackage $CrgReleasePackage -ApprovedManifestSha256 $CrgApprovedManifestSha256
if ($LASTEXITCODE -ne 0) { throw 'Central package import failed; no activation requested' }
$CrgReleaseId = $CrgApprovedManifestSha256
```

The exact parameter is `-ReleasePackage`, naming the extracted `release/`
directory, not a ZIP or the outer package directory. Import verifies every
manifest-owned byte and retains the approved source provenance without requiring
a source clone. No release payload is executed to establish package approval.

## Install the stable launcher once, then activate

For a new store, install from the successfully published/imported release:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -InstallRuntimeLauncher -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Stable launcher installation failed; no activation requested' }
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -ActivateRuntime -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Central activation failed' }
$CrgLauncher = Join-Path $CrgStore 'launcher.ps1'
```

Existing differing launcher bytes are refused by `-InstallRuntimeLauncher`.
Routine compatible upgrades only publish/import and activate; do not reinstall
the stable launcher from every release. Retain the launcher-origin releases and all
releases required by interrupted operations. Lock contention is not permission
to delete a lock file, change hook routing or bypass review.

For an existing ABI 1 store only, import the approved ABI 2 release, let current
invocations finish, then run the explicit migration before activation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -UpgradeRuntimeLauncher -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Launcher ABI migration incomplete; preserve the recorded transition' }
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -ActivateRuntime -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'ABI 2 activation failed' }
```

Migration preserves the predecessor release/hash in `launcher-install` and the
bounded `launcher-upgrade` recovery record. An interrupted migration resumes only
through the same command and target release; differing occupants are not replaced.
Activation checks actual installed-loader provenance and refuses an ABI mismatch
or incomplete pair. Project configuration, hooks and private history do not change.
The ABI 2 launcher retains ABI 1/2 manifest support for recorded-runtime recovery
and compatible rollback; keep the original releases required by pending work.

## Prepare the first project attachment

Select the exact public worktree root and inspect current status. The initial
deployment record must confirm the actual branch, clean software candidate, and
existing project declaration before attachment. No second consumer mutation
follows from this procedure unless separately requested.

```powershell
$CrgRepo = Read-Host 'Absolute public project worktree root'
git -C $CrgRepo status --short --branch
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Status
```

Finish unrelated staged software work before Attach. Inventory and preserve
existing public/private history, indexes, working edits and hooks. New private
history defaults to the actual public common directory's `crg-governance.git`.
An existing private database requires explicit adoption, never a reset or silent
replacement. Legacy TRACKED payload retirement requires its reviewed provenance
migration; old LOCAL files and recovery evidence are preserved. Do not delete
legacy hooks, set `core.hooksPath`, or manually manufacture `crg-*` records.

Before Attach, prepare these ordinary project files with an editor or the normal
agent editing workflow. Existing project content must be preserved and reviewed:

- `.crg-project/project.conf`: strict UTF-8 without BOM, LF-only, final LF.
- `CROSS-REVIEW-VALUES.md`: actual project context, hazards and SCOPED authority
  using the existing three-block [values contract](install-values-v1.md).
- `AGENTS.md` and `CLAUDE.md`: existing project instructions, the same canonical
  central discovery section below, and the persistent code-unit-tests-banned
  directive that leaves other testing categories available.
- Private `PLAN.md` and `History.md`: actual project requirements/work history,
  with roles in configuration. Different private paths require matching roles
  and discovery records, not duplicate placeholder documents.
- `PROJECT-MODE.md`: preserve the valid prototype declaration and actual campaign.
  For a missing declaration, author `project-mode: v1`, `mode: prototype`, and an
  actual nonempty `campaign:` using the [mode grammar](project-mode-doctrine-v1.md).

A project using the root plan/history paths starts with this configuration;
additional private directories/files must reflect actual project ownership:

```text
crg-project v1
reviewer-policy default
consistency-document private PLAN.md
private-directory .crg-project
private-file AGENTS.md
private-file CLAUDE.md
private-file CROSS-REVIEW-VALUES.md
private-file History.md
private-file PLAN.md
private-file PROJECT-MODE.md
role History.md | Private work history and document discovery
role PLAN.md | Project requirements and acceptance
```

The consistency document is privately tracked, not required in public software
history. `consistency-document -` disables only plan preprocessing when explicitly
selected; mandatory combined review still runs. Project mode controls review
treatment, never permission to work. Candidate prototype mode receives initial
review under release-owned bootstrap governance and governs subsequent pairs.

Insert this exact discovery section into both root instruction files. Replace
`C:\CrossReviewGate` with the actual `CrgStore` path and replace both private
document paths only when configuration and existing files use those paths.
Use LF line endings and preserve a final LF after the closing marker:

```text
<!-- crg-central-discovery v1 BEGIN -->
## Central cross-review gate
Runtime launcher: C:\CrossReviewGate\launcher.ps1
Project configuration: .crg-project/project.conf
Private plan: PLAN.md
Private history: History.md

Use the central launcher for Open, Stage, Commit and Resume with the explicit
TargetRepo. Commit also requires MessageFile and AuthoringAgent. This workflow
supersedes legacy per-project gate commands. Public software and local private
governance receive mandatory combined review; native commits do not substitute.
Project mode describes review treatment, not permission to work. Provider
exhaustion fallback stays automatic within the gate; no session skip flag exists.
<!-- crg-central-discovery v1 END -->
```

Prepare a real nonempty UTF-8 commit message at `.crg-project/message.txt` inside
the project. The private directory keeps that work material out of public staging.
Run one of these attachment forms:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Attach -MessageFile '.crg-project/message.txt' -AuthoringAgent codex
```

For explicit existing private-database adoption, use this form instead:

```powershell
$CrgPrivateDb = Read-Host 'Absolute existing private Git database to adopt without resetting'
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Attach -PrivateGitDir $CrgPrivateDb -MessageFile '.crg-project/message.txt' -AuthoringAgent codex
```

Use `-AuthoringAgent claude` when Claude authored the candidate. The author value
does not choose the reviewer. Initial migration captures classified private
files, moves only approved private paths out of the public candidate, preserves
working files/staged adoption state, and performs a complete first review before
activating the association. Existing public history is not rewritten. Any
previously published governance requires a separate explicit history decision.

Recognized stock Git LFS wrappers are supported: post-checkout,
post-commit and post-merge remain unchanged; pre-push runs paired-history checks
before the retained LFS transfer using the original arguments/stdin. The actual
target's LFS patterns remain project-owned. Because `commit-tree` does not execute
Git's hook dispatcher, Attach and later publication invoke the retained stock
`git-lfs.exe post-commit` after a changed public ref reaches the reviewed result
and before completion becomes visible. Interrupted Resume repeats that owned
invocation from the retained receipt. Ordinary effective attribute and config
sources remain available to stock LFS behavior. Custom or incomplete hook
compositions require explicit preservation work.

## Ordinary work and interrupted publication

After successful Attach, confirm actual attachment and governing mode with Open:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Open
```

Edit software/private documents normally, prepare the actual commit message, then
use the same launcher for both domains. `-All` stages the complete intended pair:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Stage -All
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Commit -MessageFile '.crg-project/message.txt' -AuthoringAgent codex
```

For a bounded path selection, use `-Stage -Paths` with actual repository-relative
paths instead of `-All`; no public/private index is supplied by the caller.
Native `git commit` is refused for both domains. Normal public pushes invoke the
installed pre-push guard; private content and completed-pair enforcement are not
optional. No push is required merely to install or confirm the gate.

When Status reports a pending handoff, preserve the indexes and recorded message:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Resume
```

Resume revalidates the recorded input and runs a fresh complete review under the
retained original release before finishing only the recorded publication. No
reset, saved-PASS replay, source-runtime fallback or bypass flag is appropriate.
Before a durable handoff exists, preserve the pending proposal, private database
and both indexes. Correct only explicitly named private candidate paths with the
existing launcher ABI; directory selections retain normal Stage expansion:

```powershell
& $CrgLauncher -TargetRepo $CrgRepo -Stage -Paths @('AGENTS.md', 'CLAUDE.md')
```

Pending attachment staging refuses `-All`, public selections, missing or conflicting
proposal custody, incomplete initialization records and namespace changes. The
operation accepts independent supported public/private object formats only for a
record-free adopted database. If failed migration left no staged private project
configuration, include `.crg-project/project.conf` explicitly with the correction;
all preserved private entries must remain private under that validated configuration.
The operation does not review or activate the association. After correction, repeat
the same Attach command to perform full migration and mandatory first review.

## Upgrade and rollback

Publish/import the next approved compatible release, then run the same
`-ActivateRuntime` command once. Unchanged project configuration and hooks require
no individual upgrade. Rollback selects an explicitly approved retained compatible
release through that same operation:

```powershell
$CrgRollbackReleaseId = Read-Host 'Approved retained compatible rollback release ID'
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -ActivateRuntime -RuntimeStore $CrgStore -ReleaseId $CrgRollbackReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Central rollback activation failed' }
```

Rollback changes the next invocation's runtime, not project commits, private
history, configuration or already captured in-flight operations. A missing,
malformed or conflicting selector is not permission to guess the newest directory.

## Transfer private work separately from software and the runtime

A runtime package contains no project history. A normal public clone contains no
private governance database, paired receipts, working documents or association
metadata. Private transfers require a separate authorized private destination;
never add a private bundle/database to public software or configure public object
alternates pointing at private objects.

With project operations quiescent, a private history bundle can preserve every
private Git ref, including `refs/crg-pairs/*`, and the reachable objects:

```powershell
$CrgPrivateDb = Read-Host 'Absolute private Git database from the validated project association'
$CrgPrivateBundle = Read-Host 'New absolute private backup bundle path outside all public repositories'
git --git-dir=$CrgPrivateDb bundle create $CrgPrivateBundle --all
if ($LASTEXITCODE -ne 0) { throw 'Private Git history bundle creation failed' }
```

A bundle is not a full project backup or an attachment-restoration command.
Separately preserve private working files and edits, both relevant indexes,
public software refs including retained `refs/crg-results/*`, private association
records, public Git-directory `crg-*` attachment/pointer/materialization/handoff
metadata, private review/recovery state, and required retained runtime releases.
Capture consistent filesystem state only while operations are stopped. A pending
handoff must retain the original runtime and exact candidate state.

Association/receipt records bind actual absolute worktree, Git, private-database
and store paths. Restoring to different paths requires explicit reviewed
association migration; editing path strings or deleting association records does
not repair that binding. No automatic relocation or public/private synchronization
tool is supplied by this deployment procedure. Fresh projects use fresh reviewed
Attach; existing projects require preserved, validated history and metadata.

## Completion evidence

Record actual approved source/bootstrap/archive/manifest identities, successful
publication/import and activation, stable launcher provenance, first paired review
and completed attachment, and the consumer's subsequent Open/mode and ordinary
operation results. Source parsing, native compilation and package publication
alone do not establish a deployed working consumer. Applicable functional-test
evidence may contribute but does not replace the required installed-consumer
evidence. The owning contracts are [runtime](central-runtime-v1.md),
[launcher](central-launcher-v1.md), [first attachment](first-attachment-v1.md),
[publication/recovery](central-publication-v1.md) and [guards](central-guards-v1.md).
