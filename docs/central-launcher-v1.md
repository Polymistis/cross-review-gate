# Central launcher ABI 2

Status: live integration drafted, 2026-09-07. Depends on
`central-runtime-v1.md` and the byte parsers in `private-governance-v1.md`.
The stable launcher selects one retained release for status, attachment, staging,
paired review/publication, recovery and public-push enforcement. Source integration
is not evidence of a completed consumer deployment.

## Files and ordinary entry

Central-only source payloads:

- `scripts/central-launcher.ps1`: stable loader, installed as `<store>/launcher.ps1`.
- `scripts/central-context.psm1`: release-local operation entry and paired capture.
- `scripts/private-governance.psm1`: validated attachment/configuration byte parsers.

Append these files only to the central source inventory. The legacy 17-file
`Get-CrgCurrentFileList` and ordinary TRACKED/LOCAL installers stay unchanged.

```text
bootstrap.ps1 -InstallRuntimeLauncher -RuntimeStore <absolute-directory>
  -ReleaseId <published-release-manifest-sha256>
bootstrap.ps1 -UpgradeRuntimeLauncher -RuntimeStore <absolute-directory>
  -ReleaseId <approved-ABI-2-release-manifest-sha256>
<store>/launcher.ps1 -TargetRepo <absolute-public-worktree-root> -Status
<store>/launcher.ps1 -TargetRepo <root> -Open
<store>/launcher.ps1 -TargetRepo <root> -Stage -All
<store>/launcher.ps1 -TargetRepo <root> -Stage -Paths <relative-paths>
<store>/launcher.ps1 -TargetRepo <root> -Commit -MessageFile <path>
  -AuthoringAgent codex|claude
<store>/launcher.ps1 -TargetRepo <root> -Resume
<store>/launcher.ps1 -TargetRepo <root> -Attach -MessageFile <path>
  -AuthoringAgent codex|claude [-PrivateGitDir <existing-or-new-private-database>]
```

The bootstrap form is a parameter description, not a multiline shell example.
`TargetRepo` must identify the actual public worktree root; current-directory and
ancestor fallback never select a project. Source checkout execution is not a
launcher-install substitute. The stable parameter sets expose the complete ABI
now; validated operation data goes to release-local `Invoke-CrgCentralOperation`.
The context imports the complete manifest-owned operation dependencies before
dispatch. AuthoringAgent declares the implementer, not a reviewer or provider;
runtime policy selects the opposite reviewer and automatic exhaustion fallback.
Resume uses captured leg requirements and accepts no new author override.
Operation data has Name (Open/Status/Stage/Commit/Resume/Attach/PushCheck), All (boolean), Paths
(string array, empty outside explicit Stage paths), MessageFile, and canonical
lowercase AuthoringAgent, optional initial PrivateGitDir and native push input.
PushCheck is the installed pre-push entry, with exact bounded stdin bytes and
original PushRemoteName/PushRemoteLocation arguments. No provider override follows.
The stable entry validates parameter combinations and
bounded nonempty input strings; release-local implementations validate path meaning
and governing policy before any mutation or review.

Before first attachment activation, the same ABI 2 `Stage -Paths` request can
correct an existing owned pending attachment candidate. The release-local operation
requires the exact pending proposal, its existing private database and fixed indexes,
and either matching complete initialization records or the original record-free
adoption state. Adopted public and private databases may use different supported
Git object formats; initialized new databases retain the recorded common format.
Every selected file or directory expansion must remain private under
the preserved and candidate configurations. `Stage -All` is unavailable in this
state. No attachment review, publication, migration, initialization or adoption is
performed by pending staging; a later ordinary Attach remains mandatory.

The same ABI also supports the narrow published instruction correction described
in `first-attachment-v1.md`: an unactivated first-origin handoff with both refs
already at the recorded results and no completed pointer. Only explicit root
instruction paths may change; public content and other private entries remain
unchanged. Stage and Attach use the active approved release and require a freshly
reviewed successor. No new launcher parameter or Resume override is introduced.

## First installation and provenance

An operator-approved bootstrap fully retains and validates the published release
using the existing central manifest and NativeV4 custody boundary. The selected
release must contain all three central entrypoints above as ordinary manifest
payloads. Copy the exact verified `central-launcher.ps1` bytes create-new to the
stable store path; never execute a bootstrap or launcher from an imported package
to establish approval. Existing matching launcher bytes are idempotent; differing
bytes refuse without an automatic update or Force switch.

New ABI 2 `launcher-install` is bounded ASCII/LF metadata:

```text
crg-runtime-launcher v2
launcher-abi 2
release <64-lowercase-hex>
sha256 <64-lowercase-hex>
previous-release <64-lowercase-hex-or-dash>
previous-sha256 <64-lowercase-hex-or-dash>
```

Both predecessor fields are `-` for first installation; migration records the
exact ABI 1 origin and hash. Legacy v1 provenance retains its original header,
release and hash records and is admitted only for an ABI 1 origin. The source
release identity and launcher hash record installed-loader provenance, not the
active runtime version or a project pin. The ordinary installed entry
is an operator-custodied trust root, like the existing per-clone dispatcher;
a self-reported hash is not an independent authority for executing arbitrary code.
Retain the exact source release. Install the provenance record only after the
verified launcher exists; incomplete installation refuses launcher use and can
resume only against the same verified bytes. Foreign metadata is preserved.

Routine central activation changes only `active-release`. ABI 2 keeps launcher
bytes and invocation conventions stable; no project configuration or thin shim
changes during a core release activation. An exceptional launcher ABI migration
uses the explicit `-UpgradeRuntimeLauncher` operation, not an implicit routine
upgrade. The supported transition is ABI 1 to ABI 2 at the same store path, with
project config schema 1 unchanged. The approved target manifest supplies exact
new bytes; the existing installation and retained origin manifest must prove the
old bytes. No arbitrary replacement launcher or caller-supplied predecessor is
accepted.

Before replacing either fixed leaf, migration retains the desired v2 record as
`launcher-upgrade`. The same rooted no-replace writer then publishes provenance
and launcher bytes. The retained record also preserves the predecessor after
completion. Existing launcher read leases must end before replacement; no running
invocation is detached. A partial or mismatched installed pair refuses execution
and activation. Repeating the same explicit migration validates the retained
transition and accepts only exact old/new bytes or positively absent fixed names;
conflicting occupants remain untouched. This changes neither the active selector
nor any project. Retain both origin releases and the transition record.

## Selection and execution

The launcher derives the store from the installed script location. The loader
contains only strict record readers and a narrow read-only native lease: ordinary
directory/file opens, held shape checks, and the existing persistent lock model.
No installer, generic rooted mutation engine, deletion API, or signing framework
is copied into the launcher. Child opens remain relative to retained directory
handles, with no-follow semantics; untrusted path traversal never supplies code.

1. Retain the actual store directory chain and installation record. Validate the
   exact installed launcher and ABI against recorded installed-origin provenance.
2. Hold `runtime.lock`, capture exactly one `active-release`, and verify the named
   manifest and all declared payload bytes. Require launcher ABI 1/2 and config schema 1
   and all central entrypoints before importing any active-release module.
3. Retain the selected release subtree and payload files, release the short store
   lock, then import only the exact verified context and parser modules. Retained
   files deny byte mutation/replacement through completion. Store/ancestor holds
   allow ordinary central mutation so a later activation can proceed concurrently.
4. Invoke the context module with an internal captured context and explicit
   TargetRepo. Callers cannot supply another release, manifest, private index,
   provider skip, or receipt. Children of future review/commit orchestration must
   inherit the same captured selection rather than read `active-release` again.

The internal context exposes `ReadFile` (held read-only bytes), `RetainFailure`
(preserve actual launcher owners on unconfirmed descendant cleanup), and `RetainRelease`
(Resume only). After validating the handoff, a verified Resume implementation can
reopen the recorded preceding manifest identity through the latter callback. The
loader revalidates and retains that complete release and returns the same context
shape without rereading the active selector. No public release argument exists.
Both selections remain held until invocation completion; reopening grants custody,
not approval. Fresh review under recorded preceding governance/runtime remains
required by the paired recovery contract. ABI 2 retains ABI 1 manifest support
for compatible old-runtime recovery and rollback; an ABI 1 loader rejects an
ABI 2 manifest rather than invoking a runtime without the new lifetime callback.

Executable activation validates launcher capability. Foundation-only publication
snapshots with reserved ABI metadata are not automatically executable attachment
releases. Missing payloads, mismatched digests, unsupported capability, or lost
custody refuse; no source checkout or old per-project runtime supplies fallback.

## Read-only status and later attachment activation

Status resolves actual public worktree/Git/common-directory identity before
reading `crg-attachment`. Positive absence reports unattached. A present attachment
must match the selected store and public branch, and identify a distinct private
Git database with no public/private object alternates. Git plumbing is local,
explicitly rooted, and isolated from ambient Git directory/config overrides.
Missing objects refuse; the controlled Git child disables lazy promisor fetching.

Read configuration bytes from the captured private branch commit, validate the
regular blob and exact bytes, then call `Read-CrgProjectConfigBytes`. Report the
public/private identities, configuration source, discovery-file presence, and
presence of pending/completed-pair metadata. Private HEAD is inspection data,
not proof of approved governing state. Pending records are not resumed or
interpreted as review acceptance. Status reports metadata inspection separately
from `Open`'s completed-pair admission and reports pending publication as requiring
`Resume`.
No working file, index, ref, hook, mode declaration, or configuration is changed.

Actual attachment activation is a separate reviewed operation: validate and
review the initial private candidate under runtime bootstrap rules, preserve
existing foreign guard behavior, establish the initial approved pair, materialize
reviewed discovery instructions without losing edits, then publish the association
and required public/private guards under the existing custody discipline. No
operator-written attachment record alone enables an unreviewed private workflow.

Static parsing and native compilation are distinct from ordinary installed
operation. Code unit tests are not authorized; live testing, manual checks,
ordinary program runs, and functional validation remain permitted and
important. Deployment records must identify the actual package/release, initial
paired review, final association and subsequent operation; source completion
alone does not meet that boundary.
