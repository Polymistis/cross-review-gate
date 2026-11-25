# Central launcher ABI 4

Status: live integration drafted, 2026-09-07. Depends on
`central-runtime-v1.md` and the byte parsers in `private-governance-v1.md`.
The stable launcher selects one retained release for status, attachment, staging,
paired review/publication, recovery and public-push enforcement. Source integration
is not evidence of a completed consumer deployment.

## Files and ordinary entry

Central-only source payloads:

- `scripts/central-launcher.ps1`: stable loader, installed as `<store>/launcher.ps1`.
- `scripts/central-transport.psm1`: bounded local client/host transport retained from installed-origin provenance.
- `scripts/central-context.psm1`: release-local operation entry and paired capture.
- `scripts/private-governance.psm1`: validated attachment/configuration byte parsers.

Append these files only to the central source inventory, never to
`Get-CrgCurrentFileList`.

```text
bootstrap.ps1 -InstallRuntimeLauncher -RuntimeStore <absolute-directory>
  -ReleaseId <published-release-manifest-sha256>
bootstrap.ps1 -UpgradeRuntimeLauncher -RuntimeStore <absolute-directory>
  -ReleaseId <approved-successor-ABI-release-manifest-sha256>
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
Owned requests carry a separate admitted namespace binding. The operation-read
boundary verifies that binding under the original project lock and preserves the
selected implementation and full signature. Retained ABI 2 operations use the
installed-origin orchestration guard with the recorded compiler and review modules; immutable
older payloads remain unchanged. Read facades retain the admission guard.
Resume uses captured leg requirements and accepts no new author override.
Operation data has Name (Open/Status/Stage/Commit/Resume/Attach/PushCheck), All (boolean), Paths
(string array, empty outside explicit Stage paths), MessageFile, and canonical
lowercase AuthoringAgent, optional initial PrivateGitDir and native push input.
PushCheck is the installed pre-push entry, with exact bounded stdin bytes and
original PushRemoteName/PushRemoteLocation arguments. No provider override follows.
The stable entry validates parameter combinations and
bounded nonempty input strings; release-local implementations validate path meaning
and governing policy before any mutation or review.

Normal calls are read-only clients of the installed host. The host authenticates
the caller and checks project access before invoking a fixed launcher child.
Internal stdin execution selects no alternate executable, review policy or
provider. The installing account's per-user logon entry starts `launcher.ps1
-Serve`; no project session needs permission-policy changes. The protocol,
independent worker ownership and failure transitions are specified in
[sandbox execution](sandbox-execution-v1.md).

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

New ABI 4 `launcher-install` is bounded ASCII/LF metadata:

```text
crg-runtime-launcher v4
launcher-abi 4
release <64-lowercase-hex>
sha256 <64-lowercase-hex>
previous-release <64-lowercase-hex-or-dash>
previous-sha256 <64-lowercase-hex-or-dash>
```

Both predecessor fields are `-` for first installation; migration records the
exact predecessor origin and hash. Retained v2 and v3 provenance use the same
shape with their own header and ABI. Legacy v1 provenance retains its original header,
release and hash records and is admitted only for an ABI 1 origin. The source
release identity and launcher hash record installed-loader provenance, not the
active runtime version or a project pin. The ordinary installed entry
is an operator-custodied trust root;
a self-reported hash is not an independent authority for executing arbitrary code.
Retain the exact source release. Install the provenance record only after the
verified launcher exists; incomplete installation refuses launcher use and can
resume only against the same verified bytes. Foreign metadata is preserved.
A launcher declares its ABI on its first line, `# Stable launcher ABI <n>. `,
after an optional UTF-8 byte-order mark. The ABI 4 launcher also states its ABI
as a value in its code, because PowerShell parses the script before startup
reads `launcher.ps1` again and a store restore can replace the file in between;
startup refuses unless the line-1 declaration of the file it reads and
`launcher-install` both name that value. One rule, in one bootstrap function,
applies at source publication, package import, installation, migration and
activation: a manifest or installation record of ABI 4 or later must name
exactly the ABI its launcher declares; for ABI 1-3 only a declaration naming
another ABI refuses, so retained launchers without a recognisable declaration
keep their admission. Source publication accepts only a source launcher that
declares ABI 4, because this revision's payload list carries none of the
hook-mode entries an earlier ABI's manifest requires; an earlier source
revision is published with that revision's own bootstrap.
The launcher applies the rule to the launcher of every release it opens for
execution, the active one and one a handoff records. Migration applies the rule to the target release's launcher and to
the installed predecessor launcher, and, while it has replaced neither fixed
leaf, applies to the release `active-release` names the checks the successor
launcher makes on a release it executes, refusing before its first write when
one fails: verified payloads, a launcher ABI no later than the successor's and
the launcher capabilities for every successor, and this rule for an ABI 4
successor, since earlier launchers do not apply it. A bootstrap from before
the rule (before source commit `4025c2c`) could publish an ABI 4 launcher as
ABI 3 and activate that release, which the ABI 3 launcher runs and the ABI 4
launcher refuses. The migration cannot see handoffs, which are project state:
before migrating, the operator finishes or resumes to completion, with the
still-installed launcher, every pending operation bound to a release the
successor refuses, and activates a release that both launchers admit. Before it changes or reaffirms
`active-release`, activation applies it to the installed launcher against
`launcher-install` and to the selected release's own launcher against the
selected manifest; a release without a launcher payload is foundation data,
whose activation the capability checks decide.

Routine central activation changes only `active-release`. ABI 4 keeps launcher
bytes and invocation conventions stable; no project configuration or thin shim
changes during a core release activation. An exceptional launcher ABI migration
uses the explicit `-UpgradeRuntimeLauncher` operation, not an implicit routine
upgrade. Supported transitions advance from ABI 1 to ABI 2, ABI 2 to ABI 3 or
ABI 3 to ABI 4 at the same store path, with
project config schema 1 unchanged. The approved target manifest supplies exact
new bytes; the existing installation and retained origin manifest must prove the
old bytes. No arbitrary replacement launcher or caller-supplied predecessor is
accepted.

Before replacing either fixed leaf, migration retains the successor record.
ABI 2 retains `launcher-upgrade`; ABI 3 uses `launcher-upgrade-v3` and preserves
the exact preceding installation record in `launcher-prior-v3`; ABI 4 likewise
uses `launcher-upgrade-v4` and `launcher-prior-v4`, leaving earlier transition
records in place. The prior record keeps the exact preceding installation
record, which classification below compares byte for byte with the record the
store's history implies. The same rooted no-replace writer then publishes provenance
and launcher bytes. The retained record also preserves the predecessor after
completion. Existing launcher read leases must end before replacement; no running
invocation is detached, and migration ends no process. Every gate host and
command holds both fixed leaves, sharing only reads, while it runs, so before
migration to ABI 4 the operator ends every gate host and command of the store in
every logon. Before ending one, the operator lets its operations complete,
inspects every unknown outcome with Status or Resume and confirms that it keeps
no custody of an unconfirmed descendant, which the holder list cannot tell
from an idle host; while a holder cannot be resolved so, the operator defers
the migration. Under the store lock and before its first write, that
migration, while it still has a leaf to replace, refuses while any process
other than itself holds either leaf, and refuses a leaf's holder list that does
not name the migration's own open of that leaf. It names each
holding process and its session when the holder shares reads; a holder that
denies read sharing or holds write or delete access makes the migration's own
open of the leaf fail with a sharing violation, and that refusal names no
process. Before
its first write, migration to ABI 3 or later also refuses a conflict in the
current account's startup entry that host installation would refuse; host
installation repeats that check on the registry key it writes; a value another
writer creates between that check and the registration is not detected. A process that
opens a leaf after these checks blocks the leaf's replacement with a sharing
violation unless it holds only read access and shares both reads and deletion;
every launcher process denies delete sharing and so blocks it. At
`launcher-install` the complete predecessor pair then remains, and at
`launcher.ps1` successor provenance sits beside predecessor launcher bytes,
which no launcher executes. A rerun resumes either state. Migration to ABI 3 or
later starts the successor host for the current logon. Repeating the same
explicit migration validates the retained transition and accepts only exact
old/new bytes or positively absent fixed names; conflicting occupants remain
untouched. A repetition after both leaves were replaced replaces nothing and
checks no holder: it repairs only the current account's startup entry and host.

The newest recorded transition owns the installation. One bootstrap function
reads it and classifies the installed pair against it alone, and activation and
migration both act on that classification:

- predecessor: `launcher-install` equals the transition's preceding provenance
  and `launcher.ps1` has the predecessor hash. The preceding provenance is the
  installation record the store's history implies for the transition's
  predecessor fields, compared as complete bytes, since two records can name the
  same release and hash with different predecessors. For ABI 3 and later the
  retained `launcher-prior` record must equal it byte for byte; the ABI 2
  transition keeps no prior record.
- successor: `launcher-install` equals the transition record and `launcher.ps1`
  has its hash.
- partial: each fixed leaf is absent or one of those two sides.
- conflict: anything else.

Each migration keeps its transition record, and from ABI 3 on its prior
record, for the life of the store, so every class, the successor included,
also requires them: the prior record of a transition to ABI 3 or later must
equal its preceding provenance, and while that provenance is itself an earlier
transition record, that transition's prior record, where its ABI keeps one,
must equal the provenance implied for its own predecessor, back to the first
installation. Only the newest transition is classified against the fixed
leaves. A missing or differing record makes the pair a conflict, and a
malformed transition record refuses activation and migration.

Installation writes `launcher-install` only while no transition is recorded,
with both predecessor fields `-`, and every migration writes it equal to its
own transition record. The record the store's history implies for an ABI,
release and hash is therefore the transition record to that ABI when one is
recorded and names that release and hash, the first-installation form while no
transition to that ABI or below is recorded, and none when the newest such
transition targets a lower ABI. Activation and a new migration also require
`launcher-install` itself to equal that record.

Activation accepts the predecessor pair, for releases its launcher admits, and
the successor pair. A resumed migration completes the predecessor and partial
states and reports the successor as complete, repairing only host
registration. A new migration requires the newest recorded transition, if any,
to classify as successor, and a migration to an ABI below the newest
transition's refuses before writing anything. A partial pair refuses activation
and execution until the operator retries the same migration, which completes
it. A conflict refuses activation and every migration and is preserved; the
operator restores the store's launcher files and records to one side of the
transition. Launchers do not read transition records, so a conflicting pair
whose provenance, launcher hash and origin agree with each other still starts.
Migration changes neither the active selector nor any project. Retain both
origin releases and the transition record.

## Selection and execution

The launcher derives the store from the installed script location. The loader
contains strict record readers and a narrow read-only native lease: ordinary
directory/file opens and held shape checks, with no project-side central lock.
No installer, generic rooted mutation engine, deletion API, or signing framework
is copied into the launcher. Child opens remain relative to retained directory
handles, with no-follow semantics; untrusted path traversal never supplies code.

1. Retain the actual store directory chain and installation record. Validate the
   exact installed launcher and ABI against recorded installed-origin provenance;
   the ABI is the value in the executing code, which the retained file's line-1
   declaration and `launcher-install` must both name.
2. The owned worker captures `active-release` through a shared read lease and verifies
   the named manifest and all declared payload bytes. Require a supported retained
   ABI, configuration schema and central entrypoints before importing release code.
3. Retain the selected release subtree and payload files, release the selector
   lease, then import the exact verified context and parser modules. ABI 2
   selection additionally retains the installed-origin dispatcher for the
   operation-read admission guard; selected compiler and review modules remain
   unchanged. Retained files deny byte mutation/replacement through completion. Store/ancestor holds
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
ABI 4 manifests do not require the hook-mode entry points. The ABI 4 loader
still admits retained ABI 1-3 manifests, which keep those entries because their
own loaders require them, so recorded-runtime Resume and the active release
continue after migration when their launcher declaration agrees with their
manifest; an ABI 3 loader rejects an ABI 4 manifest.

Executable activation validates launcher capability. Foundation-only publication
snapshots with reserved ABI metadata are not automatically executable attachment
releases. Missing payloads, mismatched digests, unsupported capability, or lost
custody refuse; no source checkout or old per-project runtime supplies fallback.

## Status inspection and later attachment activation

Status resolves actual public worktree/Git/common-directory identity before
reading `crg-attachment`. Positive absence reports unattached. A present attachment
must match the selected store and public branch, and identify a distinct private
Git database with no public/private object alternates. Git plumbing is local,
explicitly rooted, and isolated from ambient Git directory/config overrides.
Missing objects refuse; the controlled Git child disables lazy promisor fetching.
The installed host binds metadata to the requested project before dispatch, then
the owned worker validates the exact namespace and selector state under the
project operation lock. The empty project lock file can be created during Status;
inspection never writes to the central store.

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
