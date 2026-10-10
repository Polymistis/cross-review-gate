# First attachment v1

First attachment has a separate record origin, `first-attachment-v1`. Ordinary
`paired-v1` records remain strict and unchanged. These byte APIs do not activate
an attachment, establish review authority, or publish a commit.

## Initial authority and ancestry

The approved retained runtime supplies bootstrap governance for the first review.
Candidate configuration and adopted private history are review data, not the
authority for accepting that same candidate. Review the complete candidate
governance against the real Git empty tree, independently of adopted ancestry.
Existing public history is not retrospectively reviewed or rewritten.

Use the real existing public parent. Private ancestry is either the actual
adopted private commit or the literal `absent` for genuinely new private history.
Never substitute a zero OID, fabricated commit or synthetic previous receipt.
New private history receives an actual root commit; changed adoption retains
the actual adopted parent; unchanged adoption retains the existing commit.
Unchanged public history receives no companion commit. Explicit public migration
changes still require their actual diff and reviewed result.

Initial review is mandatory even when adoption changes neither history. Only
the first-attachment receipt permits both results unchanged. Initial unit readers
return `RequiresReview = true`; no ordinary no-change shortcut applies.

`New-CrgBootstrapProjectPreparationBytes -RuntimeSha256 -TemplateBytes` in
`project-preparation.psm1` compiles release-owned neutral configuration and values,
the normal mandatory reviewer policy, absent project mode with shipped defaults,
no SCOPED exemptions, and no preceding consistency-document selection. Candidate
configuration remains fully reviewed data and governs subsequent ordinary pairs.
`Read-CrgBootstrapProjectPreparationBytes -Bytes -ExpectedRuntimeSha256
-TemplateBytes` requires exact recomputation, not merely a valid governing frame.
`New-CrgFirstAttachmentModeBlockBytes` takes the governing/candidate preparations,
runtime digest and template; the generated block names runtime-bootstrap authority
and reports candidate mode as evidence without inventing a governing commit.

## Record grammar

Strict UTF-8, no BOM, LF-only records and final LF, exact order, limits, field
types, digest semantics and review leg/attempt rules are shared with
`private-governance-v1.md`. The ordinary public readers reject initial records.
Initial readers reject ordinary records. Shared private parsing does not relax
either public schema.

The first unit and receipt use header `crg-first-attachment-receipt v1`. The
identity prefix has the ordinary field order, with exactly these differences:

- `private-parent` admits `absent` or an actual private-format nonzero OID.
- `private-baseline-tree` replaces `previous-pair` at the same position. The value
  must equal the independently computed empty-tree OID for the private format.
- No `previous-pair` record is permitted.

All other identity fields remain mandatory, including the proposed attachment
digest, runtime digest, bootstrap/candidate preparations, both candidate trees
and diff digests, consistency envelope and private message blob/digest. A unit
ends at `message-sha256`; a receipt appends the existing unit digest, result
commits and complete successful review schedule. Parsing a schedule is data
validation, never proof that reviewers ran.

Initial pending publication uses `crg-first-attachment-handoff v1`, the ordinary
handoff field order without `previous-pair`, and exact values derived from the
initial receipt. `private-old` can consequently be `absent`. No mutable phase
field or arbitrary recovery queue is introduced. Resume still requires fresh
exact-state review under the retained bootstrap runtime before publication.

## Completed-pair pointer

The operator-custodied `crg-pair` record is bounded to 256 bytes:

```text
crg-completed-pair v1
origin paired-v1
receipt-sha256 <64-lowercase-hex>
```

The only other origin is `first-attachment-v1`. The receipt digest covers exact
receipt bytes, not a Git object identifier. The pointer never supplies a file
path or executable. `Read-CrgCompletedPairReceiptBytes` validates the pointer,
dispatches to exactly the named schema, and verifies the raw receipt digest.
The first completed receipt anchors subsequent ordinary `previous-pair` values.

## Prepared input

The first descriptor uses `crg-prepared-first-attachment v1`, with the ordinary
descriptor's ordered fields and fixed buffer names. The transport leaf remains
`prepared-pair.txt`; the exact descriptor digest and explicitly selected reader
pin the origin, not the filename. Initial and ordinary descriptor readers reject
the opposite origin. Initial bundle readers require exact runtime-bootstrap
recompilation before accepting the governing preparation, prompt and mode block.
The bootstrap configuration selects no preceding consistency document; a candidate
selection remains reviewed data for subsequent ordinary pairs.

`paired-review-input.psm1` exports `Read-CrgPreparedFirstAttachmentDescriptorBytes`,
`Read/New-CrgPreparedFirstAttachmentBundleBytes`, and
`Read-CrgPreparedFirstAttachmentFiles`. Argument shapes match the ordinary
counterparts. Initial assembly replaces `previous-pair` in `IdentityFields` with
`private-baseline-tree`; both candidate tree listings, raw domain evidence,
message and complete context blobs remain mandatory. No displayed policy override
or missing private context is accepted. Filesystem acquisition, object provenance
and retained runtime authority remain separate from these byte checks.

## Actual Git acquisition

`first-attachment-context.psm1` exports
`Get-CrgCentralFirstAttachmentProjectContext -TargetRepo -Context -AttachmentBytes`.
The retained read callback holds the selected Git executable, candidate indexes
and existing indirection files. Resolve the actual public worktree/branch and
separate Git/object namespaces, require direct parent refs, and distinguish
positively absent private history from a failed Git read. Existing attachment,
completed-pair or handoff records, in-progress Git markers and object alternates
refuse. Actual parent tree reads and repeated ref checks bind the returned
context; no database, index, association or activation is created by this reader.

`first-attachment-preparation.psm1` exports
`Get-CrgCentralFirstAttachmentReviewInput -ProjectContext -AttachmentBytes
-OperationId -MessageBytes -TempParent -MaximumBlobBytes -MaximumContextBytes`.
The live owner supplies the actual captured public parent and either the actual
adopted private parent or literal `absent`, with an existing private database,
selected candidate index and real empty-tree object. Absent private ancestry
requires that empty tree as `ParentTree`. Proposed attachment bytes are parsed
and matched to the captured project, refs, private database and runtime store;
acquisition neither reads an activated attachment nor creates an association.

Capture both retained indexes through the existing copied-index owner. Generate
and reparse exact runtime-bootstrap governing preparation, then capture candidate
configuration, values, mode and document bindings from the actual candidate trees.
Validate ownership and acquire every context blob within the explicit bounds.
The public diff uses the actual public parent tree. Independently compute and
read the private-format empty tree, and always use that tree for the complete
initial private diff, regardless of adopted ancestry. Capture real parent history;
only literal private absence produces an empty private history buffer.

The mechanical author-lint prepass still validates that complete review input.
When private ancestry was adopted, the live publication owner independently
reads and verifies the original review-unit parent commit and tree, then captures
an attribute-neutral parent-to-candidate private diff after the publication
guards and captured-state checks. Recovery uses that original ancestry even when
partial publication advanced the current private ref; original literal absence
remains absence. Only added-line attribution uses that operation-owned diff:
unchanged adopted files are outside the lint change set, and a strict UTF-8 patch
attributes only added hunks in each modified file. If historical payload bytes make
that patch undecodable, strict name-status endpoints still exclude unchanged files;
deletions have no candidate content to scan, while each changed surviving file is
conservatively attributed as the whole validated candidate blob. No lossy decoding
is used. No launcher input or saved diff supplies this evidence.
For a private addition, an exact same-path regular-file public deletion is also
treated as unchanged when the complete deleted bytes, file mode and retained
private candidate bytes match. New, modified, binary or unprovable private
content keeps the normal lint handling. Neither attribution rule removes either
domain diff from the mandatory initial review.

The existing message helper writes and verifies the message blob only in the
private object namespace, anchored by `ParentTree` rather than requiring a private
commit. Assemble the strict first bundle with no previous receipt. Return the
ordinary captured indexes, preparation sources, context and bundle shape, plus
`RequiresReview=true`. `HasChanges` compares candidate trees with actual ancestry
trees; unchanged adoption still returns a complete mandatory-review input.

This dependency writes candidate tree/message objects, not result commits, refs,
indexes, configuration or working files. Successful byte checks and captured
objects do not establish an approved retained
release, installed end-to-end dispatch, reviewer execution, custody for later
publication or attachment activation. Every result retains `ReadyForReview=false`;
the live owner still holds the proposed association/runtime/project inputs and
completes retention, review, materialization and final publication guards.

## Artifact origin

First artifacts retain the ordinary exact ordered outer header, except
`REVIEW-INPUT: first-attachment-v1`. `Read/New-CrgFirstAttachmentArtifactBytes`
and `Read-CrgSuccessfulFirstAttachmentArtifactBytes` use the ordinary argument
shapes and shared semantic classifier/pass rules. Only the validated outer header
supplies identity; quoted header text in the model body remains prose. First and
ordinary readers reject the opposite origin or review-unit schema.

`Read-CrgFirstAttachmentExhaustionBytes` requires the existing flat machine-string
schema with `reviewInput` set to `first-attachment-v1` and `scope` set to
`first-attachment-` plus the first twelve unit-digest characters. Provider-specific
positive-exhaustion metadata and complete scheduled-pass validation are unchanged.
Matching artifact bytes never prove current child execution, exhaustion or approval.

## Origin-bound host transport

Both review wrappers accept `-PreparedOrigin first-attachment-v1` only in the
existing explicit `PreparedPair` parameter set. Omission retains `paired-v1`;
the selector never infers origin from model prose or falls back between readers.
The shared host pins the first descriptor/file reader and artifact constructor,
keeps the first scope in artifact/exhaustion/follow-up identity, and retains the
same native input and reviewer-descendant lifetime owners.

`New-CrgPairedInputSnapshot` and `New-CrgPairedProviderSnapshot` carry the same
explicit selector. A first snapshot may materialize an unchanged adoption,
but must still pass the complete first bundle reader. Ordinary no-change input
remains ineligible. The fixed provider consistency alias and exact namespace
checks remain unchanged; no candidate file becomes reviewer instructions.

`Invoke-CrgFirstAttachmentReviewSession -Runtime -CapturedInput -AuthoringAgent`
selects first readers and passes the origin to each normal provider host. The
ordinary session signature is unchanged. Both use the same mandatory provider
schedule, strict current-run artifact semantics, positive-exhaustion-only fallback,
and descendant drain/uncertain-owner handling. Saved review material still cannot
authorize publication. Initial Git acquisition and installed end-to-end execution
remain separate completion evidence, not consequences of wiring these calls.

## Data-only API and integration boundary

`paired-governance.psm1` exports `Read/New-CrgFirstAttachmentUnitBytes`,
`Read/New-CrgFirstAttachmentReceiptBytes`, and
`Read/New-CrgFirstAttachmentHandoffBytes`, with the ordinary counterparts' argument
shapes and explicit public/private object formats. Existing ordinary exports
retain their signatures and serialization. Pointer APIs are
`Read-CrgCompletedPairPointerBytes -Bytes` and
`New-CrgCompletedPairPointerBytes -Origin -ReceiptSha256`. Closed receipt resolution
takes `-Bytes -PointerBytes -PublicObjectFormat -PrivateObjectFormat`.

Installed first-host execution, actual result-object validation, private
retention, conflict-preserving instruction materialization and guarded attachment
activation require the live coordinator described below.
No first receipt or pointer constructed from caller data grants passage. Only
the live owner may publish the completed pointer after actual review, guards and
verified ref/materialization state. Missing adopted files remain working deletions;
no invented materialization baseline permits automatic restoration.

## Live admission and migration

`central-attachment.psm1` exports
`Open-CrgCentralAttachment -Runtime -TargetRepo -MessageFile -AuthoringAgent
[-PrivateGitDir]` and the internal pending-candidate form
`Open-CrgCentralAttachment -Runtime -TargetRepo -StagePaths`. The retained runtime
and canonical public worktree are explicit.
Relative message paths resolve against that worktree. The message must contain
non-whitespace strict UTF-8 text, at most 1048576 bytes, without a BOM or NUL,
and end with LF. The message remains inside the worktree and is validated and
captured before migration; no later normalization changes the reviewed bytes. The root
`.crg-project/project.conf` must already exist and pass the strict configuration
reader. Candidate configuration selects private ownership, never bootstrap review
authority.

Admission retains the actual public-worktree operation lock, installed Git
executable, project directory/read owners and independent hook custody. Existing
attachment or completed-pair records refuse a new Attach. A handoff also refuses
ordinary Attach except for the published instruction correction below. Effective
`core.hooksPath` must be positively unset before index initialization or migration;
absent or exact recognized CRG hooks are admitted, while foreign hooks are
preserved and refused. Publication repeats the guard validation.
Hook-capable index/ref mutations bind `core.hooksPath` for each command to the
retained private execution projection described in `central-guards-v1.md`, with
admitted bytes and explicit no-effect entries for absent supported hooks.
Ordinary effective configuration is queried without that binding and custom
hook paths still refuse.

The default new private database is `<public-common-dir>/crg-governance.git`.
Storage must satisfy the shared admission rule in `private-governance-v1.md`:
outside the public worktree or beneath the actual protected public `.git`, never
the public object store or a publicly stageable custom metadata directory.
Existing attachments and pending proposals cannot bypass the same validation.
An existing database requires explicit `PrivateGitDir` adoption, unless an exact
pending proposal already identifies that database. Recorded new initialization
uses retained ordinary directory owners and the public object format. The minimal
bare layout contains the object/ref directories, an unborn HEAD naming the proposed
private branch and an exact local config selecting bare storage, Windows file-mode
handling and the public object format. Missing components use create-new directories
and durable no-replace files; exact existing components are retained. Initialization
invokes no `git init`, template or hook. Existing read-only Git capture corroborates
the resulting namespace and empty ref set before initialization completes.
No public private-content objects, existing
history resets or replacement database creation are permitted.

The fixed private index is `<public-git-dir>/crg-private-index`. An existing fixed
index is preserved. Otherwise, adoption copies the exact existing private Git
index to a unique temporary file inside the public Git directory. The complete
copy is flushed and verified against the captured source bytes under the retained
publication handle before an atomic no-replace rename exposes the fixed path.
Interrupted copying can leave inert metadata scratch, never a partial fixed
index; the original adopted index remains unchanged. Without an existing private
index, initialization starts from the actual adopted parent or the empty tree
under retained temporary custody. Initialization runs
against that temporary index, then publishes to the fixed path with an atomic
no-replace rename on the public Git directory's filesystem. An index created
concurrently remains preserved and causes refusal. No initializer overwrites
staged adoption state.

Initial migration copies private-classified public staged blobs into the private
object store without filters and removes only those paths from the public index.
Existing private staged contents must match conflicting public staged contents;
no implicit winner resolves a conflict. Existing private staging takes precedence
over unstaged working edits. A leaf present in the actual adopted private parent
but absent from the preserved private index is a staged deletion, not a new file.
Leftover or recreated working bytes do not restore that path. A public staged file
at the same private-classified path conflicts with the deletion and refuses before
migration writes; required configuration deletion likewise refuses rather than
being restored. Tree directory entries are not deletion paths. Newly classified,
untracked private files are captured
from the working tree. Working files and prior published history are untouched.
Unrelated preexisting staged software changes refuse admission and remain
preserved; Attach does not include an unrelated application candidate. The staged
configuration must equal the captured root configuration. Installed payload
retirement requires separate exact provenance; private classification alone does
not establish ownership of an old installed runtime.

The returned operation contains `OriginalRuntime`, `Runtime`, `ProjectContext`,
`OperationLock`, `ReadOwner`, `GitExecutableOwner`, `GuardCustody`,
`AttachmentBytes`, `CapturedInput` and the migration path report. `CapturedInput`
is the fully captured first-origin input. The same project object remains bound
to guard custody while actual namespace and index fields are refreshed. No
attachment, branch ref, completed-pair pointer or hook activation follows from
opening an operation. `ReadyForPublication` remains false.

## Pending proposal, association and completion

Admission publishes exact proposed attachment bytes at
`<public-git-dir>/crg-attachment-pending` using durable no-replace creation or exact
existing-byte agreement. This proposal locates unfinished initialization and
later recovery; no authority or review credit follows from the proposal.
Attach can repeat the same proposal before a handoff exists. Resume requires the
durable handoff, independently retained receipt, actual state validation and a
fresh review under the retained bootstrap runtime.

An ABI 2 `Stage -Paths` request can update explicitly selected private paths after
an Attach failure and before any handoff or activation. Pending staging requires
the exact existing proposal, private namespace, fixed public/private indexes,
association state and guard custody. New-database proposals require both exact
initialization records; adopted-database proposals require both records to remain
absent. Mixed or conflicting records refuse. Adopted public/private databases may
use different supported object formats; a newly initialized private database must
match the recorded public format. Selection retains ordinary Stage file and directory
expansion semantics, but every resolved selected path must be private under the union
of the preserved staged configuration and the selected candidate configuration.
When migration failed before staging any private configuration, the selection must
explicitly include a valid working `.crg-project/project.conf`; that captured file
establishes initial classification, and every preserved private index entry must
remain private. Missing selected private leaves become staged deletions.
All unselected index entries remain preserved, and `Stage -All` is refused.
Pending staging performs no broad migration, initialization, adoption, review,
publication or activation. A subsequent ordinary Attach revalidates the proposal
and runs the complete mandatory first review.

### Published instruction correction

An unactivated first attachment can require an instruction correction after both
result refs have already published. A later Resume review can block the recorded
candidate even though an earlier review permitted publication. Repeating an
unchanged review is not a correction path; rewriting the old receipt or results
would lose transaction identity.

The active approved release admits a bounded successor through the existing
`Stage -Paths` and `Attach` operations. Admission requires the exact pending
proposal and association, no active attachment or completed-pair pointer, a
strict first-origin handoff and retained receipt, and both refs exactly at the
recorded results. The receipt, retention refs, result commits, parents, trees
and message identities are validated as a preservation baseline. The old runtime
identity must agree across handoff and receipt; old prepared input is not
recompiled with a new compiler, and no historical PASS supplies review credit.

Correction staging accepts only explicit literal `AGENTS.md` and `CLAUDE.md`
paths. Each selected entry must remain a regular file with unchanged mode. The
public tree and every other private entry, including project configuration,
values and mode, must remain unchanged. Existing staged instruction corrections
are allowed so a blocked correction can be revised; unrelated staged changes,
deletions, directory expansion and `-All` refuse. Staging does not change refs,
handoff, receipts or activation state.

Attach revalidates that boundary and captures the complete corrected pair under
the active approved release. A changed instruction candidate and fresh complete
first-attachment review are required. The already-published results are real
parents, not rewritten history. Only after PASS and new immutable retention may
publication replace the exact old handoff using the normal expected-byte writer.
The original receipt remains retained. Normal expected-old publication and
activation then apply; interruption after replacement uses ordinary Resume under
the new handoff's recorded release. A blocked review leaves the old handoff and
refs unchanged, with the staged correction available for another correction.

Other recovery states remain Resume-only. This exception provides no general
abandonment, provider override, public-software correction or policy-change path.

New-database admission records initialization intent before creating the private
directory at `<public-git-dir>/crg-attachment-initialization`. The exact bytes are:

```text
crg-private-initialization v1
attachment-sha256 <sha256-of-exact-proposed-attachment-bytes>
public-git-dir <canonical actual public Git directory>
object-format <sha1|sha256>
```

The phase boundary is `<public-git-dir>/crg-attachment-initialized`, containing
the same exact bytes and published only after successful layout corroboration,
before any index or migration write. Neither record supplies review authority.
The proposal and records must agree before continuation:

- A pending new-database proposal with an absent private path can establish
  initialization intent. An existing database without initialization intent uses
  adoption; an unusable existing directory is not guessed to be owned initialization.
- Initialization intent without completion admits an absent directory or a partial
  exact minimal layout. Actual directory identities and present metadata are retained.
  Foreign config, refs, objects, hooks, links or unrelated entries refuse without
  removal or reset. Initialization adds missing components only.
- Interrupted atomic file writes can leave ordinary
  `.crg-initialize-HEAD-<guid>` or `.crg-initialize-config-<guid>` scratch files.
  Only byte prefixes of the corresponding exact proposed metadata are admitted;
  old scratch is preserved and never used as HEAD, configuration or executable input.
  Read-only corroboration creates no private operation scratch before completion.
- Exact completion selects ordinary existing-database admission, preserving later
  staged/private object state instead of reapplying the empty-layout restriction.
  A missing database after recorded completion refuses rather than recreating history.

Initialization records remain local provenance after activation. A failed Attach
does not convert a marker, partial layout or retained scratch into publication credit.

Each selected private ref has a fixed association record at
`<private-git-dir>/crg-association-<sha256-of-exact-UTF8-private-ref>`:

```text
crg-private-association v1
public-git-dir <canonical actual public Git directory>
attachment-sha256 <sha256-of-exact-proposed-attachment-bytes>
```

`Complete-CrgCentralAttachmentAssociation -Operation` requires the original
registered operation owner and validates the durable first-origin handoff against
the actual retained receipt and attachment identity. The coordinator calls this
function only after current review and durable handoff creation, before branch
publication. Atomic create-new arbitrates simultaneous adoption; an exact existing
association is idempotent, while a conflicting association remains untouched.
An unfinished exact record stays available for recovery. This record is neither
a review result nor a general-purpose private-history lock.

`Register-CrgCentralAttachmentRecovery -Operation -AttachmentBytes` registers the
coordinator's independently acquired live lock/read/executable owners after exact
pending-proposal agreement. Registration provides metadata custody, never saved
PASS credit. The coordinator retains control of receipt validation, fresh review,
expected-old ref updates, instruction materialization and guarded activation.

After completed publication, exact active attachment/pointer validation and
handoff removal, `Remove-CrgCentralAttachmentProposal -Operation` deletes only the
matching pending proposal by its retained native handle. A failed operation does
not erase a private database, index, working file or partial publication record.
Open failures return live ownership in exception data
`CrgCentralAttachmentOperation`. The caller must establish child quiescence before
`Close-CrgCentralAttachment -Operation`; uncertain descendants retain all owners.
Close releases handles, not persistent initialization metadata, and does not close
the original retained runtime owned by the launcher.

Verification uses source inspection, parser/build checks, mandatory code review,
ordinary program operation, and functional validation. Code unit tests and
unit-test-only support are banned; live testing, manual checks, ordinary program
runs, and functional validation remain permitted.
