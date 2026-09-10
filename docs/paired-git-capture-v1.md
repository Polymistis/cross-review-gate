# Paired Git capture v1

Status: implemented read-only object and attribute-neutral diff dependencies.
Index-to-tree capture is an internal object-writing dependency. Materialization,
live guards and paired publication remain subsequent integration, not claims of
these capture APIs.

## Explicit context

The retained central context owns project association discovery. Resolve Git
once, retain the executable through the launcher's existing read lease, and use
that exact executable for all children in the operation. Resolve the actual
public worktree/Git/common directories, hold Git indirection files, require a
matching public branch, and resolve the distinct attached private database.
Absent attachment permits read-only unattached Status only. A private database
must be the actual configured common root, without public/private alternates.
Both object formats come from Git, not object-ID width guesses.

The returned context contains the explicit public/private Git prefixes, actual
directories, branch refs and captured parent commit/tree OIDs, plus the selected
public index path and per-public-worktree crg-private-index path. Index paths
are internal data, never public launcher parameters or arbitrary caller choices.
This read-only step does not write-tree, refresh an index or stage content.

Controlled children remove inherited GIT_* selectors/configuration, disable lazy
fetching, replacement objects, external system/global config and optional locks.
No caller environment retargets the associated database. Retained files and
namespace checks corroborate paths; parsed context alone is not provenance or
review authority. Ref values can subsequently move and require final live checks.

## Read API

The release-local central-context module exports:

```text
Get-CrgCentralProjectContext -TargetRepo <actual root> -Context <launcher context>
Read-CrgCentralTreeBytes -ProjectContext <captured context>
  -Domain public|private -TreeOid <concrete tree OID>
Read-CrgCentralBlobBytes -ProjectContext <captured context>
  -Domain public|private -BlobOid <concrete blob OID> -Maximum <byte bound>
```

Only already imported paired-tree syntax validation is used for NUL tree output.
The tree reader requires an actual tree object, retains each original mode/type/
OID/path, and returns exact raw `ls-tree --full-tree -r -t -z` bytes. Namespace
ownership remains the paired-tree reader's separate full-union responsibility.

Blob reads require a canonical nonzero OID of the domain's actual object format,
regular Git blob object type, successful bounded size capture and exact raw bytes.
Independently recompute the Git `blob <length>\0` hash. Symlink blob contents are
data; materialization support is not inferred from a successful object read.
No private object is written into the public object store or exposed through an
alternate. A missing object refuses without contacting a promisor remote.

These APIs return captured data, not a review approval or permanent repository
association. The live coordinator retains runtime/context lifetime and repeats
required ref/index/candidate checks before publication. No persisted context
object or on-disk receipt substitutes for that coordinator.

## Preparation source capture

`Read-CrgCentralPreparationSource -ProjectContext -PublicTreeOid -PrivateTreeOid`
reads the exact private `.crg-project/project.conf`, `CROSS-REVIEW-VALUES.md` and
optional `PROJECT-MODE.md` from explicit concrete trees. Config and values are
required regular blobs with their compiler bounds; positive mode absence is an
empty buffer plus ModePresent=false. A non-file mode entry refuses rather than
becoming absence. Each configured role resolves to one regular public or private
blob; the result records the original domain/path/mode/OID binding.
Each listing receives per-domain syntax/namespace validation here. No ownership
union runs with a single captured configuration standing in for both versions.

The result carries both raw tree listings, source buffers and parsed config,
not a governing/candidate declaration or compiler output. The coordinator selects
preceding approved trees versus candidate trees independently, validates the full
ownership union, and supplies the captured buffers and retained runtime template
to the existing compiler. Capture does not infer approval from current private
HEAD, role contents or a caller-supplied tree. Role existence/type is checked here;
the later complete context capture owns role content and all other leaf buffers.

## Raw diff API

The release-local paired-diff module exports:

```text
Get-CrgPairedGitDiffEvidence -ProjectContext <captured context>
  -Domain public|private -ParentTree <concrete tree OID>
  -CandidateTree <concrete tree OID> -TempParent <owned private scratch parent>
```

Both tree identities pass the retained central reader before diff extraction.
The existing owned attribute-neutral Git closure holds the selected domain's
object directory, creates its own temporary bare database and verifies the
highest-precedence diff-attribute reset. No repository config, custom diff
driver, textconv or lazy fetch supplies review content. Only the temporary
database receives an alternate to exactly one domain object directory; neither
real database receives an alternate. Exact owned cleanup follows capture.

Success returns Ok=true, Domain, ParentTree, CandidateTree, and exact PatchBytes,
StatBytes and NameStatusBytes. Patch, Stat and NameStatus retain the existing
UTF-8 display decoding; identity uses raw bytes, never a decode/re-encode cycle.
An unchanged tree pair returns three empty byte buffers. A capture or exact
cleanup failure returns Ok=false with Reason, never usable diff evidence.

The caller supplies an already owned private scratch parent and retains the
live project context. This module does not establish installation authority,
make a combined synthetic tree, launch reviewers or modify indexes/refs. Existing
native ownership operations are retained from the review host; wrapper-only
test hooks are omitted and an added read-only open supports binary-file custody. Executable
wrappers and renderer verification code are not imported.

## Selected index capture

`git write-tree` writes tree objects and requires a fully merged index. Capture
each exact selected index separately into the corresponding owned database;
do not add --missing-ok or borrow the public index for private changes. Index
capture uses `Get-CrgCentralIndexTree -ProjectContext -Domain public|private`.
The selected path is derived from the public worktree association, never accepted
as a caller parameter: public GitDir/index or public GitDir/crg-private-index.
Missing indexes refuse; attachment/staging owns initialization.

Hold the original index read-only through the existing launcher callback, then
copy the captured bytes into a create-new private scratch directory using the
retained paired-diff module's New-CrgPairedIndexCopy/Close-CrgPairedIndexCopy
ownership helpers. Only that copy is supplied as GIT_INDEX_FILE for write-tree.
The original public/private indexes never receive write-tree's index lock,
cache-tree writeback or post-index-change dispatch. Bind only the capture child
to a retained ordinary empty-file `core.hooksPath` sentinel, not a directory.
Hook child paths remain unavailable without spawning executable no-op scripts,
which the read-only capture transport does not own as descendants.
Normal commit and review hook admission remains unchanged. Optional-lock
suppression and fsmonitor=false are additional child settings, not the mechanism
that prevents index writes.
If Git reports a split-index backing file, validate its concrete local pathname
under the captured domain Git/common directory and retain that file as well.
Confirm that the copied index resolves the same retained backing path before
write-tree. Set splitIndex.maxPercentChange=100 for the copy child: Git then
never creates a new shared index or performs creation-triggered shared-index
expiry in the real domain Git directory. Both index buffers are bounded to
64 MiB. Capture their raw SHA256 digests and the resulting concrete,
syntax-validated tree in the correct object database.
Publication retains the original index and split-index backing leases through
final ref/bookkeeping publication; selective metadata replacement does not
release either file. Instruction materialization acquires this custody before
collecting the staged inventory used for preservation decisions.
Unmerged, missing-object or malformed-index states refuse normally through Git.
No refresh, stage, ref update or repository-configuration mutation occurs here.
The child can create a lock beside the owned copied index. The read-only copy
lease prevents cache writeback; Git may ignore that writeback failure after
producing the tree. Exact cleanup must finish before returning usable evidence.
Timeout or uncertain cleanup preserves/reports the owned scratch path instead
of deleting an unidentified lock or leaving an original index lock behind.

The installed Git git-write-tree and git-rev-parse documentation are the local
references. Copy raw bytes without converting the index format or adding an
index parser. This replaces the rejected direct-index approach: write-tree's
lock, hook and writeback operations are not optional-lock sub-operations.

The read and diff APIs above are preparation dependencies. Source object capture
does not confer publication authority or remove the coordinator's final checks.

## Pinned history and private message object

`Read-CrgCentralCommitLogBytes -ProjectContext -Domain public|private` captures
up to twelve distinct commits per domain, starting with the already captured
concrete parent. Commit IDs are enumerated separately; each complete raw commit
object is read without pretty-format recoding and length-framed. Bundle assembly
independently verifies each Git object identity before labeled, data-only display.
No worktree mailmap, notes, decoration, configured pretty format or signature
child participates. Returned framed bytes remain separate per domain.

`Get-CrgPreparedHistoryBounds` in the retained `paired-review-input` module owns
the shared capture, assembly, host-read and retention limits. Each raw commit may
contain 2,097,152 bytes, matching publication's verified commit-object limit and
preserving the accepted 1,048,576-byte message plus Git headers. Each framed
domain allows 25,166,818 bytes: the 22-byte version marker plus twelve objects,
each with at most 81 bytes of framing for a 64-character object ID, seven-digit
length and separators. Both domains together allow 50,331,648 raw object bytes.
The escaped `COMMIT-LOG.txt` limit is 201,392,128 bytes: four times that aggregate
plus 65,536 bytes reserved for authority, domain and commit framing. Oversized
input refuses; message bytes and selected history are never silently truncated.
The paired-review-input module must already be imported before history capture.

The history child overrides GIT_GRAFT_FILE and GIT_SHALLOW_FILE with one owned,
retained empty file, excluding repository-local ancestry overlays independently
of replacement-ref suppression. Reuse New-CrgPairedIndexCopy with zero bytes
and Close-CrgPairedIndexCopy for custody; the empty file is never supplied as an
index. The paired-diff module must already be imported. Confirm exact cleanup
before returning usable history; preserve/report uncertain scratch ownership.
Genuinely missing ancestor objects refuse normally; no shallow truncation or
lazy fetch substitutes for the pinned history evidence.

`Write-CrgCentralPrivateMessageBlob -ProjectContext -Bytes` writes 1 through
1,048,576 exact message bytes only to the captured private database, with filters
disabled. Independently verify the returned blob identity and exact readback.
The existing Git transport supplies no-preamble binary stdin on both supported
PowerShell engines using bootstrap's established construction rule. No message
bytes enter the public object store through this helper. The coordinator still
owns the input file lease, nonempty commit-message semantics, retention ref and
receipt publication. An unreachable message object is not a reviewed commit.
