# Completed-pair retention v1

Draft dependent storage boundary for the closed origins `paired-v1` and
`first-attachment-v1`. No installed flow, review authority, attachment activation,
branch publication, completed-pair activation or recovery execution is delivered
by this module. Receipt/prepared-pair grammars and storage serialization remain
unchanged. `private-governance-v1.md` owns publication/recovery policy;
`first-attachment-v1.md` owns initial authority.

## API and authority

The retained runtime imports dependencies before `scripts/paired-retention.psm1`:
central-context, paired-diff, paired-process, paired-tree, private-governance, project-preparation,
review-preparation, paired-review-input and paired-governance with artifact readers.
Module discovery never autoloads an unselected dependency. The caller owns the
verified runtime/module provenance, live operation lock, attached project custody,
current reviewer-child provenance and publication guards. No mutable object flag
or retained receipt supplies any of that authority.

- `Write-CrgPairRetention -ProjectContext -OperationLock -ReceiptBytes -CapturedInput
  -ReviewAttempts` validates exact ordinary data, writes immutable retention
  objects/references, and returns the same reread result as the reader.
- `Read-CrgPairRetention -ProjectContext -ReceiptSha256` requires the recorded
  retained runtime/template and both actual object databases. The result includes
  origin `paired-v1`, receipt bytes/record, private reference/commit/tree IDs,
  public result reference, fixed file buffers, validated metadata and reloaded
  context blobs. `ReadyForPublication` remains false.
- `Write-CrgFirstAttachmentRetention` and `Read-CrgFirstAttachmentRetention`
  have the respective ordinary argument shapes plus optional `-AttachmentBytes`.
  Both write APIs require the actual `OperationLock`; read signatures are unchanged.
  The explicit first-origin entry points reject ordinary receipts. Proposed
  attachment bytes are required before an actual attachment exists, parsed with
  the closed attachment reader, and bound to the exact receipt, project context,
  runtime store, private database and branches. An existing actual attachment
  must match supplied bytes; conflicting bytes never override that association.
- `Read-CrgCompletedPairRetention -ProjectContext -PointerBytes
  [-AttachmentBytes]` validates the bounded completed-pointer grammar, dispatches
  only to the named origin and verifies the raw receipt digest again after full
  storage reread. Ordinary pointers reject proposed attachment bytes. No pointer
  path, arbitrary origin name or caller-supplied reader is executable input.

First-origin contexts retain the same concrete namespace/runtime shape. Only the
private Parent may be the literal `absent`; the public Parent must be an actual
commit. Namespace-only Git commands validate paths and object directories without
substituting an OID for absent ancestry. Context construction and runtime approval
remain live-caller obligations, not conclusions of these storage functions.

ReviewAttempts supplies only ordered TranscriptBytes, VerdictBytes and
ExhaustionBytes from current captured evidence. The canonical receipt determines
leg/attempt numbers, providers, pass counts, digests and positive absence. Caller
Directory/OutputRoot values are never used. A dash requires null, not fabricated
empty evidence. Artifact and exhaustion semantics are rechecked with existing
exported readers. These checks establish retained identity, not a historical
claim that a provider child actually ran.

## Fixed storage shape

Private `refs/crg-pairs/<receipt-sha256>` points to a metadata commit, not a
governance branch. The sole parent is the actual private-result commit, retaining
private result ancestry. The exact metadata commit message is:

```text
crg-pair-retention v1
receipt-sha256 <receipt-sha256>
```

Both lines end in LF. Metadata author/committer identify Cross Review Gate;
creation time is ordinary Git metadata, not part of receipt identity. Retries use
an existing exact retained record instead of recreating or replacing that commit.
The same fixed storage frame admits either closed receipt origin. The exact
receipt header, checked by the selected closed reader, identifies the origin;
no extra pointer leaf or ordinary wire-format change is introduced.

The metadata tree is flat and admits only mode100644 blobs:

- receipt.txt, prepared-pair.txt, public.tree, private.tree;
- the seventeen existing prepared-pair fixed buffers, without renamed leaves;
- leg-N-attempt-N.transcript for every counted attempt, plus .verdict and
  .exhaustion only when the corresponding receipt digest is present.

No extra file, directory, executable mode, symlink, gitlink or arbitrary evidence
path is accepted. Raw tree-listing bytes are evidence, not imported public Git
trees. REVIEW_SRC is not copied into the private database; regular context blobs
are reloaded from the proper domain's retained candidate tree.

Public `refs/crg-results/<public-result-oid>` points directly to that existing
software commit. No private receipt-key ref, metadata commit, private blob,
alternate or cross-database parent enters the public database. The result OID uses
the public object format; receipt SHA256 and the private retention commit OID are
distinct identities, including when both happen to contain 64 characters.

The writer uses no-filter blob writes, mktree, private metadata commit-tree and
create-only reference transactions. No selected index, working file, associated
branch, crg-pair, crg-handoff or crg-materialized is written. Retention refs must be
direct. Symbolic refs, conflicting targets and malformed existing objects refuse;
no-deref and Git's zero-expected-old transaction prevent redirected writes.
Reference updates preserve admitted reference-transaction behavior and run under
the existing paired-process child-job owner. The supplied operation lock and current
guard owner bind each reference transaction's `core.hooksPath` to the exact
private execution projection at
`<private-git-dir>/.crg-hooks-<guid>/<domain>`. Registered guard ownership and the
private domain path are validated; admitted bytes and explicit no-effect entries
for absent supported hooks remain held through the child. Unbound effective
configuration is checked before and after the child; a custom hook path cannot
gain authority through retention.
Complete descendant exit is required; timeout/uncertain cleanup preserves
operation state without claiming completion.
An unconfirmed Stop/Close carries CrgPairedProcessSession and the fixed uncertain
reference in exception state. A Git child of the retention helper
(`Invoke-CrgRetentionGit`) or of the central object batch or status reader
whose exit the bounded wait after its stop cannot confirm carries
CrgUncertainGitChild, its undisposed process object. For either marker, every
retention custody open at the time (the context opener's verification, the
reader and the writer) adds its pins to CrgPairRetentionNamespacePins, with
CrgPairRetentionProjectContext, on that exception and does not dispose them.
The marker travels on the exception or an inner exception of it. The paired
diff capture (`Get-CrgPairedGitDiffEvidence`) reports failure as a result
that carries the exception as `Failure`; retention's first-attachment
recapture, paired and first-attachment preparation and first-attachment lint
attribution each rethrow it as the inner exception of their own failure. A
component that turns a failure into text drops the marker.
The operation caller must retain that exception and the underlying runtime leases
until explicit cleanup establishes quiescence; dropping the exception is not
cleanup. Confirmed quiescent failures release pins and remain ordinary failures.
Every reference and stored byte is reread. Failure preserves immutable objects
and any exact partial retention; no guessed cleanup/reset follows.

## Validation and bounds

Actual commit objects are independently hashed and parsed as raw bytes, avoiding
graft/shallow graph projection. Changed results require the recorded sole parent,
tree and exact agreed message. Unchanged results preserve the real parent and
parent tree without comparing the new message to historical message bytes.
Preparation inputs are re-read from recorded domain trees and recompiled under
the exact retained runtime. Current attachment bytes, unit, descriptor, buffers,
message blob, artifact identities and prior retained-result/parent binding must
agree. Public/private object formats are never inferred from arbitrary digests.

First writes require receipt parents to match the captured context and current
direct branch refs before retaining anything. A private `absent` parent requires
positive branch absence and an actual zero-parent result commit with the exact
agreed message. Changed adoption keeps the actual sole parent; unchanged adoption
keeps the existing commit and historical message. Both unchanged results still
require the complete mandatory first review schedule and first-origin artifacts.
No empty companion commit, invented parent or previous receipt is accepted.

Initial governing preparation is independently recompiled from the exact
retained runtime bootstrap defaults, never adopted or candidate policy. Candidate
preparation comes from the actual result trees. The private baseline is the
independently hashed empty Git tree, required as an actual object. Initial reads
and writes recapture raw patch/stat/name-status evidence against that empty tree
for private governance and the actual parent tree for public software. Recapture
uses the existing attribute-neutral helper's owned temporary directory under the
private Git directory, with exact cleanup. Adopted private ancestry never replaces
the full empty-tree review baseline. First-origin bundle, artifact and exhaustion
readers remain explicitly selected; ordinary readers are not relaxed.

Commit bytes are limited to2MiB; receipt64KiB; descriptor16KiB; tree listings and
ordinary buffers16MiB; preparations20MiB; transcripts64MiB; verdict/exhaustion
buffers16MiB. `COMMIT-LOG.txt` instead uses the shared
`Get-CrgPreparedHistoryBounds` rendered limit of201,392,128 bytes: four times
the48MiB raw history aggregate plus64KiB for authority/domain/commit framing.
Both retention writing and rereading admit the same complete escaped history as
capture and the provider host. The complete metadata payload remains at most512MiB;
the larger history leaf does not relax that independent aggregate limit. Context admits
regular files only, at most32MiB per blob and512MiB total. Missing objects refuse;
lazy fetch, alternates, replacements and caller Git environment selectors are not
fallbacks. Native directory pins retain both object namespaces through use.
Namespace roots acquire rename-denying custody in ancestor-first order, including
the common directory before a linked worktree's Git directory. Descendant-chain
pins cannot upgrade a weaker ancestor handle after acquisition.

An ordinary predecessor resolves the fixed private ref by the exact recorded
receipt SHA256. Only an actual retained ordinary or first-origin receipt is
accepted; raw receipt hash, fixed evidence-leaf shape, metadata message, sole
private-result parent and actual prior result/tree/association bindings must
match. The preceding public result-only ref must also exist exactly. Internal
closed dispatch constructs no persisted completion pointer and supplies no
approval authority. Prior runtime IDs may differ after an approved upgrade;
predecessor identity checks do not replay historical provider execution or claim
the older runtime is currently retained. Full reads require the receipt's exact
retained runtime/template. No fake ordinary parent or previous receipt adapts
the first-origin record into the ordinary schema.

Retention completion is not pair publication. The live coordinator must verify
both branch results before replacing completed-pair metadata and removing the
exact handoff. After process loss, every admissible resume state requires fresh
review under the recorded retained runtime. Stored original artifacts stay
immutable forensics and never become reusable publication permission.

## Historical draft observations and current verification boundary

The pre-integration draft recorded the observations below. Those observations
are historical and are not authorization to restore or run tests. Current
integration uses source inspection, static parsing, native compilation, mandatory
review and actual authorized operation; historical simulations supply no PASS
or installed-operation evidence.

PowerShell5.1 and7.6.5 parse/import checks and exact export checks passed. Focused
read-only checks parse and independently hash the actual capture commit's raw
bytes, preserve the exact message, and refuse wrong-format/truncated input.
Failure-only in-memory control-flow checks establish owner retention for
unconfirmed Stop/Close, and disposal for confirmed failure. Those simulations
launch no native child, write no reference and create no review receipt/PASS.
`logs/paired-retention-focused-20260907.log` records the focused output.

The additive first-origin checks in
`logs/paired-retention-first-focused-20260907.log` pass on both engines: five
closed exports, unchanged ordinary signatures, exact artifact-reader selection,
both empty-tree hashes, and namespace-only dispatch with absent private ancestry.
Actual existing root/child commit objects establish root, changed-adoption and
unchanged-adoption behavior; ordinary absence, non-root initial results and wrong
adopted parents refuse. Failure-only in-memory checks verify closed pointer
routing, unsupported-origin refusal, conflicting attachment refusal, and exact
uncertain-owner retention/confirmed-failure disposal through both writer wrappers.
These checks construct no persisted pointer, attachment, receipt or review PASS.

No complete storage write/read, provider review, installed coordinator flow,
persisted first-origin predecessor or real reference-hook timeout has been exercised.
Integration evidence remains unavailable until the actual authorized flow exists;
syntax and control-flow checks do not stand in for that evidence.
