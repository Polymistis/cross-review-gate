# Paired review input v1

Status: central integration contract, 2026-09-06. The shared pure preparation
module, byte-buffer descriptor/bundle reader and constructor, retained input
materializer, native file reader and explicit provider-host branches are implemented.
Live scheduling, paired evidence collection and publication remain dependent
integration work; no attached review/commit capability follows
from importing these modules.
The v1 descriptor below covers ordinary pairs with existing parents and a
preceding completed pair only. Initial attachment/governance review needs a
separate integration contract; never fabricate parents, a previous receipt or
historical PASS to force initial attachment through this ordinary-pair ABI.

## Shared preparation boundary

`scripts/review-preparation.psm1` exports exactly these existing Codex helpers:

| Function | Responsibility |
|---|---|
| `Resolve-ConsistencyDocConfig` | Existing explicit path-value normalization. |
| `Test-ConsistencyDocInNameStatus` | Exact configured-path participation. |
| `Test-PlanConsistencyEvidenceEnvelope` | Existing finite envelope validation. |
| `New-PlanConsistencyEvidenceEnvelope` | Existing finite envelope construction. |
| `Get-TouchedPlanLines` | Raw patch section/hunk parsing. |
| `Get-PlanConsistencyReport` | Existing documentary consistency production. |
| `ConvertFrom-ProjectModeDeclaration` | Existing declaration-byte grammar. |
| `Format-ProjectModeBlock` | Existing governing/candidate mode presentation. |
| `Join-ReviewPromptAssembly` | Existing prompt assembly separators/order. |

Function bodies retain `scripts/codex/auto-review.ps1` at `d1bfbda` verbatim,
apart from line-ending representation and one intentional compatibility change:
`ConvertFrom-ProjectModeDeclaration` uses unlimited split count `0` rather than
`-1`, preserving the intended declaration grammar on both PowerShell 5.1 and 7.
Legacy wrappers retain the older engine-dependent line. Import performs no
Git/provider I/O and does not load an executable wrapper, extract an AST, or
discover ambient policy.
Legacy embedded helpers remain: existing TRACKED/LOCAL trusted extraction ships
self-contained hosts. Neither legacy wrappers nor the frozen 17-file inventory
change in this unit. The new central runtime must explicitly inventory and pin
the module before an integrated host imports the module from that runtime.

These helpers do not establish descriptor custody, repository identity, object
availability, mode acquisition, review success, or commit authority. Existing
semantics otherwise remain unchanged; no wider compatibility sweep accompanies
the declared single-line correction. The central compiler/reader must validate
explicit inputs and call the helpers only after the applicable acquisition checks.

## Internal PreparedPair invocation

The integration interface is a distinct `PreparedPair` parameter set on each
existing Codex/Claude review host:

```text
-PreparedPairPath <absolute descriptor path>
-PreparedPairSha256 <expected descriptor SHA-256>
-PreparedPublicTreeSha256 <expected public listing SHA-256>
-PreparedPrivateTreeSha256 <expected private listing SHA-256>
-OutDir <owned private attempt directory>
```

Supplying `PreparedPairPath` selects the set; do not combine legacy `Scope`,
`Target`, `Tip` or `PromptPath` selectors with the set. Codex also requires explicit
`ReviewPasses` and nonempty `ReasoningEffort`; neither is resolved from ambient
child configuration. Existing tier validation remains unchanged. Claude retains
its existing model/effort and tagged single-pass interface. Provider-specific
parameters are constrained by the live coordinator's captured policy.
No environment variable chooses a different pair or preparation.
The descriptor is input, never a receipt, PASS token or publication capability.
The two listing pins cover fixed public.tree/private.tree transfer files beside
the descriptor. These preserve the original full per-domain Git listings,
including directory entries. No listing is reconstructed from leaf inventory,
and no synthetic Git object or combined tree is created. These live-parent
transfer pins extend the internal host invocation, not descriptor v1
or the stable project configuration schema.

The live coordinator retains the expected descriptor digest, review-unit ID,
both tree OIDs, runtime identity and scheduling requirements independently in
memory. The child validates a bounded captured descriptor and all referenced
bytes before provider launch. The parent owns shared input lifetime until every
launched child is quiescent; each attempt owns a separate output/scratch area.
Read-only provider tools, ancestor-instruction checks, Git-environment isolation,
native lifetime custody and existing actual child-exit validation remain required.
Matching files alone cannot supply any of those guarantees.

### Provider-host connection

Each existing review host imports the paired modules from the executed release
only for its distinct PreparedPair parameter set, after legacy function
declarations and before any legacy native initialization. The paired path skips
ambient Git scope capture, loose prompt/mode/consistency lookup, public/default
output selection, legacy follow-up routing and destructive log pruning. Legacy
parameter sets retain the existing behavior.

`Open-CrgPairedHostInput` in `paired-preparation` accepts the internal invocation
fields plus HostScriptPath and Backend. The executed path must have the selected
`releases/<manifest-digest>/scripts/<backend>/auto-review.ps1` shape; the bounded
held manifest hashes to that identity. Read the prompt template from the same
release, acquire the parent snapshot through `Open-CrgPairedReadContext`, run the
complete file/bundle reader with the supplied pins and assert the exact namespace.
The live coordinator independently verifies and retains all runtime payloads;
the child path/hash check cannot authenticate an unapproved release by itself.

OutDir must already be the coordinator-owned private directory
`<private-git-dir>/crg-review-state/runs/<operation-id>/<attempt>` named by the
captured unit. Attempt names are bounded lowercase ASCII letters/digits/hyphens.
No public logs path or environment-selected pending destination participates.
The private coordinator owns path custody and output retention through child
completion. Runtime/input readers remain held by the host as well.

`New-CrgPairedProviderSnapshot -InputBundle -RuntimeTemplateBytes -TempParent
-Backend` revalidates and copies the input into a separate owned provider root.
The original parent input remains unchanged. Evidence files retain the fixed
names above directly beside REVIEW_SRC. Codex receives a runtime-owned root
AGENTS.md trust frame; candidate instructions remain exclusively under REVIEW_SRC.
The delivered prompt combines fixed paired framing, governing mode and compiled
governing PROMPT.md. Tool-backed reviewers receive the scope's policy-authority
statements inline and read the complete validated SCOPE.md from the evidence
snapshot; the identity listing is not duplicated in the prompt. The tool-less
Grok API transport retains the full inline scope. Existing provider tool restrictions,
ancestor-instruction checks, launch, liveness and semantic verdict logic remain.
Codex additionally corroborates each runner's reported exit file with that
current Process object's observed exit; a mismatch is invocation failure, never
exhaustion or a verdict.

The coordinator supplies exactly one nonempty, case-exact Path entry in the
raw child environment. The host asserts that native block instead of repairing
inherited aliases through the legacy managed setter; PowerShell 7 can bind a
null string as empty and leave an alias present. A different/ambiguous child
environment refuses rather than changing the captured executable search path.
Before provider/helper children launch, the host joins a fresh non-breakaway
Windows job used to count the host and all descendants. Unsupported assignment
refuses before launch. The outer coordinator separately owns kill-on-close
lifetime containment for the entire review host; local accounting is not a
substitute for that parent duty. `Complete-CrgPairedHostInput -HostInput
-ProviderSnapshot` accepts a null snapshot on early failure and returns one
boolean. After a bounded drain, require only the current host to remain in the
local job before exact snapshot cleanup. Unavailable counts, remaining children,
changed input or unconfirmed cleanup preserve scratch and force invocation
failure. Read leases are disposed without deleting the parent input. No root
process exit or artifact alone proves descendant quiescence.

`paired-process.psm1` supplies the parent-owned launch boundary, independently
of the host's local child accounting. `Start-CrgPairedReviewProcess` accepts an
explicit executable, argument array, working directory and raw environment
entries. Create the review host suspended, assign a private non-breakaway
kill-on-close job, then resume; failed assignment never resumes the process.
The raw environment must contain exactly one nonempty case-exact Path entry.
An optional caller-owned writable synchronous TranscriptStream supplies one
duplicated handle for combined stdout/stderr; no output path is accepted by
the process primitive. The caller retains the private stream and reads/hashes
the transcript only after complete job quiescence. Standard input and the
default inherited-output form remain unchanged. Provider selection/exhaustion
details stay in the private transcript rather than changing caller-facing PASS.
The caller owns policy, canonical environment construction and input/output
custody; this primitive does not discover a provider or grant review authority.

`Wait-CrgPairedReviewProcess` observes actual root exit and whole-job active
process count while retaining ownership. `Complete-CrgPairedReviewProcess`
closes only after observed root exit and zero active processes.
`Stop-CrgPairedReviewProcess` requests termination and bounded drain but retains
handles; `Close-CrgPairedReviewProcess` performs the same quiescence check before
closing. Each returns one observation with exit/count/quiescence/closed/error
fields. Timeout or unavailable observation preserves ownership and inputs, never
permits cleanup or fallback. An uncertain failed launch carries the retained
session and observation in exception data for subsequent cancellation/drain.
These functions do not replace the live coordinator or successful artifact reader.

Paired QUALITY capture uses `Write-CrgPairedFollowups -HostInput -VerdictText
-VerdictFile -Backend`. The private attempt receives an exclusively created
`followups.pending.json` record with kind `paired-followups-v1`, complete paired
identity, artifact basename and bounded structural finding fields: severity,
validated citation, canonical finding digest and optional SCOPED claim. Only the
first nonblank indented body line can supply that claim; the digest still covers
the complete finding body. Model prose remains in the verdict artifact. Claims
are not adjudicated authority and do not mint legacy single-tree tags or prune
exemptions. Paired artifacts are retained. `Publish-CrgPairedFollowups` derives
the same structural rows from the current successful artifacts after complete
review and immutable receipt retention, before publication or attachment
activation. Missing or malformed pending sidecars cannot suppress findings:
the coordinator independently validates and parses the captured verdict bytes.
Resume performs the same promotion using the fresh review, after retaining the
recovery correlation record; an older PASS supplies no current rows.

The private index is an append-only directory at
`<private-git-dir>/crg-review-state/followups/`. Each `<sha256>.json` transaction
has kind `paired-followups-index-v1`, receipt/input/runtime identities and
successful-attempt finding rows with private artifact paths and digests.
`publicationEvidence: false` is literal: reviewed findings can remain indexed
when later publication fails, and only the completed pair proves landing.
SCOPED claims remain unadjudicated data. No legacy index tags, automatic pruning
or authority to dismiss a finding follows from promotion.

Promotion creates and flushes a held temporary file, validates complete bytes,
then publishes by same-parent no-replace rename under project operation custody.
A matching existing transaction is validated before idempotent acceptance;
conflicting contents are preserved. Unpublished `.crg-followups-*` files are
failure evidence, never index entries. Readers accept only complete UTF-8 JSON
with the matching payload digest and schema, not a filename alone. Triage copies
findings into privately reviewed project work; indexed transactions are not edited.
Capture or promotion failure warns with the preserved location and returns a
warning status without converting a passing QUALITY verdict into a blocker.

`Write-CrgPairedExhaustionSidecar -HostInput -Path -Backend -SignatureClass
-ProcessOutcome` exclusively writes the existing `token-exhaustion` kind with
paired-v1 identity instead of reviewTreeOid. The host calls this writer only
after the unchanged positive provider-specific classifier succeeds. Missing
durable evidence prevents exit4. No synthetic verdict accompanies positive
verdict absence, and a parent must validate the entire identity and current
attempt outcome before scheduling the existing full-leg substitute.

`Read-CrgPairExhaustionBytes` in paired-governance accepts the captured unit,
object formats, descriptor/display digests, expected backend and scheduled pass
count alongside the complete sidecar bytes. Validate the exact twelve-field
flat machine-string schema without collapsing duplicate keys, including full
paired identity, scope, calendar-valid producer timestamp and the actual
provider-specific signature/outcome grammar. Unknown or legacy single-tree
fields refuse. Codex errored-pass counts must fit the scheduled complete leg;
Claude requires the existing single-pass invocation/error-envelope outcome.
The reader performs no file or provider operations and returns
ReadyForPublication=false. Matching metadata never proves actual exit4,
positive classification or complete descendant drain; the live parent owns
those observations before automatic substitution.

### Byte-buffer API implemented before host integration

`scripts/paired-review-input.psm1` exposes:

```text
Read-CrgPreparedPairDescriptorBytes -Bytes -ExpectedSha256 -GoverningConfigBytes
Read-CrgPreparedPairBundleBytes -DescriptorBytes -ExpectedDescriptorSha256
  -Buffers -GoverningConfigBytes -CandidateConfigBytes
  -PublicTreeBytes -PrivateTreeBytes -RuntimeTemplateBytes -ContextBlobBuffers
```

`Buffers` is an exact, case-sensitive fixed-name map of byte arrays for the
bundle table below. `ContextBlobBuffers` maps each inventoried blob leaf's exact
canonical path to byte-array content; gitlinks have no blob buffer. Empty arrays
are valid content, null/non-byte values are not. Parameters are explicit data,
not filesystem selectors. The caller owns bounded acquisition and custody.

The caller imports `private-governance`, `paired-governance`, `paired-tree`,
`review-preparation` and `project-preparation` from the same retained approved
runtime. RuntimeTemplateBytes is the exact independently retained runtime prompt
template, including document-role policy boundaries. The byte reader
resolves only already imported exported functions by named module/command;
missing/ambiguous dependencies refuse without ambient module autoload. Module
names do not authenticate runtime files, so retained-runtime provenance remains
an explicit caller obligation.

The descriptor reader checks exact grammar/digest and consistency selection
against `Read-CrgProjectConfigBytes` output. The bundle reader reuses
`Read-CrgReviewUnitBytes` and `Read-CrgPairedTreeBytes`, checks all fixed digests,
leaf identity/content correspondence and finite consistency evidence. The
candidate config bytes must equal the regular private candidate leaf at
`.crg-project/project.conf`. A touched report is recomputed from the selected
candidate blob and raw-domain patch; a malformed/indeterminate or mismatching
envelope refuses. An alleged untouched name-status cannot hide a positively
parsed section in that raw patch. Leaf and message bytes also reproduce the
named Git blob OIDs using the respective object format; existence, retention
and listing-to-pinned-tree provenance still require the caller's actual capture.

Both preparation buffers are reparsed and exactly recompiled with the required
kind, unit runtime identity and supplied runtime template. Each config must match
the corresponding explicit config input. PROMPT.md must equal the governing
compiled prompt. PROJECT-MODE.txt must equal New-CrgPairedModeBlockBytes with the
unit's private-parent OID. Candidate values and mode are checked against regular
private candidate blobs; candidate role paths must resolve to regular blobs.
Non-file mode presence refuses here rather than inventing absent-mode evidence;
metadata tree parsing alone does not implement non-file materialization support.
Governing inputs still require independent preceding-tree provenance.

Returned metadata includes descriptor/unit fields, exact buffer digests,
recompiled preparations, context leaf identities, consistency state and decoded
display buffers. Success
is explicitly `descriptor-metadata-only` or `bundle-metadata-only`, with
`ReadyForReview = false`. The bundle's `PendingBindings` names preceding private
config/values/mode/role provenance, scope/display-diff/history projection,
pinned Git object/diff capture, private message-blob provenance, materialization/
custody and retained runtime. The descriptor's pending fields name governing
config provenance and retained runtime/custody. The compiler owns the preparation
encoding; no returned metadata becomes an approval token.

## Descriptor grammar and fixed bundle

### Staged Git acquisition into the byte constructor

`scripts/paired-preparation.psm1` supplies the dependent internal
`Get-CrgCentralStagedReviewInput -ProjectContext -OperationId -PreviousPairSha256
-MessageBytes -TempParent -MaximumBlobBytes -MaximumContextBytes` interface.
The caller imports the capture, compiler and bundle modules from the retained
runtime first. No launcher operation or public caller override is added here.

Capture and check the attached project record against the explicit context,
then capture both retained indexes. Two unchanged trees return HasChanges=false
without generating a review unit, diff or message object. Otherwise capture
preceding preparation from the recorded parent trees and candidate preparation
from the staged trees, compile both with the retained runtime prompt bytes,
validate the full preceding/candidate ownership union, and read every blob leaf
from the original domain. Explicit caller bounds apply per blob and to the
total context; exceeding a bound refuses without truncation or omission.
Symlink bytes and gitlink metadata remain data, not materialization support.

Capture both raw-domain diffs and pinned histories, write/read back the exact
message blob only in the private database, and call the deterministic constructor.
Identity fields come from captured association, parents, indexes and runtime;
only the live coordinator supplies the operation and preceding-pair IDs.
The result retains indexes, both source bindings, context bytes, message identity
and assembled bundle. All successful results have ReadyForReview=false.

This command performs Git preparation, not approval. The preceding-pair digest
is an identity input, never proof that current parents were approved. The live
coordinator must establish that relation before calling, retain all source and
scratch custody, and complete object retention, materialization, provider-child
provenance and final guards before publication. No receipt is invented, no ref
or index is rewritten, and no environment variable substitutes for these duties.

### Deterministic byte assembly

`New-CrgPreparedPairBundleBytes` constructs the existing descriptor/bundle from
explicit IdentityFields, PublicObjectFormat, PrivateObjectFormat,
GoverningPreparationBytes, CandidatePreparationBytes, PublicTreeBytes,
PrivateTreeBytes, RuntimeTemplateBytes, ContextBlobBuffers and EvidenceBuffers.
IdentityFields contains only operation/project/attachment, actual public worktree
and Git/common/private Git directories, both refs/parents/candidate trees,
previous-pair and runtime-manifest-sha256. Derived preparation/diff/report/message
digests and the message blob OID are calculated, never accepted as overrides.

EvidenceBuffers is an exact case-sensitive map of raw byte arrays:
public.patch, private.patch, public.stat, private.stat, public.name-status,
private.name-status, public.history, private.history and COMMIT-MESSAGE.txt.
The constructor recompiles both preparations, validates the full candidate tree
ownership union and every supplied blob, builds an ordinal context inventory,
and uses the same consistency producer as the reader. PROMPT.md and mode come
only from the compiled preparations. Display diff combines the raw patches beneath
fixed domain labels without changing either raw patch. History capture separately
enumerates pinned commit identities and length-frames exact raw commit-object
bytes, without pretty-format recoding. The assembler verifies each object's Git
identity, the domain's captured parent and bounded distinct entries before display.
`Get-CrgPreparedHistoryBounds` supplies the shared bounds: at most twelve commits
per domain, 2,097,152 bytes per raw commit object, 25,166,818 framed bytes per
domain and 50,331,648 raw object bytes across both domains. The per-object limit
matches verified published commits, including the accepted 1,048,576-byte message
and Git headers. Overflow refuses rather than shortening messages or history.
COMMIT-LOG.txt carries the existing data-only authority header and machine-authored
domain/commit labels. Every raw content line, including commit metadata, receives
the quote prefix after injective byte escaping: backslash becomes `\x5C`, LF
separates quoted lines, and every other byte outside printable ASCII becomes `\xNN`.
Raw object identity and framing remain separate from that display transformation;
the descriptor binds the displayed channel through retention and fresh-review
recovery. Display escaping does not alter raw patch or message identity.
The rendered history limit is 201,392,128 bytes: four times the combined raw
limit plus 65,536 bytes for fixed authority, domain and commit framing. LF and
quote prefixes consume at most three characters per raw LF; other escaped bytes
consume at most four, so full admitted raw history remains representable.
Prepared file readers require an explicit `MaximumHistoryBytes`, clamped to this
closed limit, independently of `MaximumBufferBytes`. The common provider host
supplies the complete history bound while preserving the ordinary 20 MiB buffer
limit. Retention uses the same history leaf bound and keeps the separate 512 MiB
complete metadata limit. Provider context/request limits remain independent:
valid history can exceed a provider's complete-input capacity without being
malformed; such a failure supplies no review approval or truncation authority.
SCOPE.md derives from the identity fields and states the preceding/candidate
governance boundary. No arbitrary displayed scope, prompt, mode, report or
inventory is accepted. The final bundle passes the existing complete byte reader
before return.

Success returns DescriptorBytes, DescriptorSha256, Buffers and Metadata, with
ReadyForReview=false. This is deterministic data assembly, not Git acquisition,
materialization, provider launch or approval. Pinned-history/object provenance,
preceding approval, message retention, and live custody remain caller duties.
Initial attachment still does not use fabricated parents or a previous receipt.
Input/returned byte arrays are data, not an immutable capability; the coordinator
owns lifetime and rechecks exact serialized hashes at the materialization boundary.

`prepared-pair.txt` uses strict UTF-8/no BOM, LF only and a final LF. Maximum
16,384 bytes. Reject CR, NUL, DEL, other C0 controls, blank/comment records,
unknown fields, duplicates and different ordering. Fields are exactly:

```text
crg-prepared-pair v1
review-unit-sha256 <sha256>
public-object-format <sha1-or-sha256>
private-object-format <sha1-or-sha256>
consistency-document <selection>
context-inventory-sha256 <sha256>
display-diff-sha256 <sha256>
scope-sha256 <sha256>
prompt-template-sha256 <sha256>
project-mode-block-sha256 <sha256>
public-stat-sha256 <sha256>
private-stat-sha256 <sha256>
public-name-status-sha256 <sha256>
private-name-status-sha256 <sha256>
commit-log-sha256 <sha256>
```

`sha256` is exactly 64 lowercase hexadecimal characters. One ASCII space
separates a field name from the value. `selection` is exactly `-`,
`public <canonical path>`, or `private <canonical path>`, using the scoped
configuration grammar in `private-governance-v1.md`. Object formats are literal
`sha1` or `sha256`, verified against the actual associated databases. No path,
object format or selection is an executable selector or authority override.

All files below have fixed names relative to the owned descriptor directory;
the descriptor cannot redirect a file to an arbitrary path. Digests cover exact
raw bytes without newline normalization. Empty evidence files remain real files
with the digest of empty bytes, not missing-file exceptions.

| Bundle path | Binding |
|---|---|
| `review-unit.txt` | `review-unit-sha256`; exact receipt identity prefix described below. |
| `governing.preparation` | Identity prefix's governing-preparation digest. |
| `candidate.preparation` | Identity prefix's candidate-preparation digest. |
| `public.patch`, `private.patch` | Identity prefix's respective raw-domain diff digests. |
| `PLAN-CONSISTENCY-REPORT.md` | Identity prefix's consistency-envelope digest. |
| `COMMIT-MESSAGE.txt` | Identity prefix's message digest and retained private blob. |
| `context-inventory.txt` | `context-inventory-sha256`. |
| `DIFF.patch` | `display-diff-sha256`. |
| `SCOPE.md` | `scope-sha256`. |
| `PROMPT.md` | `prompt-template-sha256`. |
| `PROJECT-MODE.txt` | `project-mode-block-sha256`. |
| `public.stat`, `private.stat` | Respective stat digests. |
| `public.name-status`, `private.name-status` | Respective name-status digests. |
| `COMMIT-LOG.txt` | `commit-log-sha256`; labeled pinned-domain history only. |
| `REVIEW_SRC/` | Exact validated context inventory and both pinned Git trees. |

`review-unit.txt` is the exact `crg-pair-receipt v1` prefix from that header
through the `message-sha256` record's LF, as defined in
`private-governance-v1.md`. No `review-unit-sha256` record, results or review
attempts occur inside the prefix. This is not a complete receipt. Strictly parse
the prefix with `Read-CrgReviewUnitBytes -Bytes -PublicObjectFormat
-PrivateObjectFormat` from `scripts/paired-governance.psm1`; the result supplies
`Schema`, `ReviewUnitSha256` and `Fields`. Construct prefixes with
`New-CrgReviewUnitBytes -Fields -PublicObjectFormat -PrivateObjectFormat`,
retaining the same canonical receipt identity
validation. Do not introduce another prefix parser, placeholder results or a
historical PASS. The prefix binds operation/project/attachment,
actual database/worktree identities, refs, parents, both trees, preceding pair,
runtime, both preparation buffers, raw patches, report and message. The live
parent corroborates those fields before accepting child output.

The preceding approved preparation supplies compiled configuration, project
values/roles, governing mode and trusted prompt context. The candidate buffer
supplies the distinct proposed preparation for review. The compiler owns the
buffer encoding; the descriptor binds exact already-compiled bytes, not a
second configuration parser. Validate each displayed prompt/mode/scope buffer
against that captured preparation and pinned context before writing the
descriptor. Candidate instructions never become trusted root framing. The
expected descriptor digest binds the entire bundle presentation in addition to
the receipt's review-unit identity; neither digest substitutes for live custody.

## Exact context and collision refusal

### Retained filesystem snapshot

The central-only `paired-diff` module also owns
`New-CrgPairedInputSnapshot -CapturedInput -RuntimeTemplateBytes -TempParent`,
`Assert-CrgPairedInputSnapshot -Snapshot`, and
`Close-CrgPairedInputSnapshot -Snapshot`. Reuse the existing native relative
create-new, ordinary-file/directory identity and exact-cleanup helpers; no
executable wrapper or renderer SelfTest is loaded.

Revalidate the complete captured bundle before creating any snapshot path.
Create a unique owned directory below the explicit private temporary parent,
write the descriptor and fixed buffers, and materialize the exact REVIEW_SRC
namespace. Also retain both raw tree transfer files and return their independent
PublicTreeSha256/PrivateTreeSha256 pins for the host invocation. The v1 descriptor
and fixed bundle remain unchanged. Ordinary binary files are byte-exact;
explicit empty Git directories remain directories. Symlinks and gitlinks are
unsupported by this initial materializer and refuse before creating files.
Every file is created relative to a retained parent and remains read-shared
without write/delete sharing; content hashes and ordinary single-link identity
are checked through retained handles. Recheck the complete path/type set and
digests before passing a snapshot to a host.

The returned snapshot is retained input, not a provider working root or review
approval. `Read-CrgPreparedPairFiles` reads that snapshot using the live caller's
retained `ReadFile -Path -Maximum` callback. The caller supplies the descriptor
and two raw-tree digest pins, expected retained runtime identity/template and
explicit per-buffer/blob/complete-context byte bounds. Require one present
byte-array result within each bound. Parse the digest-bound descriptor fields
before interpreting object formats, recompile both preparations, validate the
complete paired tree namespace before resolving REVIEW_SRC leaves, and rerun
the full bundle reader before returning metadata. Ordinary source bytes remain
exact; this reader supports the same regular-file modes as the materializer.

The callback owns no-follow directory/file leases through child completion;
the live host/coordinator still checks the exact materialized namespace. This
reader neither creates/deletes files nor claims native custody from a callback
result, and returned ReadyForReview remains false. A saved snapshot plus matching
digests cannot establish preceding approval or replace current-run provider and
publication checks.

`Open-CrgPairedReadContext`, `Assert-CrgPairedReadContext` and
`Close-CrgPairedReadContext` provide the host's native input read leases through
the existing paired-diff native boundary. Opens are relative to retained ordinary
directory handles, regular files deny write/delete sharing, and assertions bind
file bytes plus the complete namespace to the validated bundle. Directory readers
share delete access to coexist with the coordinator's retained DELETE-capable
creation handles; the live coordinator still owns namespace custody and must not
release or delete the snapshot before every child is quiescent. Reader close
only releases handles and never deletes coordinator-owned input. No standalone
read context supplies preceding approval or provider-exit evidence.

Provider snapshots additionally project the validated `PLAN-CONSISTENCY-REPORT.md`
bytes to the governing template's canonical
`CODEX_REVIEW_EVIDENCE/PLAN-CONSISTENCY.txt` path under the same retained custody.
The provider-only copy does not change the parent input namespace, descriptor
or compiled prompt bytes.

Candidate instruction files remain below REVIEW_SRC. A review host
still establishes trusted root framing, ancestor-instruction isolation, exact
descriptor acquisition and provider restrictions. No instructions from this
snapshot are implicitly loaded as trusted root policy.

The live owner closes the snapshot only after all launched children are
confirmed quiescent. Close performs the existing identity-matched cleanup;
uncertain cleanup preserves/reports residual paths and never recursively deletes
a replacement. A constructor failure uses the same cleanup without launching a
child. Snapshot objects and descriptor hashes do not establish preceding approval,
current-run PASS or permission to publish.

Capture both complete candidate trees and required unchanged context even when
only one domain changes. Validate both Git namespaces and the union before any
materialization. Retain the existing Windows tree-path/type checks; additionally
reject public/private leaf/type overlap, case aliases, file/directory collisions and paths
contradicting the union of preceding/candidate private inventories. No overwrite
priority, public copy of private objects, private Git alternates or synthetic
combined Git tree is permitted.
Ordinary exact-case directory containers may be shared: public
`docs/requirements.md` and private `docs/PLAN.md` coexist below `docs/`.
Original per-domain directory entries validate each namespace but do not become
duplicate mixed-domain inventory entries.

`context-inventory.txt` is strict UTF-8/no BOM, LF with final LF, starting with
`crg-pair-context v1`. Each following record is exactly:

```text
entry <public-or-private> <mode> <oid> <sha256-or-dash> <canonical path>
```

Records are ordered by canonical path using ordinal comparison; duplicate paths
or Windows aliases refuse. Split the first five spaces only, preserving literal
spaces inside the path. Path admission uses the existing validated Windows
tree-path model through `Read-CrgPairedTreeBytes`, not shell/pathspec
interpretation. Inventory records describe every non-`040000` leaf exactly once,
not directory containers. `oid` must match the named domain's object format and
supplied tree entry; the pure parser cannot authenticate that listing against a
Git database. Blob modes `100644`, `100755` and `120000` carry exact blob-byte
SHA-256 values; mode `160000` carries dash and no blob buffer. Before activation, the materializer
must support every accepted tree-entry type explicitly; a symlink/gitlink cannot
silently become an omitted file or followed external tree. Unsupported entry
types refuse before launch. Metadata acceptance of a symlink/gitlink is not
materialization support or authority to follow a target. Regular-file and
symlink blob entries never accept dash.

`REVIEW_SRC/` contains the canonical union, not an authority-bearing checkout.
Every materialized regular file must match the inventory's raw digest and named
Git blob; no undeclared path may appear. Original domain/mode/OID remain in the
inventory for citations and identity checks. All candidate AGENTS, CLAUDE,
configuration, values, history and mode files stay below this data boundary.
Required unchanged governing context must be distinguishable from proposed
candidate context. The child cannot replace pinned preparation by rereading
live private HEAD, ambient configuration, or loose project files.

## Raw-domain parsing versus displayed evidence

Capture each domain's patch/stat/name-status against the recorded parent and
candidate tree using existing attribute-neutral acquisition. Keep raw patches
unaltered. `DIFF.patch` is the exact labeled combined presentation for reviewers;
display labels and omission evidence may occur there. `display-diff-sha256`
and the artifact's `DIFF-SHA256` always hash those displayed bytes, not either
raw patch, a recomputed approximation, or the context inventory.

The preceding approved `consistency-document` selects either the public or
private raw patch, corresponding name-status and regular candidate document
blob. Public nested requirements remain supported. The configured selection
must match the approved inventory and actual candidate blob. Candidate config
changes are review data and cannot disable the preceding duty or authorize
different rules for the current review.

For a touched configured document, call `Get-PlanConsistencyReport` with exact
candidate text, that domain's raw patch and the exact configured path. Never
feed combined labels, skipped-untracked footers or the other domain's patch
into the parser. Disabled configuration yields `skipped-not-configured`;
verified absence from the selected domain's name-status yields
`skipped-not-in-diff`. Missing/failed acquisition is not verified absence.
Preserve existing supported input decoding and fail-closed diagnostics.

Generate one envelope and validate with `Test-PlanConsistencyEvidenceEnvelope`
before either host launches. A produced report's documentary findings retain
existing QUALITY treatment; missing/malformed or required indeterminate evidence
retains the existing refusal/BLOCKER boundary. Claude's legacy no-producer guard
remains unchanged for legacy scopes; only validated PreparedPair inputs can
use this shared producer. Both hosts present the same report and instructions.

## Explicit paired artifact identity

Paired output extends producer-owned metadata, not the reviewer verdict body
protocol. The paired header has exactly these ten lines, then one blank line,
then the existing semantic verdict body:

```text
REVIEW-INPUT: paired-v1
PREPARED-PAIR-SHA256: <sha256>
REVIEW-UNIT-SHA256: <sha256>
REVIEW-PUBLIC-TREE-OID: <public-oid>
REVIEW-PRIVATE-TREE-OID: <private-oid>
DIFF-SHA256: <display-diff-sha256>
REVIEW-BACKEND: <codex-or-claude>
REVIEW-EFFORT: <existing provider effort value>
REVIEW-SEVERITY-CONTRACT: blocker-only
REVIEW-DURATION-SECS: <existing canonical duration value>

<existing verdict body>
```

The wrapper emits metadata from validated captured inputs, never model prose.
`New-CrgPairArtifactBytes` and `Read-CrgPairArtifactBytes` in paired-governance
implement this metadata format. Both take the caller's exact review-unit bytes,
object formats, descriptor/display-diff digests and provider. The constructor
roundtrips through the reader; only the exact outer header supplies identity.
Quoted identity-looking lines in the body remain prose, not metadata. The reader
uses the existing provider effort/duration grammar. The complete artifact is
bounded to the existing artifact acquisition limit.
Returned VerdictText is unclassified: semantic verdict/group validation and
observed current child exit remain separate duties. These pure functions
perform no file I/O or provider calls and cannot enable paired review alone.

`Read-CrgSuccessfulPairArtifactBytes` takes the same reader parameters plus
the live caller's ScheduledPassCount. Reuse the existing pure
Get-VerdictExitCode body from auto-merge without changing category, severity or
VERDICT precedence. Claude requires one unframed successful body. Codex requires
the exact producer pass separators, ordered contiguous pass numbers, matching
denominators/count and complete successful bodies. Unknown/malformed separators,
leading content, failed-closed envelopes or any unsuccessful body refuse.
Generated group boundaries retain the producer's LF framing; model prose within
a body retains the existing classifier semantics. The general metadata reader
continues to admit unsuccessful forensic bodies and does not gain success authority.
The successful reader returns per-pass classifications with
ReadyForPublication=false: saved successful text cannot prove current child exit,
required policy, runtime custody, completed review scheduling or publication guards.

Reuse existing effort/duration validation and semantic verdict/union checks.
There is deliberately no `REVIEW-TREE-OID`: no single real Git tree identifies
the pair. Existing six-line single-tree headers remain unchanged. Paired readers
must recognize this exact era, not loosen legacy header allowlists or accept a
public-only identity as equivalent. Compare both tree OIDs, unit digest,
descriptor digest and displayed diff digest with the live parent's pins, plus
actual backend, required passes, current child exit and semantic result.

Existing private follow-up capture and exhaustion evidence must retain this
same paired identity before attached mode activates. A public-only tree/diff
SCOPED key cannot grant a paired prune exemption. Exhaustion still requires the
existing positive classification and complete-leg automatic fallback. Claude
may emit an exhaustion sidecar and exit before constructing a verdict artifact;
record positive absence rather than fabricating a successful/empty verdict.
Protected changes retain separate complete review legs. Positively identified
exhaustion permits automatic substitution without distinct effective providers;
mandatory pass coverage remains coordinator policy. This contract introduces no provider, quota switch or review bypass.

The smallest downstream change is an explicit paired-context arm in existing
capture/SCOPED authority resolution and artifact projection. Supply the captured
preceding and candidate document bytes with original domain/path/OID, private
capture destinations and paired identity; do not let a late default resolve
authority documents through public Git, current private HEAD, loose working
files or public logs. The same rule covers output-path selection, follow-up
index/prune decisions, completion capture and exhaustion sidecars. All paired
evidence remains private. An unchanged legacy reader must refuse paired input
or report unsupported format, never accept a partial single-tree projection.
No existing reader is broadened by this extraction unit.

Every artifact, descriptor and receipt is identity/forensics, never persisted
PASS authority. Only the live coordinator's current-invocation provenance plus
both guard sets can authorize publication. Recovery after process loss performs
fresh exact-pair review under retained preceding governance/runtime, including
when the recorded pair has already advanced both refs. Existing single pending
handoff and finite recovery rules remain owned by `private-governance-v1.md`.

## Integration acceptance boundary

The preparation module's verification is nine-function parity with the single declared
split-count exception, import/export/parse checks and bounded existing-input
function checks. No new suite or provider
invocation is needed for this extraction unit. A later host/coordinator unit
must implement descriptor custody, compiler bindings, both-domain materialization,
exact paired artifact readers/capture and live scheduling together before
claiming combined review works. No legacy inventory removal or runtime AST
loading is a shortcut for that integration. Byte-reader verification covers
only explicit in-memory metadata/content inputs; success cannot certify the
pending compiler, Git or filesystem bindings listed by the returned object.

## Live dispatch and first-attachment host integration

`scripts/paired-review-session.psm1` exports `Invoke-CrgPairedReviewSession` and
`Invoke-CrgFirstAttachmentReviewSession`, each requiring the retained runtime,
captured input and canonical authoring agent. The distinct first-attachment origin
uses runtime bootstrap authority, never a fabricated preceding pair. Both hosts
accept `-PreparedOrigin paired-v1|first-attachment-v1` with exact descriptor and
public/private tree-transfer digest pins. Origin-specific readers and artifact
writers reject cross-origin records.

The dispatcher owns each suspended child in a private kill-on-close job, supplies
an explicit standard-handle inheritance allowlist and waits for observed root exit
plus zero active descendants before acquiring verdict evidence or releasing input.
After observing root exit with descendants still active, the coordinator allows
one further bounded ten-second drain interval, then fails the attempt through
owned termination and close. Unconfirmed cleanup retains native, input, output
and transcript custody. This post-exit bound imposes no wall-clock limit on a
reviewer host that remains alive and never substitutes for review acceptance.
Separate required review legs remain separate complete calls even when exhaustion
substitution selects the same effective provider. Saved verdicts supply no live
publication authority. The caller receives current review identity, legs, attempts
and private evidence location; final publication guards remain the caller's duty.

Snapshot-construction exceptions retain partial ownership and exact cleanup state.
Both hosts retain the original failure and refuse generic scratch cleanup after
such a failure. No pathname-based retry may reinterpret disposed custody as an
owned snapshot. Successful construction retains the existing exact cleanup path.

The optional `scripts/grok/auto-review.ps1` API host uses the same captured input
and semantic verdict/artifact boundary without execution tools. Governing private
configuration must explicitly enable the supported API/model/effort record.
Initial routes remain Codex/Claude; only two complete positive-exhaustion attempts
permit the bounded third Grok attempt. Default policy still permits at most two
attempts. Full context bounds refuse without silently omitting source, and no
HTTP status alone proves account exhaustion. Grok remains inactive on default
consumer configuration; no API call is required merely to install the adapter.

The operator code unit-test ban applies to this integration. Source inspection,
static parse, native compilation, ordinary operation, applicable functional
testing, and mandatory review provide verification. Older fixture or suite
references remain historical; no testing category beyond code unit tests is
prohibited merely by category.
