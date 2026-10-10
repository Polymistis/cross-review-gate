# Private governance v1: attachment and paired commits

Status: configuration/attachment and paired-record parsing plus literal ownership
classification authorized, 2026-09-06;
live attachment, review and publication integration remain pending. This is the dependent launcher-ABI-1/config-schema-1 contract
for `central-runtime-v1.md`, not a change to released TRACKED or LOCAL behavior.
One central activation governs every attached project's next operation. No
attachment or project configuration contains a runtime version or release pin.

## Supported entry points

The proposed stable entry is `<runtime-store>/launcher.ps1`. Parameter forms
below are interfaces, not multiline shell examples:

```text
launcher.ps1 -TargetRepo <root> -Open
launcher.ps1 -TargetRepo <root> -Status
launcher.ps1 -TargetRepo <root> -Stage -All
launcher.ps1 -TargetRepo <root> -Stage -Paths <relative-path-array>
launcher.ps1 -TargetRepo <root> -Commit -MessageFile <path>
launcher.ps1 -TargetRepo <root> -Resume
```

`TargetRepo` is mandatory; no current-directory or ancestor fallback selects a
project. Ordinary work is edit, `-Stage`, then `-Commit`. Both software and
private documents participate in these same commands. No caller supplies a
private index, alternate Git directory, provider-skip flag, or receipt override.
The launcher resolves the attachment, captures and retains one centrally active
release under the short store lock, then delegates to that release. Children
receive the captured release identity rather than rereading `active-release`.
The central lock is released before provider work; the per-worktree gate lock
serializes paired staging/commit/open/recovery. `-Status` reports pending state
without recovering or editing anything. No new provider is authorized by attach.

## Storage and attachment

```text
<public-worktree>/
  .crg-project/project.conf
  AGENTS.md, CLAUDE.md, CROSS-REVIEW-VALUES.md
  PROJECT-MODE.md, PLAN.md, History.md       # when selected/present
<public-git-dir>/
  crg-attachment
  crg-private-index
  crg-pair                                 # latest completed pair receipt ID
  crg-handoff                              # one pending publication, when present
<private-git-dir>/                          # separate Git object database/refs
```

Root governance files are the private repository's working files at the public
worktree root, not duplicate editable copies. The gate supplies the separate
database/worktree/index association internally. New attachments default the
private database to `<public-common-dir>/crg-governance.git`; explicit adoption
may use an existing database such as `.git/local-development.git` in place.
Existing objects, refs, staged changes, and working edits are inventoried and
preserved. Adoption never silently replaces a private index or resets a branch.

Each public worktree has one attachment, its own private index, and a distinct
private branch association. A second attachment cannot write the same private
branch concurrently. Detached/unborn public HEAD and in-progress Git merges are
outside initial attachment; report the required explicit branch resolution.
Normal branch switching requires an explicit association, not reuse of the old
private branch merely because the root path is unchanged.

`crg-attachment` is operator-custodied metadata, not a review-policy source.
Maximum 16,384 bytes; strict UTF-8/no BOM, LF records, final LF; exact field order:

```text
crg-attachment v1
project-id <32-lowercase-hex>
runtime-store <canonical-absolute-local-path>
private-git-dir <canonical-absolute-local-path>
public-ref <full-refs/heads/name>
private-ref <full-refs/heads/name>
```

No extra, duplicate, blank, or control-bearing records are admitted. Split each
field at the first ASCII space; spaces inside absolute paths remain literal.
Absolute paths use a local drive letter and backslashes, not UNC/device paths,
drive-relative paths, a drive root, or trailing separators. Apply the component
rules below; `.git` is permitted only in the private database's absolute path.
Full branch refs must also satisfy Git ref grammar, including rejection of
`..`, `@{`, whitespace, forbidden ref characters, dot-prefixed components and
`.lock` suffixes. Parsing validates text, not repository existence or custody.
Resolve the actual worktree/common-directory identities and configured private
database before use; the two databases must be distinct and share no object
alternates. Attachment paths cannot select a project configuration filename,
different policy, fallback runtime, or public object destination. A moved store
or database needs explicit attachment repair, not directory searching.

Private storage must be outside the public worktree, except beneath the actual
protected `<worktree>/.git` directory when that directory is the captured public
Git directory or common directory. A custom metadata directory inside the
worktree is still publicly stageable and does not qualify. The private database
cannot equal either public Git metadata root, occupy the public object store or
any descendant, or contain the public worktree. External non-overlapping storage
and the ordinary main/linked-worktree defaults remain supported. New attachment,
existing attachment admission and pending recovery apply the same canonical path
rule; configuration ownership or an existing association cannot exempt storage.

Initial attachment and association changes are explicit operator operations
whose exact bootstrap interface belongs to the integration unit. Review the
initial private candidate with the active approved runtime's bootstrap rules
and actual existing software state before activation. New governance cannot
approve itself; existing public history is not retrospectively re-reviewed.

## Editable project configuration: schema 1

The fixed source is private `.crg-project/project.conf`. No executable config,
JSON/YAML library, general parser framework, interpolation, include, shell value,
or environment fallback is involved. Use strict built-in UTF-8 decoding and
literal/anchored record validation. Validate the whole file before using a field.
Maximum 65,536 bytes, no BOM/CR/NUL, LF records with final LF. Outside LF, reject
C0 controls and DEL. Blank/comment records and unknown fields are not supported.

The header and two required single-value fields come first in the shown order;
subsequent records occur in the listed groups. Repeated path/role records retain
source order, without sorting or rewriting the editable file:

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
role History.md | Work-history pointer index
role PLAN.md | Requirements and acceptance
```

The example is an editable shape, not a declaration of an actual project.
`reviewer-policy default` retains compatible Codex/Claude routing with Grok
disabled. Optional `reviewer-policy grok-fallback` enables the Grok fallback
reviewer with a central profile (operator ruling 2026-09-23). A project names at
most a profile, never a model, effort or transport: an optional record
`grok-profile <recommended|strong|fast>` immediately after
`consistency-document`, before inventory records. Without that record the
profile is `recommended`. The runtime release owns the profile table
(`Get-CrgGrokProfileTable` in `scripts/private-governance.psm1`), so a model or
effort change is one reviewed release and one central activation, never an edit
in each attached project. The 2.4.0 table:

| Profile | Model | Effort | Transport / authentication |
|---|---|---|---|
| `recommended` | `grok-4.7` | `xhigh` | `cli` / `local-login` |
| `strong` | `grok-4.7` | `high` | `cli` / `local-login` |
| `fast` | `grok-4.7-build-fast` | `high` | `cli` / `local-login` |

A legacy record `grok-provider <api|cli> <grok-4.6|grok-4.7> xhigh
<environment-key|local-login>` from releases before 2.4.0 still parses forever,
because push guards and completed-pair reads re-parse historical configuration.
Its model and effort are superseded by the `recommended` profile (operator
ruling 2026-09-23: the central runtime owns the model), but it keeps its own
transport and authentication, so the account route that carries review material
never changes without a reviewed record change. Review-input capture refuses a
new or changed legacy record (a first attachment always refuses one); an
unchanged one may remain until the project replaces it. Replacing a CLI
`local-login` record with nothing or with `grok-profile recommended` changes
nothing under the 2.4.0 table; replacing an API record moves the route to the
table's transport. Releases before 2.4.0 reject a `grok-profile`
record and a `grok-fallback` policy without a provider record, and their push
guards require a Grok review's model to equal the governing record's own model,
so they also reject a 2.4.0 review that ran `grok-4.7` under an unchanged
`grok-4.6` record. Push guards revalidate the whole retained completed-pair
chain, so the restriction follows history, not current configuration: activate
2.4.0 before any project uses either new shape, and once any attached project's
retained history holds either shape or a Grok review run under 2.4.0 or later,
do not roll back below 2.4.0, even after its configuration changes back.

Grok artifacts record the requested model and effort. Live acceptance (adapter
self-check, review session, follow-up promotion) requires both to equal the
current table entry for the governing profile. Historical validation (retention,
push guards) requires governing `grok-fallback` enablement and a model and
effort the governing selection could have run (`Get-CrgGrokAllowedIdentities`):
any mapping of the governing profile in the append-only profile history
(`Get-CrgGrokProfileHistory`), plus, for a legacy record, its own model at
`xhigh`, which releases before 2.4.0 requested. Each review unit records the
runtime manifest ID, which identifies the release whose table ran it, and
retention runs only under that exact runtime. Push guards instead revalidate
retained history under the current release without loading retained releases,
so an old review may match any historical mapping of its own profile, never
another profile's. Default policy refuses a profile or
provider record. Installation, a saved CLI login or an API key alone never
enables Grok.
Reviewed governing configuration selects the route. Enabling
`reviewer-policy grok-fallback` in that configuration is the operator's
authorization for xAI to receive the review material and for the selected
account usage; no further per-review consent applies, and live calls that test
the Grok reviewer are part of the gate's operation. Candidate
configuration cannot enable the current review. API credentials remain external
in `XAI_API_KEY`; CLI credentials remain owned by Grok Build's existing local
login and are never read or copied by the gate. Authentication failure does not
silently change transports.
The [Grok adapter contract](v2.2-grok-reviewer-design.md) defines capability bounds.
No persisted quota-avoidance state participates in project configuration.

`consistency-document` is exactly `-` (disabled preprocessing, never disabled
review), `private <path>`, or `public <path>`. An enabled document must exist as
a regular blob in the selected candidate tree. For example, public project
requirements can use `consistency-document public docs/requirements.md` without
moving those requirements into private history. The declared scope must match
the private-path inventory; the parser rejects a contradictory declaration,
while later snapshot validation proves actual blob presence and shape.

Optional `unit-tests` records loosen the operator's code unit-test ban for one
project (operator ruling 2026-10-07: the ban stays the default and only reviewed
configuration loosens it). They follow `consistency-document` and any Grok
record, before inventory records, in one canonical order: at most one
`unit-tests allowed-in-mode prototype`, then zero or more
`unit-tests allowed-path <folder>` (at most 64; a folder is a canonical path as
defined below, without a trailing slash, whose folder names use only letters,
digits, `.`, `_` and `-` because the compiled review policy quotes them
verbatim; no duplicates, and the shared spelling audit rejects Windows case
aliases against every other configuration reference and the captured tree). No record means the ban, and no record spells the ban explicitly. The
mode allowance permits code unit tests anywhere while the governing
`PROJECT-MODE.md` validly declares `mode: prototype`; an absent or malformed
declaration runs shipped defaults and never loosens. A path allowance permits
them in files under the named folders in every mode. Only the governing
configuration and mode select the scope, and the compiled review prompt carries
it ([project preparation](project-preparation-v1.md)); a candidate that adds or
widens the records is reviewed under the preceding scope. The records loosen
review only: authoring sessions also follow the operator's global instruction
files, which a project's own instructions must reconcile. Releases before 2.5.0
reject these records, and push guards re-parse retained configuration under the
active release, so once any attached project's retained history holds one, do
not roll back below 2.5.0.

Next come one or more `private-directory` records,
three or more `private-file` records, then zero or more `role` records. There
are at most 256 path records and 128 roles. `.crg-project` and the three root
files `AGENTS.md`, `CLAUDE.md`, `CROSS-REVIEW-VALUES.md` are mandatory private
entries. `PROJECT-MODE.md`, `PLAN.md`, and `History.md` are private whenever
present, even when omitted from an editable inventory.

A path is canonical repository-relative text using `/`: no empty, `.` or `..`
component, leading/trailing slash, backslash, colon, `|`, control character, or
component with leading/trailing whitespace or a trailing dot. Reject Win32
reserved punctuation (`<`, `>`, `"`, `?`, `*`) and device stems, including
`CON`, `PRN`, `AUX`, `NUL`, `CLOCK$`, `CONIN$`, `CONOUT$`, and numbered COM/LPT
aliases, even with an extension. No glob or Git pathspec syntax is evaluated.
Directory records classify the directory and descendants; file records classify
one exact path. Reject duplicate records and Windows case-aliases. A `.git`
component cannot be configured as work content. The required config
directory is always private. Other nested public user documentation can remain
public; private-directory selection must not swallow unrelated software.

A role record contains exactly `role <path> | <description>`; description is
1–1,024 UTF-8 bytes, nonblank, single-line, with no `|`. Roles are unique per
path and name an existing document in the combined candidate. Role prose is
review context, not authority to alter verdict grammar, independent review,
severity, or mandatory input capture. Configuration changes receive ordinary
review under the preceding approved configuration.

Project context/hazards/SCOPED-authority remain in the existing three-block
`CROSS-REVIEW-VALUES.md` grammar; no fourth install-value block is introduced.
The selected private blob supplies those bytes. `PROJECT-MODE.md` retains the
existing declaration grammar and shipped fallback for positive absence or
positive malformed input. An unreadable/missing private repository is not an
absent declaration and refuses. Prototype remains review context, not a work
permit; it changes the code unit-test scope only under a configured
`unit-tests allowed-in-mode prototype` record. Commit and merge wrappers never
reinterpret mode as mutation permission.

## Instruction discovery and preparation

Both root `AGENTS.md` and `CLAUDE.md` are ordinary locally editable, privately
tracked files. Each contains the same reviewed discovery section naming the
stable launcher, `.crg-project/project.conf`, and the selected private plan/history
paths. That section is supplied and reviewed during attach/configuration changes;
opening a project does not inject unreviewed text into existing instructions.

Initial attachment materializes approved instruction files before activating the
association. On later `-Open`, only a clean file may advance from the recorded
approved private state to the associated approved state. Existing staged or
working edits are preserved and reported; a missing previously materialized
file is an unstaged deletion, not permission to restore automatically. No
automatic overwrite, duplicate instruction source, or every-update root-file rewrite.
The installed launcher remains discoverable from either tool's ordinary root
instructions. Runtime activation leaves project instructions/configuration alone.

Before review, prepare immutable prompt/configuration buffers from the retained
release and exact private Git blobs. Render only existing values slots, the
declared document-role input and the configured code unit-test scope; preserve
exact bytes outside those surfaces.
Record the governing and candidate preparation digests separately. Candidate
configuration, values, instructions, and mode are review data; the last completed
private state governs the current review. No loose-file reread can change review
policy after capture. New policy governs only a subsequent completed pair.

### Parsing foundation boundary

`scripts/private-governance.psm1` exports `Read-CrgAttachmentBytes -Bytes <byte[]>`
and `Read-CrgProjectConfigBytes -Bytes <byte[]>`. Inputs are complete bounded
buffers; outputs are validated data objects, never execution/commit authority.
No filesystem access, environment lookup, Git process, provider, module framework,
or state publication occurs during parsing. Source/attachment custody, file
existence, non-overlap, instruction discovery and paired enforcement are later
integration obligations. Ship the module only through the new central payload
inventory; frozen v2.1 `Get-CrgCurrentFileList` and consumer inventory are unchanged.

## Staging and ordinary review/commit

`-Stage -All` captures ordinary public changes under normal public ignore rules
and every change within the approved/candidate private inventory, including
ignored private files. `-Stage -Paths` handles only the explicit literal paths
and related deletions; no wildcard expansion. Validate classification first.
Union the preceding approved and candidate private inventories when excluding
public paths, including deletions/renames. A config edit cannot declassify and
publish private material in the same operation. Unclassified existing private
tracked paths refuse until explicitly mapped; nothing is silently discarded.

### Pure ownership classification

`Get-CrgPathOwnership -GoverningConfigBytes <byte[]>
-CandidateConfigBytes <byte[]> -Paths <string[]>` in `private-governance.psm1`
reparses both complete configurations and validates every literal path before
returning any result. An explicit empty path array returns an empty result array;
null, duplicates, invalid relative paths and Windows path/prefix case aliases
refuse. Component spelling must agree across both configurations, document
references and supplied paths, including prefixes such as `Docs/a` versus `docs/b`.
Reject contradictory file/directory-prefix declarations within one configuration;
directory coverage plus an explicit descendant file is normal overlap. A file to
directory transition between versions is permitted; actual tree shape is a later
validation, never inferred by this function.

Results retain input order and contain `Path`, `Ownership` (`public` or `private`),
`GoverningPrivate`, `CandidatePrivate`, and `MandatoryPrivate`. Each configuration
classifies explicit private files by exact name and private directories by exact
name or slash-delimited descendant. Both configurations also retain the six fixed
root private files and `.crg-project` directory described above. Final ownership
is the union: removal from candidate inventory cannot publish preceding private
content in that unit. Mandatory root names do not become filename heuristics for
unrelated nested public documents; roles alone do not make documents private.

Classification of a directory name is not recursive staging authorization: a
public directory can contain explicitly private children. Staging/capture must
enumerate and classify every actual tree/index leaf before writing either index.
No filesystem, Git, staging, ref, provider, ignore expansion, byte-secret detection
or publication occurs here. Unknown paths already tracked in private history
still require a later explicit refusal/mapping; a `public` result cannot discard
private history or prove that an input path actually belongs in the public tree.

### Ordinary staged publication

The gate updates the public and associated private indexes, then reports both
staged diffs. Staging is not review or publication. A partial staging failure
reports both actual index states and preserves working files; no claimed atomic
two-index rollback. No command stages private bytes into the public object
database as an intermediate step. Raw `git add` cannot establish paired staging;
the public commit check rejects any private path regardless of ignore rules.

`-Commit` consumes both staged trees, not all loose working changes. The exact
message-file bytes apply to each changed history and participate in review
context. Capture public/private parents, refs and trees, the last completed pair,
runtime manifest ID, governing-config digest and candidate-preparation digest.
An unchanged side keeps the previous commit; no empty companion commit is
manufactured. Both unchanged returns an explicit no-change result without review.

Review covers the combined diff and required unchanged context. Software-only,
governance-only, and paired changes all require normal independent review.
Consistency preprocessing reads the explicitly scoped document from the combined
snapshot, without fabricating public `PLAN.md` or dropping supported public
consistency documents. Existing verdict/consistency checks,
provider eligibility, automatic exhaustion handling, and mandatory merge panels
remain required. Platform/provider denial is not a review result or permission
to switch destinations manually. Historical receipts identify past work and
never authorize a new invocation, even when the candidate unit is unchanged.

Before publication, the live coordinator obtains validated current-run review
with owned reviewer-child exit provenance, runs both non-review commit guard
sets, and confirms refs, parents, staged trees, governing pair and prepared
bytes still match. Attached native pre-commit shims refuse raw `git commit` and
name the supported launcher; no receipt path/environment switch grants passage.
The live coordinator owns internal `commit-tree` and expected-old ref updates.
Existing custom/foreign hook checks must be explicitly preserved or attachment
refuses. No hook is silently dropped; no `--no-verify`, persisted receipt bypass,
new signing/IPC framework, or caller-supplied review acceptance is introduced.

## Receipt and bounded publication

The receipt binds existing review evidence; no new reviewer-output protocol or
persisted PASS authority is introduced. Store the immutable receipt in private
metadata with a stable digest and retention reference. Neither receipt nor private
object/reference enters public history. `crg-pair` identifies the last completed
receipt; historical review uses that recorded preceding pair, never an unrelated
current private HEAD. This grammar covers ordinary commits with existing parents.
Initial attachment and branch/merge panels retain separate integration contracts.

### Exact record grammar

Both records use strict UTF-8/no BOM, LF only with final LF, no blank/comment or
unknown records; reject DEL and every C0 control except LF. Field order is exact;
one ASCII space separates tokens. Absolute path values preserve internal spaces
and use the attachment path rules; Git-directory fields admit `.git` components.
`id32` and `sha256` are respectively 32 and 64 lowercase hexadecimal characters.
`oid` is nonzero lowercase hex of the named database's object-format width:
40 for SHA-1 or 64 for SHA-256. Public/private formats are explicit parser inputs,
not inferred from an arbitrary record. Head refs use canonical full `refs/heads/`
names. No symbolic selector, revision expression, absent-parent token or pathspec.

Receipt maximum: 65,536 bytes. Angle brackets below explain values, not literal bytes.

```text
crg-pair-receipt v1
operation-id <id32>
project-id <id32>
attachment-sha256 <sha256>
public-worktree <absolute-path>
public-git-dir <absolute-path>
public-common-dir <absolute-path>
private-git-dir <absolute-path>
public-ref <head-ref>
private-ref <head-ref>
public-parent <public-oid>
private-parent <private-oid>
public-tree <public-oid>
private-tree <private-oid>
previous-pair <sha256>
runtime-manifest-sha256 <sha256>
governing-preparation-sha256 <sha256>
candidate-preparation-sha256 <sha256>
public-diff-sha256 <sha256>
private-diff-sha256 <sha256>
consistency-envelope-sha256 <sha256>
message-private-blob <private-oid>
message-sha256 <sha256>
review-unit-sha256 <sha256>
public-result <public-oid>
private-result <private-oid>
review-leg-count <1-or-2>
review-leg <leg> <preferred-provider> <required-pass-count>
review-attempt-count <1-through-6>
review-attempt <leg> <attempt> <actual-provider> <scheduled-pass-count> <observed-exit> <transcript-sha256> <verdict-sha256-or-dash> <exhaustion-sha256-or-dash>
```

Emit exactly the counted legs followed by the attempt count and exactly the
counted attempts. Leg numbers start at 1, contiguous; each leg has one through
three contiguous attempts, ordered by leg then attempt. Preferred providers are
exactly `claude` or `codex`; `grok` is permitted only as a configured third
attempt. Pass counts are canonical decimal 1 through 10. Every attempt's
scheduled count equals that leg's required count: exhaustion substitution reruns
the complete leg, never partial coverage. Initial ordinary commit policy remains
one pass. Captured runtime policy determines required coverage, provider capability
and protected-change independence; records cannot choose different requirements.

The first attempt uses the preferred provider. A second attempt uses the other
provider and requires first-attempt exit 4 plus an exhaustion digest. A third
attempt requires second-attempt exit 4 with a separate positive exhaustion
digest and governing `grok-fallback` configuration. No Grok exhaustion is
invented: the final attempt passes completely or the operation fails. Receipt
grammar cannot establish provider authorization independently. Every leg
ends with exit 0, a verdict digest and dash for exhaustion. Exit-4 attempts may
carry a verdict digest or dash for a positively absent verdict; Claude exhaustion
can finish before verdict-file construction. Never manufacture a verdict artifact.
Transcript digests are always required. Nonfinal success, final exhaustion,
BLOCKER/indeterminate/denied/failed runs cannot form a pending-publication receipt.

The receipt ID hashes all raw receipt bytes, including final LF. No self-digest
field is embedded. `review-unit-sha256` hashes the exact raw prefix from the header
through the `message-sha256` record's LF, excluding the review-unit record and all
following records. Other digests cover exact captured bytes without normalization:
both raw patches; governing/candidate configuration, values, roles, mode and prompt
preparations; mandatory consistency envelope (including explicit skipped state);
message; retained transcript/verdict/exhaustion snapshots. No arbitrary evidence
path or executable config is accepted. The message blob belongs only to the private
database. Actual object formats/types/content, message digest, previous-pair binding
and evidence existence require later retained-object validation, not byte parsing.

A changed result must be the retained ordinary commit with the recorded sole parent,
tree and agreed message bytes. An unchanged side keeps the parent and that parent's
tree; no historical message rewrite. Both unchanged refuses a new receipt/handoff.
Recovery never regenerates result commits with different metadata.

Handoff maximum: 16,384 bytes. Exactly these records; no mutable phase or queue:

```text
crg-handoff v1
operation-id <id32>
project-id <id32>
attachment-sha256 <sha256>
receipt-sha256 <sha256>
previous-pair <sha256>
runtime-manifest-sha256 <sha256>
public-ref <head-ref>
public-old <public-oid>
public-new <public-oid>
private-ref <head-ref>
private-old <private-oid>
private-new <private-oid>
```

Every duplicated field equals the revalidated receipt; old/new equal its
parent/result fields. The handoff's raw SHA-256 identifies the exact pending
record, not review credit. `crg-pair` may name the previous pair, or this receipt
only when both refs already equal their new values. Any other pointer refuses.
Positive pointer absence after both refs advanced also permits fresh-review
recovery when exact no-replace pointer publication moved the predecessor aside.
The immutable preceding receipt and durable handoff remain required.

### Data-only API

`scripts/paired-governance.psm1` exports data-only functions. Every function requires
`-PublicObjectFormat sha1|sha256` and `-PrivateObjectFormat sha1|sha256`:

- `Read-CrgPairReceiptBytes -Bytes <byte[]>` returns `Schema`, `ReceiptSha256`,
  ordered wire-name `Fields`, `ReviewLegs`, and `ReviewAttempts`.
- `New-CrgPairReceiptBytes -Fields <IDictionary> -ReviewLegs <IDictionary[]>
  -ReviewAttempts <IDictionary[]>` returns canonical bytes after full validation.
  Fields are the receipt's singletons except computed `review-unit-sha256` and
  group counts; every key/value is an exact case-sensitive schema name/string.
  Leg keys are `leg`, `preferred-provider`, `required-pass-count`. Attempt keys
  are `leg`, `attempt`, `actual-provider`, `scheduled-pass-count`, `observed-exit`,
  `transcript-sha256`, `verdict-sha256`, `exhaustion-sha256`.
- `Read-CrgPairHandoffBytes -Bytes <byte[]> -ReceiptBytes <byte[]>` revalidates
  the receipt and returns `Schema`, `HandoffSha256`, and ordered wire-name `Fields`.
- `New-CrgPairHandoffBytes -ReceiptBytes <byte[]>` derives exact handoff bytes
  solely from a revalidated receipt, with no caller identity overrides.

Before review, `New-CrgReviewUnitBytes -Fields <IDictionary>` constructs only the
identity prefix through `message-sha256`; `Read-CrgReviewUnitBytes -Bytes <byte[]>`
validates that exact prefix and returns `Schema`, `ReviewUnitSha256`, and ordered
wire-name `Fields`. The constructor admits only the prefix singletons. No results,
review groups, computed digest record or placeholder PASS belongs in this input.
`paired-review-input-v1.md` owns the dependent prepared-review bundle; the prefix
API identifies input before a complete receipt can exist, not review acceptance.

Parsed leg properties are `Leg`, `PreferredProvider`, `RequiredPassCount`;
attempt properties are `Leg`, `Attempt`, `ActualProvider`, `ScheduledPassCount`,
`ObservedExit`, `TranscriptSha256`, `VerdictSha256`, `ExhaustionSha256`.
These are data objects, not retained custody or authorization handles. Mutation
of an output object never changes canonical input bytes or grants authority.
The module performs no filesystem, Git, provider, environment or state operations.
Only the new central inventory may ship this dependent module; legacy inventory
and the existing configuration/attachment parser API remain unchanged.

### Publication integration boundary

There is one bounded `crg-handoff` per worktree under the existing gate lock, not
a general journal framework. After PASS and final identity checks, prepare changed
commit objects and durably record the receipt digest, exact expected old/new refs
for both databases and prior completed-pair ID before changing either ref. Retain
the captured release through completion. Publish private then public refs using
expected-old comparisons; verify both, publish completed-pair identity, then remove
the exact handoff record. Report success only after that final state verifies.

| Recorded refs on resume | Outcome |
|---|---|
| Both old | Freshly review the recorded pair, then continue exact publication. |
| Private new, public old | Freshly review the same recorded pair, verify the private result, then finish public publication. |
| Both new | Freshly review the same recorded pair, verify both results, then finish completed-pair bookkeeping. |
| Public new while changed private remains old | Refuse the publication-order mismatch; preserve state. |
| Any other refs, invalid/missing receipt, or conflicting record | Refuse; preserve state and report the mismatch. No reset or invented completion. |

An unchanged side has identical old/new IDs and is already satisfied, not an
out-of-order publication. `-Resume` handles only
the recorded transaction. After process loss, the persisted record and receipt
prove identity only: every resumable state requires a fresh current-run review
of that exact pair under the retained preceding governance/runtime, including
the both-new state. Ordinary candidate staging refuses an existing handoff.
The narrowly scoped published instruction correction in `first-attachment-v1.md`
is the exception: an unactivated first-origin transaction with both result refs
present and no completed pointer can stage root-instruction-only corrections,
then obtain fresh first-attachment review through Attach under the active release.
No old receipt or PASS grants publication credit, and Resume remains immutable.
Central activation during interruption does not silently substitute a new runtime;
the verified retained release named by the handoff finishes that transaction.
Missing required old release/state refuses. A process crash can leave unreachable
prepared objects or a partial paired ref update; neither is successful completion.
Fresh recovery artifacts bind operation ID, receipt ID and review-unit digest;
retain/report those artifacts as the actual recovery review evidence. The original
receipt remains immutable initial-review forensics. Another process loss requires
another fresh review, not reuse of recovery artifacts or a receipt rewrite. Changed
associated indexes/preparation refuse continuation; no reset or automatic repair.

The live coordinator and recovery ownership are specified in
`central-publication-v1.md`; parsed records alone never provide that authority.

## Public boundary and migration limits

Public commit validation excludes private paths under the reviewed classification.
Pre-push checks every outgoing post-attachment commit against recorded private-path
authority and completed-pair evidence; a direct private commit or stale receipt is
not sufficient. No private alternates, objects, refs, config, instructions, or
receipt files are inserted into the public repository for capture or review.
Previously published governance requires a separate explicit history decision.
This is path/authority enforcement, not a claim to detect arbitrary secret bytes.

Existing AR4-style private databases are adoptable without rewriting history or
copying runtime customization automatically. Mapping, root instruction discovery,
private classification and the first combined review precede dispatcher activation.
Existing TRACKED runtime removal is a reviewed migration; LOCAL ignored data and
recovery evidence are preserved. No application cleanup or live migration is
authorized by this draft. Portable transfer carries private history and paired
receipts separately from software; remote selection and credentials remain explicit.

New attached shape only: private-blob preparation and reviewed root instruction
materialization replace the fixed-root indexed-values/public-mode-authority rules
only for this shape. Released TRACKED/LOCAL manifests, LOCAL authorization,
standalone rendering/recovery and declaration rules remain unchanged. Routine
central upgrades continue to accept config schema 1 with launcher ABI 2 without
project edits; the preceding ABI 1 loader requires one explicit store-wide upgrade.

The parsing foundation does not implement the approved launcher surface or live
attachment. Receipt/handoff grammar is settled here; current-invocation
authorization, retained-object verification and publication plumbing remain pending.
Existing checks for ordinary software/private/
paired work, interrupted handoff, discovery and public exclusion supply bounded
acceptance; no new code unit-test framework or broadened verification campaign is
specified. Live testing, manual checks, ordinary program runs, and functional
validation remain permitted.
