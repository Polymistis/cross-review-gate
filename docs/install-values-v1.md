# Installed project values v1

This document is the NORMATIVE contract for rendering project-owned review
context into an installed cross-review gate. V21-06B implements this contract;
runtime code must not choose a different source, grammar, marker, authority
rule, or publication order.

The design removes model-visible customization placeholders from installed
reviewer and agent material. Project values are resolved and rendered before
installation. Commit hooks, review wrappers, merge wrappers, dispatchers, and
review processes never read a values file at runtime.

## 1. Fixed source and render surface

The sole values source is:

```
<target-repository-root>/CROSS-REVIEW-VALUES.md
```

No command-line override, environment override, ancestor search, package-root
fallback, backup search, or alternate filename participates. A missing or
invalid source refuses before target mutation.

The source defines exactly these blocks:

- `project-context`
- `project-hazards`
- `scoped-authority`

The fixed render map is:

| installed output | required slots |
|---|---|
| `scripts/codex/review-prompt-template.md` | `project-context`, `project-hazards`, `scoped-authority` |
| `docs/AGENTS.md.template` | `scoped-authority` |

`docs/AGENTS.md.template` is rendered as an installed merge source. Bootstrap
does not open, create, or edit a consumer root `AGENTS.md` or `CLAUDE.md`.
Merging the rendered template into those files remains a separate explicit
project operation.

`docs/audit-protocol.md` is the sole non-rendered model-visible Markdown
surface in the installed inventory covered by the reserved-placeholder rule.
V21-06B replaces the obsolete legacy hazard-heading reference and the obsolete
placeholder-based SCOPED dormancy signal in that file. The file has no render
slot and receives no slot substitution. The ordinary provenance stamp described
in section 7 still forms part of the installed bytes.

The three values are project configuration, not package configuration. A
package copy never supplies target values. No fourth value exists in v1.
In particular, `CROSS_REVIEW_CONSISTENCY_DOC` and `PLAN.md` are not install
values. Leaving `CROSS_REVIEW_CONSISTENCY_DOC` unset retains the full mandatory
review; only the optional consistency-report producer and corresponding
backend-routing constraint remain disabled.

## 2. Values-file byte grammar

`CROSS-REVIEW-VALUES.md` has this exact outer form, in this exact block order:

```markdown
cross-review-values v1
<!-- crg-install-value v1 project-context BEGIN -->
<project-context Markdown fragment>
<!-- crg-install-value v1 project-context END -->
<!-- crg-install-value v1 project-hazards BEGIN -->
<project-hazards Markdown fragment>
<!-- crg-install-value v1 project-hazards END -->
<!-- crg-install-value v1 scoped-authority BEGIN -->
<scoped-authority fragment>
<!-- crg-install-value v1 scoped-authority END -->
```

The header and marker lines are case-sensitive ASCII and occupy complete
records. Every record, including the final `END` marker, ends with one LF byte.
No bytes may occur before the header, between frames, or after the final LF.
Blank lines belong to a block body only; blank separator records outside a body
are invalid. Each block occurs exactly once. Blocks cannot nest.

The whole source must satisfy every following boundary before parsing:

- maximum encoded size: 262,144 bytes;
- strict UTF-8, without a BOM;
- LF record separators only; any CR byte is invalid;
- no NUL, no C0 control character other than horizontal tab and LF, and no
  DEL character;
- a final LF is mandatory.

Each block body is the exact byte range after the opening marker's LF and
through the LF immediately before the closing marker. Each body must contain
at least one character other than space, horizontal tab, or LF and may contain
at most 65,536 encoded bytes. No trimming, newline conversion, Unicode
normalization, case folding, or Markdown rewriting occurs. A body containing a
complete line beginning with `<!-- crg-install-value v1 ` or
`<!-- crg-render-slot v1 ` is invalid. Those namespaces are structural, never
project prose.

`project-context` and `project-hazards` are Markdown fragments placed beneath
fixed package headings. Package headings therefore do not belong in either
body. Semantic accuracy remains a project review duty; the renderer validates
the byte and structural contract rather than inventing project facts.

`scoped-authority` has a narrower grammar. The body is either this exact
single record:

```markdown
- No authority documents. SCOPED capture is dormant.
```

or one or more records of this exact form:

```markdown
- `docs/deferred-scope.md`
- `docs/another-project-register.md`
```

Each non-sentinel record starts with an ASCII hyphen, one space, and a
backtick; each record ends with a backtick. The enclosed path is a non-empty
canonical repository-relative Git path: `/` separators,
no leading or trailing `/`, no empty, `.` or `..` segment, no backslash, no
backtick, and no control or DEL character. Paths compare with ordinal,
case-sensitive equality and cannot repeat. The sentinel cannot coexist with a
path record. This grammar declares only the authority set; stricter entry
schemas and field-pairing rules remain in each named authority document.

## 3. Tracked and LOCAL source authority

The rules in this section grade a new render transaction or `-Check`. They are
not recovery predicates for a valid standalone `PREPARED` record; the section 5
rollback ordering precedes them.

The values source never selects an install shape. Before accepting source
authority, bootstrap classifies each render-bearing output from strict `HEAD`,
stage-0 index, and effective-ignore probes:

- **TRACKED-existing** requires one regular `HEAD` blob and one stage-0 index
  blob with the same mode and object ID. Ignore state does not demote a tracked
  path; tracked authority remains the `HEAD` baseline.
- **TRACKED-new** requires positive absence from both `HEAD` and the stage-0
  index and a positive `not ignored` result. This is the fresh-install state
  whose output will enter the later bootstrap commit.
- **LOCAL** requires positive absence from both `HEAD` and the stage-0 index
  and a positive `ignored` result.

A failed, indeterminate, unmerged, or non-regular `HEAD` or index probe; an
index-only output; a `HEAD`/index mode or object-ID difference; or an
indeterminate ignore probe refuses before mutation. Working-tree occupancy
does not select authority: the existing destination custody, collision, and
trusted-baseline rules grade an occupied output separately.

The aggregate is TRACKED only when every output is TRACKED-existing or
TRACKED-new, and LOCAL only when every output is LOCAL. Any cross-family
mixture has no single values authority and refuses before mutation. Hybrid
components outside the render-bearing outputs retain the per-file behavior
defined by `docs/local-install-v1.md`. No classifier falls back from one family
to the other.

### TRACKED authority

For a TRACKED render operation, all of these conditions are mandatory:

1. `CROSS-REVIEW-VALUES.md` resolves in the target index as one regular Git
   blob. A new source may be staged before the first gate-install commit.
2. The working-tree path is an ordinary, non-reparse, single-link file opened
   without following a substitute object.
3. Raw working-tree bytes equal the exact indexed blob bytes. Clean filters,
   checkout conversion, and a matching decoded string do not establish
   equality.
4. The held bytes pass the v1 grammar.

The index blob is the reviewed project configuration. Bootstrap does not
stage or commit the source. A working edit must be staged first, then rendered;
an unstaged or partially staged source refuses. The source is not admitted
through an ignored-file rule when any index or `HEAD` probe is failed or
indeterminate.

### LOCAL authority

For a LOCAL render operation, all of these conditions are mandatory:

1. `CROSS-REVIEW-VALUES.md` is positively absent from both `HEAD` and the
   target index. An unborn `HEAD` is positive absence only after the ordinary
   unborn-repository probe succeeds.
2. Git positively reports the path ignored under the target repository's
   effective ignore rules.
3. The working-tree path is an ordinary, non-reparse, single-link file opened
   without following a substitute object.
4. The held bytes pass the v1 grammar.

The LOCAL source is operator-held project configuration. The source is not a
local gate component, is not listed in `crg-local-install`, and is not sealed
into the install manifest. Ignored status routes custody but never supplies a
runtime trust decision: only already-rendered, manifest-pinned installed bytes
run later.

Before a fresh LOCAL install, effective ignore rules must cover the values
source and every incoming LOCAL gate destination. Before a v2.0 LOCAL upgrade,
effective ignore rules must also cover newly delivered v2.1 destinations,
including `docs/AGENTS.md.template` and
`scripts/render-project-values.ps1`. Bootstrap may add the generated `logs/`
rule under the existing local-install doctrine, but bootstrap never invents
ignore authority for the values source or a gate destination. A newly
delivered exposed path creates a mixed classification and refuses before
mutation.

A source that is tracked only in `HEAD`, untracked but not ignored, or
indeterminate under any Git probe satisfies neither rule.
The renderer reports the failed condition and refuses without guessing.

### Source custody

The accepted source file is opened once and retained under no-write,
no-delete, and no-rename sharing from validation through rendered-output
publication and, for LOCAL installation, through manifest and authorization
publication. Hash and identity are revalidated from that retained handle at
the final pre-mutation boundary and again before metadata commit. A platform
that cannot provide this custody refuses. A pathname reopen cannot replace the
retained source evidence.

Bootstrap repeats every `HEAD`, stage-0 index, and ignore predicate used to
classify the outputs and source at the final pre-mutation boundary and again
before metadata commit. Any changed result refuses. Bootstrap does not stage or
commit during the interval, so no authority transition is an expected side
effect of rendering.

### TRACKED checkout-attribute authority

Every TRACKED values source and render output has a named checkout contract.
The package root and a TRACKED consumer root carry these exact root
`.gitattributes` records:

```gitattributes
CROSS-REVIEW-VALUES.md text eol=lf -filter -ident -working-tree-encoding
scripts/codex/review-prompt-template.md text eol=lf -filter -ident -working-tree-encoding
docs/AGENTS.md.template text eol=lf -filter -ident -working-tree-encoding
```

The named records, not a repository-wide Markdown glob, are package authority.
Effective attributes must resolve `text` to set and `eol` to `lf` for each
path. `filter`, `ident`, and `working-tree-encoding` must resolve to unset or
unspecified; a set state or any string value refuses. A macro, nested
`.gitattributes`, later rule, global attribute file, or `info/attributes` file
cannot override the effective result.

Bootstrap constructs the prospective target attribute graph in isolated
scratch state before target mutation, including any exact records awaiting
append. The probe uses only repository-owned attribute files and disables
ambient global, system, and `info/attributes` input. The ordinary retained,
single-link `.gitattributes` mutation contract remains in force. Required
records are published only after the complete render preflight succeeds, and
the live effective graph is rechecked before install metadata commits.

Standalone Apply and `-Check` do not add or repair attributes. Both require the
index attribute graph and working-tree attribute graph to produce the same
valid effective result before any render decision. A difference that changes
any required effective state, a missing rule, or an indeterminate probe
refuses. A tracked source blob and every tracked output blob must also satisfy
the strict UTF-8/no-BOM/LF byte grammar; attributes never excuse invalid bytes.

Validation includes Git's conversion behavior, not only rendered attribute
strings. Under an isolated `core.autocrlf=true` probe for each path:

1. CRLF probe bytes clean to the corresponding LF blob.
2. A strict UTF-8 LF blob checks out byte-for-byte with LF and without a BOM.
3. Literal `$Id$` bytes remain literal, proving `ident` expansion inactive.
4. Non-ASCII UTF-8 probe bytes round-trip exactly, proving no working-tree
   encoding transform.
5. No clean or smudge filter command executes.

The same behavioral probe runs against the package rules, every prospective
TRACKED install rule set, and the final installed rule set. A clean checkout
under `core.autocrlf=true` must leave the values source and both render outputs
byte-identical to the committed blobs and must pass renderer `-Check`.

The conversion-behavior probe retains the exact created scratch namespace and
object bytes through Git use and cleanup. Object creation is relative to retained
parents; Git reads the held object store without publishing a loose object by
pathname. Cleanup uses exact held-object disposition, never pathname-recursive
deletion or ReadOnly-attribute rewriting. An unconfirmed cleanup refuses and
reports the retained operation failure rather than claiming successful validation.

LOCAL paths are outside Git checkout conversion. Bootstrap neither requires,
adds, nor removes attribute records for a LOCAL values source or LOCAL render
output. The strict raw-byte grammar and retained-file custody remain mandatory.
An attribute result never promotes a path into LOCAL or TRACKED authority.

## 4. Template and slot grammar

Package and installed templates use these exact retained marker lines:

```markdown
<!-- crg-render-slot v1 project-context BEGIN -->
<!-- crg-render-slot v1 project-context END -->
<!-- crg-render-slot v1 project-hazards BEGIN -->
<!-- crg-render-slot v1 project-hazards END -->
<!-- crg-render-slot v1 scoped-authority BEGIN -->
<!-- crg-render-slot v1 scoped-authority END -->
```

Each required slot occurs exactly once in the target named by the render map.
An opening marker must precede the matching closing marker. Slots cannot nest
or overlap. An unknown block name, duplicate marker, orphan marker, reversed
pair, or recognized marker in an undeclared target refuses. Marker matching is
case-sensitive and line-exact.

Every template is validated before replacement under the same strict UTF-8,
no-BOM, LF-only, control-character, final-LF, and retained-handle rules as the
values source. A template and a rendered output may each contain at most
1,048,576 encoded bytes.

Rendering replaces only the body between a slot's marker lines. Both marker
lines and every byte outside the slot remain byte-identical. The replacement
body is the corresponding values body byte-for-byte. Re-rendering the same
inputs therefore produces identical bytes, and rendering an already matching
output is a content no-op.

After assembly, every output is reparsed before any destination mutation. The
output must retain the exact required slot set, and every slot body must equal
the selected value bytes. Source-frame markers are forbidden in an output.
The complete output is also scanned with ordinal-ignore-case ASCII matching
for `REPLACE ME`, `REPLACE-ME`, and `REPLACE_ME`, with one or more ASCII space,
hyphen, or underscore characters between the two words. Any match is an
unresolved project placeholder and refuses.

Package preflight applies the same reserved-spelling scan to the retained raw
bytes of `docs/audit-protocol.md`. The shipped audit text must name the fixed
project-hazards heading and must describe SCOPED dormancy through the exact
`- No authority documents. SCOPED capture is dormant.` sentinel rather than a
legacy placeholder. A match in that non-rendered installed surface is a
package defect and refuses before target mutation. Package prose in the exact
model-visible Markdown surface named by section 1 must not reproduce a reserved
spelling merely to describe the old placeholder. This separator family is the
exhaustive v1 definition of an equivalent project-placeholder spelling.

The package copies carry valid cross-review-gate project content inside every
slot so the self-hosted package has no unresolved placeholder. Consumer
rendering replaces that stock slot body; stock content is not a target-value
fallback.

## 5. Rendering interfaces

`scripts/render-project-values.ps1` is backend-neutral and ships in both the
archive and installed inventory. The complete standalone invocation surface is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\render-project-values.ps1 -TargetRepo <path>
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\render-project-values.ps1 -TargetRepo <path> -Check
```

Apply is the default when `-TargetRepo` is present without `-Check`.
`-TargetRepo` is mandatory for both modes. No current-directory default
participates.

### Direct-entry Git environment boundary

After argument-only validation, the standalone adapter establishes this
boundary before its first Git invocation, target or Git-directory resolution,
repository inspection, install-lock or renderer-state open, or target mutation.
This ordering also precedes recovery because the resolved Git directory names
the fixed renderer state.

The adapter enumerates the native raw process environment and parses each exact
record as one name and value. For an ordinary record, the first `=` is the
separator and its index must be greater than zero. For a record beginning with
`=`, the next `=` is the separator and its index must be greater than one,
requiring a nonempty Windows pseudo-variable name after the leading `=`. Every
other shape is malformed. Empty or NUL-bearing records, a missing or invalid
separator, failed enumeration, or incomplete parsing refuses before Git or
target mutation. Matching examines only the parsed name, never text inside a
value.

The ordinal-ignore-case presence of any following raw name refuses, including
an entry whose value is empty:

- `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR`,
  `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_NAMESPACE`,
  or `GIT_REFERENCE_BACKEND`;
- `GIT_REPLACE_REF_BASE`, `GIT_GRAFT_FILE`, or `GIT_SHALLOW_FILE`;
- `GIT_ATTR_SOURCE` or `GIT_ATTR_NOSYSTEM`;
- `GIT_CONFIG`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`,
  `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_PARAMETERS`, or `GIT_CONFIG_COUNT`; or
- a complete name matching `GIT_CONFIG_KEY_<digits>` or
  `GIT_CONFIG_VALUE_<digits>`, where `<digits>` is one or more ASCII decimal
  digits.

Only after the selector scan proves clean does the adapter normalize replacement
suppression in the native raw process environment. The adapter removes every
ordinal-ignore-case spelling of `GIT_NO_REPLACE_OBJECTS`, proving that each
removal decreases the raw match count; re-enumerates and requires zero matches;
installs exactly `GIT_NO_REPLACE_OBJECTS=1` with canonical name casing; then
re-enumerates and requires one match with exact name, value, and count. A
removal, installation, enumeration, parsing, or postcondition failure refuses
before Git or target mutation.

Every Git child environment independently preserves the same boundary. An
explicit child-environment builder strips all inherited prohibited selector
names, admits only validated internal settings derived from the already pinned
target and this contract, then removes every replacement-suppression spelling,
installs canonical `GIT_NO_REPLACE_OBJECTS=1`, and verifies the exact singleton
after all child-environment additions and immediately before launch. A direct
inherited-environment launch repeats the raw selector scan and raw singleton
normalization and verification immediately before launch. No child builder
relies on the parent's earlier canonical value. Any failure prevents the child
from starting.

For Apply and `-Check`, the supplied path must resolve to one existing Git
working tree. The script normalizes the path through
`git rev-parse --show-toplevel`; that canonical top level is the sole target
root for the fixed values source and every destination. For `-Check`, and for a
new Apply transaction after positive absence of the fixed transaction state,
both fixed render-bearing destinations must already exist as ordinary,
non-reparse, single-link files. The standalone path opens those files as both
retained slot-bearing inputs and destinations. A missing destination or one
that fails this file-shape requirement refuses during render preflight, before
creating a state stage or output stage and before destination mutation, and
directs the operator to the full package `bootstrap.ps1 -TargetRepo <root>`
installation path. Bootstrap alone creates a missing render output from its
retained raw package templates. Apply changes only slot bodies in the existing
files; `-Check` writes nothing. Apply evaluates these new-transaction
requirements only after positive absence of the fixed transaction state.

The script's code root is the canonical parent of `$PSScriptRoot` and is not
caller-selectable. No `-PackageRoot`, values-path, template-root, output-root,
environment, ancestor-search, or package-fallback override exists. Bootstrap
instead passes already-retained raw package-template byte buffers directly
to the shared parser and renderer core; standalone root discovery never
participates in bootstrap installation. The shared core accepts retained byte
buffers and declared slot identities only. The core performs no environment,
path, Git, repository, or process lookup and launches no child. Bootstrap
retains the existing bootstrap trust boundary, calls the shared core directly,
and never invokes the standalone adapter.

The standalone interface has these modes:

- For a new transaction, Apply mode validates the authority class, source,
  templates, and all outputs, then replaces only the declared render outputs.
  A new Apply transaction is permitted only for TRACKED authority.
- `-Check` performs the same source, template, slot, and final-output
  validation without writing. Success requires every destination slot body to
  equal the selected values body.

After positive state-record absence, a new direct Apply transaction under LOCAL
authority refuses and directs the operator to the package
`bootstrap.ps1 -TargetRepo <root> -Force` path. Only bootstrap owns the locks,
destination custody, manifest publication, and authorization-marker transaction
required to change executable LOCAL gate bytes. `-Check` remains valid for
LOCAL authority because no state changes.

### Standalone TRACKED Apply publication

Standalone TRACKED Apply is one recoverable multi-output transaction, not two
independent file writes. The transaction uses the target worktree's existing
per-worktree `crg-install-lock`, so bootstrap, seal, and standalone rendering
cannot publish concurrently. No dispatcher lock is needed because standalone
Apply never changes the dispatcher. A held install lock never waits for the
dispatcher lock, preserving bootstrap's dispatcher-lock-before-install-lock
order.

The sole persistent renderer state name is the fixed per-worktree
`<git-dir>/crg-render-project-values-transaction`. No companion marker, second
journal, alternate filename, or search path exists. Apply acquires
`crg-install-lock` before opening or classifying that name and holds the lock
through new publication or recovery and all terminal cleanup. `-Check` also
acquires the install lock before classifying the name and holds the lock until
the check exits, but never performs recovery. A state occupant makes `-Check`
fail with a direction to run Apply's recovery arm.

After invocation and environment validation, canonical target and Git-directory
resolution, and install-lock acquisition, Apply classifies the fixed state name
before every TRACKED or LOCAL authority probe, values-source operation,
attribute probe, template operation, and new-output check. Positive state
absence permits ordinary new-transaction preflight. A valid `PREPARED` record
instead enters recovery-only rollback immediately. Recovery uses the retained
record, fixed derived paths, and only the recorded destination, stage, custody,
backup, archive, and recovery-copy identities, link counts, lengths, digests,
and bytes. Recovery does not resolve, open, parse, or hash the current values
source; compare `values-sha256` with current source bytes; grade current
authority, ignore, or attribute state; open package templates; or validate new
inputs. Those predicates govern only a later new-transaction invocation.

Every other operation that acquires `crg-install-lock` must classify this
fixed state immediately after lock acquisition and before any mutation. Full
bootstrap, same-version refresh, version upgrade, and `-SealManifest` continue
only on positive state-record absence. Any occupant, including a valid
`PREPARED` record, fails closed and directs the operator to run
standalone TRACKED Apply so the renderer recovery owner can finish. Those
operations never recover, replace, archive, or delete renderer state.
An operation needing both locks acquires the dispatcher lock first and the
install lock second, without an intervening mutation, then performs this state
classification.
`-DispatcherOnly` is exempt because it takes only the dispatcher lock and does
not mutate per-worktree render or install state.

#### State-record grammar

The record has exactly these 26 ordered, LF-terminated records:

```text
crg-render-project-values-transaction v1
phase: PREPARED
transaction-id: <transaction-id>
values-sha256: <sha256>
output-1: review-prompt
output-1-preimage-volume-id: <volume-id>
output-1-preimage-file-id: <file-id>
output-1-preimage-link-count: 1
output-1-preimage-length: <length>
output-1-preimage-sha256: <sha256>
output-1-postimage-volume-id: <volume-id>
output-1-postimage-file-id: <file-id>
output-1-postimage-link-count: 1
output-1-postimage-length: <length>
output-1-postimage-sha256: <sha256>
output-2: agents-template
output-2-preimage-volume-id: <volume-id>
output-2-preimage-file-id: <file-id>
output-2-preimage-link-count: 1
output-2-preimage-length: <length>
output-2-preimage-sha256: <sha256>
output-2-postimage-volume-id: <volume-id>
output-2-postimage-file-id: <file-id>
output-2-postimage-link-count: 1
output-2-postimage-length: <length>
output-2-postimage-sha256: <sha256>
```

The complete record is at most 4,096 bytes and contains only printable ASCII
bytes `0x20` through `0x7e` plus the 26 separating LF bytes. A BOM, CR, NUL,
tab, non-ASCII byte, missing final LF, blank record, leading or trailing
whitespace, reordered, repeated, unknown, or extra field is invalid. Field
names and the two output lines are literal and case-sensitive. Parsing is
strict whole-file parsing from one retained no-follow, ordinary, single-link
handle; a partial read, reread difference, pathname/handle identity mismatch,
or trailing byte refuses.

`phase: PREPARED` is literal; no other phase or result field exists. A
transaction ID is exactly 32 lowercase hexadecimal characters produced from
128 bits of cryptographically secure random input. A SHA-256 value is exactly
64 lowercase hexadecimal characters. A volume ID is exactly 16 lowercase
hexadecimal characters and a file ID is exactly 32 lowercase hexadecimal
characters, encoding the retained native identity without
byte-order-dependent text. A length is canonical unsigned decimal in the
range 0 through 18446744073709551615: zero is `0`, and a nonzero value has no
leading zero.
Every digest is standard SHA-256 over the exact retained raw byte sequence,
without text decoding or newline normalization: `values-sha256` covers the
values source, and each preimage or postimage field covers that complete file.

Every preimage and postimage field is concrete. Each identity, length, and
SHA-256 field follows the grammar above, and each link-count record contains
the literal value `1`. No field admits `-`. No whitespace, prefix, uppercase
hexadecimal, alternate numeric spelling, escape, or path value is accepted in
a placeholder.

The output identifiers eliminate attacker-selected recovery paths.
`review-prompt` maps only to
`scripts/codex/review-prompt-template.md`; `agents-template` maps only to
`docs/AGENTS.md.template`. For each output, the sibling stage is the fixed
destination text followed by `.crg-render-stage-<transaction-id>` and custody
is the destination followed by `.crg-render-custody-<transaction-id>`. The
parser derives those repository-relative paths from the fixed identifier and
transaction ID; no record field can supply or redirect a path. The state
creation stage is the fixed state name followed by `.new-<transaction-id>`.
The verified recovery-copy root is
`<git-common-dir>/crg-backups/render-<transaction-id>/`; preimage copies use
`preimage/<fixed-destination>` below that root and aborted-postimage copies use
`aborted-postimage/<fixed-destination>`. The permanent same-volume identity
backup for each present preimage is the destination followed by
`.crg-render-backup-<transaction-id>`; the permanent same-volume archive for a
rolled-back postimage is the destination followed by
`.crg-render-aborted-<transaction-id>`. Every derived name must be positively
absent before create-new use. An unowned occupant at a derived name, or an
orphan bearing the temporary `.new-*`, `.crg-render-stage-*`, or
`.crg-render-custody-*` suffix, is preserved and refuses a new transaction.
Verified permanent backup and aborted-postimage archives from an earlier
transaction are retained history and do not block a fresh transaction ID.

After read-only preflight, initial publication uses a dedicated state-record
share-none helper to create the empty state stage as the transaction's first
filesystem mutation, with read, write, and DELETE access and share mode exactly
zero. Failure to obtain that share-none custody performs no mutation and
refuses. Output stages are created only while this handle remains held. Apply
then writes, flushes, reparses, and byte-verifies the complete `PREPARED` record
through the same handle, atomically renames that retained identity without
replacement to the fixed absent state name, and keeps the handle open through
the transaction. Recovery classifies an existing record only by opening it
once with read, write, and DELETE access and share mode exactly zero, parses
only through that handle, and retains that identity through rollback and
terminalization. The dedicated helper owns both creation and recovery opens;
existing helpers that admit read sharing are prohibited at this boundary.
Failure to obtain recovery share-none custody, including conflict with a
foreign reader, refuses before mutation. A derived creation stage is never
authority; a crash before its fixed-name rename leaves destinations unchanged,
and a later run preserves and reports the orphan rather than adopting or
deleting it.

`DeleteHeldExact` is the only terminal record operation and the publication
commit point. It first proves that the fixed name still denotes the exact
retained `PREPARED` identity and bytes, marks that object for deletion through
the same share-none handle, and enters delete-pending state. Deletion completes
only when the owning code calls `CloseHandle` on that exact handle. The owner
then proves durable positive absence at the fixed name before releasing the
install lock; delete disposition alone, a foreign close, or observation of a
delete-pending name is not commit. No pathname delete, state-record rewrite,
replacement record, second phase, or companion marker is permitted. A
platform that cannot provide this same-retained-handle, share-mode-zero,
close-completed durable exact deletion refuses before destination mutation.
Process termination before delete disposition leaves the complete `PREPARED`
record authoritative. After disposition, process teardown closes the sole
owner handle and completes the same deletion that explicit owner `CloseHandle`
would complete; every publication prerequisite already holds at that boundary.
Completion leaves one fully terminal destination set and no transaction
cleanup outstanding. The publication arm reports success only when that set is
the rendered postimage set. The rollback arm uses the same terminal deletion
after restoring the pre-run set but reports the triggering failure, never
publication success. Within either arm, state absence after verified exact
deletion denotes the complete committed terminal set; while a `PREPARED`
record remains openable, recovery unconditionally selects rollback.

For a new transaction, Apply performs this sequence:

1. Under the already-held install lock, classify the fixed state name as
   positively absent. Open the values source and both current output files
   once through no-follow, ordinary single-link handles. Output handles carry
   the access needed for identity-bound rename while denying external write,
   delete, and rename access.
2. Validate TRACKED authority and both actual attribute graphs. Read the input
   bytes through retained handles, render every final byte array, and reparse
   every result. No filesystem write occurs during this render preflight.
3. Mint the transaction ID, derive every sibling stage, custody, and permanent
   backup name, and prove every name reserved for that transaction absent.
4. Create and retain the empty share-none state stage as the first filesystem
   mutation. Then create each sibling output stage with create-new semantics,
   write and flush the complete postimage, verify bytes through the retained
   stage handle, and keep that handle. A collision refuses; no existing
   pathname is overwritten. A crash in this pre-record interval leaves both
   destinations unchanged and only inert, derived stages. A later run reports
   and preserves such a stage rather than adopting or deleting an identity no
   record owns.
5. Through the already-retained share-none state handle, assemble and publish
   the strict `PREPARED` record with the retained values digest and every
   preimage and postimage native identity, link count, byte length, and SHA-256
   digest. The complete state reaches durable storage before the first
   destination rename.
6. Rename each retained destination identity to the recorded custody name
   without pathname replacement. Only after that identity-bound rename may
   Apply classify or back up the preimage. Revalidate native identity, link
   count, length, and digest against the state record; any mismatch starts
   rollback before a postimage lands. Place a verified recovery copy under the
   deterministic preimage path in the existing backup area and retain both the
   custody identity and recovery evidence.
7. Rename each retained stage identity to the now-empty destination without
   replacement. Reopen nothing as authority. Verify recorded native identity,
   link count, length, and digest for each installed postimage through the
   retained stage handle, then revalidate the values source and attribute
   graphs.
8. After both postimages simultaneously verify, finish every fallible action
   while the held `PREPARED` record still requires rollback. Flush and verify
   each deterministic preimage recovery copy. Move each preimage's
   retained custody identity without replacement to its permanent same-volume
   backup name and verify its recorded identity and bytes there. Prove the
   state-creation stage and every output stage and custody name absent, then
   revalidate both destination postimages, the retained values source, both
   attribute graphs, the record, and every permanent backup. At this boundary
   no temporary or custody namespace remains and no later cleanup is required;
   only the final destinations, durably retained deterministic backups, and
   the held state record exist. Flush the affected backup and sibling parent
   namespaces so every archive and terminal absence is durable before
   proceeding.
9. Invoke `DeleteHeldExact` on that state handle. Exact durable deletion is the
   publication commit point. Only the permanently retained backups remain
   outside the two committed destinations, and Apply can report success.

No observer is promised that two filesystem renames occur in one hardware
operation. Atomicity means that no command success, install metadata, or gate
authority names a mixed output epoch. Before the commit point, an absent,
custodied, or divergent tracked prompt makes the existing gate checks refuse.
After the commit point, both declared outputs match the same retained values
epoch and no transaction record or temporary namespace remains.

Any failure before the commit point runs reverse-order rollback. Each published
postimage at a destination first moves through the retained identity back to
its empty derived stage name without replacement. A postimage already at that
stage remains held; one already at its permanent same-volume aborted archive
must verify there. From the stage, Apply creates and verifies the deterministic
aborted-postimage recovery copy, then moves the retained identity to the
permanent aborted archive. A preimage already at its destination is
reverified; one in custody or at its permanent same-volume backup returns by
retained identity to an empty destination without replacement and is
reverified. Any missing recorded identity or pathname occupant of unknown
identity is preserved and causes loud refusal, never deletion or overwrite.

Apply accepts rollback only after both original destination states and bytes
verify, every rollback-evidence copy is durable, and every state-creation,
stage, and custody name is absent. At that point only the restored destinations
and deterministic permanent backups remain. `DeleteHeldExact` then terminalizes
and deletes the aborted transaction state. Apply reports a nonzero
`recovery-aborted` result and ends that invocation without starting a fresh
transaction. A later Apply invocation performs ordinary new-transaction
preflight from positive state absence. Rollback failure leaves `PREPARED` and
every known recovery identity intact. A failure while a Git child of the run
cannot be confirmed ended does not start rollback: `PREPARED`, every recovery
identity and every transaction owner are kept until the process ends, the
refusal names the original failure, and the next Apply recovers the record as
after process termination.

Process termination leaves the durable state record and recovery names. The
next Apply acquires the install lock before opening the record. A valid
`PREPARED` record always rolls back and never finishes publication, even when
both postimages and every permanent backup already verify. Apply derives the
only allowed paths, classifies each destination, custody, stage, identity
backup, and recovery copy against the record, and restores the exact complete
pre-run output set. A recorded preimage identity can move from custody or the
same-volume permanent backup back to its destination; a recovery copy never
substitutes for that native identity. Already completed rollback archival and
namespace-terminalization steps are accepted only after the corresponding
identity, digest, terminal destination set, and expected absence reverify.
The record's `values-sha256` remains evidence of the interrupted transaction
epoch; recovery validates the field's record grammar but never compares the
field with current source bytes.

Recovery keeps the retained state handle and install lock through exact
rollback, durable archive completion, temporary/custody terminalization, and
terminal `DeleteHeldExact`. A crash before delete disposition leaves
`PREPARED`, so the next Apply repeats the bounded rollback. Once disposition
succeeds, explicit owner `CloseHandle` or process teardown of that sole handle
completes exact deletion. The next Apply then finds a complete terminal state
with no cleanup to resume.

A malformed, non-file, reparse, multiply linked, identity-unstable, or
non-`PREPARED` state refuses without touching a destination. Missing required
recovery bytes, a foreign occupant, or an identity, link-count, length, or
digest mismatch for a recorded destination, stage, custody, backup, archive, or
recovery-copy object stops recovery and preserves all evidence for operator
repair. Current values-source, authority, ignore, attribute, template, and new-
input faults are not recovery mismatches. No new transaction starts until
recovery reaches the exact pre-run terminal set and deletes the state record
through its retained handle.

Repeated Apply after committed publication or verified rollback is safe.
Standalone Apply publishes no install manifest, install-version record, LOCAL
authorization marker, or persistent source digest; TRACKED history remains the
trust baseline, while the transient state record governs only publication and
recovery.

Bootstrap and the standalone renderer must call one parser and renderer
implementation. If bootstrap's single-file boundary requires an embedded
copy, byte-exact source identity is a release invariant checked by source
inspection. Similar-looking implementations with divergent marked cores are
not conforming. Code unit-test authoring and execution are prohibited; live
testing, manual checks, ordinary program runs, and functional validation remain
permitted.

No rendering mode edits a root `AGENTS.md` or `CLAUDE.md`. No commit, review,
merge, hook, or dispatcher path invokes the renderer implicitly.

## 6. Full-install transaction

Every full install, same-version refresh, and version upgrade follows this
order:

1. Resolve package identity and classify the target install shape. This
   repository-state classification does not inspect or grade occupied
   destination bytes.
2. Open and retain the values source under the matching authority rule.
3. Open and retain every raw package template; validate every byte boundary
   and required slot.
4. Construct and behaviorally validate the prospective checkout-attribute
   graph for TRACKED paths.
5. Produce every rendered destination byte array in memory.
6. Reparse and validate every complete rendered output, including the
   unresolved-placeholder scan and output-size bound.
7. Revalidate every retained source and template identity, digest, authority
   predicate, and prospective attribute result. Finish non-mutating namespace,
   lock, and mutation-authority checks.
8. Only after all preceding steps succeed, enter destination mutation. For
   every occupied ordinary render destination, first rename the retained
   destination identity to a collision-checked sibling custody name. Only
   after that rename may bootstrap classify the held bytes against `HEAD` or
   manifest baselines and create the verified backup. A failed classification
   restores from custody under the doctrine's reverse recovery order.
9. Publish and verify the rendered destinations and any required tracked
   attribute update through the remaining custody and recovery protocol in
   `docs/local-install-v1.md`.
10. Hash and read back each final installed output, revalidate live tracked
   attributes where applicable, then publish install
   metadata from those exact verified bytes.

Steps 1 through 7 are the render preflight. Any failure in that region leaves
every destination, manifest, version record, dispatcher, and authorization
marker unchanged and creates no destination-stage or custody name.
Occupied-byte baseline and backup classification deliberately occurs after the
first custody rename in step 8; that post-preflight failure is a rollback case,
not a preflight failure.

The source and package-template handles remain held until step 10 completes.
Late writes, renames, link additions, or identity changes therefore fail the
operation rather than mixing value epochs. A successful run cannot combine an
earlier source block with a later source block or hash an output assembled from
an identity no longer held.

Destination replacement retains the existing verified backup and restoration
rules. A failure after mutation starts must end in one of two states:

- every changed destination is restored to the exact pre-run identity and
  bytes, with the prior metadata restored under the existing transaction; or
- the operation fails loudly, preserves every known recovery object, and
  leaves no changed or incomplete destination admitted by the prior LOCAL
  manifest.

Rerunning after a fully verified rollback is valid. A foreign occupant,
unverified restoration, or unresolved recovery object refuses a retry until
operator reconciliation; `-Force` does not waive that refusal.

### LOCAL publication

A LOCAL install acquires the dispatcher lock and per-worktree install lock in
the order defined by `docs/local-install-v1.md`. Bootstrap verifies and retains
the complete prior LOCAL authority state before the first rendered destination
mutation. During destination mutation, the prior manifest and marker remain
unchanged and authorize only exact per-component bytes matching the prior
manifest. A newly created or differing rendered destination therefore fails
LOCAL verification immediately; no new or changed byte gains authority. After
every rendered and non-rendered installed component verifies and the new
manifest digest exists, but before the manifest namespace moves, bootstrap
places the fixed authorization-marker name in the doctrine's durable invalid
reservation state. The marker remains invalid while the manifest is
incomplete.

Bootstrap publishes a manifest only after every rendered and non-rendered
installed component verifies. Final authorization is epoch-bound to that
manifest and commits last. Failure before marker reservation leaves the prior
metadata unchanged, and the prior manifest admits no newly created or changed
destination. Failure after reservation preserves an invalid marker unless the
complete prior destination set, prior manifest, and prior marker have all been
restored and reverified through retained identities. Partial rendered output
never gains LOCAL authority.

For a v2.1 render-bearing install, `-SealManifest` first requires a valid LOCAL
values source and a successful in-process shared-core render. Bootstrap does
not invoke the standalone adapter or reacquire the install lock. The ordinary
arm also requires the equivalent of `-Check` against every v2.1 slot-bearing
render output before minting a baseline. A source/output mismatch can enter
only the bounded current-v2.1 LOCAL recovery arm in section 8; that sanctioned
arm authorizes the held installed bytes solely as a replacement baseline and
does not claim source agreement.

The exact source-agreement exceptions are the bounded current-v2.1 recovery
arm and the frozen-v1.7 and frozen-v2.0 LOCAL recovery arms in section 8. Each
exception seals a complete held inventory under the existing operator sanction
so a later full bootstrap can compare and replace the held bytes.

## 7. Manifest and provenance treatment

Package provenance remains bound to the raw package files. Rendering never
modifies package sources during an ordinary consumer install, and consumer
values never enter a package-source digest or source-commit calculation.
Provenance stamping, where applicable, is part of deterministic installed-byte
assembly after slot substitution.

`crg-install-manifest` records the SHA-256 digest of each final, stamped,
rendered installed file exactly as read back from the destination. The manifest
does not record a raw-template digest in place of the destination digest.

`CROSS-REVIEW-VALUES.md` is never:

- copied from the package;
- overwritten, renamed, deleted, stamped, or backed up by bootstrap;
- listed as package payload or an install-manifest entry;
- listed in the LOCAL authorization marker; or
- represented by a values digest, values epoch, or new manifest field.

The rendered-output digests already bind the executable reviewer and agent
material consumed by the gate. Adding a source digest would incorrectly turn
project-owned configuration into package-owned runtime state.

## 8. Fresh install, refresh, and upgrade

A valid explicit source is mandatory before any operation that creates,
refreshes, upgrades, checks, or seals a render-bearing install. The same source
path and authority rules apply to fresh installs and later runs.

On refresh or upgrade, bootstrap treats the source as desired project content
and the prior manifest or tracked baseline as evidence about existing
destination bytes. A source change authorizes a newly rendered candidate; a
source change does not authorize destruction of an unrelated destination edit.
Every occupied destination must still match the trusted prior baseline or pass
the existing explicit recovery path before replacement. Successful replacement
backs up the prior installed file under the ordinary upgrade protocol.

The project-owned source remains at the target root across package upgrades.
Bootstrap neither replaces the source with stock data nor imports a source from
the incoming archive.

An existing customized v2.0 install without `CROSS-REVIEW-VALUES.md` refuses
before any mutation, including under `-Force`. The diagnostic names the fixed
path and directs these manual actions:

1. create a v1 source;
2. copy the intended project context, project hazards, and SCOPED authority set
   from the existing installed customization into the corresponding blocks;
3. establish TRACKED index authority or LOCAL ignored-file authority as
   applicable; and
4. rerun bootstrap.

Bootstrap does not scrape installed templates, infer values from headings,
read a backup, auto-import legacy text, or synthesize a source. Existing prose
cannot be partitioned safely without an explicit project decision. Automatic
legacy import is outside v2.1.

### Current-package LOCAL recovery

A metadata-free current-package LOCAL install, or one with a deliberately changed
render output outside the recorded baseline, preserves the existing sanctioned
seal-then-replace recovery path. Eligibility is exact and non-fallback:

1. The v1 values source satisfies LOCAL authority, and the shared core parses
   the source and every retained slot-bearing input and produces complete
   candidate outputs. Only candidate-versus-installed byte equality may fail.
2. The present inventory contains every non-retired path in one of, in order,
   the current shared-layout `Get-CrgSealRecoveryFileList`, the frozen
   pre-2.6.0 `Get-CrgPreCommonRecoveryFileList`, the frozen pre-2.4.4
   `Get-CrgPreLivenessRecoveryFileList` or the frozen
   `Get-CrgPreRelocationRecoveryFileList`, including
   `scripts/render-project-values.ps1` and `docs/AGENTS.md.template`. A frozen
   shape also requires every current path it lacks (such as
   `scripts/review-common.ps1`, `scripts/review-liveness.psm1`, or the
   shared-only paths for v2.1/v2.2) to
   be positively absent. A partial upgrade cannot fall back to an older shape.
   The current catalog preserves current installation order; each frozen
   catalog preserves its own authorization-marker order. Each present
   retired path from the selected historical inventory also enters the ordinary
   seal custody. With a strict prior manifest, only retired paths named by that
   manifest join the replacement baseline; surviving files omitted by a completed
   upgrade do not enlarge that baseline. Without metadata, every present retired
   path joins the baseline. Original authorization-marker order is preserved.
   Every held path is an ordinary, non-reparse, single-link file, positively
   absent from `HEAD` and the stage-0 index, and positively ignored. A missing
   required path, an unsupported retired-path occupant, only one new v2.1
   destination, or an extra future metadata entry refuses. Recovery entries are
   not package sources or delivery authority.
3. Install metadata is positively absent, or the complete selected recovery baseline
   differs from the recorded baseline while the prior strict manifest and
   authorization marker name exactly the same selected inventory. An absent retired file
   still named by prior metadata refuses; recovery never invents or restores
   missing bytes. A foreign metadata occupant refuses.
4. The fixed renderer transaction state is positively absent.
5. The existing `CROSS_REVIEW_ALLOW_SEAL=1` operator sanction is present for
   exactly the seal invocation. No new switch or environment authority exists.

After producing candidate outputs only in memory for the eligibility check,
this arm hashes the exact held installed bytes, publishes the ordinary
manifest, and epoch-binds the ordinary LOCAL authorization marker. The arm
publishes no rendered output and performs no file replacement, source
inference, root agent-file edit, review bypass, or provider bypass. The
published baseline authorizes the held bytes, not agreement with the values
source. After removing the sanction, the operator immediately runs the full
`bootstrap.ps1 -TargetRepo <root> -Force`; ordinary baseline comparison,
backup, render preflight, publication, and recovery rules remain mandatory.
Until that full run succeeds, renderer `-Check` continues to report the source
mismatch. An interruption between seal and replacement leaves only the exact
held pre-recovery bytes under LOCAL authority.

The subsequent full bootstrap distributes only `Get-CrgCurrentFileList` and
publishes that reduced inventory. Retired paths are never copied or restored;
retired fixture paths are never executed. Surviving historical files remain
outside current distribution and are not deleted by this recovery operation.

### Frozen legacy LOCAL recovery

A LOCAL v2.0 install whose existing manifest and authorization marker still
verify needs no reseal: after manual source creation, the normal full `-Force`
upgrade consumes that trusted baseline. A metadata-free install, or one with a
deliberately customized file outside the recorded baseline, uses the existing
operator-sanctioned seal workflow before the full upgrade. Released v1.7 has no
install metadata, so an admitted v1.7 inventory follows that seal path.

Legacy seal eligibility is exact and non-fallback:

1. The v1 values source satisfies LOCAL authority.
2. The present installed inventory matches one of the following preserved
   release shapes. Every present path is an ordinary, non-reparse, single-link
   file, positively absent from `HEAD` and the stage-0 index, positively
   ignored, and retained under the ordinary seal custody.

   The complete frozen `v2.0.0` inventory is:

   ```text
   scripts/codex/auto-review.ps1
   scripts/codex/auto-merge.ps1
   scripts/codex/commit.ps1
   scripts/codex/analyze-blocker-trends.ps1
   scripts/codex/author-lint.ps1
   scripts/codex/dispatch-checklist.ps1
   scripts/codex/worker-audit.ps1
   scripts/codex/review-prompt-template.md
   scripts/claude/auto-review.ps1
   scripts/claude/commit.ps1
   scripts/git-hooks/pre-commit
   scripts/run-gate.sh
   scripts/codex/selftest-fixtures/e2e-probe-base-1.rs
   scripts/codex/selftest-fixtures/e2e-probe-base-2.rs
   docs/audit-protocol.md
   ```

   The frozen `v1.7.0` core is:

   ```text
   scripts/codex/auto-review.ps1
   scripts/codex/auto-merge.ps1
   scripts/codex/commit.ps1
   scripts/codex/analyze-blocker-trends.ps1
   scripts/codex/author-lint.ps1
   scripts/codex/dispatch-checklist.ps1
   scripts/codex/review-prompt-template.md
   scripts/claude/auto-review.ps1
   scripts/claude/commit.ps1
   scripts/git-hooks/pre-commit
   docs/audit-protocol.md
   ```

   That complete v1.7 core may carry any present subset of these recognized
   v2.0 additions, under the same file and authority requirements:

   ```text
   scripts/codex/worker-audit.ps1
   scripts/run-gate.sh
   scripts/codex/selftest-fixtures/e2e-probe-base-1.rs
   scripts/codex/selftest-fixtures/e2e-probe-base-2.rs
   ```

   A missing v1.7 core path or an arbitrary partial core refuses.
3. `scripts/render-project-values.ps1` and the installed
   `docs/AGENTS.md.template` destination are absent, and the held legacy prompt
   contains no v1 render-slot marker. Any partial or mixed v2.1 render state
   refuses.
4. The existing `CROSS_REVIEW_ALLOW_SEAL=1` operator sanction is present for
   exactly the seal invocation. No new switch or environment authority exists.

The legacy branch performs only the existing seal act: hash the exact held
legacy bytes, publish the ordinary manifest, and epoch-bind the ordinary LOCAL
authorization marker. The branch performs no rendering, legacy-text parsing, value
inference, root agent-file edit, review bypass, or provider bypass. A missing
frozen path, an extra v2.1 render destination, a foreign metadata occupant, or
any failed custody or repository probe refuses.

Legacy selection uses the independent recovery catalog, not the current
distribution list. Every present recognized retired path therefore participates
in the same authority checks, held-byte hashing, and exact prior metadata
comparison as the frozen core. The later full upgrade neither distributes nor
restores retired fixtures.

The complete recovery sequence is:

1. Extract the tagged v2.1 archive and run the archive's `bootstrap.ps1 -TargetRepo
   <root> -DispatcherOnly`, as required by the existing metadata-free LOCAL
   recovery doctrine.
2. Manually create `<root>/CROSS-REVIEW-VALUES.md`, copy the intended project
   context, project hazards, and SCOPED authority set into the three blocks,
   establish LOCAL ignored-file authority, and add every newly delivered v2.1
   gate destination to the effective LOCAL ignore rules. Bootstrap performs no
   import and adds no gate-destination ignore authority.
3. If the existing v2.0 manifest and marker verify the complete legacy
   inventory, continue directly. Otherwise inspect the retained legacy bytes,
   set `CROSS_REVIEW_ALLOW_SEAL=1` for one
   `bootstrap.ps1 -TargetRepo <root> -SealManifest` invocation, and remove the
   variable immediately afterward.
4. Run the tagged v2.1 `bootstrap.ps1 -TargetRepo <root> -Force`. The sealed or
   already-valid v2.0 manifest supplies only the trusted replacement baseline;
   the explicit values source supplies every new rendered body. Ordinary
   backup, render preflight, manifest, marker, and version publication rules
   remain mandatory.
5. Run `scripts/render-project-values.ps1 -TargetRepo <root> -Check` and the
   installed-shape verification. Success requires the v2.1 outputs, manifest,
   marker, and values source to agree.

An interruption before step 4 leaves the exact v2.0 bytes under the ordinary
LOCAL baseline. An interruption during step 4 follows the full-install recovery
rules in section 6. The legacy seal never authorizes partial v2.1 output.

`-DispatcherOnly` touches no render-bearing file or install manifest and does
not require a values source. A later full install, refresh, upgrade, check, or
seal still requires the source before corresponding work begins.

## 9. Package self-install and portable archive

Package self-install means the canonical package root and target repository
root are the same directory. Under that condition, bootstrap performs render
Check only. No self-install mode applies consumer values to, stamps, or
rewrites a render-bearing package template. A mismatch between the package's
tracked values source and stock slot bodies refuses and names the mismatched
slot. Package maintainers update the source and stock slot bodies as an
ordinary reviewed source change.

The package repository's own `CROSS-REVIEW-VALUES.md` is project-owned
self-check input, not distributable target configuration. The release archive
excludes that file. The archive includes the raw slot-bearing templates,
renderer and installer under the package-root prefix; code-unit-test-only assets
are not package payload.

An extracted archive must support ordinary consumer installation and renderer
`-Check` without package `.git` metadata. Package source provenance may
use the existing documented `unknown` form when no package repository identity
is available. The target remains a Git repository because TRACKED or LOCAL
values authority cannot be established without target repository evidence.

Before ordinary installation from an archive, project values are supplied
separately at the fixed target-root path. Source lookup never walks into the
extracted package directory, so package self-check values cannot become a
consumer fallback.

## 10. Source inspection and production evidence

Code unit-test creation and execution are prohibited, including unit-test
fixtures, SelfTest modes that execute code unit tests, and code unit tests renamed
as ad-hoc assertion scripts or synthetic failure or process-termination cases.
Live testing, manual checks, ordinary program runs, and functional validation
remain permitted and important. Mandatory cross-review and every
production validation, custody, publication, and recovery requirement above
remain binding.

Source inspection establishes conformance with the retained contracts and shared
core identity. Evidence from separately authorized actual installation, rendering,
`-Check`, or recovery operations records the operation performed, exact source
identity, actual outcome, and any remaining uncertainty. Do not create disposable
repositories or simulated inputs to turn a code unit test into a renamed test.
Unexecuted behavior remains unverified; historical receipts do not establish a
new execution or waive mandatory review.

Any implementation that performs runtime lookup, chooses an alternate source,
silently falls back between authority classes, mutates before full render
preflight, hashes raw templates as installed results, packages project values,
admits TRACKED values without the checkout-attribute contract, or edits root
agent-instruction files violates this contract.
