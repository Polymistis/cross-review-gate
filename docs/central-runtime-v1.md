# Central runtime v1: publication and activation

Status: first v2.2 central-runtime foundation, 2026-09-06.
`bootstrap.ps1` implements this bounded publication/activation surface. This unit
publishes verified local
release snapshots and selects one release centrally. Project attachment, dispatch,
private governance, combined receipts, and consumer migration are dependent units,
not delivered or implicitly authorized by a successful publication or activation.

## Normal operation and authority

1. Review a gate source revision through the existing mandatory gate workflow.
2. Publish the approved source bytes, or import an approved release package, into
   an operator-selected machine-local runtime store. Publication does not activate.
3. Activate the published release once. Every future attached invocation selects
   the same central release; no per-project version, pin, or upgrade command exists.
4. An invocation captures one release before review and retains that selection
   through child reviews and commit/merge completion. Activation never redirects an
   in-flight operation. Current releases retain launcher ABI 2 and configuration
   schema 1; existing ABI 1 loaders require the explicit store-wide migration.

Source approval and byte identity are distinct. An expected source commit or
manifest digest identifies the operator-approved input; neither value manufactures
a review receipt. Publication records provenance and verifies bytes, not provider
approval. No command adds provider authorization, suppresses review, fetches remote
content, executes a package payload, or deletes a release or source input.

## Entry points and placement

Add isolated `bootstrap.ps1` parameter sets; no central command accepts `TargetRepo`,
`Force`, `DispatcherOnly`, `SealManifest`, or install-only fault switches:

```text
bootstrap.ps1 -PublishRuntime -RuntimeStore <absolute-directory>
  -SourceRoot <absolute-source-directory> -ApprovedSourceCommit <full-oid>
bootstrap.ps1 -PublishRuntime -RuntimeStore <absolute-directory>
  -ReleasePackage <absolute-extracted-release-directory>
  -ApprovedManifestSha256 <sha256>
bootstrap.ps1 -ActivateRuntime -RuntimeStore <absolute-directory>
  -ReleaseId <sha256>
bootstrap.ps1 -UpgradeRuntimeLauncher -RuntimeStore <absolute-directory>
  -ReleaseId <approved-ABI-2-release-sha256>
```

Commands above are parameter forms, not multiline shell examples. The operator
invokes an approved bootstrap, never an executable supplied by `ReleasePackage`.
`SourceRoot` must be an actual source Git root, not a directory borrowing an
ancestor repository. `ReleasePackage` is extracted data containing the release
manifest and payload; ZIP extraction and export commands are outside this unit.
All central paths must resolve below the explicitly selected ordinary local store;
device paths, reparse traversal, alternate streams, and hard-linked metadata refuse.
The store must not overlap the publication input or a Git metadata directory.

```text
<store>/
  runtime.lock
  active-release
  releases/<release-id>/
    runtime-manifest
    VERSION
    scripts/...
    docs/...
```

`release-id` is the lowercase SHA-256 of the complete manifest bytes. Neither a
version string nor a source commit is a mutable release-directory alias. Existing
release bytes are never overwritten. Transient stages and exact prior active-record
recovery files stay under the store and are never eligible release selectors.

## Exact records

Both record formats are case-sensitive ASCII with LF separators and exactly one
final LF. Reject BOM, CR, NUL, tabs, trailing spaces, blank lines, extra fields,
duplicate fields, truncated input, and bytes outside the stated grammar. Parse the
complete bounded byte buffer before acting. SHA-256 is exactly 64 lowercase hex
digits; a Git OID is exactly 40 or 64 lowercase hex digits. No `unknown` source OID
is admitted to this new format; v2.1 `unknown` records remain valid v2.1 evidence.

`runtime-manifest` (maximum 65,536 bytes), in this exact field order:

```text
crg-runtime-manifest v1
version <semver>
source-commit <git-oid>
launcher-abi 2
config-schema 1
file <sha256> <decimal-byte-length> <relative-path>
```

The `file` line repeats once per payload, sorted by relative path using ordinal
comparison. `<semver>` uses the existing bounded `VERSION` parser; the manifest
version must equal the parsed payload `VERSION`. Decimal lengths contain no sign
or leading zero except the single digit `0`, and are at most 16,777,216 bytes per
payload, at most 256 payloads and 268,435,456 aggregate payload bytes. Paths have
at most 240 characters, use `/`, and contain only ASCII letters, digits, `.`, `_`, and `-` in
nonempty components, and contain no `.` or `..` component. Paths are unique under
both ordinal and Windows ordinal-ignore-case comparison. Components ending in `.`
or matching a Windows reserved device name refuse. File/directory prefix conflicts
are invalid. The manifest owns the exact inventory of an imported or retained
release; helpers can change across compatible releases without a publisher update.
Supported launcher ABIs 1/2 require exact `VERSION`, `scripts/run-gate.sh`, `scripts/git-hooks/pre-commit`,
`scripts/codex/{auto-review,auto-merge,commit}.ps1`,
`scripts/claude/{auto-review,commit}.ps1`, and
`scripts/codex/review-prompt-template.md` entries (braces abbreviate this list only).
Source publication uses this bootstrap's explicit `Get-CrgRuntimePayloadPaths`:
`VERSION`, the existing `Get-CrgCurrentFileList` source paths, and the central-only
launcher, context, governance, tree, and preparation modules. Those additions do
not alter the legacy installer inventory. On-disk omissions, extras, or different casing versus the manifest
refuse. `runtime-manifest` cannot be a payload and does not hash itself.
Frozen v1.7/v2.0 inventories and
the v2.1 consumer payload inventory remain unchanged by this unit.

`active-release` (exactly 95 bytes):

```text
crg-runtime-active v1
release <sha256>
```

The record contains no project identity, configuration override, provider choice,
filesystem path, timestamp, or fallback release. Missing, malformed, or unreadable
selection refuses central selection; no search for a latest directory, source
checkout, old LOCAL installation, or recovered record supplies implicit authority.

## Publication

For source publication, capture the exact repository/common-directory identity
and HEAD, require equality with `ApprovedSourceCommit`, and retain the source
namespace, `VERSION`, and every payload through the existing bootstrap custody
helpers. Existing provenance validation must prove every retained payload against
that captured commit with the existing conversion contract. A changed runtime
payload, untracked payload, indeterminate provenance, or changed source identity
refuses publication. Unrelated unshipped work is not published or executed.

For package import, retain and parse `runtime-manifest`, require the exact
`ApprovedManifestSha256`, and verify every declared payload length and digest.
Preserve the approved manifest's source OID; package claims without the separately
approved digest are insufficient. An old archive lacking this manifest is not
silently assigned new source provenance. No input script is dot-sourced or run.

Write only retained verified byte buffers into a create-new release stage beside
the final directory under `releases/`, permitting same-parent publication. Retain
destination identities and verify exact lengths, digests, and
inventory before publishing the complete release under the manifest-derived ID.
Use existing rooted, no-follow, same-object, no-replace publication mechanisms.
The stable release name must not authorize partial contents. A matching existing
release is an idempotent success only after full retained validation; conflicting
or partial existing contents refuse without overwrite. Report the preserved path.
Publication failure does not alter `active-release`.
Existing identity-proven transient cleanup remains permitted; release and source
deletion remain forbidden. Uncertain cleanup preserves and reports the exact stage.

## Activation, selection, and recovery

`runtime.lock` serializes central mutation and the short selection-capture phase.
Lock contention reports an operation in progress; no stale-path deletion or lock
bypass. A released operating-system handle, not deleting the lock pathname, ends
ownership. Provider work does not hold the central mutation lock.

Activation first retains and fully validates the named published manifest and
payload, including launcher ABI and configuration schema support. Only ABIs 1/2
and schema 1 are accepted; source publication now emits ABI 2. Installed launcher
bytes, installation provenance and the retained origin manifest must agree. An
ABI 1 loader cannot activate an ABI 2 release; an ABI 2 release requires a complete
installed loader. Publish the new active record through the existing retained
stage/prior-custody/no-replace update mechanism while holding the store lock.
Re-read the resulting exact record before reporting activation complete. Selecting
the already active verified release is an idempotent success. No consumer file,
configuration, Git ref, hook, or install authorization marker changes.

First launcher installation requires the manifest to own
`scripts/central-launcher.ps1`, `scripts/central-context.psm1`, and
`scripts/private-governance.psm1`. Pre-launcher foundation snapshots reserved ABI 1
but did not supply these executable capabilities. Such snapshots remain valid for
publication/import and activation in stores without a launcher. Once either stable
launcher file exists, every activation requires complete installation and the
required executable capabilities, including reselecting the current release or
repairing an absent selector. A partial launcher installation cannot enable
selection of an incapable release.

Enabling execution from a pre-launcher store is explicit: publish/import an approved
launcher-capable release, install the stable launcher from that release if absent,
then activate that exact release ID. Retain the old snapshot; no deletion or
configuration rewrite is required. After this transition, compatible rollback
targets must retain these capabilities. Rejecting an incapable target at
activation preserves the current executable selection instead of switching all
attached projects to a release that can only fail at invocation.

An existing ABI 1 installation uses `-UpgradeRuntimeLauncher` with an approved
published ABI 2 release before activation. The store-wide operation retains exact
predecessor/target provenance in `launcher-upgrade`, then replaces only verified
old/new launcher and installation bytes through the existing rooted no-replace
writer. Existing invocation leases prevent migration while those bytes remain in
use. An incomplete launcher/provenance pair refuses activation; repeating the same
explicit migration accepts only the recorded old/new bytes or positive absence,
never foreign occupants. Retain the transition record and both origin releases.
No project configuration, hooks, active selector or private history changes.

The existing custody mechanism can briefly remove the active pathname while the
exact prior record is held at a recovery name. Cooperating selection readers take
the same short lock and cannot observe this intermediate state. Process death
can leave no active record; this is a refusal, not permission to guess a release.
An in-process failure restores the exact prior when custody permits. Otherwise
report the current selector state and preserved recovery paths without claiming
rollback. A subsequent explicit activation revalidates the operator-selected
release and repairs a positively absent selector. Malformed or foreign occupied
selectors require operator disposition; no automatic overwrite or recovery scan.

Rollback uses the same activation command with a retained compatible release ID.
All subsequent attached invocations switch together. Existing invocations retain
the captured manifest identity and exact release/configuration snapshot; dependent
launcher integration must hold validated payload authority through execution and
pass the captured selection to descendants, never reread `active-release` midway.

## Stable interface and bounded completion

Launcher ABI 2 extends ABI 1 with Attach/PushCheck arguments and the internal
`RetainFailure` lifetime callback. Config schema remains 1. The ABI 2 loader reads
retained ABI 1/2 manifests and preserves the recorded-runtime Resume callback;
unknown ABIs refuse. Old ABI 1 loaders and bootstraps reject ABI 2 manifests before
dispatch or publication, rather than accepting an incompatible active release.

Routine upgrades must support the unchanged schema and launcher ABI. Optional
future settings need compatible defaults; unknown schema or settings never silently
alter policy. Incompatible changes require an explicitly approved migration, not
routine project edits. Configuration changes still require mandatory review under
preceding trusted governance; unchanged configuration needs no consumer re-review
when a source-reviewed runtime release is activated centrally.

TRACKED and LOCAL v2.1 installation, manifest, marker, rendering, mode authority,
review routing, and recovery contracts remain unchanged. This unit adds no live
dispatcher, consumer attachment, private-governance enforcement, or provider path.
Completion requires focused evidence for exact source/package publication,
idempotence and mismatch refusal, activation/rollback, and retained selection
across a central switch. No new code unit-test framework is included; live
testing, manual checks, ordinary program runs, and functional validation remain
permitted.
