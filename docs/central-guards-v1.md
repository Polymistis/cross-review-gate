# Central publication guards v1

`scripts/central-guards.psm1` owns the attached shape's non-review publication
guards and native-hook boundary. Mandatory live review remains coordinator-owned.
The module does not review, stage, construct result commits, update refs, activate
attachments, push public Git refs, or grant authority from a receipt or caller
environment flag. An admitted Git LFS pre-push transfer follows history validation.

## Coordinator interface

- `Open-CrgCentralGuardCustody -ProjectContext -OperationLock -Origin` accepts
  `paired-v1` or `first-attachment-v1` and returns an opaque, process-local owner.
  The exact original owner is required; copied objects do not represent custody.
- `Get-CrgCentralGuardBinding -ProjectContext -OperationLock -Domain` requires
  the current guard owner for that exact project and lock, checks ordinary
  effective `core.hooksPath` without an override, and returns only the admitted
  domain's retained execution projection at
  `<private-git-dir>/.crg-hooks-<guid>/<domain>`. Configured paths, including empty
  values, refuse; no caller-supplied hook directory becomes a binding.
- `Assert-CrgCentralPublicationGuards -ProjectContext -OperationLock
  -CapturedInput -Origin -GuardCustody` runs before and after live review. Both
  effective Git configurations must positively leave `core.hooksPath` unset;
  empty configured values still refuse. Both captured trees must satisfy the
  governing/candidate private-ownership union and namespace/shape contract.
- `Install-CrgCentralGuards -GuardCustody` belongs only to first attachment,
  after live review and durable handoff, before final attachment activation.
  The result reports preserved recovery paths, not publication authority.
- `Close-CrgCentralGuardCustody -GuardCustody` requires coordinator-established
  child quiescence. Keep the owner with the operation/runtime on unconfirmed
  child exit; no mutable boolean or persisted review result establishes cleanup.

The coordinator separately verifies actual refs, parents, public/private index
identities and trees, attachment/completed-pair state, message bytes and prepared
buffers at the final publication boundary. Parsed captured-tree objects are not
those live checks. The coordinator also owns the existing author-lint prepass;
the guard module does not duplicate that run.

Effective Git operations retain the existing raw-environment/namespace checks
and actual child lifetime owner. Runtime and reviewer code come from the retained
central release rather than project-local TRACKED/LOCAL execution copies.
Migration of those old copies remains a separate reviewed operation. Neither
project mode nor private configuration grants work permission or review bypass.

Stage acquires the same ordinary guard and validates both domains before staging
inventory or writes. Guard custody remains held across private object/index
writes and public filtered staging through child quiescence. Unconfirmed cleanup
retains the guard with the stage operation rather than releasing hook custody.
Hook-capable Git mutations bind command-scoped `core.hooksPath` to the admitted
private execution projection, preventing mutable local/global/included
configuration from redirecting hook execution after admission. The unbound
configuration query still refuses custom paths; ordinary effective Git configuration otherwise remains in
use. Recorded new private initialization adds only missing components of an exact
minimal bare layout without invoking `git init`, templates or hooks. Read-only
namespace corroboration precedes the initialization-complete record; index/ref
operations still require the admitted guard projection. Copied-index capture
separately binds hook lookup to a retained ordinary empty-file sentinel, not a
directory, so no executable placeholder spawns a child on that capture path.

## Native hook ownership

Both databases receive a `pre-commit` shim that always refuses raw `git commit`
and names the stable launcher. No receipt path, environment switch, private-index
argument, or special commit message admits a raw commit. Internal reviewed
publication uses the coordinator's existing `commit-tree` and expected-old refs.

The public database also receives `pre-push`. Git-for-Windows supplies the actual
non-bare hook working directory; `pwd -W` passes that worktree root to the absolute
Windows PowerShell host and stable launcher `-PushCheck`. Shared common-directory
hooks never embed the first worktree root. Hook bytes depend on the stable store
path, not the active release, so routine central activation does not rewrite hooks.
The launcher preserves native pre-push stdin bytes and both remote arguments,
and fails on validation errors. Without an admitted Git LFS hook composition,
`-PushCheck` performs no network request. With that composition, paired-history
validation precedes the preserved Git LFS pre-push transfer; Git remains owner of
the eventual public ref push.

Read owners pin both default hook directories and every relevant ordinary,
single-link hook file. Ordinary operations use concurrent read owners; first
attachment retains publication-capable owners for the bounded replacement.
Foreign/custom hooks, nonordinary occupants, indeterminate presence, configured
hook redirection, and unknown active hook material refuse. Standard inactive
`.sample` files and named gate recovery material remain untouched. Existing custom
`prepare-commit-msg`, `commit-msg`, `reference-transaction`, or other hooks cannot
be silently omitted because internal publication does not run raw `git commit`.
Ordinary UTF-8 `pre-commit.<label>.bak` files are inert historical backups,
not hook entrypoints. The bounded label admits ASCII letters, digits, `_`, `-`
and `.`. These files remain byte/identity-held and are never run, rewritten or
deleted; every real hook name retains the original guard checks.

Execution does not revisit mutable absent names in the live hook directories.
The private projection copies admitted hook bytes and fills every absent name in
the supported catalog, including `post-index-change`, with an explicit retained
no-effect script. The absent `reference-transaction` script drains stdin before
successful exit. Projection files and directories remain identity/byte-held
through dependent child execution. No placeholder is written into the live hook
directory, and custom hooks are still refused rather than suppressed.

This absence model serves only the runtime's closed owned Git operations, not
arbitrary Git commands or protocol-bearing server hooks. Consumers require the
registered guard owner for the exact project/lock and validate the domain's
private projection path. Installation refreshes the execution projection after
live hook changes; all projection generations remain retained until confirmed
child quiescence permits exact cleanup.

First attachment accepts an absent hook, the exact central shim, or an exact
recognized stock CRG pre-commit dispatcher plus matching v1 digest. Recognized
stock digests are derived from the literal dispatcher in `83b40f6:bootstrap.ps1`
and released `v2.1.0:bootstrap.ps1`, each with LF and CRLF bytes. A capability
marker and self-supplied matching sidecar alone do not classify custom code as
stock. Other legacy variants require explicit preservation/adoption work.

The supported Git LFS composition is the exact LF-only stock `post-checkout`,
`post-commit`, `post-merge`, and `pre-push` wrappers emitted by the installed LFS
3.7.1. Fixed wrapper-byte
digests classify this bounded compatibility case; changed or incomplete wrappers
still refuse. The three post hooks retain the original bytes and file identities.
The old pre-push wrapper is preserved through the same no-replace recovery path
as the old CRG dispatcher. Private custom hooks remain unsupported. LFS use is
derived from the held public hook composition, never a caller flag or environment
grant, and cannot remove any paired-history validation.

`commit-tree` does not execute Git's native post-commit hook. After a changed
public ref reaches the reviewed result, the coordinator therefore invokes the
retained distribution `git-lfs.exe post-commit` directly under the admitted
public Git/worktree association, ordinary effective environment and private hook
projection. The completed-pair pointer remains unpublished until that owned
child exits successfully. Resume repeats the invocation from immutable receipt
parent/result fields even when interruption already advanced the public ref.
This preserves stock Git LFS handling of effective lockable attributes without
granting execution to arbitrary or custom hook source.

Installation creates and flushes candidate bytes under retained parents, moves
the exact preceding hook/attestation to `.crg-prior-<leaf>-<random32>`, and uses
no-replace publication for the new name. Prior bytes are not deleted. On failure,
the held prior is restored only into a free destination; conflicting occupants
survive with a recovery diagnostic. A crash can leave partial hook installation
and prior files. First-attachment resume rechecks recognized occupants and requires
fresh review before completing installation; ordinary attached operations refuse
missing or mismatched central hooks. No atomic multi-hook replacement is claimed.

## Public push boundary

The native hook obtains the current worktree through Git-for-Windows `pwd -W`.
The PushCheck boundary converts that drive-qualified slash spelling to native
backslashes, validates the canonical local path, and corroborates the actual Git
root before opening the paired operation. Only redundant matching hook-exported
repository selectors are cleared temporarily; the original values are restored
when the operation ends. Other operation path contracts remain unchanged.

`Invoke-CrgCentralPushCheck -ProjectContext -OperationLock -InputBytes -RemoteName
-RemoteLocation` consumes exact native pre-push stdin, bounded to 1 MiB, and the
original bounded remote arguments. Complete LF-only records identify
public branch/tag updates with canonical object IDs. Duplicate/malformed refs,
noncommit targets, indeterminate history and unsupported ref namespaces refuse.
Annotated commit tags are peeled by the owned Git operation. Deletions carry no
new objects but retain the project/guard admission checks.

The custodied current completed-pair pointer anchors the private retention chain.
Each link validates receipt syntax/digest, private retention ancestry/message,
exact evidence inventory and buffer/artifact digests, result commit parents,
trees and agreed message, project association, public result retention, and
predecessor linkage. Historical preparation is validated by recorded byte identity;
older runtimes are not executed and historical PASS never authorizes a new commit.

Actual private parent/result configuration blobs supply the stable schema's
governing/candidate union. Actual public/private result trees must satisfy that
ownership and namespace contract. First attachment uses the candidate inventory
with the fixed mandatory-private names; previous public history is not silently
rewritten or retrospectively re-reviewed.

For each pushed tip, owned Git enumeration checks every reachable commit after
the validated first-attachment public baseline. Every such commit must appear in
the anchored completed-pair history. This includes outgoing intermediate commits,
not only the current tree; remote-old objects need not exist locally to enforce
the boundary. Shallow/grafted histories refuse rather than hide intermediate
commits. The chain is cycle-checked and bounded to 100,000 receipts; outgoing
enumeration is bounded to 16 MiB. Performance is not claimed from static checks.

When exact stock LFS hooks are admitted, `Invoke-CrgPairedGitLfsPrePush` runs only
after that history validation. The owned Git executable supplies its actual
Git-for-Windows `libexec/git-core` directory; the adjacent `bin/git-lfs.exe` is
retained and launched directly, not the PATH forwarding shim. Captured stdin is
flushed into a handle-relative private scratch file and inherited through a
read-only duplicate of the held stream. No shell spool or pathname reopen feeds
the child. The existing explicit inherited-handle allowlist and suspended-launch
private job remain unchanged. The LFS operation alone has a 30-minute lifetime
bound, 15-second progress updates and 16-MiB private output limit; ordinary Git
deadlines are unchanged. Any failure refuses the public push. Input, transcript,
executable and project owners remain retained until whole-job quiescence;
unconfirmed descendant cleanup preserves the exception's operation owners.

Because direct Git LFS launches Git internally, the gate generates a bounded
internal `GIT_CONFIG_COUNT` binding for `core.hooksPath` alongside the captured
public Git/worktree association. Nested Git therefore uses the same admitted
public execution projection; ambient configuration selectors remain refused.

No private object, receipt, config, instruction, alternate, or private reference is
written into the public object database by capture or push validation. Both actual
object namespaces remain distinct and alternate-free. These are path/authority
checks, not content-secret detection or a claim to remove previously public data.

Provider/model authorization, review routing, merge panels, package activation,
consumer migration and arbitrary private synchronization remain outside this
module. Verification uses source inspection, static parsing, builds, normal
authorized operation, and applicable functional testing. Code unit tests or
renamed code unit tests are not authorized; other testing categories are not
prohibited merely by category.
