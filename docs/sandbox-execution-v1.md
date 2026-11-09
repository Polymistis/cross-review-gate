# Project-owned sandbox execution

The installed launcher is a read-only client. A user-installed local gate host
executes existing operations with the installing account's normal permissions.
Installation supplies this capability. Project sessions require no approval
exception, writable-root addition, network grant or permission-policy change.

## Ownership and admission

Ordinary operations never open a central file for writing. Approved immutable
software and installation metadata belong to the central store; operation locks,
Git state, review records and recovery state belong to the target project.
Unrelated projects do not share an operation lock. Central publication,
activation and installation remain explicit maintenance operations.

The host accepts only existing operation records. Clients cannot supply a
command, executable, environment override, review result, runtime selection,
index path, provider override or script. The host verifies the local caller and
impersonates that caller while retaining a write-capable, no-follow directory
lease for the explicit target. A restricted caller cannot operate on a project
outside the caller's writable scope. Before operation dispatch, the host retains
the ordinary Git directory chain and `.git` indirection. A distinct common Git
database requires the reciprocal worktree record inside
`<common>/worktrees/<id>`, or actual caller write authority to that database.
A back-link inside a caller-owned directory grants no foreign common authority.
Attached projects must match an immutable completed or recovery receipt, including
the public and private database paths and attachment digest. A separate Git
database without a back-link keeps the receipt's exact worktree-folder binding;
a writable proxy folder cannot substitute for the recorded folder. Metadata
capture reads fixed Git objects without opening an operation lock or returning
private configuration. Namespace custody lasts through child exit.

Initial attachment without a receipt accepts the public `.git` directory or a
common-database-owned linked-worktree record. An external separate database additionally
requires the installing caller's write authority until a receipt binds the root.
Private databases under the admitted common Git directory belong to that
admission, including explicit adoption. A supplied path must match an existing
association before external write authority is considered.
External private storage requires explicit caller authority or an existing exact
private-to-public association. Existing attached separate databases and absorbed
submodules use receipt admission without requiring direct sandbox Git writes.

## Local channel and execution

A Windows named pipe identifies the store, account and interactive logon. Remote
clients are rejected. The owner and logon identity receive transport access;
the logon grant admits restricted tokens without granting filesystem rights.
The client verifies the unrestricted server account and logon before sending
project material. A restricted process cannot masquerade as the installed host.

Strict UTF-8 JSON carries an exact schema, protocol version, TargetRepo and
operation. The target requires a local absolute path before normalization; the
client transmits the canonical record. Message paths resolve only inside that
target, and explicit private database paths require a local absolute path.
Frames and push input are bounded. Stdout, stderr and exit frames are
streamed. A health request performs no project operation. Worker capacity is
bounded, with independent workers and explicit refusal before execution when full.
The next listener exists before an accepted connection is dispatched, preventing
endpoint substitution between connections. An occupied endpoint at startup
refuses instead of joining a foreign server.

Each worker invokes the fixed installed launcher as an owned PowerShell child
and supplies an internal envelope through stdin. The envelope contains the
canonical request, admitted Git/common/private directories and exact
present/absent selector digests. Public clients cannot supply that envelope.
The child checks the binding under the project's operation lock before acquiring
operation read owners or expanding roots. Subsequent association and common-dir
reads remain bounded to the admitted databases while publication changes records.
Status also uses project lock custody; application files, indexes and refs remain
unchanged by inspection. Both output pipes are drained
through confirmed child exit. A disconnected client does not cancel publication.
No operation is automatically replayed; an unknown outcome requires the existing
Status/Resume workflow. Connection failures, refusal delivery and failed worker
completion remain isolated from the listener. Every started owner is drained;
unconfirmed read children retain the host and namespace and consume worker
capacity rather than releasing custody during shutdown. An uncertain owned child
keeps the selected runtime and native owners alive after closing output; the host
reports unknown outcome once output drains and process exit remains unconfirmed.

Before concurrent workers start, the host pins the private process input-encoding
cache to UTF-8 without a byte-order mark. Existing metadata readers temporarily
select the same encoding. The prior cache is restored only after all workers
drain. Shared console code pages remain unchanged, and redirected launch verifies
the preamble-free invariant before process start.

## Runtime capture and installation

Launcher ABI 3 preserves ordinary command forms and retained release support.
The worker validates installed provenance, captures active-release with a retained
read handle, validates the immutable release, releases the selector and invokes
existing code. Readers share read access and never acquire runtime.lock.
Selection retries only positive absence or sharing conflict during bounded
maintenance transitions. Invalid bytes, denied access and integrity failures
refuse immediately. No failure authorizes selecting another release.

Maintenance retains rooted identity-checked publication and recovery. A missing
selector beyond the bounded transition refuses and preserves recovery material.
The existing release retention, preceding-runtime Resume and uncertain-child
custody contracts remain binding.

Explicit ABI 2 to ABI 3 migration validates predecessor provenance and retains
the transition separately from earlier migration metadata. Installation creates
a per-user logon startup entry and starts the host for the current logon. Foreign
startup entries are preserved and refused. Startup metadata contains no project
root or review state. Compatible activation needs no session or project change.

Transport code is retained from the installed-origin manifest. Workers capture
the active runtime independently. The operation-read guard preserves the selected
runtime's complete implementation and signature, adding validation at the held
lock boundary and preserving the guard on read facades. Retained ABI 2 execution
uses the trusted ABI 3 orchestration boundary while retaining the recorded
compiler, review modules and runtime identity. No immutable older payload changes.
Existing discovery sections remain admissible;
normal reviewed instruction edits adopt the current host/client description.

## Failure transitions

| State | Failure | Required outcome |
| --- | --- | --- |
| Before connection | Host unavailable | Refuse; no project operation starts |
| Before admission | Invalid frame, schema, caller or target | Refuse; no child starts |
| Child admission | Changed selector or expanded namespace under lock | Refuse before dependent reads or mutation |
| Read owner created | Guard wrapping fails | Close the new read owner; let the original caller unwind the lock |
| Admitted | Capacity or launch failure | Report failure; release only owned resources |
| Child running | Client disconnect | Finish and drain child; preserve normal recovery state |
| Child running | Gate refusal or blocked review | Return exact result without weakening safeguards |
| Child exit unconfirmed | Process or output uncertainty | Retain custody; infer neither cancellation nor completion |
| Child completed | Response delivery fails | Unknown client outcome; no replay |
| Selection | Transient missing/shared selector | Retry bounded capture without fallback |
| Selection | Invalid selector or payload | Refuse before release-local execution |
| Installation | Partial migration/startup failure | Preserve provenance and report incomplete installation; repair validates exact predecessor/target bytes |

## Acceptance

Use source/native compilation, mandatory review and ordinary installed-consumer
runs. Code unit tests remain banned. Required evidence covers unchanged workspace
sandbox permissions; denied direct central/protected-Git writes; successful gate
Open, Stage, Commit and reviewed recovery; independent projects; rejected targets
outside the caller's writable scope; and unchanged central runtime bytes after
project operations. A full-access launch is not sandbox acceptance.
