# Effective Git operation plumbing v1

`scripts/paired-git-operation.psm1` supplies closed Git capabilities for the
future live paired coordinator. No launcher dispatch, attachment activation,
review acceptance, completed-pair publication, or caller bypass is implemented
by this module. The live coordinator still owes both non-review guard sets and
current owned review evidence under `private-governance-v1.md`.

## Closed calls

Every exported call requires `ProjectContext`, the actual `OperationLock`, and
the canonical `public` or `private` domain. Optional `IndexPath` must exactly
equal the selected domain's fixed context-associated index; arbitrary command
arguments, hook directories, environment maps, refs, and message paths are not
accepted.

| API | Additional input | Result value |
|---|---|---|
| `Get-CrgPairedGitHooksPath` | None | Effective `core.hooksPath` state and set value |
| `Get-CrgPairedGitIdentity` | `Kind`: `Author` or `Committer` | Actual public-project effective Git identity line |
| `New-CrgPairedGitResultCommit` | `TreeOid`, `ParentOid`, exact `MessageBytes` | Verified result commit identity, tree, parent, message digest, author and committer |
| `Set-CrgPairedGitExpectedRef` | `ExpectedOldOid`, `NewOid` | Selected context branch and exact old/new identities |

Results contain bounded raw merged output bytes, the exact completed native
child observation, and bounded prerequisite observations. `ReadyForPublication`
is always false. Failed parsing or Git exit raises an error; completed command
observations remain in exception data. Buffers can contain private commit bytes
and are not public evidence or a safe-to-upload classification.

## Effective configuration and identity

The child environment preserves ordinary HOME/XDG/global/system configuration
lookup and legitimate author/committer metadata. Raw Git repository, object,
index, configuration, attribute, history, namespace, and executable-redirection
carriers are refused, including empty values and case variants. Remaining
ambiguous duplicate raw names are refused. Path is canonicalized to one
nonempty entry; replacement objects and lazy fetch are disabled. Ambient
`CROSS_REVIEW_*` variables do not reach these children. No complete environment
block is logged or written to a file.

The hooks query distinguishes exit 1 with empty output (unset) from exit 0
(set, including an empty value). Other exits or malformed merged output refuse.
The query does not attest a dispatcher, approve a custom hook, or replace the
coordinator's hook-preservation/refusal obligation. Global and system config are
not replaced with `NUL`. The hooks query itself remains unbound, so a configured
custom path still refuses. After guard admission, hook-capable mutations (`add`,
`update-index`, `read-tree` and `update-ref`) receive a command-scoped
`core.hooksPath` binding to the retained domain projection at
`<private-git-dir>/.crg-hooks-<guid>/<domain>`. The binding requires the registered
guard owner for the same project and operation lock and validates that private
path; no caller-selected path is accepted. Admitted bytes and explicit no-effect
entries for absent supported hooks remain held through child execution, as
specified in `central-guards-v1.md`. Other ordinary configuration remains
effective. Direct Git LFS pre-push receives the same public binding through
internally generated `GIT_CONFIG_COUNT` entries for nested Git children.

Author and committer identity for both result domains is resolved from the
public project's ordinary effective Git context under the same operation lock,
retained executable and configuration custody. This permits a minimal or adopted
private database to omit local identity configuration without inventing an author.
Private identity configuration is neither mutated nor accepted as a substitute;
no new caller identity parameter is accepted.

`Initialize-CrgPairedPrivateDatabase` takes the retained `OwnedDirectory` and
exact `AttachmentBytes` in addition to `ProjectContext` and `OperationLock`.
Initialization requires matching durable pending-proposal and initialization
records and an absent completion record, as specified in `first-attachment-v1.md`.
Only the recorded new database can enter this path; adoption never invokes an
initializer. Missing components of the fixed minimal bare layout use create-new
directories and durable no-replace HEAD/config publication. Existing components
must match exactly. Recorded initialization can resume an interrupted layout
without resetting history, overwriting metadata or discarding unrelated data.

Initialization invokes no `git init`, template or hook. Existing read-only Git
capture corroborates common/object paths, object format, unborn HEAD and empty
refs while layout custody remains retained. This route creates no private Git
operation scratch before the caller publishes the initialization-complete record.
Interrupted atomic metadata scratch is admitted only under the fixed initializer
names with bytes that prefix the exact intended leaf; existing scratch remains
inert and preserved. Index initialization and subsequent staging still require
the admitted domain hook projection.

`Initialize-CrgPairedPrivateIndex` requires initial fixed-index absence but never
writes that path through `read-tree`. The owned child constructs a self-contained
index beneath retained temporary custody in the actual public Git directory,
with the private object namespace and admitted private hooks unchanged. The
temporary index disables split-index output and sparse-checkout projection.
After confirmed descendant quiescence, the existing ordinary single-link
publication handle and atomic no-replace rename publish `crg-private-index` on
the same filesystem. Concurrent destination creation refuses without replacement.
Only unpublished owned scratch is eligible for exact cleanup; uncertain child
exit retains operation custody, and published staged state is never rolled back.

Result creation resolves the public project's actual author and committer
identities first, then pins the resolved names, emails and dates in each domain's
result-child environment.
No fixed retention-metadata identity is substituted. Message bytes are copied
to an owned private file and passed through `commit-tree -F`; normalization is
not an acceptance rule. The actual raw commit must reproduce the agreed
message bytes and captured identity headers exactly. A mismatch can leave an
unreferenced object but cannot authorize a ref update.

## Public path staging

`Add-CrgPairedGitPublicPaths` requires `ProjectContext`, the actual
`OperationLock`, the public-eligible `Paths`, and a nonempty
`-PrivateExclusions` set. It writes only `:(top,literal)<positive>` entries to
an owned pathspec file and runs
`git add --force --pathspec-from-file=<file> --pathspec-file-nul`. Every
positive must be a present file or gitlink directory the caller classified,
and the caller must already have removed any stale index leaf that a positive
replaces (a former directory under a new file, or the reverse) through
`Remove-CrgPairedGitIndexPaths`; `git add` records the removal of index
entries a positive shadows, so that precondition, not the add, keeps removals
on the explicit route. `--force` stays because the caller's eligibility
classification, not Git's ignore rules, decides what a selected path is.

Git 2.55 pathspec matching of untracked files under negative pathspecs is
order-dependent, so negatives are not passed to git. Before the add, a private
exclusion that is a prefix of any positive (a positive under a private
directory) is a failed stage. After the add, `git ls-files --stage -z` of the
positives (the literal reader `Get-CrgPairedGitStageInventory` also uses) must
show each positive in the public index, including a gitlink (mode 160000); a
missing positive is a failed stage. The same inventory of the private
exclusions is taken before and after the add: a private entry the add created,
or whose mode or object changed, is a failed stage, not a warning. A
private-owned path already in the public index before the add is not this
operation's failure — selection-mode staging removes only selected private
paths from the public index, and the public commit check refuses any that
remain.

## Namespace, ancestry and lifetime

Both databases must remain distinct, with exact common/object directories and
positively absent object alternates. The public operation lock must match the
captured public worktree Git directory. Runtime dependency paths, executable
identity and bytes, and native directory/file custody are checked. Executable
hard links are supported as read-only aliases; project and evidence leaves
retain ordinary single-link requirements.

`ParentOid` and `ExpectedOldOid` must equal the captured domain parent. Only
private positive absence permits a real root result. Otherwise a result is a
sole-parent successor. Object identities are raw and nonzero, actual object
types are checked, and raw commit bytes are independently rehashed. Result
creation changes no ref. Ref updates target only the selected context branch,
require a direct ref or positive absence, use `update-ref --no-deref` with the
explicit expected-old identity, and require exact direct-ref reread.

Outgoing ancestry enumeration refuses existing graft/shallow overlays and binds
`GIT_GRAFT_FILE` and `GIT_SHALLOW_FILE` to an owned immutable empty file. The file
remains retained through every ancestry child and any uncertain cleanup; a later
overlay insertion cannot alter the accepted outgoing set. Ambient override
variables remain refused rather than used as caller-selected history controls.
Every Git child runs with `advice.graftFileDeprecated=false`: Git 2.55 prints a
graft-deprecation hint for any graft file, including the empty control file,
and that hint in the merged transcript would make every ancestry result
noncanonical.

Admitted reference-transaction behavior remains enabled through the retained
projection; unsupported custom hooks still refuse. All Git children
use `paired-process` descendant ownership and `paired-diff` private transcript
custody. Each child has a completion bound — the launcher's default, a
caller-set value within the launcher's accepted range, or the fixed Git LFS
hook lifetime — and bounded output acquisition. Merged diagnostics cannot be parsed as canonical success. A ref
update can already have changed state when a diagnostic or reread fails; the
caller must inspect actual refs rather than assume rollback.

Confirmed child quiescence permits exact cleanup of owned scratch files and
directories. Unconfirmed Stop/Close retains the native session and complete
operation state in exception data, including streams, namespace pins, runtime,
and borrowed operation lock. No PID check, stale-file deletion, force flag, or
release of launcher payload ownership establishes quiescence.

## Verification boundary

The integrated source is checked through PowerShell 5.1/7.6.5 static parsing,
literal native compilation and mandatory source review. Earlier draft fixture
observations are historical, not current acceptance or instructions to run tests.
Result creation, expected-old ref mutation, real reference-hook execution and
live paired publication still require evidence from actual authorized operation.
