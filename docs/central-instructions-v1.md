# Central instructions v1

The root `AGENTS.md` and `CLAUDE.md` remain ordinary privately versioned files.
`central-instructions.psm1` owns only the shared reviewed discovery section and
clean-only materialization of those exact root files. No general template engine,
instruction merge, review bypass or private-index reset belongs to this module.

## Reviewed discovery

`New-CrgCentralInstructionDiscoveryBytes -RuntimeStore -PlanPath -HistoryPath`
returns a canonical LF section bounded by
`<!-- crg-central-discovery v1 BEGIN -->` and
`<!-- crg-central-discovery v1 END -->`. The section identifies the stable
`<runtime-store>/launcher.ps1`, `.crg-project/project.conf`, and explicit private
plan/history paths. Normal consumers select `PLAN.md` and `History.md`; custom
paths are explicit document pointers, not roles inferred from description prose.
The section names the central Open/Stage/Commit/Resume workflow and automatic
provider fallback.

Consumer preparation places this same section in both root instruction files
before review. The generator does not edit files. `Assert-CrgCentralInstructionDiscovery
-Operation -CapturedInput` requires exactly one canonical matching section in
each actual captured private blob. Both selected documents must be regular private
tree leaves with explicit configured roles. Runtime store, blob identities,
section grammar and exact section equality are checked; a duplicate or modified
section refuses. Candidate instructions remain review data and never supply the
rules used to approve that candidate.

The coordinator calls this assertion before review, adding `-RequireWorkingBytes`
for first attachment. That mode compares each working instruction file to the
actual captured private blob without applying text or line-ending normalization.
Missing files or different bytes stop before reviewer dispatch and publication;
existing edits are preserved. Final activation still repeats the exact-byte check
under instruction custody. Ordinary paired commits do not require working bytes
to match staged instructions during this precheck.

Opening a project never
injects a missing section or upgrades instruction prose merely because a new
central runtime was activated. A release that changes the canonical section
bytes therefore leaves every attached project's approved section stale: after
activation, that project's Open and Commit refuse until a reviewed Commit
carries the new section in both root files. Only the candidate is checked on
Commit, so that rewrite is admitted without accepting the old bytes.

## Initial materialization

After current review, durable retention and expected-old publication of the
paired result refs, but before attachment activation, the coordinator calls
`Sync-CrgCentralInstructions -Operation -Initial -CapturedInput -ReceiptBytes`.
The passed first-origin receipt must match the actual captured private tree and
review unit. Initial bookkeeping does not require a completed pointer before
that pointer can exist. Current-run review authority remains exclusively with
the live coordinator, including a freshly reviewed Resume.

Initial attachment requires both reviewed root files already present with exact
approved bytes and matching private staged entries. Existing working edits,
staged changes or missing files refuse activation without overwrite. This
supported boundary avoids guessing whether an existing file is an old checkout,
an intentional deletion or an unpublished edit. Consumer preparation must keep
intended raw working bytes equal to the private candidate, including line endings;
the module does not apply a public Git clean filter to private instructions.

## Per-file approved baselines

The local `<public-git-dir>/crg-materialized` record is strict UTF-8, LF-only,
final-LF text, bounded to 1,024 bytes:

```text
crg-materialized v1
attachment-sha256 <exact-attachment-sha256>
AGENTS.md <paired-v1-or-first-attachment-v1> <approved-receipt-sha256>
CLAUDE.md <paired-v1-or-first-attachment-v1> <approved-receipt-sha256>
```

Each root file has an independent baseline. Resolve the referenced immutable
receipt and actual private tree/blob before comparing working contents. Baseline
metadata alone cannot invent old bytes or establish a review PASS. The receipt
must bind the same attachment, public worktree/Git directory and private
database/ref. Historical runtime activation does not rewrite the baseline or
recompile an older receipt with a newly selected compiler.

`Sync-CrgCentralInstructions -Operation` runs during ordinary Open after current
completed-pair admission. For each file:

| Observed state | Action |
| --- | --- |
| Private index differs from the current approved blob, or visibility flags hide the entry | Preserve staged and working state; report `staged-edits-preserved`. |
| Working file absent | Preserve the deletion; report `working-deletion`. |
| Baseline absent | Preserve files; report `baseline-absent-preserved`; no automatic restoration. |
| Working bytes already equal current approved bytes | Leave the file unchanged; advance the baseline to the current approved receipt. |
| Working bytes exactly equal the recorded old approved baseline | Publish current approved bytes; advance that file's baseline after exact readback. |
| Any other working bytes | Preserve edits and the preceding baseline; report `working-edits-preserved`. |

No existing file needs rewriting during a central runtime upgrade that keeps
the canonical discovery section bytes.
The result is a per-file array containing `Path`, `State` and `Changed`.

## Write custody and interrupted operations

Materialization acquires the fixed private index and any validated split-index
backing before collecting staged entries. The actual operation lock,
directory/runtime/executable owners and those index leases remain held through
preservation decisions and publication. Only the exact root file being replaced
or `crg-materialized` record is released from the general read owner.
Initial root files and the fixed private index remain separately read-held on
`Operation.InstructionReadOwner` through activation and attachment teardown;
general metadata read-phase releases do not dispose that owner. Ordinary writes
reuse the exact native no-replace publisher from `paired-state.psm1` through
`Write-CrgRootInstruction -ProjectContext -OperationLock -Name -ExpectedBytes
-Bytes`. Only `AGENTS.md` or `CLAUDE.md` at the captured public root are accepted,
with a 16 MiB byte bound and required exact existing contents. Metadata entry
points retain the existing fixed Git-directory leaves and 64 KiB bound.

Instruction candidates `.crg-state-<guid>` and prior copies `.crg-prior-<guid>`
remain under the retained ordinary `<public-root>/.crg-project` directory, never
beside root instruction files. This namespace is mandatorily private regardless
of candidate classification or ignore settings. An ordinary no-reparse child
stays on the root filesystem even when the private Git database uses another
volume, preserving atomic handle-relative renames. Missing or nonordinary
`.crg-project` refuses publication without creating a replacement directory.
Metadata-only callers keep scratch and prior records in the public Git directory.

The native writer validates the ordinary single-link preceding file under a
publication-capable handle, durably writes the replacement, moves the held old
file aside, then publishes by no-replace rename. A synchronous publication
failure attempts restoration only from that exact held prior into a positively
free destination. A process loss can leave a named prior/scratch file preserved;
instruction remnants stay in the private namespace, and failed exact rollback
reports the actual private prior path rather than a root-relative guess.
No later Open guesses that a missing root should be restored. The new approved
root and baseline receive exact readback. `Close-CrgCentralAttachment` asserts
and closes the independent initial instruction owner after publication or a
quiescent failure. Ordinary Open closes the extra read owner locally.

A crash after one root advances but before baseline publication leaves the old
record and new approved bytes. A later Open recognizes current approved bytes
without overwriting and records the matching approved baseline. A root missing
after interruption remains a preserved deletion/conflict requiring explicit
resolution. No recursive cleanup or temporary-fixture process is introduced;
verification uses source inspection, parser/build checks, mandatory review,
ordinary program operation and functional validation. Code unit tests remain
prohibited; live testing, manual checks, ordinary program runs, and functional
validation remain permitted.
