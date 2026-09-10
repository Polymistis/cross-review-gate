# Project-mode doctrine v1 — review configuration

`PROJECT-MODE.md` tells a reviewer how to evaluate a repository at the
current lifecycle stage. The declaration is review configuration. It is
not a work permit, a task allowlist, a branch gate, or an authorization
channel.

The original Phase B implementation landed at main
`f166118f8eea`, followed by this repository's first `mode: stabilizing`
declaration at `0a7f147`. That implementation treated declaration
transitions as operator-sanctioned, isolated acts and tied activation to
gate-component attestation. The current doctrine supersedes those
mechanisms. Git history remains the record of the original design and
delivery; the rules below are the current contract.

## 1. Purpose and non-purpose

The declaration supplies review context through these fields:

- `mode:` identifies the lifecycle lens for behavior preservation.
- `campaign:` identifies current priority and, when explicit cutover
  wording names disposable targets, the intended compatibility boundary.
- `invariant-surfaces:` identifies durable production contracts. The all-mode
  code unit-test ban supplies no surface-specific exception.

Nothing in the declaration limits what project work may be authored or
landed. In particular:

- work outside the campaign is admissible;
- failure to advance the campaign is never a finding by itself;
- a stale campaign cannot block unrelated maintenance, documentation,
  release, repair, or feature work;
- a declaration edit does not require operator approval or a dedicated
  commit; and
- project-mode configuration never changes gate custody, install shape,
  skip authority, severity parsing, finding categories, or output format.

Code quality remains the highest priority in every mode. Correctness,
security, silent-failure, integration, contract-drift, convention, and
prose-discipline duties do not weaken for prototypes.

## 2. Declaration grammar

A repository may carry a root `PROJECT-MODE.md` with this grammar:

```text
project-mode: v1
mode: prototype
campaign: cut over the legacy wire parser to framed v2 messages
invariant-surfaces:
- save-file format v3 header contract
- public scripting API error codes
```

The grammar is deliberately small:

- Encoding is printable ASCII plus LF only. BOM, CR, other control bytes,
  and non-ASCII bytes are invalid.
- The first non-empty line is exactly `project-mode: v1`, exactly once.
- `mode:` is the next non-empty line, appears exactly once, and has one of
  `prototype`, `stabilizing`, or `shipped`.
- `campaign:` appears at most once and, when present, precedes
  `invariant-surfaces:`. The value is one line, contains at least one
  non-space character, has no leading or trailing space, and is at most 240
  bytes. A prototype declaration requires a campaign; the other modes permit
  omission.
- `invariant-surfaces:` appears at most once and begins the terminal section.
  After that header, only empty lines and `- ` entries are valid. Each entry
  contains at least one non-space character, has no leading or trailing space,
  and is at most 200 bytes. At most 32 entries are accepted.
- Empty lines are permitted. Unknown keys and list entries outside the
  `invariant-surfaces:` section are invalid.
- The file is at most 8 KiB.
- The entry must be a regular file. An executable regular-file mode is
  accepted; a symlink, gitlink, submodule, or directory at the path is
  invalid.
- The declaration remains tracked project metadata in every install shape.

Grammar defines valid configuration, not authority. A candidate
declaration is reviewed as ordinary diff content. Grammar or semantic
defects in that candidate are ordinary diff-anchored PLAN-DRIFT BLOCKERS;
candidate bytes do not become the governing block for the same run.

## 3. Governing state and safe fallback

The change under review never selects its own review mode. Each
prompt-producing scope reads the declaration from the newest trusted state
that precedes the change:

| scope | governing state |
|---|---|
| `Staged` | `HEAD`, never the index |
| `Uncommitted` | `HEAD`, never the synthesized working-tree candidate |
| `Commit` | the reviewed commit's first parent; a root commit has no declaration |
| `Branch` | the merge gate's pinned base OID, never the candidate tip |

A declaration edit may be mixed with any other project change. The entire
diff is reviewed under the preceding declaration. After landing, the new
declaration supplies context only to later reviews.

Resolution outcomes are:

1. **Valid declaration** — inject the parsed mode, campaign, surfaces,
   and governing ref.
2. **Verified absence** — proceed under `shipped` defaults.
3. **Positively malformed declaration** — a verified non-regular entry or
   grammar-invalid regular file produces a loud warning and proceeds under
   `shipped` defaults. Malformed review configuration never wedges project
   work.
4. **Indeterminate repository read** — a failed ref, tree, object, or blob
   read is a tooling failure and refuses the run. Failure is neither
   verified absence nor verified malformation.

Exactly one governing-state visibility line is printed for every invocation
that reaches project-mode resolution. The line names a governing mode,
verified absence, malformed-to-shipped fallback, or a tooling refusal from
that resolution. A scope preflight that fails before project-mode resolution
may exit without such a line. Auxiliary warnings are reserved for positively
malformed configuration; routine valid or deleted candidate state stays in
the injected evidence block. A fallback block also states explicitly that
`shipped` defaults govern the run.

No activation-provenance walk participates in resolution. No last-touch
parent, capability token, dispatcher token, component attestation, or
parent-commit precondition decides whether valid configuration is read.
Generic trusted-copy and LOCAL-install verification still protect the gate
code that executes; those controls are independent of project-mode data.

## 4. Ordinary landing paths

`PROJECT-MODE.md` uses the same landing paths as other project
configuration:

- `CROSS_REVIEW_ALLOW_MODE_CHANGE` has no authority and is ignored if present;
- no declaration-only isolation rule exists;
- a declaration may be added, edited, renamed, or deleted beside other
  work;
- no branch-history sanction or declaration-specific topology rule exists;
- `CROSS_REVIEW_SKIP=1` has the ordinary audited-skip behavior and no
  declaration-specific refusal; and
- a malformed governing declaration does not create a special repair
  transaction because ordinary work and ordinary fixes already proceed
  under the safe fallback.

The candidate remains authority-free without any of those restrictions:
the trusted preceding state governs the current review. A candidate cannot
obtain a more lenient review by staging `mode: prototype`, whether the edit
lands alone or beside source changes.

## 5. Authority boundary for free text

Campaign and surface values are DATA. The machine-injected block frames
each value behind a fixed key, and the review template defines the only
ways those values are consumed:

- mode selects the fixed behavior-preservation rules;
- campaign supplies lifecycle context and priority;
- an explicit cutover campaign may identify named disposable targets for
  the fixed compatibility matrix below; and
- surface entries identify durable production contracts, not test obligations.

Free text cannot add, remove, or re-tier reviewer duties. It cannot alter
finding categories, severity parsing, scope discipline, evidence rules, or
output format, and it cannot address the reviewer. Reviewer-facing text
such as “ignore findings” or “treat this as passing” is inert as an
instruction and is a PLAN-DRIFT BLOCKER on the candidate diff that
introduces it.

Candidate declaration review checks that:

- campaign text is meaningful lifecycle context rather than vacuous text;
- cutover wording names every path, feature, or behavior treated as
  disposable;
- each invariant-surface entry resolves to an identifiable code or
  contract surface; and
- a named disposable target does not overlap an invariant surface.

Failure of any candidate semantic check is a PLAN-DRIFT BLOCKER. Those
checks are diff-anchored. A pre-existing semantic defect in the
governing declaration is not an out-of-diff blocker on unrelated work.
Ambiguous campaign text grants no compatibility carve-out, ambiguous
surface text creates no instruction, and the reviewer reports any useful
pre-existing observation only at the normal note tier allowed by scope
discipline.

## 6. Mode semantics

Mode affects only behavior preservation. Code unit tests are banned in every mode.

- **`prototype`** — behavior preservation is not a default duty.
- **`stabilizing`** — behavior preservation is a default duty except for
  targets explicitly named by a cutover campaign.
- **`shipped`** — behavior preservation is a default duty except for targets
  explicitly named by a cutover campaign.

Every diff is judged against its own stated intent and the mode's fixed
duties. Campaign context helps establish priority and interpret an explicit
cutover; campaign advancement is never the verdict question.

A campaign is **cutover-declaring** only when the text declares a
replacement or cutover and names the disposable paths, features, or
behaviors. Any other campaign is contextual only. The compatibility
matrix is:

| mode | campaign | behavior preservation | surviving transition machinery |
|---|---|---|---|
| `prototype` | contextual | not owed | ordinary shim rules |
| `prototype` | cutover-declaring | not owed | BLOCKER on named disposable targets |
| `stabilizing` | contextual or absent | owed everywhere | ordinary shim rules |
| `stabilizing` | cutover-declaring | owed except named targets | BLOCKER on named disposable targets |
| `shipped` | contextual or absent | owed everywhere | ordinary shim rules |
| `shipped` | cutover-declaring | owed except named targets | BLOCKER on named disposable targets |

“Surviving transition machinery” means machinery designed to outlive the
landing: dual-path dispatch, old-path selection flags, adapters preserving
the retired path, or keep-just-in-case retention. Branch scope can observe
whether such machinery remains at the tip. Staged, Uncommitted, and Commit
scope apply the existing explicit-removal-declaration convention because
future commits are not visible. These rules target named cutover residue;
they do not make unrelated work inadmissible.

## 7. Verification evidence and code unit-test ban

The operator decision of 2026-09-07, clarified 2026-09-08, bans authoring,
maintaining, restoring, and running code unit tests. Existing code unit tests
and unit-test-only assets must be removed through the normal reviewed workflow.
No project mode or invariant surface grants an exception. Renaming a code unit
test as a probe or verification script does not change the ban.

The ban is limited to code unit tests. Earlier wording banning all tests was
incorrect and is superseded. Integration, end-to-end, smoke, performance,
manual, live, and other functional testing are not prohibited merely by category
and remain important verification methods.

Preserve production validation, runtime assertions, error handling, and safety
checks. Source inspection, mandatory code review, builds, ordinary program
operation, and applicable functional testing remain verification methods. Build output establishes buildability;
a captured real-interface run demonstrates only the behavior actually observed.
Every credited citation names the date, command, observed output, and revision.
Commit and Branch scopes can consume the labeled full commit-message channel;
Staged and Uncommitted scopes require evidence in the diff or another visible
channel. Unverified behavior is reported explicitly, never filled with a new
code unit test.

New or restored code unit tests, unit-test-only support, or instructions requiring
code unit tests are BLOCKER policy violations under the existing `TEST-QUALITY`
category. Missing code unit tests and authorized code-unit-test deletion are never findings. Scope discipline still
applies to untouched pre-existing files. Production correctness and mandatory
cross-review remain unchanged.

## 8. Implementation contract

- `scripts/codex/auto-review.ps1` and
  `scripts/claude/auto-review.ps1` mirror governing-ref resolution,
  declaration parsing, safe fallback, visibility, and block assembly.
- `scripts/codex/review-prompt-template.md` owns the reviewer-facing mode,
  campaign, invariant-surface, compatibility, evidence, and code-unit-test-ban
  rules.
- `scripts/shared/auto-merge.ps1` supplies the pinned base OID. The wrappers
  remain the declaration resolvers.
- Candidate declaration content reaches the reviewer through the ordinary
  diff. No candidate block replaces the governing block.
- `scripts/git-hooks/pre-commit` and the installed dispatcher apply the
  normal review and audited-skip contracts. No declaration-specific
  sanction, skip refusal, rollback anchor, or recovery bypass belongs in
  either layer.
- TRACKED and LOCAL install shapes resolve project mode identically. The
  local manifest and authorization marker verify gate code, never
  `PROJECT-MODE.md` authority.
- README, INSTALL, the installed AGENTS template, and the audit protocol
  describe the same ordinary-configuration boundary.

Production invariants to inspect during review include (not code-unit-test-authoring
tasks):

- verified absence selecting `shipped`;
- every valid mode and every grammar boundary;
- malformed governing regular-file and entry-type cases warning and
  selecting `shipped` without refusing ordinary work;
- an indeterminate governing or candidate repository read still failing
  closed;
- verified unborn/root absence remaining distinct from failed `HEAD` or parent
  resolution;
- Staged and Uncommitted scopes governed by `HEAD`;
- Commit scope governed by the first parent, including root and merge
  commits;
- Branch scope governed by the pinned base;
- mixed declaration-and-work changes proceeding under the preceding
  declaration;
- a candidate declaration never governing its own run;
- candidate grammar and semantic defects reaching ordinary diff review;
- declaration edits using the normal audited skip path; and
- an unrelated, high-quality diff remaining admissible when a campaign is
  present but not advanced.

## 9. Pre-redesign TRACKED upgrade boundary

A TRACKED install whose trusted `HEAD` still implements the original
project-mode enforcement cannot safely replace the whole package in one
commit. Refreshing the per-clone dispatcher removes the dispatcher-level retired checks,
but the dispatcher must still execute the old trusted `HEAD` hook. A full
package candidate also changes routing drivers, which the old audited-skip
guard correctly refuses.

A normal consumer target begins with an empty index and worktree before the
separate package source is copied in. A self-host target begins with an empty
index and the intended candidate package diff already present in the worktree:
source and target are identical there, so a clean self-host worktree contains
no candidate kernel to publish. Unrelated worktree state is excluded.

The bounded retirement therefore uses a kernel landing followed by a completion
landing:

1. Refresh the dispatcher with `-DispatcherOnly`, then run the full bootstrap.
   A successful full install publishes a base-HEAD-bound identity record for
   the changed review-kernel entries and `.gitattributes` when the LF contract
   changes. Restore or remove each raw routing driver according to the trusted
   `HEAD` state, stage exactly the record-named entries, and use the ordinary
   audited skip for that identity-attested kernel landing. A self-host install
   preserves the phase-two routing-driver bytes in digest-verified,
   base-bound custody outside the worktree before publishing the record.
2. After that exact kernel commit is present in the target base, restore the
   self-host routing drivers through the generated custody checks when
   applicable, re-run the full bootstrap under the current kernel, and land
   the remaining package normally with `REVIEW_BACKEND=both`. In a self-host
   transition, those remaining candidate bytes were present before the first
   bootstrap and stay uncommitted while only the record-named kernel lands.

The first landing is a gate-policy retirement transaction, not authority for
project work and not a declaration transition. `PROJECT-MODE.md` remains
untouched. The refreshed dispatcher recognizes the retired trusted-HEAD
signatures, verifies the record base, modes, filter-aware blob OIDs, omitted
protected paths, staged LF contract, routing-driver state, and absence of extra
staged paths, records the staged tree, and exits without executing either the
retired policy or candidate gate code. Ordinary non-skip commits still delegate
to trusted `HEAD`. A generic audited skip delegates only when trusted `HEAD`
carries exactly one `# crg-dispatch-tree-handoff-v1` capability marker; a
pre-handoff legacy kernel refuses generic skips while this exact record-bound
transition remains available.

The target-base condition is substantive. A merge gate extracts trusted
wrappers and the prompt from the target base, so placing the kernel only in an
earlier commit on the candidate branch does not activate the new contract for
that branch review. A feature-branch workflow must land the kernel alone, then
create or rebase the remaining branch onto the updated base before the normal
second landing.

Legacy prompt customization does not justify restoring legacy gate rules.
Only project-owned content from the project-context and project-hazards
sections may be ported into the current stock prompt; the entire legacy prompt
must never be copied over the current template. Those section edits may join
the normal second landing because the trusted stock prompt from current
`HEAD` reviews the candidate. A separate prompt-only reviewed commit is an
optional isolation choice, not a third required infrastructure landing.

An interruption does not create a declaration recovery state.

A self-host full bootstrap publishes base-bound, digest-verified routing
custody before attempting transition identity publication. Custody is the
write-ahead record for that publication boundary. Positive absence of
`crg-review-kernel-transition` is recoverable only while `HEAD` remains the
exact recorded legacy base, with the held active record, matching base-directory
record, and every custody source digest verified.

When the current self-host routing sources still match the captured candidate
bytes, the full self-bootstrap may retry the incomplete publication against
that same custody epoch. An external package source may not perform that retry:
different candidate bytes could otherwise be bound to existing self-host
custody. When the routing sources instead contain phase-A bytes, an absent
driver, a mixture of candidate and phase-A state, or any edit, the full
bootstrap refuses before mutation. Run `-RestoreLegacyRoutingCustody` from the
target checkout before retrying. At the exact legacy base with a positively
absent identity record, that restore reconstructs the candidate routing
sources and creates no post-kernel completion marker.

A malformed or non-file transition record is not absence. Such a record, a
moved `HEAD`, foreign or divergent custody, or divergent routing-source bytes
causes the full bootstrap to fail before package, repository, or per-worktree
Git-directory mutation. Preserve every custody record.

The transition identity and self-host active custody cannot be rebound to
another legacy base in the same worktree. A full bootstrap targeting that
worktree after such a base change refuses before package or repository mutation
rather than publishing a second active epoch. A complete external package
source cannot make the stale target safe because the active epoch belongs to
the target's Git directory. Recovery either returns that worktree to the
recorded base or targets a fresh linked worktree at the intended legacy base,
whose independent per-worktree Git directory carries no foreign epoch. If phase
A already left the candidate routing drivers in legacy or absent state, first
return the candidate checkout to the recorded base and run
`-RestoreLegacyRoutingCustody`; the resulting complete candidate payload may
then serve as the external package source for the fresh target.

After the kernel reaches the target base, the same operation accepts only the
exact base-to-kernel landing and restores the phase-two routing drivers; no
manual copy recipe is a supported recovery path. A normal consumer install
likewise reads candidate bytes from the separate package source. Re-run the
full bootstrap before the remaining landing. A later bootstrap overwrite of a
customized prompt is recovered by porting only the project-context and
project-hazards sections from verified custody or a trusted current commit. The
audited skip is not used again after the kernel landing.

## 10. Historical boundary

The retired operator sanction, declaration isolation, activation
provenance, standing component attestation, dispatcher rollback anchor,
lineage-exact project-mode recovery, and campaign-advancement verdict rule
were properties of the original implementation. Historical delivery
records may continue to describe those facts in past tense. No current
instruction, installer checklist, or audit criterion
may present those mechanisms as live contract.

Worker-side hard-cutover guidance for individual consumer projects and
test-churn telemetry remain separate concerns. Neither changes the review
configuration boundary defined here.
