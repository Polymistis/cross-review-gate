# Port reconciliation contract (migration P1)

The design contract governing every slice of the 2026-08 upstream migration
(`docs/migration-plan-2026-08.md`). It precedes every code slice, per the
source project's design-before-code ruling. Every slice conforms to this
contract; a slice that needs to deviate stops and amends this document first,
as its own docs round.

## Contract

The port is a MERGE of the source project's modern capability onto this
package's hardening — never a file replacement in either direction. The
source copies are newer and larger; this package's copies carry deliberate
generalizations the source dropped. Both survive.

**Trust tier.** Gate scripts guard the review process; the follow-up index
and its lock are workspace-writable execution state. Execution-state
mechanisms receive correctness review, not adversarial hardening against a
local actor who could delete the artifact outright — the calibration the
source project's severity contract already encodes.

**Namespace.** The complete rename mapping — every slice uses exactly this
table, nothing renames by wildcard:

| source name | package name |
|---|---|
| `SC_SKIP_REVIEW` | `CROSS_REVIEW_SKIP` |
| `SC_SKIP_AUTHOR_LINT` | `CROSS_REVIEW_SKIP_AUTHOR_LINT` |
| `SC_COMMIT_REVIEW_EFFORT` | `CROSS_REVIEW_COMMIT_EFFORT` |
| `SC_FOLLOWUPS_PENDING` | `CROSS_REVIEW_FOLLOWUPS_PENDING` |
| `SC_REVIEW_PASSES` | `CROSS_REVIEW_PASSES` |
| `SC_FOLLOWUP_*` doctrine/lock shell constants | `CROSS_REVIEW_FOLLOWUP_*`, renamed in their lockstep slice (script-internal; the doctrine FRAME bytes contain no names and are untouched) |
| `SC_ALLOW_MASTER_MUTATION` | project-only — guards a machine-local hook outside this package's scope; retained project-side, no package counterpart |

`REVIEW_BACKEND` is package-owned, unprefixed, and unchanged. A rename lands
with BOTH sides of each env handshake in the same slice; a half-renamed
handshake silently drops staged follow-ups or pass counts.

**Index location.** The follow-up index lives at `logs/review-followups.md`,
resolved submodule-aware. The source project's `.orchestrator/` relocation is
a consumer-side choice and never ships as the package default; if a
configurable index directory is wanted, it is added as an explicit seam in
its own slice.

**Seams that survive the merge** (each was silently reversed in the source
copies and must be restored around the incoming capability):
- the configurable consistency-doc (`CROSS_REVIEW_CONSISTENCY_DOC` with
  blob-kind fail-closed validation) — never a hardcoded plan-file name
- the `CROSS_REVIEW_PRUNE_TOOL` seam with validated fallback — never a
  machine-local delete-tool path
- submodule-aware log and index dir selection
- origin/HEAD base-branch resolution in the merge gate — never a hardcoded
  base name
- the no-recursive-delete cleanup policy (`Remove-TreeNoRecurse` and the
  sh equivalent) even for the gate's own scratch
- the PS 5.1 child-launch PATH contract: preserve the effective
  case-insensitive lookup order first, append directories found only in
  additional raw case variants, then collapse all variants to one verified
  canonical `Path` entry or fail closed
- the sh hook's Unix-tool PATH repair and `core.excludesfile` neutralization

**Lockstep sets.** The capture-doctrine frame is byte-identity-pinned across
every index writer — so the lock-protocol slice lands the complete writer file set
as a single gated unit, or not at all. Any wording change to the frame is a
doctrine version bump across every writer, never an edit.

**Doctrine-version semantics.** The version numbers the frame's STATED
CONTRACT — what the doctrine promises — not the reader implementation. A
change that alters what the frame promises (a new exempt state, a narrowed
duty, a different locator grammar) bumps the version and rewords the frame
across every writer in lockstep. A reader-side change that makes a scanner
CONFORM to the current frame's stated promises — denying the prune on a
shape the validator rejects, treating an unresolvable or torn claim as
unresolved, failing toward duty — is a conformance fix, not a contract
change, and does not bump: the frame already said it, the reader now honors
it. The discriminating test: would the frame's text need to change to
describe the new behavior truthfully? If the existing text already describes
it, no bump. Conformance fixes additionally lean toward safety in the
common case — a conforming reader treats more states as unresolved, so it
deletes less than a non-conforming one on those states — but that is a
tendency of the fail-toward-duty rule, not a construction proof; a
conformance fix still carries its own review of what its reader deletes,
and a mixed-version deployment is expected (not guaranteed) to degrade
toward retention.

**Prose hygiene.** Source-project provenance (iteration numbers, dated
incident citations, machine paths, memory-file references, project fixture
vocabulary) is re-genericized to this package's scrubbed style on entry.
Comments citing source-only artifacts are re-pointed at package docs or made
conditional. Code unit tests and unit-test-only material must not be ported.

**Verification bar.** Every slice lands through the normal commit and merge
review gates. Inspect changed production paths, parse edited scripts, and
record applicable ordinary-operation and functional-test outcomes. The operator
decision of 2026-09-07, clarified 2026-09-08, bans code unit tests and
unit-test-only support, not integration, end-to-end, smoke, performance, manual,
live, or other functional testing merely by category. Earlier broader removals
remain historical facts pending separate impact assessment; this contract does
not restore files or create replacement obligations.

**Exit paths.** `CROSS_REVIEW_SKIP=1` remains the sole audited bypass, with
its fixed local `refs/crg-review-skips` commit-chain publication remaining
fail-closed. No slice adds iteration caps,
early-stops, or retry limits TO GATE-REVIEW CONVERGENCE — a review iterates
to its verdict and is never truncated by a counter. Distinct from that banned
class: MECHANISM-INTERNAL bounded retry budgets that fail loud (warn-and-drop,
warn-and-skip) are ported source design wherever the source carries them —
the follow-up lock's contention budget and its delete-pending-window retry
are the canonical cases. Their bounds are load-bearing: removing them trades
a loud, recorded drop for an unbounded hang on an ANCILLARY step — and the
gate's ancillary machinery must always terminate. (The review WAIT itself is
the sanctioned exception: the merge gate deliberately waits unbounded on a
launched review child, because abandoning a still-valid review is worse than
an operator-visible hang; the bounded budgets govern the mechanism-internal
steps around it, never the review wait.) A slice may port such budgets
verbatim; it may not invent new ones without amending this contract first.

**Versioning.** The reconciled line releases as v2.0.0 through the
migration's versioning slice (VERSION stamp, upgrade mode, per-file hash
manifest with refuse-on-local-drift). No consuming project re-vendors before
that slice lands.
