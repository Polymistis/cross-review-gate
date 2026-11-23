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

**Trust tier.** Gate scripts guard the review process; review logs and
findings records are workspace-writable execution state. Execution-state
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
| `SC_REVIEW_PASSES` | `CROSS_REVIEW_PASSES` |
| `SC_ALLOW_MASTER_MUTATION` | project-only — guards a machine-local hook outside this package's scope; retained project-side, no package counterpart |

`REVIEW_BACKEND` is package-owned, unprefixed, and unchanged. A rename lands
with BOTH sides of each env handshake in the same slice; a half-renamed
handshake silently drops pass counts.

**Seams that survive the merge** (each was silently reversed in the source
copies and must be restored around the incoming capability):
- the configurable consistency-doc (`CROSS_REVIEW_CONSISTENCY_DOC` with
  blob-kind fail-closed validation) — never a hardcoded plan-file name
- submodule-aware log dir selection
- origin/HEAD base-branch resolution in the merge gate — never a hardcoded
  base name
- the no-recursive-delete cleanup policy (`Remove-TreeNoRecurse` and the
  sh equivalent) even for the gate's own scratch
- the PS 5.1 child-launch PATH contract: preserve the effective
  case-insensitive lookup order first, append directories found only in
  additional raw case variants, then collapse all variants to one verified
  canonical `Path` entry or fail closed
- the sh hook's Unix-tool PATH repair and `core.excludesfile` neutralization

**Prose hygiene.** Source-project provenance (iteration numbers, dated
incident citations, machine paths, memory-file references, project fixture
vocabulary) is re-genericized to this package's scrubbed style on entry.
Comments citing source-only artifacts are re-pointed at package docs or made
conditional. Code unit tests and unit-test-only material must not be ported.

**Verification bar.** Every slice lands through the normal commit and merge
review gates. Inspect changed production paths, parse edited scripts, and
record applicable ordinary-operation and functional-validation outcomes. The
operator decision bans code unit tests and unit-test-only support; live testing,
manual checks, ordinary program runs, and functional validation remain
permitted. Earlier broader removals
remain historical facts pending separate impact assessment; this contract does
not restore files or create replacement obligations.

**Exit paths.** `CROSS_REVIEW_SKIP=1` remains the sole audited bypass, with
its fixed local `refs/crg-review-skips` commit-chain publication remaining
fail-closed. No slice adds iteration caps,
early-stops, or retry limits TO GATE-REVIEW CONVERGENCE — a review iterates
to its verdict and is never truncated by a counter. Distinct from that banned
class: MECHANISM-INTERNAL bounded retry budgets that fail loud (warn-and-drop,
warn-and-skip) are ported source design wherever the source carries them.
Their bounds are load-bearing: removing them trades
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
