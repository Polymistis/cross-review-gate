# Live paired publication and recovery

The central launcher invokes release-local code for each operation. The source
integration has not itself deployed a consumer. `first-attachment-v1.md` owns
initial database admission/migration; `central-guards-v1.md` owns non-review
guards. Existing immutable input and retention contracts remain authoritative.

## Ordinary operation

`-Open` admits the actual attachment and preceding completed pair, then reports
the governing private configuration, project mode and instruction state.
Admission requires the private branch at the preceding pair's private result,
since only the gate writes the private database. Admission accepts the public
branch tip whatever commit it is: the preceding public result, a descendant
reached through commits made outside the gate, an earlier commit after a reset,
or an unrelated commit after a rewrite (operator decision 2026-11-23). Commits
made outside the gate are not reviewed; the next review covers only the
submitted change, which is the proposed commit message, the staged software
change against that tip and the staged private change against the private
branch tip, and a changed public result takes the captured public branch tip
as its sole parent. `-Stage` classifies literal public/private paths before either index
changes. Partial staging failures report actual index state without claiming a
two-index rollback.

Open, Stage and Commit still read the tip's public tree, and Commit's
commit-log capture still reads the commits it lists from the tip
(`paired-git-capture-v1.md`). Every existing validation and capture bound on
what these operations read, including the indexes and the working files Stage
reads, is unchanged and applies to every commit and file, whoever made it. When
both trees hold a leaf at a configured role path, the private leaf binds the
role, so Open, Stage and Commit are not refused for that duplicate at the tip;
staging that path removes the public leaf from the public index, as every gate
candidate requires, and stages the working file as the private document, which
requires the working file to pass Stage's own checks and size limit like any
staged file.

`-Commit -MessageFile <path> -AuthoringAgent codex|claude` captures both indexes,
the agreed UTF-8 message and immutable prepared review input. Relative message
paths are anchored at the explicit worktree root; supported message files remain
within that project namespace. Both unchanged ordinary trees report no change.
Initial attachment still requires review when adoption changes neither tree.

Message files require non-whitespace strict UTF-8 text, at most 1048576 bytes,
without a BOM or NUL, and ending with LF. Admission rejects unsupported framing
before review or attachment migration. Message bytes are never normalized after
capture; result commits must preserve the exact reviewed bytes.

The coordinator runs one author-lint pass, followed by the complete current
review schedule. AuthoringAgent is implementer identity, not provider selection.
Only positively identified exhaustion activates the automatic fallback. A saved
receipt, caller boolean or parsed artifact alone supplies no publication credit.

After live PASS, guards, indexed trees, direct refs and exact association metadata
are checked again. The retained public `HEAD` must still name the captured public
ref, and both domains must remain free of merge, rebase, cherry-pick, revert and
sequencer state. Changed results retain real sole parents and exact agreed message
bytes; unchanged sides keep existing commits. Immutable retention is completed
before a durable handoff. Publication order is private ref, public ref,
owned stock Git LFS post-commit for a changed LFS public result, completed-pair
pointer, then exact handoff removal. Initial publication also establishes the
unique private-ref association and required guards/instructions before activating
the public attachment. Success requires final-state rereads.

Both captured indexes, any split-index backing files, and the public `HEAD` remain
read-held through final publication, including Resume. Both domains' absent
operation-marker observations are retained and revalidated over the same interval.
`Release-CrgPairedOperationReadFiles -Owner -Paths` releases only the canonical
project metadata paths undergoing replacement; explicit branch ref updates and
hook installation release neither index nor `HEAD` custody. Association and
pending-proposal publication/cleanup follow the same exact-path rule. Full read
release remains reserved for actual staging/migration phases and final teardown;
first attachment recaptures all required observations afterward.

`paired-state.psm1` mutates only fixed bounded public-Git-directory records under
the actual operation lock. Exact old bytes are retained before any replacement.
Create-new candidates are durably written and hashed, with handle-relative
no-replace publication. Old records move to an exact recovery name first. No
recursive cleanup or overwrite of an unexpected replacement is permitted.

## Recovery

`-Resume` has no new author, message, candidate, provider or release argument.
The loader captures the handoff identity and retains the named original release
before importing live operation modules. Full schema and receipt validation then
binds that same handoff to actual namespaces, results, parents, preceding pair,
prepared bytes, message and recorded compiler. Both current indexes must still
match the immutable candidate.

The data-only resume classifier accepts both-old, private-new/public-old and
both-new states; unchanged sides already satisfy the recorded result. A changed
public-new/private-old state or any unrecorded ref refuses, including a public
branch moved by commits made outside the gate while the handoff is pending: the
recorded transaction binds exact old and new public endpoints and its result's
sole parent. An ordinary missing
pointer is accepted only after both refs reached the results: no-replace pointer
publication can have moved the predecessor aside. The immutable predecessor and
handoff remain mandatory; absence supplies no review credit.

Every accepted state runs a fresh complete review under the original governing
runtime. The runtime must independently derive the recorded leg requirements.
Fresh attempt directories and a create-new private recovery correlation record
bind operation ID, receipt ID, review-unit/descriptor/runtime identities and
actual attempt artifact hashes. The original receipt remains unchanged. Another
process loss requires another review, including after both refs already advanced.

Resume publishes only missing recorded ref transitions and bookkeeping. No
replacement commits, invented parents, index reset, receipt rewrite or replayed
PASS is permitted. When immutable receipt fields record a changed public result
under the admitted stock LFS composition, Resume runs owned LFS post-commit after
both refs reach their results, including when the public ref was already advanced
at recovery admission. Interrupted first attachment uses the exact pending
proposal and private-ref association before finishing activation.

For the bounded published instruction correction in `first-attachment-v1.md`,
ordinary Attach starts a freshly reviewed successor instead of resuming the old
candidate. The prior exact handoff remains part of the captured-state checks
through review. After PASS and new immutable retention, the normal expected-byte
writer replaces that handoff; publication then follows the ordinary first-origin
sequence. The old receipt grants no authority and remains retained. This path
requires unchanged public content and governing configuration and is unavailable
after activation or completed-pair publication. Resume itself is unchanged.

## Lifetime and evidence

Actual process ownership and confirmed descendant drain govern cleanup. Native
uncertainty retains project reads, operation lock, executable/runtime leases,
snapshots and guard owners through the exception chain. Persisted flags, PIDs and
historical receipts cannot prove quiescence. Ordinary confirmed failures preserve
durable forensic data and release only owned resources.

Static parsing, literal native compilation and mandatory source reviews remain
separate evidence from actual installed operation. Code unit tests, renamed code
unit tests, and synthetic review receipts are not authorized by this integration;
live testing, manual checks, ordinary program runs, and functional validation
remain permitted and important.
