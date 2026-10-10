# Capture doctrine v6 — positive transaction framing (design)

This doctrine defines the closure through positive transaction framing for the
follow-up-index format: every append is bracketed between an explicit opening
marker and a completion record bound to its rows by a digest, with pruning
denied for any transaction lacking valid completion. The closure covers
every content-losing cut that reaches the file under v6 (an append that
dies before its first byte lands leaves no trace any format can see, and
a cut costing only a trailing blank separator costs no content); a pre-v6 tail is unverifiable by construction —
a v5-era line-boundary tear left no evidence any reader can recover — so
migrated legacy content is QUARANTINED behind an operator-directed seal,
byte-bound to the inspected content (§2, §4), rather than silently
accepted. Per the
reconciliation contract's doctrine-version
semantics this is a PROMISE change (the frame's text must describe the new
records), so it bumps the doctrine to v6 and rewords the frame across every
writer in lockstep. The contract itself does not specify the index format;
nothing here deviates from it, so no contract amendment accompanies this
design.

Operator ruling, 2026-09-07, clarified 2026-09-08: code unit tests are banned
and existing code unit tests and unit-test-only assets must be removed. No code
unit-test authoring or execution is required or permitted by this doctrine.
Live testing, manual checks, ordinary program runs, and functional validation
remain permitted. The production contracts below remain mandatory; verification
uses normal gated review, static parsing, read-only source inspection, and
functional validation. Historical
observations remain evidence, not instructions to recreate or run code unit tests.

## 1. The defect being closed

Under v5, every runtime decided "is the index's last transaction complete?"
the same way: is the file's final byte LF (`Test-FollowupIndexTerminated`,
and `crg_followup_index_is_terminated` in the shell hook up to 2.6.0 —
still exactly that final-byte test today; under v6 the COMPLETION question
moved to the grammar validators, `Get-FollowupTailState`/
`Test-FollowupIntervalComplete` and, in a 2.6.0 hook,
`crg_followup_tail_state`/`crg_followup_block_check`, with the final-byte
test kept as the cheap first check and as the whole test only for a legacy
index with no v6 region). The v5 rule caught a write cut mid-line and
nothing else. A write cut at a LINE boundary — after the block header, after
a row, after a complete frame, or inside prefix prose — left
the file LF-terminated: the append path accepted the tail, the prune scanner
read what remained as complete (a shortened block, or ignorable preamble),
and the rows that were cut (which may have included a capture claim) vanished
without any signal. (Cuts inside the frame v5 already catches — an
unclosed frame denies the prune today; the silent cuts are those leaving
complete-looking structures behind.) The same blindness means a torn tail that a later writer
has already appended over is undetectable after the fact: the splice
restored the terminal newline, which was the only evidence.

Under v5, completion was inferred from the ABSENCE of damage. v6 makes it
POSITIVE: each append carries its own proof of completeness — an opening
marker written before any other byte, and a closing record that vouches for
the rows — and the destructive reader trusts nothing that lacks either end.

## 2. The transaction markers

Every v6 append is one transaction, bracketed by a pair of marker lines.

**The OPEN marker** is the append's FIRST bytes — written before every
optional prefix byte, the index title prose and the doctrine frame included,
whenever the append carries them:

    <!-- review-followups: transaction v1 OPEN -->

Grammar (anchored, byte-exact):
`^<!-- review-followups: transaction v1 OPEN -->$`

**The record line** closes the transaction's block:

    <!-- review-followups: transaction v1 rows=<n> sha256=<hex> -->

- Grammar (anchored, byte-exact):
  `^<!-- review-followups: transaction v1 rows=(0|[1-9][0-9]*) sha256=[0-9a-f]{64} -->$`
- `v1` is the TRANSACTION FORMAT's own version, independent of the doctrine
  version — the same precedent as the `v1:` locator wire. A future doctrine
  bump that leaves the marker grammar untouched does not renumber it; a
  changed grammar mints `v2` and is mechanically distinguishable.
- `rows=<n>` counts the block's row lines exactly. The grammar permits zero
  rows so a record can vouch for any block a writer legitimately emits —
  the seal operation's stamp block (below) is the zero-row producer.
- `sha256=<hex>` is SHA-256, lowercase hex, over the block's EXACT BYTES from
  the first byte of its `## ` header line through the LF that ends its last
  row — header and rows as written (UTF-8, LF-terminated lines), scoped tags
  included; the marker lines, any prefix bytes, and the blank separator are
  excluded. A block with no rows has no last row: its digest covers the
  LF-terminated header line alone, so composer and destructive reader share
  a defined byte range at every row count.

**The LEGACY SEAL** is an operator-directed line admitting a migrated
file's pre-v6 content back to duty rules (§4), byte-bound to the content
the operator inspected:

    <!-- review-followups: legacy-seal v1 bytes=<len> sha256=<hex> -->

Grammar (anchored, byte-exact):
`^<!-- review-followups: legacy-seal v1 bytes=[1-9][0-9]* sha256=[0-9a-f]{64} -->$`.
(`bytes=0` is excluded by grammar: a seal exists only over a nonempty
legacy region, so the zero case is a near-miss, not a shape.)
`bytes=<len>` is the byte length of the LEGACY REGION — the file's bytes
from its start to the byte before the first OPEN marker or complete,
byte-valid current frame (frame states, §4) — and `sha256=<hex>` is SHA-256, lowercase hex,
over exactly those bytes. A seal admits the legacy region only while BOTH
match the region's CURRENT bytes: a legacy edit after sealing — a removed
capture row included — mismatches, the seal goes INERT, and the quarantine
holds for exactly as long as the mismatch does. Matching is the WHOLE
criterion, in both directions: an edit that later restores exactly the
recorded length and digest returns the seal to force with no further act —
it once again covers precisely the bytes the operator inspected — and a
region that never again matches stays quarantined until the operator
re-inspects and seals it afresh. A seal is emitted
only by the SEAL OPERATION below, never by default and never from values
computed at emission alone. The seal, like every marker in this file,
proves no authenticity — it records that the operator inspected the
unverifiable legacy tail, and which bytes were inspected.

**The seal operation.** Sealing is its own lock-protected append,
independent of review findings — a clean run must still be able to seal,
so no rendered follow-up block is involved. The operator inspects the
legacy tail and captures the region's length and digest AT INSPECTION; an
explicit operator-directed mode on the wrappers (`-Scope SealLegacy`,
in the wrappers' existing parameter style;
the contract's rename table governs only migrated names)
receives those EXPECTED values; on a file whose legacy region is EMPTY the
operation refuses up front — "nothing to seal", no transaction emitted — a
zero-length region needs no seal and the seal grammar admits none. On a
nonempty region the operation proceeds and,
under the cross-writer lock AND an exclusive file handle
(FileShare.None, the append path's existing discipline), recomputes
the region's current length and digest, compares them to the expectation,
and appends the sealing transaction through that same handle. The handle
is then DISPOSED — FileShare.None refuses every opener, the operation's
own included, so revalidation cannot run through it — and POST-APPEND
REVALIDATION re-opens the pathname under the still-held cross-writer
lock: a fresh read of the legacy region and the appended tail, requiring
the region digest and the new seal transaction both intact. (The pathname
re-open is deliberate: re-reading through the held handle would close the
Win32 window but could never see a swapped file — swap detection is worth
admitting ordinary openers during the read.) Success means
exactly this: NO DISCREPANCY WAS OBSERVED during that pass. The pass is
an ordinary read, not an atomic snapshot — a foreign writer racing it (an
already-open descriptor, a POSIX-side write, a pathname swap) can
interleave so that no single instant held the state the read assembled,
before the message prints or during the read itself — and no stronger
claim is made: success is a best-effort verification report, and a seal
the file no longer matches is caught INERT by prune-time validation, the
enforcement that endures.
A discrepancy at any checked step — recomputation mismatch before the
append, revalidation failure after it — reports FAILURE with
re-inspection instructions. A pre-append mismatch emits nothing. After
the append, a detected discrepancy leaves the file state UNCLASSIFIED —
the racing actor may have left the appended seal intact, damaged it, or
removed it outright (a truncation or pathname swap included) — so the
failure report claims no marker survival: it states what the revalidation
read OBSERVED and instructs re-inspection, with recovery keyed to the
observed state. An intact seal over mismatching bytes sits inert under
the pure-matching rule; a damaged final transaction is repaired by hand
before any re-seal, since the append gate refuses a damaged tail; an
absent marker leaves the quarantine simply standing. SUCCESS is never
reported over an unverified seal.
On a match the operation writes a seal-provenance artifact into the
central review-log directory (expected and measured values, timestamp,
backend) and appends one transaction: OPEN, frame when due, the seal line,
and a ZERO-ROW block whose header stamps the operation and names that
artifact by locator — the header grammar is unchanged, and the zero-row
shape admitted above is exactly this operation's block. The artifact
takes its OWN name shape (`seal-<timestamp>.md`, or
`seal-<timestamp>-<n>.md` with `<n>` in 1–99 when a same-second
invocation collides), disjoint from the
`review-…` verdict namespace: the trend and checklist consumers classify
every `review-…` file as a verdict and fail closed on anything else, so a
seal record must never enter that grammar. Its locator parses like any
path under the review-log roots, and ordinary age-pruning applies to it —
the seal LINE in the index is the durable record; the artifact is
diagnostics. Aging needs its own implementation contract: the wrappers'
prune classifier recognized only `review-*` names before v6, so v6 adds a
DIRECTORY-SAFE `seal-*` class — classified only inside the central
review-log roots, never in arbitrary output directories, where a
matching name stays untouched (§6). The operation
appends directly under the lock; no parent-to-promoter propagation is
involved.

**Numeric fields** (`rows=`, `bytes=`) compare as digit strings — length,
then lexicographic — or as arbitrary-precision integers, never through a
fixed-width parse: an oversized value must fail its equality test, not
overflow it. The frame-version comparison already applies this discipline;
these fields inherit it.

**The prefix production** — defined once here; every rule that mentions a
transaction's prefix means exactly this, in this order between the OPEN
line and the block header:

1. the index-title prose (byte-pinned): REQUIRED when the OPEN begins the
   file, inadmissible anywhere else. A reader byte-checks the title ONLY
   when the frame sharing that first transaction is of the reader's OWN
   version — the single title constant it carries. A first transaction of
   an OLDER era is legacy-era content: its title span is skipped
   unvalidated, the same policy legacy frames get (never byte-checked —
   the writers deliberately carry no retired canonical bytes), while
   row-shaped lines in it are still classified wherever they sit. No
   reader accumulates era constants, and no later bump strands a
   v6-created index. A first transaction of a FUTURE era is the reverse
   case and is NOT skippable: its title span has no length this reader
   can delimit, so the whole tail is unvalidatable and the append
   refuses, warns, and drops (the future-migrated row of §5) — fail
   closed, never an append over an unvalidated transaction;
2. the doctrine frame with its bounding blank lines: REQUIRED in the
   transaction that BEGINS the v6 region — the first transaction of a new
   file and the migration transaction of a legacy file; afterwards
   admissible only when its version exceeds every complete frame above it
   (the transaction that raises the file's version); inadmissible
   otherwise — a byte-corrupt frame inside the v6 region is DAMAGE,
   repaired by hand (§4), never by an automatic same-version re-append.
   Every condition here reads from the FILE, never
   from the writer: validity cannot depend on knowing which generation
   wrote an append;
3. the legacy seal: admissible only when a nonempty legacy region exists.

Anything else in that span denies.

**Transaction shape and terminal shape.** A transaction serializes as: OPEN
line; the prefix production above; header line; row lines; record line; blank
separator line — every line LF-terminated, and EXACTLY ONE block per
transaction: the interval from an OPEN to the next OPEN or the end of the
file holds that one record-closed block, with AT MOST ONE blank line after
its record — the same zero-or-one separator bound every validator applies. A transaction is COMPLETE at its record line's LF: the blank
separator after it is PRESENTATION, never proof — a proof role for the
separator would be unenforceable, since a later append's leading line
break, which no record covers, could supply a missing one. The TERMINAL
SHAPES a completeness predicate accepts are therefore byte-exact and
enumerated: the file (or pending payload) ends with the record line closed
by its LF, or with that shape followed by the single separator LF writers
emit. Completeness is judged over the whole
interval, both ends included: the OPEN present, the prefix admissible, the
block vouched by count and digest, the record closing it at its own LF.
Normal serialization satisfies every test; a cut ANYWHERE
in an append breaks one of them — mid-line leaves a non-LF final byte, at
any prefix or block line boundary leaves the last OPEN unmatched, and
inside the record line leaves a malformed tail — except the separator
cut: a cut between the record's LF and the separator sits AFTER every
content byte and loses nothing. No
CONTENT-LOSING cut that reaches the file is silent. (An append whose process dies before its first
byte lands leaves no trace by definition — the loss the best-effort
recording contract already accepts: the findings stay in the verdict
artifact and the gate output.) A splice, a foreign termination of a torn tail, or an edit that
does not recompute the record likewise leaves the tail without a record
that vouches for what now stands: no record at all, content outside the
grammar, or a count or digest that does not match what is above it. What
the markers prove is that a write RAN TO COMPLETION — they detect
uncoordinated damage and establish no authenticity: the index stays
workspace-writable, and an editor that recomputes the record leaves a valid
transaction, exactly as the doctrine's binding-not-authenticity rule
already states. The vouching covers what STANDS: a transaction removed
WHOLE at its OPEN boundary, or an intact block-and-record pair
transplanted, leaves a grammar-valid file no record contradicts — the
records chain nothing. Detection here is calibrated to TEARING and
surviving-block corruption; the gated tracked tree stays the only trusted
layer. (On a first creation the OPEN marker
precedes the title prose, so the file's first line is a marker comment — a
deliberate cosmetic cost. Head-by-position readers exist: every runtime's
interval validator enforces the §2 prefix production positionally against
a first-creation head, so a new head-of-file consumer must accept the
byte-exact OPEN-then-title prefix too.)

**Ownership.** The record is emitted by the writer that COMPOSES the block:
the wrappers' block renderers, in staging mode and direct-append mode alike,
so every pending file they stage is already record-closed. The OPEN marker
is emitted by the APPENDER — the writer holding the cross-writer lock, which
alone knows whether title prose or a migration frame joins the buffer: the
wrappers when they append directly, the promoter when it promotes. The
promoter — `Invoke-FollowupPromotion`, which the commit gate and the merge
gate both run to read staged pending files and append them (§7) — composes
no block content and emits no record of its own (a promoter adding one would
double the close, a shape the scanner denies); it verifies each staged block
end to end before appending any bytes (§4). Digest COMPUTATION at
composition and its RECOMPUTATION at every promotion and append gate are
PowerShell's.

## 3. Frame v6

Marker lines bump to `capture-doctrine v6 BEGIN/END`. The wording changes
below land in this single bump, per the known-debt same-bump rule.

**(a) New completion paragraph**, inserted after the "prune deletes only
under a byte-valid frame of ITS OWN doctrine version" paragraph:

    COMPLETION IS POSITIVE FROM THIS VERSION ON. Every append a writer makes
    under THIS doctrine version is ONE TRANSACTION, bracketed by marker
    lines:
    it begins with `<!-- review-followups: transaction v1 OPEN -->` written
    before any other byte -- this file's title and this frame included, when
    the append carries them -- and its block -- a header, its rows -- is
    closed by a TRANSACTION RECORD on its own line, spelled
    `<!-- review-followups: transaction v1 rows=<n> sha256=<hex> -->`, where
    <n> counts the block's rows and the digest is SHA-256 over the block's
    exact bytes from the first byte of its header line through the line
    break ending its last row -- its header line, when it has no rows. Below
    the first OPEN marker or complete, byte-valid frame of THIS version,
    every
    transaction is EXACTLY one OPEN, its prefix -- in order: this file's
    title exactly as written, only when the OPEN begins the file; the
    doctrine frame, in the region's first transaction or one raising the
    file's version; a legacy seal, only over a legacy region -- and ONE
    record-closed block, complete at its record line's line break (the
    blank line after it is presentation, not proof). A block that lacks a
    valid
    record -- absent or malformed, a count differing from the rows above
    it, or a digest that does not match -- an OPEN whose interval, running
    to the next OPEN or the end of the file, holds no record-closed block,
    holds prefix content beyond that admitted order, or holds anything past
    that block's record other than a single blank line (a second block
    included) -- a frame whose OWN interval holds no such
    block, completion never being borrowed across an OPEN -- and a frame or
    block with no OPEN above it at all -- are each an INCOMPLETE
    transaction: a write was cut
    off, or something rewrote or appended over it without recomputing the
    record, and either way the record that would vouch for the content does
    not. Like the scoped-tag binding above, these markers defeat ACCIDENTAL
    damage and establish no authenticity, and they vouch only for content
    that STANDS: a transaction removed whole at its boundaries leaves no
    incomplete shape behind -- the gated tracked tree is the only trusted
    layer, as stated above. While any incomplete
    transaction stands, NOTHING in this file is pruned, and every affected
    row carries ordinary duty. Content ABOVE the first OPEN marker or
    complete, byte-valid frame of this version predates these markers,
    and nothing can PROVE
    its final write ran to completion. While such content is PRESENT and
    this file carries no LEGACY SEAL -- the line
    `<!-- review-followups: legacy-seal v1 bytes=<len> sha256=<hex> -->` in
    a transaction's prefix, added only on the operator's explicit go-ahead
    after inspecting that legacy tail, its length and digest matching the
    legacy bytes EXACTLY AS INSPECTED -- the nonempty legacy region is an
    unresolved state and NOTHING in this file is pruned. A file whose
    every byte sits inside a transaction has no legacy region and needs no
    seal. Under a MATCHING
    seal the legacy content keeps every duty rule stated here; a seal the
    current legacy bytes no longer match is INERT and the quarantine holds
    again. The seal, like every marker here, proves no authenticity. Writers
    REFUSE to append onto any tail whose last OPEN interval is not a
    COMPLETE transaction under every test above -- and equally onto a file
    with no OPEN at all that holds a byte-valid frame of this version or a
    complete frame of a higher one. (A CORRUPT copy of this version's
    frame with no OPEN beside it leaves a file that is still legacy: the
    migration append, whose canonical frame is the repair, is how such a
    file heals.) Appending onto anything less would terminate a torn
    write and bury the evidence.

(The marker templates are quoted mid-line, as the frame already quotes the
`[scoped: ...]` example. What makes the quotes harmless is that every
marker grammar is anchored and byte-exact while the quoted forms carry
backticks and `<n>`/`<hex>` placeholders, so none can match a production —
the mid-line quoting convention is load-bearing, not cosmetic.)

**(b) The stale device-path mechanism sentence** in the dereference
paragraph rewords to name the mechanism in force
(`Test-CaptureLocatorSegmentSafe`):

    v5: "... a shape the validator rejects (a device path normalizes to a dot
    segment, and dot segments are refused) is an unlocatable claim ..."
    v6: "... a shape the validator rejects (a reserved device segment refused
    by its NAME, a segment ending in a dot or a space, a dot segment) is an
    unlocatable claim ..."

**(c) The legacy-migration sentence** — v5's "a legacy index resumes
pruning once the next write migrates it" — rewords in the same bump, since
under the seal a migration alone no longer readmits pruning:

    v6: "... and a legacy index resumes pruning once the next write
    migrates it AND a valid legacy seal admits its unverifiable tail."

**(d) The index-title prose** rewords in the same bump: the pinned
v5-era first-creation title promised "QUALITY findings from PASSING
adversarial-gate runs" only, which a seal-audit transaction's zero-row
stamp block would falsify. The canonical title for new first
creations describes the transaction kinds the index actually records —
follow-up recording and seal-audit stamps; like the frame, the exact
title BYTE sequence is normative in the writers (`Get-FollowupIndexTitle`
and its mirrored copies), while this document is normative for what the
title must SAY. A migrated index keeps its legacy title in the legacy
region untouched, and a v6-created index keeps validating across later
bumps because only a same-era reader byte-checks the title (prefix rule
1): later eras treat it as legacy-era content, never byte-checked, the
policy legacy frames already get.

Everything else in the frame carries over verbatim from v5. The batch-pass
instruction (frame step 1's "CANONICAL numbered declaration audit") remains
unchanged. Every writer emits the exact v6 frame bytes
(`Get-FollowupCaptureDoctrine` in `scripts/review-common.ps1` and the
pre-commit hook's mirrored copy), and readers compare a frame with those
bytes directly; no SHA-256 of the frame is pinned anywhere. This document
is normative for the WORDING above, the implementation for the bytes.

## 4. Writer-side checks

**Raw-byte uniformity.** Every completeness test consumes RAW BYTES. The
wrappers' v5-era prune entry stripped a UTF-8 BOM before scanning
(`Get-CapturePruneIndexText`) while the append paths read bytes — under a
format whose OPEN must occupy an append's first bytes, that split would
give the boundaries different accept sets. v6 removes the normalization
rather than spreading it: no writer emits a BOM, so an index carrying one
was made by a foreign tool or a hand edit. v6 appends refuse it (the repair
instruction says to remove it), the destructive reader records it as an
unresolved reason and denies, and the merge promoter's BOM-aware text entry
is re-pointed at the same raw-byte read. Every runtime must reject the
BOM-prefixed index consistently at these boundaries.

**Frame states, reader-relative.** Every rule in this design classifies a
delimiter-complete frame (paired BEGIN/END markers) by the version its
markers carry, relative to the version the reading implementation speaks —
disjoint states:

- LEGACY frame — version below the reader's: superseded content, never a
  region trigger, never byte-checked;
- BYTE-VALID CURRENT frame — the reader's own version, bytes identical to
  its canonical copy: a v6-region trigger;
- CORRUPT CURRENT frame — the reader's own version, delimiter-complete but
  bytes differing from canonical: NEVER a region trigger. In a file with
  no other v6 presence it leaves the file LEGACY, and the migration append
  is the repair; inside a region it is damage — interval invalid, prune
  denied, manual repair;
- FUTURE frame — version above the reader's: unverifiable by construction,
  since no canonical copy exists in this reader. Its presence stops the
  prune entirely (the retained v5 promise, before any region reasoning),
  and routes the append gate to arm 3.

Unpaired frame markers stay foreign content under the existing rules.
Wherever this document says a region begins at a byte-valid frame, the
BYTE-VALID CURRENT state is meant.

**Append tail check** (widens the final-byte-LF predicate; every runtime,
same answers). Before any arm: an index whose first bytes are a UTF-8 BOM
refuses the append outright, per the raw-byte uniformity above — the arms
below see only BOM-free files.

1. Empty index: appendable (unchanged).
2. Index containing no v6 presence at all — no OPEN marker, no byte-valid
   current frame, and no future frame (legacy and corrupt-current frames
   do not count as presence): LEGACY index — after the BOM refusal above,
   the final-byte-LF rule governs
   alone, unchanged, because the append must be able to migrate a file
   whose legacy tail nothing can verify: a v5-era cut at a line boundary
   left no evidence, and refusing here would block recording forever. The
   safety for that unverifiable tail is downstream — pruning stays denied
   until the operator seals it (§2, prune rules below). The append that
   lands migrates the index (one transaction: OPEN, frame, record-closed
   block), after which the next arm governs.
3. Index with any v6 presence — an OPEN marker, a byte-valid current
   frame, or a future frame: the FINAL OPEN INTERVAL — from the file's
   last OPEN marker to the end of the file — must be a COMPLETE transaction
   under the one completeness predicate: the prefix state machine, exactly
   one block, a structurally valid record, row count equality, digest
   equality, and one of §2's enumerated terminal shapes closing the
   file. Any failure — an OPEN with nothing valid after it (a cut inside
   the title prose, the frame, or before the block), a row or header as the
   last content line, a record cut before its LF, a
   count or digest that does not vouch for the block, surplus or foreign
   interval content, or a v6-region file with no OPEN at all — is a torn or
   foreign tail: REFUSE, warn loudly with the repair instruction, drop the
   record — the existing torn-tail contract, widened to every line-boundary
   cut and every unvouched tail.

Under this test the append gate accepts NO torn or unvouched v6 tail: a
mid-line cut fails the LF test, a cut at any prefix or block line boundary
leaves the last OPEN unmatched, a cut INSIDE the record line leaves a
malformed tail (a cut after the record's LF is the accepted content-free
case), and a tail damaged without its record recomputed fails
its count or digest (whole-transaction removal at exact boundaries leaves
a valid EARLIER tail — vouching covers what stands, per §2; a separator
cut is the §2-stated content-free exception). Completeness is specified ONCE — this section's tests
— and asked at every boundary: by the append gate on the final interval, by
the promoter on the pending payload, by the destructive reader on every
interval. Since 2.6.1 only the PowerShell implementation ships, but a
2.6.0 hook's shell implementation may still write the same index, so
source review must keep the accept set this section specifies. The
append gate validates the FINAL interval only: damage buried deeper in the
file is already durable, cannot be hidden by a further append, and belongs
to the destructive reader, which walks every interval. Repair is by hand,
exactly as the current torn-tail warning already instructs.

**Promotion validation** (`Invoke-FollowupPromotion`, run by the commit and
merge gates, §7): a promoter is the last gate before staged content becomes
durable, and a tail-shape check
alone would pass a pending file whose header or rows were altered under an
intact record — planting a block the prune scanner can only refuse forever.
So each promoter parses the pending payload as EXACTLY ONE block and
verifies it end to end BEFORE appending any bytes: byte-exact grammar
(header line, row lines, record line, then the separator or the end of the
payload — §2's enumerated shapes), row
count equality, and digest recomputation over the header+rows bytes. The
grammar's DECODED accept set is deliberately narrow — printable ASCII per
row — because a promoted row's bytes later feed path-bearing consumers
(locator dereference, prune classification), and a non-ASCII or
control-bearing row could smuggle Unicode device-path or normalization
tricks past a byte-naive reader; a payload outside the accept set refuses
like any other malformation.
Any failure — mismatch, foreign content, a payload that is not one block, an
unreadable file, or a promoter that cannot compute SHA-256 — refuses the
promotion: WARN and drop, the best-effort recording contract's existing
failure direction, and never an append. A valid payload is then appended as
one transaction carrying the COMPLETE prefix the production requires: the
promoter's OPEN marker, the canonical title prose when this append creates
the file, the migration frame when due, the block. Each promoter creating
the index from empty must include the title; omitting the title would mint
a transaction rejected by the promoter's own prefix validation.

**Prune-side validation** (PowerShell scanner, `Get-CaptureExemptionScan`):
the grammar gains the marker productions — an OPEN line, and a record line
valid only as the close of the block above it. A FUTURE frame anywhere
short-circuits first: the prune stops entirely before region reasoning,
the retained v5 promise. Otherwise validation runs over the v6 region —
everything from the first OPEN marker or byte-valid current frame onward
(the single region-start definition; frame states, above):

- every block: structural record parse, row count equality, digest
  recomputation over its header+rows bytes. The transaction is complete at
  the record's LF: at most one blank line after it is presentation, and
  anything else between the record and the next OPEN or the end of the
  file denies as content belonging to no transaction — the zero-or-one
  separator bound, identical at every validator;
- every OPEN marker: its interval — running to the next OPEN or the end of
  the file — holds EXACTLY one valid block, preceded only by the prefix
  production (§2). An interval with no
  block, with anything but at most one blank line past the block's record
  (a second block included),
  or with prefix content out of the production's order denies: a v6 transaction carries one
  block, so anything more was appended over it by a writer that never
  checked;
- every byte-valid current frame: bound to the block inside its OWN
  interval — completion is never borrowed from a block after a later OPEN.
  A frame whose interval holds no valid block is a torn migration even when
  later transactions are complete, and a frame is only ever appended inside
  a transaction, so a bare one denies even if its OPEN was lost to a hand
  edit. A CORRUPT current frame inside the region is damage: its interval
  is invalid and denies (frame states, above);
- every frame and every block in the v6 region: inside exactly one OPEN
  interval. Completion under this doctrine is proof at BOTH ends, so a
  region that begins at a frame or a block with no OPEN above it — the
  marker lost to a hand edit, or the shape forged without one — has content
  belonging to no transaction, and it denies: the every-OPEN rule must
  never pass vacuously over a zero-OPEN region;
- the legacy region: content above the first OPEN or byte-valid current
  frame
  predates positive completion, and nothing can prove its final legacy
  write ran to completion — a cut at a legacy line boundary is precisely
  what v5 cannot see. Until the file carries a legacy seal whose length and
  digest match the region's CURRENT bytes (§2), a
  nonempty legacy region is an unresolved reason and the prune is denied
  entirely; under a matching seal it returns to v5 treatment, and a seal
  the bytes no longer match is inert — the quarantine resumes. A first
  creation under v6 has no legacy region and needs no seal.

Any failure adds an unresolved reason (deny the prune), same as every other
unreadable shape. Between an OPEN marker and its block header the ONLY
admissible content is the prefix production of §2, validated as a state
machine over byte-pinned strings — never skipped as free prose, except
where §2's prefix rule 1 grants the era skip: in a region-opening
transaction carrying a complete OLDER-era frame pair, the legacy content —
the first-creation title span where one exists, and the older frame's own
body bytes between its positionally checked BEGIN/END marker lines and
bounding blanks, in the migration form too, where no title span exists —
is skipped unvalidated within those exact boundaries (row-shaped lines in
the skipped title span are still classified wherever they sit; the frame's
body rides inside its marker lines outside every row scan). Outside that
carve-out, anything else in the span — foreign prose, surplus blank lines,
doubled or reordered prefix content, row-shaped lines — denies completion
for the interval: the byte-exact grammar admits no free-form span inside a
transaction. (Row-shaped content is additionally classified wherever it
sits and denies as unbound, as the preamble rule states.) Inside the v6 region, a record line with no block above it or a doubled
record matches no production and denies as foreign content already does.
The v6 REGION begins only at the first OPEN marker or BYTE-VALID CURRENT
frame — never at a stray record-shaped line, a corrupt current frame, or a
future frame (whose presence stops the prune entirely before any region
reasoning applies). OPEN-SHAPED lines trigger WHEREVER they sit, an
ancient preamble included: no legacy writer ever emitted the shape, so
its presence there is a hand edit, and treating it as the region start
routes the file to prune DENIAL — its interval holds no valid block, a
loud unresolved reason, never a silently truncated seal boundary. The
append gate is a TAIL guard and stays governed by the final interval
alone: when a complete transaction stands at the tail, appends continue
over the denied mid-file damage, exactly as for every other buried-damage
state. Content
before the region scans under v5 treatment unchanged, the v5 preamble
policy included: a RECORD-shaped or SEAL-shaped comment sitting in an
ancient preamble is legacy prose there, skipped as it always was — those
shapes trigger nothing, bind nothing, and vouch for nothing, so skipping
them retains exactly what v5 retained. What the seal
gates is DESTRUCTION, not scanning: the legacy rows' duty and retention
rules apply throughout, and pruning anywhere in the file waits on the seal
(bullet above).
The whole-file terminated check is retained (it still guards the legacy
region and mid-line tears).

**Corrupt frames and the retired auto-repair.** v5's writers append a
canonical same-version frame when the winning frame's bytes are corrupt.
Inside the v6 region that path is UNREACHABLE by design: a corrupt frame
invalidates its interval, the destructive reader denies, and a corrupt
FINAL interval refuses appends — so the repair is MANUAL, guided by the
warning text, like every other v6 damage state. The automatic re-append
survives only where it still runs soundly: a corrupt v6-shaped frame in a
file with no OPEN marker, no byte-valid current frame, and no future
frame leaves the file
LEGACY — the frame-state taxonomy above — so
arm 2 admits the migration append, whose canonical frame IS the repair.
The distinction depends on actual index content: a corrupt frame beside a
byte-valid current frame is v6 PRESENCE, requiring arm 3's refusal and
region denial. A corrupt frame alone, with no byte-valid frame or OPEN,
leaves a LEGACY index whose repair-by-migration remains admissible.

## 5. Mixed-version behavior (all directions degrade toward retention)

| situation | outcome |
|---|---|
| v5 reader, v6 index | future-version frame: prunes nothing (existing v5 promise) |
| v5 writer, v6 index | appends an unbracketed block into the final OPEN interval; v6 prune denies AND the next v6 append refuses (surplus interval content), so v6 recording stops until hand repair — while a v5 writer keeps appending raw blocks, each denied in turn — loud, retentive |
| v6 writer, legacy index | LF rule on the legacy tail; the append migrates the index inside one bracketed transaction; legacy content keeps legacy duty rules, with every prune waiting on the byte-bound seal |
| torn tail later terminated by a non-checking writer | the spliced region carries no record vouching for what stands — absent, malformed, or count/digest-mismatched — prune denied: the P2 BLOCKER's closure |
| cut at any line boundary inside a v6 append — prefix, header, or row | last OPEN unmatched → append refused, prune denied |
| cut inside the record line | malformed tail → append refused, prune denied |
| cut between the record's LF and the separator | complete at the record's LF — no content lost; the tail is appendable, and a later append's leading bytes are harmless |
| cut inside a migration append before any v6 structure lands (mid-OPEN) | final byte not LF → torn under the retained v5 rule, append refused |
| v6 writer, index migrated to a future version | appends ONLY when the final transaction validates completely under a grammar this writer recognizes; a future tail it cannot validate refuses, warns, and drops — never an append over an unvalidated transaction. Admitted content is judged from file state alone, never writer identity |
| legacy tail torn at a line boundary, then migrated | undetectable by construction → quarantined: every prune denied until a seal matching the inspected legacy bytes; duty retained throughout |
| sealed legacy region later edited | seal length/digest mismatch → seal inert, quarantine resumes; a further edit restoring the recorded bytes returns the seal to force (matching is the whole criterion) |

The residual window: a migration append to a LEGACY index cut so early
that not even the OPEN line's LF reached the file leaves bytes the v5 rules
already govern — mid-line leaves a torn tail v5 refuses. There is no cut of
a v6 append that lands after the OPEN line without leaving an unmatched
OPEN, so no prefix cut is silent. A LEGACY tear is different in kind: a
v5-era write cut at a line boundary left no evidence at all, and no later
reader can conjure it. v6 does not claim to detect it — it QUARANTINES it:
the migrated file denies every prune until the operator inspects the legacy
tail and seals it, so the undetectable damage is never silently
grandfathered into a pruning file.

## 6. Implementation round (lockstep, one landing)

Every writer belongs in one gated landing: the frame and first-creation
title are byte-pinned, so partial updates violate the cross-writer
identity contract. Preserve these production duties through source review:

- Across the writer set (the commit-review wrappers, the merge gate, the
  pre-commit hook; since 2.6.1 the hook promotes through the shared
  PowerShell promoter, §7, while a 2.6.0 hook still writes with its own shell
  code): identical v6 frame bytes in every writer; the first-creation title
  bytes reworded and pinned per §3(d), preserving the same cross-writer
  byte identity as the frame; the doctrine version
  constant bumped to 6; the final-interval completeness check at the append
  gate (the shared predicate); OPEN emission at every append site; the
  torn-tail warning text updated for the widened refusal; the wrappers'
  legacy-frame prune-denial message reworded — the v5-era wording promised
  that "the next QUALITY write appends the current frame" restores pruning,
  which the seal quarantine falsifies; the prune
  entry's BOM strip removed in favor of raw-byte reads at every boundary;
  the seal operation as a dedicated lock-protected mode taking the
  operator's inspection-derived expected values, with its provenance
  artifact and zero-row stamp block; the wrappers' prune classifier
  extended with the directory-safe `seal-*` class (§2), landing at the
  classifier boundary where the caller already holds the directory, in
  each wrapper and the mirror-contract comment alike. In the wrappers' block renderers: record emission. In the
  promoters: the single-block end-to-end pending validation. In the scanner:
  the marker productions and the v6-region completion validation.
- Production validation and retention requirements:
  line-boundary-torn tail refused at append and denied at prune; cuts at
  EVERY prefix boundary of a migration append — after the OPEN line, after
  the frame's leading blank, after the complete frame — and of a
  first-creation append — after the OPEN line, inside the title prose,
  inside the frame — each refused at append and denied at prune (a cut
  after a valid SEAL line but before the zero-row stamp header is the
  same denied class); a record cut before
  its LF refused at append and denied at prune; a `record`-LF tail with
  the separator cut accepted as complete, including the splice where a
  non-checking writer's leading line break lands directly after it —
  harmless, no content lost; a final transaction carrying a
  count or digest mismatch refused at append; digest mismatch;
  row-count mismatch; record with no header; a doubled record denied; a
  zero-row block with a valid record accepted; an interval holding a second
  valid block denied; a bare frame followed by a later complete transaction
  still denied; a byte-valid frame and record-closed block with no OPEN
  above them denied; foreign or misplaced prefix content — prose after a
  non-first OPEN, a doubled frame, prose that is not the pinned bytes —
  denied; an unrecorded v5-writer block appended after a completed v6
  transaction denied at prune AND refused by the next v6 append (surplus
  interval content); legacy (pre-v6) content still prunable/duty-carrying
  under v5 rules ONLY once a matching seal admits the legacy region (§5 —
  unsealed, every prune waits on the operator's seal), record-shaped and
  seal-shaped preamble comments
  included, while an OPEN-shaped preamble line starts the region and requires
  the denial; a mid-file denied interval under a complete final
  transaction, with the append gate still accepting (the tail-guard
  contract); a tampered
  pending block under an intact record refused by every promoter; a pending
  payload that is not exactly one block refused; a digest-valid payload the
  destructive reader cannot key — a header without its verdict= field, or a
  valid-UTF-8 byte outside the reader's printable-ASCII whitelist — refused
  by every promoter, the production promotion path included, with the
  reader's own scan denying the same block (the
  promoter accept set sits inside the reader's); cross-runtime parity
  across the tail check's arms, multibyte and invalid-UTF-8 legacy bytes
  ahead of a valid migrated transaction included — preserving byte
  (not character) offset semantics in each runtime's scanner — and invalid
  UTF-8 inside a digest-matching block refused at both the append tail and
  the pending promotion in every runtime, since a digest vouches for bytes,
  not for their decodability; marker
  near-misses rejected — a wrong
  transaction version, `rows=00`, uppercase digest hex, trailing bytes
  after the close, for the OPEN and record grammars alike; the digest binds
  the exact header bytes, row bytes, and terminal-LF range boundary, so
  changes without a recomputed record are detected; a BOM-prefixed
  index refused at append and denied at prune in every runtime; an
  LF-terminated header-only legacy tail and a shortened-row legacy tail
  each migrated, then every prune denied until a legacy seal; under the
  seal they diverge — the header-only tail resumes, while the shortened
  row stays denied by the positive row grammar, since the seal lifts only
  the quarantine and fail-toward-duty is not its to waive; seal
  near-misses (`bytes=0` included) and a doubled seal in
  one prefix rejected; a
  sealed file whose legacy bytes are then edited re-quarantined (inert
  seal), with a fresh matching seal readmitting it, and — cross-runtime —
  a byte-exact restoration of the recorded bytes returning the original
  seal to force with no re-seal; the seal operation on an EMPTY legacy
  region reporting "nothing to seal" with the index and artifact
  directory left unchanged; a well-formed seal sitting over an EMPTY
  legacy region denied as inadmissible (prefix rule 3); the
  seal-as-migration prefix — an operator sealing a not-yet-migrated
  index, whose one transaction carries frame AND seal together — admissible
  through the full state machine; seal-artifact aging — a central `seal-*`
  artifact aged by the prune classifier, and a matching name OUTSIDE the
  review-log roots left untouched; the seal operation
  refusing when the region no longer matches the inspection-derived
  expectation, including changes between inspection and the operation's
  exclusive open, and succeeding only under §2's observed-state contract.
  A foreign write inside the operation's own exclusive-handle window is
  refused at the foreign writer by FileShare.None. An edit landing after
  revalidation's read is outside the success claim of "no discrepancy
  observed"; durable enforcement remains prune-time validation catching
  the seal inert. No success claim implies an atomic revalidation snapshot;
  oversized syntactically valid `rows=` and `bytes=` values answered
  identically in every runtime (digit-string comparison, no overflow);
  frame-state discrimination — a corrupt current
  frame with no OPEN taking the legacy arm and repaired by migration, the
  same frame beside an OPEN denied as damage, a future frame with a valid
  v1 tail admitting the append while stopping the prune, and a future
  frame with an unrecognized tail refusing.
- Operator-facing documentation in the same landing: `INSTALL.md`,
  `README.md`, and the `AGENTS.md.template` log-directory table (whose
  "Auto-pruned" promise is exactly the behavior the quarantine suspends)
  gain the seal mode — the quarantine every migrated legacy
  index enters, the inspection procedure, and how to seal — beside the
  prune's existing operator knobs. v6 stops every prune on an install
  whose index carries a nonempty legacy region — the common case for
  existing installs — until the operator runs this mode; shipping the
  code without the doc ships a silent freeze there.
- The sh hook's SHA-256 utility: the discovery order is named at
  implementation, and both promotion and append paths refuse when no
  utility is found. Historically, pre-v6 `sha256sum` ran only in the
  self-test; v6 made the utility a production dependency. Since 2.6.1 the
  hook's promotion is PowerShell (§7), which hashes in-process; the hook
  still needs the utility to pin the reviewed diff before any review.
- Project-owned tracked rollout records are updated in a separate post-landing
  commit naming the landed SHA; a branch cannot truthfully assert its own
  landing, so such status never rides the slice itself.

## 7. Index location, binding and lock

Through 2.6.0 every writer opened `logs/review-followups.md` and its lock by
path, and a commit gate's follow-ups were promoted by shell code that could
only follow paths. Since 2.6.1 every writer is PowerShell and reaches the
index only through a held folder, as the findings records are reached
(`docs/review-feedback-v1.md`).

**Location.** The logs folder is the one `Resolve-FollowupGitContext` derives
from Git (the common Git directory's parent, or a submodule's working tree).
`Enter-FollowupLogsBinding` holds that root, checked to be the folder whose
identity (volume serial and file ID) was read when the context was resolved,
and holds `logs` below it, creating it when missing. Every directory from
the volume root down stays held, so none can be renamed or deleted until the
caller lets go. When Git cannot name the folder, or a folder cannot be held
or no longer has its identity, a follow-up record is dropped with a warning,
the prune stays off, and the seal refuses. Nothing falls back to the current
folder: a record filed under an unconfirmed folder could feed another
repository's prune, while a dropped record's findings stay in its verdict
file.

**Index access.** Every open is by one name relative to the held logs folder,
without following a link, and classified on the handle it returns:

- append: read and write, no sharing, an existing ordinary single-link file
  or a new one (`Open-FollowupIndexForAppend`);
- prune read: read-only with all sharing, an ordinary file; a confirmed
  absence allows the prune with no exemptions, and any other open failure
  keeps it off;
- seal: the append open, its provenance record created new below the held
  logs folder, and the revalidation read reopened relative to it.

**Lock.** The lock is still the directory `review-followups.md.lock` beside
the index, holding an `owner` marker (`<unix-seconds> <tag>:<pid>:<seconds>`
and LF), so a 2.6.0 writer, which takes it with `mkdir` or
`CreateDirectoryW`, and a 2.6.1 writer exclude each other. A 2.6.1 writer:

1. creates the directory new relative to the held logs folder, with DELETE
   access and delete sharing withheld, so no other process can rename or
   delete it while held;
2. creates `owner` new through the directory's handle and writes and flushes
   the marker;
3. on release, deletes `owner` and then the directory through the handles
   that created them, retrying the directory delete briefly while a reader's
   handle keeps the deleted `owner` name present.

A handle names only the object it created, so release needs no marker
comparison and can never remove another writer's lock. The marker serves
diagnostics: the holder warning shows it (as an ASCII whitelist) and its age,
taken from its leading acquisition time, which every writer version records.

| state | outcome |
|---|---|
| logs folder not held | no lock; the caller drops its records or keeps the prune off |
| lock name taken | retried; then the holder warning, no lock |
| `owner` create or write fails | both deleted through their handles and the acquisition retried; when that delete fails the lock is left (warning and housekeeping line) and no retry is made |
| writer ends while holding | the lock stays until removed by hand |
| release delete fails | the lock stays (warning and housekeeping line) |

There is still no automatic takeover: a 2.6.0 writer holds the lock without
any handle, so nothing distinguishes its live lock from a crashed writer's
residue.

**One promoter.** `Invoke-FollowupPromotion` in `scripts/review-common.ps1`
promotes for both gates. It reads each pending file by path (the gate's own
temporary file, validated whole before use), validates it with
`Test-FollowupPendingPayload` (§4), and appends every valid payload in one
write under one lock: the first transaction carries the prefix (title and
frame for a new index, the migration when due), each later one its OPEN
marker and its block. It returns 10 when the transactions were appended, 0
when nothing was (each drop warned), and 11 when the write itself failed and
part of it may be in the index. The merge gate calls it after its ff-merge.
The pre-commit hook calls it once, between its pre-append and post-append
staged-tree checks, as `powershell.exe -Command` with fixed text that runs
the trusted `review-common.ps1` copy the review wrappers ran from. The hook
pins that copy's SHA-256 when it captures the review snapshot; the child
reads the copy once, runs those bytes from memory only if they still match,
and receives the paths and the digest only through environment names the
hook owns (every inherited case variant is removed first, since Windows
PowerShell resolves environment names without case). The child first sets
UTF-8 decoding of native-command output, so Git's paths are read as
written. Status 12 means that decoding could not be
set, or that copy could not be read or loaded or has no promoter (it is
older than the hook), 13 that it no longer matches the pinned bytes; in both the records
are dropped. Any status other than 0, 10, 11, 12 and 13 leaves the index
state unknown and is reported as a possibly partial append. The hook no
longer holds the lock across its pre-append check: the promoter takes and
releases it inside its own process, so a staged-tree change during the call
is caught by the post-append check, and the rows stay indexed (they record a
completed review, not a landing).

**Mixed versions.** A 2.6.0 hook keeps its own shell promotion, frame and
grammar, which §2 through §4 still describe byte for byte; the shared lock
directory keeps it and 2.6.1 writers from appending at once.
