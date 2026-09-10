# Reviewer liveness and effectiveness (design)

Design-before-code artifact for the reviewer-liveness slice (operator
directive 2026-08-29, raised from a live incident: a Claude review child
ran far past its typical wall time while the waiting side had no way to
tell a stalled reviewer from a working one, and the supervising agent
could not read any transcript of what the reviewer was doing). This
document precedes the code slice per the source project's
design-before-code ruling; the slice conforms to it or amends it first.

## Threat model

A review child is a long-running opaque process that the gate DELIBERATELY
waits on without a timeout: the port reconciliation contract sanctions the
unbounded review wait (abandoning a still-valid review is worse than an
operator-visible hang), and no part of this design adds a kill, cap, or
retry to review convergence. The failure mode is therefore not the wait --
it is the BLINDNESS of the wait:

- The heartbeat lines the wrappers print are TIMER output from the
  wrapper's own thread. They prove the wrapper is scheduled, and nothing
  else: a hung CLI under a healthy wrapper ticks heartbeats forever.
- The Claude wrapper collects the CLI's stdout in memory and reads it only
  at exit (`--output-format json` emits a single envelope at the end), so
  during the run there is NO externally observable evidence of progress
  and no artifact a supervising agent can inspect.
- Nothing records how long a review took, so there is no baseline against
  which "this reviewer is taking far too long" is even a measurable claim.

## Design

The mechanisms below share a rule: none truncates a review.

### 1. Activity-evidence heartbeats with per-pass stall escalation

The heartbeat stops being a bare timer and starts sampling EVIDENCE FILES
-- artifacts that grow only when the reviewer under it is actually doing
work:

- codex: the per-pass `events-*.jsonl` files in the run scratch dir. The
  codex CLI streams an event record per action into them already; a
  working pass grows its file, a stalled one does not.
- claude: the streamed output file introduced by mechanism 2 below.

Sampling is PER FILE, never aggregate: codex passes run concurrently, and
an aggregate delta stays nonzero while any one pass works -- hiding a
stalled sibling behind a healthy one, which would defeat the whole
mechanism. Each watched file carries its own last-size/last-growth state,
and quiet is judged per file. A file is escalation-ELIGIBLE only while
its OWNING PROCESS IS ALIVE: each codex evidence file maps to its pass
child's process id, captured by the parent at launch, and the beat probes
that process each interval. Quiet with a live process is the stall shape;
quiet with a dead process is either completion or a crash, both of which
the parent's own exit handling already reports loudly, and neither of
which the heartbeat may re-report as a stall. (Marker-file semantics were
measured wrong here: the runner's pre-seeded crash sentinel survives a
hard child crash, so sentinel-means-active would escalate a dead pass
forever.) Process-id reuse within a run's window is the accepted residual
-- a reused id can delay a file's exemption, and in the worst case it can
hold a completed pass's quiet file escalation-eligible, surfacing a
warn-only false STALL-SUSPECT; it can never suppress evidence of a live
stall, and every escalation stays warn-not-kill.
The claude stream carries no mapping and counts active for the whole
invocation: the CLI runs in the wrapper's own pipeline, so a crashed CLI
ends the invocation and the heartbeat with it.

Each beat prints the per-file sizes and deltas. When an ACTIVE file's
growth has been quiet for longer than the threshold, the beat escalates to
a `STALL-SUSPECT` warning naming that file and its quiet duration --
still warn-not-kill, and self-clearing: growth resumes, the escalation
stops. The threshold is `CROSS_REVIEW_STALL_WARN_SECS`: an integer-seconds
value in 30..86400, default 300 when unset or blank; a SET-but-invalid
value (non-integer, or out of that range) fails the review closed as an
invocation/config error, like the other env knobs.

Samples and escalation TRANSITIONS are also appended, with an ISO-8601
local arrival timestamp, to a run-owned LIVENESS LOG preserved alongside
the run's forensics (`review-<ts>-<tag>-r<pid>.liveness.jsonl` -- the
`.jsonl` suffix keeps it inside the consolidation and prune regexes, and
the pid component keeps same-second runs' artifacts disjoint). Appends and
preservation are best-effort with LOUD failure reporting: a denied
append retries briefly then warns, never silently thinning the record.
Console lines serve the live watcher; the log serves the post-run audit,
which otherwise could not reconstruct quiet intervals or see that an
escalation ever fired (raw event streams carry neither arrival times nor
the escalation itself).

The C# heartbeat helper is extended under a NEW versioned type name (a
loaded type can never be redefined in-process); each wrapper carries the
mirrored copy, updated in lockstep.

### 2. Claude stream-visible output (the reviewer's activity transcript)

The Claude CLI invocation moves from `--output-format json` (one envelope
at exit, held in memory) to `--output-format stream-json` (NDJSON events
as the review progresses) TOGETHER WITH `--verbose` -- the CLI's own
print-mode validation refuses `-p --output-format stream-json` without it,
so replacing the format flag alone would fail argument validation and
force every review to exit 3 instead of running; the args builder carries
the flag to satisfy the combined print/stream/verbose contract. Stdout is redirected to a run-dir file:

- The file grows per model turn and tool call, feeding mechanism 1.
- The file IS the reviewer's activity transcript: what it read, what it
  claimed, when it went quiet -- readable mid-run by any supervising
  agent (the wrapper announces the scratch path at launch), and preserved
  afterward as `review-<ts>-<tag>-r<pid>.stream.jsonl` (the pid component
  keeps same-second runs' artifacts disjoint -- the timestamp has
  one-second resolution and scope/tag values repeat). That SHAPE is the
  contract: the merge gate centralizes only the closed
  `review-<ts>-<tag>...` artifact shape and deletes consolidated child
  run dirs, so a nonmatching name would be excluded as transient
  scaffolding and LOST at cleanup -- the `.jsonl` tail also places the
  file in the wrappers' forensics prune class. This closes the
  "transcripts are invisible" gap without touching machine-global session
  storage (the wrapper keeps `--no-session-persistence`).
- The RESULT ENVELOPE the failure classification depends on is the
  stream's final `type: result` record, held to a STRICT stream grammar
  -- the fail-closed posture the at-exit envelope had, not a lenient
  scan: every non-blank line must parse as a JSON object, EXACTLY ONE
  record may carry `type: result`, and it must be the FINAL non-blank
  record. A malformed line, a duplicate result, records trailing the
  result, or no result at all each REJECT the stream with a named
  reason, and a rejected stream classifies as malformed output (exit 3)
  exactly as a malformed envelope does today -- noise tolerance would
  let a corrupted or tampered stream still feed gate classification.
  The accepted record's JSON feeds the existing
  `ConvertFrom-ClaudeResultEnvelope` ->
  `Resolve-ClaudeFailureClassification` chain with its input SHAPE
  unchanged. Review the accepted shape, each rejection arm, and the
  classification chain together; code unit-test authoring and execution are
  banned, without categorically prohibiting other functional testing.

### 3. Effectiveness measurement and reviewer audits

- Each wrapper stamps `REVIEW-DURATION-SECS:` in the verdict identity
  header block: one line, a base-10 NON-NEGATIVE INTEGER, the FLOOR of
  the invocation's wall-clock seconds (launch of the review children to
  header assembly), no unit suffix, no padding. The stamp is
  forensics/metadata like the rest of the block -- no gate decision reads
  it -- but it makes reviewer latency a recorded, comparable quantity, so
  anomalies ("this backend's passes tripled in wall time") are observable
  from the verdict archive rather than from memory.
- `docs/audit-protocol.md` gains a REVIEW-THE-REVIEWERS section: a
  periodic check that recent verdicts carry sane durations, that finding
  volume is commensurate with diff size (a reviewer that returns CLEAN
  instantly on large diffs is as suspect as one that stalls), and that
  stall escalations in recent runs were investigated. The audit reads the
  duration stamps and the preserved stream/events forensics.

## Consumer documents

The slice updates the operator-facing inventories WITH the mechanisms,
never after them: `INSTALL.md` documents `CROSS_REVIEW_STALL_WARN_SECS`
(grammar, default, fail-closed rule) and the liveness-log artifact; the
`docs/AGENTS.md.template` wrapper rows state the stream-json invocation,
the preserved stream/liveness artifacts, and the duration stamp; and
`docs/audit-protocol.md` carries the review-the-reviewers section that
consumes them. A mechanism whose knob, artifact, or header is absent from
those inventories is not landed.

## Out of scope, stated deliberately

- No timeout, kill, or retry on review convergence (contract-banned; the
  design makes the wait VISIBLE, not bounded).
- No machine-global session persistence for the review CLI.
- No supervising-agent API; the interface is files and console lines,
  which every supervisor already has.

## Consumers checked

Verdict-header consumers were verified against the added header line:
the trend analyzer and dispatch-checklist each hold a CLOSED whitelist
regex over header-fragment lines and fail closed on anything outside it
(measured at their `$headerLineRe` definitions), so `REVIEW-DURATION-SECS:`
joins each consumer regex in the same slice that makes
the wrappers emit it; landing the emitters without the widened consumers
would make every new verdict read as malformed. a pattern sweep of the script tree surfaced no further whitelist copy.
