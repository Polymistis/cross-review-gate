# Authoring-side invariant checklist

Every class below has been raised by the review gate repeatedly
across this package's history. The purpose of this file is to move the
catch from the REVIEW side to the AUTHORING side: walk every new or
edited surface against every class BEFORE staging it. One authoring
walk costs minutes; every missed class costs a full review round.

This is the durable form of the "maintain a checklist of repeated
defect classes" discipline. When the gate raises a class not listed
here twice, ADD it here in the same fix commit — a class held only in
session memory recurs in the next session.

## Defect classes

1. **Byte domain vs text domain (Windows).** Any question about CR,
   LF, BOM, or encoding is answered with byte tools (`wc -c` raw vs
   `tr -d '\r'` counts, `[System.IO.File]` byte APIs), never with
   grep/awk/Get-Content — text-mode readers on this platform strip CR
   on read and launder exactly the bytes an LF-only grammar refuses.
   Known instrument hazards: PS 5.1 `1>` writes UTF-16LE+BOM; PS 5.1
   `Set-Content -Encoding UTF8` emits a BOM, and a Get-Content/Set-Content
   round trip re-terminates every line (the pair is never byte-faithful).

2. **Probe-status exhaustiveness.** Every external probe (git exit
   status above all) is classified over its FULL outcome set:
   positive-yes, positive-no, indeterminate. Indeterminate always
   refuses. Never read "non-zero" as one state, never classify by
   stdout when the tool reports by status (`git config --get` reports
   a set-but-empty value with exit 0). The producer's OWN status
   decides, never a downstream stage's: a shell pipeline reports its
   last command, so `$(git diff --cached | git hash-object --stdin)`
   and `$(sha256sum f | cut | tr)` launder a producer that failed
   after partial output into a plausible value. Capture each producer
   alone (`x=$(cmd) || refuse`, or `cmd > tmp` with its own status),
   then post-process the captured value in checked steps (parameter
   expansion, `case` validation, a checked awk stage) -- and prefer
   no producer at all where a closed pattern decides (`case` over the
   accept set instead of `tr` case-folding).

3. **State-machine walk before the first fix.** For any guard,
   recovery, or rollback path: enumerate every state × every failure
   and prescribe each transition BEFORE writing code. An adversarial
   reviewer walks transitions mechanically, round after round; every
   unclassified state (an unborn HEAD, a staged-but-absent file, a
   cancelled pairwise diff) is a finding waiting its turn.

4. **Filter-mediated git comparisons.** `git diff`/`git status`
   compare through clean filters and EOL normalization; a claim about
   RAW executed bytes needs `git hash-object --stdin` against the blob
   oid. Blob-to-blob comparisons (`git diff --cached HEAD`) are
   filter-free and stay valid. State in the comment which domain a
   comparison runs in.

5. **Object identity at a path.** `-f`/`-L`/`Test-Path` conflate
   shapes: a symlink hides target bytes from git's probes, a FIFO or
   device reads as ABSENT to `-f` while still supplying bytes, a
   DANGLING reparse point reads as absent to every pathname probe
   while a follow-open create then creates its target elsewhere, and a
   directory or multi-link file breaks write assumptions. Enumerate
   the shapes, refuse non-regular ones BEFORE anything opens the path
   (opening a FIFO hangs), classify shape ON THE HANDLE of a no-follow
   open (never by a pathname pre-check that a racer or a dangling link
   can answer differently), create through a no-follow CREATE_NEW
   only, pin identity with a held handle across any validate-then-
   mutate window (no pathname reopen), never write through a
   multi-link occupant (every alias receives the bytes), and admit a
   git object as content only after its index/tree MODE is a regular
   blob (a symlink-mode entry's blob bytes are not what git reads at
   that path).

6. **Anchors and shared grammars.** .NET `$` matches before a final
   newline — exact-end means `\z`. awk counts an unterminated final
   line as a record. Every record grammar has ONE byte-exact accept
   set shared verbatim by every reader, writer, and clearer; a looser
   reader accepts what the producer never writes. Host-language
   grammar hazards that have each cost rounds repeatedly: a PowerShell
   double-quoted `"$name: ..."` parses as a drive-qualified variable
   (write `${name}:`), `<<<` does not exist in PowerShell, and the
   `-File` binder cannot pass an array (give the CSV form its own
   parameter). Run the interpreter's parser over every edited script
   before staging.

7. **Ambient environment as a redirect vector.** CDPATH steers and
   pollutes `cd` substitutions; GIT_* overrides re-aim every probe and
   the commit itself; host global config (core.autocrlf, excludesfile,
   init.templateDir, gpgsign) affects ordinary installs and Git operations.
   Neutralize (`unset CDPATH`, `-c key=` overrides, sanitized HOME) or
   refuse outright; never assume a clean inherited environment.

8. **Effective-value verification for configuration writes, by
   BEHAVIOR.** A tool's rendered report of a setting is a string, not
   the setting: `git check-attr` prints `set` / `unspecified` for the
   literal values `text=set` / `filter=unspecified` exactly as for the
   states, while git treats the literals as not set. Prove a contract
   by exercising the mechanism it governs (`hash-object --path` for
   clean conversion, `cat-file --filters` for checkout conversion,
   `check-attr --all` for "nothing specified"), comparing raw bytes.
   After
   writing configuration (attributes, ignores, hooks), verify the
   EFFECTIVE outcome through the platform's own oracle
   (`git check-attr`, `git check-ignore`) over the COMPLETE relevant
   surface — one attribute alone can read correct while a sibling
   (`-text`, `filter`, `working-tree-encoding`) defeats the contract.
   Textual presence of a rule proves nothing under last-match-wins.

9. **Claim-truth sweep.** Every comment and doc sentence asserting
   behavior is re-verified against the tree in the same pass that
   changes the behavior, at every mention site: staging recipes,
   README trees and step lists, INSTALL enumerations, the AGENTS
   template row, audit-protocol steps, and nearby code comments. A
   stale "exactly one line" comment beside a two-line matcher is a
   standing finding.

10. **Code unit-test ban.** Do not author, maintain, restore, or run code unit
    tests or unit-test-only support under another name. Remove existing code
    unit tests through the authorized reviewed workflow. Integration,
    end-to-end, smoke, performance, manual, live, and other functional testing
    remain permitted and important. Preserve production validation and use
    source inspection, static parsing, builds, ordinary program operation, and
    applicable functional testing for verification. A missing code unit test is
    never a finding.

## Operational rules (bind the rounds, not the code)

- **Resource checkpoint**: follow `docs/resource-efficiency.md` before repeating
  an operation identified as wasteful or unexpectedly slow. A reported delay is
  a diagnostic trigger, not permission to normalize the same expensive path.
  Check existing evidence, expected scope and remaining work before spending
  another review or verification cycle; retain the mandatory review contract.
- **Class-sweep, not line-fix**: a cited line is one instance; grep
  the whole tree for the class before fixing anything.
- **Fix-on-fix halt**: a BLOCKER inside the previous round's
  remediation halts patching — extract the invariant every finding
  violates, re-derive the mechanism against it, land one round.
- **Round-budget tripwire**: two consecutive blocked rounds on one
  commit force a step-back derivation, never a third instance fix.
- **Recurrence escalation (campaign level)**: the tripwire above is
  scoped to one commit, and that scope is a known blind spot — a
  slice can burn many rounds without ever tripping it twice in a row,
  and a class can recur across slices while every individual commit
  looks disciplined. When rounds keep landing across a slice or a
  class recurs from an earlier slice, HALT the fix line and research
  the systemic cause instead: name the organ that should have caught
  the class on the authoring side, build or repair it, and land the
  process fix as a TRACKED ARTIFACT in the same effort — a process
  fix that exists only as session memory is the recurrence.
- **Walk this list before every staging**, and append new
  twice-raised classes here in the fix commit that closes them.
