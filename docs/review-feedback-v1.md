# Review feedback v1: findings files, the non-blocking findings notice, the PASS line and blocked retries

Audit source: a consumer project's corrective audit of 2026-10-07. It
found that NOTE findings were not kept anywhere a later session would see
them, that findings raised against a file were not shown to the next review
of that file, and that a gate PASS was being read as approval of target
behaviour or deployment. Section 3 answers the first: a review is for the
session that submitted the change, so its findings are shown to that
session and none is recorded as work for a later session. Section 2 says
why the second stays so, and section 4 covers the third. Section 5 covers a
gap the review of this design itself exposed: a blocked commit was retried
with only the cited line of each finding fixed, so each review round found
the next instance of the same class. The review prompt's change-propagation
duties are separate and documented where they live.

## Scope

Ordinary review path of both review wrappers (`scripts/codex/auto-review.ps1`,
`scripts/claude/auto-review.ps1`), which also serve the commit gate and the
merge gate; the blocked-retry check (section 5) applies to staged reviews,
the commit gate's. Findings files and the blocked-retry check do not apply
to PreparedPair (paired) reviews or the Grok adapter. The Grok adapter
prints only the coverage wording of
the PASS line below. The paired session prints that wording in its own PASS
line and then, for each passing attempt, a line naming the provider and the
verdict file, then that verdict's non-blocking findings through the notice
of section 3 (`Write-CrgPairNonBlockingFindings`), and then the task
reminder (section 4).

## File identity

Every directory from the volume root down to a file's folder is held for the
whole operation (`Enter-CrgHeldDirectory`). Extended-length drive and UNC
spellings (`\\?\C:\...`, `\\?\UNC\server\share\...`) are accepted like their
plain forms; any other `\\?\` or `\\.\` path names a device and is refused.
Only the volume root is opened by path. Each directory below it is opened by its one name relative to its held
parent's handle, without following a link, with directory-listing access and
delete sharing withheld, so it cannot be renamed or deleted meanwhile, and
checked to be an ordinary directory. A missing folder the gate may create
(`logs`, `review-findings`, or a submodule's `crg-review-findings`,
section 1) is created relative to its held
parent. Paths are compared exactly, never ignoring letter case: in a
case-sensitive folder `logs` and `LOGS` are different objects, so a held
directory is reused only for the same spelling. Every file is then opened by
its one name relative to its folder's held handle, again without following a
link, and its shape is classified on that handle
(`docs/authoring-invariant-checklist.md` item 5): an ordinary file, and
single-link whenever the handle may change or delete it. No full path is
resolved again after a check, so a directory turned into a link afterwards
(an empty held directory can still gain a junction) cannot redirect a name.
Every read, change and delete goes through the handle that was checked:
content reads are bounded (1 MiB, strict UTF-8), a file is created only through a
no-follow CREATE_NEW, and the only explicit deletions set the delete
disposition on the held handle, and only on files this run created through
that handle: a findings file or `PRIOR-BLOCKERS.txt` this run created and
failed to write (neither is yet a record).
No review record is ever deleted. Text a file must hold exactly (a path
with a lone UTF-16 surrogate, which a Windows name may contain) is refused
before anything is written, since UTF-8 would store U+FFFD and the file
would read back as another value. A path Git reports is used with only
its line end removed, and one the Windows PowerShell path functions would
change (a last name ending in whitespace, or any name ending in a dot,
which .NET Framework drops; `.` and `..` segments are resolved first,
keeping every name) is refused rather than replaced by the folder it would
then name, as is a path that is not a full one (a drive root or a share):
a common Git directory so named gives the review no repository, so no
findings file is written or read, and a working tree's Git directory so
named gives no retry key (section 5). Folder
listings go by path but only supply names, each then opened relative to the
held folder. Work left undone is reported, as a WARN or, in the review
evidence, a `NOT SHOWN` or `unavailable` line. When the review's Git
context is resolved (`Resolve-ReviewGitContext`), the identities (volume
serial and file ID) of the common Git directory, of the logs folder's
parent and of the working tree's own Git directory are read and kept with
their paths. Writing a findings file or scanning for blocked rounds first
holds the common Git directory and the parent of every findings folder
written or read (section 1) and refuses one that is no longer the folder
whose identity was kept
(`Enter-CrgReviewLogsBinding`). So a record goes into, and is matched
against, the repository the review started in; the logs and findings
folders are then reached through those held entries. A file's name is
checked as stored on its held handle (`StoredName`), since a
case-insensitive folder opens `x.FINDINGS` for `x.findings`. The
repository is discovered once (`Resolve-CrgMainCheckout`): its Git
children run from the review's folder and from the candidate main
checkout, isolated from inherited repository selectors (`GIT_DIR`,
`GIT_INDEX_FILE` and the rest of `Get-CrgGitSelectorEnvironmentKeys`). The
first must report the same common Git directory the review used; it also
names the working tree's own Git directory. Git run in the candidate
checkout must report that common directory and the checkout as its top
level, with both folders held, and the common directory's identity is
taken from that hold. Where no main checkout is confirmed, that identity
is read by path, as the identity of the working tree's own Git directory
always is.

## 1. Findings files

When a staged review blocks, the wrapper records the round (section 5) as
one findings file in the
repository's findings folder (beside the review logs, or for a submodule
inside its common Git directory, below):

    <logs>/review-findings/<backend>-review-<written, UTC yyyyMMdd-HHmmss>-<12 hex>.findings

`<logs>` is the folder above the review logs
(`Get-ReviewLogsFolder`: `logs` beside the common Git directory, which is
the main checkout's in the usual layout). The folder is fixed by the
common Git directory (`Get-ReviewFindingsLocation`), so every working tree
of a repository writes and reads the same records and no checkout change
moves them. A submodule is the exception to `<logs>`: its review logs
are in the current working tree's `logs`, which each linked worktree has its
own of, so its findings files go in `crg-review-findings` inside its common
Git directory (`.git/modules/<name>/crg-review-findings`), never committed.
Placing them under the submodule's main checkout was tried during 2.6.0
development and dropped: a main checkout moved, or retargeted by
`core.worktree`, took its records out of every later scan without a trace.
Earlier versions (from commit 176d51b, where findings files began) kept a
submodule's files in the current working tree's own `logs/review-findings`;
a submodule's scan also reads that folder, never writing there, so none of
those files drops out of that working tree's scans. A non-submodule
repository's earlier place is this same one. When Git cannot name the
repository, or the common Git directory or the findings folder's parent is
no longer the folder confirmed when the review started, no findings file
is written (a WARN says why). Several
repositories can share it (separate Git directories under one parent), so
every file names its repository (below). A
separate folder keeps these files out of `logs/<backend>/reviews`, whose
trend and checklist readers have their own file-name rules. The
time in the name is the file's `written` time to the second, so the
blocked-round scan (section 5) can pass over old files by name alone. The
12 hex digits are the start of
the file content's SHA-256, so two records written in the same second get
different names in practice. The name is bound to the content: a file
whose backend, time or hash disagrees with its content is invalid, so an
edited record is reported. The name alone guarantees nothing: an existing file of that name
is the same record, already written, only when it is stored under exactly
that name and its content is identical; any other is refused with a WARN. A write that fails
deletes the partly written file through its handle; one left by a process
that died while writing is counted invalid and named in a WARN by the next
blocked-round scan (section 5).

Content (UTF-8 lines, each ending with LF, written once, never edited):

    review-findings v1
    repository <the repository's common Git directory, absolute>
    verdict <verdict locator>
    backend codex|claude
    written <UTC, yyyy-MM-ddTHH:mm:ssZ>
    retry-worktree <the working tree's own Git directory, absolute>
    retry-head <the HEAD commit id, or unborn>
    finding BLOCKER <sha256 hex digest> <path>:<line>[:<col>] or -
    cite <path>:<line>[:<col>]
    > <the finding's text, escaped, one line of it per quote line>
    end

`finding` blocks repeat one or more times; `-` stands for no opening
citation. Each `finding` line is followed
by zero or more `cite` lines, the finding's further citations (below), no
two the same and none repeating the opening one. This is the only valid
form: a file without both retry lines, or with a finding other than
`BLOCKER`, is not a valid findings file. Each `finding` line and its `cite` lines are
followed by one or more quote lines holding the finding's text (the lines its digest covers)
escaped and quoted exactly as in `COMMIT-LOG.txt` (injective `\xNN`
escaping, `> ` prefix on every content line), so the
quote lines hold only printable ASCII and none can pass for a format line.
The file is UTF-8: the repository, the verdict locator and the retry
working tree, all paths, may hold any other character except the ASCII
control characters (U+0000 to U+001F and U+007F; a Windows name may hold
the C1 ones). The writer refuses any
name outside the form above. The format
is line based so it parses identically on every PowerShell version (PowerShell 7's JSON reader turns date strings
into dates before any check could see them), and the `end` line makes a
partly written file invalid.

- `repository` is the common Git directory the review's Git context
  resolved (full path, no trailing separator except at a volume root, where
  `C:\` stays `C:\` because `C:` names the drive's current folder), as Git
  reports it with inherited repository selectors removed; a context whose
  inherited selectors name another repository has none. It is what binds a
  record to its repository: the blocked-round scan (section 5) uses only its
  own repository's files.
  A run without one writes no findings file.
- The verdict locator (`Get-ReviewArtifactLocator`) is
  the repository-relative central path when the verdict ends up in
  `logs/<backend>/reviews`; otherwise the path relative to the logs folder's
  parent (the main checkout in
  the usual layout) when the verdict lies inside it, else the absolute path.
- A finding is a column-one `BLOCKER:` line of the verdict artifact. The digest is
  `Get-CaptureFindingDigest` over the finding's lines. The citation is the
  strict `path:line[:col]` citation (`Get-ReviewFindingCitation`) stored as a repository
  path: backslashes become `/` and leading `./` is removed. Reviewers work
  from the review root, whose `REVIEW_SRC/` folder is the copy of the
  reviewed tree. A citation written relative to that root
  (`./REVIEW_SRC/...`) always has its one `REVIEW_SRC/` removed, so
  `./REVIEW_SRC/REVIEW_SRC/a.ps1` names the tree's `REVIEW_SRC/a.ps1`. A
  bare `REVIEW_SRC/...` is removed only when the reviewed tree (the
  verdict's `REVIEW-TREE-OID`, as the wrapper listed it recursively, folder
  entries included, before the review; an empty folder counts) has no
  top-level entry named `REVIEW_SRC` in any letter case; when it has one,
  or no listing of that tree was given, the citation is kept as written.
  The listing is the one the snapshot is built from, so it is complete
  whenever a review ran and needs no main checkout; the live checkout is
  not consulted. The decision is
  made once, when the file is written; nothing later interprets the
  verdict again. Repeated findings across passes are recorded once (same
  digest).
- The further citations are every other citation in the finding's text
  (the verdict format lists the other instances of a multi-instance
  finding as `also at <file:line>, ...`), in order of first appearance,
  stored the same way: a citation standing alone (not preceded by a path
  character or a colon, so a drive letter or a URL is not one, and not
  followed by more of a number, a word or another `:<digit>`, the ending
  the opening citation also needs) whose path is a file of the reviewed
  tree (a file or submodule entry of the same listing) or a path the change
  touches. Prose such as `21:05` fits the grammar but names no file, and
  every rule on the text's shape also excluded real paths (`VERSION`,
  `2026/10`), so the repository decides. When no listing of the tree was
  given, only the grammar, the same normalization as the opening citation
  and the refusal of a path starting with `/` decide; the live checkout is
  not read instead.
- The file is self-contained: every later reader (the blocked-round scan of
  section 5, or a person reading the file) gets the severity, citations and text
  from it alone, through one parser that decodes each text (strict UTF-8)
  and checks it against its digest, and accepts the file only when the
  writer, given the parsed values, would produce it byte for byte (so a
  `\x41` where the writer puts `A` makes the file invalid: each record has
  one stored form, and the size limits of section 5
  read that form), so a record cannot be read differently from how it was
  written. An earlier design kept the text only in the
  verdict artifact and re-read it there by digest; that re-interpretation
  (verdict paths, the REVIEW_SRC decision, verdicts deleted over time) was
  a way for a record to be read differently from how it was written, and
  was dropped (2026-10-09); do not move the text back out of this file.
  The text stays reviewer output: it is escaped and quoted, never prose that
  a session-start file shows.
- A passing or failed review writes no findings file. A blocked review's
  QUALITY and NOTE findings are not recorded either; the review that
  follows the fix gives its own verdict. Only a blocked staged review records its
  BLOCKER findings, as a blocked round (section 5).
- The gate never deletes findings files or the review logs in the logs
  folder. Files written more than 14 days ago are not read by the
  blocked-round scan (section 5); remove old ones by hand through the
  Recycle Bin when wanted.
- Writing never affects the verdict or the exit code; a failure is a WARN.

## 2. No carry-forward between reviews

Content a change leaves as it was is never the subject of a finding in its
review, apart from an unchanged line the change makes wrong, which is
reported at the changed line that causes it (operator rule, 2026-11-23; the
prompt's "Scope of a finding"). Project-supplied text rendered into the
prompt (project context and hazards) cannot make such content a finding, so
retained project text that asks for findings on unchanged content has no
effect. A passing review writes no findings file (section 1), and its
findings are not shown to any later review; section 3 shows them to the
session that submitted the change. An
earlier design carried passing reviews' QUALITY and NOTE findings into
every later review that touched a cited file: a `CARRIED-FINDINGS.txt`
evidence file, a `CARRIED FINDINGS` scope-text section, a prompt duty to
raise each one again while it still applied, and `carried` lines in the
findings files acknowledging the occurrences shown. It was removed (2026-11-23) because it put findings
about other commits, and about content the later change left untouched, in
front of reviewers, who then reported them against that change; do not
reintroduce it. Blocked rounds are kept apart from this: section 5 shows
them to a later staged review of the same working tree and HEAD, and
another change staged on the same HEAD in the same working tree counts
there as the same change.

## 3. Non-blocking findings notice

A review is for the session that submitted the change. After a passing
verdict a wrapper run on its own shows that session the verdict's
non-blocking findings (`Write-NonBlockingFindingsNotice`), and the paired
review session does the same for each passing verdict; a wrapper launched
by the commit hook or the merge gate prints no notice, and the gate shows
the findings itself (below). The notice takes the finding lines exactly as
the verdict classifier (`Get-VerdictExitCode`) counts them. The verdict text is
split at line feeds only; one CR before a line feed is the line ending, and
any other CR is part of its line. A finding line starts at column one with
the exact, case-sensitive prefix `QUALITY:` (or legacy `NON-BLOCKER:`) or
`NOTE:`; its indented explanation stays in the verdict file. Lines are never
trimmed. A line that repeats an earlier one exactly (compared character by
character, so a line differing only in letter case or trailing white space
is kept) is dropped; the rest keep their first-seen order.

A finding line is reviewer text, so the notice shows a UTF-16 code unit as
itself only when its Unicode category is a letter, mark, number,
punctuation, symbol or space separator. Every other code unit is shown as a
`\u{XXXX}` escape of four uppercase hex digits (an escape character as
`\u{001B}`): control characters including tab, DEL and the C1 range, format
characters such as the bidirectional and zero-width controls, line and
paragraph separators, surrogates (so a character outside the Basic
Multilingual Plane, such as an emoji, appears as two escapes), private-use
and unassigned code units, and a CR inside a line. Grouping uses the
original lines, and the verdict file keeps its bytes. Under a lead line
saying that they do not block, the lines are grouped by what each finding's
opening citation names (`Get-NonBlockingFindingGroups`), in this order:

1. `QUALITY:` findings citing product code or configuration: any other
   path, and a finding without a valid opening citation;
2. `QUALITY:` findings citing records or documentation: a path ending in
   `.md`, `.markdown`, `.txt`, `.rst` or `.adoc` in any letter case, which
   covers `History.md`, `TASKS.md` and `PLAN.md`
   (`Test-ReviewRecordCitationPath`);
3. `NOTE:` findings.

The opening citation is looked for after the label and only the white space
that awk's `[[:space:]]` matches in the C locale (space, tab, line feed,
vertical tab, form feed, carriage return), so the commit hook's awk copy of
the rule puts every line in the same group. A finding whose text then opens
with any other white space, such as a no-break space, has no valid opening
citation and goes in group 1.

The session fixes the findings worth fixing as part of the current change.
Nothing records a finding as work for a later session: the gate writes no
task list, index or other hand-off. A finding the session does not act on
stays in the verdict file, and no later review is shown it (section 2).
The notice is console output
only. The commit hook and the merge gate launch the wrappers with
`-NoFindingsNotice`, which turns the notice off: a launched wrapper's output
is the transcript the gate validates under a size limit, and the notice's
lines and escapes would only grow it. A gate prints only a checked
projection of a passing review's output (section 4), so the commit hook
(`prepare_success_projection`, which repeats the grouping rule in awk) and
the merge gate (`Get-CrgSuccessfulReviewProjection`) take the accepted
verdict artifacts' non-blocking finding lines into that projection in the
same groups under the same lead line, each printed as a
`review result:` line (a legacy
`NON-BLOCKER:` shown as `QUALITY:`, an empty group omitted; the hook also
sorts each group):

    [pre-commit] review result: The review passed. The findings below do not block and are not kept as tasks for a later session; fix the ones worth fixing as part of this change.
    [pre-commit] review result: QUALITY findings citing product code or configuration:
    [pre-commit] review result:   QUALITY: <finding line>
    [pre-commit] review result: QUALITY findings citing records or documentation:
    [pre-commit] review result:   QUALITY: <finding line>
    [pre-commit] review result: NOTE findings:
    [pre-commit] review result:   NOTE: <finding line>

The merge gate prints the same lines with `[auto-merge]` in place of
`[pre-commit]`. The gates' projections keep their own checks and do not
use the notice's escaping. Each refuses an accepted verdict that is not
valid UTF-8 without a byte-order mark, or that holds a CR, DEL or a C0
control character other than the line feed, and a finding line longer than
4096 bytes (the hook) or 4096 UTF-16 code units (the merge gate) or with
only white space after its label. The hook and the merge gate count different
characters as white space there: the hook only those `[[:space:]]` matches in the C
locale (space, tab, line feed, vertical tab, form feed, carriage return), so
it accepts a body of only no-break spaces; the merge gate every character
.NET's `IsNullOrWhiteSpace` counts, so it refuses that body. The lines they
accept are printed unescaped.

Showing the findings is display only. When the notice fails, the wrapper
writes a warning to standard error and keeps the verdict's exit code; the
paired session writes such a warning for that verdict, keeps its result and
goes on to the next verdict.
The grouping only orders lines the gate has already accepted, so when it
fails (the hook's awk exits non-zero; the merge gate's grouping throws, or
leaves the lead line or a heading empty or a line count other than the
accepted findings'), the gate prints the accepted finding lines ungrouped,
without the lead line and headings, and its result is unchanged. The hook
writes the ungrouped projection first and refuses when that cannot be read
or written in full. The grouped form is built in a file beside it and
replaces it by a rename; when the grouped form cannot be built or renamed,
the ungrouped projection stays, so a failed grouped write does not refuse
the commit.
A failed print of the projection is not a gate failure: the hook ignores
it, and the merge gate reports it on standard error.

When a provider exhausts its allowance (exit 4) and a replacement review
passes, the findings of passes that completed before the exhaustion stay in
the exhausted run's verdict and forensics files: that run prints no notice,
and the gates project only the accepted review's artifacts. The replacement reviewed the same change in full, and
its findings are the ones shown.

Upgrading from before 2.8.0. By operator decision (2026-11-23), 2.8.0 keeps
no compatibility code for the follow-up index or review tasks of earlier
releases. Every gate is upgraded as a whole: a central installation by activating the
release, a per-project install by installing all of its gate files
together. A mix of 2.8.0 and earlier gate files is not supported, and no
gate checks for one. A follow-up index (`<logs>/review-followups.md`) and
review task lines in `TASKS.md` left by an earlier release are not read,
protected or cleaned up by 2.8.0: delete them by hand. In a per-project
install, the commit that lands 2.8.0 is reviewed by the wrappers already in
HEAD. The fast-forward that brings 2.8.0 into a base that does not have it
yet is run with that base's own merge gate script
(`scripts/shared/auto-merge.ps1` in the base's checkout) as well as the
base's wrappers: the 2.8.0 merge gate launches every wrapper with
`-NoFindingsNotice`, which earlier wrappers do not have. The earlier
wrappers in HEAD and the base record follow-ups and review tasks one last
time. The 2.8.0 wrappers do not read `CROSS_REVIEW_PRUNE_TOOL` and never
delete review logs; delete old ones by hand.
Findings files that earlier releases wrote for passing reviews are not
valid findings files (section 1): while their names are inside the
blocked-round scan's window, a staged review reports them as skipped
(section 5). Delete them by hand.

## 4. PASS line and review-feedback status

Every PASS line states what the review covers:

    ... PASS - covers this source diff only, not target execution or
    deployment readiness

Each ordinary review prints its own PASS line with the coverage wording
(`Get-ReviewPassCoverageText`, after the notice of section 3).

A passing submission also prints one reminder line, with exactly this text
(`Get-ReviewTaskReminderText`; the hook keeps a byte-equal copy,
`CRG_TASK_REMINDER`):

    Reminder: once this change has landed, if it completes a task, delete that task from TASKS.md and every other task list. Task lists hold unfinished work only: a finished task is deleted, not checked off.

The commit hook prints it right after its final PASS line, before the final
staged-tree identity check, after which the hook prints nothing more for
a commit it authorizes; like that
PASS line it does not prove that the commit landed. The merge gate prints it
after its `OK - '<base>' is now at <sha>` line, once the fast-forward is
applied, and the paired review session after its PASS, before central
publication commits the result or recovery finalizes the retained result.
The commit hook and the paired
session print it before the change has landed, so the text itself makes
landing the condition for deleting a task. The review wrappers do not print
it. A reminder that cannot be printed never fails the run: the merge gate
and the paired session report that on standard error, and the commit hook
ignores it.

On success a gate prints only a checked projection of the accepted review's
output (`validate_success_projection_pair` in `scripts/git-hooks/pre-commit`,
`Get-CrgSuccessfulReviewProjection` in `scripts/shared/auto-merge.ps1`), so
a plain WARN from the feedback path was lost whenever the review passed.
Every outcome of that path the operator has to act on is therefore also
printed as a `review-feedback WARN: ` line (`Write-ReviewFeedbackStatus`):
findings files skipped by the blocked-round scan (counted, not named), and a
blocked-retry check or prior blocked findings unavailable (section 5).
Housekeeping the review skipped or left half done is printed the same way
as a `housekeeping WARN: ` line (`-Housekeeping`), with fixed text: folder
holds kept until the review process ends because a Git child could not be
confirmed ended, which can leave a temporary review folder behind. The
rules below apply to both kinds.

- Each gate collects these lines apart from the strict projection
  (`crg_feedback_status` in the hook, `Get-CrgReviewFeedbackStatusLines` in
  the merge gate) and prints them as `review result:` lines. They are read
  from every launched review invocation, not only the accepted one: an
  exhausted leg, or a passing child of a panel whose provider was replaced,
  may still have printed them.
- Neither collecting nor printing them can fail a passed gate: a line that
  cannot be shown (over 4096 bytes without the tag, with a control character,
  or not in the form) becomes a fixed notice, an unreadable or missing
  transcript one notice, and more than 32 distinct warnings are counted on
  one line. The hook prints them straight to the console after the
  projection display, with no file of its own, so they take no space a
  required write needs; the merge gate's collector only reads, inside one guard. (Earlier
  forms were dropped the same day: checking these lines inside the
  strict projection read only the accepted review and could refuse a passed
  gate; adding them to the projection file tied their bytes to its required
  write.)
- Transcripts are read as the wrapper and its provider tools wrote them: a
  CR before the line end is removed, and the merge gate reads each child log
  line by line with invalid bytes replaced, since its strict evidence reader
  refuses a whole log for one control character anywhere in it.
- The writer keeps each message to at most 600 UTF-16 units, shortened with
  a marker and never inside a surrogate pair; with the tag and prefix the
  line stays under 4096 bytes in any console encoding. It prints at most 12
  warnings of each kind per review, then one line saying more were left out.
- A successful gate's output must read the same whichever provider
  reviewed, so these texts name the Git directory, the logs
  folder, a setting or Git's own messages,
  never a findings file, a verdict or a per-provider log folder, whose
  names carry the backend; detail that could (a path, an exception message)
  stays on a plain WARN line, which a failed gate shows. The collectors remove the
  tag naming the wrapper.

The commit gate's own lines (`scripts/git-hooks/pre-commit`: per backend and
final), the paired session PASS (`scripts/paired-review-session.psm1`) and
the Grok adapter PASS (`scripts/grok/auto-review.ps1`) carry the coverage
wording only.

## 5. Blocked retries

A blocked staged change was being resubmitted with each cited line fixed
and nothing else, so every review round found the next instance of the
same defect class. The authoring rules that answer this (class sweep,
fix-on-fix halt, round-budget tripwire in
`docs/authoring-invariant-checklist.md`) were prose only. This section has
the gate hold a retry to them before another review is spent.

- The change under retry is a staged review (the commit gate's scope) in
  one working tree at one HEAD, keyed by that working tree's own Git
  directory (the context's `GitDir`, from the same Git answer that confirms
  the repository in `Resolve-CrgMainCheckout`, with inherited selectors
  removed) and the HEAD commit id, or `unborn`. Retries share both; when
  the commit lands HEAD moves, and the next change starts with no rounds.
  Both are compared exactly, and the checkout's own location is not part of
  the key: a main checkout moved with its `.git` folder starts afresh, since
  its Git directory path changes, while a linked worktree moved with
  `git worktree move` keeps its Git directory under the common one, and so
  its rounds. Another
  change staged on the same HEAD in the same working tree counts as the
  same change: an identity taken from the staged content would change with
  every fix. Its record can say why no site changed, and the reviewer
  judges that.
- Only the final gate exit decides whether a run is a round. A fail-closed
  run (exit 3) is not one, even when passes that completed raised BLOCKER
  findings (they stay in its verdict file), and neither is a positively
  identified exhaustion without a BLOCKER; the next run reviews the change
  without a remediation requirement from them. A staged review whose final
  gate exit is 2 records the column-one `BLOCKER` findings of every
  pass that can block it, the preserved bodies of errored passes included
  (exhausted passes beside a BLOCKER still block), as a blocked round: a
  findings file with
  the retry lines (section 1), through the same writer, name binding and
  folder. The gate never deletes one, writing it never affects the verdict,
  and a failure is a WARN, after which the retry is asked only about the
  rounds kept. The commit gate runs one wrapper per leg and stops at the
  first blocked leg, and a leg that falls back after exhaustion reviews
  once, so one commit attempt adds at most one round.
- A staged review scans the findings folders of section 1
  (`Select-ReviewBlockedRounds`) for this change's rounds: valid files of
  this repository (their `repository` equals this review's, compared
  exactly) with the same working tree and HEAD, written in the last 14 days
  and not after the current time, newest 20, with older ones counted toward
  the number of rounds only. Other repositories' files sharing the folder
  are passed over. The findings folder is read before a submodule's working-tree
  folder, and a name is taken only by a valid file of this repository, so
  a damaged or foreign copy takes nothing. The folder is listed one name at
  a time; a name older than the window (its `written` time) is passed over
  without being opened, and a name outside the stored form (`x.FINDINGS`
  included, since the listing matches `.findings` in any letter case) is
  counted invalid without being opened. At most 40 rounds, each from at
  most 64 KiB, are kept in memory. A file that is invalid, refused (a link
  or not an ordinary file; a directory with a findings name counts as
  unreadable, since Windows refuses it with the error of a denied access)
  or unreadable is counted on a `review-feedback WARN:` line (section 4)
  and named, with the reason, on plain WARN lines up to 20, since it can be
  a lost round; a file dated in the future is counted on that status line
  only. A folder that cannot be listed fails
  the scan rather than reading as empty. A scan that
  fails, or a working tree whose Git directory is unknown, makes the check
  unavailable: a `review-feedback WARN:` status line (section 4) and a
  `PRIOR BLOCKERS unavailable` scope-text line, and the review runs. The
  rounds are an aid the gate keeps; losing them
  returns the gate to reviewing without them, never to passing anything
  unreviewed.
- The remediation record is `crg-remediation.txt` in the working tree's own
  Git directory (`.git/` in a main checkout, `.git/worktrees/<name>/` in a
  linked one), so each working tree has its own and it cannot be committed:

      finding <digest> [<digest> ...]
      [finding <digest> ...]
      invariant <the rule every instance broke>
      sweep <where and how every instance was searched for>
      sites <every place changed, or why none needed to change>
      approach <why the approach is right, or how it was re-derived>

  One block per defect class; a block may name several findings, since one
  class often surfaces as several. Blank lines separate blocks. Lines may
  end with LF or CR LF and a leading byte-order mark is ignored, because
  the editors that write the record produce either; everything else is
  strict: one or more `finding` lines (a line holds at most 63 digests, so
  a larger class continues on the next), then the other three lines in that
  order, each with text of at most 4096
  characters and no control characters (ASCII or C1), no digest named
  twice, and at most one `approach` line, after the last block. The record
  is read through a no-follow handle relative to its held folder, strict
  UTF-8, at most 64 KiB, and only while that folder is the working tree's
  Git directory confirmed when the review started (its identity is kept
  with the context, as in "File identity"); otherwise it counts as
  unreadable and the retry is refused. A digest that is not among this
  change's prior findings is allowed, so one record can be kept across
  rounds and changes; a block naming none of them is not shown to the
  reviewer.
- Before any reviewer is launched, every prior BLOCKER digest the record
  is asked to cover must be in a block: those of the kept rounds, newest
  round first, up to 256. That many take about 17 KB of `finding` lines
  packed 63 to a line, and under 30 KB as one block per digest with
  one-word text, so a record that answers them always fits its 64 KiB;
  the kept rounds can hold more than any record
  could (each round file may be 64 KiB), so further digests are counted on
  the refusal and left to their round files. Once the change has blocked
  twice (the round-budget tripwire), or has more digests than that, the
  record needs the `approach` line. Otherwise
  the wrapper exits 2 without a review or a new round, naming the record,
  what is missing, the format, and the findings still needing a block
  (digest, round file, citation; at most 100 named, and the round files
  hold every one); the commit gate reports a blocked commit. The check is
  mechanical: it proves that a record exists for every finding, not that
  the record is true. The reviewer judges that.
- On an accepted retry the evidence bundle gets `PRIOR-BLOCKERS.txt`,
  created new and deleted if writing it fails (the review then runs without
  it, with a `review-feedback WARN:` status line and a
  `PRIOR BLOCKERS unavailable` scope-text line): each prior finding quoted as
  in `COMMIT-LOG.txt`, within 8 KiB per finding and 64 KiB in total
  (counting the citation) and at most 100 shown, the rest counted on
  a `NOT SHOWN` line, then the record's blocks that name one of those
  findings and its approach line, rebuilt from the validated fields and
  quoted the same way; that part is bounded by the record's own 64 KiB,
  which the `\xNN` escaping can grow up to fourfold. The scope text lists
  the prior findings in a `PRIOR BLOCKERS` section. The prompt's
  change-propagation duty 4 has the reviewer apply the class sweep to each
  block's invariant across the whole diff, not only at the listed sites (a
  remaining in-diff instance is a finding at its own severity), and report
  a record that misstates the class, the sweep or a site as a `QUALITY:`
  finding under DOC-VS-CODE-DRIFT.
- Out of scope: merge reviews (each fix after a blocked merge is a new
  commit through the commit gate, where this check applies), paired reviews
  and the Grok adapter. The check holds an author to the discipline; it is
  not a security boundary, since the round files and the record are local
  files under the operator's control, like the commit itself.
