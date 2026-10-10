# Review feedback v1: findings files, carry-forward, TASKS.md, the PASS line and blocked retries

Audit source: a consumer project's corrective audit of 2026-10-07. It
found that NOTE findings were not kept anywhere a later session would see
them, that findings raised against a file were not shown to the next review
of that file, and that a gate PASS was being read as approval of target
behaviour or deployment. This design covers those gaps. Section 5 covers a
gap the review of this design itself exposed: a blocked commit was retried
with only the cited line of each finding fixed, so each review round found
the next instance of the same class. The fix-on-fix
advisory (`Get-FixOnFixAdvisory`) and the review prompt's change-propagation
duties are separate and documented where they live; the advisory reads
committed history, so it never sees retries of one uncommitted change.

## Scope

Ordinary review path of both review wrappers (`scripts/codex/auto-review.ps1`,
`scripts/claude/auto-review.ps1`), which also serve the commit gate and the
merge gate; the blocked-retry check (section 5) applies to staged reviews,
the commit gate's. PreparedPair (paired) reviews and the Grok adapter keep their own
follow-up path (`Write-CrgPairedFollowups`, the paired private index); they
get only the coverage wording of the PASS line below.

## File identity

Every directory from the volume root down to a file's folder is held for the
whole operation (`Enter-CrgHeldDirectory`). Extended-length drive and UNC
spellings (`\\?\C:\...`, `\\?\UNC\server\share\...`) are accepted like their
plain forms; any other `\\?\` or `\\.\` path names a device and is refused.
Only the volume root is opened by path. Each directory below it is opened by its one name relative to its held
parent's handle, without following a link, with directory-listing access and
delete sharing withheld, so it cannot be renamed or deleted meanwhile, and
checked to be an ordinary directory. A missing folder the gate may create
(`logs`, `review-findings`, `.git/info`) is created relative to its held
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
content reads are bounded (1 MiB, strict UTF-8; the task count in section 4
only scans line prefixes and has no limit), a file is created only through a
no-follow CREATE_NEW, and the only explicit deletions set the delete
disposition on the held handle, and only on files this run created through
that handle: the recovery copies (`TASKS.md`'s and the exclude file's) and
their `.partial` forms (section 3), a `TASKS.md` this run created and failed
to write, and a findings file, `CARRIED-FINDINGS.txt` or
`PRIOR-BLOCKERS.txt` this run created and failed to write (none is yet a
record). Apart from these, the main checkout's `index.lock`, which
the task write creates delete-on-close (section 3), is removed by the
system when its handle closes, the process's end included.
No review record is ever deleted. Text a file must hold exactly (a path
with a lone UTF-16 surrogate, which a Windows name may contain) is refused
before anything is written, since UTF-8 would store U+FFFD and the file
would read back as another value. A path Git reports is used with only
its line end removed, and one the Windows PowerShell path functions would
change (a last name ending in whitespace, or any name ending in a dot,
which .NET Framework drops; `.` and `..` segments are resolved first,
keeping every name) is refused rather than replaced by the folder it would
then name, as is a path that is not a full one (a drive root or a share):
a main checkout so named is not confirmed, with that
reason, and a working tree's Git directory so named gives no retry key
(section 5). Folder
listings go by path but only supply names, each then opened relative to the
held folder. Work left undone is reported, as a WARN or a `NOT CARRIED`
line. The main checkout and its Git directory are confirmed once, while
held, when the review's Git context is resolved, and their identities
(volume serial and file ID) are kept with their paths; every later use
(task writing, the task counts) holds them again
and refuses a folder that is no longer the one confirmed
(`Enter-CrgMainCheckoutBinding`). The identities of the common Git
directory and of the logs folder's parent are kept the same way even when
there is no main checkout, and writing a findings file or selecting
carried findings first holds the common Git directory and the parent of
every findings folder written or read (section 1) and refuses one that changed
(`Enter-CrgReviewLogsBinding`). So a record goes into, and is matched
against, the repository the review started in; the logs and findings
folders are then reached through those held entries. A file's name is
checked as stored on its held handle (`StoredName`), since a
case-insensitive folder opens `x.FINDINGS` for `x.findings` and
`tasks.md` for `TASKS.md`. That first confirmation
(`Resolve-CrgMainCheckout`) has to discover the repository: its Git
children run from the review's folder and from the candidate checkout,
isolated from inherited repository selectors (`GIT_DIR`, `GIT_INDEX_FILE`
and the rest of `Get-CrgGitSelectorEnvironmentKeys`), and Git run there
must report the same common Git directory and top level, with that common
directory as the checkout's own Git directory. Every Git child
after it is isolated the same way and names the repository explicitly
(`--git-dir` and `GIT_COMMON_DIR` set to the common Git directory). The
task queries (`Read-ReviewMainGitBytes`) also set `--work-tree` to the main
checkout, whose Git directory the common one is, so they read that
checkout's own index, not a hook's. They never
rediscover the repository through the checkout's `.git` entry
or a `commondir` file in the Git directory: in a submodule or a
`--separate-git-dir` checkout that entry is a file naming the Git
directory, and either file can be rewritten while the folders stay held.
A path Git names for a file the gate changes or creates (`info/exclude`,
the recovery copies, the index and its lock) must be exactly that name in
the confirmed Git directory, or no task is added
(`Resolve-ReviewGitDirPath`).

## 1. Findings file per passing verdict

When a wrapper's verdict passes (exit 0) and it has findings or was shown
carried findings (section 2), the wrapper writes one findings file in the
repository's findings folder (beside the review logs, or for a submodule
inside its common Git directory, below):

    <logs>/review-findings/<backend>-review-<written, UTC yyyyMMdd-HHmmss>-<12 hex>.findings

`<logs>` is the folder that holds `review-followups.md`
(`Get-FollowupIndexDir`: `logs` beside the common Git directory, which is
the main checkout's in the usual layout). The folder is fixed by the
common Git directory (`Get-ReviewFindingsLocation`), so every working tree
of a repository writes and reads the same records and no checkout change
moves them. A submodule is the exception to `<logs>`: its follow-up index
is in the current working tree's `logs`, which each linked worktree has its
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
is written (a WARN says why) and no task is added. Several
repositories can share it (separate Git directories under one parent), so
every file names its repository (below). A
separate folder keeps these files out of `logs/<backend>/reviews`, whose
age-prune, trend and checklist readers have their own file-name rules. The
time in the name is the file's `written` time to the second, so section 2
can pass over old files by name alone. The 12 hex digits are the start of
the file content's SHA-256, so two records written in the same second get
different names in practice. The name is bound to the content: a file
whose backend, time or hash disagrees with its content, or whose `carried`
line names its own file, is invalid, so an edited record is reported
rather than read as a retirement. The name alone guarantees nothing: an existing file of that name
is the same record, already written, only when it is stored under exactly
that name and its content is identical; any other is refused with a WARN. A write that fails
deletes the partly written file through its handle; one left by a process
that died while writing is counted invalid and named in a WARN by the next
carry-forward scan (section 2).

Content (UTF-8 lines, each ending with LF, written once, never edited):

    review-findings v1
    repository <the repository's common Git directory, absolute>
    verdict <verdict locator>
    backend codex|claude
    written <UTC, yyyy-MM-ddTHH:mm:ssZ>
    finding QUALITY|NOTE <sha256 hex digest> <path>:<line>[:<col>] or -
    cite <path>:<line>[:<col>]
    > <the finding's text, escaped, one line of it per quote line>
    carried <sha256 hex digest> <findings file name>
    end

`finding` blocks and `carried` lines repeat zero or more times, in that
order; `-` stands for no opening citation. Each `finding` line is followed
by zero or more `cite` lines, the finding's further citations (below), no
two the same and none repeating the opening one. A blocked round (section 5) uses the same
format and name with two more lines after `written`,

    retry-worktree <the working tree's own Git directory, absolute>
    retry-head <the HEAD commit id, or unborn>

one or more `finding` blocks, all `BLOCKER`, and no `carried` line; a
passing review's file has neither retry line and no `BLOCKER` finding. The
writer refuses any other mix, and the reader's byte-for-byte check below
holds both kinds to it. Each `finding` line and its `cite` lines are
followed by one or more quote lines holding the finding's text (the lines its digest covers)
escaped and quoted exactly as in `CARRIED-FINDINGS.txt` (section 2), so the
quote lines hold only printable ASCII and none can pass for a format line.
The file is UTF-8: the repository, the verdict locator and the retry
working tree, all paths, may hold any other character except the ASCII
control characters (U+0000 to U+001F and U+007F; a Windows name may hold
the C1 ones). The writer refuses any
name outside the form above, so every file can be named by a later
`carried` line. The format
is line based so it parses identically on every PowerShell version (PowerShell 7's JSON reader turns date strings
into dates before any check could see them), and the `end` line makes a
partly written file invalid.

- `repository` is the common Git directory the review's Git context
  resolved (full path, no trailing separator except at a volume root, where
  `C:\` stays `C:\` because `C:` names the drive's current folder), as Git
  reports it with inherited repository selectors removed; a context whose
  inherited selectors name another repository has none. It is what binds a
  record to its repository: section 2 uses only its own repository's files.
  A run without one writes no findings file.
- The verdict locator is the follow-up index's (`Get-ReviewArtifactLocator`):
  the repository-relative central path when the verdict ends up in
  `logs/<backend>/reviews`; otherwise the path relative to the logs folder's
  parent (the follow-up index's locator root, which is the main checkout in
  the usual layout) when the verdict lies inside it, else the absolute path.
- A finding is a column-one `QUALITY:`, legacy `NON-BLOCKER:` (recorded as
  QUALITY) or `NOTE:` line of the verdict artifact, or for a blocked round
  a column-one `BLOCKER:` line. The digest is
  `Get-CaptureFindingDigest` over the finding's lines. The citation is the
  follow-up index's strict `path:line[:col]` citation stored as a repository
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
- The file is self-contained: every later reader (section 2, a person or
  agent following a task in section 3) gets the severity, citations and text
  from it alone, through one parser that decodes each text (strict UTF-8)
  and checks it against its digest, and accepts the file only when the
  writer, given the parsed values, would produce it byte for byte (so a
  `\x41` where the writer puts `A` makes the file invalid: each record has
  one stored form, and the size limits of section 2 read that form), so a
  record cannot be read differently from how it was written. An earlier design kept the text only in the
  verdict artifact and re-read it there by digest; that re-interpretation
  (verdict paths, the REVIEW_SRC decision, verdicts pruned over time) was
  a way for a record to be read differently from how it was written, and
  was dropped (2026-10-09); do not move the text back out of this file.
  The text stays reviewer output: it is escaped and quoted, never prose that
  a session-start file shows.
- Each `carried` line names one occurrence this review was shown under
  section 2: a digest and the earlier findings file that holds it.
- A failed review writes no findings file. A blocked review's QUALITY and
  NOTE findings are not recorded either: they are re-raised by the review
  that follows the fix. A blocked staged review records its BLOCKER
  findings as a blocked round (section 5).
- Findings files are never deleted by the gate. Review-log deletion goes
  only through the operator's `CROSS_REVIEW_PRUNE_TOOL` safe-delete script
  (off when unset; see `INSTALL.md`), which does not cover this folder; an
  expiry that deleted these files directly was removed for bypassing
  that contract. Files written more than 14 days ago are never carried
  forward (section 2); remove old ones by hand through the Recycle Bin when
  wanted.
- Writing never affects the verdict or the exit code; a failure is a WARN.

## 2. Carry-forward into later reviews

While building the scope text, each wrapper looks for open findings from
earlier reviews that cite a file in the current change:

- A findings file is used only when it is exactly the version-1 format
  above with valid values (citations in stored form, the timestamp in
  exactly the written shape). Stored citations are checked, never
  normalized again, so whatever the writer stores reads back unchanged. Any
  other file is skipped and counted on a `NOT CARRIED` line (links and
  non-files counted apart from invalid content; a directory or directory
  link with a findings name is listed too and, since Windows refuses to open
  it as a file with the same error as a denied access, counted as a file
  that could not be read), so a malformed file can
  neither suppress nor retire a finding. Skipped files (invalid, refused or
  unreadable) are also named in WARN lines with the reason, up to 20; the
  counts cover the rest. Their names go only to the WARN lines, never the
  scope text, since a name that failed validation is not machine-authored.
  A findings folder that cannot
  be listed makes carry-forward `unavailable` rather than empty. A findings
  file larger than 64 KiB is invalid, and the writer refuses to write one.
- Candidates: valid passing-review findings files of this repository (their `repository`
  equals this review's, compared exactly), from the folders of section 1
  (the findings folder, then a submodule's working-tree folder; a name is
  taken only by a valid file of this repository, so a later copy of a
  taken name is passed over, and a damaged or foreign copy takes nothing),
  whose `written` is within the
  last 14 days and not after the current time, newest first, at most 200
  files. Blocked rounds (section 5) are never candidates: their BLOCKER
  findings are not carried, and having no `carried` line they retire
  nothing. Another repository's files sharing the folder are neither selected
  nor allowed to retire anything, and are not counted: they hold nothing of
  this repository's. A file dated in the future is skipped and counted on
  the `NOT CARRIED` line. The folder is listed one name at a time and the
  scan keeps at most 400 parsed files, plus at most 40 blocked rounds
  (section 5), each from at most 64 KiB, in memory.
  Because the gate deletes no findings file, a file whose name (its
  `written` time) is older than the window is passed over without being
  opened, and a name outside the stored form is counted invalid without
  being opened (the listing matches `.findings` in any letter case, so
  `x.FINDINGS` is counted too): content reads follow the window, while
  listing the names still grows with the folder.
- An occurrence (a finding in one findings file) is open until a candidate's
  `carried` line names both its digest and that file. That is the retirement
  rule: a carried finding is shown to one review that passes, which retires
  exactly the occurrences it was shown. A review can name only files that
  existed when it was shown them, so an acknowledgement never retires an
  occurrence written later: a finding raised again, even by a review that
  overlapped the acknowledging one, sits in a new file and stays open. An
  acknowledgement in a file tied, to the second, with the oldest kept
  candidate can fall outside the newest 200; that shows its finding once
  more and never hides one.
- Selected when the path of any of its citations (the opening one or a
  `cite` line) is one of the change's paths (both sides of a rename), and
  labelled with the first such citation. Findings without any citation are
  not carried. At most 20 are
  selected, newest first, within 64 KiB in total, each finding counting its
  label citation and quote lines (the evidence and scope text repeat the
  citation); a finding whose citation and quote lines pass 8 KiB is named on
  its own `NOT CARRIED` line, by its findings file and digest rather than its
  citation, and takes no place, so it never keeps a smaller finding out.
  Up to 20 such lines are written; one more line counts the rest.
- Every limit that leaves something out is counted on a `NOT CARRIED`
  line. Open findings beyond the 20 selected or the 64 KiB total and
  occurrences beyond 10 per finding share one line: they are not retired,
  so they are offered to a later review. Candidate files beyond the newest 200 get their own line
  saying they were not used in this review. No exclusion is recorded: each
  review selects its candidates afresh, so which files are left out can
  change from one review to the next.
- The same finding often sits in several findings files (a commit gate and
  a merge gate raising one text). Occurrences are grouped only when digest,
  severity and stored citations all match, so each occurrence in a group
  passed the same changed-path check and is quoted under the one label
  shown; up to 10 open occurrences are kept per group. The digest covers the
  text, so every occurrence in a group holds the same text; it is taken from
  the newest occurrence, as parsed in the scan. Nothing is read from verdict
  files.
- The text goes into `CARRIED-FINDINGS.txt`, created no-follow and new in
  the held evidence bundle folder, as the stored quote lines under a machine
  header: escaped and quote-framed exactly as `COMMIT-LOG.txt` (injective
  `\xNN` escaping, `> ` prefix on every content line, machine headers alone
  at column zero), never truncated: a write that fails deletes the file
  through its handle, and the scope text then says it is unavailable and not
  to be used. It is data for the reviewer, never instructions.
- The scope text gets a `CARRIED FINDINGS` section listing severity,
  citation and source findings file name for each, and the `NOT CARRIED`
  lines, because reviewers often open only `DIFF.patch`.
- The prompt (`review-prompt-template.md`, change-propagation duty 5) tells
  the reviewer to check each carried finding against the current diff and
  raise it again, at its proper severity, only if it still applies. A
  carried finding is not a finding by itself.
- Only the occurrences of findings actually quoted are recorded in this
  review's findings file (`carried`); a `NOT CARRIED` finding stays open.
- A failure prints a WARN with the reason, puts a fixed `unavailable` line
  (no failure detail) in the scope text and never stops the review.

## 3. TASKS.md

`TASKS.md` is per-user work tracking, not project state: it lives at the root
of the main checkout, is never committed, and differs between people working
on the same project. The main checkout is, from the main working tree
itself, that tree's top level, and from a linked worktree the first working
tree `git worktree list` names; either is accepted only when Git run there
reports that top level with this repository's common Git directory as its
own Git directory, so a linked worktree is never taken for it (only the
main working tree uses the common directory's index). It is
never inferred from `<logs>`, whose parent is not the checkout when the Git
directory is kept elsewhere. When Git lists the Git directory itself as
the first entry, the candidate is the main working tree the repository's
`core.worktree` setting records (Git keeps a submodule's that way, so a
linked worktree of a submodule finds its main checkout, as does any
repository with that setting). A repository that records no usable main
working tree there (a `--separate-git-dir` repository usually has no
`core.worktree`) gives a review run from one of its linked worktrees no
main checkout, while one run in its main working tree finds it. Without a
confirmed main checkout (that case, a bare
repository, or a checkout that cannot be confirmed) no task is added, and
the task count reads `could not be counted`; a review that has findings to
add as tasks also gets a WARN giving the reason.
The checkout and its Git directory are confirmed while held, and every
later use checks that the held folders are still the ones confirmed (see
"File identity"). Every Git child for tasks is bound
to that confirmed checkout and its Git directory (`--work-tree`,
`--git-dir`).

After a passing verdict with QUALITY or NOTE findings, the wrapper adds
tasks to that file:

- QUALITY findings go under the heading `## Review follow-ups: QUALITY (do
  these first)`; NOTE findings under `## Review follow-ups: NOTE`. An
  existing section stays where it is. A missing QUALITY section is created
  as the first section: before the file's first `## ` heading, else after a
  `# ` title line, else at the top. QUALITY is an immediate follow-up by
  design. A missing NOTE section is created at the end of the file.
- Each task is one line:
  `- [ ] QUALITY <citation> - <record> (<date>)`, with
  `(no validated citation)` for a finding without any citation. A finding
  gets one task per citation (its opening one and each `cite` line), so it
  is found from every file it cites. `<record>` is
  the findings file just written (its path relative to the main checkout
  when inside it, else absolute), which the gate never deletes, so a task
  keeps leading to its finding's text however old the verdict gets. When
  the findings file could not be written, no task is added and a WARN says
  so: a task names only a record the gate keeps. (Falling back to the
  verdict locator was tried and dropped: verdicts are pruned, and the
  duplicate check would then keep a task leading nowhere while blocking a
  usable one.) Finding prose is not copied: agents read
  `TASKS.md` at session start, and finding text is reviewer output (the same
  boundary rule as the follow-up index; merge-gate BLOCKER 2026-07-11).
- Tasks are kept one per severity and citation: a citation adds no task
  when an unchecked task with the same severity and citation already exists
  in its section as a complete task line of the form above (any other line,
  however close, is kept and suppresses nothing), so distinct findings at one citation share the first
  task's line and record. An uncited finding adds no task only when an
  uncited task whose record field is exactly this record exists, so uncited
  findings from different reviews are not merged. Each task line is read as
  its fields (the citation, and the record running up to the final date), and
  the fields are compared whole, never by prefix. Whether an existing task's record still exists is not
  checked: the gate deletes none, and one removed by hand is the remover's
  choice. (An earlier design pointed tasks at verdict files, which are
  pruned over time, and so had to treat a task with a missing verdict as
  absent, with a grace period for merge-panel verdicts published late; that
  existence check is gone with the verdict link.)
- The gate never removes, reorders or edits other lines; people and agents
  check tasks off or delete them. Lines end at CR LF, CR or LF; every
  existing line keeps its own line break, mixed endings included; new lines
  use the file's first line break (LF for a new file), and a final line
  without a break gets one only when a line is added after it. A leading
  byte-order mark is kept. A `TASKS.md` that is not valid UTF-8, is over
  1 MiB, or would grow past 1 MiB with the new lines, is left alone with a
  WARN, so the gate never writes a file it could not read back.
- Missing file: created with the needed sections.
- If the main checkout cannot be resolved, or `TASKS.md` is tracked by Git
  in that repository (matched case-insensitively, since `tasks.md` is the
  same file on Windows), nothing is written and a WARN says why: editing a
  tracked file would leave the checkout dirty and block merges. The check
  runs first, before the exclude file is touched, and again where its
  answer has to hold, under the main checkout's index lock: Git serializes
  every index writer with `<index>.lock`, so a Git command that has already
  hashed `TASKS.md` but not yet written the index holds it. The writer
  creates that lock itself, exclusively and deleted when its handle closes
  (a killed process leaves none behind), and runs this check and the ignore
  check below (while the handle on an existing `TASKS.md` is held, or
  immediately before a missing one is created) and the write under it; Git commands in the main checkout
  meanwhile fail with Git's own `index.lock: File exists`. Plain
  `git commit`, which the gate's commit wrappers run, holds no lock during
  the pre-commit hook. A lock that already exists means no task is added,
  with a WARN naming it: `git commit -a` and partial commits hold it through
  the hook, as does any other Git command or a lock left behind. Earlier
  approaches were dropped: relying on the exclusive `TASKS.md` handle alone
  (a Git command that had hashed the file before the check could still
  write an index tracking it afterwards), and accepting an existing lock
  when an inherited `GIT_INDEX_FILE` named it, as `git commit -a` sets it (a
  path in the environment proves neither who holds the lock nor that the
  holder waits for this review, and a run not holding the lock cannot stop
  the index changing between the check and the write).
- Because the exclude file makes a local `TASKS.md` an ignored file, which a
  checkout may overwrite silently, the merge gate fast-forwards with
  `--no-overwrite-ignore`: an incoming tree that tracks `TASKS.md` (or any
  other path ignored locally) makes the merge refuse instead.
- `/TASKS.md` is appended to the repository's local exclude file
  (`git rev-parse --git-path info/exclude`) when that exact line is absent,
  through the handle that read it, unless that would take it past 1 MiB
  (then a WARN). The file is read as Git reads it: a record ends at LF, a
  CR right before the LF (or at the very end of the file, which Git ends
  with an LF before reading) and trailing unescaped spaces are dropped, and
  any other CR stays part of the record; the append starts with an LF
  whenever the file does not already end with one. That file is itself
  untracked and per-clone. A partly
  written append is not harmless (`/TASKS` alone ignores another path), so
  the file's original content is first copied to
  `git rev-parse --git-path crg-exclude-recovery` (as a recovery copy,
  below); a failed append is cut back to the original length through the
  same handle and the copy deleted. A copy left by an earlier run (an
  interrupted append, one that could not be cut back, or a copy whose
  deletion failed) is looked for first, before the exclude file is opened or
  created and before an already present line can count as done: it blocks
  task writing with a WARN naming it until someone compares it with the
  exclude file, restores that file from it if needed, and deletes it.
  Writing then
  goes ahead only when `git check-ignore` confirms `TASKS.md` is effectively
  ignored (plain `check-ignore`, which prints only paths Git ends up
  ignoring, with negation applied; no pattern text is parsed, since a
  pattern can itself contain colons): a root `.gitignore` line `!TASKS.md`
  outranks the exclude file, and then nothing is written and a WARN says
  why. The check names exactly `TASKS.md`, so an existing task file stored
  under another letter case (`tasks.md`, which `core.ignorecase=false`
  leaves unignored) is refused with a WARN asking for the rename. The
  ignore check runs again under the index lock with the tracking check: a
  checkout or pull completing before the lock could bring in a `.gitignore`
  with `!TASKS.md`.
- A recovery copy (`TASKS.md`'s and the exclude file's) exists under its
  name only once complete: it is written as `<copy>.partial`, created new,
  and renamed to its name without replacing anything. A copy written in
  place could be cut off and then read, by its name alone, as complete. A
  run deletes only a `.partial` it created itself, through the handle that
  created it. A `.partial` found already there is kept: one no writer holds
  is most likely from a run that died before its copy was complete, and so
  before it changed anything, but nothing shows the gate made it. It is
  looked for as early as its copy, before anything can count as already
  done, and task writing stops with a WARN naming it until someone checks
  it and deletes it. (Deleting it automatically, on the guess that the gate made
  it, was dropped in the merge review of 2026-10-09.)
- Every writer holds `TASKS.md` through one exclusive no-follow handle for
  its whole read, check and write; that handle is what serializes writers,
  the gate's own runs and an editor alike. An existing `TASKS.md` must be one
  ordinary single-link file stored as exactly `TASKS.md` (a link, several
  links or another letter case write nothing). The recovery copy, at
  `git rev-parse --git-path crg-tasks-recovery.md` (in the Git directory,
  which Git never stages), is the guard: it is made before `TASKS.md` is
  created or rewritten. A copy left by an earlier run is looked for first,
  before `TASKS.md` is read, so a run whose lines are already present still
  reports it. The new content, which only
  adds lines, is written whole to the copy, then to `TASKS.md` (through the
  held handle, or through a new CREATE_NEW handle when `TASKS.md` was
  missing), and the copy is deleted through its handle. If writing
  `TASKS.md` fails, an existing file gets its old text back, a newly created
  one is deleted, and the copy is deleted; if that restore fails, or the
  process dies after the copy is complete, the copy stays. A copy that exists
  and is held by another writer makes this writer retry; one that cannot be
  opened for another reason (a link, several links, access denied) is
  reported with that state and reason; one that no writer holds makes every
  writer refuse with a WARN naming it, until someone
  compares it with `TASKS.md`, restores `TASKS.md` from it if needed, and
  deletes it. A writer that finds `TASKS.md` or the copy in use retries for
  about two seconds, then gives up with a WARN, and one that finds
  `TASKS.md` created by another writer before its own create starts over.
- Earlier designs were dropped. The follow-up index's directory lock
  (`TASKS.md.lock`, which also held the recovery copy) writes and removes its
  owner marker by path, and a `.gitignore` could leave the copy inside it
  visible to Git, while the exclusive handle already serializes writers.
  Replacing the file by rename overwrote an editor's save made between the
  read and the rename.
- Tasks record a passing review, not a landed commit. The wrapper writes
  them at its own pass even when a parent gate stages the follow-up index
  rows for later promotion: if a later leg blocks, the passing leg's
  findings still describe code that is being reworked, and the
  duplicate check stops a retry from adding them twice.
- A failure never affects the verdict or the exit code; it is a WARN.

## 4. PASS line and review-feedback status

Every PASS line states what the review covers. The merge gate's PASS line
also gives the open review-task counts:

    ... PASS - covers this source diff only, not target execution or
    deployment readiness; open review tasks in TASKS.md: QUALITY=<q> NOTE=<n>

Each ordinary review prints its own PASS line with the coverage wording
(`Write-ReviewFeedbackRecords`, after its records, both wrappers) and then
the counts as a review-feedback status line:

    review-feedback: open review tasks in TASKS.md: QUALITY=<q> NOTE=<n>

On success a gate prints only a checked projection of the accepted review's
output (`validate_success_projection_pair` in `scripts/git-hooks/pre-commit`,
`Get-CrgSuccessfulReviewProjection` in `scripts/shared/auto-merge.ps1`), so
a plain WARN from the feedback path was lost whenever the review passed.
Every outcome of that path the operator has to act on is therefore also
printed as a `review-feedback WARN: ` line (`Write-ReviewFeedbackStatus`):
tasks not added and why, recovery copies or `.partial` files left, a
findings file not written, findings files skipped (counted, not named),
carried findings unavailable, QUALITY follow-ups not staged, and a
blocked-retry check or prior blocked findings unavailable (section 5).
Housekeeping the review skipped or left half done is printed the same way
as a `housekeeping WARN: ` line (`-Housekeeping`), with fixed text beside the
plain WARN that carries the detail: the review-log age-prune skipped, off
for unidentifiable index entries, limited to a partial folder listing, or
not run because `CROSS_REVIEW_PRUNE_TOOL` cannot be used; prune batches that
failed; and a follow-up index lock that could not be removed and stays. The
rules below apply to both kinds.

- Each gate collects these lines apart from the strict projection
  (`crg_feedback_status` in the hook, `Get-CrgReviewFeedbackStatusLines` in
  the merge gate) and prints them as `review result:` lines. They are read
  from every launched review invocation, not only the accepted one: an
  exhausted leg, or a passing child of a panel whose provider was replaced,
  may still have written records or staged follow-ups. The follow-up
  promotion each gate runs itself (`docs/capture-doctrine-v6.md` section 7)
  is not a review invocation: its plain WARN and `housekeeping WARN: ` lines
  print directly on the console, pass or fail, and are not collected.
- Neither collecting nor printing them can fail a passed gate: a line that
  cannot be shown (over 4096 bytes without the tag, with a control character,
  or not in the form) becomes a fixed notice, an unreadable or missing
  transcript one notice, and more than 32 distinct warnings are counted on
  one line. The hook prints them straight to the console after every write
  the commit depends on (the projection display and the follow-up append),
  with no file of its own, so they take no space or step a required write
  needs; the merge gate's collector only reads, inside one guard. (Earlier
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
  reviewed, so these texts name `TASKS.md`, the Git directory, the logs
  folder, a setting, the shared follow-up index lock or Git's own messages,
  never a findings file, a verdict or a per-provider log folder, whose
  names carry the backend; detail that could (a path, an exception message)
  stays on a plain WARN line, which a failed gate shows. The collectors remove the
  tag naming the wrapper.
- The commit gate shows the last count line of the last accepted review,
  read after every leg added its tasks; the merge gate shows no child count
  line, since its own PASS line counts after all of them.

Counts come from one function, `Get-ReviewTaskCounts`: the main checkout
folder is held as in "File identity", and must still be the folder
confirmed when the review started, and `TASKS.md` opened no-follow; lines
end at CR LF, CR or LF; a UTF-8 byte-order mark at the start of the file is
ignored; a line counts when it begins with `- [ ] QUALITY ` or `- [ ] NOTE `;
there is no size or encoding limit, and the count reads through a fixed
64 KiB buffer, so memory does not grow with the file or any line. Only a
file positively absent counts
zero; a replaced checkout, a link, a non-file or a failed read shows
`could not be counted`. The
commit gate's own lines (`scripts/git-hooks/pre-commit`: per backend and
final), the paired session PASS (`scripts/paired-review-session.psm1`) and
the Grok adapter PASS (`scripts/grok/auto-review.ps1`) carry the coverage
wording only; the commit gate's counts are the projected review-feedback
line above. The hook does not count: a shell cannot hold the no-follow
handle a count needs, and a second counter there once disagreed with the
PowerShell one. Paired reviews run from captured inputs rather than the
working checkout and write no TASKS.md tasks.

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
- The carry-forward scan (section 2) also returns this change's rounds:
  same repository, working tree and HEAD, within the same window, newest
  20, with older ones counted toward the number of rounds only. A scan that
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
  in `CARRIED-FINDINGS.txt`, within the same per-finding and total size
  limits (counting the citation) and at most 100 shown, the rest counted on
  a `NOT SHOWN` line, then the record's blocks that name one of those
  findings and its approach line, rebuilt from the validated fields and
  quoted the same way; that part is bounded by the record's own 64 KiB,
  which the `\xNN` escaping can grow up to fourfold. The scope text lists
  the prior findings in a `PRIOR BLOCKERS` section. The prompt's
  change-propagation duty 6 has the reviewer apply the class sweep to each
  block's invariant across the whole diff, not only at the listed sites (a
  remaining in-diff instance is a finding at its own severity), and report
  a record that misstates the class, the sweep or a site as a `QUALITY:`
  finding under DOC-VS-CODE-DRIFT.
- Out of scope: merge reviews (each fix after a blocked merge is a new
  commit through the commit gate, where this check applies), paired reviews
  and the Grok adapter. The check holds an author to the discipline; it is
  not a security boundary, since the round files and the record are local
  files under the operator's control, like the commit itself.
