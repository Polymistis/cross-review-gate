# Review feedback v1: the non-blocking findings notice and the PASS line

Audit source: a consumer project's corrective audit of 2026-10-07. It
found that NOTE findings were not kept anywhere a later session would see
them, that findings raised against a file were not shown to the next review
of that file, and that a gate PASS was being read as approval of target
behaviour or deployment. Section 3 answers the first: a review is for the
session that submitted the change, so its findings are shown to that
session and none is recorded as work for a later session. Section 2 says
why the second stays so, and section 4 covers the third. The review prompt's change-propagation
duties are separate and documented where they live.

## Scope

The paired review session (`scripts/paired-review-session.psm1`) and the
Grok adapter. The Grok adapter
prints only the coverage wording of
the PASS line below. The paired session prints that wording in its own PASS
line and then, for each passing attempt, a line naming the provider and the
verdict file, then that verdict's non-blocking findings through the notice
of section 3 (`Write-CrgPairNonBlockingFindings`), and then the task
reminder (section 4).

## 2. No carry-forward between reviews

Content a change leaves as it was is never the subject of a finding in its
review, apart from an unchanged line the change makes wrong, which is
reported at the changed line that causes it (operator rule, 2026-11-23; the
prompt's "Scope of a finding"). Project-supplied text rendered into the
prompt (project context and hazards) cannot make such content a finding, so
retained project text that asks for findings on unchanged content has no
effect. A passing review's
findings are not shown to any later review; section 3 shows them to the
session that submitted the change. An
earlier design carried passing reviews' QUALITY and NOTE findings into
every later review that touched a cited file: a `CARRIED-FINDINGS.txt`
evidence file, a `CARRIED FINDINGS` scope-text section, a prompt duty to
raise each one again while it still applied, and `carried` lines in the
findings files acknowledging the occurrences shown. It was removed (2026-11-23) because it put findings
about other commits, and about content the later change left untouched, in
front of reviewers, who then reported them against that change; do not
reintroduce it.

## 3. Non-blocking findings notice

A review is for the session that submitted the change. Only after every
review leg has passed does the paired review session show that session each
passing verdict's non-blocking findings (`Write-CrgPairNonBlockingFindings`,
which calls `Write-NonBlockingFindingsNotice`); when a later leg blocks or
fails, an earlier passing leg's findings stay in its verdict file and no
notice is printed. The review wrappers print no notice. The notice takes the
finding lines exactly as
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
   covers `TASKS.md` and `PLAN.md`
   (`Test-ReviewRecordCitationPath`);
3. `NOTE:` findings.

The opening citation is looked for after the label and only the white space
that awk's `[[:space:]]` matches in the C locale (space, tab, line feed,
vertical tab, form feed, carriage return). A finding whose text then opens
with any other white space, such as a no-break space, has no valid opening
citation and goes in group 1.

The session fixes the findings worth fixing as part of the current change.
Nothing records a finding as work for a later session: the gate writes no
task list, index or other hand-off. A finding the session does not act on
stays in the verdict file, and no later review is shown it (section 2).
The notice is console output
only.

Showing the findings is display only. When the notice fails, the
paired session writes a warning for that verdict, keeps its result and
goes on to the next verdict.

When a provider exhausts its allowance (exit 4) and a replacement review
passes, the findings of passes that completed before the exhaustion stay in
the exhausted run's verdict and forensics files, and that run prints no
notice. The replacement reviewed the same change in full, and its findings
are the ones shown.

Upgrading from before 2.8.0. By operator decision (2026-11-23), 2.8.0 keeps
no compatibility code for the follow-up index or review tasks of earlier
releases. A central installation is upgraded as a whole by activating the
release. A follow-up index (`<logs>/review-followups.md`) and
review task lines in `TASKS.md` left by an earlier release are not read,
protected or cleaned up by 2.8.0: delete them by hand. The 2.8.0 wrappers do not read `CROSS_REVIEW_PRUNE_TOOL` and never
delete review logs; delete old ones by hand.

## 4. PASS line

Every PASS line states what the review covers:

    ... PASS - covers this source diff only, not target execution or
    deployment readiness

A passing submission also prints one reminder line, with exactly this text
(`Get-ReviewTaskReminderText`):

    Reminder: once this change has landed, if it completes a task, delete that task from TASKS.md and every other task list. Task lists hold unfinished work only: a finished task is deleted, not checked off.

The paired review session prints it after its PASS, before central
publication commits the result or recovery finalizes the retained result.
It is printed before the change has landed, so the text itself makes
landing the condition for deleting a task. The review wrappers do not print
it. A reminder that cannot be printed never fails the run: the paired
session reports that on standard error.

The paired session PASS (`scripts/paired-review-session.psm1`) and the Grok
adapter PASS (`scripts/grok/auto-review.ps1`) carry the coverage wording
only.
