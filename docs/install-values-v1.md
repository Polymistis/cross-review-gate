# Project values v1

This document is the NORMATIVE contract for rendering project-owned review
context into the review prompt. Central review preparation
(`scripts/project-preparation.psm1`) implements this contract; runtime code
must not choose a different source, grammar, or marker.

Project values are resolved and rendered before a reviewer starts: central
review preparation renders the captured values into the prompt bytes of each
review without writing a file.

## 1. Fixed source and render surface

The values source is the project's root `CROSS-REVIEW-VALUES.md`. Central
review preparation receives the captured bytes of that file and opens no file
itself. A missing or invalid source refuses preparation.

The source defines exactly these blocks:

- `project-context`
- `project-hazards`
- `scoped-authority`

The fixed render map is:

| template | required slots |
|---|---|
| `scripts/codex/review-prompt-template.md` | `project-context`, `project-hazards`, `scoped-authority` |

No fourth value exists in v1.

## 2. Values-file byte grammar

`CROSS-REVIEW-VALUES.md` has this exact outer form, in this exact block order:

```markdown
cross-review-values v1
<!-- crg-install-value v1 project-context BEGIN -->
<project-context Markdown fragment>
<!-- crg-install-value v1 project-context END -->
<!-- crg-install-value v1 project-hazards BEGIN -->
<project-hazards Markdown fragment>
<!-- crg-install-value v1 project-hazards END -->
<!-- crg-install-value v1 scoped-authority BEGIN -->
<scoped-authority fragment>
<!-- crg-install-value v1 scoped-authority END -->
```

The header and marker lines are case-sensitive ASCII and occupy complete
records. Every record, including the final `END` marker, ends with one LF byte.
No bytes may occur before the header, between frames, or after the final LF.
Blank lines belong to a block body only; blank separator records outside a body
are invalid. Each block occurs exactly once. Blocks cannot nest.

The whole source must satisfy every following boundary before parsing:

- maximum encoded size: 262,144 bytes;
- strict UTF-8, without a BOM;
- LF record separators only; any CR byte is invalid;
- no NUL, no C0 control character other than horizontal tab and LF, and no
  DEL character;
- a final LF is mandatory.

Each block body is the exact byte range after the opening marker's LF and
through the LF immediately before the closing marker. Each body must contain
at least one character other than space, horizontal tab, or LF and may contain
at most 65,536 encoded bytes. No trimming, newline conversion, Unicode
normalization, case folding, or Markdown rewriting occurs. A body containing a
complete line beginning with `<!-- crg-install-value v1 ` or
`<!-- crg-render-slot v1 ` is invalid. Those namespaces are structural, never
project prose.

`project-context` and `project-hazards` are Markdown fragments placed beneath
fixed package headings. Package headings therefore do not belong in either
body. Semantic accuracy remains a project review duty; preparation validates
the byte and structural contract rather than inventing project facts.

`scoped-authority` has a narrower grammar. The body is either this exact
single record:

```markdown
- No authority documents. SCOPED capture is dormant.
```

or one or more records of this exact form:

```markdown
- `docs/deferred-scope.md`
- `docs/another-project-register.md`
```

Each non-sentinel record starts with an ASCII hyphen, one space, and a
backtick; each record ends with a backtick. The enclosed path is a non-empty
canonical repository-relative Git path: `/` separators,
no leading or trailing `/`, no empty, `.` or `..` segment, no backslash, no
backtick, and no control or DEL character. Paths compare with ordinal,
case-sensitive equality and cannot repeat. The sentinel cannot coexist with a
path record. This grammar declares only the authority set; stricter entry
schemas and field-pairing rules remain in each named authority document.

## 3. Template and slot grammar

The template uses these exact retained marker lines:

```markdown
<!-- crg-render-slot v1 project-context BEGIN -->
<!-- crg-render-slot v1 project-context END -->
<!-- crg-render-slot v1 project-hazards BEGIN -->
<!-- crg-render-slot v1 project-hazards END -->
<!-- crg-render-slot v1 scoped-authority BEGIN -->
<!-- crg-render-slot v1 scoped-authority END -->
```

Each required slot occurs exactly once in the target named by the render map.
An opening marker must precede the matching closing marker. Slots cannot nest
or overlap. An unknown block name, duplicate marker, orphan marker, or reversed
pair refuses. Marker matching is case-sensitive and line-exact.

Every template is validated before replacement under the same strict UTF-8,
no-BOM, LF-only, control-character, and final-LF rules as the values source. A
template and a rendered output may each contain at most 1,048,576 encoded
bytes.

Rendering replaces only the body between a slot's marker lines. Both marker
lines and every byte outside the slot remain byte-identical. The replacement
body is the corresponding values body byte-for-byte. In the review prompt,
that rendered project text cannot make content a change leaves as it was a
finding (the prompt's "Scope of a finding"), so retained project text that
asks for such findings has no effect on that content. Re-rendering the same
inputs therefore produces identical bytes. Preparation separately replaces the
document-role and code unit-test policy bodies under the conditions in
`docs/project-preparation-v1.md`; both bodies lie outside every slot.

After assembly, the output is reparsed. The output must retain the exact
required slot set, and every slot body must equal the selected value bytes.
Source-frame markers are forbidden in an output.
The complete output is also scanned with ordinal-ignore-case ASCII matching
for `REPLACE ME`, `REPLACE-ME`, and `REPLACE_ME`, with one or more ASCII space,
hyphen, or underscore characters between the two words. Any match is an
unresolved project placeholder and refuses. This separator family is the
exhaustive v1 definition of an equivalent project-placeholder spelling.

The package template carries valid cross-review-gate project content inside
every slot. Rendering replaces that stock slot body; stock content is not a
values fallback.
