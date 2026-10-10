# Project preparation v1

Status: bounded central-only compiler, 2026-09-06. This contract depends on
`private-governance-v1.md` and `paired-review-input-v1.md`. Compilation prepares
bytes, not approval, Git identity, provider authorization, or publication custody.
No instruction file, installed runtime, index, ref, or consumer is changed.

## Inputs and API

`scripts/project-preparation.psm1` exports:

```text
New-CrgProjectPreparationBytes -Kind governing|candidate -RuntimeSha256 <sha256>
  -ConfigBytes <byte[]> -ValuesBytes <byte[]> -ModePresent <bool>
  -ModeBytes <byte[]> -TemplateBytes <byte[]>
Read-CrgProjectPreparationBytes -Bytes <byte[]> -ExpectedKind governing|candidate
  -ExpectedRuntimeSha256 <sha256> -TemplateBytes <byte[]>
New-CrgPairedModeBlockBytes -GoverningBytes <byte[]> -CandidateBytes <byte[]>
  -ExpectedRuntimeSha256 <sha256> -TemplateBytes <byte[]> -GoverningRef <private-oid>
```

Every argument is explicit and required. ModeBytes is an empty byte array only
for positive absence or a present empty file; ModePresent distinguishes those
states. A present null buffer refuses. Kind and runtime identity never come from
ambient variables, current private HEAD, or an untrusted preparation header.
The reader requires the independently selected kind/runtime/template, reparses
all source bytes, recompiles derived outputs, and compares exact bytes.

The constructor returns one canonical byte array. The reader returns Kind,
RuntimeSha256, PreparationSha256, ConfigSha256, ValuesSha256, ModeSha256,
TemplateSha256, RolesSha256, PromptSha256, ConfigBytes, ValuesBytes, ModeBytes,
RolesBytes, PromptBytes, Config, Values, ModePresent, ModeState, and Mode.
Mode is the existing parsed declaration result when present, otherwise null.
Returned buffers are copies, not a capability or a promise that caller-owned
arrays cannot subsequently be modified; custody remains the coordinator's duty.

Load the verified central `private-governance.psm1` and
`review-preparation.psm1` modules first. The compiler uses the already-loaded
Read-CrgProjectConfigBytes and ConvertFrom-ProjectModeDeclaration exports;
missing/ambiguous dependencies refuse without ambient module discovery.
The caller binds exact template bytes to the retained runtime manifest and
config/values/mode bytes to the selected private tree before compilation.

## Exact preparation encoding

All header lines are ASCII with exactly one space between tokens, LF only, no
BOM, and canonical lowercase hex digests. The complete buffer is at most
20,971,520 bytes. Fixed header records, in this exact order:

```text
crg-project-preparation v1
kind <governing-or-candidate>
runtime-sha256 <sha256>
config-sha256 <sha256>
values-sha256 <sha256>
mode-state <absent-or-valid-or-fallback>
mode-sha256 <sha256-or-dash>
template-sha256 <sha256>
roles-sha256 <sha256>
prompt-sha256 <sha256>
```

Each SHA-256 is exactly 64 lowercase hexadecimal characters and hashes the
exact named raw bytes. Dash is permitted only for positively absent mode.
The template digest covers the independently supplied retained runtime template,
not the rendered prompt. Five frames follow, in order: config, values, mode,
roles, prompt. Each frame consists of this ASCII/LF prefix immediately followed
by the declared number of raw bytes:

```text
bytes <frame-name> <length>
```

Length is `0` or a nonzero decimal without leading zeroes, at most eight digits.
No separator or padding follows a body: the next frame prefix starts at the
exact byte offset after that body. EOF follows the prompt body. Unknown,
duplicate, reordered, truncated, oversized, or trailing records refuse.
Raw mode bytes may contain malformed text; framing never interprets those bytes
as record syntax. Config/values/template retain the existing strict text grammar.

| Buffer | Maximum bytes |
|---|---:|
| config | 65,536 |
| values | 262,144 |
| mode capture | 16,777,216 |
| runtime template / rendered prompt | 1,048,576 each |
| rendered roles | 262,144 |

Config and values must parse completely. ModePresent=false requires zero mode
bytes and produces mode-state absent, with shipped semantics. Present bytes use
the existing declaration parser: success produces valid; positive malformation,
including a present empty or greater-than-8-KiB declaration, produces fallback.
Capture above 16 MiB refuses; missing/read-failed acquisition also refuses.
Neither condition invents absence or a successful fallback acquisition.
Candidate mode diagnostics remain evidence and do not select governing rules.

## Deterministic values and document roles

The compiler contains the renderer's marked byte-only values core as source.
Marked copies must remain byte-identical by source inspection. Code unit-test
authoring/execution is banned by operator decision; live testing, manual checks,
ordinary program runs, and functional validation remain permitted.
The accepted PowerShell compatibility repair lands alongside this compiler:
SCOPED path splitting uses unlimited count 0 in every copy, preserving intended
grammar on PowerShell 5.1 and 7. The renderer's Git/state record splits receive
the same previously verified correction; no scratch-custody execution is claimed.
No renderer is imported/executed and no runtime source/AST extraction occurs.
Existing three-block values grammar, byte bounds, placeholder rejection, and
exact replacement of the three prompt values bodies are otherwise unchanged.

RolesBytes is strict UTF-8 without BOM, with final LF:

```text
crg-project-roles v1
role <canonical-path> | <description>
```

Zero or more role records retain parsed configuration order and exact path/text.
The supplied template contains exactly one ordered nonnested pair of standalone
`<!-- crg-document-role-policy v1 BEGIN -->` / `END` comments around the complete
stock role-collision body. These comments are not install-values/render slots.

With zero roles the stock body remains byte-identical. With explicit roles the
complete marked body is replaced by fixed diff-anchored collision instructions
and the configured role records. The stock sole-owner table and unconditional
second-package/receipt/history restrictions do not remain alongside conflicting
configured ownership. Configured descriptions define document ownership only;
no role can alter independent review, severity, output grammar, or capture duties.
QUALITY classification and diff-only scope remain fixed. Bytes outside the three
existing values bodies, the role-policy body and the unit-test policy body remain
unchanged.

From 2.5.0 the template also carries one ordered nonnested pair of standalone
`<!-- crg-unit-test-policy v1 BEGIN -->` / `END` comments around the complete
stock code unit-test ban, outside every values slot and the role-policy body;
every other template statement about code unit tests defers to that policy.
The boundaries are validated in the supplied template before any replacement
and again in the compiled output. The compiler derives the permitted scope from the parsed configuration's
`unit-tests` records and the same preparation's mode (`Get-CrgUnitTestScope`,
[private governance](private-governance-v1.md)). With no scope in effect, the
stock body and every other byte remain unchanged, and a template without the
boundaries is accepted. With a scope in effect, the complete marked body is
replaced by fixed text naming the scope (anywhere, for an effective prototype
allowance; otherwise the configured folders) and keeping the stock rules outside
it, and a template without the boundaries refuses. The paired PROJECT-MODE
block's `pm-authority` line then defers to that policy instead of stating the
every-mode ban; the legacy wrappers' copies of that block serve installs without
project configuration and keep the ban.

The caller proves role-document presence, original domain, and regular blob shape
from pinned combined context. Pure compilation cannot authenticate that inventory.
No fourth values block, general template engine, or per-project runtime patch exists.

## Integration and verification boundary

Compile governing and candidate states separately. Only preceding approved
governing preparation supplies the current trusted prompt/configuration/mode;
candidate preparation is separately hashed proposal data. The paired descriptor
binds the exact two buffers through the review-unit identity. The paired-mode
constructor reparses both preparations and uses the existing mode formatter.
GoverningRef is the concrete private parent OID. Candidate diagnostics appear
only when captured mode presence or bytes differ: deleted, valid with mode, or
invalid with the existing grammar reason/anchor. Output is exact UTF-8 without
BOM or an added final newline, matching the existing formatter. No live Git or
name-status lookup can change the supplied preparation.
Persisted preparation bytes never supply historical PASS or publication authority.

Focused in-memory checks use identical buffers on PowerShell 5.1 and 7: valid
round-trip, role replacement versus stock preservation, positive mode absence/
malformation, wrong required bindings, and exact-byte tamper refusal. No new
tracked suite, provider invocation, renderer custody execution, or consumer
mutation is part of this compiler unit.

Verification on 2026-09-06, integration worktree based on `02afe35` plus this
candidate: `powershell -NoProfile -ExecutionPolicy Bypass -File
logs/shared-core-check.ps1` and the equivalent verified `pwsh -NoProfile -File`
invocation both exited 0. The existing bootstrap byte-only fixture passed source
and rendering parity for all copies; no executable renderer or renderer SelfTest
was loaded. Compiler and paired-input focused checks also exited 0 on PowerShell
5.1.26100.9168 and 7.6.5. Compiler source SHA256 at verification:
`7ff138c722039dde934d96d9144b07531fd1b34b56c7d16c60bca74006207ad2`.
This is bounded verification evidence, not a full bootstrap-suite claim.
