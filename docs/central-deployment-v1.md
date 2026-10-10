# Central deployment v1

This is the operator procedure for the Windows central runtime and privately
tracked project governance. Source integration is not a release or deployment
record. Actual source OID, manifest ID, archive/bootstrap hashes, review evidence
and consumer results must be recorded by the release operation; no example below
supplies an approval or fabricated release identity.

One activation updates every attached project's next invocation. Existing
invocations retain the selected release through completion. Routine compatible
upgrades retain launcher ABI 2 and project configuration schema 1, with no
per-project release pin, copied runtime update or configuration rewrite.
Existing ABI 1 stores require one explicit store-wide launcher migration before
activating ABI 2; fresh stores install ABI 2 directly.

## Prerequisites and input approval

Use Windows PowerShell 5.1 (included with Windows), Git for Windows, and the
configured reviewer CLIs. The Claude route requires Claude Code 2.1.248 or later;
its `opus` alias selects Opus 5.5 only from Claude Code 2.1.280.
Mandatory review and automatic positive-exhaustion fallback remain active; no
manual reviewer-suppression flag is part of this procedure. Installing or
attaching a project supplies no new provider or data-transmission authorization.
An attachment using `reviewer-policy default` does not enable xAI.
Code unit tests remain banned. Live testing, manual checks, ordinary program
runs, and functional validation remain permitted and important alongside builds
and review.

Choose an ordinary absolute machine-local store outside source repositories,
project Git metadata and extracted release input. The store's parent must exist.
The approved bootstrap is an independently trusted operator executable, not a
script executed merely because an imported manifest mentions an archive.

The following PowerShell variable is operator input, not an environment switch:

```powershell
$CrgStore = Read-Host 'Absolute machine-local central runtime store'
```

Run either source publication or package import, not both for the same input.
Publication/import does not activate a release or change a consumer.

## Prepare the operator session

Trust boundary: the operator account and session, SYSTEM and the Administrators
group are trusted. The procedure defends its inputs against substitution by
every other account and against accidental replacement. Code already running as
a trusted principal could equally rewrite the runtime store or launcher after
installation; no installation procedure prevents that.

Within that boundary, the object a check approves is the object later used:

- All work happens in a private directory directly under the system drive
  root, which cannot be renamed. One operating-system call creates the
  directory new (refusing any existing occupant), applies an access list
  granting only the trusted principals, and returns a handle held without delete
  sharing until `Close-CrgPrivateWork`. No other account can therefore open,
  write or map anything in the directory, or rename or replace it at any point,
  whatever rights that account holds on the drive root, and a later command
  naming its path reaches the same directory. A user-profile location is not
  used: its folders can be renamed by sandbox groups that hold rights across a
  user profile.
- A file the procedure did not create can still change through a writable
  memory mapping opened before any check. Every such input (the transferred
  archive, or a source bootstrap) is therefore copied into the private
  directory, and only the copy is hashed and used, including the bootstrap that
  runs.
- `bootstrap.ps1` refuses inherited Git selector variables, so they are cleared
  before the first bootstrap command.
- Before approval, the only resource consumed is the bounded input copy: the
  archive up to the runtime manifest's 256 MiB payload limit plus 32 MiB for
  operator documents and archive structure, a source bootstrap up to 16 MiB.
- In the preparation, publication, import, launcher and activation blocks,
  every error stops the procedure: a PowerShell error through
  `$ErrorActionPreference = 'Stop'`, and a failed bootstrap command through the
  exit-code check after it. Outside those blocks, a native command with no
  exit-code check after it (Git and the launcher's project operations)
  reports failure only by its output and exit code. Run
  `Close-CrgPrivateWork` after the last bootstrap command or after a failure; ending the PowerShell session also
  releases the directories. Private directories remain afterwards; send them to
  the Recycle Bin when no longer needed.

Run this block once per Windows PowerShell 5.1 session, before publication or
import:

```powershell
$ErrorActionPreference = 'Stop'
# The named set is what bootstrap.ps1 refuses. The numbered pairs are inert once
# GIT_CONFIG_COUNT is cleared; removing them keeps later native Git commands in
# this session on the operator's ordinary configuration.
$CrgGitSelectors = @('GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM',
  'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE',
  'GIT_COMMON_DIR', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_NAMESPACE',
  'GIT_REFERENCE_BACKEND', 'GIT_ATTR_SOURCE', 'GIT_ATTR_NOSYSTEM', 'GIT_REPLACE_REF_BASE',
  'GIT_GRAFT_FILE', 'GIT_SHALLOW_FILE')
# Names match without letter case, as Windows does, but ordinally: -in and -match
# compare by culture, which ignores U+00AD and folds U+212A onto K, and would
# clear a variable that is not a selector.
$CrgIsGitSelector = {
  param([string]$Name)
  if ([Linq.Enumerable]::Contains([string[]]$CrgGitSelectors, $Name, [StringComparer]::OrdinalIgnoreCase)) { return $true }
  foreach ($CrgPrefix in @('GIT_CONFIG_KEY_', 'GIT_CONFIG_VALUE_')) {
    if ($Name.StartsWith($CrgPrefix, [StringComparison]::OrdinalIgnoreCase) -and $Name.Substring($CrgPrefix.Length) -cmatch '\A[0-9]+\z') { return $true }
  }
  return $false
}
foreach ($CrgName in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
  if (& $CrgIsGitSelector $CrgName) { [Environment]::SetEnvironmentVariable($CrgName, $null, 'Process') }
}
$CrgLeft = @(@([Environment]::GetEnvironmentVariables('Process').Keys) | Where-Object { & $CrgIsGitSelector $_ })
if ($CrgLeft.Count -gt 0) { throw "Git selector environment variables remain set: $($CrgLeft -join ', ')" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
if (-not ('CrgPrivateDirectory' -as [type])) {
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class CrgPrivateDirectory {
  [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public int Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Descriptor, Qos; }
  [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status, Information; }
  [DllImport("ntdll.dll")] static extern int NtCreateFile(out IntPtr handle, uint access, ref ObjectAttributes attributes, out IoStatus status, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
  [DllImport("ntdll.dll")] static extern int RtlNtStatusToDosError(int status);
  // Creating, protecting and holding must be one call: separate steps leave a
  // gap in which another directory can take the name. Create-new refuses any
  // existing occupant, link or not. List access makes the share mode binding
  // (attribute-only opens skip share checks); read and write sharing without
  // delete sharing blocks rename and delete while the handle is held.
  public static SafeFileHandle Create(string path, byte[] descriptor) {
    string name = @"\??\" + path;
    IntPtr text = Marshal.StringToHGlobalUni(name), unicode = IntPtr.Zero, security = IntPtr.Zero;
    try {
      UnicodeString value = new UnicodeString(); value.Length = (ushort)(name.Length * 2); value.MaximumLength = value.Length; value.Buffer = text;
      unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString))); Marshal.StructureToPtr(value, unicode, false);
      security = Marshal.AllocHGlobal(descriptor.Length); Marshal.Copy(descriptor, 0, security, descriptor.Length);
      ObjectAttributes attributes = new ObjectAttributes(); attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
      attributes.Name = unicode; attributes.Attributes = 0x40; attributes.Descriptor = security;
      IntPtr raw; IoStatus io;
      int status = NtCreateFile(out raw, 0x001000A1, ref attributes, out io, IntPtr.Zero, 0, 3, 2, 0x21, IntPtr.Zero, 0);
      if (status < 0) throw new IOException("cannot create private directory " + path + " (Windows error " + RtlNtStatusToDosError(status) + ")");
      return new SafeFileHandle(raw, true);
    } finally {
      Marshal.FreeHGlobal(text);
      if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode);
      if (security != IntPtr.Zero) Marshal.FreeHGlobal(security);
    }
  }
}
'@
}
$CrgTrusted = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
$CrgDriveRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$CrgHolds = New-Object 'System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]'
function Close-CrgPrivateWork { foreach ($CrgHold in $CrgHolds) { $CrgHold.Dispose() }; $CrgHolds.Clear() }
function New-CrgPrivateWork {
  param([string]$Purpose)
  $CrgPath = Join-Path $CrgDriveRoot ('crg-' + $Purpose + '-' + [Guid]::NewGuid().ToString('N'))
  $CrgSecurity = New-Object Security.AccessControl.DirectorySecurity
  $CrgSecurity.SetSecurityDescriptorSddlForm('D:P' + (($CrgTrusted | ForEach-Object { "(A;OICI;FA;;;$_)" }) -join ''))
  $CrgHolds.Add([CrgPrivateDirectory]::Create($CrgPath, $CrgSecurity.GetSecurityDescriptorBinaryForm()))
  Write-Host "Private $Purpose directory: $CrgPath"
  return $CrgPath
}
# Copies exactly the length observed at open, so an input that grows or shrinks
# during the copy is refused rather than captured partially.
function Copy-CrgIntoPrivate {
  param([string]$Source, [string]$Destination, [long]$Limit)
  if ($Source -cnotmatch '\A([A-Za-z]:\\|\\\\[^\\])') { throw "Not an absolute path: $Source" }
  $CrgInput = [IO.File]::Open($Source, 'Open', 'Read', 'ReadWrite')
  try {
    $CrgRemaining = $CrgInput.Length
    if ($CrgRemaining -le 0 -or $CrgRemaining -gt $Limit) { throw "$Source is empty or larger than $Limit bytes" }
    $CrgCopy = [IO.File]::Open($Destination, 'CreateNew', 'Write', 'None')
    try {
      $CrgBuffer = New-Object byte[] 1048576
      while ($CrgRemaining -gt 0) {
        $CrgRead = $CrgInput.Read($CrgBuffer, 0, [int][Math]::Min($CrgBuffer.Length, $CrgRemaining))
        if ($CrgRead -le 0) { throw "$Source shrank while being copied" }
        $CrgCopy.Write($CrgBuffer, 0, $CrgRead)
        $CrgRemaining -= $CrgRead
      }
      if ($CrgInput.Read($CrgBuffer, 0, 1) -ne 0) { throw "$Source grew while being copied" }
    } finally { $CrgCopy.Dispose() }
  } finally { $CrgInput.Dispose() }
}
function Get-CrgFileSha256 { param([string]$Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
```

## Publish a normally reviewed source revision

The source must be an actual Git worktree rooted at `CrgSource`, with HEAD equal
to the full source OID from the completed normal source review/landing record.
Every shipped payload must match that revision; uncommitted or untracked payloads
cannot be published as reviewed content.

```powershell
$CrgBootstrapSource = Read-Host 'Absolute path to the approved source bootstrap.ps1'
$CrgApprovedBootstrapSha256 = Read-Host 'Approved bootstrap SHA256 from the release record'
$CrgSource = Read-Host 'Absolute root of the reviewed cross-review-gate source worktree'
$CrgApprovedSource = Read-Host 'Full approved source commit OID'
if ($CrgApprovedBootstrapSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Approved bootstrap SHA256 must be 64 lowercase hexadecimal digits' }
$CrgBootstrap = Join-Path (New-CrgPrivateWork 'publish') 'bootstrap.ps1'
Copy-CrgIntoPrivate $CrgBootstrapSource $CrgBootstrap 16777216
if (-not [string]::Equals((Get-CrgFileSha256 $CrgBootstrap), $CrgApprovedBootstrapSha256, [StringComparison]::Ordinal)) { throw 'Bootstrap approval/hash mismatch' }
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -PublishRuntime -RuntimeStore $CrgStore -SourceRoot $CrgSource -ApprovedSourceCommit $CrgApprovedSource
if ($LASTEXITCODE -ne 0) { throw 'Central source publication failed; no activation requested' }
$CrgReleaseId = Read-Host 'Exact 64-character release ID reported by successful publication'
```

Publication reports release ID, version and source OID. The release ID is the
SHA-256 of the complete `runtime-manifest`, not the source OID or version string.
The published directory is `releases/<release-id>` inside the store. Existing
matching releases are revalidated; conflicting contents are preserved and refused.

## Import a portable package without source Git metadata

The portable archive separates executable bootstrap approval from release data:

```text
extracted-package/
  bootstrap.ps1                separately approved operator bootstrap
  INSTALL.md                   operator documentation, outside release data
  docs/...                     the operator documents listed below
  release/
    runtime-manifest
    VERSION
    scripts/...                exactly the manifest inventory
    docs/...                   exactly the manifest inventory
```

The release producer copies the already published release bytes without changing
encoding or inventory. `release/` contains no extra bootstrap, archive, source
`.git`, project values/configuration, review logs, private repository or credentials.
Operator documentation remains outside `release/`. A legacy ZIP without the
approved runtime manifest is not a central package.

Outside `release/` the archive carries exactly `bootstrap.ps1`, `INSTALL.md`
and these operator documents from the source commit's `docs/`:
`AGENTS.md.template`, `audit-protocol.md`, `capture-doctrine-v6.md`,
`central-deployment-v1.md`, `central-guards-v1.md`,
`central-instructions-v1.md`, `central-launcher-v1.md`,
`central-publication-v1.md`, `central-runtime-v1.md`,
`first-attachment-v1.md`, `install-values-v1.md`, `local-install-v1.md`,
`paired-git-capture-v1.md`, `paired-git-operation-v1.md`,
`paired-retention-v1.md`, `paired-review-input-v1.md`,
`private-governance-v1.md`, `project-mode-doctrine-v1.md`,
`project-preparation-v1.md`, `review-feedback-v1.md`,
`reviewer-liveness-design.md` and `v2.2-grok-reviewer-design.md`. The list is explicit because following links
cannot tell operator documents from development records: the contracts cite
plans, registers and audits by path. The gate source's own `AGENTS.md` and
`CLAUDE.md`, earlier release records under `deploy/`, and the development
records in `docs/` (plans, audits, investigations, the debt and scope
registers, migration contracts, incident notes and session guidance) are not
packaged. A new operator document ships only once it is added to this list.

Obtain archive, bootstrap and manifest hashes from the approved release record
through the established distribution channel. A digest read only from the
untrusted archive does not establish approval. Supply the values:

```powershell
$CrgArchive = Read-Host 'Absolute path to the transferred portable archive'
$CrgApprovedArchiveSha256 = Read-Host 'Approved archive SHA256 from the release record'
$CrgApprovedBootstrapSha256 = Read-Host 'Approved bootstrap SHA256 from the release record'
$CrgApprovedManifestSha256 = Read-Host 'Approved runtime-manifest SHA256 from the release record'
```

Then copy, verify, extract and import. Release deployment guides carry this
block unchanged, with the values above given as literals:

```powershell
foreach ($CrgApproved in @($CrgApprovedArchiveSha256, $CrgApprovedBootstrapSha256, $CrgApprovedManifestSha256)) {
  if ($CrgApproved -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Each approved SHA256 must be 64 lowercase hexadecimal digits' }
}
$CrgImport = New-CrgPrivateWork 'import'
$CrgArchiveCopy = Join-Path $CrgImport 'package.zip'
Copy-CrgIntoPrivate $CrgArchive $CrgArchiveCopy 301989888
if (-not [string]::Equals((Get-CrgFileSha256 $CrgArchiveCopy), $CrgApprovedArchiveSha256, [StringComparison]::Ordinal)) { throw 'Archive approval/hash mismatch' }
$CrgPackage = Join-Path $CrgImport 'package'
[IO.Compression.ZipFile]::ExtractToDirectory($CrgArchiveCopy, $CrgPackage)
$CrgBootstrap = Join-Path $CrgPackage 'bootstrap.ps1'
if (-not [string]::Equals((Get-CrgFileSha256 $CrgBootstrap), $CrgApprovedBootstrapSha256, [StringComparison]::Ordinal)) { throw 'Bootstrap approval/hash mismatch' }
$CrgReleasePackage = Join-Path $CrgPackage 'release'
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -PublishRuntime -RuntimeStore $CrgStore -ReleasePackage $CrgReleasePackage -ApprovedManifestSha256 $CrgApprovedManifestSha256
if ($LASTEXITCODE -ne 0) { throw 'Central package import failed; no activation requested' }
$CrgReleaseId = $CrgApprovedManifestSha256
```

Extraction uses .NET `ZipFile.ExtractToDirectory`, which refuses any entry that
would land outside the package directory or on a file already extracted, so
escaping entries and duplicate or case-colliding file entries stop
extraction; repeated or differently cased directory entries reuse the
directory already created. ZIP link
metadata is not interpreted: every file entry becomes an ordinary file. The
exact parameter is `-ReleasePackage`, naming the extracted `release/`
directory, not a ZIP or the outer package directory. Import verifies every
manifest-owned byte and retains the approved source provenance without
requiring a source clone. No release payload is executed to establish package
approval.

## Install the stable launcher once, then activate

Run these commands in the same session, after the publication or import block
and before `Close-CrgPrivateWork`, so `$CrgBootstrap` names its verified
private copy in a still-held directory. For a new store, install from the
successfully published/imported release:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -InstallRuntimeLauncher -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Stable launcher installation failed; no activation requested' }
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -ActivateRuntime -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Central activation failed' }
$CrgLauncher = Join-Path $CrgStore 'launcher.ps1'
```

Existing differing launcher bytes are refused by `-InstallRuntimeLauncher`.
Routine compatible upgrades only publish/import and activate; do not reinstall
the stable launcher from every release. Retain the launcher-origin releases and all
releases required by interrupted operations. Lock contention is not permission
to delete a lock file, change hook routing or bypass review.

For an existing ABI 1 store only, import the approved ABI 2 release, let current
invocations finish, then run the explicit migration before activation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -UpgradeRuntimeLauncher -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Launcher ABI migration incomplete; preserve the recorded transition' }
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -ActivateRuntime -RuntimeStore $CrgStore -ReleaseId $CrgReleaseId
if ($LASTEXITCODE -ne 0) { throw 'ABI 2 activation failed' }
```

After the last bootstrap command, release the private directories:

```powershell
Close-CrgPrivateWork
```

Migration preserves the predecessor release/hash in `launcher-install` and the
bounded `launcher-upgrade` recovery record. An interrupted migration resumes only
through the same command and target release; differing occupants are not replaced.
Activation checks actual installed-loader provenance and refuses an ABI mismatch
or incomplete pair. Project configuration, hooks and private history do not change.
The ABI 2 launcher retains ABI 1/2 manifest support for recorded-runtime recovery
and compatible rollback; keep the original releases required by pending work.

## Prepare the first project attachment

Select the exact public worktree root and inspect current status. The initial
deployment record must confirm the actual branch, clean software candidate, and
existing project declaration before attachment. No second consumer mutation
follows from this procedure unless separately requested.

```powershell
$CrgRepo = Read-Host 'Absolute public project worktree root'
git -C $CrgRepo status --short --branch
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Status
```

Finish unrelated staged software work before Attach. Inventory and preserve
existing public/private history, indexes, working edits and hooks. New private
history defaults to the actual public common directory's `crg-governance.git`.
An existing private database requires explicit adoption, never a reset or silent
replacement. Legacy TRACKED payload retirement requires its reviewed provenance
migration; old LOCAL files and recovery evidence are preserved. Do not delete
legacy hooks, set `core.hooksPath`, or manually manufacture `crg-*` records.

Before Attach, prepare these ordinary project files with an editor or the normal
agent editing workflow. Existing project content must be preserved and reviewed:

- `.crg-project/project.conf`: strict UTF-8 without BOM, LF-only, final LF.
- `CROSS-REVIEW-VALUES.md`: actual project context, hazards and SCOPED authority
  using the existing three-block [values contract](install-values-v1.md).
- `AGENTS.md` and `CLAUDE.md`: existing project instructions, the same canonical
  central discovery section below, and the persistent code-unit-tests-banned
  directive that keeps live testing, manual checks, ordinary program runs, and
  functional validation permitted.
- Private `PLAN.md` and `History.md`: actual project requirements/work history,
  with roles in configuration. Different private paths require matching roles
  and discovery records, not duplicate placeholder documents.
- `PROJECT-MODE.md`: preserve the valid prototype declaration and actual campaign.
  For a missing declaration, author `project-mode: v1`, `mode: prototype`, and an
  actual nonempty `campaign:` using the [mode grammar](project-mode-doctrine-v1.md).

A project using the root plan/history paths starts with this configuration;
additional private directories/files must reflect actual project ownership:

```text
crg-project v1
reviewer-policy default
consistency-document private PLAN.md
private-directory .crg-project
private-file AGENTS.md
private-file CLAUDE.md
private-file CROSS-REVIEW-VALUES.md
private-file History.md
private-file PLAN.md
private-file PROJECT-MODE.md
role History.md | Private work history and document discovery
role PLAN.md | Project requirements and acceptance
```

The consistency document is privately tracked, not required in public software
history. `consistency-document -` disables only plan preprocessing when explicitly
selected; mandatory combined review still runs. Project mode controls review
treatment, never permission to work. Candidate prototype mode receives initial
review under release-owned bootstrap governance and governs subsequent pairs.

Insert this exact discovery section into both root instruction files. Replace
`C:\CrossReviewGate` with the actual `CrgStore` path and replace both private
document paths only when configuration and existing files use those paths.
Use LF line endings and preserve a final LF after the closing marker:

```text
<!-- crg-central-discovery v1 BEGIN -->
## Central cross-review gate
Runtime launcher: C:\CrossReviewGate\launcher.ps1
Project configuration: .crg-project/project.conf
Private plan: PLAN.md
Private history: History.md

Use the central launcher for Open, Stage, Commit and Resume with the explicit
TargetRepo. Commit also requires MessageFile and AuthoringAgent. This workflow
supersedes legacy per-project gate commands. Public software and local private
governance receive mandatory combined review; native commits do not substitute.
Project mode describes review treatment, not permission to work. Provider
exhaustion fallback stays automatic within the gate; no session skip flag exists.
<!-- crg-central-discovery v1 END -->
```

Prepare a real nonempty UTF-8 commit message at `.crg-project/message.txt` inside
the project. The private directory keeps that work material out of public staging.
Run one of these attachment forms:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Attach -MessageFile '.crg-project/message.txt' -AuthoringAgent codex
```

For explicit existing private-database adoption, use this form instead:

```powershell
$CrgPrivateDb = Read-Host 'Absolute existing private Git database to adopt without resetting'
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Attach -PrivateGitDir $CrgPrivateDb -MessageFile '.crg-project/message.txt' -AuthoringAgent codex
```

Use `-AuthoringAgent claude` when Claude authored the candidate. The author value
does not choose the reviewer. Initial migration captures classified private
files, moves only approved private paths out of the public candidate, preserves
working files/staged adoption state, and performs a complete first review before
activating the association. Existing public history is not rewritten. Any
previously published governance requires a separate explicit history decision.

Recognized stock Git LFS wrappers are supported: post-checkout,
post-commit and post-merge remain unchanged; pre-push runs paired-history checks
before the retained LFS transfer using the original arguments/stdin. The actual
target's LFS patterns remain project-owned. Because `commit-tree` does not execute
Git's hook dispatcher, Attach and later publication invoke the retained stock
`git-lfs.exe post-commit` after a changed public ref reaches the reviewed result
and before completion becomes visible. Interrupted Resume repeats that owned
invocation from the retained receipt. Ordinary effective attribute and config
sources remain available to stock LFS behavior. Custom or incomplete hook
compositions require explicit preservation work.

## Ordinary work and interrupted publication

After successful Attach, confirm actual attachment and governing mode with Open:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Open
```

Edit software/private documents normally, prepare the actual commit message, then
use the same launcher for both domains. `-All` stages the complete intended pair:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Stage -All
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Commit -MessageFile '.crg-project/message.txt' -AuthoringAgent codex
```

For a bounded path selection, use `-Stage -Paths` with actual repository-relative
paths instead of `-All`; no public/private index is supplied by the caller.
Native `git commit` is refused for both domains. Normal public pushes invoke the
installed pre-push guard; private content and completed-pair enforcement are not
optional. No push is required merely to install or confirm the gate.

When Status reports a pending handoff, preserve the indexes and recorded message:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgLauncher -TargetRepo $CrgRepo -Resume
```

Resume revalidates the recorded input and runs a fresh complete review under the
retained original release before finishing only the recorded publication. No
reset, saved-PASS replay, source-runtime fallback or bypass flag is appropriate.
Before a durable handoff exists, preserve the pending proposal, private database
and both indexes. Correct only explicitly named private candidate paths with the
existing launcher ABI; directory selections retain normal Stage expansion:

```powershell
& $CrgLauncher -TargetRepo $CrgRepo -Stage -Paths @('AGENTS.md', 'CLAUDE.md')
```

Pending attachment staging refuses `-All`, public selections, missing or conflicting
proposal custody, incomplete initialization records and namespace changes. The
operation accepts independent supported public/private object formats only for a
record-free adopted database. If failed migration left no staged private project
configuration, include `.crg-project/project.conf` explicitly with the correction;
all preserved private entries must remain private under that validated configuration.
The operation does not review or activate the association. After correction, repeat
the same Attach command to perform full migration and mandatory first review.

If a first attachment published both result refs but did not activate, and a
later review requires a root-instruction correction, an approved runtime with
published instruction correction support can accept the same explicit
`Stage -Paths @('AGENTS.md', 'CLAUDE.md')` form followed by Attach. Select only
instruction files that need correction. The gate requires the exact pending
proposal and first-origin handoff, absent active attachment/completed pointer,
unchanged public content and unchanged other private entries. No mode, reviewer
configuration, values, software, deletion or general directory edit is admitted.
Failed correction review preserves the original handoff and published refs;
restaging a further root-instruction correction remains supported. Fresh review
and new immutable retention precede handoff replacement and activation. Ordinary
Resume remains the route for finishing an unchanged recorded transaction and
continues to reject indexes that differ from that transaction.

## Upgrade and rollback

Publish/import the next approved compatible release, then run the same
`-ActivateRuntime` command once. Unchanged project configuration and hooks require
no individual upgrade. Rollback selects an explicitly approved retained compatible
release through that same operation. Run it in a session where the publication
or import block left `$CrgBootstrap` naming a verified private bootstrap copy
whose directory is still held:

```powershell
$CrgRollbackReleaseId = Read-Host 'Approved retained compatible rollback release ID'
powershell -NoProfile -ExecutionPolicy Bypass -File $CrgBootstrap -ActivateRuntime -RuntimeStore $CrgStore -ReleaseId $CrgRollbackReleaseId
if ($LASTEXITCODE -ne 0) { throw 'Central rollback activation failed' }
Close-CrgPrivateWork
```

Rollback changes the next invocation's runtime, not project commits, private
history, configuration or already captured in-flight operations. A missing,
malformed or conflicting selector is not permission to guess the newest directory.

## Transfer private work separately from software and the runtime

A runtime package contains no project history. A normal public clone contains no
private governance database, paired receipts, working documents or association
metadata. Private transfers require a separate authorized private destination;
never add a private bundle/database to public software or configure public object
alternates pointing at private objects.

With project operations quiescent, a private history bundle can preserve every
private Git ref, including `refs/crg-pairs/*`, and the reachable objects:

```powershell
$CrgPrivateDb = Read-Host 'Absolute private Git database from the validated project association'
$CrgPrivateBundle = Read-Host 'New absolute private backup bundle path outside all public repositories'
git --git-dir=$CrgPrivateDb bundle create $CrgPrivateBundle --all
if ($LASTEXITCODE -ne 0) { throw 'Private Git history bundle creation failed' }
```

A bundle is not a full project backup or an attachment-restoration command.
Separately preserve private working files and edits, both relevant indexes,
public software refs including retained `refs/crg-results/*`, private association
records, public Git-directory `crg-*` attachment/pointer/materialization/handoff
metadata, private review/recovery state, and required retained runtime releases.
Capture consistent filesystem state only while operations are stopped. A pending
handoff must retain the original runtime and exact candidate state.

Association/receipt records bind actual absolute worktree, Git, private-database
and store paths. Restoring to different paths requires explicit reviewed
association migration; editing path strings or deleting association records does
not repair that binding. No automatic relocation or public/private synchronization
tool is supplied by this deployment procedure. Fresh projects use fresh reviewed
Attach; existing projects require preserved, validated history and metadata.

## Completion evidence

Record actual approved source/bootstrap/archive/manifest identities, successful
publication/import and activation, stable launcher provenance, first paired review
and completed attachment, and the consumer's subsequent Open/mode and ordinary
operation results. Source parsing, native compilation and package publication
alone do not establish a deployed working consumer. Functional-validation
evidence may contribute but does not replace the required installed-consumer
evidence. The owning contracts are [runtime](central-runtime-v1.md),
[launcher](central-launcher-v1.md), [first attachment](first-attachment-v1.md),
[publication/recovery](central-publication-v1.md) and [guards](central-guards-v1.md).
