# Cross-review commit wrapper for Claude-as-implementer.
#
# Used when Claude authored the staged changes. Sets the REVIEW_BACKEND
# env var to `codex` so the pre-commit hook routes review to the Codex
# wrapper (cross-review). Then forwards arguments to `git commit`,
# EXCEPT hook-bypass flags (`--no-verify`, `-n`, and clustered short
# options containing `n` such as `-nF` or `-nm`) which are rejected
# before forwarding. The wrapper exists to enforce cross-review
# routing, so it refuses to participate in a hook-bypass path; use
# CROSS_REVIEW_SKIP=1 (audited per your project's AGENTS.md) for the
# documented skip case. Exits with git's exit code, or 1 on a pre-commit
# abort before `git commit` runs: a bypass-flag rejection, an ambient Git
# selector, a set core.hooksPath that would redirect the pre-commit dispatcher,
# a missing/foreign/tampered default dispatcher, or a failure to prepare the
# controlled Git environment.
#
# Usage examples (run from the Claude session):
#   scripts/claude/commit.ps1 -m "task X: short summary"
#   scripts/claude/commit.ps1 -F .commit-msg.tmp
#   scripts/claude/commit.ps1 --amend
#
# Setting REVIEW_BACKEND=codex here is REQUIRED -- the pre-commit
# hook has NO implicit default and rejects bare `git commit` when
# REVIEW_BACKEND is unset. The wrapper makes the implementer-vs-
# reviewer pairing explicit and symmetric with scripts/codex/commit.ps1
# (saved/restored so later commits in the same shell are not
# affected). It also makes future workflow changes (e.g.,
# REVIEW_BACKEND=both for high-stakes commits) a one-line edit in
# the wrapper rather than every commit call site.
#
# The wrapper does NOT skip the pre-commit hook -- it just selects
# which backend reviews. CROSS_REVIEW_SKIP=1 is still the only skip path
# (documented in scripts/git-hooks/pre-commit and your AGENTS.md).
#
# Symmetric counterpart for Codex-as-implementer:
# scripts/codex/commit.ps1 (sets REVIEW_BACKEND=claude).

# Save/restore the caller's REVIEW_BACKEND so the env mutation is
# scoped to THIS `git commit` only. Symmetric with
# scripts/codex/commit.ps1 (leaving REVIEW_BACKEND set would route
# later bare commits to a stale backend, defeating the wrapper's
# purpose).
# Reject hook-bypass flags BEFORE invoking git: the wrapper's comment
# block above promises "does NOT skip the pre-commit hook", but a
# naive `git commit @args` pass-through would forward `--no-verify` /
# `-n` straight to git, bypassing the hook before REVIEW_BACKEND
# routing runs. Reject those flags explicitly so the wrapper's stated
# contract holds against caller misuse.
# Value-taking options for `git commit`. See scripts/codex/commit.ps1
# for the full per-letter rationale + the optional-attached split.
$alwaysValueShort   = @('m','F','c','C','t')
$optionalValueShort = @('S','u')
$valueTakingShortOpts = $alwaysValueShort + $optionalValueShort

function Test-Bypass-Args {
  param([string[]]$ArgList)
  $skipNext = $false
  $afterDoubleDash = $false
  $bypass = $false
  $offending = ''
  foreach ($a in $ArgList) {
    if ($afterDoubleDash) { continue }
    if ($skipNext) { $skipNext = $false; continue }
    if ($a -eq '--') { $afterDoubleDash = $true; continue }
    if ($valueTakingLongOpts -contains $a) { $skipNext = $true; continue }
    if ($a -match '^-([a-zA-Z])$' -and ($alwaysValueShort -ccontains $matches[1])) {
      $skipNext = $true; continue
    }
    if ($a -match '^--no-v') { $bypass = $true; $offending = $a; break }
    if ($a -match '^-[a-zA-Z]' -and $a -notmatch '^--') {
      $letters = $a.Substring(1).ToCharArray()
      for ($i = 0; $i -lt $letters.Length; $i++) {
        $ch = $letters[$i]
        if ($ch -ceq 'n') { $bypass = $true; $offending = $a; break }
        if ($valueTakingShortOpts -ccontains [string]$ch) {
          if ($i -eq $letters.Length - 1 -and $alwaysValueShort -ccontains [string]$ch) {
            $skipNext = $true
          }
          break
        }
        if ($ch -notmatch '[a-zA-Z]') { break }
      }
      if ($bypass) { break }
    }
  }
  return @{ Bypass = $bypass; Offending = $offending }
}
$valueTakingLongOpts = @(
  '--message', '--file', '--author', '--date', '--template',
  '--reuse-message', '--reedit-message', '--fixup', '--squash',
  '--cleanup', '--pathspec-from-file', '--trailer'
)
# `--gpg-sign` and `--untracked-files` take OPTIONAL values only --
# see scripts/codex/commit.ps1 for the full rationale. Both must use
# the attached `=<value>` form, not the separate-argv form.

# Classify the `git config --get core.hooksPath` exit status for the
# config-redirect guard below. Exit 1 = key ABSENT (the required UNSET
# state) -> 'proceed'; exit 0 = key SET to ANY value
# INCLUDING an empty `core.hooksPath=` (still a configured hook-path state
# that can redirect the dispatcher) -> 'abort-set'; anything else = git
# error -> 'abort-indeterminate' (fail closed). Byte-identical to the copy
# in scripts/codex/commit.ps1.
function Resolve-HooksPathGuard {
  param([int]$ExitCode)
  if ($ExitCode -eq 1) { return 'proceed' }
  if ($ExitCode -eq 0) { return 'abort-set' }
  return 'abort-indeterminate'
}

# PURE PATH-assembly helper for Enable-GitUnixToolPathForHook (below): given the
# (already existence-filtered) candidate tool dirs + the current PATH string,
# return the ordered, case-insensitively-deduped parts with the candidates
# PREPENDED, then the current PATH's parts (skipping blanks and any already
# contributed by a candidate). Byte-identical to the copies in
# scripts/codex/commit.ps1, scripts/shared/auto-merge.ps1, and
# scripts/codex/auto-review.ps1 and scripts/shared/author-lint.ps1.
function Get-PrependedToolPathParts {
  param([string[]]$CandidateDirs, [string]$CurrentPath)
  $parts = New-Object 'System.Collections.Generic.List[string]'
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  if ($CandidateDirs) {
    foreach ($c in $CandidateDirs) {
      if (-not [string]::IsNullOrWhiteSpace($c) -and $seen.Add($c)) { [void]$parts.Add($c) }
    }
  }
  foreach ($p in (($CurrentPath -split [System.IO.Path]::PathSeparator))) {
    if (-not [string]::IsNullOrWhiteSpace($p) -and $seen.Add($p)) { [void]$parts.Add($p) }
  }
  return ,$parts.ToArray()
}

# Collect EVERY PATH-spelling VALUE from the process environment BLOCK. A Windows
# process can inherit a DUPLICATE surface with both 'Path' and 'PATH' as distinct
# case-variant entries holding DIFFERENT dirs; [Environment]::GetEnvironmentVariable
# is case-INSENSITIVE and returns only ONE of them (Path == PATH at runtime), so a
# two-lookup read cannot see both -- enumerate the raw block instead.
# [Environment]::GetEnvironmentVariables('Process') returns a case-SENSITIVE
# Hashtable, so both keys survive when present.
# The effective case-insensitive lookup value is emitted FIRST because that is
# the executable-search order the caller observes before normalization. Remaining
# distinct raw values follow in ordinal key-name order so no extra dirs are lost.
function Get-ProcessPathSpellings {
  $EnvEntries = [Environment]::GetEnvironmentVariables('Process')
  $EffectivePath = [Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::Process)
  $out = New-Object 'System.Collections.Generic.List[string]'
  $seenValues = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  if (-not [string]::IsNullOrEmpty($EffectivePath) -and $seenValues.Add($EffectivePath)) {
    [void]$out.Add($EffectivePath)
  }
  $rawMatches = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([System.StringComparer]::Ordinal)
  foreach ($k in @($EnvEntries.Keys)) {
    $name = [string]$k
    if ([string]::Equals($name, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)) {
      $rawMatches[$name] = [string]$EnvEntries[$k]
    }
  }
  foreach ($entry in $rawMatches.GetEnumerator()) {
    $v = [string]$entry.Value
    if (-not [string]::IsNullOrEmpty($v) -and $seenValues.Add($v)) { [void]$out.Add($v) }
  }
  return ,$out.ToArray()
}

# PURE: union the given process PATH-spelling VALUES (0..N of them -- see
# Get-ProcessPathSpellings; a duplicate surface yields two DIFFERING strings) into
# the ordered, case-insensitively-deduped parts, candidates PREPENDED. The
# effective lookup spelling precedes deterministic raw-only additions; reading
# only ONE spelling would silently DROP the other's dirs. Delegates the dedup to
# Get-PrependedToolPathParts.
# Byte-identical to the copies in scripts/codex/commit.ps1,
# scripts/shared/auto-merge.ps1, scripts/codex/auto-review.ps1, and
# scripts/shared/author-lint.ps1.
function Get-UnionProcessPathParts {
  param([string[]]$Spellings, [string[]]$CandidateDirs = @())
  $joined = (@($Spellings) | Where-Object { -not [string]::IsNullOrEmpty($_) }) -join [System.IO.Path]::PathSeparator
  return Get-PrependedToolPathParts -CandidateDirs $CandidateDirs -CurrentPath $joined
}

function Set-CanonicalProcessPathEnvironment {
  param([Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Value)
  while ($true) {
    $before = [Environment]::GetEnvironmentVariables('Process')
    $beforeKeys = @($before.Keys | Where-Object {
      [string]::Equals([string]$_, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($beforeKeys.Count -eq 0) { break }
    $removeName = [string]$beforeKeys[0]
    [Environment]::SetEnvironmentVariable($removeName, $null, [EnvironmentVariableTarget]::Process)
    $afterRemoval = [Environment]::GetEnvironmentVariables('Process')
    $afterCount = @($afterRemoval.Keys | Where-Object {
      [string]::Equals([string]$_, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)
    }).Count
    if ($afterCount -ge $beforeKeys.Count) {
      throw [System.InvalidOperationException]::new("could not remove inherited PATH spelling '$removeName'")
    }
  }
  [Environment]::SetEnvironmentVariable('Path', $Value, [EnvironmentVariableTarget]::Process)
  $final = [Environment]::GetEnvironmentVariables('Process')
  $finalKeys = @($final.Keys | Where-Object {
    [string]::Equals([string]$_, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)
  })
  if ($finalKeys.Count -ne 1 -or [string]$finalKeys[0] -cne 'Path' -or
      -not [string]::Equals([string]$final['Path'], $Value, [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new("canonical Path postcondition failed (raw spelling count=$($finalKeys.Count))")
  }
}

# Return raw environment NAMES for Git selectors that can redirect the target
# repository, object/ref/index domain, history, diff/attribute semantics, or
# configuration resolution.
# Values are deliberately never read: only presence has authority, and Windows
# process blocks can carry a case-variant spelling that a named lookup misses.
function Get-CrgGitSelectorEnvironmentKeys {
  param([System.Collections.IDictionary]$EnvEntries)
  if ($null -eq $EnvEntries) { $EnvEntries = [Environment]::GetEnvironmentVariables('Process') }
  $exactNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($canonicalName in @(
      'GIT_GRAFT_FILE', 'GIT_SHALLOW_FILE', 'GIT_ATTR_SOURCE', 'GIT_ATTR_NOSYSTEM',
      'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
      'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_NAMESPACE',
      'GIT_REFERENCE_BACKEND',
      'GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM',
      'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT'
    )) {
    [void]$exactNames.Add($canonicalName)
  }
  $numberedConfigOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
  $names = New-Object 'System.Collections.Generic.List[string]'
  foreach ($rawName in @($EnvEntries.Keys)) {
    $name = [string]$rawName
    if ($exactNames.Contains($name) -or
        [regex]::IsMatch($name, '\AGIT_CONFIG_(?:KEY|VALUE)_[0-9]+\z', $numberedConfigOptions)) {
      [void]$names.Add($name)
    }
  }
  return $names.ToArray()
}

# A named environment lookup can hide case-variant duplicates on Windows, while
# native Git consumes the raw block. Discover by ordinal-ignore-case comparison,
# remove every exact spelling, then prove one canonical entry before any child
# launch. The child-map helper covers ProcessStartInfo environments explicitly
# instead of relying on the already-normalized parent. Kept byte-identical in
# both commit wrappers and auto-merge.
function Get-CrgNoReplaceObjectsEnvironmentKeys {
  param([AllowNull()][object]$EnvEntries)
  if ([object]::ReferenceEquals($null, $EnvEntries)) {
    $EnvEntries = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
  }
  if ([object]::ReferenceEquals($null, $EnvEntries) -or
      $null -eq $EnvEntries.PSObject.Properties['Keys']) {
    throw [System.InvalidOperationException]::new('raw environment enumeration is unavailable')
  }
  try { $rawNames = @($EnvEntries.Keys) }
  catch { throw [System.InvalidOperationException]::new("raw environment enumeration failed: $($_.Exception.Message)") }
  $names = New-Object 'System.Collections.Generic.List[string]'
  foreach ($rawName in $rawNames) {
    $name = [string]$rawName
    if ([string]::Equals($name, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::OrdinalIgnoreCase)) {
      [void]$names.Add($name)
    }
  }
  return $names.ToArray()
}

function Assert-CrgNoReplaceObjectsEnvironment {
  param([Parameter(Mandatory=$true)][object]$EnvEntries)
  $names = @(Get-CrgNoReplaceObjectsEnvironmentKeys -EnvEntries $EnvEntries)
  if ($names.Count -ne 1 -or
      -not [string]::Equals([string]$names[0], 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new("replacement-suppression singleton postcondition failed (raw spelling count=$($names.Count))")
  }
  $value = $null
  try { $value = [string]$EnvEntries[$names[0]] }
  catch { throw [System.InvalidOperationException]::new("replacement-suppression value verification failed: $($_.Exception.Message)") }
  if (-not [string]::Equals($value, '1', [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new('the canonical replacement-suppression value did not verify as exactly 1')
  }
}

function Set-CrgNoReplaceObjectsInChildEnvironment {
  param([Parameter(Mandatory=$true)][object]$EnvEntries)
  if ([object]::ReferenceEquals($null, $EnvEntries)) {
    throw [System.InvalidOperationException]::new('child environment is unavailable')
  }
  while ($true) {
    $before = @(Get-CrgNoReplaceObjectsEnvironmentKeys -EnvEntries $EnvEntries)
    if ($before.Count -eq 0) { break }
    $exactName = [string]$before[0]
    try { [void]$EnvEntries.Remove($exactName) }
    catch { throw [System.InvalidOperationException]::new("could not remove child environment spelling '$exactName': $($_.Exception.Message)") }
    $after = @(Get-CrgNoReplaceObjectsEnvironmentKeys -EnvEntries $EnvEntries)
    if ($after.Count -ge $before.Count) {
      throw [System.InvalidOperationException]::new("child environment removal made no progress for spelling '$exactName'")
    }
  }
  $remaining = @(Get-CrgNoReplaceObjectsEnvironmentKeys -EnvEntries $EnvEntries)
  if ($remaining.Count -ne 0) {
    throw [System.InvalidOperationException]::new("replacement-suppression spelling(s) survived child-environment removal: $($remaining -join ', ')")
  }
  try { $EnvEntries.Set_Item('GIT_NO_REPLACE_OBJECTS', '1') }
  catch { throw [System.InvalidOperationException]::new("could not install canonical child replacement suppression: $($_.Exception.Message)") }
  Assert-CrgNoReplaceObjectsEnvironment -EnvEntries $EnvEntries
}

function Set-CrgNoReplaceObjects {
  while ($true) {
    $before = @(Get-CrgNoReplaceObjectsEnvironmentKeys)
    if ($before.Count -eq 0) { break }
    $exactName = [string]$before[0]
    try { [Environment]::SetEnvironmentVariable($exactName, $null, [EnvironmentVariableTarget]::Process) }
    catch { throw [System.InvalidOperationException]::new("could not remove process environment spelling '$exactName': $($_.Exception.Message)") }
    $after = @(Get-CrgNoReplaceObjectsEnvironmentKeys)
    if ($after.Count -ge $before.Count) {
      throw [System.InvalidOperationException]::new("process environment removal made no progress for spelling '$exactName'")
    }
  }
  $remaining = @(Get-CrgNoReplaceObjectsEnvironmentKeys)
  if ($remaining.Count -ne 0) {
    throw [System.InvalidOperationException]::new("replacement-suppression spelling(s) survived process-environment removal: $($remaining -join ', ')")
  }
  [Environment]::SetEnvironmentVariable('GIT_NO_REPLACE_OBJECTS', '1', [EnvironmentVariableTarget]::Process)
  Assert-CrgNoReplaceObjectsEnvironment -EnvEntries (
    [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
  )
}

# Read and launch through the native Windows environment boundary. A managed
# ProcessStartInfo map can reject duplicate case-variant names before the child
# can normalize them, so the native-invoked proxy constructs the complete child block
# without projecting the caller's environment through a case-insensitive map.
function Initialize-CrgCommitNativeEnvironment {
  if ('CrgCommitEnvironment.NativeV1' -as [type]) { return }
  Add-Type -TypeDefinition @'
namespace CrgCommitEnvironment {
  using System;
  using System.Collections.Generic;
  using System.ComponentModel;
  using System.Runtime.InteropServices;
  using System.Text;

  public static class NativeV1 {
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint JOB_OBJECT_TERMINATE = 0x00000008;
    private const int JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private const uint INFINITE = 0xFFFFFFFF;
    private const uint SYNCHRONIZE = 0x00100000;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
      public int cb;
      public string lpReserved;
      public string lpDesktop;
      public string lpTitle;
      public int dwX;
      public int dwY;
      public int dwXSize;
      public int dwYSize;
      public int dwXCountChars;
      public int dwYCountChars;
      public int dwFillAttribute;
      public int dwFlags;
      public short wShowWindow;
      public short cbReserved2;
      public IntPtr lpReserved2;
      public IntPtr hStdInput;
      public IntPtr hStdOutput;
      public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
      public IntPtr hProcess;
      public IntPtr hThread;
      public uint dwProcessId;
      public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
      public long PerProcessUserTimeLimit;
      public long PerJobUserTimeLimit;
      public uint LimitFlags;
      public UIntPtr MinimumWorkingSetSize;
      public UIntPtr MaximumWorkingSetSize;
      public uint ActiveProcessLimit;
      public UIntPtr Affinity;
      public uint PriorityClass;
      public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS {
      public ulong ReadOperationCount;
      public ulong WriteOperationCount;
      public ulong OtherOperationCount;
      public ulong ReadTransferCount;
      public ulong WriteTransferCount;
      public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
      public IO_COUNTERS IoInfo;
      public UIntPtr ProcessMemoryLimit;
      public UIntPtr JobMemoryLimit;
      public UIntPtr PeakProcessMemoryUsed;
      public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetEnvironmentStringsW();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeEnvironmentStringsW(IntPtr environmentBlock);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
      string applicationName,
      StringBuilder commandLine,
      IntPtr processAttributes,
      IntPtr threadAttributes,
      bool inheritHandles,
      uint creationFlags,
      IntPtr environment,
      string currentDirectory,
      ref STARTUPINFO startupInfo,
      out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
      IntPtr job,
      int informationClass,
      ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
      uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
      string fileName,
      uint desiredAccess,
      uint shareMode,
      IntPtr securityAttributes,
      uint creationDisposition,
      uint flagsAndAttributes,
      IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
      IntPtr sourceProcess,
      IntPtr sourceHandle,
      IntPtr targetProcess,
      out IntPtr targetHandle,
      uint desiredAccess,
      bool inheritHandle,
      uint options);

    public static string[] ReadProcessEntries() {
      IntPtr block = GetEnvironmentStringsW();
      if (block == IntPtr.Zero) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "GetEnvironmentStringsW failed");
      }
      Exception pending = null;
      try {
        List<string> entries = new List<string>();
        IntPtr cursor = block;
        while (true) {
          string entry = Marshal.PtrToStringUni(cursor);
          if (entry == null) {
            throw new InvalidOperationException("raw environment block contained an unreadable entry");
          }
          if (entry.Length == 0) { break; }
          entries.Add(entry);
          cursor = IntPtr.Add(cursor, checked((entry.Length + 1) * 2));
        }
        return entries.ToArray();
      } catch (Exception ex) {
        pending = ex;
        throw;
      } finally {
        if (!FreeEnvironmentStringsW(block) && pending == null) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "FreeEnvironmentStringsW failed");
        }
      }
    }

    private sealed class EnvironmentEntry {
      public string Text;
      public string Name;
      public int Position;
    }

    private static string GetEnvironmentEntryName(string entry) {
      if (String.IsNullOrEmpty(entry) || entry.IndexOf('\0') >= 0) {
        throw new ArgumentException("environment entries must be non-empty and NUL-free");
      }
      int separator = entry[0] == '=' ? entry.IndexOf('=', 1) : entry.IndexOf('=');
      int minimum = entry[0] == '=' ? 1 : 0;
      if (separator <= minimum) {
        throw new ArgumentException("environment entries must use name=value grammar");
      }
      return entry.Substring(0, separator);
    }

    private static IntPtr DuplicateStandardHandle(int standardHandle) {
      IntPtr source = GetStdHandle(standardHandle);
      if (source == INVALID_HANDLE_VALUE) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "GetStdHandle failed");
      }
      bool closeSource = false;
      if (source == IntPtr.Zero) {
        uint access = standardHandle == STD_INPUT_HANDLE ? GENERIC_READ : GENERIC_WRITE;
        source = CreateFileW("NUL", access, FILE_SHARE_READ | FILE_SHARE_WRITE,
          IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (source == IntPtr.Zero || source == INVALID_HANDLE_VALUE) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "opening NUL for an absent standard stream failed");
        }
        closeSource = true;
      }
      IntPtr duplicate = IntPtr.Zero;
      IntPtr process = GetCurrentProcess();
      bool duplicated = DuplicateHandle(process, source, process, out duplicate, 0, true, DUPLICATE_SAME_ACCESS);
      int duplicateError = duplicated ? 0 : Marshal.GetLastWin32Error();
      if (closeSource && !CloseHandle(source)) {
        int closeError = Marshal.GetLastWin32Error();
        if (duplicate != IntPtr.Zero) { CloseHandle(duplicate); }
        throw new Win32Exception(closeError, "closing the temporary NUL standard-stream handle failed");
      }
      if (!duplicated) {
        throw new Win32Exception(duplicateError, "DuplicateHandle for a standard stream failed");
      }
      return duplicate;
    }

    public sealed class ProcessSession : IDisposable {
      private IntPtr processHandle;
      private IntPtr jobHandle;
      internal ProcessSession(IntPtr process, IntPtr job) {
        processHandle = process;
        jobHandle = job;
      }

      private IntPtr GetLiveHandle() {
        if (processHandle == IntPtr.Zero) { throw new ObjectDisposedException("ProcessSession"); }
        return processHandle;
      }

      public bool HasExited {
        get {
          uint wait = WaitForSingleObject(GetLiveHandle(), 0);
          if (wait == WAIT_OBJECT_0) { return true; }
          if (wait == WAIT_TIMEOUT) { return false; }
          throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject commit-worker probe failed");
        }
      }

      public int WaitForExitCode() {
        IntPtr handle = GetLiveHandle();
        uint wait = WaitForSingleObject(handle, INFINITE);
        if (wait != WAIT_OBJECT_0) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject commit-worker wait failed");
        }
        uint exitCode;
        if (!GetExitCodeProcess(handle, out exitCode)) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess commit-worker read failed");
        }
        return unchecked((int)exitCode);
      }

      public int CompleteRootAndCloseJob() {
        int exitCode = WaitForExitCode();
        if (jobHandle != IntPtr.Zero) {
          if (!CloseHandle(jobHandle)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle commit-worker job completion failed");
          }
          jobHandle = IntPtr.Zero;
        }
        return exitCode;
      }

      public void TerminateAndWait() {
        IntPtr process = GetLiveHandle();
        bool stopped = jobHandle != IntPtr.Zero
          ? TerminateJobObject(jobHandle, 1)
          : TerminateProcess(process, 1);
        int stopError = stopped ? 0 : Marshal.GetLastWin32Error();
        if (!stopped) {
          uint probe = WaitForSingleObject(process, 0);
          if (probe == WAIT_OBJECT_0) { return; }
          if (probe == WAIT_TIMEOUT) {
            throw new Win32Exception(stopError, "commit-worker cleanup termination failed");
          }
          throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject commit-worker cleanup probe failed");
        }
        uint wait = WaitForSingleObject(process, INFINITE);
        if (wait != WAIT_OBJECT_0) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject terminated commit-worker failed");
        }
      }

      public void Dispose() {
        IntPtr process = processHandle;
        IntPtr job = jobHandle;
        processHandle = IntPtr.Zero;
        jobHandle = IntPtr.Zero;
        if (process != IntPtr.Zero) { CloseHandle(process); }
        if (job != IntPtr.Zero) { CloseHandle(job); }
      }
    }

    private static void StopFailedLaunch(IntPtr process, IntPtr job, bool assigned) {
      uint wait = WaitForSingleObject(process, 0);
      if (wait == WAIT_OBJECT_0) { return; }
      if (wait != WAIT_TIMEOUT) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed-launch probe failed");
      }
      bool stopped = assigned ? TerminateJobObject(job, 1) : TerminateProcess(process, 1);
      if (!stopped) {
        wait = WaitForSingleObject(process, 0);
        if (wait != WAIT_OBJECT_0) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "commit-worker failed-launch termination failed");
        }
        return;
      }
      wait = WaitForSingleObject(process, INFINITE);
      if (wait != WAIT_OBJECT_0) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "commit-worker failed-launch wait failed");
      }
    }

    public static ProcessSession StartProcess(
        string applicationName,
        string commandLine,
        string currentDirectory,
        string[] entries) {
      return StartProcessCore(applicationName, commandLine, currentDirectory, entries);
    }

    private static ProcessSession StartProcessCore(
        string applicationName,
        string commandLine,
        string currentDirectory,
        string[] entries) {
      if (String.IsNullOrWhiteSpace(applicationName)) { throw new ArgumentException("applicationName is required"); }
      if (String.IsNullOrWhiteSpace(commandLine)) { throw new ArgumentException("commandLine is required"); }
      if (commandLine.Length > 32767) { throw new ArgumentException("commandLine exceeds the CreateProcessW limit"); }
      if (String.IsNullOrWhiteSpace(currentDirectory)) { throw new ArgumentException("currentDirectory is required"); }
      if (entries == null) { throw new ArgumentNullException("entries"); }

      List<EnvironmentEntry> sortedEntries = new List<EnvironmentEntry>();
      for (int index = 0; index < entries.Length; index++) {
        string entry = entries[index];
        sortedEntries.Add(new EnvironmentEntry {
          Text = entry,
          Name = GetEnvironmentEntryName(entry),
          Position = index
        });
      }
      sortedEntries.Sort(delegate(EnvironmentEntry left, EnvironmentEntry right) {
        int byName = StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name);
        return byName != 0 ? byName : left.Position.CompareTo(right.Position);
      });

      StringBuilder blockBuilder = new StringBuilder();
      foreach (EnvironmentEntry entry in sortedEntries) {
        blockBuilder.Append(entry.Text).Append('\0');
      }
      blockBuilder.Append('\0');

      IntPtr environment = Marshal.StringToHGlobalUni(blockBuilder.ToString());
      PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
      STARTUPINFO startupInfo = new STARTUPINFO();
      startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
      IntPtr standardInput = IntPtr.Zero;
      IntPtr standardOutput = IntPtr.Zero;
      IntPtr standardError = IntPtr.Zero;
      IntPtr job = IntPtr.Zero;
      bool assigned = false;
      try {
        job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObjectW commit-worker launch failed");
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ref limits,
            checked((uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject commit-worker launch failed");
        }
        standardInput = DuplicateStandardHandle(STD_INPUT_HANDLE);
        standardOutput = DuplicateStandardHandle(STD_OUTPUT_HANDLE);
        standardError = DuplicateStandardHandle(STD_ERROR_HANDLE);
        startupInfo.dwFlags = STARTF_USESTDHANDLES;
        startupInfo.hStdInput = standardInput;
        startupInfo.hStdOutput = standardOutput;
        startupInfo.hStdError = standardError;
        StringBuilder mutableCommandLine = new StringBuilder(commandLine);
        if (!CreateProcessW(applicationName, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, true,
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, environment, currentDirectory,
            ref startupInfo, out processInformation)) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW commit-worker launch failed");
        }
        if (!AssignProcessToJobObject(job, processInformation.hProcess)) {
          int assignmentError = Marshal.GetLastWin32Error();
          // The v2.1 membership-only fallback (retired 2026-09-06) could not
          // bound an inherited job to this invocation. Never resume without
          // the private kill-on-close job that completion and cancellation own.
          // Finally terminates and waits for this still-suspended worker; any
          // cleanup failure replaces this refusal rather than claiming success.
          throw new Win32Exception(assignmentError,
            "AssignProcessToJobObject commit-worker launch failed: descendant lifetime ownership is unavailable; worker was not resumed");
        } else {
          assigned = true;
        }
        if (ResumeThread(processInformation.hThread) == UInt32.MaxValue) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread commit-worker launch failed");
        }
        ProcessSession session = new ProcessSession(
          processInformation.hProcess, job);
        processInformation.hProcess = IntPtr.Zero;
        job = IntPtr.Zero;
        return session;
      } finally {
        try {
          if (processInformation.hProcess != IntPtr.Zero) {
            StopFailedLaunch(processInformation.hProcess, job, assigned);
          }
        } finally {
          if (standardInput != IntPtr.Zero) { CloseHandle(standardInput); }
          if (standardOutput != IntPtr.Zero) { CloseHandle(standardOutput); }
          if (standardError != IntPtr.Zero) { CloseHandle(standardError); }
          if (processInformation.hThread != IntPtr.Zero) { CloseHandle(processInformation.hThread); }
          if (processInformation.hProcess != IntPtr.Zero) { CloseHandle(processInformation.hProcess); }
          if (job != IntPtr.Zero) { CloseHandle(job); }
          Marshal.FreeHGlobal(environment);
        }
      }
    }
  }
}
'@ -Language CSharp -ErrorAction Stop
  if (-not ('CrgCommitEnvironment.NativeV1' -as [type])) {
    throw [System.PlatformNotSupportedException]::new('native commit-worker environment support is unavailable')
  }
}

function Get-CrgRawCommitEnvironmentEntries {
  Initialize-CrgCommitNativeEnvironment
  $entries = [CrgCommitEnvironment.NativeV1]::ReadProcessEntries()
  if ($null -eq $entries) {
    throw [System.InvalidOperationException]::new('raw Windows environment enumeration returned null')
  }
  return [string[]]$entries
}

function ConvertFrom-CrgRawCommitEnvironmentEntry {
  param([Parameter(Mandatory=$true)][string]$Entry)
  if ([string]::IsNullOrEmpty($Entry) -or $Entry.IndexOf([char]0) -ge 0) {
    throw [System.InvalidOperationException]::new('raw environment entries must be non-empty and NUL-free')
  }
  $separator = $(if ($Entry.StartsWith('=', [System.StringComparison]::Ordinal)) {
    $Entry.IndexOf('=', 1)
  } else {
    $Entry.IndexOf('=')
  })
  $minimum = $(if ($Entry.StartsWith('=', [System.StringComparison]::Ordinal)) { 1 } else { 0 })
  if ($separator -le $minimum) {
    throw [System.InvalidOperationException]::new('raw environment entry does not use name=value grammar')
  }
  return [pscustomobject]@{
    Name = $Entry.Substring(0, $separator)
    Value = $Entry.Substring($separator + 1)
    Text = $Entry
  }
}

function Get-CrgRawCommitEnvironmentMatches {
  param(
    [Parameter(Mandatory=$true)][string[]]$Entries,
    [Parameter(Mandatory=$true)][string]$Name
  )
  $matches = New-Object 'System.Collections.Generic.List[object]'
  foreach ($entry in $Entries) {
    $parsed = ConvertFrom-CrgRawCommitEnvironmentEntry -Entry ([string]$entry)
    if ([string]::Equals($parsed.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      [void]$matches.Add($parsed)
    }
  }
  return $matches.ToArray()
}

function Assert-CrgRawCommitEnvironmentSingleton {
  param(
    [Parameter(Mandatory=$true)][string[]]$Entries,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Value
  )
  $matches = @(Get-CrgRawCommitEnvironmentMatches -Entries $Entries -Name $Name)
  if ($matches.Count -ne 1 -or
      -not [string]::Equals([string]$matches[0].Name, $Name, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals([string]$matches[0].Value, $Value, [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new("raw environment singleton '$Name=$Value' did not verify (spelling count=$($matches.Count))")
  }
}

function Assert-CrgRawCommitPathSingleton {
  param([Parameter(Mandatory=$true)][string[]]$Entries)
  $matches = @(Get-CrgRawCommitEnvironmentMatches -Entries $Entries -Name 'Path')
  if ($matches.Count -ne 1 -or
      -not [string]::Equals([string]$matches[0].Name, 'Path', [System.StringComparison]::Ordinal) -or
      [string]::IsNullOrEmpty([string]$matches[0].Value)) {
    throw [System.InvalidOperationException]::new("raw environment Path singleton did not verify (spelling count=$($matches.Count))")
  }
}

# A direct `& commit.ps1` call shares the invoking PowerShell process. The
# outer wrapper therefore invokes a native PowerShell proxy, which mutates only
# an explicit worker environment. This marker bounds the proxy-to-worker hop but grants no authority: a worker must also
# prove the independent replacement-suppression singleton before any Git use.
$script:CrgCommitWorkerMarker = 'CRG_COMMIT_WORKER_V1'

function Test-CrgCommitWorkerCommandTarget {
  [string[]]$commandArguments = @([Environment]::GetCommandLineArgs())
  for ($index = 1; $index -lt ($commandArguments.Count - 1); $index++) {
    if (-not [string]::Equals($commandArguments[$index], '-File', [System.StringComparison]::OrdinalIgnoreCase)) {
      continue
    }
    try {
      $actualTarget = [System.IO.Path]::GetFullPath([string]$commandArguments[$index + 1])
      $expectedTarget = [System.IO.Path]::GetFullPath($PSCommandPath)
      return [string]::Equals($actualTarget, $expectedTarget, [System.StringComparison]::OrdinalIgnoreCase)
    } catch {
      return $false
    }
  }
  return $false
}

function Test-CrgCommitWorkerProcess {
  [string[]]$entries = @(Get-CrgRawCommitEnvironmentEntries)
  $markers = @(Get-CrgRawCommitEnvironmentMatches -Entries $entries -Name $script:CrgCommitWorkerMarker)
  if ($markers.Count -eq 0) { return $false }
  if (-not (Test-CrgCommitWorkerCommandTarget)) { return $false }
  if ($markers.Count -ne 1 -or
      -not [string]::Equals([string]$markers[0].Name, $script:CrgCommitWorkerMarker, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals([string]$markers[0].Value, '1', [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new('the commit-worker marker is malformed or ambiguous')
  }
  Assert-CrgRawCommitEnvironmentSingleton -Entries $entries -Name 'GIT_NO_REPLACE_OBJECTS' -Value '1'
  Assert-CrgRawCommitPathSingleton -Entries $entries
  return $true
}

function New-CrgCommitWorkerEnvironment {
  [string[]]$rawEntries = @(Get-CrgRawCommitEnvironmentEntries)
  $childEntries = New-Object 'System.Collections.Generic.List[string]'
  $pathSpellings = New-Object 'System.Collections.Generic.List[string]'
  $seenPathValues = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $effectivePath = [Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::Process)
  if (-not [string]::IsNullOrEmpty($effectivePath) -and $seenPathValues.Add($effectivePath)) {
    [void]$pathSpellings.Add($effectivePath)
  }
  foreach ($entry in $rawEntries) {
    $parsed = ConvertFrom-CrgRawCommitEnvironmentEntry -Entry $entry
    if ([string]::Equals($parsed.Name, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($parsed.Name, $script:CrgCommitWorkerMarker, [System.StringComparison]::OrdinalIgnoreCase)) {
      continue
    }
    if ([string]::Equals($parsed.Name, 'PATH', [System.StringComparison]::OrdinalIgnoreCase)) {
      if (-not [string]::IsNullOrEmpty($parsed.Value) -and $seenPathValues.Add([string]$parsed.Value)) {
        [void]$pathSpellings.Add([string]$parsed.Value)
      }
      continue
    }
    [void]$childEntries.Add([string]$parsed.Text)
  }
  $pathParts = Get-UnionProcessPathParts -Spellings $pathSpellings.ToArray()
  if ($pathParts.Count -eq 0) {
    throw [System.InvalidOperationException]::new('no non-empty process PATH value is available for the dedicated child')
  }
  $childPath = [string]::Join([System.IO.Path]::PathSeparator, $pathParts)
  [void]$childEntries.Add("Path=$childPath")
  [void]$childEntries.Add('GIT_NO_REPLACE_OBJECTS=1')
  [void]$childEntries.Add("$($script:CrgCommitWorkerMarker)=1")
  $finalEntries = $childEntries.ToArray()
  Assert-CrgRawCommitEnvironmentSingleton -Entries $finalEntries -Name 'Path' -Value $childPath
  Assert-CrgRawCommitEnvironmentSingleton -Entries $finalEntries -Name 'GIT_NO_REPLACE_OBJECTS' -Value '1'
  Assert-CrgRawCommitEnvironmentSingleton -Entries $finalEntries -Name $script:CrgCommitWorkerMarker -Value '1'
  return $finalEntries
}


function ConvertTo-CrgCommitProcessArgumentLine {
  param([AllowNull()][string[]]$ArgList)
  if ($null -eq $ArgList) { return '' }
  $quoted = foreach ($argumentValue in $ArgList) {
    if ($null -eq $argumentValue) { $argumentValue = '' }
    if ($argumentValue.Length -gt 0 -and ($argumentValue.IndexOfAny([char[]]@(' ', "`t", '"')) -lt 0)) {
      $argumentValue
    } else {
      $builder = [System.Text.StringBuilder]::new()
      [void]$builder.Append('"')
      $slashes = 0
      foreach ($character in $argumentValue.ToCharArray()) {
        if ($character -eq '\') {
          $slashes++
        } elseif ($character -eq '"') {
          [void]$builder.Append('\' * ($slashes * 2 + 1))
          [void]$builder.Append('"')
          $slashes = 0
        } else {
          if ($slashes -gt 0) { [void]$builder.Append('\' * $slashes); $slashes = 0 }
          [void]$builder.Append($character)
        }
      }
      if ($slashes -gt 0) { [void]$builder.Append('\' * ($slashes * 2)) }
      [void]$builder.Append('"')
      $builder.ToString()
    }
  }
  return ($quoted -join ' ')
}

# Relaunch through the edition's known command-line engine. The current host
# process can be powershell_ise.exe or an arbitrary runspace host that rejects
# -NoProfile/-File even though the process is an ordinary executable.
function Get-CrgPowerShellCliExecutablePath {
  $edition = [string]$PSVersionTable.PSEdition
  if ([string]::Equals($edition, 'Desktop', [System.StringComparison]::Ordinal)) {
    $engineName = 'powershell.exe'
  } elseif ([string]::Equals($edition, 'Core', [System.StringComparison]::Ordinal)) {
    $engineName = 'pwsh.exe'
  } else {
    throw [System.PlatformNotSupportedException]::new("unsupported PowerShell edition '$edition'")
  }

  try {
    $powerShellHomeText = [string]$PSHOME
    if ([string]::IsNullOrWhiteSpace($powerShellHomeText) -or
        -not [System.IO.Path]::IsPathRooted($powerShellHomeText)) {
      throw [System.InvalidOperationException]::new('PSHOME is unavailable or not rooted')
    }
    $powerShellHome = [System.IO.Path]::GetFullPath($powerShellHomeText).TrimEnd('\', '/')
    $enginePath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($powerShellHome, $engineName))
    $engineParent = [System.IO.Path]::GetDirectoryName($enginePath).TrimEnd('\', '/')
    if (-not [string]::Equals($engineParent, $powerShellHome, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw [System.InvalidOperationException]::new('the CLI engine path escaped PSHOME')
    }
  } catch {
    throw [System.InvalidOperationException]::new('the known PowerShell CLI engine path could not be resolved', $_.Exception)
  }

  try {
    $engineItem = Get-Item -LiteralPath $enginePath -Force -ErrorAction Stop
  } catch {
    throw [System.IO.FileNotFoundException]::new('the known PowerShell CLI engine is unavailable', $enginePath, $_.Exception)
  }
  if ($engineItem -isnot [System.IO.FileInfo] -or
      ($engineItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      -not [string]::Equals($engineItem.FullName, $enginePath, [System.StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::Equals($engineItem.Name, $engineName, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw [System.IO.FileNotFoundException]::new('the known PowerShell CLI engine is not an ordinary direct file', $enginePath)
  }
  return $enginePath
}

$script:CrgCommitProxyArgument = '--crg-commit-environment-proxy-v1'
$script:CrgCommitWorkerArgument = '--crg-commit-worker-arguments-v1'
$script:CrgCommitArgumentEnvelopeMaxBytes = 1048576
$script:CrgCommitArgumentEnvelopeMaxCount = 32767

function ConvertTo-CrgCommitArgumentEnvelope {
  [CmdletBinding()]
  param([AllowNull()][string[]]$ForwardArgs)

  [string[]]$argumentList = @($ForwardArgs)
  if ($argumentList.Count -gt $script:CrgCommitArgumentEnvelopeMaxCount) {
    throw [System.ArgumentException]::new('commit argument count exceeds the bounded transport domain')
  }
  $encoding = [System.Text.UnicodeEncoding]::new($false, $false, $true)
  $stream = [System.IO.MemoryStream]::new()
  $writer = [System.IO.BinaryWriter]::new($stream, [System.Text.UTF8Encoding]::new($false, $true), $true)
  try {
    [byte[]]$magic = [System.Text.Encoding]::ASCII.GetBytes('CRGARGV1')
    $writer.Write($magic)
    $writer.Write([int]0)
    $writer.Write([int]$argumentList.Count)
    foreach ($forwardArgument in $argumentList) {
      if ($null -eq $forwardArgument) { $forwardArgument = '' }
      $argumentValue = [string]$forwardArgument
      if ($argumentValue.IndexOf([char]0) -ge 0) {
        throw [System.ArgumentException]::new('commit arguments cannot contain NUL characters')
      }
      if ($argumentValue.Length -gt ($script:CrgCommitArgumentEnvelopeMaxBytes / 2)) {
        throw [System.ArgumentException]::new('a commit argument exceeds the bounded transport domain')
      }
      [byte[]]$argumentBytes = $encoding.GetBytes($argumentValue)
      if (($stream.Length + 4 + $argumentBytes.Length) -gt $script:CrgCommitArgumentEnvelopeMaxBytes) {
        throw [System.ArgumentException]::new('commit arguments exceed the bounded transport domain')
      }
      $writer.Write([int]$argumentBytes.Length)
      $writer.Write($argumentBytes)
    }
    $writer.Flush()
    [byte[]]$envelope = $stream.ToArray()
    [byte[]]$declaredLength = [System.BitConverter]::GetBytes([int]$envelope.Length)
    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($declaredLength) }
    [Array]::Copy($declaredLength, 0, $envelope, 8, 4)
    return ,$envelope
  } finally {
    $writer.Dispose()
    $stream.Dispose()
  }
}

function ConvertFrom-CrgCommitArgumentEnvelope {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][byte[]]$Envelope)

  if ($Envelope.Length -lt 16 -or $Envelope.Length -gt $script:CrgCommitArgumentEnvelopeMaxBytes) {
    throw [System.FormatException]::new('commit argument envelope length is outside the bounded domain')
  }
  $encoding = [System.Text.UnicodeEncoding]::new($false, $false, $true)
  $stream = [System.IO.MemoryStream]::new($Envelope, $false)
  $reader = [System.IO.BinaryReader]::new($stream, [System.Text.UTF8Encoding]::new($false, $true), $true)
  try {
    [byte[]]$expectedMagic = [System.Text.Encoding]::ASCII.GetBytes('CRGARGV1')
    [byte[]]$actualMagic = $reader.ReadBytes($expectedMagic.Length)
    if ($actualMagic.Length -ne $expectedMagic.Length) {
      throw [System.FormatException]::new('commit argument envelope header is truncated')
    }
    for ($magicIndex = 0; $magicIndex -lt $expectedMagic.Length; $magicIndex++) {
      if ($actualMagic[$magicIndex] -ne $expectedMagic[$magicIndex]) {
        throw [System.FormatException]::new('commit argument envelope magic or version is invalid')
      }
    }
    $declaredLength = $reader.ReadInt32()
    if ($declaredLength -ne $Envelope.Length) {
      throw [System.FormatException]::new('commit argument envelope length binding is invalid')
    }
    $argumentCount = $reader.ReadInt32()
    if ($argumentCount -lt 0 -or $argumentCount -gt $script:CrgCommitArgumentEnvelopeMaxCount) {
      throw [System.FormatException]::new('commit argument envelope count is outside the bounded domain')
    }
    $decodedArguments = New-Object 'System.Collections.Generic.List[string]'
    for ($argumentIndex = 0; $argumentIndex -lt $argumentCount; $argumentIndex++) {
      if (($stream.Length - $stream.Position) -lt 4) {
        throw [System.FormatException]::new('commit argument envelope record length is truncated')
      }
      $argumentByteLength = $reader.ReadInt32()
      if ($argumentByteLength -lt 0 -or ($argumentByteLength % 2) -ne 0 -or
          $argumentByteLength -gt ($stream.Length - $stream.Position)) {
        throw [System.FormatException]::new('commit argument envelope record length is invalid')
      }
      [byte[]]$argumentBytes = $reader.ReadBytes($argumentByteLength)
      if ($argumentBytes.Length -ne $argumentByteLength) {
        throw [System.FormatException]::new('commit argument envelope record is truncated')
      }
      $decodedArgument = $encoding.GetString($argumentBytes)
      if ($decodedArgument.IndexOf([char]0) -ge 0) {
        throw [System.FormatException]::new('commit argument envelope contains a NUL-bearing argument')
      }
      [void]$decodedArguments.Add($decodedArgument)
    }
    if ($stream.Position -ne $stream.Length) {
      throw [System.FormatException]::new('commit argument envelope contains trailing bytes')
    }
    return [pscustomobject]@{ Arguments = [string[]]$decodedArguments.ToArray() }
  } finally {
    $reader.Dispose()
    $stream.Dispose()
  }
}

function Get-CrgCommitArgumentEnvelopeDigest {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][byte[]]$Envelope)

  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try { [byte[]]$hashBytes = $sha256.ComputeHash($Envelope) }
  finally { $sha256.Dispose() }
  return (($hashBytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-CrgCommitArgumentTransportMetadata {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$MappingName,
    [AllowNull()][string]$LengthText,
    [AllowNull()][string]$Digest
  )

  $regexOptions = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
  if ([string]::IsNullOrEmpty($MappingName) -or
      -not [System.Text.RegularExpressions.Regex]::IsMatch(
        $MappingName,
        '\ALocal\\crg-commit-arguments-v1-[0-9a-f]{32}\z',
        $regexOptions
      )) {
    throw [System.FormatException]::new('commit argument mapping name is malformed')
  }
  $length = 0
  if ([string]::IsNullOrEmpty($LengthText) -or
      -not [int]::TryParse(
        $LengthText,
        [System.Globalization.NumberStyles]::None,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$length
      ) -or $length -lt 16 -or $length -gt $script:CrgCommitArgumentEnvelopeMaxBytes -or
      -not [string]::Equals(
        $LengthText,
        $length.ToString([System.Globalization.CultureInfo]::InvariantCulture),
        [System.StringComparison]::Ordinal
      )) {
    throw [System.FormatException]::new('commit argument mapping length is malformed or out of bounds')
  }
  if ([string]::IsNullOrEmpty($Digest) -or
      -not [System.Text.RegularExpressions.Regex]::IsMatch($Digest, '\A[0-9a-f]{64}\z', $regexOptions)) {
    throw [System.FormatException]::new('commit argument mapping digest is malformed')
  }
  return [pscustomobject]@{
    MappingName = $MappingName
    Length = $length
    LengthText = $LengthText
    Digest = $Digest
  }
}

function New-CrgCommitArgumentTransport {
  [CmdletBinding()]
  param([AllowNull()][string[]]$ForwardArgs)

  [byte[]]$envelope = ConvertTo-CrgCommitArgumentEnvelope -ForwardArgs $ForwardArgs
  $digest = Get-CrgCommitArgumentEnvelopeDigest -Envelope $envelope
  $mapping = $null
  $mappingName = $null
  $lastCollision = $null
  for ($attempt = 0; $attempt -lt 16 -and $null -eq $mapping; $attempt++) {
    $mappingName = 'Local\crg-commit-arguments-v1-' + [guid]::NewGuid().ToString('N')
    try {
      $mapping = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew(
        $mappingName,
        [long]$envelope.Length,
        [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite
      )
    } catch [System.IO.IOException] {
      $lastCollision = $_.Exception
    }
  }
  if ($null -eq $mapping) {
    throw [System.InvalidOperationException]::new('could not create a unique commit argument mapping', $lastCollision)
  }
  try {
    $view = $mapping.CreateViewStream(0, $envelope.Length, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Write)
    try {
      $view.Write($envelope, 0, $envelope.Length)
      $view.Flush()
    } finally {
      $view.Dispose()
    }
    return [pscustomobject]@{
      Owner = $mapping
      MappingName = $mappingName
      LengthText = $envelope.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture)
      Digest = $digest
    }
  } catch {
    $mapping.Dispose()
    throw
  }
}

function Read-CrgCommitArgumentTransport {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$MappingName,
    [AllowNull()][string]$LengthText,
    [AllowNull()][string]$Digest
  )

  $metadata = Get-CrgCommitArgumentTransportMetadata -MappingName $MappingName -LengthText $LengthText -Digest $Digest
  [byte[]]$snapshot = New-Object byte[] $metadata.Length
  $mapping = $null
  $view = $null
  try {
    $mapping = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
      $metadata.MappingName,
      [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::Read
    )
    $view = $mapping.CreateViewStream(0, $metadata.Length, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read)
    $offset = 0
    while ($offset -lt $snapshot.Length) {
      $read = $view.Read($snapshot, $offset, $snapshot.Length - $offset)
      if ($read -le 0) {
        throw [System.IO.EndOfStreamException]::new('commit argument mapping ended before the declared length')
      }
      $offset += $read
    }
  } finally {
    if ($null -ne $view) { $view.Dispose() }
    if ($null -ne $mapping) { $mapping.Dispose() }
  }
  $actualDigest = Get-CrgCommitArgumentEnvelopeDigest -Envelope $snapshot
  if (-not [string]::Equals($actualDigest, $metadata.Digest, [System.StringComparison]::Ordinal)) {
    throw [System.Security.Cryptography.CryptographicException]::new('commit argument mapping digest does not match the private snapshot')
  }
  return ConvertFrom-CrgCommitArgumentEnvelope -Envelope $snapshot
}

function Invoke-CrgCommitEnvironmentProxy {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$MappingName,
    [Parameter(Mandatory=$true)][string]$LengthText,
    [Parameter(Mandatory=$true)][string]$Digest,
    [Parameter(Mandatory=$true)][ref]$ExitCode
  )
  $ExitCode.Value = 1
  [void](Get-CrgCommitArgumentTransportMetadata -MappingName $MappingName -LengthText $LengthText -Digest $Digest)
  $enginePath = Get-CrgPowerShellCliExecutablePath
  $workingDirectory = (Get-Location).ProviderPath
  if ([string]::IsNullOrWhiteSpace($workingDirectory) -or -not [System.IO.Directory]::Exists($workingDirectory)) {
    throw [System.InvalidOperationException]::new('the current filesystem working directory is unavailable')
  }
  [string[]]$childEnvironment = @(New-CrgCommitWorkerEnvironment)
  $commandLine = ConvertTo-CrgCommitProcessArgumentLine -ArgList (
    @(
      $enginePath, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
      $script:CrgCommitWorkerArgument, $MappingName, $LengthText, $Digest
    )
  )
  $session = $null
  $sessionWaitCompleted = $false
  try {
    $session = [CrgCommitEnvironment.NativeV1]::StartProcess(
      $enginePath,
      $commandLine,
      $workingDirectory,
      $childEnvironment
    )
    $ExitCode.Value = $session.CompleteRootAndCloseJob()
    $sessionWaitCompleted = $true
  } finally {
    try {
      if ($null -ne $session -and -not $sessionWaitCompleted) {
        try {
          $session.TerminateAndWait()
        } finally {
          $session.Dispose()
          $session = $null
        }
      }
    } finally {
      if ($null -ne $session) { $session.Dispose() }
    }
  }
}

function Invoke-CrgDedicatedCommitProcess {
  [CmdletBinding()]
  param(
    [AllowNull()][string[]]$ForwardArgs,
    [Parameter(Mandatory=$true)][ref]$ExitCode
  )
  $ExitCode.Value = 1
  $enginePath = Get-CrgPowerShellCliExecutablePath
  $transport = New-CrgCommitArgumentTransport -ForwardArgs $ForwardArgs
  $proxyExitCode = $null
  try {
    [string[]]$proxyArguments = @(
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
      $script:CrgCommitProxyArgument, $transport.MappingName, $transport.LengthText, $transport.Digest
    )
    $proxyCommandLine = ConvertTo-CrgCommitProcessArgumentLine -ArgList (@($enginePath) + $proxyArguments)
    if ($proxyCommandLine.Length -gt 32767) {
      throw [System.InvalidOperationException]::new('fixed commit proxy metadata exceeds the native command-line limit')
    }
    & $enginePath @proxyArguments
    $proxyExitCode = $LASTEXITCODE
  } finally {
    $transport.Owner.Dispose()
  }
  if ($null -eq $proxyExitCode) {
    throw [System.InvalidOperationException]::new('the commit environment proxy returned no process exit code')
  }
  $ExitCode.Value = [int]$proxyExitCode
}

# Verify the default dispatcher from one byte snapshot plus bootstrap's adjacent
# digest record. `core.hooksPath` is proved unset before the caller invokes this
# helper, so `git rev-parse --git-path hooks/pre-commit` names the hook the
# upcoming commit will execute. The record grammar is producer-owned and exact:
# two LF-terminated ASCII lines, a fixed v1 header and one lowercase SHA-256.
# This is a detective install-integrity check, matching run-gate.sh; the hook's
# own dispatcher chain remains the enforcement boundary after Git opens it.
function Get-CrgDefaultHookAttestation {
  param([AllowNull()][string]$HookPath)
  if ([string]::IsNullOrWhiteSpace($HookPath)) {
    return @{ Ok = $false; State = 'indeterminate'; Reason = 'the default pre-commit hook path is empty or indeterminate' }
  }
  try {
    if (-not (Test-Path -LiteralPath $HookPath -PathType Leaf)) {
      return @{ Ok = $false; State = 'missing-hook'; Reason = "no pre-commit dispatcher exists at the default hooks path '$HookPath'" }
    }
    $hookItem = Get-Item -LiteralPath $HookPath -Force -ErrorAction Stop
    if (($hookItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      return @{ Ok = $false; State = 'foreign-hook'; Reason = "the pre-commit dispatcher at '$HookPath' is a reparse point rather than an ordinary file" }
    }
    $hookBytes = [System.IO.File]::ReadAllBytes($HookPath)
    if ($hookBytes.Length -lt 2 -or $hookBytes[0] -ne 0x23 -or $hookBytes[1] -ne 0x21) {
      return @{ Ok = $false; State = 'foreign-hook'; Reason = "the pre-commit dispatcher at '$HookPath' does not begin with a shebang (disarmed or foreign bytes)" }
    }
    $hookText = [System.Text.Encoding]::ASCII.GetString($hookBytes)
    if ($hookText.IndexOf('crg-gate-untrack-guard-v1', [System.StringComparison]::Ordinal) -lt 0) {
      return @{ Ok = $false; State = 'foreign-hook'; Reason = "the pre-commit dispatcher at '$HookPath' lacks the crg-gate-untrack-guard-v1 capability marker" }
    }

    $digestPath = "$HookPath.crg-sha256"
    if (-not (Test-Path -LiteralPath $digestPath -PathType Leaf)) {
      return @{ Ok = $false; State = 'missing-attestation'; Reason = "no dispatcher attestation exists at '$digestPath'" }
    }
    $digestItem = Get-Item -LiteralPath $digestPath -Force -ErrorAction Stop
    if (($digestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      return @{ Ok = $false; State = 'malformed-attestation'; Reason = "the dispatcher attestation at '$digestPath' is a reparse point rather than an ordinary file" }
    }
    $digestBytes = [System.IO.File]::ReadAllBytes($digestPath)
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes("crg-dispatcher-digest v1`n")
    $expectedLength = $headerBytes.Length + 64 + 1
    $grammarOk = ($digestBytes.Length -eq $expectedLength)
    if ($grammarOk) {
      for ($i = 0; $i -lt $headerBytes.Length; $i++) {
        if ($digestBytes[$i] -ne $headerBytes[$i]) { $grammarOk = $false; break }
      }
    }
    $digestChars = New-Object char[] 64
    if ($grammarOk) {
      for ($i = 0; $i -lt 64; $i++) {
        $b = $digestBytes[$headerBytes.Length + $i]
        if (-not (($b -ge 0x30 -and $b -le 0x39) -or ($b -ge 0x61 -and $b -le 0x66))) {
          $grammarOk = $false; break
        }
        $digestChars[$i] = [char]$b
      }
    }
    if ($grammarOk -and $digestBytes[$expectedLength - 1] -ne 0x0A) { $grammarOk = $false }
    if (-not $grammarOk) {
      return @{ Ok = $false; State = 'malformed-attestation'; Reason = "the dispatcher attestation at '$digestPath' is not the exact bootstrap v1 two-line LF-only record" }
    }
    $expectedDigest = -join $digestChars
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $actualBytes = $sha.ComputeHash($hookBytes) } finally { $sha.Dispose() }
    $actualDigest = (($actualBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    if (-not [string]::Equals($actualDigest, $expectedDigest, [System.StringComparison]::Ordinal)) {
      return @{ Ok = $false; State = 'digest-mismatch'; Reason = "the pre-commit dispatcher at '$HookPath' does not hash to the bootstrap-recorded digest in '$digestPath'" }
    }
    return @{ Ok = $true; State = 'verified'; Reason = '' }
  } catch {
    return @{ Ok = $false; State = 'indeterminate'; Reason = "default dispatcher attestation could not be verified: $($_.Exception.Message)" }
  }
}

if ($args.Count -ge 1 -and
    [string]::Equals([string]$args[0], $script:CrgCommitProxyArgument, [System.StringComparison]::Ordinal)) {
  if (-not (Test-CrgCommitWorkerCommandTarget)) {
    Write-Error 'scripts/claude/commit.ps1: ABORT -- the commit environment proxy requires an exact PowerShell -File invocation of this wrapper.'
    exit 1
  }
  if ($args.Count -ne 4) {
    Write-Error 'scripts/claude/commit.ps1: ABORT -- the commit environment proxy mapping descriptor is malformed.'
    exit 1
  }
  $proxyExitCode = 1
  try {
    Invoke-CrgCommitEnvironmentProxy `
      -MappingName ([string]$args[1]) `
      -LengthText ([string]$args[2]) `
      -Digest ([string]$args[3]) `
      -ExitCode ([ref]$proxyExitCode)
  }
  catch {
    Write-Error "scripts/claude/commit.ps1: ABORT -- the commit environment proxy failed ($($_.Exception.Message))."
    exit 1
  }
  exit $proxyExitCode
}

try { $crgCommitWorker = Test-CrgCommitWorkerProcess }
catch {
  Write-Error "scripts/claude/commit.ps1: ABORT -- commit-worker authority is invalid ($($_.Exception.Message))."
  exit 1
}
if (-not $crgCommitWorker) {
  $dedicatedCommitExit = 1
  try { Invoke-CrgDedicatedCommitProcess -ForwardArgs $args -ExitCode ([ref]$dedicatedCommitExit) }
  catch {
    Write-Error "scripts/claude/commit.ps1: ABORT -- could not establish the dedicated commit-process boundary ($($_.Exception.Message))."
    exit 1
  }
  exit $dedicatedCommitExit
}

if ($args.Count -ne 4 -or
    -not [string]::Equals([string]$args[0], $script:CrgCommitWorkerArgument, [System.StringComparison]::Ordinal)) {
  Write-Error 'scripts/claude/commit.ps1: ABORT -- authenticated commit-worker argument transport is missing or malformed.'
  exit 1
}
try {
  $workerTransport = Read-CrgCommitArgumentTransport `
    -MappingName ([string]$args[1]) `
    -LengthText ([string]$args[2]) `
    -Digest ([string]$args[3])
  $args = [string[]]@($workerTransport.Arguments)
} catch {
  Write-Error "scripts/claude/commit.ps1: ABORT -- authenticated commit-worker arguments are invalid ($($_.Exception.Message))."
  exit 1
}

$crgGitSelectorKeys = @(Get-CrgGitSelectorEnvironmentKeys)
if ($crgGitSelectorKeys.Count -ne 0) {
  Write-Error 'scripts/claude/commit.ps1: ABORT -- an ambient Git selector is present (repository/object/ref/index, history, attribute, or config-override family; case-insensitive, including empty values); this direct wrapper binds the current worktree and refuses before the first Git command.'
  exit 1
}

# Apply bypass check via the shared Test-Bypass-Args function.
$bypassResult = Test-Bypass-Args -ArgList $args
if ($bypassResult.Bypass) {
  Write-Error "scripts/claude/commit.ps1: refusing $($bypassResult.Offending) -- this wrapper exists to enforce cross-review routing; --no-verify / -n / clustered -n* short options / --no-v[erify] prefix abbreviations would bypass the pre-commit hook entirely. Use CROSS_REVIEW_SKIP=1 (audited per your project's AGENTS.md) for the documented skip path; never --no-verify."
  exit 1
}

$prevBackend = [Environment]::GetEnvironmentVariable('REVIEW_BACKEND')
$prevBackendWasSet = $null -ne $prevBackend

function Enable-GitUnixToolPathForHook {
  # Git for Windows can hand POSIX hooks a duplicate PATH surface where the
  # stale uppercase entry wins over PowerShell's Path edits. Normalize BOTH
  # spellings to one process PATH (via Get-UnionProcessPathParts below) and prepend
  # Git's Unix tools so the dispatcher can resolve mktemp/env/find/rm under
  # PowerShell-launched commits.
  $candidates = @()
  $gitCmd = Get-Command git -ErrorAction SilentlyContinue
  if ($gitCmd -and -not [string]::IsNullOrWhiteSpace($gitCmd.Source)) {
    $gitExeDir = Split-Path -Parent $gitCmd.Source
    $gitRoot = Split-Path -Parent $gitExeDir
    if (-not [string]::IsNullOrWhiteSpace($gitRoot)) {
      $candidates += (Join-Path $gitRoot 'usr\bin')
      $candidates += (Join-Path $gitRoot 'bin')
    }
  }
  if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
    $candidates += (Join-Path $env:ProgramFiles 'Git\usr\bin')
    $candidates += (Join-Path $env:ProgramFiles 'Git\bin')
  }

  # Existence-filter the discovered candidates (I/O), then assemble the deduped-
  # prepended parts via the pure Get-UnionProcessPathParts. The
  # effective lookup order stays first; deterministic raw-only additions preserve
  # dirs hidden behind extra PATH case variants.
  $existingCandidates = @($candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Container) })
  $pathParts = Get-UnionProcessPathParts -Spellings (Get-ProcessPathSpellings) -CandidateDirs $existingCandidates
  # Side-effect only (mutates Env:PATH); the caller captures the ORIGINAL PATH
  # BEFORE invoking this -- inside its restore-covered try -- and restores it in
  # the finally. The Unix-tool prepend is only needed WHILE the hook runs; leaving
  # it mutated would leak into the dedicated worker's later operations, same
  # class as the REVIEW_BACKEND restore. An empty $pathParts
  # is indeterminate and fails closed. Mirrors scripts/codex/commit.ps1
  # and auto-merge.ps1's Normalize-ProcessPathEnvForStartProcess (caller owns save/restore).
  if ($pathParts.Count -eq 0) { throw [System.InvalidOperationException]::new('no non-empty process PATH value is available to prepare') }
  $joinedPath = [string]::Join([System.IO.Path]::PathSeparator, $pathParts)
  Set-CanonicalProcessPathEnvironment -Value $joinedPath
}

# Capture the ORIGINAL process PATH BEFORE the try so the finally can restore it
# even if Enable-GitUnixToolPathForHook throws MID-mutation (a partial Env:PATH
# edit would otherwise leak into the caller). Enable-... is invoked INSIDE the try
# below -- NOT here -- so a PATH-prep failure runs the restore finally and cannot
# leak REVIEW_BACKEND or a partial PATH mutation into
# later worker operations. Mirrors auto-merge.ps1's
# save-before-try discipline around Normalize-ProcessPathEnvForStartProcess. The
# capture preserves the effective lookup order first and appends deterministic
# raw-only additions so the finally restores every directory without changing
# which executable wins.
$savedProcessPath = (Get-UnionProcessPathParts -Spellings (Get-ProcessPathSpellings)) -join [System.IO.Path]::PathSeparator
$env:REVIEW_BACKEND = 'codex'
try {
  # The native-invoked proxy established replacement suppression in this worker's child
  # environment. Re-verify every trampoline singleton before the first Git command.
  [string[]]$commitEnvironment = @(Get-CrgRawCommitEnvironmentEntries)
  Assert-CrgRawCommitEnvironmentSingleton -Entries $commitEnvironment -Name 'GIT_NO_REPLACE_OBJECTS' -Value '1'
  Assert-CrgRawCommitEnvironmentSingleton -Entries $commitEnvironment -Name $script:CrgCommitWorkerMarker -Value '1'
  Assert-CrgRawCommitPathSingleton -Entries $commitEnvironment

  # Prepare the Git Unix-tool PATH for the pre-commit dispatcher, INSIDE this
  # restore-covered try: a throw here runs the finally (restoring
  # REVIEW_BACKEND + PATH) before the abort propagates.
  Enable-GitUnixToolPathForHook

  # PRIMARY config-redirect guard: validate the EFFECTIVE core.hooksPath.
  # Raw direct-entry refusal above covers the GIT_CONFIG override family. Git
  # still resolves ordinary config through HOME / XDG_CONFIG_HOME, which must
  # remain available for commit identity. `git config --get core.hooksPath` reads the
  # effective value honoring EVERY config source the upcoming `git commit`
  # will use, so it catches a redirect from any of them. This gate requires
  # core.hooksPath UNSET so the per-clone `.git/hooks/pre-commit` dispatcher
  # fires; ANY set value can redirect the hook to a no-op dir and bypass
  # review (while REVIEW_BACKEND looks correct and no CROSS_REVIEW_SKIP audit
  # entry is written). Refuse to commit if it is set -- one check closes the
  # whole config-redirect class. core.hooksPath lives in shared repo config,
  # so this passes identically in the main checkout and linked worktrees
  # (both leave it unset). Symmetric with scripts/codex/commit.ps1.
  #
  # This guard runs INSIDE the try so the finally below restores
  # REVIEW_BACKEND and PATH even when the guard aborts.
  $effectiveHooksPath = (& git config --get core.hooksPath 2>$null)
  $hooksPathExit = $LASTEXITCODE
  # Exit-status decides this, NOT stdout: the mapping lives in the shared,
  # Resolve-HooksPathGuard (exit 1 = unset -> proceed; exit 0
  # = set to ANY value incl. an empty `core.hooksPath=` -> abort; other = git
  # error -> fail closed). A stdout-only check (IsNullOrWhiteSpace) would let a
  # set-empty value (exit 0, empty stdout) slip through.
  switch (Resolve-HooksPathGuard -ExitCode $hooksPathExit) {
    'abort-set' {
      Write-Error "scripts/claude/commit.ps1: ABORT -- core.hooksPath is SET (value: '$effectiveHooksPath'); this gate requires it UNSET so the .git/hooks/pre-commit dispatcher fires. A set value (incl. empty, or one from ordinary HOME/XDG/global/system configuration) can redirect the pre-commit hook to a no-op dir and bypass review. Unset it (git config --unset core.hooksPath) or investigate the config source."
      exit 1
    }
    'abort-indeterminate' {
      Write-Error "scripts/claude/commit.ps1: ABORT -- 'git config --get core.hooksPath' exited $hooksPathExit (neither 0=set nor 1=unset); failing closed rather than committing with an indeterminate hook-path state."
      exit 1
    }
  }

  # `core.hooksPath` is now proved unset. Resolve the exact default hook name
  # Git will use, then attest the installed dispatcher before crossing the
  # production commit boundary. Relative `--git-path` output is anchored to
  # PowerShell's current filesystem location explicitly; .NET's process current
  # directory does not reliably follow Set-Location in Windows PowerShell.
  $defaultHookRows = @(& git rev-parse --git-path hooks/pre-commit 2>$null)
  $defaultHookExit = $LASTEXITCODE
  if ($defaultHookExit -ne 0 -or $defaultHookRows.Count -ne 1 -or
      [string]::IsNullOrWhiteSpace([string]$defaultHookRows[0])) {
    Write-Error "scripts/claude/commit.ps1: ABORT -- 'git rev-parse --git-path hooks/pre-commit' did not resolve exactly one default dispatcher path (exit=$defaultHookExit, rows=$($defaultHookRows.Count)); refusing to commit with an indeterminate hook identity."
    exit 1
  }
  try {
    $defaultHookText = [string]$defaultHookRows[0]
    $currentFileSystemPath = (Get-Location).ProviderPath
    if ([string]::IsNullOrWhiteSpace($currentFileSystemPath)) {
      throw 'the current PowerShell location has no filesystem provider path'
    }
    if ([System.IO.Path]::IsPathRooted($defaultHookText)) {
      $defaultHookPath = [System.IO.Path]::GetFullPath($defaultHookText)
    } else {
      $defaultHookPath = [System.IO.Path]::GetFullPath((Join-Path -Path $currentFileSystemPath -ChildPath $defaultHookText))
    }
  } catch {
    Write-Error "scripts/claude/commit.ps1: ABORT -- the resolved default dispatcher path could not be normalized ($($_.Exception.Message)); refusing to commit with an indeterminate hook identity."
    exit 1
  }
  $defaultHookAttestation = Get-CrgDefaultHookAttestation -HookPath $defaultHookPath
  if (-not $defaultHookAttestation.Ok) {
    Write-Error "scripts/claude/commit.ps1: ABORT -- default dispatcher attestation is $($defaultHookAttestation.State): $($defaultHookAttestation.Reason); refusing to commit un-gated. Investigate a digest mismatch first per docs/audit-protocol.md; repair the installation afterward with bootstrap.ps1 -DispatcherOnly."
    exit 1
  }
  & git commit @args
  $gitExit = $LASTEXITCODE
} catch {
  # A controlled-Git-environment or PATH-prep failure reaches here; the finally
  # below still restores the environment, then the commit aborts with exit 1.
  Write-Error "scripts/claude/commit.ps1: ABORT -- failed to prepare the controlled Git environment or Unix-tool PATH for the pre-commit dispatcher ($($_.Exception.Message))."
  $gitExit = 1
} finally {
  if ($prevBackendWasSet) {
    try { $env:REVIEW_BACKEND = $prevBackend }
    catch { Write-Warning "scripts/claude/commit.ps1: failed to restore REVIEW_BACKEND='$prevBackend' ($($_.Exception.Message))." }
  } else {
    try { Remove-Item -LiteralPath Env:REVIEW_BACKEND -ErrorAction Stop }
    catch { Write-Warning "scripts/claude/commit.ps1: failed to clear REVIEW_BACKEND ($($_.Exception.Message))." }
  }
  # Restore the pre-Enable PATH (the Unix-tool prepend was only for the hook).
  # Skip on an empty original (a capture failure, not a real empty PATH). Mirrors
  # scripts/codex/commit.ps1.
  if (-not [string]::IsNullOrEmpty($savedProcessPath)) {
    try {
      Set-CanonicalProcessPathEnvironment -Value $savedProcessPath
    } catch { Write-Warning "scripts/claude/commit.ps1: failed to restore PATH after the commit ($($_.Exception.Message)); later commands in this shell may retain the Git-Unix-tool-prepended PATH." }
  }
}
exit $gitExit
