# bootstrap.ps1 - central runtime operations for cross-review-gate: publish a
# release into a runtime store from an approved source commit or an approved
# portable package, install or upgrade the store's stable launcher, and
# activate a published release. The operator procedure is
# docs/central-deployment-v1.md.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -PublishRuntime -RuntimeStore <store> -SourceRoot <source-root> -ApprovedSourceCommit <oid>
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -PublishRuntime -RuntimeStore <store> -ReleasePackage <release-dir> -ApprovedManifestSha256 <sha256>
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -InstallRuntimeLauncher -RuntimeStore <store> -ReleaseId <release-id>
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -UpgradeRuntimeLauncher -RuntimeStore <store> -ReleaseId <release-id>
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -ActivateRuntime -RuntimeStore <store> -ReleaseId <release-id>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimeSource')]
  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimePackage')]
  [switch]$PublishRuntime,

  [Parameter(Mandatory = $true, ParameterSetName = 'ActivateRuntime')]
  [switch]$ActivateRuntime,

  [Parameter(Mandatory = $true, ParameterSetName = 'InstallRuntimeLauncher')]
  [switch]$InstallRuntimeLauncher,

  [Parameter(Mandatory = $true, ParameterSetName = 'UpgradeRuntimeLauncher')]
  [switch]$UpgradeRuntimeLauncher,

  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimeSource')]
  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimePackage')]
  [Parameter(Mandatory = $true, ParameterSetName = 'ActivateRuntime')]
  [Parameter(Mandatory = $true, ParameterSetName = 'InstallRuntimeLauncher')]
  [Parameter(Mandatory = $true, ParameterSetName = 'UpgradeRuntimeLauncher')]
  [string]$RuntimeStore,

  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimeSource')]
  [string]$SourceRoot,
  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimeSource')]
  [string]$ApprovedSourceCommit,

  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimePackage')]
  [string]$ReleasePackage,
  [Parameter(Mandatory = $true, ParameterSetName = 'PublishRuntimePackage')]
  [string]$ApprovedManifestSha256,

  [Parameter(Mandatory = $true, ParameterSetName = 'ActivateRuntime')]
  [Parameter(Mandatory = $true, ParameterSetName = 'InstallRuntimeLauncher')]
  [Parameter(Mandatory = $true, ParameterSetName = 'UpgradeRuntimeLauncher')]
  [string]$ReleaseId
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell's Process.Start builds a redirected child's input writer
# from the cached [Console]::InputEncoding, and PowerShell decodes native
# output with the cached [Console]::OutputEncoding. The public setters also
# set the code page of the console window this process shares with the
# invoking shell, and a process killed before putting it back leaves that
# console changed, so the private cache field is set instead: the change stays
# in this process, and passing back the returned prior value (null when the
# cache was never filled) restores the earlier state exactly. For output, a
# redirected standard stream's writer that was not replaced through SetOut or
# SetError is flushed and dropped, as the setter drops it, so it is rebuilt
# with the new encoding for whoever reads the pipe. A stream attached to the
# console keeps a writer in the console's own code page, created now if it
# does not exist yet: that code page does not change, so a writer rebuilt in
# the new encoding would garble non-ASCII text there. These scripts read
# standard input only as a raw stream, never through Console.In, so the input
# reader is left alone. The fields are private (_name in .NET Framework,
# s_name in .NET Core), so a runtime with neither is refused rather than
# changing the console in their place. Several scripts carry an identical
# copy.
function Set-CrgProcessConsoleEncoding {
  param([switch]$ConsoleInput, [System.Text.Encoding]$Encoding)
  $flags = [System.Reflection.BindingFlags]'NonPublic, Static'
  $name = if ($ConsoleInput) { 'inputEncoding' } else { 'outputEncoding' }
  $prefix = @('_', 's_') | Where-Object { $null -ne [Console].GetField($_ + $name, $flags) } | Select-Object -First 1
  if ($null -eq $prefix) { throw "this .NET runtime has no private console $name cache to set" }
  $field = [Console].GetField($prefix + $name, $flags)
  $streams = @()
  if (-not $ConsoleInput) {
    foreach ($spec in @(@('out', 'isOutTextWriterRedirected', 'Out', [Console]::IsOutputRedirected), @('error', 'isErrorTextWriterRedirected', 'Error', [Console]::IsErrorRedirected))) {
      $writer = [Console].GetField($prefix + $spec[0], $flags)
      $replaced = [Console].GetField($prefix + $spec[1], $flags)
      if ($null -eq $writer -or $null -eq $replaced) { throw "this .NET runtime has no private console $($spec[0]) writer to rebuild" }
      $streams += [pscustomobject]@{ Writer = $writer; Replaced = $replaced; Property = $spec[2]; Redirected = [bool]$spec[3] }
    }
  }
  $prior = $field.GetValue($null)
  foreach ($stream in $streams) {
    if ($stream.Redirected) {
      $current = $stream.Writer.GetValue($null)
      if ($null -ne $current -and -not [bool]$stream.Replaced.GetValue($null)) {
        $current.Flush()
        $stream.Writer.SetValue($null, $null)
      }
    } else { $null = [Console]::($stream.Property) }
  }
  $field.SetValue($null, $Encoding)
  return $prior
}

# A write-only stream that keeps the first bytes up to its limit and discards
# the rest, so a Git child copying its stderr into it never blocks on a full
# pipe and never makes the capture buffer more than the limit. Exceeded means
# bytes were discarded: once the copy has finished, every caller refuses an
# exceeded capture whatever the exit code, since a short or empty capture
# alone never shows that nothing was discarded. Several scripts carry their
# own copy under the same name and one process can load more than one, so
# whichever compiles first serves them all: a change to its members needs a
# new type name, and each copy refuses a loaded type that lacks a member it
# calls.
function Initialize-CrgBoundedSinkNative {
  if (-not ('CrgBoundedCapture.SinkV1' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @'
namespace CrgBoundedCapture {
  using System;
  using System.IO;

  public sealed class SinkV1 : Stream {
    private readonly MemoryStream kept = new MemoryStream();
    private readonly long limit;
    private bool exceeded;

    public SinkV1(long limit) {
      if (limit < 0) { throw new ArgumentOutOfRangeException("limit"); }
      this.limit = limit;
    }

    public bool Exceeded { get { lock (kept) { return exceeded; } } }

    public byte[] ToArray() { lock (kept) { return kept.ToArray(); } }

    public override void Write(byte[] buffer, int offset, int count) {
      lock (kept) {
        if (exceeded) { return; }
        long room = limit - kept.Length;
        if (count > room) {
          kept.Write(buffer, offset, (int)room);
          exceeded = true;
          return;
        }
        kept.Write(buffer, offset, count);
      }
    }

    public override bool CanRead { get { return false; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return true; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }
  }
}
'@
    if (-not ('CrgBoundedCapture.SinkV1' -as [type])) { throw 'the bounded capture stream could not be compiled' }
  }
  $sinkType = [CrgBoundedCapture.SinkV1]
  if ($null -eq $sinkType.GetConstructor([type[]]@([long])) -or $null -eq $sinkType.GetProperty('Exceeded') -or $null -eq $sinkType.GetMethod('ToArray')) {
    throw 'a loaded CrgBoundedCapture.SinkV1 lacks a member this copy calls; a changed copy needs a new type name'
  }
}

# Whether a started Git child has exited and every holder of its output pipes
# has closed them. The root's exit alone does not show that: Git for
# Windows' launcher can be stopped while its worker, which inherits the pipes
# and holds them until it exits, runs on. Stdout and stderr reach end of file
# only once every holder of their write ends has closed them; a process that
# holds neither pipe is outside what this shows. The stop is
# attempted first, whatever follows: the root is killed and its input closed,
# so a child waiting for more input can end. A stdout read the caller
# abandoned (PendingRead) must settle before stdout is drained, since a
# stream takes one read at a time; then a stream whose copy was never started
# is drained, and the root's exit and both copies' completion at end of file
# are awaited, each within the bound. A wait that runs out, a copy that ended
# in a read error, or a probe that throws returns $false; the caller then
# keeps what the child could be using and raises the failure as uncertain.
# Every copy of this function must stay byte-identical.
function Test-CrgGitChildQuiescent {
  param([System.Diagnostics.Process]$Process, [object]$OutputCopy, [object]$ErrorCopy, [object]$PendingRead, [int]$Milliseconds = 2000)
  try {
    if (-not $Process.HasExited) { try { $Process.Kill() } catch { } }
    if ($Process.StartInfo.RedirectStandardInput) { try { $Process.StandardInput.Close() } catch { } }
    if ($null -ne $PendingRead) {
      try { if (-not $PendingRead.Wait($Milliseconds)) { return $false } } catch { }
    }
    if ($null -eq $OutputCopy) { $OutputCopy = $Process.StandardOutput.BaseStream.CopyToAsync([System.IO.Stream]::Null) }
    if ($null -eq $ErrorCopy) { $ErrorCopy = $Process.StandardError.BaseStream.CopyToAsync([System.IO.Stream]::Null) }
    if (-not $Process.WaitForExit($Milliseconds)) { return $false }
    $copies = [System.Threading.Tasks.Task[]]@($OutputCopy, $ErrorCopy)
    if (-not [System.Threading.Tasks.Task]::WaitAll($copies, $Milliseconds)) { return $false }
    foreach ($copy in $copies) { if ($copy.Status -ne [System.Threading.Tasks.TaskStatus]::RanToCompletion) { return $false } }
    return $true
  } catch { return $false }
}

# Once one Git child cannot be confirmed ended, which child used which owner
# is not tracked, so for the rest of this process no owner of what Git
# children read is released. Those owners (private scratch contexts, the
# rooted namespace, the runtime lock, and the source and release holds) are
# released only by Close-CrgPrivateAttributeContext and the cleanup of
# Invoke-CrgCentralRuntimeOperation; while this list exists, the context close
# keeps the context and refuses, and the cleanup keeps the owners here until
# exit. The uncertain process and failure are kept here too.
function Add-CrgUncertainGitOwner {
  param([object]$Owner)
  if ($null -eq $script:CrgUncertainGitOwners) { $script:CrgUncertainGitOwners = New-Object 'System.Collections.Generic.List[object]' }
  $script:CrgUncertainGitOwners.Add($Owner)
}

# The first retained uncertain failure's original cause, for reports that
# would otherwise not name it.
function Get-CrgUncertainGitCause {
  $ucFailure = @($script:CrgUncertainGitOwners | ForEach-Object { $_.Failure } | Where-Object { $null -ne $_ })[0]
  if ($null -ne $ucFailure -and $null -ne $ucFailure.InnerException) { return $ucFailure.InnerException.Message }
  return "$($ucFailure.Message)"
}

# Live process state must come from the native Windows block. Managed
# environment dictionaries can collapse case-distinct names under PowerShell
# Core, while native Git consumes the raw ordered block.
function Initialize-CrgProcessNoReplaceEnvironmentNative {
  if ('CrgProcessNoReplaceEnvironment.NativeV1' -as [type]) { return }
  Add-Type -TypeDefinition @'
namespace CrgProcessNoReplaceEnvironment {
  using System;
  using System.Collections.Generic;
  using System.ComponentModel;
  using System.Runtime.InteropServices;

  public static class NativeV1 {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetEnvironmentStringsW();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeEnvironmentStringsW(IntPtr environmentBlock);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetEnvironmentVariableW(string name, string value);

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

    private static void ValidateName(string name) {
      if (String.IsNullOrEmpty(name) || name.IndexOf('\0') >= 0 || name.IndexOf('=') >= 0) {
        throw new ArgumentException("environment variable names must be non-empty, NUL-free, and '='-free", "name");
      }
    }

    private static void ValidateValue(string value) {
      if (value == null || value.IndexOf('\0') >= 0) {
        throw new ArgumentException("environment variable values must be non-null and NUL-free", "value");
      }
    }

    public static void SetProcessVariable(string name, string value) {
      ValidateName(name);
      ValidateValue(value);
      if (!SetEnvironmentVariableW(name, value)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetEnvironmentVariableW failed for " + name);
      }
    }

    public static void RemoveProcessVariable(string name) {
      ValidateName(name);
      if (!SetEnvironmentVariableW(name, null)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetEnvironmentVariableW removal failed for " + name);
      }
    }
  }
}
'@ -Language CSharp -ErrorAction Stop
  if (-not ('CrgProcessNoReplaceEnvironment.NativeV1' -as [type])) {
    throw [System.PlatformNotSupportedException]::new('raw Windows replacement-suppression environment support is unavailable')
  }
}

function Get-CrgRawProcessEnvironmentEntries {
  Initialize-CrgProcessNoReplaceEnvironmentNative
  $entries = [CrgProcessNoReplaceEnvironment.NativeV1]::ReadProcessEntries()
  if ($null -eq $entries) {
    throw [System.InvalidOperationException]::new('raw Windows environment enumeration returned null')
  }
  return [string[]]$entries
}

function ConvertFrom-CrgRawEnvironmentEntry {
  param([Parameter(Mandatory = $true)][string]$Entry)
  if ([string]::IsNullOrEmpty($Entry) -or $Entry.IndexOf([char]0) -ge 0) {
    throw [System.InvalidOperationException]::new('raw environment entries must be non-empty and NUL-free')
  }
  # [char] overloads: IndexOf(string) compares by culture.
  $separator = if ($Entry.StartsWith('=', [System.StringComparison]::Ordinal)) {
    $Entry.IndexOf([char]'=', 1)
  } else {
    $Entry.IndexOf([char]'=')
  }
  $minimum = if ($Entry.StartsWith('=', [System.StringComparison]::Ordinal)) { 1 } else { 0 }
  if ($separator -le $minimum) {
    throw [System.InvalidOperationException]::new('raw environment entry does not use name=value grammar')
  }
  return [pscustomobject]@{
    Name = $Entry.Substring(0, $separator)
    Value = $Entry.Substring($separator + 1)
  }
}

function Get-CrgNoReplaceRawEntries {
  param([AllowEmptyCollection()][string[]]$Entries)
  $matches = New-Object 'System.Collections.Generic.List[object]'
  foreach ($entry in @($Entries)) {
    $parsed = ConvertFrom-CrgRawEnvironmentEntry -Entry ([string]$entry)
    if ([string]::Equals($parsed.Name, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::OrdinalIgnoreCase)) {
      $matches.Add($parsed) | Out-Null
    }
  }
  return $matches.ToArray()
}

# Return every spelling from an explicit child-environment dictionary. Named
# process access is forbidden here; this helper is only for a materialized map
# that will itself become a child environment.
function Get-CrgNoReplaceObjectsEnvironmentKeys {
  param([Parameter(Mandatory = $true)][object]$Environment)
  if ($null -eq $Environment -or $null -eq $Environment.PSObject.Properties['Keys']) {
    throw [System.InvalidOperationException]::new('replacement-suppression environment enumeration is unavailable')
  }
  $nrKeys = New-Object 'System.Collections.Generic.List[string]'
  try {
    foreach ($nrKeyObject in @($Environment.Keys)) {
      if ($null -eq $nrKeyObject) { throw [System.InvalidOperationException]::new('replacement-suppression environment contains a null name') }
      $nrKey = [string]$nrKeyObject
      if ([string]::Equals($nrKey, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::OrdinalIgnoreCase)) {
        $nrKeys.Add($nrKey) | Out-Null
      }
    }
  } catch {
    throw [System.InvalidOperationException]::new('replacement-suppression environment could not be enumerated', $_.Exception)
  }
  return $nrKeys.ToArray()
}

# Collapse the live process block to exactly one canonical entry. Removal is a
# progress-checked loop because SetEnvironmentVariableW uses case-insensitive
# Windows lookup when duplicate spellings already exist; one call cannot prove
# which duplicate was removed. Every iteration re-enumerates the raw names, and
# the final read proves count, spelling, and value before any child launch.
function Set-CrgNoReplaceObjectsProcessSingleton {
  $nrReadRaw = { Get-CrgRawProcessEnvironmentEntries }
  $nrWriteRaw = {
    param([string]$Name, $Value)
    Initialize-CrgProcessNoReplaceEnvironmentNative
    if ($null -eq $Value) { [CrgProcessNoReplaceEnvironment.NativeV1]::RemoveProcessVariable($Name) }
    else { [CrgProcessNoReplaceEnvironment.NativeV1]::SetProcessVariable($Name, [string]$Value) }
  }
  while ($true) {
    try { [string[]]$nrBeforeEntries = @(& $nrReadRaw) }
    catch { throw [System.InvalidOperationException]::new('raw process-environment enumeration failed', $_.Exception) }
    $nrBeforeMatches = @(Get-CrgNoReplaceRawEntries -Entries $nrBeforeEntries)
    if ($nrBeforeMatches.Count -eq 0) { break }
    $nrRemoveName = [string]$nrBeforeMatches[0].Name
    try {
      $null = & $nrWriteRaw $nrRemoveName $null
    } catch {
      throw [System.InvalidOperationException]::new("could not remove inherited replacement-suppression spelling '$nrRemoveName'", $_.Exception)
    }
    try { [string[]]$nrAfterEntries = @(& $nrReadRaw) }
    catch { throw [System.InvalidOperationException]::new('raw process-environment enumeration failed', $_.Exception) }
    $nrAfterMatches = @(Get-CrgNoReplaceRawEntries -Entries $nrAfterEntries)
    if ($nrAfterMatches.Count -ge $nrBeforeMatches.Count) {
      throw [System.InvalidOperationException]::new("removing inherited replacement-suppression spelling '$nrRemoveName' made no raw-environment progress")
    }
  }
  try {
    $null = & $nrWriteRaw 'GIT_NO_REPLACE_OBJECTS' '1'
  } catch {
    throw [System.InvalidOperationException]::new('could not install canonical GIT_NO_REPLACE_OBJECTS=1', $_.Exception)
  }
  try { [string[]]$nrFinalEntries = @(& $nrReadRaw) }
  catch { throw [System.InvalidOperationException]::new('raw process-environment enumeration failed', $_.Exception) }
  $nrFinalMatches = @(Get-CrgNoReplaceRawEntries -Entries $nrFinalEntries)
  if ($nrFinalMatches.Count -ne 1 -or
      -not [string]::Equals([string]$nrFinalMatches[0].Name, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::Ordinal) -or
      -not [string]::Equals([string]$nrFinalMatches[0].Value, '1', [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new("canonical GIT_NO_REPLACE_OBJECTS postcondition failed (raw spelling count=$($nrFinalMatches.Count))")
  }
}

# ProcessStartInfo environments are independently constructed trust boundaries.
# Normalize and verify the completed dictionary instead of assuming that the
# parent singleton survived Clear(), allowlisting, or later overrides.
function Set-CrgNoReplaceObjectsChildEnvironmentSingleton {
  param([Parameter(Mandatory = $true)][object]$Environment)
  if ($null -eq $Environment -or $null -eq $Environment.PSObject.Properties['Keys']) {
    throw [System.InvalidOperationException]::new('child replacement-suppression environment is unavailable')
  }
  while ($true) {
    $nrBeforeKeys = @(Get-CrgNoReplaceObjectsEnvironmentKeys -Environment $Environment)
    if ($nrBeforeKeys.Count -eq 0) { break }
    $nrRemoveName = [string]$nrBeforeKeys[0]
    try { $null = $Environment.Remove($nrRemoveName) } catch {
      throw [System.InvalidOperationException]::new("could not remove child replacement-suppression spelling '$nrRemoveName'", $_.Exception)
    }
    $nrAfterKeys = @(Get-CrgNoReplaceObjectsEnvironmentKeys -Environment $Environment)
    if ($nrAfterKeys.Count -ge $nrBeforeKeys.Count) {
      throw [System.InvalidOperationException]::new("removing child replacement-suppression spelling '$nrRemoveName' made no environment progress")
    }
  }
  try { $Environment['GIT_NO_REPLACE_OBJECTS'] = '1' } catch {
    throw [System.InvalidOperationException]::new('could not install canonical GIT_NO_REPLACE_OBJECTS=1 in the child environment', $_.Exception)
  }
  $nrFinalKeys = @(Get-CrgNoReplaceObjectsEnvironmentKeys -Environment $Environment)
  if ($nrFinalKeys.Count -ne 1 -or
      -not [string]::Equals([string]$nrFinalKeys[0], 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::Ordinal) -or
      -not [string]::Equals([string]$Environment[$nrFinalKeys[0]], '1', [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new("child GIT_NO_REPLACE_OBJECTS postcondition failed (raw spelling count=$($nrFinalKeys.Count))")
  }
}

$script:CrgUtf8Strict = New-Object System.Text.UTF8Encoding($false, $true)

# The review wrappers and their support files every runtime release carries
# beside the central modules. The installed launcher refuses a release manifest
# that lacks the review entrypoints among them.
function Get-CrgCurrentFileList {
  return @(
    @{ Src = 'scripts/codex/auto-review.ps1';            Dst = 'scripts/codex/auto-review.ps1' },
    @{ Src = 'scripts/shared/author-lint.ps1';            Dst = 'scripts/shared/author-lint.ps1' },
    @{ Src = 'scripts/codex/review-prompt-template.md';  Dst = 'scripts/codex/review-prompt-template.md' },
    @{ Src = 'scripts/claude/auto-review.ps1';           Dst = 'scripts/claude/auto-review.ps1' },
    @{ Src = 'scripts/review-liveness.psm1';             Dst = 'scripts/review-liveness.psm1' },
    @{ Src = 'scripts/review-common.ps1';                Dst = 'scripts/review-common.ps1' },
    @{ Src = 'docs/audit-protocol.md';                   Dst = 'docs/audit-protocol.md' }
  )
}

function Convert-CrgWindowsProcessArgument {
  param([AllowEmptyString()][string]$Argument)
  if ($null -eq $Argument) { throw 'process argument cannot be null' }
  $qaEscaped = [regex]::Replace($Argument, '(\\*)"', '$1$1\"')
  $qaEscaped = [regex]::Replace($qaEscaped, '(\\+)$', '$1$1')
  return '"' + $qaEscaped + '"'
}

function Get-CrgGitObjectIdOfBytes {
  param([ValidatePattern('\A(?:blob|tree)\z', Options = 'None')][string]$Type, [byte[]]$Bytes, [ValidatePattern('\A(?:40|64)\z', Options = 'None')][int]$ObjectIdLength)
  if ($null -eq $Bytes) { throw 'Git object-ID calculation received null bytes' }
  $goHeader = [System.Text.Encoding]::ASCII.GetBytes("$Type $($Bytes.Length)`0")
  $goStream = New-Object System.IO.MemoryStream
  $goHash = if ($ObjectIdLength -eq 64) { [System.Security.Cryptography.SHA256]::Create() } else { [System.Security.Cryptography.SHA1]::Create() }
  try {
    $goStream.Write($goHeader, 0, $goHeader.Length)
    if ($Bytes.Length -gt 0) { $goStream.Write($Bytes, 0, $Bytes.Length) }
    $goStream.Position = 0
    return (([System.BitConverter]::ToString($goHash.ComputeHash($goStream))) -replace '-', '').ToLowerInvariant()
  } finally { $goHash.Dispose(); $goStream.Dispose() }
}

function Get-CrgGitLooseObjectBytes {
  param([ValidatePattern('\A(?:blob|tree)\z', Options = 'None')][string]$Type, [byte[]]$Bytes)
  if ($null -eq $Bytes) { throw 'Git loose-object encoding received null bytes' }
  $glHeader = [System.Text.Encoding]::ASCII.GetBytes("$Type $($Bytes.Length)`0")
  $glRaw = New-Object byte[] ($glHeader.Length + $Bytes.Length)
  [System.Array]::Copy($glHeader, 0, $glRaw, 0, $glHeader.Length)
  if ($Bytes.Length -gt 0) { [System.Array]::Copy($Bytes, 0, $glRaw, $glHeader.Length, $Bytes.Length) }
  $glOut = New-Object System.IO.MemoryStream
  try {
    # DeflateStream emits the raw DEFLATE payload on Windows PowerShell 5.
    # Git loose objects require the RFC 1950 zlib header and Adler-32 trailer.
    $glOut.WriteByte(0x78); $glOut.WriteByte(0x9C)
    $glDeflate = New-Object System.IO.Compression.DeflateStream($glOut, [System.IO.Compression.CompressionMode]::Compress, $true)
    try { $glDeflate.Write($glRaw, 0, $glRaw.Length) } finally { $glDeflate.Dispose() }
    [uint64]$glA = 1; [uint64]$glB = 0
    foreach ($glByte in $glRaw) { $glA = ($glA + $glByte) % 65521; $glB = ($glB + $glA) % 65521 }
    [uint64]$glAdler = ($glB -shl 16) -bor $glA
    foreach ($glShift in @(24, 16, 8, 0)) { $glOut.WriteByte([byte](($glAdler -shr $glShift) -band 0xFF)) }
    return ,([byte[]]$glOut.ToArray())
  } finally { $glOut.Dispose() }
}

function Invoke-CrgIsolatedGitProcess {
  param(
    [string]$IsoRoot,
    [string]$WorkDir,
    [string[]]$GitArgs,
    [byte[]]$InputBytes,
    [switch]$UseAmbientConfig,
    [switch]$UseAmbientAttributes,
    [hashtable]$ExtraEnvironment,
    # Every stdout capture is bounded. The default admits a filtered gate-file
    # checkout or an attribute listing over the gate's paths; a caller that
    # expects less passes a tighter bound.
    [ValidateRange(1, 16777216)][int64]$MaxOutputBytes = 16777216
  )
  $ipGit = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
  $ipPsi = New-Object System.Diagnostics.ProcessStartInfo
  $ipPsi.FileName = $ipGit
  $ipPsi.UseShellExecute = $false
  $ipPsi.RedirectStandardOutput = $true
  $ipPsi.RedirectStandardError = $true
  $ipPsi.RedirectStandardInput = ($null -ne $InputBytes)
  $ipPsi.CreateNoWindow = $true
  $ipPsi.WorkingDirectory = $WorkDir
  $null = $ipPsi.Environment
  $ipEnvironment = $ipPsi.Environment
  if ($null -eq $ipEnvironment) { throw 'could not materialize the isolated Git environment' }
  $ipEnvironment.Clear()
  $ipKeepNames = @('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP')
  if ($UseAmbientConfig) { $ipKeepNames += @('HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL') }
  foreach ($ipKeep in $ipKeepNames) {
    $ipValue = [Environment]::GetEnvironmentVariable($ipKeep)
    if ($null -ne $ipValue) { $ipEnvironment[$ipKeep] = $ipValue }
  }
  if (-not $UseAmbientConfig) {
    $ipEnvironment['HOME'] = Join-Path $IsoRoot 'no-home'
    $ipEnvironment['XDG_CONFIG_HOME'] = Join-Path $IsoRoot 'no-xdg'
    $ipEnvironment['GIT_CONFIG_NOSYSTEM'] = '1'
    $ipEnvironment['GIT_CONFIG_GLOBAL'] = 'NUL'
  }
  if (-not $UseAmbientAttributes) { $ipEnvironment['GIT_ATTR_NOSYSTEM'] = '1' }
  $ipEnvironment['GIT_OPTIONAL_LOCKS'] = '0'
  if ($null -ne $ExtraEnvironment) {
    foreach ($ipExtraName in $ExtraEnvironment.Keys) {
      if ("$ipExtraName" -cnotmatch '\A[A-Z][A-Z0-9_]*\z' -or $null -eq $ExtraEnvironment[$ipExtraName]) { throw "invalid isolated Git environment override '$ipExtraName'" }
      $ipEnvironment["$ipExtraName"] = "$($ExtraEnvironment[$ipExtraName])"
    }
  }
  Set-CrgNoReplaceObjectsChildEnvironmentSingleton -Environment $ipEnvironment
  $ipPsi.Arguments = (($GitArgs | ForEach-Object { Convert-CrgWindowsProcessArgument -Argument $_ }) -join ' ')
  Initialize-CrgBoundedSinkNative
  $ipErrors = New-Object CrgBoundedCapture.SinkV1 ([long]65536)
  $ipPriorConsoleInputEncoding = $null
  $ipSwitchedConsoleInput = $false
  $ipStandardInput = $null
  if ($null -ne $InputBytes -and $null -ne $ipPsi.PSObject.Properties['StandardInputEncoding']) {
    $ipPsi.StandardInputEncoding = New-Object System.Text.UTF8Encoding($false)
  } elseif ($null -ne $InputBytes) {
    # Windows PowerShell's .NET Framework ProcessStartInfo has no
    # StandardInputEncoding property. Process.StandardInput snapshots
    # Console.InputEncoding when its StreamWriter is created, so select a
    # no-preamble encoding in this process's cache only for that
    # construction and put it back before any Git input is written. A switch
    # or restore that fails is raised, not ended here: the callers' catches
    # fail closed and first name what they preserved, which an exit would
    # skip. A
    # restore failure is written through the host when it happens, since a
    # caller's catch can replace the raised message, and is raised only after
    # the child's exit is confirmed: its input writer was built before the
    # restore, so the child is unaffected. Tried and dropped: switching
    # through the [Console]::InputEncoding setter (2.6.4 and earlier), which
    # also set the shared console's input code page and left it changed when
    # this process was killed before the restore; killing the child on a
    # restore failure (staged review, 2026-10-10), which cannot confirm the
    # exit when the kill fails; ending the run with exit 1 from this helper
    # (2.6.1), which skipped the callers' catches and so left a file they had
    # moved aside unrestored and unnamed.
    $ipPriorConsoleInputEncoding = Set-CrgProcessConsoleEncoding -ConsoleInput -Encoding (New-Object System.Text.UTF8Encoding($false))
    $ipSwitchedConsoleInput = $true
  }
  $ipProcess = $null
  $ipErrCopy = $null; $ipConfirmed = $false; $ipFailure = $null
  $ipRestoreFailure = $null
  # Start sits inside the try whose finally confirms the exit, so no failure
  # after a successful start can bypass the confirmation.
  try {
    try {
      $ipProcess = [System.Diagnostics.Process]::Start($ipPsi)
      if ($null -ne $InputBytes) { $ipStandardInput = $ipProcess.StandardInput }
    } finally {
      if ($ipSwitchedConsoleInput) {
        try { $null = Set-CrgProcessConsoleEncoding -ConsoleInput -Encoding $ipPriorConsoleInputEncoding }
        catch {
          $ipRestoreFailure = $_.Exception.Message
          $Host.UI.WriteErrorLine("bootstrap.ps1: ERROR: could not put back the cached console input encoding around a Git start ($ipRestoreFailure).")
        }
      }
    }
    $ipErrCopy = $ipProcess.StandardError.BaseStream.CopyToAsync($ipErrors)
    if ($null -ne $InputBytes) {
      try {
        if ($InputBytes.Length -gt 0) { $ipStandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length) }
      } finally { $ipStandardInput.Close() }
    }
    $ipOutput = New-Object System.IO.MemoryStream
    try {
      $ipOutputBuffer = New-Object byte[] 8192
      $ipOutputExceeded = $false
      while (($ipOutputRead = $ipProcess.StandardOutput.BaseStream.Read($ipOutputBuffer, 0, $ipOutputBuffer.Length)) -gt 0) {
        if (($ipOutput.Length + $ipOutputRead) -gt $MaxOutputBytes) {
          $ipOutputExceeded = $true
          try { $ipProcess.Kill() } catch { }
          continue
        }
        if (-not $ipOutputExceeded) { $ipOutput.Write($ipOutputBuffer, 0, $ipOutputRead) }
      }
      if (-not $ipProcess.WaitForExit(10000)) { throw 'isolated Git closed its output but did not exit within 10 seconds' }
      if (-not $ipErrCopy.Wait(10000)) { throw 'isolated Git stderr did not reach end of file after the root exited' }
      $null = $ipErrCopy.GetAwaiter().GetResult()
      $ipConfirmed = $true
      $ipError = [System.Text.UTF8Encoding]::new($false).GetString($ipErrors.ToArray())
      if ($ipOutputExceeded) { throw "isolated Git stdout exceeded the $MaxOutputBytes-byte bound" }
      if ($ipErrors.Exceeded) { throw "isolated Git stderr exceeded the 65536-byte capture bound (exit $($ipProcess.ExitCode))" }
      [byte[]]$ipOutputBytes = $ipOutput.ToArray()
    } finally { $ipOutput.Dispose() }
    $ipOutputText = [System.Text.UTF8Encoding]::new($false).GetString($ipOutputBytes)
    $ipResult = [pscustomobject]@{ Exit = $ipProcess.ExitCode; Bytes = $ipOutputBytes; OutputText = $ipOutputText; ErrorText = $ipError; Text = ($ipOutputText + $ipError) }
  } catch { $ipFailure = $_.Exception; throw }
  finally {
    # A failure above can leave the child, or the worker of a stopped Git for
    # Windows launcher, running. A child Test-CrgGitChildQuiescent cannot
    # confirm is kept by Add-CrgUncertainGitOwner, with the uncertain failure
    # (original failure inside), before anything else can fail, and raised
    # instead of being released while it may still run. Exception.Data takes
    # only serializable values on Windows PowerShell 5.1, which a Process from
    # Process.Start is not, so Data carries the CrgUncertainGitChild key with
    # a marker value; readers test the key. The uncertain failure is raised
    # instead of a recorded restore failure, which was already written out.
    if ($null -ne $ipProcess) {
      if (-not $ipConfirmed -and -not (Test-CrgGitChildQuiescent -Process $ipProcess -OutputCopy $null -ErrorCopy $ipErrCopy)) {
        $ipUncertain = New-Object InvalidOperationException -ArgumentList "isolated Git cleanup could not confirm that the child exited and every holder of its output pipes closed them ($($ipFailure.Message))", $ipFailure
        Add-CrgUncertainGitOwner -Owner ([pscustomobject]@{ Process = $ipProcess; Failure = $ipUncertain })
        $ipUncertain.Data['CrgUncertainGitChild'] = $true
        throw $ipUncertain
      }
      $ipProcess.Dispose()
    }
    if ($null -ne $ipRestoreFailure) { throw "the cached console input encoding could not be put back around a Git start ($ipRestoreFailure)" }
  }
  return $ipResult
}

function Assert-CrgGitAttributeSourceCapability {
  param([string]$ScratchRoot, [string]$WorkDir)
  $acVersion = Invoke-CrgIsolatedGitProcess -IsoRoot $ScratchRoot -WorkDir $WorkDir -GitArgs @('version')
  if ($acVersion.Exit -ne 0 -or $acVersion.OutputText.Trim() -cnotmatch '\Agit version (?<major>[0-9]+)\.(?<minor>[0-9]+)(?:\.|\z)') {
    throw 'Git version could not be classified for immutable attribute-source support'
  }
  $acMajor = [int]$Matches['major']; $acMinor = [int]$Matches['minor']
  if ($acMajor -lt 2 -or ($acMajor -eq 2 -and $acMinor -lt 41)) {
    throw "Git $acMajor.$acMinor is too old for immutable --attr-source plus hash-object --stdin conversion; Git 2.41 or newer is required"
  }
}

function Invoke-CrgIsolatedPackageGit {
  param([string]$Root, [string[]]$GitArgs, [byte[]]$InputBytes, [switch]$UseAmbientConfig)
  $pkArgs = @('--no-optional-locks', '-C', $Root) + @($GitArgs)
  return Invoke-CrgIsolatedGitProcess -IsoRoot $Root -WorkDir $Root -GitArgs $pkArgs -InputBytes $InputBytes -UseAmbientConfig:$UseAmbientConfig
}

function Invoke-CrgCapturedPackageGit {
  param([object]$Candidate, [string[]]$GitArgs, [byte[]]$InputBytes, [switch]$UseAmbientConfig, [int64]$MaxOutputBytes = 16777216)
  if ($null -eq $Candidate -or [string]::IsNullOrWhiteSpace("$($Candidate.GitDir)") -or [string]::IsNullOrWhiteSpace("$($Candidate.Root)")) { throw 'captured package Git invocation received no retained namespace' }
  $pkArgs = @('--no-optional-locks', "--git-dir=$($Candidate.GitDir)", "--work-tree=$($Candidate.Root)") + @($GitArgs)
  return Invoke-CrgIsolatedGitProcess -IsoRoot $Candidate.Root -WorkDir $Candidate.Root -GitArgs $pkArgs -InputBytes $InputBytes -UseAmbientConfig:$UseAmbientConfig -ExtraEnvironment @{ GIT_COMMON_DIR = "$($Candidate.CommonDir)" } -MaxOutputBytes $MaxOutputBytes
}

function Get-CrgPackageProvenanceCandidate {
  param([string]$Root)
  try {
    $pcTop = Invoke-CrgIsolatedPackageGit -Root $Root -GitArgs @('rev-parse', '--show-toplevel')
    if ($pcTop.Exit -ne 0 -or $pcTop.ErrorText.Length -ne 0 -or @($pcTop.OutputText -split "`r?`n" | Where-Object { $_.Length -gt 0 }).Count -ne 1) { return $null }
    $pcTopNative = $pcTop.OutputText.Trim().Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar)
    $pcTopFull = [System.IO.Path]::GetFullPath($pcTopNative)
    $pcRootFull = [System.IO.Path]::GetFullPath($Root)
    $pcTopPathRoot = [System.IO.Path]::GetPathRoot($pcTopFull)
    $pcRootPathRoot = [System.IO.Path]::GetPathRoot($pcRootFull)
    $pcTopCanonical = if ([string]::Equals($pcTopFull, $pcTopPathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $pcTopPathRoot } else { $pcTopFull.TrimEnd('\', '/') }
    $pcRootCanonical = if ([string]::Equals($pcRootFull, $pcRootPathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $pcRootPathRoot } else { $pcRootFull.TrimEnd('\', '/') }
    if (-not [string]::Equals($pcTopCanonical, $pcRootCanonical, [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
    $pcFormat = Invoke-CrgIsolatedPackageGit -Root $Root -GitArgs @('rev-parse', '--show-object-format')
    $pcHead = Invoke-CrgIsolatedPackageGit -Root $Root -GitArgs @('rev-parse', '--verify', 'HEAD^{commit}')
    $pcGitDir = Invoke-CrgIsolatedPackageGit -Root $Root -GitArgs @('rev-parse', '--path-format=absolute', '--git-dir')
    $pcCommonDir = Invoke-CrgIsolatedPackageGit -Root $Root -GitArgs @('rev-parse', '--path-format=absolute', '--git-common-dir')
    if ($pcFormat.Exit -ne 0 -or $pcHead.Exit -ne 0 -or $pcGitDir.Exit -ne 0 -or $pcCommonDir.Exit -ne 0) { return $null }
    $pcFormatText = $pcFormat.OutputText.Trim(); $pcHeadText = $pcHead.OutputText.Trim()
    $pcOidLength = if ([string]::Equals($pcFormatText, 'sha256', [System.StringComparison]::Ordinal)) { 64 } elseif ([string]::Equals($pcFormatText, 'sha1', [System.StringComparison]::Ordinal)) { 40 } else { 0 }
    if ($pcOidLength -eq 0 -or $pcHeadText -cnotmatch "\A[0-9a-f]{$pcOidLength}\z") { throw 'package Git metadata returned a malformed object format or HEAD identity' }
    $pcCandidate = [pscustomobject]@{
      Root = $pcRootCanonical
      Head = $pcHeadText
      ObjectIdLength = $pcOidLength
      GitDir = [System.IO.Path]::GetFullPath($pcGitDir.OutputText.Trim().Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar))
      CommonDir = [System.IO.Path]::GetFullPath($pcCommonDir.OutputText.Trim().Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar))
      Conversion = $null
    }
    $pcCandidate.Conversion = Get-CrgIsolatedPackageConversionSettings -Candidate $pcCandidate
    return $pcCandidate
  } catch {
    throw "package Git provenance capture failed: $($_.Exception.Message)"
  }
}

function Assert-CrgCapturedPackageProvenanceCandidate {
  param([object]$Candidate)
  if ($null -eq $Candidate) { throw 'captured package provenance candidate is absent' }
  $cpTop = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('rev-parse', '--show-toplevel')
  $cpFormat = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('rev-parse', '--show-object-format')
  $cpHead = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('rev-parse', '--verify', 'HEAD^{commit}')
  $cpGitDir = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('rev-parse', '--path-format=absolute', '--git-dir')
  $cpCommonDir = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('rev-parse', '--path-format=absolute', '--git-common-dir')
  foreach ($cpResult in @($cpTop, $cpFormat, $cpHead, $cpGitDir, $cpCommonDir)) {
    if ($cpResult.Exit -ne 0 -or @($cpResult.OutputText -split "`r?`n" | Where-Object { $_.Length -gt 0 }).Count -ne 1) {
      throw "captured package Git metadata could not be revalidated: $($cpResult.Text.Trim())"
    }
  }
  $cpCanonical = {
    param([string]$Path)
    $cpRaw = [System.IO.Path]::GetFullPath($Path.Trim().Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar))
    $cpRoot = [System.IO.Path]::GetPathRoot($cpRaw)
    return $(if ([string]::Equals($cpRaw, $cpRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $cpRoot } else { $cpRaw.TrimEnd('\', '/') })
  }
  $cpExpectedFormat = if ($Candidate.ObjectIdLength -eq 64) { 'sha256' } elseif ($Candidate.ObjectIdLength -eq 40) { 'sha1' } else { '<invalid>' }
  if (-not [string]::Equals((& $cpCanonical $cpTop.OutputText), (& $cpCanonical $Candidate.Root), [System.StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::Equals($cpFormat.OutputText.Trim(), $cpExpectedFormat, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($cpHead.OutputText.Trim(), $Candidate.Head, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals((& $cpCanonical $cpGitDir.OutputText), (& $cpCanonical $Candidate.GitDir), [System.StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::Equals((& $cpCanonical $cpCommonDir.OutputText), (& $cpCanonical $Candidate.CommonDir), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'captured package repository identity changed while its namespace was being retained'
  }
  $cpConversion = Get-CrgIsolatedPackageConversionSettings -Candidate $Candidate
  if ($null -eq $Candidate.Conversion -or
      -not [string]::Equals($cpConversion.AutoCrlf, $Candidate.Conversion.AutoCrlf, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($cpConversion.Eol, $Candidate.Conversion.Eol, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($cpConversion.SafeCrlf, $Candidate.Conversion.SafeCrlf, [System.StringComparison]::Ordinal) -or
      $cpConversion.FileMode -cne $Candidate.Conversion.FileMode) {
    throw 'captured package conversion configuration changed while its namespace was being retained'
  }
  return $true
}

function Get-CrgIsolatedPackageConversionSettings {
  param([object]$Candidate)
  $icGet = {
    param([string]$Name)
    return Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('config', '--get', $Name) -UseAmbientConfig
  }
  $icAutoResult = & $icGet 'core.autocrlf'
  if ($icAutoResult.Exit -eq 1) { $icAuto = 'false' }
  elseif ($icAutoResult.Exit -eq 0 -and @($icAutoResult.OutputText -split "`r?`n" | Where-Object { $_.Length -gt 0 }).Count -eq 1) {
    $icAutoRaw = $icAutoResult.OutputText.Trim()
    if ([string]::Equals($icAutoRaw, 'input', [System.StringComparison]::OrdinalIgnoreCase)) { $icAuto = 'input' }
    else {
      $icAutoCanonical = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('-c', "core.autocrlf=$icAutoRaw", 'config', '--type=bool', '--get', 'core.autocrlf') -UseAmbientConfig
      if ($icAutoCanonical.Exit -ne 0 -or -not ([string]::Equals($icAutoCanonical.OutputText.Trim(), 'true', [System.StringComparison]::Ordinal) -or [string]::Equals($icAutoCanonical.OutputText.Trim(), 'false', [System.StringComparison]::Ordinal))) { throw 'package core.autocrlf is not a canonical boolean or input value' }
      $icAuto = $icAutoCanonical.OutputText.Trim()
    }
  } else { throw 'package core.autocrlf could not be captured exactly' }
  $icEolResult = & $icGet 'core.eol'
  if ($icEolResult.Exit -eq 1) { $icEol = 'native' }
  elseif ($icEolResult.Exit -eq 0 -and [System.Linq.Enumerable]::Contains([string[]]@('lf', 'crlf', 'native'), $icEolResult.OutputText.Trim().ToLowerInvariant(), [System.StringComparer]::Ordinal)) { $icEol = $icEolResult.OutputText.Trim().ToLowerInvariant() }
  else { throw 'package core.eol could not be captured exactly' }
  $icSafeResult = & $icGet 'core.safecrlf'
  if ($icSafeResult.Exit -eq 1) { $icSafe = 'false' }
  elseif ($icSafeResult.Exit -eq 0) {
    $icSafeRaw = $icSafeResult.OutputText.Trim()
    if ([string]::Equals($icSafeRaw, 'warn', [System.StringComparison]::OrdinalIgnoreCase)) { $icSafe = 'warn' }
    else {
      $icSafeCanonical = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('-c', "core.safecrlf=$icSafeRaw", 'config', '--type=bool', '--get', 'core.safecrlf') -UseAmbientConfig
      if ($icSafeCanonical.Exit -ne 0 -or -not ([string]::Equals($icSafeCanonical.OutputText.Trim(), 'true', [System.StringComparison]::Ordinal) -or [string]::Equals($icSafeCanonical.OutputText.Trim(), 'false', [System.StringComparison]::Ordinal))) { throw 'package core.safecrlf is not a canonical boolean or warn value' }
      $icSafe = $icSafeCanonical.OutputText.Trim()
    }
  } else { throw 'package core.safecrlf could not be captured exactly' }
  return [pscustomobject]@{ AutoCrlf = $icAuto; Eol = $icEol; SafeCrlf = $icSafe; FileMode = 'false' }
}

function Read-CrgIsolatedPackageBlobBytes {
  param([object]$Candidate, [string]$Oid, [int]$MaxLength)
  if ($Oid -cnotmatch "\A[0-9a-f]{$($Candidate.ObjectIdLength)}\z") { throw 'package blob reader received a malformed object ID' }
  # One byte past the proof bound is enough to refuse, so the read stops there;
  # at the helper's own maximum the helper's refusal stands in for that byte.
  $ibResult = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('cat-file', 'blob', $Oid) -MaxOutputBytes ([Math]::Min([Math]::Max([int64]$MaxLength, 0) + 1, 16777216))
  if ($ibResult.Exit -ne 0) { throw "package git cat-file failed for '$Oid': $($ibResult.Text.Trim())" }
  if ($ibResult.Bytes.Length -gt $MaxLength) { throw "package blob '$Oid' exceeds the $MaxLength-byte proof bound" }
  if ((Get-CrgGitObjectIdOfBytes -Type blob -Bytes $ibResult.Bytes -ObjectIdLength $Candidate.ObjectIdLength) -cne $Oid) { throw "package blob '$Oid' failed independent object-ID verification" }
  return ,([byte[]]$ibResult.Bytes)
}

function Get-CrgHeldPackageProvenance {
  param([object]$Candidate, [byte[]]$VersionBytes, [object[]]$SourceOwners, [string]$ScratchRoot)
  if ($null -eq $Candidate) { return 'unknown' }
  $hpContext = $null; $hpCleanupOk = $true
  try {
    $hpBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    $hpBuffers['VERSION'] = [byte[]]$VersionBytes
    foreach ($hpOwner in $SourceOwners) {
      if ([string]::Equals($hpOwner.RelativePath, 'VERSION', [System.StringComparison]::Ordinal)) { continue }
      if ($null -eq $hpOwner.Stream -or $hpOwner.Bytes -isnot [byte[]] -or [string]::IsNullOrWhiteSpace("$($hpOwner.RelativePath)")) { throw 'package provenance received an incomplete held-source owner' }
      $hpPath = "$($hpOwner.RelativePath)" -replace '\\', '/'
      if ($hpBuffers.ContainsKey($hpPath)) { throw "duplicate held package source '$hpPath'" }
      $hpBuffers[$hpPath] = [byte[]]$hpOwner.Bytes
    }
    $hpTreeMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    foreach ($hpPath in $hpBuffers.Keys) {
      $hpTreeResult = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('ls-tree', $Candidate.Head, '--', $hpPath)
      $hpTreeRows = @($hpTreeResult.OutputText -split "`r?`n" | Where-Object { $_.Length -gt 0 })
      if ($hpTreeResult.Exit -ne 0 -or $hpTreeRows.Count -ne 1) { return 'unknown' }
      $hpTreePattern = '^(?<mode>100644|100755) blob (?<oid>[0-9a-f]{' + $Candidate.ObjectIdLength + '})\t' + [regex]::Escape($hpPath) + '$'
      if ($hpTreeRows[0] -cnotmatch $hpTreePattern) { throw "package commit entry '$hpPath' is not one regular matching-format blob" }
      $hpTreeMap[$hpPath] = [pscustomobject]@{ Mode = $Matches['mode']; Oid = $Matches['oid'] }
    }
    $hpAttributePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    [void]$hpAttributePaths.Add('.gitattributes')
    foreach ($hpPath in $hpBuffers.Keys) {
      $hpComponents = @($hpPath -split '/')
      if ($hpComponents.Count -le 1) { continue }
      $hpCursor = ''
      for ($hpI = 0; $hpI -lt ($hpComponents.Count - 1); $hpI++) {
        $hpCursor = if ($hpCursor.Length -eq 0) { $hpComponents[$hpI] } else { "$hpCursor/$($hpComponents[$hpI])" }
        [void]$hpAttributePaths.Add("$hpCursor/.gitattributes")
      }
    }
    $hpAttributeBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    foreach ($hpAttributePath in $hpAttributePaths) {
      $hpAttrResult = Invoke-CrgCapturedPackageGit -Candidate $Candidate -GitArgs @('ls-tree', $Candidate.Head, '--', $hpAttributePath)
      $hpAttrRows = @($hpAttrResult.OutputText -split "`r?`n" | Where-Object { $_.Length -gt 0 })
      if ($hpAttrResult.Exit -ne 0 -or $hpAttrRows.Count -gt 1) { throw "package attribute entry '$hpAttributePath' could not be classified" }
      if ($hpAttrRows.Count -eq 0) { continue }
      $hpAttrPattern = '^(100644|100755) blob (?<oid>[0-9a-f]{' + $Candidate.ObjectIdLength + '})\t' + [regex]::Escape($hpAttributePath) + '$'
      if ($hpAttrRows[0] -cnotmatch $hpAttrPattern) { throw "package attribute entry '$hpAttributePath' is not one regular matching-format blob" }
      $hpAttributeBuffers[$hpAttributePath] = Read-CrgIsolatedPackageBlobBytes -Candidate $Candidate -Oid $Matches['oid'] -MaxLength 1048576
    }
    $hpContext = New-CrgPrivateAttributeContext -ScratchRoot $ScratchRoot -ObjectIdLength $Candidate.ObjectIdLength
    $hpWriter = { param([string]$Type, [byte[]]$Bytes) Add-CrgPrivateGitObject -Context $hpContext -Type $Type -Bytes $Bytes }
    # `check-attr --all` reports a special -filter/-ident/-working-tree-encoding
    # state as specified. Accept it only for the fixed rendered-value surface
    # after the pathspec state proof distinguishes it from literal collisions.
    $hpInstallValuePaths = @('scripts/codex/review-prompt-template.md')
    if (@($hpInstallValuePaths | Where-Object { -not $hpBuffers.ContainsKey($_) }).Count -ne 0) { throw 'package provenance is missing a fixed rendered install-values surface' }
    $hpAttributeTree = New-CrgGitAttributeSourceTree -AttributeBuffers $hpAttributeBuffers -ObjectIdLength $Candidate.ObjectIdLength -WriteObject $hpWriter -ProbePaths $hpInstallValuePaths
    Assert-CrgPrivateInstallValuesAttributeStates -Context $hpContext -TreeOid $hpAttributeTree -Paths $hpInstallValuePaths
    $hpSpecified = Get-CrgPrivateSpecifiedAttributeMap -Context $hpContext -TreeOid $hpAttributeTree -Paths @($hpBuffers.Keys)
    foreach ($hpSpecifiedKey in $hpSpecified.Keys) {
      $hpSpecifiedPath = "$hpSpecifiedKey".Substring(0, "$hpSpecifiedKey".IndexOf([char]0))
      $hpSpecifiedAttribute = "$hpSpecifiedKey".Substring("$hpSpecifiedKey".IndexOf([char]0) + 1)
      if (-not [System.Linq.Enumerable]::Contains([string[]]@($hpInstallValuePaths), [string]$hpSpecifiedPath, [System.StringComparer]::Ordinal) -and
          [System.Linq.Enumerable]::Contains([string[]]@('filter', 'ident', 'working-tree-encoding'), [string]$hpSpecifiedAttribute, [System.StringComparer]::Ordinal)) { throw "package commit explicitly specifies unsupported content transform '$hpSpecifiedAttribute' for an installed source" }
    }
    $hpConversion = $Candidate.Conversion
    if ($null -eq $hpConversion) { throw 'captured package provenance is missing its conversion contract' }
    foreach ($hpPath in $hpBuffers.Keys) {
      $hpOid = Get-CrgPrivateFilteredObjectIdOfBytes -Context $hpContext -TreeOid $hpAttributeTree -RepoPath $hpPath -Bytes ([byte[]]$hpBuffers[$hpPath]) -Conversion $hpConversion
      if (-not [string]::Equals($hpOid, $hpTreeMap[$hpPath].Oid, [System.StringComparison]::Ordinal)) { return 'unknown' }
    }
    return $Candidate.Head
  } finally {
    if ($null -ne $hpContext -and -not (Close-CrgPrivateAttributeContext -Context $hpContext)) { $hpCleanupOk = $false }
    if (-not $hpCleanupOk) { throw 'package provenance context could not be exactly cleaned' }
  }
}

function New-CrgImmutableGitScratchFile {
  param([string]$Path, [byte[]]$Bytes, [string]$Label)
  if ($null -eq $Bytes) { throw "$Label received null bytes" }
  $isHandle = $null; $isStream = $null; $isError = 0; $isComplete = $false
  try {
    $isHandle = [CrgBootstrap.NativeV4]::CreatePinnedImmutableGitFileNoFollow($Path, [ref]$isError)
    if ($null -eq $isHandle -or $isHandle.IsInvalid) { throw "$Label create-new failed at '$Path' (Win32 error $isError)" }
    $isAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($isHandle)
    if ($isAttrs -lt 0 -or ($isAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($isHandle) -ne 1) { throw "$Label is not one ordinary non-reparse single-link file" }
    $isStream = New-Object System.IO.FileStream($isHandle, [System.IO.FileAccess]::ReadWrite)
    $isHandle = $null
    if ($Bytes.Length -gt 0) { $isStream.Write($Bytes, 0, $Bytes.Length) }
    $isStream.Flush($true)
    $isStream.Position = 0
    $isReadback = New-Object byte[] $Bytes.Length
    $isRead = 0
    while ($isRead -lt $isReadback.Length) {
      $isGot = $isStream.Read($isReadback, $isRead, $isReadback.Length - $isRead)
      if ($isGot -le 0) { break }
      $isRead += $isGot
    }
    if ($isRead -ne $Bytes.Length -or -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$Bytes, [byte[]]$isReadback)) { throw "$Label held readback did not match the exact source bytes" }
    $isStream.Position = 0
    $isComplete = $true
    return [pscustomobject]@{ Path = $Path; Stream = $isStream; Bytes = $Bytes; Label = $Label }
  } finally {
    if (-not $isComplete) {
      if ($null -ne $isStream) { try { $isStream.Dispose() } catch { } }
      elseif ($null -ne $isHandle -and -not $isHandle.IsInvalid) { try { $isHandle.Dispose() } catch { } }
      # No pathname cleanup follows a constructor/write failure. The random,
      # non-authoritative remnant is preserved because DELETE access was never
      # released into an identity-free cleanup operation.
    }
  }
}

function Remove-CrgImmutableGitScratchFile {
  param([object]$File)
  if ($null -eq $File -or $null -eq $File.Stream) { return $false }
  $iiOriginal = $File.Stream.SafeFileHandle
  $iiHandoff = $null; $iiCleanup = $null
  try {
    if ($iiOriginal.IsInvalid -or [CrgBootstrap.NativeV3]::GetLinkCount($iiOriginal) -ne 1) { throw 'the immutable proof file lost ordinary single-link shape' }
    $iiHandoffError = 0
    $iiHandoff = [CrgBootstrap.NativeV4]::OpenReadShareAllNoFollow($File.Path, [ref]$iiHandoffError)
    if ($null -eq $iiHandoff -or $iiHandoff.IsInvalid -or [CrgBootstrap.NativeV3]::GetLinkCount($iiHandoff) -ne 1 -or
        -not [CrgBootstrap.NativeV4]::SameFileIdentity($iiOriginal, $iiHandoff)) { throw "the immutable-to-cleanup handoff failed (Win32 error $iiHandoffError)" }
    $File.Stream.Dispose(); $File.Stream = $null
    $iiCleanupError = 0
    $iiCleanup = [CrgBootstrap.NativeV4]::OpenCleanupOwnerNoFollow($File.Path, [ref]$iiCleanupError)
    if ($null -eq $iiCleanup -or $iiCleanup.IsInvalid -or [CrgBootstrap.NativeV3]::GetLinkCount($iiCleanup) -ne 1 -or
        -not [CrgBootstrap.NativeV4]::SameFileIdentity($iiHandoff, $iiCleanup)) { throw "the exact cleanup-owner handoff failed (Win32 error $iiCleanupError)" }
    $iiDeleteError = 0
    $iiDeleteResult = [CrgBootstrap.NativeV4]::DeleteHeldExact($iiCleanup, $false, [ref]$iiDeleteError)
    if ($iiDeleteResult -ne 0) { throw "same-handle cleanup failed (result $iiDeleteResult, Win32 error $iiDeleteError)" }
    $iiCleanup.Dispose(); $iiCleanup = $null
    return $true
  } catch {
    Write-Host "[bootstrap] WARNING: immutable $($File.Label) at '$($File.Path)' could not be exactly cleaned ($($_.Exception.Message)); preserving the remnant."
    return $false
  } finally {
    if ($null -ne $File.Stream) { try { $File.Stream.Dispose(); $File.Stream = $null } catch { } }
    if ($null -ne $iiHandoff) { try { $iiHandoff.Dispose() } catch { } }
    if ($null -ne $iiCleanup) { try { $iiCleanup.Dispose() } catch { } }
  }
}

function Remove-CrgPinnedScratchDirectory {
  param([string]$Path, [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle, [string]$Label)
  $pdOriginal = $Handle; $pdBridge = $null; $pdCleanup = $null
  try {
    if ($null -eq $pdOriginal -or $pdOriginal.IsInvalid) { throw 'the retained directory pin is invalid' }
    $pdBridgeError = 0
    $pdBridge = [CrgBootstrap.NativeV4]::OpenDirectoryReadShareAll($Path, [ref]$pdBridgeError)
    if ($null -eq $pdBridge -or $pdBridge.IsInvalid -or -not [CrgBootstrap.NativeV4]::SameFileIdentity($pdOriginal, $pdBridge)) { throw "the directory cleanup handoff failed (Win32 error $pdBridgeError)" }
    $pdOriginal.Dispose(); $pdOriginal = $null
    $pdCleanupError = 0
    $pdCleanup = [CrgBootstrap.NativeV4]::OpenDirectoryCleanupOwnerNoFollow($Path, [ref]$pdCleanupError)
    if ($null -eq $pdCleanup -or $pdCleanup.IsInvalid -or -not [CrgBootstrap.NativeV4]::SameFileIdentity($pdBridge, $pdCleanup)) { throw "the exact directory cleanup owner could not be acquired (Win32 error $pdCleanupError)" }
    $pdDeleteError = 0
    $pdDeleteResult = [CrgBootstrap.NativeV4]::DeleteHeldExact($pdCleanup, $true, [ref]$pdDeleteError)
    if ($pdDeleteResult -ne 0) { throw "same-handle directory cleanup failed (result $pdDeleteResult, Win32 error $pdDeleteError)" }
    $pdCleanup.Dispose(); $pdCleanup = $null
    return $true
  } catch {
    Write-Host "[bootstrap] WARNING: pinned $Label at '$Path' could not be exactly cleaned ($($_.Exception.Message)); preserving the remnant."
    return $false
  } finally {
    if ($null -ne $pdOriginal) { try { $pdOriginal.Dispose() } catch { } }
    if ($null -ne $pdBridge) { try { $pdBridge.Dispose() } catch { } }
    if ($null -ne $pdCleanup) { try { $pdCleanup.Dispose() } catch { } }
  }
}

function Set-CrgPrivateDirectoryReadOnly {
  param([object]$Directory)
  if ($null -eq $Directory -or $null -eq $Directory.Handle -or $Directory.Handle.IsInvalid) { throw 'private directory downgrade received no retained authority' }
  if ($Directory.ReadOnlyPin) { return }
  $pcOriginal = $Directory.Handle
  $pcBridge = $null
  $pcPin = $null
  $pcOriginalReleased = $false
  try {
    $pcBridgeError = 0
    $pcBridge = [CrgBootstrap.NativeV4]::OpenDirectoryReadShareAll($Directory.Path, [ref]$pcBridgeError)
    if ($null -eq $pcBridge -or $pcBridge.IsInvalid -or -not [CrgBootstrap.NativeV4]::SameFileIdentity($pcOriginal, $pcBridge)) {
      throw "$($Directory.Label) mutation-to-read handoff failed (Win32 error $pcBridgeError)"
    }
    [CrgBootstrap.NativeV4]::UnregisterRootedIo($Directory.Path, $pcOriginal)
    $pcOriginal.Dispose()
    $pcOriginalReleased = $true
    $Directory.Handle = $pcBridge
    $Directory.ReadOnlyPin = $true
    $pcBridge = $null

    $pcPinError = 0
    $pcPin = [CrgBootstrap.NativeV4]::OpenDirectoryPinned($Directory.Path, [ref]$pcPinError)
    if ($null -eq $pcPin -or $pcPin.IsInvalid -or -not [CrgBootstrap.NativeV4]::SameFileIdentity($Directory.Handle, $pcPin)) {
      throw "$($Directory.Label) restrictive read pin handoff failed (Win32 error $pcPinError)"
    }
    if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($Directory.Path, $pcPin, $false)) {
      throw "$($Directory.Label) could not be registered as read-only rooted authority"
    }
    $pcReleasedBridge = $Directory.Handle
    $Directory.Handle = $pcPin
    $pcPin = $null
    $pcReleasedBridge.Dispose()
  } catch {
    $pcTransitionError = $_
    if ($pcOriginalReleased -and $null -ne $Directory.Handle -and -not $Directory.Handle.IsInvalid) {
      # Preserve exact rooted read authority for fail-closed cleanup. The
      # share-all bridge is retained only after identity equality was proved.
      try {
        if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($Directory.Path, $Directory.Handle, $false)) {
          throw 'RegisterRootedIo returned false'
        }
      } catch {
        $pcRecoveryError = $_.Exception.Message
        $pcCombinedError = "$($Directory.Label) LOST READ-ONLY BOUNDARY after '$($pcTransitionError.Exception.Message)'; recovery registration failed: $pcRecoveryError"
        throw [System.InvalidOperationException]::new($pcCombinedError, $pcTransitionError.Exception)
      }
    }
    throw $pcTransitionError
  } finally {
    if ($null -ne $pcBridge) { try { $pcBridge.Dispose() } catch { } }
    if ($null -ne $pcPin) { try { $pcPin.Dispose() } catch { } }
  }
}

function Set-CrgPrivateDirectoryMutation {
  param([object]$Directory)
  if ($null -eq $Directory -or $null -eq $Directory.Handle -or $Directory.Handle.IsInvalid) { throw 'private directory upgrade received no retained authority' }
  if (-not $Directory.ReadOnlyPin) { return }
  $pcOriginal = $Directory.Handle
  $pcBridge = $null
  $pcMutation = $null
  $pcOriginalReleased = $false
  try {
    $pcBridgeError = 0
    $pcBridge = [CrgBootstrap.NativeV4]::OpenDirectoryReadShareAll($Directory.Path, [ref]$pcBridgeError)
    if ($null -eq $pcBridge -or $pcBridge.IsInvalid -or -not [CrgBootstrap.NativeV4]::SameFileIdentity($pcOriginal, $pcBridge)) {
      throw "$($Directory.Label) read-to-mutation handoff failed (Win32 error $pcBridgeError)"
    }
    [CrgBootstrap.NativeV4]::UnregisterRootedIo($Directory.Path, $pcOriginal)
    $pcOriginal.Dispose()
    $pcOriginalReleased = $true
    $Directory.Handle = $pcBridge
    $pcBridge = $null

    $pcMutationError = 0
    $pcMutation = [CrgBootstrap.NativeV4]::OpenDirectoryMutationCleanupOwnerNoFollow($Directory.Path, [ref]$pcMutationError)
    if ($null -eq $pcMutation -or $pcMutation.IsInvalid -or -not [CrgBootstrap.NativeV4]::SameFileIdentity($Directory.Handle, $pcMutation)) {
      throw "$($Directory.Label) controlled mutation handoff failed (Win32 error $pcMutationError)"
    }
    if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($Directory.Path, $pcMutation, $true)) {
      throw "$($Directory.Label) could not be registered as rooted mutation authority"
    }
    $pcReleasedBridge = $Directory.Handle
    $Directory.Handle = $pcMutation
    $Directory.ReadOnlyPin = $false
    $pcMutation = $null
    $pcReleasedBridge.Dispose()
  } catch {
    $pcTransitionError = $_
    if ($pcOriginalReleased -and $null -ne $Directory.Handle -and -not $Directory.Handle.IsInvalid) {
      # Failed promotion remains a read-only rooted boundary. No descendant
      # cleanup may fall through to writable ancestor authority.
      $Directory.ReadOnlyPin = $true
      try {
        if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($Directory.Path, $Directory.Handle, $false)) {
          throw 'RegisterRootedIo returned false'
        }
      } catch {
        $pcRecoveryError = $_.Exception.Message
        $pcCombinedError = "$($Directory.Label) LOST READ-ONLY BOUNDARY after '$($pcTransitionError.Exception.Message)'; recovery registration failed: $pcRecoveryError"
        throw [System.InvalidOperationException]::new($pcCombinedError, $pcTransitionError.Exception)
      }
    }
    throw $pcTransitionError
  } finally {
    if ($null -ne $pcBridge) { try { $pcBridge.Dispose() } catch { } }
    if ($null -ne $pcMutation) { try { $pcMutation.Dispose() } catch { } }
  }
}

function New-CrgPrivateAttributeContext {
  param(
    [string]$ScratchRoot,
    [ValidatePattern('\A(?:40|64)\z', Options = 'None')][int]$ObjectIdLength,
    [AllowEmptyCollection()][byte[]]$InfoAttributesBytes = @()
  )
  if ($null -eq $InfoAttributesBytes -or $InfoAttributesBytes.Length -gt 1048576) {
    throw 'private attribute context received an invalid or oversized info/attributes snapshot'
  }
  $pc = [pscustomobject]@{
    ScratchRoot = $ScratchRoot
    CommonDir = (Join-Path $ScratchRoot 'git')
    GitDir = (Join-Path $ScratchRoot 'git/worktrees/crg-proof')
    WorkDir = (Join-Path $ScratchRoot 'work')
    GlobalAttributes = (Join-Path $ScratchRoot 'global-attributes')
    ObjectIdLength = $ObjectIdLength
    Files = (New-Object 'System.Collections.Generic.List[object]')
    Directories = (New-Object 'System.Collections.Generic.List[object]')
    Fanouts = (New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal))
    Objects = (New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal))
  }
  $pcNewDirectory = {
    param([string]$Path, [string]$Label, [switch]$ReadOnlyPin)
    $pcDirError = 0; $pcDirHandle = $null; $pcDirRegistered = $false; $pcDirTransferred = $false
    try {
      $pcDirHandle = [CrgBootstrap.NativeV4]::CreateOwnedDirectoryAtomic($Path, [ref]$pcDirError)
      if ($null -eq $pcDirHandle -or $pcDirHandle.IsInvalid) { throw "$Label atomic create-new failed at '$Path' (Win32 error $pcDirError)" }
      $pcDirAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($pcDirHandle)
      if ($pcDirAttrs -lt 0 -or ($pcDirAttrs -band 0x410) -ne 0x10) { throw "$Label is not one ordinary held directory" }
      # A requested read-only directory starts with mutation authority because
      # required fixed children must be created before the Git-facing phase.
      # An identity-bound downgrade follows those creations below.
      $pcDirRegistered = [CrgBootstrap.NativeV4]::RegisterRootedIo($Path, $pcDirHandle, $true)
      if (-not $pcDirRegistered) { throw "$Label could not be registered as a rooted directory" }
      $pc.Directories.Add([pscustomobject]@{ Path = $Path; Handle = $pcDirHandle; Label = $Label; ReadOnlyPin = $false; RequestedReadOnlyPin = [bool]$ReadOnlyPin }) | Out-Null
      $pcDirTransferred = $true
      $pcDirHandle = $null
    } finally {
      if ($null -ne $pcDirHandle) {
        if ($pcDirRegistered) { [CrgBootstrap.NativeV4]::UnregisterRootedIo($Path, $pcDirHandle) }
        $pcDirRemoved = Remove-CrgOwnedScratchHandle -Path $Path -Handle $pcDirHandle -Directory -Label $Label
        if (-not $pcDirRemoved) { throw "$Label failed before ownership transfer and its exact remnant could not be cleaned: '$Path'" }
        $pcDirHandle = $null
      } elseif (-not $pcDirTransferred -and $pcDirRegistered) {
        throw "$Label lost its retained handle before ownership transfer"
      }
    }
  }
  try {
    & $pcNewDirectory $pc.ScratchRoot 'private attribute root'
    foreach ($pcRel in @('git', 'git/objects', 'git/objects/info', 'git/objects/pack', 'git/info', 'git/refs', 'git/worktrees', 'git/worktrees/crg-proof', 'work')) {
      & $pcNewDirectory (Join-Path $pc.ScratchRoot $pcRel) "private attribute directory '$pcRel'" -ReadOnlyPin:($pcRel -ceq 'work')
    }
    $pcConfig = "[core]`n`trepositoryformatversion = $(if ($ObjectIdLength -eq 64) { '1' } else { '0' })`n`tbare = false`n`tattributesFile = `"$(($pc.GlobalAttributes -replace '\\','/'))`"`n`tfsmonitor = false`n`tsplitIndex = false`n`tuntrackedCache = false`n"
    if ($ObjectIdLength -eq 64) { $pcConfig += "[extensions]`n`tobjectFormat = sha256`n" }
    $pcGitDirText = ([System.IO.Path]::GetFullPath($pc.GitDir) -replace '\\', '/')
    $pcWorkDotGitText = ((Join-Path ([System.IO.Path]::GetFullPath($pc.WorkDir)) '.git') -replace '\\', '/')
    foreach ($pcFileSpec in @(
      [pscustomobject]@{ Path = (Join-Path $pc.CommonDir 'config'); Bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($pcConfig); Label = 'private Git config' },
      [pscustomobject]@{ Path = (Join-Path $pc.GitDir 'HEAD'); Bytes = [System.Text.UTF8Encoding]::new($false).GetBytes("ref: refs/heads/crg-proof`n"); Label = 'private Git HEAD' },
      [pscustomobject]@{ Path = (Join-Path $pc.GitDir 'commondir'); Bytes = [System.Text.UTF8Encoding]::new($false).GetBytes("../..`n"); Label = 'private fixed common-directory indirection' },
      [pscustomobject]@{ Path = (Join-Path $pc.GitDir 'gitdir'); Bytes = [System.Text.UTF8Encoding]::new($false).GetBytes("$pcWorkDotGitText`n"); Label = 'private fixed worktree back-pointer' },
      [pscustomobject]@{ Path = (Join-Path $pc.WorkDir '.git'); Bytes = [System.Text.UTF8Encoding]::new($false).GetBytes("gitdir: $pcGitDirText`n"); Label = 'private fixed worktree pointer' },
      [pscustomobject]@{ Path = (Join-Path $pc.CommonDir 'info/attributes'); Bytes = [byte[]]$InfoAttributesBytes; Label = 'private retained info attributes' },
      [pscustomobject]@{ Path = $pc.GlobalAttributes; Bytes = [byte[]]@(); Label = 'private empty global attributes' }
    )) { $pc.Files.Add((New-CrgImmutableGitScratchFile -Path $pcFileSpec.Path -Bytes $pcFileSpec.Bytes -Label $pcFileSpec.Label)) | Out-Null }
    foreach ($pcReadOnlyDirectory in @($pc.Directories | Where-Object { $_.RequestedReadOnlyPin })) {
      Set-CrgPrivateDirectoryReadOnly -Directory $pcReadOnlyDirectory
    }
    Assert-CrgGitAttributeSourceCapability -ScratchRoot $pc.ScratchRoot -WorkDir $pc.WorkDir
    $pcCapabilityBuffers = @{ '.gitattributes' = [System.Text.UTF8Encoding]::new($false).GetBytes("crg-capability-probe text eol=lf`n") }
    $pcCapabilityWriter = { param([string]$Type, [byte[]]$Bytes) Add-CrgPrivateGitObject -Context $pc -Type $Type -Bytes $Bytes }
    $pcCapabilityTree = New-CrgGitAttributeSourceTree -AttributeBuffers $pcCapabilityBuffers -ObjectIdLength $ObjectIdLength -WriteObject $pcCapabilityWriter -ProbePaths @('crg-capability-probe')
    $pcProbePath = [System.Text.UTF8Encoding]::new($false).GetBytes("crg-capability-probe`0")
    $pcCheckProbe = Invoke-CrgPrivateAttributeGit -Context $pc -GitArgs @("--attr-source=$pcCapabilityTree", 'check-attr', '-z', '--stdin', 'text', 'eol') -InputBytes $pcProbePath
    [byte[]]$pcCheckExpected = [System.Text.UTF8Encoding]::new($false).GetBytes("crg-capability-probe`0text`0set`0crg-capability-probe`0eol`0lf`0")
    if ($pcCheckProbe.Exit -ne 0 -or $pcCheckProbe.ErrorText.Length -ne 0 -or -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$pcCheckExpected, [byte[]]$pcCheckProbe.Bytes)) {
      throw "Git does not provide exact isolated check-attr --source semantics ($($pcCheckProbe.Text.Trim()))"
    }
    Assert-CrgPrivateInstallValuesAttributeStates -Context $pc -TreeOid $pcCapabilityTree -Paths @('crg-capability-probe')
    [byte[]]$pcProbeCrlf = [System.Text.UTF8Encoding]::new($false).GetBytes("one`r`ntwo`r`n")
    [byte[]]$pcProbeLf = [System.Text.UTF8Encoding]::new($false).GetBytes("one`ntwo`n")
    $pcHashProbe = Invoke-CrgPrivateAttributeGit -Context $pc -GitArgs @("--attr-source=$pcCapabilityTree", 'hash-object', '--path=crg-capability-probe', '--stdin') -InputBytes $pcProbeCrlf
    $pcExpectedProbeBlob = Get-CrgGitObjectIdOfBytes -Type blob -Bytes $pcProbeLf -ObjectIdLength $ObjectIdLength
    if ($pcHashProbe.Exit -ne 0 -or $pcHashProbe.ErrorText.Length -ne 0 -or -not [string]::Equals($pcHashProbe.OutputText.Trim(), $pcExpectedProbeBlob, [System.StringComparison]::Ordinal)) { throw "Git does not provide exact global --attr-source stdin conversion semantics ($($pcHashProbe.Text.Trim()))" }
    return $pc
  } catch {
    if ($null -ne $pc) { $null = Close-CrgPrivateAttributeContext -Context $pc }
    throw
  }
}

function Add-CrgPrivateGitObject {
  param([object]$Context, [ValidatePattern('\A(?:blob|tree)\z', Options = 'None')][string]$Type, [byte[]]$Bytes)
  $poOid = Get-CrgGitObjectIdOfBytes -Type $Type -Bytes $Bytes -ObjectIdLength $Context.ObjectIdLength
  if ($Context.Objects.ContainsKey($poOid)) { return $poOid }
  $poPrefix = $poOid.Substring(0, 2)
  if (-not $Context.Fanouts.ContainsKey($poPrefix)) {
    $poFanoutPath = Join-Path (Join-Path $Context.CommonDir 'objects') $poPrefix
    $poFanoutError = 0; $poFanoutHandle = $null; $poFanoutRegistered = $false; $poFanoutTransferred = $false
    try {
      $poFanoutHandle = [CrgBootstrap.NativeV4]::CreateOwnedDirectoryAtomic($poFanoutPath, [ref]$poFanoutError)
      if ($null -eq $poFanoutHandle -or $poFanoutHandle.IsInvalid) { throw "private object fanout '$poPrefix' create-new failed (Win32 error $poFanoutError)" }
      $poFanoutAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($poFanoutHandle)
      if ($poFanoutAttrs -lt 0 -or ($poFanoutAttrs -band 0x410) -ne 0x10) { throw "private object fanout '$poPrefix' is not one ordinary held directory" }
      $poFanoutRegistered = [CrgBootstrap.NativeV4]::RegisterRootedIo($poFanoutPath, $poFanoutHandle, $true)
      if (-not $poFanoutRegistered) { throw "private object fanout '$poPrefix' could not be registered as a rooted directory" }
      $poFanout = [pscustomobject]@{ Path = $poFanoutPath; Handle = $poFanoutHandle; Label = "private object fanout '$poPrefix'" }
      $Context.Directories.Add($poFanout) | Out-Null
      $Context.Fanouts[$poPrefix] = $poFanout
      $poFanoutTransferred = $true
      $poFanoutHandle = $null
    } finally {
      if ($null -ne $poFanoutHandle) {
        if ($poFanoutRegistered) { [CrgBootstrap.NativeV4]::UnregisterRootedIo($poFanoutPath, $poFanoutHandle) }
        if (-not (Remove-CrgOwnedScratchHandle -Path $poFanoutPath -Handle $poFanoutHandle -Directory -Label "private object fanout '$poPrefix'")) { throw "private object fanout '$poPrefix' failed before ownership transfer and its exact remnant could not be cleaned: '$poFanoutPath'" }
        $poFanoutHandle = $null
      } elseif (-not $poFanoutTransferred -and $poFanoutRegistered) {
        throw "private object fanout '$poPrefix' lost its retained handle before ownership transfer"
      }
    }
  }
  $poPath = Join-Path $Context.Fanouts[$poPrefix].Path $poOid.Substring(2)
  [byte[]]$poLoose = Get-CrgGitLooseObjectBytes -Type $Type -Bytes $Bytes
  $poFile = New-CrgImmutableGitScratchFile -Path $poPath -Bytes $poLoose -Label "private $Type object $poOid"
  $Context.Files.Add($poFile) | Out-Null
  $Context.Objects[$poOid] = $poFile
  return $poOid
}

function Invoke-CrgPrivateAttributeGit {
  param([object]$Context, [string[]]$GitArgs, [byte[]]$InputBytes)
  $pgArgs = @('--no-optional-locks', "--git-dir=$($Context.GitDir)", "--work-tree=$($Context.WorkDir)", '-c', 'core.bare=false', '-c', "core.worktree=$($Context.WorkDir)", '-c', "core.attributesFile=$($Context.GlobalAttributes)", '-c', 'core.fsmonitor=false', '-c', 'core.splitIndex=false', '-c', 'core.untrackedCache=false') + @($GitArgs)
  return Invoke-CrgIsolatedGitProcess -IsoRoot $Context.ScratchRoot -WorkDir $Context.WorkDir -GitArgs $pgArgs -InputBytes $InputBytes -ExtraEnvironment @{ GIT_COMMON_DIR = "$($Context.CommonDir)"; GIT_WORK_TREE = "$($Context.WorkDir)" }
}

function Get-CrgPrivateSpecifiedAttributeMap {
  param([object]$Context, [string]$TreeOid, [string[]]$Paths)
  if ($null -eq $Context -or $TreeOid -cnotmatch "\A[0-9a-f]{$($Context.ObjectIdLength)}\z" -or $null -eq $Paths -or $Paths.Count -lt 1) {
    throw 'private specified-attribute query received an invalid context, tree, or path inventory'
  }
  $psExpectedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $psInput = New-Object System.IO.MemoryStream
  try {
    foreach ($psPath in $Paths) {
      if ($psPath -cnotmatch '\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z' -or $psPath.StartsWith('/', [System.StringComparison]::Ordinal) -or $psPath.EndsWith('/', [System.StringComparison]::Ordinal)) { throw "unsafe private specified-attribute path '$psPath'" }
      foreach ($psComponent in @($psPath -split '/')) { if ([string]::Equals($psComponent, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($psComponent, '..', [System.StringComparison]::Ordinal)) { throw "unsafe private specified-attribute path '$psPath'" } }
      if (-not $psExpectedPaths.Add($psPath)) { throw "duplicate private specified-attribute path '$psPath'" }
      $psPathBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($psPath)
      $psInput.Write($psPathBytes, 0, $psPathBytes.Length); $psInput.WriteByte(0)
    }
    [byte[]]$psInputBytes = $psInput.ToArray()
  } finally { $psInput.Dispose() }
  $psResult = Invoke-CrgPrivateAttributeGit -Context $Context -GitArgs @("--attr-source=$TreeOid", 'check-attr', '-z', '--stdin', '--all') -InputBytes $psInputBytes
  if ($psResult.Exit -ne 0 -or $psResult.ErrorText.Length -ne 0) { throw "private check-attr --all query failed (exit $($psResult.Exit)): $($psResult.Text.Trim())" }
  $psMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  if ($psResult.Bytes.Length -eq 0) { return $psMap }
  $psText = [System.Text.UTF8Encoding]::new($false, $true).GetString($psResult.Bytes)
  $psParts = $psText.Split([char[]]@([char]0), [System.StringSplitOptions]::None)
  if ($psParts.Count -lt 4 -or $psParts[$psParts.Count - 1].Length -ne 0 -or (($psParts.Count - 1) % 3) -ne 0) { throw 'private check-attr --all returned malformed NUL triples' }
  for ($psI = 0; $psI -lt ($psParts.Count - 1); $psI += 3) {
    $psPath = $psParts[$psI]; $psAttribute = $psParts[$psI + 1]; $psValue = $psParts[$psI + 2]
    if (-not $psExpectedPaths.Contains($psPath) -or $psAttribute -cnotmatch '\A[A-Za-z0-9_.-]+\z') { throw 'private check-attr --all returned an unexpected path or malformed attribute' }
    $psKey = "$psPath`0$psAttribute"
    if ($psMap.ContainsKey($psKey)) { throw "private check-attr --all returned duplicate key '$psPath/$psAttribute'" }
    $psMap[$psKey] = $psValue
  }
  return $psMap
}

function Get-CrgPrivateFilteredObjectIdOfBytes {
  param([object]$Context, [string]$TreeOid, [string]$RepoPath, [byte[]]$Bytes, [object]$Conversion)
  if ($null -eq $Context -or $TreeOid -cnotmatch "\A[0-9a-f]{$($Context.ObjectIdLength)}\z" -or
      $RepoPath -cnotmatch '\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z' -or $null -eq $Bytes -or $null -eq $Conversion) {
    throw 'private filtered-object probe received an invalid context, tree, path, buffer, or conversion contract'
  }
  foreach ($pfComponent in @($RepoPath -split '/')) { if ([string]::Equals($pfComponent, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($pfComponent, '..', [System.StringComparison]::Ordinal)) { throw "unsafe private filtered-object path '$RepoPath'" } }
  if (-not [System.Linq.Enumerable]::Contains([string[]]@('true', 'false', 'input'), [string]$Conversion.AutoCrlf, [System.StringComparer]::Ordinal) -or
      -not [System.Linq.Enumerable]::Contains([string[]]@('lf', 'crlf', 'native'), [string]$Conversion.Eol, [System.StringComparer]::Ordinal) -or
      -not [System.Linq.Enumerable]::Contains([string[]]@('true', 'false', 'warn'), [string]$Conversion.SafeCrlf, [System.StringComparer]::Ordinal)) {
    throw 'private filtered-object probe received non-canonical conversion settings'
  }
  $pfResult = Invoke-CrgPrivateAttributeGit -Context $Context -GitArgs @(
    '-c', "core.autocrlf=$($Conversion.AutoCrlf)",
    '-c', "core.eol=$($Conversion.Eol)",
    '-c', "core.safecrlf=$($Conversion.SafeCrlf)",
    "--attr-source=$TreeOid", 'hash-object', "--path=$RepoPath", '--stdin'
  ) -InputBytes $Bytes
  $pfOid = $pfResult.OutputText.Trim()
  if ($pfResult.Exit -ne 0 -or $pfOid -cnotmatch "\A[0-9a-f]{$($Context.ObjectIdLength)}\z") { throw "private hash-object failed for '$RepoPath' (exit $($pfResult.Exit)): $($pfResult.Text.Trim())" }
  return $pfOid
}

function Close-CrgPrivateAttributeContext {
  param([object]$Context)
  if ($null -eq $Context) { return $true }
  # The existing refusal ($false) is returned so each caller's restore and
  # report path still runs; raising here instead escaped callers whose
  # contract is to return $null (review, 2026-10-11), leaving a moved gate
  # file in unreported custody. Callers' own messages do not name the
  # unconfirmed child, so the warning reports the retained failure.
  if ($null -ne $script:CrgUncertainGitOwners) {
    Add-CrgUncertainGitOwner -Owner $Context
    Write-Host "[bootstrap] WARNING: a Git child could not be confirmed ended ($(Get-CrgUncertainGitCause)); private attribute context '$($Context.ScratchRoot)' is kept until this process ends and its cleanup is refused."
    return $false
  }
  $pcCloseOk = $true
  # Git runs only while requested read-only roots are restrictive. Cleanup
  # begins by proving an identity-bound transition back to controlled mutation
  # authority; failed transitions retain the read-only boundary and make every
  # descendant cleanup fail closed.
  foreach ($pcDir in @($Context.Directories | Where-Object { $_.ReadOnlyPin })) {
    try { Set-CrgPrivateDirectoryMutation -Directory $pcDir }
    catch {
      Write-Host "[bootstrap] WARNING: $($pcDir.Label) could not return to controlled mutation authority ($($_.Exception.Message)); preserving descendants."
      $pcCloseOk = $false
      break
    }
  }
  if (-not $pcCloseOk) { return $false }
  for ($pcFileI = $Context.Files.Count - 1; $pcFileI -ge 0; $pcFileI--) {
    if (-not (Remove-CrgImmutableGitScratchFile -File $Context.Files[$pcFileI])) { $pcCloseOk = $false }
  }
  for ($pcDirI = $Context.Directories.Count - 1; $pcDirI -ge 0; $pcDirI--) {
    $pcDir = $Context.Directories[$pcDirI]
    if ($null -ne $pcDir.Handle) {
      [CrgBootstrap.NativeV4]::UnregisterRootedIo($pcDir.Path, $pcDir.Handle)
      $pcDirRemoved = if ($pcDir.ReadOnlyPin) { Remove-CrgPinnedScratchDirectory -Path $pcDir.Path -Handle $pcDir.Handle -Label $pcDir.Label } else { Remove-CrgOwnedScratchHandle -Path $pcDir.Path -Handle $pcDir.Handle -Directory -Label $pcDir.Label }
      if (-not $pcDirRemoved) { $pcCloseOk = $false }
      $pcDir.Handle = $null
    }
  }
  return $pcCloseOk
}

function Convert-CrgGitHexObjectIdToBytes {
  param([string]$ObjectId)
  if ($ObjectId -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { throw 'tree builder received a malformed object ID' }
  $ghBytes = New-Object byte[] ($ObjectId.Length / 2)
  for ($ghI = 0; $ghI -lt $ghBytes.Length; $ghI++) { $ghBytes[$ghI] = [Convert]::ToByte($ObjectId.Substring($ghI * 2, 2), 16) }
  return ,$ghBytes
}

function New-CrgGitAttributeSourceTree {
  param(
    [hashtable]$AttributeBuffers,
    [ValidatePattern('\A(?:40|64)\z', Options = 'None')][int]$ObjectIdLength,
    [scriptblock]$WriteObject,
    [AllowEmptyCollection()][string[]]$ProbePaths = @()
  )
  if ($null -eq $AttributeBuffers -or $null -eq $WriteObject) { throw 'attribute-source tree builder received no buffers or object writer' }
  $atEntries = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  $atDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $atFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  [void]$atDirectories.Add('')
  foreach ($atPath in $AttributeBuffers.Keys) {
    $atNorm = "$atPath" -replace '\\', '/'
    if ($atNorm -cnotmatch '\A(?:[A-Za-z0-9._-]+/)*\.gitattributes\z' -or $AttributeBuffers[$atPath] -isnot [byte[]]) { throw "unsafe attribute-source path '$atPath'" }
    foreach ($atComponent in @($atNorm -split '/')) { if ([string]::Equals($atComponent, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($atComponent, '..', [System.StringComparison]::Ordinal)) { throw "unsafe attribute-source component in '$atPath'" } }
    if (-not $atFiles.Add($atNorm)) { throw "duplicate normalized attribute-source path '$atNorm'" }
    $atParent = if ($atNorm.Contains('/')) { $atNorm.Substring(0, $atNorm.LastIndexOf([char]'/')) } else { '' }
    $atName = if ($atNorm.Contains('/')) { $atNorm.Substring($atNorm.LastIndexOf([char]'/') + 1) } else { $atNorm }
    $atCursor = $atParent
    while ($atCursor.Length -gt 0) {
      [void]$atDirectories.Add($atCursor)
      $atCursor = if ($atCursor.Contains('/')) { $atCursor.Substring(0, $atCursor.LastIndexOf([char]'/')) } else { '' }
    }
    if (-not $atEntries.ContainsKey($atParent)) { $atEntries[$atParent] = New-Object 'System.Collections.Generic.List[object]' }
    $atExpectedBlobOid = Get-CrgGitObjectIdOfBytes -Type blob -Bytes ([byte[]]$AttributeBuffers[$atPath]) -ObjectIdLength $ObjectIdLength
    $atBlobOid = & $WriteObject 'blob' ([byte[]]$AttributeBuffers[$atPath])
    if ($atBlobOid -cnotmatch "\A[0-9a-f]{$ObjectIdLength}\z" -or $atBlobOid -cne $atExpectedBlobOid) { throw "attribute blob '$atPath' was not written with the exact target object identity" }
    $atEntries[$atParent].Add([pscustomobject]@{ Mode = '100644'; Name = $atName; Oid = $atBlobOid }) | Out-Null
  }
  foreach ($atProbePath in @($ProbePaths)) {
    $atNorm = "$atProbePath" -replace '\\', '/'
    if ($atNorm -cnotmatch '\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z' -or $atNorm.StartsWith('/', [System.StringComparison]::Ordinal) -or $atNorm.EndsWith('/', [System.StringComparison]::Ordinal)) {
      throw "unsafe attribute-state probe path '$atProbePath'"
    }
    foreach ($atComponent in @($atNorm -split '/')) { if ([string]::Equals($atComponent, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($atComponent, '..', [System.StringComparison]::Ordinal)) { throw "unsafe attribute-state probe component in '$atProbePath'" } }
    if (-not $atFiles.Add($atNorm)) { throw "duplicate or colliding attribute-state probe path '$atNorm'" }
    $atParent = if ($atNorm.Contains('/')) { $atNorm.Substring(0, $atNorm.LastIndexOf([char]'/')) } else { '' }
    $atName = if ($atNorm.Contains('/')) { $atNorm.Substring($atNorm.LastIndexOf([char]'/') + 1) } else { $atNorm }
    $atCursor = $atParent
    while ($atCursor.Length -gt 0) {
      [void]$atDirectories.Add($atCursor)
      $atCursor = if ($atCursor.Contains('/')) { $atCursor.Substring(0, $atCursor.LastIndexOf([char]'/')) } else { '' }
    }
    if (-not $atEntries.ContainsKey($atParent)) { $atEntries[$atParent] = New-Object 'System.Collections.Generic.List[object]' }
    [byte[]]$atProbeBytes = @()
    $atExpectedProbeOid = Get-CrgGitObjectIdOfBytes -Type blob -Bytes $atProbeBytes -ObjectIdLength $ObjectIdLength
    $atProbeOid = & $WriteObject 'blob' $atProbeBytes
    if ($atProbeOid -cnotmatch "\A[0-9a-f]{$ObjectIdLength}\z" -or $atProbeOid -cne $atExpectedProbeOid) { throw "attribute-state probe '$atProbePath' was not written with the exact target object identity" }
    $atEntries[$atParent].Add([pscustomobject]@{ Mode = '100644'; Name = $atName; Oid = $atProbeOid }) | Out-Null
  }
  foreach ($atFile in $atFiles) { if ($atDirectories.Contains($atFile)) { throw "attribute-source file/directory collision at '$atFile'" } }
  $atTreeOids = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  $atMaxDepth = 0
  foreach ($atDirName in $atDirectories) { $atDepth = if ($atDirName.Length -eq 0) { 0 } else { @($atDirName -split '/').Count }; if ($atDepth -gt $atMaxDepth) { $atMaxDepth = $atDepth } }
  $atOrderedDirs = New-Object 'System.Collections.Generic.List[string]'
  for ($atDepth = $atMaxDepth; $atDepth -ge 0; $atDepth--) {
    $atAtDepth = New-Object 'System.Collections.Generic.List[string]'
    foreach ($atDirName in $atDirectories) {
      $atDirDepth = if ($atDirName.Length -eq 0) { 0 } else { @($atDirName -split '/').Count }
      if ($atDirDepth -eq $atDepth) { $atAtDepth.Add($atDirName) }
    }
    $atAtDepth.Sort([System.StringComparer]::Ordinal)
    foreach ($atDirName in $atAtDepth) { $atOrderedDirs.Add($atDirName) }
  }
  foreach ($atDir in $atOrderedDirs) {
    $atDirect = New-Object 'System.Collections.Generic.List[object]'
    if ($atEntries.ContainsKey($atDir)) { foreach ($atEntry in $atEntries[$atDir]) { $atDirect.Add($atEntry) | Out-Null } }
    foreach ($atChildDir in $atTreeOids.Keys) {
      $atChildParent = if ($atChildDir.Contains('/')) { $atChildDir.Substring(0, $atChildDir.LastIndexOf([char]'/')) } else { '' }
      if ($atChildParent -ceq $atDir) {
        $atChildName = if ($atChildDir.Contains('/')) { $atChildDir.Substring($atChildDir.LastIndexOf([char]'/') + 1) } else { $atChildDir }
        $atDirect.Add([pscustomobject]@{ Mode = '40000'; Name = $atChildName; Oid = $atTreeOids[$atChildDir] }) | Out-Null
      }
    }
    $atDirectMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    foreach ($atEntry in $atDirect) {
      if ($atDirectMap.ContainsKey($atEntry.Name)) { throw "duplicate Git tree entry '$($atEntry.Name)' below '$atDir'" }
      $atDirectMap[$atEntry.Name] = $atEntry
    }
    $atDirectSort = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    $atDirectKeys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($atEntryName in $atDirectMap.Keys) {
      $atEntryForKey = $atDirectMap[$atEntryName]
      $atSortKey = $atEntryName + $(if ($atEntryForKey.Mode -ceq '40000') { '/' } else { '' })
      if ($atDirectSort.ContainsKey($atSortKey)) { throw "ambiguous canonical Git tree ordering below '$atDir'" }
      $atDirectSort[$atSortKey] = $atEntryForKey
      $atDirectKeys.Add($atSortKey)
    }
    $atDirectKeys.Sort([System.StringComparer]::Ordinal)
    $atTreeStream = New-Object System.IO.MemoryStream
    try {
      foreach ($atSortKey in $atDirectKeys) {
        $atEntry = $atDirectSort[$atSortKey]
        $atPrefix = [System.Text.Encoding]::ASCII.GetBytes("$($atEntry.Mode) $($atEntry.Name)`0")
        $atTreeStream.Write($atPrefix, 0, $atPrefix.Length)
        [byte[]]$atOidBytes = Convert-CrgGitHexObjectIdToBytes -ObjectId $atEntry.Oid
        $atTreeStream.Write($atOidBytes, 0, $atOidBytes.Length)
      }
      [byte[]]$atTreeBytes = $atTreeStream.ToArray()
    } finally { $atTreeStream.Dispose() }
    $atExpectedTreeOid = Get-CrgGitObjectIdOfBytes -Type tree -Bytes $atTreeBytes -ObjectIdLength $ObjectIdLength
    $atTreeOid = & $WriteObject 'tree' $atTreeBytes
    if ($atTreeOid -cnotmatch "\A[0-9a-f]{$ObjectIdLength}\z" -or $atTreeOid -cne $atExpectedTreeOid) { throw "attribute tree '$atDir' was not written with the exact target object identity" }
    $atTreeOids[$atDir] = $atTreeOid
  }
  return $atTreeOids['']
}

# `git check-attr` renders both a special state and a colliding literal string
# as the same word (`set`, `unset`, or `unspecified`). Attribute pathspec
# predicates retain that type distinction. The pathspecs per path below
# enumerate the only accepted state combinations without invoking conversion
# or any target-configured clean/smudge driver.
function Assert-CrgPrivateInstallValuesAttributeStates {
  param([object]$Context, [string]$TreeOid, [string[]]$Paths)
  if ($null -eq $Context -or $TreeOid -cnotmatch "\A[0-9a-f]{$($Context.ObjectIdLength)}\z" -or $null -eq $Paths -or $Paths.Count -lt 1) {
    throw 'private install-values attribute-state proof received an invalid context, tree, or path inventory'
  }
  $asExpected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $asPathspecs = New-Object 'System.Collections.Generic.List[string]'
  foreach ($asPath in $Paths) {
    if ($asPath -cnotmatch '\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z' -or $asPath.StartsWith('/', [System.StringComparison]::Ordinal) -or $asPath.EndsWith('/', [System.StringComparison]::Ordinal)) {
      throw "unsafe private install-values attribute-state path '$asPath'"
    }
    foreach ($asComponent in @($asPath -split '/')) { if ([string]::Equals($asComponent, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($asComponent, '..', [System.StringComparison]::Ordinal)) { throw "unsafe private install-values attribute-state path '$asPath'" } }
    if (-not $asExpected.Add($asPath)) { throw "duplicate private install-values attribute-state path '$asPath'" }
    for ($asMask = 0; $asMask -lt 8; $asMask++) {
      $asFilter = if (($asMask -band 1) -ne 0) { '!filter' } else { '-filter' }
      $asIdent = if (($asMask -band 2) -ne 0) { '!ident' } else { '-ident' }
      $asEncoding = if (($asMask -band 4) -ne 0) { '!working-tree-encoding' } else { '-working-tree-encoding' }
      $asPathspecs.Add(":(top,attr:text eol=lf $asFilter $asIdent $asEncoding)$asPath") | Out-Null
    }
  }
  $asResult = Invoke-CrgPrivateAttributeGit -Context $Context -GitArgs (@(
    "--attr-source=$TreeOid", 'ls-files', '-z', '--cached', "--with-tree=$TreeOid", '--'
  ) + $asPathspecs.ToArray())
  if ($asResult.Exit -ne 0 -or $asResult.ErrorText.Length -ne 0) {
    throw "private state-sensitive attribute query failed (exit $($asResult.Exit)): $($asResult.Text.Trim())"
  }
  $asActual = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  if ($asResult.Bytes.Length -gt 0) {
    $asText = $script:CrgUtf8Strict.GetString($asResult.Bytes)
    $asParts = $asText.Split([char[]]@([char]0), [System.StringSplitOptions]::None)
    if ($asParts.Count -lt 2 -or $asParts[$asParts.Count - 1].Length -ne 0) { throw 'private state-sensitive attribute query returned malformed NUL-delimited paths' }
    for ($asI = 0; $asI -lt ($asParts.Count - 1); $asI++) {
      if (-not $asExpected.Contains($asParts[$asI]) -or -not $asActual.Add($asParts[$asI])) {
        throw "private state-sensitive attribute query returned an unexpected or duplicate path '$($asParts[$asI])'"
      }
    }
  }
  foreach ($asPath in $Paths) {
    if (-not $asActual.Contains($asPath)) {
      throw "'$asPath' does not resolve to exact special text=set, eol=lf, and filter/ident/working-tree-encoding unset-or-unspecified states (an overriding or string-valued collision is active)"
    }
  }
}

function Get-CrgSha256HexOfBytes {
  param([byte[]]$Bytes)
  $crgBSha = [System.Security.Cryptography.SHA256]::Create()
  try { return ([System.BitConverter]::ToString($crgBSha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() } finally { $crgBSha.Dispose() }
}
# Classify what occupies a path for a FAILURE DIAGNOSIS. Absence is decided
# by the no-follow open's OWN status ('empty' only on ERROR_FILE_NOT_FOUND /
# ERROR_PATH_NOT_FOUND), and a file occupant's shape is read from the opened
# handle. OpenReadNoFollow cannot open a directory or a directory reparse
# point (no backup semantics), so those shapes are read from the
# pathname ATTRIBUTES, which do not follow links -- a DANGLING junction thus
# reports 'reparse' where Test-Path reported absence. Any other open failure
# is 'unknown:<error>'.
function Get-CrgPathOccupantKind {
  param([string]$Path)
  $h = $null
  $err = 0
  try {
    try { $h = [CrgBootstrap.NativeV4]::OpenReadShareReadNoFollow($Path, [ref]$err) } catch { $h = $null; $err = -1 }
    if ($null -eq $h -or $h.IsInvalid) {
      if ($err -eq 2 -or $err -eq 3) { return 'empty' }
      # A directory (or a directory reparse point) refuses a plain file open;
      # the pathname attribute probe distinguishes those shapes without
      # following anything.
      try {
        $attrs = [System.IO.File]::GetAttributes($Path)
        if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return 'reparse' }
        if (($attrs -band [System.IO.FileAttributes]::Directory) -ne 0) { return 'directory' }
      } catch { }
      return "unknown:$err"
    }
    $shape = [CrgBootstrap.NativeV3]::GetHandleAttributes($h)
    if ($shape -lt 0) { return 'unknown:attributes' }
    if ($shape -band 0x400) { return 'reparse' }
    if ($shape -band 0x10) { return 'directory' }
    return 'file'
  } finally {
    if ($null -ne $h -and -not $h.IsInvalid) { $h.Dispose() }
  }
}

# The native type name is VERSIONED: a type name, once loaded, can
# never be redefined in a PowerShell process, so an unversioned guard
# would accept an OLDER bootstrap's definition (missing the newer
# methods) whenever both versions run in one process, and every newer
# call would fail method resolution. A new method set gets a new
# suffix.
if (-not ('CrgBootstrap.NativeV3' -as [type])) {
  Add-Type -Namespace 'CrgBootstrap' -Name 'NativeV3' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);

// Opens an EXCLUSIVE REWRITE handle on an existing file:
// GENERIC_READ|GENERIC_WRITE access with a share mode of NONE, so
// every other open -- reads included -- fails while it is held; a
// hook held this way makes a concurrent `git commit` FAIL CLOSED
// (git cannot spawn an unopenable hook) instead of running ungated.
// FILE_FLAG_OPEN_REPARSE_POINT keeps a racer-planted symlink from
// silently redirecting the open to its target (callers refuse the
// reparse shape before opening). Returns an invalid handle on
// failure (caller probes).
//
// WARNING -- rejected namespace-transition designs, do not retry
// (2026-08-28, each one review-blocked or platform-refused):
//   1. custody-rename then create: a LONG empty-name interval where
//      git silently runs no hook;
//   2. rename-with-replace with the source held: Win32 refuses a
//      replace onto a held destination (error 5 on every refresh;
//      FileShare.Delete does not exempt it);
//   3. release-then-replace: a racer's destination file is silently
//      overwritten (replace cannot validate destination identity);
//   4. POSIX-disposition unlink through the handle: reported success
//      but left a delete-pending name denying every reclaim;
//   5. rename-aside through the handle then create-only move: still
//      an empty-name instant a concurrent commit can cross ungated.
// The IN-PLACE rewrite through this exclusive handle is the design
// that satisfies "a fail-closed hook at every observable instant":
// the name never changes, other openers fail loudly while it is
// held, and the disarm-first write protocol (the shebang re-armed
// by one atomic byte only after the body verifies) keeps every torn
// write state refusing at spawn -- git will not run a hook without
// a shebang. The lone diagnosed exception: a disarm whose own
// confirmation fails is reported as possibly armed, never claimed
// safe.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenExclusive(string path) {
    return CreateFileW(path, 0x80000000u | 0x40000000u, 0x0u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
}

public struct BY_HANDLE_FILE_INFORMATION {
    public uint FileAttributes;
    public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
}

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

// A hard-linked file has ONE file object under many names, so an
// in-place rewrite through any alias rewrites them all -- callers
// refuse multi-link occupants before the first write. Returns -1
// when the count cannot be queried (callers fail closed on it).
public static int GetLinkCount(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(handle, out info)) { return -1; }
    return (int)info.NumberOfLinks;
}

// OpenExclusive plus the Win32 status of a FAILED open: a caller decides
// "positively absent" from ERROR_FILE_NOT_FOUND alone. A pathname probe
// reports a DANGLING reparse point as absent, and a follow-open create
// reached on that answer would create the link's TARGET; the no-follow
// open here opens the link itself, so the caller classifies it on the
// handle (GetHandleAttributes) instead.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenExclusive2(string path, out int error) {
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u | 0x40000000u, 0x0u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Read-share no-follow open for a file consumed as INPUT (an attribute
// source copied into the isolated context); the shape is classified on
// the handle before any byte is read.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenReadNoFollow(string path, out int error) {
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u, 0x1u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Atomic no-follow CREATE_NEW (disposition 1): under
// FILE_FLAG_OPEN_REPARSE_POINT the name's reparse point IS the occupant,
// so a dangling symlink collides (ERROR_FILE_EXISTS) instead of being
// followed to create its target. Every fixed-name create site uses this
// (a System.IO CreateNew follows the link).
public static Microsoft.Win32.SafeHandles.SafeFileHandle CreateNewNoFollow(string path, out int error) {
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u | 0x40000000u, 0x0u, System.IntPtr.Zero, 1u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Attributes of the OPEN object, never of a pathname: a reparse point
// opened no-follow reports FILE_ATTRIBUTE_REPARSE_POINT (0x400) here, a
// directory 0x10. Returns -1 when unqueryable (callers fail closed).
public static long GetHandleAttributes(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(handle, out info)) { return -1; }
    return (long)info.FileAttributes;
}
'@
}
# INTERPROCESS TRANSACTION LOCK: authority comes from a no-follow ordinary
# single-link lock object held with
# FileShare.None. The persistent pathname is never deleted. Cooperative
# bootstraps serialize, while every metadata object that can authorize a
# replacement is independently held across the full hostile-writer window.
function Open-CrgTransactionLockNoFollow {
  param([string]$Path, [string]$Name)
  $crgLkHandle = $null
  $crgLkStream = $null
  $crgLkError = 0
  try {
    try { $crgLkHandle = [CrgBootstrap.NativeV4]::OpenLockNoFollow($Path, [ref]$crgLkError) }
    catch { $crgLkHandle = $null; $crgLkError = -1 }
    if ($null -eq $crgLkHandle -or $crgLkHandle.IsInvalid) {
      throw "no-follow exclusive open failed (Win32 error $crgLkError)"
    }
    $crgLkAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($crgLkHandle)
    $crgLkLinks = [CrgBootstrap.NativeV3]::GetLinkCount($crgLkHandle)
    if ($crgLkAttrs -lt 0 -or ($crgLkAttrs -band 0x410) -ne 0 -or $crgLkLinks -ne 1) {
      throw "the held lock occupant is not one ordinary non-reparse single-link file (attributes=$crgLkAttrs, links=$crgLkLinks)"
    }
    $crgLkStream = New-Object System.IO.FileStream($crgLkHandle, [System.IO.FileAccess]::ReadWrite)
    $crgLkHandle = $null
    return $crgLkStream
  } catch {
    if ($null -ne $crgLkStream) { try { $crgLkStream.Dispose() } catch { } }
    Write-Host "[bootstrap] ERROR: could not acquire the $Name transaction lock at '$Path' ($($_.Exception.Message)) - commonly another bootstrap run holding the exact lock object, or a directory/reparse/hard-link occupant that cannot carry lock authority. Preserve the occupant, repair the path deliberately, then re-run."
    return $null
  } finally {
    if ($null -ne $crgLkHandle -and -not $crgLkHandle.IsInvalid) { try { $crgLkHandle.Dispose() } catch { } }
  }
}

function Read-CrgHeldStreamBytes {
  param([object]$Stream, [int64]$MaxLength, [string]$Label)
  if ($null -eq $Stream -or -not $Stream.CanRead -or -not $Stream.CanSeek -or $MaxLength -lt 0) { throw "a readable seekable held stream is required for $Label" }
  $crgRbPos = $Stream.Position
  try {
    if ($Stream.Length -gt $MaxLength -or $Stream.Length -gt [int]::MaxValue) { throw "$Label exceeds its $MaxLength-byte bound" }
    $Stream.Position = 0
    $crgRbBytes = New-Object byte[] ([int]$Stream.Length)
    $crgRbRead = 0
    while ($crgRbRead -lt $crgRbBytes.Length) {
      $crgRbGot = $Stream.Read($crgRbBytes, $crgRbRead, $crgRbBytes.Length - $crgRbRead)
      if ($crgRbGot -le 0) { break }
      $crgRbRead += $crgRbGot
    }
    if ($crgRbRead -ne $crgRbBytes.Length) { throw "$Label could not be read exactly through its retained owner" }
    return ,([byte[]]$crgRbBytes)
  } finally { $Stream.Position = $crgRbPos }
}

# The package's own version, read from the published source's VERSION file --
# never a constant duplicated in code, because a second copy is a value that can
# disagree with the file a release tags.
#
# The reader returns $null for missing or malformed bytes rather than inventing
# a value, and source publication refuses that result.
#
# Validated on the RAW BYTES against an exact grammar, before any normalization.
# Trimming first and validating after cannot enforce a single-line contract: the
# trim removes the very CR/LF a multi-line file would be rejected for, so
# blank-wrapped multi-line content passes a later `[\r\n]` test. The grammar is
# SemVer because the version exists to be COMPARED -- an arbitrary printable
# string satisfies "a version was recorded" while making "is this newer"
# undecidable, so accepting one would defer a contradiction into the upgrade
# path rather than reject it here.
# ONE SemVer accept-set, used by the package VERSION reader and the runtime
# manifest reader alike, so a manifest cannot record a version the package's
# own reader would reject.
$script:CrgSemVerBody = "\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)" +
                        "(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?" +
                        "(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?"

# Reads BYTES so the version is derived from the buffered snapshot that
# provenance is proven against, without a second re-read of a file that may
# have changed since.
function Get-CrgPackageVersionFromBytes {
  param([byte[]]$Bytes)
  $verBytes = $Bytes
  if ($null -eq $verBytes) { return $null }
  return (Convert-CrgVersionBytes -Bytes $verBytes)
}

function Convert-CrgVersionBytes {
  param([byte[]]$Bytes)
  $verBytes = $Bytes
  # Bounded before decode: the file is a version string, so anything large is
  # not a truncated version but a different file in the version's place.
  if ($verBytes.Length -eq 0 -or $verBytes.Length -gt 128) { return $null }
  # A UTF-8 BOM is a legitimate authoring artifact on this platform and is the
  # only prefix skipped; every other byte must satisfy the grammar below.
  $verOff = 0
  if ($verBytes.Length -ge 3 -and $verBytes[0] -eq 0xEF -and $verBytes[1] -eq 0xBB -and $verBytes[2] -eq 0xBF) { $verOff = 3 }
  $verText = [System.Text.Encoding]::ASCII.GetString($verBytes, $verOff, $verBytes.Length - $verOff)
  # EXACTLY one SemVer line, with at most one trailing terminator. `\A...\z` is
  # what makes this a whole-file assertion -- `^...$` matches per line in .NET,
  # which is precisely the hole that let blank-wrapped content through.
  #
  # The identifier rules are the published SemVer ones, not a permissive
  # character class: a prerelease is dot-separated NON-EMPTY identifiers, a
  # numeric one carries no leading zero, and build metadata is dot-separated
  # non-empty alphanumerics. A loose `[0-9A-Za-z.-]+` accepts `2.0.0-01`,
  # `2.0.0-rc..1`, and `2.0.0-.`, none of which order against anything -- which
  # defeats the only reason to demand SemVer here.
  #
  # The terminator is GROUPED as `(\r\n|\n)`: independent `\r?` and `\n?`
  # quantifiers accept a lone carriage return, a shape no editor produces and
  # nothing downstream expects.
  if ($verText -cnotmatch ($script:CrgSemVerBody + "(\r\n|\n)?\z")) { return $null }
  return $verText.TrimEnd("`r", "`n")
}

# V4 adds identity-bound scratch cleanup and no-follow persistent lock opens.
# V3 is intentionally immutable once loaded in a PowerShell process (see the
# versioning note above it), so the new Win32 surface receives a new type name.
if (-not ('CrgBootstrap.NativeV4' -as [type])) {
  Add-Type -Namespace 'CrgBootstrap' -Name 'NativeV4' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool GetFileInformationByHandleEx(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, int fileInformationClass, out FILE_ID_INFO lpFileInformation, uint dwBufferSize);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool CloseHandle(System.IntPtr hObject);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool SetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, int fileInformationClass, System.IntPtr lpFileInformation, uint dwBufferSize);

[System.Runtime.InteropServices.DllImport("ntdll.dll")]
static extern int NtCreateFile(out System.IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, System.IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions, System.IntPtr eaBuffer, uint eaLength);

[System.Runtime.InteropServices.DllImport("ntdll.dll")]
static extern int NtSetInformationFile(Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock, System.IntPtr fileInformation, uint length, int fileInformationClass);

[System.Runtime.InteropServices.DllImport("ntdll.dll")]
static extern uint RtlNtStatusToDosError(int status);

[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct UNICODE_STRING {
    public ushort Length;
    public ushort MaximumLength;
    public System.IntPtr Buffer;
}

[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES {
    public int Length;
    public System.IntPtr RootDirectory;
    public System.IntPtr ObjectName;
    public uint Attributes;
    public System.IntPtr SecurityDescriptor;
    public System.IntPtr SecurityQualityOfService;
}

[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct IO_STATUS_BLOCK {
    public System.IntPtr Status;
    public System.IntPtr Information;
}

public struct BY_HANDLE_FILE_INFORMATION {
    public uint FileAttributes;
    public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
}

[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct FILE_ID_INFO {
    public ulong VolumeSerialNumber;
    [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] FileId;
}

private sealed class ROOT_BINDING {
    public string Path;
    public Microsoft.Win32.SafeHandles.SafeFileHandle Handle;
    public bool Mutation;
}

private sealed class RELATIVE_PARENT_LEASE : System.IDisposable {
    public Microsoft.Win32.SafeHandles.SafeFileHandle Parent;
    public string Leaf;
    public System.Collections.Generic.List<Microsoft.Win32.SafeHandles.SafeFileHandle> Temporaries = new System.Collections.Generic.List<Microsoft.Win32.SafeHandles.SafeFileHandle>();
    public Microsoft.Win32.SafeHandles.SafeFileHandle Root;
    public bool RootAdded;
    public void Dispose() {
        for (int i = Temporaries.Count - 1; i >= 0; i--) { try { Temporaries[i].Dispose(); } catch { } }
        Temporaries.Clear();
        if (RootAdded && Root != null) { try { Root.DangerousRelease(); } catch { } }
        RootAdded = false;
        Parent = null;
        Root = null;
    }
}

private static readonly object RootedIoSync = new object();
private static readonly System.Collections.Generic.List<ROOT_BINDING> RootedIoRoots = new System.Collections.Generic.List<ROOT_BINDING>();
private static bool RootedIoRequired = false;

private static string NormalizeRootedPath(string path) {
    if (System.String.IsNullOrWhiteSpace(path) || path.StartsWith("\\\\.\\", System.StringComparison.Ordinal) || path.StartsWith("\\\\?\\", System.StringComparison.Ordinal) || path.StartsWith("\\??\\", System.StringComparison.Ordinal)) { throw new System.ArgumentException("unsupported device namespace", "path"); }
    string full = System.IO.Path.GetFullPath(path);
    string root = System.IO.Path.GetPathRoot(full);
    if (!System.String.Equals(full, root, System.StringComparison.OrdinalIgnoreCase)) { full = full.TrimEnd('\\', '/'); }
    return full;
}

public static void ClearRootedIo() {
    lock (RootedIoSync) { RootedIoRequired = false; RootedIoRoots.Clear(); }
}

public static bool RegisterRootedIo(string path, Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    return RegisterRootedIo(path, handle, false);
}

public static bool RegisterRootedIo(string path, Microsoft.Win32.SafeHandles.SafeFileHandle handle, bool mutation) {
    if (handle == null || handle.IsInvalid) { return false; }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(handle, out info) || (info.FileAttributes & 0x10u) == 0 || (info.FileAttributes & 0x400u) != 0) { return false; }
    string full = NormalizeRootedPath(path);
    lock (RootedIoSync) {
        for (int i = 0; i < RootedIoRoots.Count; i++) {
            ROOT_BINDING existing = RootedIoRoots[i];
            if (!System.String.Equals(existing.Path, full, System.StringComparison.OrdinalIgnoreCase)) { continue; }
            if (System.Object.ReferenceEquals(existing.Handle, handle)) {
                return existing.Mutation == mutation;
            }
            if (!SameFileIdentity(existing.Handle, handle)) { return false; }
            // Authority grade changes require an explicit unregister/handoff.
            // Parallel handles for one path may coexist only at one grade.
            if (existing.Mutation != mutation) { return false; }
        }
        ROOT_BINDING binding = new ROOT_BINDING();
        binding.Path = full;
        binding.Handle = handle;
        binding.Mutation = mutation;
        RootedIoRoots.Add(binding);
    }
    return true;
}

public static void UnregisterRootedIo(string path, Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    string full;
    try { full = NormalizeRootedPath(path); } catch { return; }
    lock (RootedIoSync) {
        for (int i = RootedIoRoots.Count - 1; i >= 0; i--) {
            if (System.String.Equals(RootedIoRoots[i].Path, full, System.StringComparison.OrdinalIgnoreCase) &&
                (handle == null || System.Object.ReferenceEquals(RootedIoRoots[i].Handle, handle))) { RootedIoRoots.RemoveAt(i); }
        }
    }
}

public static void RequireRootedIo(bool required) {
    lock (RootedIoSync) { RootedIoRequired = required; }
}

private static Microsoft.Win32.SafeHandles.SafeFileHandle InvalidHandle() {
    return new Microsoft.Win32.SafeHandles.SafeFileHandle(new System.IntPtr(-1), true);
}

public static long GetHandleAttributes(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
    if (handle == null || handle.IsInvalid) { return -1; }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(handle, out info)) { return -1; }
    return (long)info.FileAttributes;
}

public static bool SameFileIdentity(Microsoft.Win32.SafeHandles.SafeFileHandle left, Microsoft.Win32.SafeHandles.SafeFileHandle right) {
    if (left == null || left.IsInvalid || right == null || right.IsInvalid) { return false; }
    FILE_ID_INFO a;
    FILE_ID_INFO b;
    uint size = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(FILE_ID_INFO));
    if (!GetFileInformationByHandleEx(left, 18, out a, size) || !GetFileInformationByHandleEx(right, 18, out b, size) || a.FileId == null || b.FileId == null || a.FileId.Length != 16 || b.FileId.Length != 16 || a.VolumeSerialNumber != b.VolumeSerialNumber) { return false; }
    for (int i = 0; i < 16; i++) { if (a.FileId[i] != b.FileId[i]) { return false; } }
    return true;
}

private static bool ValidRelativeComponent(string component) {
    if (System.String.IsNullOrEmpty(component) || component == "." || component == "..") { return false; }
    if (component.IndexOf('\\') >= 0 || component.IndexOf('/') >= 0 || component.IndexOf(':') >= 0 || component.IndexOf('\0') >= 0 || component.EndsWith(".", System.StringComparison.Ordinal) || component.EndsWith(" ", System.StringComparison.Ordinal)) { return false; }
    string stem = component.Split('.')[0].ToUpperInvariant();
    if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CLOCK$" ||
        (stem.Length == 4 && (stem.StartsWith("COM", System.StringComparison.Ordinal) || stem.StartsWith("LPT", System.StringComparison.Ordinal)) && stem[3] >= '1' && stem[3] <= '9')) { return false; }
    return true;
}

private static Microsoft.Win32.SafeHandles.SafeFileHandle NtOpenRelative(Microsoft.Win32.SafeHandles.SafeFileHandle parent, string component, uint desiredAccess, uint shareAccess, uint disposition, uint options, out int error) {
    error = unchecked((int)0xC000000D);
    if (parent == null || parent.IsInvalid || !ValidRelativeComponent(component)) { return InvalidHandle(); }
    System.IntPtr text = System.IntPtr.Zero;
    System.IntPtr name = System.IntPtr.Zero;
    System.IntPtr rawHandle = System.IntPtr.Zero;
    bool parentAdded = false;
    try {
        parent.DangerousAddRef(ref parentAdded);
        text = System.Runtime.InteropServices.Marshal.StringToHGlobalUni(component);
        UNICODE_STRING unicode = new UNICODE_STRING();
        unicode.Length = checked((ushort)(component.Length * 2));
        unicode.MaximumLength = unicode.Length;
        unicode.Buffer = text;
        name = System.Runtime.InteropServices.Marshal.AllocHGlobal(System.Runtime.InteropServices.Marshal.SizeOf(typeof(UNICODE_STRING)));
        System.Runtime.InteropServices.Marshal.StructureToPtr(unicode, name, false);
        OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
        attributes.Length = System.Runtime.InteropServices.Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        attributes.RootDirectory = parent.DangerousGetHandle();
        attributes.ObjectName = name;
        attributes.Attributes = 0x40u;
        IO_STATUS_BLOCK status;
        int ntStatus = NtCreateFile(out rawHandle, desiredAccess | 0x00100000u, ref attributes, out status, System.IntPtr.Zero, 0x80u, shareAccess, disposition, options | 0x20u, System.IntPtr.Zero, 0u);
        error = ntStatus < 0 ? unchecked((int)RtlNtStatusToDosError(ntStatus)) : 0;
        System.GC.KeepAlive(parent);
        if (ntStatus < 0 || rawHandle == System.IntPtr.Zero || rawHandle == new System.IntPtr(-1)) {
            if (rawHandle != System.IntPtr.Zero && rawHandle != new System.IntPtr(-1)) { CloseHandle(rawHandle); }
            return InvalidHandle();
        }
        try {
            Microsoft.Win32.SafeHandles.SafeFileHandle owned = new Microsoft.Win32.SafeHandles.SafeFileHandle(rawHandle, true);
            rawHandle = System.IntPtr.Zero;
            return owned;
        } catch {
            if (rawHandle != System.IntPtr.Zero && rawHandle != new System.IntPtr(-1)) { CloseHandle(rawHandle); }
            throw;
        }
    } finally {
        if (parentAdded) { parent.DangerousRelease(); }
        if (name != System.IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(name); }
        if (text != System.IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(text); }
    }
}

private static bool TryResolveRelativeParent(string path, bool mutation, out RELATIVE_PARENT_LEASE lease, out int error) {
    lease = null;
    error = 3;
    string full;
    try { full = NormalizeRootedPath(path); } catch { error = 123; return false; }
    ROOT_BINDING authority = null;
    ROOT_BINDING selectedParent = null;
    lock (RootedIoSync) {
        for (int i = 0; i < RootedIoRoots.Count; i++) {
            ROOT_BINDING candidate = RootedIoRoots[i];
            string prefix = candidate.Path.EndsWith("\\", System.StringComparison.Ordinal) ? candidate.Path : candidate.Path + "\\";
            bool exact = System.String.Equals(full, candidate.Path, System.StringComparison.OrdinalIgnoreCase);
            bool descendant = full.StartsWith(prefix, System.StringComparison.OrdinalIgnoreCase);
            if (!exact && !descendant) { continue; }
            if (authority == null || candidate.Path.Length > authority.Path.Length) { authority = candidate; }
            if (descendant && (selectedParent == null || candidate.Path.Length > selectedParent.Path.Length)) { selectedParent = candidate; }
        }
    }
    // The deepest registered namespace owns authority for every descendant.
    // Exact roots participate too: a read-only child denies mutation instead
    // of exposing a writable ancestor as an alternate route to the same name.
    if (authority != null && mutation && !authority.Mutation) { error = 5; return false; }
    if (authority == null || authority.Handle == null || authority.Handle.IsInvalid) { return false; }
    BY_HANDLE_FILE_INFORMATION authorityInfo;
    if (!GetFileInformationByHandle(authority.Handle, out authorityInfo) || (authorityInfo.FileAttributes & 0x10u) == 0 || (authorityInfo.FileAttributes & 0x400u) != 0) { error = 4390; return false; }
    // Relative NT opens need a strict ancestor even when the exact binding
    // supplied authority for the operation on that binding's own path.
    if (selectedParent == null || selectedParent.Handle == null || selectedParent.Handle.IsInvalid) { return false; }
    BY_HANDLE_FILE_INFORMATION selectedInfo;
    if (!GetFileInformationByHandle(selectedParent.Handle, out selectedInfo) || (selectedInfo.FileAttributes & 0x10u) == 0 || (selectedInfo.FileAttributes & 0x400u) != 0) { error = 4390; return false; }
    string relative = full.Substring(selectedParent.Path.Length).TrimStart('\\', '/');
    string[] components = relative.Split(new char[] { '\\', '/' }, System.StringSplitOptions.RemoveEmptyEntries);
    if (components.Length == 0) { error = 123; return false; }
    for (int i = 0; i < components.Length; i++) { if (!ValidRelativeComponent(components[i])) { error = 123; return false; } }
    RELATIVE_PARENT_LEASE result = new RELATIVE_PARENT_LEASE();
    result.Root = selectedParent.Handle;
    try {
        selectedParent.Handle.DangerousAddRef(ref result.RootAdded);
        Microsoft.Win32.SafeHandles.SafeFileHandle parent = selectedParent.Handle;
        for (int i = 0; i < components.Length - 1; i++) {
            int openError;
            uint parentAccess = mutation ? 0xA3u : 0xA1u;
            uint parentShare = mutation ? 0x3u : 0x1u;
            Microsoft.Win32.SafeHandles.SafeFileHandle next = NtOpenRelative(parent, components[i], parentAccess, parentShare, 1u, 0x00200001u, out openError);
            if (next == null || next.IsInvalid) { if (next != null) { next.Dispose(); } error = openError; result.Dispose(); return false; }
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(next, out info) || (info.FileAttributes & 0x10u) == 0 || (info.FileAttributes & 0x400u) != 0) {
                error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                next.Dispose();
                result.Dispose();
                return false;
            }
            result.Temporaries.Add(next);
            parent = next;
        }
        result.Parent = parent;
        result.Leaf = components[components.Length - 1];
        lease = result;
        error = 0;
        return true;
    } catch {
        result.Dispose();
        throw;
    }
}

private static bool HasRootedIoMatch(string path) {
    string full;
    try { full = NormalizeRootedPath(path); } catch { return false; }
    lock (RootedIoSync) {
        for (int i = 0; i < RootedIoRoots.Count; i++) {
            string root = RootedIoRoots[i].Path;
            string prefix = root.EndsWith("\\", System.StringComparison.Ordinal) ? root : root + "\\";
            if (System.String.Equals(full, root, System.StringComparison.OrdinalIgnoreCase) || full.StartsWith(prefix, System.StringComparison.OrdinalIgnoreCase)) { return true; }
        }
    }
    return false;
}

private static bool IsRootedIoRequired() { lock (RootedIoSync) { return RootedIoRequired; } }

private static Microsoft.Win32.SafeHandles.SafeFileHandle OpenRootedLeaf(string path, bool mutation, uint desiredAccess, uint shareAccess, uint disposition, uint options, out int error, out bool matched) {
    RELATIVE_PARENT_LEASE lease;
    error = 3;
    matched = HasRootedIoMatch(path);
    if (!matched || !TryResolveRelativeParent(path, mutation, out lease, out error)) { return InvalidHandle(); }
    try { return NtOpenRelative(lease.Parent, lease.Leaf, desiredAccess, shareAccess, disposition, options, out error); }
    finally { lease.Dispose(); }
}

// OPEN_ALWAYS, no-follow, and FileShare.None make the persistent lock file's
// held object -- not path existence -- the transaction authority. BACKUP_SEMANTICS
// lets callers classify and reject a directory occupant through the same handle.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenLockNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x80000000u | 0x40000000u, 0x0u, 3u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u | 0x40000000u, 0x0u, System.IntPtr.Zero, 4u, 0x02200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Read/write ownership with read sharing: Git may read an exclusively
// validated candidate while every writer, delete, rename, and reparse swap is
// denied until the caller releases the handle.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenReadWriteShareReadNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x80000000u | 0x40000000u, 0x1u, 1u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u | 0x40000000u, 0x1u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenExclusiveNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x80000000u | 0x40000000u, 0x0u, 1u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u | 0x40000000u, 0x0u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenReadShareReadNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, false, 0x80000000u, 0x1u, 1u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u, 0x1u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Existing install custody authority: DELETE access binds the exact occupant
// through same-handle rename/restore, and read-only sharing makes any already-
// open writer that did not anticipate this transaction refuse the acquisition.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenOwnedExistingFileNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x80010000u, 0x1u, 1u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80010000u, 0x1u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Writable metadata authority: same identity and sharing contract as the
// read-only owner, with GENERIC_WRITE added for disarm-first in-place commits.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenOwnedExistingReadWriteNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0xC0010000u, 0x1u, 1u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xC0010000u, 0x1u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Scratch ownership includes DELETE access from the create-new instant. Read
// sharing admits Git's ordinary read-only opens while write/delete sharing is
// withheld, so the exact owned object cannot be replaced before same-handle
// disposition. A stage uses share-none and WRITE_THROUGH because no reader needs
// access before handle-based publication.
public static Microsoft.Win32.SafeHandles.SafeFileHandle CreateOwnedFileNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0xC0010000u, 0x1u, 2u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xC0010000u, 0x1u, System.IntPtr.Zero, 1u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// A Git-readable scratch file with no write/delete access granted to later
// opens. DELETE sharing is admitted only so cleanup can acquire a second exact
// owner after Git finishes; the handoff compares the full 128-bit FILE_ID_INFO
// while this original handle remains live.
public static Microsoft.Win32.SafeHandles.SafeFileHandle CreatePinnedReadableFileNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0xC0000000u, 0x5u, 2u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xC0000000u, 0x5u, System.IntPtr.Zero, 1u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Git-readable proof files must remain at one fixed namespace identity while
// Git consumes them.  Withholding delete sharing prevents rename/replacement;
// withholding write sharing prevents byte mutation.  After Git exits, callers
// hand the identity to a share-all read handle while this creator is still
// live, then acquire DELETE custody without an identity-free interval.
public static Microsoft.Win32.SafeHandles.SafeFileHandle CreatePinnedImmutableGitFileNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0xC0000000u, 0x1u, 2u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xC0000000u, 0x1u, System.IntPtr.Zero, 1u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenReadShareAllNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, false, 0x80000000u, 0x7u, 1u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80000000u, 0x7u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenCleanupOwnerNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x80010000u, 0x3u, 1u, 0x00200040u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x80010000u, 0x3u, System.IntPtr.Zero, 3u, 0x00200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle CreateOwnedStageNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0xC0010000u, 0x0u, 2u, 0x00200042u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xC0010000u, 0x0u, System.IntPtr.Zero, 1u, 0x80200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// FILE_CREATE returns the directory handle from the same namespace operation
// that proves positive absence. There is no create-to-reopen interval in which
// a replacement directory can be adopted and later dispositioned as owned.
public static Microsoft.Win32.SafeHandles.SafeFileHandle CreateOwnedDirectoryAtomic(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x001100A3u, 0x1u, 2u, 0x00200001u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    string full = System.IO.Path.GetFullPath(path);
    string ntPath;
    if (full.StartsWith("\\\\.\\", System.StringComparison.Ordinal)) {
        throw new System.ArgumentException("unsupported device namespace", "path");
    } else if (full.StartsWith("\\\\?\\UNC\\", System.StringComparison.OrdinalIgnoreCase)) {
        ntPath = "\\??\\UNC\\" + full.Substring(8);
    } else if (full.StartsWith("\\\\?\\", System.StringComparison.Ordinal)) {
        string drivePath = full.Substring(4);
        if (drivePath.Length < 3 || !System.Char.IsLetter(drivePath[0]) || drivePath[1] != ':' || (drivePath[2] != '\\' && drivePath[2] != '/')) { throw new System.ArgumentException("unsupported extended device namespace", "path"); }
        ntPath = "\\??\\" + drivePath;
    } else if (full.StartsWith("\\\\", System.StringComparison.Ordinal)) {
        ntPath = "\\??\\UNC\\" + full.Substring(2);
    } else {
        if (full.Length < 3 || !System.Char.IsLetter(full[0]) || full[1] != ':' || (full[2] != '\\' && full[2] != '/')) { throw new System.ArgumentException("path is not an absolute drive or UNC path", "path"); }
        ntPath = "\\??\\" + full;
    }
    System.IntPtr text = System.IntPtr.Zero;
    System.IntPtr name = System.IntPtr.Zero;
    System.IntPtr rawHandle = System.IntPtr.Zero;
    try {
        text = System.Runtime.InteropServices.Marshal.StringToHGlobalUni(ntPath);
        UNICODE_STRING unicode = new UNICODE_STRING();
        unicode.Length = checked((ushort)(ntPath.Length * 2));
        unicode.MaximumLength = checked((ushort)(unicode.Length + 2));
        unicode.Buffer = text;
        name = System.Runtime.InteropServices.Marshal.AllocHGlobal(System.Runtime.InteropServices.Marshal.SizeOf(typeof(UNICODE_STRING)));
        System.Runtime.InteropServices.Marshal.StructureToPtr(unicode, name, false);
        OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
        attributes.Length = System.Runtime.InteropServices.Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        attributes.RootDirectory = System.IntPtr.Zero;
        attributes.ObjectName = name;
        attributes.Attributes = 0x40u;
        attributes.SecurityDescriptor = System.IntPtr.Zero;
        attributes.SecurityQualityOfService = System.IntPtr.Zero;
        IO_STATUS_BLOCK status;
        int ntStatus = NtCreateFile(out rawHandle, 0x001100A3u, ref attributes, out status, System.IntPtr.Zero, 0x80u, 0x1u, 2u, 0x00200021u, System.IntPtr.Zero, 0u);
        error = ntStatus < 0 ? unchecked((int)RtlNtStatusToDosError(ntStatus)) : 0;
        if (ntStatus < 0 || rawHandle == System.IntPtr.Zero || rawHandle == new System.IntPtr(-1)) {
            if (rawHandle != System.IntPtr.Zero && rawHandle != new System.IntPtr(-1)) { CloseHandle(rawHandle); }
            return new Microsoft.Win32.SafeHandles.SafeFileHandle(new System.IntPtr(-1), true);
        }
        try {
            Microsoft.Win32.SafeHandles.SafeFileHandle owned = new Microsoft.Win32.SafeHandles.SafeFileHandle(rawHandle, true);
            rawHandle = System.IntPtr.Zero;
            return owned;
        } catch {
            if (rawHandle != System.IntPtr.Zero && rawHandle != new System.IntPtr(-1)) { CloseHandle(rawHandle); }
            throw;
        }
    } finally {
        if (name != System.IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(name); }
        if (text != System.IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(text); }
    }
}

// A directory hold denies rename/delete of the owned directory while allowing
// child files to be created and read.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenDirectoryPinned(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, false, 0xA1u, 0x1u, 1u, 0x00200001u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xA1u, 0x1u, System.IntPtr.Zero, 3u, 0x02200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenDirectoryReadShareAll(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, false, 0xA1u, 0x7u, 1u, 0x00200001u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xA1u, 0x7u, System.IntPtr.Zero, 3u, 0x02200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenDirectoryCleanupOwnerNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x001100A1u, 0x1u, 1u, 0x00200001u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x001100A1u, 0x1u, System.IntPtr.Zero, 3u, 0x02200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// Existing-directory mutation custody combines child creation rights with
// DELETE ownership so a private rooted directory can produce descendants and
// later be removed through the same retained handle.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenDirectoryMutationCleanupOwnerNoFollow(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x001100A3u, 0x3u, 1u, 0x00200001u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0x001100A3u, 0x3u, System.IntPtr.Zero, 3u, 0x02200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

// A retained mutation-directory handle carries the add-child rights needed by
// handle-relative rename and creation. Windows internally requests write share
// during FileRenameInformation, so write sharing cannot be withheld here. Every
// operation remains relative to this exact handle, and the ordinary non-reparse
// shape is rechecked at relative-resolution boundaries.
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenDirectoryMutationPinned(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0xA3u, 0x3u, 1u, 0x00200001u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(path, 0xA3u, 0x3u, System.IntPtr.Zero, 3u, 0x02200080u, System.IntPtr.Zero);
    error = h.IsInvalid ? System.Runtime.InteropServices.Marshal.GetLastWin32Error() : 0;
    return h;
}

public static Microsoft.Win32.SafeHandles.SafeFileHandle CreateOwnedMutationDirectoryAtomic(string path, out int error) {
    bool matched;
    Microsoft.Win32.SafeHandles.SafeFileHandle rooted = OpenRootedLeaf(path, true, 0x001100A3u, 0x3u, 2u, 0x00200001u, out error, out matched);
    if (matched || IsRootedIoRequired()) { return rooted; }
    rooted.Dispose();
    error = 50;
    return InvalidHandle();
}

// Same-handle disposition: file IDs are diagnostic only. Windows can reuse a
// file ID after deletion and the 64-bit BY_HANDLE ID is not guaranteed unique
// on ReFS, so reopening a pathname and comparing IDs cannot prove ownership.
// Result: 0 marked for deletion, 3 bad shape, 4 query failure, 5 disposition
// failure. The caller closes the same handle after this returns.
public static int DeleteHeldExact(Microsoft.Win32.SafeHandles.SafeFileHandle h, bool directory, out int error) {
    error = 0;
    if (h == null || h.IsInvalid) { return 4; }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(h, out info)) {
        error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
        return 4;
    }
    bool isDirectory = (info.FileAttributes & 0x10u) != 0;
    bool isReparse = (info.FileAttributes & 0x400u) != 0;
    if (isReparse || isDirectory != directory || (!directory && info.NumberOfLinks != 1u)) { return 3; }
    System.IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(1);
    try {
        System.Runtime.InteropServices.Marshal.WriteByte(buffer, 0, 1);
        if (!SetFileInformationByHandle(h, 4, buffer, 1u)) {
            error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            return 5;
        }
        return 0;
    } finally {
        System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
    }
}

// Atomic same-object, no-replace publication through FILE_RENAME_INFO class 3.
// Rooted transactions supply the retained destination-parent handle and one
// validated leaf; a non-rooted caller retains the absolute fallback.
// The variable filename buffer excludes a terminator, per the Win32 contract.
public static bool RenameHeldNoReplace(Microsoft.Win32.SafeHandles.SafeFileHandle h, string source, string destination, out int error) {
    error = 0;
    if (h == null || h.IsInvalid || String.IsNullOrEmpty(destination)) { error = 87; return false; }
    bool rootedMatch = HasRootedIoMatch(destination);
    RELATIVE_PARENT_LEASE rootedLease = null;
    if (rootedMatch && !TryResolveRelativeParent(destination, true, out rootedLease, out error)) { return false; }
    if (!rootedMatch && IsRootedIoRequired()) { error = 3; return false; }
    bool rootedSibling = false;
    if (rootedMatch && !System.String.IsNullOrWhiteSpace(source)) {
        string sourceFull;
        try { sourceFull = NormalizeRootedPath(source); } catch { if (rootedLease != null) { rootedLease.Dispose(); } error = 123; return false; }
        string sourceParent = System.IO.Path.GetDirectoryName(sourceFull);
        string destinationParent = System.IO.Path.GetDirectoryName(NormalizeRootedPath(destination));
        rootedSibling = System.String.Equals(sourceParent, destinationParent, System.StringComparison.OrdinalIgnoreCase);
    }
    // Rooted publication uses the NT FileRenameInformation contract so the
    // retained destination-parent handle and one relative leaf are the only
    // namespace inputs. Cross-directory rooted moves remain unsupported here.
    if (rootedMatch && !rootedSibling) { rootedLease.Dispose(); error = 87; return false; }
    string destinationName = rootedMatch ? rootedLease.Leaf : destination;
    byte[] name = System.Text.Encoding.Unicode.GetBytes(destinationName);
    int rootOffset = System.IntPtr.Size == 8 ? 8 : 4;
    int lengthOffset = System.IntPtr.Size == 8 ? 16 : 8;
    int nameOffset = System.IntPtr.Size == 8 ? 20 : 12;
    int size = checked(nameOffset + name.Length + 2);
    System.IntPtr buffer = System.IntPtr.Zero;
    try {
        buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        for (int i = 0; i < size; i++) { System.Runtime.InteropServices.Marshal.WriteByte(buffer, i, 0); }
        System.Runtime.InteropServices.Marshal.WriteByte(buffer, 0, 0); // ReplaceIfExists = FALSE
        System.Runtime.InteropServices.Marshal.WriteIntPtr(buffer, rootOffset, rootedMatch ? rootedLease.Parent.DangerousGetHandle() : System.IntPtr.Zero);
        System.Runtime.InteropServices.Marshal.WriteInt32(buffer, lengthOffset, name.Length);
        System.Runtime.InteropServices.Marshal.Copy(name, 0, System.IntPtr.Add(buffer, nameOffset), name.Length);
        bool ok;
        if (rootedMatch) {
            IO_STATUS_BLOCK renameStatus;
            int ntStatus = NtSetInformationFile(h, out renameStatus, buffer, (uint)size, 10);
            ok = ntStatus >= 0;
            error = ok ? 0 : unchecked((int)RtlNtStatusToDosError(ntStatus));
        } else {
            ok = SetFileInformationByHandle(h, 3, buffer, (uint)size);
            error = ok ? 0 : System.Runtime.InteropServices.Marshal.GetLastWin32Error();
        }
        if (rootedMatch) { System.GC.KeepAlive(rootedLease.Parent); }
        return ok;
    } finally {
        if (buffer != System.IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer); }
        if (rootedLease != null) { rootedLease.Dispose(); }
    }
}

public static bool RenameHeldNoReplace(Microsoft.Win32.SafeHandles.SafeFileHandle h, string destination, out int error) {
    return RenameHeldNoReplace(h, null, destination, out error);
}
'@
}

function Enter-CrgPinnedAbsoluteDirectoryChain {
  param([string]$Path, [string]$Label = 'mutation root', [switch]$MutationLeaf)
  $pcFull = [System.IO.Path]::GetFullPath($Path)
  if ($pcFull.StartsWith('\\.\', [System.StringComparison]::Ordinal) -or $pcFull.StartsWith('\\?\GLOBALROOT', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label uses an unsupported device namespace: '$pcFull'"
  }
  $pcRoot = [System.IO.Path]::GetPathRoot($pcFull)
  if ([string]::IsNullOrWhiteSpace($pcRoot)) { throw "$Label is not an absolute drive or UNC path: '$pcFull'" }
  $pcPaths = New-Object 'System.Collections.Generic.List[string]'
  $pcPaths.Add($pcRoot) | Out-Null
  $pcCurrent = $pcRoot
  $pcRelative = $pcFull.Substring($pcRoot.Length).Trim('\', '/')
  if ($pcRelative.Length -gt 0) {
    foreach ($pcPart in @($pcRelative -split '[\\/]')) {
      if ([string]::IsNullOrWhiteSpace($pcPart) -or [string]::Equals($pcPart, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($pcPart, '..', [System.StringComparison]::Ordinal) -or $pcPart.Contains(':')) { throw "$Label contains an unsafe directory component: '$pcPart'" }
      $pcCurrent = Join-Path $pcCurrent $pcPart
      $pcPaths.Add($pcCurrent) | Out-Null
    }
  }
  $pcHandles = New-Object 'System.Collections.Generic.List[object]'
  if ($null -eq $script:CrgPinnedChainHandles) { $script:CrgPinnedChainHandles = New-Object System.Collections.Hashtable([System.StringComparer]::OrdinalIgnoreCase) }
  $pcLeafHandle = $null
  try {
    for ($pcPathI = 0; $pcPathI -lt $pcPaths.Count; $pcPathI++) {
      $pcPath = $pcPaths[$pcPathI]
      $pcCanonicalPath = [System.IO.Path]::GetFullPath($pcPath)
      if (-not [string]::Equals($pcCanonicalPath, [System.IO.Path]::GetPathRoot($pcCanonicalPath), [System.StringComparison]::OrdinalIgnoreCase)) { $pcCanonicalPath = $pcCanonicalPath.TrimEnd('\', '/') }
      if ($script:CrgPinnedChainHandles.ContainsKey($pcCanonicalPath)) {
        $pcCached = $script:CrgPinnedChainHandles[$pcCanonicalPath]
        if ($MutationLeaf -and $pcPathI -eq ($pcPaths.Count - 1) -and -not $pcCached.Mutation) {
          throw "$Label directory '$pcPath' was retained earlier without mutation capability"
        }
        $pcLeafHandle = $pcCached.Handle
        continue
      }
      $pcErr = 0
      $pcIsMutation = $MutationLeaf -and $pcPathI -eq ($pcPaths.Count - 1)
      $pcHandle = if ($pcIsMutation) {
        [CrgBootstrap.NativeV4]::OpenDirectoryMutationPinned($pcPath, [ref]$pcErr)
      } else { [CrgBootstrap.NativeV4]::OpenDirectoryPinned($pcPath, [ref]$pcErr) }
      if ($null -eq $pcHandle -or $pcHandle.IsInvalid) {
        if ($null -ne $pcHandle) { $pcHandle.Dispose() }
        throw "$Label directory '$pcPath' could not be pinned without write/delete sharing (error $pcErr)"
      }
      $pcAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($pcHandle)
      if (($pcAttrs -band 0x10) -eq 0 -or ($pcAttrs -band 0x400) -ne 0) {
        $pcHandle.Dispose()
        throw "$Label directory '$pcPath' is not one ordinary non-reparse directory"
      }
      $pcHandles.Add($pcHandle) | Out-Null
      $script:CrgPinnedChainHandles[$pcCanonicalPath] = [pscustomobject]@{ Handle = $pcHandle; Mutation = $pcIsMutation }
      $pcLeafHandle = $pcHandle
    }
    $pcCanonical = if ([string]::Equals($pcFull, $pcRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $pcRoot } else { $pcFull.TrimEnd('\', '/') }
    return [pscustomobject]@{ FullPath = $pcCanonical; LeafHandle = $pcLeafHandle; Handles = $pcHandles }
  } catch {
    for ($pcI = $pcHandles.Count - 1; $pcI -ge 0; $pcI--) { try { $pcHandles[$pcI].Dispose() } catch { } }
    throw
  }
}

function Initialize-CrgRootedNamespace {
  param([object[]]$Roots)
  [CrgBootstrap.NativeV4]::ClearRootedIo()
  $script:CrgPinnedChainHandles = New-Object System.Collections.Hashtable([System.StringComparer]::OrdinalIgnoreCase)
  $script:CrgRootedDirectoryPins = New-Object 'System.Collections.Generic.List[object]'
  $script:CrgRootedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $script:CrgRootedMutationPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $rnChains = New-Object 'System.Collections.Generic.List[object]'
  try {
    # A directory cached as an intermediate restrictive pin cannot later gain
    # mutation access or write sharing. Canonicalize and coalesce first, then
    # open every writable ancestor before writable descendants and read-only
    # roots so a cached handle's recorded capability always reflects creation.
    # Publish bindings only after every chain is open: otherwise the first
    # registered root would route a later chain open through restrictive cached
    # intermediate pins before that later exact authority exists.
    $rnRootMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rnInput in @($Roots)) {
      if ($null -eq $rnInput -or [string]::IsNullOrWhiteSpace("$($rnInput.Path)")) { continue }
      $rnInputRaw = [System.IO.Path]::GetFullPath("$($rnInput.Path)")
      $rnInputPathRoot = [System.IO.Path]::GetPathRoot($rnInputRaw)
      $rnInputPath = if ([string]::Equals($rnInputRaw, $rnInputPathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $rnInputPathRoot } else { $rnInputRaw.TrimEnd('\', '/') }
      $rnInputWritable = $null -ne $rnInput.PSObject.Properties['Writable'] -and $rnInput.Writable -eq $true
      if ($rnRootMap.ContainsKey($rnInputPath)) {
        if ($rnInputWritable) {
          $rnRootMap[$rnInputPath].Writable = $true
          $rnRootMap[$rnInputPath].Label = "$($rnInput.Label)"
        }
      } else {
        $rnRootMap.Add($rnInputPath, [pscustomobject]@{ Path = $rnInputPath; Label = "$($rnInput.Label)"; Writable = $rnInputWritable })
      }
    }
    $rnOrderedRoots = @($rnRootMap.Values | Sort-Object @{ Expression = { if ($_.Writable) { 0 } else { 1 } } }, @{ Expression = { $_.Path.Length } }, @{ Expression = { $_.Path } })
    $rnOpenedRoots = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rnRoot in $rnOrderedRoots) {
      $rnWritable = $rnRoot.Writable -eq $true
      $rnChain = Enter-CrgPinnedAbsoluteDirectoryChain -Path $rnRoot.Path -Label $rnRoot.Label -MutationLeaf:$rnWritable
      $rnChains.Add($rnChain) | Out-Null
      $rnOpenedRoots.Add([pscustomobject]@{ Chain = $rnChain; Writable = $rnWritable }) | Out-Null
    }
    foreach ($rnOpenedRoot in $rnOpenedRoots) {
      if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($rnOpenedRoot.Chain.FullPath, $rnOpenedRoot.Chain.LeafHandle, $rnOpenedRoot.Writable)) { throw "could not register rooted I/O authority for '$($rnOpenedRoot.Chain.FullPath)'" }
      [void]$script:CrgRootedPaths.Add($rnOpenedRoot.Chain.FullPath)
      if ($rnOpenedRoot.Writable) { [void]$script:CrgRootedMutationPaths.Add($rnOpenedRoot.Chain.FullPath) }
    }
    [CrgBootstrap.NativeV4]::RequireRootedIo($true)
    return [pscustomobject]@{ Chains = $rnChains; DirectoryPins = $script:CrgRootedDirectoryPins }
  } catch {
    [CrgBootstrap.NativeV4]::ClearRootedIo()
    for ($rnI = $rnChains.Count - 1; $rnI -ge 0; $rnI--) {
      for ($rnJ = $rnChains[$rnI].Handles.Count - 1; $rnJ -ge 0; $rnJ--) { try { $rnChains[$rnI].Handles[$rnJ].Dispose() } catch { } }
    }
    $script:CrgRootedDirectoryPins = $null
    $script:CrgRootedPaths = $null
    $script:CrgRootedMutationPaths = $null
    $script:CrgPinnedChainHandles = $null
    throw
  }
}

function Ensure-CrgRootedDirectory {
  param([string]$Path, [string]$Label = 'transaction directory')
  if ($null -eq $script:CrgRootedPaths -or $null -eq $script:CrgRootedMutationPaths -or $null -eq $script:CrgRootedDirectoryPins) { throw 'rooted namespace is not initialized' }
  $rdRawFull = [System.IO.Path]::GetFullPath($Path)
  $rdPathRoot = [System.IO.Path]::GetPathRoot($rdRawFull)
  $rdFull = if ([string]::Equals($rdRawFull, $rdPathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $rdPathRoot } else { $rdRawFull.TrimEnd('\', '/') }
  if ($script:CrgRootedMutationPaths.Contains($rdFull)) { return $true }
  $rdMissing = New-Object 'System.Collections.Generic.List[string]'
  $rdCurrent = $rdFull
  while (-not $script:CrgRootedMutationPaths.Contains($rdCurrent)) {
    $rdReadOnlyRegistered = $script:CrgRootedPaths.Contains($rdCurrent)
    $rdOpenErr = 0
    $rdOpen = [CrgBootstrap.NativeV4]::OpenDirectoryMutationPinned($rdCurrent, [ref]$rdOpenErr)
    if ($null -ne $rdOpen -and -not $rdOpen.IsInvalid) {
      $rdAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($rdOpen)
      if (($rdAttrs -band 0x10) -eq 0 -or ($rdAttrs -band 0x400) -ne 0) { $rdOpen.Dispose(); throw "$Label '$rdCurrent' is not one ordinary non-reparse directory" }
      if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($rdCurrent, $rdOpen, $true)) { $rdOpen.Dispose(); throw "$Label '$rdCurrent' could not be registered as a retained rooted directory" }
      $script:CrgRootedDirectoryPins.Add($rdOpen) | Out-Null
      [void]$script:CrgRootedPaths.Add($rdCurrent)
      [void]$script:CrgRootedMutationPaths.Add($rdCurrent)
      break
    }
    if ($null -ne $rdOpen) { $rdOpen.Dispose() }
    if ($rdReadOnlyRegistered) { throw "$Label '$rdCurrent' is retained only as read-only namespace authority and could not be upgraded safely (Win32 error $rdOpenErr)" }
    $rdMissing.Add($rdCurrent) | Out-Null
    $rdParent = Split-Path -Parent $rdCurrent
    if ([string]::IsNullOrWhiteSpace($rdParent) -or [string]::Equals($rdParent, $rdCurrent, [System.StringComparison]::OrdinalIgnoreCase)) { throw "$Label '$rdFull' is outside every retained mutation root (last error $rdOpenErr)" }
    $rdParentFull = [System.IO.Path]::GetFullPath($rdParent)
    $rdParentRoot = [System.IO.Path]::GetPathRoot($rdParentFull)
    $rdCurrent = if ([string]::Equals($rdParentFull, $rdParentRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $rdParentRoot } else { $rdParentFull.TrimEnd('\', '/') }
  }
  for ($rdI = $rdMissing.Count - 1; $rdI -ge 0; $rdI--) {
    $rdCreateErr = 0
    $rdCreated = [CrgBootstrap.NativeV4]::CreateOwnedMutationDirectoryAtomic($rdMissing[$rdI], [ref]$rdCreateErr)
    if ($null -eq $rdCreated -or $rdCreated.IsInvalid) {
      if ($null -ne $rdCreated) { $rdCreated.Dispose() }
      throw "$Label '$($rdMissing[$rdI])' could not be atomically created under retained parents (error $rdCreateErr)"
    }
    $rdAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($rdCreated)
    if (($rdAttrs -band 0x10) -eq 0 -or ($rdAttrs -band 0x400) -ne 0) { $rdCreated.Dispose(); throw "$Label '$($rdMissing[$rdI])' did not create as an ordinary directory" }
    if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($rdMissing[$rdI], $rdCreated, $true)) { $rdCreated.Dispose(); throw "$Label '$($rdMissing[$rdI])' could not be registered as a retained rooted directory" }
    $script:CrgRootedDirectoryPins.Add($rdCreated) | Out-Null
    [void]$script:CrgRootedPaths.Add($rdMissing[$rdI])
    [void]$script:CrgRootedMutationPaths.Add($rdMissing[$rdI])
  }
  return $true
}

function Enter-CrgRootedExistingDirectory {
  param([string]$Path, [string]$Label = 'existing transaction directory', [switch]$Mutation)
  if ($null -eq $script:CrgRootedPaths -or $null -eq $script:CrgRootedMutationPaths -or $null -eq $script:CrgRootedDirectoryPins) { throw 'rooted namespace is not initialized' }
  $edRaw = [System.IO.Path]::GetFullPath($Path)
  $edRoot = [System.IO.Path]::GetPathRoot($edRaw)
  $edFull = if ([string]::Equals($edRaw, $edRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $edRoot } else { $edRaw.TrimEnd('\', '/') }
  if (($Mutation -and $script:CrgRootedMutationPaths.Contains($edFull)) -or
      (-not $Mutation -and $script:CrgRootedPaths.Contains($edFull))) { return $true }
  $edErr = 0
  $edHandle = if ($Mutation) {
    [CrgBootstrap.NativeV4]::OpenDirectoryMutationPinned($edFull, [ref]$edErr)
  } else { [CrgBootstrap.NativeV4]::OpenDirectoryPinned($edFull, [ref]$edErr) }
  if ($null -eq $edHandle -or $edHandle.IsInvalid) {
    if ($null -ne $edHandle) { $edHandle.Dispose() }
    throw "$Label '$edFull' could not be retained as an existing directory (Win32 error $edErr)"
  }
  $edAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($edHandle)
  if (($edAttrs -band 0x10) -eq 0 -or ($edAttrs -band 0x400) -ne 0 -or -not [CrgBootstrap.NativeV4]::RegisterRootedIo($edFull, $edHandle, [bool]$Mutation)) {
    $edHandle.Dispose()
    throw "$Label '$edFull' is not one ordinary registered non-reparse directory"
  }
  $script:CrgRootedDirectoryPins.Add($edHandle) | Out-Null
  [void]$script:CrgRootedPaths.Add($edFull)
  if ($Mutation) { [void]$script:CrgRootedMutationPaths.Add($edFull) }
  return $true
}

function Close-CrgRootedNamespace {
  param([object]$Lease)
  [CrgBootstrap.NativeV4]::ClearRootedIo()
  if ($null -ne $Lease -and $null -ne $Lease.DirectoryPins) {
    for ($rnI = $Lease.DirectoryPins.Count - 1; $rnI -ge 0; $rnI--) { try { $Lease.DirectoryPins[$rnI].Dispose() } catch { } }
  }
  if ($null -ne $Lease -and $null -ne $Lease.Chains) {
    for ($rnI = $Lease.Chains.Count - 1; $rnI -ge 0; $rnI--) {
      for ($rnJ = $Lease.Chains[$rnI].Handles.Count - 1; $rnJ -ge 0; $rnJ--) { try { $Lease.Chains[$rnI].Handles[$rnJ].Dispose() } catch { } }
    }
  }
  $script:CrgRootedDirectoryPins = $null
  $script:CrgRootedPaths = $null
  $script:CrgRootedMutationPaths = $null
  $script:CrgPinnedChainHandles = $null
}

# Publish a transformed small text/config leaf without ever writing the prior
# object. The exact prior is read and retained, the candidate is fully written
# under a random same-parent stage handle, the unchanged prior moves to retained
# recovery, and the stage publishes no-replace. A late winner is preserved and
# the exact prior is restored only through the still-held handle. No pathname
# read, deletion, or replacement authorizes any transition.
function Update-CrgRootedFileBytes {
  param(
    [string]$Path,
    [scriptblock]$Transform,
    [string]$Label = 'repository metadata file',
    [int64]$MaxLength = 16777216
  )
  if ($null -eq $Transform) { throw "$Label has no byte transform" }
  $ufParent = Split-Path -Parent $Path
  $null = Ensure-CrgRootedDirectory -Path $ufParent -Label "$Label parent"
  $ufPriorH = $null
  $ufPriorFs = $null
  $ufPriorPresent = $false
  $ufPriorMoved = $false
  $ufOld = [byte[]]@()
  $ufStagePath = "$Path.crg-new-$crgBackupStamp-$([Guid]::NewGuid().ToString('N'))"
  $ufRecoveryPath = "$Path.crg-old-$crgBackupStamp-$([Guid]::NewGuid().ToString('N'))"
  $ufStageH = $null
  $ufStageFs = $null
  $ufStagePublished = $false
  $ufStageQuarantined = $false
  try {
    $ufErr = 0
    $ufPriorH = [CrgBootstrap.NativeV4]::OpenOwnedExistingFileNoFollow($Path, [ref]$ufErr)
    if ($null -eq $ufPriorH -or $ufPriorH.IsInvalid) {
      if ($null -ne $ufPriorH) { $ufPriorH.Dispose(); $ufPriorH = $null }
      if ($ufErr -ne 2 -and $ufErr -ne 3) { throw "$Label '$Path' could not be opened no-follow for exact update (Win32 error $ufErr)" }
    } else {
      $ufPriorPresent = $true
      $ufAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($ufPriorH)
      if ($ufAttrs -lt 0 -or ($ufAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($ufPriorH) -ne 1) { throw "$Label '$Path' is not one ordinary non-reparse single-link file" }
      $ufPriorFs = New-Object System.IO.FileStream($ufPriorH, [System.IO.FileAccess]::Read)
      $ufPriorH = $null
      if ($ufPriorFs.Length -gt $MaxLength) { throw "$Label '$Path' exceeds the $MaxLength-byte bound" }
      $ufOld = New-Object byte[] ([int]$ufPriorFs.Length)
      $ufRead = 0
      while ($ufRead -lt $ufOld.Length) {
        $ufGot = $ufPriorFs.Read($ufOld, $ufRead, $ufOld.Length - $ufRead)
        if ($ufGot -le 0) { break }
        $ufRead += $ufGot
      }
      if ($ufRead -ne $ufOld.Length) { throw "$Label '$Path' could not be read completely through its retained handle" }
      $ufPriorFs.Position = 0
    }

    $ufTransformRows = @(& $Transform $ufOld)
    if ($ufTransformRows.Count -ne 1 -or $ufTransformRows[0] -isnot [psobject] -or
        $ufTransformRows[0].PSObject.Properties['Ok'] -eq $null -or $ufTransformRows[0].Ok -cne $true -or
        $ufTransformRows[0].PSObject.Properties['Bytes'] -eq $null -or $ufTransformRows[0].Bytes -isnot [byte[]]) {
      throw "$Label '$Path' transform must return exactly one { Ok = true; Bytes = [byte[]] } result"
    }
    [byte[]]$ufDesired = $ufTransformRows[0].Bytes
    if ($ufDesired.Length -gt $MaxLength) { throw "$Label '$Path' transform returned an oversized byte sequence" }
    $ufSame = $ufPriorPresent -and ($ufOld.Length -eq $ufDesired.Length)
    if ($ufSame) {
      for ($ufI = 0; $ufI -lt $ufOld.Length; $ufI++) { if ($ufOld[$ufI] -ne $ufDesired[$ufI]) { $ufSame = $false; break } }
    }
    if ($ufSame) { return [pscustomobject]@{ State = 'ok'; Changed = $false; Created = $false; PreviousBytes = $ufOld; Bytes = $ufDesired; PriorRemnant = $null } }

    $ufStageErr = 0
    $ufStageH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($ufStagePath, [ref]$ufStageErr)
    if ($null -eq $ufStageH -or $ufStageH.IsInvalid) { throw "$Label candidate stage could not be created no-follow at '$ufStagePath' (Win32 error $ufStageErr)" }
    try { $ufStageFs = New-Object System.IO.FileStream($ufStageH, [System.IO.FileAccess]::ReadWrite); $ufStageH = $null }
    catch {
      if ($null -ne $ufStageH -and -not $ufStageH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $ufStagePath -Handle $ufStageH -Label "$Label candidate stage"; $ufStageH = $null }
      throw
    }
    if ($ufDesired.Length -gt 0) { $ufStageFs.Write($ufDesired, 0, $ufDesired.Length) }
    $ufStageFs.Flush($true)
    $ufStageFs.Position = 0
    $ufBack = New-Object byte[] $ufDesired.Length
    $ufRead = 0
    while ($ufRead -lt $ufBack.Length) {
      $ufGot = $ufStageFs.Read($ufBack, $ufRead, $ufBack.Length - $ufRead)
      if ($ufGot -le 0) { break }
      $ufRead += $ufGot
    }
    $ufVerified = ($ufRead -eq $ufDesired.Length -and $ufStageFs.Length -eq $ufDesired.Length)
    if ($ufVerified) { for ($ufI = 0; $ufI -lt $ufDesired.Length; $ufI++) { if ($ufBack[$ufI] -ne $ufDesired[$ufI]) { $ufVerified = $false; break } } }
    if (-not $ufVerified -or [CrgBootstrap.NativeV3]::GetLinkCount($ufStageFs.SafeFileHandle) -ne 1) { throw "$Label candidate did not verify as one exact ordinary single-link stage" }

    if ([CrgBootstrap.NativeV3]::GetLinkCount($ufStageFs.SafeFileHandle) -ne 1) { throw "$Label candidate acquired an extra hard link before publication" }
    if ($ufPriorPresent) {
      if ([CrgBootstrap.NativeV3]::GetLinkCount($ufPriorFs.SafeFileHandle) -ne 1) { throw "$Label prior acquired an extra hard link before custody" }
      $ufMoveErr = 0
      if (-not [CrgBootstrap.NativeV4]::RenameHeldNoReplace($ufPriorFs.SafeFileHandle, $Path, $ufRecoveryPath, [ref]$ufMoveErr)) { throw "$Label prior could not move to exact no-replace recovery '$ufRecoveryPath' (Win32 error $ufMoveErr)" }
      $ufPriorMoved = $true
      if ([CrgBootstrap.NativeV3]::GetLinkCount($ufPriorFs.SafeFileHandle) -ne 1) { throw "$Label prior acquired an extra hard link after custody; recovery is preserved" }
    }
    if ([CrgBootstrap.NativeV3]::GetLinkCount($ufStageFs.SafeFileHandle) -ne 1) { throw "$Label candidate acquired an extra hard link at the publication boundary" }
    $ufPublishErr = 0
    if (-not [CrgBootstrap.NativeV4]::RenameHeldNoReplace($ufStageFs.SafeFileHandle, $ufStagePath, $Path, [ref]$ufPublishErr)) { throw "$Label candidate publication lost the no-replace race (Win32 error $ufPublishErr)" }
    $ufStagePublished = $true
    if ([CrgBootstrap.NativeV3]::GetLinkCount($ufStageFs.SafeFileHandle) -ne 1) {
      $ufQuarantinePath = "$Path.crg-failed-$crgBackupStamp-$([Guid]::NewGuid().ToString('N'))"
      $ufQuarantineErr = 0
      if ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($ufStageFs.SafeFileHandle, $Path, $ufQuarantinePath, [ref]$ufQuarantineErr)) {
        $ufStagePublished = $false
        $ufStageQuarantined = $true
        $ufStagePath = $ufQuarantinePath
      }
      throw "$Label published candidate acquired an extra hard link; the fixed name was $(if ($ufStageQuarantined) { 'quarantined' } else { 'left fail-closed as a multi-link object' })"
    }

    $ufPriorRemnant = $null
    if ($ufPriorMoved) {
      if (Remove-CrgOwnedScratchHandle -Path $ufRecoveryPath -Stream $ufPriorFs -Label "$Label prior recovery") { $ufPriorFs = $null }
      else { $ufPriorFs = $null; $ufPriorRemnant = $ufRecoveryPath }
    }
    $ufState = if ($null -eq $ufPriorRemnant) { 'ok' } else { 'committed-with-recovery' }
    return [pscustomobject]@{ State = $ufState; Changed = $true; Created = (-not $ufPriorPresent); PreviousBytes = $ufOld; Bytes = $ufDesired; PriorRemnant = $ufPriorRemnant }
  } catch {
    $ufFailure = $_.Exception.Message
    if ($null -ne $ufStageFs -and -not $ufStagePublished) {
      if (-not $ufStageQuarantined -or [CrgBootstrap.NativeV3]::GetLinkCount($ufStageFs.SafeFileHandle) -eq 1) { $null = Remove-CrgOwnedScratchHandle -Path $ufStagePath -Stream $ufStageFs -Label "$Label candidate stage"; $ufStageFs = $null }
    } elseif ($null -ne $ufStageH -and -not $ufStageH.IsInvalid) {
      $null = Remove-CrgOwnedScratchHandle -Path $ufStagePath -Handle $ufStageH -Label "$Label candidate stage"
      $ufStageH = $null
    }
    if ($ufPriorMoved -and $null -ne $ufPriorFs) {
      if ([CrgBootstrap.NativeV3]::GetLinkCount($ufPriorFs.SafeFileHandle) -eq 1) {
        $ufRestoreErr = 0
        if ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($ufPriorFs.SafeFileHandle, $ufRecoveryPath, $Path, [ref]$ufRestoreErr)) { $ufPriorMoved = $false }
        else { $ufFailure = "$ufFailure; exact prior remains at '$ufRecoveryPath' because no-replace restore failed (Win32 error $ufRestoreErr)" }
      } else { $ufFailure = "$ufFailure; exact prior remains at '$ufRecoveryPath' after losing single-link shape" }
    }
    throw $ufFailure
  } finally {
    if ($null -ne $ufStageFs) { $ufStageFs.Dispose() }
    if ($null -ne $ufStageH) { $ufStageH.Dispose() }
    if ($null -ne $ufPriorFs) { $ufPriorFs.Dispose() }
    if ($null -ne $ufPriorH) { $ufPriorH.Dispose() }
  }
}

function Read-CrgRootedFileBytesExact {
  param([string]$Path, [string]$Label = 'repository metadata file', [int64]$MaxLength = 16777216)
  $rfH = $null
  $rfFs = $null
  try {
    $rfErr = 0
    $rfH = [CrgBootstrap.NativeV4]::OpenOwnedExistingFileNoFollow($Path, [ref]$rfErr)
    if ($null -eq $rfH -or $rfH.IsInvalid) {
      if ($null -ne $rfH) { $rfH.Dispose(); $rfH = $null }
      if ($rfErr -eq 2 -or $rfErr -eq 3) { return [pscustomobject]@{ State = 'absent'; Bytes = [byte[]]@() } }
      throw "$Label '$Path' could not be opened no-follow (Win32 error $rfErr)"
    }
    $rfAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($rfH)
    if ($rfAttrs -lt 0 -or ($rfAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($rfH) -ne 1) { throw "$Label '$Path' is not one ordinary non-reparse single-link file" }
    $rfFs = New-Object System.IO.FileStream($rfH, [System.IO.FileAccess]::Read)
    $rfH = $null
    if ($rfFs.Length -gt $MaxLength) { throw "$Label '$Path' exceeds the $MaxLength-byte bound" }
    $rfBytes = New-Object byte[] ([int]$rfFs.Length)
    $rfRead = 0
    while ($rfRead -lt $rfBytes.Length) {
      $rfGot = $rfFs.Read($rfBytes, $rfRead, $rfBytes.Length - $rfRead)
      if ($rfGot -le 0) { break }
      $rfRead += $rfGot
    }
    if ($rfRead -ne $rfBytes.Length) { throw "$Label '$Path' could not be read completely through its retained handle" }
    return [pscustomobject]@{ State = 'held'; Bytes = $rfBytes }
  } finally {
    if ($null -ne $rfFs) { $rfFs.Dispose() }
    if ($null -ne $rfH) { $rfH.Dispose() }
  }
}

function Open-CrgPackageSourceHold {
  param(
    [string]$Path,
    [string]$RelativePath,
    [int64]$MaxLength = 16777216,
    [switch]$TransferableOwner,
    [switch]$AllowAbsent
  )
  $psH = $null
  $psFs = $null
  try {
    $psErr = 0
    $psH = if ($TransferableOwner) { [CrgBootstrap.NativeV4]::OpenOwnedExistingFileNoFollow($Path, [ref]$psErr) } else { [CrgBootstrap.NativeV4]::OpenReadShareReadNoFollow($Path, [ref]$psErr) }
    if ($null -eq $psH -or $psH.IsInvalid) {
      if ($null -ne $psH) { $psH.Dispose(); $psH = $null }
      if ($AllowAbsent -and $psErr -in @(2, 3)) { return $null }
      throw "package source '$RelativePath' could not be opened no-follow under the retained package root (Win32 error $psErr)"
    }
    $psAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($psH)
    if ($psAttrs -lt 0 -or ($psAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($psH) -ne 1) { throw "package source '$RelativePath' is not one ordinary non-reparse single-link file" }
    $psFs = New-Object System.IO.FileStream($psH, [System.IO.FileAccess]::Read)
    $psH = $null
    if ($psFs.Length -gt $MaxLength) { throw "package source '$RelativePath' exceeds the $MaxLength-byte bound" }
    $psBytes = New-Object byte[] ([int]$psFs.Length)
    $psRead = 0
    while ($psRead -lt $psBytes.Length) {
      $psGot = $psFs.Read($psBytes, $psRead, $psBytes.Length - $psRead)
      if ($psGot -le 0) { break }
      $psRead += $psGot
    }
    if ($psRead -ne $psBytes.Length -or [CrgBootstrap.NativeV3]::GetLinkCount($psFs.SafeFileHandle) -ne 1) { throw "package source '$RelativePath' could not be read completely while retaining single-link identity" }
    $psFs.Position = 0
    $psResult = [pscustomobject]@{ Path = $Path; RelativePath = $RelativePath; Stream = $psFs; Bytes = $psBytes }
    $psFs = $null
    return $psResult
  } finally {
    if ($null -ne $psFs) { $psFs.Dispose() }
    if ($null -ne $psH) { $psH.Dispose() }
  }
}

function Open-CrgGitIndirectionHold {
  param(
    [string]$Path,
    [ValidatePattern('\A(?:gitdir|commondir)\z', Options = 'None')][string]$Kind,
    [string]$RelativeBase,
    [string]$ExpectedDirectory,
    [switch]$AllowAbsent
  )
  $giH = $null
  $giFs = $null
  try {
    $giErr = 0
    # The indirection is authority INPUT only: retained READ access with read
    # sharing excludes every pre-existing/future writer, delete, rename, and
    # reparse swap without requiring DELETE permission on protected Git
    # metadata. No caller ever mutates or renames this held object.
    $giH = [CrgBootstrap.NativeV4]::OpenReadShareReadNoFollow($Path, [ref]$giErr)
    if ($null -eq $giH -or $giH.IsInvalid) {
      if ($null -ne $giH) { $giH.Dispose(); $giH = $null }
      if ($AllowAbsent -and $giErr -in @(2, 3)) { return $null }
      throw "$Kind indirection '$Path' could not be held no-follow (Win32 error $giErr)"
    }
    $giAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($giH)
    if ($giAttrs -lt 0 -or ($giAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($giH) -ne 1) { throw "$Kind indirection '$Path' is not one ordinary non-reparse single-link file" }
    $giFs = New-Object System.IO.FileStream($giH, [System.IO.FileAccess]::Read)
    $giH = $null
    if ($giFs.Length -lt 1 -or $giFs.Length -gt 4096) { throw "$Kind indirection '$Path' has an invalid length" }
    $giBytes = New-Object byte[] ([int]$giFs.Length)
    $giRead = 0
    while ($giRead -lt $giBytes.Length) {
      $giGot = $giFs.Read($giBytes, $giRead, $giBytes.Length - $giRead)
      if ($giGot -le 0) { break }
      $giRead += $giGot
    }
    if ($giRead -ne $giBytes.Length) { throw "$Kind indirection '$Path' could not be read completely through its retained handle" }
    foreach ($giByte in $giBytes) { if ($giByte -eq 0 -or $giByte -gt 0x7F) { throw "$Kind indirection '$Path' is not bounded ASCII" } }
    $giText = [System.Text.Encoding]::ASCII.GetString($giBytes).TrimEnd([char[]]@("`r", "`n"))
    if ($Kind -ceq 'gitdir') {
      if ($giText -cnotmatch '\Agitdir: (?<p>[^\r\n]+)\z') { throw "gitdir indirection '$Path' has malformed bytes" }
      $giPointer = $Matches['p']
    } else {
      if ($giText -match '[\r\n]' -or [string]::IsNullOrWhiteSpace($giText)) { throw "commondir indirection '$Path' has malformed bytes" }
      $giPointer = $giText
    }
    if (-not [System.IO.Path]::IsPathRooted($giPointer)) { $giPointer = Join-Path $RelativeBase $giPointer }
    $giResolved = [System.IO.Path]::GetFullPath($giPointer).TrimEnd('\', '/')
    $giExpected = [System.IO.Path]::GetFullPath($ExpectedDirectory).TrimEnd('\', '/')
    if (-not [string]::Equals($giResolved, $giExpected, [System.StringComparison]::OrdinalIgnoreCase)) { throw "$Kind indirection '$Path' resolves to '$giResolved', not the retained directory '$giExpected'" }
    $giFs.Position = 0
    return [pscustomobject]@{ Path = $Path; Stream = $giFs; Bytes = $giBytes; Directory = $giResolved }
  } catch {
    if ($null -ne $giFs) { $giFs.Dispose(); $giFs = $null }
    throw
  } finally {
    if ($null -ne $giH) { $giH.Dispose() }
  }
}

function Remove-CrgOwnedScratchHandle {
  param([string]$Path, [object]$Stream, [object]$Handle, [switch]$Directory, [string]$Label = 'scratch path')
  $crgScHandle = if ($null -ne $Stream) { $Stream.SafeFileHandle } else { $Handle }
  if ($null -eq $crgScHandle -or $crgScHandle.IsInvalid) {
    Write-Host "[bootstrap] WARNING: $Label at '$Path' has no retained ownership handle; preserving the path for inspection."
    if ($null -ne $Stream) { try { $Stream.Dispose() } catch { } }
    elseif ($null -ne $Handle) { try { $Handle.Dispose() } catch { } }
    return $false
  }
  $crgScErr = 0
  try { $crgScResult = [CrgBootstrap.NativeV4]::DeleteHeldExact($crgScHandle, [bool]$Directory, [ref]$crgScErr) }
  catch {
    Write-Host "[bootstrap] WARNING: same-handle cleanup threw for $Label at '$Path' ($($_.Exception.Message)); preserving the owned remnant."
    return $false
  } finally {
    if ($null -ne $Stream) { try { $Stream.Dispose() } catch { } }
    elseif ($null -ne $Handle) { try { $Handle.Dispose() } catch { } }
  }
  switch ($crgScResult) {
    0 { return $true }
    3 { Write-Host "[bootstrap] WARNING: the retained $Label handle at '$Path' no longer reports the owned ordinary $(if ($Directory) { 'directory' } else { 'single-link file' }) shape; preserving the remnant."; return $false }
    5 { Write-Host "[bootstrap] WARNING: same-handle deletion failed for $Label at '$Path' (Win32 error $crgScErr); the owned remnant is preserved."; return $false }
    default { Write-Host "[bootstrap] WARNING: the retained $Label handle at '$Path' could not be queried for exact cleanup (Win32 error $crgScErr); preserving the remnant."; return $false }
  }
}

$gitConfigEnvNames = @(
  'GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM',
  'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT'
)
$gitRepositoryEnvNames = @(
  'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
  'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_NAMESPACE',
  'GIT_REFERENCE_BACKEND'
)
$gitAttributeEnvNames = @('GIT_ATTR_SOURCE', 'GIT_ATTR_NOSYSTEM')
$gitHistoryEnvNames = @('GIT_REPLACE_REF_BASE', 'GIT_GRAFT_FILE', 'GIT_SHALLOW_FILE')
$gitOverrideEnvNames = @($gitConfigEnvNames + $gitRepositoryEnvNames + $gitAttributeEnvNames + $gitHistoryEnvNames)

# No package input is executed during central publication, and no consumer
# authorization is inferred here.
function Get-CrgRuntimePayloadPaths {
  [string[]]$rtPaths = @('VERSION', 'scripts/central-launcher.ps1', 'scripts/central-transport.psm1', 'scripts/central-context.psm1',
    'scripts/private-governance.psm1', 'scripts/paired-governance.psm1', 'scripts/paired-tree.psm1',
    'scripts/review-preparation.psm1', 'scripts/project-preparation.psm1',
    'scripts/paired-review-input.psm1', 'scripts/paired-diff.psm1', 'scripts/paired-preparation.psm1',
    'scripts/paired-process.psm1', 'scripts/paired-review-session.psm1', 'scripts/paired-operation.psm1',
    'scripts/paired-project-operation.psm1', 'scripts/paired-git-operation.psm1', 'scripts/paired-stage.psm1',
    'scripts/paired-retention.psm1', 'scripts/paired-resume-state.psm1', 'scripts/paired-state.psm1',
    'scripts/first-attachment-context.psm1', 'scripts/first-attachment-preparation.psm1',
    'scripts/central-attachment.psm1', 'scripts/central-guards.psm1', 'scripts/central-publication.psm1',
    'scripts/central-recovery.psm1', 'scripts/central-instructions.psm1',
    'scripts/grok/auto-review.ps1') + @(Get-CrgCurrentFileList | ForEach-Object { $_.Src })
  [Array]::Sort($rtPaths, [System.StringComparer]::Ordinal)
  return $rtPaths
}

function Read-CrgRuntimeManifestBytes {
  param([byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 65536) { throw 'runtime manifest has an invalid byte length' }
  foreach ($rtByte in $Bytes) {
    if ($rtByte -ne 10 -and ($rtByte -lt 32 -or $rtByte -gt 126)) { throw 'runtime manifest must be exact LF ASCII' }
  }
  $rtLines = @([System.Text.Encoding]::ASCII.GetString($Bytes).Split([char]10))
  if ($rtLines.Count -lt 7 -or $rtLines.Count -gt 262 -or -not [string]::Equals($rtLines[-1], '', [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($rtLines[0], 'crg-runtime-manifest v1', [System.StringComparison]::Ordinal) -or
      -not ([Linq.Enumerable]::Contains([string[]]@('launcher-abi 1', 'launcher-abi 2', 'launcher-abi 3', 'launcher-abi 4'), $rtLines[3], [StringComparer]::Ordinal)) -or
      -not [string]::Equals($rtLines[4], 'config-schema 1', [System.StringComparison]::Ordinal)) {
    throw 'runtime manifest header, ABI, schema, inventory count, or final LF is invalid'
  }
  $rtLauncherAbi = [int]$rtLines[3].Substring('launcher-abi '.Length)
  if ($rtLines[1] -cnotmatch '\Aversion (?<v>[^ ]+)\z') { throw 'runtime manifest version field is invalid' }
  $rtVersion = $Matches['v']
  if ($rtVersion -cnotmatch ($script:CrgSemVerBody + '\z') -or $rtVersion.Length -gt 128) { throw 'runtime manifest version is not bounded SemVer' }
  if ($rtLines[2] -cnotmatch '\Asource-commit (?<o>[0-9a-f]{40}|[0-9a-f]{64})\z') { throw 'runtime manifest source commit is invalid' }
  $rtSource = $Matches['o']
  $rtEntries = New-Object 'System.Collections.Generic.List[object]'
  $rtSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $rtPrevious = ''; $rtTotal = [int64]0
  for ($rtI = 0; $rtI -lt ($rtLines.Count - 6); $rtI++) {
    if ($rtLines[$rtI + 5] -cnotmatch '\Afile (?<h>[0-9a-f]{64}) (?<n>0|[1-9][0-9]{0,7}) (?<p>[A-Za-z0-9._/-]+)\z') { throw 'runtime manifest contains an invalid payload row' }
    $rtLength = [int]$Matches['n']; $rtPath = $Matches['p']; $rtHash = $Matches['h']
    $rtTotal += $rtLength
    if ($rtLength -gt 16777216 -or $rtTotal -gt 268435456 -or $rtPath.Length -gt 240 -or
        [string]::Equals($rtPath, 'runtime-manifest', [System.StringComparison]::OrdinalIgnoreCase) -or -not $rtSeen.Add($rtPath) -or
        [System.StringComparer]::Ordinal.Compare($rtPrevious, $rtPath) -ge 0) { throw "runtime manifest payload '$rtPath' has an invalid length, path, or order" }
    foreach ($rtPart in @($rtPath.Split([char]'/'))) {
      if ($rtPart.Length -eq 0 -or [string]::Equals($rtPart, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($rtPart, '..', [System.StringComparison]::Ordinal) -or $rtPart.EndsWith('.', [System.StringComparison]::Ordinal) -or
          $rtPart -match '\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|\z)') { throw "runtime manifest payload '$rtPath' has an unsupported component" }
    }
    $rtParent = $rtPath
    while ($rtParent.Contains('/')) {
      $rtParent = $rtParent.Substring(0, $rtParent.LastIndexOf([char]'/'))
      if ($rtSeen.Contains($rtParent)) { throw "runtime manifest payload '$rtPath' conflicts with a file parent" }
    }
    $rtPrevious = $rtPath
    $rtEntries.Add([pscustomobject]@{ Path = $rtPath; Length = $rtLength; Hash = $rtHash }) | Out-Null
  }
  # Retained ABIs keep these dispatch/review entrypoints stable, not the publisher's
  # entire optional helper inventory. Approved manifests own release contents.
  # ABI 4 requires only entries that launcher dispatch and review execute or
  # read. ABI 1-3 launchers also require the hook-mode entry points, so a
  # manifest declaring one of those ABIs keeps them: every launcher of its
  # declared ABI must admit it, and activation trusts that declaration.
  $rtRequiredEntries = @('VERSION', 'scripts/codex/auto-review.ps1', 'scripts/codex/review-prompt-template.md', 'scripts/claude/auto-review.ps1')
  if ($rtLauncherAbi -lt 4) { $rtRequiredEntries += @('scripts/run-gate.sh', 'scripts/git-hooks/pre-commit', 'scripts/codex/auto-merge.ps1', 'scripts/codex/commit.ps1', 'scripts/claude/commit.ps1') }
  # The declaration rule needs the launcher's bytes from ABI 4 on. ABI 1
  # foundation packages predate the launcher and stay admissible without it.
  else { $rtRequiredEntries += 'scripts/central-launcher.ps1' }
  foreach ($rtRequired in $rtRequiredEntries) {
    if (@($rtEntries | Where-Object { $_.Path -ceq $rtRequired }).Count -ne 1) { throw "runtime manifest lacks required entrypoint '$rtRequired'" }
  }
  if ($rtLauncherAbi -ge 3 -and @($rtEntries | Where-Object { [string]::Equals($_.Path, 'scripts/central-transport.psm1', [StringComparison]::Ordinal) }).Count -ne 1) { throw "ABI $rtLauncherAbi manifest lacks the local gate transport" }
  return [pscustomobject]@{ Bytes = $Bytes; Id = (Get-CrgSha256HexOfBytes -Bytes $Bytes); Version = $rtVersion; Source = $rtSource; LauncherAbi = $rtLauncherAbi; Entries = $rtEntries }
}

function Read-CrgRuntimeLauncherBytes {
  param([byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 1024) { throw 'launcher provenance has an invalid byte length' }
  foreach ($value in $Bytes) { if ($value -gt 127) { throw 'launcher provenance must be ASCII' } }
  $text = [Text.Encoding]::ASCII.GetString($Bytes)
  if ($text -cmatch '\Acrg-runtime-launcher v1\nrelease (?<r>[0-9a-f]{64})\nsha256 (?<h>[0-9a-f]{64})\n\z') {
    return [pscustomobject]@{ Schema = 1; LauncherAbi = 1; ReleaseId = $Matches['r']; Hash = $Matches['h']; PreviousReleaseId = '-'; PreviousHash = '-' }
  }
  if ($text -cnotmatch '\Acrg-runtime-launcher v(?<a>[234])\nlauncher-abi \k<a>\nrelease (?<r>[0-9a-f]{64})\nsha256 (?<h>[0-9a-f]{64})\nprevious-release (?<p>[0-9a-f]{64}|-)\nprevious-sha256 (?<s>[0-9a-f]{64}|-)\n\z') { throw 'launcher provenance grammar is invalid' }
  $record = [pscustomobject]@{ Schema = [int]$Matches['a']; LauncherAbi = [int]$Matches['a']; ReleaseId = $Matches['r']; Hash = $Matches['h']; PreviousReleaseId = $Matches['p']; PreviousHash = $Matches['s'] }
  if (($record.PreviousReleaseId -ceq '-') -ne ($record.PreviousHash -ceq '-') -or $record.PreviousReleaseId -ceq $record.ReleaseId) { throw 'launcher provenance predecessor is inconsistent' }
  return $record
}

function New-CrgRuntimeLauncherBytes {
  param([int]$LauncherAbi, [string]$ReleaseId, [string]$Hash, [string]$PreviousReleaseId = '-', [string]$PreviousHash = '-')
  $text = if ($LauncherAbi -eq 1) { "crg-runtime-launcher v1`nrelease $ReleaseId`nsha256 $Hash`n" }
    elseif ($LauncherAbi -in @(2, 3, 4)) { "crg-runtime-launcher v$LauncherAbi`nlauncher-abi $LauncherAbi`nrelease $ReleaseId`nsha256 $Hash`nprevious-release $PreviousReleaseId`nprevious-sha256 $PreviousHash`n" }
    else { throw 'unsupported installed launcher ABI' }
  $bytes = [Text.Encoding]::ASCII.GetBytes($text)
  $null = Read-CrgRuntimeLauncherBytes -Bytes $bytes
  return ,$bytes
}

function Assert-CrgRuntimeLauncherOrigin {
  param([string]$Store, [object]$Installation, [object]$Owners)
  $manifestOwner = Open-CrgPackageSourceHold -Path (Join-Path $Store ('releases/' + $Installation.ReleaseId + '/runtime-manifest')) -RelativePath 'launcher origin manifest' -MaxLength 65536
  $Owners.Add($manifestOwner) | Out-Null
  $manifest = Read-CrgRuntimeManifestBytes -Bytes $manifestOwner.Bytes
  $entry = @($manifest.Entries | Where-Object { $_.Path -ceq 'scripts/central-launcher.ps1' })
  if ($manifest.Id -cne $Installation.ReleaseId -or $manifest.LauncherAbi -ne $Installation.LauncherAbi -or
      $entry.Count -ne 1 -or $entry[0].Hash -cne $Installation.Hash) { throw 'installed launcher provenance differs from its retained approved origin' }
}

# A launcher declares its ABI on its first line, after an optional UTF-8
# byte-order mark that PowerShell runs unchanged. The grammar must stay equal to
# the one the launcher applies to its own bytes at startup; 0 means the bytes
# carry no recognisable declaration.
function Get-CrgRuntimeLauncherDeclaredAbi {
  param([byte[]]$Bytes)
  if ($null -ne $Bytes -and [Text.Encoding]::UTF8.GetString($Bytes, 0, [Math]::Min(64, $Bytes.Length)) -cmatch '\A\uFEFF?# Stable launcher ABI (?<a>[1-9][0-9]?)\. ') { return [int]$Matches['a'] }
  return 0
}

# Launchers of ABI 4 and later require at startup that their line-1 declaration
# and launcher-install both name the ABI their code implements, so a manifest or
# installation record of ABI 4 or later must name exactly the declared ABI. ABI 1-3 launchers never read
# the declaration and their packages were admitted without one, so for those
# ABIs only a recognisable declaration naming another ABI refuses. Every
# maintenance entry point applies this one rule before it publishes, writes
# provenance or changes active-release.
function Assert-CrgRuntimeLauncherDeclaration {
  param([int]$LauncherAbi, [byte[]]$Bytes)
  $declared = Get-CrgRuntimeLauncherDeclaredAbi -Bytes $Bytes
  if (($declared -ne 0 -or $LauncherAbi -ge 4) -and $declared -ne $LauncherAbi) {
    throw "launcher bytes declare $(if ($declared -eq 0) { 'no launcher ABI' } else { "launcher ABI $declared" }) where ABI $LauncherAbi is recorded; a release's manifest and an installation's provenance must name the ABI its launcher declares"
  }
}

# A held transition record stays the record every later check of this
# operation reads; $null means the record is positively absent.
function Open-CrgRuntimeLauncherTransitionRecord {
  param([string]$Store, [object]$Owners, [int]$LauncherAbi)
  $path = Join-Path $Store $(if ($LauncherAbi -ge 3) { "launcher-upgrade-v$LauncherAbi" } else { 'launcher-upgrade' })
  $owner = Open-CrgPackageSourceHold -Path $path -RelativePath 'launcher upgrade record' -MaxLength 1024 -AllowAbsent
  if ($null -eq $owner) { return $null }
  $Owners.Add($owner) | Out-Null
  $record = Read-CrgRuntimeLauncherBytes -Bytes $owner.Bytes
  if ($record.Schema -ne $LauncherAbi -or $record.PreviousReleaseId -ceq '-') { throw "launcher upgrade record '$path' is not an exact ABI $LauncherAbi transition" }
  return [pscustomobject]@{ Owner = $owner; Record = $record }
}

# Installation writes launcher-install only while no launcher transition is
# recorded, always with both predecessor fields '-', and every migration writes
# it byte for byte equal to its own transition record. The store's records
# therefore imply the complete installation record of an ABI, release and hash:
# the transition record to that ABI, which must name that release and hash; the
# first-installation form while no transition to that ABI or below is recorded;
# and none when the newest such transition targets a lower ABI, since only a
# recorded migration installs an ABI after a migration. Provenance is accepted
# by these complete bytes, never by selected fields, because two records can
# name the same release and hash with different predecessors.
function Get-CrgRuntimeLauncherLineage {
  param([string]$Store, [object]$Owners, [int]$LauncherAbi, [string]$ReleaseId, [string]$Hash)
  for ($abi = $LauncherAbi; $abi -ge 2; $abi--) {
    $transition = Open-CrgRuntimeLauncherTransitionRecord -Store $Store -Owners $Owners -LauncherAbi $abi
    if ($null -eq $transition) { continue }
    if ($abi -eq $LauncherAbi -and [string]::Equals($transition.Record.ReleaseId, $ReleaseId, [StringComparison]::Ordinal) -and [string]::Equals($transition.Record.Hash, $Hash, [StringComparison]::Ordinal)) { return ,[byte[]]$transition.Owner.Bytes }
    return $null
  }
  return ,(New-CrgRuntimeLauncherBytes -LauncherAbi $LauncherAbi -ReleaseId $ReleaseId -Hash $Hash)
}

# The newest recorded launcher transition owns the installed pair: a later
# record supersedes every earlier one, whose fixed leaves it replaced or will
# replace. Activation and migration act on this one classification.
# predecessor: launcher-install equals the preceding provenance and launcher.ps1
# hashes to the predecessor hash. The preceding provenance is the installation
# record the store's history implies for the transition's predecessor fields
# (Get-CrgRuntimeLauncherLineage); for ABI 3 and later the retained
# launcher-prior record must equal it byte for byte, while the ABI 2 transition
# keeps no prior record. successor: launcher-install equals the transition
# record and launcher.ps1 hashes to its hash. partial: each fixed leaf is absent
# or one of those two sides, which only a resumed migration completes.
# conflict: anything else. Each migration keeps its transition and prior
# records for the life of the store, and the bootstrap of launcher ABI 3
# required them before it reported a migration complete, so every state, the
# successor included, also requires that history: for a transition to ABI 3 or
# later its prior record and, while the preceding provenance is itself an
# earlier transition record, that transition's prior record where its ABI
# keeps one, back to the first installation. A missing or
# differing one is a conflict and a malformed transition record refuses; the
# earlier records are checked, never classified against the fixed leaves.
function Get-CrgRuntimeLauncherTransition {
  param([string]$Store, [object]$Owners, [object]$Install, [object]$Launcher)
  foreach ($abi in @(4, 3, 2)) {
    $transition = Open-CrgRuntimeLauncherTransitionRecord -Store $Store -Owners $Owners -LauncherAbi $abi
    if ($null -eq $transition) { continue }
    $owner = $transition.Owner; $record = $transition.Record
    $predecessor = [pscustomobject]@{ LauncherAbi = $abi - 1; ReleaseId = $record.PreviousReleaseId; Hash = $record.PreviousHash }
    $launcherHash = if ($null -ne $Launcher) { Get-CrgSha256HexOfBytes -Bytes $Launcher.Bytes } else { '-' }
    $isSuccessor = $null -ne $Install -and [Linq.Enumerable]::SequenceEqual([byte[]]$Install.Bytes, [byte[]]$owner.Bytes)
    $priorBytes = $null; $stepAbi = $abi; $stepRecord = $record
    do {
      $implied = Get-CrgRuntimeLauncherLineage -Store $Store -Owners $Owners -LauncherAbi ($stepAbi - 1) -ReleaseId $stepRecord.PreviousReleaseId -Hash $stepRecord.PreviousHash
      if ($null -ne $implied -and $stepAbi -ge 3) {
        $prior = Open-CrgPackageSourceHold -Path (Join-Path $Store "launcher-prior-v$stepAbi") -RelativePath 'exact preceding launcher provenance' -MaxLength 1024 -AllowAbsent
        if ($null -ne $prior) { $Owners.Add($prior) | Out-Null }
        if ($null -eq $prior -or -not [Linq.Enumerable]::SequenceEqual([byte[]]$prior.Bytes, [byte[]]$implied)) { $implied = $null }
      }
      if ($null -eq $implied) { $priorBytes = $null; break }
      if ($null -eq $priorBytes) { $priorBytes = $implied }
      $stepRecord = Read-CrgRuntimeLauncherBytes -Bytes $implied
      $stepAbi = $stepRecord.LauncherAbi
    } while (-not [string]::Equals($stepRecord.PreviousReleaseId, '-', [StringComparison]::Ordinal))
    $isPredecessor = $null -ne $priorBytes -and $null -ne $Install -and [Linq.Enumerable]::SequenceEqual([byte[]]$Install.Bytes, [byte[]]$priorBytes)
    $state = if ($null -eq $priorBytes) { 'conflict' }
      elseif ($isSuccessor -and $launcherHash -ceq $record.Hash) { 'successor' }
      elseif ($isPredecessor -and $launcherHash -ceq $predecessor.Hash) { 'predecessor' }
      elseif (($null -eq $Install -or $isSuccessor -or $isPredecessor) -and $launcherHash -cin @('-', $record.Hash, $predecessor.Hash)) { 'partial' }
      else { 'conflict' }
    return [pscustomobject]@{ LauncherAbi = $abi; Owner = $owner; Record = $record; Predecessor = $predecessor; PriorBytes = $priorBytes; State = $state }
  }
  return $null
}

function Update-CrgRuntimeLauncherAbi {
  param([string]$Store, [object]$Release, [object]$Owners)
  $targetAbi = $Release.Manifest.LauncherAbi
  if ($targetAbi -notin @(2, 3, 4)) { throw 'launcher migration requires an approved successor ABI target' }
  $target = @($Release.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [System.StringComparison]::Ordinal) })
  if ($target.Count -ne 1) { throw 'launcher migration target lacks the exact launcher payload' }
  Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $targetAbi -Bytes $target[0].Bytes
  $targetHash = Get-CrgSha256HexOfBytes -Bytes $target[0].Bytes
  # Each target ABI owns its record names, so a completed earlier migration's
  # transition and prior provenance stay retained beside the new ones.
  $migrationPath = Join-Path $Store $(if ($targetAbi -ge 3) { "launcher-upgrade-v$targetAbi" } else { 'launcher-upgrade' })
  $installOwner = Open-CrgPackageSourceHold -Path (Join-Path $Store 'launcher-install') -RelativePath 'installed launcher provenance' -MaxLength 1024 -AllowAbsent
  $launcherOwner = Open-CrgPackageSourceHold -Path (Join-Path $Store 'launcher.ps1') -RelativePath 'installed launcher' -AllowAbsent
  foreach ($owner in @($installOwner, $launcherOwner)) { if ($null -ne $owner) { $Owners.Add($owner) | Out-Null } }
  $transition = Get-CrgRuntimeLauncherTransition -Store $Store -Owners $Owners -Install $installOwner -Launcher $launcherOwner
  # Resuming an earlier transition after a later one was recorded would restore
  # provenance the later one replaced, and a new transition may follow only a
  # completed one. Every record classified here stays held through the writes
  # below. The store lock serializes maintenance operations only: a record a
  # restore writes during this operation at a pathname found absent is not
  # observed, so a restore of store files is never run during maintenance.
  if ($null -ne $transition -and $transition.LauncherAbi -gt $targetAbi) { throw "the recorded launcher transition to ABI $($transition.LauncherAbi) owns the installation, so no migration to an earlier ABI follows it; -UpgradeRuntimeLauncher -ReleaseId $($transition.Record.ReleaseId) resumes that transition or confirms that it is complete" }
  $recorded = $null -ne $transition -and $transition.LauncherAbi -eq $targetAbi
  if ($recorded) {
    if ($transition.Record.ReleaseId -cne $Release.Manifest.Id -or $transition.Record.Hash -cne $targetHash) { throw 'launcher upgrade record selects another exact transition' }
    if ($transition.State -ceq 'successor') {
      Assert-CrgRuntimeLauncherOrigin -Store $Store -Installation $transition.Predecessor -Owners $Owners
      Write-Host "[bootstrap] exact ABI $targetAbi launcher migration is already complete for release $($Release.Manifest.Id); no release activated and no consumer changed."
      return
    }
    if ($transition.State -ceq 'conflict') { throw 'launcher migration preserves an installed pair or preceding provenance that is neither side of its recorded transition; restore the store''s launcher files and records to one side of that transition' }
    $predecessor = $transition.Predecessor; $previousBytes = [byte[]]$transition.PriorBytes; $desired = [byte[]]$transition.Owner.Bytes
  } else {
    if ($null -ne $transition -and $transition.State -cne 'successor') { throw "a new launcher migration requires the completed successor of the recorded launcher transition to ABI $($transition.LauncherAbi); the installed pair is $($transition.State); $(if ($transition.State -ceq 'conflict') { 'restore the store''s launcher files and records to one side of that transition' } else { "complete that transition first with -UpgradeRuntimeLauncher -ReleaseId $($transition.Record.ReleaseId)" })" }
    if ($null -eq $installOwner -or $null -eq $launcherOwner) { throw 'new launcher migration requires a complete verified predecessor installation' }
    $predecessor = Read-CrgRuntimeLauncherBytes -Bytes $installOwner.Bytes
    if ($predecessor.LauncherAbi -ne ($targetAbi - 1)) { throw 'launcher migration requires the immediately preceding ABI; routine releases use activation' }
    if ((Get-CrgSha256HexOfBytes -Bytes $launcherOwner.Bytes) -cne $predecessor.Hash) { throw 'existing launcher differs from its approved predecessor origin' }
    $previousBytes = Get-CrgRuntimeLauncherLineage -Store $Store -Owners $Owners -LauncherAbi $predecessor.LauncherAbi -ReleaseId $predecessor.ReleaseId -Hash $predecessor.Hash
    if ($null -eq $previousBytes -or -not [Linq.Enumerable]::SequenceEqual([byte[]]$installOwner.Bytes, [byte[]]$previousBytes)) { throw 'installed launcher provenance is not the exact record the recorded launcher transitions imply; nothing was written, restore the store''s launcher files and records' }
    $desired = New-CrgRuntimeLauncherBytes -LauncherAbi $targetAbi -ReleaseId $Release.Manifest.Id -Hash $targetHash -PreviousReleaseId $predecessor.ReleaseId -PreviousHash $predecessor.Hash
  }
  Assert-CrgRuntimeLauncherOrigin -Store $Store -Installation $predecessor -Owners $Owners
  if ($null -ne $launcherOwner -and (Get-CrgSha256HexOfBytes -Bytes $launcherOwner.Bytes) -ceq $predecessor.Hash) { Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $predecessor.LauncherAbi -Bytes $launcherOwner.Bytes }
  # The successor launcher must be able to open the release active-release
  # names. Every launcher a migration installs refuses a release that fails
  # verification, one of a later ABI than its own and one without the launcher
  # capabilities; only the ABI 4 launcher applies the declaration rule, so
  # that test runs only for an ABI 4 successor. A
  # bootstrap from before the declaration rule could publish an ABI 4 launcher
  # payload as ABI 3 and activate it, and the ABI 3 launcher runs it. While no
  # fixed leaf is replaced the predecessor launcher can still settle that
  # release's operations and activation can still change the selection, so a
  # migration in that state refuses while the successor would reject the
  # active release. A partial pair starts neither launcher and refuses
  # activation until the migration completes, so refusing it would leave no
  # way to act on the selection; a replacement this bootstrap began passed
  # this check first. Handoffs are project state that the store does not
  # list; the deployment guide has the operator settle the ones bound to a
  # rejected release before migrating.
  if (-not $recorded -or [string]::Equals($transition.State, 'predecessor', [StringComparison]::Ordinal)) {
    $activeOwner = Open-CrgPackageSourceHold -Path (Join-Path $Store 'active-release') -RelativePath 'central active release' -MaxLength 95 -AllowAbsent
    if ($null -ne $activeOwner) {
      $Owners.Add($activeOwner) | Out-Null
      $activeId = Read-CrgRuntimeActiveBytes -Bytes $activeOwner.Bytes
      $replace = "activate a release that the installed ABI $($predecessor.LauncherAbi) launcher and the ABI $targetAbi launcher both admit, and rerun the migration"
      try {
        $active = Open-CrgRuntimeRelease -Root (Join-Path $Store "releases/$activeId") -ExpectedId $activeId
      } catch {
        throw "active release $activeId does not verify ($($_.Exception.Message)); this run of the migration wrote nothing. No launcher runs a release that fails verification: restore that release's files, or $replace"
      }
      foreach ($owner in $active.Owners) { $Owners.Add($owner) | Out-Null }
      if ($active.Manifest.LauncherAbi -gt $targetAbi) { throw "active release $activeId is a launcher ABI $($active.Manifest.LauncherAbi) release, which the ABI $targetAbi launcher cannot open; this run of the migration wrote nothing. To proceed, $replace" }
      try {
        foreach ($required in @('scripts/central-launcher.ps1', 'scripts/central-context.psm1', 'scripts/private-governance.psm1')) {
          if (@($active.Manifest.Entries | Where-Object { [string]::Equals($_.Path, $required, [StringComparison]::Ordinal) }).Count -ne 1) { throw "release lacks launcher capability '$required'" }
        }
        if ($targetAbi -ge 4) { Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $active.Manifest.LauncherAbi -Bytes @($active.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [StringComparison]::Ordinal) })[0].Bytes }
      } catch {
        throw "the ABI $targetAbi launcher would refuse active release $activeId ($($_.Exception.Message)); this run of the migration wrote nothing. With the still-installed ABI $($predecessor.LauncherAbi) launcher, finish or resume to completion every pending project operation bound to that release, which the ABI $targetAbi launcher cannot resume, then $replace"
      }
    }
  }
  if ($targetAbi -ge 4) { Assert-CrgRuntimeLauncherUnheld -Holds @($installOwner, $launcherOwner) }
  if ($targetAbi -ge 3) {
    # A startup conflict that host installation refuses after the replacements
    # refuses here instead, before any write. Installation repeats the check on
    # its own key handle, since the key can change in between.
    $startup = Get-CrgRuntimeHostStartup -Store $Store
    $runKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $false)
    if ($null -ne $runKey) { try { $null = Test-CrgRuntimeHostStartupEntry -Key $runKey -Startup $startup } finally { $runKey.Dispose() } }
  }
  if (-not $recorded) {
    if ($targetAbi -ge 3) {
      $priorPath = Join-Path $Store "launcher-prior-v$targetAbi"
      $null = Update-CrgRootedFileBytes -Path $priorPath -MaxLength 1024 -Label 'exact preceding launcher provenance' -Transform {
        param([byte[]]$Previous)
        if (($Previous.Length -gt 0 -or (Get-CrgPathOccupantKind -Path $priorPath) -cne 'empty') -and -not [Linq.Enumerable]::SequenceEqual([byte[]]$Previous, $previousBytes)) { throw 'preceding launcher provenance conflicts with the current verified installation' }
        return [pscustomobject]@{ Ok = $true; Bytes = $previousBytes }
      }
      # Resumed migration and activation classify the pair against this
      # record, so the published bytes stay held, and therefore unchanged,
      # until the transition record and both fixed leaves are written.
      $priorOwner = Open-CrgPackageSourceHold -Path $priorPath -RelativePath 'exact preceding launcher provenance' -MaxLength 1024
      $Owners.Add($priorOwner) | Out-Null
      if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$priorOwner.Bytes, [byte[]]$previousBytes)) { throw 'preceding launcher provenance readback differs from the verified installation' }
    }
    # Retain the exact transition before replacing either fixed leaf. The
    # existing no-replace writer can leave a temporary name absent after a
    # crash; this bounded record authorizes only the recorded old/new bytes.
    $null = Update-CrgRootedFileBytes -Path $migrationPath -MaxLength 1024 -Label 'launcher upgrade record' -Transform {
      param([byte[]]$Previous)
      if (($Previous.Length -gt 0 -or (Get-CrgPathOccupantKind -Path $migrationPath) -cne 'empty') -and
          -not [Linq.Enumerable]::SequenceEqual([byte[]]$Previous, [byte[]]$desired)) { throw 'launcher upgrade record conflicts with the approved transition' }
      return [pscustomobject]@{ Ok = $true; Bytes = $desired }
    }
    $migrationOwner = Open-CrgPackageSourceHold -Path $migrationPath -RelativePath 'launcher upgrade record' -MaxLength 1024
    $Owners.Add($migrationOwner) | Out-Null
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$migrationOwner.Bytes, [byte[]]$desired)) { throw 'launcher upgrade record readback differs from the approved transition' }
  }
  foreach ($owner in @($installOwner, $launcherOwner)) {
    if ($null -ne $owner) { $owner.Stream.Dispose(); $owner.Stream = $null }
  }
  $installPath = Join-Path $Store 'launcher-install'
  $null = Update-CrgRootedFileBytes -Path $installPath -MaxLength 1024 -Label 'successor launcher provenance' -Transform {
    param([byte[]]$Previous)
    $absent = $Previous.Length -eq 0 -and (Get-CrgPathOccupantKind -Path $installPath) -ceq 'empty'
    if (-not $absent -and -not [Linq.Enumerable]::SequenceEqual([byte[]]$Previous, [byte[]]$previousBytes) -and
        -not [Linq.Enumerable]::SequenceEqual([byte[]]$Previous, [byte[]]$desired)) { throw 'launcher provenance changed outside the recorded migration' }
    return [pscustomobject]@{ Ok = $true; Bytes = $desired }
  }
  $verifiedInstall = Open-CrgPackageSourceHold -Path $installPath -RelativePath 'upgraded launcher provenance' -MaxLength 1024
  $Owners.Add($verifiedInstall) | Out-Null
  if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$verifiedInstall.Bytes, [byte[]]$desired)) { throw 'upgraded launcher provenance readback differs' }
  $launcherPath = Join-Path $Store 'launcher.ps1'
  $null = Update-CrgRootedFileBytes -Path $launcherPath -Label 'successor stable launcher' -Transform {
    param([byte[]]$Previous)
    $absent = $Previous.Length -eq 0 -and (Get-CrgPathOccupantKind -Path $launcherPath) -ceq 'empty'
    if (-not $absent -and (Get-CrgSha256HexOfBytes -Bytes $Previous) -cnotin @($predecessor.Hash, $targetHash)) { throw 'launcher bytes changed outside the recorded migration' }
    return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$target[0].Bytes }
  }
  $verifiedLauncher = Open-CrgPackageSourceHold -Path $launcherPath -RelativePath 'upgraded stable launcher'
  $Owners.Add($verifiedLauncher) | Out-Null
  if ((Get-CrgSha256HexOfBytes -Bytes $verifiedLauncher.Bytes) -cne $targetHash) { throw 'upgraded launcher readback differs from the approved release' }
  Write-Host "[bootstrap] stable launcher upgraded from ABI $($targetAbi - 1) to ABI $targetAbi using verified release $($Release.Manifest.Id); no release activated and no consumer changed."
  Write-Host "[bootstrap] exact launcher transition retained at '$migrationPath'; preceding release $($predecessor.ReleaseId) remains required."
}

# Every installed launcher process - the gate host of any logon or account, a
# project command, a gate worker - holds launcher.ps1 and launcher-install,
# sharing only reads, from startup until it exits, and an ABI 3 host can
# neither be asked to release them nor confirm that it keeps no custody for an
# operation. A migration to ABI 4 that still has a launcher file to replace
# therefore ends no process and refuses while any process other than itself
# holds either file; a rerun after the transition completed replaces nothing,
# repairs only host registration and does not check. A holder can be keeping
# custody for an operation whose outcome or descendant exit is unconfirmed,
# which the list cannot tell from an idle host, so the refusal has the
# operator resolve that custody before ending a holder and defer the
# migration while it stays unresolved. The holder list names processes
# of every session and account without matching names or command lines. It
# covers only holders the migration's own read-only open can coexist with: a
# holder that denies read sharing or holds write or delete access makes that
# open fail with a sharing violation first, and that refusal names no process.
# A process that opens a file after this check blocks its replacement with a
# sharing violation unless it holds only read access and shares both reads and
# deletion; every launcher process denies delete sharing and so blocks it.
# Either failure leaves a state a rerun resumes.
# An empty or short list must not read as "unheld", so each file's list has to
# name a holder known to exist before this process is excluded from it. The
# list omits the open the query runs through and names the process of every
# other open, the querying process's other opens included: on 2026-11-24
# (Windows 11, NTFS) a query through a process's only open of a file returned
# an empty list, and named only the other process while a second process also
# held the file; queried through a second open, it named both. Querying
# through the migration's own hold and requiring this process in the result
# therefore refused every migration; do not retry that. Each file is queried
# through a separate attribute-only reopen of the hold, which keeps the hold a
# known holder: a list that omits this process, or whose returned length
# fits neither identifier layout for its count, refuses before any write.
function Assert-CrgRuntimeLauncherUnheld {
  param([object[]]$Holds)
  # A PowerShell process keeps the first type compiled under a name, so a
  # change to this helper's code takes a new type name.
  if (-not ('CrgBootstrap.LauncherHoldersV3' -as [type])) {
    Add-Type -Namespace 'CrgBootstrap' -Name 'LauncherHoldersV3' -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
struct IO_STATUS_BLOCK { public System.IntPtr Status, Information; }
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool ProcessIdToSessionId(uint id, out uint session);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern Microsoft.Win32.SafeHandles.SafeFileHandle ReOpenFile(System.Runtime.InteropServices.SafeHandle original, uint access, uint share, uint flags);
[System.Runtime.InteropServices.DllImport("ntdll.dll")]
static extern int NtQueryInformationFile(System.Runtime.InteropServices.SafeHandle file, out IO_STATUS_BLOCK status, System.IntPtr information, uint length, int informationClass);

public static long SessionOf(uint id) { uint session; return ProcessIdToSessionId(id, out session) ? (long)session : -1L; }
// FileProcessIdsUsingFileInformation names every process with the file open,
// whatever its account or session, except through the open queried. The
// attribute-only reopen takes part in no sharing check, so it neither fails
// against nor blocks another open while it exists.
public static ulong[] FileHolders(System.Runtime.InteropServices.SafeHandle hold) {
    const int size = 65536;
    using (Microsoft.Win32.SafeHandles.SafeFileHandle query = ReOpenFile(hold, 0x80u, 0x7u, 0x00200000u)) {
        if (query.IsInvalid) { throw new System.IO.IOException("launcher holder enumeration could not reopen the held file (Win32 error " + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + ")"); }
        System.IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try {
            IO_STATUS_BLOCK status;
            int result = NtQueryInformationFile(query, out status, buffer, (uint)size, 47);
            if (result != 0) { throw new System.IO.IOException("launcher holder enumeration failed (NTSTATUS 0x" + result.ToString("X8") + ")"); }
            int count = System.Runtime.InteropServices.Marshal.ReadInt32(buffer);
            int width = System.IntPtr.Size;
            if (count < 0 || ((long)count + 1) * width > size) { throw new System.IO.IOException("launcher holder list exceeds its bound"); }
            // The identifier array starts at pointer alignment after the count,
            // in this process's layout. A 32-bit process on 64-bit Windows
            // receives 4-byte identifiers while the reported length is that
            // of the system's 8-byte layout (2026-11-25: one identifier at
            // offset 4, reported length 16), so either length confirms the
            // count there; the caller's own-process test confirms the read.
            long returned = status.Information.ToInt64();
            if (returned != ((long)count + 1) * width && !(width == 4 && returned == ((long)count + 1) * 8)) { throw new System.IO.IOException("launcher holder enumeration returned " + returned + " bytes for " + count + " holder(s), which fits no identifier layout of this process"); }
            ulong[] ids = new ulong[count];
            for (int i = 0; i < count; i++) { ids[i] = width == 8 ? (ulong)System.Runtime.InteropServices.Marshal.ReadInt64(buffer, (i + 1) * 8) : (ulong)(uint)System.Runtime.InteropServices.Marshal.ReadInt32(buffer, (i + 1) * 4); }
            return ids;
        } finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer); }
    }
}
'@
  }
  $holders = New-Object 'System.Collections.Generic.HashSet[uint64]'
  foreach ($hold in @($Holds | Where-Object { $null -ne $_ })) {
    [uint64[]]$listed = [CrgBootstrap.LauncherHoldersV3]::FileHolders($hold.Stream.SafeFileHandle)
    if ($listed -notcontains [uint64]$PID) { throw "launcher holder enumeration did not list this process's own open of the $($hold.RelativePath), so its holder list is unconfirmed; this run of the migration wrote nothing" }
    foreach ($holder in $listed) { [void]$holders.Add($holder) }
  }
  $others = @($holders | Where-Object { $_ -ne [uint64]$PID } | Sort-Object)
  if ($others.Count -gt 0) {
    $named = @($others | ForEach-Object { $session = [CrgBootstrap.LauncherHoldersV3]::SessionOf([uint32]$_); "$_ (session $(if ($session -ge 0) { $session } else { 'unknown' }))" }) -join ', '
    throw "the installed launcher is held by process(es) $named. Every gate host and gate command of this store, in every logon, must have exited before -UpgradeRuntimeLauncher; this run of the migration wrote nothing. End a gate host only after its operations have completed, every unknown outcome has been inspected with Status or Resume, and no unconfirmed descendant remains in its custody; while a holder cannot be resolved so, defer the migration. Rerun once those processes have exited"
  }
}

function Get-CrgRuntimeHostStartup {
  param([string]$Store)
  $shell = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'WindowsPowerShell\v1.0\powershell.exe'
  $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $Store 'launcher.ps1') + '" -Serve'
  $command = '"' + $shell + '" ' + $arguments
  if ($command.Length -gt 260) { throw 'runtime store path exceeds the Windows Run startup command bound; host installation is incomplete' }
  # Explorer reads the Run key at logon and stops at a value name it cannot
  # enumerate. The original name, the prefix plus the full store hash, ended
  # that enumeration at every logon from 2026-10-25 to 2026-11-13: neither the
  # host nor any entry after it started, while a shorter name ahead of it
  # launched. The exact limit is not established, so the name carries only a
  # store-hash prefix; do not lengthen it.
  $storeHash = Get-CrgSha256HexOfBytes -Bytes ([Text.Encoding]::UTF8.GetBytes($Store.ToUpperInvariant()))
  return [pscustomobject]@{ Shell = $shell; Arguments = $arguments; Command = $command; Name = ('CrossReviewGate-' + $storeHash.Substring(0, 16)); LegacyName = ('CrossReviewGate-' + $storeHash) }
}

# The one conflict predicate for the per-user startup entry. A caller that
# writes evaluates it on the key handle it writes through, so no result of an
# earlier, separately opened check decides whether a value is written.
function Test-CrgRuntimeHostStartupEntry {
  param([object]$Key, [object]$Startup)
  # Presence comes from the value-name list: GetValue returns its default for
  # a value whose type .NET cannot decode, which would read as absent. A
  # failed enumeration throws and leaves the installation incomplete.
  $present = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($valueName in $Key.GetValueNames()) { [void]$present.Add($valueName) }
  # A remaining legacy-name entry still ends enumeration before this entry.
  # The registry has no conditional delete: removing it here could delete a
  # value another writer put there after validation, so installation names
  # it and stops, and the operator removes it.
  if ($present.Contains($Startup.LegacyName)) {
    throw "legacy gate startup entry '$($Startup.LegacyName)' in HKCU\Software\Microsoft\Windows\CurrentVersion\Run stops Explorer before the gate host starts at logon; host installation is incomplete. Remove it with: reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v $($Startup.LegacyName), then rerun this installation"
  }
  if (-not $present.Contains($Startup.Name)) { return $false }
  $installed = $Key.GetValue($Startup.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if ($Key.GetValueKind($Startup.Name) -ne [Microsoft.Win32.RegistryValueKind]::String -or $installed -isnot [string] -or -not [string]::Equals($installed, $Startup.Command, [StringComparison]::Ordinal)) {
    throw 'gate startup registration is occupied by a different command; preserve the existing entry'
  }
  return $true
}

function Install-CrgRuntimeHost {
  param([string]$Store, [object]$Release)
  if ($Release.Manifest.LauncherAbi -lt 3) { return }
  $transport = @($Release.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-transport.psm1', [StringComparison]::Ordinal) })
  if ($transport.Count -ne 1) { throw 'host installation requires the exact retained transport payload' }
  Import-Module -Name $transport[0].Path -ErrorAction Stop
  $startup = Get-CrgRuntimeHostStartup -Store $Store
  $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
  try {
    if (-not (Test-CrgRuntimeHostStartupEntry -Key $key -Startup $startup)) { $key.SetValue($startup.Name, $startup.Command, [Microsoft.Win32.RegistryValueKind]::String); $key.Flush() }
    $installed = $key.GetValue($startup.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($key.GetValueKind($startup.Name) -ne [Microsoft.Win32.RegistryValueKind]::String -or $installed -isnot [string] -or -not [string]::Equals($installed, $startup.Command, [StringComparison]::Ordinal)) {
      throw 'gate startup registration readback differs from the installed command'
    }
  } finally { $key.Dispose() }
  if (Test-CrgHostAvailable -Store $Store) { Write-Host '[bootstrap] installed local gate host is available.'; return }
  $process = Start-Process -FilePath $startup.Shell -ArgumentList $startup.Arguments -WorkingDirectory $Store -WindowStyle Hidden -PassThru
  $watch = [Diagnostics.Stopwatch]::StartNew()
  while ($watch.ElapsedMilliseconds -lt 15000) {
    if (Test-CrgHostAvailable -Store $Store) { Write-Host '[bootstrap] installed local gate host started; project commands require no sandbox exception.'; return }
    if ($process.HasExited) { throw 'installed gate host exited before availability; launcher installation is incomplete' }
    Start-Sleep -Milliseconds 100
  }
  throw "installed gate host did not confirm availability; preserve process $($process.Id) and installation provenance for repair"
}

function Read-CrgRuntimeActiveBytes {
  param([byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -ne 95) { throw 'central active record must be exactly 95 bytes' }
  foreach ($rtByte in $Bytes) { if ($rtByte -gt 127) { throw 'central active record is not ASCII' } }
  if ([System.Text.Encoding]::ASCII.GetString($Bytes) -cnotmatch '\Acrg-runtime-active v1\nrelease (?<h>[0-9a-f]{64})\n\z') { throw 'central active record grammar is invalid' }
  return $Matches['h']
}

function Get-CrgRuntimeAbsolutePath {
  param([string]$Path, [string]$Label)
  if ([string]::IsNullOrWhiteSpace($Path) -or $Path -cnotmatch '\A[A-Za-z]:[\\/]') { throw "$Label must be an absolute local drive path" }
  foreach ($rtPart in @($Path.Substring(3) -split '[\\/]')) {
    if ($rtPart.Length -eq 0 -or [string]::Equals($rtPart, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($rtPart, '..', [System.StringComparison]::Ordinal) -or
        $rtPart.EndsWith('.', [System.StringComparison]::Ordinal) -or $rtPart.EndsWith(' ', [System.StringComparison]::Ordinal) -or
        $rtPart.IndexOfAny([char[]]@(':', '*', '?', '"', '<', '>', '|')) -ge 0 -or [string]::Equals($rtPart, '.git', [System.StringComparison]::OrdinalIgnoreCase)) { throw "$Label contains an unsupported path component" }
  }
  $rtFull = [System.IO.Path]::GetFullPath($Path)
  if ($rtFull.Length -le 3) { throw "$Label must not be a drive root" }
  return $rtFull.TrimEnd('\', '/')
}

function Test-CrgRuntimePathContains {
  param([string]$Parent, [string]$Child)
  return [string]::Equals($Parent, $Child, [System.StringComparison]::OrdinalIgnoreCase) -or
    $Child.StartsWith($Parent.TrimEnd('\', '/') + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-CrgRuntimeInventory {
  param([string]$Root, [object]$Manifest)
  $rtExpected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($rtPath in @('runtime-manifest') + @($Manifest.Entries | ForEach-Object { $_.Path })) { [void]$rtExpected.Add($rtPath) }
  $rtPending = New-Object 'System.Collections.Generic.Stack[string]'
  $rtPending.Push('')
  while ($rtPending.Count -gt 0) {
    $rtRelative = $rtPending.Pop()
    $rtDirectory = if ($rtRelative.Length -eq 0) { $Root } else { Join-Path $Root $rtRelative }
    $null = Enter-CrgRootedExistingDirectory -Path $rtDirectory -Label 'runtime payload directory'
    foreach ($rtChild in [System.IO.Directory]::EnumerateFileSystemEntries($rtDirectory)) {
      $rtName = [System.IO.Path]::GetFileName($rtChild)
      $rtChildRelative = if ($rtRelative.Length -eq 0) { $rtName } else { "$rtRelative/$rtName" }
      $rtKind = Get-CrgPathOccupantKind -Path $rtChild
      if ($rtKind -ceq 'directory') {
        if (@($rtExpected | Where-Object { $_.StartsWith($rtChildRelative + '/', [System.StringComparison]::Ordinal) }).Count -eq 0) { throw "unexpected runtime directory '$rtChildRelative'" }
        $rtPending.Push($rtChildRelative)
      } elseif ($rtKind -ceq 'file') {
        if (-not $rtExpected.Remove($rtChildRelative)) { throw "unexpected runtime payload '$rtChildRelative'" }
      } else { throw "runtime payload '$rtChildRelative' is not an ordinary file or directory" }
    }
  }
  if ($rtExpected.Count -ne 0) { throw 'runtime directory is missing declared payloads' }
}

function Open-CrgRuntimeRelease {
  param([string]$Root, [string]$ExpectedId)
  $rtOwners = New-Object 'System.Collections.Generic.List[object]'
  try {
    $null = Enter-CrgRootedExistingDirectory -Path $Root -Label 'runtime release directory'
    $rtManifestOwner = Open-CrgPackageSourceHold -Path (Join-Path $Root 'runtime-manifest') -RelativePath 'runtime-manifest' -MaxLength 65536
    $rtOwners.Add($rtManifestOwner) | Out-Null
    $rtManifest = Read-CrgRuntimeManifestBytes -Bytes $rtManifestOwner.Bytes
    if (-not [string]::Equals($rtManifest.Id, $ExpectedId, [System.StringComparison]::Ordinal)) { throw 'runtime manifest digest differs from the approved release identity' }
    Assert-CrgRuntimeInventory -Root $Root -Manifest $rtManifest
    foreach ($rtEntry in $rtManifest.Entries) {
      $rtOwner = Open-CrgPackageSourceHold -Path (Join-Path $Root $rtEntry.Path) -RelativePath $rtEntry.Path
      $rtOwners.Add($rtOwner) | Out-Null
      if ($rtOwner.Bytes.Length -ne $rtEntry.Length -or (Get-CrgSha256HexOfBytes -Bytes $rtOwner.Bytes) -cne $rtEntry.Hash) { throw "runtime payload '$($rtEntry.Path)' differs from the manifest" }
      if ([string]::Equals($rtEntry.Path, 'VERSION', [System.StringComparison]::Ordinal) -and -not [string]::Equals((Get-CrgPackageVersionFromBytes -Bytes $rtOwner.Bytes), $rtManifest.Version, [System.StringComparison]::Ordinal)) { throw 'runtime VERSION differs from the manifest' }
    }
    Assert-CrgRuntimeInventory -Root $Root -Manifest $rtManifest
    return [pscustomobject]@{ Root = $Root; Manifest = $rtManifest; Owners = $rtOwners }
  } catch {
    foreach ($rtOwner in $rtOwners) { if ($null -ne $rtOwner.Stream) { $rtOwner.Stream.Dispose() } }
    throw
  }
}

function Publish-CrgRuntimeSnapshot {
  param([string]$Store, [object]$Manifest, [object[]]$Owners)
  $rtReleases = Join-Path $Store 'releases'
  $null = Ensure-CrgRootedDirectory -Path $rtReleases -Label 'central releases directory'
  $rtDestination = Join-Path $rtReleases $Manifest.Id
  $rtKind = Get-CrgPathOccupantKind -Path $rtDestination
  if ($rtKind -cne 'empty') { return Open-CrgRuntimeRelease -Root $rtDestination -ExpectedId $Manifest.Id }
  $rtStage = Join-Path $rtReleases ('.stage-' + [Guid]::NewGuid().ToString('N'))
  $rtDirectories = New-Object 'System.Collections.Generic.List[object]'
  $rtFiles = New-Object 'System.Collections.Generic.List[object]'
  $rtPublished = $false
  try {
    $rtDirectoryPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    [void]$rtDirectoryPaths.Add('')
    foreach ($rtEntry in $Manifest.Entries) {
      $rtParent = $rtEntry.Path
      while ($rtParent.Contains('/')) { $rtParent = $rtParent.Substring(0, $rtParent.LastIndexOf([char]'/')); [void]$rtDirectoryPaths.Add($rtParent) }
    }
    foreach ($rtRelative in @($rtDirectoryPaths | Sort-Object Length, { $_ })) {
      $rtPath = if ($rtRelative.Length -eq 0) { $rtStage } else { Join-Path $rtStage $rtRelative }
      $rtError = 0
      $rtHandle = [CrgBootstrap.NativeV4]::CreateOwnedMutationDirectoryAtomic($rtPath, [ref]$rtError)
      if ($null -eq $rtHandle -or $rtHandle.IsInvalid) { if ($null -ne $rtHandle) { $rtHandle.Dispose() }; throw "runtime stage directory create failed at '$rtPath' (Win32 error $rtError)" }
      $rtDirectories.Add([pscustomobject]@{ Path = $rtPath; Handle = $rtHandle }) | Out-Null
      if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($rtPath, $rtHandle, $true)) { throw "runtime stage directory could not be retained at '$rtPath'" }
    }
    $rtBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    foreach ($rtOwner in $Owners) { $rtBuffers[$rtOwner.RelativePath] = [byte[]]$rtOwner.Bytes }
    $rtBuffers['runtime-manifest'] = [byte[]]$Manifest.Bytes
    foreach ($rtRelative in @('runtime-manifest') + @($Manifest.Entries | ForEach-Object { $_.Path })) {
      if (-not $rtBuffers.ContainsKey($rtRelative)) { throw "runtime snapshot is missing '$rtRelative'" }
      $rtPath = Join-Path $rtStage $rtRelative; $rtError = 0
      $rtHandle = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($rtPath, [ref]$rtError)
      if ($null -eq $rtHandle -or $rtHandle.IsInvalid) { if ($null -ne $rtHandle) { $rtHandle.Dispose() }; throw "runtime stage payload create failed at '$rtPath' (Win32 error $rtError)" }
      try { $rtStream = New-Object System.IO.FileStream($rtHandle, [System.IO.FileAccess]::ReadWrite) } catch { $rtHandle.Dispose(); throw }
      $rtFiles.Add([pscustomobject]@{ Path = $rtPath; Stream = $rtStream }) | Out-Null
      [byte[]]$rtBytes = $rtBuffers[$rtRelative]
      $rtStream.Write($rtBytes, 0, $rtBytes.Length); $rtStream.Flush($true)
      $rtBack = Read-CrgHeldStreamBytes -Stream $rtStream -MaxLength 16777216 -Label 'runtime stage payload'
      if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$rtBytes, [byte[]]$rtBack) -or [CrgBootstrap.NativeV3]::GetLinkCount($rtStream.SafeFileHandle) -ne 1) { throw "runtime stage readback failed for '$rtRelative'" }
    }
    # Windows directory publication requires releasing child handles. The
    # directory owner survives the rename; the published release is then fully
    # reopened/verified before success or any active-record mutation is possible.
    foreach ($rtFile in $rtFiles) { $rtFile.Stream.Dispose(); $rtFile.Stream = $null }
    for ($rtI = $rtDirectories.Count - 1; $rtI -ge 0; $rtI--) {
      [CrgBootstrap.NativeV4]::UnregisterRootedIo($rtDirectories[$rtI].Path, $rtDirectories[$rtI].Handle)
      if ($rtI -gt 0) { $rtDirectories[$rtI].Handle.Dispose() }
    }
    $rtError = 0
    if (-not [CrgBootstrap.NativeV4]::RenameHeldNoReplace($rtDirectories[0].Handle, $rtStage, $rtDestination, [ref]$rtError)) { throw "runtime same-parent publication failed (Win32 error $rtError)" }
    $rtPublished = $true
    $rtDirectories[0].Handle.Dispose()
    return Open-CrgRuntimeRelease -Root $rtDestination -ExpectedId $Manifest.Id
  } catch {
    Write-Host "[bootstrap] runtime publication refused; preserved $(if ($rtPublished) { $rtDestination } else { $rtStage }). No release was activated."
    throw
  } finally {
    foreach ($rtFile in $rtFiles) { if ($null -ne $rtFile.Stream) { $rtFile.Stream.Dispose() } }
    foreach ($rtDirectory in $rtDirectories) {
      if (-not $rtDirectory.Handle.IsClosed) { [CrgBootstrap.NativeV4]::UnregisterRootedIo($rtDirectory.Path, $rtDirectory.Handle); $rtDirectory.Handle.Dispose() }
    }
  }
}

function Invoke-CrgCentralRuntimeOperation {
  param([string]$Operation)
  $rtStore = Get-CrgRuntimeAbsolutePath -Path $RuntimeStore -Label 'RuntimeStore'
  $rtInput = $null; $rtCandidate = $null
  if ($Operation -ceq 'PublishRuntimeSource') {
    if ($ApprovedSourceCommit -cnotmatch '\A([0-9a-f]{40}|[0-9a-f]{64})\z') { throw 'ApprovedSourceCommit must be a full lowercase Git OID' }
    $rtInput = Get-CrgRuntimeAbsolutePath -Path $SourceRoot -Label 'SourceRoot'
    $rtDotGitPath = Join-Path $rtInput '.git'
    $rtDotGitKind = Get-CrgPathOccupantKind -Path $rtDotGitPath
    if ($rtDotGitKind -cnotin @('file', 'directory')) { throw "source .git has unsupported occupant kind '$rtDotGitKind'" }
    $rtCandidate = Get-CrgPackageProvenanceCandidate -Root $rtInput
    if ((Get-CrgPathOccupantKind -Path $rtDotGitPath) -cne $rtDotGitKind) { throw 'source .git occupant changed during provenance capture' }
    if ($null -eq $rtCandidate -or $rtCandidate.Head -cne $ApprovedSourceCommit) { throw 'SourceRoot is not the approved source Git root and HEAD' }
  } elseif ($Operation -ceq 'PublishRuntimePackage') {
    if ($ApprovedManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'ApprovedManifestSha256 must be a lowercase SHA-256' }
    $rtInput = Get-CrgRuntimeAbsolutePath -Path $ReleasePackage -Label 'ReleasePackage'
  } elseif ($Operation -cin @('ActivateRuntime', 'InstallRuntimeLauncher', 'UpgradeRuntimeLauncher')) {
    if ($ReleaseId -cnotmatch '\A[0-9a-f]{64}\z') { throw 'ReleaseId must be a lowercase SHA-256' }
    if ((Get-CrgPathOccupantKind -Path $rtStore) -cne 'directory') { throw 'activation or launcher installation requires an existing runtime store' }
  } else { throw 'unknown central runtime operation' }
  if ($null -ne $rtInput -and ((Test-CrgRuntimePathContains -Parent $rtInput -Child $rtStore) -or (Test-CrgRuntimePathContains -Parent $rtStore -Child $rtInput))) { throw 'runtime store must not overlap the publication input' }
  $rtRoots = @([pscustomobject]@{ Path = (Split-Path -Parent $rtStore); Label = 'runtime store parent'; Writable = $true })
  if ($null -ne $rtInput) { $rtRoots += [pscustomobject]@{ Path = $rtInput; Label = 'runtime publication input'; Writable = $false } }
  if ($null -ne $rtCandidate) {
    foreach ($rtGitPath in @($rtCandidate.GitDir, $rtCandidate.CommonDir)) {
      if ((Test-CrgRuntimePathContains -Parent $rtGitPath -Child $rtStore) -or (Test-CrgRuntimePathContains -Parent $rtStore -Child $rtGitPath)) { throw 'runtime store must not overlap source Git metadata' }
      $rtRoots += [pscustomobject]@{ Path = $rtGitPath; Label = 'source Git metadata'; Writable = $false }
    }
  }
  $rtLease = $null; $rtLock = $null; $rtRelease = $null; $rtImported = $null
  $rtOwners = New-Object 'System.Collections.Generic.List[object]'
  $crgBackupStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture) + '-' + [Guid]::NewGuid().ToString('N')
  try {
    $rtLease = Initialize-CrgRootedNamespace -Roots $rtRoots
    $null = Ensure-CrgRootedDirectory -Path $rtStore -Label 'central runtime store'
    $rtLock = Open-CrgTransactionLockNoFollow -Path (Join-Path $rtStore 'runtime.lock') -Name 'central runtime'
    if ($null -eq $rtLock) { throw 'central runtime lock is unavailable' }
    if ($Operation -ceq 'PublishRuntimeSource') {
      # Positive absence is valid for commondir only when no indirection is
      # required.
      if ((Get-CrgPathOccupantKind -Path $rtDotGitPath) -cne $rtDotGitKind) { throw 'source .git occupant changed while namespace custody was acquired' }
      if ($rtDotGitKind -ceq 'file') {
        $rtOwner = Open-CrgGitIndirectionHold -Path $rtDotGitPath -Kind gitdir -RelativeBase $rtInput -ExpectedDirectory $rtCandidate.GitDir
        $rtOwners.Add($rtOwner) | Out-Null
      } elseif (-not [string]::Equals([IO.Path]::GetFullPath($rtDotGitPath).TrimEnd('\', '/'), [IO.Path]::GetFullPath($rtCandidate.GitDir).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source .git directory differs from the captured per-worktree Git directory'
      }
      $rtCommonOwner = Open-CrgGitIndirectionHold -Path (Join-Path $rtCandidate.GitDir 'commondir') -Kind commondir -RelativeBase $rtCandidate.GitDir -ExpectedDirectory $rtCandidate.CommonDir -AllowAbsent
      if ($null -ne $rtCommonOwner) { $rtOwners.Add($rtCommonOwner) | Out-Null }
      elseif (-not [string]::Equals([IO.Path]::GetFullPath($rtCandidate.GitDir).TrimEnd('\', '/'), [IO.Path]::GetFullPath($rtCandidate.CommonDir).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'source Git/common directories differ without a retained commondir indirection'
      }
      $null = Assert-CrgCapturedPackageProvenanceCandidate -Candidate $rtCandidate
      $rtPayloadOwners = New-Object 'System.Collections.Generic.List[object]'
      foreach ($rtPath in (Get-CrgRuntimePayloadPaths)) {
        $null = Enter-CrgRootedExistingDirectory -Path (Split-Path -Parent (Join-Path $rtInput $rtPath)) -Label 'runtime source parent'
        $rtOwner = Open-CrgPackageSourceHold -Path (Join-Path $rtInput $rtPath) -RelativePath $rtPath
        $rtOwners.Add($rtOwner) | Out-Null; $rtPayloadOwners.Add($rtOwner) | Out-Null
      }
      $rtVersionOwner = @($rtPayloadOwners | Where-Object { [string]::Equals($_.RelativePath, 'VERSION', [System.StringComparison]::Ordinal) })[0]
      $rtVersion = Get-CrgPackageVersionFromBytes -Bytes $rtVersionOwner.Bytes
      if ($null -eq $rtVersion) { throw 'source VERSION is not bounded SemVer' }
      $rtSource = Get-CrgHeldPackageProvenance -Candidate $rtCandidate -VersionBytes $rtVersionOwner.Bytes -SourceOwners $rtPayloadOwners.ToArray() -ScratchRoot (Join-Path $rtStore ('.proof-' + [Guid]::NewGuid().ToString('N')))
      if ($rtSource -cne $ApprovedSourceCommit) { throw 'retained runtime bytes do not match the approved source commit' }
      $null = Assert-CrgCapturedPackageProvenanceCandidate -Candidate $rtCandidate
      # Get-CrgRuntimePayloadPaths is the ABI 4 list: it carries none of the
      # hook-mode entries a manifest of an earlier ABI requires, so only ABI 4
      # source is publishable here. An earlier source revision is published
      # with that revision's own bootstrap.
      $rtLauncherSource = @($rtPayloadOwners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [System.StringComparison]::Ordinal) })[0]
      $rtAbi = Get-CrgRuntimeLauncherDeclaredAbi -Bytes $rtLauncherSource.Bytes
      if ($rtAbi -ne 4) { throw "source launcher declares $(if ($rtAbi -eq 0) { 'no launcher ABI' } else { "launcher ABI $rtAbi" }) on its first line; this bootstrap publishes only launcher ABI 4 source, and an earlier source revision is published with that revision's own bootstrap.ps1" }
      $rtLines = @('crg-runtime-manifest v1', "version $rtVersion", "source-commit $rtSource", "launcher-abi $rtAbi", 'config-schema 1')
      foreach ($rtOwner in $rtPayloadOwners) { $rtLines += "file $(Get-CrgSha256HexOfBytes -Bytes $rtOwner.Bytes) $($rtOwner.Bytes.Length) $($rtOwner.RelativePath)" }
      $rtManifest = Read-CrgRuntimeManifestBytes -Bytes ([System.Text.Encoding]::ASCII.GetBytes(($rtLines -join "`n") + "`n"))
      Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $rtManifest.LauncherAbi -Bytes $rtLauncherSource.Bytes
      $rtRelease = Publish-CrgRuntimeSnapshot -Store $rtStore -Manifest $rtManifest -Owners $rtPayloadOwners.ToArray()
    } elseif ($Operation -ceq 'PublishRuntimePackage') {
      $rtImported = Open-CrgRuntimeRelease -Root $rtInput -ExpectedId $ApprovedManifestSha256
      # The manifest reader requires the launcher entry from ABI 4 on; an
      # earlier package without one has no launcher bytes to check.
      $rtImportedLauncher = @($rtImported.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [System.StringComparison]::Ordinal) })
      if ($rtImportedLauncher.Count -eq 1) { Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $rtImported.Manifest.LauncherAbi -Bytes $rtImportedLauncher[0].Bytes }
      $rtRelease = Publish-CrgRuntimeSnapshot -Store $rtStore -Manifest $rtImported.Manifest -Owners $rtImported.Owners.ToArray()
    } else {
      $rtRelease = Open-CrgRuntimeRelease -Root (Join-Path $rtStore "releases/$ReleaseId") -ExpectedId $ReleaseId
      $rtCapabilities = @('scripts/central-launcher.ps1', 'scripts/central-context.psm1', 'scripts/private-governance.psm1')
      if ($rtRelease.Manifest.LauncherAbi -ge 3) { $rtCapabilities += 'scripts/central-transport.psm1' }
      $rtMissingCapabilities = $rtCapabilities | Where-Object {
        $rtRequired = $_
        @($rtRelease.Manifest.Entries | Where-Object { $_.Path -ceq $rtRequired }).Count -ne 1
      }
      if ($Operation -ceq 'UpgradeRuntimeLauncher') {
        if (@($rtMissingCapabilities).Count -gt 0) { throw 'launcher migration target lacks required central entrypoints' }
        Update-CrgRuntimeLauncherAbi -Store $rtStore -Release $rtRelease -Owners $rtOwners
        Install-CrgRuntimeHost -Store $rtStore -Release $rtRelease
        return
      }
      if ($Operation -ceq 'InstallRuntimeLauncher') {
        if ($null -ne (Get-CrgRuntimeLauncherTransition -Store $rtStore -Owners $rtOwners -Install $null -Launcher $null)) {
          throw 'a recorded launcher migration requires UpgradeRuntimeLauncher for retry; a completed migration needs only normal release activation'
        }
        if (@($rtMissingCapabilities).Count -gt 0) { throw "release lacks executable launcher capability: $($rtMissingCapabilities -join ', ')" }
        $rtLauncherOwner = @($rtRelease.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [System.StringComparison]::Ordinal) })[0]
        Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $rtRelease.Manifest.LauncherAbi -Bytes $rtLauncherOwner.Bytes
        $rtLauncherHash = Get-CrgSha256HexOfBytes -Bytes $rtLauncherOwner.Bytes
        $rtInstallBuffers = @(
          [pscustomobject]@{ Name = 'launcher.ps1'; Bytes = [byte[]]$rtLauncherOwner.Bytes; Maximum = 16777216 },
          [pscustomobject]@{ Name = 'launcher-install'; Bytes = (New-CrgRuntimeLauncherBytes -LauncherAbi $rtRelease.Manifest.LauncherAbi -ReleaseId $ReleaseId -Hash $rtLauncherHash); Maximum = 1024 }
        )
        # Existing identical files stay read-held without mutation access, so
        # installation is idempotent while ordinary launcher readers are active.
        $rtExistingInstall = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
        foreach ($rtItem in $rtInstallBuffers) {
          $rtExisting = Open-CrgPackageSourceHold -Path (Join-Path $rtStore $rtItem.Name) -RelativePath $rtItem.Name -MaxLength $rtItem.Maximum -AllowAbsent
          if ($null -ne $rtExisting) {
            $rtOwners.Add($rtExisting) | Out-Null
            if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$rtExisting.Bytes, [byte[]]$rtItem.Bytes)) { throw "stable launcher installation preserves differing '$($rtItem.Name)'" }
            $rtExistingInstall.Add($rtItem.Name, $rtExisting)
          }
        }
        foreach ($rtItem in $rtInstallBuffers) {
          if ($rtExistingInstall.ContainsKey($rtItem.Name)) { continue }
          $rtItemPath = Join-Path $rtStore $rtItem.Name
          $null = Update-CrgRootedFileBytes -Path $rtItemPath -MaxLength $rtItem.Maximum -Label 'stable launcher installation' -Transform {
            param([byte[]]$Previous)
            if (($Previous.Length -gt 0 -or (Get-CrgPathOccupantKind -Path $rtItemPath) -cne 'empty') -and
                -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$Previous, [byte[]]$rtItem.Bytes)) { throw "stable launcher installation preserves differing '$($rtItem.Name)'" }
            return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$rtItem.Bytes }
          }
          $rtInstalled = Open-CrgPackageSourceHold -Path $rtItemPath -RelativePath $rtItem.Name -MaxLength $rtItem.Maximum
          $rtOwners.Add($rtInstalled) | Out-Null
          if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$rtInstalled.Bytes, [byte[]]$rtItem.Bytes)) { throw 'stable launcher installed readback differs from approved release bytes' }
        }
        Write-Host "[bootstrap] stable launcher installed from verified release $ReleaseId; no release activated and no consumer changed."
        Install-CrgRuntimeHost -Store $rtStore -Release $rtRelease
        return
      }
      $rtInstalledFiles = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
      foreach ($rtItem in @('launcher.ps1', 'launcher-install')) {
        $rtExisting = Open-CrgPackageSourceHold -Path (Join-Path $rtStore $rtItem) -RelativePath $rtItem -MaxLength 16777216 -AllowAbsent
        if ($null -ne $rtExisting) { $rtOwners.Add($rtExisting) | Out-Null; $rtInstalledFiles.Add($rtItem, $rtExisting) }
      }
      # A recorded transition admits activation only on its exact predecessor
      # pair, which still executes the releases its own ABI admits, or on its
      # successor. A partial pair refuses until the same migration completes.
      $rtTransition = Get-CrgRuntimeLauncherTransition -Store $rtStore -Owners $rtOwners -Install $rtInstalledFiles['launcher-install'] -Launcher $rtInstalledFiles['launcher.ps1']
      if ($null -ne $rtTransition -and $rtTransition.State -cnotin @('predecessor', 'successor')) {
        if ($rtTransition.State -ceq 'partial') { throw "activation requires completion of the recorded launcher migration to ABI $($rtTransition.LauncherAbi); resume it with -UpgradeRuntimeLauncher -ReleaseId $($rtTransition.Record.ReleaseId)" }
        throw "activation refuses an installed launcher pair or preceding provenance that is neither side of the latest recorded launcher transition (ABI $($rtTransition.LauncherAbi), release $($rtTransition.Record.ReleaseId)); preserve the store and restore its launcher files and records to one side of that transition"
      }
      $rtLauncherPresent = $rtInstalledFiles.Count -gt 0
      if ($rtLauncherPresent) {
        if ($rtInstalledFiles.Count -ne 2) { throw 'activation requires complete launcher installation; resume the explicit install or ABI migration' }
        $rtInstallation = Read-CrgRuntimeLauncherBytes -Bytes $rtInstalledFiles['launcher-install'].Bytes
        $rtLineage = Get-CrgRuntimeLauncherLineage -Store $rtStore -Owners $rtOwners -LauncherAbi $rtInstallation.LauncherAbi -ReleaseId $rtInstallation.ReleaseId -Hash $rtInstallation.Hash
        if ($null -eq $rtLineage -or -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$rtInstalledFiles['launcher-install'].Bytes, [byte[]]$rtLineage)) { throw 'activation refuses launcher provenance that is not the exact record the recorded launcher transitions imply; preserve the store and restore its launcher files and records' }
        Assert-CrgRuntimeLauncherOrigin -Store $rtStore -Installation $rtInstallation -Owners $rtOwners
        if ((Get-CrgSha256HexOfBytes -Bytes $rtInstalledFiles['launcher.ps1'].Bytes) -cne $rtInstallation.Hash) { throw 'activation refuses launcher bytes outside the recorded approved origin; resume an interrupted ABI migration explicitly' }
        Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $rtInstallation.LauncherAbi -Bytes $rtInstalledFiles['launcher.ps1'].Bytes
        if ($rtInstallation.LauncherAbi -lt $rtRelease.Manifest.LauncherAbi) { throw 'installed launcher ABI cannot execute the requested release; run the explicit UpgradeRuntimeLauncher operation first' }
      } elseif ($rtRelease.Manifest.LauncherAbi -ge 2) { throw 'executable central activation requires InstallRuntimeLauncher first' }
      # The selector names, or keeps naming, only a release whose own launcher
      # agrees with its manifest's ABI, whichever bootstrap published it. A
      # release without a launcher payload is foundation data, whose activation
      # the capability checks decide.
      $rtSelectedLauncher = @($rtRelease.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [System.StringComparison]::Ordinal) })
      if ($rtSelectedLauncher.Count -eq 1) { Assert-CrgRuntimeLauncherDeclaration -LauncherAbi $rtRelease.Manifest.LauncherAbi -Bytes $rtSelectedLauncher[0].Bytes }
      [byte[]]$rtDesired = [System.Text.Encoding]::ASCII.GetBytes("crg-runtime-active v1`nrelease $ReleaseId`n")
      $rtUpdate = Update-CrgRootedFileBytes -Path (Join-Path $rtStore 'active-release') -MaxLength 95 -Label 'central active release' -Transform {
        param([byte[]]$Previous)
        # An existing empty file is malformed, not the helper's empty buffer
        # for positive absence. A held prior cannot disappear during this check;
        # a later winner after absence remains protected by no-replace publish.
        $rtPreviousId = $null
        if ($Previous.Length -gt 0 -or (Get-CrgPathOccupantKind -Path (Join-Path $rtStore 'active-release')) -cne 'empty') { $rtPreviousId = Read-CrgRuntimeActiveBytes -Bytes $Previous }
        # ABI 1 foundation-only stores retain their data-selection contract.
        # Once installed, the loader must execute even an unchanged selector;
        # re-affirmation cannot excuse missing execution capabilities.
        if ($rtLauncherPresent -and @($rtMissingCapabilities).Count -gt 0) {
          throw "release lacks executable launcher capability: $($rtMissingCapabilities -join ', ')"
        }
        return [pscustomobject]@{ Ok = $true; Bytes = $rtDesired }
      }
      $rtCurrent = Read-CrgRootedFileBytesExact -Path (Join-Path $rtStore 'active-release') -Label 'central active release' -MaxLength 95
      if ($rtCurrent.State -cne 'held' -or (Read-CrgRuntimeActiveBytes -Bytes $rtCurrent.Bytes) -cne $ReleaseId) { throw 'central active release post-publication readback did not confirm the selected release' }
      if ($null -ne $rtUpdate.PriorRemnant) { Write-Host "[bootstrap] exact prior active-record recovery remains at '$($rtUpdate.PriorRemnant)'." }
    }
    Write-Host "[bootstrap] central runtime $(if ($Operation -ceq 'ActivateRuntime') { 'activated' } else { 'published (not activated)' }): $($rtRelease.Manifest.Id), version $($rtRelease.Manifest.Version), source $($rtRelease.Manifest.Source)."
    Write-Host '[bootstrap] No consumer attachment or dispatcher changed.'
  } finally {
    # After an unconfirmed Git child nothing here is released, and these
    # locals are kept in the list.
    if ($null -ne $script:CrgUncertainGitOwners) {
      Add-CrgUncertainGitOwner -Owner ([pscustomobject]@{ Releases = @($rtRelease, $rtImported); Owners = $rtOwners; Lock = $rtLock; Lease = $rtLease })
      Write-Host "[bootstrap] WARNING: a Git child could not be confirmed ended ($(Get-CrgUncertainGitCause)); the runtime lock, release owners and rooted namespace stay held until this process ends."
    } else {
      foreach ($rtHeldRelease in @($rtRelease, $rtImported)) {
        if ($null -ne $rtHeldRelease) { foreach ($rtOwner in $rtHeldRelease.Owners) { if ($null -ne $rtOwner.Stream) { $rtOwner.Stream.Dispose() } } }
      }
      foreach ($rtOwner in $rtOwners) { if ($null -ne $rtOwner.Stream) { $rtOwner.Stream.Dispose() } }
      if ($null -ne $rtLock) { $rtLock.Dispose() }
      if ($null -ne $rtLease) { Close-CrgRootedNamespace -Lease $rtLease }
    }
  }
}

# Earliest production Git trust boundary, for every parameter set. Git repository
# selectors can redirect every proof (`-C` included) while filesystem writes
# still target the operation's own destination (-RuntimeStore);
# attribute-source overrides can change the clean/eol/filter domain used by
# `check-attr` and filter-aware `hash-object --path`; graft/shallow/replace-base
# overrides can rewrite ancestry and object reads while Git still exits zero;
# config overrides can mask config state inspected after scrubbing.
# Enumerate the process environment and compare actual names ordinal-ignore-case:
# Windows permits casing variants, so case-sensitive named lookups are not a
# complete boundary. Internal isolated-index/attribute values are introduced
# only later, after this clean entry check.
$crgForbiddenGitEnv = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($crgForbiddenGitEnvName in $gitOverrideEnvNames) { [void]$crgForbiddenGitEnv.Add($crgForbiddenGitEnvName) }
$maskingGitOverrideEnv = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
foreach ($crgRawEnvEntry in [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process).GetEnumerator()) {
  $crgRawEnvName = [string]$crgRawEnvEntry.Key
  if ($crgForbiddenGitEnv.Contains($crgRawEnvName)) { $maskingGitOverrideEnv.Add($crgRawEnvName) | Out-Null }
}
$maskingGitOverrideEnv = @($maskingGitOverrideEnv | Sort-Object)
if ($maskingGitOverrideEnv.Count -gt 0) {
  Write-Error "bootstrap.ps1: refusing to run with git-config override env var(s), repository-selector override(s), attribute-resolution override(s), or history-resolution override(s) set: $($maskingGitOverrideEnv -join ', '). These can redirect Git proofs away from the repository being inspected or alter the config, attribute, object, or ancestry domain used for trusted identity checks. Unset every named variable and re-run -- PowerShell: Remove-Item Env:<NAME>; bash: unset <NAME>. Nothing has been modified: no repository, source, or runtime store was touched."
  exit 1
}
try {
  Set-CrgNoReplaceObjectsProcessSingleton
} catch {
  Write-Error "bootstrap.ps1: could not establish exactly one canonical GIT_NO_REPLACE_OBJECTS=1 entry before the first Git proof ($($_.Exception.Message)). Nothing has been modified: no repository, source, or runtime store was touched."
  exit 1
}

try { Invoke-CrgCentralRuntimeOperation -Operation $PSCmdlet.ParameterSetName }
catch { Write-Error "bootstrap.ps1: central runtime operation refused: $($_.Exception.Message)"; exit 1 }
exit 0
