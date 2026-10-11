# bootstrap.ps1 - install cross-review-gate into a target git repo.
#
# Installs the gate file set (the $fileList table below is the
# authoritative inventory; README.md and INSTALL.md carry the
# operator-facing enumeration), ignores the gate's generated artifacts by
# appending `logs/` to the target's root .gitignore -- or to the git
# common dir's info/exclude when the gate hook path is already ignored
# (the LOCAL install shape, docs/local-install-v1.md); each append is
# idempotent -- then
# installs a per-clone dispatcher at .git/hooks/pre-commit (NOT
# `git config core.hooksPath` -- the dispatcher closes a `git rm gate`
# bypass that a versioned core.hooksPath install would leave open).
# Prints a customization checklist of remaining manual steps.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -TargetRepo <path-to-repo>
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -TargetRepo <path-to-repo> -DispatcherOnly
#   powershell -NoProfile -ExecutionPolicy Bypass -File bootstrap.ps1 -TargetRepo <path-to-repo> -RestoreLegacyRoutingCustody
#
# By default, refuses to overwrite existing files in the target tree.
# Use -Force to overwrite (useful when upgrading to a new package
# version).

[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
  [string]$TargetRepo,

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
  [string]$ReleaseId,

  [Parameter(ParameterSetName = 'Install')]
  [switch]$Force,

  # Install/refresh ONLY the per-clone dispatcher at .git/hooks/pre-commit;
  # touch NO tracked file. This is the named remedy for a legacy, absent, or
  # stale dispatcher: an existing clone needs its dispatcher upgraded to the
  # current non-blocking review-context behavior and gate-untracking guard. A
  # pre-redesign dispatcher may still carry retired PROJECT-MODE enforcement
  # even when a generic guard marker is present. A fresh clone of an ALREADY-installed
  # TRACKED-shape repo has no dispatcher at all (per-clone files do not
  # clone; a fresh LOCAL-shape clone instead needs a full bootstrap --
  # it has neither gate files nor a per-worktree manifest, and the
  # dispatcher alone would refuse every commit). A bare
  # -Force re-run would replace every generated render destination and other
  # package payload -- the broad mutation shape this switch exists to avoid.
  # Implies overwriting an
  # existing dispatcher (that is its purpose), so -Force is not required.
  [Parameter(ParameterSetName = 'Install')]
  [switch]$DispatcherOnly,

  # Rewrite the install manifest from one exact admitted LOCAL inventory and
  # refresh the epoch-bound local-shape authorization marker beside it, copying
  # no gate file and touching no tracked file (the superseded manifest is held
  # under an exact no-replace recovery name). This is a bounded operator-only
  # recovery act for an eligible metadata-free or deliberately changed current
  # v2.1 inventory, or an admitted frozen legacy inventory. The published
  # baseline is transient replacement authority only: after removing the
  # sanction, immediately run the full package bootstrap with -Force and the
  # installed renderer with -Check. Never commit or merge directly against the
  # sealed drift. Runs the same custody channel as the install (the operator
  # invoking bootstrap against machine state under .git).
  [Parameter(ParameterSetName = 'Install')]
  [switch]$SealManifest,

  # Durable self-host interruption recovery after the bounded legacy kernel
  # landing. Reads the base-bound active custody record from this worktree's
  # git dir, proves every driver still has its recorded phase-A state, then
  # restores and re-hashes only the recorded routing drivers. Copies no package
  # payload and publishes no install/transition metadata.
  [Parameter(ParameterSetName = 'Install')]
  [switch]$RestoreLegacyRoutingCustody
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

# Git prints paths and reference names in UTF-8, unquoted, so a capture whose
# output is such an identifier (a path from rev-parse or core.hooksPath, a
# reference from symbolic-ref) goes through this helper, which reads Git's
# stdout as bytes and decodes them as UTF-8 itself. Other captures print
# hashes or ASCII keywords, are read only for their exit code or emptiness,
# or list paths that are only compared with the gate's fixed ASCII paths,
# which a misdecoded non-ASCII name cannot equal. The rows are split as
# PowerShell splits native output, and the exit code lands in $LASTEXITCODE.
# Any stderr output is raised, as Windows PowerShell raises native stderr
# under this script's Stop preference; every caller that catches it turns it
# into a refusal or an indeterminate result, never an absence. Git runs from
# PowerShell's current location, resolved like `& git`, never from a git.exe
# in that folder. Tried and dropped (staged review, 2026-10-10): decoding
# through PowerShell's native-output reader after setting
# [Console]::OutputEncoding to UTF-8 for the call, which also sets the output
# code page of the console window bootstrap shares with the invoking shell,
# so a run killed between the switch and its restore left that console on
# UTF-8; setting the code pages for the whole run with a PowerShell.Exiting
# restore (it runs only when the engine exits and loses its failures in the
# event job); ending the run here with exit 1, which skipped the custody
# restoration of a gate file moved aside during install.
function Invoke-CrgGitUtf8 {
  param([string[]]$GitArgs)
  $guLocation = (Get-Location).ProviderPath
  if ([string]::IsNullOrWhiteSpace($guLocation)) { throw 'the current PowerShell location has no filesystem path to run Git from' }
  $guPsi = New-Object System.Diagnostics.ProcessStartInfo
  $guPsi.FileName = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
  $guPsi.Arguments = ((@($GitArgs) | ForEach-Object { Convert-CrgWindowsProcessArgument -Argument $_ }) -join ' ')
  $guPsi.WorkingDirectory = $guLocation
  $guPsi.UseShellExecute = $false
  $guPsi.RedirectStandardOutput = $true
  $guPsi.RedirectStandardError = $true
  $guPsi.CreateNoWindow = $true
  Initialize-CrgBoundedSinkNative
  $guErrors = New-Object CrgBoundedCapture.SinkV1 ([long]65536)
  $guProc = [System.Diagnostics.Process]::Start($guPsi)
  try {
    $guErrCopy = $guProc.StandardError.BaseStream.CopyToAsync($guErrors)
    # These captures print one identifier, so output past the bound is
    # refused; reading stops keeping bytes there and the child is stopped.
    $guBuffer = New-Object byte[] 8192
    $guKept = New-Object System.IO.MemoryStream
    $guExceeded = $false
    while (($guRead = $guProc.StandardOutput.BaseStream.Read($guBuffer, 0, $guBuffer.Length)) -gt 0) {
      if (-not $guExceeded -and ($guKept.Length + $guRead) -gt 1048576) {
        $guExceeded = $true
        try { $guProc.Kill() } catch { }
      }
      if (-not $guExceeded) { $guKept.Write($guBuffer, 0, $guRead) }
    }
    $guProc.WaitForExit()
    $null = $guErrCopy.GetAwaiter().GetResult()
    if ($guExceeded) { throw "git $($GitArgs -join ' ') printed more than the 1048576-byte identifier-capture bound" }
    if ($guErrors.Exceeded) { throw "git $($GitArgs -join ' ') wrote more than the 65536-byte stderr capture bound (exit $($guProc.ExitCode))" }
    $guOut = [System.Text.UTF8Encoding]::new($false).GetString($guKept.ToArray())
    $guErr = [System.Text.UTF8Encoding]::new($false).GetString($guErrors.ToArray())
    $global:LASTEXITCODE = $guProc.ExitCode
  } finally {
    # A failure above can leave the child running; its exit is confirmed
    # before disposal, as in Invoke-CrgIsolatedGitProcess.
    if (-not $guProc.HasExited) {
      try { $guProc.Kill() } catch { }
      try { $guProc.StandardOutput.BaseStream.CopyTo([System.IO.Stream]::Null) } catch { }
      $guProc.WaitForExit()
    }
    $guProc.Dispose()
  }
  if ($guErr.Length -gt 0) { throw "git $($GitArgs -join ' ') wrote to stderr (exit $($global:LASTEXITCODE)): $($guErr.Trim())" }
  $guReader = New-Object System.IO.StringReader($guOut)
  while ($null -ne ($guLine = $guReader.ReadLine())) { $guLine }
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

# Classify the `git config --get core.hooksPath` exit status. BYTE-IDENTICAL to
# the copy in scripts/claude/commit.ps1, the shared commit wrapper (there is no
# shared module to import, so the classifier is kept identical by hand) so the
# INSTALLER and the commit WRAPPER agree on what "set" means: exit 1 = key
# ABSENT (the required UNSET state) -> 'proceed'; exit 0 = key SET to ANY value
# INCLUDING an empty `core.hooksPath=` -> 'abort-set'; anything else = git error
# -> 'abort-indeterminate' (fail closed). Without this shared classification the
# installer could report success under a set-empty or config-error state that the
# wrappers then abort on -- an install that cannot use the documented wrappers.
function Resolve-HooksPathGuard {
  param([int]$ExitCode)
  if ($ExitCode -eq 1) { return 'proceed' }
  if ($ExitCode -eq 0) { return 'abort-set' }
  return 'abort-indeterminate'
}
# === CRG-INSTALL-VALUES-CORE-BEGIN v1 ===
# The marked region is byte-buffer-only and shared with bootstrap and project preparation.
$script:CrgUtf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
$script:CrgUtf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Compare-CrgInstallValueBytes {
  param([AllowNull()][AllowEmptyCollection()][byte[]]$Left, [AllowNull()][AllowEmptyCollection()][byte[]]$Right)
  if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
  for ($i = 0; $i -lt $Left.Length; $i++) { if ($Left[$i] -ne $Right[$i]) { return $false } }
  return $true
}

function Copy-CrgInstallValueByteRange {
  param([byte[]]$Bytes, [int]$Offset, [int]$Count)
  if ($null -eq $Bytes -or $Offset -lt 0 -or $Count -lt 0 -or $Offset + $Count -gt $Bytes.Length) {
    throw [System.ArgumentOutOfRangeException]::new('Count', 'invalid byte range')
  }
  $result = New-Object byte[] $Count
  if ($Count -gt 0) { [System.Array]::Copy($Bytes, $Offset, $result, 0, $Count) }
  return ,([byte[]]$result)
}

function Read-CrgInstallValueRecords {
  param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [int]$MaxBytes, [string]$Label)
  if ($Bytes.Length -eq 0 -or $Bytes.Length -gt $MaxBytes) { throw "$Label must contain 1 through $MaxBytes bytes" }
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { throw "$Label has a UTF-8 BOM" }
  if ($Bytes[$Bytes.Length - 1] -ne 0x0A) { throw "$Label must end with LF" }
  foreach ($value in $Bytes) {
    if ($value -eq 0x0D) { throw "$Label contains CR" }
    if (($value -lt 0x20 -and $value -ne 0x09 -and $value -ne 0x0A) -or $value -eq 0x7F) { throw "$Label contains a prohibited control byte" }
  }
  try { $null = $script:CrgUtf8Strict.GetString($Bytes) }
  catch { throw "$Label is not strict UTF-8 without a BOM" }

  $records = New-Object 'System.Collections.Generic.List[object]'
  $start = 0
  for ($i = 0; $i -lt $Bytes.Length; $i++) {
    if ($Bytes[$i] -ne 0x0A) { continue }
    [byte[]]$lineBytes = Copy-CrgInstallValueByteRange -Bytes $Bytes -Offset $start -Count ($i - $start)
    try { $lineText = $script:CrgUtf8Strict.GetString($lineBytes) }
    catch { throw "$Label contains an invalid UTF-8 record" }
    $records.Add([pscustomobject]@{ Start = $start; Length = $i - $start; EndExclusive = $i + 1; Text = $lineText }) | Out-Null
    $start = $i + 1
  }
  return $records.ToArray()
}

function Assert-CrgScopedAuthorityBody {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  $sentinel = $script:CrgUtf8NoBom.GetBytes("- No authority documents. SCOPED capture is dormant.`n")
  if (Compare-CrgInstallValueBytes -Left $Bytes -Right $sentinel) { return }
  $records = Read-CrgInstallValueRecords -Bytes $Bytes -MaxBytes 65536 -Label 'scoped-authority body'
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($record in $records) {
    $text = [string]$record.Text
    if ($text.Length -lt 5 -or -not $text.StartsWith('- `', [System.StringComparison]::Ordinal) -or -not $text.EndsWith('`', [System.StringComparison]::Ordinal)) {
      throw 'scoped-authority records must use the exact - `path` grammar'
    }
    $path = $text.Substring(3, $text.Length - 4)
    if ([string]::IsNullOrEmpty($path) -or $path.StartsWith('/', [System.StringComparison]::Ordinal) -or $path.EndsWith('/', [System.StringComparison]::Ordinal) -or
        $path.IndexOf([char]'\') -ge 0 -or $path.IndexOf([char]'`') -ge 0) { throw "scoped-authority path '$path' is not canonical" }
    foreach ($character in $path.ToCharArray()) {
      if ([int][char]$character -lt 0x20 -or [int][char]$character -eq 0x7F) { throw 'scoped-authority path contains a control character' }
    }
    foreach ($segment in @($path -split '/', 0)) {
      if ([string]::IsNullOrEmpty($segment) -or [string]::Equals($segment, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($segment, '..', [System.StringComparison]::Ordinal)) { throw "scoped-authority path '$path' has a noncanonical segment" }
    }
    if (-not $seen.Add($path)) { throw "scoped-authority path '$path' is duplicated" }
  }
}

function Read-CrgInstallValuesBytes {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  $records = Read-CrgInstallValueRecords -Bytes $Bytes -MaxBytes 262144 -Label 'CROSS-REVIEW-VALUES.md'
  if ($records.Count -eq 0 -or -not [string]::Equals($records[0].Text, 'cross-review-values v1', [System.StringComparison]::Ordinal)) { throw 'CROSS-REVIEW-VALUES.md has an invalid header' }
  $names = @('project-context', 'project-hazards', 'scoped-authority')
  $blocks = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
  $cursor = 1
  foreach ($name in $names) {
    $open = "<!-- crg-install-value v1 $name BEGIN -->"
    $close = "<!-- crg-install-value v1 $name END -->"
    if ($cursor -ge $records.Count -or -not [string]::Equals($records[$cursor].Text, $open, [System.StringComparison]::Ordinal)) { throw "CROSS-REVIEW-VALUES.md is missing the ordered $name opening marker" }
    $bodyStart = $records[$cursor].EndExclusive
    $cursor++
    $closeRecord = $null
    while ($cursor -lt $records.Count) {
      $recordText = [string]$records[$cursor].Text
      if ([string]::Equals($recordText, $close, [System.StringComparison]::Ordinal)) { $closeRecord = $records[$cursor]; break }
      if ($recordText.StartsWith('<!-- crg-install-value v1 ', [System.StringComparison]::Ordinal) -or
          $recordText.StartsWith('<!-- crg-render-slot v1 ', [System.StringComparison]::Ordinal)) {
        throw "CROSS-REVIEW-VALUES.md contains a structural marker inside $name"
      }
      $cursor++
    }
    if ($null -eq $closeRecord) { throw "CROSS-REVIEW-VALUES.md is missing the $name closing marker" }
    [byte[]]$body = Copy-CrgInstallValueByteRange -Bytes $Bytes -Offset $bodyStart -Count ($closeRecord.Start - $bodyStart)
    if ($body.Length -gt 65536) { throw "$name exceeds 65536 bytes" }
    $hasContent = $false
    foreach ($value in $body) { if ($value -ne 0x20 -and $value -ne 0x09 -and $value -ne 0x0A) { $hasContent = $true; break } }
    if (-not $hasContent) { throw "$name must contain a non-whitespace character" }
    if ($name -ceq 'scoped-authority') { Assert-CrgScopedAuthorityBody -Bytes $body }
    $blocks[$name] = $body
    $cursor++
  }
  if ($cursor -ne $records.Count) { throw 'CROSS-REVIEW-VALUES.md contains bytes outside the three ordered frames' }
  return [pscustomobject]@{ Bytes = $Bytes; Blocks = $blocks }
}

function Assert-CrgNoReservedProjectPlaceholder {
  param(
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][string]$Label
  )
  for ($i = 0; $i -le $Bytes.Length - 9; $i++) {
    $word = @(0x52,0x45,0x50,0x4C,0x41,0x43,0x45)
    $matches = $true
    for ($j = 0; $j -lt $word.Count; $j++) {
      $actual = $Bytes[$i + $j]
      if ($actual -ge 0x61 -and $actual -le 0x7A) { $actual = $actual - 0x20 }
      if ($actual -ne $word[$j]) { $matches = $false; break }
    }
    if (-not $matches) { continue }
    $at = $i + 7
    $separatorCount = 0
    while ($at -lt $Bytes.Length -and $Bytes[$at] -in @(0x20, 0x2D, 0x5F)) { $separatorCount++; $at++ }
    if ($separatorCount -eq 0 -or $at + 1 -ge $Bytes.Length) { continue }
    $m = $Bytes[$at]; $e = $Bytes[$at + 1]
    if ($m -ge 0x61 -and $m -le 0x7A) { $m = $m - 0x20 }
    if ($e -ge 0x61 -and $e -le 0x7A) { $e = $e - 0x20 }
    if ($m -eq 0x4D -and $e -eq 0x45) { throw "$Label contains an unresolved project placeholder" }
  }
}

function Get-CrgRenderSlotLayout {
  param(
    [Parameter(Mandatory = $true)][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:review-prompt|agents-template)\z', Options = 'None')][string]$Target,
    [switch]$FinalOutput
  )
  $records = Read-CrgInstallValueRecords -Bytes $Bytes -MaxBytes 1048576 -Label $Target
  $required = if ([string]::Equals($Target, 'review-prompt', [System.StringComparison]::Ordinal)) { @('project-context', 'project-hazards', 'scoped-authority') } else { @('scoped-authority') }
  $allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($name in $required) { $null = $allowed.Add($name) }
  $found = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
  $active = $null
  foreach ($record in $records) {
    $text = [string]$record.Text
    if ($text.StartsWith('<!-- crg-install-value v1 ', [System.StringComparison]::Ordinal)) { throw "$Target contains a source-frame marker" }
    if (-not $text.StartsWith('<!-- crg-render-slot v1 ', [System.StringComparison]::Ordinal)) { continue }
    if ($text -cnotmatch '^<!-- crg-render-slot v1 ([a-z-]+) (BEGIN|END) -->$') { throw "$Target contains an unknown render-slot marker" }
    $name = [string]$Matches[1]
    $kind = [string]$Matches[2]
    if (-not $allowed.Contains($name)) { throw "$Target contains undeclared render slot '$name'" }
    if ($kind -ceq 'BEGIN') {
      if ($null -ne $active) { throw "$Target contains nested render slots" }
      if ($found.Contains($name)) { throw "$Target duplicates render slot '$name'" }
      $active = [pscustomobject]@{ Name = $name; Open = $record }
    } else {
      if ($null -eq $active -or $active.Name -cne $name) { throw "$Target contains an orphan or mismatched closing marker for '$name'" }
      $bodyStart = $active.Open.EndExclusive
      [byte[]]$body = Copy-CrgInstallValueByteRange -Bytes $Bytes -Offset $bodyStart -Count ($record.Start - $bodyStart)
      $found[$name] = [pscustomobject]@{ Name = $name; Open = $active.Open; Close = $record; Body = $body }
      $active = $null
    }
  }
  if ($null -ne $active) { throw "$Target has an unclosed render slot '$($active.Name)'" }
  foreach ($name in $required) { if (-not $found.Contains($name)) { throw "$Target is missing render slot '$name'" } }
  if ($found.Count -ne $required.Count) { throw "$Target has an invalid render-slot set" }

  if ($FinalOutput) { Assert-CrgNoReservedProjectPlaceholder -Bytes $Bytes -Label $Target }
  return [pscustomobject]@{ Bytes = $Bytes; Target = $Target; Required = $required; Slots = $found }
}

function Invoke-CrgInstallValueRender {
  param(
    [Parameter(Mandatory = $true)][object]$Values,
    [Parameter(Mandatory = $true)][byte[]]$TemplateBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:review-prompt|agents-template)\z', Options = 'None')][string]$Target
  )
  if ($null -eq $Values.Blocks) { throw 'renderer received no parsed values blocks' }
  $layout = Get-CrgRenderSlotLayout -Bytes $TemplateBytes -Target $Target
  $ordered = @($layout.Slots.Values | Sort-Object { $_.Open.Start })
  $stream = New-Object System.IO.MemoryStream
  try {
    $cursor = 0
    foreach ($slot in $ordered) {
      $prefixLength = $slot.Open.EndExclusive - $cursor
      if ($prefixLength -gt 0) { $stream.Write($TemplateBytes, $cursor, $prefixLength) }
      [byte[]]$body = $Values.Blocks[$slot.Name]
      if ($null -eq $body) { throw "renderer received no value for slot '$($slot.Name)'" }
      if ($body.Length -gt 0) { $stream.Write($body, 0, $body.Length) }
      $cursor = $slot.Close.Start
    }
    if ($cursor -lt $TemplateBytes.Length) { $stream.Write($TemplateBytes, $cursor, $TemplateBytes.Length - $cursor) }
    if ($stream.Length -gt 1048576) { throw "$Target rendered output exceeds 1048576 bytes" }
    [byte[]]$result = $stream.ToArray()
  } finally { $stream.Dispose() }

  $final = Get-CrgRenderSlotLayout -Bytes $result -Target $Target -FinalOutput
  foreach ($name in $final.Required) {
    if (-not (Compare-CrgInstallValueBytes -Left $final.Slots[$name].Body -Right $Values.Blocks[$name])) {
      throw "$Target rendered slot '$name' does not equal the selected value bytes"
    }
  }
  return ,([byte[]]$result)
}
# === CRG-INSTALL-VALUES-CORE-END v1 ===

function Assert-CrgInstallValuesAuditSurface {
  param([byte[]]$Bytes, [string]$Label = 'audit protocol')

  if ($null -eq $Bytes -or $Bytes.Length -lt 1 -or $Bytes.Length -gt 1048576) {
    throw "$Label must contain 1 through 1048576 retained raw bytes"
  }
  $crgAuditHazardsHeading = '## Project hazards that have repeatedly affected this codebase'
  $crgAuditDormancySentinel = '- No authority documents. SCOPED capture is dormant.'
  if (-not (Test-CrgInstallValueByteSequence -Bytes $Bytes -Needle ($script:CrgUtf8NoBom.GetBytes($crgAuditHazardsHeading)))) {
    throw "$Label does not contain the exact fixed project-hazards heading '$crgAuditHazardsHeading'"
  }
  if (-not (Test-CrgInstallValueByteSequence -Bytes $Bytes -Needle ($script:CrgUtf8NoBom.GetBytes($crgAuditDormancySentinel)))) {
    throw "$Label does not contain the exact SCOPED dormancy sentinel '$crgAuditDormancySentinel'"
  }
  Assert-CrgNoReservedProjectPlaceholder -Bytes $Bytes -Label $Label
}

# ---- local-install manifest machinery (docs/local-install-v1.md) ----
function Get-CrgSha256Hex {
  param([string]$Path)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $fs = [System.IO.File]::OpenRead($Path)
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() }
    finally { $fs.Dispose() }
  } finally { $sha.Dispose() }
}
function Get-CrgGitCommonDir {
  param([string]$RepoRoot)
  # try/catch so the $null contract holds: Invoke-CrgGitUtf8 raises on any
  # Git stderr, a failed launch or an exceeded capture bound, which would
  # otherwise end the caller instead of reaching the $null it diagnoses.
  try { $raw = (Invoke-CrgGitUtf8 -GitArgs @('-C', $RepoRoot, 'rev-parse', '--git-common-dir')) } catch { return $null }
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace("$raw")) { return $null }
  $p = "$raw".Trim()
  if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $RepoRoot $p }
  return $p
}
# Per-WORKTREE git dir (docs/local-install-v1.md section 2): the
# install manifest lives here, NOT in the common dir -- the verified
# gate files are worktree-local, so a shared manifest would let one
# worktree's reseal or refresh silently invalidate every sibling
# worktree's baseline.
function Get-CrgGitDir {
  param([string]$RepoRoot)
  try { $raw = (Invoke-CrgGitUtf8 -GitArgs @('-C', $RepoRoot, 'rev-parse', '--absolute-git-dir')) } catch { return $null }
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace("$raw")) { return $null }
  return "$raw".Trim()
}
# Parse a v1 manifest into @{repo-relative-path -> sha256-hex}. The
# grammar is LF-only: ANY CR byte anywhere, an unknown leading version
# line, or an unreadable file answers $null -- callers treat that as
# ABSENT and fail toward the backup/refusal paths, never toward parsing
# by guess. Byte-level so the accept set matches the sh readers exactly
# (a line-splitting API would silently launder a CRLF manifest that the
# sh side refuses).
function Read-CrgInstallManifestBytes {
  param([byte[]]$Bytes)
  $manifestBytes = $Bytes
  if ($null -eq $manifestBytes -or $manifestBytes.Length -eq 0 -or $manifestBytes.Length -gt 1048576) { return $null }
  # Byte domain: printable ASCII (0x20-0x7E) plus LF only, enforced on
  # RAW BYTES before any decode -- PowerShell's UTF-8 decode substitutes
  # U+FFFD for invalid sequences, so two distinct invalid byte paths
  # could collapse to one string here while the raw-byte sh readers keep
  # them distinct, splitting the accept set. CR sits outside the domain,
  # so the LF-only rule rides on the same check.
  foreach ($mb in $manifestBytes) { if (-not (($mb -eq 0x0A) -or ($mb -ge 0x20 -and $mb -le 0x7E))) { return $null } }
  $manifestLines = ([System.Text.Encoding]::UTF8.GetString($manifestBytes)) -split "`n"
  # ORDINAL string operations only: PowerShell's -ceq/-cne are
  # culture-sensitive (a culture-ignorable char like U+00AD compares
  # equal to its absence), which would accept headers and paths the
  # LC_ALL=C sh readers refuse.
  # BOTH VERSIONS ARE ACCEPTED, and they mean the same thing to a reader: the
  # digest of the INSTALLED file. They differ only in whether that file carries
  # a provenance line, which v2 installs stamp and v1 installs do not -- so a
  # reader hashes the file on disk either way. Accepting v1 preserves the
  # pre-stamp manifest format used during P9 development; released v1.7 wrote no
  # manifest and is recognized separately by its frozen inventory. The current
  # writer only emits v2.
  if ($manifestLines.Count -lt 3 -or -not ([string]::Equals($manifestLines[0], 'crg-install-manifest v1', [System.StringComparison]::Ordinal) -or [string]::Equals($manifestLines[0], 'crg-install-manifest v2', [System.StringComparison]::Ordinal))) { return $null }
  if ($manifestLines[1] -cnotmatch '^installed: [0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$') { return $null }
  # STRICT whole-file grammar, kept IDENTICAL to the sh readers
  # (crg_local_manifest_want): every entry line is exactly
  # <64-hex><two spaces><path not starting with a space>; any junk line,
  # any duplicate path, or a missing `installed: ` record refuses the
  # WHOLE manifest. A tolerant reader here would accept a manifest a
  # stricter stage later refuses, splitting one trust decision in two.
  # ORDINAL comparer: a literal @{} compares keys case-insensitively,
  # which would call `a/b` and `A/b` duplicates while awk's seen[]
  # under LC_ALL=C keeps them distinct -- paths compare byte-exact in
  # every runtime.
  $map = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  for ($mi = 2; $mi -lt $manifestLines.Count; $mi++) {
    $ln = $manifestLines[$mi]
    if ($ln.Length -eq 0 -and $mi -eq $manifestLines.Count - 1) { continue }
    if ($ln -cnotmatch '^([0-9a-f]{64})  ([^ ].*)$') { return $null }
    if ($map.ContainsKey($Matches[2])) { return $null }
    $map[$Matches[2]] = $Matches[1]
  }
  return $map
}

function Read-CrgInstallManifest {
  param([string]$ManifestPath)
  if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $null }
  try { $manifestBytes = [System.IO.File]::ReadAllBytes($ManifestPath) } catch { return $null }
  return (Read-CrgInstallManifestBytes -Bytes $manifestBytes)
}

function Open-CrgInstallManifestOwner {
  param([string]$ManifestPath, [switch]$RequireStrict)

  $omHandle = $null
  $omStream = $null
  $omErr = 0
  try {
    $omHandle = [CrgBootstrap.NativeV4]::OpenOwnedExistingFileNoFollow($ManifestPath, [ref]$omErr)
    if ($null -eq $omHandle -or $omHandle.IsInvalid) { throw "no-follow manifest owner open refused (Win32 error $omErr)" }
    $omAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($omHandle)
    if ($omAttrs -lt 0 -or ($omAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($omHandle) -ne 1) { throw 'the manifest is not one ordinary single-link file' }
    $omStream = New-Object System.IO.FileStream($omHandle, [System.IO.FileAccess]::Read)
    $omHandle = $null
    if ($omStream.Length -gt 1048576 -or ($RequireStrict -and $omStream.Length -le 0)) { throw 'the manifest exceeds the bounded grammar' }
    $omBytes = New-Object byte[] ([int]$omStream.Length)
    $omRead = 0
    while ($omRead -lt $omBytes.Length) {
      $omGot = $omStream.Read($omBytes, $omRead, $omBytes.Length - $omRead)
      if ($omGot -le 0) { break }
      $omRead += $omGot
    }
    $omStream.Position = 0
    if ($omRead -ne $omBytes.Length) { throw 'the held manifest could not be read exactly' }
    $omMap = Read-CrgInstallManifestBytes -Bytes $omBytes
    if ($RequireStrict -and $null -eq $omMap) { throw 'the held manifest does not satisfy the strict grammar' }
    $omResult = [pscustomobject]@{ Path = $ManifestPath; Stream = $omStream; Map = $omMap; Bytes = $omBytes }
    $omStream = $null
    return $omResult
  } finally {
    if ($null -ne $omStream) { $omStream.Dispose() }
    elseif ($null -ne $omHandle -and -not $omHandle.IsInvalid) { $omHandle.Dispose() }
  }
}

function Open-CrgBoundedOwnerFileNoFollow {
  param([string]$Path, [int]$MaxLength, [string]$Label, [switch]$Writable)

  $obHandle = $null
  $obStream = $null
  $obErr = 0
  try {
    $obHandle = if ($Writable) { [CrgBootstrap.NativeV4]::OpenOwnedExistingReadWriteNoFollow($Path, [ref]$obErr) } else { [CrgBootstrap.NativeV4]::OpenOwnedExistingFileNoFollow($Path, [ref]$obErr) }
    if ($null -eq $obHandle -or $obHandle.IsInvalid) { throw "no-follow owner open refused (Win32 error $obErr)" }
    $obAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($obHandle)
    if ($obAttrs -lt 0 -or ($obAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($obHandle) -ne 1) { throw "$Label is not one ordinary single-link file" }
    $obStream = New-Object System.IO.FileStream($obHandle, $(if ($Writable) { [System.IO.FileAccess]::ReadWrite } else { [System.IO.FileAccess]::Read }))
    $obHandle = $null
    if ($obStream.Length -gt $MaxLength) { throw "$Label exceeds its $MaxLength-byte bound" }
    $obBytes = New-Object byte[] ([int]$obStream.Length)
    $obRead = 0
    while ($obRead -lt $obBytes.Length) {
      $obGot = $obStream.Read($obBytes, $obRead, $obBytes.Length - $obRead)
      if ($obGot -le 0) { break }
      $obRead += $obGot
    }
    $obStream.Position = 0
    if ($obRead -ne $obBytes.Length) { throw "$Label could not be read exactly through its held object" }
    $obResult = [pscustomobject]@{ Path = $Path; Stream = $obStream; Bytes = $obBytes }
    $obStream = $null
    return $obResult
  } finally {
    if ($null -ne $obStream) { $obStream.Dispose() }
    elseif ($null -ne $obHandle -and -not $obHandle.IsInvalid) { $obHandle.Dispose() }
  }
}

# Tri-state check-ignore probe: 'ignored', 'exposed', or 'error:<code>'
# for a failed probe. Callers must never fold a failure into either
# shape answer -- an indeterminate probe routing the logs/ rule or the
# checklist shape would act on a guess.
function Get-CrgCheckIgnoreState {
  param([string]$Repo, [string]$Path)
  # The probe ANSWERS, never throws: under EAP=Stop a native stderr
  # line through a redirection becomes a terminating error (git prints
  # a fatal: line for an unreachable repo), which would crash the
  # caller instead of reaching its error branch.
  try {
    & git -C $Repo check-ignore -q -- $Path 2>$null
  } catch {
    return 'error:threw'
  }
  if ($LASTEXITCODE -eq 0) { return 'ignored' }
  if ($LASTEXITCODE -eq 1) { return 'exposed' }
  return "error:$LASTEXITCODE"
}

# Index membership, answered per PATH. Pairs with Get-CrgCheckIgnoreState
# wherever a staging decision is made: ignore rules do not apply to a
# tracked path, so "ignored" alone never justifies dropping one.
function Get-CrgTrackedState {
  param([string]$Repo, [string]$Path)
  # Same ANSWERS-never-throws contract as the ignore probe above.
  try {
    $crgTsOut = & git -C $Repo ls-files --cached -- $Path 2>$null
  } catch {
    return 'error:threw'
  }
  if ($LASTEXITCODE -ne 0) { return "error:$LASTEXITCODE" }
  if ([string]::IsNullOrWhiteSpace(($crgTsOut -join ''))) { return 'untracked' }
  return 'tracked'
}

# The package inventory has deliberately separate current and frozen authorities:
#
# * Get-CrgCurrentFileList is the complete payload shipped by THIS package.
# * Get-CrgSealRecoveryFileList preserves historical LOCAL recovery identities
#   independently of delivery, including retired paths that are never copied.
# * Get-CrgLegacyV170Paths is the frozen release payload shipped by release
#   v1.7.0 at commit 3a3efbf. That release predates install metadata, so its
#   complete on-disk inventory is the only positive evidence available during
#   the supported v1.7 -> v2 upgrade. Never derive the legacy set by subtracting
#   today's additions: doing so would silently rewrite history whenever a later
#   release adds or removes another component.
function Get-CrgCurrentFileList {
  return @(
    @{ Src = 'scripts/codex/auto-review.ps1';            Dst = 'scripts/codex/auto-review.ps1' },
    @{ Src = 'scripts/codex/auto-merge.ps1';             Dst = 'scripts/codex/auto-merge.ps1' },
    @{ Src = 'scripts/shared/auto-merge.ps1';            Dst = 'scripts/shared/auto-merge.ps1' },
    @{ Src = 'scripts/codex/commit.ps1';                 Dst = 'scripts/codex/commit.ps1' },
    @{ Src = 'scripts/shared/analyze-blocker-trends.ps1'; Dst = 'scripts/shared/analyze-blocker-trends.ps1' },
    @{ Src = 'scripts/shared/author-lint.ps1';            Dst = 'scripts/shared/author-lint.ps1' },
    @{ Src = 'scripts/shared/dispatch-checklist.ps1';     Dst = 'scripts/shared/dispatch-checklist.ps1' },
    @{ Src = 'scripts/shared/worker-audit.ps1';           Dst = 'scripts/shared/worker-audit.ps1' },
    @{ Src = 'scripts/codex/review-prompt-template.md';  Dst = 'scripts/codex/review-prompt-template.md' },
    @{ Src = 'scripts/claude/auto-review.ps1';           Dst = 'scripts/claude/auto-review.ps1' },
    @{ Src = 'scripts/claude/commit.ps1';                Dst = 'scripts/claude/commit.ps1' },
    @{ Src = 'scripts/git-hooks/pre-commit';             Dst = 'scripts/git-hooks/pre-commit' },
    @{ Src = 'scripts/run-gate.sh';                      Dst = 'scripts/run-gate.sh' },
    @{ Src = 'scripts/render-project-values.ps1';        Dst = 'scripts/render-project-values.ps1' },
    @{ Src = 'scripts/review-liveness.psm1';             Dst = 'scripts/review-liveness.psm1' },
    @{ Src = 'scripts/review-common.ps1';                Dst = 'scripts/review-common.ps1' },
    @{ Src = 'docs/audit-protocol.md';                   Dst = 'docs/audit-protocol.md' },
    @{ Src = 'docs/AGENTS.md.template';                  Dst = 'docs/AGENTS.md.template' }
  )
}

# Recovery order is part of the authorization-marker identity. The current
# catalog follows Get-CrgCurrentFileList order after retired entries are
# filtered, while retaining historical paths without making them package
# sources. An absent retired file cannot satisfy a prior manifest that still
# names the path. Present entries require the ordinary seal custody.
function Get-CrgSealRecoveryFileList {
  return @(
    @{ Dst = 'scripts/codex/auto-review.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/auto-merge.ps1';             Retired = $false },
    @{ Dst = 'scripts/shared/auto-merge.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/commit.ps1';                 Retired = $false },
    @{ Dst = 'scripts/codex/analyze-blocker-trends.ps1'; Retired = $true },
    @{ Dst = 'scripts/codex/author-lint.ps1';            Retired = $true },
    @{ Dst = 'scripts/codex/dispatch-checklist.ps1';     Retired = $true },
    @{ Dst = 'scripts/codex/worker-audit.ps1';           Retired = $true },
    @{ Dst = 'scripts/shared/analyze-blocker-trends.ps1'; Retired = $false },
    @{ Dst = 'scripts/shared/author-lint.ps1';            Retired = $false },
    @{ Dst = 'scripts/shared/dispatch-checklist.ps1';     Retired = $false },
    @{ Dst = 'scripts/shared/worker-audit.ps1';           Retired = $false },
    @{ Dst = 'scripts/codex/review-prompt-template.md';  Retired = $false },
    @{ Dst = 'scripts/claude/auto-review.ps1';           Retired = $false },
    @{ Dst = 'scripts/claude/commit.ps1';                Retired = $false },
    @{ Dst = 'scripts/git-hooks/pre-commit';             Retired = $false },
    @{ Dst = 'scripts/run-gate.sh';                      Retired = $false },
    @{ Dst = 'scripts/render-project-values.ps1';        Retired = $false },
    @{ Dst = 'scripts/review-liveness.psm1';             Retired = $false },
    @{ Dst = 'scripts/review-common.ps1';                Retired = $false },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-1.rs'; Retired = $true },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-2.rs'; Retired = $true },
    @{ Dst = 'docs/audit-protocol.md';                   Retired = $false },
    @{ Dst = 'docs/AGENTS.md.template';                  Retired = $false }
  )
}

# Exact shared-layout recovery order before scripts/review-common.ps1 joined
# the inventory in 2.6.0 (the 2.4.4 through 2.5.0 layout). This frozen catalog
# admits such a complete LOCAL installation whose newer paths are all
# positively absent; it is never derived by subtracting today's paths.
function Get-CrgPreCommonRecoveryFileList {
  return @(
    @{ Dst = 'scripts/codex/auto-review.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/auto-merge.ps1';             Retired = $false },
    @{ Dst = 'scripts/shared/auto-merge.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/commit.ps1';                 Retired = $false },
    @{ Dst = 'scripts/codex/analyze-blocker-trends.ps1'; Retired = $true },
    @{ Dst = 'scripts/codex/author-lint.ps1';            Retired = $true },
    @{ Dst = 'scripts/codex/dispatch-checklist.ps1';     Retired = $true },
    @{ Dst = 'scripts/codex/worker-audit.ps1';           Retired = $true },
    @{ Dst = 'scripts/shared/analyze-blocker-trends.ps1'; Retired = $false },
    @{ Dst = 'scripts/shared/author-lint.ps1';            Retired = $false },
    @{ Dst = 'scripts/shared/dispatch-checklist.ps1';     Retired = $false },
    @{ Dst = 'scripts/shared/worker-audit.ps1';           Retired = $false },
    @{ Dst = 'scripts/codex/review-prompt-template.md';  Retired = $false },
    @{ Dst = 'scripts/claude/auto-review.ps1';           Retired = $false },
    @{ Dst = 'scripts/claude/commit.ps1';                Retired = $false },
    @{ Dst = 'scripts/git-hooks/pre-commit';             Retired = $false },
    @{ Dst = 'scripts/run-gate.sh';                      Retired = $false },
    @{ Dst = 'scripts/render-project-values.ps1';        Retired = $false },
    @{ Dst = 'scripts/review-liveness.psm1';             Retired = $false },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-1.rs'; Retired = $true },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-2.rs'; Retired = $true },
    @{ Dst = 'docs/audit-protocol.md';                   Retired = $false },
    @{ Dst = 'docs/AGENTS.md.template';                  Retired = $false }
  )
}

# Exact shared-layout recovery order before scripts/review-liveness.psm1 joined
# the inventory in 2.4.4. This frozen catalog admits such a
# complete LOCAL installation whose newer paths are all positively absent; it
# is never derived by subtracting today's paths.
function Get-CrgPreLivenessRecoveryFileList {
  return @(
    @{ Dst = 'scripts/codex/auto-review.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/auto-merge.ps1';             Retired = $false },
    @{ Dst = 'scripts/shared/auto-merge.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/commit.ps1';                 Retired = $false },
    @{ Dst = 'scripts/codex/analyze-blocker-trends.ps1'; Retired = $true },
    @{ Dst = 'scripts/codex/author-lint.ps1';            Retired = $true },
    @{ Dst = 'scripts/codex/dispatch-checklist.ps1';     Retired = $true },
    @{ Dst = 'scripts/codex/worker-audit.ps1';           Retired = $true },
    @{ Dst = 'scripts/shared/analyze-blocker-trends.ps1'; Retired = $false },
    @{ Dst = 'scripts/shared/author-lint.ps1';            Retired = $false },
    @{ Dst = 'scripts/shared/dispatch-checklist.ps1';     Retired = $false },
    @{ Dst = 'scripts/shared/worker-audit.ps1';           Retired = $false },
    @{ Dst = 'scripts/codex/review-prompt-template.md';  Retired = $false },
    @{ Dst = 'scripts/claude/auto-review.ps1';           Retired = $false },
    @{ Dst = 'scripts/claude/commit.ps1';                Retired = $false },
    @{ Dst = 'scripts/git-hooks/pre-commit';             Retired = $false },
    @{ Dst = 'scripts/run-gate.sh';                      Retired = $false },
    @{ Dst = 'scripts/render-project-values.ps1';        Retired = $false },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-1.rs'; Retired = $true },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-2.rs'; Retired = $true },
    @{ Dst = 'docs/audit-protocol.md';                   Retired = $false },
    @{ Dst = 'docs/AGENTS.md.template';                  Retired = $false }
  )
}

# Exact pre-relocation current recovery order. This frozen catalog admits a
# complete v2.1/v2.2 LOCAL installation whose shared-layout paths are all
# positively absent; it is never derived by subtracting today's paths.
function Get-CrgPreRelocationRecoveryFileList {
  return @(
    @{ Dst = 'scripts/codex/auto-review.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/auto-merge.ps1';             Retired = $false },
    @{ Dst = 'scripts/codex/commit.ps1';                 Retired = $false },
    @{ Dst = 'scripts/codex/analyze-blocker-trends.ps1'; Retired = $false },
    @{ Dst = 'scripts/codex/author-lint.ps1';            Retired = $false },
    @{ Dst = 'scripts/codex/dispatch-checklist.ps1';     Retired = $false },
    @{ Dst = 'scripts/codex/worker-audit.ps1';           Retired = $false },
    @{ Dst = 'scripts/codex/review-prompt-template.md';  Retired = $false },
    @{ Dst = 'scripts/claude/auto-review.ps1';           Retired = $false },
    @{ Dst = 'scripts/claude/commit.ps1';                Retired = $false },
    @{ Dst = 'scripts/git-hooks/pre-commit';             Retired = $false },
    @{ Dst = 'scripts/run-gate.sh';                      Retired = $false },
    @{ Dst = 'scripts/render-project-values.ps1';        Retired = $false },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-1.rs'; Retired = $true },
    @{ Dst = 'scripts/codex/selftest-fixtures/e2e-probe-base-2.rs'; Retired = $true },
    @{ Dst = 'docs/audit-protocol.md';                   Retired = $false },
    @{ Dst = 'docs/AGENTS.md.template';                  Retired = $false }
  )
}

# Frozen v2.0.0 release inventory. Legacy seal eligibility is derived from
# release identity, never by subtracting current additions from today's list.
function Get-CrgLegacyV200Paths {
  return @(
    'scripts/codex/auto-review.ps1',
    'scripts/codex/auto-merge.ps1',
    'scripts/codex/commit.ps1',
    'scripts/codex/analyze-blocker-trends.ps1',
    'scripts/codex/author-lint.ps1',
    'scripts/codex/dispatch-checklist.ps1',
    'scripts/codex/worker-audit.ps1',
    'scripts/codex/review-prompt-template.md',
    'scripts/claude/auto-review.ps1',
    'scripts/claude/commit.ps1',
    'scripts/git-hooks/pre-commit',
    'scripts/run-gate.sh',
    'scripts/codex/selftest-fixtures/e2e-probe-base-1.rs',
    'scripts/codex/selftest-fixtures/e2e-probe-base-2.rs',
    'docs/audit-protocol.md'
  )
}

function Get-CrgLegacyV170Paths {
  return @(
    'scripts/codex/auto-review.ps1',
    'scripts/codex/auto-merge.ps1',
    'scripts/codex/commit.ps1',
    'scripts/codex/analyze-blocker-trends.ps1',
    'scripts/codex/author-lint.ps1',
    'scripts/codex/dispatch-checklist.ps1',
    'scripts/codex/review-prompt-template.md',
    'scripts/claude/auto-review.ps1',
    'scripts/claude/commit.ps1',
    'scripts/git-hooks/pre-commit',
    'docs/audit-protocol.md'
  )
}

function Get-CrgLegacyV170RecognizedAdditions {
  return @(
    'scripts/codex/worker-audit.ps1',
    'scripts/run-gate.sh',
    'scripts/codex/selftest-fixtures/e2e-probe-base-1.rs',
    'scripts/codex/selftest-fixtures/e2e-probe-base-2.rs'
  )
}

function Test-CrgCompleteLeafInventory {
  param([string]$RepoRoot, [array]$FileList)
  foreach ($crgInvFile in $FileList) {
    if ((Get-CrgPathOccupantKind -Path (Join-Path $RepoRoot $crgInvFile.Dst)) -cne 'file') { return $false }
  }
  return $true
}

# Tri-state trusted baseline for an installed TRACKED component. A regular blob
# in HEAD is authoritative; a successful ls-tree with no row is positive
# absence and permits the local manifest fallback. Operational failures and
# non-regular entries stay distinct from absence so an unreadable/corrupt HEAD
# can never silently promote mutable manifest state into tracked authority.
function Get-CrgHeadPathBaseline {
  param([string]$Repo, [string]$Path)

  try { $crgHbHeads = @(& git -C $Repo rev-parse -q --verify 'HEAD^{commit}' 2>$null) } catch {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = ''; Reason = 'HEAD commit probe threw' }
  }
  if ($LASTEXITCODE -ne 0) {
    try { $crgHbRef = (Invoke-CrgGitUtf8 -GitArgs @('-C', $Repo, 'symbolic-ref', '-q', 'HEAD')) } catch {
      return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = ''; Reason = 'HEAD symbolic-ref probe threw' }
    }
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace("$crgHbRef")) {
      return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = ''; Reason = 'HEAD is unreadable and not a symbolic ref' }
    }
    try { & git -C $Repo show-ref --verify --quiet "$crgHbRef" 2>$null } catch {
      return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = ''; Reason = 'HEAD ref absence probe threw' }
    }
    if ($LASTEXITCODE -eq 1) {
      return [pscustomobject]@{ State = 'absent'; Mode = $null; Oid = $null; Head = ''; Reason = 'unborn branch positively has no HEAD path' }
    }
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = ''; Reason = 'HEAD commit failed but its symbolic ref was not absent' }
  }
  if ($crgHbHeads.Count -ne 1 -or "$($crgHbHeads[0])".Trim() -cnotmatch '\A([0-9a-f]{40}|[0-9a-f]{64})\z') {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = ''; Reason = 'HEAD commit probe returned a malformed identity' }
  }
  $crgHbHead = "$($crgHbHeads[0])".Trim()

  try { $crgHbRows = @(& git -C $Repo ls-tree $crgHbHead -- $Path 2>$null) } catch {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = $crgHbHead; Reason = 'HEAD path probe threw' }
  }
  if ($LASTEXITCODE -ne 0) {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = $crgHbHead; Reason = 'HEAD path probe failed' }
  }
  if ($crgHbRows.Count -eq 0 -or [string]::IsNullOrWhiteSpace(($crgHbRows -join ''))) {
    return [pscustomobject]@{ State = 'absent'; Mode = $null; Oid = $null; Head = $crgHbHead; Reason = 'path positively absent from captured HEAD' }
  }
  if ($crgHbRows.Count -ne 1 -or "$($crgHbRows[0])" -cnotmatch '^(100644|100755) blob ([0-9a-f]{40}|[0-9a-f]{64})\t(.+)$' -or
      -not [string]::Equals($Matches[3], $Path, [System.StringComparison]::Ordinal)) {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = $crgHbHead; Reason = 'HEAD path is not exactly one regular blob' }
  }
  if ($Matches[2].Length -ne $crgHbHead.Length) {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Head = $crgHbHead; Reason = 'HEAD path object format differs from the captured commit' }
  }
  return [pscustomobject]@{ State = 'present'; Mode = $Matches[1]; Oid = $Matches[2]; Head = $crgHbHead; Reason = 'regular blob in captured HEAD' }
}

# Tri-state stage-0 index identity for one installed path. The upgrade guard
# compares this immutable staged snapshot to HEAD before any destination move:
# a worktree-only custody check cannot see a staged edit after the worktree is
# restored, and a later `git add` would then destroy the index's sole copy.
# Unmerged rows, non-regular modes, malformed output, and Git failures are
# indeterminate rather than absence.
function Get-CrgIndexPathBaseline {
  param([string]$Repo, [string]$Path)

  try { $crgIbRows = @(& git -C $Repo ls-files --stage -- $Path 2>$null) } catch {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Reason = 'index path probe threw' }
  }
  if ($LASTEXITCODE -ne 0) {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Reason = 'index path probe failed' }
  }
  $crgIbRows = @($crgIbRows | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") })
  if ($crgIbRows.Count -eq 0) {
    return [pscustomobject]@{ State = 'absent'; Mode = $null; Oid = $null; Reason = 'path positively absent from the index' }
  }
  if ($crgIbRows.Count -ne 1 -or "$($crgIbRows[0])" -cnotmatch '^(100644|100755) ([0-9a-f]{40}|[0-9a-f]{64}) 0\t(.+)$' -or
      -not [string]::Equals($Matches[3], $Path, [System.StringComparison]::Ordinal)) {
    return [pscustomobject]@{ State = 'error'; Mode = $null; Oid = $null; Reason = 'index path is unmerged, non-regular, or not exactly one stage-0 entry' }
  }
  return [pscustomobject]@{ State = 'present'; Mode = $Matches[1]; Oid = $Matches[2]; Reason = 'regular stage-0 index blob' }
}

$script:CrgInstallValueOutputs = @(
  [pscustomobject]@{ Id = 'review-prompt'; RelativePath = 'scripts/codex/review-prompt-template.md' },
  [pscustomobject]@{ Id = 'agents-template'; RelativePath = 'docs/AGENTS.md.template' }
)

# Classify the complete render-bearing surface as one authority family. Every
# Git predicate is retained in the result so the same epoch can be proven again
# immediately before mutation and immediately before metadata publication.
function Get-CrgInstallValueOutputAuthority {
  param([string]$RepoRoot)
  $crgRaEntries = New-Object 'System.Collections.Generic.List[object]'
  foreach ($crgRaOutput in $script:CrgInstallValueOutputs) {
    $crgRaHead = Get-CrgHeadPathBaseline -Repo $RepoRoot -Path $crgRaOutput.RelativePath
    $crgRaIndex = Get-CrgIndexPathBaseline -Repo $RepoRoot -Path $crgRaOutput.RelativePath
    $crgRaIgnore = Get-CrgCheckIgnoreState -Repo $RepoRoot -Path $crgRaOutput.RelativePath
    if ($crgRaHead.State -ceq 'error') { throw "render output '$($crgRaOutput.RelativePath)' has indeterminate HEAD authority: $($crgRaHead.Reason)" }
    if ($crgRaIndex.State -ceq 'error') { throw "render output '$($crgRaOutput.RelativePath)' has indeterminate index authority: $($crgRaIndex.Reason)" }
    if ($crgRaIgnore -clike 'error:*') { throw "render output '$($crgRaOutput.RelativePath)' has indeterminate ignore authority ($crgRaIgnore)" }

    if ($crgRaHead.State -ceq 'present') {
      if ($crgRaIndex.State -cne 'present' -or
          -not [string]::Equals($crgRaHead.Mode, $crgRaIndex.Mode, [System.StringComparison]::Ordinal) -or
          -not [string]::Equals($crgRaHead.Oid, $crgRaIndex.Oid, [System.StringComparison]::Ordinal)) {
        throw "render output '$($crgRaOutput.RelativePath)' is tracked in HEAD but the stage-0 index differs"
      }
      $crgRaClass = 'TRACKED-existing'
      $crgRaFamily = 'TRACKED'
    } else {
      if ($crgRaIndex.State -cne 'absent') { throw "render output '$($crgRaOutput.RelativePath)' is index-only" }
      if ($crgRaIgnore -ceq 'ignored') {
        $crgRaClass = 'LOCAL'
        $crgRaFamily = 'LOCAL'
      } elseif ($crgRaIgnore -ceq 'exposed') {
        $crgRaClass = 'TRACKED-new'
        $crgRaFamily = 'TRACKED'
      } else {
        throw "render output '$($crgRaOutput.RelativePath)' returned unknown ignore authority '$crgRaIgnore'"
      }
    }
    $crgRaEntries.Add([pscustomobject]@{
      Id = $crgRaOutput.Id
      RelativePath = $crgRaOutput.RelativePath
      Class = $crgRaClass
      Family = $crgRaFamily
      HeadState = $crgRaHead.State
      HeadIdentity = $crgRaHead.Head
      HeadMode = $crgRaHead.Mode
      HeadOid = $crgRaHead.Oid
      IndexState = $crgRaIndex.State
      IndexMode = $crgRaIndex.Mode
      IndexOid = $crgRaIndex.Oid
      IgnoreState = $crgRaIgnore
    }) | Out-Null
  }
  $crgRaFamilySet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($crgRaEntry in $crgRaEntries) { [void]$crgRaFamilySet.Add([string]$crgRaEntry.Family) }
  $crgRaFamilies = @($crgRaFamilySet | Sort-Object)
  if ($crgRaFamilies.Count -ne 1) {
    $crgRaShape = @($crgRaEntries | ForEach-Object { "$($_.RelativePath)=$($_.Class)" }) -join ', '
    throw "render outputs do not share one authority family ($crgRaShape)"
  }
  return [pscustomobject]@{ Family = $crgRaFamilies[0]; Entries = $crgRaEntries.ToArray() }
}

function Assert-CrgInstallValueOutputAuthorityEqual {
  param([object]$Expected, [object]$Actual)
  if ($null -eq $Expected -or $null -eq $Actual -or
      -not [string]::Equals([string]$Expected.Family, [string]$Actual.Family, [System.StringComparison]::Ordinal) -or
      @($Expected.Entries).Count -ne @($Actual.Entries).Count) {
    throw 'render-output authority family changed during the install transaction'
  }
  for ($crgReI = 0; $crgReI -lt @($Expected.Entries).Count; $crgReI++) {
    $crgReLeft = @($Expected.Entries)[$crgReI]
    $crgReRight = @($Actual.Entries)[$crgReI]
    foreach ($crgReProperty in @('Id', 'RelativePath', 'Class', 'Family', 'HeadState', 'HeadIdentity', 'HeadMode', 'HeadOid', 'IndexState', 'IndexMode', 'IndexOid', 'IgnoreState')) {
      if (-not [string]::Equals([string]$crgReLeft.$crgReProperty, [string]$crgReRight.$crgReProperty, [System.StringComparison]::Ordinal)) {
        throw "render-output authority changed for '$($crgReLeft.RelativePath)' at '$crgReProperty'"
      }
    }
  }
}

function Open-CrgInstallValuesSourceHold {
  param([string]$RepoRoot)
  $crgVsPath = Join-Path $RepoRoot 'CROSS-REVIEW-VALUES.md'
  $crgVsOwner = Open-CrgBoundedOwnerFileNoFollow -Path $crgVsPath -MaxLength 262144 -Label 'CROSS-REVIEW-VALUES.md'
  if ($null -eq $crgVsOwner -or $null -eq $crgVsOwner.Stream -or $crgVsOwner.Bytes -isnot [byte[]]) {
    throw "the fixed values source '$crgVsPath' could not be retained"
  }
  $crgVsOwner | Add-Member -NotePropertyName RelativePath -NotePropertyValue 'CROSS-REVIEW-VALUES.md'
  $crgVsOwner | Add-Member -NotePropertyName Sha256 -NotePropertyValue (Get-CrgSha256HexOfBytes -Bytes $crgVsOwner.Bytes)
  return $crgVsOwner
}

function Get-CrgInstallValuesSourceEvidence {
  param([string]$RepoRoot, [ValidatePattern('\A(?:TRACKED|LOCAL)\z', Options = 'None')][string]$Family, [object]$SourceOwner)
  if ($null -eq $SourceOwner -or $null -eq $SourceOwner.Stream -or $SourceOwner.Bytes -isnot [byte[]]) { throw 'values-source custody is absent' }
  $crgVsAttributes = [CrgBootstrap.NativeV4]::GetHandleAttributes($SourceOwner.Stream.SafeFileHandle)
  if ($crgVsAttributes -lt 0 -or
      [CrgBootstrap.NativeV3]::GetLinkCount($SourceOwner.Stream.SafeFileHandle) -ne 1 -or
      ($crgVsAttributes -band 0x410) -ne 0) {
    throw 'CROSS-REVIEW-VALUES.md lost ordinary single-link custody'
  }
  $crgVsHead = Get-CrgHeadPathBaseline -Repo $RepoRoot -Path 'CROSS-REVIEW-VALUES.md'
  $crgVsIndex = Get-CrgIndexPathBaseline -Repo $RepoRoot -Path 'CROSS-REVIEW-VALUES.md'
  $crgVsIgnore = Get-CrgCheckIgnoreState -Repo $RepoRoot -Path 'CROSS-REVIEW-VALUES.md'
  if ($crgVsHead.State -ceq 'error') { throw "values source HEAD authority is indeterminate: $($crgVsHead.Reason)" }
  if ($crgVsIndex.State -ceq 'error') { throw "values source index authority is indeterminate: $($crgVsIndex.Reason)" }
  if ($crgVsIgnore -clike 'error:*') { throw "values source ignore authority is indeterminate ($crgVsIgnore)" }

  if ($Family -ceq 'TRACKED') {
    if ($crgVsIndex.State -cne 'present') { throw 'TRACKED rendering requires CROSS-REVIEW-VALUES.md as one regular stage-0 index blob' }
    [byte[]]$crgVsIndexedBytes = Read-CrgGitBlobBytes -RepoRoot $RepoRoot -Oid $crgVsIndex.Oid -MaxLength 262144
    if (-not (Compare-CrgInstallValueBytes -Left $SourceOwner.Bytes -Right $crgVsIndexedBytes)) {
      throw 'working CROSS-REVIEW-VALUES.md bytes do not equal the staged blob bytes; stage the intended values first'
    }
  } else {
    if ($crgVsHead.State -cne 'absent' -or $crgVsIndex.State -cne 'absent' -or $crgVsIgnore -cne 'ignored') {
      throw 'LOCAL rendering requires CROSS-REVIEW-VALUES.md absent from HEAD and index and positively ignored'
    }
  }
  return [pscustomobject]@{
    Family = $Family
    HeadState = $crgVsHead.State
    HeadIdentity = $crgVsHead.Head
    HeadMode = $crgVsHead.Mode
    HeadOid = $crgVsHead.Oid
    IndexState = $crgVsIndex.State
    IndexMode = $crgVsIndex.Mode
    IndexOid = $crgVsIndex.Oid
    IgnoreState = $crgVsIgnore
    Sha256 = $SourceOwner.Sha256
    Length = $SourceOwner.Bytes.Length
  }
}

function Assert-CrgInstallValuesEpoch {
  param([string]$RepoRoot, [object]$OutputAuthority, [object]$SourceEvidence, [object]$SourceOwner)
  Assert-CrgInstallValueOutputAuthorityEqual -Expected $OutputAuthority -Actual (Get-CrgInstallValueOutputAuthority -RepoRoot $RepoRoot)
  $crgVeActualSource = Get-CrgInstallValuesSourceEvidence -RepoRoot $RepoRoot -Family $OutputAuthority.Family -SourceOwner $SourceOwner
  foreach ($crgVeProperty in @('Family', 'HeadState', 'HeadIdentity', 'HeadMode', 'HeadOid', 'IndexState', 'IndexMode', 'IndexOid', 'IgnoreState', 'Sha256', 'Length')) {
    if (-not [string]::Equals([string]$SourceEvidence.$crgVeProperty, [string]$crgVeActualSource.$crgVeProperty, [System.StringComparison]::Ordinal)) {
      throw "values-source authority changed at '$crgVeProperty' during the install transaction"
    }
  }
  [byte[]]$crgVeBytes = Read-CrgHeldStreamBytes -Stream $SourceOwner.Stream -MaxLength 262144 -Label 'retained CROSS-REVIEW-VALUES.md'
  if (-not (Compare-CrgInstallValueBytes -Left $SourceOwner.Bytes -Right $crgVeBytes)) { throw 'retained CROSS-REVIEW-VALUES.md bytes changed during the install transaction' }
}

function Assert-CrgHeldPackageSnapshot {
  param([object[]]$Owners)
  foreach ($crgPsOwner in @($Owners)) {
    if ($null -eq $crgPsOwner -or $null -eq $crgPsOwner.Stream -or $crgPsOwner.Bytes -isnot [byte[]]) {
      throw 'a retained package-snapshot owner is absent'
    }
    $crgPsAttributes = [CrgBootstrap.NativeV4]::GetHandleAttributes($crgPsOwner.Stream.SafeFileHandle)
    if ($crgPsAttributes -lt 0 -or ($crgPsAttributes -band 0x410) -ne 0 -or
        [CrgBootstrap.NativeV3]::GetLinkCount($crgPsOwner.Stream.SafeFileHandle) -ne 1) {
      throw "retained package source '$($crgPsOwner.RelativePath)' lost ordinary single-link custody"
    }
    [byte[]]$crgPsBytes = Read-CrgHeldStreamBytes -Stream $crgPsOwner.Stream -MaxLength 16777216 -Label "retained package source '$($crgPsOwner.RelativePath)'"
    if (-not (Compare-CrgInstallValueBytes -Left $crgPsOwner.Bytes -Right $crgPsBytes)) {
      throw "retained package source '$($crgPsOwner.RelativePath)' changed during the install transaction"
    }
  }
}

function Test-CrgInstallValueByteSequence {
  param([byte[]]$Bytes, [byte[]]$Needle)
  if ($null -eq $Bytes -or $null -eq $Needle -or $Needle.Length -eq 0 -or $Needle.Length -gt $Bytes.Length) { return $false }
  for ($crgBsI = 0; $crgBsI -le $Bytes.Length - $Needle.Length; $crgBsI++) {
    $crgBsMatch = $true
    for ($crgBsJ = 0; $crgBsJ -lt $Needle.Length; $crgBsJ++) {
      if ($Bytes[$crgBsI + $crgBsJ] -ne $Needle[$crgBsJ]) { $crgBsMatch = $false; break }
    }
    if ($crgBsMatch) { return $true }
  }
  return $false
}

function Assert-CrgLocalSealPathAuthority {
  param([string]$RepoRoot, [string[]]$Paths)
  foreach ($crgLsPath in @($Paths)) {
    $crgLsHead = Get-CrgHeadPathBaseline -Repo $RepoRoot -Path $crgLsPath
    $crgLsIndex = Get-CrgIndexPathBaseline -Repo $RepoRoot -Path $crgLsPath
    $crgLsIgnore = Get-CrgCheckIgnoreState -Repo $RepoRoot -Path $crgLsPath
    if ($crgLsHead.State -cne 'absent' -or $crgLsIndex.State -cne 'absent' -or $crgLsIgnore -cne 'ignored') {
      throw "LOCAL seal path '$crgLsPath' is not positively absent from HEAD/index and positively ignored (HEAD=$($crgLsHead.State), index=$($crgLsIndex.State), ignore=$crgLsIgnore)"
    }
  }
}

function Assert-CrgRendererTransactionStateAbsent {
  param([string]$GitDir)
  $crgRsPath = Join-Path $GitDir 'crg-render-project-values-transaction'
  $crgRsKind = Get-CrgPathOccupantKind -Path $crgRsPath
  if ($crgRsKind -cne 'empty') {
    throw "renderer transaction state has occupant kind '$crgRsKind' at '$crgRsPath'; run scripts/render-project-values.ps1 -TargetRepo <root> so the standalone recovery owner can finish"
  }
}

# Classify whether the trusted HEAD review kernel still contains the retired
# PROJECT-MODE enforcement that predates review-context-only semantics. The
# answer is derived from HEAD, never from candidate worktree bytes. `absent`
# means a positively unborn branch or no kernel surface in a readable HEAD;
# `current` means the surfaces are readable and none carries a retired
# signature; `legacy` means at least one exact retired signature is present;
# `error` keeps an operational failure distinct from every semantic state.
function Get-CrgRetiredProjectModeCommitSnapshot {
  param([string]$Repo, [string]$Commit)
  if ($Commit -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') {
    return [pscustomobject]@{ State = 'error'; Reason = 'the supplied HEAD identity is not one canonical commit OID'; Head = ''; Identity = '' }
  }
  try { & git -C $Repo cat-file -e "${Commit}^{commit}" 2>$null } catch {
    return [pscustomobject]@{ State = 'error'; Reason = 'git cat-file threw while validating the captured HEAD commit'; Head = $Commit; Identity = "commit:$Commit" }
  }
  if ($LASTEXITCODE -ne 0) {
    return [pscustomobject]@{ State = 'error'; Reason = 'the captured HEAD OID is not a readable commit'; Head = $Commit; Identity = "commit:$Commit" }
  }

  $crgPmSurfaces = @(
    'scripts/git-hooks/pre-commit',
    'scripts/codex/auto-review.ps1',
    'scripts/claude/auto-review.ps1',
    'scripts/codex/review-prompt-template.md'
  )
  $crgPmPresent = New-Object 'System.Collections.Generic.List[string]'
  foreach ($crgPmSurface in $crgPmSurfaces) {
    try { $crgPmTree = @(& git -C $Repo ls-tree $Commit -- $crgPmSurface 2>$null) } catch {
      return [pscustomobject]@{ State = 'error'; Reason = "git ls-tree threw for '$crgPmSurface'"; Head = $Commit; Identity = "commit:$Commit" }
    }
    if ($LASTEXITCODE -ne 0) {
      return [pscustomobject]@{ State = 'error'; Reason = "git ls-tree failed for '$crgPmSurface'"; Head = $Commit; Identity = "commit:$Commit" }
    }
    if ($crgPmTree.Count -eq 0 -or [string]::IsNullOrWhiteSpace(($crgPmTree -join ''))) { continue }
    if ($crgPmTree.Count -ne 1 -or "$($crgPmTree[0])" -cnotmatch '^(100644|100755) blob [0-9a-f]{40}([0-9a-f]{24})?\t') {
      return [pscustomobject]@{ State = 'error'; Reason = "captured HEAD '$crgPmSurface' is not one regular blob"; Head = $Commit; Identity = "commit:$Commit" }
    }
    $crgPmPresent.Add($crgPmSurface) | Out-Null
  }
  if ($crgPmPresent.Count -eq 0) {
    return [pscustomobject]@{ State = 'absent'; Reason = 'no review-kernel surface exists in the captured HEAD'; Head = $Commit; Identity = "commit:$Commit" }
  }

  foreach ($crgPmSurface in $crgPmPresent) {
    try {
      & git -C $Repo grep -q `
        -e 'crg_pm_staged_touches_declaration' `
        -e 'function Test-ProjectModeBranchRange' `
        -e 'Green is campaign-anchored' `
        $Commit -- $crgPmSurface 2>$null
    } catch {
      return [pscustomobject]@{ State = 'error'; Reason = "git grep threw while reading captured HEAD '$crgPmSurface'"; Head = $Commit; Identity = "commit:$Commit" }
    }
    if ($LASTEXITCODE -eq 0) {
      return [pscustomobject]@{ State = 'legacy'; Reason = "a retired project-mode enforcement signature exists in captured HEAD '$crgPmSurface'"; Head = $Commit; Identity = "commit:$Commit" }
    }
    if ($LASTEXITCODE -ne 1) {
      return [pscustomobject]@{ State = 'error'; Reason = "git grep failed while reading captured HEAD '$crgPmSurface'"; Head = $Commit; Identity = "commit:$Commit" }
    }
  }
  return [pscustomobject]@{ State = 'current'; Reason = 'no retired project-mode enforcement signature exists in the captured HEAD'; Head = $Commit; Identity = "commit:$Commit" }
}

function Get-CrgRetiredProjectModeHeadState {
  param([string]$Repo)

  try { $crgPmHead = @(& git -C $Repo rev-parse -q --verify 'HEAD^{commit}' 2>$null) } catch {
    return [pscustomobject]@{ State = 'error'; Reason = 'git rev-parse --verify HEAD threw'; Head = ''; Identity = '' }
  }
  if ($LASTEXITCODE -eq 0 -and $crgPmHead.Count -eq 1 -and "$($crgPmHead[0])".Trim() -cmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') {
    return Get-CrgRetiredProjectModeCommitSnapshot -Repo $Repo -Commit "$($crgPmHead[0])".Trim()
  }
  if ($LASTEXITCODE -ne 0) {
    try { $crgPmRef = (Invoke-CrgGitUtf8 -GitArgs @('-C', $Repo, 'symbolic-ref', '-q', 'HEAD')) } catch {
      return [pscustomobject]@{ State = 'error'; Reason = 'git symbolic-ref HEAD threw after HEAD failed to resolve'; Head = ''; Identity = '' }
    }
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace("$crgPmRef")) {
      return [pscustomobject]@{ State = 'error'; Reason = 'HEAD failed to resolve and was not a readable symbolic ref'; Head = ''; Identity = '' }
    }
    $crgPmRef = "$crgPmRef".Trim()
    try { & git -C $Repo show-ref --verify --quiet "$crgPmRef" 2>$null } catch {
      return [pscustomobject]@{ State = 'error'; Reason = 'git show-ref threw while proving an unborn branch'; Head = ''; Identity = '' }
    }
    if ($LASTEXITCODE -eq 1) {
      return [pscustomobject]@{ State = 'absent'; Reason = 'branch is positively unborn'; Head = ''; Identity = "unborn:$crgPmRef" }
    }
    return [pscustomobject]@{ State = 'error'; Reason = 'HEAD failed to resolve but its symbolic branch was not positively absent'; Head = ''; Identity = '' }
  }
  return [pscustomobject]@{ State = 'error'; Reason = 'HEAD resolution returned a malformed commit identity'; Head = ''; Identity = '' }
}

function Read-CrgGitBlobBytes {
  param([string]$RepoRoot, [string]$Oid, [int64]$MaxLength = 16777216)
  if ($Oid -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { throw 'blob reader received a non-canonical object ID' }
  $gbGit = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
  $gbPsi = New-Object System.Diagnostics.ProcessStartInfo
  $gbPsi.FileName = $gbGit
  $gbPsi.UseShellExecute = $false
  $gbPsi.RedirectStandardOutput = $true
  $gbPsi.RedirectStandardError = $true
  $gbPsi.CreateNoWindow = $true
  $gbPsi.Arguments = ((@('-C', $RepoRoot, 'cat-file', 'blob', $Oid) | ForEach-Object { Convert-CrgWindowsProcessArgument -Argument $_ }) -join ' ')
  Initialize-CrgBoundedSinkNative
  $gbErrors = New-Object CrgBoundedCapture.SinkV1 ([long]65536)
  $gbProc = [System.Diagnostics.Process]::Start($gbPsi)
  try {
    $gbErrCopy = $gbProc.StandardError.BaseStream.CopyToAsync($gbErrors)
    $gbOut = New-Object System.IO.MemoryStream
    try {
      # The bound is enforced while reading, so an oversized blob is never
      # buffered whole; the rest of its output is drained after the stop.
      $gbBuffer = New-Object byte[] 8192
      $gbExceeded = $false
      while (($gbRead = $gbProc.StandardOutput.BaseStream.Read($gbBuffer, 0, $gbBuffer.Length)) -gt 0) {
        if (-not $gbExceeded -and ($gbOut.Length + $gbRead) -gt $MaxLength) {
          $gbExceeded = $true
          try { $gbProc.Kill() } catch { }
        }
        if (-not $gbExceeded) { $gbOut.Write($gbBuffer, 0, $gbRead) }
      }
      $gbProc.WaitForExit()
      $null = $gbErrCopy.GetAwaiter().GetResult()
      $gbErr = [System.Text.UTF8Encoding]::new($false).GetString($gbErrors.ToArray())
      if ($gbExceeded) { throw "blob '$Oid' exceeds the $MaxLength-byte transition bound" }
      if ($gbProc.ExitCode -ne 0) { throw "git cat-file failed for blob '$Oid' ($gbErr)" }
      if ($gbErrors.Exceeded) { throw "git cat-file for blob '$Oid' wrote more than the 65536-byte stderr capture bound" }
      return ,([byte[]]$gbOut.ToArray())
    } finally { $gbOut.Dispose() }
  } finally {
    # A failure above can leave the child running; its exit is confirmed
    # before disposal, as in Invoke-CrgIsolatedGitProcess.
    if (-not $gbProc.HasExited) {
      try { $gbProc.Kill() } catch { }
      try { $gbProc.StandardOutput.BaseStream.CopyTo([System.IO.Stream]::Null) } catch { }
      $gbProc.WaitForExit()
    }
    $gbProc.Dispose()
  }
}

function Convert-CrgWindowsProcessArgument {
  param([AllowEmptyString()][string]$Argument)
  if ($null -eq $Argument) { throw 'process argument cannot be null' }
  $qaEscaped = [regex]::Replace($Argument, '(\\*)"', '$1$1\"')
  $qaEscaped = [regex]::Replace($qaEscaped, '(\\+)$', '$1$1')
  return '"' + $qaEscaped + '"'
}

function Get-CrgGitConversionSettings {
  param([string]$RepoRoot)

  $gcAutoRows = @(& git -C $RepoRoot config --get core.autocrlf 2>$null)
  $gcAutoRc = $LASTEXITCODE
  if ($gcAutoRc -eq 1) { $gcAuto = 'false' }
  elseif ($gcAutoRc -eq 0 -and $gcAutoRows.Count -eq 1) {
    $gcAutoRaw = "$($gcAutoRows[0])"
    if ([string]::Equals($gcAutoRaw.Trim(), 'input', [System.StringComparison]::OrdinalIgnoreCase)) { $gcAuto = 'input' }
    else {
      $gcAutoCanonical = @(& git -C $RepoRoot -c "core.autocrlf=$gcAutoRaw" config --type=bool --get core.autocrlf 2>$null)
      if ($LASTEXITCODE -ne 0 -or $gcAutoCanonical.Count -ne 1 -or -not ([string]::Equals("$($gcAutoCanonical[0])", 'true', [System.StringComparison]::Ordinal) -or [string]::Equals("$($gcAutoCanonical[0])", 'false', [System.StringComparison]::Ordinal))) { throw 'effective core.autocrlf is not a valid boolean or input value' }
      $gcAuto = "$($gcAutoCanonical[0])"
    }
  } else { throw 'effective core.autocrlf could not be captured exactly' }

  $gcEolRows = @(& git -C $RepoRoot config --get core.eol 2>$null)
  $gcEolRc = $LASTEXITCODE
  if ($gcEolRc -eq 1) { $gcEol = 'native' }
  elseif ($gcEolRc -eq 0 -and $gcEolRows.Count -eq 1 -and [System.Linq.Enumerable]::Contains([string[]]@('lf', 'crlf', 'native'), "$($gcEolRows[0])".Trim().ToLowerInvariant(), [System.StringComparer]::Ordinal)) { $gcEol = "$($gcEolRows[0])".Trim().ToLowerInvariant() }
  else { throw 'effective core.eol could not be captured exactly' }

  $gcSafeRows = @(& git -C $RepoRoot config --get core.safecrlf 2>$null)
  $gcSafeRc = $LASTEXITCODE
  if ($gcSafeRc -eq 1) { $gcSafe = 'false' }
  elseif ($gcSafeRc -eq 0 -and $gcSafeRows.Count -eq 1) {
    $gcSafeRaw = "$($gcSafeRows[0])"
    if ([string]::Equals($gcSafeRaw.Trim(), 'warn', [System.StringComparison]::OrdinalIgnoreCase)) { $gcSafe = 'warn' }
    else {
      $gcSafeCanonical = @(& git -C $RepoRoot -c "core.safecrlf=$gcSafeRaw" config --type=bool --get core.safecrlf 2>$null)
      if ($LASTEXITCODE -ne 0 -or $gcSafeCanonical.Count -ne 1 -or -not ([string]::Equals("$($gcSafeCanonical[0])", 'true', [System.StringComparison]::Ordinal) -or [string]::Equals("$($gcSafeCanonical[0])", 'false', [System.StringComparison]::Ordinal))) { throw 'effective core.safecrlf is not a valid boolean or warn value' }
      $gcSafe = "$($gcSafeCanonical[0])"
    }
  } else { throw 'effective core.safecrlf could not be captured exactly' }

  $gcModeRows = @(& git -C $RepoRoot config --type=bool --get core.filemode 2>$null)
  $gcModeRc = $LASTEXITCODE
  if ($gcModeRc -eq 1) { $gcMode = 'false' }
  elseif ($gcModeRc -eq 0 -and $gcModeRows.Count -eq 1 -and ([string]::Equals("$($gcModeRows[0])", 'true', [System.StringComparison]::Ordinal) -or [string]::Equals("$($gcModeRows[0])", 'false', [System.StringComparison]::Ordinal))) { $gcMode = "$($gcModeRows[0])" }
  else { throw 'effective core.filemode could not be captured exactly' }

  return [pscustomobject]@{ AutoCrlf = $gcAuto; Eol = $gcEol; SafeCrlf = $gcSafe; FileMode = $gcMode }
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
    # or restore that fails is raised, not ended here: the callers sit inside
    # install, transition and recovery steps whose catches fail closed and
    # first put back or name what they moved, which an exit would skip. A
    # restore failure is written through the host when it happens, since a
    # caller's catch can replace the raised message, and is raised only after
    # the child's exit is confirmed: its input writer was built before the
    # restore, so the child is unaffected. Tried and dropped: switching
    # through the [Console]::InputEncoding setter (2.6.4 and earlier), which
    # also set the shared console's input code page and left it changed when
    # this process was killed before the restore; killing the child on a
    # restore failure (staged review, 2026-10-10), which cannot confirm the
    # exit when the kill fails; ending the run with exit 1 from this helper
    # and from Invoke-CrgGitUtf8 (2.6.1), which left a gate file moved aside
    # during install custody unrestored and unnamed.
    $ipPriorConsoleInputEncoding = Set-CrgProcessConsoleEncoding -ConsoleInput -Encoding (New-Object System.Text.UTF8Encoding($false))
    $ipSwitchedConsoleInput = $true
  }
  $ipProcess = $null
  $ipRestoreFailure = $null
  # Start sits inside the try whose finally confirms the exit, so no failure
  # after a successful start can bypass the confirmation or drop a recorded
  # restore failure.
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
      $ipProcess.WaitForExit()
      $null = $ipErrCopy.GetAwaiter().GetResult()
      $ipError = [System.Text.UTF8Encoding]::new($false).GetString($ipErrors.ToArray())
      if ($ipOutputExceeded) { throw "isolated Git stdout exceeded the $MaxOutputBytes-byte bound" }
      if ($ipErrors.Exceeded) { throw "isolated Git stderr exceeded the 65536-byte capture bound (exit $($ipProcess.ExitCode))" }
      [byte[]]$ipOutputBytes = $ipOutput.ToArray()
    } finally { $ipOutput.Dispose() }
    $ipOutputText = [System.Text.UTF8Encoding]::new($false).GetString($ipOutputBytes)
    $ipResult = [pscustomobject]@{ Exit = $ipProcess.ExitCode; Bytes = $ipOutputBytes; OutputText = $ipOutputText; ErrorText = $ipError; Text = ($ipOutputText + $ipError) }
  } finally {
    # A failure above can leave the child running. Its exit is confirmed
    # before disposal, as on the output-bound path: a stop that fails is
    # outlasted by closing its input, draining its output to the end so it
    # cannot block on a full pipe, and waiting for the exit, so a caller's
    # scratch cleanup never runs under a live Git child.
    if ($null -ne $ipProcess) {
      if (-not $ipProcess.HasExited) {
        try { $ipProcess.Kill() } catch { }
        if ($null -ne $ipStandardInput) { try { $ipStandardInput.Close() } catch { } }
        try { $ipProcess.StandardOutput.BaseStream.CopyTo([System.IO.Stream]::Null) } catch { }
        $ipProcess.WaitForExit()
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

function Test-CrgPathWithin {
  param([string]$Path, [string]$Root)
  $pwPathRaw = [System.IO.Path]::GetFullPath($Path)
  $pwRootRaw = [System.IO.Path]::GetFullPath($Root)
  $pwPathRoot = [System.IO.Path]::GetPathRoot($pwPathRaw)
  $pwRootRoot = [System.IO.Path]::GetPathRoot($pwRootRaw)
  $pwPath = if ([string]::Equals($pwPathRaw, $pwPathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $pwPathRoot } else { $pwPathRaw.TrimEnd('\', '/') }
  $pwRoot = if ([string]::Equals($pwRootRaw, $pwRootRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $pwRootRoot } else { $pwRootRaw.TrimEnd('\', '/') }
  if ([string]::Equals($pwPath, $pwRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  $pwBoundary = if ($pwRoot.EndsWith('\', [System.StringComparison]::Ordinal) -or $pwRoot.EndsWith('/', [System.StringComparison]::Ordinal)) { $pwRoot } else { "$pwRoot$([System.IO.Path]::DirectorySeparatorChar)" }
  return $pwPath.StartsWith($pwBoundary, [System.StringComparison]::OrdinalIgnoreCase)
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
    # state as specified. Accept it only for the fixed rendered-value surfaces
    # after the pathspec state proof distinguishes it from literal collisions.
    $hpInstallValuePaths = @('scripts/codex/review-prompt-template.md', 'docs/AGENTS.md.template')
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

function Get-CrgPrivateAttributeMap {
  param([object]$Context, [string]$TreeOid, [string[]]$Paths, [string[]]$Attributes)
  if ($null -eq $Context -or $TreeOid -cnotmatch "\A[0-9a-f]{$($Context.ObjectIdLength)}\z" -or $null -eq $Paths -or $null -eq $Attributes -or $Paths.Count -lt 1 -or $Attributes.Count -lt 1) {
    throw 'private attribute query received an invalid context, tree, path inventory, or attribute inventory'
  }
  $paExpectedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $paExpectedAttributes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $paInput = New-Object System.IO.MemoryStream
  try {
    foreach ($paPath in $Paths) {
      if ($paPath -cnotmatch '\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z' -or $paPath.StartsWith('/', [System.StringComparison]::Ordinal) -or $paPath.EndsWith('/', [System.StringComparison]::Ordinal)) { throw "unsafe private attribute query path '$paPath'" }
      foreach ($paComponent in @($paPath -split '/')) { if ([string]::Equals($paComponent, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($paComponent, '..', [System.StringComparison]::Ordinal)) { throw "unsafe private attribute query path '$paPath'" } }
      if (-not $paExpectedPaths.Add($paPath)) { throw "duplicate private attribute query path '$paPath'" }
      $paPathBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($paPath)
      $paInput.Write($paPathBytes, 0, $paPathBytes.Length); $paInput.WriteByte(0)
    }
    foreach ($paAttribute in $Attributes) {
      if ($paAttribute -cnotmatch '\A[A-Za-z0-9_.-]+\z' -or -not $paExpectedAttributes.Add($paAttribute)) { throw "unsafe or duplicate private attribute query name '$paAttribute'" }
    }
    [byte[]]$paInputBytes = $paInput.ToArray()
  } finally { $paInput.Dispose() }

  $paResult = Invoke-CrgPrivateAttributeGit -Context $Context -GitArgs (@("--attr-source=$TreeOid", 'check-attr', '-z', '--stdin') + @($Attributes)) -InputBytes $paInputBytes
  if ($paResult.Exit -ne 0 -or $paResult.ErrorText.Length -ne 0) { throw "private check-attr query failed (exit $($paResult.Exit)): $($paResult.Text.Trim())" }
  $paText = [System.Text.UTF8Encoding]::new($false, $true).GetString($paResult.Bytes)
  $paParts = $paText.Split([char[]]@([char]0), [System.StringSplitOptions]::None)
  $paExpectedCount = $Paths.Count * $Attributes.Count
  if ($paParts.Count -ne (($paExpectedCount * 3) + 1) -or $paParts[$paParts.Count - 1].Length -ne 0) { throw 'private check-attr returned a malformed or non-bijective NUL inventory' }
  $paMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  for ($paI = 0; $paI -lt ($paParts.Count - 1); $paI += 3) {
    $paPath = $paParts[$paI]; $paAttribute = $paParts[$paI + 1]; $paValue = $paParts[$paI + 2]
    if (-not $paExpectedPaths.Contains($paPath) -or -not $paExpectedAttributes.Contains($paAttribute)) { throw 'private check-attr returned an unexpected path or attribute' }
    $paKey = "$paPath`0$paAttribute"
    if ($paMap.ContainsKey($paKey)) { throw "private check-attr returned duplicate key '$paPath/$paAttribute'" }
    $paMap[$paKey] = $paValue
  }
  if ($paMap.Count -ne $paExpectedCount) { throw 'private check-attr omitted an expected path/attribute pair' }
  return $paMap
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

function Assert-CrgProspectiveLiveInstallValuesAttributeOverrides {
  param(
    [string]$RepoRoot,
    [string]$ScratchRoot,
    [hashtable]$AttributeBuffers,
    [ValidatePattern('\A(?:40|64)\z', Options = 'None')][int]$ObjectIdLength
  )
  if ([string]::IsNullOrWhiteSpace($RepoRoot) -or [string]::IsNullOrWhiteSpace($ScratchRoot) -or
      -not (Test-Path -LiteralPath $RepoRoot -PathType Container) -or -not (Test-Path -LiteralPath $ScratchRoot -PathType Container) -or
      $null -eq $AttributeBuffers -or -not $AttributeBuffers.ContainsKey('.gitattributes')) {
    throw 'prospective live installed-project-values override validation received an invalid repository, scratch root, or retained attribute graph'
  }
  $loPaths = @(
    'CROSS-REVIEW-VALUES.md',
    'scripts/codex/review-prompt-template.md',
    'docs/AGENTS.md.template'
  )

  # The unpublished repository-owned candidate has already passed its isolated
  # graph and conversion proof. Reconstruct only Git's higher-priority mutable
  # info/attributes layer here: importing the target's configuration could run
  # a configured driver, while requiring the live named states would reject a
  # fresh install before the candidate root rules exist.
  $loCommonDir = Get-CrgGitCommonDir -RepoRoot $RepoRoot
  if ([string]::IsNullOrWhiteSpace($loCommonDir)) { throw 'live target common directory could not be resolved for state-sensitive attribute validation' }
  $loInfoSnapshot = Read-CrgRootedFileBytesExact -Path (Join-Path $loCommonDir 'info/attributes') -Label 'live common-dir info/attributes' -MaxLength 1048576
  [byte[]]$loInfoBytes = [byte[]]::new(0)
  if ($loInfoSnapshot.State -ceq 'held') { $loInfoBytes = [byte[]]$loInfoSnapshot.Bytes }
  $loStateContext = $null
  $loStateScratch = Join-Path $ScratchRoot ("crg-live-av-" + [guid]::NewGuid().ToString('N'))
  try {
    $loStateContext = New-CrgPrivateAttributeContext -ScratchRoot $loStateScratch -ObjectIdLength $ObjectIdLength -InfoAttributesBytes $loInfoBytes
    $loStateWriter = { param([string]$Type, [byte[]]$Bytes) Add-CrgPrivateGitObject -Context $loStateContext -Type $Type -Bytes $Bytes }
    $loStateTree = New-CrgGitAttributeSourceTree -AttributeBuffers $AttributeBuffers -ObjectIdLength $ObjectIdLength -WriteObject $loStateWriter -ProbePaths $loPaths
    Assert-CrgPrivateInstallValuesAttributeStates -Context $loStateContext -TreeOid $loStateTree -Paths $loPaths
  } finally {
    if ($null -ne $loStateContext -and -not (Close-CrgPrivateAttributeContext -Context $loStateContext)) {
      throw 'live state-sensitive attribute proof scratch could not be exactly cleaned'
    }
  }
}

function Assert-CrgLiveInstallValuesAttributeGraph {
  param(
    [string]$RepoRoot,
    [string]$ScratchRoot,
    [hashtable]$AttributeBuffers,
    [ValidatePattern('\A(?:40|64)\z', Options = 'None')][int]$ObjectIdLength
  )
  if ([string]::IsNullOrWhiteSpace($RepoRoot) -or [string]::IsNullOrWhiteSpace($ScratchRoot) -or
      -not (Test-Path -LiteralPath $RepoRoot -PathType Container) -or -not (Test-Path -LiteralPath $ScratchRoot -PathType Container) -or
      $null -eq $AttributeBuffers -or -not $AttributeBuffers.ContainsKey('.gitattributes')) {
    throw 'live installed-project-values attribute validation received an invalid repository, scratch root, or retained attribute graph'
  }
  $laPaths = @(
    'CROSS-REVIEW-VALUES.md',
    'scripts/codex/review-prompt-template.md',
    'docs/AGENTS.md.template'
  )
  $laAttributes = @('text', 'eol', 'filter', 'ident', 'working-tree-encoding')
  $laExpectedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $laExpectedAttributes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  $laInput = New-Object System.IO.MemoryStream
  try {
    foreach ($laPath in $laPaths) {
      [void]$laExpectedPaths.Add($laPath)
      $laPathBytes = $script:CrgUtf8NoBom.GetBytes($laPath)
      $laInput.Write($laPathBytes, 0, $laPathBytes.Length); $laInput.WriteByte(0)
    }
    foreach ($laAttribute in $laAttributes) { [void]$laExpectedAttributes.Add($laAttribute) }
    [byte[]]$laInputBytes = $laInput.ToArray()
  } finally { $laInput.Dispose() }

  $laParseTriples = {
    param([byte[]]$Bytes, [string]$Label, [bool]$AllowEmpty)
    $laText = $script:CrgUtf8Strict.GetString($Bytes)
    $laParts = $laText.Split([char[]]@([char]0), [System.StringSplitOptions]::None)
    if ($laParts.Count -lt 1 -or $laParts[$laParts.Count - 1].Length -ne 0 -or (($laParts.Count - 1) % 3) -ne 0 -or
        (-not $AllowEmpty -and $laParts.Count -eq 1)) {
      throw "$Label returned malformed NUL-delimited triples"
    }
    $laMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    for ($laI = 0; $laI -lt ($laParts.Count - 1); $laI += 3) {
      $laPath = $laParts[$laI]; $laAttribute = $laParts[$laI + 1]; $laValue = $laParts[$laI + 2]
      if (-not $laExpectedPaths.Contains($laPath) -or $laAttribute -cnotmatch '\A[A-Za-z0-9_.-]+\z') {
        throw "$Label returned an unexpected path or malformed attribute name"
      }
      $laKey = "$laPath`0$laAttribute"
      if ($laMap.ContainsKey($laKey)) { throw "$Label returned duplicate key '$laPath/$laAttribute'" }
      $laMap[$laKey] = $laValue
    }
    return $laMap
  }

  # This query intentionally uses the real target repository and ambient Git
  # config/attribute domain. `check-attr` resolves precedence without invoking
  # clean or smudge commands; conversion remains confined to the immutable
  # repository-owned graph after this live override check succeeds.
  $laGitPrefix = @('--no-optional-locks', '-C', $RepoRoot, 'check-attr', '-z', '--stdin')
  $laAll = Invoke-CrgIsolatedGitProcess -IsoRoot $ScratchRoot -WorkDir $RepoRoot -GitArgs ($laGitPrefix + @('--all')) -InputBytes $laInputBytes -UseAmbientConfig -UseAmbientAttributes -MaxOutputBytes 1048576
  if ($laAll.Exit -ne 0 -or $laAll.ErrorText.Length -ne 0) { throw "live target check-attr --all failed (exit $($laAll.Exit)): $($laAll.Text.Trim())" }
  $laAllMap = & $laParseTriples $laAll.Bytes 'live target check-attr --all' $true
  foreach ($laKey in @($laAllMap.Keys)) {
    $laSeparator = $laKey.IndexOf([char]0)
    if ($laSeparator -lt 1) { throw 'live target check-attr --all returned a malformed key' }
    $laAttribute = $laKey.Substring($laSeparator + 1)
    if ([System.Linq.Enumerable]::Contains([string[]]@('filter', 'ident', 'working-tree-encoding'), [string]$laAttribute, [System.StringComparer]::Ordinal) -and -not [string]::Equals($laAllMap[$laKey], 'unset', [System.StringComparison]::Ordinal)) {
      throw "live target attribute override activates '$laAttribute' for '$($laKey.Substring(0, $laSeparator))'"
    }
  }

  $laNamed = Invoke-CrgIsolatedGitProcess -IsoRoot $ScratchRoot -WorkDir $RepoRoot -GitArgs ($laGitPrefix + $laAttributes) -InputBytes $laInputBytes -UseAmbientConfig -UseAmbientAttributes -MaxOutputBytes 1048576
  if ($laNamed.Exit -ne 0 -or $laNamed.ErrorText.Length -ne 0) { throw "live target check-attr named query failed (exit $($laNamed.Exit)): $($laNamed.Text.Trim())" }
  $laNamedMap = & $laParseTriples $laNamed.Bytes 'live target check-attr named query' $false
  if ($laNamedMap.Count -ne ($laPaths.Count * $laAttributes.Count)) { throw 'live target check-attr named query returned the wrong bounded inventory' }
  foreach ($laKey in @($laNamedMap.Keys)) {
    $laSeparator = $laKey.IndexOf([char]0)
    if ($laSeparator -lt 1 -or -not $laExpectedAttributes.Contains($laKey.Substring($laSeparator + 1))) {
      throw 'live target check-attr named query returned an unexpected attribute'
    }
  }
  foreach ($laPath in $laPaths) {
    foreach ($laAttribute in $laAttributes) {
      $laKey = "$laPath`0$laAttribute"
      $laNamedValue = $laNamedMap[$laKey]
      if (([string]::Equals($laNamedValue, 'unspecified', [System.StringComparison]::Ordinal) -and $laAllMap.ContainsKey($laKey)) -or
          (-not [string]::Equals($laNamedValue, 'unspecified', [System.StringComparison]::Ordinal) -and (-not $laAllMap.ContainsKey($laKey) -or -not [string]::Equals($laAllMap[$laKey], $laNamedValue, [System.StringComparison]::Ordinal)))) {
        throw "live target check-attr queries disagreed for '$laPath/$laAttribute'"
      }
    }
    if (-not [string]::Equals($laNamedMap["$laPath`0text"], 'set', [System.StringComparison]::Ordinal) -or -not [string]::Equals($laNamedMap["$laPath`0eol"], 'lf', [System.StringComparison]::Ordinal)) {
      throw "live target attribute override prevents '$laPath' from resolving to text=set and eol=lf"
    }
    foreach ($laUnsafe in @('filter', 'ident', 'working-tree-encoding')) {
      if (-not ([string]::Equals($laNamedMap["$laPath`0$laUnsafe"], 'unset', [System.StringComparison]::Ordinal) -or [string]::Equals($laNamedMap["$laPath`0$laUnsafe"], 'unspecified', [System.StringComparison]::Ordinal))) {
        throw "live target attribute override activates '$laUnsafe' for '$laPath'"
      }
    }
  }

  Assert-CrgProspectiveLiveInstallValuesAttributeOverrides -RepoRoot $RepoRoot -ScratchRoot $ScratchRoot -AttributeBuffers $AttributeBuffers -ObjectIdLength $ObjectIdLength
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
# predicates retain that type distinction. The eight pathspecs per path below
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

function Get-CrgInstallValuesRootAttributeCandidate {
  param(
    [string]$RepoRoot,
    [string[]]$RequiredRules,
    [switch]$AppendMissing,
    [AllowEmptyCollection()][byte[]]$RootBytes
  )
  $crgAcPath = Join-Path $RepoRoot '.gitattributes'
  if ($PSBoundParameters.ContainsKey('RootBytes')) {
    if ($null -eq $RootBytes -or $RootBytes.Length -gt 1048576) { throw 'retained root .gitattributes bytes are null or exceed 1048576 bytes' }
    [byte[]]$crgAcOriginal = $RootBytes
  } else {
    $crgAcSnapshot = Read-CrgRootedFileBytesExact -Path $crgAcPath -Label 'root .gitattributes' -MaxLength 1048576
    [byte[]]$crgAcOriginal = if ($crgAcSnapshot.State -ceq 'held') { $crgAcSnapshot.Bytes } else { New-Object byte[] 0 }
  }
  $crgAcOffset = 0
  $crgAcEncoding = New-Object System.Text.UTF8Encoding($false, $true)
  if ($crgAcOriginal.Length -ge 3 -and $crgAcOriginal[0] -eq 0xEF -and $crgAcOriginal[1] -eq 0xBB -and $crgAcOriginal[2] -eq 0xBF) {
    $crgAcOffset = 3
  } elseif ($crgAcOriginal.Length -ge 2 -and $crgAcOriginal[0] -eq 0xFF -and $crgAcOriginal[1] -eq 0xFE) {
    $crgAcOffset = 2
    $crgAcEncoding = New-Object System.Text.UnicodeEncoding($false, $false, $true)
  } elseif ($crgAcOriginal.Length -ge 2 -and $crgAcOriginal[0] -eq 0xFE -and $crgAcOriginal[1] -eq 0xFF) {
    $crgAcOffset = 2
    $crgAcEncoding = New-Object System.Text.UnicodeEncoding($true, $false, $true)
  }
  try { $crgAcText = $crgAcEncoding.GetString($crgAcOriginal, $crgAcOffset, $crgAcOriginal.Length - $crgAcOffset) }
  catch { throw "root .gitattributes cannot be decoded without substitution: $($_.Exception.Message)" }

  $crgAcLines = if ($crgAcText.Length -eq 0) { @() } else { @($crgAcText -split "`r?`n") }
  $crgAcMissing = New-Object 'System.Collections.Generic.List[string]'
  foreach ($crgAcRule in @($RequiredRules)) {
    $crgAcFound = $false
    foreach ($crgAcLine in $crgAcLines) {
      if ([string]::Equals($crgAcLine, $crgAcRule, [System.StringComparison]::Ordinal)) { $crgAcFound = $true; break }
    }
    if (-not $crgAcFound) { $crgAcMissing.Add($crgAcRule) | Out-Null }
  }
  if ($crgAcMissing.Count -eq 0) { return ,([byte[]]$crgAcOriginal) }
  if (-not $AppendMissing) { throw "root .gitattributes lacks exact required record(s): $($crgAcMissing -join '; ')" }

  $crgAcPrefix = if ($crgAcOriginal.Length -eq 0) { '' } else { "`n" }
  $crgAcBlock = $crgAcPrefix + '# cross-review-gate: exact checkout rules for installed gate surfaces' + "`n" + (($crgAcMissing.ToArray() -join "`n") + "`n")
  [byte[]]$crgAcAppend = $crgAcEncoding.GetBytes($crgAcBlock)
  if ([int64]$crgAcOriginal.Length + [int64]$crgAcAppend.Length -gt 1048576) { throw 'prospective root .gitattributes exceeds 1048576 bytes' }
  $crgAcStream = New-Object System.IO.MemoryStream
  try {
    if ($crgAcOriginal.Length -gt 0) { $crgAcStream.Write($crgAcOriginal, 0, $crgAcOriginal.Length) }
    $crgAcStream.Write($crgAcAppend, 0, $crgAcAppend.Length)
    return ,([byte[]]$crgAcStream.ToArray())
  } finally { $crgAcStream.Dispose() }
}

# Prove the named install-values checkout contract in an isolated attribute
# graph. Ambient system/global/info attributes and filters never participate.
function Assert-CrgInstallValuesAttributeGraph {
  param(
    [string]$RepoRoot,
    [string]$ScratchRoot,
    [string]$GitRepoRoot = $RepoRoot,
    [switch]$AppendMissing,
    [hashtable]$RetainedAttributeBuffers,
    [switch]$PassThruProof
  )
  $crgAgPaths = @(
    'CROSS-REVIEW-VALUES.md',
    'scripts/codex/review-prompt-template.md',
    'docs/AGENTS.md.template'
  )
  $crgAgRules = @(
    'CROSS-REVIEW-VALUES.md text eol=lf -filter -ident -working-tree-encoding',
    'scripts/codex/review-prompt-template.md text eol=lf -filter -ident -working-tree-encoding',
    'docs/AGENTS.md.template text eol=lf -filter -ident -working-tree-encoding'
  )
  $crgAgBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  if ($null -ne $RetainedAttributeBuffers) {
    if ($AppendMissing -or -not $RetainedAttributeBuffers.ContainsKey('.gitattributes')) { throw 'retained package attribute graph lacks one exact root source or requested target mutation' }
    foreach ($crgAgAttributePath in @($RetainedAttributeBuffers.Keys)) {
      if (-not [System.Linq.Enumerable]::Contains([string[]]@('.gitattributes', 'scripts/.gitattributes', 'scripts/codex/.gitattributes', 'docs/.gitattributes'), "$crgAgAttributePath", [System.StringComparer]::Ordinal) -or
          $RetainedAttributeBuffers[$crgAgAttributePath] -isnot [byte[]]) {
        throw "retained package attribute graph contains an invalid source '$crgAgAttributePath'"
      }
      $crgAgBuffers["$crgAgAttributePath"] = [byte[]]$RetainedAttributeBuffers[$crgAgAttributePath]
    }
    $crgAgBuffers['.gitattributes'] = Get-CrgInstallValuesRootAttributeCandidate -RepoRoot $RepoRoot -RequiredRules $crgAgRules -RootBytes ([byte[]]$crgAgBuffers['.gitattributes'])
  } else {
    $crgAgBuffers['.gitattributes'] = Get-CrgInstallValuesRootAttributeCandidate -RepoRoot $RepoRoot -RequiredRules $crgAgRules -AppendMissing:$AppendMissing
    foreach ($crgAgAttributePath in @('scripts/.gitattributes', 'scripts/codex/.gitattributes', 'docs/.gitattributes')) {
      $crgAgSnapshot = Read-CrgRootedFileBytesExact -Path (Join-Path $RepoRoot $crgAgAttributePath) -Label "attribute source '$crgAgAttributePath'" -MaxLength 1048576
      if ($crgAgSnapshot.State -ceq 'held') { $crgAgBuffers[$crgAgAttributePath] = [byte[]]$crgAgSnapshot.Bytes }
    }
  }

  $crgAgContext = $null
  try {
    $crgAgFormatRows = @(& git -C $GitRepoRoot rev-parse --show-object-format 2>$null)
    if ($LASTEXITCODE -ne 0 -or $crgAgFormatRows.Count -ne 1 -or -not ([string]::Equals("$($crgAgFormatRows[0])", 'sha1', [System.StringComparison]::Ordinal) -or [string]::Equals("$($crgAgFormatRows[0])", 'sha256', [System.StringComparison]::Ordinal))) { throw 'repository object format could not be captured' }
    $crgAgOidLength = if ([string]::Equals("$($crgAgFormatRows[0])", 'sha256', [System.StringComparison]::Ordinal)) { 64 } else { 40 }
    $crgAgContext = New-CrgPrivateAttributeContext -ScratchRoot $ScratchRoot -ObjectIdLength $crgAgOidLength
    $crgAgWriter = { param([string]$Type, [byte[]]$Bytes) Add-CrgPrivateGitObject -Context $crgAgContext -Type $Type -Bytes $Bytes }
    $crgAgTree = New-CrgGitAttributeSourceTree -AttributeBuffers $crgAgBuffers -ObjectIdLength $crgAgOidLength -WriteObject $crgAgWriter -ProbePaths $crgAgPaths
    $crgAgMap = Get-CrgPrivateAttributeMap -Context $crgAgContext -TreeOid $crgAgTree -Paths $crgAgPaths -Attributes @('text', 'eol', 'filter', 'ident', 'working-tree-encoding')
    Assert-CrgPrivateInstallValuesAttributeStates -Context $crgAgContext -TreeOid $crgAgTree -Paths $crgAgPaths
    foreach ($crgAgPath in $crgAgPaths) {
      if (-not [string]::Equals($crgAgMap["$crgAgPath`0text"], 'set', [System.StringComparison]::Ordinal) -or -not [string]::Equals($crgAgMap["$crgAgPath`0eol"], 'lf', [System.StringComparison]::Ordinal)) {
        throw "'$crgAgPath' does not resolve to text=set and eol=lf"
      }
      foreach ($crgAgUnsafe in @('filter', 'ident', 'working-tree-encoding')) {
        if (-not ([string]::Equals($crgAgMap["$crgAgPath`0$crgAgUnsafe"], 'unset', [System.StringComparison]::Ordinal) -or [string]::Equals($crgAgMap["$crgAgPath`0$crgAgUnsafe"], 'unspecified', [System.StringComparison]::Ordinal))) {
          throw "'$crgAgPath' has active $crgAgUnsafe checkout transformation '$($crgAgMap["$crgAgPath`0$crgAgUnsafe"])'"
        }
      }
    }

    $crgAgUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    [byte[]]$crgAgLf = $crgAgUtf8.GetBytes("crg-values-probe`nline-two`n")
    [byte[]]$crgAgCrlf = $crgAgUtf8.GetBytes("crg-values-probe`r`nline-two`r`n")
    $crgAgExpectedLfOid = Get-CrgGitObjectIdOfBytes -Type blob -Bytes $crgAgLf -ObjectIdLength $crgAgOidLength
    [byte[]]$crgAgSpecial = $crgAgUtf8.GetBytes(('$Id$' + "`ninstall-values-caf$([char]0x00E9)`n"))
    $crgAgSpecialOid = Add-CrgPrivateGitObject -Context $crgAgContext -Type blob -Bytes $crgAgSpecial
    $crgAgConversion = [pscustomobject]@{ AutoCrlf = 'true'; Eol = 'native'; SafeCrlf = 'false' }
    foreach ($crgAgPath in $crgAgPaths) {
      $crgAgCrlfOid = Get-CrgPrivateFilteredObjectIdOfBytes -Context $crgAgContext -TreeOid $crgAgTree -RepoPath $crgAgPath -Bytes $crgAgCrlf -Conversion $crgAgConversion
      if (-not [string]::Equals($crgAgCrlfOid, $crgAgExpectedLfOid, [System.StringComparison]::Ordinal)) { throw "'$crgAgPath' does not clean CRLF to the exact LF blob under core.autocrlf=true" }
      $crgAgCheckout = Invoke-CrgPrivateAttributeGit -Context $crgAgContext -GitArgs @("--attr-source=$crgAgTree", '-c', 'core.autocrlf=true', 'cat-file', '--filters', "--path=$crgAgPath", $crgAgSpecialOid)
      if ($crgAgCheckout.Exit -ne 0 -or $crgAgCheckout.ErrorText.Length -ne 0 -or
          -not (Compare-CrgInstallValueBytes -Left ([byte[]]$crgAgCheckout.Bytes) -Right $crgAgSpecial)) {
        throw "'$crgAgPath' does not check out strict UTF-8 LF, literal `$Id`$, and non-ASCII bytes exactly"
      }
    }
  } finally {
    if ($null -ne $crgAgContext -and -not (Close-CrgPrivateAttributeContext -Context $crgAgContext)) {
      throw 'install-values attribute proof scratch could not be exactly cleaned'
    }
  }
  if ($PassThruProof) {
    return [pscustomobject]@{
      AttributeBuffers = $crgAgBuffers
      ObjectIdLength = $crgAgOidLength
    }
  }
}

# Convert one held worktree buffer in the exact attribute domain of a captured
# commit. Only root and containing-directory .gitattributes blobs from that
# immutable tree are admitted. Mutable worktree/info/global/system attributes
# and repository filter commands never enter the private Git context; any
# transform that would require such a command or reinterpretation refuses.
function Get-CrgControlledBasePathObjectId {
  param(
    [string]$RepoRoot,
    [string]$ProofScratchRoot,
    [string]$BaseCommit,
    [string]$RepoPath,
    [byte[]]$HeldBytes
  )

  if ([string]::IsNullOrWhiteSpace($RepoRoot) -or [string]::IsNullOrWhiteSpace($ProofScratchRoot) -or
      -not [System.IO.Path]::IsPathRooted($ProofScratchRoot) -or
      $BaseCommit -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z' -or
      $RepoPath -cnotmatch '\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z' -or
      $RepoPath.StartsWith('/', [System.StringComparison]::Ordinal) -or $RepoPath.EndsWith('/', [System.StringComparison]::Ordinal) -or $null -eq $HeldBytes) {
    return $null
  }
  foreach ($bpComponent in @($RepoPath -split '/')) {
    if ([string]::Equals($bpComponent, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($bpComponent, '..', [System.StringComparison]::Ordinal)) { return $null }
  }
  try {
    $bpRepoFull = [System.IO.Path]::GetFullPath($RepoRoot)
    $bpProofFull = [System.IO.Path]::GetFullPath($ProofScratchRoot)
  } catch { return $null }
  if (Test-CrgPathWithin -Path $bpProofFull -Root $bpRepoFull) { return $null }

  $bpScratch = Join-Path $bpProofFull ("crg-bp-" + [Guid]::NewGuid().ToString('N'))
  $bpContext = $null
  $bpResult = $null
  $bpCleanupOk = $true
  try {
    & git -C $bpRepoFull cat-file -e "${BaseCommit}^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'the captured base identity is not one readable commit' }
    $bpFormatRows = @(& git -C $bpRepoFull rev-parse --show-object-format 2>$null)
    $bpExpectedFormat = if ($BaseCommit.Length -eq 64) { 'sha256' } else { 'sha1' }
    if ($LASTEXITCODE -ne 0 -or $bpFormatRows.Count -ne 1 -or -not [string]::Equals("$($bpFormatRows[0])", $bpExpectedFormat, [System.StringComparison]::Ordinal)) {
      throw 'the captured base identity does not match the repository object format'
    }

    $bpAttributePaths = New-Object 'System.Collections.Generic.List[string]'
    $bpAttributePaths.Add('.gitattributes') | Out-Null
    $bpComponents = @($RepoPath -split '/')
    $bpCursor = ''
    for ($bpI = 0; $bpI -lt ($bpComponents.Count - 1); $bpI++) {
      $bpCursor = if ($bpCursor.Length -eq 0) { $bpComponents[$bpI] } else { "$bpCursor/$($bpComponents[$bpI])" }
      $bpAttributePaths.Add("$bpCursor/.gitattributes") | Out-Null
    }

    $bpAttributeBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    foreach ($bpAttributePath in $bpAttributePaths) {
      $bpRows = @(& git -C $bpRepoFull ls-tree $BaseCommit -- $bpAttributePath 2>$null)
      if ($LASTEXITCODE -ne 0 -or $bpRows.Count -gt 1) { throw "base attribute entry '$bpAttributePath' could not be classified" }
      if ($bpRows.Count -eq 0 -or [string]::IsNullOrWhiteSpace("$($bpRows[0])")) { continue }
      $bpPattern = '^(100644|100755) blob (?<oid>[0-9a-f]{' + $BaseCommit.Length + '})\t' + [regex]::Escape($bpAttributePath) + '$'
      if ("$($bpRows[0])" -cnotmatch $bpPattern) { throw "base attribute entry '$bpAttributePath' is not one regular matching-format blob" }
      $bpAttributeOid = $Matches['oid']
      [byte[]]$bpAttributeBytes = Read-CrgGitBlobBytes -RepoRoot $bpRepoFull -Oid $bpAttributeOid -MaxLength 1048576
      if ((Get-CrgGitObjectIdOfBytes -Type blob -Bytes $bpAttributeBytes -ObjectIdLength $BaseCommit.Length) -cne $bpAttributeOid) {
        throw "base attribute entry '$bpAttributePath' did not match its captured object identity"
      }
      $bpAttributeBuffers[$bpAttributePath] = $bpAttributeBytes
    }

    $bpConversion = Get-CrgGitConversionSettings -RepoRoot $bpRepoFull
    $bpContext = New-CrgPrivateAttributeContext -ScratchRoot $bpScratch -ObjectIdLength $BaseCommit.Length
    $bpWriter = { param([string]$Type, [byte[]]$Bytes) Add-CrgPrivateGitObject -Context $bpContext -Type $Type -Bytes $Bytes }
    $bpTree = New-CrgGitAttributeSourceTree -AttributeBuffers $bpAttributeBuffers -ObjectIdLength $BaseCommit.Length -WriteObject $bpWriter
    $bpSpecified = Get-CrgPrivateSpecifiedAttributeMap -Context $bpContext -TreeOid $bpTree -Paths @($RepoPath)
    foreach ($bpSpecifiedKey in $bpSpecified.Keys) {
      $bpSpecifiedAttribute = "$bpSpecifiedKey".Substring("$bpSpecifiedKey".IndexOf([char]0) + 1)
      if ([System.Linq.Enumerable]::Contains([string[]]@('filter', 'ident', 'working-tree-encoding'), [string]$bpSpecifiedAttribute, [System.StringComparer]::Ordinal)) {
        throw "captured base attributes explicitly specify unsupported content transform '$bpSpecifiedAttribute' for '$RepoPath'"
      }
    }
    $bpResult = Get-CrgPrivateFilteredObjectIdOfBytes -Context $bpContext -TreeOid $bpTree -RepoPath $RepoPath -Bytes $HeldBytes -Conversion $bpConversion
  } catch {
    Write-Host "[bootstrap] ERROR: controlled base-bound identity failed for '$RepoPath' ($($_.Exception.Message))."
    $bpResult = $null
  } finally {
    if ($null -ne $bpContext -and -not (Close-CrgPrivateAttributeContext -Context $bpContext)) { $bpCleanupOk = $false }
  }
  if (-not $bpCleanupOk) {
    Write-Host '[bootstrap] ERROR: a base-bound attribute proof source could not be reacquired for exact cleanup; rejecting the identity because a namespace replacement may have supplied Git bytes.'
    return $null
  }
  return $bpResult
}

# Hash the held, pre-append root attributes in a conversion domain derived only
# from the captured BaseHead blob. Ambient info/global/system attributes and
# config are replaced by owned empty sources; unsafe content transforms refuse.
# A returned OID can therefore be compared directly with the BaseHead blob OID
# without laundering a worktree edit through a mutable clean filter.
function Get-CrgControlledLegacyAttributeOid {
  param(
    [string]$RepoRoot,
    [string]$ProofScratchRoot,
    [string]$BaseHead,
    [string]$BaseAttributeOid,
    [byte[]]$HeldBytes
  )

  if ([string]::IsNullOrWhiteSpace($ProofScratchRoot) -or -not [System.IO.Path]::IsPathRooted($ProofScratchRoot) -or
      $BaseHead -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z' -or
      $BaseAttributeOid -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z' -or
      $BaseHead.Length -ne $BaseAttributeOid.Length -or $null -eq $HeldBytes) { return $null }
  # Keep Git's explicit private GIT_DIR independent of the target Git-dir
  # length. Git for Windows rejects an explicit GIT_DIR longer than
  # PATH_MAX-40 before repository validation; a linked worktree's per-worktree
  # Git dir can already consume that budget. The caller supplies the separately
  # retained and overlap-checked proof root.
  $caScratch = Join-Path $ProofScratchRoot ("crg-ca-" + [Guid]::NewGuid().ToString('N'))
  $caContext = $null
  $caResult = $null
  $caCleanupOk = $true
  try {
    [byte[]]$caBaseAttributeBytes = Read-CrgGitBlobBytes -RepoRoot $RepoRoot -Oid $BaseAttributeOid -MaxLength 1048576
    if ((Get-CrgGitObjectIdOfBytes -Type blob -Bytes $caBaseAttributeBytes -ObjectIdLength $BaseHead.Length) -cne $BaseAttributeOid) { throw 'captured BaseHead .gitattributes bytes do not match the recorded blob identity' }
    $caConversion = Get-CrgGitConversionSettings -RepoRoot $RepoRoot
    $caContext = New-CrgPrivateAttributeContext -ScratchRoot $caScratch -ObjectIdLength $BaseHead.Length
    $caBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    $caBuffers['.gitattributes'] = [byte[]]$caBaseAttributeBytes
    $caWriter = { param([string]$Type, [byte[]]$Bytes) Add-CrgPrivateGitObject -Context $caContext -Type $Type -Bytes $Bytes }
    $caTree = New-CrgGitAttributeSourceTree -AttributeBuffers $caBuffers -ObjectIdLength $BaseHead.Length -WriteObject $caWriter
    $caSpecifiedMap = Get-CrgPrivateSpecifiedAttributeMap -Context $caContext -TreeOid $caTree -Paths @('.gitattributes')
    foreach ($caSpecifiedKey in $caSpecifiedMap.Keys) {
      $caSpecifiedAttribute = "$caSpecifiedKey".Substring("$caSpecifiedKey".IndexOf([char]0) + 1)
      if ([System.Linq.Enumerable]::Contains([string[]]@('filter', 'ident', 'working-tree-encoding'), [string]$caSpecifiedAttribute, [System.StringComparer]::Ordinal)) { throw "BaseHead .gitattributes explicitly specifies unsafe content transform '$caSpecifiedAttribute' for itself" }
    }
    $caResult = Get-CrgPrivateFilteredObjectIdOfBytes -Context $caContext -TreeOid $caTree -RepoPath '.gitattributes' -Bytes $HeldBytes -Conversion $caConversion
  } catch {
    Write-Host "[bootstrap] ERROR: controlled BaseHead .gitattributes verification failed ($($_.Exception.Message))."
    $caResult = $null
  } finally {
    if ($null -ne $caContext -and -not (Close-CrgPrivateAttributeContext -Context $caContext)) { $caCleanupOk = $false }
  }
  if (-not $caCleanupOk) {
    Write-Host '[bootstrap] ERROR: an identity-bound attribute-base proof source could not be reacquired for exact cleanup; rejecting the proof because a namespace replacement may have supplied Git bytes.'
    return $null
  }
  return $caResult
}

# Publish the one-time transition identity record consumed by the generated
# dispatcher for a pre-redesign review-kernel landing. Derivation runs in an
# atomically owned private worktree and private Git metadata directory. Candidate
# files are exact installed buffers, root attributes are the exact held result of
# bootstrap's append, ancestor attributes come only from BaseHead, and no target
# info/global/system attribute source is visible. Git still performs the pinned
# target core.autocrlf normalization, so recorded OIDs match real staging without
# letting a mutable clean filter choose the audited identity. The real index is
# never mutated.
function Publish-CrgLegacyReviewKernelTransitionRecord {
  param(
    [string]$RepoRoot,
    [string]$GitDir,
    [string]$ProofScratchRoot,
    [string]$BaseHead,
    [hashtable]$CandidateBuffers,
    [byte[]]$AttributeExpectedBytes
  )

  # The shared review files ride the same transition: the new wrappers load
  # them, so landing the wrappers without them would leave the next commit with
  # no runnable trusted reviewer.
  $trPaths = @(
    '.gitattributes',
    'scripts/git-hooks/pre-commit',
    'scripts/codex/auto-review.ps1',
    'scripts/claude/auto-review.ps1',
    'scripts/codex/review-prompt-template.md',
    'scripts/review-liveness.psm1',
    'scripts/review-common.ps1'
  )
  $trCore = @(
    'scripts/git-hooks/pre-commit',
    'scripts/codex/auto-review.ps1',
    'scripts/claude/auto-review.ps1',
    'scripts/codex/review-prompt-template.md',
    'scripts/review-liveness.psm1',
    'scripts/review-common.ps1'
  )
  if ([string]::IsNullOrWhiteSpace($ProofScratchRoot) -or -not [System.IO.Path]::IsPathRooted($ProofScratchRoot)) {
    Write-Host '[bootstrap] ERROR: the legacy transition proof root is not one absolute retained namespace; refusing to publish an identity record.'
    return $null
  }
  if ($BaseHead -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') {
    Write-Host '[bootstrap] ERROR: the legacy transition base is not one canonical Git object ID; refusing to publish an identity record.'
    return $null
  }
  $trLiveHead = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
  if ($LASTEXITCODE -ne 0 -or -not [string]::Equals("$trLiveHead".Trim(), $BaseHead, [System.StringComparison]::Ordinal)) {
    Write-Host '[bootstrap] ERROR: HEAD changed after the legacy transition preflight; refusing to publish an identity record for a stale base.'
    return $null
  }
  & git -C $RepoRoot diff --cached --quiet --no-ext-diff --no-textconv --no-renames --ignore-submodules=none $BaseHead -- 2>$null
  if ($LASTEXITCODE -ne 0) {
    Write-Host '[bootstrap] ERROR: the real index is no longer clean at the captured legacy base; refusing to publish a transition identity record beside unrelated staged state.'
    return $null
  }

  # The transition record belongs in the target Git dir, but its ephemeral
  # private Git repository does not. Keeping the proof below the caller-retained
  # external root avoids Git for Windows' explicit-GIT_DIR length ceiling for
  # linked worktrees without changing any proof, ownership, or cleanup rule.
  $trScratch = Join-Path $ProofScratchRoot ("crg-tr-" + [Guid]::NewGuid().ToString('N'))
  $trContext = $null
  $trRecord = Join-Path $GitDir 'crg-review-kernel-transition'
  $trStage = "$trRecord.crg-new-$crgBackupStamp-$([Guid]::NewGuid().ToString('N'))"
  $trEntries = New-Object 'System.Collections.Generic.List[string]'
  $trChangedPaths = New-Object 'System.Collections.Generic.List[string]'
  $trChangedCore = 0
  $trSourceHolds = New-Object 'System.Collections.Generic.List[object]'
  $trBaseMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  $trExpectedIndexMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  $trDeriveFailed = $false
  $trCleanupOk = $true
  try {
    if ($null -eq $CandidateBuffers) { throw 'no exact installed candidate buffers were supplied' }
    foreach ($trCorePath in $trCore) {
      if (-not $CandidateBuffers.ContainsKey($trCorePath) -or $CandidateBuffers[$trCorePath] -isnot [byte[]]) {
        throw "exact installed candidate bytes are absent for '$trCorePath'"
      }
      if ($CandidateBuffers[$trCorePath].Length -gt 16777216) { throw "installed candidate '$trCorePath' exceeds the transition bound" }
      $trLive = Open-CrgLegacyRoutingHeldFile -Path (Join-Path $RepoRoot $trCorePath) -MaxLength 16777216 -ReadBytes
      if (-not (Test-CrgLegacyRoutingBytesEqual -Left $trLive.Bytes -Right $CandidateBuffers[$trCorePath])) {
        $trLive.Stream.Dispose()
        throw "installed review-kernel path '$trCorePath' no longer matches the exact bytes this transaction installed"
      }
      $trSourceHolds.Add($trLive.Stream) | Out-Null
    }

    foreach ($trPath in $trPaths) {
      $trBaseRows = @(& git -C $RepoRoot ls-tree $BaseHead -- $trPath 2>$null)
      if ($LASTEXITCODE -ne 0 -or $trBaseRows.Count -gt 1) { throw "base-tree entry for '$trPath' could not be classified" }
      if ($trBaseRows.Count -eq 0 -or [string]::IsNullOrWhiteSpace("$($trBaseRows[0])")) {
        $trBaseMap[$trPath] = [pscustomobject]@{ Present = $false; Mode = ''; Oid = '' }
      } else {
        $trBasePattern = '^(?<mode>100644|100755) blob (?<oid>[0-9a-f]{40}([0-9a-f]{24})?)\t' + [regex]::Escape($trPath) + '$'
        if ("$($trBaseRows[0])" -cnotmatch $trBasePattern -or $Matches['oid'].Length -ne $BaseHead.Length) { throw "base-tree entry for '$trPath' was not one regular matching-format blob" }
        $trBaseMap[$trPath] = [pscustomobject]@{ Present = $true; Mode = $Matches['mode']; Oid = $Matches['oid'] }
      }
    }

    $trConversion = Get-CrgGitConversionSettings -RepoRoot $RepoRoot
    $trContext = New-CrgPrivateAttributeContext -ScratchRoot $trScratch -ObjectIdLength $BaseHead.Length
    $trAttributeBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    if ($null -ne $AttributeExpectedBytes) { $trAttributeBuffers['.gitattributes'] = [byte[]]$AttributeExpectedBytes }
    foreach ($trAttrPath in @('scripts/.gitattributes', 'scripts/git-hooks/.gitattributes', 'scripts/codex/.gitattributes', 'scripts/claude/.gitattributes')) {
      $trAttrRows = @(& git -C $RepoRoot ls-tree $BaseHead -- $trAttrPath 2>$null)
      if ($LASTEXITCODE -ne 0 -or $trAttrRows.Count -gt 1) { throw "trusted ancestor attributes '$trAttrPath' could not be classified at BaseHead" }
      if ($trAttrRows.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace("$($trAttrRows[0])")) {
        $trAttrPattern = '^(100644|100755) blob (?<oid>[0-9a-f]{40}([0-9a-f]{24})?)\t' + [regex]::Escape($trAttrPath) + '$'
        if ("$($trAttrRows[0])" -cnotmatch $trAttrPattern -or $Matches['oid'].Length -ne $BaseHead.Length) { throw "trusted ancestor attributes '$trAttrPath' is not one regular matching-format blob" }
        [byte[]]$trAttrBytes = Read-CrgGitBlobBytes -RepoRoot $RepoRoot -Oid $Matches['oid'] -MaxLength 1048576
        if ((Get-CrgGitObjectIdOfBytes -Type blob -Bytes $trAttrBytes -ObjectIdLength $BaseHead.Length) -cne $Matches['oid']) { throw "trusted ancestor attributes '$trAttrPath' did not match its BaseHead object identity" }
        $trAttributeBuffers[$trAttrPath] = $trAttrBytes
      }
    }
    $trAttributeWriter = { param([string]$Type, [byte[]]$Bytes) Add-CrgPrivateGitObject -Context $trContext -Type $Type -Bytes $Bytes }
    $trValuesOutputPath = 'scripts/codex/review-prompt-template.md'
    $trAttributeTree = New-CrgGitAttributeSourceTree -AttributeBuffers $trAttributeBuffers -ObjectIdLength $BaseHead.Length -WriteObject $trAttributeWriter -ProbePaths @($trValuesOutputPath)
    $trAddPaths = @($trCore)
    if ($null -ne $AttributeExpectedBytes) {
      $trAddPaths = @('.gitattributes') + $trAddPaths
    }
    Assert-CrgPrivateInstallValuesAttributeStates -Context $trContext -TreeOid $trAttributeTree -Paths @($trValuesOutputPath)
    $trSpecifiedMap = Get-CrgPrivateSpecifiedAttributeMap -Context $trContext -TreeOid $trAttributeTree -Paths $trAddPaths
    foreach ($trSpecifiedKey in $trSpecifiedMap.Keys) {
      $trSpecifiedPath = "$trSpecifiedKey".Substring(0, "$trSpecifiedKey".IndexOf([char]0))
      $trSpecifiedAttribute = "$trSpecifiedKey".Substring("$trSpecifiedKey".IndexOf([char]0) + 1)
      if (-not [string]::Equals($trSpecifiedPath, $trValuesOutputPath, [System.StringComparison]::Ordinal) -and
          [System.Linq.Enumerable]::Contains([string[]]@('filter', 'ident', 'working-tree-encoding'), [string]$trSpecifiedAttribute, [System.StringComparer]::Ordinal)) {
        throw "private transition path explicitly specifies unsafe content-transform attribute '$trSpecifiedAttribute'"
      }
    }
    $trAttrMap = Get-CrgPrivateAttributeMap -Context $trContext -TreeOid $trAttributeTree -Paths $trAddPaths -Attributes @('text', 'eol')
    if (-not [string]::Equals($trAttrMap["scripts/git-hooks/pre-commit`0text"], 'set', [System.StringComparison]::Ordinal) -or -not [string]::Equals($trAttrMap["scripts/git-hooks/pre-commit`0eol"], 'lf', [System.StringComparison]::Ordinal)) {
      throw 'the private transition hook does not resolve the exact installer-authored text=set/eol=lf contract'
    }
    $trSignatures = @('crg_pm_staged_touches_declaration', 'function Test-ProjectModeBranchRange', 'Green is campaign-anchored')
    foreach ($trCorePath in $trCore) {
      foreach ($trSignature in $trSignatures) {
        $trSignatureFound = $false
        foreach ($trEncoding in @([System.Text.Encoding]::ASCII, [System.Text.Encoding]::Unicode, [System.Text.Encoding]::BigEndianUnicode)) {
          [byte[]]$trNeedle = $trEncoding.GetBytes($trSignature)
          for ($trByteI = 0; $trByteI -le $CandidateBuffers[$trCorePath].Length - $trNeedle.Length; $trByteI++) {
            $trNeedleMatch = $true
            for ($trNeedleI = 0; $trNeedleI -lt $trNeedle.Length; $trNeedleI++) {
              if ($CandidateBuffers[$trCorePath][$trByteI + $trNeedleI] -ne $trNeedle[$trNeedleI]) { $trNeedleMatch = $false; break }
            }
            if ($trNeedleMatch) { $trSignatureFound = $true; break }
          }
          if ($trSignatureFound) { break }
        }
        if ($trSignatureFound) { throw "installed candidate review-kernel path '$trCorePath' still contains retired signature '$trSignature'" }
      }
    }
    foreach ($trAddPath in $trAddPaths) {
      [byte[]]$trCandidateBytes = if ($trAddPath -ceq '.gitattributes') { $AttributeExpectedBytes } else { $CandidateBuffers[$trAddPath] }
      $trFilteredOid = Get-CrgPrivateFilteredObjectIdOfBytes -Context $trContext -TreeOid $trAttributeTree -RepoPath $trAddPath -Bytes $trCandidateBytes -Conversion $trConversion
      $trBaseEntry = $trBaseMap[$trAddPath]
      $trAddMode = if ($trBaseEntry.Present) { $trBaseEntry.Mode } else { '100644' }
      $trExpectedIndexMap[$trAddPath] = [pscustomobject]@{ Mode = $trAddMode; Oid = $trFilteredOid }
    }

    # The transition map is derived only from exact held candidate buffers and
    # their isolated, filter-aware hashes. No mutable index is created or read:
    # a private-path replacement therefore cannot choose an authorized OID.
    foreach ($trPath in $trAddPaths) {
      $trExpectedEntry = $trExpectedIndexMap[$trPath]
      $trMode = $trExpectedEntry.Mode
      $trOid = $trExpectedEntry.Oid

      $trBaseEntry = $trBaseMap[$trPath]
      $trSame = $trBaseEntry.Present -and
        [string]::Equals($trMode, $trBaseEntry.Mode, [System.StringComparison]::Ordinal) -and
        [string]::Equals($trOid, $trBaseEntry.Oid, [System.StringComparison]::Ordinal)
      if (-not $trSame) {
        $trEntries.Add("entry: $trMode $trOid $trPath") | Out-Null
        $trChangedPaths.Add($trPath) | Out-Null
        if ([System.Linq.Enumerable]::Contains([string[]]@($trCore), [string]$trPath, [System.StringComparer]::Ordinal)) { $trChangedCore++ }
      }
    }
  } catch {
    Write-Host "[bootstrap] ERROR: could not derive the legacy review-kernel transition identity ($($_.Exception.Message)). No identity record was published."
    $trDeriveFailed = $true
  } finally {
    foreach ($trSourceHold in $trSourceHolds) { if ($null -ne $trSourceHold) { try { $trSourceHold.Dispose() } catch { } } }
    if ($null -ne $trContext -and -not (Close-CrgPrivateAttributeContext -Context $trContext)) { $trCleanupOk = $false }
  }
  if (-not $trCleanupOk) {
    Write-Host '[bootstrap] ERROR: an identity-bound transition proof source could not be reacquired for exact cleanup; rejecting the derivation because a namespace replacement may have supplied Git bytes.'
    return $null
  }
  if ($trDeriveFailed) { return $null }

  if ($trChangedCore -lt 1) {
    Write-Host '[bootstrap] ERROR: trusted HEAD was classified as legacy, but the installed candidate changes no review-kernel blob. No transition can retire the detected policy, so no identity record was published.'
    return $null
  }

  $trLines = @('crg-review-kernel-transition v1', "base: $BaseHead") + @($trEntries)
  $trBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($trLines -join "`n") + "`n"))
  $trExisting = $null
  $trPublished = $null
  $trStageFs = $null
  $trStagePublished = $false
  try {
    $trKind = Get-CrgPathOccupantKind -Path $trRecord
    if ([string]::Equals($trKind, 'file', [System.StringComparison]::Ordinal)) {
      $trExisting = Open-CrgLegacyRoutingHeldFile -Path $trRecord -MaxLength 2048 -ReadBytes
      if (-not (Test-CrgLegacyRoutingBytesEqual -Left $trExisting.Bytes -Right $trBytes)) {
        throw 'an existing transition record differs from the exact record derived for this base and candidate'
      }
      return [pscustomobject]@{ RecordPath = $trRecord; Paths = @($trChangedPaths); BaseHead = $BaseHead; Reused = $true; Hold = $trExisting }
    }
    if (-not [string]::Equals($trKind, 'empty', [System.StringComparison]::Ordinal)) {
      throw "transition-record path has occupant kind $trKind"
    }
    $trStageH = $null
    $trStageErr = 0
    try {
      $trStageH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($trStage, [ref]$trStageErr)
      if ($null -eq $trStageH -or $trStageH.IsInvalid) { throw "transition stage create-new failed (Win32 error $trStageErr)" }
      $trStageFs = New-Object System.IO.FileStream($trStageH, [System.IO.FileAccess]::ReadWrite)
      $trStageH = $null
      $trStageFs.Write($trBytes, 0, $trBytes.Length)
      $trStageFs.Flush($true)
      $trStageFs.Position = 0
      $trBack = New-Object byte[] $trBytes.Length
      $trRead = 0
      while ($trRead -lt $trBack.Length) {
        $trGot = $trStageFs.Read($trBack, $trRead, $trBack.Length - $trRead)
        if ($trGot -le 0) { break }
        $trRead += $trGot
      }
      if ($trRead -ne $trBytes.Length -or $trStageFs.Length -ne $trBytes.Length) { throw 'staged record did not read back at the expected length' }
      for ($trI = 0; $trI -lt $trBytes.Length; $trI++) {
        if ($trBack[$trI] -ne $trBytes[$trI]) { throw 'staged record did not read back byte-for-byte' }
      }
      $trStageFs.Position = 0
    } finally {
      if ($null -ne $trStageH -and -not $trStageH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $trStage -Handle $trStageH -Label 'transition record stage' }
    }
    $trHeadBeforePublish = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not [string]::Equals("$trHeadBeforePublish".Trim(), $BaseHead, [System.StringComparison]::Ordinal)) {
      throw 'HEAD changed before transition publication; the exact owned stage will be removed without publishing an identity'
    }
    $trRenameErr = 0
    if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($trStageFs.SafeFileHandle, $trStage, $trRecord, [ref]$trRenameErr))) {
      throw "same-handle create-new record publication failed (Win32 error $trRenameErr); any destination occupant is preserved"
    }
    $trStagePublished = $true
    $trPublished = [pscustomobject]@{ Stream = $trStageFs; Length = $trBytes.Length; Hash = (Get-CrgSha256HexOfBytes -Bytes $trBytes); Bytes = $trBytes; Path = $trRecord }
    $trStageFs = $null
    $trHeadAfterPublish = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not [string]::Equals("$trHeadAfterPublish".Trim(), $BaseHead, [System.StringComparison]::Ordinal)) {
      $trRemoved = Remove-CrgOwnedScratchHandle -Path $trRecord -Stream $trPublished.Stream -Label 'newly published transition record after HEAD movement'
      $trPublished = $null
      if (-not $trRemoved) { throw "HEAD changed during transition publication; the exact published record could not be removed and remains at '$trRecord'" }
      throw 'HEAD changed during transition publication; the exact newly published identity was removed'
    }
  } catch {
    if ($null -ne $trExisting -and $null -ne $trExisting.Stream) { try { $trExisting.Stream.Dispose() } catch { } }
    if ($null -ne $trPublished -and $null -ne $trPublished.Stream) { try { $trPublished.Stream.Dispose() } catch { } }
    Write-Host "[bootstrap] ERROR: could not publish the legacy review-kernel transition identity record at '$trRecord' ($($_.Exception.Message))."
    return $null
  } finally {
    if ($null -ne $trStageFs) {
      if ($trStagePublished) { try { $trStageFs.Dispose() } catch { } }
      else { $null = Remove-CrgOwnedScratchHandle -Path $trStage -Stream $trStageFs -Label 'transition record stage' }
      $trStageFs = $null
    }
  }

  return [pscustomobject]@{ RecordPath = $trRecord; Paths = @($trChangedPaths); BaseHead = $BaseHead; Reused = $false; Hold = $trPublished }
}

# Preserve only the pre-hook routing drivers a self-hosted legacy transition
# must temporarily restore/remove. The custody directory is bound to the base
# OID, lives outside the worktree, and never becomes a package input. Source
# bytes come only from the already-proven package snapshot; every custody copy,
# strict record, and phase-A Git identity is held through transition publication.
function Publish-CrgLegacyRoutingDriverCustody {
  param(
    [string]$RepoRoot,
    [string]$GitDir,
    [string]$BaseHead,
    [hashtable]$SourceBuffers
  )

  $cuMaps = @(
    @{ RepoPath = 'scripts/codex/commit.ps1';  FileName = 'codex-commit.ps1' },
    @{ RepoPath = 'scripts/claude/commit.ps1'; FileName = 'claude-commit.ps1' },
    @{ RepoPath = 'scripts/run-gate.sh';       FileName = 'run-gate.sh' }
  )
  if ($BaseHead -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') {
    Write-Host '[bootstrap] ERROR: cannot bind self-host routing custody to a non-canonical base OID.'
    return $null
  }
  $cuDir = Join-Path $GitDir ("crg-review-kernel-routing-custody-$BaseHead")
  $cuRecord = Join-Path $cuDir 'custody-record'
  $cuStageDir = "$cuDir.crg-new-$([Guid]::NewGuid().ToString('N'))"
  $cuStageRecord = Join-Path $cuStageDir 'custody-record'
  $cuActive = Join-Path $GitDir 'crg-review-kernel-routing-custody-active'
  $cuActiveStage = "$cuActive.crg-new-$([Guid]::NewGuid().ToString('N'))"
  $cuPayloads = @()
  $cuEntries = @()
  $cuOwnsStage = $false
  $cuStageReleased = $false
  $cuStageDirHandle = $null
  $cuOwnedStageFiles = @()
  $cuActiveStageFs = $null
  $cuActivePublished = $false
  $cuLease = $null
  $cuActiveCustody = $null
  $cuHasExactInventory = {
    param([string]$Directory)
    try { $cuNames = @([System.IO.Directory]::GetFileSystemEntries($Directory) | ForEach-Object { [System.IO.Path]::GetFileName($_) }) } catch { return $false }
    $cuExpectedNames = @('custody-record') + @($cuMaps | ForEach-Object { $_.FileName })
    if ($cuNames.Count -ne $cuExpectedNames.Count) { return $false }
    foreach ($cuExpectedName in $cuExpectedNames) {
      if (@($cuNames | Where-Object { [string]::Equals("$_", $cuExpectedName, [System.StringComparison]::Ordinal) }).Count -ne 1) { return $false }
    }
    return $true
  }

  try {
    foreach ($cuMap in $cuMaps) {
      if ($null -eq $SourceBuffers -or -not $SourceBuffers.ContainsKey($cuMap.RepoPath) -or
          $SourceBuffers[$cuMap.RepoPath] -isnot [byte[]]) {
        throw "the buffered package snapshot lacks routing source '$($cuMap.RepoPath)'"
      }
      [byte[]]$cuSourceBytes = $SourceBuffers[$cuMap.RepoPath]
      if ($cuSourceBytes.Length -gt 16777216) {
        throw "routing source '$($cuMap.RepoPath)' exceeds the 16777216-byte recovery bound"
      }
      $cuSourceHash = Get-CrgSha256HexOfBytes -Bytes $cuSourceBytes
      $cuBaseRows = @(& git -C $RepoRoot ls-tree $BaseHead -- $cuMap.RepoPath 2>$null)
      if ($LASTEXITCODE -ne 0 -or $cuBaseRows.Count -gt 1) { throw "base phase-A state for '$($cuMap.RepoPath)' could not be classified" }
      $cuBasePresent = $false
      $cuBaseMode = $null
      $cuBaseOid = $null
      if ($cuBaseRows.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace("$($cuBaseRows[0])")) {
        $cuBasePattern = '^(?<mode>100644|100755) blob (?<oid>[0-9a-f]{40}([0-9a-f]{24})?)\t' + [regex]::Escape($cuMap.RepoPath) + '$'
        if ("$($cuBaseRows[0])" -cnotmatch $cuBasePattern) { throw "base phase-A state for '$($cuMap.RepoPath)' is not one regular blob" }
        $cuBasePresent = $true
        $cuBaseMode = $Matches['mode']
        $cuBaseOid = $Matches['oid']
        if ($cuBaseOid.Length -ne $BaseHead.Length) { throw "base phase-A object for '$($cuMap.RepoPath)' has the wrong object format" }
      }
      $cuPayloads += @{ Map = $cuMap; Bytes = $cuSourceBytes; Hash = $cuSourceHash }
      $cuEntries += [pscustomobject]@{ RepoPath = $cuMap.RepoPath; FileName = $cuMap.FileName; Hash = $cuSourceHash; CustodyPath = (Join-Path $cuDir $cuMap.FileName); BasePresent = $cuBasePresent; BaseMode = $cuBaseMode; BaseOid = $cuBaseOid }
    }

    $cuLines = @('crg-review-kernel-routing-custody v1', "base: $BaseHead")
    foreach ($cuEntry in $cuEntries) {
      if ($cuEntry.BasePresent) { $cuLines += "phase-a: present $($cuEntry.BaseMode) $($cuEntry.BaseOid) $($cuEntry.RepoPath)" }
      else { $cuLines += "phase-a: absent - - $($cuEntry.RepoPath)" }
      $cuLines += "sha256: $($cuEntry.Hash) $($cuEntry.FileName) $($cuEntry.RepoPath)"
    }
    $cuBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($cuLines -join "`n") + "`n"))
    $cuExpectedRecordHash = Get-CrgSha256HexOfBytes -Bytes $cuBytes

    $cuKind = Get-CrgPathOccupantKind -Path $cuDir
    $cuReusedDirectory = [string]::Equals($cuKind, 'directory', [System.StringComparison]::Ordinal)
    if ([string]::Equals($cuKind, 'directory', [System.StringComparison]::Ordinal)) {
      if (-not (& $cuHasExactInventory $cuDir)) { throw "existing base-bound custody directory '$cuDir' does not have the exact owned inventory" }
    } elseif ([string]::Equals($cuKind, 'empty', [System.StringComparison]::Ordinal)) {
      if (-not [string]::Equals((Get-CrgPathOccupantKind -Path $cuStageDir), 'empty', [System.StringComparison]::Ordinal)) { throw "unique custody staging path '$cuStageDir' is occupied" }
      $cuDirCreateErr = 0
      $cuStageDirHandle = [CrgBootstrap.NativeV4]::CreateOwnedDirectoryAtomic($cuStageDir, [ref]$cuDirCreateErr)
      if ($null -eq $cuStageDirHandle -or $cuStageDirHandle.IsInvalid) { throw "atomic custody staging-directory create-and-hold failed (Win32 error $cuDirCreateErr); any occupant that won the name is preserved" }
      $cuOwnsStage = $true
      $cuAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($cuStageDirHandle)
      if ($cuAttrs -lt 0 -or ($cuAttrs -band 0x410) -ne 0x10) { throw "new custody staging path '$cuStageDir' is not one plain held directory" }
      if (-not [CrgBootstrap.NativeV4]::RegisterRootedIo($cuStageDir, $cuStageDirHandle, $true)) { throw 'custody staging directory could not be registered as a retained rooted namespace' }
      foreach ($cuItem in $cuPayloads) {
        $cuEntry = @($cuEntries | Where-Object { $_.RepoPath -ceq $cuItem.Map.RepoPath })[0]
        $cuStagePath = Join-Path $cuStageDir $cuEntry.FileName
        $cuNew = $null
        $cuOut = $null
        $cuNewErr = 0
        try {
          $cuNew = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($cuStagePath, [ref]$cuNewErr)
          if ($null -eq $cuNew -or $cuNew.IsInvalid) { throw "custody create-new failed for '$cuStagePath' (Win32 error $cuNewErr)" }
          $cuOut = New-Object System.IO.FileStream($cuNew, [System.IO.FileAccess]::ReadWrite)
          $cuNew = $null
          $cuOwnedStageFiles += [pscustomobject]@{ Path = $cuStagePath; Stream = $cuOut; Label = "custody payload '$($cuEntry.RepoPath)'" }
          $cuOut.Write($cuItem.Bytes, 0, $cuItem.Bytes.Length)
          $cuOut.Flush($true)
          $cuOut.Position = 0
          $cuOutSha = [System.Security.Cryptography.SHA256]::Create()
          try { $cuOutHash = ([System.BitConverter]::ToString($cuOutSha.ComputeHash($cuOut)) -replace '-', '').ToLowerInvariant() } finally { $cuOutSha.Dispose() }
          if ($cuOut.Length -ne $cuItem.Bytes.Length -or $cuOutHash -cne $cuItem.Hash) { throw "custody held readback failed for '$($cuEntry.RepoPath)'" }
          $cuOut.Position = 0
          $cuOut = $null
        } finally {
          if ($null -ne $cuOut) { $cuOut.Dispose() }
          elseif ($null -ne $cuNew -and -not $cuNew.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $cuStagePath -Handle $cuNew -Label "custody payload '$($cuEntry.RepoPath)'" }
        }
      }
      $cuRecH = $null
      $cuRecFs = $null
      $cuRecErr = 0
      try {
        $cuRecH = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($cuStageRecord, [ref]$cuRecErr)
        if ($null -eq $cuRecH -or $cuRecH.IsInvalid) { throw "custody record create-new failed (Win32 error $cuRecErr)" }
        $cuRecFs = New-Object System.IO.FileStream($cuRecH, [System.IO.FileAccess]::ReadWrite)
        $cuRecH = $null
        $cuOwnedStageFiles += [pscustomobject]@{ Path = $cuStageRecord; Stream = $cuRecFs; Label = 'custody record stage' }
        $cuRecFs.Write($cuBytes, 0, $cuBytes.Length)
        $cuRecFs.Flush($true)
        $cuRecFs.Position = 0
        $cuRecSha = [System.Security.Cryptography.SHA256]::Create()
        try { $cuRecHash = ([System.BitConverter]::ToString($cuRecSha.ComputeHash($cuRecFs)) -replace '-', '').ToLowerInvariant() } finally { $cuRecSha.Dispose() }
        if ($cuRecFs.Length -ne $cuBytes.Length -or $cuRecHash -cne $cuExpectedRecordHash) { throw 'custody record failed held readback' }
        $cuRecFs.Position = 0
        $cuRecFs = $null
      } finally {
        if ($null -ne $cuRecFs) { $cuRecFs.Dispose() }
        elseif ($null -ne $cuRecH -and -not $cuRecH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $cuStageRecord -Handle $cuRecH -Label 'custody record stage' }
      }
      if (-not (& $cuHasExactInventory $cuStageDir)) { throw 'new custody staging directory failed its exact held inventory proof' }

      # A random stage has no authority. After every owned child is durable, the
      # same retained directory handle publishes the complete bundle relative to
      # the pinned Git-directory namespace. A crash before the rename leaves only
      # an ignorable random remnant; a failure exact-cleans only held objects.
      foreach ($cuOwnedStageFile in $cuOwnedStageFiles) {
        if ($null -ne $cuOwnedStageFile.Stream) { $cuOwnedStageFile.Stream.Dispose(); $cuOwnedStageFile.Stream = $null }
      }
      $cuDirRenameErr = 0
      [CrgBootstrap.NativeV4]::UnregisterRootedIo($cuStageDir, $cuStageDirHandle)
      if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($cuStageDirHandle, $cuStageDir, $cuDir, [ref]$cuDirRenameErr))) {
        throw "same-handle custody-directory publication failed (error $cuDirRenameErr)"
      }
      $cuStageDirHandle.Dispose()
      $cuStageDirHandle = $null
      $cuStageReleased = $true
      $cuOwnsStage = $false
    } else {
      throw "custody path '$cuDir' has a non-directory occupant ($cuKind)"
    }

    # The directory record and every custody source are opened and retained
    # before the fixed active name becomes visible. Existing epochs are admitted
    # only when those held identities exactly match the buffered package bytes.
    $cuCustodyData = [pscustomobject]@{
      BaseHead = $BaseHead; Directory = $cuDir; RecordPath = $cuActive
      RecordHash = $cuExpectedRecordHash; Bytes = $cuBytes; Entries = $cuEntries
      Hold = $null
    }
    $cuLease = Assert-CrgLegacyRoutingDriverCustodyEpoch -RepoRoot $RepoRoot -Custody $cuCustodyData
    if (-not (& $cuHasExactInventory $cuDir)) { throw 'base-bound custody inventory changed after its held content proof' }

    $cuActiveKind = Get-CrgPathOccupantKind -Path $cuActive
    $cuReusedActive = [string]::Equals($cuActiveKind, 'file', [System.StringComparison]::Ordinal)
    if ([string]::Equals($cuActiveKind, 'file', [System.StringComparison]::Ordinal)) {
      $cuActiveCustody = Read-CrgLegacyRoutingDriverCustodyRecord -RecordPath $cuActive -GitDir $GitDir
      $cuLease.Custody = $cuActiveCustody
      if ($cuActiveCustody.RecordHash -cne $cuExpectedRecordHash -or
          -not (Test-CrgLegacyRoutingBytesEqual -Left $cuActiveCustody.Bytes -Right $cuBytes)) {
        throw "existing active-custody record '$cuActive' belongs to a different epoch"
      }
    } elseif ([string]::Equals($cuActiveKind, 'empty', [System.StringComparison]::Ordinal)) {
      $cuActiveH = $null
      $cuActiveErr = 0
      try {
        $cuActiveH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($cuActiveStage, [ref]$cuActiveErr)
        if ($null -eq $cuActiveH -or $cuActiveH.IsInvalid) { throw "active-custody stage create-new failed (Win32 error $cuActiveErr)" }
        $cuActiveStageFs = New-Object System.IO.FileStream($cuActiveH, [System.IO.FileAccess]::ReadWrite)
        $cuActiveH = $null
        $cuActiveStageFs.Write($cuBytes, 0, $cuBytes.Length)
        $cuActiveStageFs.Flush($true)
        $cuActiveStageFs.Position = 0
        $cuActiveBack = New-Object byte[] $cuBytes.Length
        $cuActiveRead = 0
        while ($cuActiveRead -lt $cuActiveBack.Length) {
          $cuActiveGot = $cuActiveStageFs.Read($cuActiveBack, $cuActiveRead, $cuActiveBack.Length - $cuActiveRead)
          if ($cuActiveGot -le 0) { break }
          $cuActiveRead += $cuActiveGot
        }
        if ($cuActiveRead -ne $cuBytes.Length -or $cuActiveStageFs.Length -ne $cuBytes.Length -or
            -not (Test-CrgLegacyRoutingBytesEqual -Left $cuActiveBack -Right $cuBytes)) {
          throw 'active-custody stage failed held byte-for-byte readback'
        }
        $cuActiveStageFs.Position = 0
        if (-not (& $cuHasExactInventory $cuDir)) { throw 'base-bound custody inventory changed before active publication' }
        $cuActiveRenameErr = 0
        if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($cuActiveStageFs.SafeFileHandle, $cuActiveStage, $cuActive, [ref]$cuActiveRenameErr))) {
          throw "same-handle active-custody publication failed (Win32 error $cuActiveRenameErr); any destination occupant is preserved"
        }
        $cuActivePublished = $true
        $cuActiveHold = [pscustomobject]@{ Stream = $cuActiveStageFs; Length = $cuBytes.Length; Hash = $cuExpectedRecordHash; Bytes = $cuBytes; Path = $cuActive }
        $cuActiveStageFs = $null
        $cuActiveCustody = [pscustomobject]@{
          BaseHead = $BaseHead; Directory = $cuDir; RecordPath = $cuActive
          RecordHash = $cuExpectedRecordHash; Bytes = $cuBytes; Entries = $cuEntries
          Hold = $cuActiveHold
        }
        $cuLease.Custody = $cuActiveCustody
      } finally {
        if ($null -ne $cuActiveH -and -not $cuActiveH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $cuActiveStage -Handle $cuActiveH -Label 'active-custody stage' }
      }
    } else {
      throw "active-custody path '$cuActive' has occupant kind $cuActiveKind"
    }
    return [pscustomobject]@{
      Directory = $cuDir; RecordPath = $cuRecord; ActivePath = $cuActive
      Entries = $cuActiveCustody.Entries; BaseHead = $BaseHead
      Reused = ($cuReusedDirectory -and $cuReusedActive); Lease = $cuLease
    }
  } catch {
    if ($null -ne $cuLease) { Close-CrgLegacyRoutingCustodyLease -Lease $cuLease }
    if ($null -ne $cuActiveCustody -and $null -ne $cuActiveCustody.Hold -and
        ($null -eq $cuLease -or -not [object]::ReferenceEquals($cuLease.Custody, $cuActiveCustody))) {
      try { $cuActiveCustody.Hold.Stream.Dispose() } catch { }
    }
    Write-Host "[bootstrap] ERROR: self-host routing-driver custody failed ($($_.Exception.Message)). Existing paths are preserved for inspection; no transition identity record was published."
    return $null
  } finally {
    if ($null -ne $cuActiveStageFs) {
      if ($cuActivePublished) { try { $cuActiveStageFs.Dispose() } catch { } }
      else { $null = Remove-CrgOwnedScratchHandle -Path $cuActiveStage -Stream $cuActiveStageFs -Label 'active-custody stage' }
      $cuActiveStageFs = $null
    }
    if ($cuOwnsStage) {
      for ($cuCleanupI = $cuOwnedStageFiles.Count - 1; $cuCleanupI -ge 0; $cuCleanupI--) {
        $cuOwnedStageFile = $cuOwnedStageFiles[$cuCleanupI]
        if ($null -ne $cuOwnedStageFile.Stream) { $null = Remove-CrgOwnedScratchHandle -Path $cuOwnedStageFile.Path -Stream $cuOwnedStageFile.Stream -Label $cuOwnedStageFile.Label }
      }
      if ($null -ne $cuStageDirHandle) { [CrgBootstrap.NativeV4]::UnregisterRootedIo($cuStageDir, $cuStageDirHandle); $null = Remove-CrgOwnedScratchHandle -Path $cuStageDir -Handle $cuStageDirHandle -Directory -Label 'custody staging directory'; $cuStageDirHandle = $null }
    } elseif (-not $cuStageReleased -and $null -ne $cuStageDirHandle) {
      try { $cuStageDirHandle.Dispose() } catch { }
    }
  }
}

# Open one ordinary, single-link file without following a reparse point and
# keep the read exclusion alive in the returned object. Callers own Stream.
# A positive MaxLength bounds files whose grammar or in-memory recovery copy
# has a deliberately small domain.
function Open-CrgLegacyRoutingHeldFile {
  param([string]$Path, [long]$MaxLength = 0, [switch]$ReadBytes)

  $rhHandle = $null
  $rhStream = $null
  $rhError = 0
  try {
    try { $rhHandle = [CrgBootstrap.NativeV4]::OpenReadShareReadNoFollow($Path, [ref]$rhError) } catch { $rhHandle = $null; $rhError = -1 }
    if ($null -eq $rhHandle -or $rhHandle.IsInvalid) { throw "no-follow open failed (Win32 error $rhError)" }
    $rhAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($rhHandle)
    if ($rhAttrs -lt 0 -or ($rhAttrs -band 0x410) -ne 0) { throw 'the held occupant is not an ordinary file' }
    $rhLinks = [CrgBootstrap.NativeV3]::GetLinkCount($rhHandle)
    if ($rhLinks -ne 1) { throw "the held occupant has hard-link count $rhLinks" }
    $rhStream = New-Object System.IO.FileStream($rhHandle, [System.IO.FileAccess]::Read)
    $rhHandle = $null
    if ($MaxLength -gt 0 -and $rhStream.Length -gt $MaxLength) { throw "the held file exceeds the $MaxLength-byte bound" }
    $rhSha = [System.Security.Cryptography.SHA256]::Create()
    try { $rhHash = ([System.BitConverter]::ToString($rhSha.ComputeHash($rhStream)) -replace '-', '').ToLowerInvariant() } finally { $rhSha.Dispose() }
    $rhStream.Position = 0
    $rhBytes = $null
    if ($ReadBytes) {
      if ($rhStream.Length -gt [int]::MaxValue) { throw 'the held file is too large to read into a byte array' }
      $rhBytes = New-Object byte[] ([int]$rhStream.Length)
      $rhRead = 0
      while ($rhRead -lt $rhBytes.Length) {
        $rhGot = $rhStream.Read($rhBytes, $rhRead, $rhBytes.Length - $rhRead)
        if ($rhGot -le 0) { break }
        $rhRead += $rhGot
      }
      if ($rhRead -ne $rhBytes.Length) { throw 'the held file ended before its captured length' }
      $rhStream.Position = 0
    }
    $rhResult = [pscustomobject]@{ Stream = $rhStream; Length = $rhStream.Length; Hash = $rhHash; Bytes = $rhBytes; Path = $Path }
    $rhStream = $null
    return $rhResult
  } finally {
    if ($null -ne $rhStream) { $rhStream.Dispose() }
    elseif ($null -ne $rhHandle -and -not $rhHandle.IsInvalid) { $rhHandle.Dispose() }
  }
}

function Test-CrgLegacyRoutingBytesEqual {
  param([byte[]]$Left, [byte[]]$Right)
  if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
  for ($rbI = 0; $rbI -lt $Left.Length; $rbI++) { if ($Left[$rbI] -ne $Right[$rbI]) { return $false } }
  return $true
}

# Strict fixed-order parser for the machine-local routing custody record. The
# active record stays held while recovery validates the matching base directory
# record and all source copies, so a concurrent replacement cannot redirect a
# restore after validation.
function Read-CrgLegacyRoutingDriverCustodyRecord {
  param([string]$RecordPath, [string]$GitDir)

  $rrHold = Open-CrgLegacyRoutingHeldFile -Path $RecordPath -MaxLength 2048 -ReadBytes
  try {
    $rrBytes = $rrHold.Bytes
    if ($rrBytes.Length -lt 1 -or $rrBytes[$rrBytes.Length - 1] -ne 0x0A) { throw 'the record is empty or lacks its final LF' }
    foreach ($rrByte in $rrBytes) {
      if (-not ($rrByte -eq 0x0A -or ($rrByte -ge 0x20 -and $rrByte -le 0x7E))) { throw 'the record contains a byte outside printable ASCII plus LF' }
    }
    $rrText = [System.Text.Encoding]::ASCII.GetString($rrBytes, 0, $rrBytes.Length - 1)
    $rrLines = @($rrText -split "`n")
    if ($rrLines.Count -ne 8 -or -not [string]::Equals($rrLines[0], 'crg-review-kernel-routing-custody v1', [System.StringComparison]::Ordinal)) {
      throw 'the record does not have the exact v1 eight-line shape'
    }
    if ($rrLines[1] -cnotmatch '^base: (?<base>[0-9a-f]{40}([0-9a-f]{24})?)$') { throw 'the record base is not one canonical object ID' }
    $rrBase = $Matches['base']
    $rrMaps = @(
      @{ RepoPath = 'scripts/codex/commit.ps1';  FileName = 'codex-commit.ps1' },
      @{ RepoPath = 'scripts/claude/commit.ps1'; FileName = 'claude-commit.ps1' },
      @{ RepoPath = 'scripts/run-gate.sh';       FileName = 'run-gate.sh' }
    )
    $rrDirectory = Join-Path $GitDir ("crg-review-kernel-routing-custody-$rrBase")
    if ((Get-CrgPathOccupantKind -Path $rrDirectory) -cne 'directory') { throw 'the base-bound custody path is not one plain directory' }
    try { $rrNames = @([System.IO.Directory]::GetFileSystemEntries($rrDirectory) | ForEach-Object { [System.IO.Path]::GetFileName($_) }) } catch { throw 'the base-bound custody directory cannot be enumerated' }
    $rrExpectedNames = @('custody-record') + @($rrMaps | ForEach-Object { $_.FileName })
    if ($rrNames.Count -ne $rrExpectedNames.Count) { throw 'the base-bound custody directory does not have the exact recorded inventory' }
    foreach ($rrExpectedName in $rrExpectedNames) {
      if (@($rrNames | Where-Object { [string]::Equals("$_", $rrExpectedName, [System.StringComparison]::Ordinal) }).Count -ne 1) {
        throw "the base-bound custody directory is missing or duplicates '$rrExpectedName'"
      }
    }
    $rrEntries = @()
    for ($rrN = 0; $rrN -lt $rrMaps.Count; $rrN++) {
      $rrMap = $rrMaps[$rrN]
      $rrPhase = $rrLines[2 + (2 * $rrN)]
      $rrDigest = $rrLines[3 + (2 * $rrN)]
      $rrPhasePattern = '^phase-a: (?<state>present|absent) (?<mode>100644|100755|-) (?<oid>[0-9a-f]{40}([0-9a-f]{24})?|-)' + ' ' + [regex]::Escape($rrMap.RepoPath) + '$'
      if ($rrPhase -cnotmatch $rrPhasePattern) { throw "the phase-A line for '$($rrMap.RepoPath)' is malformed" }
      $rrPresent = [string]::Equals($Matches['state'], 'present', [System.StringComparison]::Ordinal)
      $rrMode = $Matches['mode']
      $rrOid = $Matches['oid']
      if ($rrPresent) {
        if ($rrMode -ceq '-' -or $rrOid -ceq '-' -or $rrOid.Length -ne $rrBase.Length) { throw "the present phase-A identity for '$($rrMap.RepoPath)' is inconsistent" }
      } elseif ($rrMode -cne '-' -or $rrOid -cne '-') {
        throw "the absent phase-A identity for '$($rrMap.RepoPath)' is inconsistent"
      }
      $rrDigestPattern = '^sha256: (?<hash>[0-9a-f]{64}) ' + [regex]::Escape($rrMap.FileName) + ' ' + [regex]::Escape($rrMap.RepoPath) + '$'
      if ($rrDigest -cnotmatch $rrDigestPattern) { throw "the digest line for '$($rrMap.RepoPath)' is malformed" }
      $rrEntries += [pscustomobject]@{
        RepoPath = $rrMap.RepoPath
        FileName = $rrMap.FileName
        Hash = $Matches['hash']
        CustodyPath = Join-Path $rrDirectory $rrMap.FileName
        BasePresent = $rrPresent
        BaseMode = if ($rrPresent) { $rrMode } else { $null }
        BaseOid = if ($rrPresent) { $rrOid } else { $null }
      }
    }
    return [pscustomobject]@{
      BaseHead = $rrBase
      Directory = $rrDirectory
      RecordPath = $RecordPath
      RecordHash = $rrHold.Hash
      Bytes = $rrBytes
      Entries = $rrEntries
      Hold = $rrHold
    }
  } catch {
    if ($null -ne $rrHold -and $null -ne $rrHold.Stream) { $rrHold.Stream.Dispose() }
    throw
  }
}

# Validate the immutable base directory behind an already-held active record.
# The active pointer alone authenticates only its own bytes; the directory
# record and every recovery source must still match before an incomplete
# publication can be admitted as a recoverable transaction phase.
function Close-CrgLegacyRoutingCustodyLease {
  param([object]$Lease)
  if ($null -eq $Lease) { return }
  if ($null -ne $Lease.Transition -and $null -ne $Lease.Transition.Hold -and $null -ne $Lease.Transition.Hold.Stream) {
    try { $Lease.Transition.Hold.Stream.Dispose() } catch { }
  }
  foreach ($clSource in @($Lease.Sources)) {
    if ($null -ne $clSource -and $null -ne $clSource.Hold -and $null -ne $clSource.Hold.Stream) {
      try { $clSource.Hold.Stream.Dispose() } catch { }
    }
  }
  if ($null -ne $Lease.DirectoryRecord -and $null -ne $Lease.DirectoryRecord.Stream) {
    try { $Lease.DirectoryRecord.Stream.Dispose() } catch { }
  }
  if ($null -ne $Lease.Custody -and $null -ne $Lease.Custody.Hold -and $null -ne $Lease.Custody.Hold.Stream) {
    try { $Lease.Custody.Hold.Stream.Dispose() } catch { }
  }
  if ($null -ne $Lease.DirectoryHandle) {
    try { $Lease.DirectoryHandle.Dispose() } catch { }
  }
}

function Assert-CrgLegacyRoutingDriverCustodyEpoch {
  param([string]$RepoRoot, [object]$Custody)

  if ($null -eq $Custody) { throw 'the active custody record was not parsed' }
  $ceDirectoryHandle = $null
  $ceDirRecord = $null
  $ceSources = @()
  try {
    $ceDirectoryErr = 0
    $ceDirectoryHandle = [CrgBootstrap.NativeV4]::OpenDirectoryPinned($Custody.Directory, [ref]$ceDirectoryErr)
    if ($null -eq $ceDirectoryHandle -or $ceDirectoryHandle.IsInvalid) { throw "the base-bound custody directory could not be pinned (Win32 error $ceDirectoryErr)" }
    $ceDirectoryAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($ceDirectoryHandle)
    if ($ceDirectoryAttrs -lt 0 -or ($ceDirectoryAttrs -band 0x410) -ne 0x10) { throw 'the base-bound custody directory is not one ordinary held directory' }
    $ceDirRecord = Open-CrgLegacyRoutingHeldFile -Path (Join-Path $Custody.Directory 'custody-record') -MaxLength 2048 -ReadBytes
    if ($ceDirRecord.Hash -cne $Custody.RecordHash -or
        -not (Test-CrgLegacyRoutingBytesEqual -Left $ceDirRecord.Bytes -Right $Custody.Bytes)) {
      throw 'the base-directory custody record does not exactly match the held active record'
    }
    foreach ($ceEntry in @($Custody.Entries)) {
      $ceBaseRows = @(& git -C $RepoRoot ls-tree $Custody.BaseHead -- $ceEntry.RepoPath 2>$null)
      if ($LASTEXITCODE -ne 0 -or $ceBaseRows.Count -gt 1) {
        throw "recorded phase-A identity for '$($ceEntry.RepoPath)' could not be verified against the custody base"
      }
      if ($ceEntry.BasePresent) {
        $ceBaseWant = "$($ceEntry.BaseMode) blob $($ceEntry.BaseOid)`t$($ceEntry.RepoPath)"
        if ($ceEntry.BaseOid.Length -ne $Custody.BaseHead.Length -or $ceBaseRows.Count -ne 1 -or
            -not [string]::Equals("$($ceBaseRows[0])", $ceBaseWant, [System.StringComparison]::Ordinal)) {
          throw "recorded present phase-A identity for '$($ceEntry.RepoPath)' does not match the custody base tree"
        }
      } elseif ($ceBaseRows.Count -ne 0 -and -not [string]::IsNullOrWhiteSpace(($ceBaseRows -join ''))) {
        throw "recorded absent phase-A identity for '$($ceEntry.RepoPath)' is present in the custody base tree"
      }
      $ceSource = Open-CrgLegacyRoutingHeldFile -Path $ceEntry.CustodyPath -MaxLength 16777216
      $ceSources += [pscustomobject]@{ Entry = $ceEntry; Hold = $ceSource }
      if ($ceSource.Hash -cne $ceEntry.Hash) {
        throw "custody digest mismatch for '$($ceEntry.RepoPath)'"
      }
    }
    $ceLease = [pscustomobject]@{ Custody = $Custody; DirectoryHandle = $ceDirectoryHandle; DirectoryRecord = $ceDirRecord; Sources = @($ceSources); Transition = $null }
    $ceDirectoryHandle = $null
    $ceDirRecord = $null
    $ceSources = @()
    return $ceLease
  } catch {
    foreach ($ceSource in $ceSources) {
      if ($null -ne $ceSource -and $null -ne $ceSource.Hold -and $null -ne $ceSource.Hold.Stream) { try { $ceSource.Hold.Stream.Dispose() } catch { } }
    }
    if ($null -ne $ceDirRecord -and $null -ne $ceDirRecord.Stream) { try { $ceDirRecord.Stream.Dispose() } catch { } }
    if ($null -ne $ceDirectoryHandle -and -not $ceDirectoryHandle.IsInvalid) { try { $ceDirectoryHandle.Dispose() } catch { } }
    throw
  }
}

# Determine whether a self-host retry still has the exact candidate routing
# sources captured by custody. This check runs before any retry mutation. A
# phase-A restoration, absence, or unrelated edit remains recoverable through
# -RestoreLegacyRoutingCustody, but cannot become a new package input.
function Get-CrgLegacyRoutingCandidateSourceState {
  param([hashtable]$SourceBuffers, [object]$Custody)

  foreach ($csEntry in @($Custody.Entries)) {
    if ($null -eq $SourceBuffers -or -not $SourceBuffers.ContainsKey($csEntry.RepoPath) -or
        $SourceBuffers[$csEntry.RepoPath] -isnot [byte[]]) {
      return [pscustomobject]@{ Ready = $false; Reason = "the buffered package snapshot lacks routing source '$($csEntry.RepoPath)'" }
    }
    [byte[]]$csBytes = $SourceBuffers[$csEntry.RepoPath]
    if ($csBytes.Length -gt 16777216) {
      return [pscustomobject]@{ Ready = $false; Reason = "routing source '$($csEntry.RepoPath)' exceeds the recovery bound" }
    }
    if ((Get-CrgSha256HexOfBytes -Bytes $csBytes) -cne $csEntry.Hash) {
      return [pscustomobject]@{ Ready = $false; Reason = "routing source '$($csEntry.RepoPath)' no longer matches verified custody" }
    }
  }
  return [pscustomobject]@{ Ready = $true; Reason = 'all routing sources match verified custody' }
}

function Read-CrgLegacyReviewKernelTransitionRecord {
  param([string]$RecordPath, [string]$ExpectedBase)

  $rtHold = Open-CrgLegacyRoutingHeldFile -Path $RecordPath -MaxLength 2048 -ReadBytes
  try {
    $rtBytes = $rtHold.Bytes
    if ($rtBytes.Length -lt 1 -or $rtBytes[$rtBytes.Length - 1] -ne 0x0A) { throw 'the transition record is empty or lacks its final LF' }
    foreach ($rtByte in $rtBytes) {
      if (-not ($rtByte -eq 0x0A -or ($rtByte -ge 0x20 -and $rtByte -le 0x7E))) { throw 'the transition record contains a byte outside printable ASCII plus LF' }
    }
    $rtText = [System.Text.Encoding]::ASCII.GetString($rtBytes, 0, $rtBytes.Length - 1)
    $rtLines = @($rtText -split "`n")
    if ($rtLines.Count -lt 3 -or $rtLines.Count -gt 9 -or -not [string]::Equals($rtLines[0], 'crg-review-kernel-transition v1', [System.StringComparison]::Ordinal)) {
      throw 'the transition record does not have the bounded v1 shape'
    }
    if ($rtLines[1] -cnotmatch '^base: (?<base>[0-9a-f]{40}([0-9a-f]{24})?)$' -or
        -not [string]::Equals($Matches['base'], $ExpectedBase, [System.StringComparison]::Ordinal)) {
      throw 'the transition record is not bound to the active custody base'
    }
    $rtRanks = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $rtRanks.Add('.gitattributes', 1)
    $rtRanks.Add('scripts/git-hooks/pre-commit', 2)
    $rtRanks.Add('scripts/codex/auto-review.ps1', 3)
    $rtRanks.Add('scripts/claude/auto-review.ps1', 4)
    $rtRanks.Add('scripts/codex/review-prompt-template.md', 5)
    $rtRanks.Add('scripts/review-liveness.psm1', 6)
    $rtRanks.Add('scripts/review-common.ps1', 7)
    $rtPrev = 0
    $rtCore = 0
    $rtEntries = @()
    for ($rtN = 2; $rtN -lt $rtLines.Count; $rtN++) {
      if ($rtLines[$rtN] -cnotmatch '^entry: (?<mode>100644|100755) (?<oid>[0-9a-f]{40}([0-9a-f]{24})?) (?<path>.+)$') { throw 'a transition entry is malformed' }
      $rtPath = $Matches['path']
      if (-not $rtRanks.ContainsKey($rtPath) -or $rtRanks[$rtPath] -le $rtPrev -or $Matches['oid'].Length -ne $ExpectedBase.Length) {
        throw "transition path '$rtPath' is unknown, duplicated, out of order, or has the wrong object format"
      }
      $rtPrev = $rtRanks[$rtPath]
      if ($rtPath -cne '.gitattributes') { $rtCore++ }
      $rtEntries += [pscustomobject]@{ Mode = $Matches['mode']; Oid = $Matches['oid']; RepoPath = $rtPath }
    }
    if ($rtCore -lt 1) { throw 'the transition record changes no protected review-kernel entry' }
    return [pscustomobject]@{ BaseHead = $ExpectedBase; Entries = $rtEntries; Bytes = $rtBytes; Hold = $rtHold }
  } catch {
    if ($null -ne $rtHold -and $null -ne $rtHold.Stream) { $rtHold.Stream.Dispose() }
    throw
  }
}

function Get-CrgRetiredProjectModeCommitState {
  param([string]$Repo, [string]$Commit)
  try { & git -C $Repo cat-file -e "${Commit}^{commit}" 2>$null } catch { return 'error' }
  if ($LASTEXITCODE -ne 0) { return 'error' }
  foreach ($rcSurface in @('scripts/git-hooks/pre-commit', 'scripts/codex/auto-review.ps1', 'scripts/claude/auto-review.ps1', 'scripts/codex/review-prompt-template.md')) {
    try {
      & git -C $Repo grep -q -e 'crg_pm_staged_touches_declaration' -e 'function Test-ProjectModeBranchRange' -e 'Green is campaign-anchored' $Commit -- $rcSurface 2>$null
    } catch { return 'error' }
    if ($LASTEXITCODE -eq 0) { return 'legacy' }
    if ($LASTEXITCODE -ne 1) { return 'error' }
  }
  return 'current'
}

# Prove either the untouched base (interruption before landing) or the exact
# one-parent kernel landing. A same-looking later commit is deliberately not a
# recovery point: custody is scoped to one base->tree transition, not a path
# pattern that can be replayed after unrelated history.
function Get-CrgLegacyRoutingLandingState {
  param([string]$RepoRoot, [object]$Custody, [object]$Transition, [string]$Commit)

  if ($Commit -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { throw 'the recovery HEAD is not one canonical commit ID' }
  if ([string]::Equals($Commit, $Custody.BaseHead, [System.StringComparison]::Ordinal)) {
    if ((Get-CrgRetiredProjectModeCommitState -Repo $RepoRoot -Commit $Commit) -cne 'legacy') { throw 'the custody base no longer classifies as the retired kernel recorded by bootstrap' }
    return [pscustomobject]@{ Phase = 'pre-kernel'; Head = $Commit; BaseHead = $Custody.BaseHead }
  }

  # Read the commit object's own header. `rev-list --parents` is a history
  # view and can be rewritten by graft/shallow metadata while still exiting
  # zero; `cat-file commit` under the process-wide NO_REPLACE boundary exposes
  # the canonical stored parent lines. Parse only through the required blank
  # header separator so message text can never masquerade as ancestry.
  $rlCommitRaw = @(& git -C $RepoRoot cat-file commit $Commit 2>$null)
  if ($LASTEXITCODE -ne 0) { throw 'the prospective kernel landing commit object could not be read' }
  $rlHeaderEnd = -1
  for ($rlHeaderI = 0; $rlHeaderI -lt $rlCommitRaw.Count; $rlHeaderI++) {
    if ([string]::IsNullOrEmpty("$($rlCommitRaw[$rlHeaderI])")) { $rlHeaderEnd = $rlHeaderI; break }
  }
  if ($rlHeaderEnd -lt 1) { throw 'the prospective kernel landing commit lacks a complete raw header' }
  $rlOidWidth = $Commit.Length
  $rlTreePattern = '\Atree [0-9a-f]{' + $rlOidWidth + '}\z'
  if ("$($rlCommitRaw[0])" -cnotmatch $rlTreePattern) { throw 'the prospective kernel landing commit has no canonical tree header' }
  $rlParentPattern = '\Aparent (?<oid>[0-9a-f]{' + $rlOidWidth + '})\z'
  $rlParentOids = New-Object 'System.Collections.Generic.List[string]'
  for ($rlHeaderI = 1; $rlHeaderI -lt $rlHeaderEnd; $rlHeaderI++) {
    $rlHeaderLine = "$($rlCommitRaw[$rlHeaderI])"
    if ($rlHeaderLine -cmatch $rlParentPattern) {
      $rlParentOids.Add($Matches['oid']) | Out-Null
    } elseif ($rlHeaderLine.StartsWith('parent', [System.StringComparison]::Ordinal)) {
      throw 'the prospective kernel landing commit has a malformed parent header'
    }
  }
  if ($rlParentOids.Count -ne 1 -or
      -not [string]::Equals($rlParentOids[0], $Custody.BaseHead, [System.StringComparison]::Ordinal)) {
    throw 'recovery requires the exact one-parent kernel landing directly above the recorded base'
  }
  if ((Get-CrgRetiredProjectModeCommitState -Repo $RepoRoot -Commit $Commit) -cne 'current') { throw 'the exact landing still contains retired project-mode enforcement or could not be classified' }

  $rlDiffPaths = @(& git -C $RepoRoot diff-tree --no-ext-diff --no-textconv --no-renames --ignore-submodules=none --no-commit-id --name-only -r $Custody.BaseHead $Commit -- 2>$null | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($LASTEXITCODE -ne 0 -or $rlDiffPaths.Count -ne $Transition.Entries.Count) { throw 'the exact landing path inventory does not match the transition record' }
  foreach ($rlEntry in @($Transition.Entries)) {
    $rlSeen = @($rlDiffPaths | Where-Object { [string]::Equals("$_", $rlEntry.RepoPath, [System.StringComparison]::Ordinal) })
    if ($rlSeen.Count -ne 1) { throw "the exact landing does not change recorded path '$($rlEntry.RepoPath)' exactly once" }
    $rlTree = @(& git -C $RepoRoot ls-tree $Commit -- $rlEntry.RepoPath 2>$null)
    $rlExpected = "$($rlEntry.Mode) blob $($rlEntry.Oid)`t$($rlEntry.RepoPath)"
    if ($LASTEXITCODE -ne 0 -or $rlTree.Count -ne 1 -or -not [string]::Equals("$($rlTree[0])", $rlExpected, [System.StringComparison]::Ordinal)) {
      throw "the exact landing tree entry for '$($rlEntry.RepoPath)' does not match the transition record"
    }
  }
  return [pscustomobject]@{ Phase = 'post-kernel'; Head = $Commit; BaseHead = $Custody.BaseHead }
}

function Publish-CrgLegacyRoutingRestoredMarker {
  param(
    [string]$GitDir,
    [object]$Custody,
    [string]$LandingHead
  )
  $rmPath = Join-Path $GitDir 'crg-review-kernel-routing-custody-restored'
  $rmBytes = [System.Text.UTF8Encoding]::new($false).GetBytes("crg-review-kernel-routing-restored v1`nbase: $($Custody.BaseHead)`nlanding-head: $LandingHead`ncustody-sha256: $($Custody.RecordHash)`n")
  $rmExpected = Get-CrgSha256HexOfBytes -Bytes $rmBytes
  $rmKind = Get-CrgPathOccupantKind -Path $rmPath
  if ([string]::Equals($rmKind, 'file', [System.StringComparison]::Ordinal)) {
    $rmExisting = Open-CrgLegacyRoutingHeldFile -Path $rmPath -MaxLength 512 -ReadBytes
    try {
      if ($rmExisting.Hash -ceq $rmExpected -and (Test-CrgLegacyRoutingBytesEqual -Left $rmExisting.Bytes -Right $rmBytes)) { return $rmPath }
      throw "an existing completion marker at '$rmPath' does not match this exact custody landing"
    } finally { $rmExisting.Stream.Dispose() }
  }
  if (-not [string]::Equals($rmKind, 'empty', [System.StringComparison]::Ordinal)) { throw "completion-marker path '$rmPath' has a $rmKind occupant" }
  $rmStage = "$rmPath.crg-new-$([Guid]::NewGuid().ToString('N'))"
  $rmFs = $null
  $rmPublished = $false
  try {
    $rmHandle = $null
    $rmErr = 0
    try {
      $rmHandle = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($rmStage, [ref]$rmErr)
      if ($null -eq $rmHandle -or $rmHandle.IsInvalid) { throw "completion-marker stage create-new failed (Win32 error $rmErr)" }
      $rmFs = New-Object System.IO.FileStream($rmHandle, [System.IO.FileAccess]::ReadWrite)
      $rmHandle = $null
      $rmFs.Write($rmBytes, 0, $rmBytes.Length)
      $rmFs.Flush($true)
      $rmFs.Position = 0
      $rmBack = New-Object byte[] $rmBytes.Length
      $rmRead = 0
      while ($rmRead -lt $rmBack.Length) {
        $rmGot = $rmFs.Read($rmBack, $rmRead, $rmBack.Length - $rmRead)
        if ($rmGot -le 0) { break }
        $rmRead += $rmGot
      }
      if ($rmRead -ne $rmBytes.Length -or $rmFs.Length -ne $rmBytes.Length -or
          -not (Test-CrgLegacyRoutingBytesEqual -Left $rmBack -Right $rmBytes)) { throw 'the staged completion marker failed held readback' }
      $rmFs.Position = 0
    } finally {
      if ($null -ne $rmHandle -and -not $rmHandle.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $rmStage -Handle $rmHandle -Label 'completion-marker stage' }
    }
    $rmRenameErr = 0
    if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($rmFs.SafeFileHandle, $rmStage, $rmPath, [ref]$rmRenameErr))) { throw "same-handle create-new completion-marker publication failed (Win32 error $rmRenameErr)" }
    $rmPublished = $true
    return $rmPath
  } finally {
    if ($null -ne $rmFs) {
      if ($rmPublished) { try { $rmFs.Dispose() } catch { } }
      else { $null = Remove-CrgOwnedScratchHandle -Path $rmStage -Stream $rmFs -Label 'completion-marker stage' }
    }
  }
}

function Test-CrgLegacyRoutingRestoredMarker {
  param([string]$RepoRoot, [string]$GitDir, [object]$Custody, [object]$Transition, [ref]$LandingHeadRef)
  if ($null -ne $LandingHeadRef) { $LandingHeadRef.Value = '' }
  $tmPath = Join-Path $GitDir 'crg-review-kernel-routing-custody-restored'
  if ([string]::Equals((Get-CrgPathOccupantKind -Path $tmPath), 'empty', [System.StringComparison]::Ordinal)) { return $false }
  $tmHold = Open-CrgLegacyRoutingHeldFile -Path $tmPath -MaxLength 512 -ReadBytes
  try {
    foreach ($tmByte in $tmHold.Bytes) { if (-not ($tmByte -eq 0x0A -or ($tmByte -ge 0x20 -and $tmByte -le 0x7E))) { return $false } }
    if ($tmHold.Bytes.Length -lt 1 -or $tmHold.Bytes[$tmHold.Bytes.Length - 1] -ne 0x0A) { return $false }
    $tmLines = @([System.Text.Encoding]::ASCII.GetString($tmHold.Bytes, 0, $tmHold.Bytes.Length - 1) -split "`n")
    if ($tmLines.Count -ne 4 -or -not [string]::Equals($tmLines[0], 'crg-review-kernel-routing-restored v1', [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($tmLines[1], "base: $($Custody.BaseHead)", [System.StringComparison]::Ordinal) -or -not [string]::Equals($tmLines[3], "custody-sha256: $($Custody.RecordHash)", [System.StringComparison]::Ordinal) -or
        $tmLines[2] -cnotmatch '^landing-head: (?<head>[0-9a-f]{40}([0-9a-f]{24})?)$') { return $false }
    $tmLanding = $Matches['head']
    try { $tmState = Get-CrgLegacyRoutingLandingState -RepoRoot $RepoRoot -Custody $Custody -Transition $Transition -Commit $tmLanding } catch { return $false }
    if ($tmState.Phase -cne 'post-kernel') { return $false }
    & git -C $RepoRoot merge-base --is-ancestor $tmLanding HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    if ($null -ne $LandingHeadRef) { $LandingHeadRef.Value = $tmLanding }
    return $true
  } finally { $tmHold.Stream.Dispose() }
}

function Get-CrgLegacyRoutingResumeState {
  param([string]$RepoRoot, [string]$GitDir)
  $rsActive = Join-Path $GitDir 'crg-review-kernel-routing-custody-active'
  $rsKind = Get-CrgPathOccupantKind -Path $rsActive
  if ([string]::Equals($rsKind, 'empty', [System.StringComparison]::Ordinal)) { return [pscustomobject]@{ State = 'none'; Reason = 'no active custody record'; BaseHead = ''; LandingHead = '' } }
  if (-not [string]::Equals($rsKind, 'file', [System.StringComparison]::Ordinal)) { return [pscustomobject]@{ State = 'blocked'; Reason = "active custody path has occupant kind $rsKind"; BaseHead = ''; LandingHead = '' } }
  $rsCustody = $null
  $rsTransition = $null
  $rsLease = $null
  $rsTransfer = $false
  try {
    $rsCustody = Read-CrgLegacyRoutingDriverCustodyRecord -RecordPath $rsActive -GitDir $GitDir
    $rsLease = Assert-CrgLegacyRoutingDriverCustodyEpoch -RepoRoot $RepoRoot -Custody $rsCustody
    $rsTransitionPath = Join-Path $GitDir 'crg-review-kernel-transition'
    $rsTransitionKind = Get-CrgPathOccupantKind -Path $rsTransitionPath
    if ([string]::Equals($rsTransitionKind, 'file', [System.StringComparison]::Ordinal)) {
      $rsTransition = Read-CrgLegacyReviewKernelTransitionRecord -RecordPath $rsTransitionPath -ExpectedBase $rsCustody.BaseHead
      $rsLease.Transition = $rsTransition
    } elseif ([string]::Equals($rsTransitionKind, 'empty', [System.StringComparison]::Ordinal)) {
      $rsHead = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
      if ($LASTEXITCODE -ne 0 -or "$rsHead".Trim() -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { throw 'current HEAD could not be captured' }
      $rsLanding = Get-CrgLegacyRoutingLandingState -RepoRoot $RepoRoot -Custody $rsCustody -Transition $null -Commit "$rsHead".Trim()
      if ($rsLanding.Phase -cne 'pre-kernel') { throw 'an absent transition record is recoverable only at the exact recorded legacy base' }
      $rsTransfer = $true
      return [pscustomobject]@{
        State = 'pre-transition'
        Reason = 'verified routing custody is active at the exact legacy base, but transition publication has not completed'
        BaseHead = $rsCustody.BaseHead
        LandingHead = ''
        Custody = $rsCustody
        Lease = $rsLease
      }
    } else {
      throw "transition-record path has occupant kind $rsTransitionKind"
    }
    $rsRestoredLanding = ''
    if (Test-CrgLegacyRoutingRestoredMarker -RepoRoot $RepoRoot -GitDir $GitDir -Custody $rsCustody -Transition $rsTransition -LandingHeadRef ([ref]$rsRestoredLanding)) {
      return [pscustomobject]@{ State = 'restored'; Reason = 'a verified completion marker binds the exact kernel landing and custody record'; BaseHead = $rsCustody.BaseHead; LandingHead = $rsRestoredLanding }
    }
    $rsHead = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or "$rsHead".Trim() -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { throw 'current HEAD could not be captured' }
    $rsLanding = Get-CrgLegacyRoutingLandingState -RepoRoot $RepoRoot -Custody $rsCustody -Transition $rsTransition -Commit "$rsHead".Trim()
    if ($rsLanding.Phase -ceq 'pre-kernel') {
      $rsTransfer = $true
      return [pscustomobject]@{ State = 'pre-kernel'; Reason = 'HEAD is still the exact recorded base'; BaseHead = $rsCustody.BaseHead; LandingHead = ''; Custody = $rsCustody; Lease = $rsLease }
    }
    return [pscustomobject]@{ State = 'pending'; Reason = 'HEAD is the exact kernel landing and custody has not been restored'; BaseHead = $rsCustody.BaseHead; LandingHead = '' }
  } catch {
    $rsKnownBase = if ($null -ne $rsCustody) { $rsCustody.BaseHead } else { '' }
    return [pscustomobject]@{ State = 'blocked'; Reason = $_.Exception.Message; BaseHead = $rsKnownBase; LandingHead = '' }
  } finally {
    if (-not $rsTransfer) {
      if ($null -ne $rsLease) { Close-CrgLegacyRoutingCustodyLease -Lease $rsLease }
      else {
        if ($null -ne $rsTransition -and $null -ne $rsTransition.Hold) { $rsTransition.Hold.Stream.Dispose() }
        if ($null -ne $rsCustody -and $null -ne $rsCustody.Hold) { $rsCustody.Hold.Stream.Dispose() }
      }
    }
  }
}

# Restore only the recorded routing-driver custody copies. Base-present worktree
# occupants are exclusively held and proven from their captured bytes in the
# recorded base commit's private attribute domain before the same handles are
# rewritten. A base-absent destination is published only through CREATE_NEW plus
# a no-replace move. Thus a user or concurrent edit appearing after the Git
# probes is refused, never overwritten.
function Restore-CrgLegacyRoutingDriverCustody {
  param([string]$RepoRoot, [string]$GitDir, [string]$ProofScratchRoot)

  $rrActive = Join-Path $GitDir 'crg-review-kernel-routing-custody-active'
  $rrCustody = $null
  $rrEpoch = $null
  $rrDirRecord = $null
  $rrTransition = $null
  $rrSources = @()
  $rrDestinations = @()
  try {
    if ([string]::IsNullOrWhiteSpace($ProofScratchRoot) -or -not [System.IO.Path]::IsPathRooted($ProofScratchRoot) -or
        (Test-CrgPathWithin -Path $ProofScratchRoot -Root $RepoRoot)) {
      throw 'routing recovery requires one absolute immutable-proof scratch root outside the target repository'
    }
    $rrCustody = Read-CrgLegacyRoutingDriverCustodyRecord -RecordPath $rrActive -GitDir $GitDir
    $rrEpoch = Assert-CrgLegacyRoutingDriverCustodyEpoch -RepoRoot $RepoRoot -Custody $rrCustody
    $rrDirRecord = $rrEpoch.DirectoryRecord
    $rrSources = @($rrEpoch.Sources)
    $rrHead = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or "$rrHead".Trim() -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { throw 'current HEAD could not be captured as one commit' }
    $rrHead = "$rrHead".Trim()
    $rrTransitionPath = Join-Path $GitDir 'crg-review-kernel-transition'
    $rrTransitionKind = Get-CrgPathOccupantKind -Path $rrTransitionPath
    if ([string]::Equals($rrTransitionKind, 'file', [System.StringComparison]::Ordinal)) {
      $rrTransition = Read-CrgLegacyReviewKernelTransitionRecord -RecordPath $rrTransitionPath -ExpectedBase $rrCustody.BaseHead
      $rrEpoch.Transition = $rrTransition
      $rrLanding = Get-CrgLegacyRoutingLandingState -RepoRoot $RepoRoot -Custody $rrCustody -Transition $rrTransition -Commit $rrHead
    } elseif ([string]::Equals($rrTransitionKind, 'empty', [System.StringComparison]::Ordinal)) {
      if (-not [string]::Equals($rrHead, $rrCustody.BaseHead, [System.StringComparison]::Ordinal)) {
        throw 'an absent transition record is recoverable only while HEAD is the exact recorded legacy base'
      }
      $rrLanding = Get-CrgLegacyRoutingLandingState -RepoRoot $RepoRoot -Custody $rrCustody -Transition $null -Commit $rrHead
    } else {
      throw "transition-record path has occupant kind $rrTransitionKind"
    }

    foreach ($rrEntry in @($rrCustody.Entries)) {
      $rrDestPath = Join-Path $RepoRoot $rrEntry.RepoPath
      if ($rrEntry.BasePresent) {
        $rrDestHandle = $null
        $rrDestFs = $null
        $rrDestError = 0
        try {
          try { $rrDestHandle = [CrgBootstrap.NativeV4]::OpenExclusiveNoFollow($rrDestPath, [ref]$rrDestError) } catch { $rrDestHandle = $null; $rrDestError = -1 }
          if ($null -eq $rrDestHandle -or $rrDestHandle.IsInvalid) { throw "base-present destination '$($rrEntry.RepoPath)' could not be exclusively frozen (Win32 error $rrDestError)" }
          $rrDestAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($rrDestHandle)
          $rrDestLinks = [CrgBootstrap.NativeV3]::GetLinkCount($rrDestHandle)
          if ($rrDestAttrs -lt 0 -or ($rrDestAttrs -band 0x410) -ne 0 -or $rrDestLinks -ne 1) { throw "base-present destination '$($rrEntry.RepoPath)' is not one ordinary single-link file" }
          $rrDestFs = New-Object System.IO.FileStream($rrDestHandle, [System.IO.FileAccess]::ReadWrite)
          $rrDestHandle = $null
        } finally {
          if ($null -ne $rrDestHandle -and -not $rrDestHandle.IsInvalid) { $rrDestHandle.Dispose() }
        }
        $rrDest = [pscustomobject]@{ Entry = $rrEntry; Path = $rrDestPath; State = 'checking'; Stream = $rrDestFs; OriginalBytes = $null; OriginalHash = $null }
        $rrDestinations += $rrDest
        if ($rrDestFs.Length -gt 16777216) { throw "base-present destination '$($rrEntry.RepoPath)' exceeds the recovery bound" }
        $rrMem = New-Object System.IO.MemoryStream
        try { $rrDestFs.CopyTo($rrMem); $rrOriginal = $rrMem.ToArray() } finally { $rrMem.Dispose() }
        $rrDestFs.Position = 0
        $rrOriginalHash = Get-CrgSha256HexOfBytes -Bytes $rrOriginal
        $rrAlready = [string]::Equals($rrOriginalHash, $rrEntry.Hash, [System.StringComparison]::Ordinal)
        $rrDest.OriginalBytes = $rrOriginal
        $rrDest.OriginalHash = $rrOriginalHash
        if (-not $rrAlready) {
          $rrPhaseOid = Get-CrgControlledBasePathObjectId -RepoRoot $RepoRoot -ProofScratchRoot $ProofScratchRoot -BaseCommit $rrCustody.BaseHead -RepoPath $rrEntry.RepoPath -HeldBytes $rrOriginal
          if ($null -eq $rrPhaseOid -or -not [string]::Equals($rrPhaseOid, $rrEntry.BaseOid, [System.StringComparison]::Ordinal)) { throw "worktree bytes for '$($rrEntry.RepoPath)' changed after phase A; refusing to overwrite them" }
        }
        $rrDest.State = if ($rrAlready) { 'restored' } else { 'pending' }
      } else {
        $rrKind = Get-CrgPathOccupantKind -Path $rrDestPath
        if ([string]::Equals($rrKind, 'empty', [System.StringComparison]::Ordinal)) {
          $rrDestinations += [pscustomobject]@{ Entry = $rrEntry; Path = $rrDestPath; State = 'pending-create'; Stream = $null; OriginalBytes = $null; OriginalHash = $null }
        } elseif ([string]::Equals($rrKind, 'file', [System.StringComparison]::Ordinal)) {
          $rrExisting = Open-CrgLegacyRoutingHeldFile -Path $rrDestPath -MaxLength 16777216
          if ($rrExisting.Hash -cne $rrEntry.Hash) { $rrExisting.Stream.Dispose(); throw "base-absent destination '$($rrEntry.RepoPath)' gained different worktree bytes; refusing to overwrite them" }
          $rrDestinations += [pscustomobject]@{ Entry = $rrEntry; Path = $rrDestPath; State = 'restored'; Stream = $rrExisting.Stream; OriginalBytes = $null; OriginalHash = $rrExisting.Hash }
        } else {
          throw "base-absent destination '$($rrEntry.RepoPath)' gained a $rrKind occupant; refusing to replace it"
        }
      }
    }

    # HEAD and index identity are checked only after every present destination
    # is frozen. A concurrent worktree writer can no longer cross this check.
    foreach ($rrDest in $rrDestinations) {
      $rrEntry = $rrDest.Entry
      $rrTree = @(& git -C $RepoRoot ls-tree $rrLanding.Head -- $rrEntry.RepoPath 2>$null)
      if ($LASTEXITCODE -ne 0) { throw "HEAD phase-A probe failed for '$($rrEntry.RepoPath)'" }
      $rrIndex = @(& git -C $RepoRoot ls-files --stage -- $rrEntry.RepoPath 2>$null)
      if ($LASTEXITCODE -ne 0) { throw "index phase-A probe failed for '$($rrEntry.RepoPath)'" }
      if ($rrEntry.BasePresent) {
        $rrTreeWant = "$($rrEntry.BaseMode) blob $($rrEntry.BaseOid)`t$($rrEntry.RepoPath)"
        $rrIndexWant = "$($rrEntry.BaseMode) $($rrEntry.BaseOid) 0`t$($rrEntry.RepoPath)"
        if ($rrTree.Count -ne 1 -or -not [string]::Equals("$($rrTree[0])", $rrTreeWant, [System.StringComparison]::Ordinal) -or $rrIndex.Count -ne 1 -or -not [string]::Equals("$($rrIndex[0])", $rrIndexWant, [System.StringComparison]::Ordinal)) {
          throw "tracked phase-A identity changed for '$($rrEntry.RepoPath)'"
        }
      } elseif ($rrTree.Count -ne 0 -or $rrIndex.Count -ne 0) {
        throw "base-absent routing path '$($rrEntry.RepoPath)' gained a HEAD or index entry"
      }
    }

    $rrHeadBeforeWrite = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not [string]::Equals("$rrHeadBeforeWrite".Trim(), $rrLanding.Head, [System.StringComparison]::Ordinal)) {
      throw 'HEAD changed after the exact recovery landing was proved; no routing destination was rewritten'
    }

    foreach ($rrDest in $rrDestinations) {
      if ($rrDest.State -ceq 'restored') { continue }
      $rrSource = @($rrSources | Where-Object { $_.Entry.RepoPath -ceq $rrDest.Entry.RepoPath })[0]
      $rrSource.Hold.Stream.Position = 0
      if ($rrDest.State -ceq 'pending') {
        try {
          $rrDest.Stream.Position = 0
          $rrDest.Stream.SetLength(0)
          $rrSource.Hold.Stream.CopyTo($rrDest.Stream)
          $rrDest.Stream.Flush($true)
          $rrDest.Stream.Position = 0
          $rrWriteSha = [System.Security.Cryptography.SHA256]::Create()
          try { $rrWriteHash = ([System.BitConverter]::ToString($rrWriteSha.ComputeHash($rrDest.Stream)) -replace '-', '').ToLowerInvariant() } finally { $rrWriteSha.Dispose() }
          if ($rrWriteHash -cne $rrDest.Entry.Hash) { throw 'restored digest did not match custody' }
          $rrDest.Stream.Position = 0
          $rrDest.State = 'restored'
        } catch {
          $rrRestoreFailure = $_.Exception.Message
          try {
            $rrDest.Stream.Position = 0
            $rrDest.Stream.SetLength(0)
            $rrDest.Stream.Write($rrDest.OriginalBytes, 0, $rrDest.OriginalBytes.Length)
            $rrDest.Stream.Flush($true)
            $rrDest.Stream.Position = 0
            $rrRollbackSha = [System.Security.Cryptography.SHA256]::Create()
            try { $rrRollbackHash = ([System.BitConverter]::ToString($rrRollbackSha.ComputeHash($rrDest.Stream)) -replace '-', '').ToLowerInvariant() } finally { $rrRollbackSha.Dispose() }
            if ($rrRollbackHash -cne $rrDest.OriginalHash) { throw 'rollback digest mismatch' }
          } catch {
            throw "restore failed for '$($rrDest.Entry.RepoPath)' ($rrRestoreFailure), and phase-A rollback failed ($($_.Exception.Message)). Candidate recovery bytes remain at '$($rrDest.Entry.CustodyPath)'; tracked phase-A bytes remain named by $($rrDest.Entry.BaseOid)."
          }
          throw "restore failed for '$($rrDest.Entry.RepoPath)' ($rrRestoreFailure); phase-A bytes were restored through the held handle. Candidate recovery bytes remain at '$($rrDest.Entry.CustodyPath)'."
        }
      } else {
        $rrStage = "$($rrDest.Path).crg-restore-$([Guid]::NewGuid().ToString('N'))"
        $rrStageHandle = $null
        $rrStageFs = $null
        $rrStageErr = 0
        try {
          $rrStageHandle = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($rrStage, [ref]$rrStageErr)
          if ($null -eq $rrStageHandle -or $rrStageHandle.IsInvalid) { throw "create-new staging failed for base-absent '$($rrDest.Entry.RepoPath)' (Win32 error $rrStageErr)" }
          $rrStageFs = New-Object System.IO.FileStream($rrStageHandle, [System.IO.FileAccess]::ReadWrite)
          $rrStageHandle = $null
          $rrSource.Hold.Stream.CopyTo($rrStageFs)
          $rrStageFs.Flush($true)
          $rrStageFs.Position = 0
          $rrStageSha = [System.Security.Cryptography.SHA256]::Create()
          try { $rrStageHash = ([System.BitConverter]::ToString($rrStageSha.ComputeHash($rrStageFs)) -replace '-', '').ToLowerInvariant() } finally { $rrStageSha.Dispose() }
          if ($rrStageHash -cne $rrDest.Entry.Hash) { throw 'create-new staging digest mismatch' }
          $rrStageFs.Position = 0
          $rrRenameErr = 0
          if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($rrStageFs.SafeFileHandle, $rrStage, $rrDest.Path, [ref]$rrRenameErr))) {
            throw "base-absent destination '$($rrDest.Entry.RepoPath)' became occupied (Win32 error $rrRenameErr); no bytes were overwritten"
          }
          $rrDest.Stream = $rrStageFs
          $rrStageFs = $null
          $rrDest.State = 'restored'
        } finally {
          if ($null -ne $rrStageFs) { $null = Remove-CrgOwnedScratchHandle -Path $rrStage -Stream $rrStageFs -Label "restore stage for '$($rrDest.Entry.RepoPath)'" }
          elseif ($null -ne $rrStageHandle -and -not $rrStageHandle.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $rrStage -Handle $rrStageHandle -Label "restore stage for '$($rrDest.Entry.RepoPath)'" }
        }
      }
    }

    $rrHeadAfterWrite = (& git -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not [string]::Equals("$rrHeadAfterWrite".Trim(), $rrLanding.Head, [System.StringComparison]::Ordinal)) {
      throw "HEAD changed during routing recovery. Verified candidate bytes remain in custody at '$($rrCustody.Directory)', and every completed destination matches that custody; no completion marker was published."
    }
    $rrMarker = $null
    if ($rrLanding.Phase -ceq 'post-kernel') {
      $rrMarker = Publish-CrgLegacyRoutingRestoredMarker -GitDir $GitDir -Custody $rrCustody -LandingHead $rrLanding.Head
    }
    return [pscustomobject]@{ BaseHead = $rrCustody.BaseHead; LandingHead = $rrLanding.Head; Phase = $rrLanding.Phase; MarkerPath = $rrMarker; Directory = $rrCustody.Directory; Entries = $rrCustody.Entries }
  } catch {
    $rrDir = if ($null -ne $rrCustody) { $rrCustody.Directory } else { Join-Path $GitDir 'crg-review-kernel-routing-custody-<recorded-base>' }
    Write-Host "[bootstrap] ERROR: legacy self-host routing recovery refused or failed ($($_.Exception.Message)). Verified custody is preserved under '$rrDir'; no unverified destination occupant was overwritten."
    return $null
  } finally {
    foreach ($rrDest in $rrDestinations) { if ($null -ne $rrDest.Stream) { try { $rrDest.Stream.Dispose() } catch { } } }
    if ($null -ne $rrEpoch) { Close-CrgLegacyRoutingCustodyLease -Lease $rrEpoch }
    else {
      if ($null -ne $rrTransition -and $null -ne $rrTransition.Hold) { try { $rrTransition.Hold.Stream.Dispose() } catch { } }
      if ($null -ne $rrCustody -and $null -ne $rrCustody.Hold) { try { $rrCustody.Hold.Stream.Dispose() } catch { } }
    }
  }
}

# The bootstrap-commit recovery command's staging list, DERIVED per candidate
# and never a fixed literal: this installer supports hybrid shapes where some
# components are deliberately ignored (the local shape's hook path) and where a
# config file was routed elsewhere or never created, and naming such a path
# makes `git add` exit nonzero -- the published command then fails on exactly
# the layouts this installer advertises. Both states are decided per PATH, so a
# DIRECTORY candidate would read an ignored parent and drop every component
# beneath it that `git add` would stage happily, publishing a command that
# installs PARTIALLY (merge-panel BLOCKER 2026-08-30). Tracked state is probed
# FIRST because ignore rules do not apply to a tracked path. A candidate whose
# state cannot be probed is KEPT and called out, never dropped -- a silently
# shortened list would under-stage the install.
function Get-CrgStagingPlan {
  param([string]$Repo, [string[]]$Candidates)
  $crgSpList = New-Object 'System.Collections.Generic.List[string]'
  $crgSpUnknown = New-Object 'System.Collections.Generic.List[string]'
  foreach ($crgSpCand in $Candidates) {
    if (-not (Test-Path -LiteralPath (Join-Path $Repo $crgSpCand))) { continue }
    $crgSpTrk = Get-CrgTrackedState -Repo $Repo -Path $crgSpCand
    if (([string]$crgSpTrk).StartsWith('error:', [System.StringComparison]::Ordinal)) {
      $crgSpUnknown.Add($crgSpCand) | Out-Null
      $crgSpList.Add($crgSpCand) | Out-Null
      continue
    }
    if ([string]::Equals($crgSpTrk, 'tracked', [System.StringComparison]::Ordinal)) {
      $crgSpList.Add($crgSpCand) | Out-Null
      continue
    }
    $crgSpIgn = Get-CrgCheckIgnoreState -Repo $Repo -Path $crgSpCand
    if ([string]::Equals($crgSpIgn, 'ignored', [System.StringComparison]::Ordinal)) { continue }
    if (([string]$crgSpIgn).StartsWith('error:', [System.StringComparison]::Ordinal)) { $crgSpUnknown.Add($crgSpCand) | Out-Null }
    $crgSpList.Add($crgSpCand) | Out-Null
  }
  return @{ List = $crgSpList.ToArray(); Unknown = $crgSpUnknown.ToArray() }
}

# Positive-observation state line for restoration diagnostics: every
# location claim is derived from a live probe, never assumed -- a
# vanished file reported as "preserved" would conceal data loss.
function Get-CrgRcLocState {
  param([string]$CustodyPath, [string]$BackupPath)
  $crgRcC = if (Test-Path -LiteralPath $CustodyPath -PathType Leaf) { "the ORIGINAL remains at '$CustodyPath'" } else { "the custody file is GONE from '$CustodyPath'" }
  $crgRcB = if (Test-Path -LiteralPath $BackupPath -PathType Leaf) { "its backup copy is at '$BackupPath'" } else { "the backup copy is MISSING from '$BackupPath'" }
  return "$crgRcC; $crgRcB."
}
# BEST-EFFORT, LAYERED restoration after a FAILED replacement:
# custody first, then the verified backup. UNVERIFIED bytes are never
# placed at the path -- a set-aside destination occupant stays
# preserved off-path at its announced location -- and the return value
# says whether a VERIFIED file stands at the path, so the dispatcher
# caller can put a fail-closed sentinel in place of nothing. A hostile
# race can still defeat every layer, but never silently: each outcome
# names every location that still holds bytes.
function Restore-CrgCustody {
  param([string]$CustodyPath, [string]$DestPath, [string]$BackupPath, [string]$BackupHash, [string]$Label, [object]$CustodyOwner, [object]$BackupStream)
  $crgRcMoved = $false
  $crgRcAside = $null
  if (Test-Path -LiteralPath $DestPath) {
    if (-not (Test-Path -LiteralPath $DestPath -PathType Leaf)) {
      # A non-file occupant would make a container-tolerant move nest
      # the custody file INSIDE it while this helper reported a
      # restore -- refuse.
      Write-Host "[bootstrap] WARNING: a non-file occupies '$DestPath'; NOT restoring '$Label' over it. $(Get-CrgRcLocState -CustodyPath $CustodyPath -BackupPath $BackupPath)"
      return $false
    }
    # A leaf occupant here has UNVERIFIED ORIGIN -- a concurrent
    # writer's file or this installer's own partial replacement -- and
    # no backup either way: set it aside under its own collision-checked
    # name rather than deleting it. File.Move is the exact-destination
    # primitive throughout this helper: unlike Move-Item, an existing
    # destination (a racing directory included) makes it THROW rather
    # than nest the moved file inside.
    $crgRcAside = "$DestPath.crg-occupant-$crgBackupStamp"
    if (Test-Path -LiteralPath $crgRcAside) {
      Write-Host "[bootstrap] WARNING: cannot set aside the destination occupant of '$DestPath' ('$crgRcAside' already exists); NOT restoring '$Label'. $(Get-CrgRcLocState -CustodyPath $CustodyPath -BackupPath $BackupPath)"
      return $false
    }
    try {
      [System.IO.File]::Move($DestPath, $crgRcAside)
      $crgRcMoved = $true
    } catch {
      Write-Host "[bootstrap] WARNING: could not set aside the destination occupant of '$DestPath' ($($_.Exception.Message)); NOT restoring '$Label'. $(Get-CrgRcLocState -CustodyPath $CustodyPath -BackupPath $BackupPath)"
      return $false
    }
    # Location claims come from POSITIVE post-move probes, never from a
    # move call's success alone.
    if (Test-Path -LiteralPath $crgRcAside -PathType Leaf) {
      Write-Host "[bootstrap] preserved the destination occupant of '$DestPath' at '$crgRcAside' - reconcile it by hand."
    } else {
      Write-Host "[bootstrap] WARNING: the destination occupant of '$DestPath' was moved aside but does not probe at '$crgRcAside'; inspect by hand."
    }
  }
  # The PRIMARY restoration is hash-verified end to end: custody is
  # hashed immediately before the move and the destination re-hashed
  # after it, so a filter rewrite or concurrent deletion cannot stand
  # behind a success message -- a failed post-verification enters the
  # SAME layered fallback as a failed move, where the verified backup
  # still waits.
  $crgRcErr = $null
  $crgRcPrimHash = if ($null -ne $CustodyOwner -and $null -ne $CustodyOwner.Stream) { Get-CrgSha256HexOfHeldStream -Stream $CustodyOwner.Stream } else { Get-CrgSha256HexSafe -Path $CustodyPath }
  try {
    if ($null -ne $CustodyOwner -and $null -ne $CustodyOwner.Stream) {
      $crgRcRenameErr = 0
      if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($CustodyOwner.Stream.SafeFileHandle, $CustodyOwner.Path, $DestPath, [ref]$crgRcRenameErr))) { throw "same-handle custody restore refused (Win32 error $crgRcRenameErr)" }
      $CustodyOwner.Path = $DestPath
      $crgRcRestoredHash = Get-CrgSha256HexOfHeldStream -Stream $CustodyOwner.Stream
    } else {
      [System.IO.File]::Move($CustodyPath, $DestPath)
      $crgRcRestoredHash = Get-CrgSha256HexSafe -Path $DestPath
    }
    if ((Test-Path -LiteralPath $DestPath -PathType Leaf) -and $null -ne $crgRcPrimHash -and [string]::Equals($crgRcRestoredHash, $crgRcPrimHash, [System.StringComparison]::Ordinal)) {
      Write-Host "[bootstrap] restored '$Label' from custody after the failed replacement (verified byte-for-byte at the path). $(Get-CrgBakState -BackupPath $BackupPath)"
      return $true
    }
    $crgRcErr = 'the restored custody bytes did not verify at the path'
  } catch {
    $crgRcErr = $_.Exception.Message
  }
  # FALLBACK ENTRY. Any leaf now at the destination is UNVERIFIED --
  # the primary move's failed-verification bytes or a racer -- and is
  # set aside UNCONDITIONALLY before anything else, so the path holds
  # either a verified refill or NOTHING when this helper returns: a
  # missing gate file fail-closes downstream, and the hooks path gets
  # the caller's sentinel. Diagnostics claim only POSITIVELY OBSERVED
  # locations (Get-CrgRcLocState probes at message time).
  $crgRcFilled = $false
  $crgRcRefillable = $true
  if (Test-Path -LiteralPath $DestPath) {
    if (Test-Path -LiteralPath $DestPath -PathType Leaf) {
      $crgRcFailedAside = "$DestPath.crg-failed-$crgBackupStamp-" + [guid]::NewGuid().ToString('N').Substring(0, 8)
      try {
        if ($null -ne $CustodyOwner -and $null -ne $CustodyOwner.Stream -and
            [string]::Equals("$($CustodyOwner.Path)", $DestPath, [System.StringComparison]::OrdinalIgnoreCase)) {
          $crgRcAsideErr = 0
          if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($CustodyOwner.Stream.SafeFileHandle, $CustodyOwner.Path, $crgRcFailedAside, [ref]$crgRcAsideErr))) { throw "same-handle set-aside refused (Win32 error $crgRcAsideErr)" }
          $CustodyOwner.Path = $crgRcFailedAside
        } else {
          [System.IO.File]::Move($DestPath, $crgRcFailedAside)
        }
        if (Test-Path -LiteralPath $crgRcFailedAside -PathType Leaf) {
          Write-Host "[bootstrap] preserved the unverified destination bytes of '$Label' at '$crgRcFailedAside' - inspect them by hand."
        } else {
          Write-Host "[bootstrap] WARNING: the unverified destination bytes of '$Label' were moved aside but do not probe at '$crgRcFailedAside'; inspect by hand."
        }
      } catch {
        Write-Host "[bootstrap] WARNING: could not set aside the unverified destination bytes of '$Label' ($($_.Exception.Message)); $(if (Test-Path -LiteralPath $DestPath -PathType Leaf) { "they REMAIN at '$DestPath' - do not trust them" } elseif (Test-Path -LiteralPath $DestPath) { "a NON-FILE now occupies '$DestPath'" } else { "the path '$DestPath' no longer holds them (location unknown)" }). $(Get-CrgRcLocState -CustodyPath $CustodyPath -BackupPath $BackupPath)"
        $crgRcRefillable = $false
      }
    } else {
      Write-Host "[bootstrap] WARNING: a non-file occupies '$DestPath' after the failed restore; NOT refilling over it. $(Get-CrgRcLocState -CustodyPath $CustodyPath -BackupPath $BackupPath)"
      $crgRcRefillable = $false
    }
  }
  # The VERIFIED backup refill STAGES through a collision-checked
  # sibling and verifies THERE, then moves into place -- File.Copy is
  # non-transactional and a partial copy landing directly at the
  # destination would stand as unverified live bytes. Stage-name
  # ownership is established ATOMICALLY by the CreateNew handle: a
  # racing writer that claims the pathname first makes the open throw,
  # so only a stage THIS handle created is ever this run's to touch --
  # a pathname-only absence probe would let the racer's file be
  # treated as "ours".
  $crgRcStage = "$DestPath.crg-refill-$crgBackupStamp"
  $crgRcStageOwned = $false
  $crgRcRefillErr = $null
  if ($crgRcRefillable) {
    try {
      $crgRcStageFs = [System.IO.File]::Open($crgRcStage, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
      $crgRcStageOwned = $true
      try {
        if ($null -ne $BackupStream) {
          $BackupStream.Position = 0
          $BackupStream.CopyTo($crgRcStageFs)
        } else {
          $crgRcBakBytes = [System.IO.File]::ReadAllBytes($BackupPath)
          $crgRcStageFs.Write($crgRcBakBytes, 0, $crgRcBakBytes.Length)
        }
      } finally { $crgRcStageFs.Dispose() }
      if ([string]::Equals((Get-CrgSha256HexSafe -Path $crgRcStage), $BackupHash, [System.StringComparison]::Ordinal)) {
        [System.IO.File]::Move($crgRcStage, $DestPath)
        # The DESTINATION is rehashed after the move: the stage hash
        # alone would let a concurrent rewrite between move and
        # announcement stand behind a "verified" claim.
        if ((Test-Path -LiteralPath $DestPath -PathType Leaf) -and [string]::Equals((Get-CrgSha256HexSafe -Path $DestPath), $BackupHash, [System.StringComparison]::Ordinal)) {
          $crgRcFilled = $true
          Write-Host "[bootstrap] WARNING: restore of '$Label' from custody failed ($crgRcErr); the path was refilled from the BACKUP copy at '$BackupPath' (verified byte-for-byte at the path). $(Get-CrgRcLocState -CustodyPath $CustodyPath -BackupPath $BackupPath)$(if ($crgRcMoved -and (Test-Path -LiteralPath $crgRcAside -PathType Leaf)) { " The set-aside occupant remains at '$crgRcAside'." })"
        } elseif (Test-Path -LiteralPath $DestPath -PathType Leaf) {
          # The moved bytes no longer verify at the path: set them
          # aside so the live path never keeps unverified bytes past
          # the return.
          $crgRcPostAside = "$DestPath.crg-failed-$crgBackupStamp-" + [guid]::NewGuid().ToString('N').Substring(0, 8)
          try {
            [System.IO.File]::Move($DestPath, $crgRcPostAside)
            if (Test-Path -LiteralPath $crgRcPostAside -PathType Leaf) {
              Write-Host "[bootstrap] preserved the unverified refill bytes of '$Label' at '$crgRcPostAside' - inspect them by hand."
            } else {
              Write-Host "[bootstrap] WARNING: the unverified refill bytes of '$Label' were moved aside but do not probe at '$crgRcPostAside'; inspect by hand."
            }
          } catch {
            Write-Host "[bootstrap] WARNING: could not set aside the unverified refill bytes of '$Label' ($($_.Exception.Message)); $(if (Test-Path -LiteralPath $DestPath -PathType Leaf) { "they REMAIN at '$DestPath' - do not trust them" } elseif (Test-Path -LiteralPath $DestPath) { "a NON-FILE now occupies '$DestPath'" } else { "the path '$DestPath' no longer holds them (location unknown)" })."
          }
        }
      }
    } catch { $crgRcRefillErr = $_.Exception.Message }
  }
  if (-not $crgRcFilled) {
    if ($crgRcStageOwned) {
      # Path-based deletion is never automated (a racer can replace
      # the pathname after this run's handle closed); the failed
      # stage -- a copy of the still-existing backup -- is retained
      # and named for hand cleanup instead.
      if (Test-Path -LiteralPath $crgRcStage) {
        Write-Host "[bootstrap] NOTE: this run's refill stage remains at '$crgRcStage' - remove it by hand."
      }
    } elseif ($crgRcRefillable -and (Test-Path -LiteralPath $crgRcStage)) {
      Write-Host "[bootstrap] WARNING: a pre-existing file blocks the refill staging path '$crgRcStage'; it was left untouched - inspect it by hand."
    }
    # UNVERIFIED bytes are never returned to the path -- a set-aside
    # occupant stays preserved off-path at its announced location; the
    # caller decides what fail-closed content (if any) stands in.
    $crgRcState = if (Test-Path -LiteralPath $DestPath) { "an occupant now sits at '$DestPath' - inspect it" } else { "the path '$DestPath' is EMPTY" }
    Write-Host "[bootstrap] WARNING: could not restore '$Label' from custody or the backup (custody: $crgRcErr$(if ($null -ne $crgRcRefillErr) { "; backup refill: $crgRcRefillErr" })); $crgRcState.$(if ($crgRcMoved -and (Test-Path -LiteralPath $crgRcAside -PathType Leaf)) { " The set-aside occupant remains at '$crgRcAside' (never returned unverified)." }) $(Get-CrgRcLocState -CustodyPath $CustodyPath -BackupPath $BackupPath) Restore by hand before committing."
  }
  return $crgRcFilled
}
# Best-effort custody ARCHIVAL (docs/local-install-v1.md section 4):
# a HARDLINK proves same-volume identity -- it can only be created on
# one filesystem and names the same data, so removing the custody name
# afterwards loses nothing, and post-hash writes through any open
# handle land in the archive-named file. Where the hardlink cannot be
# created the archive is a verified-readable copy with the custody
# file retained in place; every failure is reported, never swallowed.
function Save-CrgCustodyArchive {
  param([string]$CustodyPath, [string]$ArchivePath, [string]$BackupPath, [string]$Label, [object]$CustodyStream)
  $crgCaLinked = $false
  try {
    New-Item -ItemType HardLink -Path $ArchivePath -Value $CustodyPath -ErrorAction Stop | Out-Null
    $crgCaLinked = $true
  } catch { }
  if ($crgCaLinked -and (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
    # ARCHIVE-AND-RETAIN: the custody NAME is never deleted -- any
    # path-based deletion can race a concurrent replacement of the
    # name and destroy bytes that have no backup, and .NET Framework
    # offers no handle-coupled unlink that could cancel on a failed
    # identity check. The hardlink means both names share one data
    # stream (late writes land in both), so retention costs only a
    # named leftover for hand cleanup.
    $crgCaNameState = if (Test-Path -LiteralPath $CustodyPath -PathType Leaf) { "the custody name remains at '$CustodyPath' - remove it by hand once reconciled" } else { "the custody name no longer probes at '$CustodyPath'" }
    Write-Host "[bootstrap] NOTE: archived '$Label' custody by hardlink at '$ArchivePath'; $crgCaNameState (path-based deletion is never automated here)."
    return
  }
  $crgCaState = $null
  $crgCaErr = 'the archive copy did not read back'
  try {
    # Archival success requires BYTE EQUALITY with the custody file as
    # it stood at copy time -- a readable-but-corrupted copy behind a
    # success message would direct eventual custody cleanup at the
    # wrong record. Custody moving on AFTER this capture is the
    # late-write check's job downstream.
    $crgCaPreHash = if ($null -ne $CustodyStream) { Get-CrgSha256HexOfHeldStream -Stream $CustodyStream } else { Get-CrgSha256HexSafe -Path $CustodyPath }
    if ($null -ne $CustodyStream) {
      $crgCaArchiveH = $null
      $crgCaArchiveFs = $null
      $crgCaArchiveErr = 0
      try {
        $crgCaArchiveH = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($ArchivePath, [ref]$crgCaArchiveErr)
        if ($null -eq $crgCaArchiveH -or $crgCaArchiveH.IsInvalid) { throw "archive create-new failed (Win32 error $crgCaArchiveErr)" }
        $crgCaArchiveFs = New-Object System.IO.FileStream($crgCaArchiveH, [System.IO.FileAccess]::ReadWrite)
        $crgCaArchiveH = $null
        $CustodyStream.Position = 0
        $CustodyStream.CopyTo($crgCaArchiveFs)
        $crgCaArchiveFs.Flush($true)
        $crgCaGot = Get-CrgSha256HexOfHeldStream -Stream $crgCaArchiveFs
      } finally {
        if ($null -ne $crgCaArchiveFs) { $crgCaArchiveFs.Dispose() }
        elseif ($null -ne $crgCaArchiveH -and -not $crgCaArchiveH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $ArchivePath -Handle $crgCaArchiveH -Label "custody archive for '$Label'" }
      }
    } else {
      [System.IO.File]::Copy($CustodyPath, $ArchivePath, $false)
      $crgCaGot = Get-CrgSha256HexSafe -Path $ArchivePath
    }
    if ($null -ne $crgCaGot -and $null -ne $crgCaPreHash -and [string]::Equals($crgCaGot, $crgCaPreHash, [System.StringComparison]::Ordinal)) {
      $crgCaState = "its archive copy is at '$ArchivePath' (verified byte-for-byte)"
    } elseif ($null -ne $crgCaGot) {
      $crgCaErr = 'the archive copy did not match the custody bytes'
    }
  } catch {
    $crgCaState = $null
    $crgCaErr = $_.Exception.Message
  }
  # Custody claims are live-probed at message time: a vanished custody
  # file must report GONE, never "remains" -- and unarchived post-hash
  # writes are claimed only after probing that no matching archive
  # exists (a pre-existing archive naming the same bytes falsifies it).
  $crgCaCust = Test-Path -LiteralPath $CustodyPath -PathType Leaf
  if ($null -ne $crgCaState) {
    $crgCaCustText = if ($crgCaCust) { "the custody file for '$Label' remains at '$CustodyPath'" } else { "the custody file for '$Label' is GONE from '$CustodyPath'" }
    Write-Host "[bootstrap] NOTE: same-volume archival is unprovable here (the hardlink probe failed); $crgCaCustText ($crgCaState) - remove it once reconciled."
  } else {
    $crgCaArchHash = Get-CrgSha256HexSafe -Path $ArchivePath
    $crgCaCustHash = Get-CrgSha256HexSafe -Path $CustodyPath
    $crgCaCustText = if (-not $crgCaCust) { "the custody file is GONE from '$CustodyPath' (no post-hash copy remains)" }
      elseif ($null -ne $crgCaArchHash -and [string]::Equals($crgCaArchHash, $crgCaCustHash, [System.StringComparison]::Ordinal)) { "the custody file remains at '$CustodyPath' and a matching copy already sits at '$ArchivePath'" }
      else { "the custody file at '$CustodyPath' holds post-hash writes that are NOT archived anywhere - do not remove it until reconciled" }
    Write-Host "[bootstrap] WARNING: the custody archive copy for '$Label' FAILED ($crgCaErr); $crgCaCustText. $(Get-CrgBakState -BackupPath $BackupPath)"
  }
}
# Probed backup-location sentence: the positive-observation contract
# covers the backup claim too -- a backup removed during recovery must
# not receive a positive location diagnostic.
function Get-CrgBakState {
  param([string]$BackupPath)
  if (Test-Path -LiteralPath $BackupPath -PathType Leaf) { return "The pre-rename backup is at '$BackupPath'." }
  return "The pre-rename backup is MISSING from '$BackupPath'."
}
# FAIL-CLOSED sentinel hook: when no VERIFIED dispatcher can stand at
# the hooks path, an absent or partial hook would let commits run
# ungated (a truncated dispatcher can exit 0 before enforcing) -- a
# minimal refusing hook is published instead, itself only VERIFIED
# (CreateNew + re-hash) or not at all, with any unverified occupant
# preserved off-path first.
function Get-CrgSentinelBytes {
  # Shared by the sentinel installer and the dispatcher rewrite's
  # in-place fallback -- one authoritative byte sequence, so the
  # consumers never drift apart.
  return [System.Text.UTF8Encoding]::new($false).GetBytes("{ echo `"[pre-commit:dispatcher] FAIL-CLOSED sentinel: a bootstrap operation could not leave a verified dispatcher here. Re-run the package's bootstrap.ps1 (-DispatcherOnly for an already-installed repo) before committing.`" >&2; exit 1; }`n")
}
# Dispatcher DIGEST sidecar ('<hooks-path>/pre-commit.crg-sha256'):
# run-gate.sh verifies the hook's bytes against this bootstrap-recorded
# sha256 before firing a commit. The check is DETECTIVE, like every
# wrapper/driver guard in this package: it catches drift, stale or
# foreign hook bytes, and partial installs LOUDLY -- it is not a
# security boundary against a principal who can write the hooks path
# (that principal can rewrite any local record; no preflight in the
# firing process can close that, and the hook's own guard doctrine
# records the same posture for the routing drivers). The sidecar is
# meant to exist only beside a verified dispatcher: post-mutation
# failure paths and sentinel installs remove it BEST-EFFORT, while
# pre-mutation aborts deliberately preserve a verified dispatcher WITH
# its sidecar. A removal failure warns loudly rather than passing
# silently - a locked sidecar can survive, which is why run-gate.sh
# treats a digest MISMATCH as a refusal rather than trusting sidecar
# presence.
# Publication is an EXCLUSIVE CreateNew transaction with reparse
# refusal and a read-back verify -- a plain overwrite of a predictable
# path would hand a racer a truncation target, the section-4 hazard the
# dispatcher writers already refuse.
function Get-CrgSha256HexOfBytes {
  param([byte[]]$Bytes)
  $crgBSha = [System.Security.Cryptography.SHA256]::Create()
  try { return ([System.BitConverter]::ToString($crgBSha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() } finally { $crgBSha.Dispose() }
}
function Publish-CrgDispatcherDigest {
  # One handle carries create-write-verify: identity is pinned from
  # creation through the read-back (no pathname reopen a racer can
  # interpose on), and any post-create failure truncates through the
  # SAME handle -- a zero-length sidecar is fail-closed in run-gate.
  # A CreateNew collision claims only a ZERO-LENGTH regular leftover
  # (the shape clearing produces, carrying no data to lose) through an
  # exclusive no-follow open; any other occupant is a concurrent
  # foreign occupant and is PRESERVED with a $false return.
  param([string]$DispatcherPath, [byte[]]$Bytes)
  $crgDigPath = "$DispatcherPath.crg-sha256"
  $crgDigFs = $null
  $crgDigClaimEx = $null
  $script:CrgDigestFailureUsable = $false
  try {
    # The record carries a VERSIONED OWNERSHIP HEADER ahead of the
    # digest line: content shape alone must never read as ownership (a
    # foreign file that happens to hold 64 hex characters is not this
    # machinery's to touch), and the reader/clearing/publisher all hold
    # this one byte-exact two-line grammar.
    $crgDigBytes = [System.Text.UTF8Encoding]::new($false).GetBytes("crg-dispatcher-digest v1`n" + (Get-CrgSha256HexOfBytes -Bytes $Bytes) + "`n")
    # No-follow CREATE_NEW: a dangling reparse point at the digest name is
    # an occupant that collides, never a redirect that creates its target.
    $crgDigNewErr = 0
    $crgDigNew = $null
    try { $crgDigNew = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($crgDigPath, [ref]$crgDigNewErr) } catch { $crgDigNew = $null }
    if ($null -ne $crgDigNew -and -not $crgDigNew.IsInvalid) {
      $crgDigFs = New-Object System.IO.FileStream($crgDigNew, [System.IO.FileAccess]::ReadWrite)
    } else {
      try { $crgDigClaimEx = [CrgBootstrap.NativeV4]::OpenExclusiveNoFollow($crgDigPath, [ref]$crgDigNewErr) } catch { $crgDigClaimEx = $null }
      if ($null -eq $crgDigClaimEx -or $crgDigClaimEx.IsInvalid) {
        throw "the digest path is occupied and could not be exclusively opened - a concurrent foreign occupant is preserved"
      }
      $crgDigClaimShape = [CrgBootstrap.NativeV3]::GetHandleAttributes($crgDigClaimEx)
      if ($crgDigClaimShape -lt 0 -or ($crgDigClaimShape -band 0x400)) {
        throw "the digest path's occupant is a reparse point or could not be classified - preserved, not written through"
      }
      $crgDigFs = New-Object System.IO.FileStream($crgDigClaimEx, [System.IO.FileAccess]::ReadWrite)
      if ([CrgBootstrap.NativeV3]::GetLinkCount($crgDigClaimEx) -ne 1) {
        throw "a multi-link occupant holds the digest path - preserved, not written through (every alias would receive the bytes)"
      }
      if ($crgDigFs.Length -ne 0) {
        throw "a non-empty concurrent occupant holds the digest path - preserved, not overwritten"
      }
    }
    try {
      $crgDigFs.Write($crgDigBytes, 0, $crgDigBytes.Length)
      $crgDigFs.Flush($true)
      $crgDigFs.Position = 0
      $crgDigChkMs = New-Object System.IO.MemoryStream
      $crgDigFs.CopyTo($crgDigChkMs)
      $crgDigChkOk = ([System.BitConverter]::ToString($crgDigChkMs.ToArray()) -ceq [System.BitConverter]::ToString($crgDigBytes))
      $crgDigChkMs.Dispose()
      if (-not $crgDigChkOk) { throw 'the written digest did not read back byte-for-byte through its own handle' }
      return $true
    } catch {
      # Post-create failure: truncate through the HELD handle so no
      # partial attestation survives -- never a pathname delete. A
      # FAILED cleanup is verified positively: a residual that does not
      # satisfy the full record grammar is inert (the reader refuses
      # it), while a complete valid record surviving a failed truncate
      # is a USABLE attestation after a fatal report -- flagged so the
      # caller sentinelizes the dispatcher and the whole gate fails
      # closed instead.
      $crgDigCleanOk = $false
      try { $crgDigFs.SetLength(0); $crgDigFs.Flush($true); $crgDigCleanOk = $true } catch { }
      if (-not $crgDigCleanOk) {
        try {
          $crgDigFs.Position = 0
          $crgDigResMs = New-Object System.IO.MemoryStream
          $crgDigFs.CopyTo($crgDigResMs)
          if ([System.BitConverter]::ToString($crgDigResMs.ToArray()) -ceq [System.BitConverter]::ToString($crgDigBytes)) {
            $script:CrgDigestFailureUsable = $true
          }
          $crgDigResMs.Dispose()
        } catch {
          # The residual could not even be read: assume usable.
          $script:CrgDigestFailureUsable = $true
        }
      }
      throw
    }
  } catch {
    Write-Host "[bootstrap] WARNING: could not record the dispatcher digest at '$crgDigPath' ($($_.Exception.Message))."
    return $false
  } finally {
    if ($null -ne $crgDigFs) { try { $crgDigFs.Dispose() } catch { } }
    elseif ($null -ne $crgDigClaimEx) { try { $crgDigClaimEx.Dispose() } catch { } }
  }
}
# Classify what occupies a path for a FAILURE DIAGNOSIS. Absence is decided
# by the no-follow open's OWN status ('empty' only on ERROR_FILE_NOT_FOUND /
# ERROR_PATH_NOT_FOUND), and a file occupant's shape is read from the opened
# handle. OpenReadNoFollow cannot open a directory or a directory reparse
# point (no backup semantics), so those shapes are read from the
# pathname ATTRIBUTES, which do not follow links -- a DANGLING junction thus
# reports 'reparse' where Test-Path reported absence (and sent the operator
# to "re-run bootstrap" against an occupant no re-run can replace). Any
# other open failure is 'unknown:<error>'.
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

function Remove-CrgDispatcherDigest {
  # CLEARS the attestation: returns $true when the path is absent or
  # was truncated to zero bytes through an exclusively held, no-follow
  # handle; $false on any refusal or failure. NOTHING is ever deleted
  # by pathname -- a pathname delete races a swap between validation
  # and removal, so removal here means truncation through the pinned
  # identity (a zero-length sidecar is fail-closed: run-gate refuses it
  # as not-a-digest), and the zero-byte residual is the documented
  # cost. ABSENCE is decided by the no-follow open's OWN status
  # (ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND), never by a pathname
  # probe: Test-Path follows a reparse point and reports a DANGLING one
  # as absent, which would let a foreign occupant read as "nothing to
  # clear" and the dispatcher rewrite proceed until publication collides.
  # A directory refuses at the open (no backup semantics); a reparse
  # point opens as the LINK itself (no follow) and is refused by the
  # handle's own attributes -- foreign occupants survive.
  param([string]$DispatcherPath)
  $crgDigPath = "$DispatcherPath.crg-sha256"
  $crgDigRmEx = $null
  $crgDigRmFs = $null
  $crgDigRmErr = 0
  try {
    try { $crgDigRmEx = [CrgBootstrap.NativeV4]::OpenExclusiveNoFollow($crgDigPath, [ref]$crgDigRmErr) } catch { $crgDigRmEx = $null; $crgDigRmErr = -1 }
    if ($null -eq $crgDigRmEx -or $crgDigRmEx.IsInvalid) {
      if ($crgDigRmErr -eq 2 -or $crgDigRmErr -eq 3) { return $true }
      Write-Host "[bootstrap] WARNING: the occupant at the digest path '$crgDigPath' could not be exclusively opened (a non-file occupant, a lock holder, or a reparse point shape) - refusing to touch it; remove it by hand. Bootstrap only ever writes a regular file there."
      return $false
    }
    $crgDigRmShape = [CrgBootstrap.NativeV3]::GetHandleAttributes($crgDigRmEx)
    if ($crgDigRmShape -lt 0 -or ($crgDigRmShape -band 0x400) -or ($crgDigRmShape -band 0x10)) {
      Write-Host "[bootstrap] WARNING: the occupant at the digest path '$crgDigPath' could not be cleared: it is a reparse point or directory (or its shape could not be classified through its handle) - a non-file occupant this installer must not touch; move it aside by hand."
      return $false
    }
    $crgDigRmFs = New-Object System.IO.FileStream($crgDigRmEx, [System.IO.FileAccess]::ReadWrite)
    # Only an AUTHENTICATED sidecar is cleared: a single-link regular
    # file holding exactly the versioned two-line ownership record --
    # the crg-dispatcher-digest header line then one lowercase sha256
    # line -- or this helper's own zero-length residual. Anything else
    # at the path is unrelated data this helper must not truncate --
    # and a multi-linked file would lose content through every alias.
    $crgDigRmLinks = [CrgBootstrap.NativeV3]::GetLinkCount($crgDigRmEx)
    if ($crgDigRmLinks -ne 1) {
      Write-Host "[bootstrap] WARNING: the file at the digest path '$crgDigPath' has a hard-link count of $crgDigRmLinks - refusing to clear it (truncation would reach every alias); repair the links by hand."
      return $false
    }
    if ($crgDigRmFs.Length -ne 0) {
      $crgDigRmMs = New-Object System.IO.MemoryStream
      $crgDigRmFs.CopyTo($crgDigRmMs)
      $crgDigRmText = [System.Text.Encoding]::ASCII.GetString($crgDigRmMs.ToArray())
      $crgDigRmMs.Dispose()
      # OWNERSHIP is the full versioned two-line record, byte-exact:
      # the header line then one lowercase digest line, LF-only, and
      # NOTHING after the final LF -- anchored with \z, because .NET's
      # $ matches before a trailing newline and would accept an
      # extra-LF shape run-gate's reader rejects (cross-module
      # accept-set drift on a destructive path). Content shape alone
      # never reads as ownership, so a foreign 64-hex file is refused,
      # not truncated.
      if ($crgDigRmText -cnotmatch "^crg-dispatcher-digest v1`n[0-9a-f]{64}`n\z") {
        Write-Host "[bootstrap] WARNING: the file at the digest path '$crgDigPath' does not look like a bootstrap-written attestation - refusing to clear it; move it aside by hand."
        return $false
      }
    }
    $crgDigRmFs.SetLength(0)
    $crgDigRmFs.Flush($true)
    return $true
  } catch {
    Write-Host "[bootstrap] WARNING: could not clear the stale dispatcher digest at '$crgDigPath' ($($_.Exception.Message)) - clear it by hand; a stale digest must not bless foreign hook bytes."
    return $false
  } finally {
    if ($null -ne $crgDigRmFs) { try { $crgDigRmFs.Dispose() } catch { } }
    elseif ($null -ne $crgDigRmEx) { try { $crgDigRmEx.Dispose() } catch { } }
  }
}
function Install-CrgDispatcherSentinel {
  # -RetryDepth bounds the vanished-occupant reclassification below
  # (an occupant deleted between a probe and the exclusive open drops
  # to the empty-path publication instead of leaving the hooks path
  # bare); callers never pass it.
  param([string]$DispatcherPath, [int]$RetryDepth = 0, [string]$PreservationPath)
  # Single-line BRACE form, no shebang, chosen for truncation
  # robustness: every proper nonempty prefix FAILS CLOSED under sh --
  # almost all as syntax errors from the unclosed brace or quote, and
  # the prefix that only loses the trailing newline still runs the
  # refusal and exits nonzero -- while a multi-line hook truncated
  # after its shebang or echo line would exit 0 and silently pass.
  # Git-for-windows refuses to SPAWN a shebang-less hook outright
  # ('cannot spawn', the commit aborts -- measured 2026-08-28), so at
  # commit time the sentinel fails closed at spawn and the sh-level
  # prefix contract is the second layer. The residual left by this form is a ZERO-BYTE file (a
  # write that throws before its first byte), which git also refuses
  # to spawn; the retry loop below still re-claims that case, and the
  # residual past the final attempt is documented in
  # docs/local-install-v1.md section 4.
  $crgSnBytes = Get-CrgSentinelBytes
  $crgSnSha = [System.Security.Cryptography.SHA256]::Create()
  try { $crgSnWant = ([System.BitConverter]::ToString($crgSnSha.ComputeHash($crgSnBytes)) -replace '-', '').ToLowerInvariant() } finally { $crgSnSha.Dispose() }
  if (Test-Path -LiteralPath $DispatcherPath -PathType Leaf) {
    # An occupied path transitions occupant->sentinel by the same
    # IN-PLACE exclusive rewrite the dispatcher replacement uses: the
    # name never changes, a concurrent commit during the rewrite
    # fails closed on the exclusion, and only the exact held identity
    # is ever rewritten. The occupant's bytes are preserved from the
    # HELD stream first, and preservation is MANDATORY: without a
    # verified copy the occupant is refused, not destroyed.
    try { $crgSnAttrs = [System.IO.File]::GetAttributes($DispatcherPath) } catch { $crgSnAttrs = $null }
    if ($null -eq $crgSnAttrs -or (($crgSnAttrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
      if ((-not (Test-Path -LiteralPath $DispatcherPath)) -and ($RetryDepth -lt 2)) {
        # The occupant vanished between the probes (a racer's deletion
        # or rename): the path is now the EMPTY case the create-new
        # publication below exists for.
        return (Install-CrgDispatcherSentinel -DispatcherPath $DispatcherPath -RetryDepth ($RetryDepth + 1) -PreservationPath $PreservationPath)
      }
      Write-Host "[bootstrap] WARNING: the occupant at '$DispatcherPath' is unreadable or a reparse point (symlink/junction); the FAIL-CLOSED sentinel was NOT installed - repair the path by hand before committing."
      return $false
    }
    $crgSnEx = $null
    $crgSnExFs = $null
    $crgSnAsideH = $null
    $crgSnAsideFs = $null
    $crgSnAsideVerified = $false
    $crgSnErr = 0
    try {
      try { $crgSnEx = [CrgBootstrap.NativeV4]::OpenExclusiveNoFollow($DispatcherPath, [ref]$crgSnErr) } catch { $crgSnEx = $null }
      if ($null -eq $crgSnEx -or $crgSnEx.IsInvalid) {
        if ((-not (Test-Path -LiteralPath $DispatcherPath)) -and ($RetryDepth -lt 2)) {
          return (Install-CrgDispatcherSentinel -DispatcherPath $DispatcherPath -RetryDepth ($RetryDepth + 1) -PreservationPath $PreservationPath)
        }
        Write-Host "[bootstrap] WARNING: could not exclusively open the occupant at '$DispatcherPath' (commonly another process holding it); the FAIL-CLOSED sentinel was NOT installed - unverified bytes remain there; repair by hand before committing."
        return $false
      }
      $crgSnLinks = [CrgBootstrap.NativeV3]::GetLinkCount($crgSnEx)
      if ($crgSnLinks -ne 1) {
        Write-Host "[bootstrap] WARNING: the occupant at '$DispatcherPath' has a hard-link count of $crgSnLinks (an in-place rewrite would alter every alias, or the count could not be queried); the FAIL-CLOSED sentinel was NOT installed - repair the links by hand before committing."
        return $false
      }
      $crgSnExFs = New-Object System.IO.FileStream($crgSnEx, [System.IO.FileAccess]::ReadWrite)
      $crgSnOldMs = New-Object System.IO.MemoryStream
      $crgSnExFs.CopyTo($crgSnOldMs)
      $crgSnOldBytes = $crgSnOldMs.ToArray()
      $crgSnOldMs.Dispose()
      $crgSnAside = if ([string]::IsNullOrWhiteSpace($PreservationPath)) { "$DispatcherPath.crg-failed-$crgBackupStamp-" + [guid]::NewGuid().ToString('N').Substring(0, 8) } else { $PreservationPath }
      try {
        # The preservation copy is durably flushed, verified by
        # readback through its own handle, and that handle stays HELD
        # until this function returns -- a racer cannot remove or
        # replace the only faithful recovery copy between its report
        # and the occupant's overwrite below.
        $crgSnAsideErr = 0
        $crgSnAsideH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($crgSnAside, [ref]$crgSnAsideErr)
        if ($null -eq $crgSnAsideH -or $crgSnAsideH.IsInvalid) { throw "no-follow preservation create-new failed (Win32 error $crgSnAsideErr)" }
        $crgSnAsideFs = New-Object System.IO.FileStream($crgSnAsideH, [System.IO.FileAccess]::ReadWrite)
        $crgSnAsideH = $null
        $crgSnAsideFs.Write($crgSnOldBytes, 0, $crgSnOldBytes.Length)
        $crgSnAsideFs.Flush($true)
        $crgSnAsideFs.Position = 0
        $crgSnAsideMs = New-Object System.IO.MemoryStream
        $crgSnAsideFs.CopyTo($crgSnAsideMs)
        $crgSnAsideOk = ([System.BitConverter]::ToString($crgSnAsideMs.ToArray()) -ceq [System.BitConverter]::ToString($crgSnOldBytes))
        $crgSnAsideMs.Dispose()
        if (-not $crgSnAsideOk) { throw "the preservation copy at '$crgSnAside' did not verify byte-for-byte through its held handle" }
        $crgSnAsideVerified = $true
        Write-Host "[bootstrap] preserved unverified dispatcher bytes at '$crgSnAside' (verified through a held handle) - inspect them by hand."
      } catch {
        Write-Host "[bootstrap] WARNING: could not preserve a verified copy of the unverified dispatcher bytes ($($_.Exception.Message)); the FAIL-CLOSED sentinel was NOT installed (the occupant is never destroyed unpreserved) - unverified bytes remain at '$DispatcherPath'; repair by hand before committing."
        return $false
      }
      # The digest sidecar is removed here (best-effort, loud on
      # failure), after preservation succeeded and before the first
      # occupant-byte mutation: an abort above leaves the occupant AND
      # any still-matching attestation untouched, while from here the
      # path holds sentinel or transitional bytes. The sentinel WRITE
      # proceeds even on a refused clearing: a sentinel has no shebang,
      # so run-gate refuses it before ever consulting the digest.
      $null = Remove-CrgDispatcherDigest -DispatcherPath $DispatcherPath
      # DISARM-FIRST here as well: the occupant may carry an armed
      # shebang over unverified bytes, so byte 1 is flipped and
      # verified through the handle before the sentinel body lands --
      # a write that dies mid-sentinel leaves a hook git refuses to
      # spawn.
      $crgSnExFs.Position = 1
      $crgSnExFs.Write(([byte[]]@(0x58)), 0, 1)
      $crgSnExFs.Flush($true)
      $crgSnExFs.Position = 1
      if ($crgSnExFs.ReadByte() -ne 0x58) { throw 'the disarm byte did not read back' }
      $crgSnExFs.Position = 0
      $crgSnExFs.Write($crgSnBytes, 0, $crgSnBytes.Length)
      $crgSnExFs.SetLength($crgSnBytes.Length)
      $crgSnExFs.Flush($true)
      $crgSnExFs.Position = 0
      $crgSnChkMs = New-Object System.IO.MemoryStream
      $crgSnExFs.CopyTo($crgSnChkMs)
      $crgSnChkOk = ([System.BitConverter]::ToString($crgSnChkMs.ToArray()) -ceq [System.BitConverter]::ToString($crgSnBytes))
      $crgSnChkMs.Dispose()
      if ($crgSnChkOk) {
        Write-Host "[bootstrap] installed a FAIL-CLOSED sentinel hook at '$DispatcherPath' - every commit refuses until bootstrap is re-run."
        return $true
      }
      Write-Host "[bootstrap] WARNING: the FAIL-CLOSED sentinel could not be installed verified; the bytes at '$DispatcherPath' are UNVERIFIED but DISARMED (the occupant's shebang byte was flipped before the write, so git refuses to spawn whatever landed) - do NOT commit until repaired. Re-run bootstrap before committing."
      return $false
    } catch {
      Write-Host "[bootstrap] WARNING: the FAIL-CLOSED sentinel could not replace the occupant ($($_.Exception.Message)); UNVERIFIED bytes remain at '$DispatcherPath' - do NOT commit until repaired. Re-run bootstrap before committing."
      return $false
    } finally {
      if ($null -ne $crgSnAsideFs) {
        if ($crgSnAsideVerified) { try { $crgSnAsideFs.Dispose() } catch { } }
        else { $null = Remove-CrgOwnedScratchHandle -Path $crgSnAside -Stream $crgSnAsideFs -Label 'unverified dispatcher preservation stage' }
      } elseif ($null -ne $crgSnAsideH -and -not $crgSnAsideH.IsInvalid) {
        $null = Remove-CrgOwnedScratchHandle -Path $crgSnAside -Handle $crgSnAsideH -Label 'unverified dispatcher preservation stage'
      }
      if ($null -ne $crgSnExFs) { try { $crgSnExFs.Dispose() } catch { } }
      elseif ($null -ne $crgSnEx) { try { $crgSnEx.Dispose() } catch { } }
    }
  }
  # An EMPTY (or non-file) path: CreateNew directly, with NO move of
  # any occupant, ever -- moving an occupant off the live hook name
  # opens an empty-name interval where a concurrent commit runs
  # ungated. A collision (an occupant appearing behind the absence
  # probe, a non-file, or this function's own partial write) is
  # RECLASSIFIED through the bounded retry: a file occupant takes the
  # exclusive in-place path above on the next call, a non-file keeps
  # refusing loudly. A partial own write fails closed at spawn (no
  # complete shebang line ever exists in sentinel bytes) and under
  # sh's proper-prefix contract; the zero-byte residual past the
  # final attempt is documented in docs/local-install-v1.md
  # section 4.
  # A stale digest must not stand beside the sentinel about to land
  # (best-effort removal, loud on failure; the sentinel has no shebang,
  # so run-gate refuses it before consulting any surviving digest).
  $null = Remove-CrgDispatcherDigest -DispatcherPath $DispatcherPath
  try {
    # No-follow CREATE_NEW: a dangling reparse point at the hook name is an
    # occupant that collides (reclassified below), never a redirect that
    # creates its target outside the hooks dir.
    $crgSnNewErr = 0
    $crgSnNew = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($DispatcherPath, [ref]$crgSnNewErr)
    if ($null -eq $crgSnNew -or $crgSnNew.IsInvalid) { throw "no-follow CREATE_NEW refused (Win32 error $crgSnNewErr)" }
    $crgSnFs = New-Object System.IO.FileStream($crgSnNew, [System.IO.FileAccess]::Write)
    try { $crgSnFs.Write($crgSnBytes, 0, $crgSnBytes.Length) } finally { $crgSnFs.Dispose() }
  } catch {
    if ((Test-Path -LiteralPath $DispatcherPath) -and ($RetryDepth -lt 2)) {
      return (Install-CrgDispatcherSentinel -DispatcherPath $DispatcherPath -RetryDepth ($RetryDepth + 1) -PreservationPath $PreservationPath)
    }
    $crgSnKind = Get-CrgPathOccupantKind -Path $DispatcherPath
    Write-Host "[bootstrap] WARNING: the FAIL-CLOSED sentinel could not be created at '$DispatcherPath' ($($_.Exception.Message)) - $(switch -Wildcard -CaseSensitive ($crgSnKind) { 'file' { "an occupant holds the path; repair it by hand before committing" } 'reparse' { "a REPARSE-POINT occupant (a symlink or junction, possibly dangling) holds the hook name; no re-run can replace it -- remove the link by hand, then re-run bootstrap" } 'directory' { "a DIRECTORY occupies the path; remove it by hand, then re-run bootstrap" } 'empty' { "the path is EMPTY (git silently runs no hook); re-run bootstrap before committing" } default { "the occupant could not be classified ($crgSnKind); diagnose the path by hand before committing" } })."
    return $false
  }
  if ([string]::Equals((Get-CrgSha256HexSafe -Path $DispatcherPath), $crgSnWant, [System.StringComparison]::Ordinal)) {
    Write-Host "[bootstrap] installed a FAIL-CLOSED sentinel hook at '$DispatcherPath' - every commit refuses until bootstrap is re-run."
    return $true
  }
  if ($RetryDepth -lt 2) {
    return (Install-CrgDispatcherSentinel -DispatcherPath $DispatcherPath -RetryDepth ($RetryDepth + 1) -PreservationPath $PreservationPath)
  }
  $crgSnFinal = if (Test-Path -LiteralPath $DispatcherPath) { "UNVERIFIED bytes remain at '$DispatcherPath' - do NOT commit until repaired" } else { "the path '$DispatcherPath' is EMPTY" }
  Write-Host "[bootstrap] WARNING: the FAIL-CLOSED sentinel could not be installed verified; $crgSnFinal. Re-run bootstrap before committing."
  return $false
}
# Put the custody original back at its path and return an HONEST,
# probe-based description of where the bytes ended up -- a
# "restored" claim requires the destination to re-hash to the baseline
# (a leaf probe alone cannot rule out a filter rewrite), and with no
# baseline hash available the move is described as unverifiable rather
# than restored.
function Restore-CrgCustodySimple {
  param([string]$CustodyPath, [string]$DestPath, [string]$BaselineHash, [object]$CustodyOwner)
  $crgRsOk = $false
  if ($null -ne $CustodyOwner -and $null -ne $CustodyOwner.Stream) {
    $crgRsErr = 0
    try {
      $crgRsOk = [CrgBootstrap.NativeV4]::RenameHeldNoReplace($CustodyOwner.Stream.SafeFileHandle, $CustodyOwner.Path, $DestPath, [ref]$crgRsErr)
      if ($crgRsOk) { $CustodyOwner.Path = $DestPath }
    } catch { $crgRsOk = $false }
  } else {
    try { [System.IO.File]::Move($CustodyPath, $DestPath); $crgRsOk = $true } catch { }
  }
  if ($crgRsOk -and (Test-Path -LiteralPath $DestPath -PathType Leaf)) {
    if ([string]::IsNullOrEmpty($BaselineHash)) { return "moved back to '$DestPath' (bytes unverifiable - no baseline hash could be read)" }
    $crgRsGot = if ($null -ne $CustodyOwner -and $null -ne $CustodyOwner.Stream) { Get-CrgSha256HexOfHeldStream -Stream $CustodyOwner.Stream } else { Get-CrgSha256HexSafe -Path $DestPath }
    if ($null -ne $crgRsGot -and [string]::Equals($crgRsGot, $BaselineHash, [System.StringComparison]::Ordinal)) { return "restored to '$DestPath' (verified byte-for-byte)" }
    return "moved back to '$DestPath' but the bytes did not verify - inspect before trusting"
  }
  if (Test-Path -LiteralPath $CustodyPath -PathType Leaf) { return "preserved at '$CustodyPath' - recover it from there" }
  return "GONE from '$CustodyPath' (no recovery copy exists)"
}
# Manifest publication is an exact held-object transaction. Every listed gate
# file stays read-held while the staged manifest is verified and published, so
# the recorded cross-file snapshot cannot move under verification. The prior
# manifest, when authoritative, is a no-follow ordinary single-link object held
# from locked classification through a same-handle no-replace rename to the
# supersession name. The create-new stage is likewise retained through its
# byte-exact verification and same-handle no-replace rename to the final name.
# A late final-name or supersession-name occupant wins and is preserved; no
# pathname replacement or pathname cleanup is authorized. Failure disposes the
# exact new object and restores the exact prior object only after a fresh
# single-link check. Success can transfer both held objects to the marker
# transaction so rollback never crosses a released-identity interval.
#
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
function Publish-CrgInstallManifest {
  param([string]$ManifestPath, [string[]]$Lines, [string]$RepoRoot, [array]$FileList, [array]$PayloadOwners, [object]$PriorOwner, [string]$PriorState = 'classify', [ref]$PublicationRef)
  $pubTmp = "$ManifestPath.crg-new-$crgBackupStamp"
  $pubOld = "$ManifestPath.crg-old-$crgBackupStamp"
  $pubBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($Lines -join "`n") + "`n"))
  $pubHeld = @()
  $pubOldSrcFs = $null
  $pubStageFs = $null
  $pubPriorMoved = $false
  $pubPublished = $false
  $pubSuccess = $false
  try {
    if ($null -ne $PayloadOwners) {
      $pubSupplied = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
      foreach ($pubSuppliedOwner in @($PayloadOwners)) {
        if ($null -eq $pubSuppliedOwner -or [string]::IsNullOrWhiteSpace("$($pubSuppliedOwner.Dst)") -or $null -eq $pubSuppliedOwner.Fs -or $pubSupplied.ContainsKey("$($pubSuppliedOwner.Dst)")) { throw 'supplied payload-owner set is malformed or not bijective' }
        $pubSupplied["$($pubSuppliedOwner.Dst)"] = $pubSuppliedOwner
      }
      if ($pubSupplied.Count -ne $FileList.Count) { throw 'supplied payload-owner set does not cover the exact manifest inventory' }
      foreach ($pubF in $FileList) {
        if (-not $pubSupplied.ContainsKey($pubF.Dst) -or [CrgBootstrap.NativeV3]::GetLinkCount($pubSupplied[$pubF.Dst].Fs.SafeFileHandle) -ne 1) { throw "supplied payload owner for '$($pubF.Dst)' is absent or lost single-link shape" }
        $pubHeld += $pubSupplied[$pubF.Dst]
      }
    } else {
      foreach ($pubF in $FileList) {
        try {
          $pubPayloadOwner = Open-CrgBoundedOwnerFileNoFollow -Path (Join-Path $RepoRoot $pubF.Dst) -MaxLength 16777216 -Label "installed payload '$($pubF.Dst)'"
          $pubHeld += @{ Dst = $pubF.Dst; Fs = $pubPayloadOwner.Stream; Hash = $null }
          $pubPayloadOwner.Stream = $null
        } catch {
          Write-Host "[bootstrap] ERROR: cannot hold '$($pubF.Dst)' stable for manifest publication ($($_.Exception.Message)); refusing to publish while the file is missing, unreadable, or held by a writer. The existing manifest (if any) is untouched."
          return $null
        }
      }
    }
    $pubStageH = $null
    $pubStageErr = 0
    try {
      $pubStageH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($pubTmp, [ref]$pubStageErr)
      if ($null -eq $pubStageH -or $pubStageH.IsInvalid) { throw "create-new no-follow failed (Win32 error $pubStageErr)" }
      $pubStageFs = New-Object System.IO.FileStream($pubStageH, [System.IO.FileAccess]::ReadWrite)
      $pubStageH = $null
      $pubStageFs.Write($pubBytes, 0, $pubBytes.Length)
      $pubStageFs.Flush($true)
      $pubStageFs.Position = 0
      $pubBack = New-Object byte[] $pubBytes.Length
      $pubRead = 0
      while ($pubRead -lt $pubBack.Length) {
        $pubGot = $pubStageFs.Read($pubBack, $pubRead, $pubBack.Length - $pubRead)
        if ($pubGot -le 0) { break }
        $pubRead += $pubGot
      }
      $pubStageFs.Position = 0
      if ($pubRead -ne $pubBytes.Length -or $pubStageFs.Length -ne $pubBytes.Length -or -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$pubBack, [byte[]]$pubBytes)) { throw 'held stage did not read back byte-for-byte' }
    } finally {
      if ($null -ne $pubStageH -and -not $pubStageH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $pubTmp -Handle $pubStageH -Label 'install-manifest stage' }
    }
    $pubMap = Read-CrgInstallManifestBytes -Bytes $pubBack
    if ($null -eq $pubMap) {
      Write-Host "[bootstrap] ERROR: the freshly staged manifest failed its own strict-grammar re-read; refusing to publish it. $(if (Test-Path -LiteralPath $pubTmp -PathType Leaf) { "The unpublished record is at '$pubTmp'." } else { "The staged record no longer probes at '$pubTmp'." }) The existing manifest (if any) is untouched."
      return $null
    }
    # Verification reads THROUGH the held handles: the hash is valid
    # for the rest of the hold because the sharing mode denies every
    # other writer. Comparing a fresh path-read instead would reopen
    # the cross-file coherence gap the exclusion exists to close.
    foreach ($pubH in $pubHeld) {
      $pubHash = $null
      try {
        # Supplied freshly-written streams legitimately sit at EOF. Hash from
        # byte zero and restore the caller's position; hashing the current
        # position alone turns every such payload into the empty-file digest.
        $pubHash = Get-CrgSha256HexOfHeldStream -Stream $pubH.Fs
      } catch { }
      if ($null -eq $pubHash -or -not $pubMap.ContainsKey($pubH.Dst) -or -not [string]::Equals($pubMap[$pubH.Dst], $pubHash, [System.StringComparison]::Ordinal)) {
        Write-Host "[bootstrap] ERROR: '$($pubH.Dst)' does not hash to the digest being published (edited after it was hashed, or unreadable); refusing to publish a baseline the current files do not satisfy. Re-run bootstrap once the tree is quiescent. $(if (Test-Path -LiteralPath $pubTmp -PathType Leaf) { "The unpublished record is at '$pubTmp'." } else { "The staged record no longer probes at '$pubTmp'." }) The existing manifest (if any) is untouched."
        return $null
      }
      $pubH.Hash = $pubHash
    }
    if (-not [System.Linq.Enumerable]::Contains([string[]]@('classify', 'held', 'absent', 'foreign'), [string]$PriorState, [System.StringComparer]::Ordinal)) { throw "unrecognized prior-manifest transaction state '$PriorState'" }
    if ($PriorState -ceq 'held') {
      if ($null -eq $PriorOwner.Stream -or -not [string]::Equals("$($PriorOwner.Path)", $ManifestPath, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'the supplied prior manifest owner is absent or names a different path' }
      $pubOldSrcFs = $PriorOwner.Stream
      $PriorOwner.Stream = $null
    } elseif ($PriorState -ceq 'foreign') {
      throw 'the locked prior manifest classification was foreign or unowned; refusing to replace it'
    } elseif ($PriorState -ceq 'classify') {
      $pubPriorKind = Get-CrgPathOccupantKind -Path $ManifestPath
      if ($pubPriorKind -ceq 'file') {
        $pubOpenedPrior = Open-CrgInstallManifestOwner -ManifestPath $ManifestPath
        $pubOldSrcFs = $pubOpenedPrior.Stream
        $pubOpenedPrior.Stream = $null
      } elseif ($pubPriorKind -cne 'empty') { throw "manifest path has occupant kind $pubPriorKind" }
    }
    if ($null -ne $pubOldSrcFs) {
      if ([CrgBootstrap.NativeV3]::GetLinkCount($pubOldSrcFs.SafeFileHandle) -ne 1) { throw 'the exact previous manifest no longer has single-link shape' }
      if ([CrgBootstrap.NativeV3]::GetLinkCount($pubOldSrcFs.SafeFileHandle) -ne 1) { throw 'the exact previous manifest acquired another link before supersession' }
      $pubOldRenameErr = 0
      if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($pubOldSrcFs.SafeFileHandle, $ManifestPath, $pubOld, [ref]$pubOldRenameErr))) { throw "exact previous manifest could not move to its supersession path without replacement (Win32 error $pubOldRenameErr)" }
      $pubPriorMoved = $true
    }
    $pubPublishErr = 0
    if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($pubStageFs.SafeFileHandle, $pubTmp, $ManifestPath, [ref]$pubPublishErr))) { throw "same-handle no-replace manifest publication failed (Win32 error $pubPublishErr)" }
    $pubPublished = $true
    # SUCCESS returns the published record's DIGEST -- the exact epoch
    # identity the marker publication and any conditional rollback must
    # bind to; a re-hash of the path at a later moment could name a
    # concurrent run's manifest instead. ($null is the failure return,
    # so `-not` checks by callers stay valid.)
    $pubDoneHash = $null
    try {
      $pubDoneSha = [System.Security.Cryptography.SHA256]::Create()
      try { $pubDoneHash = ([System.BitConverter]::ToString($pubDoneSha.ComputeHash($pubBytes)) -replace '-', '').ToLowerInvariant() } finally { $pubDoneSha.Dispose() }
    } catch { }
    if ($null -eq $pubDoneHash) {
      Write-Host "[bootstrap] ERROR: could not compute the published manifest's digest for the epoch handoff; treat this publication as failed and re-run."
      return $null
    }
    $pubPublication = [pscustomobject]@{
      Hash = $pubDoneHash
      PublishedOwner = [pscustomobject]@{ Path = $ManifestPath; Stream = $pubStageFs; Bytes = $pubBytes; PayloadOwners = @($pubHeld) }
      PreviousOwner = if ($null -ne $pubOldSrcFs) { [pscustomobject]@{ Path = $pubOld; Stream = $pubOldSrcFs } } else { $null }
    }
    $pubStageFs = $null
    $pubOldSrcFs = $null
    $pubHeld = @()
    if ($null -ne $PublicationRef) { $PublicationRef.Value = $pubPublication }
    else {
      $pubPublication.PublishedOwner.Stream.Dispose()
      $pubPublication.PublishedOwner.Stream = $null
      foreach ($pubPayload in @($pubPublication.PublishedOwner.PayloadOwners)) { if ($null -ne $pubPayload.Fs) { $pubPayload.Fs.Dispose(); $pubPayload.Fs = $null } }
      if ($null -ne $pubPublication.PreviousOwner) { $pubPublication.PreviousOwner.Stream.Dispose(); $pubPublication.PreviousOwner.Stream = $null }
    }
    $pubSuccess = $true
    return $pubDoneHash
  } catch {
    Write-Host "[bootstrap] ERROR: manifest publication at '$ManifestPath' failed ($($_.Exception.Message)). No foreign occupant was overwritten."
    return $null
  } finally {
    if (-not $pubSuccess -and $null -ne $pubStageFs) {
      $pubStagePath = if ($pubPublished) { $ManifestPath } else { $pubTmp }
      $null = Remove-CrgOwnedScratchHandle -Path $pubStagePath -Stream $pubStageFs -Label $(if ($pubPublished) { 'newly published manifest' } else { 'install-manifest stage' })
      $pubStageFs = $null
    }
    if (-not $pubSuccess -and $null -ne $pubOldSrcFs) {
      if ($pubPriorMoved) {
        $pubRestoreErr = 0
        if ([CrgBootstrap.NativeV3]::GetLinkCount($pubOldSrcFs.SafeFileHandle) -ne 1) {
          Write-Host "[bootstrap] WARNING: the exact previous manifest gained another link and remains at '$pubOld'; restoration authority was revoked."
        } elseif ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($pubOldSrcFs.SafeFileHandle, $pubOld, $ManifestPath, [ref]$pubRestoreErr)) {
          Write-Host "[bootstrap] restored the exact previous manifest after publication failure -> '$ManifestPath'."
        } else {
          Write-Host "[bootstrap] WARNING: the exact previous manifest remains at '$pubOld' because the final name could not be reclaimed without replacement (Win32 error $pubRestoreErr)."
        }
      }
      try { $pubOldSrcFs.Dispose() } catch { }
      $pubOldSrcFs = $null
    }
    foreach ($pubH in $pubHeld) { if ($null -ne $pubH.Fs) { try { $pubH.Fs.Dispose() } catch { }; $pubH.Fs = $null } }
  }
}
# LOCAL-SHAPE AUTHORIZATION writer (docs/local-install-v1.md section
# 2): the byte-exact marker beside the manifest is what admits LOCAL
# authority -- the manifest alone must not, because every full install
# writes one (tracked installs use it for refresh-drift reporting), so
# a candidate commit could untrack and ignore the gate files and
# self-select local authority without any operator act. The marker is
# EPOCH-BOUND: its second line pins the SHA-256 of the just-published
# manifest, so a marker minted for an earlier local epoch dies when
# any later install or reseal republishes the manifest -- an old
# authorization cannot be replayed against a new baseline. Observation
# is PER-COMPONENT and TRI-STATE: each gate path is confirmed local
# (untracked AND ignored), confirmed non-local, or ERROR -- and any
# probe error refuses the whole decision (returns $false; callers
# abort), because a transient git failure must never strip a valid
# local install of its authorization behind a success banner. The
# marker records the AUTHORIZED PATH SET, so a hybrid layout (section
# 1: per-file trust) keeps authorization for exactly its local
# components; revocation (published as the fixed-name fail-closed
# reservation, never deleted) happens only when ZERO components are confirmed
# local. The untracking of a tracked gate component is separately
# guarded at every landing gateway -- the hook's and the installed
# dispatcher's per-commit gate-untracking sanction, and the merge
# gate's base..tip range guard -- closing the re-track-then-untrack
# replay cycle.
# INTERPROCESS TRANSACTION LOCK for the whole manifest+marker transaction:
# authority comes from a no-follow ordinary single-link lock object held with
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
function Get-CrgSha256HexOfHeldStream {
  param([object]$Stream)
  if ($null -eq $Stream -or -not $Stream.CanRead) { throw 'a readable held stream is required' }
  $crgSPos = $Stream.Position
  try {
    $Stream.Position = 0
    $crgSSha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($crgSSha.ComputeHash($Stream)) -replace '-', '').ToLowerInvariant() } finally { $crgSSha.Dispose() }
  } finally { $Stream.Position = $crgSPos }
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

function Enter-CrgInstallTransactionLock {
  param([string]$GitDir)
  return Open-CrgTransactionLockNoFollow -Path (Join-Path $GitDir 'crg-install-lock') -Name 'install'
}
# The DISPATCHER lock is a separate lock keyed to the git COMMON dir:
# the baseline (manifest+marker) is per-worktree, but every linked
# worktree shares its dispatcher at the common hooks path, so a
# per-worktree lock cannot serialize dispatcher mutation -- sibling
# worktrees would hold distinct locks while racing the same file.
# Every operation that mutates OR validates-for-arming the shared
# dispatcher holds this lock; when the per-worktree install lock is
# also needed, the FIXED ORDER is common dispatcher lock first, then
# the per-worktree lock. Same handle-exclusivity discipline as the
# install lock (persistent OpenOrCreate file, FileShare.None, loud
# refusal, no deletion ever needed).
function Enter-CrgDispatcherLock {
  param([string]$CommonDir)
  return Open-CrgTransactionLockNoFollow -Path (Join-Path $CommonDir 'crg-dispatcher-lock') -Name 'dispatcher'
}
# PROBE half: runs BEFORE the manifest is published, so a probe error
# aborts with EVERYTHING untouched -- the previous manifest, and a
# previous marker still bound to it and therefore still valid.
function Get-CrgLocalAuthorizationPaths {
  param([string]$RepoRoot, [array]$FileList)
  $crgAuthPaths = @()
  foreach ($crgAuthF in $FileList) {
    try { $crgAuthTracked = @(& git -C $RepoRoot ls-files --cached -- $crgAuthF.Dst 2>$null) } catch { $crgAuthTracked = $null }
    if ($null -eq $crgAuthTracked -or $LASTEXITCODE -ne 0) {
      Write-Host "[bootstrap] ERROR: could not probe the tracked state of '$($crgAuthF.Dst)' for the local-shape authorization; refusing to decide authorization on a failed probe (nothing was published; the existing manifest and marker, if any, are untouched)."
      return @{ Ok = $false; Paths = @() }
    }
    if ($crgAuthTracked.Count -gt 0) { continue }
    $crgAuthIgn = Get-CrgCheckIgnoreState -Repo $RepoRoot -Path $crgAuthF.Dst
    if ($crgAuthIgn -clike 'error:*') {
      Write-Host "[bootstrap] ERROR: could not probe the ignore state of '$($crgAuthF.Dst)' ($crgAuthIgn) for the local-shape authorization; refusing to decide authorization on a failed probe (nothing was published; the existing manifest and marker, if any, are untouched)."
      return @{ Ok = $false; Paths = @() }
    }
    if ($crgAuthIgn -ceq 'ignored') { $crgAuthPaths += $crgAuthF.Dst }
  }
  return @{ Ok = $true; Paths = $crgAuthPaths }
}
# PUBLISH half: the marker's locked-start state is explicit. A held prior marker
# never leaves the fixed authority name: its exact bytes are backed up, then the
# held fixed object is rewritten disarm-first to a full-length invalid record.
# Positive absence publishes the same invalid record create-new/no-replace.
# Manifest publication occurs only while that exact invalid/revoked object is
# held. Finalization rewrites the full invalid body and flips the one commit byte
# last through the same handle. Failure returns 'failed-reserved' with the exact
# invalid marker and recovery object still held for delete-new/restore-old/
# restore-marker ordering; success returns 'ok'.

# ARMING PRECONDITION for local trust: a marker must never be ARMED
# beside a dispatcher that predates the gate-untracking guard -- a
# pre-guard dispatcher honors the audited skip before the tracked hook
# runs, and an armed marker beside it would recreate the one landing
# surface new code cannot reach retroactively. Every arming caller
# (the install transaction and the seal) validates the ON-DISK
# dispatcher for that guard marker and the absence of retired PROJECT-MODE
# enforcement -- and the validation must stay TRUE at the
# instant the marker lands, so the content is read through a handle
# that denies writes, deletion, and renames (FileShare.Read), which
# the caller HOLDS from validation through marker publication and
# disposes afterwards. Absence, unreadability, and a missing marker
# all fail closed like every other authorization probe (Ok=$false,
# Handle=$null -- nothing to hold). A revoke (no local paths) disarms
# and needs no dispatcher.
function Get-CrgDispatcherGuardHold {
  param([string]$RepoRoot)
  $capOwner = $null
  try {
    $capHooksRel = (Invoke-CrgGitUtf8 -GitArgs @('-C', $RepoRoot, 'rev-parse', '--git-path', 'hooks/pre-commit'))
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($capHooksRel)) { return @{ Ok = $false; Handle = $null } }
    # --git-path is repo-relative in a plain repo; anchor it at the
    # repo root, never the process CWD.
    $capHooksRel = "$capHooksRel".Trim()
    $capDisp = if ([System.IO.Path]::IsPathRooted($capHooksRel)) { $capHooksRel } else { Join-Path $RepoRoot $capHooksRel }
    $capOwner = Open-CrgBoundedOwnerFileNoFollow -Path $capDisp -MaxLength 16777216 -Label 'installed dispatcher'
    $capContent = [System.Text.Encoding]::UTF8.GetString($capOwner.Bytes)
    $capHasRetiredProjectMode =
      ($capContent.IndexOf("PM_DECLARATION='PROJECT-MODE.md'", [System.StringComparison]::Ordinal) -ge 0) -or
      ($capContent.IndexOf('pm_staged_touches_declaration()', [System.StringComparison]::Ordinal) -ge 0) -or
      ($capContent.IndexOf('project-mode attestation FAILED', [System.StringComparison]::Ordinal) -ge 0)
    if (($capContent.IndexOf('crg-gate-untrack-guard-v1', [System.StringComparison]::Ordinal) -ge 0) -and
        (-not $capHasRetiredProjectMode)) {
      $capHeld = $capOwner.Stream
      $capOwner.Stream = $null
      return @{ Ok = $true; Handle = $capHeld }
    }
    return @{ Ok = $false; Handle = $null }
  } catch {
    return @{ Ok = $false; Handle = $null }
  } finally {
    if ($null -ne $capOwner -and $null -ne $capOwner.Stream) { try { $capOwner.Stream.Dispose() } catch { } }
  }
}

function Set-CrgHeldMarkerBytesCommitLast {
  param([object]$Stream, [byte[]]$FinalBytes)

  if ($null -eq $Stream -or -not $Stream.CanRead -or -not $Stream.CanWrite -or $null -eq $FinalBytes -or $FinalBytes.Length -lt 1) { return $false }
  $cmInvalid = [byte[]]$FinalBytes.Clone()
  $cmInvalid[0] = [byte][char]'x'
  try {
    # Disarm the currently visible object before any length or tail changes.
    # Every intermediate byte string therefore begins with an invalid token.
    $Stream.Position = 0
    $Stream.WriteByte([byte][char]'x')
    $Stream.Flush($true)
    $Stream.Position = 0
    $Stream.Write($cmInvalid, 0, $cmInvalid.Length)
    $Stream.SetLength($cmInvalid.Length)
    $Stream.Flush($true)
    if ($Stream.Length -ne $cmInvalid.Length -or
        -not [string]::Equals((Get-CrgSha256HexOfHeldStream -Stream $Stream), (Get-CrgSha256HexOfBytes -Bytes $cmInvalid), [System.StringComparison]::Ordinal)) { return $false }
    # One byte is the commit record. No fallible transformation follows it.
    $Stream.Position = 0
    $Stream.WriteByte($FinalBytes[0])
    $Stream.Flush($true)
    $cmCommitted = $Stream.Length -eq $FinalBytes.Length -and
      [string]::Equals((Get-CrgSha256HexOfHeldStream -Stream $Stream), (Get-CrgSha256HexOfBytes -Bytes $FinalBytes), [System.StringComparison]::Ordinal)
    if (-not $cmCommitted) {
      # A detected post-commit fault returns the fixed name to invalid before
      # releasing authority. A process stop after the commit byte is the defined
      # successful metadata commit point; every earlier persisted state refuses.
      $Stream.Position = 0
      $Stream.WriteByte([byte][char]'x')
      $Stream.Flush($true)
      return $false
    }
    return $true
  } catch {
    try { $Stream.Position = 0; $Stream.WriteByte([byte][char]'x'); $Stream.Flush($true) } catch { }
    return $false
  }
}

# Publish a held fail-closed marker reservation BEFORE the manifest can move.
# A crash then leaves the fixed marker name absent or explicitly revoked, never
# an older marker that can accidentally bind a predictable new-manifest digest.
function Start-CrgLocalAuthorizationMarkerReservationExact {
  param([string]$GitDir, [array]$Paths, [string]$ExpectedManifestHash, [object]$PriorOwner, [string]$PriorState = 'classify')

  $mrPath = Join-Path $GitDir 'crg-local-install'
  $mrStage = "$mrPath.crg-reserve-$crgBackupStamp"
  $mrOld = "$mrPath.crg-old-$crgBackupStamp"
  if ($Paths.Count -eq 0) {
    $mrFinalBytes = [System.Text.Encoding]::ASCII.GetBytes("crg-local-install-authorization revoked`n")
    $mrInvalidBytes = $mrFinalBytes
    $mrCommitted = $true
  } else {
    if ([string]::IsNullOrEmpty($ExpectedManifestHash) -or $ExpectedManifestHash -cnotmatch '\A[0-9a-f]{64}\z') { throw 'a strict expected manifest digest is required for an armed marker reservation' }
    $mrFinalBytes = [System.Text.Encoding]::ASCII.GetBytes("crg-local-install-authorization v1`nmanifest-sha256: $ExpectedManifestHash`n" + (($Paths -join "`n") + "`n"))
    $mrInvalidBytes = [byte[]]$mrFinalBytes.Clone()
    # The fixed-name reservation already has its final length and tail before
    # manifest publication. Only this deliberately invalid first byte differs;
    # finalization flips it last, so every prefix/old-tail intermediate refuses.
    $mrInvalidBytes[0] = [byte][char]'x'
    $mrCommitted = $false
  }
  $mrPrior = $null
  $mrReservationFs = $null
  $mrBackupFs = $null
  $mrBackupPath = $null
  $mrFreshStagePath = $null
  $mrRewroteFixed = $false
  $mrSuccess = $false
  try {
    if (-not [System.Linq.Enumerable]::Contains([string[]]@('classify', 'held', 'absent', 'foreign'), [string]$PriorState, [System.StringComparer]::Ordinal)) { throw "unrecognized prior-marker transaction state '$PriorState'" }
    if ($PriorState -ceq 'held') {
      if ($null -eq $PriorOwner -or $null -eq $PriorOwner.Stream -or -not [string]::Equals("$($PriorOwner.Path)", $mrPath, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'the supplied prior marker owner is absent or names a different path' }
      $mrPrior = [pscustomobject]@{ Path = $PriorOwner.Path; Stream = $PriorOwner.Stream; Bytes = $PriorOwner.Bytes }
      $PriorOwner.Stream = $null
    } elseif ($PriorState -ceq 'foreign') {
      throw 'the locked prior marker classification was foreign or unowned; refusing to reserve its authority name'
    } elseif ($PriorState -ceq 'classify') {
      $mrKind = Get-CrgPathOccupantKind -Path $mrPath
      if ($mrKind -ceq 'file') { $mrPrior = Open-CrgBoundedOwnerFileNoFollow -Path $mrPath -MaxLength 1048576 -Label 'local-shape authorization marker' -Writable }
      elseif ($mrKind -cne 'empty') { throw "authorization-marker path has occupant kind $mrKind" }
    }

    if ($null -ne $mrPrior) {
      # Preserve the prior bytes under a held create-new recovery object BEFORE
      # disarming the fixed name. The fixed object itself never moves: it is
      # rewritten in place to the invalid/revoked reservation, eliminating the
      # old-manifest + marker-vacancy authority gap.
      $mrBackupH = $null
      $mrBackupErr = 0
      try {
        $mrBackupH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($mrOld, [ref]$mrBackupErr)
        if ($null -eq $mrBackupH -or $mrBackupH.IsInvalid) { throw "previous-marker recovery create-new failed (Win32 error $mrBackupErr)" }
        $mrBackupFs = New-Object System.IO.FileStream($mrBackupH, [System.IO.FileAccess]::ReadWrite)
        $mrBackupH = $null
        $mrBackupFs.Write($mrPrior.Bytes, 0, $mrPrior.Bytes.Length)
        $mrBackupFs.Flush($true)
        if ($mrBackupFs.Length -ne $mrPrior.Bytes.Length -or
            -not [string]::Equals((Get-CrgSha256HexOfHeldStream -Stream $mrBackupFs), (Get-CrgSha256HexOfBytes -Bytes $mrPrior.Bytes), [System.StringComparison]::Ordinal)) { throw 'previous-marker recovery object did not verify byte-for-byte' }
        $mrBackupPath = $mrOld
      } finally {
        if ($null -ne $mrBackupH -and -not $mrBackupH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $mrOld -Handle $mrBackupH -Label 'previous-marker recovery object' }
      }
      if ([CrgBootstrap.NativeV3]::GetLinkCount($mrPrior.Stream.SafeFileHandle) -ne 1) { throw 'the exact previous marker acquired another link before reservation' }
      $mrRewroteFixed = $true
      if (-not (Set-CrgHeldMarkerBytesCommitLast -Stream $mrPrior.Stream -FinalBytes $mrInvalidBytes)) { throw 'the fixed previous marker could not be rewritten to the fail-closed reservation' }
      $mrReservationFs = $mrPrior.Stream
      $mrPrior.Stream = $null
    } else {
      $mrStageH = $null
      $mrStageErr = 0
      try {
        $mrStageH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($mrStage, [ref]$mrStageErr)
        if ($null -eq $mrStageH -or $mrStageH.IsInvalid) { throw "marker reservation create-new failed (Win32 error $mrStageErr)" }
        $mrReservationFs = New-Object System.IO.FileStream($mrStageH, [System.IO.FileAccess]::ReadWrite)
        $mrStageH = $null
        $mrFreshStagePath = $mrStage
        $mrReservationFs.Write($mrInvalidBytes, 0, $mrInvalidBytes.Length)
        $mrReservationFs.Flush($true)
        if ($mrReservationFs.Length -ne $mrInvalidBytes.Length -or
            -not [string]::Equals((Get-CrgSha256HexOfHeldStream -Stream $mrReservationFs), (Get-CrgSha256HexOfBytes -Bytes $mrInvalidBytes), [System.StringComparison]::Ordinal)) { throw 'marker reservation did not read back byte-for-byte' }
      } finally {
        if ($null -ne $mrStageH -and -not $mrStageH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $mrStage -Handle $mrStageH -Label 'authorization-marker reservation stage' }
      }
      $mrPublishErr = 0
      if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($mrReservationFs.SafeFileHandle, $mrStage, $mrPath, [ref]$mrPublishErr))) { throw "same-handle no-replace marker reservation failed (Win32 error $mrPublishErr)" }
      $mrFreshStagePath = $null
    }
    if ([CrgBootstrap.NativeV3]::GetLinkCount($mrReservationFs.SafeFileHandle) -ne 1) { throw 'the fixed marker reservation no longer has one exact namespace identity' }
    if ($null -ne $mrBackupFs -and [CrgBootstrap.NativeV3]::GetLinkCount($mrBackupFs.SafeFileHandle) -ne 1) { throw 'the previous-marker recovery object no longer has one exact namespace identity' }
    $mrResult = [pscustomobject]@{
      ReservationOwner = [pscustomobject]@{ Path = $mrPath; Stream = $mrReservationFs; Bytes = $mrInvalidBytes }
      PreviousOwner = if ($null -ne $mrBackupFs) { [pscustomobject]@{ Path = $mrBackupPath; Stream = $mrBackupFs; Bytes = $mrPrior.Bytes } } else { $null }
      FinalBytes = $mrFinalBytes
      InvalidBytes = $mrInvalidBytes
      Committed = $mrCommitted
    }
    $mrReservationFs = $null
    $mrBackupFs = $null
    $mrPrior = $null
    $mrSuccess = $true
    return $mrResult
  } catch {
    Write-Host "[bootstrap] ERROR: fail-closed marker reservation failed ($($_.Exception.Message)). No manifest was published."
    return $null
  } finally {
    if (-not $mrSuccess -and $null -ne $mrReservationFs) {
      if ($mrRewroteFixed) {
        # Preserve the invalid/revoked fixed-name object. Deleting it beside the
        # still-live prior manifest would reopen an authorization namespace.
        try { $mrReservationFs.Dispose() } catch { }
      } else {
        $null = Remove-CrgOwnedScratchHandle -Path $mrFreshStagePath -Stream $mrReservationFs -Label 'authorization-marker reservation stage'
      }
      $mrReservationFs = $null
    }
    if (-not $mrSuccess -and $null -ne $mrBackupFs) {
      if ($mrRewroteFixed) {
        try { $mrBackupFs.Dispose() } catch { }
        Write-Host "[bootstrap] WARNING: the exact previous marker bytes remain in the held recovery object at '$mrBackupPath'; the fixed marker name remains fail-closed."
      } else {
        $null = Remove-CrgOwnedScratchHandle -Path $mrBackupPath -Stream $mrBackupFs -Label 'unused previous-marker recovery object'
      }
      $mrBackupFs = $null
    }
    if ($null -ne $mrPrior -and $null -ne $mrPrior.Stream) {
      try { $mrPrior.Stream.Dispose() } catch { }
      $mrPrior.Stream = $null
    }
  }
}

function Publish-CrgLocalAuthorizationMarkerExact {
  param([string]$GitDir, [array]$Paths, [string]$ManifestPath, [string]$ExpectedManifestHash, [object]$ManifestOwner, [object]$GuardHold, [object]$Reservation, [ref]$FailedReservationRef)

  $amPath = Join-Path $GitDir 'crg-local-install'
  $amOld = "$amPath.crg-old-$crgBackupStamp"
  $amPrior = $null
  $amReservationFs = $null
  $amManifestFs = $null
  $amPayloadOwners = @()
  try {
    if ($null -eq $Reservation -or $null -eq $Reservation.ReservationOwner -or $null -eq $Reservation.ReservationOwner.Stream -or
        -not [string]::Equals("$($Reservation.ReservationOwner.Path)", $amPath, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'the supplied fail-closed marker reservation is absent or names a different path' }
    $amReservationFs = $Reservation.ReservationOwner.Stream
    $Reservation.ReservationOwner.Stream = $null
    if ($null -eq $Reservation.InvalidBytes -or $amReservationFs.Length -ne $Reservation.InvalidBytes.Length -or
        -not [string]::Equals((Get-CrgSha256HexOfHeldStream -Stream $amReservationFs), (Get-CrgSha256HexOfBytes -Bytes $Reservation.InvalidBytes), [System.StringComparison]::Ordinal)) { throw 'the held marker reservation is not the exact planned fail-closed record' }
    if ($null -ne $Reservation.PreviousOwner) {
      if ($null -eq $Reservation.PreviousOwner.Stream -or -not [string]::Equals("$($Reservation.PreviousOwner.Path)", $amOld, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'the supplied previous marker owner is not retained at the expected rollback path' }
      $amPrior = $Reservation.PreviousOwner
      $Reservation.PreviousOwner = $null
    }

    if ($Paths.Count -eq 0) {
      $amBytes = [System.Text.Encoding]::ASCII.GetBytes("crg-local-install-authorization revoked`n")
      $amWhat = 'published the fail-closed revoked local-shape authorization marker (no local component observed)'
    } else {
      if ($null -eq $GuardHold -or $null -eq $GuardHold.Handle -or
          [CrgBootstrap.NativeV3]::GetLinkCount($GuardHold.Handle.SafeFileHandle) -ne 1) { throw 'the validated dispatcher is not retained as one exact ordinary single-link object through marker commit' }
      if ($null -ne $ManifestOwner) {
        if ($null -eq $ManifestOwner.Stream -or -not [string]::Equals("$($ManifestOwner.Path)", $ManifestPath, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'the supplied published-manifest owner is absent or names a different path' }
        $amManifestFs = $ManifestOwner.Stream
      } else {
        throw 'an armed marker requires the exact published-manifest owner and retained payload identities'
      }
      $amManifestHash = Get-CrgSha256HexOfHeldStream -Stream $amManifestFs
      if ([string]::IsNullOrEmpty($ExpectedManifestHash) -or -not [string]::Equals($amManifestHash, $ExpectedManifestHash, [System.StringComparison]::Ordinal)) { throw 'the held manifest is not the exact epoch this run published' }
      $amPayloadProperty = $ManifestOwner.PSObject.Properties['PayloadOwners']
      $amPayloadOwners = if ($null -ne $amPayloadProperty) { @($amPayloadProperty.Value) } else { @() }
      if ($amPayloadOwners.Count -eq 0) { throw 'the published manifest does not retain its installed payload identities through marker commit' }
      foreach ($amPayload in $amPayloadOwners) {
        if ($null -eq $amPayload.Fs -or [CrgBootstrap.NativeV3]::GetLinkCount($amPayload.Fs.SafeFileHandle) -ne 1) { throw "installed payload '$($amPayload.Dst)' lost its retained ordinary single-link identity before marker commit" }
        $amHeldPayloadHash = Get-CrgSha256HexOfHeldStream -Stream $amPayload.Fs
        if ([string]::IsNullOrEmpty("$($amPayload.Hash)") -or -not [string]::Equals($amHeldPayloadHash, "$($amPayload.Hash)", [System.StringComparison]::Ordinal)) { throw "installed payload '$($amPayload.Dst)' changed before marker commit" }
      }
      $amBytes = [System.Text.Encoding]::ASCII.GetBytes("crg-local-install-authorization v1`nmanifest-sha256: $amManifestHash`n" + (($Paths -join "`n") + "`n"))
      $amWhat = "wrote local-shape authorization marker ($($Paths.Count) local component(s) authorized)"
    }

    if ([CrgBootstrap.NativeV3]::GetLinkCount($amReservationFs.SafeFileHandle) -ne 1) { throw 'the fixed marker reservation acquired another link before final publication' }
    if ($null -eq $Reservation.FinalBytes -or $Reservation.FinalBytes.Length -ne $amBytes.Length -or
        -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$Reservation.FinalBytes, [byte[]]$amBytes)) { throw 'the planned reservation bytes do not match the final marker for the held manifest epoch' }
    if ($Paths.Count -gt 0) {
      $amManifestNow = Get-CrgSha256HexOfHeldStream -Stream $amManifestFs
      if (-not [string]::Equals($amManifestNow, $amManifestHash, [System.StringComparison]::Ordinal)) { throw 'the held manifest failed marker revalidation' }
    }
    if ([CrgBootstrap.NativeV3]::GetLinkCount($amReservationFs.SafeFileHandle) -ne 1) { throw 'the fixed marker reservation acquired another link at the final commit boundary' }
    if ($Paths.Count -gt 0 -and [CrgBootstrap.NativeV3]::GetLinkCount($GuardHold.Handle.SafeFileHandle) -ne 1) { throw 'the retained dispatcher acquired another link at the final commit boundary' }
    foreach ($amPayload in $amPayloadOwners) {
      if ([CrgBootstrap.NativeV3]::GetLinkCount($amPayload.Fs.SafeFileHandle) -ne 1) { throw "installed payload '$($amPayload.Dst)' acquired another link at the final commit boundary" }
    }
    if (-not (Set-CrgHeldMarkerBytesCommitLast -Stream $amReservationFs -FinalBytes $amBytes)) { throw 'same-handle marker commit-last finalization failed and the fixed name was returned to its invalid state' }
    $Reservation.Committed = $true
    $amReservationFs.Dispose()
    $amReservationFs = $null
    if ($null -ne $amPrior) {
      $null = Remove-CrgOwnedScratchHandle -Path $amOld -Stream $amPrior.Stream -Label 'superseded authorization-marker recovery object'
      $amPrior = $null
    }
    Write-Host "[bootstrap] $amWhat -> $amPath"
    return 'ok'
  } catch {
    Write-Host "[bootstrap] ERROR: exact local-shape authorization publication failed ($($_.Exception.Message))."
    if ($null -ne $amReservationFs -and $null -ne $Reservation.InvalidBytes -and
        [CrgBootstrap.NativeV3]::GetLinkCount($amReservationFs.SafeFileHandle) -eq 1) {
      $null = Set-CrgHeldMarkerBytesCommitLast -Stream $amReservationFs -FinalBytes $Reservation.InvalidBytes
    }
    if ($null -ne $FailedReservationRef -and $null -ne $Reservation) {
      if ($null -ne $Reservation.ReservationOwner) { $Reservation.ReservationOwner.Stream = $amReservationFs }
      $Reservation.PreviousOwner = $amPrior
      $Reservation.Committed = $false
      $FailedReservationRef.Value = $Reservation
      $amReservationFs = $null
      $amPrior = $null
    }
    return 'failed-reserved'
  } finally {
    if ($null -ne $amReservationFs) { try { $amReservationFs.Dispose() } catch { } }
    if ($null -ne $amPrior -and $null -ne $amPrior.Stream) { try { $amPrior.Stream.Dispose() } catch { } }
  }
}
function Restore-CrgManifestPublicationExact {
  param([string]$ManifestPath, [string]$OnlyIfManifestHash, [object]$Publication, [object]$MarkerReservation)

  $mxNew = if ($null -ne $Publication) { $Publication.PublishedOwner } else { $null }
  $mxOld = if ($null -ne $Publication) { $Publication.PreviousOwner } else { $null }
  $mxCurrentMarker = if ($null -ne $MarkerReservation) { $MarkerReservation.ReservationOwner } else { $null }
  $mxPreviousMarker = if ($null -ne $MarkerReservation) { $MarkerReservation.PreviousOwner } else { $null }
  try {
    if ($null -eq $mxNew -or $null -eq $mxNew.Stream) {
      Write-Host '[bootstrap] no held manifest publication exists for exact rollback; the current invalid marker reservation remains fail-closed for hand repair.'
      return $false
    }
    $mxMarkerPath = Join-Path (Split-Path -Parent $ManifestPath) 'crg-local-install'
    $mxMarkerGuarded = $false
    if ($null -eq $mxCurrentMarker -or $null -eq $mxCurrentMarker.Stream -or
        -not [string]::Equals("$($mxCurrentMarker.Path)", $mxMarkerPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        $null -eq $MarkerReservation.InvalidBytes -or
        [CrgBootstrap.NativeV3]::GetLinkCount($mxCurrentMarker.Stream.SafeFileHandle) -ne 1) {
      Write-Host '[bootstrap] no exact invalid marker reservation spans failed-manifest rollback; the exact new manifest must remain live because no manifest namespace mutation is safe.'
    } else {
      $mxMarkerGuarded = Set-CrgHeldMarkerBytesCommitLast -Stream $mxCurrentMarker.Stream -FinalBytes $MarkerReservation.InvalidBytes
      if (-not $mxMarkerGuarded) { Write-Host '[bootstrap] WARNING: the fixed marker could not be re-proven invalid; no previous metadata will be restored.' }
    }
    if (-not $mxMarkerGuarded) {
      Write-Host '[bootstrap] the exact new manifest remains live because marker invalidation was not positively held and verified; no manifest namespace mutation is safe.'
      return $false
    }
    $mxHash = $null
    try { $mxHash = Get-CrgSha256HexOfHeldStream -Stream $mxNew.Stream } catch { }
    $mxEpochMatches = -not [string]::IsNullOrEmpty($OnlyIfManifestHash) -and $null -ne $mxHash -and
      [string]::Equals($mxHash, $OnlyIfManifestHash, [System.StringComparison]::Ordinal)
    if (-not $mxEpochMatches) { Write-Host '[bootstrap] the retained new manifest digest is indeterminate, but the exact held object is still disarmed; previous-state restoration is suppressed.' }
    if (-not (Remove-CrgOwnedScratchHandle -Path $ManifestPath -Stream $mxNew.Stream -Label 'new manifest after failed marker publication')) {
      $mxNew.Stream = $null
      Write-Host '[bootstrap] WARNING: the exact new manifest could not be dispositioned after marker failure; the invalid fixed-name marker remains fail-closed for hand repair.'
      return $false
    }
    $mxNew.Stream = $null

    # Restore the prior manifest while the fixed marker is still invalid. A
    # foreign manifest winner therefore cannot pair with valid prior-marker
    # bytes; the marker commit occurs only after this exact rename succeeds.
    $mxHadPriorManifest = $null -ne $mxOld -and $null -ne $mxOld.Stream
    $mxOldRestored = -not $mxHadPriorManifest
    if (-not $mxOldRestored -and $mxEpochMatches -and $mxMarkerGuarded) {
      $mxRestoreErr = 0
      if ([CrgBootstrap.NativeV3]::GetLinkCount($mxOld.Stream.SafeFileHandle) -eq 1 -and
          [CrgBootstrap.NativeV4]::RenameHeldNoReplace($mxOld.Stream.SafeFileHandle, $mxOld.Path, $ManifestPath, [ref]$mxRestoreErr)) {
        $mxOld.Path = $ManifestPath
        $mxOldRestored = $true
      } else {
        Write-Host "[bootstrap] WARNING: the exact previous manifest remains at '$($mxOld.Path)'; the live manifest name was not reclaimed while the marker stayed invalid."
      }
    }

    $mxMarkerRestored = $null -eq $mxPreviousMarker -or $null -eq $mxPreviousMarker.Stream
    if ($mxHadPriorManifest -and $mxOldRestored -and $mxEpochMatches -and $mxMarkerGuarded -and -not $mxMarkerRestored -and
        [CrgBootstrap.NativeV3]::GetLinkCount($mxOld.Stream.SafeFileHandle) -eq 1 -and
        $null -ne $mxCurrentMarker -and $null -ne $mxCurrentMarker.Stream -and
        [CrgBootstrap.NativeV3]::GetLinkCount($mxCurrentMarker.Stream.SafeFileHandle) -eq 1 -and
        [CrgBootstrap.NativeV3]::GetLinkCount($mxPreviousMarker.Stream.SafeFileHandle) -eq 1 -and
        $null -ne $mxPreviousMarker.Bytes -and $mxPreviousMarker.Bytes.Length -gt 0) {
      if (Set-CrgHeldMarkerBytesCommitLast -Stream $mxCurrentMarker.Stream -FinalBytes $mxPreviousMarker.Bytes) {
        $mxMarkerRestored = $true
        if (-not (Remove-CrgOwnedScratchHandle -Path $mxPreviousMarker.Path -Stream $mxPreviousMarker.Stream -Label 'previous-marker recovery object after exact rollback')) {
          $mxPreviousMarker.Stream = $null
          Write-Host "[bootstrap] WARNING: previous marker bytes were restored, but the exact recovery object remains at '$($mxPreviousMarker.Path)'."
        } else { $mxPreviousMarker.Stream = $null }
      }
    }
    if ($mxOldRestored -and $mxMarkerRestored) {
      Write-Host '[bootstrap] failed marker publication rolled back to the previous metadata state through retained handles.'
      return $true
    }
    if (-not $mxHadPriorManifest -and -not $mxMarkerRestored) {
      Write-Host '[bootstrap] prior manifest absence cannot authorize rearming a previous marker; the fixed marker remains invalid and the exact prior-marker recovery object is preserved.'
    }
    Write-Host '[bootstrap] the exact new manifest was removed and the fixed marker remains invalid; unrecoverable prior objects were preserved for hand repair.'
    return $true
  } finally {
    if ($null -ne $mxNew) {
      $mxPayloadProperty = $mxNew.PSObject.Properties['PayloadOwners']
      if ($null -ne $mxPayloadProperty) {
        foreach ($mxPayloadOwner in @($mxPayloadProperty.Value)) { if ($null -ne $mxPayloadOwner.Fs) { try { $mxPayloadOwner.Fs.Dispose() } catch { }; $mxPayloadOwner.Fs = $null } }
      }
    }
    if ($null -ne $mxNew -and $null -ne $mxNew.Stream) { try { $mxNew.Stream.Dispose() } catch { }; $mxNew.Stream = $null }
    if ($null -ne $mxOld -and $null -ne $mxOld.Stream) { try { $mxOld.Stream.Dispose() } catch { }; $mxOld.Stream = $null }
    if ($null -ne $mxCurrentMarker -and $null -ne $mxCurrentMarker.Stream) { try { $mxCurrentMarker.Stream.Dispose() } catch { }; $mxCurrentMarker.Stream = $null }
    if ($null -ne $mxPreviousMarker -and $null -ne $mxPreviousMarker.Stream) { try { $mxPreviousMarker.Stream.Dispose() } catch { }; $mxPreviousMarker.Stream = $null }
  }
}
# Hash read that ANSWERS instead of throwing: the post-rename
# verification branches must reach their rollback/diagnostic paths even
# when the file vanished, became unreadable, or is exclusively locked --
# an exception there would skip rollback and leave the path empty.
function Get-CrgSha256HexSafe {
  param([string]$Path)
  try { return Get-CrgSha256Hex -Path $Path } catch { return $null }
}

# Resolve package root (directory containing this script).
$packageRoot = Split-Path -Parent $PSCommandPath
if ([string]::IsNullOrWhiteSpace($packageRoot)) {
  Write-Error "bootstrap.ps1: could not resolve package root from `$PSCommandPath"
  exit 1
}

# The package's own version, read from the VERSION file beside this script --
# never a constant duplicated in code, because a second copy is a value that can
# disagree with the file a release tags. A release is the tag plus the zip built
# from the tagged tree, so VERSION is the one thing that has to be right.
#
# The reader returns $null for missing, unreadable, or malformed bytes rather
# than inventing a value. Full-install callers treat that result as fatal package
# damage before mutation; payload-free dispatcher refresh, manifest seal, and
# routing-custody recovery operations do not read VERSION at all.
#
# Validated on the RAW BYTES against an exact grammar, before any normalization.
# Trimming first and validating after cannot enforce a single-line contract: the
# trim removes the very CR/LF a multi-line file would be rejected for, so
# blank-wrapped multi-line content passes a later `[\r\n]` test. The grammar is
# SemVer because the version exists to be COMPARED -- an arbitrary printable
# string satisfies "a version was recorded" while making "is this newer"
# undecidable, so accepting one would defer a contradiction into the upgrade
# path rather than reject it here.
# ONE SemVer accept-set, used by the package VERSION reader and the install
# record reader alike. Two grammars would let a record hold a version the
# package's own reader would reject, and the refusal compares those two values
# to each other -- so a looser record grammar is a way to disarm it.
$script:CrgSemVerBody = "\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)" +
                        "(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?" +
                        "(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?"

# One accept-set, two entry points -- the same shape the install-record reader
# uses. The BYTES form exists so the version can be re-derived from the buffered
# snapshot that provenance is proven against, without a second re-read of a file
# that may have changed since.
function Get-CrgPackageVersionFromBytes {
  param([byte[]]$Bytes)
  $verBytes = $Bytes
  if ($null -eq $verBytes) { return $null }
  return (Convert-CrgVersionBytes -Bytes $verBytes)
}

function Get-CrgPackageVersion {
  param([string]$Root)
  $verPath = Join-Path $Root 'VERSION'
  if (-not (Test-Path -LiteralPath $verPath -PathType Leaf)) { return $null }
  try { $verBytes = [System.IO.File]::ReadAllBytes($verPath) } catch { return $null }
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
  #
  # The grammar BODY is shared with the install-record reader. A record whose
  # version does not satisfy the same grammar as the package's cannot be
  # compared against it, and a looser record grammar was how a damaged record
  # could equal the package version by accident and disarm the refusal.
  if ($verText -cnotmatch ($script:CrgSemVerBody + "(\r\n|\n)?\z")) { return $null }
  return $verText.TrimEnd("`r", "`n")
}

# Strict reader for a published install-version record. Returns a hashtable with
# Version/SourceCommit/Installed, or $null when the record is absent or does not
# satisfy the grammar exactly.
#
# STRICT, like the manifest reader beside it: an unrecognised line is a refusal,
# not a skip. A record this reader cannot vouch for reads as NO record, which
# routes an upgrade into its no-prior-version path rather than into a comparison
# against a value nothing validated.

# The provenance line stamped into every installed file, so a copy found in a
# consuming repository states its own origin instead of requiring the reader to
# know that a record exists under `.git`.
#
# COMMENT SYNTAX IS PER FILE TYPE and the set is CLOSED: an unrecognised
# extension is a refusal, not an un-stamped file. Guessing `#` for an unknown
# type could corrupt it, and silently skipping would produce an install whose
# files disagree about whether provenance is present.
#
# A SHEBANG MUST STAY ON LINE 1. `scripts/git-hooks/pre-commit` (`#!/bin/sh`)
# and `scripts/run-gate.sh` (`#!/usr/bin/env bash`) are executed by their
# interpreter line; a header prepended above it silently disables the
# interpreter selection, so the stamp goes on line 2 there.
# Takes BYTES, not a path: the caller buffers every source file up front and
# proves that buffer corresponds to one commit, so re-reading here would
# reintroduce the window that proof exists to close.
function Get-CrgStampedFileBytes {
  param([byte[]]$SourceBytes, [string]$Dst, [string]$Version, [string]$SourceCommit)
  $sfSrc = $SourceBytes
  if ($null -eq $sfSrc) { throw "source bytes are absent for installed file '$Dst'" }
  $sfLeaf = [System.IO.Path]::GetFileName($Dst)
  $sfExt = [System.IO.Path]::GetExtension($Dst)
  $sfText = "cross-review-gate v$Version (source $SourceCommit) - installed by bootstrap.ps1; edit the package, not this copy"
  $sfLine = if ([string]::Equals($Dst, 'docs/AGENTS.md.template', [System.StringComparison]::Ordinal)) {
    "<!-- $sfText -->"
  } else {
    switch -Regex ($sfExt) {
      '^\.(ps1|psm1|sh)$' { "# $sfText"; break }
      '^\.rs$'       { "// $sfText"; break }
      '^\.md$'       { "<!-- $sfText -->"; break }
      default {
        if ([string]::Equals($sfLeaf, 'pre-commit', [System.StringComparison]::Ordinal)) { "# $sfText" }
        else { $null }
      }
    }
  }
  if ($null -eq $sfLine) {
    throw "no comment syntax is defined for installed file '$Dst'; add one to Get-CrgStampedFileBytes before shipping this file type"
  }
  # The source's OWN terminator is reused so a stamped file does not acquire a
  # mixed-ending first line. Absent any terminator (single-line or empty
  # source), LF is the package's checked-in form.
  $sfNl = "`n"
  $sfCut = 0
  $sfLfIdx = [Array]::IndexOf($sfSrc, [byte]10)
  if ($sfLfIdx -ge 0) {
    if ($sfLfIdx -gt 0 -and $sfSrc[$sfLfIdx - 1] -eq [byte]13) { $sfNl = "`r`n" }
    # A shebang is recognised only as the literal first two bytes.
    if ($sfSrc.Length -ge 2 -and $sfSrc[0] -eq [byte]35 -and $sfSrc[1] -eq [byte]33) { $sfCut = $sfLfIdx + 1 }
  }
  $sfEnc = New-Object System.Text.UTF8Encoding($false)
  $sfHeader = $sfEnc.GetBytes($sfLine + $sfNl)
  $sfLength = [int64]$sfSrc.Length + [int64]$sfHeader.Length
  if ($sfLength -gt [int]::MaxValue) { throw "stamped content for installed file '$Dst' exceeds the supported byte-array length" }
  $sfResult = New-Object byte[] ([int]$sfLength)
  $sfOffset = 0
  if ($sfCut -gt 0) {
    [System.Buffer]::BlockCopy($sfSrc, 0, $sfResult, 0, $sfCut)
    $sfOffset = $sfCut
  }
  [System.Buffer]::BlockCopy($sfHeader, 0, $sfResult, $sfOffset, $sfHeader.Length)
  $sfOffset += $sfHeader.Length
  $sfTailLength = $sfSrc.Length - $sfCut
  if ($sfTailLength -gt 0) { [System.Buffer]::BlockCopy($sfSrc, $sfCut, $sfResult, $sfOffset, $sfTailLength) }
  # A byte[] is enumerable in the PowerShell pipeline. Unary comma keeps the
  # result as one byte-array object instead of boxing every byte into Object[].
  return ,$sfResult
}

# The grammar lives here, on BYTES, so the publisher can validate a staged
# record it is still holding open. Re-reading that record BY PATH cannot work:
# the staging handle is open for write, and any second opener requesting read
# access with FileShare.Read is refused while a write handle is live -- the
# reader would return $null for a perfectly good record. One accept-set, two
# entry points; never a second parser.
function Read-CrgInstallVersionBytes {
  param([byte[]]$Bytes)
  $rvBytes = $Bytes
  if ($null -eq $rvBytes -or $rvBytes.Length -eq 0 -or $rvBytes.Length -gt 4096) { return $null }
  # RAW BYTES FIRST, before any decode. ASCII.GetString maps every byte above
  # 0x7E to '?', which is itself printable -- so decoding first would launder a
  # high byte inside the version value into a character that satisfies both the
  # printable-domain check and `\S+`, admitting a malformed record through a
  # boundary whose whole purpose is to reject one. Matches the manifest reader.
  foreach ($rvB in $rvBytes) {
    if ($rvB -ne 10 -and ($rvB -lt 32 -or $rvB -gt 126)) { return $null }
  }
  $rvText = [System.Text.Encoding]::ASCII.GetString($rvBytes)
  $rvLines = @($rvText -split "`n")
  if ($rvLines.Count -lt 5 -or -not [string]::Equals($rvLines[$rvLines.Count - 1], '', [System.StringComparison]::Ordinal)) { return $null }
  if (-not [string]::Equals($rvLines[0], 'crg-install-version v1', [System.StringComparison]::Ordinal)) { return $null }
  # SemVer, not "any non-whitespace". This value is compared against the
  # package's version to decide whether the refusal arms, so a record holding a
  # string the package reader would never produce must not be able to match it.
  if ($rvLines[1] -cnotmatch ('\Aversion: (?<v>' + $script:CrgSemVerBody.Substring(2) + ')\z')) { return $null }
  $rvVersion = $Matches['v']
  if ($rvLines[2] -cnotmatch '\Asource-commit: (?<c>[0-9a-f]{40}|[0-9a-f]{64}|unknown)\z') { return $null }
  $rvCommit = $Matches['c']
  # SHAPE IS NOT VALIDITY. The digit pattern alone admits 2026-99-99T99:99:99Z,
  # and a record that parses is a record the refusal trusts -- so an impossible
  # instant must be rejected as a malformed record, not carried as data.
  if ($rvLines[3] -cnotmatch '\Ainstalled: (?<t>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\z') { return $null }
  $rvStamp = [ref]([DateTime]::MinValue)
  if (-not [DateTime]::TryParseExact($Matches['t'], "yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture, ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal), $rvStamp)) { return $null }
  $rvInstalled = $Matches['t']
  if ($rvLines.Count -ne 5) { return $null }
  return @{ Version = $rvVersion; SourceCommit = $rvCommit; Installed = $rvInstalled }
}

function Read-CrgInstallVersion {
  param([string]$RecordPath)
  if (-not (Test-Path -LiteralPath $RecordPath -PathType Leaf)) { return $null }
  try { $rvFileBytes = [System.IO.File]::ReadAllBytes($RecordPath) } catch { return $null }
  return (Read-CrgInstallVersionBytes -Bytes $rvFileBytes)
}

# Open a positive version record as transaction authority. The retained
# READ+DELETE/share-READ handle denies every writer and pathname replacement;
# ordinary single-link shape and strict bytes are proved on that same object.
function Open-CrgInstallVersionOwner {
  param([string]$RecordPath)

  $ovHandle = $null
  $ovStream = $null
  $ovErr = 0
  try {
    $ovHandle = [CrgBootstrap.NativeV4]::OpenOwnedExistingFileNoFollow($RecordPath, [ref]$ovErr)
    if ($null -eq $ovHandle -or $ovHandle.IsInvalid) { throw "no-follow version-record owner open refused (Win32 error $ovErr)" }
    $ovAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($ovHandle)
    if ($ovAttrs -lt 0 -or ($ovAttrs -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($ovHandle) -ne 1) { throw 'the version record is not one ordinary single-link file' }
    $ovStream = New-Object System.IO.FileStream($ovHandle, [System.IO.FileAccess]::Read)
    $ovHandle = $null
    if ($ovStream.Length -le 0 -or $ovStream.Length -gt 4096) { throw 'the version record exceeds the bounded grammar' }
    $ovBytes = New-Object byte[] ([int]$ovStream.Length)
    $ovRead = 0
    while ($ovRead -lt $ovBytes.Length) {
      $ovGot = $ovStream.Read($ovBytes, $ovRead, $ovBytes.Length - $ovRead)
      if ($ovGot -le 0) { break }
      $ovRead += $ovGot
    }
    $ovStream.Position = 0
    if ($ovRead -ne $ovBytes.Length) { throw 'the held version record could not be read exactly' }
    $ovRecord = Read-CrgInstallVersionBytes -Bytes $ovBytes
    if ($null -eq $ovRecord) { throw 'the held version record does not satisfy the strict grammar' }
    $ovResult = [pscustomobject]@{ Path = $RecordPath; Stream = $ovStream; Record = $ovRecord }
    $ovStream = $null
    return $ovResult
  } finally {
    if ($null -ne $ovStream) { $ovStream.Dispose() }
    elseif ($null -ne $ovHandle -and -not $ovHandle.IsInvalid) { $ovHandle.Dispose() }
  }
}

# Publish the install-version record. Returns 'ok', 'failed-absent' when exact
# cleanup leaves no record, or fatal 'failed-remnant' when an unowned occupant
# wins the name or an exact held cleanup cannot complete.
#
# Ordering: this runs LAST, after the manifest and the authorization marker have
# both published. The manifest is the trust artifact and must not queue behind
# provenance, and a failed authorization rolls the manifest back -- leaving the
# PREVIOUS version record beside the PREVIOUS manifest, which is coherent.
#
# Failure removes rather than retains. A stale record is worse than none: it
# describes an install that no longer exists, and an upgrade comparing against
# it would decide against a version the tree does not carry. Absence routes the
# next upgrade into its no-prior-version path, which is the honest answer.
#
# Publication is staged under a retained DELETE-capable handle. A strict prior
# record is held and dispositioned through its exact handle, then the stage is
# renamed no-replace through the same object handle. The short absent interval is
# intentional: stale provenance is unsafe, while absence makes the next upgrade
# take the conservative unknown-version path. A racer winning the final name is
# preserved and reported as a remnant.
function Publish-CrgInstallVersion {
  param([string]$RecordPath, [string]$Version, [string]$SourceCommit, [object]$PriorOwner, [string]$PriorState = 'classify')
  $pvTmp = "$RecordPath.crg-new-$crgBackupStamp"
  $pvLines = @(
    'crg-install-version v1',
    ('version: ' + $Version),
    ('source-commit: ' + $SourceCommit),
    ('installed: ' + [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture))
  )
  $pvBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($pvLines -join "`n") + "`n"))
  $pvPriorFs = $null
  $pvPriorDeleteEligible = $false
  $pvStageFs = $null
  $pvPublished = $false
  $pvFailure = $null
  try {
    if (-not [System.Linq.Enumerable]::Contains([string[]]@('classify', 'held', 'absent', 'foreign'), [string]$PriorState, [System.StringComparer]::Ordinal)) { throw "unrecognized prior-version transaction state '$PriorState'" }
    if ($PriorState -ceq 'held') {
      if ($null -eq $PriorOwner.Stream -or
          -not [string]::Equals("$($PriorOwner.Path)", $RecordPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'the supplied prior version-record owner is absent or names a different path'
      }
      $pvPriorFs = $PriorOwner.Stream
      $PriorOwner.Stream = $null
      $pvPriorRecord = $PriorOwner.Record
      if ($null -eq $pvPriorRecord) { throw 'the supplied held version record has no strict parsed authority' }
      $pvPriorDeleteEligible = $true
    } elseif ($PriorState -ceq 'foreign') {
      throw 'the locked prior version-record classification was foreign or unowned; refusing to replace it'
    } elseif ($PriorState -ceq 'classify') {
      $pvKind = Get-CrgPathOccupantKind -Path $RecordPath
      if ([string]::Equals($pvKind, 'file', [System.StringComparison]::Ordinal)) {
        $pvOpenedOwner = Open-CrgInstallVersionOwner -RecordPath $RecordPath
        $pvPriorFs = $pvOpenedOwner.Stream
        $pvOpenedOwner.Stream = $null
        $pvPriorDeleteEligible = $true
      } elseif (-not [string]::Equals($pvKind, 'empty', [System.StringComparison]::Ordinal)) {
        throw "version-record path has occupant kind $pvKind"
      }
    }

    $pvStageH = $null
    $pvStageErr = 0
    try {
      $pvStageH = [CrgBootstrap.NativeV4]::CreateOwnedStageNoFollow($pvTmp, [ref]$pvStageErr)
      if ($null -eq $pvStageH -or $pvStageH.IsInvalid) { throw "version-record stage create-new failed (Win32 error $pvStageErr)" }
      $pvStageFs = New-Object System.IO.FileStream($pvStageH, [System.IO.FileAccess]::ReadWrite)
      $pvStageH = $null
      $pvStageFs.Write($pvBytes, 0, $pvBytes.Length)
      $pvStageFs.Flush($true)
      $pvStageFs.Position = 0
      $pvBack = New-Object byte[] $pvBytes.Length
      $pvRead = 0
      while ($pvRead -lt $pvBytes.Length) {
        $pvGot = $pvStageFs.Read($pvBack, $pvRead, $pvBytes.Length - $pvRead)
        if ($pvGot -le 0) { break }
        $pvRead += $pvGot
      }
      $pvSame = ($pvRead -eq $pvBytes.Length) -and ($pvStageFs.Length -eq $pvBytes.Length)
      if ($pvSame) {
        for ($pvI = 0; $pvI -lt $pvBytes.Length; $pvI++) {
          if ($pvBack[$pvI] -ne $pvBytes[$pvI]) { $pvSame = $false; break }
        }
      }
      if (-not $pvSame) { throw 'the staged version record did not read back byte-for-byte under its own handle' }
      # Parsed as well as byte-compared: a record that cannot be parsed back is
      # one a later upgrade would treat as absent, and publishing it would hide
      # that behind a file that merely exists. Parsed from the bytes just read
      # back off the held handle -- the same accept-set the path-based reader
      # uses, without releasing custody of the staged name.
      $pvCheck = Read-CrgInstallVersionBytes -Bytes $pvBack
      if ($null -eq $pvCheck -or -not [string]::Equals($pvCheck.Version, $Version, [System.StringComparison]::Ordinal)) {
        throw 'the staged version record failed its own strict re-read'
      }
      $pvStageFs.Position = 0
    } finally {
      if ($null -ne $pvStageH -and -not $pvStageH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $pvTmp -Handle $pvStageH -Label 'install-version stage' }
    }

    if ($null -ne $pvPriorFs) {
      if ([CrgBootstrap.NativeV3]::GetLinkCount($pvPriorFs.SafeFileHandle) -ne 1) {
        $pvPriorDeleteEligible = $false
        throw 'the exact previous version record no longer has single-link shape'
      }
      $pvPriorDeleteErr = 0
      $pvPriorDelete = [CrgBootstrap.NativeV4]::DeleteHeldExact($pvPriorFs.SafeFileHandle, $false, [ref]$pvPriorDeleteErr)
      if ($pvPriorDelete -ne 0) { throw "the exact previous version record could not be dispositioned (result $pvPriorDelete, Win32 error $pvPriorDeleteErr)" }
      $pvPriorFs.Dispose()
      $pvPriorFs = $null
      $pvPriorDeleteEligible = $false
    }
    $pvRenameErr = 0
    if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($pvStageFs.SafeFileHandle, $pvTmp, $RecordPath, [ref]$pvRenameErr))) {
      throw "same-handle no-replace version-record publication failed (Win32 error $pvRenameErr)"
    }
    $pvPublished = $true
    return 'ok'
  } catch {
    $pvFailure = $_.Exception.Message
    Write-Host "[bootstrap] WARNING: could not publish the install version record at '$RecordPath' ($($_.Exception.Message))."
  } finally {
    if ($null -ne $pvPriorFs) {
      # Once gate files have changed, a held previous record is stale. Remove
      # only that exact object; failure preserves it and forces failed-remnant.
      $pvOldCleanupErr = 0
      $pvOldCleanup = if ($pvPriorDeleteEligible) { [CrgBootstrap.NativeV4]::DeleteHeldExact($pvPriorFs.SafeFileHandle, $false, [ref]$pvOldCleanupErr) } else { -1 }
      $pvPriorFs.Dispose()
      $pvPriorFs = $null
      if ($pvPriorDeleteEligible -and $pvOldCleanup -ne 0) { $pvFailure = "previous-record exact cleanup failed (result $pvOldCleanup, Win32 error $pvOldCleanupErr); $pvFailure" }
    }
    if ($null -ne $pvStageFs) {
      $pvStagePath = if ($pvPublished) { $RecordPath } else { $pvTmp }
      if ($null -ne $pvFailure) {
        $pvStageCleanup = Remove-CrgOwnedScratchHandle -Path $pvStagePath -Stream $pvStageFs -Label $(if ($pvPublished) { 'newly published install-version record' } else { 'install-version stage' })
        if (-not $pvStageCleanup) { $pvFailure = "owned version-record cleanup failed; $pvFailure" }
      } else {
        $pvStageFs.Dispose()
      }
      $pvStageFs = $null
    }
  }
  if ((Get-CrgPathOccupantKind -Path $RecordPath) -cne 'empty') {
    Write-Host "[bootstrap] WARNING: a version-record occupant remains at '$RecordPath' after the failed transaction; preserving it as a remnant."
    return 'failed-remnant'
  }
  Write-Host '[bootstrap] The install is complete and verified; a later upgrade will read this install as version-unknown, which is the safe reading.'
  return 'failed-absent'
}

# Dispatcher refresh, manifest reseal, and custody recovery consume only
# embedded/current target state. Requiring VERSION plus every package source
# for any operation turns
# recovery of an incomplete package into a catch-22 and lets unrelated payload
# damage block an operation that never reads or copies that payload. These
# switches remain mutually exclusive because each owns a separate recovery or
# publication transaction.
$crgExclusiveOperationCount = 0
foreach ($crgOperationSwitch in @($DispatcherOnly, $SealManifest, $RestoreLegacyRoutingCustody)) {
  if ($crgOperationSwitch) { $crgExclusiveOperationCount++ }
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

function Remove-CrgPinnedReadableScratch {
  param([string]$Path, [object]$Stream, [object]$Handle, [object]$CleanupHandle, [string]$Label = 'Git-readable scratch file')
  $prOriginal = if ($null -ne $Stream) { $Stream.SafeFileHandle } else { $Handle }
  $prCleanup = $CleanupHandle
  try {
    if ($null -eq $prOriginal -or $prOriginal.IsInvalid -or
        [CrgBootstrap.NativeV3]::GetLinkCount($prOriginal) -ne 1) { throw 'the original retained handle lost ordinary single-link shape' }
    if ($null -eq $prCleanup -or $prCleanup.IsInvalid) {
      $prErr = 0
      $prCleanup = [CrgBootstrap.NativeV4]::OpenCleanupOwnerNoFollow($Path, [ref]$prErr)
      if ($null -eq $prCleanup -or $prCleanup.IsInvalid) { throw "cleanup-owner open failed (Win32 error $prErr)" }
    }
    if ([CrgBootstrap.NativeV3]::GetLinkCount($prCleanup) -ne 1 -or
        -not [CrgBootstrap.NativeV4]::SameFileIdentity($prOriginal, $prCleanup)) { throw 'the cleanup pathname does not name the exact retained 128-bit file identity' }
    if ($null -ne $Stream) { $Stream.Dispose(); $Stream = $null } else { $Handle.Dispose(); $Handle = $null }
    $prDeleteErr = 0
    $prDeleteResult = [CrgBootstrap.NativeV4]::DeleteHeldExact($prCleanup, $false, [ref]$prDeleteErr)
    if ($prDeleteResult -ne 0) { throw "same-handle disposition failed (result $prDeleteResult, Win32 error $prDeleteErr)" }
    $prCleanup.Dispose(); $prCleanup = $null
    return $true
  } catch {
    Write-Host "[bootstrap] WARNING: $Label at '$Path' could not be identity-handed to exact cleanup ($($_.Exception.Message)); preserving the remnant."
    return $false
  } finally {
    if ($null -ne $Stream) { try { $Stream.Dispose() } catch { } }
    elseif ($null -ne $Handle) { try { $Handle.Dispose() } catch { } }
    if ($null -ne $prCleanup) { try { $prCleanup.Dispose() } catch { } }
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
if ($crgExclusiveOperationCount -gt 1) {
  Write-Error "bootstrap.ps1: -SealManifest, -DispatcherOnly, and -RestoreLegacyRoutingCustody are separate operations; run only one."
  exit 1
}
$crgNeedsPackagePayload = (-not $DispatcherOnly) -and (-not $SealManifest) -and (-not $RestoreLegacyRoutingCustody)

# SETTLED ONCE, HERE, AND NEVER REPLACED. The bytes are captured at this single
# read and every consumer downstream -- the upgrade classification, the header
# stamped into each installed file, and the install record -- uses the value
# derived from them.
#
# An earlier draft re-read VERSION during the source-snapshot proof and could
# adopt a different value there. That put the decision AFTER the upgrade guard
# had already been chosen with the old one, so a package switching version A to
# B could leave the guard disabled while B's bytes overwrote locally edited
# files. The proof now settles only the COMMIT; the version is immutable before
# any classification depends on it.
$crgVersionBytes = $null
$crgPackageVersion = $null
# Resolved where the package bytes are BUFFERED, not here: provenance must be
# proven against the bytes actually installed, so it is proven against the
# sampled commit's own blobs there. Both consumers -- the header stamped into
# every installed file and the install record published at the end -- read that
# one proven value.
#
# DECLARED HERE with the honest default. A normal self-install skips the copy
# loop but still publishes a version record; dispatcher-only and seal operations
# return before that publisher and therefore never need package provenance.
$crgSourceCommit = 'unknown'

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

# Central publication is deliberately separate from target installation. No
# package input is executed, and no consumer authorization is inferred here.
function Get-CrgRuntimePayloadPaths {
  [string[]]$rtPaths = @('VERSION', 'scripts/central-launcher.ps1', 'scripts/central-context.psm1',
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
      -not ([string]::Equals($rtLines[3], 'launcher-abi 1', [System.StringComparison]::Ordinal) -or [string]::Equals($rtLines[3], 'launcher-abi 2', [System.StringComparison]::Ordinal)) -or
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
  # ABIs 1/2 keep these dispatch/review entrypoints stable, not the publisher's
  # entire optional helper inventory. Approved manifests own release contents.
  foreach ($rtRequired in @('VERSION', 'scripts/run-gate.sh', 'scripts/git-hooks/pre-commit',
      'scripts/codex/auto-review.ps1', 'scripts/codex/auto-merge.ps1', 'scripts/codex/commit.ps1',
      'scripts/codex/review-prompt-template.md', 'scripts/claude/auto-review.ps1', 'scripts/claude/commit.ps1')) {
    if (@($rtEntries | Where-Object { $_.Path -ceq $rtRequired }).Count -ne 1) { throw "runtime manifest lacks required entrypoint '$rtRequired'" }
  }
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
  if ($text -cnotmatch '\Acrg-runtime-launcher v2\nlauncher-abi 2\nrelease (?<r>[0-9a-f]{64})\nsha256 (?<h>[0-9a-f]{64})\nprevious-release (?<p>[0-9a-f]{64}|-)\nprevious-sha256 (?<s>[0-9a-f]{64}|-)\n\z') { throw 'launcher provenance grammar is invalid' }
  $record = [pscustomobject]@{ Schema = 2; LauncherAbi = 2; ReleaseId = $Matches['r']; Hash = $Matches['h']; PreviousReleaseId = $Matches['p']; PreviousHash = $Matches['s'] }
  if (($record.PreviousReleaseId -ceq '-') -ne ($record.PreviousHash -ceq '-') -or $record.PreviousReleaseId -ceq $record.ReleaseId) { throw 'launcher provenance predecessor is inconsistent' }
  return $record
}

function New-CrgRuntimeLauncherBytes {
  param([int]$LauncherAbi, [string]$ReleaseId, [string]$Hash, [string]$PreviousReleaseId = '-', [string]$PreviousHash = '-')
  $text = if ($LauncherAbi -eq 1) { "crg-runtime-launcher v1`nrelease $ReleaseId`nsha256 $Hash`n" }
    elseif ($LauncherAbi -eq 2) { "crg-runtime-launcher v2`nlauncher-abi 2`nrelease $ReleaseId`nsha256 $Hash`nprevious-release $PreviousReleaseId`nprevious-sha256 $PreviousHash`n" }
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

function Update-CrgRuntimeLauncherAbi {
  param([string]$Store, [object]$Release, [object]$Owners)
  if ($Release.Manifest.LauncherAbi -ne 2) { throw 'launcher migration requires an approved ABI 2 target' }
  $target = @($Release.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [System.StringComparison]::Ordinal) })
  if ($target.Count -ne 1) { throw 'launcher migration target lacks the exact launcher payload' }
  $targetHash = Get-CrgSha256HexOfBytes -Bytes $target[0].Bytes
  $migrationPath = Join-Path $Store 'launcher-upgrade'
  $migrationOwner = Open-CrgPackageSourceHold -Path $migrationPath -RelativePath 'launcher upgrade record' -MaxLength 1024 -AllowAbsent
  if ($null -ne $migrationOwner) { $Owners.Add($migrationOwner) | Out-Null }
  $installOwner = Open-CrgPackageSourceHold -Path (Join-Path $Store 'launcher-install') -RelativePath 'installed launcher provenance' -MaxLength 1024 -AllowAbsent
  $launcherOwner = Open-CrgPackageSourceHold -Path (Join-Path $Store 'launcher.ps1') -RelativePath 'installed launcher' -AllowAbsent
  foreach ($owner in @($installOwner, $launcherOwner)) { if ($null -ne $owner) { $Owners.Add($owner) | Out-Null } }
  if ($null -eq $migrationOwner) {
    if ($null -eq $installOwner -or $null -eq $launcherOwner) { throw 'new launcher migration requires a complete verified ABI 1 installation' }
    $predecessor = Read-CrgRuntimeLauncherBytes -Bytes $installOwner.Bytes
    if ($predecessor.LauncherAbi -ne 1) { throw 'only the explicit ABI 1 to ABI 2 launcher migration is supported; routine releases use activation' }
    Assert-CrgRuntimeLauncherOrigin -Store $Store -Installation $predecessor -Owners $Owners
    if ((Get-CrgSha256HexOfBytes -Bytes $launcherOwner.Bytes) -cne $predecessor.Hash) { throw 'existing launcher differs from its approved ABI 1 origin' }
    $desired = New-CrgRuntimeLauncherBytes -LauncherAbi 2 -ReleaseId $Release.Manifest.Id -Hash $targetHash -PreviousReleaseId $predecessor.ReleaseId -PreviousHash $predecessor.Hash
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
  }
  $migration = Read-CrgRuntimeLauncherBytes -Bytes $migrationOwner.Bytes
  if ($migration.Schema -ne 2 -or $migration.PreviousReleaseId -ceq '-' -or
      $migration.ReleaseId -cne $Release.Manifest.Id -or $migration.Hash -cne $targetHash) { throw 'launcher upgrade record selects another exact transition' }
  $predecessor = [pscustomobject]@{ LauncherAbi = 1; ReleaseId = $migration.PreviousReleaseId; Hash = $migration.PreviousHash }
  Assert-CrgRuntimeLauncherOrigin -Store $Store -Installation $predecessor -Owners $Owners
  $previousBytes = New-CrgRuntimeLauncherBytes -LauncherAbi 1 -ReleaseId $predecessor.ReleaseId -Hash $predecessor.Hash
  $desired = [byte[]]$migrationOwner.Bytes
  if ($null -ne $installOwner -and
      -not [Linq.Enumerable]::SequenceEqual([byte[]]$installOwner.Bytes, [byte[]]$previousBytes) -and
      -not [Linq.Enumerable]::SequenceEqual([byte[]]$installOwner.Bytes, [byte[]]$desired)) { throw 'launcher migration preserves conflicting installation metadata' }
  if ($null -ne $launcherOwner -and (Get-CrgSha256HexOfBytes -Bytes $launcherOwner.Bytes) -cnotin @($predecessor.Hash, $targetHash)) { throw 'launcher migration preserves unrecognized installed bytes' }
  if ($null -ne $installOwner -and $null -ne $launcherOwner -and
      [Linq.Enumerable]::SequenceEqual([byte[]]$installOwner.Bytes, [byte[]]$desired) -and
      (Get-CrgSha256HexOfBytes -Bytes $launcherOwner.Bytes) -ceq $targetHash) {
    Write-Host "[bootstrap] exact ABI 2 launcher migration is already complete for release $($Release.Manifest.Id); no release activated and no consumer changed."
    return
  }
  foreach ($owner in @($installOwner, $launcherOwner)) {
    if ($null -ne $owner) { $owner.Stream.Dispose(); $owner.Stream = $null }
  }
  $installPath = Join-Path $Store 'launcher-install'
  $null = Update-CrgRootedFileBytes -Path $installPath -MaxLength 1024 -Label 'ABI 2 launcher provenance' -Transform {
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
  $null = Update-CrgRootedFileBytes -Path $launcherPath -Label 'ABI 2 stable launcher' -Transform {
    param([byte[]]$Previous)
    $absent = $Previous.Length -eq 0 -and (Get-CrgPathOccupantKind -Path $launcherPath) -ceq 'empty'
    if (-not $absent -and (Get-CrgSha256HexOfBytes -Bytes $Previous) -cnotin @($predecessor.Hash, $targetHash)) { throw 'launcher bytes changed outside the recorded migration' }
    return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$target[0].Bytes }
  }
  $verifiedLauncher = Open-CrgPackageSourceHold -Path $launcherPath -RelativePath 'upgraded stable launcher'
  $Owners.Add($verifiedLauncher) | Out-Null
  if ((Get-CrgSha256HexOfBytes -Bytes $verifiedLauncher.Bytes) -cne $targetHash) { throw 'upgraded launcher readback differs from the approved release' }
  Write-Host "[bootstrap] stable launcher upgraded from ABI 1 to ABI 2 using verified release $($Release.Manifest.Id); no release activated and no consumer changed."
  Write-Host "[bootstrap] exact launcher transition retained at '$migrationPath'; preceding release $($predecessor.ReleaseId) remains required."
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
      # Match the install path's complete Git-indirection matrix. Positive
      # absence is valid for commondir only when no indirection is required.
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
      $rtLines = @('crg-runtime-manifest v1', "version $rtVersion", "source-commit $rtSource", 'launcher-abi 2', 'config-schema 1')
      foreach ($rtOwner in $rtPayloadOwners) { $rtLines += "file $(Get-CrgSha256HexOfBytes -Bytes $rtOwner.Bytes) $($rtOwner.Bytes.Length) $($rtOwner.RelativePath)" }
      $rtManifest = Read-CrgRuntimeManifestBytes -Bytes ([System.Text.Encoding]::ASCII.GetBytes(($rtLines -join "`n") + "`n"))
      $rtRelease = Publish-CrgRuntimeSnapshot -Store $rtStore -Manifest $rtManifest -Owners $rtPayloadOwners.ToArray()
    } elseif ($Operation -ceq 'PublishRuntimePackage') {
      $rtImported = Open-CrgRuntimeRelease -Root $rtInput -ExpectedId $ApprovedManifestSha256
      $rtRelease = Publish-CrgRuntimeSnapshot -Store $rtStore -Manifest $rtImported.Manifest -Owners $rtImported.Owners.ToArray()
    } else {
      $rtRelease = Open-CrgRuntimeRelease -Root (Join-Path $rtStore "releases/$ReleaseId") -ExpectedId $ReleaseId
      $rtMissingCapabilities = @('scripts/central-launcher.ps1', 'scripts/central-context.psm1', 'scripts/private-governance.psm1') | Where-Object {
        $rtRequired = $_
        @($rtRelease.Manifest.Entries | Where-Object { $_.Path -ceq $rtRequired }).Count -ne 1
      }
      if ($Operation -ceq 'UpgradeRuntimeLauncher') {
        if (@($rtMissingCapabilities).Count -gt 0) { throw 'launcher migration target lacks required central entrypoints' }
        Update-CrgRuntimeLauncherAbi -Store $rtStore -Release $rtRelease -Owners $rtOwners
        return
      }
      if ($Operation -ceq 'InstallRuntimeLauncher') {
        $rtUpgrade = Open-CrgPackageSourceHold -Path (Join-Path $rtStore 'launcher-upgrade') -RelativePath 'launcher upgrade record' -MaxLength 1024 -AllowAbsent
        if ($null -ne $rtUpgrade) {
          $rtOwners.Add($rtUpgrade) | Out-Null
          throw 'a recorded launcher migration requires UpgradeRuntimeLauncher for retry; a completed migration needs only normal release activation'
        }
        if (@($rtMissingCapabilities).Count -gt 0) { throw "release lacks executable launcher capability: $($rtMissingCapabilities -join ', ')" }
        $rtLauncherOwner = @($rtRelease.Owners | Where-Object { [string]::Equals($_.RelativePath, 'scripts/central-launcher.ps1', [System.StringComparison]::Ordinal) })[0]
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
        return
      }
      $rtInstalledFiles = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
      foreach ($rtItem in @('launcher.ps1', 'launcher-install')) {
        $rtExisting = Open-CrgPackageSourceHold -Path (Join-Path $rtStore $rtItem) -RelativePath $rtItem -MaxLength 16777216 -AllowAbsent
        if ($null -ne $rtExisting) { $rtOwners.Add($rtExisting) | Out-Null; $rtInstalledFiles.Add($rtItem, $rtExisting) }
      }
      $rtUpgrade = Open-CrgPackageSourceHold -Path (Join-Path $rtStore 'launcher-upgrade') -RelativePath 'launcher upgrade record' -MaxLength 1024 -AllowAbsent
      if ($null -ne $rtUpgrade) {
        $rtOwners.Add($rtUpgrade) | Out-Null
        $rtUpgradeRecord = Read-CrgRuntimeLauncherBytes -Bytes $rtUpgrade.Bytes
        if ($rtUpgradeRecord.Schema -ne 2 -or $rtUpgradeRecord.PreviousReleaseId -ceq '-' -or $rtInstalledFiles.Count -ne 2) { throw 'activation requires completion of the recorded launcher migration' }
      }
      $rtLauncherPresent = $rtInstalledFiles.Count -gt 0
      if ($rtLauncherPresent) {
        if ($rtInstalledFiles.Count -ne 2) { throw 'activation requires complete launcher installation; resume the explicit install or ABI migration' }
        $rtInstallation = Read-CrgRuntimeLauncherBytes -Bytes $rtInstalledFiles['launcher-install'].Bytes
        Assert-CrgRuntimeLauncherOrigin -Store $rtStore -Installation $rtInstallation -Owners $rtOwners
        if ((Get-CrgSha256HexOfBytes -Bytes $rtInstalledFiles['launcher.ps1'].Bytes) -cne $rtInstallation.Hash) { throw 'activation refuses launcher bytes outside the recorded approved origin; resume an interrupted ABI migration explicitly' }
        if ($rtInstallation.LauncherAbi -lt $rtRelease.Manifest.LauncherAbi) { throw 'installed launcher ABI cannot execute the requested release; run the explicit UpgradeRuntimeLauncher operation first' }
      } elseif ($rtRelease.Manifest.LauncherAbi -eq 2) { throw 'ABI 2 activation requires InstallRuntimeLauncher first' }
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
    foreach ($rtHeldRelease in @($rtRelease, $rtImported)) {
      if ($null -ne $rtHeldRelease) { foreach ($rtOwner in $rtHeldRelease.Owners) { if ($null -ne $rtOwner.Stream) { $rtOwner.Stream.Dispose() } } }
    }
    foreach ($rtOwner in $rtOwners) { if ($null -ne $rtOwner.Stream) { $rtOwner.Stream.Dispose() } }
    if ($null -ne $rtLock) { $rtLock.Dispose() }
    if ($null -ne $rtLease) { Close-CrgRootedNamespace -Lease $rtLease }
  }
}

# Earliest production Git trust boundary. Git repository selectors can redirect
# every proof (`-C` included) while filesystem writes still target -TargetRepo;
# attribute-source overrides can change the clean/eol/filter domain used by
# `check-attr` and filter-aware `hash-object --path`; graft/shallow/replace-base
# overrides can rewrite ancestry and object reads while Git still exits zero;
# config overrides can mask hooks/config state inspected after scrubbing.
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
  Write-Error "bootstrap.ps1: refusing to run with git-config override env var(s), repository-selector override(s), attribute-resolution override(s), or history-resolution override(s) set: $($maskingGitOverrideEnv -join ', '). These can redirect Git proofs away from -TargetRepo or alter the config, attribute, object, or ancestry domain used for trusted identity checks. Unset every named variable and re-run -- PowerShell: Remove-Item Env:<NAME>; bash: unset <NAME>. Nothing has been modified in the target repository."
  exit 1
}
try {
  Set-CrgNoReplaceObjectsProcessSingleton
} catch {
  Write-Error "bootstrap.ps1: could not establish exactly one canonical GIT_NO_REPLACE_OBJECTS=1 entry before the first Git proof ($($_.Exception.Message)). Nothing has been modified in the target repository."
  exit 1
}

if ([System.Linq.Enumerable]::Contains([string[]]@('PublishRuntimeSource', 'PublishRuntimePackage', 'ActivateRuntime', 'InstallRuntimeLauncher', 'UpgradeRuntimeLauncher'), [string]$PSCmdlet.ParameterSetName, [System.StringComparer]::Ordinal)) {
  try { Invoke-CrgCentralRuntimeOperation -Operation $PSCmdlet.ParameterSetName }
  catch { Write-Error "bootstrap.ps1: central runtime operation refused: $($_.Exception.Message)"; exit 1 }
  exit 0
}

# Resolve and validate target repo. Use `git rev-parse --is-inside-work-tree`
# instead of `Test-Path .git`: a git worktree (created via `git worktree add`)
# has a `.git` FILE (with a `gitdir:` pointer), not a `.git` directory, and
# a submodule's main checkout has a similar layout. The `Test-Path -PathType
# Container` check would false-reject any of those legitimate setups. Let git
# itself decide whether the target is a valid working tree.
if (-not (Test-Path -LiteralPath $TargetRepo -PathType Container)) {
  Write-Error "bootstrap.ps1: -TargetRepo '$TargetRepo' is not a directory."
  exit 1
}
$targetRepoAbs = (Resolve-Path -LiteralPath $TargetRepo).Path
$gitCheck = & git -C $targetRepoAbs rev-parse --is-inside-work-tree 2>&1
if ($LASTEXITCODE -ne 0 -or -not [string]::Equals("$gitCheck".Trim(), 'true', [System.StringComparison]::Ordinal)) {
  Write-Error "bootstrap.ps1: -TargetRepo '$targetRepoAbs' is not a git working tree (git rev-parse --is-inside-work-tree failed or did not return 'true')."
  exit 1
}
# Normalize to the working-tree TOP-LEVEL. If the user passed a
# subdirectory of the repo, file copies would land at
# `<subdir>/scripts/...` but the dispatcher (installed under
# .git/hooks/) resolves `git rev-parse --show-toplevel` -- which
# points at the REAL top-level, not the subdir -- and would then
# fail to find the in-tree gate at commit time. Apparently-successful
# install followed by every-commit failure is the worst outcome;
# normalize so the file copies land in the same tree the dispatcher
# will look in.
$gitTopLevel = Invoke-CrgGitUtf8 -GitArgs @('-C', $targetRepoAbs, 'rev-parse', '--show-toplevel')
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitTopLevel)) {
  Write-Error "bootstrap.ps1: 'git rev-parse --show-toplevel' failed inside '$targetRepoAbs'."
  exit 1
}
$gitTopLevel = (Resolve-Path -LiteralPath ($gitTopLevel.Trim())).Path
if (-not [string]::Equals($gitTopLevel, $targetRepoAbs, [System.StringComparison]::OrdinalIgnoreCase)) {
  Write-Host "[bootstrap] normalizing -TargetRepo from '$targetRepoAbs' to working-tree top-level '$gitTopLevel' (file copies must land in the same tree the dispatcher resolves at commit time)."
  $targetRepoAbs = $gitTopLevel
}

# Capture the governing HEAD state before any install write. A legacy review
# kernel needs a bounded kernel-and-completion transition because the refreshed
# per-clone dispatcher cannot make candidate tracked files trusted. An
# indeterminate read cannot safely select either the ordinary
# checklist or the legacy transition checklist.
$crgRetiredPmHead = Get-CrgRetiredProjectModeHeadState -Repo $targetRepoAbs
if ([string]::Equals($crgRetiredPmHead.State, 'error', [System.StringComparison]::Ordinal)) {
  Write-Error "bootstrap.ps1: could not classify the trusted HEAD review kernel while checking for retired PROJECT-MODE enforcement ($($crgRetiredPmHead.Reason)). Repair the repository read failure, then re-run. Nothing has been modified in the target repository."
  exit 1
}

# Package/target identity and the target's per-worktree Git directory must be
# resolved before every legacy-transition preflight. An unresolved active
# custody epoch belongs to that Git directory; allowing any full install whose
# target state is not an exact admitted resume state to reach package buffering
# or config inspection would make the later publication failure look like a
# safe retry. This is target-state-driven even when HEAD has no kernel surface.
$packageRootRaw = [System.IO.Path]::GetFullPath($packageRoot)
$packageRootPathRoot = [System.IO.Path]::GetPathRoot($packageRootRaw)
$packageRootFull = if ([string]::Equals($packageRootRaw, $packageRootPathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $packageRootPathRoot } else { $packageRootRaw.TrimEnd('\', '/') }
$targetRepoRaw = [System.IO.Path]::GetFullPath($targetRepoAbs)
$targetRepoPathRoot = [System.IO.Path]::GetPathRoot($targetRepoRaw)
$targetRepoFull = if ([string]::Equals($targetRepoRaw, $targetRepoPathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $targetRepoPathRoot } else { $targetRepoRaw.TrimEnd('\', '/') }
$selfInstall = [string]::Equals($packageRootFull, $targetRepoFull, [System.StringComparison]::OrdinalIgnoreCase)
$crgGitDir = Get-CrgGitDir -RepoRoot $targetRepoAbs
if ($null -eq $crgGitDir) {
  Write-Error "bootstrap.ps1: the target's per-worktree git directory could not be resolved. No install or custody operation can continue."
  exit 1
}
$crgCommonDir = Get-CrgGitCommonDir -RepoRoot $targetRepoAbs
if ($null -eq $crgCommonDir) {
  Write-Error "bootstrap.ps1: the target's Git common directory could not be resolved. No shared dispatcher or backup mutation can continue."
  exit 1
}
$crgNamespaceLease = $null
$crgDispLock = $null
$crgStageLock = $null
$crgDispHold = $null
$crgRoutingLease = $null
$crgLegacyTransitionHold = $null
$crgLegacyAttrHold = $null
$crgLegacyAttrExpectedBytes = $null
$crgAttributeSourceHolds = New-Object 'System.Collections.Generic.List[object]'
$crgInstallValuesAttributeHolds = New-Object 'System.Collections.Generic.List[object]'
$crgInstallValuesAttributeAbsences = New-Object 'System.Collections.Generic.List[string]'
$crgUpVersionOwner = $null
$crgUpVersionPriorState = 'absent'
$crgUpPrev = $null
$crgUpVersionFailure = $null
$crgManifestOwner = $null
$crgManifestPublication = $null
$crgManifestPriorState = 'absent'
$crgAuthMarkerOwner = $null
$crgAuthMarkerPriorState = 'absent'
$crgMarkerReservation = $null
$crgFailedMarkerReservation = $null
$crgGitIndirectionHolds = New-Object 'System.Collections.Generic.List[object]'
$crgPackageSourceOwners = New-Object 'System.Collections.Generic.List[object]'
$crgPackageAttributeOwners = New-Object 'System.Collections.Generic.List[object]'
$crgPackageAttributeBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
$crgInstalledPayloadOwners = New-Object 'System.Collections.Generic.List[object]'
$crgValuesSourceOwner = $null
$crgValuesSourceEvidence = $null
$crgRenderOutputAuthority = $null
$crgRenderedRawBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
$crgPackageProvenanceCandidate = $null
$crgPackageDotGitPath = Join-Path $packageRootFull '.git'
$crgPackageDotGitKindPre = 'not-required'
$crgProofScratchParentRaw = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$crgProofScratchParentRoot = [System.IO.Path]::GetPathRoot($crgProofScratchParentRaw)
$crgProofScratchParent = if ([string]::Equals($crgProofScratchParentRaw, $crgProofScratchParentRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $crgProofScratchParentRoot } else { $crgProofScratchParentRaw.TrimEnd('\', '/') }
$crgCapabilityScratch = Join-Path $crgProofScratchParent ("crg-attribute-capability-proof-" + [Guid]::NewGuid().ToString('N'))
$crgPackageProvenanceScratch = Join-Path $crgProofScratchParent ("crg-package-provenance-proof-" + [Guid]::NewGuid().ToString('N'))
$crgInstallValuesPackageAttributeScratch = Join-Path $crgProofScratchParent ("crg-install-values-package-attributes-" + [Guid]::NewGuid().ToString('N'))
$crgInstallValuesTargetAttributeScratch = Join-Path $crgProofScratchParent ("crg-install-values-target-attributes-" + [Guid]::NewGuid().ToString('N'))
$crgGitEnvironmentBound = $false
$crgInstallCustodyOwners = New-Object 'System.Collections.Generic.List[object]'
$crgInstallBackupStreams = New-Object 'System.Collections.Generic.List[object]'
$fileList = @(Get-CrgCurrentFileList)
try {
if ($crgNeedsPackagePayload) {
  $crgRoutingResume = Get-CrgLegacyRoutingResumeState -RepoRoot $targetRepoAbs -GitDir $crgGitDir
  if ($null -ne $crgRoutingResume.Lease) { $crgRoutingLease = $crgRoutingResume.Lease }
  if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal) -and -not [System.Linq.Enumerable]::Contains([string[]]@('none', 'pre-kernel', 'pre-transition'), [string]$crgRoutingResume.State, [System.StringComparer]::Ordinal)) {
    $crgRoutingEntryHead = (& git -C $targetRepoAbs rev-parse --verify 'HEAD^{commit}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or "$crgRoutingEntryHead".Trim() -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { $crgRoutingEntryHead = '<unreadable-legacy-head>' }
    else { $crgRoutingEntryHead = "$crgRoutingEntryHead".Trim() }
    $crgRoutingRecordedBase = if ("$($crgRoutingResume.BaseHead)" -cmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { "$($crgRoutingResume.BaseHead)" } else { '<unreadable-active-record>' }
    Write-Error "bootstrap.ps1: routing custody in the target's per-worktree Git directory is already active for recorded legacy base '$crgRoutingRecordedBase', while the target worktree is at legacy HEAD '$crgRoutingEntryHead' ($($crgRoutingResume.Reason)). A second active epoch in that Git directory is forbidden, so this run refuses before package or repository mutation; no custody was created for '$crgRoutingEntryHead'. Recovery: return the target worktree to the recorded base '$crgRoutingRecordedBase'. If phase A left legacy or absent routing-driver paths, run the target checkout's bootstrap.ps1 from that checkout with -TargetRepo . -RestoreLegacyRoutingCustody so the checkout again contains the complete candidate payload. Then either re-run at that exact base, or keep that complete checkout as the external package source and run its bootstrap against a fresh linked worktree at the intended legacy base (a fresh per-worktree Git directory): powershell -NoProfile -ExecutionPolicy Bypass -File <complete-candidate-checkout>\bootstrap.ps1 -TargetRepo <fresh-linked-worktree> -Force. Preserve every existing custody record."
    exit 1
  }
  if (([string]::Equals($crgRoutingResume.State, 'pre-transition', [System.StringComparison]::Ordinal) -or [string]::Equals($crgRoutingResume.State, 'pre-kernel', [System.StringComparison]::Ordinal)) -and -not $selfInstall) {
    Write-Error "bootstrap.ps1: verified self-host routing custody is active at recorded legacy base '$($crgRoutingResume.BaseHead)' in transaction state '$($crgRoutingResume.State)'. Only the target checkout's own bootstrap.ps1 may retry that custody epoch; an external package source could bind different candidate bytes to existing custody. This run refuses before package or repository mutation."
    exit 1
  }
  if ([string]::Equals($crgRoutingResume.State, 'pending', [System.StringComparison]::Ordinal)) {
    Write-Error "bootstrap.ps1: the exact legacy kernel landing is HEAD, but the recorded target routing drivers are still in phase-A state. From the target checkout, run its bootstrap.ps1: powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -TargetRepo . -RestoreLegacyRoutingCustody ; then re-run the full install. The retired CROSS_REVIEW_ALLOW_MODE_CHANGE variable has no authority and must not be used."
    exit 1
  }
  if ([string]::Equals($crgRoutingResume.State, 'blocked', [System.StringComparison]::Ordinal)) {
    $crgRoutingRecordedBase = if ("$($crgRoutingResume.BaseHead)" -cmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') { "$($crgRoutingResume.BaseHead)" } else { '<unreadable-active-record>' }
    Write-Error "bootstrap.ps1: unresolved routing custody exists in the target's per-worktree Git directory for recorded legacy base '$crgRoutingRecordedBase', but the target's trusted HEAD state '$($crgRetiredPmHead.State)' cannot be admitted for exact bounded recovery ($($crgRoutingResume.Reason)). A full install could consume phase-A or absent routing sources or publish beside an unresolved epoch, so this run refuses before package or repository mutation. Preserve every machine-local custody record. Return the target worktree to the recorded base and run -RestoreLegacyRoutingCustody there when phase A left candidate drivers absent or legacy; otherwise keep a complete candidate checkout as the external package source and target a fresh linked worktree with its own per-worktree Git directory."
    exit 1
  }
  if (-not [System.Linq.Enumerable]::Contains([string[]]@('none', 'pre-kernel', 'pre-transition', 'restored'), [string]$crgRoutingResume.State, [System.StringComparer]::Ordinal)) {
    Write-Error "bootstrap.ps1: routing custody in the target's per-worktree Git directory returned an unrecognized state '$($crgRoutingResume.State)'. Refusing before package or repository mutation; preserve every custody record and repair the exact recorded landing before continuing."
    exit 1
  }
}
if ((Test-CrgPathWithin -Path $crgCapabilityScratch -Root $targetRepoFull) -or
    (Test-CrgPathWithin -Path $crgCapabilityScratch -Root $packageRootFull) -or
    (Test-CrgPathWithin -Path $crgPackageProvenanceScratch -Root $targetRepoFull) -or
    (Test-CrgPathWithin -Path $crgPackageProvenanceScratch -Root $packageRootFull)) {
  Write-Error "bootstrap.ps1: the validated temporary proof namespace '$crgProofScratchParent' overlaps the target or package namespace. Set TEMP and TMP to an existing ordinary directory outside both trees, then re-run. No mutation was performed."
  exit 1
}
if ($crgNeedsPackagePayload) {
  $crgPackageDotGitKindPre = Get-CrgPathOccupantKind -Path $crgPackageDotGitPath
  try { $crgPackageProvenanceCandidate = Get-CrgPackageProvenanceCandidate -Root $packageRootFull }
  catch {
    Write-Error "bootstrap.ps1: package Git provenance metadata was present but could not be captured safely ($($_.Exception.Message)). No target mutation was performed."
    exit 1
  }
  $crgPackageDotGitKindAfterCapture = Get-CrgPathOccupantKind -Path $crgPackageDotGitPath
  if ($crgPackageDotGitKindAfterCapture -cne $crgPackageDotGitKindPre) {
    Write-Error "bootstrap.ps1: the package .git occupant changed from '$crgPackageDotGitKindPre' to '$crgPackageDotGitKindAfterCapture' during provenance capture. No target mutation was performed."
    exit 1
  }
  if ($null -eq $crgPackageProvenanceCandidate) {
    if ($crgPackageDotGitKindPre -cne 'empty') {
      Write-Error "bootstrap.ps1: package .git metadata has occupant kind '$crgPackageDotGitKindPre' but no exact Git provenance namespace could be captured. Present-but-unreadable package metadata refuses; only positive .git absence may classify an extracted archive. No target mutation was performed."
      exit 1
    }
  } elseif (-not ([string]::Equals($crgPackageDotGitKindPre, 'file', [System.StringComparison]::Ordinal) -or [string]::Equals($crgPackageDotGitKindPre, 'directory', [System.StringComparison]::Ordinal))) {
    Write-Error "bootstrap.ps1: a package provenance candidate was found beside unsupported .git occupant kind '$crgPackageDotGitKindPre'. No target mutation was performed."
    exit 1
  }
}
$crgNamespaceRoots = New-Object 'System.Collections.Generic.List[object]'
$crgNamespaceRoots.Add([pscustomobject]@{ Path = $crgProofScratchParent; Label = 'external immutable-proof scratch root'; Writable = $true }) | Out-Null
$crgNamespaceRoots.Add([pscustomobject]@{ Path = $targetRepoAbs; Label = 'target repository root'; Writable = $true }) | Out-Null
$crgNamespaceRoots.Add([pscustomobject]@{ Path = $crgCommonDir; Label = 'Git common directory'; Writable = $true }) | Out-Null
$crgNamespaceRoots.Add([pscustomobject]@{ Path = $crgGitDir; Label = 'per-worktree Git directory'; Writable = $true }) | Out-Null
if ($crgNeedsPackagePayload -and -not $selfInstall) { $crgNamespaceRoots.Add([pscustomobject]@{ Path = $packageRoot; Label = 'external package root'; Writable = $false }) | Out-Null }
if ($null -ne $crgPackageProvenanceCandidate) {
  $crgNamespaceRoots.Add([pscustomobject]@{ Path = $crgPackageProvenanceCandidate.GitDir; Label = 'captured package Git directory'; Writable = $false }) | Out-Null
  if (-not [string]::Equals([System.IO.Path]::GetFullPath($crgPackageProvenanceCandidate.CommonDir), [System.IO.Path]::GetFullPath($crgPackageProvenanceCandidate.GitDir), [System.StringComparison]::OrdinalIgnoreCase)) {
    $crgNamespaceRoots.Add([pscustomobject]@{ Path = $crgPackageProvenanceCandidate.CommonDir; Label = 'captured package Git common directory'; Writable = $false }) | Out-Null
  }
}
$crgNamespaceLease = Initialize-CrgRootedNamespace -Roots $crgNamespaceRoots.ToArray()
if ($crgNeedsPackagePayload) {
  $crgPackageParents = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $crgPackageBoundary = if ($packageRootFull.EndsWith('\', [System.StringComparison]::Ordinal) -or $packageRootFull.EndsWith('/', [System.StringComparison]::Ordinal)) { $packageRootFull } else { "$packageRootFull$([System.IO.Path]::DirectorySeparatorChar)" }
  foreach ($crgPackageEntry in $fileList) {
    $crgPackageLeaf = [System.IO.Path]::GetFullPath((Join-Path $packageRoot $crgPackageEntry.Src))
    if (-not $crgPackageLeaf.StartsWith($crgPackageBoundary, [System.StringComparison]::OrdinalIgnoreCase)) { throw "package inventory path '$($crgPackageEntry.Src)' escapes the retained package root" }
    $crgPackageParent = Split-Path -Parent $crgPackageLeaf
    while (-not [string]::Equals($crgPackageParent, $packageRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
      [void]$crgPackageParents.Add($crgPackageParent)
      $crgPackageNextParent = Split-Path -Parent $crgPackageParent
      if ([string]::IsNullOrWhiteSpace($crgPackageNextParent) -or [string]::Equals($crgPackageNextParent, $crgPackageParent, [System.StringComparison]::OrdinalIgnoreCase)) { throw "package inventory parent for '$($crgPackageEntry.Src)' escaped the retained package root" }
      $crgPackageParent = $crgPackageNextParent
    }
  }
  foreach ($crgPackageParent in @($crgPackageParents | Sort-Object { $_.Length }, { $_ })) {
    if ($selfInstall) {
      $null = Enter-CrgRootedExistingDirectory -Path $crgPackageParent -Label 'self-install package/target parent' -Mutation
    } else {
      $null = Enter-CrgRootedExistingDirectory -Path $crgPackageParent -Label 'package source parent'
    }
  }
}
$crgDotGitPath = Join-Path $targetRepoAbs '.git'
$crgDotGitKind = Get-CrgPathOccupantKind -Path $crgDotGitPath
if ($crgDotGitKind -ceq 'file') {
  $crgDotGitHold = Open-CrgGitIndirectionHold -Path $crgDotGitPath -Kind gitdir -RelativeBase $targetRepoAbs -ExpectedDirectory $crgGitDir
  $crgGitIndirectionHolds.Add($crgDotGitHold) | Out-Null
} elseif ($crgDotGitKind -ceq 'directory') {
  if (-not [string]::Equals([System.IO.Path]::GetFullPath($crgDotGitPath).TrimEnd('\', '/'), [System.IO.Path]::GetFullPath($crgGitDir).TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Error "bootstrap.ps1: the retained .git directory does not equal the resolved per-worktree Git directory '$crgGitDir'. No mutation was performed."
    exit 1
  }
} else {
  Write-Error "bootstrap.ps1: the target .git entry has unsupported rooted occupant kind '$crgDotGitKind'. No mutation was performed."
  exit 1
}
$crgCommonPointerPath = Join-Path $crgGitDir 'commondir'
$crgCommonPointerHold = Open-CrgGitIndirectionHold -Path $crgCommonPointerPath -Kind commondir -RelativeBase $crgGitDir -ExpectedDirectory $crgCommonDir -AllowAbsent
if ($null -ne $crgCommonPointerHold) { $crgGitIndirectionHolds.Add($crgCommonPointerHold) | Out-Null }
elseif (-not [string]::Equals([System.IO.Path]::GetFullPath($crgGitDir).TrimEnd('\', '/'), [System.IO.Path]::GetFullPath($crgCommonDir).TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
  Write-Error "bootstrap.ps1: the resolved common Git directory differs from the per-worktree Git directory, but no exact commondir indirection file could be retained. No mutation was performed."
  exit 1
}
if ($crgNeedsPackagePayload) {
  $crgPackageDotGitKindPinned = Get-CrgPathOccupantKind -Path $crgPackageDotGitPath
  if ($crgPackageDotGitKindPinned -cne $crgPackageDotGitKindPre) {
    Write-Error "bootstrap.ps1: the package .git occupant changed from '$crgPackageDotGitKindPre' to '$crgPackageDotGitKindPinned' while namespace custody was being acquired. No mutation was performed."
    exit 1
  }
  if ($null -ne $crgPackageProvenanceCandidate) {
    if ($selfInstall) {
      $crgSelfCandidateGitDir = [System.IO.Path]::GetFullPath($crgPackageProvenanceCandidate.GitDir).TrimEnd('\', '/')
      $crgSelfTargetGitDir = [System.IO.Path]::GetFullPath($crgGitDir).TrimEnd('\', '/')
      $crgSelfCandidateCommonDir = [System.IO.Path]::GetFullPath($crgPackageProvenanceCandidate.CommonDir).TrimEnd('\', '/')
      $crgSelfTargetCommonDir = [System.IO.Path]::GetFullPath($crgCommonDir).TrimEnd('\', '/')
      if (-not [string]::Equals($crgSelfCandidateGitDir, $crgSelfTargetGitDir, [System.StringComparison]::OrdinalIgnoreCase) -or
          -not [string]::Equals($crgSelfCandidateCommonDir, $crgSelfTargetCommonDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Error "bootstrap.ps1: self-install package provenance resolved to Git/common directories different from the retained target namespace. No mutation was performed."
        exit 1
      }
    } else {
      if ($crgPackageDotGitKindPinned -ceq 'file') {
        $crgPackageDotGitHold = Open-CrgGitIndirectionHold -Path $crgPackageDotGitPath -Kind gitdir -RelativeBase $packageRootFull -ExpectedDirectory $crgPackageProvenanceCandidate.GitDir
        $crgGitIndirectionHolds.Add($crgPackageDotGitHold) | Out-Null
      } else {
        $crgPackageDotGitDirectory = [System.IO.Path]::GetFullPath($crgPackageDotGitPath).TrimEnd('\', '/')
        $crgPackageGitDirectory = [System.IO.Path]::GetFullPath($crgPackageProvenanceCandidate.GitDir).TrimEnd('\', '/')
        if (-not [string]::Equals($crgPackageDotGitDirectory, $crgPackageGitDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
          Write-Error "bootstrap.ps1: the retained package .git directory does not equal the captured package Git directory '$($crgPackageProvenanceCandidate.GitDir)'. No mutation was performed."
          exit 1
        }
      }
      $crgPackageCommonPointerPath = Join-Path $crgPackageProvenanceCandidate.GitDir 'commondir'
      $crgPackageCommonPointerHold = Open-CrgGitIndirectionHold -Path $crgPackageCommonPointerPath -Kind commondir -RelativeBase $crgPackageProvenanceCandidate.GitDir -ExpectedDirectory $crgPackageProvenanceCandidate.CommonDir -AllowAbsent
      if ($null -ne $crgPackageCommonPointerHold) { $crgGitIndirectionHolds.Add($crgPackageCommonPointerHold) | Out-Null }
      elseif (-not [string]::Equals([System.IO.Path]::GetFullPath($crgPackageProvenanceCandidate.GitDir).TrimEnd('\', '/'), [System.IO.Path]::GetFullPath($crgPackageProvenanceCandidate.CommonDir).TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Error "bootstrap.ps1: captured package Git/common directories differ, but no exact commondir indirection file could be retained. No mutation was performed."
        exit 1
      }
    }
    try { $null = Assert-CrgCapturedPackageProvenanceCandidate -Candidate $crgPackageProvenanceCandidate }
    catch {
      Write-Error "bootstrap.ps1: package Git provenance identity changed while its ordinary namespace was being retained ($($_.Exception.Message)). No target mutation was performed."
      exit 1
    }
  } elseif ($crgPackageDotGitKindPinned -cne 'empty') {
    Write-Error "bootstrap.ps1: package Git metadata appeared after positive archive classification ('$crgPackageDotGitKindPinned'). No target mutation was performed."
    exit 1
  }
}
$crgGitEnvironmentBound = $true
[Environment]::SetEnvironmentVariable('GIT_DIR', $crgGitDir, 'Process')
[Environment]::SetEnvironmentVariable('GIT_WORK_TREE', $targetRepoAbs, 'Process')
[Environment]::SetEnvironmentVariable('GIT_COMMON_DIR', $crgCommonDir, 'Process')
$crgPinnedTop = (Invoke-CrgGitUtf8 -GitArgs @('-C', $targetRepoAbs, 'rev-parse', '--show-toplevel'))
$crgPinnedTopExit = $LASTEXITCODE
$crgPinnedGitDir = Get-CrgGitDir -RepoRoot $targetRepoAbs
$crgPinnedCommonDir = Get-CrgGitCommonDir -RepoRoot $targetRepoAbs
$crgPinnedPmHead = Get-CrgRetiredProjectModeHeadState -Repo $targetRepoAbs
if ($crgPinnedTopExit -ne 0 -or [string]::IsNullOrWhiteSpace("$crgPinnedTop") -or
    -not [string]::Equals([System.IO.Path]::GetFullPath("$crgPinnedTop".Trim()).TrimEnd('\', '/'), [System.IO.Path]::GetFullPath($targetRepoAbs).TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase) -or
    $null -eq $crgPinnedGitDir -or -not [string]::Equals([System.IO.Path]::GetFullPath($crgPinnedGitDir).TrimEnd('\', '/'), [System.IO.Path]::GetFullPath($crgGitDir).TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase) -or
    $null -eq $crgPinnedCommonDir -or -not [string]::Equals([System.IO.Path]::GetFullPath($crgPinnedCommonDir).TrimEnd('\', '/'), [System.IO.Path]::GetFullPath($crgCommonDir).TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase) -or
    [string]::Equals($crgPinnedPmHead.State, 'error', [System.StringComparison]::Ordinal) -or
    -not [string]::Equals("$($crgPinnedPmHead.Identity)", "$($crgRetiredPmHead.Identity)", [System.StringComparison]::Ordinal) -or
    -not [string]::Equals($crgPinnedPmHead.State, $crgRetiredPmHead.State, [System.StringComparison]::Ordinal)) {
  Write-Error 'bootstrap.ps1: repository/Git-directory/HEAD identity changed while the ordinary no-reparse namespace chains were being pinned. No mutation was performed; let the namespace settle and re-run.'
  exit 1
}
$crgRetiredPmHead = $crgPinnedPmHead
$crgHooksOverride = (Invoke-CrgGitUtf8 -GitArgs @('-C', $targetRepoAbs, 'config', '--get', 'core.hooksPath'))
$crgHooksOverrideExit = $LASTEXITCODE
$crgHooksOverrideClass = Resolve-HooksPathGuard -ExitCode $crgHooksOverrideExit
if ($crgHooksOverrideClass -ceq 'abort-set') {
  $crgHooksOverrideDisplay = if ([string]::IsNullOrWhiteSpace("$crgHooksOverride")) { '<empty>' } else { "'$($crgHooksOverride.Trim())'" }
  Write-Error "bootstrap.ps1: core.hooksPath is set to $crgHooksOverrideDisplay. Rooted installation cannot delegate a security-critical hooks mutation to Git's pathname-based config writer. Run: git -C `"$targetRepoAbs`" config --unset core.hooksPath ; if an inherited value remains, unset that value at its reported config scope, then re-run. No mutation was performed."
  exit 1
}
if ($crgHooksOverrideClass -ceq 'abort-indeterminate') {
  Write-Error 'bootstrap.ps1: core.hooksPath could not be read under the pinned repository namespace. No mutation was performed.'
  exit 1
}
$crgCapabilityContext = $null
try {
  $crgCapabilityFormatRows = @(& git -C $targetRepoAbs rev-parse --show-object-format 2>$null)
  if ($LASTEXITCODE -ne 0 -or $crgCapabilityFormatRows.Count -ne 1 -or -not ([string]::Equals("$($crgCapabilityFormatRows[0])", 'sha1', [System.StringComparison]::Ordinal) -or [string]::Equals("$($crgCapabilityFormatRows[0])", 'sha256', [System.StringComparison]::Ordinal))) { throw 'the target object format could not be classified' }
  $crgCapabilityOidLength = if ([string]::Equals("$($crgCapabilityFormatRows[0])", 'sha256', [System.StringComparison]::Ordinal)) { 64 } else { 40 }
  $crgCapabilityContext = New-CrgPrivateAttributeContext -ScratchRoot $crgCapabilityScratch -ObjectIdLength $crgCapabilityOidLength
  if (-not (Close-CrgPrivateAttributeContext -Context $crgCapabilityContext)) { throw 'the exact private attribute capability context could not be cleaned' }
  $crgCapabilityContext = $null
} catch {
  if ($null -ne $crgCapabilityContext) { $null = Close-CrgPrivateAttributeContext -Context $crgCapabilityContext }
  Write-Error "bootstrap.ps1: Git's immutable attribute-source capability could not be proven and exactly cleaned before repository mutation ($($_.Exception.Message)). Git 2.41 or newer with working --attr-source/check-attr/hash-object semantics is required. No install, custody, dispatcher, manifest, marker, or version mutation was attempted."
  exit 1
}
# The fixed skip-audit ref is one leaf directly below Git's refs root. Retain
# that root through the rooted, no-follow transaction before any dispatcher can
# advertise the ref contract. A pre-existing refs junction/reparse refuses here
# instead of becoming an external Git write sink; no extra mutable namespace
# directory is introduced.
try {
  $crgSkipAuditRefDirectory = Join-Path $crgCommonDir 'refs'
  $null = Ensure-CrgRootedDirectory -Path $crgSkipAuditRefDirectory -Label 'skip-audit ref root'
} catch {
  Write-Error "bootstrap.ps1: the fixed skip-audit ref root could not be retained as ordinary Git metadata ($($_.Exception.Message)). Remove any reparse/junction occupant at '$crgCommonDir\refs' deliberately, then re-run. No payload, dispatcher, manifest, marker, or version mutation was attempted."
  exit 1
}
if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal) -and -not $DispatcherOnly -and -not $RestoreLegacyRoutingCustody) {
  try { & git -C $targetRepoAbs diff --cached --quiet --no-ext-diff --no-textconv --no-renames --ignore-submodules=none HEAD -- 2>$null } catch {
    Write-Error "bootstrap.ps1: the staged-state probe threw while preparing a legacy review-kernel transition. Start with a clean index, then re-run. Nothing has been modified in the target repository."
    exit 1
  }
  if ($LASTEXITCODE -eq 1) {
    Write-Error "bootstrap.ps1: the trusted HEAD still carries retired PROJECT-MODE enforcement, and the bounded review-kernel transition requires a CLEAN INDEX before package files are installed. Commit or unstage the current index, then re-run. Nothing has been modified in the target repository."
    exit 1
  }
  if ($LASTEXITCODE -ne 0) {
    Write-Error "bootstrap.ps1: the staged-state probe failed while preparing a legacy review-kernel transition. Start with a verifiably clean index, then re-run. Nothing has been modified in the target repository."
    exit 1
  }
}

$crgLegacyBaseHead = $null
$crgLegacyRunGateHeadPresent = $false
$crgLegacyTransitionRecord = $null
$crgLegacyRoutingCustody = $null
$crgLegacyAttrBasePresent = $false
$crgLegacyAttrBaseMode = $null
$crgLegacyAttrBaseOid = $null
if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal) -and -not $DispatcherOnly -and -not $RestoreLegacyRoutingCustody) {
  $crgLegacyBaseHead = "$($crgRetiredPmHead.Head)"
  if ($crgLegacyBaseHead -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') {
    Write-Error "bootstrap.ps1: the legacy transition base HEAD could not be captured as one commit object ID. Nothing has been modified in the target repository."
    exit 1
  }

  $crgLegacyRunGateTree = @(& git -C $targetRepoAbs ls-tree $crgLegacyBaseHead -- scripts/run-gate.sh 2>$null)
  if ($LASTEXITCODE -ne 0 -or $crgLegacyRunGateTree.Count -gt 1) {
    Write-Error "bootstrap.ps1: scripts/run-gate.sh could not be classified in the legacy base tree. Nothing has been modified in the target repository."
    exit 1
  }
  if ($crgLegacyRunGateTree.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace("$($crgLegacyRunGateTree[0])")) {
    if ("$($crgLegacyRunGateTree[0])" -cnotmatch '^(100644|100755) blob [0-9a-f]{40}([0-9a-f]{24})?\tscripts/run-gate\.sh$') {
      Write-Error "bootstrap.ps1: scripts/run-gate.sh is not one regular blob in the legacy base tree. Nothing has been modified in the target repository."
      exit 1
    }
    $crgLegacyRunGateHeadPresent = $true
  }

  # The transition may need to add the LF contract beside the review-kernel
  # surfaces. Only bootstrap-authored attribute bytes may ride the audited
  # landing: a pre-existing worktree edit would otherwise be folded into the
  # hash-bound record without review.
  $crgLegacyAttrTree = @(& git -C $targetRepoAbs ls-tree $crgLegacyBaseHead -- .gitattributes 2>$null)
  if ($LASTEXITCODE -ne 0 -or $crgLegacyAttrTree.Count -gt 1) {
    Write-Error "bootstrap.ps1: .gitattributes could not be classified in the legacy base tree. Nothing has been modified in the target repository."
    exit 1
  }
  if ($crgLegacyAttrTree.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace("$($crgLegacyAttrTree[0])")) {
    if ("$($crgLegacyAttrTree[0])" -cnotmatch '^(100644|100755) blob [0-9a-f]{40}([0-9a-f]{24})?\t\.gitattributes$') {
      Write-Error "bootstrap.ps1: .gitattributes is not one regular blob in the legacy base tree. Nothing has been modified in the target repository."
      exit 1
    }
    $crgLegacyAttrBasePresent = $true
    $crgLegacyAttrBaseMode = $Matches[1]
    if ("$($crgLegacyAttrTree[0])" -cmatch '^(100644|100755) blob (?<oid>[0-9a-f]{40}([0-9a-f]{24})?)\t\.gitattributes$') { $crgLegacyAttrBaseOid = $Matches['oid'] }
  } elseif ((Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs '.gitattributes')) -cne 'empty') {
    Write-Error "bootstrap.ps1: .gitattributes is absent from the legacy base but already occupies the worktree. Commit that repository configuration through the ordinary reviewed workflow before the legacy transition; bootstrap will not include pre-existing untracked attribute bytes in the bounded landing. Nothing has been modified in the target repository."
    exit 1
  }
}

Write-Host "[bootstrap] package root: $packageRoot"
Write-Host "[bootstrap] target repo:  $targetRepoAbs"
if ($selfInstall) {
  Write-Host "[bootstrap] self-install: package root == target repo top-level (gating this package on itself)"
}
if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal)) {
  Write-Host "[bootstrap] legacy review kernel detected in HEAD: retired PROJECT-MODE work-blocking behavior needs the bounded review-kernel transition printed below."
}
Write-Host ""

# Refresh loss-prevention baseline (docs/local-install-v1.md section 4):
# read the existing manifest BEFORE any overwrite so a destination whose
# bytes match its entry is recognized as unmodified-since-install; every
# other pre-existing destination is backed up before it is replaced.
# The manifest is PER-WORKTREE (Get-CrgGitDir); the backup area stays in
# the COMMON dir (recovery data is safe to share, and every backup path
# is collision-checked).
if ($RestoreLegacyRoutingCustody) {
  if (-not $selfInstall) {
    Write-Error "bootstrap.ps1: -RestoreLegacyRoutingCustody is only for this package repository restoring source routing drivers from machine-local custody created by a prior full self-bootstrap. The target does not equal the package root; no file was changed."
    exit 1
  }
  $crgRestoreLock = Enter-CrgInstallTransactionLock -GitDir $crgGitDir
  if ($null -eq $crgRestoreLock) { exit 1 }
  try {
    try { Assert-CrgRendererTransactionStateAbsent -GitDir $crgGitDir }
    catch {
      Write-Error "bootstrap.ps1: routing-custody restore refuses while standalone render transaction state exists ($($_.Exception.Message)). No routing-custody mutation was performed."
      exit 1
    }
    $crgRoutingRestore = Restore-CrgLegacyRoutingDriverCustody -RepoRoot $targetRepoAbs -GitDir $crgGitDir -ProofScratchRoot $crgProofScratchParent
  } finally {
    try { $crgRestoreLock.Dispose() } catch { }
  }
  if ($null -eq $crgRoutingRestore) {
    Write-Error "bootstrap.ps1: verified self-host routing custody was not restored. Keep the reported custody directory intact; do not re-run a normal self-bootstrap until the recovery refusal is resolved."
    exit 1
  }
  Write-Host "[bootstrap] restored and re-hashed the recorded self-host routing drivers from base-bound custody."
  Write-Host "[bootstrap] recovery phase: $($crgRoutingRestore.Phase); base: $($crgRoutingRestore.BaseHead); landing HEAD: $($crgRoutingRestore.LandingHead)"
  if ($null -ne $crgRoutingRestore.MarkerPath) {
    Write-Host "[bootstrap] durable completion marker: $($crgRoutingRestore.MarkerPath)"
  } else {
    Write-Host "[bootstrap] pre-kernel recovery completed; the next full legacy self-bootstrap republishes the bounded custody epoch before phase A is repeated."
  }
  Write-Host "[bootstrap] Re-run the full self-bootstrap with -TargetRepo . -Force before staging the remaining package inventory."
  exit 0
}
# NO legacy-location migration and NO compatibility read: the
# common-dir manifest location existed only in pre-release revisions of
# this development line -- no released package and no deployed install
# ever wrote one (operator-audited 2026-08-27; every consuming
# project predates manifests entirely). A migration was TRIED here and
# REVERTED the same day: in the main worktree the git dir IS the common
# dir, so a current main-worktree manifest is indistinguishable from a
# legacy shared one, and any migration silently seeds sibling
# worktrees' trust baselines forever -- the exact isolation the
# per-worktree location exists to provide. Do not reintroduce one; a
# worktree without a private manifest gets a full bootstrap run, the
# standard install path.
# The refresh baseline is intentionally NOT read here. A map captured before the
# per-worktree transaction lock can belong to a superseded manifest epoch by the
# time custody classifies live bytes. The only authoritative read is below,
# after the install lock is held.
$crgManifest = $null
# The backup area is COLLISION-RESISTANT per run: a random suffix beside
# the second-resolution stamp, because concurrent linked-worktree
# refreshes (one common dir) or same-second re-runs sharing a stamp
# would otherwise write the same paths and destroy an earlier recovery
# copy. A pre-existing backup path still refuses outright below --
# uniqueness is a convenience, refusal is the guarantee.
$crgBackupStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture) + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
$crgBackedUp = @()
$crgInstalledHashes = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
$crgInstalledBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)

# File list: (source-relative-to-package, dest-relative-to-target). The helper
# above is the single current-package inventory; the frozen v1.7 evidence set is
# intentionally separate. It was captured before namespace initialization so
# every distinct package-source parent could be pinned before any leaf read.

# ---- ONE HELD SNAPSHOT: bind the package leaves, THEN decide anything ----
# Everything downstream -- the upgrade classification, the version each file is
# stamped with, the install record -- must describe the SAME package state. So
# the snapshot is taken here, before the first decision and before the first
# repository write, and the buffer is the only source of truth afterwards:
# nothing re-reads the package past this point.
#
# Two earlier arrangements were wrong in the same way and are recorded so they
# are not retried. Buffering AFTER classification let the guard be chosen with
# one VERSION while different bytes were installed. Settling VERSION early but
# buffering sources later closed that for the version alone and still left the
# pair incoherent: the sources could move between the two reads.
#
# A DETECTED MUTATION REFUSES; it does not degrade to `unknown`. The two are
# different states. Having no commit identity at all -- an extracted zip, which
# INSTALL.md describes as the normal delivery -- is legitimate, and provenance
# is simply `unknown`. Bytes that DISAGREE with a commit this package does have
# mean the package changed while it was being read, and installing half of one
# revision and half of another is not something to record a caveat about. Every
# VERSION/payload leaf is therefore opened no-follow as one ordinary single-link
# file beneath the retained package-root chain, read once through that handle,
# and kept held through installation. No pathname re-read participates in proof.
$crgSrcBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
$crgSourceCommit = 'unknown'
# DispatcherOnly rewrites only the embedded dispatcher; SealManifest hashes only
# the selected target inventory. Neither consumes package payload, so neither
# may depend on package completeness or source provenance.
if ($crgNeedsPackagePayload) {
  try {
    $crgVersionOwner = Open-CrgPackageSourceHold -Path (Join-Path $packageRoot 'VERSION') -RelativePath 'VERSION' -MaxLength 128
    $crgPackageSourceOwners.Add($crgVersionOwner) | Out-Null
    $crgVersionBytes = [byte[]]$crgVersionOwner.Bytes
    $crgPackageVersion = Get-CrgPackageVersionFromBytes -Bytes $crgVersionBytes
  } catch {
    Write-Error "bootstrap.ps1: the package's VERSION file could not be retained safely ($($_.Exception.Message)). The package is damaged or concurrently changing. No target mutation was performed."
    exit 1
  }
  if ($null -eq $crgPackageVersion) {
    Write-Error "bootstrap.ps1: the package's VERSION file is not a single SemVer line (looked in '$packageRoot'). The package is damaged -- re-extract it. No target mutation was performed."
    exit 1
  }
  # Package Git identity is captured before target Git selectors are bound.
  # Every installed leaf is then held no-follow and compared, through an
  # isolated content-addressed attribute tree and stdin conversion, with the
  # captured commit. A dirty/archive mismatch stays honest `unknown`; no source
  # pathname is released or reread to authorize the label.
  foreach ($f in $fileList) {
    $crgBufSrc = Join-Path $packageRoot $f.Src
    try {
      $crgSourceOwner = Open-CrgPackageSourceHold -Path $crgBufSrc -RelativePath $f.Src -TransferableOwner:$selfInstall
      $crgSourceOwner | Add-Member -NotePropertyName Dst -NotePropertyValue $f.Dst
      $crgPackageSourceOwners.Add($crgSourceOwner) | Out-Null
      $crgSrcBuffers[$f.Dst] = [byte[]]$crgSourceOwner.Bytes
    }
    catch {
      Write-Error "bootstrap.ps1: could not retain package file '$($f.Src)' ($($_.Exception.Message)). The package is damaged or concurrently changing -- re-extract it or let the package tree settle. No target mutation was performed."
      exit 1
    }
  }
  foreach ($crgPackageAttributePath in @('.gitattributes', 'scripts/.gitattributes', 'scripts/codex/.gitattributes', 'docs/.gitattributes')) {
    try {
      $crgPackageAttributeOwner = Open-CrgPackageSourceHold -Path (Join-Path $packageRoot $crgPackageAttributePath) -RelativePath $crgPackageAttributePath -MaxLength 1048576 -AllowAbsent:($crgPackageAttributePath -cne '.gitattributes')
      if ($null -eq $crgPackageAttributeOwner) { continue }
      $crgPackageAttributeOwners.Add($crgPackageAttributeOwner) | Out-Null
      $crgPackageAttributeBuffers[$crgPackageAttributePath] = [byte[]]$crgPackageAttributeOwner.Bytes
    } catch {
      Write-Error "bootstrap.ps1: could not retain package attribute source '$crgPackageAttributePath' ($($_.Exception.Message)). The package checkout contract is damaged or concurrently changing. No target mutation was performed."
      exit 1
    }
  }
  if (-not $crgPackageAttributeBuffers.ContainsKey('.gitattributes')) {
    Write-Error "bootstrap.ps1: the package has no retained root .gitattributes source. No target mutation was performed."
    exit 1
  }
  $crgSnapshotMoved = $false
  foreach ($crgSourceOwner in @($crgPackageSourceOwners.ToArray()) + @($crgPackageAttributeOwners.ToArray())) {
    if ($null -eq $crgSourceOwner.Stream -or [CrgBootstrap.NativeV3]::GetLinkCount($crgSourceOwner.Stream.SafeFileHandle) -ne 1) { $crgSnapshotMoved = $true; break }
  }
  if ($crgSnapshotMoved) {
    Write-Error "bootstrap.ps1: the package at '$packageRoot' changed while its files were being read, so the bytes buffered for this install do not all belong to one state. Nothing has been modified in the target repository. Let the package tree settle (finish the checkout, stash or commit the edit), then re-run."
    exit 1
  }
  try {
    $crgPackageProvenanceOwners = @($crgPackageSourceOwners.ToArray()) + @($crgPackageAttributeOwners.ToArray())
    $crgSourceCommit = Get-CrgHeldPackageProvenance -Candidate $crgPackageProvenanceCandidate -VersionBytes $crgVersionBytes -SourceOwners $crgPackageProvenanceOwners -ScratchRoot $crgPackageProvenanceScratch
  } catch {
    Write-Error "bootstrap.ps1: held package provenance could not be proven safely ($($_.Exception.Message)). No target payload, custody, dispatcher, manifest, marker, or version mutation was attempted."
    exit 1
  }
  if ([string]::Equals($crgSourceCommit, 'unknown', [System.StringComparison]::Ordinal)) {
    Write-Host "[bootstrap] the package has no commit identity to record (an extracted archive, or a tree with uncommitted changes); its bytes were verified stable across the read, and provenance is recorded as 'unknown'."
  }
}

if ($SealManifest) {
  # OPERATOR-ONLY trust-state minting: the seal promotes one exact eligible
  # inventory into a transient LOCAL replacement baseline. An author agent must
  # never be able to invoke it (stub the hook, seal the replacement, pass every
  # later verification). The sanction env makes this trust-minting operation an
  # operator act by design; full -Force replacement and renderer -Check follow
  # immediately before any commit or merge.
  if (-not [string]::Equals($env:CROSS_REVIEW_ALLOW_SEAL, '1', [System.StringComparison]::Ordinal)) {
    Write-Error "bootstrap.ps1: -SealManifest MINTS local trust from the currently installed bytes and is an OPERATOR act; set CROSS_REVIEW_ALLOW_SEAL=1 for exactly this run (agents must never set it)."
    exit 1
  }
  # Bounded recovery seal (docs/install-values-v1.md section 8): hash the
  # CURRENTLY INSTALLED gate files and publish transient replacement authority.
  # Copies no gate file. The current recovery inventory must be complete;
  # present retired files join custody without becoming delivery payload. The historical
  # inventory begins with the frozen v1.7.0 release shape from
  # Get-CrgLegacyV170Paths; each
  # recognized post-v1.7 addition joins that seal when present, while
  # a partial legacy core or a non-file occupant refuses. This is what
  # lets a real metadata-free v1.7 install establish its first baseline
  # without blessing an arbitrary subset of gate paths.
  if ($null -eq $crgGitDir) {
    Write-Error "bootstrap.ps1: cannot resolve the git dir of '$targetRepoAbs' for -SealManifest."
    exit 1
  }
  $sealPath = Join-Path $crgGitDir 'crg-install-manifest'
  $sealSelectedList = @()
  $sealInventoryName = ''
  $sealPayloadOwners = New-Object 'System.Collections.Generic.List[object]'
  # The WHOLE transaction -- probes, dispatcher validation, manifest
  # publish, marker publish, and any rollback -- runs under both
  # interprocess locks in the fixed order the lock functions document
  # (common dispatcher lock first: the seal VALIDATES the shared
  # dispatcher for arming, and a sibling worktree's bootstrap must not
  # be mid-mutation of it; then this worktree's install lock for the
  # baseline). (`exit` inside the try still runs the finally,
  # releasing the locks.)
  if ($null -eq $crgCommonDir) {
    Write-Error "bootstrap.ps1: cannot resolve the git common dir of '$targetRepoAbs' to serialize -SealManifest against the shared dispatcher."
    exit 1
  }
  $sealDispLock = Enter-CrgDispatcherLock -CommonDir $crgCommonDir
  if ($null -eq $sealDispLock) { exit 1 }
  $sealLock = $null
  $sealDispHold = $null
  $sealPublication = $null
  $sealManifestOwner = $null
  $sealManifestPriorState = 'absent'
  $sealMarkerOwner = $null
  $sealMarkerPriorState = 'absent'
  $sealMarkerReservation = $null
  $sealFailedMarkerReservation = $null
  try {
  $sealLock = Enter-CrgInstallTransactionLock -GitDir $crgGitDir
  if ($null -eq $sealLock) { exit 1 }
  try { Assert-CrgRendererTransactionStateAbsent -GitDir $crgGitDir }
  catch {
    Write-Error "bootstrap.ps1: -SealManifest refuses while standalone render transaction state exists ($($_.Exception.Message)). Nothing was sealed."
    exit 1
  }
  try {
    $crgRenderOutputAuthority = Get-CrgInstallValueOutputAuthority -RepoRoot $targetRepoAbs
    if ($crgRenderOutputAuthority.Family -cne 'LOCAL') { throw '-SealManifest is valid only for one complete LOCAL render-output family' }
    try { $crgValuesSourceOwner = Open-CrgInstallValuesSourceHold -RepoRoot $targetRepoAbs }
    catch { throw "the mandatory fixed source '$targetRepoAbs\CROSS-REVIEW-VALUES.md' cannot be retained ($($_.Exception.Message)); create and authorize the v1 source before sealing" }
    $crgValuesSourceEvidence = Get-CrgInstallValuesSourceEvidence -RepoRoot $targetRepoAbs -Family LOCAL -SourceOwner $crgValuesSourceOwner
    $sealParsedValues = Read-CrgInstallValuesBytes -Bytes $crgValuesSourceOwner.Bytes

    $sealRendererKind = Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs 'scripts/render-project-values.ps1')
    $sealAgentsKind = Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs 'docs/AGENTS.md.template')
    $sealRecoveryList = @(Get-CrgSealRecoveryFileList)
    if ($sealRendererKind -ceq 'file' -and $sealAgentsKind -ceq 'file') {
      # The first catalog whose layout is complete wins. An older frozen
      # catalog also requires every current path it lacks to be positively
      # absent, so a partial upgrade never seals as either layout.
      $sealCatalogs = @(
        [pscustomobject]@{ Name = 'complete current shared layout'; List = $sealRecoveryList },
        [pscustomobject]@{ Name = 'complete pre-common shared layout'; List = @(Get-CrgPreCommonRecoveryFileList) },
        [pscustomobject]@{ Name = 'complete pre-liveness shared layout'; List = @(Get-CrgPreLivenessRecoveryFileList) },
        [pscustomobject]@{ Name = 'complete pre-relocation v2.1/v2.2'; List = @(Get-CrgPreRelocationRecoveryFileList) }
      )
      $sealCatalogRefusals = @()
      $sealChosenCatalog = $null
      foreach ($sealCatalog in $sealCatalogs) {
        $sealCatalogBad = @()
        foreach ($sealCatalogFile in @($sealCatalog.List | Where-Object { -not $_.Retired })) {
          $sealCatalogKind = Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs $sealCatalogFile.Dst)
          if ($sealCatalogKind -cne 'file') { $sealCatalogBad += "$($sealCatalogFile.Dst) ($sealCatalogKind)" }
        }
        $sealCatalogPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($sealCatalogFile in $sealCatalog.List) { [void]$sealCatalogPaths.Add($sealCatalogFile.Dst) }
        foreach ($sealCurrentFile in @($sealRecoveryList | Where-Object { -not $sealCatalogPaths.Contains($_.Dst) })) {
          $sealNewerKind = Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs $sealCurrentFile.Dst)
          if ($sealNewerKind -cne 'empty') { $sealCatalogBad += "newer path $($sealCurrentFile.Dst) ($sealNewerKind)" }
        }
        if ($sealCatalogBad.Count -eq 0) { $sealChosenCatalog = $sealCatalog; break }
        $sealCatalogRefusals += "$($sealCatalog.Name): $($sealCatalogBad -join ', ')"
      }
      if ($null -eq $sealChosenCatalog) {
        throw "current LOCAL recovery inventory matches no complete supported layout with every newer path positively absent ($($sealCatalogRefusals -join '; '))"
      }
      $sealRecoveryList = $sealChosenCatalog.List
      $sealInventoryName = $sealChosenCatalog.Name
      foreach ($sealRecoveryFile in $sealRecoveryList) {
        $sealRecoveryKind = Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs $sealRecoveryFile.Dst)
        if ($sealRecoveryKind -ceq 'file') { $sealSelectedList += $sealRecoveryFile }
        elseif (-not ($sealRecoveryFile.Retired -and $sealRecoveryKind -ceq 'empty')) {
          throw "current recovery path '$($sealRecoveryFile.Dst)' has unsupported occupant kind '$sealRecoveryKind'"
        }
      }
      $sealIsCurrent = $true
    } elseif ($sealRendererKind -ceq 'empty' -and $sealAgentsKind -ceq 'empty') {
      $sealLegacyCorePaths = @(Get-CrgLegacyV170Paths)
      $sealLegacyAdditionPaths = @(Get-CrgLegacyV170RecognizedAdditions)
      $sealLegacyCoreBad = @()
      foreach ($sealLegacyCorePath in $sealLegacyCorePaths) {
        $sealLegacyCoreKind = Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs $sealLegacyCorePath)
        if ($sealLegacyCoreKind -cne 'file') { $sealLegacyCoreBad += "$sealLegacyCorePath ($sealLegacyCoreKind)" }
      }
      if ($sealLegacyCoreBad.Count -gt 0) { throw "frozen v1.7 core is incomplete: $($sealLegacyCoreBad -join ', ')" }
      $sealSelectedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
      foreach ($sealLegacyCorePath in $sealLegacyCorePaths) { [void]$sealSelectedPaths.Add($sealLegacyCorePath) }
      foreach ($sealLegacyAdditionPath in $sealLegacyAdditionPaths) {
        $sealLegacyAdditionKind = Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs $sealLegacyAdditionPath)
        if ($sealLegacyAdditionKind -ceq 'file') { [void]$sealSelectedPaths.Add($sealLegacyAdditionPath) }
        elseif ($sealLegacyAdditionKind -cne 'empty') { throw "recognized legacy path '$sealLegacyAdditionPath' has unsupported occupant kind '$sealLegacyAdditionKind'" }
      }
      $sealSelectedList = @($sealRecoveryList | Where-Object { $sealSelectedPaths.Contains($_.Dst) })
      if ($sealSelectedList.Count -ne $sealSelectedPaths.Count) { throw 'the recovery catalog does not cover the exact recognized legacy inventory' }
      $sealV200Paths = @(Get-CrgLegacyV200Paths)
      $sealIsV200 = ($sealSelectedList.Count -eq $sealV200Paths.Count)
      if ($sealIsV200) {
        foreach ($sealV200Path in $sealV200Paths) { if (-not $sealSelectedPaths.Contains($sealV200Path)) { $sealIsV200 = $false; break } }
      }
      $sealInventoryName = if ($sealIsV200) { 'complete frozen v2.0.0' } else { 'complete frozen v1.7.0 core plus present recognized v2.0 additions' }
      $sealIsCurrent = $false
    } else {
      throw "mixed v2.1 seal shape: renderer=$sealRendererKind, agents-template=$sealAgentsKind; both new paths must be present for current recovery or absent for frozen legacy recovery"
    }

    $sealAuthorityPaths = @($sealSelectedList | ForEach-Object { $_.Dst }) + @('scripts/render-project-values.ps1', 'docs/AGENTS.md.template')
    Assert-CrgLocalSealPathAuthority -RepoRoot $targetRepoAbs -Paths $sealAuthorityPaths
    foreach ($sealFile in $sealSelectedList) {
      $sealOwner = Open-CrgBoundedOwnerFileNoFollow -Path (Join-Path $targetRepoAbs $sealFile.Dst) -MaxLength 16777216 -Label "seal inventory '$($sealFile.Dst)'"
      $sealHash = Get-CrgSha256HexOfHeldStream -Stream $sealOwner.Stream
      $sealPayloadOwners.Add([pscustomobject]@{ Dst = $sealFile.Dst; Fs = $sealOwner.Stream; Hash = $sealHash; Bytes = $sealOwner.Bytes }) | Out-Null
      $sealOwner.Stream = $null
    }

    $sealPromptOwner = @($sealPayloadOwners | Where-Object { $_.Dst -ceq 'scripts/codex/review-prompt-template.md' })
    if ($sealPromptOwner.Count -ne 1) { throw 'the exact held seal inventory lacks one review prompt' }
    if ($sealIsCurrent) {
      $sealAgentsOwner = @($sealPayloadOwners | Where-Object { $_.Dst -ceq 'docs/AGENTS.md.template' })
      if ($sealAgentsOwner.Count -ne 1) { throw 'the current held seal inventory lacks one AGENTS merge template' }
      $null = Invoke-CrgInstallValueRender -Values $sealParsedValues -TemplateBytes ([byte[]]$sealPromptOwner[0].Bytes) -Target 'review-prompt'
      $null = Invoke-CrgInstallValueRender -Values $sealParsedValues -TemplateBytes ([byte[]]$sealAgentsOwner[0].Bytes) -Target 'agents-template'
    } else {
      $sealSlotPrefix = $script:CrgUtf8NoBom.GetBytes('<!-- crg-render-slot v1 ')
      if (Test-CrgInstallValueByteSequence -Bytes ([byte[]]$sealPromptOwner[0].Bytes) -Needle $sealSlotPrefix) {
        throw 'the frozen legacy prompt contains a v1 render-slot marker and is not a legacy seal candidate'
      }
    }

    Assert-CrgInstallValuesEpoch -RepoRoot $targetRepoAbs -OutputAuthority $crgRenderOutputAuthority -SourceEvidence $crgValuesSourceEvidence -SourceOwner $crgValuesSourceOwner
    Assert-CrgLocalSealPathAuthority -RepoRoot $targetRepoAbs -Paths $sealAuthorityPaths
  } catch {
    Write-Error "bootstrap.ps1: -SealManifest eligibility refused before metadata mutation ($($_.Exception.Message)). Nothing was sealed."
    exit 1
  }
  $sealManifestKind = Get-CrgPathOccupantKind -Path $sealPath
  if ($sealManifestKind -ceq 'file') {
    try {
      $sealManifestOwner = Open-CrgInstallManifestOwner -ManifestPath $sealPath -RequireStrict
      $sealManifestPriorState = 'held'
    } catch {
      $sealManifestPriorState = 'foreign'
      Write-Host "[bootstrap] ERROR: -SealManifest cannot own the existing manifest as one strict no-follow ordinary single-link record ($($_.Exception.Message)); preserving it and refusing publication."
      exit 1
    }
  } elseif ($sealManifestKind -cne 'empty') {
    $sealManifestPriorState = 'foreign'
    Write-Host "[bootstrap] ERROR: -SealManifest found manifest occupant kind '$sealManifestKind'; preserving it and refusing publication."
    exit 1
  }
  $sealMarkerPath = Join-Path $crgGitDir 'crg-local-install'
  $sealMarkerKind = Get-CrgPathOccupantKind -Path $sealMarkerPath
  if ($sealMarkerKind -ceq 'file') {
    try {
      $sealMarkerOwner = Open-CrgBoundedOwnerFileNoFollow -Path $sealMarkerPath -MaxLength 1048576 -Label 'local-shape authorization marker' -Writable
      $sealMarkerPriorState = 'held'
    } catch {
      $sealMarkerPriorState = 'foreign'
      Write-Host "[bootstrap] ERROR: -SealManifest cannot own the prior authorization marker ($($_.Exception.Message)); preserving it and refusing publication."
      exit 1
    }
  } elseif ($sealMarkerKind -cne 'empty') {
    $sealMarkerPriorState = 'foreign'
    Write-Host "[bootstrap] ERROR: -SealManifest found authorization-marker occupant kind '$sealMarkerKind'; preserving it and refusing publication."
    exit 1
  }
  # A completed upgrade drops retired manifest entries without deleting the
  # historical files. Their presence must not expand that reduced baseline;
  # all captured owners still remain held and reverified through publication.
  if ($sealIsCurrent -and $sealManifestPriorState -ceq 'held') {
    $sealSelectedList = @($sealSelectedList | Where-Object { -not $_.Retired -or $sealManifestOwner.Map.ContainsKey($_.Dst) })
  }
  $sealBaselinePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($sealFile in $sealSelectedList) { [void]$sealBaselinePaths.Add($sealFile.Dst) }
  $sealBaselineOwners = @($sealPayloadOwners | Where-Object { $sealBaselinePaths.Contains($_.Dst) })
  $sealHeldHashes = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  foreach ($sealPayloadOwner in $sealBaselineOwners) { $sealHeldHashes[$sealPayloadOwner.Dst] = $sealPayloadOwner.Hash }
  if ($sealManifestPriorState -ceq 'held') {
    if ($sealMarkerPriorState -cne 'held' -or $sealManifestOwner.Map.Count -ne $sealHeldHashes.Count) {
      Write-Error 'bootstrap.ps1: -SealManifest found partial, foreign, or future install metadata rather than one marker-bound baseline for the exact admitted inventory. Existing metadata was preserved.'
      exit 1
    }
    foreach ($sealHeldPath in $sealHeldHashes.Keys) {
      if (-not $sealManifestOwner.Map.ContainsKey($sealHeldPath)) {
        Write-Error "bootstrap.ps1: -SealManifest prior metadata names a different inventory (missing '$sealHeldPath' or carrying an extra future path). Existing metadata was preserved."
        exit 1
      }
    }
    $sealPriorManifestHash = Get-CrgSha256HexOfBytes -Bytes $sealManifestOwner.Bytes
    $sealPriorMarkerBytes = [System.Text.Encoding]::ASCII.GetBytes("crg-local-install-authorization v1`nmanifest-sha256: $sealPriorManifestHash`n" + ((@($sealSelectedList | ForEach-Object { $_.Dst }) -join "`n") + "`n"))
    if (-not (Compare-CrgInstallValueBytes -Left ([byte[]]$sealMarkerOwner.Bytes) -Right $sealPriorMarkerBytes)) {
      Write-Error 'bootstrap.ps1: -SealManifest prior authorization marker does not strictly bind the exact prior manifest and admitted inventory. Existing metadata was preserved.'
      exit 1
    }
  } elseif ($sealMarkerPriorState -cne 'absent') {
    Write-Error 'bootstrap.ps1: -SealManifest found an authorization marker without one strict prior manifest. Existing metadata was preserved.'
    exit 1
  }
  $sealBaselineDiffers = $false
  if ($sealManifestPriorState -ceq 'held') {
    if ($sealManifestOwner.Map.Count -ne $sealHeldHashes.Count) {
      $sealBaselineDiffers = $true
    } else {
      foreach ($sealHeldPath in $sealHeldHashes.Keys) {
        if (-not $sealManifestOwner.Map.ContainsKey($sealHeldPath) -or
            -not [string]::Equals([string]$sealManifestOwner.Map[$sealHeldPath], [string]$sealHeldHashes[$sealHeldPath], [System.StringComparison]::Ordinal)) {
          $sealBaselineDiffers = $true
          break
        }
      }
    }
  }
  $sealMetadataAbsent = $sealManifestPriorState -ceq 'absent' -and $sealMarkerPriorState -ceq 'absent'
  if (-not $sealMetadataAbsent -and -not ($sealManifestPriorState -ceq 'held' -and $sealBaselineDiffers)) {
    Write-Error 'bootstrap.ps1: -SealManifest is a bounded recovery act, but the complete selected recovery baseline already equals the recorded manifest baseline or metadata is only partially absent. Nothing was sealed; use the existing verified baseline or reconcile the metadata state.'
    exit 1
  }
  $sealLines = @(
    'crg-install-manifest v2',
    ('installed: ' + [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture))
  )
  foreach ($sealFile in $sealSelectedList) { $sealLines += ($sealHeldHashes[$sealFile.Dst] + '  ' + $sealFile.Dst) }
  # Shape probes run BEFORE publication: a probe failure aborts with
  # the previous manifest AND its still-valid marker untouched.
  $sealAuthProbe = Get-CrgLocalAuthorizationPaths -RepoRoot $targetRepoAbs -FileList $sealSelectedList
  if (-not $sealAuthProbe.Ok) { exit 1 }
  if ($sealAuthProbe.Paths.Count -gt 0) {
    # The hold pins the validated dispatcher bytes (no write, delete,
    # or rename can land) until the marker publication below is done.
    $sealDispHold = Get-CrgDispatcherGuardHold -RepoRoot $targetRepoAbs
    if (-not $sealDispHold.Ok) {
      Write-Host "[bootstrap] ERROR: -SealManifest refused: the installed dispatcher is missing, unreadable, predates the gate-untracking guard, or still carries retired PROJECT-MODE enforcement, and a local-shape marker must never be armed beside it. Refresh the dispatcher first: powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetRepo `"$targetRepoAbs`" -DispatcherOnly; then re-run the sanctioned seal. Nothing was published; the existing manifest and marker, if any, are untouched."
      exit 1
    }
  }
  try {
    Assert-CrgInstallValuesEpoch -RepoRoot $targetRepoAbs -OutputAuthority $crgRenderOutputAuthority -SourceEvidence $crgValuesSourceEvidence -SourceOwner $crgValuesSourceOwner
    Assert-CrgLocalSealPathAuthority -RepoRoot $targetRepoAbs -Paths $sealAuthorityPaths
    foreach ($sealPayloadOwner in $sealPayloadOwners) {
      if ([CrgBootstrap.NativeV3]::GetLinkCount($sealPayloadOwner.Fs.SafeFileHandle) -ne 1 -or
          (Get-CrgSha256HexOfHeldStream -Stream $sealPayloadOwner.Fs) -cne $sealPayloadOwner.Hash) {
        throw "held seal inventory '$($sealPayloadOwner.Dst)' changed before metadata publication"
      }
    }
  } catch {
    Write-Error "bootstrap.ps1: -SealManifest source or inventory epoch changed before metadata publication ($($_.Exception.Message)). Nothing was sealed."
    exit 1
  }
  $sealPlannedManifestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes((($sealLines -join "`n") + "`n"))
  $sealPlannedManifestHash = Get-CrgSha256HexOfBytes -Bytes $sealPlannedManifestBytes
  $sealMarkerReservation = Start-CrgLocalAuthorizationMarkerReservationExact -GitDir $crgGitDir -Paths $sealAuthProbe.Paths -ExpectedManifestHash $sealPlannedManifestHash -PriorOwner $sealMarkerOwner -PriorState $sealMarkerPriorState
  if ($null -eq $sealMarkerReservation) { exit 1 }
  $sealPubHash = Publish-CrgInstallManifest -ManifestPath $sealPath -Lines $sealLines -RepoRoot $targetRepoAbs -FileList $sealSelectedList -PayloadOwners $sealBaselineOwners -PriorOwner $sealManifestOwner -PriorState $sealManifestPriorState -PublicationRef ([ref]$sealPublication)
  if (-not $sealPubHash) {
    Write-Host '[bootstrap] the manifest did not publish; the fixed marker reservation remains fail-closed rather than rearming beside an indeterminate manifest name.'
    exit 1
  }
  if (-not [string]::Equals($sealPubHash, $sealPlannedManifestHash, [System.StringComparison]::Ordinal)) {
    $null = Restore-CrgManifestPublicationExact -ManifestPath $sealPath -OnlyIfManifestHash $sealPubHash -Publication $sealPublication -MarkerReservation $sealMarkerReservation
    exit 1
  }
  $sealAuthPub = Publish-CrgLocalAuthorizationMarkerExact -GitDir $crgGitDir -Paths $sealAuthProbe.Paths -ManifestPath $sealPath -ExpectedManifestHash $sealPubHash -ManifestOwner $sealPublication.PublishedOwner -GuardHold $sealDispHold -Reservation $sealMarkerReservation -FailedReservationRef ([ref]$sealFailedMarkerReservation)
  if ($sealAuthPub -cne 'ok') {
    # Every marker failure disarms this run's exact manifest. The previous
    # manifest is restored only while its exact previous marker remains held;
    # otherwise the old manifest stays at its supersession path and the live
    # manifest name remains fail-closed absent.
    $null = Restore-CrgManifestPublicationExact -ManifestPath $sealPath -OnlyIfManifestHash $sealPubHash -Publication $sealPublication -MarkerReservation $sealFailedMarkerReservation
    exit 1
  }
  } finally {
    if ($null -ne $sealPublication) {
      if ($null -ne $sealPublication.PublishedOwner -and $null -ne $sealPublication.PublishedOwner.Stream) { try { $sealPublication.PublishedOwner.Stream.Dispose() } catch { } }
      if ($null -ne $sealPublication.PublishedOwner) { foreach ($sealPayloadOwner in @($sealPublication.PublishedOwner.PayloadOwners)) { if ($null -ne $sealPayloadOwner.Fs) { try { $sealPayloadOwner.Fs.Dispose() } catch { }; $sealPayloadOwner.Fs = $null } } }
      if ($null -ne $sealPublication.PreviousOwner -and $null -ne $sealPublication.PreviousOwner.Stream) { try { $sealPublication.PreviousOwner.Stream.Dispose() } catch { } }
    }
    if ($null -ne $sealManifestOwner -and $null -ne $sealManifestOwner.Stream) { try { $sealManifestOwner.Stream.Dispose() } catch { } }
    if ($null -ne $sealMarkerOwner -and $null -ne $sealMarkerOwner.Stream) { try { $sealMarkerOwner.Stream.Dispose() } catch { } }
    if ($null -ne $sealMarkerReservation) {
      if ($null -ne $sealMarkerReservation.ReservationOwner -and $null -ne $sealMarkerReservation.ReservationOwner.Stream) { try { $sealMarkerReservation.ReservationOwner.Stream.Dispose() } catch { } }
      if ($null -ne $sealMarkerReservation.PreviousOwner -and $null -ne $sealMarkerReservation.PreviousOwner.Stream) { try { $sealMarkerReservation.PreviousOwner.Stream.Dispose() } catch { } }
    }
    if ($null -ne $sealFailedMarkerReservation) {
      if ($null -ne $sealFailedMarkerReservation.ReservationOwner -and $null -ne $sealFailedMarkerReservation.ReservationOwner.Stream) { try { $sealFailedMarkerReservation.ReservationOwner.Stream.Dispose() } catch { } }
      if ($null -ne $sealFailedMarkerReservation.PreviousOwner -and $null -ne $sealFailedMarkerReservation.PreviousOwner.Stream) { try { $sealFailedMarkerReservation.PreviousOwner.Stream.Dispose() } catch { } }
    }
    foreach ($sealPayloadOwner in $sealPayloadOwners) {
      if ($null -ne $sealPayloadOwner.Fs) { try { $sealPayloadOwner.Fs.Dispose(); $sealPayloadOwner.Fs = $null } catch { } }
    }
    if ($null -ne $sealDispHold -and $null -ne $sealDispHold.Handle) { try { $sealDispHold.Handle.Dispose() } catch { } }
    if ($null -ne $sealLock) { try { $sealLock.Dispose() } catch { } }
    try { $sealDispLock.Dispose() } catch { }
  }
  Write-Host "[bootstrap] -SealManifest complete: $($sealSelectedList.Count) files from the $sealInventoryName inventory are the transient replacement baseline -> $sealPath"
  Write-Host '[bootstrap] REQUIRED NEXT: remove CROSS_REVIEW_ALLOW_SEAL, then immediately run the full package bootstrap with -Force and the installed renderer with -Check.'
  Write-Host '[bootstrap]   Remove-Item Env:CROSS_REVIEW_ALLOW_SEAL -ErrorAction SilentlyContinue'
  Write-Host "[bootstrap]   powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetRepo `"$targetRepoAbs`" -Force"
  Write-Host "[bootstrap]   powershell -NoProfile -ExecutionPolicy Bypass -File `"$targetRepoAbs\scripts\render-project-values.ps1`" -TargetRepo `"$targetRepoAbs`" -Check"
  Write-Host '[bootstrap] Do not retry a commit or merge against sealed drift before both commands succeed.'
  exit 0
}

# The ordinary install transaction starts before trackability/index revalidation
# and before custody becomes the write-ahead phase. Lock order is fixed across
# linked worktrees: common dispatcher first, then this worktree's install lock.
if ($null -eq $crgCommonDir) {
  Write-Error "bootstrap.ps1: cannot resolve the git common dir of '$targetRepoAbs' to serialize the shared dispatcher install; refusing to mutate the hooks path unserialized."
  exit 1
}
$crgDispLock = Enter-CrgDispatcherLock -CommonDir $crgCommonDir
if ($null -eq $crgDispLock) { exit 1 }
if (-not $DispatcherOnly) {
  $crgStageLock = Enter-CrgInstallTransactionLock -GitDir $crgGitDir
  if ($null -eq $crgStageLock) { exit 1 }
  try { Assert-CrgRendererTransactionStateAbsent -GitDir $crgGitDir }
  catch {
    Write-Error "bootstrap.ps1: a standalone render transaction must be recovered before bootstrap can mutate this worktree ($($_.Exception.Message)). No install mutation was performed."
    exit 1
  }
}

# Bind every install decision to one HEAD identity captured under the applicable
# lock. The entry snapshot is only an early fail-fast observation; movement in
# either OID/unborn-ref identity or semantic class refuses before the first
# repository mutation. DispatcherOnly shares only the common dispatcher lock,
# which is the applicable transaction lock for that mode.
$crgLockedPmHead = Get-CrgRetiredProjectModeHeadState -Repo $targetRepoAbs
if ([string]::Equals($crgLockedPmHead.State, 'error', [System.StringComparison]::Ordinal)) {
  Write-Error "bootstrap.ps1: trusted HEAD could not be classified after transaction lock acquisition ($($crgLockedPmHead.Reason)). No repository mutation was performed."
  exit 1
}
if (-not [string]::Equals("$($crgLockedPmHead.Identity)", "$($crgRetiredPmHead.Identity)", [System.StringComparison]::Ordinal) -or
    -not [string]::Equals($crgLockedPmHead.State, $crgRetiredPmHead.State, [System.StringComparison]::Ordinal)) {
  Write-Error "bootstrap.ps1: trusted HEAD changed before the locked install transaction began (entry=$($crgRetiredPmHead.Identity)/$($crgRetiredPmHead.State), locked=$($crgLockedPmHead.Identity)/$($crgLockedPmHead.State)). No repository mutation was performed."
  exit 1
}
$crgRetiredPmHead = $crgLockedPmHead
if (-not $DispatcherOnly) {
  $crgLockedManifestPath = Join-Path $crgGitDir 'crg-install-manifest'
  $crgLockedManifestKind = Get-CrgPathOccupantKind -Path $crgLockedManifestPath
  if ($crgLockedManifestKind -ceq 'file') {
    try {
      $crgManifestOwner = Open-CrgInstallManifestOwner -ManifestPath $crgLockedManifestPath -RequireStrict
      $crgManifest = $crgManifestOwner.Map
      $crgManifestPriorState = 'held'
    } catch {
      $crgManifestOwner = $null
      $crgManifest = $null
      $crgManifestPriorState = 'foreign'
      Write-Host "[bootstrap] the existing manifest cannot carry overwrite authority because no held no-follow ordinary single-link strict record could be acquired ($($_.Exception.Message)); every destination is treated as unrecognized."
    }
  } else {
    $crgManifest = $null
    $crgManifestPriorState = if ($crgLockedManifestKind -ceq 'empty') { 'absent' } else { 'foreign' }
  }
  $crgLockedVersionPath = Join-Path $crgGitDir 'crg-install-version'
  $crgLockedVersionKind = Get-CrgPathOccupantKind -Path $crgLockedVersionPath
  if ($crgLockedVersionKind -ceq 'file') {
    try {
      $crgUpVersionOwner = Open-CrgInstallVersionOwner -RecordPath $crgLockedVersionPath
      $crgUpPrev = $crgUpVersionOwner.Record
      $crgUpVersionPriorState = 'held'
    } catch {
      $crgUpVersionFailure = $_.Exception.Message
      $crgUpVersionOwner = $null
      $crgUpPrev = $null
      $crgUpVersionPriorState = 'foreign'
    }
  } elseif ($crgLockedVersionKind -cne 'empty') {
    $crgUpVersionPriorState = 'foreign'
  }
  $crgLockedAuthPath = Join-Path $crgGitDir 'crg-local-install'
  $crgLockedAuthKind = Get-CrgPathOccupantKind -Path $crgLockedAuthPath
  if ($crgLockedAuthKind -ceq 'file') {
    try {
      $crgAuthMarkerOwner = Open-CrgBoundedOwnerFileNoFollow -Path $crgLockedAuthPath -MaxLength 1048576 -Label 'local-shape authorization marker' -Writable
      $crgAuthMarkerPriorState = 'held'
    } catch {
      $crgAuthMarkerPriorState = 'foreign'
      $crgAuthMarkerOwner = $null
    }
  } elseif ($crgLockedAuthKind -cne 'empty') {
    $crgAuthMarkerPriorState = 'foreign'
  }
}

if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal) -and -not $DispatcherOnly) {
  $crgLockedHead = (& git -C $targetRepoAbs rev-parse --verify 'HEAD^{commit}' 2>$null)
  if ($LASTEXITCODE -ne 0 -or
      -not [string]::Equals("$crgLockedHead".Trim(), $crgLegacyBaseHead, [System.StringComparison]::Ordinal)) {
    Write-Error 'bootstrap.ps1: HEAD changed before the locked legacy install transaction began. No repository mutation was performed.'
    exit 1
  }
  & git -C $targetRepoAbs diff --cached --quiet --no-ext-diff --no-textconv --no-renames --ignore-submodules=none $crgLegacyBaseHead -- 2>$null
  if ($LASTEXITCODE -ne 0) {
    Write-Error 'bootstrap.ps1: the index changed before the locked legacy install transaction began. No repository mutation was performed.'
    exit 1
  }
}

if ($crgNeedsPackagePayload) {
  $crgLockedResume = Get-CrgLegacyRoutingResumeState -RepoRoot $targetRepoAbs -GitDir $crgGitDir
  $crgLockedSameState = [string]::Equals($crgLockedResume.State, $crgRoutingResume.State, [System.StringComparison]::Ordinal)
  $crgLockedSameBase = [string]::Equals("$($crgLockedResume.BaseHead)", "$($crgRoutingResume.BaseHead)", [System.StringComparison]::Ordinal)
  $crgLockedSameLanding = [string]::Equals("$($crgLockedResume.LandingHead)", "$($crgRoutingResume.LandingHead)", [System.StringComparison]::Ordinal)
  if (-not $crgLockedSameState -or -not $crgLockedSameBase -or -not $crgLockedSameLanding) {
    if ($null -ne $crgLockedResume.Lease) { Close-CrgLegacyRoutingCustodyLease -Lease $crgLockedResume.Lease }
    Write-Error "bootstrap.ps1: routing-custody state changed before the locked install transaction began (entry=$($crgRoutingResume.State), locked=$($crgLockedResume.State)). No repository mutation was performed."
    exit 1
  }
  if ($null -ne $crgLockedResume.Lease) {
    $crgOldRoutingLease = $crgRoutingLease
    $crgRoutingLease = $crgLockedResume.Lease
    $crgRoutingResume = $crgLockedResume
    if ($null -ne $crgOldRoutingLease) { Close-CrgLegacyRoutingCustodyLease -Lease $crgOldRoutingLease }
  } else { $crgRoutingResume = $crgLockedResume }
  if (([string]::Equals($crgRoutingResume.State, 'pre-transition', [System.StringComparison]::Ordinal) -or [string]::Equals($crgRoutingResume.State, 'pre-kernel', [System.StringComparison]::Ordinal))) {
    $crgLockedCandidate = Get-CrgLegacyRoutingCandidateSourceState -SourceBuffers $crgSrcBuffers -Custody $crgRoutingResume.Custody
    if (-not $crgLockedCandidate.Ready) {
      Write-Error "bootstrap.ps1: verified self-host routing custody is active at the exact recorded legacy base, but the buffered package routing sources are not the captured candidate ($($crgLockedCandidate.Reason)). Run -RestoreLegacyRoutingCustody from this checkout, then retry the full self-bootstrap. No repository mutation was performed."
      exit 1
    }
  }
}

# PRE-MUTATION preflight on the install's trackability -- the FIRST thing
# the install path does to the repository is decide whether it can finish.
# The LF checkout rules bind only once `.gitattributes` is tracked, and the
# tracked-shape install commit stages `.gitignore` too, so an ignore rule
# matching a file the install must track (a global excludesfile,
# info/exclude, a root .gitignore) makes every documented staging recipe
# fail without -f while the audited skip refuses the unstaged LF contract.
# Refusing HERE -- before the custody exclude patterns are appended, before
# any gate file is copied, before any config is written -- keeps the
# documented recovery ("remove the ignore rule, then re-run") true: a later
# refusal would leave appended config or gate files behind and turn the
# re-run into a destination-collision refusal. The shape decision mirrors
# the per-path classification the install applies later: `.gitattributes`
# carries a rule for every sh path that is NOT ignored, so ANY exposed sh
# path needs it trackable; `.gitignore` receives the logs/ rule only when
# the HOOK path is exposed (an ignored hook path is the local shape, whose
# logs/ rule goes to info/exclude), so only that shape needs it trackable
# -- a hybrid target (ignored hook path, tracked run-gate.sh, ignored
# .gitignore) is a supported install and must not refuse.
if (-not $DispatcherOnly) {
  $crgPreRgExposed = $false
  $crgPreHookExposed = $false
  foreach ($crgPreSh in @('scripts/run-gate.sh', 'scripts/git-hooks/pre-commit')) {
    $crgPreState = Get-CrgCheckIgnoreState -Repo $targetRepoAbs -Path $crgPreSh
    if (([string]$crgPreState).StartsWith('error:', [System.StringComparison]::Ordinal)) {
      Write-Error "bootstrap.ps1: git check-ignore failed ($crgPreState) probing '$crgPreSh' in '$targetRepoAbs'; cannot decide the install shape before touching the repository. Diagnose the repository, then re-run."
      exit 1
    }
    if ([string]::Equals($crgPreState, 'exposed', [System.StringComparison]::Ordinal)) {
      if ([string]::Equals($crgPreSh, 'scripts/git-hooks/pre-commit', [System.StringComparison]::Ordinal)) { $crgPreHookExposed = $true } else { $crgPreRgExposed = $true }
    }
  }
  try { $crgRenderOutputAuthority = Get-CrgInstallValueOutputAuthority -RepoRoot $targetRepoAbs }
  catch {
    Write-Error "bootstrap.ps1: render-output authority could not be classified before target mutation ($($_.Exception.Message))."
    exit 1
  }
  $crgPreCfgNeeded = @()
  if ($crgPreRgExposed -or $crgPreHookExposed) { $crgPreCfgNeeded += '.gitattributes' }
  if ([string]::Equals($crgRenderOutputAuthority.Family, 'TRACKED', [System.StringComparison]::Ordinal) -and -not [System.Linq.Enumerable]::Contains([string[]]@($crgPreCfgNeeded), '.gitattributes', [System.StringComparer]::Ordinal)) { $crgPreCfgNeeded += '.gitattributes' }
  if ($crgPreHookExposed) { $crgPreCfgNeeded += '.gitignore' }
  foreach ($crgPreCfg in $crgPreCfgNeeded) {
    $crgPreCfgState = Get-CrgCheckIgnoreState -Repo $targetRepoAbs -Path $crgPreCfg
    if (([string]$crgPreCfgState).StartsWith('error:', [System.StringComparison]::Ordinal)) {
      Write-Error "bootstrap.ps1: git check-ignore failed ($crgPreCfgState) probing '$crgPreCfg' in '$targetRepoAbs'; cannot confirm the install's config files can be tracked. Diagnose the repository, then re-run."
      exit 1
    }
    if ([string]::Equals($crgPreCfgState, 'ignored', [System.StringComparison]::Ordinal)) {
      Write-Error "bootstrap.ps1: '$crgPreCfg' is IGNORED in '$targetRepoAbs' (a global excludesfile, info/exclude, or .gitignore rule matches it), so this install shape could never stage it and the documented install commit would fail. Nothing was installed or configured. Remove that ignore rule, then re-run."
      exit 1
    }
  }
}

# Index-only work is invisible to every filesystem custody/backup path. Before
# the first repository mutation, prove each package destination plus each
# shape-derived tracked config candidate has the same stage-0 identity as HEAD,
# or is positively absent from both HEAD and the index. The config candidates
# are deliberately not a blanket pair: LOCAL/hybrid shapes that will not touch
# or stage one of these project files must not be rejected for unrelated work.
# The full package destination set still matters because a staged deletion is
# absent from the worktree and therefore is not a collision; recreating it and
# printing a later `git add` would erase the index's sole record. Same-version
# refreshes and self-installs are included because both print the staging plan,
# even though a self-install skips package copying. Non-regular/unmerged/failed
# probes fail closed.
if (-not $DispatcherOnly) {
  $crgIndexGuardPaths = @($fileList | ForEach-Object { $_.Dst }) + @($crgPreCfgNeeded)
  $crgIndexDivergences = New-Object 'System.Collections.Generic.List[string]'
  foreach ($crgIndexPath in $crgIndexGuardPaths) {
    $crgIndexHead = Get-CrgHeadPathBaseline -Repo $targetRepoAbs -Path $crgIndexPath
    $crgIndexStage = Get-CrgIndexPathBaseline -Repo $targetRepoAbs -Path $crgIndexPath
    if ($crgIndexHead.State -ceq 'present') {
      if ($crgIndexStage.State -cne 'present') {
        $crgIndexDivergences.Add("$crgIndexPath - HEAD is regular, but the index is $($crgIndexStage.State): $($crgIndexStage.Reason)") | Out-Null
      } elseif (-not [string]::Equals($crgIndexHead.Mode, $crgIndexStage.Mode, [System.StringComparison]::Ordinal) -or
                -not [string]::Equals($crgIndexHead.Oid, $crgIndexStage.Oid, [System.StringComparison]::Ordinal)) {
        $crgIndexDivergences.Add("$crgIndexPath - the stage-0 index entry differs from HEAD (staged content or mode change)") | Out-Null
      }
    } elseif ($crgIndexHead.State -ceq 'absent') {
      if ($crgIndexStage.State -cne 'absent') {
        $crgIndexDivergences.Add("$crgIndexPath - HEAD positively lacks the install path, but the index is $($crgIndexStage.State): $($crgIndexStage.Reason)") | Out-Null
      }
    } else {
      $crgIndexDivergences.Add("$crgIndexPath - HEAD is indeterminate: $($crgIndexHead.Reason)") | Out-Null
    }
  }
  if ($crgIndexDivergences.Count -gt 0) {
    Write-Host '[bootstrap] ERROR: the install found staged or indeterminate state at a path the install will write or later instruct Git to stage:'
    foreach ($crgIndexDivergence in $crgIndexDivergences) { Write-Host "  - $crgIndexDivergence" }
    Write-Host '[bootstrap] Refusing before any repository file is modified. Preserve and land/unstage the index state deliberately, restore a regular stage-0 entry where required, then re-run; the installer never treats worktree custody as a backup of staged bytes.'
    exit 1
  }
}

# Installed-project-values render preflight. Every byte that may become an
# installed destination is assembled and validated here, before routing
# custody, exclude/config writes, destination stages, or metadata publication.
# The fixed values source and raw package files stay held across the later
# mutation and metadata phases; pathname reopens never replace this evidence.
if (-not $DispatcherOnly) {
  try {
    Assert-CrgInstallValueOutputAuthorityEqual -Expected $crgRenderOutputAuthority -Actual (Get-CrgInstallValueOutputAuthority -RepoRoot $targetRepoAbs)
    try { $crgValuesSourceOwner = Open-CrgInstallValuesSourceHold -RepoRoot $targetRepoAbs }
    catch {
      throw "the mandatory fixed source '$targetRepoAbs\CROSS-REVIEW-VALUES.md' is missing or invalid ($($_.Exception.Message)). Create a v1 source, copy the intended project context, project hazards, and SCOPED authority set into its three blocks, establish $($crgRenderOutputAuthority.Family) authority, then rerun bootstrap; legacy installed prose is never inferred or imported"
    }
    $crgValuesSourceEvidence = Get-CrgInstallValuesSourceEvidence -RepoRoot $targetRepoAbs -Family $crgRenderOutputAuthority.Family -SourceOwner $crgValuesSourceOwner
    $crgParsedInstallValues = Read-CrgInstallValuesBytes -Bytes $crgValuesSourceOwner.Bytes

    if ($null -eq $crgSrcBuffers['scripts/codex/review-prompt-template.md'] -or
        $null -eq $crgSrcBuffers['docs/AGENTS.md.template'] -or
        $null -eq $crgSrcBuffers['docs/audit-protocol.md']) {
      throw 'the coherent package snapshot lacks a required render-bearing or reserved-scan surface'
    }
    Assert-CrgInstallValuesAuditSurface -Bytes ([byte[]]$crgSrcBuffers['docs/audit-protocol.md']) -Label 'package docs/audit-protocol.md'
    $crgRenderedRawBuffers['scripts/codex/review-prompt-template.md'] = [byte[]](Invoke-CrgInstallValueRender -Values $crgParsedInstallValues -TemplateBytes ([byte[]]$crgSrcBuffers['scripts/codex/review-prompt-template.md']) -Target 'review-prompt')
    $crgRenderedRawBuffers['docs/AGENTS.md.template'] = [byte[]](Invoke-CrgInstallValueRender -Values $crgParsedInstallValues -TemplateBytes ([byte[]]$crgSrcBuffers['docs/AGENTS.md.template']) -Target 'agents-template')

    # Package rules are authority even for LOCAL consumers and extracted
    # archives. Git object-format plumbing comes from the target repository;
    # only package-owned attribute bytes participate in this graph.
    Assert-CrgHeldPackageSnapshot -Owners $crgPackageAttributeOwners.ToArray()
    Assert-CrgInstallValuesAttributeGraph -RepoRoot $packageRoot -GitRepoRoot $targetRepoAbs -ScratchRoot $crgInstallValuesPackageAttributeScratch -RetainedAttributeBuffers $crgPackageAttributeBuffers
    if ($crgRenderOutputAuthority.Family -ceq 'TRACKED') {
      if ($selfInstall) {
        Assert-CrgInstallValuesAttributeGraph -RepoRoot $targetRepoAbs -ScratchRoot $crgInstallValuesTargetAttributeScratch -RetainedAttributeBuffers $crgPackageAttributeBuffers
      } else {
        Assert-CrgInstallValuesAttributeGraph -RepoRoot $targetRepoAbs -ScratchRoot $crgInstallValuesTargetAttributeScratch -AppendMissing
      }
    }

    if ($selfInstall) {
      foreach ($crgSelfRenderOutput in $script:CrgInstallValueOutputs) {
        [byte[]]$crgSelfRawTemplate = $crgSrcBuffers[$crgSelfRenderOutput.RelativePath]
        [byte[]]$crgSelfRenderedTemplate = $crgRenderedRawBuffers[$crgSelfRenderOutput.RelativePath]
        if (-not (Compare-CrgInstallValueBytes -Left $crgSelfRawTemplate -Right $crgSelfRenderedTemplate)) {
          $crgSelfRawLayout = Get-CrgRenderSlotLayout -Bytes $crgSelfRawTemplate -Target $crgSelfRenderOutput.Id
          $crgSelfMismatches = @()
          foreach ($crgSelfSlot in $crgSelfRawLayout.Required) {
            if (-not (Compare-CrgInstallValueBytes -Left $crgSelfRawLayout.Slots[$crgSelfSlot].Body -Right $crgParsedInstallValues.Blocks[$crgSelfSlot])) { $crgSelfMismatches += $crgSelfSlot }
          }
          throw "self-install is Check-only and stock slot bodies differ from CROSS-REVIEW-VALUES.md ($($crgSelfMismatches -join ', ')); update the source and stock templates through the ordinary reviewed package workflow"
        }
      }
    }

    foreach ($crgRenderFile in $fileList) {
      [byte[]]$crgRenderRaw = if ($crgRenderedRawBuffers.ContainsKey($crgRenderFile.Dst)) {
        $crgRenderedRawBuffers[$crgRenderFile.Dst]
      } else {
        $crgSrcBuffers[$crgRenderFile.Dst]
      }
      if ($null -eq $crgRenderRaw) { throw "no settled package bytes exist for '$($crgRenderFile.Dst)'" }
      [byte[]]$crgRenderInstalled = if ($selfInstall) {
        $crgRenderRaw
      } else {
        Get-CrgStampedFileBytes -SourceBytes $crgRenderRaw -Dst $crgRenderFile.Dst -Version $crgPackageVersion -SourceCommit $crgSourceCommit
      }
      if ($crgRenderedRawBuffers.ContainsKey($crgRenderFile.Dst)) {
        $crgRenderTarget = if ($crgRenderFile.Dst -ceq 'scripts/codex/review-prompt-template.md') { 'review-prompt' } else { 'agents-template' }
        $crgRenderFinalLayout = Get-CrgRenderSlotLayout -Bytes $crgRenderInstalled -Target $crgRenderTarget -FinalOutput
        foreach ($crgRenderFinalSlot in $crgRenderFinalLayout.Required) {
          if (-not (Compare-CrgInstallValueBytes -Left $crgRenderFinalLayout.Slots[$crgRenderFinalSlot].Body -Right $crgParsedInstallValues.Blocks[$crgRenderFinalSlot])) {
            throw "final installed '$($crgRenderFile.Dst)' slot '$crgRenderFinalSlot' differs from the retained values source"
          }
        }
      }
      $crgInstalledBuffers[$crgRenderFile.Dst] = $crgRenderInstalled
    }

    Assert-CrgHeldPackageSnapshot -Owners $crgPackageSourceOwners.ToArray()
    Assert-CrgHeldPackageSnapshot -Owners $crgPackageAttributeOwners.ToArray()
    Assert-CrgInstallValuesEpoch -RepoRoot $targetRepoAbs -OutputAuthority $crgRenderOutputAuthority -SourceEvidence $crgValuesSourceEvidence -SourceOwner $crgValuesSourceOwner
    Assert-CrgInstallValuesAttributeGraph -RepoRoot $packageRoot -GitRepoRoot $targetRepoAbs -ScratchRoot $crgInstallValuesPackageAttributeScratch -RetainedAttributeBuffers $crgPackageAttributeBuffers
    if ($crgRenderOutputAuthority.Family -ceq 'TRACKED') {
      $crgPreMutationTargetAttributeProof = if ($selfInstall) {
        Assert-CrgInstallValuesAttributeGraph -RepoRoot $targetRepoAbs -ScratchRoot $crgInstallValuesTargetAttributeScratch -RetainedAttributeBuffers $crgPackageAttributeBuffers -PassThruProof
      } else {
        Assert-CrgInstallValuesAttributeGraph -RepoRoot $targetRepoAbs -ScratchRoot $crgInstallValuesTargetAttributeScratch -AppendMissing -PassThruProof
      }
      Assert-CrgProspectiveLiveInstallValuesAttributeOverrides -RepoRoot $targetRepoAbs -ScratchRoot $crgProofScratchParent -AttributeBuffers $crgPreMutationTargetAttributeProof.AttributeBuffers -ObjectIdLength $crgPreMutationTargetAttributeProof.ObjectIdLength
    }
  } catch {
    Write-Error "bootstrap.ps1: installed-project-values preflight refused before target mutation ($($_.Exception.Message))."
    exit 1
  }
  if ($selfInstall) {
    # The package and target root are identical in this shape. The retained
    # package attribute snapshot has completed both package and identity-equal
    # target proofs; release only these read owners so the target .gitattributes
    # transaction can acquire write custody and independently revalidate the
    # same graph.
    foreach ($crgPackageAttributeOwner in $crgPackageAttributeOwners) {
      if ($null -ne $crgPackageAttributeOwner.Stream) {
        $crgPackageAttributeOwner.Stream.Dispose()
        $crgPackageAttributeOwner.Stream = $null
      }
    }
  }
}

# Self-host routing custody is the transaction's write-ahead phase. The complete
# buffered candidate and exact BaseHead/index state are already proved under both
# locks; the retained lease pins active record, directory record, and all custody
# sources until transition publication succeeds or the run exits.
if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal) -and -not $DispatcherOnly -and $selfInstall) {
  if ([string]::Equals($crgRoutingResume.State, 'none', [System.StringComparison]::Ordinal)) {
    $crgLegacyRoutingCustody = Publish-CrgLegacyRoutingDriverCustody -RepoRoot $targetRepoAbs -GitDir $crgGitDir -BaseHead $crgLegacyBaseHead -SourceBuffers $crgSrcBuffers
    if ($null -eq $crgLegacyRoutingCustody) {
      Write-Error 'bootstrap.ps1: exact routing-driver custody could not be activated before the first install mutation. No transition identity record was published.'
      exit 1
    }
    $crgRoutingLease = $crgLegacyRoutingCustody.Lease
    Write-Host "[bootstrap] preserved self-host routing drivers in base-bound verified custody -> $($crgLegacyRoutingCustody.Directory)"
  } elseif (([string]::Equals($crgRoutingResume.State, 'pre-transition', [System.StringComparison]::Ordinal) -or [string]::Equals($crgRoutingResume.State, 'pre-kernel', [System.StringComparison]::Ordinal))) {
    $crgLegacyRoutingCustody = $crgRoutingResume.Custody
  } else {
    Write-Error "bootstrap.ps1: legacy self-install reached the mutation boundary with inadmissible routing-custody state '$($crgRoutingResume.State)'."
    exit 1
  }
}

# Custody and backup artifact names must never enter a commit: a
# refresh leaves *.crg-refresh-* custody files beside gate files for
# hand reconciliation, and the documented staging commands add
# directories recursively (git add skips ignored files, so the exclude
# closes that path). The patterns go to the git COMMON dir's
# info/exclude BEFORE any WORKTREE custody file can be created this run. The
# base-bound routing custody above lives only in the per-worktree Git dir and is
# deliberately the earlier write-ahead phase. All are machine-local artifacts,
# so the tracked .gitignore stays untouched in every shape. Idempotent per
# pattern. -DispatcherOnly skips this: the
# dispatcher is rewritten in place under .git/hooks, where no staging
# reaches and no custody artifact is created (the crg-failed-* aside a
# sentinel preservation can leave there is equally out of staging's
# reach).
# Declared before the block that may set it so every later diagnostic reads a
# defined value on all paths (PowerShell without StrictMode yields $null for an
# unassigned variable, which here would read as "nothing changed" -- the exact
# false claim this tracking exists to prevent).
$crgExcludeMutated = $null
if (-not $DispatcherOnly) {
  $crgCustExcl = $null
  try { $crgCustExcl = ("$(Invoke-CrgGitUtf8 -GitArgs @('-C', $targetRepoAbs, 'rev-parse', '--git-path', 'info/exclude'))").Trim() }
  catch {
    Write-Error "bootstrap.ps1: the custody-artifact exclude file could not be located ($($_.Exception.Message)); without its patterns recovery artifacts could enter a recursive staging. No gate file has been written; fix the cause and re-run."
    exit 1
  }
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($crgCustExcl)) {
    if (-not [System.IO.Path]::IsPathRooted($crgCustExcl)) { $crgCustExcl = Join-Path $targetRepoAbs $crgCustExcl }
    $crgCustExclDir = Split-Path -Parent $crgCustExcl
    $null = Ensure-CrgRootedDirectory -Path $crgCustExclDir -Label 'custody-artifact exclude directory'
    $crgCustAdded = New-Object 'System.Collections.Generic.List[string]'
    $crgCustPatterns = @('*.crg-refresh-*', '*.crg-failed-*', '*.crg-occupant-*', '*.crg-refill-*', '*.crg-new-*', '*.crg-old-*')
    $crgCustLatin1 = [System.Text.Encoding]::GetEncoding(28591)
    $crgCustUtf8 = New-Object System.Text.UTF8Encoding($false)
    $crgCustTransform = {
      param([byte[]]$Bytes)
      $crgCustHave = $crgCustLatin1.GetString($Bytes)
      $crgCustOut = New-Object System.IO.MemoryStream
      try {
        if ($Bytes.Length -gt 0) { $crgCustOut.Write($Bytes, 0, $Bytes.Length) }
        # A non-LF-terminated final line would concatenate with the first
        # pattern. Delimit it before appending any missing complete lines.
        if ($Bytes.Length -gt 0 -and $Bytes[$Bytes.Length - 1] -ne 0x0A) { $crgCustOut.WriteByte(0x0A); $crgCustHave += "`n" }
        foreach ($crgCustPat in $crgCustPatterns) {
          if ($crgCustHave -cnotmatch ('(?m)^' + [regex]::Escape($crgCustPat) + '\r?$')) {
            $crgCustLine = $crgCustUtf8.GetBytes("$crgCustPat`n")
            $crgCustOut.Write($crgCustLine, 0, $crgCustLine.Length)
            $crgCustHave += "$crgCustPat`n"
            $crgCustAdded.Add($crgCustPat) | Out-Null
          }
        }
        return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$crgCustOut.ToArray() }
      } finally { $crgCustOut.Dispose() }
    }.GetNewClosure()
    try { $crgCustUpdate = Update-CrgRootedFileBytes -Path $crgCustExcl -Transform $crgCustTransform -Label 'custody-artifact exclude file' }
    catch {
      Write-Error "bootstrap.ps1: could not safely update '$crgCustExcl' through a retained no-follow single-link handle: $($_.Exception.Message)"
      exit 1
    }
    $crgCustVerify = $crgCustLatin1.GetString($crgCustUpdate.Bytes)
    foreach ($crgCustPat in $crgCustPatterns) {
      if ($crgCustVerify -cnotmatch ('(?m)^' + [regex]::Escape($crgCustPat) + '\r?$')) {
        Write-Error "bootstrap.ps1: custody-artifact exclude pattern '$crgCustPat' does not verify as a complete line in '$crgCustExcl' after the append; fix the exclude file and re-run (a broken pattern would let recovery artifacts enter a recursive staging)."
        exit 1
      }
    }
    if ($crgCustAdded.Count -gt 0) {
      Write-Host "[bootstrap] excluded custody artifact names ($($crgCustAdded -join ', ')) via '$crgCustExcl'"
      # Recorded so later diagnostics can say what HAS changed. Every abort
      # after this point once claimed "nothing has been modified", which stopped
      # being true here: the exclude file is a repository mutation, and a
      # message that conceals it sends the operator looking in the wrong place.
      $crgExcludeMutated = $crgCustExcl
    }
  } else {
    Write-Error "bootstrap.ps1: the custody-artifact exclude file could not be located (git rev-parse --git-path info/exclude exited $LASTEXITCODE or printed nothing); without its patterns recovery artifacts could enter a recursive staging. No gate file has been written; fix the cause and re-run."
    exit 1
  }
}

# File copy (skipped entirely on a self-install -- see $selfInstall above: the
# gate files are already at their destinations, and Copy-Item onto itself aborts).
# The block body below is intentionally left at its original indentation rather
# than re-indented under this guard, to keep the self-install diff minimal and
# reviewable; PowerShell is whitespace-insensitive so the guard scopes it either way.
if ($DispatcherOnly) {
  # -DispatcherOnly's contract: NO tracked file is touched. No presence
  # validation either -- the switch must work on a clone whose tracked gate is
  # broken (that is the restoration scenario it exists for); a repo without the
  # gate files simply fail-closes at commit time via the dispatcher.
  Write-Host "[bootstrap] -DispatcherOnly: skipping the file-copy step (no tracked file is touched)."
  Write-Host ""
} elseif ($selfInstall) {
  # NO PROVENANCE STAMP HERE, deliberately. Every other install writes a header
  # naming the version and source commit into each installed file, but on a
  # self-install the "installed" files ARE this package's own tracked sources:
  # stamping them would rewrite the repository's checked-in content, dirty the
  # tree, and make the package's own bytes differ from the commit it names --
  # corrupting the artifact the stamp exists to describe. The exclusion is a
  # category, not a shortfall, and `docs/migration-plan-2026-08.md` states it
  # beside the requirement. The install record and manifest still publish; the
  # manifest hashes the files as they are, which is what every verifier reads.
  #
  # Even on a self-install the gate files must actually BE present: a partial or
  # corrupt checkout (a missing script, or a directory where a script should be)
  # would otherwise skip straight to the .gitignore + dispatcher setup and report
  # success, leaving a broken self-gated package that fails LATER at commit time.
  # Validate every $fileList destination exists as a LEAF file before skipping the
  # copy. (Source == destination here by construction -- $selfInstall means the
  # package root IS the target repo top-level and every Src maps to the identical
  # Dst -- so a present destination IS a present source.)
  $selfMissing = @()
  foreach ($f in $fileList) {
    $p = Join-Path $targetRepoAbs $f.Dst
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { $selfMissing += $f.Dst }
  }
  if ($selfMissing.Count -gt 0) {
    Write-Host "[bootstrap] ERROR: self-install expected these gate files already in place, but they are MISSING or not leaf files:"
    foreach ($m in $selfMissing) { Write-Host "  - $m" }
    Write-Host "[bootstrap] A partial/corrupt checkout cannot self-gate. Restore the missing files (or run a normal install into a fresh target) and re-run."
    exit 1
  }
  foreach ($f in $fileList) {
    if ($null -eq $crgSrcBuffers[$f.Dst] -or $crgSrcBuffers[$f.Dst] -isnot [byte[]]) {
      Write-Error "bootstrap.ps1: self-install lost the exact buffered source for '$($f.Dst)' before the locked transaction. No transition identity can be derived safely."
      exit 1
    }
    $crgInstalledBuffers[$f.Dst] = [byte[]]$crgSrcBuffers[$f.Dst]
    # The self-install manifest belongs to the already-validated package
    # snapshot, not to a later read of mutable source paths. Publication still
    # verifies live destinations against these settled digests and refuses if a
    # source edit lands before the manifest is armed.
    $crgInstalledHashes[$f.Dst] = Get-CrgSha256HexOfBytes -Bytes $crgSrcBuffers[$f.Dst]
    $crgSelfOwnerMatches = @($crgPackageSourceOwners | Where-Object { "$($_.Dst)" -ceq $f.Dst -and $null -ne $_.Stream })
    if ($crgSelfOwnerMatches.Count -ne 1 -or [CrgBootstrap.NativeV3]::GetLinkCount($crgSelfOwnerMatches[0].Stream.SafeFileHandle) -ne 1) {
      Write-Error "bootstrap.ps1: self-install could not transfer one exact retained package owner for '$($f.Dst)' into manifest custody. No manifest identity can be published safely."
      exit 1
    }
    $crgSelfOwnerHash = Get-CrgSha256HexOfHeldStream -Stream $crgSelfOwnerMatches[0].Stream
    if ($crgSelfOwnerHash -cne $crgInstalledHashes[$f.Dst]) {
      Write-Error "bootstrap.ps1: self-install retained payload '$($f.Dst)' no longer matches the coherent package snapshot. No manifest identity can be published safely."
      exit 1
    }
    $crgInstalledPayloadOwners.Add([pscustomobject]@{ Dst = $f.Dst; Fs = $crgSelfOwnerMatches[0].Stream; Hash = $crgSelfOwnerHash }) | Out-Null
  }
  Write-Host "[bootstrap] self-install: all $($fileList.Count) gate files present; skipping the file-copy step."
  Write-Host ""
} else {

# Pre-check: detect destination collisions.
#
# Three classes of pre-existing state at each destination:
#   (a) leaf file collision: existing file at the path. Refuse without
#       -Force (consumer might be upgrading and want -Force).
#   (b) directory collision: a directory exists where a file should
#       go. Refuse UNCONDITIONALLY -- Copy-Item with a directory
#       destination silently copies the source INTO the directory
#       (yielding $dst/$src.basename, not $dst), so the expected file
#       would not be installed even though Copy-Item returns success.
#       Bootstrap would then print "Install complete" against a
#       broken install. -Force does not (and must not) make this
#       safe; the directory must be removed deliberately first.
#   (c) clean (no collision): proceed.
$fileCollisions = @()
$dirCollisions = @()
foreach ($f in $fileList) {
  $dstAbs = Join-Path $targetRepoAbs $f.Dst
  if (Test-Path -LiteralPath $dstAbs -PathType Container) {
    $dirCollisions += $f.Dst
  } elseif (Test-Path -LiteralPath $dstAbs -PathType Leaf) {
    $fileCollisions += $f.Dst
  }
}
if ($dirCollisions.Count -gt 0) {
  Write-Host "[bootstrap] ERROR: the following destinations exist as DIRECTORIES, not files:"
  foreach ($c in $dirCollisions) { Write-Host "  - $c" }
  Write-Host ""
  Write-Host "[bootstrap] A directory at one of these paths would cause Copy-Item to install"
  Write-Host "[bootstrap] the source INTO the directory (yielding `<dir>\<filename>`) rather"
  Write-Host "[bootstrap] than as the expected file -- a silent install failure. Inspect each"
  Write-Host "[bootstrap] directory and remove it deliberately, then re-run. -Force does not"
  Write-Host "[bootstrap] (and must not) cover this case."
  exit 1
}
if ($fileCollisions.Count -gt 0 -and -not $Force) {
  Write-Host "[bootstrap] ERROR: the following files already exist in the target repo:"
  foreach ($c in $fileCollisions) { Write-Host "  - $c" }
  Write-Host ""
  Write-Host "[bootstrap] Pass -Force to overwrite (e.g., when upgrading to a new package version)."
  Write-Host "[bootstrap] Or move/delete the existing files and re-run."
  exit 1
}

# Armed only by the block below, and only when a baseline was proven readable.
# Declared here so the copy loop reads a defined value on every path: PowerShell
# without StrictMode yields $null for an unassigned variable, which would read
# as "no upgrade detected" and silently disable the refusal on exactly the runs
# that reach the loop by another route.
$crgUpgradeGuardActive = $false

# ---- UPGRADE: what is already installed, and is it safe to overwrite? ----
# Reached only with -Force over an existing install, which is the upgrade shape.
# Two questions, in order, because the second can refuse the run:
#   (1) WHICH version is being replaced -- reported, never enforced. A version
#       comparison decides nothing here: downgrades and re-installs of the same
#       version are both legitimate operator acts, and refusing them would make
#       the version stamp a policy rather than a record.
#   (2) Has any installed file been LOCALLY MODIFIED since it was installed?
#       That question has a real answer because the install manifest records
#       each file's hash at install time, and it is the one that must refuse:
#       overwriting a deliberate local edit destroys work no backup names,
#       which is what makes an unguarded upgrade a data-loss mechanism.
# AN UNRESOLVED GIT DIR REFUSES BEFORE ANY MUTATION. Both the manifest and the
# version record live under it, so without it neither question below can be
# answered -- and skipping the block entirely (an earlier shape) left the guard
# disarmed while the copy loop went on to overwrite locally modified files. The
# null check further down runs AFTER that loop, which is too late to protect
# anything. This is the same invariant the guard itself encodes: a state that
# cannot prove the run is safe must stop it, not proceed quietly.
if ($fileCollisions.Count -gt 0 -and $Force -and $null -eq $crgGitDir) {
  Write-Error "bootstrap.ps1: '$targetRepoAbs' has gate files already installed, but its git directory could not be resolved, so neither the install manifest nor the version record can be read. Refusing to overwrite files whose local edits cannot be detected. No gate file has been written.$(if ($null -ne $crgExcludeMutated) { " Custody-artifact exclude patterns were already appended to '$crgExcludeMutated'; that append is idempotent and safe to leave." }) Check that this is a healthy git repository (git -C '<repo>' rev-parse --absolute-git-dir), then re-run."
  exit 1
}
if ($fileCollisions.Count -gt 0 -and $Force -and $null -ne $crgGitDir) {
  $crgUpManifestPath = Join-Path $crgGitDir 'crg-install-manifest'
  $crgUpVersionPath = Join-Path $crgGitDir 'crg-install-version'
  # POSITIVE EVIDENCE OF AN EXISTING INSTALL, classified atomically before the
  # copy loop mutates any destination. A fresh target that happens to contain
  # one unrelated file at a gate path is not an upgrade. Evidence is either:
  #
  # * occupancy at an installer metadata path (including a damaged non-file or
  #   unreadable occupant -- absence must be positive, never inferred from a
  #   failed read),
  # * the complete current package inventory, or
  # * the complete, frozen v1.7.0 inventory from commit 3a3efbf.
  #
  # The last case is the released upgrade population this guard exists for:
  # v1.7 wrote no manifest/version record and omits the current-only paths.
  # Deriving legacy shape from today's full inventory therefore misses every
  # real v1.7 install. Partial inventories remain ordinary collision handling;
  # treating one path as an install would make unrelated files un-overwritable.
  $crgLegacyPaths = @(Get-CrgLegacyV170Paths)
  $crgLegacyFileList = @($crgLegacyPaths | ForEach-Object { @{ Dst = $_ } })
  $crgCurrentShape = Test-CrgCompleteLeafInventory -RepoRoot $targetRepoAbs -FileList $fileList
  $crgLegacyShape = Test-CrgCompleteLeafInventory -RepoRoot $targetRepoAbs -FileList $crgLegacyFileList
  $crgUpManifestKind = $crgLockedManifestKind
  $crgUpVersionKind = $crgLockedVersionKind
  $crgMetadataEvidence = ($crgUpManifestKind -cne 'empty') -or ($crgUpVersionKind -cne 'empty')
  $crgHasInstallEvidence = $crgMetadataEvidence -or $crgCurrentShape -or $crgLegacyShape
  # A record FILE that exists but does not parse is a different state from no
  # record at all, and the two must not collapse. Absence is the honest
  # pre-versioning reading; a damaged record is evidence that a version WAS
  # recorded and can no longer be read, so whether this run is an upgrade is
  # unanswerable -- and unanswerable resolves toward the guard, never away from
  # it.
  $crgUpRecordDamaged = ($null -eq $crgUpPrev) -and ($crgUpVersionKind -cne 'empty')
  if ($null -ne $crgUpPrev) {
    $crgUpWhat = if ([string]::Equals($crgUpPrev.Version, $crgPackageVersion, [System.StringComparison]::Ordinal)) { 'RE-INSTALL of the same version' } else { "UPGRADE $($crgUpPrev.Version) -> $crgPackageVersion" }
    Write-Host "[bootstrap] $crgUpWhat (installed $($crgUpPrev.Installed), source $($crgUpPrev.SourceCommit))"
  } elseif ($crgUpRecordDamaged) {
    Write-Host "[bootstrap] the install version record at '$crgUpVersionPath' is not one held no-follow ordinary single-link strict record$(if ($null -ne $crgUpVersionFailure) { " ($crgUpVersionFailure)" }); treating this as an UPGRADE, so a locally edited gate file will be refused rather than overwritten."
  } elseif ($crgHasInstallEvidence) {
    Write-Host "[bootstrap] installing $crgPackageVersion over an existing install whose version is not recorded (installed before version records)."
  } else {
    Write-Host "[bootstrap] no complete current/v1.7 install inventory or metadata occupant was found; treating the collisions as ordinary -Force replacements."
  }
  # SCOPED TO AN UPGRADE, and to nothing else. A -Force refresh at the same
  # version -- or over an install predating version records -- ALREADY has a
  # preservation contract: every
  # replaced file is renamed into custody, copied to the backup area, and
  # reported. That story is sufficient there because the operator still HAS the
  # package whose bytes were replaced, so an edit can be recovered by diffing
  # against it. An upgrade is different in kind: it replaces files with a
  # DIFFERENT version's bytes, stranding an edit against a baseline the tree no
  # longer carries.
  #
  # DO NOT re-key this on "the package bytes differ from the manifest entry"
  # (tried 2026-08-31, reverted). It reads as a tighter, version-independent
  # test and is not one: hook content is GENERATED per install shape, so
  # `scripts/git-hooks/pre-commit` legitimately hashes differently between two
  # runs of the SAME package when the ignore list changes the shape. That
  # variant refused a same-version re-install with no edit anywhere and broke
  # the MIXED install shape. Package bytes are not a version signal.
  #
  # AN ABSENT RECORD ARMS THE GUARD TOO. An earlier draft treated absence as
  # the permissive pre-versioning status quo; that was backwards. Every install
  # made before this change has NO record, so absence is exactly the state a
  # v1.7-to-v2.0 upgrade encounters -- the one upgrade this refusal exists for.
  # Reading it as "no upgrade detected" disarmed the mechanism precisely where
  # it was needed, and a publication failure (which removes the record) put a
  # later upgrade into the same disarmed state.
  #
  # The reason absence was kept permissive -- that refusing would block the
  # recovery re-run a damaged install needs -- no longer holds: the loop admits
  # any destination whose bytes already equal what this run would write, so a
  # re-run after a partial upgrade proceeds through the files it already
  # replaced instead of refusing them.
  #
  # The per-file decision does NOT happen here. A hash taken now is stale by the
  # time the copy loop replaces the file, and a save landing in that gap would
  # become the preserved original AND be overwritten. The loop decides from each
  # file's CUSTODY bytes -- after the atomic rename that freezes them, before any
  # replacement -- which is the only point where the bytes being replaced and the
  # decision to replace them are the same bytes. There, a destination that does
  # not match its manifest entry carries a local edit; an unreadable manifest
  # makes every destination unmatched, and cannot-tell resolves toward refusal
  # because the alternative destroys work nothing names.
  # ARMED UNLESS THE RECORD POSITIVELY PROVES A SAME-VERSION RE-INSTALL. The
  # question is not "does a recorded version differ" but "can this run show it
  # is NOT an upgrade" -- absent, unreadable, and non-file records all answer
  # "cannot show", and every one of them describes a v1.7 tree, which is
  # precisely the population the v1.7-to-v2.0 upgrade will meet.
  $crgUpgradeGuardActive = $crgHasInstallEvidence -and -not ($null -ne $crgUpPrev -and [string]::Equals($crgUpPrev.Version, $crgPackageVersion, [System.StringComparison]::Ordinal))
}

# Copy each file, creating parent dirs as needed.
$copied = 0
$overwritten = 0
# Destinations already replaced this run. A mid-loop abort must be able to NAME
# them: a reader told only that the run aborted cannot tell which files are new
# and which are original, and would have to diff the tree to find out.
$crgCopiedSoFar = New-Object 'System.Collections.Generic.List[string]'
foreach ($f in $fileList) {
  $dstAbs = Join-Path $targetRepoAbs $f.Dst

  $dstDir = Split-Path -Parent $dstAbs
  $null = Ensure-CrgRootedDirectory -Path $dstDir -Label "payload parent for '$($f.Dst)'"
  # Defensive: even though the pre-check above rejected directory
  # collisions, a race or symlink-resolved-to-directory path could in
  # principle slip through between the check and this copy. Re-assert
  # before copying so the silent "copy into directory" failure mode
  # cannot ship under any code path.
  if (Test-Path -LiteralPath $dstAbs -PathType Container) {
    Write-Error "bootstrap.ps1: destination '$dstAbs' became a directory between pre-check and copy; aborting to avoid silent copy-into-directory failure."
    exit 1
  }

  # The INSTALLED-CONTENT digest is computed BEFORE any custody move: it
  # reads only the package file, and computing it later would let a
  # hash or stamping failure throw (EAP=Stop) after the destination was
  # moved to custody, terminating outside the restoration path with the
  # destination absent and no recovery locations named.
  #
  # It digests the bytes this run INTENDS TO WRITE -- package source plus
  # its provenance header -- held in memory and never re-read from the
  # destination. That preserves the property the manifest depends on: the
  # recorded baseline is what the installer produced, so a same-length
  # corruption or a concurrent edit at the destination cannot be blessed
  # as the trusted baseline by hashing whatever happens to be there.
  try {
    # The full installed byte array was rendered, stamped, reparsed, and hashed
    # during the non-mutating preflight. Destination mutation consumes only
    # that settled buffer; no package source, values source, or template is
    # reopened or transformed after mutation begins.
    [byte[]]$crgStampedBytes = $crgInstalledBuffers[$f.Dst]
    if ($null -eq $crgStampedBytes) { throw "no preflighted installed bytes were captured for '$($f.Dst)'" }
  } catch {
    # NOT "nothing has been modified": this runs inside the copy loop, so
    # destination directories may exist and earlier files may already be
    # written. The destination for THIS file is untouched, which is the only
    # claim the code can support here.
    Write-Error "bootstrap.ps1: could not build the installed content for '$($f.Dst)' ($($_.Exception.Message)). That destination is untouched.$(if ($crgCopiedSoFar.Count -gt 0) { ' Files already written this run: ' + ($crgCopiedSoFar -join '; ') + '.' })"
    exit 1
  }
  # The digest of the bytes this run WRITES: what the post-write verification
  # proves, and what the manifest records.
  #
  # RECORDING THE PACKAGE-SOURCE DIGEST INSTEAD WAS TRIED (2026-08-31) and
  # reverted. It preserved the v1 wording, but every consumer of the manifest --
  # the dispatcher's awk verifier, the pre-commit hook, and all three wrappers --
  # answers "is the file on disk the one that was installed" by hashing the file
  # on disk. A source digest makes all of them wrong at once, and the repair
  # would be frame-stripping logic duplicated into POSIX sh/awk and three
  # PowerShell copies. The format version moves instead; see the v2 header.
  $crgInstallHash = Get-CrgSha256HexOfBytes -Bytes $crgStampedBytes
  $existedBefore = Test-Path -LiteralPath $dstAbs -PathType Leaf
  if ($existedBefore) {
    # Backup-by-custody-RENAME (docs/local-install-v1.md section 4):
    # every pre-existing destination is first renamed to a SIBLING
    # custody name (same volume, so atomic), a hash-verified copy of the
    # custody file then lands in the backup area, and custody is
    # RETAINED through replacement verification and then archived
    # best-effort (never deleted; failures reported) -- a copy-based backup of
    # the live path would race a concurrent editor save between
    # verification and overwrite, losing the save in both places. After
    # the rename the destination must be GONE; a file reappearing there
    # before the replacement lands fails the create-new copy below
    # loudly instead of silently clobbering it. Destinations that no
    # longer match their manifest entry are REPORTED as backups (the
    # local-state recovery case); unmodified ones ride along unlisted.
    # The retained owner denies every pre-existing and future writer,
    # so later digest movement is an integrity failure, not an admitted
    # late-writer branch.
    if ($null -eq $crgCommonDir) {
      Write-Error "bootstrap.ps1: cannot resolve the git common dir of '$targetRepoAbs' to back up the existing '$($f.Dst)' before replacing it; refusing to overwrite without a backup."
      exit 1
    }
    $crgBakPath = Join-Path (Join-Path (Join-Path $crgCommonDir 'crg-backups') $crgBackupStamp) $f.Dst
    if (Test-Path -LiteralPath $crgBakPath) {
      Write-Error "bootstrap.ps1: backup path '$crgBakPath' already exists; refusing to overwrite an existing recovery copy. Re-run to take a fresh backup area."
      exit 1
    }
    $crgBakDir = Split-Path -Parent $crgBakPath
    $null = Ensure-CrgRootedDirectory -Path $crgBakDir -Label "backup parent for '$($f.Dst)'"
    # Atomic custody stays on the SOURCE filesystem: a linked worktree
    # can put the git common dir (and so the backup area) on another
    # volume, where a direct move degrades to copy+delete and reopens
    # the lost-save race. The rename to a sibling name is same-volume by
    # construction; the backup area then receives a hash-verified COPY,
    # and custody is retained through replacement verification, then
    # archived -- on any failure the custody file IS the preserved
    # original and the abort names it.
    $crgCustody = "$dstAbs.crg-refresh-$crgBackupStamp"
    if (Test-Path -LiteralPath $crgCustody) {
      Write-Error "bootstrap.ps1: custody path '$crgCustody' already exists; refusing to disturb it. Inspect and remove it by hand, then re-run."
      exit 1
    }
    # Bind classification to the exact existing object before the first
    # mutation. DELETE access plus read-only sharing refuses any pre-existing
    # writer whose handle could otherwise modify the renamed custody file after
    # the upgrade decision. The same handle performs the no-replace rename and
    # remains live through backup, replacement, and recovery classification.
    $crgCustodyOwner = $null
    $crgCustodyH = $null
    $crgCustodyFs = $null
    $crgTransferredSourceOwner = $null
    $crgCustodyOpenErr = 0
    try {
      if ($selfInstall) {
        $crgTransferredMatches = @($crgPackageSourceOwners | Where-Object { "$($_.Dst)" -ceq $f.Dst -and $null -ne $_.Stream })
        if ($crgTransferredMatches.Count -ne 1) { throw 'the exact held self-install source owner was not uniquely available for destination custody' }
        $crgTransferredSourceOwner = $crgTransferredMatches[0]
        $crgCustodyFs = $crgTransferredSourceOwner.Stream
      } else {
        $crgCustodyH = [CrgBootstrap.NativeV4]::OpenOwnedExistingFileNoFollow($dstAbs, [ref]$crgCustodyOpenErr)
        if ($null -eq $crgCustodyH -or $crgCustodyH.IsInvalid) { throw "no-follow owner open refused (Win32 error $crgCustodyOpenErr)" }
        $crgCustodyAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($crgCustodyH)
        $crgCustodyLinks = [CrgBootstrap.NativeV3]::GetLinkCount($crgCustodyH)
        if ($crgCustodyAttrs -lt 0 -or ($crgCustodyAttrs -band 0x410) -ne 0 -or $crgCustodyLinks -ne 1) { throw "the destination is not one ordinary single-link file" }
        $crgCustodyFs = New-Object System.IO.FileStream($crgCustodyH, [System.IO.FileAccess]::Read)
        $crgCustodyH = $null
      }
      $crgCustodyAttrs = [CrgBootstrap.NativeV3]::GetHandleAttributes($crgCustodyFs.SafeFileHandle)
      $crgCustodyLinks = [CrgBootstrap.NativeV3]::GetLinkCount($crgCustodyFs.SafeFileHandle)
      if ($crgCustodyAttrs -lt 0 -or ($crgCustodyAttrs -band 0x410) -ne 0 -or $crgCustodyLinks -ne 1) { throw "the retained destination owner is not one ordinary single-link file" }
      $crgCustodyRenameErr = 0
      if (-not ([CrgBootstrap.NativeV4]::RenameHeldNoReplace($crgCustodyFs.SafeFileHandle, $dstAbs, $crgCustody, [ref]$crgCustodyRenameErr))) {
        throw "same-handle no-replace custody rename refused (Win32 error $crgCustodyRenameErr)"
      }
      $crgCustodyOwner = [pscustomobject]@{ Stream = $crgCustodyFs; Path = $crgCustody; OriginalPath = $dstAbs; Label = $f.Dst }
      $crgInstallCustodyOwners.Add($crgCustodyOwner) | Out-Null
      if ($null -ne $crgTransferredSourceOwner) { $crgTransferredSourceOwner.Stream = $null }
      $crgCustodyFs = $null
    } catch {
      Write-Error "bootstrap.ps1: taking custody of '$($f.Dst)' failed ($($_.Exception.Message)); aborting before any replacement."
      exit 1
    } finally {
      if ($null -ne $crgCustodyFs) { $crgCustodyFs.Dispose() }
      elseif ($null -ne $crgCustodyH -and -not $crgCustodyH.IsInvalid) { $crgCustodyH.Dispose() }
    }
    if ((Test-Path -LiteralPath $dstAbs) -or -not (Test-Path -LiteralPath $crgCustody -PathType Leaf)) {
      # Probed at message time, never inferred from the branch
      # condition: both arms can hold at once, and the abort must name
      # where the surviving bytes actually are.
      $crgCtDest = if (Test-Path -LiteralPath $dstAbs -PathType Leaf) { "a file OCCUPIES the destination '$dstAbs' (unverified - do not trust it)" } elseif (Test-Path -LiteralPath $dstAbs) { "a NON-FILE occupies the destination '$dstAbs'" } else { "the destination '$dstAbs' is empty" }
      $crgCtCust = if (Test-Path -LiteralPath $crgCustody -PathType Leaf) { "the ORIGINAL is preserved at '$crgCustody' - recover it from there" } else { "NO custody file exists at '$crgCustody'" }
      Write-Error "bootstrap.ps1: taking custody of '$($f.Dst)' did not verify; aborting before any replacement. $crgCtDest; $crgCtCust."
      exit 1
    }
    $crgCustodyHash = Get-CrgSha256HexOfHeldStream -Stream $crgCustodyOwner.Stream
    if ($null -eq $crgCustodyHash) {
      $crgBkWhere = Restore-CrgCustodySimple -CustodyPath $crgCustody -DestPath $dstAbs -BaselineHash $crgCustodyHash -CustodyOwner $crgCustodyOwner
      Write-Error "bootstrap.ps1: could not hash the custody file for '$($f.Dst)' (vanished, unreadable, or locked); aborting. The ORIGINAL is $crgBkWhere."
      exit 1
    }
    # The known/modified classification reads the CUSTODY file, after the
    # rename: hashing the live destination earlier would let an editor save in
    # the gap become the preserved bytes while a stale "known" verdict
    # suppresses the report.
    #
    # Trust is per component and ordered. A regular blob in the exact captured
    # HEAD commit is authoritative for a tracked install. Custody bytes are
    # converted only through that commit's root/ancestor attributes in a private
    # Git context; mutable attributes and clean-filter config are excluded, and
    # any captured custom transform refuses. Only POSITIVE HEAD absence permits
    # the whole-file SHA-256 manifest
    # fallback used by local/untracked installs. A failed HEAD probe or a
    # non-regular HEAD entry is indeterminate, never another spelling of
    # absence. A v1 manifest still hashes its installed unstamped bytes, so the
    # fallback needs no version special case.
    $crgHeadBaseline = Get-CrgHeadPathBaseline -Repo $targetRepoAbs -Path $f.Dst
    $crgKnown = $false
    $crgBaselineIndeterminate = $false
    $crgBaselineLabel = ''
    if ($crgHeadBaseline.State -ceq 'present') {
      try { [byte[]]$crgCustodyBytes = Read-CrgHeldStreamBytes -Stream $crgCustodyOwner.Stream -MaxLength 16777216 -Label "custody bytes for '$($f.Dst)'" }
      catch { $crgCustodyBytes = $null }
      $crgCustodyOid = if ($null -ne $crgCustodyBytes) {
        Get-CrgControlledBasePathObjectId -RepoRoot $targetRepoAbs -ProofScratchRoot $crgProofScratchParent -BaseCommit $crgHeadBaseline.Head -RepoPath $f.Dst -HeldBytes $crgCustodyBytes
      } else { $null }
      if ($null -eq $crgCustodyOid) {
        $crgBaselineIndeterminate = $true
        $crgBaselineLabel = 'the captured-HEAD-bound hash of the held custody bytes failed'
      } else {
        $crgKnown = [string]::Equals($crgHeadBaseline.Oid, $crgCustodyOid, [System.StringComparison]::Ordinal)
        $crgBaselineLabel = 'trusted HEAD'
      }
    } elseif ($crgHeadBaseline.State -ceq 'absent') {
      $crgKnown = ($null -ne $crgManifest -and $crgManifest.ContainsKey($f.Dst) -and [string]::Equals($crgManifest[$f.Dst], $crgCustodyHash, [System.StringComparison]::Ordinal))
      $crgBaselineLabel = 'the install manifest (HEAD positively lacks this path)'
    } else {
      $crgBaselineIndeterminate = $true
      $crgBaselineLabel = "the HEAD baseline probe was indeterminate ($($crgHeadBaseline.Reason))"
    }
    # DRIFT REFUSAL (P9). One rule, applied only where loss is possible:
    #
    #   nothing is at risk unless the BYTES ARE CHANGING. When the package
    #   carries exactly what is already installed, the replacement is a no-op on
    #   content -- a refresh, a repair re-run after a partial install, a
    #   re-install over an unverifiable tree. This repository already contracts
    #   and pins that path: replace, preserving the prior bytes in custody and
    #   reporting them. Refusing there would block recovery to protect nothing.
    #
    #   when they ARE changing, the replacement is only safe if the bytes being
    #   destroyed are the ones this repo was GIVEN. `$crgKnown` says exactly
    #   that, decided from the CUSTODY bytes -- a pre-pass hash cannot, because
    #   a save landing between the hash and the rename would become the
    #   preserved original AND be overwritten. Anything else (a local edit, or a
    #   tree with no readable baseline to compare against) is unknown, and
    #   unknown resolves toward refusal: the alternative strands an edit against
    #   a baseline that will no longer exist anywhere, so recovering it later
    #   means diffing against a package that is gone.
    #
    # -Force says "replace the gate files", not "my edits are disposable", and a
    # timestamped backup records no intent -- an edit found in one later cannot
    # be told from an accident. The custody file is restored BEFORE the abort,
    # so the refusal leaves the tree exactly as it was found.
    #
    # Keyed on the manifest and the package bytes, never on the version record:
    # a record can be absent (every install predating records) or lost to a
    # failed publish, and keying here would let the protection be bypassed by
    # the very failure it exists to survive.
    # ALREADY-INSTALLED DESTINATIONS ARE ADMITTED. A refusal partway through
    # leaves earlier files already carrying this package's content while the
    # manifest and version record still describe the previous install, so on the
    # re-run every one of them looks unknown to the manifest. Refusing there
    # would make the abort unrecoverable by the very re-run this message asks
    # for. Nothing is at risk when the bytes on disk are already the bytes this
    # run would write -- the replacement is a content no-op.
    $crgAlreadyInstalled = [string]::Equals($crgCustodyHash, $crgInstallHash, [System.StringComparison]::Ordinal)
    if ($crgUpgradeGuardActive -and -not $crgKnown -and -not $crgAlreadyInstalled) {
      $crgDrWhere = Restore-CrgCustodySimple -CustodyPath $crgCustody -DestPath $dstAbs -BaselineHash $crgCustodyHash -CustodyOwner $crgCustodyOwner
      if ($crgBaselineIndeterminate) {
        Write-Host "[bootstrap] ERROR: whether '$($f.Dst)' matches trusted HEAD cannot be determined: $crgBaselineLabel."
        Write-Host "[bootstrap] Refusing to overwrite frozen custody bytes; the file is $crgDrWhere. Diagnose the repository/attributes/filter command, then re-run. A manifest is not a fallback for an unreadable or non-regular HEAD path."
        exit 1
      }
      # NO BASELINE AT ALL is a different situation from a file that diverges
      # from one, and it needs different guidance. An install predating
      # manifests has nothing recorded to compare against, so every file reads
      # as unknown and the discard/keep advice below is unusable -- there is
      # nothing to discard TO. Sealing is the sanctioned migration: it records
      # the bytes now in place as the baseline, after which this same upgrade
      # runs normally. Without naming it, the refusal would repeat forever.
      if ($crgHeadBaseline.State -ceq 'absent' -and $null -eq $crgManifest) {
        Write-Host "[bootstrap] ERROR: '$targetRepoAbs' carries an installed gate but no readable install manifest, so"
        Write-Host "[bootstrap] whether '$($f.Dst)' has been edited cannot be determined. Refusing to overwrite it."
        Write-Host "[bootstrap] The file is $crgDrWhere."
        Write-Host ""
        Write-Host "[bootstrap] This is the shape of an install made before manifests existed. Record the bytes now in"
        Write-Host "[bootstrap] place as a transient replacement baseline, then immediately run the full upgrade and renderer check:"
        Write-Host "[bootstrap]   powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetRepo `"$targetRepoAbs`" -SealManifest"
        Write-Host "[bootstrap]   (an OPERATOR act; needs CROSS_REVIEW_ALLOW_SEAL=1)"
        Write-Host "[bootstrap]   Remove-Item Env:CROSS_REVIEW_ALLOW_SEAL -ErrorAction SilentlyContinue"
        Write-Host "[bootstrap]   powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetRepo `"$targetRepoAbs`" -Force"
        Write-Host "[bootstrap]   powershell -NoProfile -ExecutionPolicy Bypass -File `"$targetRepoAbs\scripts\render-project-values.ps1`" -TargetRepo `"$targetRepoAbs`" -Check"
        Write-Host "[bootstrap] Seal only after confirming the installed files are the ones you intend to keep -- the"
        Write-Host "[bootstrap] seal blesses whatever is there, including any edit it cannot distinguish from the"
        Write-Host "[bootstrap] original. The upgrade then replaces them and preserves each original in backup custody."
        if ($crgCopiedSoFar.Count -gt 0) {
          Write-Host ""
          Write-Host "[bootstrap] NOTE: these gate files were already written before this refusal:"
          foreach ($crgDrDone in $crgCopiedSoFar) { Write-Host "  - $crgDrDone" }
        }
        exit 1
      }
      Write-Host "[bootstrap] ERROR: '$($f.Dst)' differs from $crgBaselineLabel, so it"
      Write-Host "[bootstrap] carries a local edit. Refusing to overwrite it. The file is $crgDrWhere."
      Write-Host ""
      Write-Host "[bootstrap] An upgrade replaces this file with a DIFFERENT version's bytes, so the edit would be"
      Write-Host "[bootstrap] stranded against a baseline this tree no longer carries. Resolve it, then re-run:"
      Write-Host "[bootstrap]   DISCARD it - restore the file from its source (git, or a prior backup under"
      Write-Host "[bootstrap]                the repository's crg-backups area), then re-run."
      Write-Host "[bootstrap]   KEEP it    - carry the change into the PACKAGE and install from that package."
      Write-Host "[bootstrap]                Sealing does NOT preserve an edit through an upgrade: it records the"
      Write-Host "[bootstrap]                current bytes as the baseline, after which this run overwrites them"
      Write-Host "[bootstrap]                with the package's. Keep a copy of the file before either route."
        Write-Host "[bootstrap]                (-SealManifest supplies only a transient replacement baseline.)"
      if ($crgCopiedSoFar.Count -gt 0) {
        # Named, never implied: an abort partway through leaves earlier files
        # already mutated, and a reader must not have to infer which.
        Write-Host ""
        Write-Host "[bootstrap] NOTE: these gate files were already written before this refusal. Overwritten ones"
        Write-Host "[bootstrap] have their original preserved in the backup area named above; created ones did not"
        Write-Host "[bootstrap] exist before this run:"
        foreach ($crgDrDone in $crgCopiedSoFar) { Write-Host "  - $crgDrDone" }
        Write-Host "[bootstrap] Re-running after resolving the edit leaves them as they are and continues."
      }
      exit 1
    }
    # Create and verify the backup directly from the retained custody stream.
    # A pathname copy can conflict with the DELETE-capable owner hold and would
    # reintroduce a second identity between custody classification and backup.
    $crgBakH = $null
    $crgBakFs = $null
    $crgBackupStream = $null
    $crgBakCreateErr = 0
    try {
      $crgBakH = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($crgBakPath, [ref]$crgBakCreateErr)
      if ($null -eq $crgBakH -or $crgBakH.IsInvalid) { throw "backup create-new failed (Win32 error $crgBakCreateErr)" }
      $crgBakFs = New-Object System.IO.FileStream($crgBakH, [System.IO.FileAccess]::ReadWrite)
      $crgBakH = $null
      $crgCustodyOwner.Stream.Position = 0
      $crgCustodyOwner.Stream.CopyTo($crgBakFs)
      $crgBakFs.Flush($true)
      $crgBakHash = Get-CrgSha256HexOfHeldStream -Stream $crgBakFs
      if ($crgBakFs.Length -ne $crgCustodyOwner.Stream.Length -or $crgBakHash -cne $crgCustodyHash) { throw 'the held backup copy did not verify byte-for-byte' }
      $crgBackupStream = $crgBakFs
      $crgInstallBackupStreams.Add($crgBackupStream) | Out-Null
      $crgBakFs = $null
    } catch {
      # A backup-phase abort restores the original to its path first --
      # the best-effort restoration covers the backup-phase aborts too,
      # not just replacement failures.
      $crgBkErr = $_.Exception.Message
      if ($null -ne $crgBakFs) { $null = Remove-CrgOwnedScratchHandle -Path $crgBakPath -Stream $crgBakFs -Label "incomplete backup for '$($f.Dst)'"; $crgBakFs = $null }
      elseif ($null -ne $crgBakH -and -not $crgBakH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $crgBakPath -Handle $crgBakH -Label "incomplete backup for '$($f.Dst)'"; $crgBakH = $null }
      $crgBkWhere = Restore-CrgCustodySimple -CustodyPath $crgCustody -DestPath $dstAbs -BaselineHash $crgCustodyHash -CustodyOwner $crgCustodyOwner
      Write-Error "bootstrap.ps1: creating the backup copy at '$crgBakPath' failed ($crgBkErr). The ORIGINAL is $crgBkWhere."
      exit 1
    } finally {
      if ($null -ne $crgBakFs) { try { $crgBakFs.Dispose() } catch { } }
      elseif ($null -ne $crgBakH -and -not $crgBakH.IsInvalid) { try { $crgBakH.Dispose() } catch { } }
    }
  }
  # The INSTALLED-CONTENT digest is the manifest's authority: the written
  # file must hash to it, and the manifest later records this verified
  # value -- never a fresh hash of the mutable destination, which would
  # bless a same-length corruption or a concurrent edit as the trusted
  # baseline.
  # CreateFile(CREATE_NEW|OPEN_REPARSE_POINT) returns the exact new leaf handle.
  # A dangling symlink arriving after the absence probe is therefore a collision,
  # never a pathname that redirects the write outside the repository. CUSTODY IS
  # RETAINED until the held replacement verifies; failure dispositions only the
  # exact owned partial before attempting layered restoration.
  $crgWriteH = $null
  $crgWriteFs = $null
  $crgWriteCreateErr = 0
  $crgDstGot = $null
  try {
    $crgWriteH = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($dstAbs, [ref]$crgWriteCreateErr)
    if ($null -eq $crgWriteH -or $crgWriteH.IsInvalid) { throw "no-follow create-new failed (Win32 error $crgWriteCreateErr)" }
    try {
      $crgWriteFs = New-Object System.IO.FileStream($crgWriteH, [System.IO.FileAccess]::ReadWrite)
      $crgWriteH = $null
    } catch {
      if ($null -ne $crgWriteH -and -not $crgWriteH.IsInvalid) {
        $null = Remove-CrgOwnedScratchHandle -Path $dstAbs -Handle $crgWriteH -Label "unwrapped replacement for '$($f.Dst)'"
        $crgWriteH = $null
      }
      throw
    }
    $crgWriteFs.Write($crgStampedBytes, 0, $crgStampedBytes.Length)
    $crgWriteFs.Flush($true)
    $crgWriteAttrs = [CrgBootstrap.NativeV4]::GetHandleAttributes($crgWriteFs.SafeFileHandle)
    $crgWriteLinks = [CrgBootstrap.NativeV3]::GetLinkCount($crgWriteFs.SafeFileHandle)
    $crgDstGot = Get-CrgSha256HexOfHeldStream -Stream $crgWriteFs
    if (($crgWriteAttrs -band 0x410) -ne 0 -or $crgWriteLinks -ne 1 -or $crgWriteFs.Length -ne $crgStampedBytes.Length -or $null -eq $crgDstGot -or $crgDstGot -cne $crgInstallHash) {
      throw 'the exact held replacement did not retain ordinary single-link shape and byte identity'
    }
    if (-not (Test-Path -LiteralPath $dstAbs -PathType Leaf)) { throw 'the exact held replacement no longer occupies the destination name' }
    $crgInstalledPayloadOwners.Add([pscustomobject]@{ Dst = $f.Dst; Fs = $crgWriteFs; Hash = $crgDstGot }) | Out-Null
    $crgWriteFs = $null
  } catch {
    $crgCopyErr = $_.Exception.Message
    if ($null -ne $crgWriteFs) {
      $null = Remove-CrgOwnedScratchHandle -Path $dstAbs -Stream $crgWriteFs -Label "incomplete replacement for '$($f.Dst)'"
      $crgWriteFs = $null
    } elseif ($null -ne $crgWriteH -and -not $crgWriteH.IsInvalid) {
      $null = Remove-CrgOwnedScratchHandle -Path $dstAbs -Handle $crgWriteH -Label "incomplete replacement for '$($f.Dst)'"
      $crgWriteH = $null
    }
    # The verified/unverified return is deliberately not consulted for
    # gate FILES: an unverified or absent working-tree gate file is
    # fail-safe (the dispatcher, hook, and wrappers verify every
    # consumed copy against HEAD or the manifest and refuse otherwise)
    # -- only the HOOKS path needs the sentinel escalation.
    if ($existedBefore) { $null = Restore-CrgCustody -CustodyPath $crgCustody -DestPath $dstAbs -BackupPath $crgBakPath -BackupHash $crgCustodyHash -Label $f.Dst -CustodyOwner $crgCustodyOwner -BackupStream $crgBackupStream }
    Write-Error "bootstrap.ps1: creating '$dstAbs' failed ($crgCopyErr). A file reappearing at the destination mid-run is a concurrent writer; investigate it, then re-run.$(if ($crgCopiedSoFar.Count -gt 0) { ' Files already written this run: ' + ($crgCopiedSoFar -join '; ') + '.' })"
    exit 1
  } finally {
    if ($null -ne $crgWriteFs) { try { $crgWriteFs.Dispose() } catch { } }
    elseif ($null -ne $crgWriteH -and -not $crgWriteH.IsInvalid) { try { $crgWriteH.Dispose() } catch { } }
  }
  if ($existedBefore) {
    Save-CrgCustodyArchive -CustodyPath $crgCustody -ArchivePath "$crgBakPath.custody" -BackupPath $crgBakPath -Label $f.Dst -CustodyStream $crgCustodyOwner.Stream
    # Defense-in-depth recovery verification. The retained custody owner
    # withholds write sharing from before rename through this point, so digest
    # movement is not a supported writer race; any divergence indicates an
    # object-level integrity failure and must be reported.
    $crgLateSrc = if (Test-Path -LiteralPath $crgCustody -PathType Leaf) { $crgCustody } elseif (Test-Path -LiteralPath "$crgBakPath.custody" -PathType Leaf) { "$crgBakPath.custody" } else { $null }
    $crgLateDiverged = $false
    if ($null -ne $crgLateSrc) {
      $crgLateHash = Get-CrgSha256HexOfHeldStream -Stream $crgCustodyOwner.Stream
      if ($null -eq $crgLateHash) {
        # An unreadable recovery copy is its own diagnosis: claiming
        # "NEWER bytes" at a path that cannot even be read would
        # conceal a possible loss behind a definite-sounding location.
        $crgLateDiverged = $true
        Write-Host "[bootstrap] WARNING: the recovery copy for '$($f.Dst)' at '$crgLateSrc' could not be read back (vanished, unreadable, or locked); verify it by hand. $(Get-CrgBakState -BackupPath $crgBakPath)"
      } elseif (-not [string]::Equals($crgLateHash, $crgCustodyHash, [System.StringComparison]::Ordinal)) {
        $crgLateDiverged = $true
        Write-Host "[bootstrap] WARNING: the retained recovery object for '$($f.Dst)' diverged after its backup hash despite the exclusive write-sharing hold; inspect '$crgLateSrc' and reconcile by hand. $(Get-CrgBakState -BackupPath $crgBakPath)"
      }
    } else {
      # Neither custody nor archive probes: the post-hash recovery
      # record is gone, which must be said rather than silently
      # skipping the comparison.
      $crgLateDiverged = $true
      Write-Host "[bootstrap] WARNING: no recovery copy of '$($f.Dst)' pre-replacement bytes could be probed (custody and archive both absent); the held recovery invariant is broken. $(Get-CrgBakState -BackupPath $crgBakPath)"
    }
    # DURING AN UPGRADE, EVERY REPLACED FILE IS NAMED, manifest-known ones
    # included. The "unmodified files ride along unlisted" rule is right for a
    # same-version refresh, where the operator still holds the package whose
    # bytes were replaced and can reproduce them at will. It is wrong for an
    # upgrade, because a file can be manifest-known and still hold content the
    # operator must not lose: `-SealManifest` records the CURRENT bytes as a
    # transient replacement baseline, so a deliberately changed file becomes "known" and would be
    # replaced by a different version's bytes without its recovery copy ever
    # being named. Overwriting a sealed replacement baseline on upgrade is the contract;
    # doing it silently is not.
    if (-not $crgKnown -or $crgLateDiverged -or $crgUpgradeGuardActive) { $crgBackedUp += $f.Dst }
  }
  $crgInstalledHashes[$f.Dst] = $crgInstallHash
  # EVERY mutated destination is recorded, created as well as overwritten. An
  # abort inventory listing only overwrites understates what the run changed:
  # a newly created gate file is a mutation the operator must know about, and
  # a partial install that names half its own footprint is not a disclosure.
  if ($existedBefore) {
    $overwritten++
    $crgCopiedSoFar.Add("$($f.Dst) (overwritten; original preserved)") | Out-Null
    Write-Host "[bootstrap] OVERWROTE  $($f.Dst)"
  } else {
    $copied++
    $crgCopiedSoFar.Add("$($f.Dst) (newly created)") | Out-Null
    Write-Host "[bootstrap] copied     $($f.Dst)"
  }
}

Write-Host ""
Write-Host "[bootstrap] file copy: $copied new, $overwritten overwritten."
if ($crgBackedUp.Count -gt 0) {
  $crgBackupListKind = if ($crgUpgradeGuardActive) { 'every replaced upgrade file, including recognized baseline content' } else { 'unrecognized pre-existing content' }
  Write-Host "[bootstrap] backed up before overwrite ($crgBackupListKind) under '$(Join-Path (Join-Path $crgCommonDir 'crg-backups') $crgBackupStamp)':"
  foreach ($b in $crgBackedUp) { Write-Host "  - $b" }
}
Write-Host ""

}  # end if (-not self-install) file-copy block

# Ensure the gate's generated artifacts are gitignored in the target repo. The
# review wrappers write verdicts under `logs/<backend>/reviews/`, and the
# dispatch-checklist defaults its output to `logs/dispatch-checklist.md`.
# Skip bypasses use the fixed local Git ref
# `refs/crg-review-skips`, never a worktree path. (The blocker-trends analyzer
# is the exception -- it defaults to the TRACKED `docs/blocker-trends.md`, a
# durable record, so it is intentionally NOT under the ignored `logs/` tree.)
# Without a gitignore entry a
# fresh install would create untracked operational artifacts (contradicting the
# AGENTS template, which describes these as gitignored). Append `logs/` to the
# target repo's root .gitignore if not already covered. Idempotent: the append is
# skipped when an existing line already ignores the root logs tree in any of the
# four common forms (`logs/`, `/logs/`, `logs`, or `/logs`) -- see the detection
# loop below.
#
# Skipped under -DispatcherOnly: that switch's contract is that no tracked file
# is touched, and .gitignore is tracked in an installed repo (checklist step 5
# commits it). Body kept at original indentation, same rationale as the
# file-copy guard above.
if (-not $DispatcherOnly) {

$gitignorePath = Join-Path $targetRepoAbs '.gitignore'
$logsEntry = 'logs/'
$needLogsIgnore = $true
$crgLogsRouted = $false
try { $crgGitignoreSnapshot = Read-CrgRootedFileBytesExact -Path $gitignorePath -Label '.gitignore' }
catch {
  Write-Error "bootstrap.ps1: could not safely read existing '$gitignorePath' before deciding its logs rule: $($_.Exception.Message)"
  exit 1
}
if ($crgGitignoreSnapshot.State -ceq 'held') {
  # Read with -ErrorAction Stop and fail LOUD: a read failure on the existing
  # .gitignore must NOT be collapsed into "no logs rule" (which would let
  # bootstrap APPEND to a file it could not read, double-adding the rule or
  # mutating a file under a permission/lock error). A config mutation requires a
  # verified read first. Aborts the bootstrap with a stable diagnostic so the
  # operator fixes the underlying read problem before retrying.
  try {
    $crgGiBytes = $crgGitignoreSnapshot.Bytes
    $crgGiEnc = New-Object System.Text.UTF8Encoding($false, $true)
    if     ($crgGiBytes.Length -ge 3 -and $crgGiBytes[0] -eq 0xEF -and $crgGiBytes[1] -eq 0xBB -and $crgGiBytes[2] -eq 0xBF) { $crgGiEnc = New-Object System.Text.UTF8Encoding($true, $true) }
    elseif ($crgGiBytes.Length -ge 2 -and $crgGiBytes[0] -eq 0xFF -and $crgGiBytes[1] -eq 0xFE) { $crgGiEnc = New-Object System.Text.UnicodeEncoding($false, $true, $true) }
    elseif ($crgGiBytes.Length -ge 2 -and $crgGiBytes[0] -eq 0xFE -and $crgGiBytes[1] -eq 0xFF) { $crgGiEnc = New-Object System.Text.UnicodeEncoding($true, $true, $true) }
    $crgGiText = $crgGiEnc.GetString($crgGiBytes).TrimStart([char]0xFEFF)
    $existingIgnore = @($crgGiText -split "`r?`n")
  } catch {
    Write-Error "bootstrap.ps1: could not read existing '$gitignorePath' to verify its ignore rules before appending 'logs/': $($_.Exception.Message). Fix the read error (permissions/lock/encoding) and re-run; the gate's generated artifacts must be gitignored, but bootstrap will not mutate a .gitignore it cannot first read."
    exit 1
  }
  foreach ($line in $existingIgnore) {
    # Detect a pre-existing rule that already ignores the root `logs/` tree, in
    # any of the four common forms a consumer might have written: `logs/`,
    # `/logs/`, `logs`, or `/logs` (anchored, no trailing slash). All four ignore
    # the same top-level directory; matching them avoids appending a duplicate
    # block. (Patterns with a leading `**/`, a trailing-comment, or a deeper path
    # are intentionally NOT matched -- they do not unambiguously cover the root
    # `logs/` tree, so the explicit `logs/` is still added.)
    # TrimEnd ONLY: git's ignore syntax strips unescaped TRAILING spaces
    # but keeps LEADING whitespace as pattern content, so ` logs/` is a
    # different (ineffective) pattern -- trimming it into a match would
    # skip the append and leave root logs/ unignored.
    $t = $line.TrimEnd()
    if ([string]::Equals($t, $logsEntry, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($t, '/logs/', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($t, 'logs', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($t, '/logs', [System.StringComparison]::OrdinalIgnoreCase)) { $needLogsIgnore = $false; break }
  }
}
if ($needLogsIgnore) {
  # LOCAL install shape (docs/local-install-v1.md): a target whose gate
  # hook path is already deliberately ignored has declared that project
  # content must not carry tooling entries, so the logs/ rule goes to
  # the git common dir's info/exclude instead of the tracked .gitignore.
  # `git check-ignore` consults every ignore source, so an operator who
  # sets the excludes BEFORE running bootstrap gets this routing on the
  # first install; a tracked-shape target never trips it. The tri-state
  # probe keeps a FAILED probe out of both answers -- routing the logs/
  # rule into the tracked .gitignore off an indeterminate answer would
  # do exactly what the local shape forbids.
  $crgHookIgnState = Get-CrgCheckIgnoreState -Repo $targetRepoAbs -Path 'scripts/git-hooks/pre-commit'
  if (([string]$crgHookIgnState).StartsWith('error:', [System.StringComparison]::Ordinal)) {
    Write-Error "bootstrap.ps1: git check-ignore failed ($crgHookIgnState) probing 'scripts/git-hooks/pre-commit' in '$targetRepoAbs'; cannot decide where the logs/ ignore rule belongs. Diagnose the repository, then re-run."
    exit 1
  }
  if ([string]::Equals($crgHookIgnState, 'ignored', [System.StringComparison]::Ordinal) -and $null -eq $crgCommonDir) {
    # A positively LOCAL shape with no resolvable common dir must not
    # fall through to the tracked-.gitignore append below -- that write
    # is exactly what the local shape exists to keep out of the
    # project.
    Write-Error "bootstrap.ps1: the gate hook path is ignored (LOCAL shape) but the git common dir of '$targetRepoAbs' cannot be resolved for the info/exclude routing; refusing to touch the tracked .gitignore instead. Diagnose the repository, then re-run."
    exit 1
  }
  if ([string]::Equals($crgHookIgnState, 'ignored', [System.StringComparison]::Ordinal)) {
    $crgLogsExcl = Join-Path $crgCommonDir 'info'
    $null = Ensure-CrgRootedDirectory -Path $crgLogsExcl -Label 'local-shape exclude directory'
    $crgExclFile = Join-Path $crgLogsExcl 'exclude'
    # Idempotence mirrors the .gitignore path above, same loud-read
    # discipline: every local-shape refresh re-enters this branch (the
    # $needLogsIgnore probe reads only .gitignore), so an unconditional
    # append would duplicate the block on each re-run.
    $crgExclState = [pscustomobject]@{ HadLogs = $false }
    $crgExclLatin1 = [System.Text.Encoding]::GetEncoding(28591)
    $crgExclUtf8 = New-Object System.Text.UTF8Encoding($false)
    $crgExclTransform = {
      param([byte[]]$Bytes)
      $crgExclText = $crgExclLatin1.GetString($Bytes)
      foreach ($crgExclLine in @($crgExclText -split "`n")) {
        $t = $crgExclLine.TrimEnd()
        if ([string]::Equals($t, $logsEntry, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($t, '/logs/', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($t, 'logs', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($t, '/logs', [System.StringComparison]::OrdinalIgnoreCase)) { $crgExclState.HadLogs = $true; return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$Bytes } }
      }
      $crgExclBlock = $crgExclUtf8.GetBytes("`n# cross-review-gate generated artifacts (verdict logs, dispatch-checklist)`nlogs/`n")
      $crgExclOut = New-Object byte[] ($Bytes.Length + $crgExclBlock.Length)
      if ($Bytes.Length -gt 0) { [System.Array]::Copy($Bytes, 0, $crgExclOut, 0, $Bytes.Length) }
      [System.Array]::Copy($crgExclBlock, 0, $crgExclOut, $Bytes.Length, $crgExclBlock.Length)
      return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$crgExclOut }
    }.GetNewClosure()
    try { $crgExclUpdate = Update-CrgRootedFileBytes -Path $crgExclFile -Transform $crgExclTransform -Label 'local-shape info/exclude' }
    catch {
      Write-Error "bootstrap.ps1: could not safely update '$crgExclFile' through a retained no-follow single-link handle: $($_.Exception.Message)"
      exit 1
    }
    if ($crgExclState.HadLogs) {
      Write-Host "[bootstrap] local install shape: the git common dir's info/exclude already ignores 'logs/' (project .gitignore left untouched)"
    } else {
      Write-Host "[bootstrap] local install shape: appended 'logs/' to the git common dir's info/exclude (project .gitignore left untouched)"
    }
    $needLogsIgnore = $false
    $crgLogsRouted = $true
  }
}
if ($needLogsIgnore) {
  # The blocker-trends report defaults to docs/ (tracked), so it is NOT listed
  # here -- only the logs/-resident artifacts (verdict logs and the dispatch-
  # checklist) are covered by the `logs/` rule.
  $ignoreBlock = "`n# cross-review-gate generated artifacts (verdict logs, dispatch-checklist)`nlogs/`n"
  $crgGiState = [pscustomobject]@{ AlreadyCovered = $false }
  $crgGiTransform = {
    param([byte[]]$Bytes)
    if ($Bytes.Length -eq 0) { return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]([System.Text.UTF8Encoding]::new($false).GetBytes($ignoreBlock.TrimStart("`n"))) } }
    $crgGiWriteEnc = New-Object System.Text.UTF8Encoding($false, $true)
    if     ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { $crgGiWriteEnc = New-Object System.Text.UTF8Encoding($true, $true) }
    elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { $crgGiWriteEnc = New-Object System.Text.UnicodeEncoding($false, $true, $true) }
    elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) { $crgGiWriteEnc = New-Object System.Text.UnicodeEncoding($true, $true, $true) }
    $crgGiCurrent = $crgGiWriteEnc.GetString($Bytes).TrimStart([char]0xFEFF)
    foreach ($crgGiLine in @($crgGiCurrent -split "`r?`n")) {
      $crgGiTrimmed = $crgGiLine.TrimEnd()
      if ([string]::Equals($crgGiTrimmed, $logsEntry, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($crgGiTrimmed, '/logs/', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($crgGiTrimmed, 'logs', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($crgGiTrimmed, '/logs', [System.StringComparison]::OrdinalIgnoreCase)) { $crgGiState.AlreadyCovered = $true; return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$Bytes } }
    }
    $crgGiAppend = $crgGiWriteEnc.GetBytes($ignoreBlock)
    $crgGiOut = New-Object byte[] ($Bytes.Length + $crgGiAppend.Length)
    [System.Array]::Copy($Bytes, 0, $crgGiOut, 0, $Bytes.Length)
    [System.Array]::Copy($crgGiAppend, 0, $crgGiOut, $Bytes.Length, $crgGiAppend.Length)
    return [pscustomobject]@{ Ok = $true; Bytes = [byte[]]$crgGiOut }
  }.GetNewClosure()
  try { $crgGiUpdate = Update-CrgRootedFileBytes -Path $gitignorePath -Transform $crgGiTransform -Label '.gitignore logs rule' }
  catch {
    Write-Error "bootstrap.ps1: could not safely update '$gitignorePath' through a retained no-follow single-link handle: $($_.Exception.Message)"
    exit 1
  }
  if ($crgGiState.AlreadyCovered) { Write-Host "[bootstrap] .gitignore already covers 'logs/' (gate artifacts)" }
  elseif (-not $crgGiUpdate.Created) { Write-Host "[bootstrap] appended 'logs/' to existing .gitignore (gate artifacts)" }
  else { Write-Host "[bootstrap] created .gitignore with 'logs/' (gate artifacts)" }
} elseif (-not $crgLogsRouted) {
  Write-Host "[bootstrap] .gitignore already covers 'logs/' (gate artifacts)"
}
Write-Host ""

}  # end if (-not DispatcherOnly) .gitignore block

# LF checkout contract for the sh-parsed gate surfaces: under
# core.autocrlf=true (the common Windows default) a fresh tracked
# checkout rewrites scripts/run-gate.sh and the tracked hook to CRLF,
# and sh fails parsing the gate-firing entry point before any guard or
# `git commit` runs. The rules are APPENDED to the target's root
# .gitattributes -- append-if-absent exactly like the logs/ ignore rule
# above, never a blind copy over consumer rules -- and name ONLY the
# gate's own paths, so a consumer repository's unrelated shell sources
# keep their own checkout behavior. Because gitattributes resolution is
# last-match-wins across arbitrary patterns, textual scanning cannot
# prove the effective value; after any append the EFFECTIVE attribute
# is verified through git's own oracle (`git check-attr`), and a value
# still not 'lf' fails LOUD (a consumer rule ordered after these lines,
# or a write that did not land). Skipped under -DispatcherOnly (no
# tracked file is touched). Each sh path is classified INDEPENDENTLY
# against the ignore state -- the local-install doctrine supports
# hybrid layouts, so an ignored hook beside a tracked run-gate.sh must
# still get the tracked path's rule (an all-or-nothing decision keyed
# off one path would leave the tracked surface exposed to CRLF
# conversion); a path that is deliberately ignored (its local shape)
# is never checkout-rewritten and gets no rule.
if (-not $DispatcherOnly) {

$crgAttrPath = Join-Path $targetRepoAbs '.gitattributes'
# Every refusal in this phase fires AFTER the file-copy phase above, so the
# gate files already occupy their destinations: the bare "then re-run" this
# phase used to prescribe stops at the existing-destination check and never
# reaches the step that failed, leaving the operator with a diagnostic whose
# recovery cannot run. The remedy names the flag that gets past it -- and
# names what that flag ALSO waives, since -Force is the same switch that
# overwrites an installed dispatcher and installs over a conflicting
# core.hooksPath (the refusals further down offer it for exactly that).
$crgAttrRerunRemedy = 'Then re-run with -Force: the gate files are already at their destinations, so a re-run without it stops at the existing-destination check before reaching this step. -Force also overwrites an existing .git/hooks/pre-commit dispatcher -- back up any hook you did not install yourself before using it. A configured core.hooksPath must be cleared explicitly before any install.'
$crgAttrShPaths = @('scripts/run-gate.sh', 'scripts/git-hooks/pre-commit')
$crgAttrRules = @()
$crgAttrVerifyPaths = @()
foreach ($crgAttrSh in $crgAttrShPaths) {
  $crgAttrShState = Get-CrgCheckIgnoreState -Repo $targetRepoAbs -Path $crgAttrSh
  if (([string]$crgAttrShState).StartsWith('error:', [System.StringComparison]::Ordinal)) {
    Write-Error "bootstrap.ps1: git check-ignore failed ($crgAttrShState) probing '$crgAttrSh' in '$targetRepoAbs'; cannot decide whether its LF checkout rule belongs in the tracked .gitattributes. Diagnose the repository. $crgAttrRerunRemedy"
    exit 1
  }
  if ([string]::Equals($crgAttrShState, 'ignored', [System.StringComparison]::Ordinal)) {
    Write-Host "[bootstrap] local-shape path '$crgAttrSh': LF checkout rule not written (an untracked, ignored file is never checkout-rewritten)"
  } else {
    $crgAttrRules += "$crgAttrSh text eol=lf"
    $crgAttrVerifyPaths += $crgAttrSh
  }
}
$crgInstallValueAttributeRules = @(
  'CROSS-REVIEW-VALUES.md text eol=lf -filter -ident -working-tree-encoding',
  'scripts/codex/review-prompt-template.md text eol=lf -filter -ident -working-tree-encoding',
  'docs/AGENTS.md.template text eol=lf -filter -ident -working-tree-encoding'
)
if ($crgRenderOutputAuthority.Family -ceq 'TRACKED') {
  $crgAttrRules += $crgInstallValueAttributeRules
  $crgAttrVerifyPaths += @('CROSS-REVIEW-VALUES.md', 'scripts/codex/review-prompt-template.md', 'docs/AGENTS.md.template')
}
if ($crgAttrVerifyPaths.Count -eq 0 -and $crgRetiredPmHead.State -cne 'legacy') {
  Write-Host "[bootstrap] local install shape: no LF checkout rules written (the tracked .gitattributes stays untouched)"
} else {
  # The whole read-decide-append runs through ONE exclusively held,
  # no-follow handle whose SHAPE is proven on the handle itself, never by
  # a pathname probe: Test-Path/AppendAllText by pathname would FOLLOW a
  # symlink or write through a hard link, mutating a target OUTSIDE the
  # repository (the digest publisher's no-pathname-reopen rationale,
  # applied to a config file), and a pathname probe reports a DANGLING
  # reparse point as absent, after which a follow-open create would
  # create the link's target. So absence is decided by the no-follow
  # open's own status (ERROR_FILE_NOT_FOUND alone), creation is one
  # atomic no-follow CREATE_NEW below, and a reparse-point, directory, or
  # multi-link occupant refuses fatally with the occupant preserved; any
  # other open failure (a lock holder, an unreadable ancestor) refuses as
  # indeterminate.
  $crgAttrExistingText = $null
  $crgAttrUtf8 = New-Object System.Text.UTF8Encoding($false)
  $crgAttrEnc = $crgAttrUtf8
  $crgAttrFs = $null
  $crgAttrEx = $null
  $crgAttrOpenErr = 0
  try {
    try {
      $crgAttrEx = if ($crgRetiredPmHead.State -ceq 'legacy') {
        [CrgBootstrap.NativeV4]::OpenReadWriteShareReadNoFollow($crgAttrPath, [ref]$crgAttrOpenErr)
      } else {
        [CrgBootstrap.NativeV4]::OpenExclusiveNoFollow($crgAttrPath, [ref]$crgAttrOpenErr)
      }
    } catch { $crgAttrEx = $null; $crgAttrOpenErr = -1 }
    if ($null -ne $crgAttrEx -and -not $crgAttrEx.IsInvalid) {
      $crgAttrShape = [CrgBootstrap.NativeV3]::GetHandleAttributes($crgAttrEx)
      if ($crgAttrShape -lt 0) {
        Write-Error "bootstrap.ps1: could not classify the occupant at '$crgAttrPath' through its handle; refusing to touch it. Diagnose the path. $crgAttrRerunRemedy"
        exit 1
      }
      if ($crgAttrShape -band 0x400) {
        Write-Error "bootstrap.ps1: '$crgAttrPath' is a reparse point (symlink/junction) - writing through it would mutate a target outside this repository. Replace it with a regular file holding your rules. $crgAttrRerunRemedy"
        exit 1
      }
      if ($crgAttrShape -band 0x10) {
        Write-Error "bootstrap.ps1: '$crgAttrPath' is a directory - refusing to touch it. Remove or rename it. $crgAttrRerunRemedy"
        exit 1
      }
      if ([CrgBootstrap.NativeV3]::GetLinkCount($crgAttrEx) -ne 1) {
        Write-Error "bootstrap.ps1: the file at '$crgAttrPath' has extra hard links - an append would land bytes at every alias, possibly outside this repository. Repair the links. $crgAttrRerunRemedy"
        exit 1
      }
      if ($crgRetiredPmHead.State -ceq 'legacy') {
        if (-not $crgLegacyAttrBasePresent) {
          Write-Error "bootstrap.ps1: .gitattributes was absent from the locked legacy BaseHead but gained a worktree occupant before the append phase. The occupant is preserved; no audited transition can include it."
          exit 1
        }
      }
      $crgAttrFs = New-Object System.IO.FileStream($crgAttrEx, [System.IO.FileAccess]::ReadWrite)
      $crgAttrEx = $null
      if ($crgAttrFs.Length -gt 1048576) {
        Write-Error "bootstrap.ps1: the held .gitattributes file exceeds the 1 MiB legacy-transition bound. The file is preserved byte-for-byte and no transition identity will be published."
        exit 1
      }
      $crgAttrMs = New-Object System.IO.MemoryStream
      $crgAttrFs.CopyTo($crgAttrMs)
      $crgAttrHead = $crgAttrMs.ToArray()
      $crgAttrMs.Dispose()
      if ($crgRetiredPmHead.State -ceq 'legacy') {
        $crgAttrControlledOid = Get-CrgControlledLegacyAttributeOid -RepoRoot $targetRepoAbs -ProofScratchRoot $crgProofScratchParent -BaseHead $crgLegacyBaseHead -BaseAttributeOid $crgLegacyAttrBaseOid -HeldBytes $crgAttrHead
        if ([string]::IsNullOrWhiteSpace("$crgAttrControlledOid") -or
            -not [string]::Equals("$crgAttrControlledOid", "$crgLegacyAttrBaseOid", [System.StringComparison]::Ordinal)) {
          $crgAttrControlledOidText = if ([string]::IsNullOrWhiteSpace("$crgAttrControlledOid")) { '<indeterminate>' } else { "$crgAttrControlledOid" }
          Write-Error "bootstrap.ps1: the held .gitattributes bytes do not resolve to the locked BaseHead blob in the controlled conversion domain (expected $crgLegacyAttrBaseOid, resolved $crgAttrControlledOidText). The edit is preserved byte-for-byte and no transition identity will be published."
          exit 1
        }
      }
      # BOM-sniffed decode/append encoding, same mixed-encoding hazard
      # and remedy as the .gitignore append above (the appended text is
      # encoded WITHOUT re-emitting a BOM).
      if     ($crgAttrHead.Length -ge 3 -and $crgAttrHead[0] -eq 0xEF -and $crgAttrHead[1] -eq 0xBB -and $crgAttrHead[2] -eq 0xBF) { $crgAttrEnc = $crgAttrUtf8; $crgAttrExistingText = $crgAttrUtf8.GetString($crgAttrHead, 3, $crgAttrHead.Length - 3) }
      elseif ($crgAttrHead.Length -ge 2 -and $crgAttrHead[0] -eq 0xFF -and $crgAttrHead[1] -eq 0xFE) { $crgAttrEnc = New-Object System.Text.UnicodeEncoding($false, $false); $crgAttrExistingText = $crgAttrEnc.GetString($crgAttrHead, 2, $crgAttrHead.Length - 2) }
      elseif ($crgAttrHead.Length -ge 2 -and $crgAttrHead[0] -eq 0xFE -and $crgAttrHead[1] -eq 0xFF) { $crgAttrEnc = New-Object System.Text.UnicodeEncoding($true, $false); $crgAttrExistingText = $crgAttrEnc.GetString($crgAttrHead, 2, $crgAttrHead.Length - 2) }
      else { $crgAttrExistingText = $crgAttrUtf8.GetString($crgAttrHead) }
    } elseif ($crgAttrOpenErr -ne 2) {
      Write-Error "bootstrap.ps1: the path '$crgAttrPath' could not be exclusively opened (Win32 error ${crgAttrOpenErr}: a lock holder, a directory, or a shape this installer must not write through) - refusing to touch it. Diagnose the path. $crgAttrRerunRemedy"
      exit 1
    } elseif ($crgRetiredPmHead.State -ceq 'legacy' -and $crgLegacyAttrBasePresent) {
      Write-Error "bootstrap.ps1: .gitattributes was present in the locked legacy BaseHead but disappeared before the held append phase. No transition identity was published."
      exit 1
    }
    $crgAttrToAdd = @()
    $crgAttrExisting = @()
    if ($null -ne $crgAttrExistingText -and $crgAttrExistingText.Length -gt 0) { $crgAttrExisting = $crgAttrExistingText -split "`r?`n" }
    foreach ($crgAttrRule in $crgAttrRules) {
      $crgAttrHave = $false
      foreach ($crgAttrLine in $crgAttrExisting) {
        # TrimEnd ONLY (leading whitespace changes gitattributes pattern
        # meaning, same rationale as the ignore scans above); presence is
        # the exact canonical rule line -- anything looser is settled by
        # the effective-attribute verification below, not by text guesses
        # here.
        $crgAttrLineMatches = if ($crgInstallValueAttributeRules -ccontains $crgAttrRule) {
          [string]::Equals($crgAttrLine, $crgAttrRule, [System.StringComparison]::Ordinal)
        } else {
          [string]::Equals($crgAttrLine.TrimEnd(), $crgAttrRule, [System.StringComparison]::Ordinal)
        }
        if ($crgAttrLineMatches) { $crgAttrHave = $true; break }
      }
      if (-not $crgAttrHave) { $crgAttrToAdd += $crgAttrRule }
    }
    if ($crgAttrToAdd.Count -gt 0) {
      $crgAttrBlock = "`n# cross-review-gate: exact checkout rules for installed gate surfaces`n" + (($crgAttrToAdd -join "`n") + "`n")
      if ($null -ne $crgAttrFs) {
        try {
          $crgAttrOut = $crgAttrEnc.GetBytes($crgAttrBlock)
          if (($crgAttrFs.Length + $crgAttrOut.Length) -gt 1048576) { throw 'the post-append .gitattributes bytes would exceed the 1 MiB legacy-transition bound' }
          $null = $crgAttrFs.Seek(0, [System.IO.SeekOrigin]::End)
          $crgAttrFs.Write($crgAttrOut, 0, $crgAttrOut.Length)
          $crgAttrFs.Flush($true)
        } catch {
          Write-Error "bootstrap.ps1: could not append the gate's LF checkout rules to '$crgAttrPath' ($($_.Exception.Message)). Add the rules manually. $crgAttrRerunRemedy"
          exit 1
        }
        Write-Host "[bootstrap] appended the gate's LF checkout rules to existing .gitattributes"
      } else {
        # Positively absent at the open above; the no-follow CREATE_NEW is
        # the only write path, so anything planted since (a file, a
        # dangling link, a directory) collides and is preserved.
        $crgAttrNewErr = 0
        $crgAttrNew = $null
        $crgAttrNewFs = $null
        $crgAttrNewComplete = $false
        try {
          $crgAttrNew = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($crgAttrPath, [ref]$crgAttrNewErr)
        } catch { $crgAttrNew = $null; $crgAttrNewErr = -1 }
        if ($null -eq $crgAttrNew -or $crgAttrNew.IsInvalid) {
          Write-Error "bootstrap.ps1: could not create '$crgAttrPath' with the gate's LF checkout rules (Win32 error $crgAttrNewErr) - an occupant that appeared behind the absence probe is preserved, never overwritten or followed. Diagnose the path. $crgAttrRerunRemedy"
          exit 1
        }
        try {
          try {
            $crgAttrNewFs = New-Object System.IO.FileStream($crgAttrNew, [System.IO.FileAccess]::ReadWrite)
            $crgAttrNew = $null
            $crgAttrOut = $crgAttrUtf8.GetBytes($crgAttrBlock.TrimStart("`n"))
            if ($crgAttrOut.Length -gt 1048576) { throw 'the new .gitattributes bytes would exceed the 1 MiB legacy-transition bound' }
            $crgAttrNewFs.Write($crgAttrOut, 0, $crgAttrOut.Length)
            $crgAttrNewFs.Flush($true)
            $crgAttrNewComplete = $true
            if ($crgRetiredPmHead.State -ceq 'legacy') {
              $crgAttrFs = $crgAttrNewFs
              $crgAttrNewFs = $null
            }
          } finally {
            if ($null -ne $crgAttrNewFs) {
              if ($crgAttrNewComplete) { $crgAttrNewFs.Dispose() }
              else { $null = Remove-CrgOwnedScratchHandle -Path $crgAttrPath -Stream $crgAttrNewFs -Label 'new .gitattributes' }
            } elseif ($null -ne $crgAttrNew -and -not $crgAttrNew.IsInvalid) {
              $null = Remove-CrgOwnedScratchHandle -Path $crgAttrPath -Handle $crgAttrNew -Label 'new .gitattributes'
            }
          }
        } catch {
          Write-Error "bootstrap.ps1: could not write the gate's LF checkout rules into the newly created '$crgAttrPath' ($($_.Exception.Message)). Add the rules manually. $crgAttrRerunRemedy"
          exit 1
        }
        Write-Host "[bootstrap] created .gitattributes with the gate's LF checkout rules"
      }
    } else {
      Write-Host "[bootstrap] .gitattributes already carries the gate's LF checkout rules"
    }
    if ($crgRetiredPmHead.State -ceq 'legacy' -and $null -ne $crgAttrFs) {
      if ($crgAttrFs.Length -gt 1048576) {
        Write-Error "bootstrap.ps1: the post-append .gitattributes bytes exceed the 1 MiB legacy-transition bound. No transition identity will be published."
        exit 1
      }
      $crgAttrFs.Position = 0
      $crgAttrCapture = New-Object System.IO.MemoryStream
      try { $crgAttrFs.CopyTo($crgAttrCapture); $crgLegacyAttrExpectedBytes = $crgAttrCapture.ToArray() } finally { $crgAttrCapture.Dispose() }
      $crgAttrFs.Position = 0
      $crgLegacyAttrHold = $crgAttrFs
      $crgAttrFs = $null
    }
  } finally {
    if ($null -ne $crgAttrFs) { try { $crgAttrFs.Dispose() } catch { } }
    elseif ($null -ne $crgAttrEx) { try { $crgAttrEx.Dispose() } catch { } }
  }
  # Verify the effective checkout contract against one content-addressed
  # attribute-source tree. Git receives every probe through stdin; no candidate,
  # config, index, or attribute pathname can be swapped between classification
  # and conversion. Private loose objects and the mandatory empty info/global
  # sources remain immutable under held handles for every child invocation.
  $crgAttrVerEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $crgAttrVer = ''
  $crgAttrVerOk = $false
  $crgAttrCleanupOk = $true
  $crgAttrContext = $null
  # Keep the final attribute oracle in the retained external proof namespace.
  # Nesting a private Git repository below a linked worktree's Git dir can cross
  # Git for Windows' explicit-GIT_DIR limit even when the target itself is valid.
  $crgAttrIso = Join-Path $crgProofScratchParent ("crg-av-" + [guid]::NewGuid().ToString('N'))
  try {
    $crgAttrFormatRows = @(& git -C $targetRepoAbs rev-parse --show-object-format 2>$null)
    if ($LASTEXITCODE -ne 0 -or $crgAttrFormatRows.Count -ne 1 -or -not ([string]::Equals("$($crgAttrFormatRows[0])", 'sha1', [System.StringComparison]::Ordinal) -or [string]::Equals("$($crgAttrFormatRows[0])", 'sha256', [System.StringComparison]::Ordinal))) { throw 'target object format could not be captured for the isolated attribute context' }
    $crgAttrOidLength = if ([string]::Equals("$($crgAttrFormatRows[0])", 'sha256', [System.StringComparison]::Ordinal)) { 64 } else { 40 }
    $crgAttrContext = New-CrgPrivateAttributeContext -ScratchRoot $crgAttrIso -ObjectIdLength $crgAttrOidLength
    $crgAttrBuffers = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    foreach ($crgAttrSourcePath in @('.gitattributes', 'scripts/.gitattributes', 'scripts/git-hooks/.gitattributes', 'scripts/codex/.gitattributes', 'docs/.gitattributes')) {
      if ($crgAttrSourcePath -ceq '.gitattributes' -and $null -ne $crgLegacyAttrExpectedBytes) {
        $crgAttrBuffers[$crgAttrSourcePath] = [byte[]]$crgLegacyAttrExpectedBytes
        continue
      }
      $crgAttrSourceAbs = Join-Path $targetRepoAbs $crgAttrSourcePath
      $crgAttrSourceError = 0; $crgAttrSourceHandle = $null; $crgAttrSourceStream = $null
      try { $crgAttrSourceHandle = [CrgBootstrap.NativeV4]::OpenReadShareReadNoFollow($crgAttrSourceAbs, [ref]$crgAttrSourceError) } catch { $crgAttrSourceHandle = $null; $crgAttrSourceError = -1 }
      if ($null -eq $crgAttrSourceHandle -or $crgAttrSourceHandle.IsInvalid) {
        if ($null -ne $crgAttrSourceHandle) { $crgAttrSourceHandle.Dispose() }
        if ($crgAttrSourceError -in @(2, 3)) {
          $crgInstallValuesAttributeAbsences.Add($crgAttrSourcePath) | Out-Null
          continue
        }
        throw "attribute source '$crgAttrSourceAbs' could not be held no-follow (Win32 error $crgAttrSourceError)"
      }
      try {
        $crgAttrSourceShape = [CrgBootstrap.NativeV4]::GetHandleAttributes($crgAttrSourceHandle)
        if ($crgAttrSourceShape -lt 0 -or ($crgAttrSourceShape -band 0x410) -ne 0 -or [CrgBootstrap.NativeV3]::GetLinkCount($crgAttrSourceHandle) -ne 1) {
          throw "attribute source '$crgAttrSourceAbs' is not one ordinary non-reparse single-link file"
        }
        $crgAttrSourceStream = New-Object System.IO.FileStream($crgAttrSourceHandle, [System.IO.FileAccess]::Read)
        $crgAttrSourceHandle = $null
        if ($crgAttrSourceStream.Length -gt 1048576) { throw "attribute source '$crgAttrSourceAbs' exceeds the 1 MiB proof bound" }
        $crgAttrSourceBytes = New-Object byte[] ([int]$crgAttrSourceStream.Length)
        $crgAttrSourceRead = 0
        while ($crgAttrSourceRead -lt $crgAttrSourceBytes.Length) {
          $crgAttrSourceGot = $crgAttrSourceStream.Read($crgAttrSourceBytes, $crgAttrSourceRead, $crgAttrSourceBytes.Length - $crgAttrSourceRead)
          if ($crgAttrSourceGot -le 0) { break }
          $crgAttrSourceRead += $crgAttrSourceGot
        }
        if ($crgAttrSourceRead -ne $crgAttrSourceBytes.Length) { throw "attribute source '$crgAttrSourceAbs' could not be read completely" }
        $crgAttrSourceStream.Position = 0
        $crgAttrBuffers[$crgAttrSourcePath] = [byte[]]$crgAttrSourceBytes
        $crgAttributeSourceHolds.Add($crgAttrSourceStream) | Out-Null
        $crgInstallValuesAttributeHolds.Add([pscustomobject]@{ RelativePath = $crgAttrSourcePath; Stream = $crgAttrSourceStream; Hash = (Get-CrgSha256HexOfBytes -Bytes $crgAttrSourceBytes) }) | Out-Null
        $crgAttrSourceStream = $null
      } finally {
        if ($null -ne $crgAttrSourceStream) { $crgAttrSourceStream.Dispose() }
        if ($null -ne $crgAttrSourceHandle) { $crgAttrSourceHandle.Dispose() }
      }
    }
    if (-not $crgAttrBuffers.ContainsKey('.gitattributes')) { throw 'the effective root .gitattributes source disappeared before immutable verification' }
    $crgAttrObjectWriter = {
      param([string]$Type, [byte[]]$Bytes)
      return Add-CrgPrivateGitObject -Context $crgAttrContext -Type $Type -Bytes $Bytes
    }
    $crgAttrStatePaths = @('CROSS-REVIEW-VALUES.md', 'scripts/codex/review-prompt-template.md', 'docs/AGENTS.md.template')
    $crgAttrTreeOid = New-CrgGitAttributeSourceTree -AttributeBuffers $crgAttrBuffers -ObjectIdLength $crgAttrOidLength -WriteObject $crgAttrObjectWriter -ProbePaths $crgAttrStatePaths
    if ($crgAttrTreeOid -cnotmatch "\A[0-9a-f]{$crgAttrOidLength}\z") { throw 'the immutable attribute-source tree did not produce one canonical object ID' }
    if ($crgRenderOutputAuthority.Family -ceq 'TRACKED') {
      Assert-CrgPrivateInstallValuesAttributeStates -Context $crgAttrContext -TreeOid $crgAttrTreeOid -Paths $crgAttrStatePaths
    }

    $crgAttrPathInputStream = New-Object System.IO.MemoryStream
    try {
      foreach ($crgAttrVerifyPath in $crgAttrVerifyPaths) {
        $crgAttrVerifyPathBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($crgAttrVerifyPath)
        $crgAttrPathInputStream.Write($crgAttrVerifyPathBytes, 0, $crgAttrVerifyPathBytes.Length)
        $crgAttrPathInputStream.WriteByte(0)
      }
      [byte[]]$crgAttrPathInput = $crgAttrPathInputStream.ToArray()
    } finally { $crgAttrPathInputStream.Dispose() }

    $crgAttrParseTriples = {
      param([byte[]]$Bytes, [string]$Label)
      $crgAttrTripleText = [System.Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
      $crgAttrTripleParts = $crgAttrTripleText.Split([char[]]@([char]0), [System.StringSplitOptions]::None)
      if ($crgAttrTripleParts.Count -lt 1 -or $crgAttrTripleParts[$crgAttrTripleParts.Count - 1].Length -ne 0 -or (($crgAttrTripleParts.Count - 1) % 3) -ne 0) { throw "$Label returned malformed NUL-delimited triples" }
      $crgAttrTripleList = New-Object System.Collections.ArrayList
      for ($crgAttrTripleI = 0; $crgAttrTripleI -lt ($crgAttrTripleParts.Count - 1); $crgAttrTripleI += 3) {
        $crgAttrTripleList.Add([pscustomobject]@{ Path = $crgAttrTripleParts[$crgAttrTripleI]; Attribute = $crgAttrTripleParts[$crgAttrTripleI + 1]; Value = $crgAttrTripleParts[$crgAttrTripleI + 2] }) | Out-Null
      }
      return [object[]]$crgAttrTripleList.ToArray()
    }

    $crgAttrExpectedPathSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($crgAttrVerifyPath in $crgAttrVerifyPaths) { [void]$crgAttrExpectedPathSet.Add($crgAttrVerifyPath) }
    $crgAttrAll = Invoke-CrgPrivateAttributeGit -Context $crgAttrContext -GitArgs @("--attr-source=$crgAttrTreeOid", 'check-attr', '-z', '--stdin', '--all') -InputBytes $crgAttrPathInput
    if ($crgAttrAll.Exit -ne 0 -or $crgAttrAll.ErrorText.Length -ne 0) { throw "immutable check-attr --all failed (exit $($crgAttrAll.Exit)): $($crgAttrAll.Text.Trim())" }
    $crgAttrFail = New-Object 'System.Collections.Generic.List[string]'
    foreach ($crgAttrAllEntry in @(& $crgAttrParseTriples $crgAttrAll.Bytes 'check-attr --all')) {
      if (-not $crgAttrExpectedPathSet.Contains($crgAttrAllEntry.Path) -or $crgAttrAllEntry.Attribute -cnotmatch '\A[A-Za-z0-9_.-]+\z') {
        throw "check-attr --all returned an unexpected path or malformed attribute name (path='$($crgAttrAllEntry.Path)', attribute='$($crgAttrAllEntry.Attribute)')"
      }
      if ([System.Linq.Enumerable]::Contains([string[]]@('filter', 'ident', 'working-tree-encoding'), [string]$crgAttrAllEntry.Attribute, [System.StringComparer]::Ordinal) -and
          (-not [string]::Equals($crgAttrAllEntry.Value, 'unset', [System.StringComparison]::Ordinal) -or -not [System.Linq.Enumerable]::Contains([string[]]@($crgAttrStatePaths), [string]$crgAttrAllEntry.Path, [System.StringComparer]::Ordinal))) {
        $crgAttrFail.Add("$($crgAttrAllEntry.Path): content-transform attribute '$($crgAttrAllEntry.Attribute)' is specified") | Out-Null
      }
    }

    $crgAttrNamed = Invoke-CrgPrivateAttributeGit -Context $crgAttrContext -GitArgs @("--attr-source=$crgAttrTreeOid", 'check-attr', '-z', '--stdin', 'text', 'eol', 'filter', 'ident', 'working-tree-encoding') -InputBytes $crgAttrPathInput
    if ($crgAttrNamed.Exit -ne 0 -or $crgAttrNamed.ErrorText.Length -ne 0) { throw "immutable check-attr named query failed (exit $($crgAttrNamed.Exit)): $($crgAttrNamed.Text.Trim())" }
    $crgAttrNamedEntries = @(& $crgAttrParseTriples $crgAttrNamed.Bytes 'check-attr named query')
    if ($crgAttrNamedEntries.Count -ne ($crgAttrVerifyPaths.Count * 5)) { throw 'check-attr named query returned the wrong bounded inventory' }
    $crgAttrNamedMap = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
    foreach ($crgAttrNamedEntry in $crgAttrNamedEntries) {
      if (-not $crgAttrExpectedPathSet.Contains($crgAttrNamedEntry.Path) -or -not [System.Linq.Enumerable]::Contains([string[]]@('text', 'eol', 'filter', 'ident', 'working-tree-encoding'), [string]$crgAttrNamedEntry.Attribute, [System.StringComparer]::Ordinal)) { throw 'check-attr named query returned an unexpected path or attribute' }
      $crgAttrNamedKey = "$($crgAttrNamedEntry.Path)`0$($crgAttrNamedEntry.Attribute)"
      if ($crgAttrNamedMap.ContainsKey($crgAttrNamedKey)) { throw 'check-attr named query returned a duplicate record' }
      $crgAttrNamedMap[$crgAttrNamedKey] = $crgAttrNamedEntry.Value
    }
    foreach ($crgAttrVerifyPath in $crgAttrVerifyPaths) {
      if (-not [string]::Equals($crgAttrNamedMap["$crgAttrVerifyPath`0text"], 'set', [System.StringComparison]::Ordinal) -or -not [string]::Equals($crgAttrNamedMap["$crgAttrVerifyPath`0eol"], 'lf', [System.StringComparison]::Ordinal)) {
        $crgAttrFail.Add("${crgAttrVerifyPath}: exact text=set/eol=lf contract is absent") | Out-Null
      }
      foreach ($crgAttrUnsafeName in @('filter', 'ident', 'working-tree-encoding')) {
        $crgAttrUnsafeAllowed = if ([System.Linq.Enumerable]::Contains([string[]]@($crgAttrStatePaths), [string]$crgAttrVerifyPath, [System.StringComparer]::Ordinal)) { @('unset', 'unspecified') } else { @('unspecified') }
        if (-not [System.Linq.Enumerable]::Contains([string[]]@($crgAttrUnsafeAllowed), [string]$crgAttrNamedMap["$crgAttrVerifyPath`0$crgAttrUnsafeName"], [System.StringComparer]::Ordinal)) {
          $crgAttrFail.Add("${crgAttrVerifyPath}: $crgAttrUnsafeName is active") | Out-Null
        }
      }
    }

    $crgAttrLfBytes = $crgAttrUtf8.GetBytes("crg-lf-probe`nline2`n")
    $crgAttrCrlfBytes = $crgAttrUtf8.GetBytes("crg-lf-probe`r`nline2`r`n")
    $crgAttrLfOid = Get-CrgGitObjectIdOfBytes -Type blob -Bytes $crgAttrLfBytes -ObjectIdLength $crgAttrOidLength
    [byte[]]$crgAttrSpecialBytes = $crgAttrUtf8.GetBytes(('$Id$' + "`ninstall-values-caf$([char]0x00E9)`n"))
    $crgAttrSpecialOid = Add-CrgPrivateGitObject -Context $crgAttrContext -Type blob -Bytes $crgAttrSpecialBytes
    foreach ($crgAttrVerifyPath in $crgAttrVerifyPaths) {
      foreach ($crgAttrProbe in @(
        [pscustomobject]@{ Label = 'CRLF'; Bytes = $crgAttrCrlfBytes },
        [pscustomobject]@{ Label = 'LF'; Bytes = $crgAttrLfBytes }
      )) {
        $crgAttrProbeRun = Invoke-CrgPrivateAttributeGit -Context $crgAttrContext -GitArgs @("--attr-source=$crgAttrTreeOid", '-c', 'core.autocrlf=true', 'hash-object', "--path=$crgAttrVerifyPath", '--stdin') -InputBytes $crgAttrProbe.Bytes
        if ($crgAttrProbeRun.Exit -ne 0 -or $crgAttrProbeRun.ErrorText.Length -ne 0 -or -not [string]::Equals($crgAttrProbeRun.OutputText.Trim(), $crgAttrLfOid, [System.StringComparison]::Ordinal)) {
          $crgAttrFail.Add("${crgAttrVerifyPath}: $($crgAttrProbe.Label) bytes do not resolve to the exact LF object under the immutable conversion domain") | Out-Null
        }
      }
      $crgAttrCheckoutRun = Invoke-CrgPrivateAttributeGit -Context $crgAttrContext -GitArgs @("--attr-source=$crgAttrTreeOid", '-c', 'core.autocrlf=true', 'cat-file', '--filters', "--path=$crgAttrVerifyPath", $crgAttrSpecialOid)
      if ($crgAttrCheckoutRun.Exit -ne 0 -or $crgAttrCheckoutRun.ErrorText.Length -ne 0 -or
          -not (Compare-CrgInstallValueBytes -Left ([byte[]]$crgAttrCheckoutRun.Bytes) -Right $crgAttrSpecialBytes)) {
        $crgAttrFail.Add("${crgAttrVerifyPath}: checkout does not preserve strict UTF-8 LF, literal `$Id`$, and non-ASCII bytes exactly") | Out-Null
      }
    }
    if ($crgRenderOutputAuthority.Family -ceq 'TRACKED') {
      Assert-CrgLiveInstallValuesAttributeGraph -RepoRoot $targetRepoAbs -ScratchRoot $crgProofScratchParent -AttributeBuffers $crgAttrBuffers -ObjectIdLength $crgAttrOidLength
    }
    $crgAttrVerOk = ($crgAttrFail.Count -eq 0)
    $crgAttrVer = ($crgAttrFail -join '; ')
  } catch {
    $crgAttrVer = "final attribute validation failed at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    $crgAttrVerOk = $false
  } finally {
    if ($null -ne $crgAttrContext -and -not (Close-CrgPrivateAttributeContext -Context $crgAttrContext)) { $crgAttrCleanupOk = $false }
  }
  if (-not $crgAttrCleanupOk) {
    $crgAttrVer = 'the immutable attribute proof namespace could not be cleaned through retained identities'
    $crgAttrVerOk = $false
  }
  $ErrorActionPreference = $crgAttrVerEap
  if (-not $crgAttrVerOk) {
    Write-Error "bootstrap.ps1: the checkout-conversion contract for the gate's tracked checkout surfaces ($($crgAttrVerifyPaths -join ', ')) does not hold after writing the rules (exact text/eol state must be text=set/eol=lf, CRLF must normalize to LF, LF must remain stable, and no filter, ident, or working-tree-encoding attribute may be specified): $($crgAttrVer.Trim()). Reconcile '$crgAttrPath' plus any overriding global, system, or info/attributes rule. Git 2.41 or newer is required for the immutable attribute proof. $crgAttrRerunRemedy"
    exit 1
  }
}
Write-Host ""

}  # end if (-not DispatcherOnly) .gitattributes block

# Install a per-clone dispatcher at .git/hooks/pre-commit. This is the
# structural defense against `git rm scripts/git-hooks/pre-commit`
# slipping past the gate: a commit can edit/delete the in-tree gate
# (which is reviewed data), but it cannot edit the dispatcher (which
# lives outside the working tree, per-clone, not versioned). The
# dispatcher's job is to detect a missing or untracked in-tree gate
# and refuse the commit -- and its own gate-untracking guard refuses
# the STAGED removal of a gate component ahead of every exit path,
# the audited CROSS_REVIEW_SKIP=1 included, unless the operator's
# CROSS_REVIEW_ALLOW_GATE_UNTRACK=1 sanctions exactly that commit
# (the merge gate guards the same removal over every landed range).
# What remains is a deliberate dispatcher edit -- a per-clone manual
# action, not a commit.
#
# DELIBERATELY does NOT set `git config core.hooksPath` (the original
# install method): core.hooksPath pointing at a versioned dir lets a
# `git rm scripts/git-hooks/pre-commit` remove the gate executable
# before git can invoke it, bypassing review with no audit trail.
# The per-clone .git/hooks/pre-commit dispatcher closes that hole.
#
# Both transaction locks were acquired before the pre-mutation trackability,
# index, custody, and routing-source revalidation above. The fixed order and
# retained leases continue through dispatcher, manifest, version, and legacy
# transition publication; every exit below reaches the shared finally.
Push-Location -LiteralPath $targetRepoAbs
try {
  $existingHooksPath = (Invoke-CrgGitUtf8 -GitArgs @('config', '--get', 'core.hooksPath'))
  $hooksPathExit = $LASTEXITCODE
  # Revalidate at the mutation boundary. A configured hooks path is never
  # rewritten by bootstrap: Git's config writer cannot participate in the
  # retained namespace transaction, and any set value would shadow the fixed
  # dispatcher installed below.
  if ((Resolve-HooksPathGuard -ExitCode $hooksPathExit) -cne 'proceed') {
    $crgHooksDisplay = if ($hooksPathExit -eq 0) { "'$($existingHooksPath.Trim())'" } else { "an indeterminate read (exit $hooksPathExit)" }
    Write-Error "bootstrap.ps1: core.hooksPath changed to $crgHooksDisplay after locked preflight. Run: git -C `"$targetRepoAbs`" config --unset core.hooksPath ; resolve any inherited value at its source, then re-run. No dispatcher mutation was performed."
    exit 1
  }

  # Resolve the actual hooks dir: `git rev-parse --git-path hooks/pre-commit`
  # handles regular repos, worktrees (where .git is a file, not a dir),
  # and submodules uniformly.
  $hooksPathRel = (Invoke-CrgGitUtf8 -GitArgs @('rev-parse', '--git-path', 'hooks/pre-commit'))
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($hooksPathRel)) {
    Write-Error "bootstrap.ps1: 'git rev-parse --git-path hooks/pre-commit' failed."
    exit 1
  }
  $hooksPathRel = $hooksPathRel.Trim()
  $dispatcherPath = if ([System.IO.Path]::IsPathRooted($hooksPathRel)) {
    $hooksPathRel
  } else {
    Join-Path $targetRepoAbs $hooksPathRel
  }
  $hooksDir = Split-Path -Parent $dispatcherPath
  $null = Ensure-CrgRootedDirectory -Path $hooksDir -Label 'hooks directory'

  $dispatcherExisted = Test-Path -LiteralPath $dispatcherPath -PathType Leaf
  if ($dispatcherExisted -and -not $Force -and -not $DispatcherOnly) {
    # An existing .git/hooks/pre-commit (from a different install or a
    # prior bootstrap) would shadow the dispatcher this bootstrap is
    # supposed to install. FAIL CLOSED -- printing "Install complete"
    # while the active pre-commit hook is whatever was already there
    # is the same trap as the core.hooksPath case above.
    # -DispatcherOnly overwrites unconditionally: replacing the existing
    # dispatcher (legacy or stale) is that switch's entire purpose, and it
    # was invoked deliberately by name.
    Write-Error "bootstrap.ps1: $dispatcherPath already exists. The bootstrap will NOT overwrite it without -Force, but leaving it in place means the dispatcher this bootstrap is supposed to install never runs. Inspect the existing hook, then either: (a) re-run with -Force to overwrite (BACKUP THE EXISTING HOOK FIRST), (b) re-run with -DispatcherOnly to replace ONLY the dispatcher (no tracked file touched), or (c) chain the existing hook to invoke '$(Join-Path $targetRepoAbs 'scripts/git-hooks/pre-commit')' yourself and skip the dispatcher install."
    exit 1
  } else {
    # Dispatcher content: POSIX sh (runs under git-for-windows bundled
    # sh). Verifies the in-tree gate exists AND is tracked in HEAD;
    # fails closed if either check fails (unless CROSS_REVIEW_SKIP=1 is
    # set for the bootstrap-commit case).
    $dispatcherContent = @'
#!/bin/sh
# cross-review-gate dispatcher (installed by bootstrap.ps1 into
# .git/hooks/pre-commit). NOT versioned -- lives per-clone outside the
# working tree so a commit cannot edit or remove it through the review
# flow. Its job is to detect when the in-tree gate has been removed or
# is untracked and refuse the commit, forcing the audit trail through
# CROSS_REVIEW_SKIP=1.
#
# Compatibility marker only: older installed wrappers require this literal
# before delegation. The dispatcher does not branch on project mode.
# crg-project-mode-capability-v1
# gate-untrack guard capability: crg-gate-untrack-guard-v1
# (docs/local-install-v1.md section 2. The guard capability exists so a
# pre-guard dispatcher -- which honors the audited skip before the tracked hook
# runs -- can never remain authorized after the untracking guard became part of
# the contract. Refresh a legacy dispatcher with
# `bootstrap.ps1 -TargetRepo <repo> -DispatcherOnly`.)

ensure_unix_tool_path() {
  # Git for Windows hooks launched from PowerShell can inherit /cmd without
  # /usr/bin. The dispatcher depends on POSIX tools from /usr/bin (mktemp,
  # rm, chmod, mkdir, date), so repair PATH before any such call.
  for d in /usr/bin /bin; do
    if [ -d "$d" ]; then
      case ":$PATH:" in
        *":$d:"*) ;;
        *) PATH="$d:$PATH" ;;
      esac
    fi
  done
  export PATH
}
ensure_unix_tool_path

# Git replacement refs rewrite commit/tree/blob reads without changing the
# object IDs printed by callers. A Windows process block can carry multiple
# case-variant spellings, so named assignment cannot establish which value a
# native Git child consumes. Remove every raw spelling, install one canonical
# entry, and verify the raw block before the first Git command. Raw entries
# remain inside the pipe parser; only matching variable names cross into the
# parent shell, and no environment snapshot reaches disk.
crg_no_replace_stream() {
  env -0
  _crg_nro_stream_status=$?
  printf '__CRG_NRO_ENUM_STATUS_%s\0' "$_crg_nro_stream_status"
}
crg_no_replace_parse() {
  _crg_nro_action=$1
  case "$_crg_nro_action" in
    names|verify) ;;
    *) return 1 ;;
  esac
  crg_no_replace_stream | (
    _crg_nro_seen_status=0
    _crg_nro_count=0
    _crg_nro_canonical=0
    while :; do
      _crg_nro_entry=
      IFS= read -r -d '' _crg_nro_entry
      _crg_nro_read_status=$?
      if [ "$_crg_nro_read_status" -ne 0 ]; then
        [ -z "$_crg_nro_entry" ] || exit 1
        break
      fi
      case "$_crg_nro_entry" in
        *=*)
          [ "$_crg_nro_seen_status" -eq 0 ] || exit 1
          _crg_nro_name=${_crg_nro_entry%%=*}
          case "$_crg_nro_name" in
            [Gg][Ii][Tt]_[Nn][Oo]_[Rr][Ee][Pp][Ll][Aa][Cc][Ee]_[Oo][Bb][Jj][Ee][Cc][Tt][Ss])
              _crg_nro_count=$((_crg_nro_count + 1))
              if [ "$_crg_nro_entry" = "GIT_NO_REPLACE_OBJECTS=1" ]; then
                _crg_nro_canonical=$((_crg_nro_canonical + 1))
              fi
              if [ "$_crg_nro_action" = "names" ]; then
                printf '%s\n' "$_crg_nro_name" || exit 1
              fi
              ;;
          esac
          ;;
        __CRG_NRO_ENUM_STATUS_0)
          [ "$_crg_nro_seen_status" -eq 0 ] || exit 1
          _crg_nro_seen_status=1
          ;;
        __CRG_NRO_ENUM_STATUS_*)
          exit 1
          ;;
        *)
          exit 1
          ;;
      esac
    done
    [ "$_crg_nro_seen_status" -eq 1 ] || exit 1
    if [ "$_crg_nro_action" = "verify" ]; then
      [ "$_crg_nro_count" -eq 1 ] && [ "$_crg_nro_canonical" -eq 1 ] || exit 1
    fi
    exit 0
  )
  _crg_nro_parse_status=$?
  unset _crg_nro_action
  return "$_crg_nro_parse_status"
}
crg_set_no_replace_singleton() {
  if ! _crg_nro_names=$(crg_no_replace_parse names); then return 1; fi
  unset GIT_NO_REPLACE_OBJECTS || return 1
  _crg_nro_saved_ifs=$IFS
  IFS='
'
  for _crg_nro_name in $_crg_nro_names; do
    case "$_crg_nro_name" in
      [Gg][Ii][Tt]_[Nn][Oo]_[Rr][Ee][Pp][Ll][Aa][Cc][Ee]_[Oo][Bb][Jj][Ee][Cc][Tt][Ss])
        unset "$_crg_nro_name" || {
          IFS=$_crg_nro_saved_ifs
          return 1
        }
        ;;
      *)
        IFS=$_crg_nro_saved_ifs
        return 1
        ;;
    esac
  done
  IFS=$_crg_nro_saved_ifs
  GIT_NO_REPLACE_OBJECTS=1
  export GIT_NO_REPLACE_OBJECTS || return 1
  if ! crg_no_replace_parse verify; then return 1; fi
  unset _crg_nro_names _crg_nro_name _crg_nro_saved_ifs _crg_nro_parse_status
  return 0
}
if ! crg_set_no_replace_singleton; then
  echo "[pre-commit:dispatcher] ERROR: could not establish exactly one canonical GIT_NO_REPLACE_OBJECTS=1 entry before repository inspection; refusing." >&2
  exit 1
fi

# Attribute selectors alter the clean/eol/filter rules used by diff and
# hash-object --path while still returning successful Git statuses. Reject raw
# case-insensitive names before the first repository command.
crg_attribute_selector_state() {
  _crg_as_dump=$(env 2>/dev/null) || return 2
  printf '%s\n' "$_crg_as_dump" | LC_ALL=C awk -F= '
    BEGIN { found = 0 }
    {
      name = tolower($1)
      if (name == "git_attr_source" || name == "git_attr_nosystem") found = 1
    }
    END { exit(found ? 0 : 1) }
  '
  _crg_as_state_rc=$?
  unset _crg_as_dump
  return "$_crg_as_state_rc"
}
crg_attribute_selector_state
_crg_as_rc=$?
if [ "$_crg_as_rc" -eq 0 ]; then
  echo "[pre-commit:dispatcher] ERROR: an ambient Git attribute-resolution selector is set (GIT_ATTR_SOURCE or GIT_ATTR_NOSYSTEM, case-insensitive); refusing before repository inspection." >&2
  exit 1
fi
if [ "$_crg_as_rc" -ne 1 ]; then
  echo "[pre-commit:dispatcher] ERROR: the process environment could not be enumerated while checking Git attribute-resolution selectors; refusing before repository inspection." >&2
  exit 1
fi
unset _crg_as_rc

# Grafts, shallow-file overrides, and an alternate ref backend alter
# parent/range/ref proofs independently of replacement refs. Enumerate raw names
# so case-variant spellings accepted by Git for Windows cannot bypass the
# boundary; no value is evaluated.
crg_history_selector_state() {
  _crg_hs_dump=$(env 2>/dev/null) || return 2
  printf '%s\n' "$_crg_hs_dump" | LC_ALL=C awk -F= '
    BEGIN { found = 0 }
    {
      name = tolower($1)
      if (name == "git_graft_file" || name == "git_shallow_file" ||
          name == "git_reference_backend") found = 1
    }
    END { exit(found ? 0 : 1) }
  '
  _crg_hs_state_rc=$?
  unset _crg_hs_dump
  return "$_crg_hs_state_rc"
}
crg_history_selector_state
_crg_hs_rc=$?
if [ "$_crg_hs_rc" -eq 0 ]; then
  echo "[pre-commit:dispatcher] ERROR: an ambient Git history selector or ref-backend selector is set (GIT_GRAFT_FILE, GIT_SHALLOW_FILE, or GIT_REFERENCE_BACKEND; case-insensitive); refusing before repository inspection." >&2
  exit 1
fi
if [ "$_crg_hs_rc" -ne 1 ]; then
  echo "[pre-commit:dispatcher] ERROR: the process environment could not be enumerated while checking Git history selectors; refusing before repository inspection." >&2
  exit 1
fi
unset _crg_hs_rc

# Windows environment lookup is case-insensitive even though this sh process
# can carry case-distinct spellings. Enumerate and remove every spelling before
# any HEAD hook or wrapper can launch a Windows child process; a plain uppercase
# `unset` leaves lowercase/mixed variants visible to child PowerShell.
crg_clear_retired_mode_env() {
  _crg_ce_all=$(mktemp 2>/dev/null || mktemp -t crg-retired-env-all) || return 1
  _crg_ce_names=$(mktemp 2>/dev/null || mktemp -t crg-retired-env-names) || {
    rm -f "$_crg_ce_all" >/dev/null 2>&1 || :
    return 1
  }
  if ! env > "$_crg_ce_all" 2>/dev/null; then
    rm -f "$_crg_ce_all" "$_crg_ce_names" >/dev/null 2>&1 || :
    return 1
  fi
  if ! LC_ALL=C awk -F= 'tolower($1) == "cross_review_allow_mode_change" { print $1 }' "$_crg_ce_all" > "$_crg_ce_names" 2>/dev/null; then
    rm -f "$_crg_ce_all" "$_crg_ce_names" >/dev/null 2>&1 || :
    return 1
  fi
  while IFS= read -r _crg_ce_name; do
    [ -n "$_crg_ce_name" ] || continue
    unset "$_crg_ce_name" || {
      rm -f "$_crg_ce_all" "$_crg_ce_names" >/dev/null 2>&1 || :
      return 1
    }
  done < "$_crg_ce_names"
  if ! env > "$_crg_ce_all" 2>/dev/null; then
    rm -f "$_crg_ce_all" "$_crg_ce_names" >/dev/null 2>&1 || :
    return 1
  fi
  LC_ALL=C awk -F= '
    tolower($1) == "cross_review_allow_mode_change" { found = 1 }
    END { exit found ? 1 : 0 }
  ' "$_crg_ce_all" >/dev/null 2>&1
  _crg_ce_verify_rc=$?
  if ! rm -f "$_crg_ce_all" "$_crg_ce_names" >/dev/null 2>&1; then return 1; fi
  [ "$_crg_ce_verify_rc" -eq 0 ] || return 1
  return 0
}
if ! crg_clear_retired_mode_env; then
  echo "[pre-commit:dispatcher] ERROR: could not enumerate, clear, and verify every case variant of retired CROSS_REVIEW_ALLOW_MODE_CHANGE before child execution; refusing." >&2
  exit 1
fi

# CHECKED capture: an unchecked root continued empty after a failed probe and
# later authority paths then resolved outside the repository.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || REPO_ROOT=''
if [ -z "$REPO_ROOT" ]; then
  echo "[pre-commit:dispatcher] ERROR: could not resolve the repository root (git rev-parse --show-toplevel failed or printed nothing; indeterminate refuses). Aborting." >&2
  exit 1
fi
unset CROSS_REVIEW_DISPATCH_TREE
CROSS_REVIEW_DISPATCH_TREE=''
if [ "$CROSS_REVIEW_SKIP" = "1" ]; then
  CROSS_REVIEW_DISPATCH_TREE=$(git write-tree 2>/dev/null) || CROSS_REVIEW_DISPATCH_TREE=''
  case "$CROSS_REVIEW_DISPATCH_TREE" in ''|*[!0-9a-f]*) CROSS_REVIEW_DISPATCH_TREE='' ;; esac
  if [ "${#CROSS_REVIEW_DISPATCH_TREE}" -ne 40 ] && [ "${#CROSS_REVIEW_DISPATCH_TREE}" -ne 64 ]; then CROSS_REVIEW_DISPATCH_TREE=''; fi
  if [ -z "$CROSS_REVIEW_DISPATCH_TREE" ]; then
    echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the immutable staged-tree identity could not be captured (indeterminate refuses)." >&2
    exit 1
  fi
  export CROSS_REVIEW_DISPATCH_TREE
fi
crg_skip_tree_stable() {
  [ "$CROSS_REVIEW_SKIP" = "1" ] || return 0
  _crg_st_live=$(git write-tree 2>/dev/null) || return 1
  [ "$_crg_st_live" = "$CROSS_REVIEW_DISPATCH_TREE" ]
}
GATE_HOOK="$REPO_ROOT/scripts/git-hooks/pre-commit"
SKIP_AUDIT_REF='refs/crg-review-skips'
SKIP_AUDIT_TIP=''
SKIP_AUDIT_COMMON_DIR=''

# Git owns the ref transaction, but an already-hostile loose-ref namespace must
# not redirect that write through a filesystem link. Bootstrap retains Git's
# refs root through rooted no-follow handles; every append revalidates the
# common-dir, refs root, optional packed-refs file, fixed loose leaf, and any
# existing reflog ancestors. The exact audit reflog must remain positively
# absent: Git appends an existing reflog even when automatic reflog creation is
# disabled, while this commit chain needs no second audit sink. The
# fixed ref is one leaf directly below refs, so no extra mutable namespace
# directory is introduced.
# A principal concurrently able to rewrite Git metadata remains outside this
# preventive check; post-CAS identity checks make such interference detective.
crg_skip_audit_storage_safe() {
  _crg_ss_common=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || return 1
  case "$_crg_ss_common" in ''|*'
'*) return 1 ;; esac
  _crg_ss_ref_storage=$(git config --local --get extensions.refStorage 2>/dev/null)
  _crg_ss_ref_storage_rc=$?
  case "$_crg_ss_ref_storage_rc" in
    0) [ "$_crg_ss_ref_storage" = files ] || return 1 ;;
    1) ;;
    *) return 1 ;;
  esac
  _crg_ss_refs="$_crg_ss_common/refs"
  for _crg_ss_dir in "$_crg_ss_common" "$_crg_ss_refs"; do
    [ -d "$_crg_ss_dir" ] && [ ! -L "$_crg_ss_dir" ] || return 1
    _crg_ss_link=$(readlink "$_crg_ss_dir" 2>/dev/null) || _crg_ss_link=''
    [ -z "$_crg_ss_link" ] || return 1
  done
  _crg_ss_packed="$_crg_ss_common/packed-refs"
  if [ -e "$_crg_ss_packed" ] || [ -L "$_crg_ss_packed" ]; then
    [ -f "$_crg_ss_packed" ] && [ ! -L "$_crg_ss_packed" ] || return 1
    _crg_ss_link=$(readlink "$_crg_ss_packed" 2>/dev/null) || _crg_ss_link=''
    [ -z "$_crg_ss_link" ] || return 1
  fi
  _crg_ss_leaf="$_crg_ss_refs/crg-review-skips"
  if [ -e "$_crg_ss_leaf" ] || [ -L "$_crg_ss_leaf" ]; then
    [ -f "$_crg_ss_leaf" ] && [ ! -L "$_crg_ss_leaf" ] || return 1
    _crg_ss_link=$(readlink "$_crg_ss_leaf" 2>/dev/null) || _crg_ss_link=''
    [ -z "$_crg_ss_link" ] || return 1
  fi
  _crg_ss_logs="$_crg_ss_common/logs"
  _crg_ss_log_refs="$_crg_ss_logs/refs"
  for _crg_ss_log_dir in "$_crg_ss_logs" "$_crg_ss_log_refs"; do
    if [ -e "$_crg_ss_log_dir" ] || [ -L "$_crg_ss_log_dir" ]; then
      [ -d "$_crg_ss_log_dir" ] && [ ! -L "$_crg_ss_log_dir" ] || return 1
      _crg_ss_link=$(readlink "$_crg_ss_log_dir" 2>/dev/null) || _crg_ss_link=''
      [ -z "$_crg_ss_link" ] || return 1
    fi
  done
  _crg_ss_reflog="$_crg_ss_log_refs/crg-review-skips"
  if [ -e "$_crg_ss_reflog" ] || [ -L "$_crg_ss_reflog" ]; then return 1; fi
  if [ -n "$SKIP_AUDIT_COMMON_DIR" ] && [ "$SKIP_AUDIT_COMMON_DIR" != "$_crg_ss_common" ]; then return 1; fi
  SKIP_AUDIT_COMMON_DIR=$_crg_ss_common
  return 0
}

# Parse the raw commit object, not revision-walk porcelain. A foreign project
# commit, merge, grafted history row, extra header, or merely similar message
# must never become the base of the audit chain. The completion marker retains
# every trailing byte from cat-file; the size check also rejects shell/NUL loss.
CRG_SKIP_VALID_TREE=''
CRG_SKIP_VALID_PARENT=''
crg_validate_skip_audit_commit() {
  _crg_vc_oid=$1
  CRG_SKIP_VALID_TREE=''
  CRG_SKIP_VALID_PARENT=''
  case "$_crg_vc_oid" in ''|*[!0-9a-f]*) return 1 ;; esac
  _crg_vc_oid_len=${#_crg_vc_oid}
  [ "$_crg_vc_oid_len" -eq 40 ] || [ "$_crg_vc_oid_len" -eq 64 ] || return 1
  _crg_vc_size=$(git --no-replace-objects cat-file -s "$_crg_vc_oid" 2>/dev/null) || return 1
  case "$_crg_vc_size" in ''|*[!0-9]*) return 1 ;; esac
  [ "$_crg_vc_size" -ge 1 ] && [ "$_crg_vc_size" -le 4096 ] || return 1
  _crg_vc_mark="__CRG_SKIP_COMMIT_END_$$_$_crg_vc_size"
  _crg_vc_raw=$(
    git --no-replace-objects cat-file commit "$_crg_vc_oid" 2>/dev/null || exit $?
    printf '%s' "$_crg_vc_mark"
  ) || return 1
  case "$_crg_vc_raw" in *"$_crg_vc_mark") ;; *) return 1 ;; esac
  _crg_vc_raw=${_crg_vc_raw%"$_crg_vc_mark"}
  _crg_vc_nl='
'
  case "$_crg_vc_raw" in *"$_crg_vc_nl") ;; *) return 1 ;; esac
  _crg_vc_got_size=$(printf '%s' "$_crg_vc_raw" | wc -c) || return 1
  set -- $_crg_vc_got_size
  [ "$#" -eq 1 ] && [ "$1" = "$_crg_vc_size" ] || return 1
  _crg_vc_row=$(printf '%s' "$_crg_vc_raw" | LC_ALL=C awk -v oidlen="$_crg_vc_oid_len" '
    function oid_ok(s) { return length(s) == oidlen && s !~ /[^0-9a-f]/ }
    { if ($0 ~ /[^ -~]/) bad = 1; line[NR] = $0 }
    END {
      i = 1
      if (substr(line[i], 1, 5) != "tree ") bad = 1
      tree = substr(line[i++], 6)
      if (!oid_ok(tree)) bad = 1
      parent = ""
      if (substr(line[i], 1, 7) == "parent ") {
        parent = substr(line[i++], 8)
        if (!oid_ok(parent)) bad = 1
      }
      author = line[i++]
      committer = line[i++]
      if (author !~ /^author Cross Review Gate <cross-review-gate@invalid> [0-9][0-9]* [+]0000$/) bad = 1
      if (committer !~ /^committer Cross Review Gate <cross-review-gate@invalid> [0-9][0-9]* [+]0000$/) bad = 1
      sub(/^author /, "", author)
      sub(/^committer /, "", committer)
      if (author != committer) bad = 1
      if (line[i++] != "") bad = 1
      if (line[i++] != "crg-review-skip-audit v1") bad = 1
      if (substr(line[i], 1, 8) != "reason: ") bad = 1
      reason = substr(line[i++], 9)
      if (reason == "" || length(reason) > 64 || reason ~ /[^a-z0-9-]/) bad = 1
      if (substr(line[i], 1, 11) != "timestamp: ") bad = 1
      stamp = substr(line[i++], 12)
      if (stamp !~ /^[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z$/) bad = 1
      if (substr(line[i], 1, 8) != "writer: ") bad = 1
      writer = substr(line[i++], 9)
      if (writer == "" || length(writer) > 20 || writer ~ /[^0-9]/) bad = 1
      if (substr(line[i], 1, 6) != "base: ") bad = 1
      base = substr(line[i++], 7)
      if (parent == "") { if (base != "none") bad = 1 }
      else if (base != parent) bad = 1
      if (substr(line[i], 1, 6) != "head: ") bad = 1
      head = substr(line[i++], 7)
      if (head != "unborn" && !oid_ok(head)) bad = 1
      if (substr(line[i], 1, 6) != "tree: ") bad = 1
      body_tree = substr(line[i++], 7)
      if (body_tree != tree || i != NR + 1) bad = 1
      if (bad) exit 1
      printf "%s %s", tree, (parent == "" ? "none" : parent)
    }
  ') || return 1
  set -- $_crg_vc_row
  [ "$#" -eq 2 ] || return 1
  CRG_SKIP_VALID_TREE=$1
  CRG_SKIP_VALID_PARENT=$2
  [ "$(git --no-replace-objects cat-file -t "$CRG_SKIP_VALID_TREE" 2>/dev/null)" = tree ] || return 1
  if [ "$CRG_SKIP_VALID_PARENT" != none ]; then
    [ "$(git --no-replace-objects cat-file -t "$CRG_SKIP_VALID_PARENT" 2>/dev/null)" = commit ] || return 1
  fi
  return 0
}

# A successful CAS can be followed immediately by another legitimate writer.
# Accept that race only when the observed tip reaches this writer's exact
# commit through a bounded chain of canonical raw single-parent records.
crg_skip_audit_chain_contains() {
  _crg_cc_tip=$1
  _crg_cc_owned=$2
  _crg_cc_steps=0
  while [ "$_crg_cc_steps" -lt 64 ]; do
    crg_validate_skip_audit_commit "$_crg_cc_tip" || return 1
    [ "$_crg_cc_tip" = "$_crg_cc_owned" ] && return 0
    [ "$CRG_SKIP_VALID_PARENT" != none ] || return 1
    _crg_cc_tip=$CRG_SKIP_VALID_PARENT
    _crg_cc_steps=$((_crg_cc_steps + 1))
  done
  return 1
}

# ---- local-install shape (docs/local-install-v1.md) ----
# A gate file that is UNTRACKED and deliberately IGNORED runs the local
# install shape: the trusted baseline is the operator-written install
# manifest in the per-worktree git dir -- the same commit-proof custody class
# as this dispatcher -- not HEAD. Every step below is fail-closed: no
# hash tool, no manifest, an unknown manifest version, a missing entry,
# and a mismatched digest each answer "not verified", never "assume
# good".
CRG_B64_DECODER=''
crg_init_b64_decoder() {
  command -v base64 >/dev/null 2>&1 || return 1
  if printf '' | base64 --decode >/dev/null 2>&1; then CRG_B64_DECODER=long
  elif printf '' | base64 -d >/dev/null 2>&1; then CRG_B64_DECODER=short
  elif printf '' | base64 -D >/dev/null 2>&1; then CRG_B64_DECODER=bsd
  else return 1
  fi
  return 0
}
crg_b64_decode() {
  case "$CRG_B64_DECODER" in
    long) base64 --decode ;;
    short) base64 -d ;;
    bsd) base64 -D ;;
    *) return 1 ;;
  esac
}
# Capture one pathname open into an ASCII-only shell buffer. Every later hash,
# grammar check, and execution decodes this buffer; no authority pathname is
# reopened after verification. The decoder validation plus exact decoded length
# also rejects malformed base64, binary/NUL truncation, and oversized input.
crg_capture_b64_path() {
  _crg_cb_path=$1
  _crg_cb_max=$2
  CRG_CAPTURE_B64=''
  CRG_CAPTURE_LEN=''
  case "$_crg_cb_max" in ''|*[!0-9]*) return 1 ;; esac
  _crg_cb_raw=$(base64 < "$_crg_cb_path" 2>/dev/null) || return 1
  printf '%s\n' "$_crg_cb_raw" | LC_ALL=C awk '
    $0 !~ /^[A-Za-z0-9+\/=]*\r?$/ { bad = 1 }
    END { exit bad ? 1 : 0 }
  ' || return 1
  _crg_cb_one=$(printf '%s' "$_crg_cb_raw" | tr -d '\r\n') || return 1
  case "$_crg_cb_one" in *[!A-Za-z0-9+\/=]*) return 1 ;; esac
  printf '%s' "$_crg_cb_one" | crg_b64_decode >/dev/null 2>&1 || return 1
  _crg_cb_len=$(printf '%s' "$_crg_cb_one" | crg_b64_decode | wc -c) || return 1
  set -- $_crg_cb_len
  [ "$#" -eq 1 ] || return 1
  _crg_cb_len=$1
  case "$_crg_cb_len" in ''|*[!0-9]*) return 1 ;; esac
  [ "$_crg_cb_len" -le "$_crg_cb_max" ] || return 1
  CRG_CAPTURE_B64=$_crg_cb_one
  CRG_CAPTURE_LEN=$_crg_cb_len
  return 0
}
crg_b64_sha256() {
  _crg_lh_b64=$1
  if command -v sha256sum >/dev/null 2>&1; then
    _crg_lh=$(printf '%s' "$_crg_lh_b64" | crg_b64_decode | sha256sum 2>/dev/null) || return 1
  elif command -v shasum >/dev/null 2>&1; then
    _crg_lh=$(printf '%s' "$_crg_lh_b64" | crg_b64_decode | shasum -a 256 2>/dev/null) || return 1
  else
    return 1
  fi
  _crg_lh=${_crg_lh%% *}
  case "$_crg_lh" in ''|*[!0-9a-f]*) return 1 ;; esac
  [ "${#_crg_lh}" -eq 64 ] || return 1
  printf '%s' "$_crg_lh"
}
crg_text_sha256() {
  _crg_ts_text=$1
  if command -v sha256sum >/dev/null 2>&1; then
    _crg_ts_hash=$(printf '%s' "$_crg_ts_text" | sha256sum 2>/dev/null) || return 1
  elif command -v shasum >/dev/null 2>&1; then
    _crg_ts_hash=$(printf '%s' "$_crg_ts_text" | shasum -a 256 2>/dev/null) || return 1
  else
    return 1
  fi
  _crg_ts_hash=${_crg_ts_hash%% *}
  case "$_crg_ts_hash" in ''|*[!0-9a-f]*) return 1 ;; esac
  [ "${#_crg_ts_hash}" -eq 64 ] || return 1
  printf '%s' "$_crg_ts_hash"
}
# Decode into one shell-owned buffer before any byte is evaluated. The sentinel
# makes command substitution preserve trailing LFs; decoder failure suppresses
# the sentinel and therefore cannot turn a syntactically complete prefix into a
# successful hook execution.
crg_decode_b64_text_exact() {
  _crg_dt_b64=$1
  CRG_DECODED_TEXT=''
  _crg_dt_mark="__CRG_B64_TEXT_END_$$"
  _crg_dt_suffix=$(printf '\n%s' "$_crg_dt_mark")
  _crg_dt_body=$(
    crg_b64_decode <<__CRG_B64_TEXT_EOF
$_crg_dt_b64
__CRG_B64_TEXT_EOF
    _crg_dt_rc=$?
    [ "$_crg_dt_rc" -eq 0 ] || exit "$_crg_dt_rc"
    printf '\n%s' "$_crg_dt_mark"
  ) || return 1
  case "$_crg_dt_body" in
    *"$_crg_dt_suffix") _crg_dt_body=${_crg_dt_body%"$_crg_dt_suffix"} ;;
    *) return 1 ;;
  esac
  CRG_DECODED_TEXT=$_crg_dt_body
  return 0
}
crg_text_byte_length() {
  _crg_tl_text=$1
  _crg_tl_had_lc=${LC_ALL+x}
  _crg_tl_old_lc=${LC_ALL-}
  LC_ALL=C
  export LC_ALL
  _crg_tl_len=${#_crg_tl_text}
  if [ "$_crg_tl_had_lc" = x ]; then LC_ALL=$_crg_tl_old_lc; export LC_ALL; else unset LC_ALL; fi
  printf '%s' "$_crg_tl_len"
}
crg_eval_sha256_text_exact() {
  _crg_es_text=$1
  _crg_es_len=$2
  _crg_es_hash=$3
  shift 3 || return 1
  _crg_es_got_len=$(crg_text_byte_length "$_crg_es_text") || return 1
  [ "$_crg_es_got_len" = "$_crg_es_len" ] || return 1
  _crg_es_got_hash=$(crg_text_sha256 "$_crg_es_text") || return 1
  [ "$_crg_es_got_hash" = "$_crg_es_hash" ] || return 1
  ( eval "$_crg_es_text" )
}
crg_eval_git_blob_text_exact() {
  _crg_eg_text=$1
  _crg_eg_len=$2
  _crg_eg_oid=$3
  shift 3 || return 1
  _crg_eg_got_len=$(crg_text_byte_length "$_crg_eg_text") || return 1
  [ "$_crg_eg_got_len" = "$_crg_eg_len" ] || return 1
  _crg_eg_got_oid=$(printf '%s' "$_crg_eg_text" | git hash-object --stdin 2>/dev/null) || return 1
  [ "$_crg_eg_got_oid" = "$_crg_eg_oid" ] || return 1
  ( eval "$_crg_eg_text" )
}
if ! crg_init_b64_decoder; then
  echo "[pre-commit:dispatcher] ERROR: no exact base64 decoder is available for retained authority buffers; refusing." >&2
  exit 1
fi
crg_local_diagnostic() {
  printf '[CRG-LOCAL:%s] %s: %s\n' "$1" "$2" "$3" >&2
  return 1
}
crg_local_manifest() {
  # PER-WORKTREE git dir (docs/local-install-v1.md section 2): the
  # verified gate files are worktree-local, so a common-dir manifest
  # would let one worktree's reseal or refresh silently invalidate
  # every sibling worktree's baseline. --absolute-git-dir is already
  # absolute, so no re-rooting applies.
  _crg_lm=$(git rev-parse --absolute-git-dir 2>/dev/null) || return 1
  [ -n "$_crg_lm" ] || return 1
  printf '%s' "$_crg_lm/crg-install-manifest"
}
# rc 0 with the digest on stdout when the manifest carries an entry for
# $1. The grammar is LF-ONLY: any CR byte anywhere refuses the whole
# manifest (normalizing CRs would accept headers the format never
# defined), and the header must match byte-exactly.
crg_local_manifest_want() {
  _crg_lw_p="$1"
  _crg_lw_orig=$(crg_local_manifest) || { crg_local_diagnostic MANIFEST-READ "$_crg_lw_p" 'Cannot locate the per-worktree manifest. Check repository access before retrying.'; return 1; }
  [ -f "$_crg_lw_orig" ] || { crg_local_diagnostic MANIFEST-READ "$_crg_lw_p" 'Install manifest is absent or not a file. Run the retained package installer for this worktree.'; return 1; }
  crg_capture_b64_path "$_crg_lw_orig" 1048576 || { crg_local_diagnostic MANIFEST-READ "$_crg_lw_p" 'Cannot capture the bounded install manifest. Check file access and restore verified installation metadata.'; return 1; }
  _crg_lw_m_b64=$CRG_CAPTURE_B64
  _crg_lw_m_len=$CRG_CAPTURE_LEN
  # LOCAL-SHAPE AUTHORIZATION marker, EPOCH-BOUND and PER-COMPONENT:
  # line 2 pins the SHA-256 of the CURRENT manifest bytes (a marker
  # minted for an earlier local epoch dies when any install or reseal
  # republishes the manifest -- a candidate cannot replay an old
  # authorization against a new baseline), and the remaining lines are
  # the AUTHORIZED PATH SET, so a hybrid layout authorizes exactly its
  # local components. Written only by an operator bootstrap or reseal
  # (revoked in place when no local component is observed); the
  # consumed path must be listed. CR detection on RAW BYTES first, the
  # same idiom as the manifest's, then the strict awk grammar.
  _crg_lw_auth="${_crg_lw_orig%crg-install-manifest}crg-local-install"
  [ -f "$_crg_lw_auth" ] || { crg_local_diagnostic AUTH-READ "$_crg_lw_p" 'LOCAL authorization marker is absent or not a file. Run the retained package installer for this worktree.'; return 1; }
  crg_capture_b64_path "$_crg_lw_auth" 1048576 || { crg_local_diagnostic AUTH-READ "$_crg_lw_p" 'Cannot capture the bounded LOCAL authorization marker. Check file access and restore verified installation metadata.'; return 1; }
  _crg_lw_auth_b64=$CRG_CAPTURE_B64
  _crg_lw_auth_len=$CRG_CAPTURE_LEN
  _crg_lw_mh=$(crg_b64_sha256 "$_crg_lw_m_b64") || { crg_local_diagnostic AUTH-HASH "$_crg_lw_p" 'Cannot hash the captured manifest. Restore SHA-256 tooling before retrying.'; return 1; }
  printf '%s' "$_crg_lw_auth_b64" | crg_b64_decode | LC_ALL=C awk -v BINMODE=3 -v n="$_crg_lw_auth_len" -v p="$_crg_lw_p" -v mh="manifest-sha256: $_crg_lw_mh" '
    { bytes += length($0) + 1 }
    $0 ~ /[^ -~]/ { bad = 1; next }
    NR == 1 { if ($0 != "crg-local-install-authorization v1") bad = 1; next }
    NR == 2 {
      if (substr($0, 1, 17) != "manifest-sha256: " || length($0) != 81 || substr($0, 18) ~ /[^0-9a-f]/) bad = 1
      else if ($0 != mh) mismatch = 1
      next
    }
    { if ($0 == "") { bad = 1; next }; if ($0 == p) found = 1 }
    END {
      if (bad || bytes != n || NR < 3) exit 10
      if (mismatch) exit 11
      if (!found) exit 12
    }
  '
  _crg_lw_rc=$?
  case "$_crg_lw_rc" in
    0) ;;
    10) crg_local_diagnostic AUTH-GRAMMAR "$_crg_lw_p" 'LOCAL authorization marker has invalid bytes or records. Restore verified installation metadata.'; return 1 ;;
    11) crg_local_diagnostic AUTH-HASH "$_crg_lw_p" 'LOCAL authorization marker names a different manifest. Reconcile installation metadata with the retained package installer.'; return 1 ;;
    12) crg_local_diagnostic AUTH-PATH "$_crg_lw_p" 'LOCAL authorization marker does not list this component. Run the retained package installer for the intended LOCAL shape.'; return 1 ;;
    *) crg_local_diagnostic AUTH-READ "$_crg_lw_p" 'Cannot parse the captured LOCAL authorization marker. Check decoder and awk availability before retrying.'; return 1 ;;
  esac
  # STRICT whole-file grammar, kept IDENTICAL to the PowerShell readers
  # (Read-CrgInstallManifest / Get-CrgLocalInstallVerifiedBytes): line 2
  # must be an `installed: ` record, and every further line is exactly
  # <64-hex><two spaces><path not starting with a space>. Any junk line,
  # any duplicate path, or a missing record refuses the WHOLE manifest.
  # Field-splitting ($1/$2) is deliberately avoided: it tolerates extra
  # separator spaces and trailing fields the grammar never defined, so a
  # manifest this stage accepted could be refused by a stricter stage
  # later -- one accept set everywhere, byte-anchored substr instead.
  # The first rule pins the byte DOMAIN: printable ASCII plus the LF
  # record separator; any other byte refuses, matching the PowerShell
  # readers raw-byte check (their UTF-8 decode would otherwise collapse
  # distinct invalid byte sequences into one replacement string).
  _crg_lw_want=$(printf '%s' "$_crg_lw_m_b64" | crg_b64_decode | LC_ALL=C awk -v BINMODE=3 -v n="$_crg_lw_m_len" -v p="$_crg_lw_p" '
    { bytes += length($0) + 1 }
    $0 ~ /[^ -~]/ { bad = 1; next }
    NR == 1 { if ($0 != "crg-install-manifest v1" && $0 != "crg-install-manifest v2") bad = 1; next }
    NR == 2 { if ($0 !~ /^installed: [0-9][0-9][0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/) bad = 1; next }
    {
      dig = substr($0, 1, 64); sep = substr($0, 65, 2); path = substr($0, 67)
      if (length($0) < 67 || sep != "  " || dig ~ /[^0-9a-f]/ || substr(path, 1, 1) == " ") { bad = 1; next }
      if (seen[path]++) { bad = 1; next }
      if (path == p) want = dig
    }
    END { if (bad || bytes != n) exit 10; if (want == "") exit 11; printf "%s", want }' 2>/dev/null)
  _crg_lw_rc=$?
  case "$_crg_lw_rc" in
    0) ;;
    10) crg_local_diagnostic MANIFEST-GRAMMAR "$_crg_lw_p" 'Install manifest has invalid bytes or records. Restore verified installation metadata.'; return 1 ;;
    11) crg_local_diagnostic MANIFEST-ENTRY "$_crg_lw_p" 'Install manifest has no entry for this component. Run the retained package installer for this worktree.'; return 1 ;;
    *) crg_local_diagnostic MANIFEST-READ "$_crg_lw_p" 'Cannot parse the captured install manifest. Check decoder and awk availability before retrying.'; return 1 ;;
  esac
  [ -n "$_crg_lw_want" ] || { crg_local_diagnostic MANIFEST-READ "$_crg_lw_p" 'Manifest parser returned no digest after success. Restore parser tooling before retrying.'; return 1; }
  printf '%s' "$_crg_lw_want"
}
# Capture and verify one local payload without any post-verification pathname
# read. Callers separately prove the appropriate tracked/ignored shape.
crg_local_install_buffer() {
  _crg_ls_p=$1
  CRG_LOCAL_INSTALL_B64=''
  CRG_LOCAL_INSTALL_LEN=''
  CRG_LOCAL_INSTALL_SHA=''
  _crg_ls_want=$(crg_local_manifest_want "$_crg_ls_p") || return 1
  crg_capture_b64_path "$REPO_ROOT/$_crg_ls_p" 16777216 || { crg_local_diagnostic SNAPSHOT-CREATE "$_crg_ls_p" 'Cannot capture the complete bounded local component. Check file access and size before retrying.'; return 1; }
  _crg_ls_got=$(crg_b64_sha256 "$CRG_CAPTURE_B64") || { crg_local_diagnostic SNAPSHOT-HASH "$_crg_ls_p" 'Cannot hash the captured local component. Restore SHA-256 tooling before retrying.'; return 1; }
  [ "$_crg_ls_got" = "$_crg_ls_want" ] || { crg_local_diagnostic SNAPSHOT-HASH "$_crg_ls_p" 'Captured local component differs from the install manifest. Investigate local edits, then refresh from the retained package.'; return 1; }
  CRG_LOCAL_INSTALL_B64=$CRG_CAPTURE_B64
  CRG_LOCAL_INSTALL_LEN=$CRG_CAPTURE_LEN
  CRG_LOCAL_INSTALL_SHA=$_crg_ls_got
  return 0
}

# Append one immutable skip-audit commit through a compare-and-swap update of
# the fixed local audit ref. The commit uses the already verified staged tree,
# links to the previous audit tip, and carries a bounded canonical identity
# record. No candidate-controlled worktree pathname is an audit sink.
write_skip_log() {
  _crg_sl_reason=$1
  if [ "${GIT_NO_REPLACE_OBJECTS-}" != 1 ]; then
    echo "[pre-commit:dispatcher] ERROR: raw skip-audit object validation lost GIT_NO_REPLACE_OBJECTS=1; refusing." >&2
    return 1
  fi
  case "$_crg_sl_reason" in ''|*[!a-z0-9-]*)
    echo "[pre-commit:dispatcher] ERROR: the skip-audit reason is not one bounded canonical token; refusing." >&2
    return 1 ;;
  esac
  [ "${#_crg_sl_reason}" -le 64 ] || {
    echo "[pre-commit:dispatcher] ERROR: the skip-audit reason exceeds its 64-byte bound; refusing." >&2
    return 1
  }
  if ! crg_skip_audit_storage_safe; then
    echo "[pre-commit:dispatcher] ERROR: the fixed skip-audit ref storage is not one stable ordinary files-backend namespace; refusing." >&2
    return 1
  fi
  if ! crg_skip_tree_stable; then
    echo "[pre-commit:dispatcher] ERROR: the live index moved away from the dispatcher-owned staged tree before skip logging; refusing." >&2
    return 1
  fi
  _crg_sl_tree=$CROSS_REVIEW_DISPATCH_TREE
  case "${#_crg_sl_tree}" in
    40) _crg_sl_zero=0000000000000000000000000000000000000000 ;;
    64) _crg_sl_zero=0000000000000000000000000000000000000000000000000000000000000000 ;;
    *) echo "[pre-commit:dispatcher] ERROR: the dispatcher-owned staged tree has an unsupported object-id length; refusing." >&2; return 1 ;;
  esac
  _crg_sl_head_state=$(_crg_head_born)
  case "$_crg_sl_head_state" in
    born)
      _crg_sl_head=$(git --no-replace-objects rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || _crg_sl_head=''
      case "$_crg_sl_head" in ''|*[!0-9a-f]*) _crg_sl_head='' ;; esac
      [ "${#_crg_sl_head}" -eq "${#_crg_sl_tree}" ] || _crg_sl_head=''
      ;;
    unborn) _crg_sl_head=unborn ;;
    *) _crg_sl_head='' ;;
  esac
  _crg_sl_time=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || _crg_sl_time=''
  case "$_crg_sl_time" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
    *) _crg_sl_time='' ;;
  esac
  if [ -z "$_crg_sl_head" ] || [ -z "$_crg_sl_time" ]; then
    echo "[pre-commit:dispatcher] ERROR: could not produce the bounded skip-audit head/time identity (indeterminate refuses)." >&2
    return 1
  fi
  _crg_sl_writer=$$
  case "$_crg_sl_writer" in ''|*[!0-9]*)
    echo "[pre-commit:dispatcher] ERROR: could not produce the bounded skip-audit writer identity; refusing." >&2
    return 1 ;;
  esac
  [ "${#_crg_sl_writer}" -le 20 ] || {
    echo "[pre-commit:dispatcher] ERROR: the skip-audit writer identity exceeds its 20-byte bound; refusing." >&2
    return 1
  }

  _crg_sl_try=0
  while [ "$_crg_sl_try" -lt 16 ]; do
    _crg_sl_try=$((_crg_sl_try + 1))
    if ! crg_skip_audit_storage_safe; then
      echo "[pre-commit:dispatcher] ERROR: the fixed skip-audit ref storage changed or became non-ordinary during publication; refusing." >&2
      return 1
    fi
    if ! crg_skip_tree_stable; then
      echo "[pre-commit:dispatcher] ERROR: the live index moved away from the dispatcher-owned staged tree during skip-audit publication; refusing." >&2
      return 1
    fi
    git symbolic-ref -q "$SKIP_AUDIT_REF" >/dev/null 2>&1
    _crg_sl_sym_rc=$?
    if [ "$_crg_sl_sym_rc" -eq 0 ]; then
      echo "[pre-commit:dispatcher] ERROR: $SKIP_AUDIT_REF is a symbolic ref (including a dangling one); refusing to follow, replace, or adopt it." >&2
      return 1
    elif [ "$_crg_sl_sym_rc" -ne 1 ]; then
      echo "[pre-commit:dispatcher] ERROR: $SKIP_AUDIT_REF could not be classified as a direct ref or positive absence; refusing." >&2
      return 1
    fi
    git show-ref --verify --quiet "$SKIP_AUDIT_REF" 2>/dev/null
    _crg_sl_ref_rc=$?
    if [ "$_crg_sl_ref_rc" -eq 0 ]; then
      _crg_sl_base=$(git show-ref --verify --hash "$SKIP_AUDIT_REF" 2>/dev/null) || {
        # A concurrent canonical writer may remove/recreate the direct ref
        # between the existence probe and value read. Reclassify within the
        # bounded loop; malformed or symbolic occupants still refuse below.
        continue
      }
      case "$_crg_sl_base" in ''|*[!0-9a-f]*) _crg_sl_base='' ;; esac
      if [ "${#_crg_sl_base}" -ne "${#_crg_sl_tree}" ] || ! crg_validate_skip_audit_commit "$_crg_sl_base"; then
        echo "[pre-commit:dispatcher] ERROR: $SKIP_AUDIT_REF does not name one canonical raw skip-audit commit; refusing to adopt or replace it." >&2
        return 1
      fi
      _crg_sl_expect=$_crg_sl_base
      _crg_sl_base_field=$_crg_sl_base
    elif [ "$_crg_sl_ref_rc" -eq 1 ]; then
      # show-ref --quiet distinguishes normal resolution statuses, but rc=1
      # alone is not an atomic proof that the direct ref name is unoccupied.
      # A verify-only, no-deref reference transaction supplies that proof.
      # Failure is a race or foreign occupant, so reclassify without adopting.
      if ! printf 'verify %s %s\n' "$SKIP_AUDIT_REF" "$_crg_sl_zero" |
        git --no-replace-objects -c core.hooksPath=/dev/null -c core.logAllRefUpdates=false update-ref --no-deref --stdin >/dev/null 2>&1; then
        continue
      fi
      _crg_sl_expect=$_crg_sl_zero
      _crg_sl_base_field=none
    else
      echo "[pre-commit:dispatcher] ERROR: $SKIP_AUDIT_REF could not be classified; refusing." >&2
      return 1
    fi

    _crg_sl_message="crg-review-skip-audit v1
reason: $_crg_sl_reason
timestamp: $_crg_sl_time
writer: $_crg_sl_writer
base: $_crg_sl_base_field
head: $_crg_sl_head
tree: $_crg_sl_tree"
    if [ "$_crg_sl_base_field" = none ]; then
      _crg_sl_commit=$(GIT_AUTHOR_NAME='Cross Review Gate' GIT_AUTHOR_EMAIL='cross-review-gate@invalid' GIT_AUTHOR_DATE="$_crg_sl_time" GIT_COMMITTER_NAME='Cross Review Gate' GIT_COMMITTER_EMAIL='cross-review-gate@invalid' GIT_COMMITTER_DATE="$_crg_sl_time" git --no-replace-objects -c core.hooksPath=/dev/null -c i18n.commitEncoding=UTF-8 commit-tree "$_crg_sl_tree" -m "$_crg_sl_message" 2>/dev/null) || _crg_sl_commit=''
    else
      _crg_sl_commit=$(GIT_AUTHOR_NAME='Cross Review Gate' GIT_AUTHOR_EMAIL='cross-review-gate@invalid' GIT_AUTHOR_DATE="$_crg_sl_time" GIT_COMMITTER_NAME='Cross Review Gate' GIT_COMMITTER_EMAIL='cross-review-gate@invalid' GIT_COMMITTER_DATE="$_crg_sl_time" git --no-replace-objects -c core.hooksPath=/dev/null -c i18n.commitEncoding=UTF-8 commit-tree "$_crg_sl_tree" -p "$_crg_sl_base" -m "$_crg_sl_message" 2>/dev/null) || _crg_sl_commit=''
    fi
    case "$_crg_sl_commit" in ''|*[!0-9a-f]*) _crg_sl_commit='' ;; esac
    if [ "${#_crg_sl_commit}" -ne "${#_crg_sl_tree}" ] || ! crg_validate_skip_audit_commit "$_crg_sl_commit" || [ "$CRG_SKIP_VALID_TREE" != "$_crg_sl_tree" ] || [ "$CRG_SKIP_VALID_PARENT" != "$_crg_sl_base_field" ]; then
      echo "[pre-commit:dispatcher] ERROR: the content-addressed skip-audit commit could not be created and verified; refusing." >&2
      return 1
    fi
    if ! crg_skip_tree_stable || ! crg_skip_audit_storage_safe; then
      echo "[pre-commit:dispatcher] ERROR: staged-tree or fixed-ref storage custody changed immediately before skip-audit publication; refusing." >&2
      return 1
    fi
    if git --no-replace-objects -c core.hooksPath=/dev/null -c core.logAllRefUpdates=false update-ref --no-deref "$SKIP_AUDIT_REF" "$_crg_sl_commit" "$_crg_sl_expect" >/dev/null 2>&1; then
      if ! crg_skip_audit_storage_safe; then
        echo "[pre-commit:dispatcher] ERROR: fixed-ref storage changed immediately after skip-audit publication; refusing." >&2
        return 1
      fi
      _crg_sl_tip=$(git show-ref --verify --hash "$SKIP_AUDIT_REF" 2>/dev/null) || _crg_sl_tip=''
      git symbolic-ref -q "$SKIP_AUDIT_REF" >/dev/null 2>&1
      _crg_sl_post_sym_rc=$?
      _crg_sl_tip_check=$(git show-ref --verify --hash "$SKIP_AUDIT_REF" 2>/dev/null) || _crg_sl_tip_check=''
      git symbolic-ref -q "$SKIP_AUDIT_REF" >/dev/null 2>&1
      _crg_sl_post_sym_rc2=$?
      if [ "$_crg_sl_post_sym_rc" -ne 1 ] || [ "$_crg_sl_post_sym_rc2" -ne 1 ] || [ "$_crg_sl_tip_check" != "$_crg_sl_tip" ]; then
        echo "[pre-commit:dispatcher] ERROR: $SKIP_AUDIT_REF did not remain one stable direct ref after publication; refusing." >&2
        return 1
      fi
      if [ "$_crg_sl_tip" != "$_crg_sl_commit" ]; then
        if [ "${#_crg_sl_tip}" -ne "${#_crg_sl_tree}" ] || ! crg_skip_audit_chain_contains "$_crg_sl_tip" "$_crg_sl_commit"; then
          echo "[pre-commit:dispatcher] ERROR: $SKIP_AUDIT_REF no longer reaches the exact committed audit entry through a bounded canonical single-parent chain; refusing." >&2
          return 1
        fi
      fi
      SKIP_AUDIT_TIP=$_crg_sl_commit
      return 0
    fi
  done
  echo "[pre-commit:dispatcher] ERROR: concurrent writers prevented a compare-and-swap append to $SKIP_AUDIT_REF after 16 retries; refusing." >&2
  return 1
}

# Mirror of the in-tree gate's staged-routing-driver skip refusal: the
# skip early-exits below run when the tracked hook is missing or not in
# HEAD, so without this mirror a staged scripts/run-gate.sh edit could
# ride CROSS_REVIEW_SKIP=1 past the hook that carries the refusal simply
# by removing the working-tree hook first. An ADDED driver (no HEAD
# baseline) stays admissible - the bootstrap install commit depends on
# the skip.
# Is HEAD BORN? -- born | unborn | error, mirroring the tracked hook's
# crg_head_born. `unborn` is only ever POSITIVE proof (a symbolic HEAD whose
# branch ref does not exist); a failed resolution is `error`, because an
# unreadable ref and a corrupt object are indistinguishable from an empty
# repository at the `rev-parse` status alone, and reading them as empty let a
# staged driver edit land through the audited skip unreviewed.
_crg_head_born() {
  if git rev-parse -q --verify HEAD >/dev/null 2>&1; then echo born; return 0; fi
  _crg_hb_ref=$(git symbolic-ref -q HEAD 2>/dev/null); _crg_hb_sr=$?
  if [ "$_crg_hb_sr" -ne 0 ] || [ -z "$_crg_hb_ref" ]; then echo error; return 0; fi
  git show-ref --verify --quiet "$_crg_hb_ref" 2>/dev/null; _crg_hb_sh=$?
  case "$_crg_hb_sh" in
    1) echo unborn ;;
    *) echo error ;;
  esac
}

crg_skip_refuses_driver_edit() {
  # PAIRWISE divergence probes plus an EXHAUSTIVE baseline walk: an
  # indeterminate probe refuses (an operational failure must never
  # read as no-baseline), an unborn HEAD classifies against the EMPTY
  # baseline instead of falling open (the worktree copy already ran
  # before any hook, born branch or not), a no-baseline present
  # unstaged driver is the LOCAL shape and must match its manifest
  # entry, and a staged initial ADD is admissible only when the
  # RAW worktree bytes ARE the staged blob (benign staged bytes must not
  # mask a dirty driver that already ran). A combined HEAD-vs-worktree
  # diff would cancel a staged edit shadowed by an unstaged revert
  # while the staged edit still lands. Only regular files are
  # admissible anywhere: the divergence probes compare a tracked
  # symlink's target PATHNAME, never the pointed-at bytes, and a
  # FIFO or device occupant reads as ABSENT to `-f` while still able
  # to supply executable bytes.
  # Candidate LF-contract validation reads only immutable blobs from the
  # dispatcher-owned staged tree. No candidate rule or probe is materialized at
  # a pathname that Git can reopen. The bounded parser is deliberately
  # conservative: relevant nested attribute files must contain only blank or
  # comment lines, macro definitions and every filter/ident/WTE token refuse,
  # and the installer-authored literal rule must be the final applicable root
  # rule. The exact three-record V21 values suffix is accepted after that rule;
  # those fixed literals cannot apply to either sh surface. Existing unrelated
  # root rules before the installer-owned suffix remain admissible.
  _crg_sd_attr_ok_for() {
    _crg_sd_surf=$1
    for _crg_sd_af in .gitattributes scripts/.gitattributes scripts/git-hooks/.gitattributes; do
      _crg_sd_afe=$(git ls-tree "$CROSS_REVIEW_DISPATCH_TREE" -- "$_crg_sd_af" 2>/dev/null) || return 2
      if [ -z "$_crg_sd_afe" ]; then
        [ "$_crg_sd_af" != .gitattributes ] || return 1
        continue
      fi
      set -- $_crg_sd_afe
      if [ "$#" -ne 4 ] || [ "$2" != blob ] || [ "$4" != "$_crg_sd_af" ]; then return 2; fi
      case "$1" in
        100644|100755) ;;
        *) return 1 ;;
      esac
      _crg_sd_aoid=$3
      case "$_crg_sd_aoid" in ''|*[!0-9a-f]*) return 2 ;; esac
      [ "${#_crg_sd_aoid}" -eq "${#CROSS_REVIEW_DISPATCH_TREE}" ] || return 2
      _crg_sd_asize=$(git cat-file -s "$_crg_sd_aoid" 2>/dev/null) || return 2
      case "$_crg_sd_asize" in ''|*[!0-9]*) return 2 ;; esac
      [ "$_crg_sd_asize" -le 1048576 ] || return 1
      if [ "$_crg_sd_af" = .gitattributes ]; then
        git cat-file blob "$_crg_sd_aoid" 2>/dev/null | LC_ALL=C awk -v BINMODE=3 -v n="$_crg_sd_asize" -v surf="$_crg_sd_surf" '
          BEGIN {
            values = "CROSS-REVIEW-VALUES.md text eol=lf -filter -ident -working-tree-encoding"
            prompt = "scripts/codex/review-prompt-template.md text eol=lf -filter -ident -working-tree-encoding"
            agents = "docs/AGENTS.md.template text eol=lf -filter -ident -working-tree-encoding"
          }
          { bytes += length($0) + 1 }
          $0 ~ /[^ -~]/ { bad = 1; next }
          $0 == "" || $0 ~ /^#/ { next }
          $0 ~ /^\[attr\]/ { bad = 1 }
          $0 ~ /(^|[ \t])[-!]?(filter|ident|working-tree-encoding)(=|[ \t]|$)/ {
            if ($0 == values) value_count++
            else if ($0 == prompt) prompt_count++
            else if ($0 == agents) agent_count++
            else bad = 1
          }
          { fifth = fourth; fourth = third; third = second; second = last; last = $0 }
          END {
            want = surf " text eol=lf"
            tailok = (last == want)
            if (surf == "scripts/run-gate.sh" && second == want && last == "scripts/git-hooks/pre-commit text eol=lf") tailok = 1
            suffix = (third == values && second == prompt && last == agents)
            fixed_count = value_count + prompt_count + agent_count
            if (fixed_count != 0 && !(suffix && value_count == 1 && prompt_count == 1 && agent_count == 1)) bad = 1
            if (suffix) {
              if (fourth == want) tailok = 1
              if (surf == "scripts/run-gate.sh" && fifth == want && fourth == "scripts/git-hooks/pre-commit text eol=lf") tailok = 1
            }
            exit (bad || bytes != n || !tailok) ? 1 : 0
          }
        ' || return 1
      else
        git cat-file blob "$_crg_sd_aoid" 2>/dev/null | LC_ALL=C awk -v BINMODE=3 -v n="$_crg_sd_asize" '
          { bytes += length($0) + 1 }
          $0 ~ /[^ -~]/ { bad = 1; next }
          $0 != "" && $0 !~ /^#/ { bad = 1 }
          END { exit (bad || bytes != n) ? 1 : 0 }
        ' || return 1
      fi
      _crg_sd_asize2=$(git cat-file -s "$_crg_sd_aoid" 2>/dev/null) || return 2
      [ "$_crg_sd_asize2" = "$_crg_sd_asize" ] || return 2
    done
    return 0
  }
  for _crg_sd_shp in scripts/run-gate.sh scripts/git-hooks/pre-commit; do
    _crg_sd_sht=$(git ls-tree "$CROSS_REVIEW_DISPATCH_TREE" -- "$_crg_sd_shp" 2>/dev/null) || return 0
    [ -n "$_crg_sd_sht" ] || continue
    # Staged OBJECT MODE is part of the contract for every sh surface, the
    # tracked hook included: this dispatcher accepts only HEAD's regular
    # hook blob and evaluates an OID-verified shell buffer, so a staged
    # symlink-mode entry must never land.
    case "$_crg_sd_sht" in
      100644\ *|100755\ *) ;;
      *) return 0 ;;
    esac
    _crg_sd_attr_ok_for "$_crg_sd_shp" || return 0
  done
  if [ -L "scripts/run-gate.sh" ]; then return 0; fi
  # A FIFO/device/directory occupant refuses here, BEFORE any probe
  # opens the path: `-f` reads those shapes as absent, and opening a
  # FIFO hangs.
  if [ -e "scripts/run-gate.sh" ] && [ ! -f "scripts/run-gate.sh" ]; then return 0; fi
  _crg_sd_ix=$(git ls-tree "$CROSS_REVIEW_DISPATCH_TREE" -- "scripts/run-gate.sh" 2>/dev/null) || return 0
  _crg_sd_ioid=''
  if [ -n "$_crg_sd_ix" ]; then
    set -- $_crg_sd_ix
    if [ "$#" -ne 4 ] || [ "$2" != blob ] || [ "$4" != scripts/run-gate.sh ]; then return 0; fi
    case "$1" in 100644|100755) ;; *) return 0 ;; esac
    _crg_sd_ioid=$3
    case "$_crg_sd_ioid" in ''|*[!0-9a-f]*) return 0 ;; esac
    [ "${#_crg_sd_ioid}" -eq "${#CROSS_REVIEW_DISPATCH_TREE}" ] || return 0
  fi
  # A failed HEAD resolution is NOT proof of an empty baseline (an unreadable
  # ref or a corrupt object fails the same way), and treating it as one sent a
  # BORN repository into the initial-add arm, where a staged driver edit whose
  # worktree matches its index landed through the audited skip unreviewed
  # (merge-panel BLOCKER 2026-08-30). `return 0` here means "this guard does
  # not fire"; an indeterminate HEAD must therefore refuse, not return.
  _crg_sd_born=$(_crg_head_born)
  if [ "$_crg_sd_born" = error ]; then
    echo "[pre-commit:dispatcher] ERROR: whether HEAD is born could not be established while classifying routing driver 'scripts/run-gate.sh' (a failed HEAD resolution is NOT proof of an empty baseline; indeterminate refuses)." >&2
    exit 1
  fi
  if [ "$_crg_sd_born" = born ]; then
    _crg_sd_ls=$(git ls-tree HEAD -- "scripts/run-gate.sh" 2>/dev/null) || return 0
    if [ -n "$_crg_sd_ls" ]; then
      case "$_crg_sd_ls" in
        100644\ *|100755\ *) ;;
        *) return 0 ;;
      esac
      # Staged-tree-vs-HEAD compares immutable rows (filter-free); the
      # worktree side runs in the RAW byte domain -- `git diff`
      # applies clean filters and EOL normalization, so a transformed
      # working copy could read clean while the EXECUTED bytes differ
      # from the staged blob (--stdin carries no path, so no
      # attribute or filter mediates the hash).
      # TRI-STATE: 0 unchanged, 1 staged (refuse), anything else an
      # indeterminate probe -- refused through the same return, never
      # read as unchanged.
      [ "$_crg_sd_ix" = "$_crg_sd_ls" ] || return 0
      [ -f "scripts/run-gate.sh" ] || return 0
      _crg_sd_ow=$(git hash-object --stdin < "scripts/run-gate.sh" 2>/dev/null) || return 0
      [ "$_crg_sd_ioid" = "$_crg_sd_ow" ] || return 0
      return 1
    fi
  fi
  # No HEAD baseline (absent from a born HEAD, or the branch is POSITIVELY
  # unborn -- an indeterminate HEAD already refused above, so it can never
  # reach this arm): classify the index/worktree pair exhaustively.
  if [ -n "$_crg_sd_ix" ]; then
    # Staged initial ADD - admissible only with raw worktree==index
    # byte identity on a present regular file (same raw-domain
    # rationale as the tracked branch above).
    [ -f "scripts/run-gate.sh" ] || return 0
    _crg_sd_ow=$(git hash-object --stdin < "scripts/run-gate.sh" 2>/dev/null) || return 0
    [ "$_crg_sd_ioid" = "$_crg_sd_ow" ] || return 0
    return 1
  fi
  if [ -f "scripts/run-gate.sh" ]; then
    # Present, unstaged, no baseline: the LOCAL shape's FULL predicate
    # set (untracked + ignored + snapshot-hash match, the
    # authoritative verifier's contract) - an exposed byte-matching
    # copy still refuses.
    git check-ignore -q -- "scripts/run-gate.sh" 2>/dev/null
    _crg_sd_ignore_rc=$?
    case "$_crg_sd_ignore_rc" in
      0) ;;
      1) crg_local_diagnostic IGNORE-STATE scripts/run-gate.sh 'Local routing driver is not ignored. Restore the intended LOCAL exclude rule before retrying.'; return 0 ;;
      *) crg_local_diagnostic IGNORE-STATE scripts/run-gate.sh 'Cannot inspect the local routing driver ignore state. Check Git configuration and repository access before retrying.'; return 0 ;;
    esac
    crg_local_install_buffer "scripts/run-gate.sh" || return 0
  fi
  return 1
}

# A refreshed dispatcher can encounter a trusted HEAD whose tracked review
# kernel still enforces the retired project-mode work-blocking contract.
# Candidate tracked files cannot govern their own landing, so one bounded,
# identity-attested transition replaces the exact changed review-kernel
# entries (plus .gitattributes only when the LF contract needs to change). The
# dispatcher owns this bridge because delegating that particular commit to the
# old HEAD hook would revive the policy being retired. Ordinary non-skip commits
# still delegate. A generic audited skip delegates only when trusted HEAD carries
# the exact dispatcher staged-tree handoff capability; pre-handoff legacy kernels
# refuse generic skips while this record-bound transition remains available.
crg_legacy_review_kernel_state() {
  _crg_lk_born=$(_crg_head_born)
  case "$_crg_lk_born" in
    unborn) return 1 ;;
    born) ;;
    *) return 2 ;;
  esac
  for _crg_lk_hp in \
    scripts/git-hooks/pre-commit \
    scripts/codex/auto-review.ps1 \
    scripts/claude/auto-review.ps1 \
    scripts/codex/review-prompt-template.md
  do
    _crg_lk_tree=$(git ls-tree HEAD -- "$_crg_lk_hp" 2>/dev/null); _crg_lk_tree_rc=$?
    [ "$_crg_lk_tree_rc" -eq 0 ] || return 2
    [ -n "$_crg_lk_tree" ] || continue
    case "$_crg_lk_tree" in
      100644\ blob\ *|100755\ blob\ *) ;;
      *) return 2 ;;
    esac
    git grep -q \
      -e 'crg_pm_staged_touches_declaration' \
      -e 'function Test-ProjectModeBranchRange' \
      -e 'Green is campaign-anchored' \
      HEAD -- "$_crg_lk_hp" 2>/dev/null
    _crg_lk_rc=$?
    case "$_crg_lk_rc" in
      0) return 0 ;;
      1) ;;
      *) return 2 ;;
    esac
  done
  return 1
}

crg_legacy_review_kernel_touched() {
  git diff --quiet --no-ext-diff --no-textconv --no-renames --ignore-submodules=none HEAD "$CROSS_REVIEW_DISPATCH_TREE" -- \
    scripts/git-hooks/pre-commit \
    scripts/codex/auto-review.ps1 \
    scripts/claude/auto-review.ps1 \
    scripts/codex/review-prompt-template.md \
    scripts/review-liveness.psm1 \
    scripts/review-common.ps1 2>/dev/null
  _crg_lk_touch_rc=$?
  case "$_crg_lk_touch_rc" in
    0) return 1 ;;
    1) return 0 ;;
    *) return 2 ;;
  esac
}

crg_legacy_review_kernel_stage() {
  _crg_lk_gitdir=$(git rev-parse --git-dir 2>/dev/null) || return 2
  [ -n "$_crg_lk_gitdir" ] || return 2
  _crg_lk_record="$_crg_lk_gitdir/crg-review-kernel-transition"
  [ -f "$_crg_lk_record" ] && [ ! -L "$_crg_lk_record" ] || return 1
  crg_capture_b64_path "$_crg_lk_record" 2048 || return 2
  _crg_lk_record_b64=$CRG_CAPTURE_B64
  _crg_lk_bytes=$CRG_CAPTURE_LEN
  [ "$_crg_lk_bytes" -ge 1 ] || return 1
  _crg_lk_head=$(git rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || return 2
  case "$_crg_lk_head" in
    *[!0-9a-f]*|'') return 2 ;;
  esac
  case "${#_crg_lk_head}" in
    40|64) ;;
    *) return 2 ;;
  esac

  _crg_lk_expected=$(printf '%s' "$_crg_lk_record_b64" | crg_b64_decode | LC_ALL=C awk -v BINMODE=3 -v bytes_expected="$_crg_lk_bytes" -v base="$_crg_lk_head" '
    function path_rank(p) {
      if (p == ".gitattributes") return 1
      if (p == "scripts/git-hooks/pre-commit") return 2
      if (p == "scripts/codex/auto-review.ps1") return 3
      if (p == "scripts/claude/auto-review.ps1") return 4
      if (p == "scripts/codex/review-prompt-template.md") return 5
      if (p == "scripts/review-liveness.psm1") return 6
      if (p == "scripts/review-common.ps1") return 7
      return 0
    }
    { bytes += length($0) + 1 }
    $0 ~ /[^ -~]/ { bad = 1; next }
    NR == 1 { if ($0 != "crg-review-kernel-transition v1") bad = 1; next }
    NR == 2 { if ($0 != "base: " base) bad = 1; next }
    NR >= 3 {
      r = path_rank($4)
      if (NF != 4 || $1 != "entry:" || ($2 != "100644" && $2 != "100755") ||
          $3 !~ /^[0-9a-f]+$/ || length($3) != length(base) || r == 0 || r <= prev) {
        bad = 1
        next
      }
      prev = r
      if (r > 1) core++
      n++
      print $2 "\t" $3 "\t" $4
    }
    END { if (bad || bytes != bytes_expected || NR < 3 || NR > 9 || n < 1 || core < 1) exit 1 }
  ' 2>/dev/null)
  _crg_lk_parse_rc=$?
  [ "$_crg_lk_parse_rc" -eq 0 ] && [ -n "$_crg_lk_expected" ] || return 1

  _crg_lk_tab=$(printf '\t')
  for _crg_lk_path in \
    .gitattributes \
    scripts/git-hooks/pre-commit \
    scripts/codex/auto-review.ps1 \
    scripts/claude/auto-review.ps1 \
    scripts/codex/review-prompt-template.md \
    scripts/review-liveness.psm1 \
    scripts/review-common.ps1
  do
    _crg_lk_row=$(printf '%s\n' "$_crg_lk_expected" | LC_ALL=C awk -F '\t' -v p="$_crg_lk_path" '
      $3 == p { if (++n > 1) exit 2; row = $0 }
      END { if (n == 1) printf "%s", row }
    ' 2>/dev/null); _crg_lk_row_rc=$?
    [ "$_crg_lk_row_rc" -eq 0 ] || return 1
    if [ -n "$_crg_lk_row" ]; then
      set -- $_crg_lk_row
      [ "$#" -eq 3 ] && [ "$3" = "$_crg_lk_path" ] || return 1
      _crg_lk_ix=$(git ls-tree "$CROSS_REVIEW_DISPATCH_TREE" -- "$_crg_lk_path" 2>/dev/null) || return 2
      [ "$_crg_lk_ix" = "$1 blob $2$_crg_lk_tab$_crg_lk_path" ] || return 1
      git diff --quiet --no-ext-diff --no-textconv --no-renames --ignore-submodules=none HEAD "$CROSS_REVIEW_DISPATCH_TREE" -- "$_crg_lk_path" 2>/dev/null
      _crg_lk_diff_rc=$?
      case "$_crg_lk_diff_rc" in 1) ;; 0) return 1 ;; *) return 2 ;; esac
    else
      git diff --quiet --no-ext-diff --no-textconv --no-renames --ignore-submodules=none HEAD "$CROSS_REVIEW_DISPATCH_TREE" -- "$_crg_lk_path" 2>/dev/null
      _crg_lk_omit_rc=$?
      case "$_crg_lk_omit_rc" in 0) ;; 1) return 1 ;; *) return 2 ;; esac
    fi
  done

  # Excluding every path the record grammar can name must leave an empty staged
  # diff. Paths omitted from this particular record were proven unchanged above.
  git diff --quiet --no-ext-diff --no-textconv --no-renames --ignore-submodules=none HEAD "$CROSS_REVIEW_DISPATCH_TREE" -- . \
    ':(exclude).gitattributes' \
    ':(exclude)scripts/git-hooks/pre-commit' \
    ':(exclude)scripts/codex/auto-review.ps1' \
    ':(exclude)scripts/claude/auto-review.ps1' \
    ':(exclude)scripts/codex/review-prompt-template.md' \
    ':(exclude)scripts/review-liveness.psm1' \
    ':(exclude)scripts/review-common.ps1' 2>/dev/null
  _crg_lk_extra_rc=$?
  case "$_crg_lk_extra_rc" in
    0) return 0 ;;
    1) return 1 ;;
    *) return 2 ;;
  esac
}

# Gate-component untracking guard, mirrored from the tracked hook and
# placed ahead of every dispatcher exit path. The hook also carries this guard,
# but the dispatcher must not depend on reaching it -- any early dispatcher exit
# would otherwise be a bypass.
GATE_UNTRACK_LIST='scripts/codex/auto-review.ps1
scripts/codex/auto-merge.ps1
scripts/shared/auto-merge.ps1
scripts/codex/commit.ps1
scripts/shared/analyze-blocker-trends.ps1
scripts/shared/author-lint.ps1
scripts/shared/dispatch-checklist.ps1
scripts/shared/worker-audit.ps1
scripts/codex/review-prompt-template.md
scripts/claude/auto-review.ps1
scripts/claude/commit.ps1
scripts/git-hooks/pre-commit
scripts/run-gate.sh
scripts/render-project-values.ps1
scripts/review-liveness.psm1
scripts/review-common.ps1
docs/AGENTS.md.template
docs/audit-protocol.md'
if [ "$CROSS_REVIEW_ALLOW_GATE_UNTRACK" != "1" ]; then
  if [ "$CROSS_REVIEW_SKIP" = "1" ]; then
    GU_BORN=$(_crg_head_born)
    case "$GU_BORN" in
      born) GU_NS=$(git diff-tree --no-ext-diff --no-textconv --no-renames --ignore-submodules=none --no-commit-id --name-status -r HEAD "$CROSS_REVIEW_DISPATCH_TREE" 2>/dev/null) || GU_NS=__CRG_PROBE_FAILED__ ;;
      unborn) GU_NS='' ;;
      *) GU_NS=__CRG_PROBE_FAILED__ ;;
    esac
  else
    GU_NS=$(git diff --cached --no-color --no-ext-diff --no-textconv --no-renames --ignore-submodules=none --name-status 2>/dev/null) || GU_NS=__CRG_PROBE_FAILED__
  fi
  if [ "$GU_NS" = "__CRG_PROBE_FAILED__" ]; then
    echo "[pre-commit:dispatcher] ERROR: could not probe the staged name-status for the gate-untracking guard (indeterminate refuses; fail closed)." >&2
    exit 1
  fi
  for gu_p in $GATE_UNTRACK_LIST; do
    if printf '%s\n' "$GU_NS" | awk -F'\t' -v p="$gu_p" '
        $1 ~ /^D/ && $2 == p { found = 1 }
        $1 ~ /^R/ && $2 == p { found = 1 }
        END { exit found ? 0 : 1 }'; then
      echo "[pre-commit:dispatcher] ERROR: the staged change REMOVES gate component '$gu_p' from tracking." >&2
      echo "[pre-commit:dispatcher] Untracking a gate component is a shape transition and lands only with the" >&2
      echo "[pre-commit:dispatcher] operator's explicit sanction: set CROSS_REVIEW_ALLOW_GATE_UNTRACK=1 for exactly that commit." >&2
      exit 1
    fi
  done
fi

# One-time bridge from a pre-redesign trusted HEAD. Generic dispatcher guards
# above still run first. The bridge activates only when a protected review-
# kernel path is staged; every other audited skip keeps following trusted HEAD.
# The routing-driver identity guard also runs, so neither an extra staged path
# nor dirty executed run-gate bytes can ride the bounded transition. No
# candidate review-kernel byte executes during this commit.
if [ "$CROSS_REVIEW_SKIP" = "1" ]; then
  crg_legacy_review_kernel_state
  _crg_lk_state_rc=$?
  if [ "$_crg_lk_state_rc" -eq 0 ]; then
    crg_legacy_review_kernel_touched
    _crg_lk_touch_rc=$?
    if [ "$_crg_lk_touch_rc" -eq 2 ]; then
      echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: whether the staged change touches the legacy review kernel could not be determined (indeterminate refuses)." >&2
      exit 1
    fi
    if [ "$_crg_lk_touch_rc" -eq 0 ]; then
      crg_legacy_review_kernel_stage
      _crg_lk_stage_rc=$?
      if [ "$_crg_lk_stage_rc" -eq 2 ]; then
        echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the hash-bound legacy review-kernel transition probe failed (indeterminate refuses)." >&2
        exit 1
      fi
      if [ "$_crg_lk_stage_rc" -ne 0 ]; then
        echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: a protected legacy review-kernel path is staged, but the index does not exactly match the successful full bootstrap's base-HEAD-bound transition record." >&2
        echo "[pre-commit:dispatcher] Re-run the full bootstrap from the intended package source, then stage exactly the paths printed in that transition identity record; arbitrary replacement bytes and every extra staged path are refused." >&2
        exit 1
      fi
      if crg_skip_refuses_driver_edit; then
        echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: routing driver 'scripts/run-gate.sh' is staged, dirty, unverifiable, or lacks the candidate LF checkout contract. Restore a tracked run-gate to HEAD; when run-gate is absent from HEAD, remove the bootstrap-created untracked worktree copy before this first landing." >&2
        exit 1
      fi
      if ! write_skip_log "legacy-review-kernel-transition"; then
        exit 1
      fi
      if ! crg_skip_tree_stable; then
        echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the live index changed after the legacy-transition audit entry; the captured staged tree no longer governs this commit." >&2
        exit 1
      fi
      echo "[pre-commit:dispatcher] legacy review-kernel transition accepted: the staged entries exactly match the filter-aware, base-HEAD-bound bootstrap record; the staged tree was recorded in $SKIP_AUDIT_REF at $SKIP_AUDIT_TIP and candidate kernel bytes were not executed."
      exit 0
    fi
  fi
  if [ "$_crg_lk_state_rc" -eq 2 ]; then
    echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the trusted HEAD review kernel could not be classified for the legacy transition (indeterminate refuses)." >&2
    exit 1
  fi
fi

if [ ! -f "$GATE_HOOK" ]; then
  if [ "$CROSS_REVIEW_SKIP" = "1" ]; then
    if crg_skip_refuses_driver_edit; then
      echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the working state modifies routing driver 'scripts/run-gate.sh', its local-shape manifest match failed, the staged LF checkout contract for a tracked sh surface fails, or a baseline probe was indeterminate; a driver edit lands only through the gate. Restore the in-tree gate and commit through it." >&2
      exit 1
    fi
    # User explicitly bypassed via CROSS_REVIEW_SKIP=1; let it through
    # ONLY after recording the bypass in the fixed skip-audit ref. The
    # in-tree gate would have written this entry itself when present;
    # the dispatcher writes it here when the gate is missing so the
    # audit trail still records every bypass.
    if ! write_skip_log "in-tree-gate-missing"; then
      exit 1
    fi
    if ! crg_skip_tree_stable; then
      echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the live index changed after skip logging; the captured staged tree no longer governs this commit." >&2
      exit 1
    fi
    echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 with in-tree gate missing -- bypass logged in $SKIP_AUDIT_REF at $SKIP_AUDIT_TIP"
    exit 0
  fi
  echo "[pre-commit:dispatcher] ERROR: in-tree gate not found at $GATE_HOOK" >&2
  echo "[pre-commit:dispatcher] A commit removed or never installed the cross-review gate." >&2
  echo "[pre-commit:dispatcher] If intentional, re-install via bootstrap.ps1 or set" >&2
  echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 for THIS one commit (audited bypass):" >&2
  echo "[pre-commit:dispatcher]   PowerShell:  \$env:CROSS_REVIEW_SKIP = '1'; git commit ...; Remove-Item Env:CROSS_REVIEW_SKIP" >&2
  echo "[pre-commit:dispatcher]   bash:        CROSS_REVIEW_SKIP=1 git commit ..." >&2
  exit 1
fi

# In-tree gate exists in the working tree. Verify it is also tracked
# in HEAD: an untracked working-tree gate has no trusted baseline.
# CROSS_REVIEW_SKIP=1 bypasses this for the initial bootstrap commit
# (when HEAD has no gate yet).
HEAD_HAS_GATE=0
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  if git cat-file -e HEAD:scripts/git-hooks/pre-commit 2>/dev/null; then
    HEAD_HAS_GATE=1
  fi
fi
if [ "$HEAD_HAS_GATE" -ne 1 ]; then
  if [ "$CROSS_REVIEW_SKIP" = "1" ]; then
    if crg_skip_refuses_driver_edit; then
      echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the working state modifies routing driver 'scripts/run-gate.sh', its local-shape manifest match failed, the staged LF checkout contract for a tracked sh surface fails, or a baseline probe was indeterminate; a driver edit lands only through the gate." >&2
      exit 1
    fi
    # Bootstrap-commit path. The in-tree gate is in the working tree
    # but not yet in HEAD; CROSS_REVIEW_SKIP=1 lets it land so the gate
    # files reach HEAD. Log the bypass for audit.
    if ! write_skip_log "bootstrap-gate-not-in-head"; then
      exit 1
    fi
    if ! crg_skip_tree_stable; then
      echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the live index changed after bootstrap-skip logging; the captured staged tree no longer governs this commit." >&2
      exit 1
    fi
    echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 with gate not in HEAD -- bootstrap bypass logged in $SKIP_AUDIT_REF at $SKIP_AUDIT_TIP"
    exit 0
  fi
  # Local install shape (docs/local-install-v1.md): the hook is
  # untracked and deliberately ignored, and the operator-written
  # manifest vouches for its exact bytes. Exec a verified SNAPSHOT of
  # the working-tree hook -- the manifest sits in the same commit-proof
  # custody as this dispatcher, and snapshotting before hashing closes
  # the verify-then-consume race, so the property the HEAD-exec exists
  # for holds: a candidate cannot swap the gate that judges it. The
  # branch runs only on POSITIVE absence (a readable HEAD that lists no
  # gate path, or an unborn branch -- a fresh local-shape clone); a
  # failed probe or any mismatch falls through to the refusal.
  crg_gate_absent=no
  if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
    crg_gate_absent=yes
  else
    crg_ls=$(git ls-tree HEAD -- scripts/git-hooks/pre-commit 2>/dev/null); crg_ls_rc=$?
    if [ "$crg_ls_rc" -eq 0 ] && [ -z "$crg_ls" ]; then crg_gate_absent=yes; fi
  fi
  if [ "$crg_gate_absent" = "yes" ]; then
    crg_local_shape=yes
    crg_local_tracked=$(git ls-files --cached -- scripts/git-hooks/pre-commit 2>/dev/null)
    crg_local_tracked_rc=$?
    if [ "$crg_local_tracked_rc" -ne 0 ]; then
      crg_local_diagnostic TRACKED-STATE scripts/git-hooks/pre-commit 'Cannot inspect the hook index state. Check Git configuration and repository access before retrying.'
      crg_local_shape=no
    elif [ -n "$crg_local_tracked" ]; then
      crg_local_diagnostic TRACKED-STATE scripts/git-hooks/pre-commit 'Hook is tracked in the index, so LOCAL authority cannot apply. Complete the intended TRACKED installation.'
      crg_local_shape=no
    elif git check-ignore -q -- scripts/git-hooks/pre-commit 2>/dev/null; then
      :
    else
      crg_local_ignore_rc=$?
      if [ "$crg_local_ignore_rc" -eq 1 ]; then
        crg_local_diagnostic IGNORE-STATE scripts/git-hooks/pre-commit 'Local hook is not ignored. Restore the intended LOCAL exclude rule before retrying.'
      else
        crg_local_diagnostic IGNORE-STATE scripts/git-hooks/pre-commit 'Cannot inspect the local hook ignore state. Check Git configuration and repository access before retrying.'
      fi
      crg_local_shape=no
    fi
    if [ "$crg_local_shape" = yes ] && crg_local_install_buffer scripts/git-hooks/pre-commit; then
      TRUSTED_HOOK_B64=$CRG_LOCAL_INSTALL_B64
      echo "[pre-commit:dispatcher] local install shape: manifest-verified gate buffer (the package's docs/local-install-v1.md)"
      if ! crg_decode_b64_text_exact "$TRUSTED_HOOK_B64"; then
        echo "[pre-commit:dispatcher] ERROR: the complete verified local hook buffer could not be decoded before execution" >&2
        exit 1
      fi
      crg_eval_sha256_text_exact "$CRG_DECODED_TEXT" "$CRG_LOCAL_INSTALL_LEN" "$CRG_LOCAL_INSTALL_SHA" "$@"
      exit $?
    fi
  fi
  echo "[pre-commit:dispatcher] ERROR: in-tree gate at $GATE_HOOK is not tracked in HEAD." >&2
  echo "[pre-commit:dispatcher] For the initial bootstrap commit, stage the gate files and use:" >&2
  echo "[pre-commit:dispatcher]   PowerShell:  \$env:CROSS_REVIEW_SKIP = '1'; git commit ...; Remove-Item Env:CROSS_REVIEW_SKIP" >&2
  echo "[pre-commit:dispatcher]   bash:        CROSS_REVIEW_SKIP=1 git commit ..." >&2
  echo "[pre-commit:dispatcher] For the LOCAL install shape (gate files deliberately ignored," >&2
  echo "[pre-commit:dispatcher] the package's docs/local-install-v1.md), this refusal means the manifest is absent" >&2
  echo "[pre-commit:dispatcher] or the working-tree gate no longer matches it. Use the retained package installer," >&2
  echo "[pre-commit:dispatcher] immediately followed by the installed renderer check:" >&2
  echo "[pre-commit:dispatcher]   powershell -NoProfile -ExecutionPolicy Bypass -File \"<path-to>\\cross-review-gate\\bootstrap.ps1\" -TargetRepo \"<repo>\" -Force" >&2
  echo "[pre-commit:dispatcher]   powershell -NoProfile -ExecutionPolicy Bypass -File \"<repo>\\scripts\\render-project-values.ps1\" -TargetRepo \"<repo>\" -Check" >&2
  echo "[pre-commit:dispatcher] If exact LOCAL recovery is required, first complete the bounded sanctioned" >&2
  echo "[pre-commit:dispatcher] -SealManifest step in docs/install-values-v1.md, then run both commands above" >&2
  echo "[pre-commit:dispatcher] in order. Never retry this commit on sealed drift." >&2
  exit 1
fi

# CRITICAL: exec HEAD's gate, NOT the working-tree gate. Without this,
# a staged commit that REPLACES the in-tree hook with a no-op shell
# script would silently approve itself: the dispatcher would verify
# `HEAD:scripts/git-hooks/pre-commit` exists (it does -- the previous
# commit's version), then exec the WORKING-TREE no-op, which exits 0
# and lets the gate-disabling commit land with no actual review. The
# bypass would mirror the very `git rm gate` hole the dispatcher
# exists to close.
#
# Read HEAD's regular hook blob into one shell-owned byte buffer, verify the
# reconstructed bytes against the content-addressed blob identity, then feed
# that exact buffer to the fixed /bin/sh interpreter. No executable tempfile
# exists for a same-user process to replace between verification and execution.
TRUSTED_HOOK_ROW=$(git ls-tree HEAD -- scripts/git-hooks/pre-commit 2>/dev/null) || TRUSTED_HOOK_ROW=''
TRUSTED_HOOK_MODE=''
TRUSTED_HOOK_TYPE=''
TRUSTED_HOOK_OID=''
TRUSTED_HOOK_PATH=''
TRUSTED_HOOK_EXTRA=''
read -r TRUSTED_HOOK_MODE TRUSTED_HOOK_TYPE TRUSTED_HOOK_OID TRUSTED_HOOK_PATH TRUSTED_HOOK_EXTRA <<__CRG_TRUSTED_HOOK_ROW_EOF
$TRUSTED_HOOK_ROW
__CRG_TRUSTED_HOOK_ROW_EOF
if [ -n "$TRUSTED_HOOK_EXTRA" ] || [ "$TRUSTED_HOOK_TYPE" != blob ] || [ "$TRUSTED_HOOK_PATH" != scripts/git-hooks/pre-commit ]; then
  echo "[pre-commit:dispatcher] ERROR: trusted HEAD hook is not one regular tree entry" >&2
  exit 1
fi
case "$TRUSTED_HOOK_MODE" in 100644|100755) ;; *) echo "[pre-commit:dispatcher] ERROR: trusted HEAD hook has a non-regular mode" >&2; exit 1 ;; esac
case "$TRUSTED_HOOK_OID" in ''|*[!0-9a-f]*) echo "[pre-commit:dispatcher] ERROR: trusted HEAD hook has a malformed object identity" >&2; exit 1 ;; esac
if [ "${#TRUSTED_HOOK_OID}" -ne 40 ] && [ "${#TRUSTED_HOOK_OID}" -ne 64 ]; then
  echo "[pre-commit:dispatcher] ERROR: trusted HEAD hook has a malformed object identity" >&2
  exit 1
fi
TRUSTED_HOOK_SIZE=$(git cat-file -s "$TRUSTED_HOOK_OID" 2>/dev/null) || TRUSTED_HOOK_SIZE=''
case "$TRUSTED_HOOK_SIZE" in ''|*[!0-9]*) TRUSTED_HOOK_SIZE='' ;; esac
if [ -z "$TRUSTED_HOOK_SIZE" ] || [ "$TRUSTED_HOOK_SIZE" -lt 1 ] || [ "$TRUSTED_HOOK_SIZE" -gt 1048576 ]; then
  echo "[pre-commit:dispatcher] ERROR: trusted HEAD hook has an invalid bounded size" >&2
  exit 1
fi
TRUSTED_HOOK_MARK="__CRG_TRUSTED_HOOK_END_$TRUSTED_HOOK_OID"
TRUSTED_HOOK_SUFFIX=$(printf '\n%s' "$TRUSTED_HOOK_MARK")
TRUSTED_HOOK_BODY=$({ git cat-file blob "$TRUSTED_HOOK_OID" 2>/dev/null; _crg_th_rc=$?; if [ "$_crg_th_rc" -eq 0 ]; then printf '\n%s' "$TRUSTED_HOOK_MARK"; fi; exit "$_crg_th_rc"; }) || TRUSTED_HOOK_BODY=''
case "$TRUSTED_HOOK_BODY" in
  *"$TRUSTED_HOOK_SUFFIX") TRUSTED_HOOK_BODY=${TRUSTED_HOOK_BODY%"$TRUSTED_HOOK_SUFFIX"} ;;
  *) echo "[pre-commit:dispatcher] ERROR: trusted HEAD hook could not be captured completely" >&2; exit 1 ;;
esac
TRUSTED_HOOK_GOT=$(printf '%s' "$TRUSTED_HOOK_BODY" | git hash-object --stdin 2>/dev/null) || TRUSTED_HOOK_GOT=''
if [ "$TRUSTED_HOOK_GOT" != "$TRUSTED_HOOK_OID" ]; then
  echo "[pre-commit:dispatcher] ERROR: trusted HEAD hook buffer does not match its tree identity" >&2
  exit 1
fi
if [ "$CROSS_REVIEW_SKIP" = "1" ]; then
  if ! printf '%s' "$TRUSTED_HOOK_BODY" | LC_ALL=C awk '
      $0 == "# crg-dispatch-tree-handoff-v1" { found++ }
      END { exit found == 1 ? 0 : 1 }
    '; then
    echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: trusted HEAD lacks the exact dispatcher staged-tree handoff capability; first land the bounded review-kernel transition or refresh HEAD through ordinary review." >&2
    exit 1
  fi
fi
if [ "$CROSS_REVIEW_SKIP" = "1" ] && ! crg_skip_tree_stable; then
  echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the live index changed before trusted-hook delegation." >&2
  exit 1
fi
crg_eval_git_blob_text_exact "$TRUSTED_HOOK_BODY" "$TRUSTED_HOOK_SIZE" "$TRUSTED_HOOK_OID" "$@"
status=$?
if [ "$status" -eq 0 ] && [ "$CROSS_REVIEW_SKIP" = "1" ] && ! crg_skip_tree_stable; then
  echo "[pre-commit:dispatcher] CROSS_REVIEW_SKIP=1 REFUSED: the live index changed while the trusted hook ran; child success cannot authorize a different staged tree." >&2
  status=1
fi
exit "$status"
'@
    $crgDispBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($dispatcherContent)
    $crgDispSha = [System.Security.Cryptography.SHA256]::Create()
    try { $crgDispWantHash = ([System.BitConverter]::ToString($crgDispSha.ComputeHash($crgDispBytes)) -replace '-', '').ToLowerInvariant() } finally { $crgDispSha.Dispose() }
    if ($dispatcherExisted) {
      # LIVE-HOOK-CONTINUOUS replacement (docs/local-install-v1.md
      # section 4): the live hook must never be silently absent, and
      # git takes no bootstrap lock -- so the replacement happens IN
      # PLACE through one exclusive handle with a disarm-first write
      # protocol (mechanics and the rejected designs at OpenExclusive
      # and at the rewrite below). Bootstraps are excluded throughout
      # by the dispatcher lock held around this whole stage.
      if ($null -eq $crgCommonDir) {
        Write-Error "bootstrap.ps1: cannot resolve the git common dir of '$targetRepoAbs' to back up the existing dispatcher at '$dispatcherPath'; refusing to overwrite without a backup."
        exit 1
      }
      $crgDispBak = Join-Path (Join-Path (Join-Path $crgCommonDir 'crg-backups') $crgBackupStamp) 'git-hooks-dispatcher/pre-commit'
      if (Test-Path -LiteralPath $crgDispBak) {
        Write-Error "bootstrap.ps1: backup path '$crgDispBak' already exists; refusing to overwrite an existing recovery copy. Re-run to take a fresh backup area."
        exit 1
      }
      $crgDispBakDir = Split-Path -Parent $crgDispBak
      $null = Ensure-CrgRootedDirectory -Path $crgDispBakDir -Label 'dispatcher backup directory'
      # Reparse points are refused BEFORE mutation: an exclusive open
      # that followed a symlink would rewrite the TARGET while the
      # hooks path kept the link -- an unsupported hook shape either
      # way (the open below also passes OPEN_REPARSE_POINT, so a
      # racer-planted link cannot silently redirect it).
      try { $crgDispAttrs = [System.IO.File]::GetAttributes($dispatcherPath) } catch { $crgDispAttrs = $null }
      if ($null -eq $crgDispAttrs -or (($crgDispAttrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        if (-not (Test-Path -LiteralPath $dispatcherPath)) {
          # The dispatcher vanished between the existence probe and
          # this one (a racer's deletion or rename): an EMPTY hooks
          # path lets commits run ungated, so the fail-closed sentinel
          # is published at the emptied path before the abort.
          $null = Install-CrgDispatcherSentinel -DispatcherPath $dispatcherPath
          Write-Error "bootstrap.ps1: the existing dispatcher at '$dispatcherPath' vanished before it could be pinned (a concurrent deletion or rename); the FAIL-CLOSED sentinel was attempted at the emptied path (its outcome is reported above). Investigate, then re-run."
          exit 1
        }
        Write-Error "bootstrap.ps1: the existing dispatcher at '$dispatcherPath' is unreadable or a reparse point (symlink/junction) - not a supported hook shape; refusing to mutate it. Replace it with a regular file by hand, then re-run."
        exit 1
      }
      $crgDispEx = $null
      $crgDispExFs = $null
      $crgDispRcHeld = @()
      $crgDispErr = 0
      try {
        try { $crgDispEx = [CrgBootstrap.NativeV4]::OpenExclusiveNoFollow($dispatcherPath, [ref]$crgDispErr) } catch { $crgDispEx = $null }
        if ($null -eq $crgDispEx -or $crgDispEx.IsInvalid) {
          if (-not (Test-Path -LiteralPath $dispatcherPath)) {
            $null = Install-CrgDispatcherSentinel -DispatcherPath $dispatcherPath
            Write-Error "bootstrap.ps1: the existing dispatcher at '$dispatcherPath' vanished before it could be pinned (a concurrent deletion or rename); the FAIL-CLOSED sentinel was attempted at the emptied path (its outcome is reported above). Investigate, then re-run."
            exit 1
          }
          Write-Error "bootstrap.ps1: cannot pin the existing dispatcher at '$dispatcherPath' for its in-place rewrite (commonly another process holding it); aborting with the live hook untouched."
          exit 1
        }
        $crgDispLinks = [CrgBootstrap.NativeV3]::GetLinkCount($crgDispEx)
        if ($crgDispLinks -ne 1) {
          # An in-place rewrite through any alias of a hard-linked
          # file rewrites every alias -- refuse the shape (and an
          # unprobeable count) before the first write.
          Write-Error "bootstrap.ps1: the existing dispatcher at '$dispatcherPath' has a hard-link count of $crgDispLinks (an in-place rewrite would alter every alias, or the count could not be queried); refusing to mutate it with the live hook untouched. Remove the extra links (fsutil hardlink list) and re-run."
          exit 1
        }
        # One EXCLUSIVE handle carries the whole replacement: the
        # backup is read through it, the rewrite happens through it,
        # and the verification reads back through it -- the identity
        # can never change hands, the hooks NAME never changes, and a
        # concurrent commit while it is held fails closed (git cannot
        # spawn an unopenable hook). See OpenExclusive's warning for
        # the rejected namespace-transition designs.
        $crgDispExFs = New-Object System.IO.FileStream($crgDispEx, [System.IO.FileAccess]::ReadWrite)
        try {
          $crgDispOldMs = New-Object System.IO.MemoryStream
          $crgDispExFs.CopyTo($crgDispOldMs)
          $crgDispOldBytes = $crgDispOldMs.ToArray()
          $crgDispOldMs.Dispose()
          # Recovery copies -- the backup and its archive twin -- come
          # from the exclusively held bytes, land through CREATE-NEW
          # handles (an occupied recovery name aborts, never
          # overwrites), verify through those same handles, and the
          # handles stay HELD until this stage ends so the verified
          # identities cannot be swapped behind the report.
          foreach ($crgDispRc in @($crgDispBak, "$crgDispBak.custody")) {
            $crgDispRcH = $null
            $crgDispRcFs = $null
            $crgDispRcErr = 0
            try {
              $crgDispRcH = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($crgDispRc, [ref]$crgDispRcErr)
              if ($null -eq $crgDispRcH -or $crgDispRcH.IsInvalid) { throw "no-follow create-new refused (Win32 error $crgDispRcErr)" }
              try { $crgDispRcFs = New-Object System.IO.FileStream($crgDispRcH, [System.IO.FileAccess]::ReadWrite); $crgDispRcH = $null }
              catch {
                if ($null -ne $crgDispRcH -and -not $crgDispRcH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $crgDispRc -Handle $crgDispRcH -Label 'dispatcher recovery copy'; $crgDispRcH = $null }
                throw
              }
              $crgDispRcFs.Write($crgDispOldBytes, 0, $crgDispOldBytes.Length)
              $crgDispRcFs.Flush($true)
              $crgDispRcFs.Position = 0
              $crgDispRcMs = New-Object System.IO.MemoryStream
              $crgDispRcFs.CopyTo($crgDispRcMs)
              $crgDispRcOk = ([System.BitConverter]::ToString($crgDispRcMs.ToArray()) -ceq [System.BitConverter]::ToString($crgDispOldBytes))
              $crgDispRcMs.Dispose()
              if (-not $crgDispRcOk) { throw "the recovery copy at '$crgDispRc' did not verify byte-for-byte through its held handle" }
              $crgDispRcHeld += [pscustomobject]@{ Path = $crgDispRc; Stream = $crgDispRcFs }
              $crgDispRcFs = $null
            } catch {
              if ($null -ne $crgDispRcFs) { $null = Remove-CrgOwnedScratchHandle -Path $crgDispRc -Stream $crgDispRcFs -Label 'dispatcher recovery copy'; $crgDispRcFs = $null }
              elseif ($null -ne $crgDispRcH -and -not $crgDispRcH.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $crgDispRc -Handle $crgDispRcH -Label 'dispatcher recovery copy'; $crgDispRcH = $null }
              throw
            }
          }
        } catch {
          Write-Error "bootstrap.ps1: backing up the existing dispatcher failed ($($_.Exception.Message)); aborting with the live hook untouched."
          exit 1
        }
        # Attestation dies NOW -- after every non-mutating precondition
        # (pin, link count, verified backups) and before the first
        # dispatcher-byte mutation: mid-rewrite bytes must never verify
        # against the previous digest, while an abort above (or a
        # refused clearing HERE) leaves the hook untouched. The
        # attestation itself survives a refusal unless the clearing
        # failed mid-truncate; a re-run records a fresh one either way.
        if (-not (Remove-CrgDispatcherDigest -DispatcherPath $dispatcherPath)) {
          Write-Error "bootstrap.ps1: the digest path beside '$dispatcherPath' could not be cleared (see the warning above); aborting BEFORE the rewrite with the live hook untouched. A re-run records a fresh attestation once the path is repaired."
          exit 1
        }
        # THE IN-PLACE REWRITE, DISARM-FIRST. Git refuses to spawn a
        # hook with no shebang ('cannot spawn', the commit aborts) --
        # measured 2026-08-28 against a disarmed-shebang dispatcher.
        # The crash armor depends on this refusal:
        # the FIRST mutation flips the shebang's second byte to 'X'
        # ('#X/bin/sh' -- a comment, not a shebang), the whole new
        # body is then written and verified with that byte still
        # disarmed, and the LAST mutation is the single-byte re-arm
        # back to '!'. Single-byte writes land atomically, so every
        # observable state of this file either keeps the pre-existing
        # hook's bytes (whatever they enforced, before the disarm),
        # refuses every commit at spawn (between the two mutations),
        # or is the verified new dispatcher (after the arm). No
        # brace-contract analysis of interleaved old/new content is
        # needed -- the disarmed byte alone carries the guarantee.
        $crgDispWriteOk = $false
        try {
          $crgDispDisarm = [byte[]]@(0x58)
          $crgDispExFs.Position = 1
          $crgDispExFs.Write($crgDispDisarm, 0, 1)
          $crgDispExFs.Flush($true)
          $crgDispNewBytes = [byte[]]$crgDispBytes.Clone()
          $crgDispNewBytes[1] = 0x58
          $crgDispExFs.Position = 0
          $crgDispExFs.Write($crgDispNewBytes, 0, $crgDispNewBytes.Length)
          $crgDispExFs.SetLength($crgDispNewBytes.Length)
          $crgDispExFs.Flush($true)
          $crgDispExFs.Position = 0
          $crgDispChkMs = New-Object System.IO.MemoryStream
          $crgDispExFs.CopyTo($crgDispChkMs)
          $crgDispBodyOk = ([System.BitConverter]::ToString($crgDispChkMs.ToArray()) -ceq [System.BitConverter]::ToString($crgDispNewBytes))
          $crgDispChkMs.Dispose()
          if ($crgDispBodyOk) {
            $crgDispArm = [byte[]]@(0x21)
            $crgDispExFs.Position = 1
            $crgDispExFs.Write($crgDispArm, 0, 1)
            $crgDispExFs.Flush($true)
            $crgDispExFs.Position = 0
            $crgDispFinMs = New-Object System.IO.MemoryStream
            $crgDispExFs.CopyTo($crgDispFinMs)
            $crgDispWriteOk = ([System.BitConverter]::ToString($crgDispFinMs.ToArray()) -ceq [System.BitConverter]::ToString($crgDispBytes))
            $crgDispFinMs.Dispose()
          }
        } catch { }
        if (-not $crgDispWriteOk) {
          # The rewrite did not verify -- fall back to the SENTINEL
          # through the SAME held handle, so even the fallback never
          # opens an unpinned instant. DISARM-FIRST here too: the
          # failed rewrite may have left an ARMED shebang over
          # unverified bytes, so byte 1 is flipped and verified
          # through the handle BEFORE the sentinel body is attempted
          # -- a fallback that dies after the disarm still leaves a
          # hook git refuses to spawn.
          $crgSnFallOk = $false
          $crgSnFallDisarmed = $false
          try {
            $crgDispExFs.Position = 1
            $crgDispExFs.Write(([byte[]]@(0x58)), 0, 1)
            $crgDispExFs.Flush($true)
            $crgDispExFs.Position = 1
            $crgSnFallDisarmed = ($crgDispExFs.ReadByte() -eq 0x58)
            if (-not $crgSnFallDisarmed) { throw 'the disarm byte did not read back' }
            $crgSnFallBytes = Get-CrgSentinelBytes
            $crgDispExFs.Position = 0
            $crgDispExFs.Write($crgSnFallBytes, 0, $crgSnFallBytes.Length)
            $crgDispExFs.SetLength($crgSnFallBytes.Length)
            $crgDispExFs.Flush($true)
            $crgDispExFs.Position = 0
            $crgSnFallMs = New-Object System.IO.MemoryStream
            $crgDispExFs.CopyTo($crgSnFallMs)
            $crgSnFallOk = ([System.BitConverter]::ToString($crgSnFallMs.ToArray()) -ceq [System.BitConverter]::ToString($crgSnFallBytes))
            $crgSnFallMs.Dispose()
          } catch { }
          if ($crgSnFallOk) {
            Write-Error "bootstrap.ps1: the in-place dispatcher rewrite did not verify; the FAIL-CLOSED sentinel was written in its place through the same pinned handle and verifies - every commit refuses until a re-run lands a verified dispatcher. The previous bytes are backed up at '$crgDispBak'."
          } elseif ($crgSnFallDisarmed) {
            Write-Error "bootstrap.ps1: the in-place dispatcher rewrite did not verify AND the in-place sentinel could not be written verified; the hook at '$dispatcherPath' holds UNVERIFIED bytes with its shebang DISARMED (git refuses to spawn it, so commits fail closed rather than silently passing) - repair it with a re-run before committing. The previous bytes are backed up at '$crgDispBak'."
          } else {
            Write-Error "bootstrap.ps1: the in-place dispatcher rewrite did not verify AND the disarm byte could not be confirmed; the hook at '$dispatcherPath' may hold ARMED UNVERIFIED bytes - do NOT commit until it is repaired by hand or a re-run. The previous bytes are backed up at '$crgDispBak'."
          }
          exit 1
        }
        # The attestation publishes BEFORE the success report, inside
        # the held-handle window: a failed publication is fatal with NO
        # success banner (a success claim over a gate run-gate.sh will
        # refuse to fire). The fatal handling itself runs AFTER the
        # finally releases the handles -- a usable-residual escalation
        # sentinelizes the dispatcher, which needs its own exclusive
        # open.
        $crgDispDigOk = (Publish-CrgDispatcherDigest -DispatcherPath $dispatcherPath -Bytes $crgDispBytes)
        if ($crgDispDigOk) {
          # The success report prints while every identity-pinning
          # handle is still held -- what it names cannot be swapped
          # behind it.
          Write-Host "[bootstrap] REPLACED existing dispatcher at $dispatcherPath (rewritten IN PLACE through one exclusive handle - the hooks name never changed, and a concurrent commit during the rewrite fails closed on the exclusion; previous copy backed up to $crgDispBak)"
        }
      } finally {
        foreach ($crgDispRcH in $crgDispRcHeld) { try { $crgDispRcH.Stream.Dispose(); $crgDispRcH.Stream = $null } catch { } }
        if ($null -ne $crgDispExFs) { try { $crgDispExFs.Dispose() } catch { } }
        elseif ($null -ne $crgDispEx) { try { $crgDispEx.Dispose() } catch { } }
      }
      if (-not $crgDispDigOk) {
        if ($script:CrgDigestFailureUsable) {
          # A complete valid record survived a failed cleanup: the gate
          # must not present a verified-looking pair after a fatal
          # report, so the dispatcher itself is sentinelized.
          $null = Install-CrgDispatcherSentinel -DispatcherPath $dispatcherPath
        }
        Write-Error "bootstrap.ps1: the rewritten dispatcher verified, but its digest attestation could not be recorded beside it - run-gate.sh refuses to fire without the attestation. Re-run bootstrap.ps1 -DispatcherOnly to repair."
        exit 1
      }
    } else {
      # CreateNew, the section-4 replacement contract: no dispatcher
      # existed, so a file appearing here mid-run is a concurrent
      # writer whose bytes have no backup -- WriteAllText would
      # silently overwrite them. A failed or partial write would leave
      # the repo with NO enforcing hook (or a truncated one that exits
      # before enforcing), so every failure attempts the FAIL-CLOSED
      # sentinel (its own failure is reported, never silent).
      # A stale digest from a since-removed dispatcher must not survive
      # into the fresh install window; a refused clearing aborts before
      # any dispatcher byte lands.
      if (-not (Remove-CrgDispatcherDigest -DispatcherPath $dispatcherPath)) {
        Write-Error "bootstrap.ps1: the digest path beside '$dispatcherPath' could not be cleared (see the warning above); aborting BEFORE the install."
        exit 1
      }
      $crgDispNew = $null
      $crgDispFs = $null
      try {
        # No-follow CREATE_NEW: a dangling reparse point at the hook name
        # collides as an occupant instead of redirecting the create.
        $crgDispNewErr = 0
        $crgDispNew = [CrgBootstrap.NativeV4]::CreateOwnedFileNoFollow($dispatcherPath, [ref]$crgDispNewErr)
        if ($null -eq $crgDispNew -or $crgDispNew.IsInvalid) { throw "no-follow CREATE_NEW refused (Win32 error $crgDispNewErr)" }
        try {
          $crgDispFs = New-Object System.IO.FileStream($crgDispNew, [System.IO.FileAccess]::ReadWrite)
          $crgDispNew = $null
        } catch {
          if ($null -ne $crgDispNew -and -not $crgDispNew.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $dispatcherPath -Handle $crgDispNew -Label 'fresh dispatcher'; $crgDispNew = $null }
          throw
        }
        $crgDispFs.Write($crgDispBytes, 0, $crgDispBytes.Length)
        $crgDispFs.Flush($true)
        $crgDispFs.Position = 0
        $crgDispGot = Get-CrgSha256HexOfHeldStream -Stream $crgDispFs
        if ([CrgBootstrap.NativeV3]::GetLinkCount($crgDispFs.SafeFileHandle) -ne 1 -or $null -eq $crgDispGot -or
            -not [string]::Equals($crgDispGot, $crgDispWantHash, [System.StringComparison]::Ordinal)) {
          throw 'the retained fresh dispatcher did not verify byte-for-byte as one single-link file'
        }
      } catch {
        $crgDispErr = $_.Exception.Message
        if ($null -ne $crgDispFs) { $null = Remove-CrgOwnedScratchHandle -Path $dispatcherPath -Stream $crgDispFs -Label 'fresh dispatcher'; $crgDispFs = $null }
        elseif ($null -ne $crgDispNew -and -not $crgDispNew.IsInvalid) { $null = Remove-CrgOwnedScratchHandle -Path $dispatcherPath -Handle $crgDispNew -Label 'fresh dispatcher'; $crgDispNew = $null }
        $crgDispKind = Get-CrgPathOccupantKind -Path $dispatcherPath
        if ([string]::Equals($crgDispKind, 'reparse', [System.StringComparison]::Ordinal)) {
          Write-Error "bootstrap.ps1: creating the dispatcher at '$dispatcherPath' failed ($crgDispErr): a REPARSE-POINT occupant (a symlink or junction, possibly dangling -- a pathname probe reads it as absent) holds the hook name, and no re-run can replace it. Remove the link by hand, then re-run."
          exit 1
        }
        $null = Install-CrgDispatcherSentinel -DispatcherPath $dispatcherPath
        Write-Error "bootstrap.ps1: creating the dispatcher at '$dispatcherPath' failed ($crgDispErr; occupant: $crgDispKind). A file appearing there mid-run is a concurrent writer; investigate it, then re-run."
        exit 1
      }
      # The digest derives from the verified SOURCE bytes, never a
      # re-read of the mutable destination, so no racer can seed the
      # attestation. A failed publication is FATAL and suppresses the
      # success report below.
      if (-not (Publish-CrgDispatcherDigest -DispatcherPath $dispatcherPath -Bytes $crgDispBytes)) {
        if ($null -ne $crgDispFs) { $crgDispFs.Dispose(); $crgDispFs = $null }
        if ($script:CrgDigestFailureUsable) {
          # A complete valid record survived a failed cleanup: the gate
          # must not present a verified-looking pair after a fatal
          # report, so the dispatcher itself is sentinelized.
          $null = Install-CrgDispatcherSentinel -DispatcherPath $dispatcherPath
        }
        Write-Error "bootstrap.ps1: the dispatcher installed and verified, but its digest attestation could not be recorded beside it - run-gate.sh refuses to fire without the attestation. Re-run bootstrap.ps1 -DispatcherOnly to repair."
        exit 1
      }
      if ($null -ne $crgDispFs) { $crgDispFs.Dispose(); $crgDispFs = $null }
    }
    Write-Host "[bootstrap] installed dispatcher at $dispatcherPath"
    Write-Host "[bootstrap] (the dispatcher fail-closes on missing/untracked in-tree gate;"
    Write-Host "[bootstrap]  it lives per-clone outside the working tree, so a commit cannot edit it.)"
  }
} finally {
  Pop-Location
}

Write-Host ""

# ---- install manifest (docs/local-install-v1.md section 2) ----
# Written on every full install, the self-install included: the
# manifest is the local shape's trusted baseline and every shape's
# refresh-drift baseline. Each entry records the INSTALLED-BYTES digest
# produced from the buffered package source plus the provenance stamp and
# verified against the destination -- the mutable destination is never
# re-hashed into the record. (A self-install writes no stamp; its in-place
# package files are the installed bytes and are hashed directly.) Skipped only
# under -DispatcherOnly (no file-copy happened,
# so there is nothing safe to record). A gate install whose baseline
# cannot be recorded fails loudly rather than reporting success over a
# shape the dispatcher cannot verify.
# ORDER CONSTRAINT: this transaction runs AFTER the dispatcher install
# above, INSIDE the same install lock acquired before any dispatcher
# mutation, and the arming step re-validates the on-disk dispatcher
# through a handle it holds until the marker lands
# (Get-CrgDispatcherGuardHold) -- an abort at any earlier stage, a
# crash anywhere in this run, or a concurrent writer racing the
# validation must never leave an armed marker beside a dispatcher that
# predates the gate-untracking guard.
if (-not $DispatcherOnly) {
  $crgManifestPath = Join-Path $crgGitDir 'crg-install-manifest'
  # v2: the entry is the digest of the INSTALLED file, which from this version
  # carries a provenance line the package file does not. v1 meant the same thing
  # for its own installs (unstamped, so the two were identical); the version
  # exists so an external validator can tell which artifact an entry describes
  # rather than silently diffing against the wrong one.
  $crgManifestLines = @(
    'crg-install-manifest v2',
    ('installed: ' + [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture))
  )
  foreach ($f in $fileList) {
    if (-not $crgInstalledHashes.ContainsKey($f.Dst) -or "$($crgInstalledHashes[$f.Dst])" -cnotmatch '\A[0-9a-f]{64}\z') {
      Write-Error "bootstrap.ps1: the settled installed-byte digest for '$($f.Dst)' is absent or malformed; refusing to construct a manifest from a later live-file read."
      exit 1
    }
    $crgEntryHash = $crgInstalledHashes[$f.Dst]
    $crgManifestLines += ($crgEntryHash + '  ' + $f.Dst)
  }
  try {
    Assert-CrgHeldPackageSnapshot -Owners $crgPackageSourceOwners.ToArray()
    if (-not $selfInstall) { Assert-CrgHeldPackageSnapshot -Owners $crgPackageAttributeOwners.ToArray() }
    Assert-CrgInstallValuesEpoch -RepoRoot $targetRepoAbs -OutputAuthority $crgRenderOutputAuthority -SourceEvidence $crgValuesSourceEvidence -SourceOwner $crgValuesSourceOwner
    # TRACKED repository-owned attributes were behaviorally verified above
    # through one immutable graph, and every contributing repository-owned file
    # remains held share-read-only through this metadata commit.
    # Reopening those same paths with DELETE access would conflict with the
    # retained proof handles rather than strengthen the epoch.
    if ($crgRenderOutputAuthority.Family -ceq 'TRACKED') {
      if ($null -ne $crgLegacyAttrExpectedBytes) {
        if ($null -eq $crgLegacyAttrHold -or
            ([CrgBootstrap.NativeV3]::GetHandleAttributes($crgLegacyAttrHold.SafeFileHandle) -band 0x410) -ne 0 -or
            [CrgBootstrap.NativeV3]::GetLinkCount($crgLegacyAttrHold.SafeFileHandle) -ne 1 -or
            (Get-CrgSha256HexOfHeldStream -Stream $crgLegacyAttrHold) -cne (Get-CrgSha256HexOfBytes -Bytes ([byte[]]$crgLegacyAttrExpectedBytes))) {
          throw 'the retained legacy-transition .gitattributes identity changed after final graph validation'
        }
      }
      foreach ($crgIvAttributeHold in $crgInstallValuesAttributeHolds) {
        if ([CrgBootstrap.NativeV3]::GetLinkCount($crgIvAttributeHold.Stream.SafeFileHandle) -ne 1 -or
            (Get-CrgSha256HexOfHeldStream -Stream $crgIvAttributeHold.Stream) -cne $crgIvAttributeHold.Hash) {
          throw "retained attribute source '$($crgIvAttributeHold.RelativePath)' changed after final graph validation"
        }
      }
      foreach ($crgIvAttributeAbsence in $crgInstallValuesAttributeAbsences) {
        if ((Get-CrgPathOccupantKind -Path (Join-Path $targetRepoAbs $crgIvAttributeAbsence)) -cne 'empty') {
          throw "previously absent attribute source '$crgIvAttributeAbsence' appeared after final graph validation"
        }
      }
    }
  } catch {
    Write-Error "bootstrap.ps1: installed-project-values epoch changed before metadata commit ($($_.Exception.Message)). Rendered destinations remain untrusted by this run; no new manifest or LOCAL authorization marker was published."
    exit 1
  }
  # Shape probes run BEFORE publication: a probe failure aborts with
  # the previous manifest AND its still-valid marker untouched.
  $crgAuthProbe = Get-CrgLocalAuthorizationPaths -RepoRoot $targetRepoAbs -FileList $fileList
  if (-not $crgAuthProbe.Ok) { exit 1 }
  if ($crgAuthProbe.Paths.Count -gt 0) {
    # The dispatcher install above just wrote and byte-verified the
    # guard-bearing dispatcher, so a failed hold here means it was
    # removed or replaced mid-run -- unknown hook bytes that local
    # trust must not be armed beside. A successful hold pins the
    # validated bytes (no write, delete, or rename can land) until the
    # marker publication below is done.
    $crgDispHold = Get-CrgDispatcherGuardHold -RepoRoot $targetRepoAbs
    if (-not $crgDispHold.Ok) {
      Write-Host "[bootstrap] ERROR: the dispatcher at the hooks path no longer carries the current guard capability this run just installed (removed, replaced mid-run, or carrying retired PROJECT-MODE enforcement); refusing to arm the local-shape marker beside it. Nothing was published; the existing manifest and marker, if any, are untouched. Investigate the hooks path and re-run."
      exit 1
    }
  }
  $crgPlannedManifestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes((($crgManifestLines -join "`n") + "`n"))
  $crgPlannedManifestHash = Get-CrgSha256HexOfBytes -Bytes $crgPlannedManifestBytes
  if ($crgRenderOutputAuthority.Family -ceq 'TRACKED') {
    try {
      Assert-CrgLiveInstallValuesAttributeGraph -RepoRoot $targetRepoAbs -ScratchRoot $crgProofScratchParent -AttributeBuffers $crgAttrBuffers -ObjectIdLength $crgAttrOidLength
    } catch {
      Write-Error "bootstrap.ps1: the final live installed-project-values attribute graph changed before metadata reservation ($($_.Exception.Message)). No new manifest or LOCAL authorization marker was published. Remove or correct the overriding global, system, or info/attributes rule and re-run."
      exit 1
    }
  }
  $crgMarkerReservation = Start-CrgLocalAuthorizationMarkerReservationExact -GitDir $crgGitDir -Paths $crgAuthProbe.Paths -ExpectedManifestHash $crgPlannedManifestHash -PriorOwner $crgAuthMarkerOwner -PriorState $crgAuthMarkerPriorState
  if ($null -eq $crgMarkerReservation) { exit 1 }
  $crgManifestPayloadOwners = $crgInstalledPayloadOwners.ToArray()
  $crgPubHash = Publish-CrgInstallManifest -ManifestPath $crgManifestPath -Lines $crgManifestLines -RepoRoot $targetRepoAbs -FileList $fileList -PayloadOwners $crgManifestPayloadOwners -PriorOwner $crgManifestOwner -PriorState $crgManifestPriorState -PublicationRef ([ref]$crgManifestPublication)
  if (-not $crgPubHash) {
    Write-Host '[bootstrap] the manifest did not publish; the fixed marker reservation remains fail-closed rather than rearming beside an indeterminate manifest name.'
    exit 1
  }
  if (-not [string]::Equals($crgPubHash, $crgPlannedManifestHash, [System.StringComparison]::Ordinal)) {
    $null = Restore-CrgManifestPublicationExact -ManifestPath $crgManifestPath -OnlyIfManifestHash $crgPubHash -Publication $crgManifestPublication -MarkerReservation $crgMarkerReservation
    exit 1
  }
  Write-Host "[bootstrap] wrote install manifest (files verified while held stable, published through retained no-replace handles) -> $crgManifestPath"
  $crgAuthPub = Publish-CrgLocalAuthorizationMarkerExact -GitDir $crgGitDir -Paths $crgAuthProbe.Paths -ManifestPath $crgManifestPath -ExpectedManifestHash $crgPubHash -ManifestOwner $crgManifestPublication.PublishedOwner -GuardHold $crgDispHold -Reservation $crgMarkerReservation -FailedReservationRef ([ref]$crgFailedMarkerReservation)
  if ($crgAuthPub -cne 'ok') {
    # Disarm the exact new manifest on every marker failure. Only an exact
    # retained previous marker authorizes restoration of the previous manifest;
    # otherwise its superseded object is preserved and the live name is absent.
    $null = Restore-CrgManifestPublicationExact -ManifestPath $crgManifestPath -OnlyIfManifestHash $crgPubHash -Publication $crgManifestPublication -MarkerReservation $crgFailedMarkerReservation
    exit 1
  }
  if ($null -ne $crgManifestPublication.PublishedOwner.Stream) { $crgManifestPublication.PublishedOwner.Stream.Dispose(); $crgManifestPublication.PublishedOwner.Stream = $null }
  foreach ($crgPayloadOwner in @($crgManifestPublication.PublishedOwner.PayloadOwners)) { if ($null -ne $crgPayloadOwner.Fs) { $crgPayloadOwner.Fs.Dispose(); $crgPayloadOwner.Fs = $null } }
  if ($null -ne $crgManifestPublication.PreviousOwner -and $null -ne $crgManifestPublication.PreviousOwner.Stream) { $crgManifestPublication.PreviousOwner.Stream.Dispose(); $crgManifestPublication.PreviousOwner.Stream = $null }
  # LAST, and only after the manifest and marker have both published. The
  # version record is PROVENANCE about a completed install: publishing it
  # earlier would attest an install the marker had not yet authorized, and a
  # failed authorization above rolls the manifest back to the previous epoch --
  # which the previous version record already describes, so the pair stays
  # coherent without this run touching it.
  $crgVersionPath = Join-Path $crgGitDir 'crg-install-version'
  $crgVerPub = Publish-CrgInstallVersion -RecordPath $crgVersionPath -Version $crgPackageVersion -SourceCommit $crgSourceCommit -PriorOwner $crgUpVersionOwner -PriorState $crgUpVersionPriorState
  if ($crgVerPub -ceq 'ok') {
    Write-Host "[bootstrap] recorded install version $crgPackageVersion (source $crgSourceCommit) -> $crgVersionPath"
  } elseif ($crgVerPub -ceq 'failed-remnant') {
    # A remnant is not a cosmetic failure. The record left behind is one this
    # run could not vouch for, and a later package whose version happens to
    # match it would classify itself as a same-version re-install -- disarming
    # the guard that refuses to overwrite local edits. The gate FILES are
    # installed and verified at this point, so the repair is a hand deletion,
    # not a re-install; reporting success here would hide a state that silently
    # weakens the next upgrade.
    Write-Error "bootstrap.ps1: the gate files are installed and verified, but a version record at '$crgVersionPath' could neither be published nor removed. DELETE IT BY HAND, then re-run bootstrap.ps1 to record this install's version. Until then a later upgrade may read that record as this install's and skip its local-edit refusal."
    exit 1
  } else {
    # `failed-absent` is safe for the NEXT upgrade but is not success for THIS
    # install: provenance publication is part of the completed transaction, and
    # silently continuing here was how a forced post-publication failure still
    # reached the success checklist. Re-running repairs the absent record without
    # risking installed bytes (the retry escape admits already-installed content).
    Write-Error "bootstrap.ps1: the gate files and manifest are installed and verified, but the install version record could not be published and was removed. Re-run the retained package explicitly: powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetRepo `"$targetRepoAbs`" -Force. This run is incomplete and reports failure."
    exit 1
  }
  if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal)) {
    # No transition identity may be published for a HEAD that moved after the
    # locked snapshot. A self-host failure here deliberately leaves the active
    # custody epoch in its admitted pre-transition state for an exact-base retry.
    $crgBeforeTransitionHead = Get-CrgRetiredProjectModeHeadState -Repo $targetRepoAbs
    if ([string]::Equals($crgBeforeTransitionHead.State, 'error', [System.StringComparison]::Ordinal) -or
        -not [string]::Equals("$($crgBeforeTransitionHead.Identity)", "$($crgRetiredPmHead.Identity)", [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($crgBeforeTransitionHead.State, $crgRetiredPmHead.State, [System.StringComparison]::Ordinal)) {
      Write-Error "bootstrap.ps1: trusted HEAD changed before legacy transition publication. No transition or completion identity was published; any active self-host custody remains bound to '$crgLegacyBaseHead' for an exact-base retry."
      exit 1
    }
    # Published only after every ordinary full-install artifact succeeded. A
    # DispatcherOnly refresh never creates this identity record, and a partial full
    # install cannot produce a transition identity record.
    if ($selfInstall) {
      if ($null -eq $crgLegacyRoutingCustody) {
        Write-Error "bootstrap.ps1: the self-host gate files installed, but the locked write-ahead routing custody is no longer available. The refreshed dispatcher will refuse a review-kernel landing."
        exit 1
      }
    }
    $crgLegacyTransitionRecord = Publish-CrgLegacyReviewKernelTransitionRecord -RepoRoot $targetRepoAbs -GitDir $crgGitDir -ProofScratchRoot $crgProofScratchParent -BaseHead $crgLegacyBaseHead -CandidateBuffers $crgInstalledBuffers -AttributeExpectedBytes $crgLegacyAttrExpectedBytes
    if ($null -eq $crgLegacyTransitionRecord) {
      Write-Error "bootstrap.ps1: the gate files installed, but the legacy transition identity record could not be published. The refreshed dispatcher will refuse a review-kernel landing; repair the reported condition and re-run the full bootstrap."
      exit 1
    }
    $crgLegacyTransitionHold = $crgLegacyTransitionRecord.Hold
    $crgLegacyTransitionDisposition = if ($crgLegacyTransitionRecord.Reused) { 'reused exact existing' } else { 'published create-new' }
    Write-Host "[bootstrap] published base-HEAD-bound legacy transition identity record ($crgLegacyTransitionDisposition) -> $($crgLegacyTransitionRecord.RecordPath)"
  }
  Write-Host ""
}

# The final success claim is bound to the same locked HEAD snapshot. The legacy
# publisher performs its own base check before publication; this post-publication
# comparison additionally prevents a concurrent commit from crossing the last
# check and still receiving a successful install report.
$crgSuccessHead = Get-CrgRetiredProjectModeHeadState -Repo $targetRepoAbs
if ([string]::Equals($crgSuccessHead.State, 'error', [System.StringComparison]::Ordinal) -or
    -not [string]::Equals("$($crgSuccessHead.Identity)", "$($crgRetiredPmHead.Identity)", [System.StringComparison]::Ordinal) -or
    -not [string]::Equals($crgSuccessHead.State, $crgRetiredPmHead.State, [System.StringComparison]::Ordinal)) {
  $crgFinalIdentityState = 'no new transition identity was published by this run'
  if ($null -ne $crgLegacyTransitionRecord -and -not $crgLegacyTransitionRecord.Reused -and
      $null -ne $crgLegacyTransitionHold -and $null -ne $crgLegacyTransitionHold.Stream) {
    $crgFinalIdentityRemoved = Remove-CrgOwnedScratchHandle -Path $crgLegacyTransitionRecord.RecordPath -Stream $crgLegacyTransitionHold.Stream -Label 'new transition identity after final HEAD movement'
    $crgLegacyTransitionHold = $null
    $crgFinalIdentityState = if ($crgFinalIdentityRemoved) { 'the exact new transition identity was removed through its retained publication handle' } else { "the exact new transition identity could not be removed and remains at '$($crgLegacyTransitionRecord.RecordPath)'" }
  }
  Write-Error "bootstrap.ps1: trusted HEAD changed before the install transaction could report success; $crgFinalIdentityState. Installed payload remains fail-closed, and active self-host custody remains retry-safe. Inspect the current HEAD and re-run from the intended commit."
  exit 1
}
$crgRetiredPmHead = $crgSuccessHead

} finally {
  if ($null -ne $crgManifestPublication) {
    if ($null -ne $crgManifestPublication.PublishedOwner -and $null -ne $crgManifestPublication.PublishedOwner.Stream) { try { $crgManifestPublication.PublishedOwner.Stream.Dispose() } catch { } }
    if ($null -ne $crgManifestPublication.PublishedOwner) { foreach ($crgPayloadOwner in @($crgManifestPublication.PublishedOwner.PayloadOwners)) { if ($null -ne $crgPayloadOwner.Fs) { try { $crgPayloadOwner.Fs.Dispose() } catch { }; $crgPayloadOwner.Fs = $null } } }
    if ($null -ne $crgManifestPublication.PreviousOwner -and $null -ne $crgManifestPublication.PreviousOwner.Stream) { try { $crgManifestPublication.PreviousOwner.Stream.Dispose() } catch { } }
  }
  if ($null -ne $crgManifestOwner -and $null -ne $crgManifestOwner.Stream) { try { $crgManifestOwner.Stream.Dispose() } catch { } }
  if ($null -ne $crgAuthMarkerOwner -and $null -ne $crgAuthMarkerOwner.Stream) { try { $crgAuthMarkerOwner.Stream.Dispose() } catch { } }
  if ($null -ne $crgMarkerReservation) {
    if ($null -ne $crgMarkerReservation.ReservationOwner -and $null -ne $crgMarkerReservation.ReservationOwner.Stream) { try { $crgMarkerReservation.ReservationOwner.Stream.Dispose() } catch { } }
    if ($null -ne $crgMarkerReservation.PreviousOwner -and $null -ne $crgMarkerReservation.PreviousOwner.Stream) { try { $crgMarkerReservation.PreviousOwner.Stream.Dispose() } catch { } }
  }
  if ($null -ne $crgFailedMarkerReservation) {
    if ($null -ne $crgFailedMarkerReservation.ReservationOwner -and $null -ne $crgFailedMarkerReservation.ReservationOwner.Stream) { try { $crgFailedMarkerReservation.ReservationOwner.Stream.Dispose() } catch { } }
    if ($null -ne $crgFailedMarkerReservation.PreviousOwner -and $null -ne $crgFailedMarkerReservation.PreviousOwner.Stream) { try { $crgFailedMarkerReservation.PreviousOwner.Stream.Dispose() } catch { } }
  }
  if ($null -ne $crgUpVersionOwner -and $null -ne $crgUpVersionOwner.Stream) { try { $crgUpVersionOwner.Stream.Dispose() } catch { } }
  foreach ($crgAttributeSourceHold in $crgAttributeSourceHolds) { if ($null -ne $crgAttributeSourceHold) { try { $crgAttributeSourceHold.Dispose() } catch { } } }
  if ($null -ne $crgLegacyAttrHold) { try { $crgLegacyAttrHold.Dispose() } catch { } }
  if ($null -ne $crgLegacyTransitionHold -and $null -ne $crgLegacyTransitionHold.Stream) { try { $crgLegacyTransitionHold.Stream.Dispose() } catch { } }
  if ($null -ne $crgRoutingLease) { Close-CrgLegacyRoutingCustodyLease -Lease $crgRoutingLease }
  foreach ($crgInstallBackupStream in $crgInstallBackupStreams) { if ($null -ne $crgInstallBackupStream) { try { $crgInstallBackupStream.Dispose() } catch { } } }
  foreach ($crgInstallCustodyOwner in $crgInstallCustodyOwners) { if ($null -ne $crgInstallCustodyOwner -and $null -ne $crgInstallCustodyOwner.Stream) { try { $crgInstallCustodyOwner.Stream.Dispose() } catch { } } }
  foreach ($crgInstalledPayloadOwner in $crgInstalledPayloadOwners) { if ($null -ne $crgInstalledPayloadOwner -and $null -ne $crgInstalledPayloadOwner.Fs) { try { $crgInstalledPayloadOwner.Fs.Dispose(); $crgInstalledPayloadOwner.Fs = $null } catch { } } }
  if ($null -ne $crgValuesSourceOwner -and $null -ne $crgValuesSourceOwner.Stream) { try { $crgValuesSourceOwner.Stream.Dispose(); $crgValuesSourceOwner.Stream = $null } catch { } }
  if ($null -ne $crgDispHold -and $null -ne $crgDispHold.Handle) { try { $crgDispHold.Handle.Dispose() } catch { } }
  if ($null -ne $crgStageLock) { try { $crgStageLock.Dispose() } catch { } }
  if ($null -ne $crgDispLock) { try { $crgDispLock.Dispose() } catch { } }
  if ($crgGitEnvironmentBound) {
    [Environment]::SetEnvironmentVariable('GIT_COMMON_DIR', $null, 'Process')
    [Environment]::SetEnvironmentVariable('GIT_WORK_TREE', $null, 'Process')
    [Environment]::SetEnvironmentVariable('GIT_DIR', $null, 'Process')
    $crgGitEnvironmentBound = $false
  }
  foreach ($crgPackageSourceOwner in $crgPackageSourceOwners) { if ($null -ne $crgPackageSourceOwner -and $null -ne $crgPackageSourceOwner.Stream) { try { $crgPackageSourceOwner.Stream.Dispose(); $crgPackageSourceOwner.Stream = $null } catch { } } }
  foreach ($crgPackageAttributeOwner in $crgPackageAttributeOwners) { if ($null -ne $crgPackageAttributeOwner -and $null -ne $crgPackageAttributeOwner.Stream) { try { $crgPackageAttributeOwner.Stream.Dispose(); $crgPackageAttributeOwner.Stream = $null } catch { } } }
  foreach ($crgGitIndirectionHold in $crgGitIndirectionHolds) { if ($null -ne $crgGitIndirectionHold -and $null -ne $crgGitIndirectionHold.Stream) { try { $crgGitIndirectionHold.Stream.Dispose(); $crgGitIndirectionHold.Stream = $null } catch { } } }
  if ($null -ne $crgNamespaceLease) { Close-CrgRootedNamespace -Lease $crgNamespaceLease; $crgNamespaceLease = $null }
}

if ($DispatcherOnly) {
  # The full checklist describes a fresh install (values-source review, agent
  # document merge, bootstrap commit, smoke test) -- none of it applies to a
  # dispatcher refresh on an already-installed clone, and printing it would
  # direct the operator at unrelated package-payload work.
  Write-Host "================================================================"
  Write-Host "[bootstrap] -DispatcherOnly complete: the per-clone dispatcher at"
  Write-Host "[bootstrap] $dispatcherPath"
  Write-Host "[bootstrap] now carries the gate-untracking guard and no longer enforces project mode itself."
  if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal)) {
    Write-Host "[bootstrap] WARNING: trusted tracked HEAD still carries retired project-mode enforcement."
    Write-Host "[bootstrap] Run the full package bootstrap with -Force. A full successful install publishes"
    Write-Host "[bootstrap] the base-HEAD-bound staged-blob identity record needed for the narrow transition"
    Write-Host "[bootstrap] (a self-host run also preserves the temporarily reset routing drivers in verified custody)."
    Write-Host "[bootstrap] DispatcherOnly deliberately creates neither record nor custody."
  } else {
    Write-Host "[bootstrap] trusted HEAD carries no detected retired project-mode enforcement."
  }
  Write-Host "[bootstrap] No tracked file was touched."
  Write-Host "================================================================"
  exit 0
}
Write-Host "================================================================"
Write-Host "[bootstrap] Install complete. REMAINING MANUAL STEPS:"
Write-Host "================================================================"
Write-Host ""
Write-Host "1. REVIEW the fixed project-values source retained at:"
Write-Host "   $targetRepoAbs\CROSS-REVIEW-VALUES.md"
Write-Host ""
Write-Host "   Bootstrap rendered the three validated value blocks into every installed"
Write-Host "   review surface. Future value changes are made only in this fixed source,"
Write-Host "   staged first for TRACKED authority, then applied with a full -Force run."
Write-Host "   Installed templates are generated outputs, not customization sources."
Write-Host ""
Write-Host "2. MERGE the agent-instruction template at:"
Write-Host "   $targetRepoAbs\docs\AGENTS.md.template"
Write-Host ""
Write-Host "   The two backends auto-discover DIFFERENT files:"
Write-Host "   - Codex CLI auto-loads AGENTS.md from the repo root."
Write-Host "   - Claude Code CLI auto-loads CLAUDE.md (project + walk-up)"
Write-Host "     AND the user-global ~/.claude/CLAUDE.md. It does NOT"
Write-Host "     auto-load AGENTS.md."
Write-Host "   Merge the template sections into BOTH AGENTS.md AND CLAUDE.md"
Write-Host "   if you want both backends to see the contract as authoritative."
Write-Host "   (Or rely on a pre-existing ~/.claude/CLAUDE.md for the Claude"
Write-Host "   side.) See $packageRoot\INSTALL.md for guidance."
Write-Host ""
Write-Host "3. CONFIGURE the backend(s) you'll use:"
Write-Host "   - Codex: $packageRoot\INSTALL.md  Step 5"
Write-Host "   - Claude: $packageRoot\INSTALL.md  Step 6 (run interactive"
Write-Host "     'claude' once on this machine to seed keychain auth)"
Write-Host ""
Write-Host ""
# LOCAL install shape (docs/local-install-v1.md): trust is decided per
# FILE (tracked -> HEAD baseline; untracked+ignored -> manifest
# baseline), but the CHECKLIST needs one workflow, so it partitions
# every gate destination -- declaring "local" off a single path would
# hand a mixed layout instructions whose bootstrap-commit or reseal
# steps do not cover the other files. TRI-STATE probe per destination:
# a failed check-ignore must not classify (either misprint would send
# the operator down the wrong workflow).
$crgSelfHostExactRestoredLanding = $false
if ($selfInstall -and $crgRoutingResume.State -ceq 'restored') {
  $crgRestoredLanding = "$($crgRoutingResume.LandingHead)"
  $crgRestoredCurrentRows = @(& git -C $targetRepoAbs rev-parse --verify 'HEAD^{commit}' 2>$null)
  if ($LASTEXITCODE -ne 0 -or $crgRestoredCurrentRows.Count -ne 1 -or
      "$($crgRestoredCurrentRows[0])" -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z' -or
      $crgRestoredLanding -cnotmatch '\A[0-9a-f]{40}([0-9a-f]{24})?\z') {
    Write-Error 'bootstrap.ps1: the restored routing-custody marker or current HEAD could not be classified for the post-kernel completion checklist. No staging command is safe to print; preserve the marker and inspect the repository state.'
    exit 1
  }
  $crgSelfHostExactRestoredLanding = [string]::Equals("$($crgRestoredCurrentRows[0])", $crgRestoredLanding, [System.StringComparison]::Ordinal)
}
$crgShapeIgnored = @()
$crgShapeExposed = @()
foreach ($f in $fileList) {
  $crgDstIgnState = Get-CrgCheckIgnoreState -Repo $targetRepoAbs -Path $f.Dst
  if (([string]$crgDstIgnState).StartsWith('error:', [System.StringComparison]::Ordinal)) {
    Write-Error "bootstrap.ps1: git check-ignore failed ($crgDstIgnState) probing '$($f.Dst)' in '$targetRepoAbs'; cannot classify the install shape. Diagnose the repository, then re-run."
    exit 1
  }
  if ([string]::Equals($crgDstIgnState, 'ignored', [System.StringComparison]::Ordinal)) { $crgShapeIgnored += $f.Dst } else { $crgShapeExposed += $f.Dst }
}
$crgShapeLocal = ($crgShapeExposed.Count -eq 0)
$crgShapeMixed = ((-not $crgShapeLocal) -and ($crgShapeIgnored.Count -gt 0))
if ([string]::Equals($crgRetiredPmHead.State, 'legacy', [System.StringComparison]::Ordinal)) {
$crgLegacyStagePaths = @($crgLegacyTransitionRecord.Paths)
Write-Host "5. PRE-REDESIGN TRACKED REVIEW KERNEL DETECTED -- USE TWO LANDINGS."
Write-Host "   HEAD still tells the old hook/wrappers/prompt to block project work"
Write-Host "   from PROJECT-MODE.md. Candidate tracked files cannot retire that policy"
Write-Host "   while the old HEAD kernel judges the same commit. The refreshed dispatcher"
Write-Host "   therefore admits one audited transition whose staged modes and filter-aware"
Write-Host "   blob IDs exactly match the successful full bootstrap's transition identity record:"
Write-Host "   $($crgLegacyTransitionRecord.RecordPath)"
Write-Host ""
Write-Host "   A. Restore every pre-hook routing driver to trusted HEAD bytes:"
if ($selfInstall) {
foreach ($crgCustodyEntry in @($crgLegacyRoutingCustody.Entries)) {
  if ($crgCustodyEntry.BasePresent) {
    Write-Host "      git restore --source=HEAD --staged --worktree -- $($crgCustodyEntry.RepoPath)"
  } else {
    Write-Host "      Remove-Item -LiteralPath $($crgCustodyEntry.RepoPath)"
    Write-Host "      ($($crgCustodyEntry.RepoPath) is positively absent from HEAD; verified custody retains its phase-two bytes.)"
  }
}
} else {
Write-Host "      git restore --source=HEAD --staged --worktree -- scripts/codex/commit.ps1 scripts/claude/commit.ps1"
if ($crgLegacyRunGateHeadPresent) {
Write-Host "      git restore --source=HEAD --staged --worktree -- scripts/run-gate.sh"
} else {
Write-Host "      Remove-Item -LiteralPath scripts/run-gate.sh"
Write-Host "      (scripts/run-gate.sh is positively absent from HEAD. Remove only the bootstrap-created"
Write-Host "       TARGET worktree copy; the package source retains the phase-two bytes.)"
}
}
Write-Host ""
Write-Host "   B. Stage exactly the paths named by the published identity record:"
Write-Host "      git add -- $($crgLegacyStagePaths -join ' ')"
Write-Host "      git diff --cached --name-only"
Write-Host "      git -c core.whitespace=cr-at-eol diff --cached --check"
Write-Host "      The dispatcher refuses a missing listed path, any mode/blob mismatch, any"
Write-Host "      extra staged path, a stale base HEAD, and staged or dirty run-gate.sh."
Write-Host ""
Write-Host "   C. Land only that kernel through raw git with the ordinary audited skip:"
Write-Host "      `$env:CROSS_REVIEW_SKIP = '1'"
Write-Host "      try { git commit -m `"cross-review-gate: transition review context`" }"
Write-Host "      finally { Remove-Item Env:CROSS_REVIEW_SKIP -ErrorAction SilentlyContinue }"
Write-Host "      The retired CROSS_REVIEW_ALLOW_MODE_CHANGE variable has no authority and"
Write-Host "      must not be used; stable entry points scrub every case spelling automatically."
Write-Host "      Candidate kernel bytes do not execute during this commit; the dispatcher"
Write-Host "      first proves every staged entry against the record, then records the staged"
Write-Host "      tree in the fixed refs/crg-review-skips audit chain."
Write-Host ""
Write-Host "   D. The kernel commit must be in the TARGET BASE before any remaining branch"
Write-Host "      review. Land the kernel alone, then update/rebase the remaining branch onto"
Write-Host "      that base. A target branch that still has the old kernel still reviews with"
Write-Host "      the old policy."
Write-Host ""
if ($selfInstall) {
Write-Host "   E. Restore the recorded raw self-host routing drivers from verified base-bound custody:"
Write-Host "      powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetRepo . -RestoreLegacyRoutingCustody"
Write-Host "      This durable recovery re-parses the active custody record, binds HEAD to the"
Write-Host "      exact recorded base->kernel landing, freezes every base-present destination,"
Write-Host "      and uses create-new publication for every base-absent destination. For audit,"
Write-Host "      the immutable custody identities are:"
foreach ($crgCustodyEntry in @($crgLegacyRoutingCustody.Entries)) {
  if ($crgCustodyEntry.BasePresent) {
    Write-Host "      - $($crgCustodyEntry.RepoPath): phase-A $($crgCustodyEntry.BaseMode) $($crgCustodyEntry.BaseOid); custody SHA-256 $($crgCustodyEntry.Hash)"
  } else {
    Write-Host "      - $($crgCustodyEntry.RepoPath): phase-A absent; custody SHA-256 $($crgCustodyEntry.Hash)"
  }
}
Write-Host "      The recovery operation restores only the routing drivers temporarily reset in A;"
Write-Host "      every other candidate package change remains in the worktree untouched."
Write-Host "      Use the durable recovery command above, then re-run the full self-bootstrap"
Write-Host "      under the now-current HEAD kernel:"
} else {
Write-Host "   E. Re-run the full package bootstrap after the kernel commit:"
}
Write-Host "      powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetRepo . -Force"
Write-Host "      Before this upgrade, place the intended legacy Project context, Project"
Write-Host "      hazards, and SCOPED authority set into CROSS-REVIEW-VALUES.md. Never"
Write-Host "      restore or scrape the whole legacy prompt; bootstrap renders only the"
Write-Host "      explicit source blocks into the current package templates."
Write-Host ""
Write-Host "   F. Stage the remaining package inventory printed by that second bootstrap"
Write-Host "      and commit through raw git under both trusted HEAD reviewers:"
Write-Host "      `$env:REVIEW_BACKEND = 'both'"
Write-Host "      try { git commit -m `"cross-review-gate: complete review-context upgrade`" }"
Write-Host "      finally { Remove-Item Env:REVIEW_BACKEND -ErrorAction SilentlyContinue }"
Write-Host "      The retired CROSS_REVIEW_ALLOW_MODE_CHANGE variable has no authority and"
Write-Host "      must not be used; stable entry points scrub every case spelling automatically."
Write-Host "      Do not invoke candidate scripts/*/commit.ps1 or scripts/run-gate.sh until"
Write-Host "      that remaining package commit has landed."
Write-Host ""
Write-Host "   Interruption recovery: before the kernel commit, restore the candidate source"
if ($selfInstall) {
Write-Host "   drivers with -RestoreLegacyRoutingCustody while HEAD is still the recorded base,"
Write-Host "   re-run the full self-bootstrap, then repeat A and B. After the kernel commit,"
} else {
Write-Host "   routing drivers with A and rebuild B. After the kernel commit, re-run E and"
Write-Host "   complete F"
}
if ($selfInstall) { Write-Host "   run the durable recovery in E and complete F" }
Write-Host "   before unrelated work. After a failed F review, fix the candidate under the"
Write-Host "   current HEAD kernel and retry normally."
} elseif ($crgSelfHostExactRestoredLanding) {
Write-Host "5. COMPLETE THE RESTORED REVIEW-CONTEXT KERNEL LANDING (tracked source inventory)."
Write-Host "   The verified routing-custody marker's landing-head is exactly current HEAD."
Write-Host "   Stage every remaining change to an ALREADY-TRACKED package-source path from"
Write-Host "   the repository root; this deliberately does not adopt arbitrary untracked files:"
Write-Host "     git add -u -- :/"
Write-Host "   Inspect the complete tracked remainder and every still-untracked path:"
Write-Host "     git status --short --untracked-files=all"
Write-Host "     git diff --cached --name-only"
Write-Host "     git diff --name-only"
Write-Host "     git -c core.whitespace=cr-at-eol diff --cached --check"
Write-Host "   Add each intentional NEW package-source path explicitly, never with git add -A or git add .:"
Write-Host "     git add -- <intentional-new-package-source-path> [<additional-path> ...]"
Write-Host "   Repeat the status/name-only/check commands, then commit through raw git under"
Write-Host "   both trusted HEAD reviewers (the audited bootstrap skip is not authorized here):"
Write-Host "     `$env:REVIEW_BACKEND = 'both'"
Write-Host "     try { git commit -m `"cross-review-gate: complete review-context upgrade`" }"
Write-Host "     finally { Remove-Item Env:REVIEW_BACKEND -ErrorAction SilentlyContinue }"
} elseif ($crgShapeLocal) {
Write-Host "5. LOCAL INSTALL SHAPE DETECTED (every gate file path is ignored;"
Write-Host "   $packageRoot\docs\local-install-v1.md): SKIP the bootstrap commit -- each"
Write-Host "   IGNORED-AND-UNTRACKED gate file verifies against the install"
Write-Host "   manifest this run wrote (an ignored file that is nonetheless"
Write-Host "   TRACKED keeps its HEAD baseline; the trust chain decides per"
Write-Host "   file). Change project configuration only in CROSS-REVIEW-VALUES.md,"
Write-Host "   then rerun the package bootstrap with -Force so both rendered outputs,"
Write-Host "   the manifest, and the authorization marker publish as one install epoch."
Write-Host "   -SealManifest remains only the operator-sanctioned recovery step for an"
Write-Host "   exact metadata-free or deliberately changed admitted inventory; normal"
Write-Host "   configuration changes never require or use a reseal."
} elseif ($crgShapeMixed) {
Write-Host "5. MIXED INSTALL SHAPE -- UNIFY BEFORE COMMITTING WORK. Trust is"
Write-Host "   decided per file (a tracked file verifies against HEAD, an"
Write-Host "   ignored file against the install manifest), so components can"
Write-Host "   verify individually -- but the split doubles the maintenance"
Write-Host "   surface (bootstrap commit AND reseal duties), this checklist"
Write-Host "   cannot give one workflow for it, and an UNTRACKED, NOT-ignored"
Write-Host "   path that the trust chain consumes at commit time refuses"
Write-Host "   commits outright (the ignored files keep verifying against"
Write-Host "   the manifest, refresh-drift protection included):"
foreach ($crgShapePath in $crgShapeIgnored) { Write-Host "   - ignored (manifest baseline): $crgShapePath" }
foreach ($crgShapePath in $crgShapeExposed) { Write-Host "   - NOT ignored (needs HEAD):    $crgShapePath" }
Write-Host "   Either add the NOT-ignored paths to the repo's info/exclude"
Write-Host "   (resolve it: git rev-parse --git-path info/exclude) and re-run"
Write-Host "   this bootstrap with -Force (LOCAL shape), or remove the gate"
Write-Host "   ignore rules and re-run with -Force (TRACKED shape -- the"
Write-Host "   checklist then prints the bootstrap-commit step this item"
Write-Host "   replaces). -Force is required over the already-copied gate files"
Write-Host "   and backs each one up before overwriting."
} else {
Write-Host "5. BOOTSTRAP COMMIT the gate files (REQUIRED -- the hook refuses"
Write-Host "   to run untracked wrapper/prompt files because they have no"
Write-Host "   trusted baseline). The first commit that adds the gate must"
Write-Host "   use CROSS_REVIEW_SKIP=1 since HEAD has nothing to verify yet."
Write-Host "   Include .gitignore (this bootstrap created/updated it with 'logs/')"
Write-Host "   so the gate-artifact ignore rule is committed for later clones:"
# The candidate set is the installer's own inventory, ONE ENTRY PER FILE plus
# the two config files: Get-CrgStagingPlan classifies each individually.
$crgStageCands = New-Object 'System.Collections.Generic.List[string]'
foreach ($crgStageF in $fileList) { $crgStageCands.Add([string]$crgStageF.Dst) | Out-Null }
foreach ($crgStageCfg in @('.gitignore', '.gitattributes')) { $crgStageCands.Add($crgStageCfg) | Out-Null }
$crgStagePlan = Get-CrgStagingPlan -Repo $targetRepoAbs -Candidates $crgStageCands.ToArray()
$crgStageList = $crgStagePlan.List
$crgStageUnknown = $crgStagePlan.Unknown
Write-Host "   - git add $($crgStageList -join ' ')"
if ($crgStageUnknown.Count -gt 0) {
  Write-Host "     (NOTE: the tracked/ignore state of $($crgStageUnknown -join ', ') could not be probed;"
  Write-Host "      if git refuses one of them as ignored, drop that path from the command.)"
}
Write-Host "   PowerShell:"
Write-Host "     - `$env:CROSS_REVIEW_SKIP = '1'"
Write-Host "     - try { git commit -m `"cross-review-gate: install`" }"
Write-Host "       finally { Remove-Item Env:CROSS_REVIEW_SKIP -ErrorAction SilentlyContinue }"
Write-Host "   bash/sh:"
Write-Host "     - CROSS_REVIEW_SKIP=1 git commit -m `"cross-review-gate: install`""
}
Write-Host ""
Write-Host "6. SMOKE-TEST end-to-end with a small commit (gate runs normally now):"
Write-Host "   - echo `"install check`" > install-check.tmp"
Write-Host "   - git add install-check.tmp"
Write-Host "   - scripts/claude/commit.ps1 -m `"install check`"   (Codex reviews)"
Write-Host "     -- or, for a Claude-only install -- scripts/codex/commit.ps1 -m `"install check`"   (Claude reviews)"
Write-Host "   - (cleanup) git rm install-check.tmp; then re-run the SAME commit.ps1 wrapper -m `"remove install check`""
Write-Host ""
Write-Host "7. (OPTIONAL) DECLARE a project mode by adding PROJECT-MODE.md at the"
Write-Host "   repo root. The tracked declaration supplies review context; no special"
Write-Host "   activation, ordering, or environment authorization applies. Land the"
Write-Host "   declaration through an ordinary reviewed commit, alongside related work"
Write-Host "   when appropriate. CROSS_REVIEW_SKIP=1 remains the same audited skip used"
Write-Host "   for any other staged path. After a valid declaration lands, it supplies"
Write-Host "   context to later reviews; the current run uses the review-base declaration."
Write-Host "   Refresh every other existing clone with bootstrap.ps1 -DispatcherOnly:"
Write-Host "   pulling tracked files cannot replace an older per-clone dispatcher that"
Write-Host "   still carries retired PROJECT-MODE enforcement."
Write-Host "   Grammar + mode semantics: $packageRoot\docs\project-mode-doctrine-v1.md"
Write-Host "   (and the 'Project mode' section of the installed prompt template)."
Write-Host ""
Write-Host "Full step-by-step reference: $packageRoot\INSTALL.md"
Write-Host "================================================================"

exit 0
