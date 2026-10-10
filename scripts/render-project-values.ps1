# render-project-values.ps1 - validate and inline project-owned review values.
#
# The standalone renderer changes only the two fixed slot-bearing outputs.
# Bootstrap consumes the marked byte-only core directly; no review, hook, or
# dispatcher path performs runtime values lookup.

[CmdletBinding(DefaultParameterSetName = 'Apply')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Apply')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Check')]
  [string]$TargetRepo,

  [Parameter(Mandatory = $true, ParameterSetName = 'Check')]
  [switch]$Check
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell caches the [Console] encodings when they are first read,
# and a code page changed later by chcp or by a child process on the same
# console does not update that cache, so the encoding to restore is taken from
# the console's own code page: the cached object while it still names that
# page (or when no console is attached), otherwise the encoding of the page.
function Get-CrgConsoleRestoreEncoding {
  param([switch]$ConsoleInput)
  if (-not ('CrgConsoleCodePage.NativeV1' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @'
namespace CrgConsoleCodePage {
  public static class NativeV1 {
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    public static extern uint GetConsoleCP();
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    public static extern uint GetConsoleOutputCP();
  }
}
'@
    if (-not ('CrgConsoleCodePage.NativeV1' -as [type])) { throw 'the console code-page reader could not be compiled' }
  }
  if ($ConsoleInput) {
    $cached = [Console]::InputEncoding
    $codePage = [CrgConsoleCodePage.NativeV1]::GetConsoleCP()
  } else {
    $cached = [Console]::OutputEncoding
    $codePage = [CrgConsoleCodePage.NativeV1]::GetConsoleOutputCP()
  }
  if ($codePage -eq 0 -or $cached.CodePage -eq $codePage) { return $cached }
  return [System.Text.Encoding]::GetEncoding([int]$codePage)
}

# Native process-environment enumeration is required because managed maps can
# collapse case-distinct Windows names before a prohibited Git selector is seen.
function Initialize-CrgRendererEnvironmentNative {
  if ('CrgProjectValues.EnvironmentNativeV1' -as [type]) { return }
  Add-Type -TypeDefinition @'
namespace CrgProjectValues {
  using System;
  using System.Collections.Generic;
  using System.ComponentModel;
  using System.Runtime.InteropServices;

  public static class EnvironmentNativeV1 {
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
          if (entry == null) { throw new InvalidOperationException("raw environment block contained an unreadable entry"); }
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

    public static void SetProcessVariable(string name, string value) {
      ValidateName(name);
      if (value == null || value.IndexOf('\0') >= 0) { throw new ArgumentException("environment variable values must be non-null and NUL-free", "value"); }
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
  if (-not ('CrgProjectValues.EnvironmentNativeV1' -as [type])) {
    throw [System.PlatformNotSupportedException]::new('raw Windows environment support is unavailable')
  }
}

function ConvertFrom-CrgRawEnvironmentEntry {
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Entry)
  if ([string]::IsNullOrEmpty($Entry) -or $Entry.IndexOf([char]0) -ge 0) {
    throw [System.InvalidOperationException]::new('raw environment entries must be non-empty and NUL-free')
  }
  $startsWithEquals = $Entry.StartsWith('=', [System.StringComparison]::Ordinal)
  # [char] overloads: IndexOf(string) compares by culture.
  $separator = if ($startsWithEquals) { $Entry.IndexOf([char]'=', 1) } else { $Entry.IndexOf([char]'=') }
  if (($startsWithEquals -and $separator -le 1) -or (-not $startsWithEquals -and $separator -le 0)) {
    throw [System.InvalidOperationException]::new('raw environment entry does not use name=value grammar')
  }
  return [pscustomobject]@{ Name = $Entry.Substring(0, $separator); Value = $Entry.Substring($separator + 1) }
}

function Test-CrgProhibitedGitSelectorName {
  param([Parameter(Mandatory = $true)][string]$Name)
  $fixed = @(
    'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
    'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_NAMESPACE',
    'GIT_REFERENCE_BACKEND', 'GIT_REPLACE_REF_BASE', 'GIT_GRAFT_FILE',
    'GIT_SHALLOW_FILE', 'GIT_ATTR_SOURCE', 'GIT_ATTR_NOSYSTEM', 'GIT_CONFIG',
    'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM',
    'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT'
  )
  foreach ($candidate in $fixed) {
    if ([string]::Equals($Name, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $Name -match '^(?i:GIT_CONFIG_(?:KEY|VALUE)_[0-9]+)$'
}

function Get-CrgRawProcessEnvironmentEntries {
  Initialize-CrgRendererEnvironmentNative
  $entries = [CrgProjectValues.EnvironmentNativeV1]::ReadProcessEntries()
  if ($null -eq $entries) { throw [System.InvalidOperationException]::new('raw process-environment enumeration returned null') }
  return [string[]]$entries
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

function Set-CrgNoReplaceObjectsProcessSingleton {
  $reader = { Get-CrgRawProcessEnvironmentEntries }
  $writer = {
    param([string]$Name, $Value)
    Initialize-CrgRendererEnvironmentNative
    if ($null -eq $Value) { [CrgProjectValues.EnvironmentNativeV1]::RemoveProcessVariable($Name) }
    else { [CrgProjectValues.EnvironmentNativeV1]::SetProcessVariable($Name, [string]$Value) }
  }

  while ($true) {
    try { [string[]]$beforeEntries = @(& $reader) }
    catch { throw [System.InvalidOperationException]::new('raw process-environment enumeration failed', $_.Exception) }
    $before = @(Get-CrgNoReplaceRawEntries -Entries $beforeEntries)
    if ($before.Count -eq 0) { break }
    $removeName = [string]$before[0].Name
    try { $null = & $writer $removeName $null }
    catch { throw [System.InvalidOperationException]::new("could not remove inherited replacement-suppression spelling '$removeName'", $_.Exception) }
    try { [string[]]$afterEntries = @(& $reader) }
    catch { throw [System.InvalidOperationException]::new('raw process-environment enumeration failed', $_.Exception) }
    $after = @(Get-CrgNoReplaceRawEntries -Entries $afterEntries)
    if ($after.Count -ge $before.Count) {
      throw [System.InvalidOperationException]::new("removing inherited replacement-suppression spelling '$removeName' made no raw-environment progress")
    }
  }

  try { $null = & $writer 'GIT_NO_REPLACE_OBJECTS' '1' }
  catch { throw [System.InvalidOperationException]::new('could not install canonical GIT_NO_REPLACE_OBJECTS=1', $_.Exception) }
  try { [string[]]$finalEntries = @(& $reader) }
  catch { throw [System.InvalidOperationException]::new('raw process-environment enumeration failed', $_.Exception) }
  $final = @(Get-CrgNoReplaceRawEntries -Entries $finalEntries)
  if ($final.Count -ne 1 -or -not [string]::Equals($final[0].Name, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::Ordinal) -or -not [string]::Equals($final[0].Value, '1', [System.StringComparison]::Ordinal)) {
    throw [System.InvalidOperationException]::new("canonical GIT_NO_REPLACE_OBJECTS postcondition failed (raw spelling count=$($final.Count))")
  }
}

function Assert-CrgDirectGitEnvironmentBoundary {
  $reader = { Get-CrgRawProcessEnvironmentEntries }
  try { [string[]]$entries = @(& $reader) }
  catch { throw [System.InvalidOperationException]::new('raw process-environment enumeration failed', $_.Exception) }
  foreach ($entry in $entries) {
    $parsed = ConvertFrom-CrgRawEnvironmentEntry -Entry ([string]$entry)
    if (Test-CrgProhibitedGitSelectorName -Name $parsed.Name) {
      throw [System.InvalidOperationException]::new("ambient Git selector '$($parsed.Name)' is prohibited")
    }
  }
  Set-CrgNoReplaceObjectsProcessSingleton
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

function Initialize-CrgRendererFileNative {
  if ('CrgProjectValues.FileNativeV1' -as [type]) { return }
  Add-Type -TypeDefinition @'
namespace CrgProjectValues {
  using System;
  using System.ComponentModel;
  using System.Globalization;
  using System.Runtime.InteropServices;
  using System.Text;
  using Microsoft.Win32.SafeHandles;

  public sealed class FileSnapshotV1 {
    public long Attributes;
    public uint LinkCount;
    public ulong Length;
    public string VolumeId;
    public string FileId;
  }

  public static class FileNativeV1 {
    private const uint GENERIC_READ = 0x80000000u;
    private const uint GENERIC_WRITE = 0x40000000u;
    private const uint DELETE = 0x00010000u;
    private const uint SYNCHRONIZE = 0x00100000u;
    private const uint FILE_READ_ATTRIBUTES = 0x80u;
    private const uint FILE_SHARE_READ = 0x1u;
    private const uint FILE_SHARE_WRITE = 0x2u;
    private const uint FILE_SHARE_DELETE = 0x4u;
    private const uint OPEN_EXISTING = 3u;
    private const uint OPEN_ALWAYS = 4u;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000u;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000u;
    private const uint FILE_FLAG_WRITE_THROUGH = 0x80000000u;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80u;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION information);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass, out FILE_ID_INFO information, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass, IntPtr information, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(SafeFileHandle handle, byte[] buffer, uint requested, out uint read, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(SafeFileHandle handle, byte[] buffer, uint requested, out uint written, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFilePointerEx(SafeFileHandle handle, long distance, out long newPosition, uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetEndOfFile(SafeFileHandle handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock, IntPtr fileInformation, uint length, int fileInformationClass);

    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION {
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

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_ID_INFO {
      public ulong VolumeSerialNumber;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
      public byte[] FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING {
      public ushort Length;
      public ushort MaximumLength;
      public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES {
      public int Length;
      public IntPtr RootDirectory;
      public IntPtr ObjectName;
      public uint Attributes;
      public IntPtr SecurityDescriptor;
      public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK {
      public IntPtr Status;
      public IntPtr Information;
    }

    private static SafeFileHandle InvalidHandle() {
      return new SafeFileHandle(new IntPtr(-1), true);
    }

    private static bool ValidLeaf(string leaf) {
      if (String.IsNullOrEmpty(leaf) || leaf == "." || leaf == ".." || leaf.IndexOf('\\') >= 0 || leaf.IndexOf('/') >= 0 || leaf.IndexOf(':') >= 0 || leaf.IndexOf('\0') >= 0 || leaf.EndsWith(".", StringComparison.Ordinal) || leaf.EndsWith(" ", StringComparison.Ordinal)) { return false; }
      string stem = leaf.Split('.')[0].ToUpperInvariant();
      if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CLOCK$" ||
          (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] >= '1' && stem[3] <= '9')) { return false; }
      return true;
    }

    private static SafeFileHandle OpenRelative(SafeFileHandle parent, string leaf, uint access, uint share, uint disposition, uint options, out int error) {
      error = 87;
      if (parent == null || parent.IsInvalid || !ValidLeaf(leaf)) { return InvalidHandle(); }
      IntPtr text = IntPtr.Zero;
      IntPtr name = IntPtr.Zero;
      IntPtr raw = IntPtr.Zero;
      bool added = false;
      try {
        parent.DangerousAddRef(ref added);
        text = Marshal.StringToHGlobalUni(leaf);
        UNICODE_STRING unicode = new UNICODE_STRING();
        unicode.Length = checked((ushort)(leaf.Length * 2));
        unicode.MaximumLength = unicode.Length;
        unicode.Buffer = text;
        name = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(unicode, name, false);
        OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        attributes.RootDirectory = parent.DangerousGetHandle();
        attributes.ObjectName = name;
        attributes.Attributes = 0x40u;
        IO_STATUS_BLOCK status;
        int ntStatus = NtCreateFile(out raw, access | SYNCHRONIZE, ref attributes, out status, IntPtr.Zero, FILE_ATTRIBUTE_NORMAL, share, disposition, options | 0x00200020u, IntPtr.Zero, 0u);
        error = ntStatus < 0 ? unchecked((int)RtlNtStatusToDosError(ntStatus)) : 0;
        GC.KeepAlive(parent);
        if (ntStatus < 0 || raw == IntPtr.Zero || raw == new IntPtr(-1)) {
          if (raw != IntPtr.Zero && raw != new IntPtr(-1)) { CloseHandle(raw); }
          return InvalidHandle();
        }
        SafeFileHandle owned = new SafeFileHandle(raw, true);
        raw = IntPtr.Zero;
        return owned;
      } finally {
        if (raw != IntPtr.Zero && raw != new IntPtr(-1)) { CloseHandle(raw); }
        if (added) { parent.DangerousRelease(); }
        if (name != IntPtr.Zero) { Marshal.FreeHGlobal(name); }
        if (text != IntPtr.Zero) { Marshal.FreeHGlobal(text); }
      }
    }

    public static SafeFileHandle OpenDirectoryAbsolute(string path, bool mutation, out int error) {
      uint access = SYNCHRONIZE | FILE_READ_ATTRIBUTES | (mutation ? 0xA3u : 0xA1u);
      SafeFileHandle handle = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
      error = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
      return handle;
    }

    public static SafeFileHandle OpenDirectoryRelative(SafeFileHandle parent, string leaf, bool mutation, out int error) {
      uint access = mutation ? 0xA3u : 0xA1u;
      return OpenRelative(parent, leaf, access, FILE_SHARE_READ | FILE_SHARE_WRITE, 1u, 0x00200001u, out error);
    }

    public static SafeFileHandle CreateDirectoryRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, 0x001100A3u, FILE_SHARE_READ | FILE_SHARE_WRITE, 2u, 0x00200001u, out error);
    }

    public static SafeFileHandle ProbeFileRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 1u, 0x00200040u, out error);
    }

    public static SafeFileHandle ProbeAnyRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 1u, 0x00200020u, out error);
    }

    public static SafeFileHandle OpenInputRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ, FILE_SHARE_READ, 1u, 0x00200040u, out error);
    }

    public static SafeFileHandle OpenDestinationRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ | DELETE, FILE_SHARE_READ, 1u, 0x00200040u, out error);
    }

    public static SafeFileHandle OpenRecoveryIdentityRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ | DELETE, FILE_SHARE_READ, 1u, 0x00200040u, out error);
    }

    public static SafeFileHandle OpenStateShareNoneRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ | GENERIC_WRITE | DELETE, 0u, 1u, 0x00200040u, out error);
    }

    public static SafeFileHandle CreateStateShareNoneRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ | GENERIC_WRITE | DELETE, 0u, 2u, 0x00200042u, out error);
    }

    public static SafeFileHandle CreateStageShareNoneRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ | GENERIC_WRITE | DELETE, 0u, 2u, 0x00200042u, out error);
    }

    public static SafeFileHandle CreateRecoveryCopyRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, 2u, 0x00200042u, out error);
    }

    public static SafeFileHandle OpenExistingLockRelative(SafeFileHandle parent, string leaf, out int error) {
      return OpenRelative(parent, leaf, GENERIC_READ | GENERIC_WRITE, 0u, 1u, 0x00200040u, out error);
    }

    public static FileSnapshotV1 Snapshot(SafeFileHandle handle) {
      if (handle == null || handle.IsInvalid) { throw new ArgumentException("invalid file handle", "handle"); }
      BY_HANDLE_FILE_INFORMATION basic;
      if (!GetFileInformationByHandle(handle, out basic)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle failed"); }
      FILE_ID_INFO identity;
      uint size = (uint)Marshal.SizeOf(typeof(FILE_ID_INFO));
      if (!GetFileInformationByHandleEx(handle, 18, out identity, size) || identity.FileId == null || identity.FileId.Length != 16) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandleEx(FileIdInfo) failed");
      }
      StringBuilder fileId = new StringBuilder(32);
      for (int i = 0; i < identity.FileId.Length; i++) { fileId.Append(identity.FileId[i].ToString("x2", CultureInfo.InvariantCulture)); }
      FileSnapshotV1 result = new FileSnapshotV1();
      result.Attributes = basic.FileAttributes;
      result.LinkCount = basic.NumberOfLinks;
      result.Length = ((ulong)basic.FileSizeHigh << 32) | basic.FileSizeLow;
      result.VolumeId = identity.VolumeSerialNumber.ToString("x16", CultureInfo.InvariantCulture);
      result.FileId = fileId.ToString();
      return result;
    }

    public static bool SameIdentity(SafeFileHandle left, SafeFileHandle right) {
      if (left == null || left.IsInvalid || right == null || right.IsInvalid) { return false; }
      FileSnapshotV1 a = Snapshot(left);
      FileSnapshotV1 b = Snapshot(right);
      return String.Equals(a.VolumeId, b.VolumeId, StringComparison.Ordinal) && String.Equals(a.FileId, b.FileId, StringComparison.Ordinal);
    }

    public static byte[] ReadAll(SafeFileHandle handle, ulong maximum) {
      FileSnapshotV1 snapshot = Snapshot(handle);
      if (snapshot.Length > maximum || snapshot.Length > Int32.MaxValue) { throw new InvalidOperationException("held file exceeds the read bound"); }
      long ignored;
      if (!SetFilePointerEx(handle, 0, out ignored, 0u)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not seek held file"); }
      byte[] result = new byte[(int)snapshot.Length];
      int offset = 0;
      while (offset < result.Length) {
        int count = Math.Min(1048576, result.Length - offset);
        byte[] chunk = new byte[count];
        uint read;
        if (!ReadFile(handle, chunk, (uint)count, out read, IntPtr.Zero)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not read held file"); }
        if (read == 0) { break; }
        Buffer.BlockCopy(chunk, 0, result, offset, (int)read);
        offset += (int)read;
      }
      if (offset != result.Length) { throw new InvalidOperationException("held file read was incomplete"); }
      if (!SetFilePointerEx(handle, 0, out ignored, 0u)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not reset held file position"); }
      return result;
    }

    public static void WriteAllAndFlush(SafeFileHandle handle, byte[] bytes) {
      if (bytes == null) { throw new ArgumentNullException("bytes"); }
      long ignored;
      if (!SetFilePointerEx(handle, 0, out ignored, 0u)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not seek held file for write"); }
      int offset = 0;
      while (offset < bytes.Length) {
        int count = Math.Min(1048576, bytes.Length - offset);
        byte[] chunk = new byte[count];
        Buffer.BlockCopy(bytes, offset, chunk, 0, count);
        uint written;
        if (!WriteFile(handle, chunk, (uint)count, out written, IntPtr.Zero)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not write held file"); }
        if (written == 0) { throw new InvalidOperationException("held file write made no progress"); }
        offset += (int)written;
      }
      if (!SetEndOfFile(handle)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not truncate held file to the written length"); }
      if (!FlushFileBuffers(handle)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not flush held file"); }
      if (!SetFilePointerEx(handle, 0, out ignored, 0u)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "could not reset held file position"); }
    }

    public static bool FlushDirectory(SafeFileHandle handle, out int error) {
      bool ok = FlushFileBuffers(handle);
      error = ok ? 0 : Marshal.GetLastWin32Error();
      return ok;
    }

    public static bool RenameHeldNoReplace(SafeFileHandle handle, SafeFileHandle destinationParent, string destinationLeaf, out int error) {
      error = 87;
      if (handle == null || handle.IsInvalid || destinationParent == null || destinationParent.IsInvalid || !ValidLeaf(destinationLeaf)) { return false; }
      byte[] name = Encoding.Unicode.GetBytes(destinationLeaf);
      int rootOffset = IntPtr.Size == 8 ? 8 : 4;
      int lengthOffset = IntPtr.Size == 8 ? 16 : 8;
      int nameOffset = IntPtr.Size == 8 ? 20 : 12;
      int size = checked(nameOffset + name.Length + 2);
      IntPtr buffer = IntPtr.Zero;
      bool added = false;
      try {
        destinationParent.DangerousAddRef(ref added);
        buffer = Marshal.AllocHGlobal(size);
        for (int i = 0; i < size; i++) { Marshal.WriteByte(buffer, i, 0); }
        Marshal.WriteByte(buffer, 0, 0);
        Marshal.WriteIntPtr(buffer, rootOffset, destinationParent.DangerousGetHandle());
        Marshal.WriteInt32(buffer, lengthOffset, name.Length);
        Marshal.Copy(name, 0, IntPtr.Add(buffer, nameOffset), name.Length);
        IO_STATUS_BLOCK status;
        int ntStatus = NtSetInformationFile(handle, out status, buffer, (uint)size, 10);
        error = ntStatus < 0 ? unchecked((int)RtlNtStatusToDosError(ntStatus)) : 0;
        GC.KeepAlive(destinationParent);
        return ntStatus >= 0;
      } finally {
        if (added) { destinationParent.DangerousRelease(); }
        if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
      }
    }

    public static int DeleteHeldExact(SafeFileHandle handle, bool directory, out int error) {
      error = 0;
      FileSnapshotV1 snapshot;
      try { snapshot = Snapshot(handle); } catch (Win32Exception ex) { error = ex.NativeErrorCode; return 4; }
      bool isDirectory = (snapshot.Attributes & 0x10L) != 0;
      bool isReparse = (snapshot.Attributes & 0x400L) != 0;
      if (isReparse || isDirectory != directory || (!directory && snapshot.LinkCount != 1u)) { return 3; }
      IntPtr buffer = Marshal.AllocHGlobal(1);
      try {
        Marshal.WriteByte(buffer, 0, 1);
        if (!SetFileInformationByHandle(handle, 4, buffer, 1u)) { error = Marshal.GetLastWin32Error(); return 5; }
        return 0;
      } finally { Marshal.FreeHGlobal(buffer); }
    }

    public static string GetFinalPath(SafeFileHandle handle) {
      StringBuilder buffer = new StringBuilder(32768);
      uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0u);
      if (length == 0 || length >= buffer.Capacity) { throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFinalPathNameByHandleW failed"); }
      return buffer.ToString();
    }
  }
}
'@ -Language CSharp -ErrorAction Stop
  if (-not ('CrgProjectValues.FileNativeV1' -as [type])) {
    throw [System.PlatformNotSupportedException]::new('required retained-file support is unavailable')
  }
}

function Get-CrgSha256OfBytes {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  $hash = [System.Security.Cryptography.SHA256]::Create()
  try { return (([System.BitConverter]::ToString($hash.ComputeHash($Bytes))) -replace '-', '').ToLowerInvariant() }
  finally { $hash.Dispose() }
}

function Get-CrgOrdinaryFileSnapshot {
  param([Parameter(Mandatory = $true)][object]$Handle, [string]$Label)
  $snapshot = [CrgProjectValues.FileNativeV1]::Snapshot($Handle)
  if (($snapshot.Attributes -band 0x410) -ne 0 -or $snapshot.LinkCount -ne 1) {
    throw "$Label is not one ordinary, non-reparse, single-link file"
  }
  if ($snapshot.VolumeId -cnotmatch '^[0-9a-f]{16}$' -or $snapshot.FileId -cnotmatch '^[0-9a-f]{32}$') {
    throw "$Label has a noncanonical native identity"
  }
  return $snapshot
}

function Read-CrgHeldFileBytes {
  param([Parameter(Mandatory = $true)][object]$Handle, [uint64]$Maximum, [string]$Label)
  $snapshot = Get-CrgOrdinaryFileSnapshot -Handle $Handle -Label $Label
  if ($snapshot.Length -gt $Maximum) { throw "$Label exceeds the $Maximum-byte bound" }
  [byte[]]$bytes = [CrgProjectValues.FileNativeV1]::ReadAll($Handle, $Maximum)
  $after = Get-CrgOrdinaryFileSnapshot -Handle $Handle -Label $Label
  if ($snapshot.VolumeId -cne $after.VolumeId -or $snapshot.FileId -cne $after.FileId -or
      $snapshot.Length -ne $after.Length -or $bytes.LongLength -ne $after.Length) {
    throw "$Label changed identity or length during its retained read"
  }
  return [pscustomobject]@{ Bytes = $bytes; Snapshot = $after; Sha256 = Get-CrgSha256OfBytes -Bytes $bytes }
}

function Get-CrgCanonicalFsPath {
  param([Parameter(Mandatory = $true)][string]$Path)
  $full = [System.IO.Path]::GetFullPath($Path)
  $root = [System.IO.Path]::GetPathRoot($full)
  if ([string]::IsNullOrWhiteSpace($root)) { throw "path '$Path' is not absolute" }
  if ([string]::Equals($full, $root, [System.StringComparison]::OrdinalIgnoreCase)) { return $root }
  return $full.TrimEnd([char]'\', [char]'/')
}

function Get-CrgPathChain {
  param([Parameter(Mandatory = $true)][string]$Path)
  $full = Get-CrgCanonicalFsPath -Path $Path
  $root = [System.IO.Path]::GetPathRoot($full)
  $paths = New-Object 'System.Collections.Generic.List[string]'
  $paths.Add($root) | Out-Null
  $relative = $full.Substring($root.Length).Trim([char]'\', [char]'/')
  $current = $root
  if ($relative.Length -gt 0) {
    foreach ($part in @($relative -split '[\\/]')) {
      if ([string]::IsNullOrEmpty($part) -or [string]::Equals($part, '.', [System.StringComparison]::Ordinal) -or [string]::Equals($part, '..', [System.StringComparison]::Ordinal) -or $part.Contains(':')) {
        throw "path '$Path' contains an unsafe directory component"
      }
      $current = Get-CrgCanonicalFsPath -Path (Join-Path $current $part)
      $paths.Add($current) | Out-Null
    }
  }
  return $paths.ToArray()
}

function Enter-CrgRendererDirectoryPins {
  param([Parameter(Mandatory = $true)][string[]]$MutationDirectories)
  Initialize-CrgRendererFileNative
  $wanted = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($path in $MutationDirectories) { $null = $wanted.Add((Get-CrgCanonicalFsPath -Path $path)) }
  $map = New-Object System.Collections.Hashtable([System.StringComparer]::OrdinalIgnoreCase)
  $owned = New-Object 'System.Collections.Generic.List[object]'
  try {
    foreach ($leafPath in @($wanted | Sort-Object { $_.Length }, { $_ })) {
      $chain = @(Get-CrgPathChain -Path $leafPath)
      $parentHandle = $null
      foreach ($componentPath in $chain) {
        $mutation = $wanted.Contains($componentPath)
        if ($map.ContainsKey($componentPath)) {
          $entry = $map[$componentPath]
          if ($mutation -and -not $entry.Mutation) { throw "directory '$componentPath' was pinned without required mutation authority" }
          $parentHandle = $entry.Handle
          continue
        }
        $errorCode = 0
        if ($null -eq $parentHandle) {
          $handle = [CrgProjectValues.FileNativeV1]::OpenDirectoryAbsolute($componentPath, $mutation, [ref]$errorCode)
        } else {
          $leaf = Split-Path -Leaf $componentPath
          $handle = [CrgProjectValues.FileNativeV1]::OpenDirectoryRelative($parentHandle, $leaf, $mutation, [ref]$errorCode)
        }
        if ($null -eq $handle -or $handle.IsInvalid) {
          if ($null -ne $handle) { $handle.Dispose() }
          throw "directory '$componentPath' could not be pinned without delete sharing (Win32 error $errorCode)"
        }
        $snapshot = [CrgProjectValues.FileNativeV1]::Snapshot($handle)
        if (($snapshot.Attributes -band 0x10) -eq 0 -or ($snapshot.Attributes -band 0x400) -ne 0) {
          $handle.Dispose()
          throw "directory '$componentPath' is not one ordinary non-reparse directory"
        }
        $entry = [pscustomobject]@{ Path = $componentPath; Handle = $handle; Mutation = $mutation }
        $map[$componentPath] = $entry
        $owned.Add($handle) | Out-Null
        $parentHandle = $handle
      }
    }
    return [pscustomobject]@{ Map = $map; Owned = $owned }
  } catch {
    for ($i = $owned.Count - 1; $i -ge 0; $i--) { try { $owned[$i].Dispose() } catch { } }
    throw
  }
}

function Close-CrgRendererDirectoryPins {
  param([AllowNull()][object]$Pins)
  if ($null -eq $Pins -or $null -eq $Pins.Owned) { return }
  for ($i = $Pins.Owned.Count - 1; $i -ge 0; $i--) { try { $Pins.Owned[$i].Dispose() } catch { } }
}

function Get-CrgPinnedDirectoryHandle {
  param([Parameter(Mandatory = $true)][object]$Pins, [Parameter(Mandatory = $true)][string]$Path)
  $canonical = Get-CrgCanonicalFsPath -Path $Path
  if (-not $Pins.Map.ContainsKey($canonical)) { throw "directory '$canonical' has no retained namespace authority" }
  return $Pins.Map[$canonical].Handle
}

function Test-CrgRelativeLeafAbsent {
  param([Parameter(Mandatory = $true)][object]$ParentHandle, [Parameter(Mandatory = $true)][string]$Leaf, [string]$Label)
  $errorCode = 0
  $probe = [CrgProjectValues.FileNativeV1]::ProbeFileRelative($ParentHandle, $Leaf, [ref]$errorCode)
  if ($null -ne $probe -and -not $probe.IsInvalid) { $probe.Dispose(); return $false }
  if ($null -ne $probe) { $probe.Dispose() }
  if ($errorCode -eq 2 -or $errorCode -eq 3) { return $true }
  throw "$Label could not be classified as present or absent (Win32 error $errorCode)"
}

function Test-CrgRelativeNameAbsent {
  param([Parameter(Mandatory = $true)][object]$ParentHandle, [Parameter(Mandatory = $true)][string]$Leaf, [string]$Label)
  $errorCode = 0
  $probe = [CrgProjectValues.FileNativeV1]::ProbeAnyRelative($ParentHandle, $Leaf, [ref]$errorCode)
  if ($null -ne $probe -and -not $probe.IsInvalid) { $probe.Dispose(); return $false }
  if ($null -ne $probe) { $probe.Dispose() }
  if ($errorCode -eq 2 -or $errorCode -eq 3) { return $true }
  throw "$Label could not be classified as present or absent (Win32 error $errorCode)"
}

function Assert-CrgRelativeLeafAbsent {
  param([object]$ParentHandle, [string]$Leaf, [string]$Label)
  if (-not (Test-CrgRelativeLeafAbsent -ParentHandle $ParentHandle -Leaf $Leaf -Label $Label)) { throw "$Label already exists" }
}

function Assert-CrgRelativeNameAbsent {
  param([object]$ParentHandle, [string]$Leaf, [string]$Label)
  if (-not (Test-CrgRelativeNameAbsent -ParentHandle $ParentHandle -Leaf $Leaf -Label $Label)) { throw "$Label already exists" }
}

function Open-CrgRendererInputHold {
  param([object]$ParentHandle, [string]$Leaf, [string]$Label, [uint64]$Maximum)
  $errorCode = 0
  $handle = [CrgProjectValues.FileNativeV1]::OpenInputRelative($ParentHandle, $Leaf, [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    throw "$Label could not be opened as a retained no-follow input (Win32 error $errorCode)"
  }
  try {
    $read = Read-CrgHeldFileBytes -Handle $handle -Maximum $Maximum -Label $Label
    return [pscustomobject]@{ Handle = $handle; Bytes = $read.Bytes; Snapshot = $read.Snapshot; Sha256 = $read.Sha256; Label = $Label }
  } catch { $handle.Dispose(); throw }
}

function Open-CrgRendererDestinationHold {
  param([object]$ParentHandle, [string]$Leaf, [string]$Label)
  $errorCode = 0
  $handle = [CrgProjectValues.FileNativeV1]::OpenDestinationRelative($ParentHandle, $Leaf, [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    throw "$Label must already exist as an ordinary file; run full bootstrap.ps1 -TargetRepo <root> installation (Win32 error $errorCode)"
  }
  try {
    $read = Read-CrgHeldFileBytes -Handle $handle -Maximum 1048576 -Label $Label
    return [pscustomobject]@{ Handle = $handle; Bytes = $read.Bytes; Snapshot = $read.Snapshot; Sha256 = $read.Sha256; Label = $Label }
  } catch {
    $detail = $_.Exception.Message
    $handle.Dispose()
    throw "$Label must already exist as an ordinary file; run full bootstrap.ps1 -TargetRepo <root> installation. Details: $detail"
  }
}

function Convert-CrgWindowsProcessArgument {
  param([AllowEmptyString()][string]$Argument)
  if ($null -eq $Argument) { throw 'process argument cannot be null' }
  $escaped = [regex]::Replace($Argument, '(\\*)"', '$1$1\"')
  $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
  return '"' + $escaped + '"'
}

function Get-CrgEnvironmentKeys {
  param([Parameter(Mandatory = $true)][object]$Environment)
  if ($null -eq $Environment.PSObject.Properties['Keys']) { throw 'child environment key enumeration is unavailable' }
  return @($Environment.Keys | ForEach-Object { [string]$_ })
}

function Set-CrgChildNoReplaceSingleton {
  param([Parameter(Mandatory = $true)][object]$Environment)
  while ($true) {
    $matches = @(Get-CrgEnvironmentKeys -Environment $Environment | Where-Object { [string]::Equals($_, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::OrdinalIgnoreCase) })
    if ($matches.Count -eq 0) { break }
    $before = $matches.Count
    $Environment.Remove($matches[0])
    $after = @(Get-CrgEnvironmentKeys -Environment $Environment | Where-Object { [string]::Equals($_, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::OrdinalIgnoreCase) }).Count
    if ($after -ge $before) { throw 'child replacement-suppression removal made no progress' }
  }
  $Environment['GIT_NO_REPLACE_OBJECTS'] = '1'
  $final = @(Get-CrgEnvironmentKeys -Environment $Environment | Where-Object { [string]::Equals($_, 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::OrdinalIgnoreCase) })
  if ($final.Count -ne 1 -or -not [string]::Equals($final[0], 'GIT_NO_REPLACE_OBJECTS', [System.StringComparison]::Ordinal) -or -not [string]::Equals([string]$Environment[$final[0]], '1', [System.StringComparison]::Ordinal)) {
    throw 'child GIT_NO_REPLACE_OBJECTS singleton verification failed'
  }
}

function Assert-CrgGitChildEnvironment {
  param([Parameter(Mandatory = $true)][object]$Environment, [string[]]$AllowedInternalSelectors)
  $allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($name in @($AllowedInternalSelectors)) { $null = $allowed.Add($name) }
  foreach ($name in @(Get-CrgEnvironmentKeys -Environment $Environment)) {
    if ((Test-CrgProhibitedGitSelectorName -Name $name) -and -not $allowed.Contains($name)) {
      throw "prohibited selector '$name' reached a Git child environment"
    }
    if ((Test-CrgProhibitedGitSelectorName -Name $name) -and $allowed.Contains($name) -and -not ([string]::Equals($name, 'GIT_OBJECT_DIRECTORY', [System.StringComparison]::Ordinal) -or [string]::Equals($name, 'GIT_ALTERNATE_OBJECT_DIRECTORIES', [System.StringComparison]::Ordinal))) {
      throw "selector '$name' is not an admitted renderer-internal Git setting"
    }
  }
  Set-CrgChildNoReplaceSingleton -Environment $Environment
}

function Invoke-CrgRendererGit {
  param(
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [byte[]]$InputBytes,
    [int64]$MaximumOutputBytes = 2097152,
    [hashtable]$InternalEnvironment
  )
  if ([string]::IsNullOrWhiteSpace($script:CrgRendererGitExe)) { throw 'Git executable authority is not initialized' }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:CrgRendererGitExe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.RedirectStandardInput = ($null -ne $InputBytes)
  $psi.CreateNoWindow = $true
  $psi.Arguments = (($Arguments | ForEach-Object { Convert-CrgWindowsProcessArgument -Argument $_ }) -join ' ')
  $environment = $null
  if ($null -ne $psi.PSObject.Properties['Environment']) { $environment = $psi.Environment }
  if ($null -eq $environment -and $null -ne $psi.PSObject.Properties['EnvironmentVariables']) { $environment = $psi.EnvironmentVariables }
  if ($null -eq $environment) { throw 'Git child environment is unavailable' }
  $environment.Clear()
  foreach ($name in @('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'XDG_CONFIG_HOME')) {
    $value = [Environment]::GetEnvironmentVariable($name, [EnvironmentVariableTarget]::Process)
    if ($null -ne $value) {
      if ($value.IndexOf([char]0) -ge 0) { throw "inherited child setting '$name' contains NUL" }
      $environment[$name] = $value
    }
  }
  $environment['GIT_OPTIONAL_LOCKS'] = '0'
  $environment['GIT_TERMINAL_PROMPT'] = '0'
  $allowedInternal = New-Object 'System.Collections.Generic.List[string]'
  if ($null -ne $InternalEnvironment) {
    foreach ($nameObject in $InternalEnvironment.Keys) {
      $name = [string]$nameObject
      if (-not ([string]::Equals($name, 'GIT_OBJECT_DIRECTORY', [System.StringComparison]::Ordinal) -or [string]::Equals($name, 'GIT_ALTERNATE_OBJECT_DIRECTORIES', [System.StringComparison]::Ordinal))) { throw "unapproved internal Git selector '$name'" }
      $value = [string]$InternalEnvironment[$nameObject]
      if ([string]::IsNullOrWhiteSpace($value) -or $value.IndexOf([char]0) -ge 0 -or -not [System.IO.Path]::IsPathRooted($value)) { throw "invalid internal Git selector value for '$name'" }
      $environment[$name] = Get-CrgCanonicalFsPath -Path $value
      $allowedInternal.Add($name) | Out-Null
    }
  }
  Assert-CrgGitChildEnvironment -Environment $environment -AllowedInternalSelectors $allowedInternal.ToArray()
  # The postcondition is repeated immediately before Process.Start so a late
  # map addition cannot restore replacement or repository-selection authority.
  Assert-CrgGitChildEnvironment -Environment $environment -AllowedInternalSelectors $allowedInternal.ToArray()

  $priorInputEncoding = $null
  if ($null -ne $InputBytes -and $null -eq $psi.PSObject.Properties['StandardInputEncoding']) {
    $priorInputEncoding = Get-CrgConsoleRestoreEncoding -ConsoleInput
    [Console]::InputEncoding = $script:CrgUtf8NoBom
  } elseif ($null -ne $InputBytes) { $psi.StandardInputEncoding = $script:CrgUtf8NoBom }
  try { $process = [System.Diagnostics.Process]::Start($psi) }
  finally { if ($null -ne $priorInputEncoding) { [Console]::InputEncoding = $priorInputEncoding } }
  try {
    $errorTask = $process.StandardError.ReadToEndAsync()
    if ($null -ne $InputBytes) {
      try { if ($InputBytes.Length -gt 0) { $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length) } }
      finally { $process.StandardInput.Close() }
    }
    $output = New-Object System.IO.MemoryStream
    try {
      $buffer = New-Object byte[] 65536
      while ($true) {
        $count = $process.StandardOutput.BaseStream.Read($buffer, 0, $buffer.Length)
        if ($count -le 0) { break }
        if ($output.Length + $count -gt $MaximumOutputBytes) { try { $process.Kill() } catch { }; throw 'Git output exceeded the bounded capture size' }
        $output.Write($buffer, 0, $count)
      }
      $process.WaitForExit()
      $errorText = $errorTask.GetAwaiter().GetResult()
      if ($errorText.Length -gt 1048576) { throw 'Git stderr exceeded the bounded capture size' }
      [byte[]]$outputBytes = $output.ToArray()
    } finally { $output.Dispose() }
    try { $outputText = $script:CrgUtf8Strict.GetString($outputBytes) }
    catch { $outputText = '' }
    return [pscustomobject]@{ Exit = $process.ExitCode; Bytes = $outputBytes; OutputText = $outputText; ErrorText = $errorText }
  } finally { $process.Dispose() }
}

function Get-CrgSingleGitLine {
  param([Parameter(Mandatory = $true)][object]$Result, [string]$Label, [switch]$AllowExitOne)
  if ($Result.Exit -ne 0) {
    if ($AllowExitOne -and $Result.Exit -eq 1) { return $null }
    throw "$Label failed with Git exit $($Result.Exit): $($Result.ErrorText.Trim())"
  }
  if ($Result.ErrorText.Length -ne 0) { throw "$Label produced unexpected stderr: $($Result.ErrorText.Trim())" }
  try { $text = $script:CrgUtf8Strict.GetString([byte[]]$Result.Bytes) }
  catch { throw "$Label returned non-UTF-8 output" }
  if ($text.IndexOf([char]0) -ge 0) { throw "$Label returned NUL-bearing output" }
  $text = $text.Replace("`r`n", "`n")
  if (-not $text.EndsWith("`n", [System.StringComparison]::Ordinal)) { throw "$Label returned an unterminated record" }
  $records = @($text.Substring(0, $text.Length - 1) -split "`n", 0)
  if ($records.Count -ne 1 -or [string]::IsNullOrWhiteSpace($records[0])) { throw "$Label did not return exactly one nonempty record" }
  return [string]$records[0]
}

function Invoke-CrgTargetGit {
  param([Parameter(Mandatory = $true)][string]$RepoRoot, [Parameter(Mandatory = $true)][string[]]$Arguments, [byte[]]$InputBytes, [int64]$MaximumOutputBytes = 2097152, [hashtable]$InternalEnvironment)
  return Invoke-CrgRendererGit -Arguments (@('--no-optional-locks', '-C', $RepoRoot) + $Arguments) -InputBytes $InputBytes -MaximumOutputBytes $MaximumOutputBytes -InternalEnvironment $InternalEnvironment
}

function Resolve-CrgRendererRepository {
  param([Parameter(Mandatory = $true)][string]$SuppliedPath)
  $topLine = Get-CrgSingleGitLine -Result (Invoke-CrgRendererGit -Arguments @('--no-optional-locks', '-C', $SuppliedPath, 'rev-parse', '--show-toplevel')) -Label 'target top-level resolution'
  $top = Get-CrgCanonicalFsPath -Path ($topLine.Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar))
  $gitDirLine = Get-CrgSingleGitLine -Result (Invoke-CrgTargetGit -RepoRoot $top -Arguments @('rev-parse', '--absolute-git-dir')) -Label 'per-worktree Git-directory resolution'
  $gitDir = Get-CrgCanonicalFsPath -Path ($gitDirLine.Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar))
  $commonLine = Get-CrgSingleGitLine -Result (Invoke-CrgTargetGit -RepoRoot $top -Arguments @('rev-parse', '--git-common-dir')) -Label 'Git common-directory resolution'
  $commonNative = $commonLine.Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar)
  if (-not [System.IO.Path]::IsPathRooted($commonNative)) { $commonNative = Join-Path $top $commonNative }
  $common = Get-CrgCanonicalFsPath -Path $commonNative
  $objectLine = Get-CrgSingleGitLine -Result (Invoke-CrgTargetGit -RepoRoot $top -Arguments @('rev-parse', '--git-path', 'objects')) -Label 'Git object-directory resolution'
  $objectNative = $objectLine.Replace([char]'/', [char][System.IO.Path]::DirectorySeparatorChar)
  if (-not [System.IO.Path]::IsPathRooted($objectNative)) { $objectNative = Join-Path $top $objectNative }
  $objectDir = Get-CrgCanonicalFsPath -Path $objectNative
  $format = Get-CrgSingleGitLine -Result (Invoke-CrgTargetGit -RepoRoot $top -Arguments @('rev-parse', '--show-object-format')) -Label 'Git object-format resolution'
  if (-not ([string]::Equals($format, 'sha1', [System.StringComparison]::Ordinal) -or [string]::Equals($format, 'sha256', [System.StringComparison]::Ordinal))) { throw "unsupported target Git object format '$format'" }
  return [pscustomobject]@{ Root = $top; GitDir = $gitDir; CommonDir = $common; ObjectDir = $objectDir; ObjectFormat = $format }
}

function Assert-CrgRepositoryResolutionStable {
  param([Parameter(Mandatory = $true)][object]$Expected)
  $actual = Resolve-CrgRendererRepository -SuppliedPath $Expected.Root
  foreach ($field in @('Root', 'GitDir', 'CommonDir', 'ObjectDir')) {
    if (-not [string]::Equals([string]$Expected.$field, [string]$actual.$field, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "target repository $field changed after namespace retention"
    }
  }
  if (-not [string]::Equals($Expected.ObjectFormat, $actual.ObjectFormat, [System.StringComparison]::Ordinal)) { throw 'target repository object format changed after namespace retention' }
}

function ConvertFrom-CrgGitNulRecords {
  param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [string]$Label)
  if ($Bytes.Length -eq 0) { return @() }
  if ($Bytes[$Bytes.Length - 1] -ne 0) { throw "$Label returned an unterminated NUL record" }
  $records = New-Object 'System.Collections.Generic.List[string]'
  $start = 0
  for ($i = 0; $i -lt $Bytes.Length; $i++) {
    if ($Bytes[$i] -ne 0) { continue }
    [byte[]]$recordBytes = Copy-CrgInstallValueByteRange -Bytes $Bytes -Offset $start -Count ($i - $start)
    try { $record = $script:CrgUtf8Strict.GetString($recordBytes) }
    catch { throw "$Label returned a non-UTF-8 record" }
    $records.Add($record) | Out-Null
    $start = $i + 1
  }
  return $records.ToArray()
}

function Get-CrgRendererHeadState {
  param([Parameter(Mandatory = $true)][object]$Repo)
  $verify = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('rev-parse', '-q', '--verify', 'HEAD^{commit}')
  if ($verify.Exit -eq 0) {
    $oid = Get-CrgSingleGitLine -Result $verify -Label 'HEAD resolution'
    $pattern = if ([string]::Equals($Repo.ObjectFormat, 'sha256', [System.StringComparison]::Ordinal)) { '^[0-9a-f]{64}$' } else { '^[0-9a-f]{40}$' }
    if ($oid -cnotmatch $pattern) { throw 'HEAD resolved to a noncanonical object ID' }
    return [pscustomobject]@{ State = 'present'; Oid = $oid }
  }
  $symbolic = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('symbolic-ref', '-q', 'HEAD')
  if ($symbolic.Exit -ne 0) { throw 'HEAD is neither one commit nor a readable symbolic reference' }
  $reference = Get-CrgSingleGitLine -Result $symbolic -Label 'HEAD symbolic-reference resolution'
  if ($reference -cnotmatch '^refs/heads/[A-Za-z0-9._/-]+$') { throw 'HEAD symbolic reference is malformed' }
  $show = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('show-ref', '--verify', '--quiet', $reference)
  if ($show.Exit -eq 1 -and $show.Bytes.Length -eq 0) { return [pscustomobject]@{ State = 'unborn'; Oid = '' } }
  throw 'HEAD failed commit resolution without proving an unborn branch'
}

function Get-CrgHeadPathEntry {
  param([object]$Repo, [object]$Head, [string]$Path)
  if ($Head.State -ceq 'unborn') { return [pscustomobject]@{ State = 'absent'; Mode = ''; Oid = '' } }
  $result = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('ls-tree', '-z', $Head.Oid, '--', $Path)
  if ($result.Exit -ne 0 -or $result.ErrorText.Length -ne 0) { throw "HEAD probe failed for '$Path'" }
  [byte[]]$probeBytes = [byte[]]@()
  if ($null -ne $result.Bytes) { $probeBytes = [byte[]]$result.Bytes }
  $records = @(ConvertFrom-CrgGitNulRecords -Bytes $probeBytes -Label "HEAD probe for '$Path'")
  if ($records.Count -eq 0) { return [pscustomobject]@{ State = 'absent'; Mode = ''; Oid = '' } }
  if ($records.Count -ne 1 -or $records[0] -cnotmatch '^(100644|100755) blob ([0-9a-f]{40}|[0-9a-f]{64})\t(.+)$' -or -not [string]::Equals($Matches[3], $Path, [System.StringComparison]::Ordinal)) {
    throw "HEAD path '$Path' is not one regular blob"
  }
  return [pscustomobject]@{ State = 'regular'; Mode = [string]$Matches[1]; Oid = [string]$Matches[2] }
}

function Get-CrgIndexPathEntry {
  param([object]$Repo, [string]$Path)
  $result = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('ls-files', '--stage', '-z', '--', $Path)
  if ($result.Exit -ne 0 -or $result.ErrorText.Length -ne 0) { throw "index probe failed for '$Path'" }
  [byte[]]$probeBytes = [byte[]]@()
  if ($null -ne $result.Bytes) { $probeBytes = [byte[]]$result.Bytes }
  $records = @(ConvertFrom-CrgGitNulRecords -Bytes $probeBytes -Label "index probe for '$Path'")
  if ($records.Count -eq 0) { return [pscustomobject]@{ State = 'absent'; Mode = ''; Oid = '' } }
  if ($records.Count -ne 1 -or $records[0] -cnotmatch '^(100644|100755) ([0-9a-f]{40}|[0-9a-f]{64}) 0\t(.+)$' -or -not [string]::Equals($Matches[3], $Path, [System.StringComparison]::Ordinal)) {
    throw "index path '$Path' is unmerged, duplicated, or not one regular stage-0 blob"
  }
  return [pscustomobject]@{ State = 'regular'; Mode = [string]$Matches[1]; Oid = [string]$Matches[2] }
}

function Get-CrgIgnorePathState {
  param([object]$Repo, [string]$Path)
  $result = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('check-ignore', '--no-index', '-q', '--', $Path)
  if ($result.Bytes.Length -ne 0 -or $result.ErrorText.Length -ne 0) { throw "ignore probe for '$Path' returned unexpected output" }
  if ($result.Exit -eq 0) { return 'ignored' }
  if ($result.Exit -eq 1) { return 'not-ignored' }
  throw "ignore probe for '$Path' was indeterminate (Git exit $($result.Exit))"
}

function Get-CrgPathAuthorityEvidence {
  param([object]$Repo, [object]$Head, [string]$Path)
  $headEntry = Get-CrgHeadPathEntry -Repo $Repo -Head $Head -Path $Path
  $indexEntry = Get-CrgIndexPathEntry -Repo $Repo -Path $Path
  $ignore = Get-CrgIgnorePathState -Repo $Repo -Path $Path
  $class = if ($headEntry.State -ceq 'regular' -and $indexEntry.State -ceq 'regular' -and
      $headEntry.Mode -ceq $indexEntry.Mode -and $headEntry.Oid -ceq $indexEntry.Oid) {
    'TRACKED-existing'
  } elseif ($headEntry.State -ceq 'absent' -and $indexEntry.State -ceq 'absent' -and $ignore -ceq 'not-ignored') {
    'TRACKED-new'
  } elseif ($headEntry.State -ceq 'absent' -and $indexEntry.State -ceq 'absent' -and $ignore -ceq 'ignored') {
    'LOCAL'
  } else { throw "'$Path' has no valid TRACKED-existing, TRACKED-new, or LOCAL authority classification" }
  return [pscustomobject]@{ Path = $Path; Class = $class; HeadState = $headEntry.State; HeadMode = $headEntry.Mode; HeadOid = $headEntry.Oid; IndexState = $indexEntry.State; IndexMode = $indexEntry.Mode; IndexOid = $indexEntry.Oid; Ignore = $ignore }
}

function Get-CrgRenderAuthority {
  param([object]$Repo)
  $head = Get-CrgRendererHeadState -Repo $Repo
  $evidence = @(
    Get-CrgPathAuthorityEvidence -Repo $Repo -Head $head -Path 'scripts/codex/review-prompt-template.md'
    Get-CrgPathAuthorityEvidence -Repo $Repo -Head $head -Path 'docs/AGENTS.md.template'
  )
  $familySet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($item in $evidence) { [void]$familySet.Add($(if ($item.Class.StartsWith('TRACKED-', [System.StringComparison]::Ordinal)) { 'TRACKED' } else { 'LOCAL' })) }
  $families = @($familySet)
  if ($families.Count -ne 1) { throw 'render-bearing outputs have a mixed TRACKED/LOCAL authority classification' }
  return [pscustomobject]@{ Family = [string]$families[0]; Head = $head; Outputs = $evidence }
}

function Get-CrgSourceAuthorityEvidence {
  param([object]$Repo, [object]$Head)
  $path = 'CROSS-REVIEW-VALUES.md'
  $headEntry = Get-CrgHeadPathEntry -Repo $Repo -Head $Head -Path $path
  $indexEntry = Get-CrgIndexPathEntry -Repo $Repo -Path $path
  $ignore = Get-CrgIgnorePathState -Repo $Repo -Path $path
  $class = if ($indexEntry.State -ceq 'regular') {
    'TRACKED-index'
  } elseif ($headEntry.State -ceq 'absent' -and $indexEntry.State -ceq 'absent' -and $ignore -ceq 'ignored') {
    'LOCAL'
  } else { throw "'$path' has no valid TRACKED index or LOCAL ignored-file authority" }
  return [pscustomobject]@{ Path = $path; Class = $class; HeadState = $headEntry.State; HeadMode = $headEntry.Mode; HeadOid = $headEntry.Oid; IndexState = $indexEntry.State; IndexMode = $indexEntry.Mode; IndexOid = $indexEntry.Oid; Ignore = $ignore }
}

function Assert-CrgAuthorityEvidenceEqual {
  param([object]$Expected, [object]$Actual, [string]$Label)
  foreach ($field in @('Path', 'Class', 'HeadState', 'HeadMode', 'HeadOid', 'IndexState', 'IndexMode', 'IndexOid', 'Ignore')) {
    if ([string]$Expected.$field -cne [string]$Actual.$field) { throw "$Label authority predicate '$field' changed during rendering" }
  }
}

function Read-CrgGitBlobBytes {
  param([object]$Repo, [string]$Oid, [uint64]$Maximum, [string]$Label)
  $pattern = if ([string]::Equals($Repo.ObjectFormat, 'sha256', [System.StringComparison]::Ordinal)) { '^[0-9a-f]{64}$' } else { '^[0-9a-f]{40}$' }
  if ($Oid -cnotmatch $pattern) { throw "$Label has a noncanonical blob object ID" }
  $result = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('cat-file', 'blob', $Oid) -MaximumOutputBytes ([int64]$Maximum + 1)
  if ($result.Exit -ne 0 -or $result.ErrorText.Length -ne 0) { throw "$Label blob read failed" }
  if ($result.Bytes.LongLength -gt $Maximum) { throw "$Label blob exceeds the $Maximum-byte bound" }
  return ,([byte[]]$result.Bytes)
}

function Assert-CrgValuesAuthority {
  param([object]$Repo, [object]$RenderAuthority, [object]$SourceHold)
  $sourceEvidence = Get-CrgSourceAuthorityEvidence -Repo $Repo -Head $RenderAuthority.Head
  if ($RenderAuthority.Family -ceq 'TRACKED') {
    if ($sourceEvidence.Class -cne 'TRACKED-index' -or $sourceEvidence.IndexState -cne 'regular') { throw 'TRACKED values source is not one regular stage-0 index blob' }
    [byte[]]$indexed = Read-CrgGitBlobBytes -Repo $Repo -Oid $sourceEvidence.IndexOid -Maximum 262144 -Label 'TRACKED values source'
    if (-not (Compare-CrgInstallValueBytes -Left $indexed -Right $SourceHold.Bytes)) { throw 'TRACKED values source working bytes do not equal the indexed blob bytes' }
    $null = Read-CrgInstallValuesBytes -Bytes $indexed
  } else {
    if ($sourceEvidence.Class -cne 'LOCAL' -or $sourceEvidence.HeadState -cne 'absent' -or $sourceEvidence.IndexState -cne 'absent' -or $sourceEvidence.Ignore -cne 'ignored') {
      throw 'LOCAL values source is not absent from HEAD/index and positively ignored'
    }
  }
  return $sourceEvidence
}

function Remove-CrgAttributeStateScratch {
  param([object]$Custody)
  if ($null -eq $Custody -or $Custody.Removed -or $Custody.Token -cnotmatch '\A[0-9a-f]{32}\z' -or
      $null -eq $Custody.Pins -or $null -eq $Custody.TempHandle -or $null -eq $Custody.RootHandle) {
    throw 'attribute-state scratch cleanup received no live retained owner'
  }
  $expectedScratch = Join-Path $Custody.TempRoot "crg-render-attribute-state-$($Custody.Token)"
  if (-not [string]::Equals((Get-CrgCanonicalFsPath -Path $Custody.Scratch), (Get-CrgCanonicalFsPath -Path $expectedScratch), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "attribute-state scratch escaped the retained temporary parent: '$($Custody.Scratch)'"
  }
  $assertDirectoryOwner = {
    param([object]$Handle, [string]$Path, [object]$Expected, [string]$Label)
    if ($null -eq $Handle -or $Handle.IsInvalid) { throw "$Label retained owner is unavailable" }
    $actual = [CrgProjectValues.FileNativeV1]::Snapshot($Handle)
    if (($actual.Attributes -band 0x10) -eq 0 -or ($actual.Attributes -band 0x400) -ne 0 -or
        ($null -ne $Expected -and ($actual.VolumeId -cne $Expected.VolumeId -or $actual.FileId -cne $Expected.FileId))) {
      throw "$Label lost ordinary-directory identity"
    }
    Assert-CrgHandleAtPath -Handle $Handle -Path $Path -Label $Label
  }
  try {
    & $assertDirectoryOwner $Custody.RootHandle $Custody.Scratch $Custody.RootSnapshot 'attribute-state scratch root'
    if ($null -ne $Custody.ObjectsHandle) {
      & $assertDirectoryOwner $Custody.ObjectsHandle $Custody.Objects $Custody.ObjectsSnapshot 'attribute-state object directory'
    }
    foreach ($file in @($Custody.Files.Values)) {
      if ($null -eq $file.Handle -or $file.Handle.IsInvalid) { throw "attribute-state object '$($file.Oid)' lost retained custody" }
      Assert-CrgHandleAtPath -Handle $file.Handle -Path $file.Path -Label "attribute-state object '$($file.Oid)'"
      $read = Read-CrgHeldFileBytes -Handle $file.Handle -Maximum 1048576 -Label "attribute-state object '$($file.Oid)'"
      if ($null -ne $file.Evidence -and ($read.Snapshot.VolumeId -cne $file.Evidence.Snapshot.VolumeId -or
          $read.Snapshot.FileId -cne $file.Evidence.Snapshot.FileId -or
          -not (Compare-CrgInstallValueBytes -Left $read.Bytes -Right $file.Evidence.Bytes))) {
        throw "attribute-state object '$($file.Oid)' changed before exact cleanup"
      }
      $deleteError = 0
      $deleteResult = [CrgProjectValues.FileNativeV1]::DeleteHeldExact($file.Handle, $false, [ref]$deleteError)
      if ($deleteResult -ne 0) { throw "attribute-state object '$($file.Oid)' exact disposition failed (result $deleteResult, Win32 error $deleteError)" }
      $file.Handle.Dispose(); $file.Handle = $null
      if (-not (Test-CrgRelativeNameAbsent -ParentHandle $file.Parent -Leaf $file.Leaf -Label "attribute-state object '$($file.Oid)' after close")) {
        throw "attribute-state object '$($file.Oid)' remained after exact disposition"
      }
    }
    foreach ($fanout in @($Custody.Fanouts.Values | Sort-Object -Property Path -Descending)) {
      & $assertDirectoryOwner $fanout.Handle $fanout.Path $fanout.Snapshot "attribute-state fanout '$($fanout.Leaf)'"
      $deleteError = 0
      $deleteResult = [CrgProjectValues.FileNativeV1]::DeleteHeldExact($fanout.Handle, $true, [ref]$deleteError)
      if ($deleteResult -ne 0) { throw "attribute-state fanout '$($fanout.Leaf)' exact disposition failed (result $deleteResult, Win32 error $deleteError)" }
      $fanout.Handle.Dispose(); $fanout.Handle = $null
      if (-not (Test-CrgRelativeNameAbsent -ParentHandle $Custody.ObjectsHandle -Leaf $fanout.Leaf -Label "attribute-state fanout '$($fanout.Leaf)' after close")) {
        throw "attribute-state fanout '$($fanout.Leaf)' remained after exact disposition"
      }
    }
    if ($null -ne $Custody.ObjectsHandle) {
      & $assertDirectoryOwner $Custody.ObjectsHandle $Custody.Objects $Custody.ObjectsSnapshot 'attribute-state object directory'
      $deleteError = 0
      $deleteResult = [CrgProjectValues.FileNativeV1]::DeleteHeldExact($Custody.ObjectsHandle, $true, [ref]$deleteError)
      if ($deleteResult -ne 0) { throw "attribute-state object directory exact disposition failed (result $deleteResult, Win32 error $deleteError)" }
      $Custody.ObjectsHandle.Dispose(); $Custody.ObjectsHandle = $null
      if (-not (Test-CrgRelativeNameAbsent -ParentHandle $Custody.RootHandle -Leaf 'objects' -Label 'attribute-state object directory after close')) {
        throw 'attribute-state object directory remained after exact disposition'
      }
    }
    & $assertDirectoryOwner $Custody.RootHandle $Custody.Scratch $Custody.RootSnapshot 'attribute-state scratch root'
    $deleteError = 0
    $deleteResult = [CrgProjectValues.FileNativeV1]::DeleteHeldExact($Custody.RootHandle, $true, [ref]$deleteError)
    if ($deleteResult -ne 0) { throw "attribute-state scratch root exact disposition failed (result $deleteResult, Win32 error $deleteError)" }
    $Custody.RootHandle.Dispose(); $Custody.RootHandle = $null
    if (-not (Test-CrgRelativeNameAbsent -ParentHandle $Custody.TempHandle -Leaf "crg-render-attribute-state-$($Custody.Token)" -Label 'attribute-state scratch root after close')) {
      throw 'attribute-state scratch root remained or was replaced after exact disposition'
    }
    Flush-CrgDirectoryExact -Handle $Custody.TempHandle -Label 'attribute-state temporary parent'
    $Custody.Removed = $true
  } finally {
    foreach ($file in @($Custody.Files.Values)) {
      if ($null -ne $file.Handle) { try { $file.Handle.Dispose() } catch { }; $file.Handle = $null }
    }
    Close-CrgRendererDirectoryPins -Pins $Custody.Pins
    $Custody.Pins = $null
  }
}

# The state proof needs a synthetic tree, but handing a pathname-only object
# directory to Git would reopen a replacement race. Encode the few required
# loose objects directly under retained create-new parents instead.
function Get-CrgAttributeStateLooseObjectBytes {
  param([ValidatePattern('\A(?:blob|tree)\z', Options = 'None')][string]$Type, [byte[]]$Bytes)
  if ($null -eq $Bytes) { throw 'attribute-state object encoding received null bytes' }
  [byte[]]$header = [System.Text.Encoding]::ASCII.GetBytes("$Type $($Bytes.Length)`0")
  [byte[]]$raw = New-Object byte[] ($header.Length + $Bytes.Length)
  [System.Array]::Copy($header, 0, $raw, 0, $header.Length)
  if ($Bytes.Length -gt 0) { [System.Array]::Copy($Bytes, 0, $raw, $header.Length, $Bytes.Length) }
  $output = New-Object System.IO.MemoryStream
  try {
    $output.WriteByte(0x78); $output.WriteByte(0x9C)
    $deflate = New-Object System.IO.Compression.DeflateStream($output, [System.IO.Compression.CompressionMode]::Compress, $true)
    try { $deflate.Write($raw, 0, $raw.Length) } finally { $deflate.Dispose() }
    [uint64]$a = 1; [uint64]$b = 0
    foreach ($byte in $raw) { $a = ($a + $byte) % 65521; $b = ($b + $a) % 65521 }
    [uint64]$adler = ($b -shl 16) -bor $a
    foreach ($shift in @(24, 16, 8, 0)) { $output.WriteByte([byte](($adler -shr $shift) -band 0xFF)) }
    return ,([byte[]]$output.ToArray())
  } finally { $output.Dispose() }
}

function Get-CrgAttributeStateObjectId {
  param([ValidatePattern('\A(?:blob|tree)\z', Options = 'None')][string]$Type, [byte[]]$Bytes, [ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$Format)
  if ($null -eq $Bytes) { throw 'attribute-state object-ID calculation received null bytes' }
  [byte[]]$header = [System.Text.Encoding]::ASCII.GetBytes("$Type $($Bytes.Length)`0")
  $stream = New-Object System.IO.MemoryStream
  $hash = if ([string]::Equals($Format, 'sha256', [System.StringComparison]::Ordinal)) { [System.Security.Cryptography.SHA256]::Create() } else { [System.Security.Cryptography.SHA1]::Create() }
  try {
    $stream.Write($header, 0, $header.Length)
    if ($Bytes.Length -gt 0) { $stream.Write($Bytes, 0, $Bytes.Length) }
    $stream.Position = 0
    return (([System.BitConverter]::ToString($hash.ComputeHash($stream))) -replace '-', '').ToLowerInvariant()
  } finally { $hash.Dispose(); $stream.Dispose() }
}

function New-CrgAttributeStateScratch {
  param([ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$ObjectFormat, [string]$Token = '')
  Initialize-CrgRendererFileNative
  if ([string]::IsNullOrEmpty($Token)) { $Token = [Guid]::NewGuid().ToString('N') }
  if ($Token -cnotmatch '\A[0-9a-f]{32}\z') { throw 'attribute-state scratch token is not canonical lowercase hexadecimal' }
  $tempRoot = Get-CrgCanonicalFsPath -Path ([System.IO.Path]::GetTempPath())
  $scratch = Join-Path $tempRoot "crg-render-attribute-state-$Token"
  $objects = Join-Path $scratch 'objects'
  $custody = [pscustomobject]@{
    Token = $Token; TempRoot = $tempRoot; Scratch = $scratch; Objects = $objects; ObjectFormat = $ObjectFormat
    Pins = $null; TempHandle = $null; RootHandle = $null; RootSnapshot = $null; ObjectsHandle = $null; ObjectsSnapshot = $null
    Files = (New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal))
    Fanouts = (New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal))
    Removed = $false
  }
  try {
    $custody.Pins = Enter-CrgRendererDirectoryPins -MutationDirectories @($tempRoot)
    $custody.TempHandle = Get-CrgPinnedDirectoryHandle -Pins $custody.Pins -Path $tempRoot
    Assert-CrgRelativeNameAbsent -ParentHandle $custody.TempHandle -Leaf "crg-render-attribute-state-$Token" -Label 'attribute-state scratch root'
    $createError = 0
    $custody.RootHandle = [CrgProjectValues.FileNativeV1]::CreateDirectoryRelative($custody.TempHandle, "crg-render-attribute-state-$Token", [ref]$createError)
    if ($null -eq $custody.RootHandle -or $custody.RootHandle.IsInvalid) {
      if ($null -ne $custody.RootHandle) { $custody.RootHandle.Dispose(); $custody.RootHandle = $null }
      throw "attribute-state scratch root create-new failed (Win32 error $createError)"
    }
    $custody.Pins.Owned.Add($custody.RootHandle) | Out-Null
    $custody.RootSnapshot = [CrgProjectValues.FileNativeV1]::Snapshot($custody.RootHandle)
    if (($custody.RootSnapshot.Attributes -band 0x10) -eq 0 -or ($custody.RootSnapshot.Attributes -band 0x400) -ne 0) { throw 'attribute-state scratch root is not one ordinary directory' }
    Assert-CrgHandleAtPath -Handle $custody.RootHandle -Path $scratch -Label 'attribute-state scratch root'
    $custody.Pins.Map[(Get-CrgCanonicalFsPath -Path $scratch)] = [pscustomobject]@{ Path = $scratch; Handle = $custody.RootHandle; Mutation = $true }
    Flush-CrgDirectoryExact -Handle $custody.TempHandle -Label 'attribute-state temporary parent'

    Assert-CrgRelativeNameAbsent -ParentHandle $custody.RootHandle -Leaf 'objects' -Label 'attribute-state object directory'
    $createError = 0
    $custody.ObjectsHandle = [CrgProjectValues.FileNativeV1]::CreateDirectoryRelative($custody.RootHandle, 'objects', [ref]$createError)
    if ($null -eq $custody.ObjectsHandle -or $custody.ObjectsHandle.IsInvalid) {
      if ($null -ne $custody.ObjectsHandle) { $custody.ObjectsHandle.Dispose(); $custody.ObjectsHandle = $null }
      throw "attribute-state object directory create-new failed (Win32 error $createError)"
    }
    $custody.Pins.Owned.Add($custody.ObjectsHandle) | Out-Null
    $custody.ObjectsSnapshot = [CrgProjectValues.FileNativeV1]::Snapshot($custody.ObjectsHandle)
    if (($custody.ObjectsSnapshot.Attributes -band 0x10) -eq 0 -or ($custody.ObjectsSnapshot.Attributes -band 0x400) -ne 0) { throw 'attribute-state object directory is not one ordinary directory' }
    Assert-CrgHandleAtPath -Handle $custody.ObjectsHandle -Path $objects -Label 'attribute-state object directory'
    $custody.Pins.Map[(Get-CrgCanonicalFsPath -Path $objects)] = [pscustomobject]@{ Path = $objects; Handle = $custody.ObjectsHandle; Mutation = $true }
    Flush-CrgDirectoryExact -Handle $custody.RootHandle -Label 'attribute-state scratch root'
    return $custody
  } catch {
    $primary = $_
    if ($null -ne $custody.RootHandle -and -not $custody.RootHandle.IsInvalid) {
      try { Remove-CrgAttributeStateScratch -Custody $custody } catch { throw [System.InvalidOperationException]::new("attribute-state scratch creation failed and exact cleanup also failed: $($primary.Exception.Message); cleanup: $($_.Exception.Message)", $primary.Exception) }
    } elseif ($null -ne $custody.Pins) {
      Close-CrgRendererDirectoryPins -Pins $custody.Pins
      $custody.Pins = $null
    }
    throw $primary
  }
}

function Add-CrgAttributeStateObject {
  param([object]$Custody, [ValidatePattern('\A(?:blob|tree)\z', Options = 'None')][string]$Type, [byte[]]$Bytes)
  if ($null -eq $Custody -or $Custody.Removed -or $null -eq $Bytes -or $null -eq $Custody.ObjectsHandle) { throw 'attribute-state object write received no live retained store' }
  $oid = Get-CrgAttributeStateObjectId -Type $Type -Bytes $Bytes -Format $Custody.ObjectFormat
  if ($Custody.Files.ContainsKey($oid)) { return $oid }
  $prefix = $oid.Substring(0, 2)
  if (-not $Custody.Fanouts.ContainsKey($prefix)) {
    Assert-CrgRelativeNameAbsent -ParentHandle $Custody.ObjectsHandle -Leaf $prefix -Label "attribute-state fanout '$prefix'"
    $createError = 0
    $fanoutHandle = [CrgProjectValues.FileNativeV1]::CreateDirectoryRelative($Custody.ObjectsHandle, $prefix, [ref]$createError)
    if ($null -eq $fanoutHandle -or $fanoutHandle.IsInvalid) {
      if ($null -ne $fanoutHandle) { $fanoutHandle.Dispose() }
      throw "attribute-state fanout '$prefix' create-new failed (Win32 error $createError)"
    }
    $fanoutPath = Join-Path $Custody.Objects $prefix
    $fanout = [pscustomobject]@{ Leaf = $prefix; Path = $fanoutPath; Handle = $fanoutHandle; Snapshot = $null }
    $Custody.Fanouts[$prefix] = $fanout
    $Custody.Pins.Owned.Add($fanoutHandle) | Out-Null
    $fanoutSnapshot = [CrgProjectValues.FileNativeV1]::Snapshot($fanoutHandle)
    if (($fanoutSnapshot.Attributes -band 0x10) -eq 0 -or ($fanoutSnapshot.Attributes -band 0x400) -ne 0) { throw "attribute-state fanout '$prefix' is not one ordinary directory" }
    Assert-CrgHandleAtPath -Handle $fanoutHandle -Path $fanoutPath -Label "attribute-state fanout '$prefix'"
    $Custody.Pins.Map[(Get-CrgCanonicalFsPath -Path $fanoutPath)] = [pscustomobject]@{ Path = $fanoutPath; Handle = $fanoutHandle; Mutation = $true }
    $fanout.Snapshot = $fanoutSnapshot
    Flush-CrgDirectoryExact -Handle $Custody.ObjectsHandle -Label 'attribute-state object directory'
  }
  $fanout = $Custody.Fanouts[$prefix]
  $leaf = $oid.Substring(2)
  Assert-CrgRelativeLeafAbsent -ParentHandle $fanout.Handle -Leaf $leaf -Label "attribute-state object '$oid'"
  [byte[]]$looseBytes = Get-CrgAttributeStateLooseObjectBytes -Type $Type -Bytes $Bytes
  $createError = 0
  $fileHandle = [CrgProjectValues.FileNativeV1]::CreateRecoveryCopyRelative($fanout.Handle, $leaf, [ref]$createError)
  if ($null -eq $fileHandle -or $fileHandle.IsInvalid) {
    if ($null -ne $fileHandle) { $fileHandle.Dispose() }
    throw "attribute-state object '$oid' create-new failed (Win32 error $createError)"
  }
  $path = Join-Path $fanout.Path $leaf
  $file = [pscustomobject]@{ Oid = $oid; Path = $path; Leaf = $leaf; Parent = $fanout.Handle; Handle = $fileHandle; Evidence = $null }
  $Custody.Files[$oid] = $file
  [CrgProjectValues.FileNativeV1]::WriteAllAndFlush($file.Handle, $looseBytes)
  $read = Read-CrgHeldFileBytes -Handle $file.Handle -Maximum 1048576 -Label "attribute-state object '$oid'"
  if (-not (Compare-CrgInstallValueBytes -Left $read.Bytes -Right $looseBytes)) { throw "attribute-state object '$oid' failed exact write verification" }
  Assert-CrgHandleAtPath -Handle $file.Handle -Path $path -Label "attribute-state object '$oid'"
  $file.Evidence = [pscustomobject]@{ Snapshot = $read.Snapshot; Bytes = $looseBytes }
  Flush-CrgDirectoryExact -Handle $fanout.Handle -Label "attribute-state fanout '$prefix'"
  return $oid
}

function New-CrgCachedAttributeStateSource {
  param([object]$Repo)
  $attributePaths = @('.gitattributes', 'scripts/.gitattributes', 'scripts/codex/.gitattributes', 'docs/.gitattributes')
  $listing = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments (@('ls-files', '--stage', '-z', '--') + $attributePaths)
  if ($listing.Exit -ne 0 -or $listing.ErrorText.Length -ne 0) { throw 'cached attribute-source inventory probe failed' }
  $records = @(ConvertFrom-CrgGitNulRecords -Bytes $listing.Bytes -Label 'cached attribute-source inventory')
  $oidLength = if ([string]::Equals($Repo.ObjectFormat, 'sha256', [System.StringComparison]::Ordinal)) { 64 } else { 40 }
  $sourceEntries = New-Object System.Collections.Hashtable([System.StringComparer]::Ordinal)
  foreach ($record in $records) {
    if ($record -cnotmatch "\A(100644|100755) ([0-9a-f]{$oidLength}) 0\t(.+)\z") { throw "cached attribute-source inventory returned a non-stage-0 regular entry: '$record'" }
    $path = [string]$Matches[3]
    if (-not [System.Linq.Enumerable]::Contains([string[]]@($attributePaths), [string]$path, [System.StringComparer]::Ordinal) -or $sourceEntries.ContainsKey($path)) { throw "cached attribute-source inventory returned an unexpected or duplicate path: '$path'" }
    $sourceEntries[$path] = [pscustomobject]@{ Mode = [string]$Matches[1]; Oid = [string]$Matches[2] }
  }

  $custody = $null
  try {
    $custody = New-CrgAttributeStateScratch -ObjectFormat $Repo.ObjectFormat
    $internal = @{ GIT_OBJECT_DIRECTORY = $custody.Objects; GIT_ALTERNATE_OBJECT_DIRECTORIES = $Repo.ObjectDir }
    $emptyOid = Add-CrgAttributeStateObject -Custody $custody -Type blob -Bytes ([byte[]]@())

    $makeTree = {
      param([object[]]$Entries, [string]$Label)
      # Git orders tree entries by their UTF-8 bytes, comparing a tree's name
      # as if it ended with '/'. Sort-Object compares by culture, and an
      # ordinal string sort compares UTF-16 code units, which order a
      # character above U+FFFF before U+E000-U+FFFF where the bytes do not;
      # the key is the bytes as lowercase hex, whose ordinal order is theirs.
      # An index array is sorted with the keys: Windows PowerShell passes an
      # object[] items array to [Array]::Sort as a converted copy, so the
      # items themselves would stay unsorted.
      [object[]]$unordered = @($Entries)
      $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
      [string[]]$sortKeys = @($unordered | ForEach-Object {
        $name = if ([string]::Equals($_.Type, 'tree', [System.StringComparison]::Ordinal)) { "$($_.Name)/" } else { [string]$_.Name }
        [BitConverter]::ToString($utf8.GetBytes($name)).Replace('-', '').ToLowerInvariant()
      })
      [int[]]$sortIndex = if ($unordered.Length -gt 0) { 0..($unordered.Length - 1) } else { @() }
      [Array]::Sort($sortKeys, $sortIndex, [System.StringComparer]::Ordinal)
      [object[]]$ordered = @($sortIndex | ForEach-Object { $unordered[$_] })
      $payload = New-Object System.IO.MemoryStream
      try {
        foreach ($entry in $ordered) {
          if ($entry.Name -cnotmatch '\A[A-Za-z0-9._-]+\z' -or $entry.Mode -cnotin @('100644', '100755', '040000') -or $entry.Type -cnotin @('blob', 'tree') -or
              $entry.Oid -cnotmatch "\A[0-9a-f]{$oidLength}\z") { throw "invalid $Label tree entry" }
          if (($entry.Type -ceq 'tree') -ne ($entry.Mode -ceq '040000')) { throw "invalid $Label tree entry type/mode pairing" }
          $treeMode = if ($entry.Type -ceq 'tree') { '40000' } else { $entry.Mode }
          [byte[]]$entryBytes = [System.Text.Encoding]::ASCII.GetBytes("$treeMode $($entry.Name)")
          $payload.Write($entryBytes, 0, $entryBytes.Length)
          $payload.WriteByte(0)
          for ($hexIndex = 0; $hexIndex -lt $entry.Oid.Length; $hexIndex += 2) {
            $payload.WriteByte([Convert]::ToByte($entry.Oid.Substring($hexIndex, 2), 16))
          }
        }
        [byte[]]$payloadBytes = $payload.ToArray()
      } finally { $payload.Dispose() }
      $treeOid = Add-CrgAttributeStateObject -Custody $custody -Type tree -Bytes $payloadBytes
      if ($treeOid -cnotmatch "\A[0-9a-f]{$oidLength}\z") { throw "$Label attribute-state tree returned a noncanonical object ID" }
      return $treeOid
    }.GetNewClosure()
    $addAttribute = {
      param([System.Collections.Generic.List[object]]$Entries, [string]$Path)
      if (-not $sourceEntries.ContainsKey($Path)) { return }
      $source = $sourceEntries[$Path]
      $Entries.Add([pscustomobject]@{ Mode = $source.Mode; Type = 'blob'; Oid = $source.Oid; Name = '.gitattributes' }) | Out-Null
    }.GetNewClosure()

    $codexEntries = New-Object 'System.Collections.Generic.List[object]'
    & $addAttribute $codexEntries 'scripts/codex/.gitattributes'
    $codexEntries.Add([pscustomobject]@{ Mode = '100644'; Type = 'blob'; Oid = $emptyOid; Name = 'review-prompt-template.md' }) | Out-Null
    $codexTree = & $makeTree $codexEntries.ToArray() 'scripts/codex'

    $scriptsEntries = New-Object 'System.Collections.Generic.List[object]'
    & $addAttribute $scriptsEntries 'scripts/.gitattributes'
    $scriptsEntries.Add([pscustomobject]@{ Mode = '040000'; Type = 'tree'; Oid = $codexTree; Name = 'codex' }) | Out-Null
    $scriptsTree = & $makeTree $scriptsEntries.ToArray() 'scripts'

    $docsEntries = New-Object 'System.Collections.Generic.List[object]'
    & $addAttribute $docsEntries 'docs/.gitattributes'
    $docsEntries.Add([pscustomobject]@{ Mode = '100644'; Type = 'blob'; Oid = $emptyOid; Name = 'AGENTS.md.template' }) | Out-Null
    $docsTree = & $makeTree $docsEntries.ToArray() 'docs'

    $rootEntries = New-Object 'System.Collections.Generic.List[object]'
    & $addAttribute $rootEntries '.gitattributes'
    $rootEntries.Add([pscustomobject]@{ Mode = '100644'; Type = 'blob'; Oid = $emptyOid; Name = 'CROSS-REVIEW-VALUES.md' }) | Out-Null
    $rootEntries.Add([pscustomobject]@{ Mode = '040000'; Type = 'tree'; Oid = $docsTree; Name = 'docs' }) | Out-Null
    $rootEntries.Add([pscustomobject]@{ Mode = '040000'; Type = 'tree'; Oid = $scriptsTree; Name = 'scripts' }) | Out-Null
    $treeOid = & $makeTree $rootEntries.ToArray() 'root'
    return [pscustomobject]@{ TreeOid = $treeOid; InternalEnvironment = $internal; Custody = $custody }
  } catch {
    if ($null -ne $custody -and -not $custody.Removed) { Remove-CrgAttributeStateScratch -Custody $custody }
    throw
  }
}

function Assert-CrgAttributeGraphStates {
  param([object]$Repo, [switch]$Cached, [object]$StateSource)
  $paths = @('CROSS-REVIEW-VALUES.md', 'scripts/codex/review-prompt-template.md', 'docs/AGENTS.md.template')
  $pathspecs = New-Object 'System.Collections.Generic.List[string]'
  foreach ($path in $paths) {
    for ($mask = 0; $mask -lt 8; $mask++) {
      $filter = if (($mask -band 1) -ne 0) { '!filter' } else { '-filter' }
      $ident = if (($mask -band 2) -ne 0) { '!ident' } else { '-ident' }
      $encoding = if (($mask -band 4) -ne 0) { '!working-tree-encoding' } else { '-working-tree-encoding' }
      $pathspecs.Add(":(top,attr:text eol=lf $filter $ident $encoding)$path") | Out-Null
    }
  }
  if ($Cached) {
    if ($null -eq $StateSource -or [string]::IsNullOrWhiteSpace([string]$StateSource.TreeOid)) { throw 'cached attribute-state proof has no source-bound tree' }
    $arguments = @("--attr-source=$($StateSource.TreeOid)", 'ls-files', '-z', '--cached', "--with-tree=$($StateSource.TreeOid)", '--') + $pathspecs.ToArray()
    $label = 'cached attribute-state proof'
  } else {
    if ($null -eq $StateSource -or [string]::IsNullOrWhiteSpace([string]$StateSource.TreeOid)) { throw 'working-tree attribute-state proof has no bounded path tree' }
    $arguments = @('ls-files', '-z', '--cached', "--with-tree=$($StateSource.TreeOid)", '--') + $pathspecs.ToArray()
    $label = 'working-tree attribute-state proof'
  }
  $result = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments $arguments -InternalEnvironment $StateSource.InternalEnvironment
  if ($result.Exit -ne 0 -or $result.ErrorText.Length -ne 0) { throw "$label failed with Git exit $($result.Exit): $($result.ErrorText.Trim())" }
  $actual = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
  foreach ($path in @(ConvertFrom-CrgGitNulRecords -Bytes $result.Bytes -Label $label)) {
    if (-not [System.Linq.Enumerable]::Contains([string[]]@($paths), [string]$path, [System.StringComparer]::Ordinal) -or -not $actual.Add($path)) { throw "$label returned an unexpected or duplicate path '$path'" }
  }
  foreach ($path in $paths) {
    if (-not $actual.Contains($path)) { throw "'$path' has a string-valued collision or invalid special state in the $label" }
  }
}

function Get-CrgAttributeGraph {
  param([object]$Repo, [switch]$Cached)
  $paths = @('CROSS-REVIEW-VALUES.md', 'scripts/codex/review-prompt-template.md', 'docs/AGENTS.md.template')
  $attributes = @('text', 'eol', 'filter', 'ident', 'working-tree-encoding')
  $stateSource = $null
  try {
    $stateSource = New-CrgCachedAttributeStateSource -Repo $Repo
    $arguments = New-Object 'System.Collections.Generic.List[string]'
    if ($Cached) { $arguments.Add("--attr-source=$($stateSource.TreeOid)") | Out-Null }
    $arguments.Add('check-attr') | Out-Null
    $arguments.Add('-z') | Out-Null
    foreach ($attribute in $attributes) { $arguments.Add($attribute) | Out-Null }
    $arguments.Add('--') | Out-Null
    foreach ($path in $paths) { $arguments.Add($path) | Out-Null }
    $internal = if ($Cached) { $stateSource.InternalEnvironment } else { $null }
    $result = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments $arguments.ToArray() -InternalEnvironment $internal
    if ($result.Exit -ne 0 -or $result.ErrorText.Length -ne 0) { throw 'checkout-attribute graph probe failed' }
    $records = @(ConvertFrom-CrgGitNulRecords -Bytes $result.Bytes -Label 'checkout-attribute graph probe')
    if ($records.Count -ne ($paths.Count * $attributes.Count * 3)) { throw 'checkout-attribute graph returned an incomplete matrix' }
    $graph = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    for ($i = 0; $i -lt $records.Count; $i += 3) {
      $path = $records[$i]; $attribute = $records[$i + 1]; $value = $records[$i + 2]
      if (-not [System.Linq.Enumerable]::Contains([string[]]@($paths), [string]$path, [System.StringComparer]::Ordinal) -or
          -not [System.Linq.Enumerable]::Contains([string[]]@($attributes), [string]$attribute, [System.StringComparer]::Ordinal)) { throw 'checkout-attribute graph returned an unknown path or attribute' }
      $key = "$path`0$attribute"
      if ($graph.Contains($key)) { throw 'checkout-attribute graph duplicated a path/attribute result' }
      $graph[$key] = $value
    }
    foreach ($path in $paths) {
      if (-not [string]::Equals($graph["$path`0text"], 'set', [System.StringComparison]::Ordinal) -or -not [string]::Equals($graph["$path`0eol"], 'lf', [System.StringComparison]::Ordinal)) { throw "'$path' lacks effective text eol=lf checkout authority" }
      foreach ($attribute in @('filter', 'ident', 'working-tree-encoding')) {
        $state = $graph["$path`0$attribute"]
        if (-not ([string]::Equals($state, 'unset', [System.StringComparison]::Ordinal) -or [string]::Equals($state, 'unspecified', [System.StringComparison]::Ordinal))) { throw "'$path' has active checkout attribute '$attribute'" }
      }
    }
    Assert-CrgAttributeGraphStates -Repo $Repo -Cached:$Cached -StateSource $stateSource
    return $graph
  } finally {
    if ($null -ne $stateSource) { Remove-CrgAttributeStateScratch -Custody $stateSource.Custody }
  }
}

function Assert-CrgAttributeGraphsEqual {
  param([object]$IndexGraph, [object]$WorkingGraph)
  if ($IndexGraph.Count -ne $WorkingGraph.Count) { throw 'index and working-tree checkout-attribute graph sizes differ' }
  foreach ($key in $IndexGraph.Keys) {
    if (-not $WorkingGraph.Contains($key) -or -not [string]::Equals([string]$IndexGraph[$key], [string]$WorkingGraph[$key], [System.StringComparison]::Ordinal)) {
      $display = $key.Replace([char]0, [char]':')
      throw "index and working-tree checkout attributes differ at '$display'"
    }
  }
}

function Get-CrgGitBlobObjectId {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes, [ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$Format)
  [byte[]]$header = [System.Text.Encoding]::ASCII.GetBytes("blob $($Bytes.Length)`0")
  $stream = New-Object System.IO.MemoryStream
  $hash = if ([string]::Equals($Format, 'sha256', [System.StringComparison]::Ordinal)) { [System.Security.Cryptography.SHA256]::Create() } else { [System.Security.Cryptography.SHA1]::Create() }
  try {
    $stream.Write($header, 0, $header.Length)
    $stream.Write($Bytes, 0, $Bytes.Length)
    $stream.Position = 0
    return (([System.BitConverter]::ToString($hash.ComputeHash($stream))) -replace '-', '').ToLowerInvariant()
  } finally { $hash.Dispose(); $stream.Dispose() }
}

function Assert-CrgTrackedAttributeBehavior {
  param([object]$Repo)
  [byte[]]$lf = $script:CrgUtf8NoBom.GetBytes("crg checkout probe`n`$Id$`ncaf$([char]0x00E9)`n")
  [byte[]]$crlf = $script:CrgUtf8NoBom.GetBytes("crg checkout probe`r`n`$Id$`r`ncaf$([char]0x00E9)`r`n")
  $expectedOid = Get-CrgGitBlobObjectId -Bytes $lf -Format $Repo.ObjectFormat
  $custody = $null
  try {
    # Retain the object-store namespace through Git reads and exact cleanup;
    # pathname-only creation and recursive cleanup cannot establish ownership.
    $custody = New-CrgAttributeStateScratch -ObjectFormat $Repo.ObjectFormat
    $writtenOid = Add-CrgAttributeStateObject -Custody $custody -Type blob -Bytes $lf
    if (-not [string]::Equals($writtenOid, $expectedOid, [System.StringComparison]::Ordinal)) { throw 'isolated attribute-probe object ID differs from the expected LF blob' }
    $internal = @{ GIT_OBJECT_DIRECTORY = $custody.Objects; GIT_ALTERNATE_OBJECT_DIRECTORIES = $Repo.ObjectDir }
    foreach ($path in @('CROSS-REVIEW-VALUES.md', 'scripts/codex/review-prompt-template.md', 'docs/AGENTS.md.template')) {
      foreach ($input in @($lf, $crlf)) {
        $clean = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('-c', 'core.autocrlf=true', 'hash-object', "--path=$path", '--stdin') -InputBytes $input -InternalEnvironment $internal
        $cleanOid = Get-CrgSingleGitLine -Result $clean -Label "core.autocrlf clean probe for '$path'"
        if (-not [string]::Equals($cleanOid, $expectedOid, [System.StringComparison]::Ordinal)) { throw "checkout clean behavior for '$path' does not preserve the required LF blob" }
      }
      $checkout = Invoke-CrgTargetGit -RepoRoot $Repo.Root -Arguments @('-c', 'core.autocrlf=true', 'cat-file', '--filters', "--path=$path", $expectedOid) -MaximumOutputBytes 4096 -InternalEnvironment $internal
      if ($checkout.Exit -ne 0 -or $checkout.ErrorText.Length -ne 0 -or -not (Compare-CrgInstallValueBytes -Left $checkout.Bytes -Right $lf)) {
        throw "checkout smudge behavior for '$path' changes strict UTF-8 LF, literal `$Id$, or non-ASCII bytes"
      }
    }
  } finally {
    if ($null -ne $custody -and -not $custody.Removed) { Remove-CrgAttributeStateScratch -Custody $custody }
  }
}

$script:CrgRendererOutputs = @(
  [pscustomobject]@{ Id = 'review-prompt'; Relative = 'scripts/codex/review-prompt-template.md'; ParentRelative = 'scripts/codex'; Leaf = 'review-prompt-template.md' },
  [pscustomobject]@{ Id = 'agents-template'; Relative = 'docs/AGENTS.md.template'; ParentRelative = 'docs'; Leaf = 'AGENTS.md.template' }
)
$script:CrgRendererStateLeaf = 'crg-render-project-values-transaction'

function ConvertTo-CrgCanonicalLength {
  param([Parameter(Mandatory = $true)][string]$Text, [string]$Label)
  if ($Text -cnotmatch '^(0|[1-9][0-9]*)$') { throw "$Label is not canonical unsigned decimal" }
  [uint64]$value = 0
  if (-not [uint64]::TryParse($Text, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value)) {
    throw "$Label exceeds UInt64"
  }
  if ($value.ToString([System.Globalization.CultureInfo]::InvariantCulture) -cne $Text) { throw "$Label is not canonical unsigned decimal" }
  return $value
}

function Read-CrgRendererStateBytes {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 4096 -or $Bytes[$Bytes.Length - 1] -ne 0x0A) { throw 'renderer state has an invalid byte length or missing final LF' }
  foreach ($value in $Bytes) { if (($value -lt 0x20 -or $value -gt 0x7E) -and $value -ne 0x0A) { throw 'renderer state contains a non-printable-ASCII byte' } }
  $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
  $lines = @($text.Substring(0, $text.Length - 1) -split "`n", 0)
  if ($lines.Count -ne 26 -or @($lines | Where-Object { $_.Length -eq 0 }).Count -ne 0) { throw 'renderer state must contain exactly 26 nonempty LF-terminated records' }
  if (-not [string]::Equals($lines[0], 'crg-render-project-values-transaction v1', [System.StringComparison]::Ordinal) -or -not [string]::Equals($lines[1], 'phase: PREPARED', [System.StringComparison]::Ordinal)) { throw 'renderer state has an invalid header or phase' }
  if ($lines[2] -cnotmatch '^transaction-id: ([0-9a-f]{32})$') { throw 'renderer state has an invalid transaction ID' }
  $transactionId = [string]$Matches[1]
  if ($lines[3] -cnotmatch '^values-sha256: ([0-9a-f]{64})$') { throw 'renderer state has an invalid values digest' }
  $valuesSha = [string]$Matches[1]
  $offsets = @(4, 15)
  $ids = @('review-prompt', 'agents-template')
  $outputs = New-Object 'System.Collections.Generic.List[object]'
  for ($i = 0; $i -lt 2; $i++) {
    $offset = $offsets[$i]
    $prefix = "output-$($i + 1)"
    if (-not [string]::Equals($lines[$offset], "$prefix`: $($ids[$i])", [System.StringComparison]::Ordinal)) { throw "renderer state has an invalid $prefix identifier" }
    $fieldValues = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    $expected = @(
      'preimage-volume-id', 'preimage-file-id', 'preimage-link-count', 'preimage-length', 'preimage-sha256',
      'postimage-volume-id', 'postimage-file-id', 'postimage-link-count', 'postimage-length', 'postimage-sha256'
    )
    for ($j = 0; $j -lt $expected.Count; $j++) {
      $field = $expected[$j]
      $literal = "$prefix-$field`: "
      $line = [string]$lines[$offset + 1 + $j]
      if (-not $line.StartsWith($literal, [System.StringComparison]::Ordinal)) { throw "renderer state is missing ordered field '$prefix-$field'" }
      $fieldValues[$field] = $line.Substring($literal.Length)
    }
    foreach ($field in @('preimage-volume-id', 'postimage-volume-id')) { if ($fieldValues[$field] -cnotmatch '^[0-9a-f]{16}$') { throw "renderer state field '$prefix-$field' is invalid" } }
    foreach ($field in @('preimage-file-id', 'postimage-file-id')) { if ($fieldValues[$field] -cnotmatch '^[0-9a-f]{32}$') { throw "renderer state field '$prefix-$field' is invalid" } }
    foreach ($field in @('preimage-sha256', 'postimage-sha256')) { if ($fieldValues[$field] -cnotmatch '^[0-9a-f]{64}$') { throw "renderer state field '$prefix-$field' is invalid" } }
    foreach ($field in @('preimage-link-count', 'postimage-link-count')) { if (-not [string]::Equals($fieldValues[$field], '1', [System.StringComparison]::Ordinal)) { throw "renderer state field '$prefix-$field' must be literal 1" } }
    $preLength = ConvertTo-CrgCanonicalLength -Text $fieldValues['preimage-length'] -Label "$prefix preimage length"
    $postLength = ConvertTo-CrgCanonicalLength -Text $fieldValues['postimage-length'] -Label "$prefix postimage length"
    $outputs.Add([pscustomobject]@{
      Id = $ids[$i]
      Pre = [pscustomobject]@{ VolumeId = $fieldValues['preimage-volume-id']; FileId = $fieldValues['preimage-file-id']; LinkCount = [uint32]1; Length = $preLength; Sha256 = $fieldValues['preimage-sha256'] }
      Post = [pscustomobject]@{ VolumeId = $fieldValues['postimage-volume-id']; FileId = $fieldValues['postimage-file-id']; LinkCount = [uint32]1; Length = $postLength; Sha256 = $fieldValues['postimage-sha256'] }
    }) | Out-Null
  }
  return [pscustomobject]@{ TransactionId = $transactionId; ValuesSha256 = $valuesSha; Outputs = $outputs.ToArray(); Bytes = $Bytes }
}

function New-CrgRendererStateBytes {
  param([string]$TransactionId, [string]$ValuesSha256, [object[]]$Outputs)
  if ($TransactionId -cnotmatch '^[0-9a-f]{32}$' -or $ValuesSha256 -cnotmatch '^[0-9a-f]{64}$' -or $Outputs.Count -ne 2) { throw 'renderer state builder received invalid transaction authority' }
  $lines = New-Object 'System.Collections.Generic.List[string]'
  $lines.Add('crg-render-project-values-transaction v1') | Out-Null
  $lines.Add('phase: PREPARED') | Out-Null
  $lines.Add("transaction-id: $TransactionId") | Out-Null
  $lines.Add("values-sha256: $ValuesSha256") | Out-Null
  for ($i = 0; $i -lt 2; $i++) {
    $number = $i + 1
    $output = $Outputs[$i]
    $lines.Add("output-$number`: $($output.Id)") | Out-Null
    foreach ($epoch in @('Pre', 'Post')) {
      $prefix = $epoch.ToLowerInvariant() + 'image'
      $snapshot = $output.$epoch
      if ($snapshot.VolumeId -cnotmatch '^[0-9a-f]{16}$' -or $snapshot.FileId -cnotmatch '^[0-9a-f]{32}$' -or $snapshot.LinkCount -ne 1 -or
          $snapshot.Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw "renderer state builder received an invalid $prefix snapshot" }
      $lines.Add("output-$number-$prefix-volume-id: $($snapshot.VolumeId)") | Out-Null
      $lines.Add("output-$number-$prefix-file-id: $($snapshot.FileId)") | Out-Null
      $lines.Add("output-$number-$prefix-link-count: 1") | Out-Null
      $lines.Add("output-$number-$prefix-length: $([uint64]$snapshot.Length)") | Out-Null
      $lines.Add("output-$number-$prefix-sha256: $($snapshot.Sha256)") | Out-Null
    }
  }
  [byte[]]$bytes = [System.Text.Encoding]::ASCII.GetBytes(($lines -join "`n") + "`n")
  $parsed = Read-CrgRendererStateBytes -Bytes $bytes
  if ($parsed.TransactionId -cne $TransactionId -or $parsed.ValuesSha256 -cne $ValuesSha256) { throw 'renderer state builder failed strict round-trip validation' }
  return ,([byte[]]$bytes)
}

function ConvertTo-CrgRecordedSnapshot {
  param([object]$Snapshot, [string]$Sha256)
  if ($Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'snapshot digest is noncanonical' }
  return [pscustomobject]@{ VolumeId = [string]$Snapshot.VolumeId; FileId = [string]$Snapshot.FileId; LinkCount = [uint32]$Snapshot.LinkCount; Length = [uint64]$Snapshot.Length; Sha256 = $Sha256 }
}

function Assert-CrgHeldSnapshotMatches {
  param([object]$Handle, [object]$Expected, [string]$Label, [uint64]$Maximum = 1048576)
  $read = Read-CrgHeldFileBytes -Handle $Handle -Maximum $Maximum -Label $Label
  if (-not [string]::Equals($read.Snapshot.VolumeId, $Expected.VolumeId, [System.StringComparison]::Ordinal) -or -not [string]::Equals($read.Snapshot.FileId, $Expected.FileId, [System.StringComparison]::Ordinal) -or
      $read.Snapshot.LinkCount -ne 1 -or [uint64]$read.Snapshot.Length -ne [uint64]$Expected.Length -or -not [string]::Equals($read.Sha256, $Expected.Sha256, [System.StringComparison]::Ordinal)) {
    throw "$Label does not match the recorded native identity, length, or digest"
  }
  return $read
}

function Get-CrgOutputSpecById {
  param([Parameter(Mandatory = $true)][string]$Id)
  $matches = @($script:CrgRendererOutputs | Where-Object { [string]::Equals($_.Id, $Id, [System.StringComparison]::Ordinal) })
  if ($matches.Count -ne 1) { throw "unknown renderer output identifier '$Id'" }
  return $matches[0]
}

function Get-CrgRendererTransactionPaths {
  param([object]$Repo, [string]$TransactionId)
  if ($TransactionId -cnotmatch '^[0-9a-f]{32}$') { throw 'transaction path derivation received an invalid ID' }
  $root = Join-Path (Join-Path $Repo.CommonDir 'crg-backups') "render-$TransactionId"
  $outputs = New-Object 'System.Collections.Generic.List[object]'
  foreach ($spec in $script:CrgRendererOutputs) {
    $destination = Join-Path $Repo.Root ($spec.Relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $parent = Split-Path -Parent $destination
    $preimageCopy = Join-Path (Join-Path $root 'preimage') ($spec.Relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $abortedCopy = Join-Path (Join-Path $root 'aborted-postimage') ($spec.Relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $outputs.Add([pscustomobject]@{
      Id = $spec.Id; Relative = $spec.Relative; Destination = $destination; Parent = $parent; Leaf = $spec.Leaf
      StageLeaf = "$($spec.Leaf).crg-render-stage-$TransactionId"
      CustodyLeaf = "$($spec.Leaf).crg-render-custody-$TransactionId"
      BackupLeaf = "$($spec.Leaf).crg-render-backup-$TransactionId"
      ArchiveLeaf = "$($spec.Leaf).crg-render-aborted-$TransactionId"
      PreimageCopy = $preimageCopy; AbortedCopy = $abortedCopy
    }) | Out-Null
  }
  return [pscustomobject]@{
    State = Join-Path $Repo.GitDir $script:CrgRendererStateLeaf
    StateLeaf = $script:CrgRendererStateLeaf
    StateStageLeaf = "$script:CrgRendererStateLeaf.new-$TransactionId"
    RecoveryRoot = $root
    BackupBase = Join-Path $Repo.CommonDir 'crg-backups'
    Outputs = $outputs.ToArray()
  }
}

function Ensure-CrgPinnedDirectory {
  param([object]$Pins, [string]$Path, [switch]$Create, [string]$Label)
  $canonical = Get-CrgCanonicalFsPath -Path $Path
  if ($Pins.Map.ContainsKey($canonical)) { return $Pins.Map[$canonical].Handle }
  $parentPath = Get-CrgCanonicalFsPath -Path (Split-Path -Parent $canonical)
  if ([string]::Equals($parentPath, $canonical, [System.StringComparison]::OrdinalIgnoreCase)) { throw "$Label is outside the retained namespace" }
  $parent = Ensure-CrgPinnedDirectory -Pins $Pins -Path $parentPath -Create:$Create -Label $Label
  $leaf = Split-Path -Leaf $canonical
  $errorCode = 0
  $handle = [CrgProjectValues.FileNativeV1]::OpenDirectoryRelative($parent, $leaf, $true, [ref]$errorCode)
  if (($null -eq $handle -or $handle.IsInvalid) -and $Create -and ($errorCode -eq 2 -or $errorCode -eq 3)) {
    if ($null -ne $handle) { $handle.Dispose() }
    $handle = [CrgProjectValues.FileNativeV1]::CreateDirectoryRelative($parent, $leaf, [ref]$errorCode)
    if ($null -ne $handle -and -not $handle.IsInvalid) { Flush-CrgDirectoryExact -Handle $parent -Label "$Label parent" }
  }
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    throw "$Label '$canonical' could not be retained$(if ($Create) { ' or created' } else { '' }) as an ordinary directory (Win32 error $errorCode)"
  }
  $snapshot = [CrgProjectValues.FileNativeV1]::Snapshot($handle)
  if (($snapshot.Attributes -band 0x10) -eq 0 -or ($snapshot.Attributes -band 0x400) -ne 0) { $handle.Dispose(); throw "$Label '$canonical' is not an ordinary non-reparse directory" }
  $Pins.Map[$canonical] = [pscustomobject]@{ Path = $canonical; Handle = $handle; Mutation = $true }
  $Pins.Owned.Add($handle) | Out-Null
  return $handle
}

function Get-CrgParentAndLeaf {
  param([object]$Pins, [string]$Path, [switch]$CreateParent, [string]$Label)
  $full = [System.IO.Path]::GetFullPath($Path)
  $parentPath = Split-Path -Parent $full
  $parent = Ensure-CrgPinnedDirectory -Pins $Pins -Path $parentPath -Create:$CreateParent -Label "$Label parent"
  return [pscustomobject]@{ Parent = $parent; ParentPath = (Get-CrgCanonicalFsPath -Path $parentPath); Leaf = (Split-Path -Leaf $full); FullPath = $full }
}

function New-CrgHeldExactFile {
  param([object]$Parent, [string]$Leaf, [byte[]]$Bytes, [string]$Label, [switch]$State)
  $errorCode = 0
  $handle = if ($State) {
    [CrgProjectValues.FileNativeV1]::CreateStateShareNoneRelative($Parent, $Leaf, [ref]$errorCode)
  } else { [CrgProjectValues.FileNativeV1]::CreateStageShareNoneRelative($Parent, $Leaf, [ref]$errorCode) }
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    throw "$Label could not be created with create-new retained custody (Win32 error $errorCode)"
  }
  try {
    if ($null -ne $Bytes) {
      [CrgProjectValues.FileNativeV1]::WriteAllAndFlush($handle, $Bytes)
      $read = Read-CrgHeldFileBytes -Handle $handle -Maximum ([uint64][Math]::Max(4096, $Bytes.Length)) -Label $Label
      if (-not (Compare-CrgInstallValueBytes -Left $read.Bytes -Right $Bytes)) { throw "$Label failed exact write verification" }
    }
    return $handle
  } catch { $handle.Dispose(); throw }
}

function New-CrgHeldRecoveryCopy {
  param([object]$Pins, [string]$Path, [byte[]]$Bytes, [object]$Expected, [string]$Label)
  $binding = Get-CrgParentAndLeaf -Pins $Pins -Path $Path -CreateParent -Label $Label
  $errorCode = 0
  $handle = [CrgProjectValues.FileNativeV1]::CreateRecoveryCopyRelative($binding.Parent, $binding.Leaf, [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    throw "$Label could not be created without replacement (Win32 error $errorCode)"
  }
  try {
    [CrgProjectValues.FileNativeV1]::WriteAllAndFlush($handle, $Bytes)
    $read = Read-CrgHeldFileBytes -Handle $handle -Maximum 1048576 -Label $Label
    if ($read.Sha256 -cne $Expected.Sha256 -or [uint64]$read.Snapshot.Length -ne [uint64]$Expected.Length -or
        -not (Compare-CrgInstallValueBytes -Left $read.Bytes -Right $Bytes)) { throw "$Label failed durable copy verification" }
    Flush-CrgDirectoryExact -Handle $binding.Parent -Label "$Label parent"
    return [pscustomobject]@{ Handle = $handle; Binding = $binding; Bytes = $read.Bytes; Sha256 = $read.Sha256 }
  } catch { $handle.Dispose(); throw }
}

function Flush-CrgDirectoryExact {
  param([object]$Handle, [string]$Label)
  $errorCode = 0
  if (-not [CrgProjectValues.FileNativeV1]::FlushDirectory($Handle, [ref]$errorCode)) { throw "$Label namespace flush failed (Win32 error $errorCode)" }
}

function ConvertFrom-CrgFinalHandlePath {
  param([Parameter(Mandatory = $true)][string]$Path)
  $native = $Path
  if ($native.StartsWith('\\?\UNC\', [System.StringComparison]::OrdinalIgnoreCase)) { $native = '\\' + $native.Substring(8) }
  elseif ($native.StartsWith('\\?\', [System.StringComparison]::Ordinal)) { $native = $native.Substring(4) }
  return Get-CrgCanonicalFsPath -Path $native
}

function Assert-CrgHandleAtPath {
  param([object]$Handle, [string]$Path, [string]$Label)
  $actual = ConvertFrom-CrgFinalHandlePath -Path ([CrgProjectValues.FileNativeV1]::GetFinalPath($Handle))
  $expected = Get-CrgCanonicalFsPath -Path $Path
  if (-not [string]::Equals($actual, $expected, [System.StringComparison]::OrdinalIgnoreCase)) { throw "$Label retained handle no longer names '$expected'" }
}

function Open-CrgRendererState {
  param([object]$GitDirHandle, [string]$StatePath)
  $errorCode = 0
  $handle = [CrgProjectValues.FileNativeV1]::OpenStateShareNoneRelative($GitDirHandle, $script:CrgRendererStateLeaf, [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    if ($errorCode -eq 2 -or $errorCode -eq 3) { return [pscustomobject]@{ State = 'absent'; Handle = $null; Record = $null } }
    throw "renderer state could not be opened with required read+write+DELETE share-none custody (Win32 error $errorCode)"
  }
  try {
    $read = Read-CrgHeldFileBytes -Handle $handle -Maximum 4096 -Label 'renderer transaction state'
    $record = Read-CrgRendererStateBytes -Bytes $read.Bytes
    Assert-CrgHandleAtPath -Handle $handle -Path $StatePath -Label 'renderer transaction state'
    return [pscustomobject]@{ State = 'prepared'; Handle = $handle; Record = $record; Bytes = $read.Bytes }
  } catch { $handle.Dispose(); throw }
}

function Remove-CrgHeldRendererStateExact {
  param([object]$State, [object]$GitDirHandle, [string]$StatePath, [ref]$DispositionStarted)
  $DispositionStarted.Value = $false
  if ($null -eq $State.Handle -or $State.Handle.IsInvalid) { throw 'renderer state owner is unavailable for terminal deletion' }
  $read = Read-CrgHeldFileBytes -Handle $State.Handle -Maximum 4096 -Label 'renderer transaction state at commit'
  if (-not (Compare-CrgInstallValueBytes -Left $read.Bytes -Right $State.Record.Bytes)) { throw 'renderer state bytes changed before terminal deletion' }
  $null = Read-CrgRendererStateBytes -Bytes $read.Bytes
  Assert-CrgHandleAtPath -Handle $State.Handle -Path $StatePath -Label 'renderer transaction state at commit'
  $errorCode = 0
  $deleteResult = [CrgProjectValues.FileNativeV1]::DeleteHeldExact($State.Handle, $false, [ref]$errorCode)
  if ($deleteResult -ne 0) { throw "renderer state exact disposition failed (result $deleteResult, Win32 error $errorCode)" }
  $DispositionStarted.Value = $true
  $State.Handle.Dispose()
  $State.Handle = $null
  if (-not (Test-CrgRelativeNameAbsent -ParentHandle $GitDirHandle -Leaf $script:CrgRendererStateLeaf -Label 'renderer transaction state after close')) {
    throw 'renderer transaction state remains present after owner CloseHandle'
  }
  Flush-CrgDirectoryExact -Handle $GitDirHandle -Label 'renderer state parent'
  if (-not (Test-CrgRelativeNameAbsent -ParentHandle $GitDirHandle -Leaf $script:CrgRendererStateLeaf -Label 'renderer transaction state after namespace flush')) {
    throw 'renderer transaction state reappeared after durable absence proof'
  }
}

function Find-CrgPinnedExistingDirectory {
  param([object]$Pins, [string]$Path, [string]$Label)
  $canonical = Get-CrgCanonicalFsPath -Path $Path
  if ($Pins.Map.ContainsKey($canonical)) { return $Pins.Map[$canonical].Handle }
  $parentPath = Get-CrgCanonicalFsPath -Path (Split-Path -Parent $canonical)
  if ([string]::Equals($parentPath, $canonical, [System.StringComparison]::OrdinalIgnoreCase)) { throw "$Label is outside retained namespace authority" }
  $parent = Find-CrgPinnedExistingDirectory -Pins $Pins -Path $parentPath -Label $Label
  if ($null -eq $parent) { return $null }
  $errorCode = 0
  $handle = [CrgProjectValues.FileNativeV1]::OpenDirectoryRelative($parent, (Split-Path -Leaf $canonical), $true, [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    if ($errorCode -eq 2 -or $errorCode -eq 3) { return $null }
    throw "$Label directory '$canonical' is occupied or cannot be retained (Win32 error $errorCode)"
  }
  $snapshot = [CrgProjectValues.FileNativeV1]::Snapshot($handle)
  if (($snapshot.Attributes -band 0x10) -eq 0 -or ($snapshot.Attributes -band 0x400) -ne 0) { $handle.Dispose(); throw "$Label directory '$canonical' is not ordinary and non-reparse" }
  $Pins.Map[$canonical] = [pscustomobject]@{ Path = $canonical; Handle = $handle; Mutation = $true }
  $Pins.Owned.Add($handle) | Out-Null
  return $handle
}

function Open-CrgRecoveryOccupant {
  param([object]$Pins, [string]$Path, [string]$Label, [uint64]$Maximum = 1048576)
  $parentPath = Split-Path -Parent ([System.IO.Path]::GetFullPath($Path))
  $parent = Find-CrgPinnedExistingDirectory -Pins $Pins -Path $parentPath -Label $Label
  if ($null -eq $parent) { return [pscustomobject]@{ State = 'absent'; Handle = $null; Binding = $null } }
  $leaf = Split-Path -Leaf $Path
  $errorCode = 0
  $handle = [CrgProjectValues.FileNativeV1]::OpenRecoveryIdentityRelative($parent, $leaf, [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    if ($errorCode -eq 2 -or $errorCode -eq 3) { return [pscustomobject]@{ State = 'absent'; Handle = $null; Binding = [pscustomobject]@{ Parent = $parent; ParentPath = $parentPath; Leaf = $leaf; FullPath = $Path } } }
    throw "$Label could not be opened for retained recovery custody (Win32 error $errorCode)"
  }
  try {
    $read = Read-CrgHeldFileBytes -Handle $handle -Maximum $Maximum -Label $Label
    Assert-CrgHandleAtPath -Handle $handle -Path $Path -Label $Label
    return [pscustomobject]@{ State = 'held'; Handle = $handle; Binding = [pscustomobject]@{ Parent = $parent; ParentPath = $parentPath; Leaf = $leaf; FullPath = $Path }; Bytes = $read.Bytes; Snapshot = $read.Snapshot; Sha256 = $read.Sha256 }
  } catch { $handle.Dispose(); throw }
}

function Test-CrgOccupantMatchesRecorded {
  param([object]$Occupant, [object]$Recorded)
  return $Occupant.State -ceq 'held' -and $Occupant.Snapshot.VolumeId -ceq $Recorded.VolumeId -and
    $Occupant.Snapshot.FileId -ceq $Recorded.FileId -and $Occupant.Snapshot.LinkCount -eq 1 -and
    [uint64]$Occupant.Snapshot.Length -eq [uint64]$Recorded.Length -and $Occupant.Sha256 -ceq $Recorded.Sha256
}

function Move-CrgHeldNoReplace {
  param([object]$Handle, [object]$DestinationParent, [string]$DestinationLeaf, [string]$DestinationPath, [string]$Label)
  $errorCode = 0
  if (-not [CrgProjectValues.FileNativeV1]::RenameHeldNoReplace($Handle, $DestinationParent, $DestinationLeaf, [ref]$errorCode)) {
    throw "$Label no-replace retained rename failed (Win32 error $errorCode)"
  }
  Assert-CrgHandleAtPath -Handle $Handle -Path $DestinationPath -Label $Label
}

function Get-CrgRecoveryCopy {
  param([object]$Pins, [string]$Path, [byte[]]$ExpectedBytes, [object]$Expected, [string]$Label)
  $existing = Open-CrgRecoveryOccupant -Pins $Pins -Path $Path -Label $Label
  if ($existing.State -ceq 'held') {
    if ($existing.Snapshot.LinkCount -ne 1 -or [uint64]$existing.Snapshot.Length -ne [uint64]$Expected.Length -or
        $existing.Sha256 -cne $Expected.Sha256 -or -not (Compare-CrgInstallValueBytes -Left $existing.Bytes -Right $ExpectedBytes)) {
      $existing.Handle.Dispose()
      throw "$Label exists with foreign bytes or shape"
    }
    return $existing
  }
  return New-CrgHeldRecoveryCopy -Pins $Pins -Path $Path -Bytes $ExpectedBytes -Expected $Expected -Label $Label
}

function Invoke-CrgRendererRecovery {
  param([object]$Repo, [object]$Pins, [object]$State)
  $paths = Get-CrgRendererTransactionPaths -Repo $Repo -TransactionId $State.Record.TransactionId
  $held = New-Object 'System.Collections.Generic.List[object]'
  $copyChecks = New-Object 'System.Collections.Generic.List[object]'
  $dispositionStarted = $false
  try {
    for ($i = 0; $i -lt 2; $i++) {
      $recorded = $State.Record.Outputs[$i]
      $path = $paths.Outputs[$i]
      if ($recorded.Id -cne $path.Id) { throw 'renderer recovery record/output mapping is inconsistent' }
      $locations = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
      $locations['destination'] = $path.Destination
      $locations['stage'] = Join-Path $path.Parent $path.StageLeaf
      $locations['custody'] = Join-Path $path.Parent $path.CustodyLeaf
      $locations['backup'] = Join-Path $path.Parent $path.BackupLeaf
      $locations['archive'] = Join-Path $path.Parent $path.ArchiveLeaf
      $occupants = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
      foreach ($name in $locations.Keys) {
        $occupant = Open-CrgRecoveryOccupant -Pins $Pins -Path $locations[$name] -Label "$($path.Id) recovery $name"
        $occupants[$name] = $occupant
        if ($occupant.State -ceq 'held') { $held.Add($occupant.Handle) | Out-Null }
      }
      if ($recorded.Pre.VolumeId -ceq $recorded.Post.VolumeId -and $recorded.Pre.FileId -ceq $recorded.Post.FileId) {
        throw "$($path.Id) recovery record assigns one native identity to both the preimage and postimage"
      }
      $preLocations = @($occupants.Keys | Where-Object { Test-CrgOccupantMatchesRecorded -Occupant $occupants[$_] -Recorded $recorded.Pre })
      $postLocations = @($occupants.Keys | Where-Object { Test-CrgOccupantMatchesRecorded -Occupant $occupants[$_] -Recorded $recorded.Post })
      foreach ($name in $occupants.Keys) {
        if ($occupants[$name].State -ceq 'held' -and $name -cnotin $preLocations -and $name -cnotin $postLocations) { throw "$($path.Id) recovery path '$name' contains a foreign identity or bytes" }
      }
      if ($preLocations.Count -ne 1 -or $preLocations[0] -cnotin @('destination', 'custody', 'backup')) { throw "$($path.Id) recorded preimage is missing or appears at an invalid recovery location" }
      if ($postLocations.Count -ne 1 -or $postLocations[0] -cnotin @('destination', 'stage', 'archive')) { throw "$($path.Id) recorded postimage is missing or appears at an invalid recovery location" }
      $path | Add-Member -NotePropertyName RecoveryOccupants -NotePropertyValue $occupants -Force
      $path | Add-Member -NotePropertyName PreLocation -NotePropertyValue ([string]$preLocations[0]) -Force
      $path | Add-Member -NotePropertyName PostLocation -NotePropertyValue ([string]$postLocations[0]) -Force
    }

    # Remove every published postimage from the destination before restoring a
    # preimage. A retained identity moves only to its fixed stage and archive.
    for ($i = 1; $i -ge 0; $i--) {
      $recorded = $State.Record.Outputs[$i]
      $path = $paths.Outputs[$i]
      $occupants = $path.RecoveryOccupants
      $post = $occupants[$path.PostLocation]
      if ($path.PostLocation -ceq 'destination') {
        if (-not [string]::Equals($occupants['stage'].State, 'absent', [System.StringComparison]::Ordinal)) { throw "$($path.Id) stage is occupied while rollback needs the fixed stage" }
        Move-CrgHeldNoReplace -Handle $post.Handle -DestinationParent $post.Binding.Parent -DestinationLeaf $path.StageLeaf -DestinationPath (Join-Path $path.Parent $path.StageLeaf) -Label "$($path.Id) rollback-to-stage"
        $path.PostLocation = 'stage'
      }
      $copy = Get-CrgRecoveryCopy -Pins $Pins -Path $path.AbortedCopy -ExpectedBytes $post.Bytes -Expected $recorded.Post -Label "$($path.Id) aborted-postimage recovery copy"
      if ($null -ne $copy.Handle) { $held.Add($copy.Handle) | Out-Null }
      $copyChecks.Add([pscustomobject]@{ Copy = $copy; Expected = $recorded.Post; Bytes = $post.Bytes; Label = "$($path.Id) aborted-postimage recovery copy" }) | Out-Null
      if ($path.PostLocation -ceq 'stage') {
        if (-not [string]::Equals($occupants['archive'].State, 'absent', [System.StringComparison]::Ordinal)) { throw "$($path.Id) aborted archive is occupied" }
        $archiveBinding = Get-CrgParentAndLeaf -Pins $Pins -Path (Join-Path $path.Parent $path.ArchiveLeaf) -Label "$($path.Id) aborted archive"
        Move-CrgHeldNoReplace -Handle $post.Handle -DestinationParent $archiveBinding.Parent -DestinationLeaf $archiveBinding.Leaf -DestinationPath $archiveBinding.FullPath -Label "$($path.Id) aborted archive"
        $path.PostLocation = 'archive'
      }
      $null = Assert-CrgHeldSnapshotMatches -Handle $post.Handle -Expected $recorded.Post -Label "$($path.Id) archived postimage"
    }

    for ($i = 1; $i -ge 0; $i--) {
      $recorded = $State.Record.Outputs[$i]
      $path = $paths.Outputs[$i]
      $occupants = $path.RecoveryOccupants
      $pre = $occupants[$path.PreLocation]
      $copy = Get-CrgRecoveryCopy -Pins $Pins -Path $path.PreimageCopy -ExpectedBytes $pre.Bytes -Expected $recorded.Pre -Label "$($path.Id) preimage recovery copy"
      if ($null -ne $copy.Handle) { $held.Add($copy.Handle) | Out-Null }
      $copyChecks.Add([pscustomobject]@{ Copy = $copy; Expected = $recorded.Pre; Bytes = $pre.Bytes; Label = "$($path.Id) preimage recovery copy" }) | Out-Null
      if (-not [string]::Equals($path.PreLocation, 'destination', [System.StringComparison]::Ordinal)) {
        $destinationParent = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $path.Parent
        if (-not (Test-CrgRelativeNameAbsent -ParentHandle $destinationParent -Leaf $path.Leaf -Label "$($path.Id) rollback destination")) { throw "$($path.Id) rollback destination is occupied" }
        Move-CrgHeldNoReplace -Handle $pre.Handle -DestinationParent $destinationParent -DestinationLeaf $path.Leaf -DestinationPath $path.Destination -Label "$($path.Id) preimage restore"
        $path.PreLocation = 'destination'
      }
      $null = Assert-CrgHeldSnapshotMatches -Handle $pre.Handle -Expected $recorded.Pre -Label "$($path.Id) restored preimage"
      Assert-CrgHandleAtPath -Handle $pre.Handle -Path $path.Destination -Label "$($path.Id) restored destination"
    }

    foreach ($path in $paths.Outputs) {
      $parent = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $path.Parent
      foreach ($leaf in @($path.StageLeaf, $path.CustodyLeaf)) {
        if (-not (Test-CrgRelativeNameAbsent -ParentHandle $parent -Leaf $leaf -Label "$($path.Id) rollback temporary name")) { throw "$($path.Id) rollback left temporary or custody namespace '$leaf'" }
      }
      Flush-CrgDirectoryExact -Handle $parent -Label "$($path.Id) rollback parent"
    }
    if (-not (Test-CrgRelativeNameAbsent -ParentHandle (Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $Repo.GitDir) -Leaf $paths.StateStageLeaf -Label 'renderer state creation stage')) {
      throw 'renderer recovery found an unexpected state-creation stage'
    }
    foreach ($check in $copyChecks) {
      $read = Read-CrgHeldFileBytes -Handle $check.Copy.Handle -Maximum 1048576 -Label $check.Label
      if ($read.Snapshot.LinkCount -ne 1 -or [uint64]$read.Snapshot.Length -ne [uint64]$check.Expected.Length -or
          $read.Sha256 -cne $check.Expected.Sha256 -or -not (Compare-CrgInstallValueBytes -Left $read.Bytes -Right $check.Bytes)) {
        throw "$($check.Label) changed before renderer-state terminalization"
      }
      Flush-CrgDirectoryExact -Handle $check.Copy.Binding.Parent -Label "$($check.Label) parent"
    }
    $statePath = Join-Path $Repo.GitDir $script:CrgRendererStateLeaf
    Remove-CrgHeldRendererStateExact -State $State -GitDirHandle (Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $Repo.GitDir) -StatePath $statePath -DispositionStarted ([ref]$dispositionStarted)
    return [pscustomobject]@{ State = 'recovery-aborted'; TransactionId = $State.Record.TransactionId }
  } finally {
    foreach ($handle in $held) { if ($null -ne $handle) { try { $handle.Dispose() } catch { } } }
    if ($null -ne $State.Handle) { try { $State.Handle.Dispose() } catch { } }
  }
}

function Assert-CrgRendererInputEpoch {
  param(
    [object]$Repo,
    [object]$ExpectedAuthority,
    [object]$ExpectedSourceEvidence,
    [object]$SourceHold,
    [object]$ExpectedIndexAttributes,
    [object]$ExpectedWorkingAttributes
  )
  $sourceRead = Read-CrgHeldFileBytes -Handle $SourceHold.Handle -Maximum 262144 -Label 'retained values source'
  if ($sourceRead.Snapshot.VolumeId -cne $SourceHold.Snapshot.VolumeId -or $sourceRead.Snapshot.FileId -cne $SourceHold.Snapshot.FileId -or
      $sourceRead.Sha256 -cne $SourceHold.Sha256 -or -not (Compare-CrgInstallValueBytes -Left $sourceRead.Bytes -Right $SourceHold.Bytes)) {
    throw 'retained values source changed during the render transaction'
  }
  Assert-CrgHandleAtPath -Handle $SourceHold.Handle -Path (Join-Path $Repo.Root 'CROSS-REVIEW-VALUES.md') -Label 'retained values source'
  $current = Get-CrgRenderAuthority -Repo $Repo
  if ($current.Family -cne $ExpectedAuthority.Family -or $current.Head.State -cne $ExpectedAuthority.Head.State -or $current.Head.Oid -cne $ExpectedAuthority.Head.Oid) {
    throw 'render authority family or HEAD identity changed during rendering'
  }
  for ($i = 0; $i -lt $ExpectedAuthority.Outputs.Count; $i++) {
    Assert-CrgAuthorityEvidenceEqual -Expected $ExpectedAuthority.Outputs[$i] -Actual $current.Outputs[$i] -Label $ExpectedAuthority.Outputs[$i].Path
  }
  $sourceEvidence = Assert-CrgValuesAuthority -Repo $Repo -RenderAuthority $current -SourceHold $SourceHold
  Assert-CrgAuthorityEvidenceEqual -Expected $ExpectedSourceEvidence -Actual $sourceEvidence -Label 'CROSS-REVIEW-VALUES.md'
  if ($ExpectedAuthority.Family -ceq 'TRACKED') {
    $indexAttributes = Get-CrgAttributeGraph -Repo $Repo -Cached
    $workingAttributes = Get-CrgAttributeGraph -Repo $Repo
    Assert-CrgAttributeGraphsEqual -IndexGraph $indexAttributes -WorkingGraph $workingAttributes
    Assert-CrgAttributeGraphsEqual -IndexGraph $ExpectedIndexAttributes -WorkingGraph $indexAttributes
    Assert-CrgAttributeGraphsEqual -IndexGraph $ExpectedWorkingAttributes -WorkingGraph $workingAttributes
  }
}

function Assert-CrgTrackedOutputBlobGrammar {
  param([object]$Repo, [object]$Authority)
  for ($i = 0; $i -lt $Authority.Outputs.Count; $i++) {
    $evidence = $Authority.Outputs[$i]
    if ($evidence.Class -cne 'TRACKED-existing') { continue }
    [byte[]]$blob = Read-CrgGitBlobBytes -Repo $Repo -Oid $evidence.IndexOid -Maximum 1048576 -Label $evidence.Path
    $target = $script:CrgRendererOutputs[$i].Id
    $null = Get-CrgRenderSlotLayout -Bytes $blob -Target $target -FinalOutput
  }
}

function New-CrgRendererTransactionId {
  $bytes = New-Object byte[] 16
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return (([System.BitConverter]::ToString($bytes)) -replace '-', '').ToLowerInvariant()
}

function Assert-CrgNoRendererOrphans {
  param([object]$Repo)
  $patterns = @(
    [pscustomobject]@{ Directory = $Repo.GitDir; Prefix = "$script:CrgRendererStateLeaf.new-"; Label = 'renderer state-creation stage' }
  )
  foreach ($spec in $script:CrgRendererOutputs) {
    $directory = Join-Path $Repo.Root ($spec.ParentRelative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $patterns += [pscustomobject]@{ Directory = $directory; Prefix = "$($spec.Leaf).crg-render-stage-"; Label = "$($spec.Id) output stage" }
    $patterns += [pscustomobject]@{ Directory = $directory; Prefix = "$($spec.Leaf).crg-render-custody-"; Label = "$($spec.Id) custody" }
  }
  foreach ($pattern in $patterns) {
    try { $entries = @([System.IO.Directory]::EnumerateFileSystemEntries($pattern.Directory, "$($pattern.Prefix)*", [System.IO.SearchOption]::TopDirectoryOnly)) }
    catch { throw "$($pattern.Label) namespace could not be enumerated: $($_.Exception.Message)" }
    if ($entries.Count -gt 0) { throw "$($pattern.Label) orphan is preserved at '$($entries[0])'" }
  }
}

function Assert-CrgNewTransactionNamesAbsent {
  param([object]$Repo, [object]$Pins, [object]$Paths)
  $gitDirHandle = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $Repo.GitDir
  Assert-CrgRelativeLeafAbsent -ParentHandle $gitDirHandle -Leaf $Paths.StateLeaf -Label 'renderer transaction state'
  if (-not (Test-CrgRelativeNameAbsent -ParentHandle $gitDirHandle -Leaf $Paths.StateStageLeaf -Label 'renderer state-creation stage')) { throw 'renderer state-creation stage already exists' }
  $backupBase = Find-CrgPinnedExistingDirectory -Pins $Pins -Path $Paths.BackupBase -Label 'renderer backup area'
  if ($null -ne $backupBase) {
    if (-not (Test-CrgRelativeNameAbsent -ParentHandle $backupBase -Leaf (Split-Path -Leaf $Paths.RecoveryRoot) -Label 'renderer recovery-copy root')) {
      throw "renderer recovery-copy root '$($Paths.RecoveryRoot)' already exists"
    }
  }
  foreach ($path in $Paths.Outputs) {
    $parent = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $path.Parent
    foreach ($entry in @(
      [pscustomobject]@{ Leaf = $path.StageLeaf; Label = "$($path.Id) output stage" },
      [pscustomobject]@{ Leaf = $path.CustodyLeaf; Label = "$($path.Id) custody" },
      [pscustomobject]@{ Leaf = $path.BackupLeaf; Label = "$($path.Id) permanent backup" },
      [pscustomobject]@{ Leaf = $path.ArchiveLeaf; Label = "$($path.Id) aborted archive" }
    )) {
      if (-not (Test-CrgRelativeNameAbsent -ParentHandle $parent -Leaf $entry.Leaf -Label $entry.Label)) { throw "$($entry.Label) already exists" }
    }
    Flush-CrgDirectoryExact -Handle $parent -Label "$($path.Id) publication capability probe"
  }
  Flush-CrgDirectoryExact -Handle $gitDirHandle -Label 'renderer state publication capability probe'
  if ($null -ne $backupBase) { Flush-CrgDirectoryExact -Handle $backupBase -Label 'renderer backup publication capability probe' }
  else { Flush-CrgDirectoryExact -Handle (Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $Repo.CommonDir) -Label 'renderer backup-parent capability probe' }
}

function Invoke-CrgTrackedRendererPublication {
  param(
    [object]$Repo,
    [object]$Pins,
    [object]$Authority,
    [object]$SourceEvidence,
    [object]$SourceHold,
    [object[]]$DestinationHolds,
    [byte[][]]$RenderedBytes,
    [object]$IndexAttributes,
    [object]$WorkingAttributes
  )
  $transactionId = New-CrgRendererTransactionId
  $paths = Get-CrgRendererTransactionPaths -Repo $Repo -TransactionId $transactionId
  Assert-CrgNoRendererOrphans -Repo $Repo
  Assert-CrgNewTransactionNamesAbsent -Repo $Repo -Pins $Pins -Paths $paths
  Assert-CrgRendererInputEpoch -Repo $Repo -ExpectedAuthority $Authority -ExpectedSourceEvidence $SourceEvidence -SourceHold $SourceHold -ExpectedIndexAttributes $IndexAttributes -ExpectedWorkingAttributes $WorkingAttributes
  for ($i = 0; $i -lt 2; $i++) {
    $null = Assert-CrgHeldSnapshotMatches -Handle $DestinationHolds[$i].Handle -Expected (ConvertTo-CrgRecordedSnapshot -Snapshot $DestinationHolds[$i].Snapshot -Sha256 $DestinationHolds[$i].Sha256) -Label "$($paths.Outputs[$i].Id) final pre-mutation template"
    Assert-CrgHandleAtPath -Handle $DestinationHolds[$i].Handle -Path $paths.Outputs[$i].Destination -Label "$($paths.Outputs[$i].Id) final pre-mutation template"
  }

  $gitDirHandle = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $Repo.GitDir
  $state = $null
  $stateStageHandle = $null
  $stages = New-Object 'System.Collections.Generic.List[object]'
  $copies = New-Object 'System.Collections.Generic.List[object]'
  $statePublished = $false
  $dispositionStarted = $false
  $success = $false
  try {
    # The empty share-none state stage is intentionally the first filesystem
    # mutation. Pre-record failures preserve inert stages for inspection.
    $stateStageHandle = New-CrgHeldExactFile -Parent $gitDirHandle -Leaf $paths.StateStageLeaf -Bytes $null -Label 'renderer state-creation stage' -State
    $stateStageSnapshot = Get-CrgOrdinaryFileSnapshot -Handle $stateStageHandle -Label 'renderer state-creation stage'
    if ($stateStageSnapshot.Length -ne 0) { throw 'renderer state-creation stage was not created empty' }

    for ($i = 0; $i -lt 2; $i++) {
      $path = $paths.Outputs[$i]
      $parent = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $path.Parent
      $handle = New-CrgHeldExactFile -Parent $parent -Leaf $path.StageLeaf -Bytes $RenderedBytes[$i] -Label "$($path.Id) output stage"
      $read = Read-CrgHeldFileBytes -Handle $handle -Maximum 1048576 -Label "$($path.Id) output stage"
      $stages.Add([pscustomobject]@{ Handle = $handle; Read = $read; Path = $path; Published = $false }) | Out-Null
    }

    $recordOutputs = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt 2; $i++) {
      $recordOutputs.Add([pscustomobject]@{
        Id = $paths.Outputs[$i].Id
        Pre = ConvertTo-CrgRecordedSnapshot -Snapshot $DestinationHolds[$i].Snapshot -Sha256 $DestinationHolds[$i].Sha256
        Post = ConvertTo-CrgRecordedSnapshot -Snapshot $stages[$i].Read.Snapshot -Sha256 $stages[$i].Read.Sha256
      }) | Out-Null
    }
    [byte[]]$stateBytes = New-CrgRendererStateBytes -TransactionId $transactionId -ValuesSha256 $SourceHold.Sha256 -Outputs $recordOutputs.ToArray()
    [CrgProjectValues.FileNativeV1]::WriteAllAndFlush($stateStageHandle, $stateBytes)
    $stateRead = Read-CrgHeldFileBytes -Handle $stateStageHandle -Maximum 4096 -Label 'renderer PREPARED state stage'
    if (-not (Compare-CrgInstallValueBytes -Left $stateRead.Bytes -Right $stateBytes)) { throw 'renderer PREPARED state failed exact write verification' }
    $record = Read-CrgRendererStateBytes -Bytes $stateRead.Bytes
    Move-CrgHeldNoReplace -Handle $stateStageHandle -DestinationParent $gitDirHandle -DestinationLeaf $paths.StateLeaf -DestinationPath $paths.State -Label 'renderer PREPARED state publication'
    $state = [pscustomobject]@{ State = 'prepared'; Handle = $stateStageHandle; Record = $record; Bytes = $stateBytes }
    $stateStageHandle = $null
    $statePublished = $true
    Flush-CrgDirectoryExact -Handle $gitDirHandle -Label 'renderer PREPARED state parent'

    Assert-CrgRendererInputEpoch -Repo $Repo -ExpectedAuthority $Authority -ExpectedSourceEvidence $SourceEvidence -SourceHold $SourceHold -ExpectedIndexAttributes $IndexAttributes -ExpectedWorkingAttributes $WorkingAttributes
    for ($i = 0; $i -lt 2; $i++) {
      $null = Assert-CrgHeldSnapshotMatches -Handle $DestinationHolds[$i].Handle -Expected $record.Outputs[$i].Pre -Label "$($paths.Outputs[$i].Id) preimage before custody"
      $null = Assert-CrgHeldSnapshotMatches -Handle $stages[$i].Handle -Expected $record.Outputs[$i].Post -Label "$($paths.Outputs[$i].Id) postimage before publication"
    }

    for ($i = 0; $i -lt 2; $i++) {
      $path = $paths.Outputs[$i]
      $parent = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $path.Parent
      Move-CrgHeldNoReplace -Handle $DestinationHolds[$i].Handle -DestinationParent $parent -DestinationLeaf $path.CustodyLeaf -DestinationPath (Join-Path $path.Parent $path.CustodyLeaf) -Label "$($path.Id) preimage custody"
      $null = Assert-CrgHeldSnapshotMatches -Handle $DestinationHolds[$i].Handle -Expected $record.Outputs[$i].Pre -Label "$($path.Id) custodied preimage"
      $copy = New-CrgHeldRecoveryCopy -Pins $Pins -Path $path.PreimageCopy -Bytes $DestinationHolds[$i].Bytes -Expected $record.Outputs[$i].Pre -Label "$($path.Id) preimage recovery copy"
      $copies.Add($copy) | Out-Null
      Move-CrgHeldNoReplace -Handle $stages[$i].Handle -DestinationParent $parent -DestinationLeaf $path.Leaf -DestinationPath $path.Destination -Label "$($path.Id) postimage publication"
      $stages[$i].Published = $true
      $null = Assert-CrgHeldSnapshotMatches -Handle $stages[$i].Handle -Expected $record.Outputs[$i].Post -Label "$($path.Id) published postimage"
      Flush-CrgDirectoryExact -Handle $parent -Label "$($path.Id) publication parent"
    }

    Assert-CrgRendererInputEpoch -Repo $Repo -ExpectedAuthority $Authority -ExpectedSourceEvidence $SourceEvidence -SourceHold $SourceHold -ExpectedIndexAttributes $IndexAttributes -ExpectedWorkingAttributes $WorkingAttributes
    for ($i = 0; $i -lt 2; $i++) {
      $path = $paths.Outputs[$i]
      $parent = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $path.Parent
      $copyRead = Read-CrgHeldFileBytes -Handle $copies[$i].Handle -Maximum 1048576 -Label "$($path.Id) durable preimage recovery copy"
      if ([uint64]$copyRead.Snapshot.Length -ne [uint64]$record.Outputs[$i].Pre.Length -or
          $copyRead.Sha256 -cne $record.Outputs[$i].Pre.Sha256 -or
          -not (Compare-CrgInstallValueBytes -Left $copyRead.Bytes -Right $DestinationHolds[$i].Bytes)) {
        throw "$($path.Id) durable preimage recovery copy changed before terminalization"
      }
      Move-CrgHeldNoReplace -Handle $DestinationHolds[$i].Handle -DestinationParent $parent -DestinationLeaf $path.BackupLeaf -DestinationPath (Join-Path $path.Parent $path.BackupLeaf) -Label "$($path.Id) permanent preimage backup"
      $null = Assert-CrgHeldSnapshotMatches -Handle $DestinationHolds[$i].Handle -Expected $record.Outputs[$i].Pre -Label "$($path.Id) permanent preimage backup"
      Flush-CrgDirectoryExact -Handle $parent -Label "$($path.Id) backup parent"
    }

    Assert-CrgTrackedAttributeBehavior -Repo $Repo
    for ($i = 0; $i -lt 2; $i++) {
      $path = $paths.Outputs[$i]
      $parent = Get-CrgPinnedDirectoryHandle -Pins $Pins -Path $path.Parent
      foreach ($leaf in @($path.StageLeaf, $path.CustodyLeaf)) {
        if (-not (Test-CrgRelativeNameAbsent -ParentHandle $parent -Leaf $leaf -Label "$($path.Id) terminal namespace")) { throw "$($path.Id) terminal namespace '$leaf' remains occupied" }
      }
      $null = Assert-CrgHeldSnapshotMatches -Handle $stages[$i].Handle -Expected $record.Outputs[$i].Post -Label "$($path.Id) final postimage"
      Assert-CrgHandleAtPath -Handle $stages[$i].Handle -Path $path.Destination -Label "$($path.Id) final destination"
      $null = Assert-CrgHeldSnapshotMatches -Handle $DestinationHolds[$i].Handle -Expected $record.Outputs[$i].Pre -Label "$($path.Id) final permanent backup"
      Assert-CrgHandleAtPath -Handle $DestinationHolds[$i].Handle -Path (Join-Path $path.Parent $path.BackupLeaf) -Label "$($path.Id) final permanent backup"
    }
    if (-not (Test-CrgRelativeNameAbsent -ParentHandle $gitDirHandle -Leaf $paths.StateStageLeaf -Label 'terminal renderer state stage')) { throw 'terminal renderer state stage remains occupied' }
    $finalStateRead = Read-CrgHeldFileBytes -Handle $state.Handle -Maximum 4096 -Label 'final renderer PREPARED state'
    if (-not (Compare-CrgInstallValueBytes -Left $finalStateRead.Bytes -Right $stateBytes)) { throw 'renderer PREPARED state changed before commit' }
    Assert-CrgRendererInputEpoch -Repo $Repo -ExpectedAuthority $Authority -ExpectedSourceEvidence $SourceEvidence -SourceHold $SourceHold -ExpectedIndexAttributes $IndexAttributes -ExpectedWorkingAttributes $WorkingAttributes
    foreach ($copy in $copies) { Flush-CrgDirectoryExact -Handle $copy.Binding.Parent -Label 'renderer recovery-copy parent' }
    Remove-CrgHeldRendererStateExact -State $state -GitDirHandle $gitDirHandle -StatePath $paths.State -DispositionStarted ([ref]$dispositionStarted)
    $success = $true
    return [pscustomobject]@{ State = 'published'; TransactionId = $transactionId }
  } catch {
    $failure = $_.Exception.Message
    if ($statePublished -and -not $dispositionStarted) {
      foreach ($copy in $copies) { if ($null -ne $copy.Handle) { try { $copy.Handle.Dispose() } catch { }; $copy.Handle = $null } }
      foreach ($stage in $stages) { if ($null -ne $stage.Handle) { try { $stage.Handle.Dispose() } catch { }; $stage.Handle = $null } }
      foreach ($destination in $DestinationHolds) { if ($null -ne $destination.Handle) { try { $destination.Handle.Dispose() } catch { }; $destination.Handle = $null } }
      try {
        $rollback = Invoke-CrgRendererRecovery -Repo $Repo -Pins $Pins -State $state
        $state = $null
        throw "recovery-aborted: transaction $transactionId rolled back after '$failure'"
      } catch {
        if ($_.Exception.Message.StartsWith('recovery-aborted:', [System.StringComparison]::Ordinal)) { throw }
        throw "$failure; renderer rollback failed and PREPARED evidence is preserved: $($_.Exception.Message)"
      }
    }
    throw
  } finally {
    if (-not $success) {
      if ($null -ne $stateStageHandle) { try { $stateStageHandle.Dispose() } catch { } }
      if ($null -ne $state -and $null -ne $state.Handle) { try { $state.Handle.Dispose() } catch { } }
    }
    foreach ($copy in $copies) { if ($null -ne $copy.Handle) { try { $copy.Handle.Dispose() } catch { } } }
    foreach ($stage in $stages) { if ($null -ne $stage.Handle) { try { $stage.Handle.Dispose() } catch { } } }
  }
}

function Invoke-CrgRendererMain {
  Assert-CrgDirectGitEnvironmentBoundary

  $gitCommand = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
  if ($null -eq $gitCommand -or [string]::IsNullOrWhiteSpace($gitCommand.Source)) { throw 'Git executable could not be resolved after environment validation' }
  $script:CrgRendererGitExe = [string]$gitCommand.Source
  $repo = Resolve-CrgRendererRepository -SuppliedPath $TargetRepo
  Initialize-CrgRendererFileNative

  $pins = $null
  $lockHandle = $null
  $sourceHold = $null
  $destinationHolds = New-Object 'System.Collections.Generic.List[object]'
  try {
    # Retain the Git and target-root chains independently because a linked
    # worktree can place them on different volumes. This opens directory
    # namespace authority only; render destinations and the values source stay
    # unopened until state absence or the recovery arm has been selected.
    $pins = Enter-CrgRendererDirectoryPins -MutationDirectories @($repo.GitDir, $repo.CommonDir, $repo.Root)
    Assert-CrgRepositoryResolutionStable -Expected $repo
    $gitDirHandle = Get-CrgPinnedDirectoryHandle -Pins $pins -Path $repo.GitDir
    $lockError = 0
    $lockHandle = [CrgProjectValues.FileNativeV1]::OpenExistingLockRelative($gitDirHandle, 'crg-install-lock', [ref]$lockError)
    if ($null -eq $lockHandle -or $lockHandle.IsInvalid) {
      if ($null -ne $lockHandle) { $lockHandle.Dispose(); $lockHandle = $null }
      $direction = if ($lockError -eq 2 -or $lockError -eq 3) { '; run full bootstrap.ps1 -TargetRepo <root> first' } else { '' }
      throw "per-worktree install lock could not be acquired without sharing (Win32 error $lockError)$direction"
    }
    $lockSnapshot = Get-CrgOrdinaryFileSnapshot -Handle $lockHandle -Label 'per-worktree install lock'
    Assert-CrgHandleAtPath -Handle $lockHandle -Path (Join-Path $repo.GitDir 'crg-install-lock') -Label 'per-worktree install lock'

    $statePath = Join-Path $repo.GitDir $script:CrgRendererStateLeaf
    $state = Open-CrgRendererState -GitDirHandle $gitDirHandle -StatePath $statePath
    if ($state.State -ceq 'prepared') {
      if ($Check) { $state.Handle.Dispose(); $state.Handle = $null; throw 'renderer PREPARED state requires standalone Apply recovery before -Check can run' }
      foreach ($spec in $script:CrgRendererOutputs) {
        $null = Ensure-CrgPinnedDirectory -Pins $pins -Path (Join-Path $repo.Root ($spec.ParentRelative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))) -Label "$($spec.Id) parent"
      }
      $null = Ensure-CrgPinnedDirectory -Pins $pins -Path $repo.CommonDir -Label 'Git common directory'
      $result = Invoke-CrgRendererRecovery -Repo $repo -Pins $pins -State $state
      [Console]::Error.WriteLine("render-project-values: recovery-aborted: transaction $($result.TransactionId) restored the exact pre-run outputs; rerun Apply for a new render")
      return 2
    }

    $rootHandle = Ensure-CrgPinnedDirectory -Pins $pins -Path $repo.Root -Label 'target repository root'
    foreach ($spec in $script:CrgRendererOutputs) {
      try {
        $null = Ensure-CrgPinnedDirectory -Pins $pins -Path (Join-Path $repo.Root ($spec.ParentRelative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))) -Label "$($spec.Id) parent"
      } catch {
        throw "$($spec.Relative) must already have an ordinary parent directory; run full bootstrap.ps1 -TargetRepo <root> installation. Details: $($_.Exception.Message)"
      }
    }
    $null = Ensure-CrgPinnedDirectory -Pins $pins -Path $repo.CommonDir -Label 'Git common directory'
    $null = Ensure-CrgPinnedDirectory -Pins $pins -Path $repo.ObjectDir -Label 'Git object directory'
    Assert-CrgRepositoryResolutionStable -Expected $repo

    $sourceHold = Open-CrgRendererInputHold -ParentHandle $rootHandle -Leaf 'CROSS-REVIEW-VALUES.md' -Label 'CROSS-REVIEW-VALUES.md' -Maximum 262144
    Assert-CrgHandleAtPath -Handle $sourceHold.Handle -Path (Join-Path $repo.Root 'CROSS-REVIEW-VALUES.md') -Label 'CROSS-REVIEW-VALUES.md'
    for ($i = 0; $i -lt $script:CrgRendererOutputs.Count; $i++) {
      $spec = $script:CrgRendererOutputs[$i]
      $parentPath = Join-Path $repo.Root ($spec.ParentRelative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
      $parentHandle = Get-CrgPinnedDirectoryHandle -Pins $pins -Path $parentPath
      $destinationHolds.Add((Open-CrgRendererDestinationHold -ParentHandle $parentHandle -Leaf $spec.Leaf -Label $spec.Relative)) | Out-Null
      Assert-CrgHandleAtPath -Handle $destinationHolds[$i].Handle -Path (Join-Path $repo.Root ($spec.Relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))) -Label $spec.Relative
    }

    $values = Read-CrgInstallValuesBytes -Bytes $sourceHold.Bytes
    $authority = Get-CrgRenderAuthority -Repo $repo
    $sourceEvidence = Assert-CrgValuesAuthority -Repo $repo -RenderAuthority $authority -SourceHold $sourceHold
    Assert-CrgTrackedOutputBlobGrammar -Repo $repo -Authority $authority
    $indexAttributes = $null
    $workingAttributes = $null
    if ($authority.Family -ceq 'TRACKED') {
      $indexAttributes = Get-CrgAttributeGraph -Repo $repo -Cached
      $workingAttributes = Get-CrgAttributeGraph -Repo $repo
      Assert-CrgAttributeGraphsEqual -IndexGraph $indexAttributes -WorkingGraph $workingAttributes
      Assert-CrgTrackedAttributeBehavior -Repo $repo
    }

    [byte[][]]$rendered = New-Object 'byte[][]' 2
    for ($i = 0; $i -lt 2; $i++) {
      $rendered[$i] = Invoke-CrgInstallValueRender -Values $values -TemplateBytes $destinationHolds[$i].Bytes -Target $script:CrgRendererOutputs[$i].Id
    }
    Assert-CrgRendererInputEpoch -Repo $repo -ExpectedAuthority $authority -ExpectedSourceEvidence $sourceEvidence -SourceHold $sourceHold -ExpectedIndexAttributes $indexAttributes -ExpectedWorkingAttributes $workingAttributes

    $allMatch = $true
    for ($i = 0; $i -lt 2; $i++) { if (-not (Compare-CrgInstallValueBytes -Left $destinationHolds[$i].Bytes -Right $rendered[$i])) { $allMatch = $false } }
    if ($Check) {
      if (-not $allMatch) { throw 'one or more installed render-slot bodies differ from CROSS-REVIEW-VALUES.md' }
      Write-Host "render-project-values: CHECK passed for '$($repo.Root)' ($($authority.Family))"
      return 0
    }
    if ($authority.Family -ceq 'LOCAL') { throw 'standalone Apply cannot mutate a LOCAL install; run package bootstrap.ps1 -TargetRepo <root> -Force' }
    if ($allMatch) { Write-Host "render-project-values: already current for '$($repo.Root)'"; return 0 }

    $publication = Invoke-CrgTrackedRendererPublication -Repo $repo -Pins $pins -Authority $authority -SourceEvidence $sourceEvidence -SourceHold $sourceHold -DestinationHolds $destinationHolds.ToArray() -RenderedBytes $rendered -IndexAttributes $indexAttributes -WorkingAttributes $workingAttributes
    Write-Host "render-project-values: published transaction $($publication.TransactionId) for '$($repo.Root)'"
    return 0
  } finally {
    if ($null -ne $sourceHold -and $null -ne $sourceHold.Handle) { try { $sourceHold.Handle.Dispose() } catch { } }
    foreach ($destination in $destinationHolds) { if ($null -ne $destination.Handle) { try { $destination.Handle.Dispose() } catch { } } }
    if ($null -ne $lockHandle) { try { $lockHandle.Dispose() } catch { } }
    Close-CrgRendererDirectoryPins -Pins $pins
  }
}

try {
  $exitCode = Invoke-CrgRendererMain
  exit $exitCode
} catch {
  [Console]::Error.WriteLine("render-project-values: ERROR: $($_.Exception.Message)")
  if ($_.Exception.Message.StartsWith('recovery-aborted:', [System.StringComparison]::Ordinal)) { exit 2 }
  exit 1
}
