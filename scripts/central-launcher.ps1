# Stable launcher ABI 2. Supports retained ABI 1/2 releases and config schema 1.
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
  [Parameter(Mandatory = $true)][string]$TargetRepo,
  [Parameter(Mandatory = $true, ParameterSetName = 'Status')][switch]$Status,
  [Parameter(Mandatory = $true, ParameterSetName = 'Open')][switch]$Open,
  [Parameter(Mandatory = $true, ParameterSetName = 'StageAll')]
  [Parameter(Mandatory = $true, ParameterSetName = 'StagePaths')][switch]$Stage,
  [Parameter(Mandatory = $true, ParameterSetName = 'StageAll')][switch]$All,
  [Parameter(Mandatory = $true, ParameterSetName = 'StagePaths')][string[]]$Paths,
  [Parameter(Mandatory = $true, ParameterSetName = 'Commit')][switch]$Commit,
  [Parameter(Mandatory = $true, ParameterSetName = 'Attach')][switch]$Attach,
  [Parameter(ParameterSetName = 'Attach')][string]$PrivateGitDir,
  [Parameter(Mandatory = $true, ParameterSetName = 'Commit')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Attach')][string]$MessageFile,
  [Parameter(Mandatory = $true, ParameterSetName = 'Commit')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Attach')][ValidateSet('codex', 'claude')][string]$AuthoringAgent,
  [Parameter(Mandatory = $true, ParameterSetName = 'Resume')][switch]$Resume,
  [Parameter(Mandatory = $true, ParameterSetName = 'PushCheck')][switch]$PushCheck,
  [Parameter(Mandatory = $true, ParameterSetName = 'PushCheck')][string]$PushRemoteName,
  [Parameter(Mandatory = $true, ParameterSetName = 'PushCheck')][string]$PushRemoteLocation
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($TargetRepo) -or $TargetRepo.Length -gt 32767 -or $TargetRepo -match '[\x00-\x1f\x7f]') { throw 'TargetRepo is invalid' }
$script:CrgLaunchOperation = if ($Stage) { 'Stage' } else { $PSCmdlet.ParameterSetName }
$operation = [pscustomobject]@{
  Name = $script:CrgLaunchOperation; All = [bool]$All
  Paths = [string[]]@($Paths | Where-Object { $null -ne $_ })
  MessageFile = $MessageFile; AuthoringAgent = ([string]$AuthoringAgent).ToLowerInvariant()
  PrivateGitDir = $PrivateGitDir; PushInput = $null
  PushRemoteName = $PushRemoteName; PushRemoteLocation = $PushRemoteLocation
}
if ($PSCmdlet.ParameterSetName -ceq 'StagePaths') {
  if ($Paths.Count -eq 0 -or $Paths.Count -gt 4096) { throw 'Stage requires a bounded nonempty path list or All' }
  foreach ($path in $Paths) { if ([string]::IsNullOrWhiteSpace($path) -or $path.Length -gt 32767 -or $path -match '[\x00-\x1f\x7f]') { throw 'Stage path is invalid' } }
}
if (($Commit -or $Attach) -and ([string]::IsNullOrWhiteSpace($MessageFile) -or $MessageFile.Length -gt 32767 -or $MessageFile -match '[\x00-\x1f\x7f]')) { throw 'Commit and Attach require a valid message-file path' }
if ($Attach -and $PSBoundParameters.ContainsKey('PrivateGitDir') -and
    ([string]::IsNullOrWhiteSpace($PrivateGitDir) -or $PrivateGitDir.Length -gt 32767 -or $PrivateGitDir -match '[\x00-\x1f\x7f]')) { throw 'Attach private database path is invalid' }
if ($PushCheck) {
  foreach ($value in @($PushRemoteName, $PushRemoteLocation)) {
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 32767 -or $value -match '[\x00-\x1f\x7f]') { throw 'pre-push requires bounded original remote arguments' }
  }
  $inputStream = [Console]::OpenStandardInput(); $inputBytes = New-Object IO.MemoryStream
  try {
    $buffer = New-Object byte[] 8192
    while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      if ($inputBytes.Length + $count -gt 1048576) { throw 'pre-push input exceeds the bounded reference list' }
      $inputBytes.Write($buffer, 0, $count)
    }
    $operation.PushInput = $inputBytes.ToArray()
  } finally { $inputBytes.Dispose(); $inputStream.Dispose() }
}
if ([IO.Path]::GetFileName($PSCommandPath) -cne 'launcher.ps1') { throw 'Invoke the operator-installed <runtime-store>/launcher.ps1, not a source checkout.' }

# Read-only subset of bootstrap's handle-relative boundary: no mutation,
# rename, disposition, or general rooted-I/O registry.
if (-not ('CrgCentralLaunch.ReadLeaseV1' -as [type])) {
  Add-Type -Namespace 'CrgCentralLaunch' -Name 'ReadLeaseV1' -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
struct UNICODE_STRING { public ushort Length, MaximumLength; public System.IntPtr Buffer; }
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
struct OBJECT_ATTRIBUTES { public int Length; public System.IntPtr RootDirectory, ObjectName; public uint Attributes; public System.IntPtr SecurityDescriptor, SecurityQualityOfService; }
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
struct IO_STATUS_BLOCK { public System.IntPtr Status, Information; }
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
struct FILE_INFO {
    public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
    public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
}
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, System.IntPtr security, uint disposition, uint flags, System.IntPtr template);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out FILE_INFO info);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
static extern bool CloseHandle(System.IntPtr handle);
[System.Runtime.InteropServices.DllImport("ntdll.dll")]
static extern int NtCreateFile(out System.IntPtr handle, uint access, ref OBJECT_ATTRIBUTES attributes, out IO_STATUS_BLOCK status, System.IntPtr size, uint fileAttributes, uint share, uint disposition, uint options, System.IntPtr ea, uint eaLength);
[System.Runtime.InteropServices.DllImport("ntdll.dll")]
static extern uint RtlNtStatusToDosError(int status);

static Microsoft.Win32.SafeHandles.SafeFileHandle Check(Microsoft.Win32.SafeHandles.SafeFileHandle handle, bool directory) {
    FILE_INFO info;
    if (handle == null || handle.IsInvalid) {
        int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
        if (handle != null) { handle.Dispose(); }
        throw new System.ComponentModel.Win32Exception(error, "central read lease open failed");
    }
    if (!GetFileInformationByHandle(handle, out info) || (info.Attributes & 0x400u) != 0 ||
        ((info.Attributes & 0x10u) != 0) != directory || (!directory && info.Links != 1u)) {
        handle.Dispose(); throw new System.IO.IOException("central lease requires an ordinary directory or single-link file");
    }
    return handle;
}
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenDrive(string path) {
    if (path == null || path.Length != 3 || !System.Char.IsLetter(path[0]) || path[1] != ':' || path[2] != '\\') { throw new System.ArgumentException("an absolute local drive root is required"); }
    return Check(CreateFileW(path, 0xA1u, 0x3u, System.IntPtr.Zero, 3u, 0x02200080u, System.IntPtr.Zero), true);
}
public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenChild(Microsoft.Win32.SafeHandles.SafeFileHandle parent, string leaf, bool directory, bool protectDirectory, bool lockFile) {
    if (parent == null || parent.IsInvalid || System.String.IsNullOrWhiteSpace(leaf) || leaf == "." || leaf == ".." ||
        leaf.IndexOfAny(new char[] {'\\','/',':','\0','*','?','"','<','>','|'}) >= 0 || leaf.EndsWith(".") || leaf.EndsWith(" ") ||
        (lockFile && (directory || leaf != "runtime.lock"))) { throw new System.ArgumentException("invalid central read-lease child"); }
    FILE_INFO parentInfo;
    if (!GetFileInformationByHandle(parent, out parentInfo) || (parentInfo.Attributes & 0x410u) != 0x10u) { throw new System.IO.IOException("central lease parent lost ordinary directory shape"); }
    System.IntPtr text = System.IntPtr.Zero, name = System.IntPtr.Zero, raw = System.IntPtr.Zero;
    bool retained = false;
    try {
        parent.DangerousAddRef(ref retained);
        text = System.Runtime.InteropServices.Marshal.StringToHGlobalUni(leaf);
        UNICODE_STRING unicode = new UNICODE_STRING();
        unicode.Length = checked((ushort)(leaf.Length * 2)); unicode.MaximumLength = unicode.Length; unicode.Buffer = text;
        name = System.Runtime.InteropServices.Marshal.AllocHGlobal(System.Runtime.InteropServices.Marshal.SizeOf(typeof(UNICODE_STRING)));
        System.Runtime.InteropServices.Marshal.StructureToPtr(unicode, name, false);
        OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
        attributes.Length = System.Runtime.InteropServices.Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        attributes.RootDirectory = parent.DangerousGetHandle(); attributes.ObjectName = name; attributes.Attributes = 0x40u;
        IO_STATUS_BLOCK status;
        uint access = directory ? 0xA1u : (lockFile ? 0xC0000000u : 0x80000000u);
        uint share = lockFile ? 0u : (directory && !protectDirectory ? 3u : 1u);
        int result = NtCreateFile(out raw, access | 0x00100000u, ref attributes, out status, System.IntPtr.Zero, 0x80u,
            share, 1u, 0x00200020u | (directory ? 1u : 0x40u), System.IntPtr.Zero, 0u);
        if (result < 0 || raw == System.IntPtr.Zero || raw == new System.IntPtr(-1)) {
            if (raw != System.IntPtr.Zero && raw != new System.IntPtr(-1)) { CloseHandle(raw); raw = System.IntPtr.Zero; }
            throw new System.ComponentModel.Win32Exception(unchecked((int)RtlNtStatusToDosError(result)), "central lease child open failed");
        }
        Microsoft.Win32.SafeHandles.SafeFileHandle owned = new Microsoft.Win32.SafeHandles.SafeFileHandle(raw, true);
        raw = System.IntPtr.Zero;
        return Check(owned, directory);
    } finally {
        if (raw != System.IntPtr.Zero && raw != new System.IntPtr(-1)) { CloseHandle(raw); }
        if (name != System.IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(name); }
        if (text != System.IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(text); }
        if (retained) { parent.DangerousRelease(); }
    }
}
'@
}
$script:CrgLaunchDirectories = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
$script:CrgLaunchOwners = New-Object 'System.Collections.Generic.List[object]'
$script:CrgSemVerBody = "\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)" +
                        "(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?" +
                        "(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?"
function Get-CrgSha256HexOfBytes {
  param([byte[]]$Bytes)
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() } finally { $hash.Dispose() }
}
function Open-CrgLaunchDirectory {
  param([string]$Path, [string]$ProtectedRoot)
  if ($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Contains('/')) { throw 'central lease requires a canonical absolute local path' }
  $full = [IO.Path]::GetFullPath($Path)
  if (-not [string]::Equals($full, $Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'central lease refuses noncanonical paths' }
  $cursor = $full.Substring(0, 3)
  if (-not $script:CrgLaunchDirectories.ContainsKey($cursor)) {
    $drive = [CrgCentralLaunch.ReadLeaseV1]::OpenDrive($cursor)
    $script:CrgLaunchOwners.Add($drive) | Out-Null
    $script:CrgLaunchDirectories.Add($cursor, [pscustomobject]@{ Handle = $drive; Protected = $false })
  }
  foreach ($part in @($full.Substring(3) -split '\\', 0 | Where-Object { $_.Length -gt 0 })) {
    $parent = $script:CrgLaunchDirectories[$cursor].Handle
    $cursor = [IO.Path]::Combine($cursor, $part)
    $protect = $ProtectedRoot.Length -gt 0 -and ($cursor -ieq $ProtectedRoot -or $cursor.StartsWith($ProtectedRoot + '\', [StringComparison]::OrdinalIgnoreCase))
    if (-not $script:CrgLaunchDirectories.ContainsKey($cursor) -or ($protect -and -not $script:CrgLaunchDirectories[$cursor].Protected)) {
      $directory = [CrgCentralLaunch.ReadLeaseV1]::OpenChild($parent, $part, $true, $protect, $false)
      $script:CrgLaunchOwners.Add($directory) | Out-Null
      $script:CrgLaunchDirectories[$cursor] = [pscustomobject]@{ Handle = $directory; Protected = $protect }
    }
  }
  return $script:CrgLaunchDirectories[$cursor].Handle
}
function Read-CrgLaunchFile {
  param([string]$Path, [int]$Maximum, [string]$ProtectedRoot, [switch]$AllowAbsent)
  $handle = $null; $stream = $null
  try {
    $parent = Open-CrgLaunchDirectory -Path ([IO.Path]::GetDirectoryName($Path)) -ProtectedRoot $ProtectedRoot
    $handle = [CrgCentralLaunch.ReadLeaseV1]::OpenChild($parent, [IO.Path]::GetFileName($Path), $false, $false, $false)
    $stream = New-Object IO.FileStream($handle, [IO.FileAccess]::Read); $handle = $null
    $script:CrgLaunchOwners.Add($stream) | Out-Null
    if ($Maximum -lt 0 -or $stream.Length -gt $Maximum) { throw "central read buffer exceeds its bound: '$Path'" }
    $bytes = New-Object byte[] ([int]$stream.Length)
    $read = 0
    while ($read -lt $bytes.Length) { $got = $stream.Read($bytes, $read, $bytes.Length - $read); if ($got -le 0) { throw 'central read buffer was truncated' }; $read += $got }
    $stream.Position = 0
    return [pscustomobject]@{ Present = $true; Path = $Path; Bytes = $bytes; Stream = $stream }
  } catch {
    $reason = $_.Exception
    while ($null -ne $reason.InnerException) { $reason = $reason.InnerException }
    if ($AllowAbsent -and $reason -is [ComponentModel.Win32Exception] -and $reason.NativeErrorCode -in @(2, 3)) {
      return [pscustomobject]@{ Present = $false; Path = $Path; Bytes = [byte[]]@(); Stream = $null }
    }
    throw
  } finally { if ($null -ne $handle) { $handle.Dispose() } }
}

function Read-CrgRuntimeManifestBytes {
  param([byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 65536) { throw 'runtime manifest has an invalid byte length' }
  foreach ($rtByte in $Bytes) {
    if ($rtByte -ne 10 -and ($rtByte -lt 32 -or $rtByte -gt 126)) { throw 'runtime manifest must be exact LF ASCII' }
  }
  $rtLines = @([System.Text.Encoding]::ASCII.GetString($Bytes).Split([char]10))
  if ($rtLines.Count -lt 7 -or $rtLines.Count -gt 262 -or $rtLines[-1] -cne '' -or
      $rtLines[0] -cne 'crg-runtime-manifest v1' -or $rtLines[3] -cnotin @('launcher-abi 1', 'launcher-abi 2') -or $rtLines[4] -cne 'config-schema 1') {
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
        $rtPath -ieq 'runtime-manifest' -or -not $rtSeen.Add($rtPath) -or
        [System.StringComparer]::Ordinal.Compare($rtPrevious, $rtPath) -ge 0) { throw "runtime manifest payload '$rtPath' has an invalid length, path, or order" }
    foreach ($rtPart in @($rtPath.Split([char]'/'))) {
      if ($rtPart.Length -eq 0 -or $rtPart -in @('.', '..') -or $rtPart.EndsWith('.') -or
          $rtPart -match '\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|\z)') { throw "runtime manifest payload '$rtPath' has an unsupported component" }
    }
    $rtParent = $rtPath
    while ($rtParent.Contains('/')) {
      $rtParent = $rtParent.Substring(0, $rtParent.LastIndexOf('/'))
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

function Read-CrgRuntimeActiveBytes {
  param([byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -ne 95) { throw 'central active record must be exactly 95 bytes' }
  foreach ($rtByte in $Bytes) { if ($rtByte -gt 127) { throw 'central active record is not ASCII' } }
  if ([System.Text.Encoding]::ASCII.GetString($Bytes) -cnotmatch '\Acrg-runtime-active v1\nrelease (?<h>[0-9a-f]{64})\n\z') { throw 'central active record grammar is invalid' }
  return $Matches['h']
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

function Open-CrgLaunchRelease {
  param([string]$Store, [string]$Id)
  if ($Id -cnotmatch '\A[0-9a-f]{64}\z') { throw 'retained release identity is not a canonical manifest digest' }
  $root = Join-Path $Store "releases\$Id"
  $record = Read-CrgLaunchFile -Path (Join-Path $root 'runtime-manifest') -Maximum 65536 -ProtectedRoot $root
  $manifest = Read-CrgRuntimeManifestBytes -Bytes $record.Bytes
  if ($manifest.Id -cne $Id) { throw 'selected runtime manifest digest mismatch' }
  $payloads = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  foreach ($entry in $manifest.Entries) {
    $file = Read-CrgLaunchFile -Path (Join-Path $root $entry.Path.Replace('/', '\')) -Maximum 16777216 -ProtectedRoot $root
    if ($file.Bytes.Length -ne $entry.Length -or (Get-CrgSha256HexOfBytes -Bytes $file.Bytes) -cne $entry.Hash) { throw "selected runtime payload mismatch: '$($entry.Path)'" }
    $payloads.Add($entry.Path, $file)
  }
  foreach ($required in @('scripts/central-launcher.ps1', 'scripts/central-context.psm1', 'scripts/private-governance.psm1')) {
    if (-not $payloads.ContainsKey($required)) { throw "selected release lacks launcher capability: '$required'" }
  }
  $versionBytes = $payloads['VERSION'].Bytes
  $versionOffset = if ($versionBytes.Length -ge 3 -and $versionBytes[0] -eq 239 -and $versionBytes[1] -eq 187 -and $versionBytes[2] -eq 191) { 3 } else { 0 }
  $version = [Text.Encoding]::ASCII.GetString($versionBytes, $versionOffset, $versionBytes.Length - $versionOffset)
  if ($versionBytes.Length -gt 128 -or $version -cnotmatch ($script:CrgSemVerBody + '(\r\n|\n)?\z') -or $version.TrimEnd([char[]]@(13, 10)) -cne $manifest.Version) { throw 'selected runtime VERSION mismatch' }
  # Inventory walks only retained ordinary directories. Extras never
  # participate in module lookup, but still invalidate the published snapshot.
  $expected = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  [void]$expected.Add('runtime-manifest')
  foreach ($entry in $manifest.Entries) { [void]$expected.Add($entry.Path) }
  $pending = New-Object 'System.Collections.Generic.Stack[string]'
  $pending.Push('')
  while ($pending.Count -gt 0) {
    $relative = $pending.Pop()
    $directoryPath = if ($relative.Length -eq 0) { $root } else { Join-Path $root $relative.Replace('/', '\') }
    $null = Open-CrgLaunchDirectory -Path $directoryPath -ProtectedRoot $root
    foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($directoryPath)) {
      $relativeChild = if ($relative.Length -eq 0) { [IO.Path]::GetFileName($child) } else { "$relative/$([IO.Path]::GetFileName($child))" }
      if ($expected.Remove($relativeChild)) { continue }
      if (@($expected | Where-Object { $_.StartsWith($relativeChild + '/', [StringComparison]::Ordinal) }).Count -eq 0) { throw "unexpected selected runtime entry '$relativeChild'" }
      $pending.Push($relativeChild)
    }
  }
  if ($expected.Count -ne 0) { throw 'selected runtime inventory is incomplete' }
  return [pscustomobject]@{ Store = $Store; Root = $root; Id = $Id; Manifest = $manifest; Payloads = $payloads }
}
function Add-CrgLaunchContext {
  param([object]$Selection)
  $Selection | Add-Member -NotePropertyName ReadFile -NotePropertyValue (Get-Command Read-CrgLaunchFile -CommandType Function).ScriptBlock
  $Selection | Add-Member -NotePropertyName RetainRelease -NotePropertyValue (Get-Command Open-CrgLaunchRetainedRelease -CommandType Function).ScriptBlock
  $Selection | Add-Member -NotePropertyName RetainFailure -NotePropertyValue (Get-Command Save-CrgLaunchFailureOwners -CommandType Function).ScriptBlock
  return $Selection
}
function Save-CrgLaunchFailureOwners {
  # A failed native descendant drain must not release runtime leases before
  # the operation owner's retained exception and native session are resolved.
  $script:CrgLaunchRetainOwners = $true
  return ,$script:CrgLaunchOwners
}
function Open-CrgLaunchRetainedRelease {
  param([string]$Id)
  # Only the verified Resume implementation can request a handoff's preceding
  # runtime. This callback confers custody, never persisted review authority.
  if ($script:CrgLaunchOperation -cne 'Resume') { throw 'retained runtime reopening is available only during Resume' }
  return Add-CrgLaunchContext -Selection (Open-CrgLaunchRelease -Store $script:CrgLaunchStore -Id $Id)
}
$lock = $null
$script:CrgLaunchRetainOwners = $false
try {
  $store = [IO.Path]::GetFullPath($PSScriptRoot)
  $script:CrgLaunchStore = $store
  $storeHandle = Open-CrgLaunchDirectory -Path $store
  $installation = Read-CrgLaunchFile -Path (Join-Path $store 'launcher-install') -Maximum 1024
  $installationRecord = Read-CrgRuntimeLauncherBytes -Bytes $installation.Bytes
  if ($installationRecord.LauncherAbi -ne 2) { throw 'ABI 2 launcher requires completed ABI 2 installation provenance' }
  $installedReleaseId = $installationRecord.ReleaseId; $installedLauncherHash = $installationRecord.Hash
  $installedLauncher = Read-CrgLaunchFile -Path $PSCommandPath -Maximum 16777216
  if ((Get-CrgSha256HexOfBytes -Bytes $installedLauncher.Bytes) -cne $installedLauncherHash) { throw 'stable launcher bytes differ from recorded first installation' }
  $originRoot = Join-Path $store "releases\$installedReleaseId"
  $originRecord = Read-CrgLaunchFile -Path (Join-Path $originRoot 'runtime-manifest') -Maximum 65536 -ProtectedRoot $originRoot
  $originManifest = Read-CrgRuntimeManifestBytes -Bytes $originRecord.Bytes
  $originLauncher = @($originManifest.Entries | Where-Object { $_.Path -ceq 'scripts/central-launcher.ps1' })
  if ($originManifest.Id -cne $installedReleaseId -or $originManifest.LauncherAbi -ne $installationRecord.LauncherAbi -or
      $originLauncher.Count -ne 1 -or $originLauncher[0].Hash -cne $installedLauncherHash) { throw 'stable launcher provenance differs from the recorded approved manifest' }
  $lock = [CrgCentralLaunch.ReadLeaseV1]::OpenChild($storeHandle, 'runtime.lock', $false, $false, $true)
  $active = Read-CrgLaunchFile -Path (Join-Path $store 'active-release') -Maximum 95
  $selectedId = Read-CrgRuntimeActiveBytes -Bytes $active.Bytes
  $selected = Open-CrgLaunchRelease -Store $store -Id $selectedId
  # The selector lease ends before delegation; retaining the selector itself
  # would prevent central upgrades while an invocation finishes.
  $active.Stream.Dispose(); $lock.Dispose(); $lock = $null
  Import-Module -Name $selected.Payloads['scripts/private-governance.psm1'].Path -Force -ErrorAction Stop
  Import-Module -Name $selected.Payloads['scripts/central-context.psm1'].Path -Force -ErrorAction Stop
  $selected = Add-CrgLaunchContext -Selection $selected
  Invoke-CrgCentralOperation -TargetRepo $TargetRepo -Operation $operation -Context $selected
} finally {
  if ($null -ne $lock) { $lock.Dispose() }
  if (-not $script:CrgLaunchRetainOwners) {
    for ($ownerIndex = $script:CrgLaunchOwners.Count - 1; $ownerIndex -ge 0; $ownerIndex--) { $script:CrgLaunchOwners[$ownerIndex].Dispose() }
  }
}
