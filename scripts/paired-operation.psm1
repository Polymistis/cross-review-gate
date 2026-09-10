# Project read custody only. No operation dispatch, mutation or review authority.
# Release/Close require the live caller to establish child quiescence first.
# No caller boolean, PID, lock-file text or stored record proves that condition.
$script:CrgOperationReadOwners = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
$script:CrgExecutableReadOwners = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)

function Get-CrgOperationReadCommand {
  param([string]$Name)
  $commands = @(Get-Command -Name $Name -Module paired-diff -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($commands.Count -ne 1) { throw "operation reads require one retained paired-diff/$Name command" }
  return $commands[0]
}

function Assert-CrgOperationReadPath {
  param([string]$Path, [switch]$Root)
  if ($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Contains('/') -or $Path.Length -le 3 -or $Path.Length -gt 32767 -or
      $Path -match '[\x00-\x1f\x7f]' -or [IO.Path]::GetFullPath($Path) -cne $Path) { throw 'operation read path must be canonical and local' }
  foreach ($part in ($Path.Substring(3) -split '\\', 0)) {
    if ($part.Length -eq 0 -or $part -in @('.', '..') -or $part.EndsWith('.') -or $part -cne $part.Trim() -or
        $part -match '[<>:"|?*]' -or $part -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)') { throw 'operation read path contains an unsupported component' }
  }
}

function Get-CrgOperationReadState {
  param([object]$Owner)
  if ($null -eq $Owner -or $Owner.Id -isnot [string] -or -not $script:CrgOperationReadOwners.ContainsKey($Owner.Id)) { throw 'operation read owner is absent, closed or not locally retained' }
  $state = $script:CrgOperationReadOwners[$Owner.Id]
  if (-not [object]::ReferenceEquals($state.Owner, $Owner)) { throw 'operation read owner differs from the retained instance' }
  return $state
}

function Get-CrgOperationReadDigest {
  param([byte[]]$Bytes)
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $hash.Dispose() }
}

function Get-CrgExecutableReadState {
  param([object]$Owner)
  if ($null -eq $Owner -or $Owner.Id -isnot [string] -or -not $script:CrgExecutableReadOwners.ContainsKey($Owner.Id)) { throw 'executable read owner is absent, closed or not locally retained' }
  $state = $script:CrgExecutableReadOwners[$Owner.Id]
  if (-not [object]::ReferenceEquals($state.Owner, $Owner) -or -not [object]::ReferenceEquals($state.Record, $Owner.Record)) { throw 'executable read owner differs from the retained instance' }
  return $state
}

function Assert-CrgExecutableReadState {
  param([object]$State)
  $record = $State.Record
  if ($record.Present -isnot [bool] -or -not $record.Present -or $record.Path -cne $State.Path -or
      $record.Bytes -isnot [byte[]] -or -not [object]::ReferenceEquals($record.Stream, $State.Stream) -or
      -not $State.Stream.CanRead -or $State.Stream.CanWrite -or $State.Stream.SafeFileHandle.IsClosed) { throw 'executable read record lost its retained Path/Bytes/Stream identity' }
  & $State.NativeModule {
    param($State)
    $custody = @{ DirectoryPins = $State.DirectoryPins.ToArray(); OwnedDirectories = @(); ControlFiles = @() }
    Assert-CrgAttributeNeutralContextStable -Context @{ Custody = $custody } -Boundary 'executable read directories'
    $probe = $null; $errorCode = 0
    try {
      # Executable hard links are read-only aliases. No executable mutation or
      # deletion uses the single-link project/payload cleanup primitives.
      $probe = [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($State.Parent.Handle, [IO.Path]::GetFileName($State.Path), [ref]$errorCode)
      if ($null -eq $probe -or $probe.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryFile($probe) -or
          -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryFile($State.Stream.SafeFileHandle) -or
          -not [CrgAttributeNeutral.NativeV1]::SameIdentity($State.Stream.SafeFileHandle, $probe)) { throw "executable read lost its exact ordinary relative identity (Win32 error $errorCode)" }
      $actual = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $State.Stream.SafeFileHandle }
      if ($actual.Length -ne $State.ExpectedLength -or $actual.Sha256 -cne $State.ExpectedSha256) { throw 'executable file bytes changed under the retained read stream' }
      Assert-CrgAttributeNeutralContextStable -Context @{ Custody = $custody } -Boundary 'executable read directories'
    } finally { if ($null -ne $probe) { $probe.Dispose() } }
  } $State
  if ($record.Bytes.Length -ne $State.ExpectedLength -or (Get-CrgOperationReadDigest -Bytes $record.Bytes) -cne $State.ExpectedSha256) { throw 'executable read buffer differs from the retained file bytes' }
}

function Open-CrgPairedExecutableRead {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$Path, [int]$Maximum = 16777216)
  Assert-CrgOperationReadPath -Path $Path
  if ($Maximum -lt 1 -or $Maximum -gt 67108864) { throw 'executable read bound must be between 1 and 67108864 bytes' }
  $native = (Get-CrgOperationReadCommand -Name Assert-CrgPairedOperationLock).Module
  $state = [pscustomobject]@{
    Owner = $null; Record = $null; Path = $Path; Stream = $null; Parent = $null; NativeModule = $native
    DirectoryPins = (New-Object 'System.Collections.Generic.List[object]')
    Directories = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase))
    ExpectedLength = 0; ExpectedSha256 = ''
  }
  $handle = $null; $complete = $false
  try {
    & $native { Initialize-CrgAttributeNeutralNative }
    $drive = [IO.Path]::GetPathRoot($Path)
    $driveRecord = & $native {
      param($Drive, $Pins)
      Enter-CrgAttributeNeutralDirectoryChain -Path $Drive -Pins $Pins -DenyLeafRename
    } $drive $state.DirectoryPins
    $state.Directories.Add($drive, $driveRecord)
    $state.Parent = Get-CrgOperationReadDirectory -State $state -Path ([IO.Path]::GetDirectoryName($Path))
    $errorCode = 0
    $handle = [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($state.Parent.Handle, [IO.Path]::GetFileName($Path), [ref]$errorCode)
    if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryFile($handle)) { throw "executable read requires an ordinary no-follow file (Win32 error $errorCode)" }
    $state.Stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read); $handle = $null
    if ($state.Stream.Length -gt $Maximum) { throw 'executable read file exceeds the requested bound' }
    $bytes = New-Object byte[] ([int]$state.Stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $count = $state.Stream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($count -le 0) { throw 'executable file was truncated during retained read' }
      $offset += $count
    }
    $state.ExpectedLength = $bytes.Length; $state.ExpectedSha256 = Get-CrgOperationReadDigest -Bytes $bytes
    $state.Record = [pscustomobject]@{ Present = $true; Path = $Path; Bytes = $bytes; Stream = $state.Stream }
    Assert-CrgExecutableReadState -State $state
    $owner = [pscustomobject]@{ Id = [guid]::NewGuid().ToString('N'); Record = $state.Record }
    $state.Owner = $owner
    $script:CrgExecutableReadOwners.Add($owner.Id, $state)
    $complete = $true
    return $owner
  } finally {
    if ($null -ne $handle) { $handle.Dispose() }
    if (-not $complete) {
      if ($null -ne $state.Stream) { $state.Stream.Dispose() }
      for ($i = $state.DirectoryPins.Count - 1; $i -ge 0; $i--) { $state.DirectoryPins[$i].Handle.Dispose() }
    }
  }
}

function Assert-CrgPairedExecutableRead {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Owner)
  Assert-CrgExecutableReadState -State (Get-CrgExecutableReadState -Owner $Owner)
}

function Close-CrgPairedExecutableRead {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Owner)
  $state = Get-CrgExecutableReadState -Owner $Owner
  # The live caller establishes complete child quiescence before releasing
  # executable custody. The operation facade borrows, never closes this owner.
  try {
    Assert-CrgExecutableReadState -State $state
    $state.Stream.Dispose()
    for ($i = $state.DirectoryPins.Count - 1; $i -ge 0; $i--) { $state.DirectoryPins[$i].Handle.Dispose() }
    $null = $script:CrgExecutableReadOwners.Remove($Owner.Id)
  } catch { $_.Exception.Data['CrgPairedExecutableReadOwner'] = $Owner; throw }
}

function Assert-CrgOperationReadRecord {
  param([object]$State, [object]$Record)
  if ($Record.Stream -isnot [IO.FileStream] -or -not $Record.Stream.CanRead -or $Record.Stream.SafeFileHandle.IsClosed) { throw 'operation read record lost its retained file stream' }
  $native = $State.NativeModule
  & $native {
    param($Record)
    Assert-CrgAttributeNeutralContextStable -Context @{ Custody = @{ DirectoryPins = @(); OwnedDirectories = @(); ControlFiles = @($Record) } } -Boundary 'operation read file'
    $actual = Get-CrgOwnedBinaryFileDigest -Record $Record
    if ($actual.Length -ne $Record.ExpectedLength -or $actual.Sha256 -cne $Record.ExpectedSha256) { throw 'operation file bytes changed under the retained stream' }
  } $Record
  if ($Record.Bytes.Length -ne $Record.ExpectedLength -or (Get-CrgOperationReadDigest -Bytes $Record.Bytes) -cne $Record.ExpectedSha256) { throw 'operation read buffer differs from the retained file bytes' }
}

function Assert-CrgOperationReadState {
  param([object]$State)
  & $State.AssertLock -Lock $State.OperationLock
  & $State.NativeModule {
    param($Pins)
    Assert-CrgAttributeNeutralContextStable -Context @{ Custody = @{ DirectoryPins = $Pins.ToArray(); OwnedDirectories = @(); ControlFiles = @() } } -Boundary 'operation read directories'
  } $State.DirectoryPins
}

function Get-CrgOperationReadDirectory {
  param([object]$State, [string]$Path, [switch]$AllowAbsent)
  if ($State.Directories.ContainsKey($Path)) { return $State.Directories[$Path] }
  $parent = Get-CrgOperationReadDirectory -State $State -Path ([IO.Path]::GetDirectoryName($Path)) -AllowAbsent:$AllowAbsent
  if ($null -eq $parent) { return $null }
  $errorCode = 0; $probe = $null; $pin = $null
  try {
    $probe = [CrgAttributeNeutral.NativeV1]::OpenReadDirectoryRelative($parent.Handle, [IO.Path]::GetFileName($Path), [ref]$errorCode)
    if ($null -eq $probe -or $probe.IsInvalid) {
      if ($AllowAbsent -and $errorCode -in @(2, 3)) { return $null }
      throw "operation read directory is unavailable (Win32 error $errorCode)"
    }
    if (-not [CrgAttributeNeutral.NativeV1]::IsOrdinaryDirectory($probe)) { throw 'operation read directory is not ordinary' }
    # The relative no-follow probe pins identity; the second handle denies
    # rename until the operation closes, including between file-read phases.
    $pin = [CrgAttributeNeutral.NativeV1]::OpenPinnedDirectoryNoFollowDenyRename($Path, [ref]$errorCode)
    if ($null -eq $pin -or $pin.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::SameIdentity($probe, $pin)) { throw "operation read directory pin differs from the relative probe (Win32 error $errorCode)" }
    $record = [pscustomobject]@{ Path = $Path; Handle = $pin; Label = 'operation read directory'; DeniesRename = $true }
    $State.DirectoryPins.Add($record); $pin = $null
    $State.Directories.Add($Path, $record)
    return $record
  } finally {
    if ($null -ne $probe) { $probe.Dispose() }
    if ($null -ne $pin) { $pin.Dispose() }
  }
}

function Open-CrgOperationReadLeaf {
  param([object]$State, [string]$Path, [switch]$AllowAbsent)
  $parent = Get-CrgOperationReadDirectory -State $State -Path ([IO.Path]::GetDirectoryName($Path)) -AllowAbsent:$AllowAbsent
  if ($null -eq $parent) { return $null }
  $errorCode = 0
  $handle = [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($parent.Handle, [IO.Path]::GetFileName($Path), [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid) {
    if ($null -ne $handle) { $handle.Dispose() }
    if ($AllowAbsent -and $errorCode -in @(2, 3)) { return $null }
    throw "operation read file is unavailable (Win32 error $errorCode)"
  }
  if (-not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) { $handle.Dispose(); throw 'operation read file must be ordinary and single-link' }
  return $handle
}

function Read-CrgOperationFile {
  param([object]$Owner, [string]$Path, [int]$Maximum, [switch]$AllowAbsent)
  $state = Get-CrgOperationReadState -Owner $Owner
  if ($state.Releasing -or $Maximum -lt 0) { throw 'operation file reads are unavailable or have an invalid bound' }
  Assert-CrgOperationReadPath -Path $Path
  Assert-CrgOperationReadState -State $state
  if ($state.ExecutableReads.ContainsKey($Path)) {
    $executable = Get-CrgExecutableReadState -Owner $state.ExecutableReads[$Path]
    Assert-CrgExecutableReadState -State $executable
    if ($executable.Record.Bytes.Length -gt $Maximum) { throw 'retained executable read exceeds the requested bound' }
    return [pscustomobject]@{ Present = $true; Path = $Path; Bytes = [byte[]]$executable.Record.Bytes.Clone(); Stream = $executable.Stream }
  }
  if ($state.Borrowed.ContainsKey($Path)) {
    $record = $state.Borrowed[$Path]
    Assert-CrgOperationReadRecord -State $state -Record $record
    if ($record.Bytes.Length -gt $Maximum) { throw 'retained runtime/executable read exceeds the requested bound' }
    return [pscustomobject]@{ Present = $true; Path = $Path; Bytes = [byte[]]$record.Bytes.Clone() }
  }
  $within = $false
  foreach ($root in $state.ProjectRoots) { if ($Path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { $within = $true; break } }
  if (-not $within) { throw 'operation file lies outside every explicitly retained project root' }
  if ($state.Files.ContainsKey($Path)) {
    $record = $state.Files[$Path]
    Assert-CrgOperationReadRecord -State $state -Record $record
    if ($record.Bytes.Length -gt $Maximum) { throw 'operation read file exceeds the requested bound' }
    return [pscustomobject]@{ Present = $true; Path = $Path; Bytes = [byte[]]$record.Bytes.Clone() }
  }
  $handle = $null; $stream = $null
  try {
    $handle = Open-CrgOperationReadLeaf -State $state -Path $Path -AllowAbsent:$AllowAbsent
    if ($null -eq $handle) {
      $null = $state.AbsentPaths.Add($Path)
      return [pscustomobject]@{ Present = $false; Path = $Path; Bytes = [byte[]]@() }
    }
    if ($state.AbsentPaths.Contains($Path)) { throw 'operation file appeared after a retained absence observation; release and recapture the read phase' }
    $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read); $handle = $null
    if ($stream.Length -gt $Maximum) { throw 'operation read file exceeds the requested bound' }
    $bytes = New-Object byte[] ([int]$stream.Length)
    $position = 0
    while ($position -lt $bytes.Length) {
      $count = $stream.Read($bytes, $position, $bytes.Length - $position)
      if ($count -le 0) { throw 'operation file was truncated during retained read' }
      $position += $count
    }
    $record = [pscustomobject]@{ Path = $Path; Stream = $stream; Handle = $stream.SafeFileHandle; Bytes = $bytes
      Label = 'operation project read file'; ExpectedLength = $bytes.Length; ExpectedSha256 = (Get-CrgOperationReadDigest -Bytes $bytes) }
    Assert-CrgOperationReadRecord -State $state -Record $record
    $state.Files.Add($Path, $record); $stream = $null
    Assert-CrgOperationReadState -State $state
    return [pscustomobject]@{ Present = $true; Path = $Path; Bytes = [byte[]]$bytes.Clone() }
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
    if ($null -ne $handle) { $handle.Dispose() }
  }
}

function Open-CrgPairedOperationReads {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Runtime,
    [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][string[]]$ProjectRoots,
    [object[]]$RetainedFiles = @(), [object[]]$ExecutableReads = @())
  if ($null -eq $Runtime -or $Runtime.Id -cnotmatch '\A[0-9a-f]{64}\z' -or $Runtime.ReadFile -isnot [scriptblock] -or
      $Runtime.Payloads -isnot [System.Collections.IDictionary] -or $null -eq $Runtime.Manifest -or $ProjectRoots.Count -lt 1 -or $ProjectRoots.Count -gt 16) { throw 'operation reads require a retained runtime and bounded explicit project roots' }
  Assert-CrgOperationReadPath -Path $Runtime.Root -Root
  Assert-CrgOperationReadPath -Path $Runtime.Store -Root
  $assertLock = Get-CrgOperationReadCommand -Name Assert-CrgPairedOperationLock
  & $assertLock -Lock $OperationLock
  $roots = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $lockWithin = $false
  foreach ($root in $ProjectRoots) {
    Assert-CrgOperationReadPath -Path $root -Root
    if (-not $roots.Add($root)) { throw 'operation project roots contain duplicates or case aliases' }
    if ($root.Equals($Runtime.Store, [StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($Runtime.Store + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $Runtime.Store.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'operation project roots must not overlap the retained runtime store' }
    if ($OperationLock.PublicGitDirectory.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        $OperationLock.PublicGitDirectory.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { $lockWithin = $true }
  }
  if (-not $lockWithin) { throw 'operation roots do not include the held public Git directory' }
  $state = [pscustomobject]@{
    Owner = $null; OriginalRuntime = $Runtime; OperationLock = $OperationLock; AssertLock = $assertLock; NativeModule = $assertLock.Module
    ProjectRoots = [string[]]@($ProjectRoots); Releasing = $false
    DirectoryPins = (New-Object 'System.Collections.Generic.List[object]')
    Directories = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase))
    Files = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase))
    Borrowed = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase))
    ExecutableReads = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal))
    AbsentPaths = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase))
  }
  $complete = $false
  try {
    & $state.NativeModule { Initialize-CrgAttributeNeutralNative }
    foreach ($root in $ProjectRoots) {
      $drive = [IO.Path]::GetPathRoot($root)
      if (-not $state.Directories.ContainsKey($drive)) {
        $record = & $state.NativeModule {
          param($Drive, $Pins)
          Enter-CrgAttributeNeutralDirectoryChain -Path $Drive -Pins $Pins -DenyLeafRename
        } $drive $state.DirectoryPins
        $state.Directories.Add($drive, $record)
      }
      $null = Get-CrgOperationReadDirectory -State $state -Path $root
    }
    $borrowed = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in $Runtime.Payloads.Keys) {
      if ($name -isnot [string] -or $name -cnotmatch '\A[A-Za-z0-9._/-]+\z') { throw 'retained runtime payload name is invalid' }
      $record = $Runtime.Payloads[$name]
      $expectedPath = Join-Path $Runtime.Root $name.Replace('/', '\')
      if ($record.Path -cne $expectedPath) { throw 'retained runtime payload path differs from the selected release' }
      $borrowed.Add($record)
    }
    foreach ($record in $RetainedFiles) { $borrowed.Add($record) }
    foreach ($record in $borrowed) {
      if ($null -eq $record -or $record.Path -isnot [string] -or $record.Bytes -isnot [byte[]] -or
          $record.Stream -isnot [IO.FileStream] -or -not $record.Stream.CanRead) { throw 'borrowed operation read requires an exact retained Path/Bytes/Stream record' }
      Assert-CrgOperationReadPath -Path $record.Path
      if ($state.Borrowed.ContainsKey($record.Path)) { throw 'borrowed operation files contain duplicate exact paths' }
      $held = [pscustomobject]@{ Path = $record.Path; Bytes = [byte[]]$record.Bytes.Clone(); Stream = $record.Stream; Handle = $record.Stream.SafeFileHandle
        OriginalRecord = $record; Label = 'borrowed runtime/executable read'; ExpectedLength = $record.Bytes.Length; ExpectedSha256 = (Get-CrgOperationReadDigest -Bytes $record.Bytes) }
      Assert-CrgOperationReadRecord -State $state -Record $held
      $state.Borrowed.Add($held.Path, $held)
    }
    if ($ExecutableReads.Count -gt 16) { throw 'operation executable read owner count exceeds its bound' }
    foreach ($executableOwner in $ExecutableReads) {
      $executable = Get-CrgExecutableReadState -Owner $executableOwner
      Assert-CrgExecutableReadState -State $executable
      $path = $executable.Path
      if ($state.Borrowed.ContainsKey($path) -or $path.Equals($Runtime.Store, [StringComparison]::OrdinalIgnoreCase) -or
          $path.StartsWith($Runtime.Store + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'operation executable path overlaps a retained runtime file or store' }
      foreach ($root in $ProjectRoots) {
        if ($path.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or $path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'operation executable path overlaps mutable project roots' }
      }
      foreach ($existing in $state.ExecutableReads.Keys) {
        if ($path.Equals($existing, [StringComparison]::OrdinalIgnoreCase)) { throw 'operation executable owners contain duplicate paths or case aliases' }
      }
      $state.ExecutableReads.Add($path, $executableOwner)
    }
    $facade = [pscustomobject]@{ Id = $Runtime.Id; Root = $Runtime.Root; Store = $Runtime.Store; Manifest = $Runtime.Manifest
      Payloads = $Runtime.Payloads; OriginalRuntime = $Runtime; ReadFile = $null }
    if ($Runtime.RetainRelease -is [scriptblock]) { $facade | Add-Member -NotePropertyName RetainRelease -NotePropertyValue $Runtime.RetainRelease }
    $owner = [pscustomobject]@{ Id = [guid]::NewGuid().ToString('N'); Runtime = $facade }
    $state.Owner = $owner
    $read = Get-Command Read-CrgOperationFile -CommandType Function -ErrorAction Stop
    $facade.ReadFile = { param([string]$Path, [int]$Maximum, [switch]$AllowAbsent) & $read -Owner $owner -Path $Path -Maximum $Maximum -AllowAbsent:$AllowAbsent }.GetNewClosure()
    Assert-CrgOperationReadState -State $state
    $script:CrgOperationReadOwners.Add($owner.Id, $state)
    $complete = $true
    return $owner
  } finally {
    if (-not $complete) {
      foreach ($record in $state.Files.Values) { $record.Stream.Dispose() }
      for ($i = $state.DirectoryPins.Count - 1; $i -ge 0; $i--) { $state.DirectoryPins[$i].Handle.Dispose() }
    }
  }
}

function Assert-CrgPairedOperationReads {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Owner)
  $state = Get-CrgOperationReadState -Owner $Owner
  if ($state.Releasing) { throw 'operation read release is incomplete' }
  Assert-CrgOperationReadState -State $state
  foreach ($record in @($state.Files.Values) + @($state.Borrowed.Values)) { Assert-CrgOperationReadRecord -State $state -Record $record }
  foreach ($executableOwner in $state.ExecutableReads.Values) { Assert-CrgPairedExecutableRead -Owner $executableOwner }
  foreach ($path in $state.AbsentPaths) {
    $handle = Open-CrgOperationReadLeaf -State $state -Path $path -AllowAbsent
    if ($null -ne $handle) { $handle.Dispose(); throw 'operation file appeared after a retained absence observation' }
  }
  Assert-CrgOperationReadState -State $state
}

function Release-CrgPairedOperationReadFiles {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Owner, [AllowEmptyCollection()][string[]]$Paths)
  $state = Get-CrgOperationReadState -Owner $Owner
  Assert-CrgOperationReadState -State $state
  $releasePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  if ($PSBoundParameters.ContainsKey('Paths')) {
    if ($null -eq $Paths) { throw 'selective operation read release requires explicit paths' }
    foreach ($path in $Paths) {
      Assert-CrgOperationReadPath -Path $path
      $within = $false
      foreach ($root in $state.ProjectRoots) { if ($path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { $within = $true; break } }
      if (-not $within -or -not $releasePaths.Add($path)) { throw 'selective operation read release requires unique paths within the held project roots' }
    }
  } else {
    foreach ($path in @($state.Files.Keys) + @($state.AbsentPaths)) { $null = $releasePaths.Add($path) }
  }
  # Native child completion is a live-caller prerequisite, not a boolean API
  # grant. Selective metadata replacement must leave captured index/backing
  # leases intact; the exclusive operation lock and directory pins stay held.
  $state.Releasing = $true
  try {
    foreach ($path in $releasePaths) {
      if ($state.Files.ContainsKey($path)) { $state.Files[$path].Stream.Dispose(); $null = $state.Files.Remove($path) }
      $null = $state.AbsentPaths.Remove($path)
    }
    Assert-CrgOperationReadState -State $state
    $state.Releasing = $false
  } catch { $_.Exception.Data['CrgPairedOperationReadOwner'] = $Owner; throw }
}

function Close-CrgPairedOperationReads {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Owner)
  $state = Get-CrgOperationReadState -Owner $Owner
  Release-CrgPairedOperationReadFiles -Owner $Owner
  $state.Releasing = $true
  try {
    for ($i = $state.DirectoryPins.Count - 1; $i -ge 0; $i--) { $state.DirectoryPins[$i].Handle.Dispose() }
    $null = $script:CrgOperationReadOwners.Remove($Owner.Id)
  } catch { $_.Exception.Data['CrgPairedOperationReadOwner'] = $Owner; throw }
  # The borrowed operation lock, runtime, RetainedFiles and executable owners are never closed.
}

Export-ModuleMember -Function Open-CrgPairedOperationReads, Assert-CrgPairedOperationReads, Release-CrgPairedOperationReadFiles, Close-CrgPairedOperationReads, Open-CrgPairedExecutableRead, Assert-CrgPairedExecutableRead, Close-CrgPairedExecutableRead
