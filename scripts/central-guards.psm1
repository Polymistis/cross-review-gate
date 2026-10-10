# Attached-shape non-review guards. Historical receipts identify completed work;
# neither a guard owner nor a persisted receipt grants current review authority.
$script:CrgCentralGuardOwners = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
# Exact LF wrappers emitted by the installed Git LFS 3.7.1. Recognition never
# executes hook source.
$script:CrgCentralLfsHooks = @{
  'post-checkout' = '8d606e58cce98604696a4abcf3ae1ebde6f9f31ac72bb0d44e2444cc39f26030'
  'post-commit' = 'f3eb4d1f62924c09d481a0563a84b158c66eb2feb3431cfdb3e6760aab4d661d'
  'post-merge' = 'cecb594e8fa65831654fc95e96db9f1249e09c52810c6fbb2b428280aac22158'
  'pre-push' = 'a52d0510d0f8c75e27852156ec6f7791f0d8ed65fc58fcc368dd1de0a60a1d74'
}

function Get-CrgCentralGuardCommand {
  param([object]$ProjectContext, [string]$Module, [string]$Name)
  $relative = 'scripts/' + $Module + '.psm1'
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($null -eq $ProjectContext -or $ProjectContext.Schema -ne 1 -or $null -eq $ProjectContext.Runtime -or
      $ProjectContext.Runtime.Payloads -isnot [System.Collections.IDictionary] -or
      -not [System.Linq.Enumerable]::Contains([string[]]@($ProjectContext.Runtime.Payloads.Keys), [string]$relative, [System.StringComparer]::Ordinal) -or $commands.Count -ne 1 -or
      -not [string]::Equals($commands[0].Module.Path, $ProjectContext.Runtime.Payloads[$relative].Path, [StringComparison]::OrdinalIgnoreCase)) {
    throw "central guards require the retained '$Module/$Name' command"
  }
  return $commands[0]
}

function Get-CrgCentralGuardDigest {
  param([byte[]]$Bytes)
  if ($null -eq $Bytes) { throw 'guard digest requires explicit bytes' }
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function ConvertTo-CrgGuardShellLiteral {
  param([string]$Value)
  if ([string]::IsNullOrEmpty($Value) -or $Value -match '[\x00-\x1f\x7f]') { throw 'guard shell argument is absent or control-bearing' }
  return "'" + $Value.Replace("'", "'\''") + "'"
}

function Get-CrgCentralGuardTemplates {
  param([object]$ProjectContext)
  $launcher = Join-Path $ProjectContext.Runtime.Store 'launcher.ps1'
  $hostPath = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $contextCommand = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module central-context -Name Read-CrgCentralTreeBytes
  & $contextCommand.Module { param($Paths) foreach ($path in $Paths) { Assert-CrgContextAbsolutePath -Path $path } } @($launcher, $hostPath)
  $quotedLauncher = ConvertTo-CrgGuardShellLiteral -Value $launcher
  $quotedHost = ConvertTo-CrgGuardShellLiteral -Value $hostPath
  $notice = ConvertTo-CrgGuardShellLiteral -Value ("[cross-review-gate] raw git commit is refused; use '$launcher' -TargetRepo <repository-root> -Commit -MessageFile <path>.")
  $commit = "#!/bin/sh`n# crg-central-commit-refusal v1`nprintf '%s\n' $notice >&2`nexit 1`n"
  # Git executes non-bare hooks at the worktree root. Common-directory hooks
  # must not bind the first attached worktree and misroute later associations.
  $push = @'
#!/bin/sh
# crg-central-public-push v1
crg_root=$(pwd -W) || exit 1
if [ -z "$crg_root" ]; then exit 1; fi
if [ "$#" -ne 2 ]; then exit 1; fi
exec __CRG_HOST__ -NoProfile -NonInteractive -ExecutionPolicy Bypass -File __CRG_LAUNCHER__ -TargetRepo "$crg_root" -PushCheck -PushRemoteName "$1" -PushRemoteLocation "$2"
'@
  $push = $push.Replace("`r`n", "`n").Replace('__CRG_HOST__', $quotedHost).Replace('__CRG_LAUNCHER__', $quotedLauncher) + "`n"
  $utf8 = [Text.UTF8Encoding]::new($false, $true)
  $files = @{ 'pre-commit' = $utf8.GetBytes($commit); 'pre-push' = $utf8.GetBytes($push) }
  foreach ($name in @('pre-commit', 'pre-push')) {
    $files[$name + '.crg-sha256'] = $utf8.GetBytes("crg-central-hook-digest v1`n" + (Get-CrgCentralGuardDigest -Bytes $files[$name]) + "`n")
  }
  return $files
}

function Get-CrgCentralGuardState {
  param([object]$GuardCustody)
  if ($null -eq $GuardCustody -or $GuardCustody.Id -isnot [string] -or -not $script:CrgCentralGuardOwners.ContainsKey($GuardCustody.Id)) { throw 'central hook custody is absent or closed' }
  $state = $script:CrgCentralGuardOwners[$GuardCustody.Id]
  if (-not [object]::ReferenceEquals($GuardCustody, $state.Owner)) { throw 'central hook custody is not the original retained owner' }
  return $state
}

function Read-CrgCentralGuardLeaf {
  param([object]$State, [object]$Directory, [string]$Leaf)
  return & $State.NativeModule {
    param($State, $Directory, $Leaf)
    $errorCode = 0; $handle = $null
    try {
      $handle = if ([string]::Equals($State.Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) {
        [CrgAttributeNeutral.NativeV1]::OpenPublicationFileRelative($Directory.Handle, $Leaf, [ref]$errorCode)
      } else { [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($Directory.Handle, $Leaf, [ref]$errorCode) }
      if ($null -eq $handle -or $handle.IsInvalid) {
        if ($errorCode -ne 2) { throw "hook '$Leaf' presence is indeterminate (Win32 error $errorCode)" }
        return [pscustomobject]@{ Leaf = $Leaf; Path = (Join-Path $Directory.Path $Leaf); Handle = $null; Bytes = $null; Present = $false; Sha256 = $null }
      }
      if (-not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) { throw "hook '$Leaf' is not one ordinary single-link file" }
      $text = [CrgAttributeNeutral.NativeV1]::ReadUtf8Exact($handle, [ref]$errorCode)
      if ($null -eq $text -or $errorCode -ne 0) { throw "hook '$Leaf' is not bounded strict UTF-8 (Win32 error $errorCode)" }
      $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($text)
      $digest = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $handle }
      if ($digest.Length -ne $bytes.Length) { throw 'hook text differs from its raw byte length' }
      $record = [pscustomobject]@{ Leaf = $Leaf; Path = (Join-Path $Directory.Path $Leaf); Handle = $handle; Bytes = $bytes; Present = $true; Sha256 = $digest.Sha256 }
      $handle = $null
      return $record
    } finally { if ($null -ne $handle) { $handle.Dispose() } }
  } $State $Directory $Leaf
}

function Assert-CrgCentralGuardInventory {
  param([object]$State)
  if ((Get-CrgCentralLfsHookMode -State $State) -ne $State.LfsEnabled) { throw 'public Git LFS hook composition changed under custody' }
  # Derived from the literal dispatcher in source 83b40f6 and released v2.1.0
  # bootstrap.ps1, with exact LF and CRLF encodings. Markers/digest sidecars
  # alone cannot prove absence of a custom hook appended to stock code.
  $stock = @('a490494bf0e95f9a23a4e5bd1c32a2ea438f65cbf80b598f174d23bd7ec7c741',
    '746ea9259b2fa2a724e24d5c9dab9b81c71f1f94f4ad381c6b5c64d9d2e1324c',
    '3466a213378091c57ac6f1c2908b5aa2b3d37301e0bb2d08ffd50ae1af3ebb30',
    'f4cc7f6c766fbd30d9461c111eff85c54963307f2c1b830442224da0945949ee')
  foreach ($domain in @('public', 'private')) {
    $directory = $State.Domains[$domain]
    if ($null -eq $directory.Hooks) {
      if (-not [string]::Equals($State.Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) { throw "$domain hooks directory is absent on an attached project" }
      continue
    }
    foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory.Hooks.Path)) {
      $name = [IO.Path]::GetFileName($path)
      if ($name -cmatch '\Apre-commit\.[A-Za-z0-9_.-]+\.bak\z' -and
          $directory.Files.ContainsKey($name) -and $directory.Files[$name].Present) { continue }
      # Ordinal: -cin/-ceq compare by culture and ignore characters such as U+00AD.
      if ([System.Linq.Enumerable]::Contains([string[]]@($State.HookNames), [string]$name, [System.StringComparer]::Ordinal) -or
          [string]::Equals($name, 'pre-commit.crg-sha256', [StringComparison]::Ordinal) -or [string]::Equals($name, 'pre-push.crg-sha256', [StringComparison]::Ordinal) -or
          ($name.EndsWith('.sample', [StringComparison]::Ordinal) -and
           [System.Linq.Enumerable]::Contains([string[]]@($State.HookNames), [string]$name.Substring(0, $name.Length - 7), [System.StringComparer]::Ordinal)) -or
          $name -cmatch '\A\.crg-(?:hook-[0-9a-f]{32}|prior-(?:pre-commit|pre-push)(?:\.crg-sha256)?-[0-9a-f]{32})\z') { continue }
      throw "$domain hooks directory contains unknown hook material '$name'; preserve and resolve explicitly"
    }
    foreach ($name in $State.HookNames) {
      $record = $directory.Files[$name]
      $required = $name -ceq 'pre-commit' -or ($domain -ceq 'public' -and $name -ceq 'pre-push')
      if (-not $required) {
        if ($record.Present -and -not ($domain -ceq 'public' -and $State.LfsEnabled -and
            [System.Linq.Enumerable]::Contains([string[]]@('post-checkout', 'post-commit', 'post-merge'), [string]$name, [StringComparer]::Ordinal) -and [string]::Equals($record.Sha256, $script:CrgCentralLfsHooks[$name], [StringComparison]::Ordinal))) {
          throw "$domain custom hook '$name' requires explicit preservation; attachment refuses"
        }
        continue
      }
      $expected = Get-CrgCentralGuardDigest -Bytes $State.Templates[$name]
      $sidecar = $directory.Files[$name + '.crg-sha256']
      $expectedSidecar = Get-CrgCentralGuardDigest -Bytes $State.Templates[$name + '.crg-sha256']
      if (-not $record.Present) {
        if (-not [string]::Equals($State.Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) { throw "$domain hook '$name' is absent" }
        if ($sidecar.Present) {
          # A process loss between moving a known prior aside and publishing
          # its replacement can leave only the attestation at the live name.
          # First-attachment recovery still requires a fresh review; no record
          # grants permission to skip that review or discard unknown hook bytes.
          $text = [Text.Encoding]::ASCII.GetString($sidecar.Bytes)
          $knownPrior = $name -ceq 'pre-commit' -and $text -cmatch '\Acrg-dispatcher-digest v1\n([0-9a-f]{64})\n\z' -and $Matches[1] -cin $stock
          if (-not [string]::Equals($sidecar.Sha256, $expectedSidecar, [StringComparison]::Ordinal) -and -not $knownPrior) { throw "$domain hook '$name' has an unknown orphan attestation" }
        }
        continue
      }
      if ([string]::Equals($record.Sha256, $expected, [StringComparison]::Ordinal)) {
        if ($sidecar.Present -and [string]::Equals($sidecar.Sha256, $expectedSidecar, [StringComparison]::Ordinal)) { continue }
        if ([string]::Equals($State.Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) {
          if (-not $sidecar.Present) { continue }
          $text = [Text.Encoding]::ASCII.GetString($sidecar.Bytes)
          if ($name -ceq 'pre-commit' -and $text -cmatch '\Acrg-dispatcher-digest v1\n([0-9a-f]{64})\n\z' -and $Matches[1] -cin $stock) { continue }
        }
        throw "$domain hook '$name' attestation differs from the required central dispatcher"
      }
      if ([string]::Equals($State.Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -and [string]::Equals($name, 'pre-commit', [StringComparison]::Ordinal) -and
          [System.Linq.Enumerable]::Contains([string[]]$stock, [string]$record.Sha256, [System.StringComparer]::Ordinal) -and $sidecar.Present) {
        $text = [Text.Encoding]::ASCII.GetString($sidecar.Bytes)
        if ([string]::Equals($text, ("crg-dispatcher-digest v1`n" + $record.Sha256 + "`n"), [StringComparison]::Ordinal)) { continue }
      }
      if ([string]::Equals($State.Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -and [string]::Equals($domain, 'public', [StringComparison]::Ordinal) -and [string]::Equals($name, 'pre-push', [StringComparison]::Ordinal) -and
          $State.LfsEnabled -and [string]::Equals($record.Sha256, $script:CrgCentralLfsHooks[$name], [StringComparison]::Ordinal) -and -not $sidecar.Present) { continue }
      throw "$domain hook '$name' is foreign, customized, or lacks exact recognized dispatcher attestation; preserve and resolve explicitly"
    }
  }
}

function Get-CrgCentralLfsHookMode {
  param([object]$State)
  $directory = $State.Domains.public
  if ($null -eq $directory.Hooks) { return $false }
  $present = 0
  foreach ($name in @('post-checkout', 'post-commit', 'post-merge')) {
    $record = $directory.Files[$name]
    if (-not $record.Present) { continue }
    if (-not [string]::Equals($record.Sha256, $script:CrgCentralLfsHooks[$name], [StringComparison]::Ordinal)) { throw "public '$name' is not the exact recognized Git LFS wrapper; preserve and resolve explicitly" }
    $present++
  }
  if ($present -ne 0 -and $present -ne 3) { throw 'public Git LFS hooks are incomplete; preserve and resolve the existing composition explicitly' }
  return $present -eq 3
}

function New-CrgCentralHookProjection {
  param([object]$State)
  Assert-CrgCentralGuardInventory -State $State
  $directories = & $State.NativeModule {
    param($State)
    $custody = $State.ExecutionCustody
    $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $State.Project.Domains.private.GitDir -Pins $custody.DirectoryPins -DenyLeafRename
    $leaf = '.crg-hooks-' + [guid]::NewGuid().ToString('N')
    $root = New-CrgAttributeNeutralOwnedDirectory -Custody $custody -Parent $parent -Leaf $leaf -Path (Join-Path $parent.Path $leaf) -Label 'admitted hook projection root'
    $result = @{}
    foreach ($domain in @('public', 'private')) {
      $bytes = @{}
      foreach ($name in $State.HookNames) {
        if ($State.Domains[$domain].Files.ContainsKey($name) -and $State.Domains[$domain].Files[$name].Present) {
          $bytes[$name] = [byte[]]$State.Domains[$domain].Files[$name].Bytes.Clone()
        }
      }
      $result[$domain] = New-CrgOwnedHookDirectory -Custody $custody -Parent $root -Leaf $domain -HookBytes $bytes
    }
    return $result
  } $State
  foreach ($domain in @('public', 'private')) { $State.Domains[$domain].Execution = $directories[$domain] }
}

function Open-CrgCentralGuardCustody {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  $assertLock = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-diff -Name Assert-CrgPairedOperationLock
  & $assertLock -Lock $OperationLock
  if (-not [string]::Equals($OperationLock.PublicGitDirectory, $ProjectContext.Domains.public.GitDir, [StringComparison]::Ordinal)) { throw 'central guards received another project operation lock' }
  $state = [pscustomobject]@{ Owner = [pscustomobject]@{ Id = [guid]::NewGuid().ToString('N') }; Project = $ProjectContext; Lock = $OperationLock; Origin = $Origin
    NativeModule = $assertLock.Module; Pins = (New-Object 'System.Collections.Generic.List[object]'); Domains = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal))
    HookNames = @(& $assertLock.Module { Get-CrgOwnedHookNames })
    ExecutionCustody = @{ DirectoryPins = (New-Object 'System.Collections.Generic.List[object]'); OwnedDirectories = (New-Object 'System.Collections.Generic.List[object]'); ControlFiles = (New-Object 'System.Collections.Generic.List[object]') }
    Templates = (Get-CrgCentralGuardTemplates -ProjectContext $ProjectContext); RecoveryPaths = (New-Object 'System.Collections.Generic.List[string]'); LfsEnabled = $false }
  $complete = $false
  try {
    foreach ($domain in @('public', 'private')) {
      $directory = & $state.NativeModule {
        param($State, $Path)
        Initialize-CrgAttributeNeutralNative
        $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $Path -Pins $State.Pins -DenyLeafRename
        $errorCode = 0; $probe = [CrgAttributeNeutral.NativeV1]::OpenReadDirectoryRelative($parent.Handle, 'hooks', [ref]$errorCode)
        $hooks = $null
        try {
          if ($null -eq $probe -or $probe.IsInvalid) { if ($errorCode -ne 2) { throw "hook directory presence is indeterminate (Win32 error $errorCode)" } }
          else {
            if (-not [CrgAttributeNeutral.NativeV1]::IsOrdinaryDirectory($probe)) { throw 'hooks path is not one ordinary directory' }
            $hooks = Enter-CrgAttributeNeutralDirectoryChain -Path (Join-Path $Path 'hooks') -Pins $State.Pins -DenyLeafRename
            if (-not [CrgAttributeNeutral.NativeV1]::SameIdentity($probe, $hooks.Handle)) { throw 'hooks directory changed during custody acquisition' }
          }
        } finally { if ($null -ne $probe) { $probe.Dispose() } }
        return [pscustomobject]@{ Parent = $parent; Hooks = $hooks; Files = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)); Execution = $null }
      } $state $ProjectContext.Domains[$domain].CommonDir
      $state.Domains[$domain] = $directory
      if ($null -ne $directory.Hooks) {
        foreach ($leaf in @($state.HookNames) + @('pre-commit.crg-sha256', 'pre-push.crg-sha256')) {
          $directory.Files[$leaf] = Read-CrgCentralGuardLeaf -State $state -Directory $directory.Hooks -Leaf $leaf
        }
        # Existing consumer backups can use pre-commit.<label>.bak, never a Git
        # hook entrypoint. Keep ordinary byte custody without executing,
        # overwriting or deleting these prior operator recovery files.
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory.Hooks.Path)) {
          $leaf = [IO.Path]::GetFileName($path)
          if ($leaf -cmatch '\Apre-commit\.[A-Za-z0-9_.-]+\.bak\z') {
            $directory.Files[$leaf] = Read-CrgCentralGuardLeaf -State $state -Directory $directory.Hooks -Leaf $leaf
          }
        }
      }
    }
    $state.LfsEnabled = Get-CrgCentralLfsHookMode -State $state
    Assert-CrgCentralGuardInventory -State $state
    New-CrgCentralHookProjection -State $state
    $script:CrgCentralGuardOwners.Add($state.Owner.Id, $state)
    $complete = $true
    return $state.Owner
  } finally {
    if (-not $complete) {
      $cleanup = & $state.NativeModule { param($Custody) Close-CrgAttributeNeutralContext -Custody $Custody } $state.ExecutionCustody
      if (-not $cleanup.Ok) { Write-Warning "hook projection acquisition cleanup retained files: $($cleanup.Reason)" }
      foreach ($directory in $state.Domains.Values) { foreach ($file in $directory.Files.Values) { if ($null -ne $file.Handle) { $file.Handle.Dispose() } } }
      for ($i = $state.Pins.Count - 1; $i -ge 0; $i--) { $state.Pins[$i].Handle.Dispose() }
    }
  }
}

function Assert-CrgCentralGuardCustody {
  param([object]$State)
  & $State.NativeModule {
    param($State)
    Assert-CrgPairedOperationLock -Lock $State.Lock
    Assert-CrgAttributeNeutralContextStable -Context @{ Custody = @{ DirectoryPins = $State.Pins.ToArray(); OwnedDirectories = @(); ControlFiles = @() } } -Boundary 'central hook guard'
    $execution = $State.ExecutionCustody
    Assert-CrgAttributeNeutralContextStable -Context @{ Custody = @{ DirectoryPins = $execution.DirectoryPins.ToArray(); OwnedDirectories = $execution.OwnedDirectories.ToArray(); ControlFiles = $execution.ControlFiles.ToArray() } } -Boundary 'admitted hook projection'
    foreach ($record in $execution.ControlFiles) {
      $actual = Get-CrgOwnedBinaryFileDigest -Record $record
      if ($actual.Length -ne $record.ExpectedLength -or -not [string]::Equals($actual.Sha256, $record.ExpectedSha256, [StringComparison]::Ordinal)) { throw 'admitted hook projection differs from retained bytes' }
    }
    foreach ($directory in $State.Domains.Values) {
      if ($null -eq $directory.Hooks) {
        $errorCode = 0; $probe = [CrgAttributeNeutral.NativeV1]::OpenReadDirectoryRelative($directory.Parent.Handle, 'hooks', [ref]$errorCode)
        try { if ($null -ne $probe -and -not $probe.IsInvalid -or $errorCode -ne 2) { throw 'previously absent hooks directory changed before publication' } }
        finally { if ($null -ne $probe) { $probe.Dispose() } }
        continue
      }
      foreach ($name in $directory.Files.Keys) {
        $record = $directory.Files[$name]; $errorCode = 0
        if ($record.Present) {
          if (-not [CrgAttributeNeutral.NativeV1]::PathNamesExactHandle($record.Path, $record.Handle, $false, [ref]$errorCode)) { throw "hook '$name' changed its exact identity" }
          $actual = Get-CrgOwnedBinaryFileDigest -Record $record
          if ($actual.Length -ne $record.Bytes.Length -or -not [string]::Equals($actual.Sha256, $record.Sha256, [StringComparison]::Ordinal)) { throw "hook '$name' bytes changed under custody" }
        } else {
          $probe = [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($directory.Hooks.Handle, $name, [ref]$errorCode)
          try { if ($null -ne $probe -and -not $probe.IsInvalid -or $errorCode -ne 2) { throw "previously absent hook '$name' changed before publication" } }
          finally { if ($null -ne $probe) { $probe.Dispose() } }
        }
      }
    }
  } $State
  Assert-CrgCentralGuardInventory -State $State
}

function Get-CrgCentralGuardBinding {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:public|private)\z', Options = 'None')][string]$Domain)
  $owners = @($script:CrgCentralGuardOwners.Values | Where-Object {
    [object]::ReferenceEquals($_.Project, $ProjectContext) -and [object]::ReferenceEquals($_.Lock, $OperationLock)
  })
  if ($owners.Count -ne 1) { throw 'hook selection requires one current guard owner for the exact project and operation lock' }
  $state = Get-CrgCentralGuardState -GuardCustody $owners[0].Owner
  Assert-CrgCentralGuardCustody -State $state
  # Admission sees ordinary effective configuration without the child override.
  # Bind the admitted value at execution: holding hook files alone cannot stop
  # local, global or included configuration from redirecting the next Git child.
  $hooks = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-git-operation -Name Get-CrgPairedGitHooksPath
  $actual = & $hooks -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $Domain
  if ($null -eq $actual -or -not [string]::Equals($actual.Value.State, 'unset', [StringComparison]::Ordinal)) { throw "$Domain effective core.hooksPath must be positively unset" }
  Assert-CrgCentralGuardCustody -State $state
  $directory = $state.Domains[$Domain]
  $path = Join-Path $directory.Parent.Path 'hooks'
  if (-not [string]::Equals($directory.Parent.Path, $ProjectContext.Domains[$Domain].CommonDir, [StringComparison]::Ordinal) -or
      ($null -ne $directory.Hooks -and -not [string]::Equals($directory.Hooks.Path, $path, [StringComparison]::Ordinal))) { throw 'hook selection differs from the retained domain namespace' }
  if ($null -eq $directory.Execution -or $directory.Execution.Path -isnot [string] -or
      -not [string]::Equals([IO.Path]::GetFileName($directory.Execution.Path), $Domain, [StringComparison]::Ordinal)) { throw 'hook execution projection is absent or selects another domain' }
  return $directory.Execution.Path
}

function Assert-CrgCentralPublicationGuards {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin,
    [Parameter(Mandatory = $true)][object]$GuardCustody)
  $state = Get-CrgCentralGuardState -GuardCustody $GuardCustody
  if (-not [object]::ReferenceEquals($state.Project, $ProjectContext) -or -not [object]::ReferenceEquals($state.Lock, $OperationLock) -or -not [string]::Equals($state.Origin, $Origin, [StringComparison]::Ordinal)) { throw 'publication guard context differs from its retained owner' }
  Assert-CrgCentralGuardCustody -State $state
  $hooks = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-git-operation -Name Get-CrgPairedGitHooksPath
  foreach ($domain in @('public', 'private')) {
    $actual = & $hooks -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $domain
    if ($null -eq $actual -or -not [string]::Equals($actual.Value.State, 'unset', [StringComparison]::Ordinal)) { throw "$domain effective core.hooksPath must be positively unset" }
  }
  if ($null -eq $CapturedInput -or $CapturedInput.Schema -ne 1 -or $CapturedInput.Indexes -isnot [System.Collections.IDictionary] -or
      $CapturedInput.PreparationSources -isnot [System.Collections.IDictionary]) { throw 'publication guard requires the complete captured paired input' }
  $tree = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-tree -Name Read-CrgPairedTreeBytes
  $null = & $tree -PublicTreeBytes $CapturedInput.Indexes.public.TreeBytes -PrivateTreeBytes $CapturedInput.Indexes.private.TreeBytes -PublicObjectFormat $ProjectContext.Domains.public.ObjectFormat -PrivateObjectFormat $ProjectContext.Domains.private.ObjectFormat -GoverningConfigBytes $CapturedInput.PreparationSources.governing.ConfigBytes -CandidateConfigBytes $CapturedInput.PreparationSources.candidate.ConfigBytes
  # The coordinator independently re-captures actual indexes, refs, messages and
  # prepared bytes at final publication. This parsed object is not that custody.
  Assert-CrgCentralGuardCustody -State $state
}

function Invoke-CrgCentralLfsPostCommit {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][object]$GuardCustody, [Parameter(Mandatory = $true)][string]$ExpectedPublicOid)
  $state = Get-CrgCentralGuardState -GuardCustody $GuardCustody
  if (-not [object]::ReferenceEquals($state.Project, $ProjectContext) -or -not [object]::ReferenceEquals($state.Lock, $OperationLock)) { throw 'Git LFS post-commit context differs from its retained guard owner' }
  Assert-CrgCentralGuardCustody -State $state
  if (-not $state.LfsEnabled) {
    return [pscustomobject]@{ Invoked = $false; ReadyForPublication = $false }
  }
  $lfs = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-git-operation -Name Invoke-CrgPairedGitLfsPostCommit
  $result = & $lfs -ProjectContext $ProjectContext -OperationLock $OperationLock -ExpectedPublicOid $ExpectedPublicOid
  Assert-CrgCentralGuardCustody -State $state
  return [pscustomobject]@{ Invoked = $true; Result = $result; ReadyForPublication = $false }
}

function Install-CrgCentralGuards {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$GuardCustody)
  $state = Get-CrgCentralGuardState -GuardCustody $GuardCustody
  if (-not [string]::Equals($state.Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) { throw 'central hook installation belongs only to reviewed first attachment' }
  Assert-CrgCentralGuardCustody -State $state
  foreach ($domain in @('public', 'private')) {
    $directory = $state.Domains[$domain]
    if ($null -eq $directory.Hooks) {
      $directory.Hooks = & $state.NativeModule {
        param($State, $Directory)
        $errorCode = 0
        $handle = [CrgAttributeNeutral.NativeV1]::CreateOwnedDirectoryRelative($Directory.Parent.Handle, 'hooks', [ref]$errorCode)
        if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryDirectory($handle)) {
          if ($null -ne $handle) { $handle.Dispose() }; throw "hook directory create-new refused (Win32 error $errorCode)"
        }
        $record = [pscustomobject]@{ Path = (Join-Path $Directory.Parent.Path 'hooks'); Handle = $handle; Label = 'created central hooks directory'; DeniesRename = $true }
        $State.Pins.Add($record)
        return $record
      } $state $directory
      foreach ($leaf in @($state.HookNames) + @('pre-commit.crg-sha256', 'pre-push.crg-sha256')) { $directory.Files[$leaf] = Read-CrgCentralGuardLeaf -State $state -Directory $directory.Hooks -Leaf $leaf }
    }
    $targets = @('pre-commit', 'pre-commit.crg-sha256')
    if ($domain -ceq 'public') { $targets += @('pre-push', 'pre-push.crg-sha256') }
    foreach ($leaf in $targets) {
      $prior = $directory.Files[$leaf]; $bytes = $state.Templates[$leaf]; $digest = Get-CrgCentralGuardDigest -Bytes $bytes
      if ($prior.Present -and [string]::Equals($prior.Sha256, $digest, [StringComparison]::Ordinal)) { continue }
      $record = & $state.NativeModule {
        param($State, $Directory, $Prior, $Leaf, $Bytes, $Digest)
        $created = $null; $published = $false; $moved = $false; $errorCode = 0
        $temporary = '.crg-hook-' + [guid]::NewGuid().ToString('N')
        $recovery = '.crg-prior-' + $Leaf + '-' + [guid]::NewGuid().ToString('N')
        try {
          Assert-CrgPairedOperationLock -Lock $State.Lock
          $created = [CrgAttributeNeutral.NativeV1]::CreatePublicationFileRelative($Directory.Hooks.Handle, $temporary, [ref]$errorCode)
          if ($null -eq $created -or $created.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($created)) { throw "hook candidate create-new refused (Win32 error $errorCode)" }
          if (-not [CrgAttributeNeutral.NativeV1]::WriteUtf8Exact($created, [Text.UTF8Encoding]::new($false, $true).GetString($Bytes), [ref]$errorCode)) { throw "hook durable write refused (Win32 error $errorCode)" }
          $actual = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $created }
          if ($actual.Length -ne $Bytes.Length -or -not [string]::Equals($actual.Sha256, $Digest, [StringComparison]::Ordinal)) { throw 'hook candidate differs from exact required bytes' }
          if ($Prior.Present) {
            if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($Prior.Handle, $Directory.Hooks.Handle, $recovery, [ref]$errorCode)) { throw "preceding hook could not move to recovery (Win32 error $errorCode)" }
            $moved = $true; $Prior.Path = Join-Path $Directory.Hooks.Path $recovery
            $State.RecoveryPaths.Add($Prior.Path)
          }
          if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($created, $Directory.Hooks.Handle, $Leaf, [ref]$errorCode)) { throw "hook no-replace publication failed (Win32 error $errorCode)" }
          $published = $true
          $result = [pscustomobject]@{ Leaf = $Leaf; Path = (Join-Path $Directory.Hooks.Path $Leaf); Handle = $created; Bytes = $Bytes; Present = $true; Sha256 = $Digest }
          if (-not [CrgAttributeNeutral.NativeV1]::PathNamesExactHandle($result.Path, $created, $false, [ref]$errorCode)) { throw 'published hook lost exact identity' }
          $created = $null
          return $result
        } catch {
          if ($moved -and -not $published) {
            if ([CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($Prior.Handle, $Directory.Hooks.Handle, $Leaf, [ref]$errorCode)) { $Prior.Path = Join-Path $Directory.Hooks.Path $Leaf }
            else { $_.Exception.Data['CrgHookRecoveryPath'] = $Prior.Path }
          }
          throw
        } finally {
          if ($null -ne $created) {
            if (-not $published -and -not $created.IsInvalid -and -not [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($created, $false, [ref]$errorCode)) { Write-Warning "central hook candidate remains at '$temporary' (Win32 error $errorCode)" }
            $created.Dispose()
          }
          # Recovery bytes remain on disk. No prior hook or attestation is erased.
          if ($published -and $null -ne $Prior.Handle) { $Prior.Handle.Dispose(); $Prior.Handle = $null }
        }
      } $state $directory $prior $leaf $bytes $digest
      $directory.Files[$leaf] = $record
    }
  }
  New-CrgCentralHookProjection -State $state
  Assert-CrgCentralGuardCustody -State $state
  return [pscustomobject]@{ Installed = $true; RecoveryPaths = $state.RecoveryPaths.ToArray(); ReadyForPublication = $false }
}

function Close-CrgCentralGuardCustody {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$GuardCustody)
  $state = Get-CrgCentralGuardState -GuardCustody $GuardCustody
  Assert-CrgCentralGuardCustody -State $state
  # The coordinator must establish actual child quiescence before release.
  # No mutable flag or stored review receipt can substitute for that boundary.
  foreach ($directory in $state.Domains.Values) { foreach ($file in $directory.Files.Values) { if ($null -ne $file.Handle) { $file.Handle.Dispose() } } }
  for ($i = $state.Pins.Count - 1; $i -ge 0; $i--) { $state.Pins[$i].Handle.Dispose() }
  $null = $script:CrgCentralGuardOwners.Remove($GuardCustody.Id)
  $cleanup = & $state.NativeModule { param($Custody) Close-CrgAttributeNeutralContext -Custody $Custody } $state.ExecutionCustody
  if (-not $cleanup.Ok) { throw "hook projection exact cleanup retained files: $($cleanup.Reason)" }
}

function Read-CrgCentralPushUpdates {
  param([AllowNull()][byte[]]$InputBytes, [string]$ObjectFormat)
  if ($null -eq $InputBytes -or $InputBytes.Length -gt 1048576) { throw 'pre-push requires explicit bounded stdin bytes' }
  $width = if ([string]::Equals($ObjectFormat, 'sha1', [StringComparison]::Ordinal)) { 40 } elseif ([string]::Equals($ObjectFormat, 'sha256', [StringComparison]::Ordinal)) { 64 } else { throw 'pre-push object format is unsupported' }
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($InputBytes)
  if ($text.Length -eq 0) { return ,([object[]]@()) }
  if (-not $text.EndsWith("`n", [StringComparison]::Ordinal) -or $text -match '[\x00-\x09\x0b-\x1f\x7f\ufeff]') { throw 'pre-push stdin is not complete strict LF-only records' }
  $pattern = '\A([^ ]+) ([0-9a-f]{' + $width + '}) (refs/(?:heads|tags)/[^ ]+) ([0-9a-f]{' + $width + '})\z'
  $updates = New-Object 'System.Collections.Generic.List[object]'
  $destinations = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($line in ($text.Substring(0, $text.Length - 1) -split "`n", 0)) {
    if ($line -cnotmatch $pattern) { throw 'pre-push record must identify public branch/tag updates with canonical object IDs' }
    $local = [string]$Matches[1]; $tip = [string]$Matches[2]; $remote = [string]$Matches[3]; $old = [string]$Matches[4]
    if (-not $destinations.Add($remote) -or $remote -match '\.\.|@\{|[~^:?*\[\\]' -or
        $remote.EndsWith('/', [StringComparison]::Ordinal) -or $remote.EndsWith('.', [StringComparison]::Ordinal) -or $remote.Contains('//') -or
        @($remote -split '/' | Where-Object { $_.StartsWith('.', [StringComparison]::Ordinal) -or $_.EndsWith('.lock', [StringComparison]::Ordinal) }).Count -ne 0) { throw 'pre-push destination ref is duplicated or malformed' }
    $delete = $tip -cmatch '\A0+\z'
    if (($delete -and -not [string]::Equals($local, '(delete)', [StringComparison]::Ordinal)) -or (-not $delete -and [string]::Equals($local, '(delete)', [StringComparison]::Ordinal))) { throw 'pre-push deletion marker disagrees with the local object identity' }
    $updates.Add([pscustomobject]@{ LocalRef = $local; TipOid = $tip; RemoteRef = $remote; RemoteOldOid = $old; Delete = $delete })
  }
  return ,$updates.ToArray()
}

function Read-CrgCentralHistoricalPair {
  param([object]$ProjectContext, [string]$ReceiptSha256, [string]$ExpectedOrigin)
  $retention = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-retention -Name Read-CrgCompletedPairRetention
  $record = & $retention.Module {
    param($Project, $Digest, $Origin)
    $record = Read-CrgRetentionRecord -ProjectContext $Project -ReceiptSha256 $Digest -ExpectedOrigin $Origin
    Assert-CrgRetentionAttachment -ProjectContext $Project -Fields $record.Receipt.Fields -Origin $record.Origin
    $fields = $record.Receipt.Fields
    $expected = @{ 'project-id' = $Project.Status.ProjectId; 'public-worktree' = $Project.Root
      'public-git-dir' = $Project.Domains.public.GitDir; 'public-common-dir' = $Project.Domains.public.CommonDir
      'private-git-dir' = $Project.Domains.private.GitDir; 'public-ref' = $Project.Domains.public.Ref; 'private-ref' = $Project.Domains.private.Ref }
    foreach ($name in $expected.Keys) { if (-not [string]::Equals($fields[$name], $expected[$name], [StringComparison]::Ordinal)) { throw "historical pair association differs at '$name'" } }
    $results = @{}
    foreach ($domain in @('public', 'private')) { $results[$domain] = Read-CrgRetentionDomainResult -ProjectContext $Project -Domain $domain -Fields $fields -Origin $record.Origin }
    if (-not [string]::Equals((Get-CrgRetentionRef -ProjectContext $Project -Domain public -Ref ('refs/crg-results/' + $fields['public-result'])), $fields['public-result'], [StringComparison]::Ordinal)) { throw 'historical public result lacks exact retained completion evidence' }
    # Validate retained evidence by canonical identity, not by rerunning an old
    # release's compiler or crediting historical PASS toward a new publication.
    $descriptorBytes = Read-CrgRetentionObject -ProjectContext $Project -Domain private -Oid $record.Entries['prepared-pair.txt'] -Type blob -Maximum $record.Bounds['prepared-pair.txt']
    $prepared = Get-CrgRetentionCommand -Module paired-review-input -Name Read-CrgPreparedPairDescriptorBytes
    $descriptor = & $prepared.Module {
      param($Bytes, $Digest, $Origin)
      Read-CrgPreparedDescriptorFields -Bytes $Bytes -ExpectedSha256 $Digest -Origin $Origin
    } $descriptorBytes (Get-CrgRetentionDigest -Bytes $descriptorBytes) $record.Origin
    if (-not [string]::Equals($descriptor.Fields['review-unit-sha256'], $fields['review-unit-sha256'], [StringComparison]::Ordinal) -or
        -not [string]::Equals($descriptor.Fields['public-object-format'], $Project.Domains.public.ObjectFormat, [StringComparison]::Ordinal) -or
        -not [string]::Equals($descriptor.Fields['private-object-format'], $Project.Domains.private.ObjectFormat, [StringComparison]::Ordinal)) { throw 'historical descriptor differs from the receipt unit or object formats' }
    $bindings = & $prepared.Module { Get-CrgPreparedBufferBindings }
    $buffers = @{}
    foreach ($name in $bindings.Keys) {
      $bytes = Read-CrgRetentionObject -ProjectContext $Project -Domain private -Oid $record.Entries[$name] -Type blob -Maximum $record.Bounds[$name]
      $binding = $bindings[$name] -split ':', 2
      $expectedDigest = if ($binding[0] -ceq 'unit') { $fields[$binding[1]] } else { $descriptor.Fields[$binding[1]] }
      if (-not [string]::Equals((Get-CrgRetentionDigest -Bytes $bytes), $expectedDigest, [StringComparison]::Ordinal)) { throw "historical evidence '$name' differs from its recorded digest" }
      if ($name -ceq 'review-unit.txt') { $buffers[$name] = $bytes }
    }
    $originCommands = Get-CrgRetentionOriginCommands -Origin $record.Origin
    $pins = @{ ReviewUnitBytes = $buffers['review-unit.txt']; DescriptorSha256 = $descriptor.DescriptorSha256
      DisplayDiffSha256 = $descriptor.Fields['display-diff-sha256']; PublicObjectFormat = $Project.Domains.public.ObjectFormat; PrivateObjectFormat = $Project.Domains.private.ObjectFormat }
    $grokModels = New-Object 'System.Collections.Generic.List[string]'
    foreach ($attempt in $record.Receipt.ReviewAttempts) {
      $stem = 'leg-' + $attempt.Leg + '-attempt-' + $attempt.Attempt
      $artifacts = @{}
      foreach ($binding in @(@('TranscriptSha256', '.transcript'), @('VerdictSha256', '.verdict'), @('ExhaustionSha256', '.exhaustion'))) {
        $digest = $attempt.($binding[0])
        if ([string]::Equals($digest, '-', [StringComparison]::Ordinal)) { continue }
        $name = $stem + $binding[1]
        $bytes = Read-CrgRetentionObject -ProjectContext $Project -Domain private -Oid $record.Entries[$name] -Type blob -Maximum $record.Bounds[$name]
        if (-not [string]::Equals((Get-CrgRetentionDigest -Bytes $bytes), $digest, [StringComparison]::Ordinal)) { throw 'historical review evidence differs from its receipt digest' }
        if ($binding[1] -cne '.transcript') { $artifacts[$binding[1]] = $bytes }
      }
      if ($attempt.ObservedExit -eq 0) {
        $reader = Get-CrgRetentionCommand -Module paired-governance -Name $originCommands.SuccessfulArtifact
        $successful = & $reader -Bytes $artifacts['.verdict'] @pins -ExpectedBackend $attempt.ActualProvider -ScheduledPassCount $attempt.ScheduledPassCount
        if ([string]::Equals($attempt.ActualProvider, 'grok', [StringComparison]::Ordinal)) { $grokModels.Add([string]$successful.RequestedModel + '|' + [string]$successful.Effort) }
      } else {
        if ([string]::Equals($attempt.ActualProvider, 'codex', [StringComparison]::Ordinal) -and -not $artifacts.ContainsKey('.verdict')) { throw 'historical Codex exhaustion lacks forensic verdict evidence' }
        if ($artifacts.ContainsKey('.verdict')) {
          $reader = Get-CrgRetentionCommand -Module paired-governance -Name $originCommands.Artifact
          $null = & $reader -Bytes $artifacts['.verdict'] @pins -ExpectedBackend $attempt.ActualProvider
        }
        $reader = Get-CrgRetentionCommand -Module paired-governance -Name $originCommands.Exhaustion
        $null = & $reader -Bytes $artifacts['.exhaustion'] @pins -ExpectedBackend $attempt.ActualProvider -ScheduledPassCount $attempt.ScheduledPassCount
      }
    }
    $readTree = Get-CrgRetentionCommand -Module central-context -Name Read-CrgCentralTreeBytes
    $trees = @{}
    foreach ($domain in @('public', 'private')) {
      $trees[$domain] = & $readTree -ProjectContext $Project -Domain $domain -TreeOid $results[$domain].Result.TreeOid
      $stored = Read-CrgRetentionObject -ProjectContext $Project -Domain private -Oid $record.Entries[$domain + '.tree'] -Type blob -Maximum $record.Bounds[$domain + '.tree']
      if (-not [string]::Equals((Get-CrgRetentionDigest -Bytes $stored), (Get-CrgRetentionDigest -Bytes $trees[$domain]), [StringComparison]::Ordinal)) { throw 'historical tree evidence differs from the exact result commit' }
    }
    $context = Get-CrgRetentionCommand -Module central-context -Name Read-CrgCentralBlobBytes
    $configs = & $context.Module {
      param($Project, $Fields, $Origin)
      $git = @("--git-dir=$($Project.Domains.private.GitDir)", "--work-tree=$($Project.Root)")
      $candidate = Get-CrgStatusBlob -Git $git -Commit $Fields['private-result'] -Path '.crg-project/project.conf' -Maximum 65536 -GitExe $Project.GitExe
      $governing = $candidate
      if ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal)) { $governing = Get-CrgStatusBlob -Git $git -Commit $Fields['private-parent'] -Path '.crg-project/project.conf' -Maximum 65536 -GitExe $Project.GitExe }
      return @{ Governing = $governing; Candidate = $candidate }
    } $Project $fields $record.Origin
    $pairedTree = Get-CrgRetentionCommand -Module paired-tree -Name Read-CrgPairedTreeBytes
    $null = & $pairedTree -PublicTreeBytes $trees.public -PrivateTreeBytes $trees.private -PublicObjectFormat $Project.Domains.public.ObjectFormat -PrivateObjectFormat $Project.Domains.private.ObjectFormat -GoverningConfigBytes $configs.Governing -CandidateConfigBytes $configs.Candidate
    # Every accepted Grok artifact is bound to the enablement of the
    # configuration that governed its review. A first attachment is governed
    # by the bootstrap `reviewer-policy default`, never by its candidate (which
    # $configs.Governing holds above for tree parsing), so no Grok success can
    # be authorized for that origin. The recorded model and effort are bound
    # to every identity the governing selection could have run (its profile's
    # historical mappings, and a legacy record's own model), not to the
    # current table: this guard runs under the current release and does not
    # load the retained release whose table may have mapped the profile
    # differently.
    if ($grokModels.Count -gt 0 -and -not [string]::Equals($record.Origin, 'paired-v1', [StringComparison]::Ordinal)) { throw 'historical first-attachment review cannot credit Grok under the bootstrap governing policy' }
    if ($grokModels.Count -gt 0) {
      $readConfig = Get-CrgRetentionCommand -Module private-governance -Name Read-CrgProjectConfigBytes
      $governingConfig = & $readConfig -Bytes $configs.Governing
      $allowed = @(& (Get-CrgRetentionCommand -Module private-governance -Name Get-CrgGrokAllowedIdentities) -Config $governingConfig)
      if (-not [string]::Equals($governingConfig.ReviewerPolicy, 'grok-fallback', [StringComparison]::Ordinal) -or $null -eq $governingConfig.Grok -or
          @($grokModels | Where-Object { -not [System.Linq.Enumerable]::Contains([string[]]$allowed, [string]$_, [System.StringComparer]::Ordinal) }).Count -gt 0) { throw 'historical Grok review lacks governing enablement or ran an identity its governing selection could not have run' }
    }
    return [pscustomobject]@{ Receipt = $record.Receipt; Origin = $record.Origin; Results = $results; PrivateRetentionOid = $record.CommitOid }
  } $ProjectContext $ReceiptSha256 $ExpectedOrigin
  return $record
}

function Invoke-CrgCentralPushCheck {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$InputBytes,
    [Parameter(Mandatory = $true)][string]$RemoteName, [Parameter(Mandatory = $true)][string]$RemoteLocation)
  foreach ($argument in @($RemoteName, $RemoteLocation)) {
    if ([string]::IsNullOrWhiteSpace($argument) -or $argument.Length -gt 16384 -or $argument -match '[\x00-\x1f\x7f]') { throw 'public push requires bounded native remote arguments' }
  }
  $updates = Read-CrgCentralPushUpdates -InputBytes $InputBytes -ObjectFormat $ProjectContext.Domains.public.ObjectFormat
  $guard = Open-CrgCentralGuardCustody -ProjectContext $ProjectContext -OperationLock $OperationLock -Origin paired-v1
  $state = Get-CrgCentralGuardState -GuardCustody $guard
  $retention = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-retention -Name Read-CrgCompletedPairRetention
  $historyPins = $null; $uncertain = $false
  try {
    $hooks = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-git-operation -Name Get-CrgPairedGitHooksPath
    foreach ($domain in @('public', 'private')) {
      $actual = & $hooks -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $domain
      if (-not [string]::Equals($actual.Value.State, 'unset', [StringComparison]::Ordinal)) { throw "$domain effective core.hooksPath must be positively unset before push" }
    }
    $historyPins = & $retention.Module { param($Project) Open-CrgRetentionContext -ProjectContext $Project } $ProjectContext
    $pending = & $ProjectContext.Runtime.ReadFile -Path (Join-Path $ProjectContext.Domains.public.GitDir 'crg-handoff') -Maximum 16384 -AllowAbsent
    if ($null -eq $pending -or $pending.Present -isnot [bool] -or $pending.Present) { throw 'public push refuses pending or indeterminate paired publication' }
    $pointerFile = & $ProjectContext.Runtime.ReadFile -Path (Join-Path $ProjectContext.Domains.public.GitDir 'crg-pair') -Maximum 256
    $readPointer = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-governance -Name Read-CrgCompletedPairPointerBytes
    $pointer = & $readPointer -Bytes $pointerFile.Bytes
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $completed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $next = $pointer.ReceiptSha256; $origin = $pointer.Origin; $successor = $null; $baseline = $null
    while ($null -ne $next) {
      if ($seen.Count -ge 100000 -or -not $seen.Add($next)) { throw 'completed-pair chain is cyclic or exceeds the supported history bound' }
      $record = Read-CrgCentralHistoricalPair -ProjectContext $ProjectContext -ReceiptSha256 $next -ExpectedOrigin $origin
      $fields = $record.Receipt.Fields
      if ($null -eq $successor) {
        foreach ($domain in @('public', 'private')) {
          if (-not [string]::Equals($fields[$domain + '-result'], $ProjectContext.Domains[$domain].Parent, [StringComparison]::Ordinal) -or
              -not [string]::Equals($fields[$domain + '-tree'], $ProjectContext.Domains[$domain].ParentTree, [StringComparison]::Ordinal)) { throw 'current project state differs from the completed-pair pointer' }
        }
      } else {
        foreach ($domain in @('public', 'private')) {
          if (-not [string]::Equals($fields[$domain + '-result'], $successor.Receipt.Fields[$domain + '-parent'], [StringComparison]::Ordinal) -or
              -not [string]::Equals($fields[$domain + '-tree'], $successor.Results[$domain].Parent.TreeOid, [StringComparison]::Ordinal)) { throw 'historical pair linkage differs from exact predecessor result and parent trees' }
        }
      }
      $null = $completed.Add($fields['public-result'])
      if ([string]::Equals($record.Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) { $baseline = $fields['public-parent']; $next = $null }
      else { $next = $fields['previous-pair']; $origin = ''; $successor = $record }
    }
    if ([string]::IsNullOrEmpty($baseline)) { throw 'completed-pair history has no validated first-attachment boundary' }
    $enumerate = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-git-operation -Name Get-CrgPairedGitOutgoingCommits
    $checked = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($update in $updates) {
      if ($update.Delete) { continue }
      $outgoing = & $enumerate -ProjectContext $ProjectContext -OperationLock $OperationLock -TipOid $update.TipOid -BoundaryOid $baseline
      foreach ($oid in $outgoing.Value.CommitOids) {
        if (-not $completed.Contains($oid)) { throw "public push contains post-attachment commit '$oid' without completed paired-review evidence" }
        $null = $checked.Add($oid)
      }
    }
    Assert-CrgCentralGuardCustody -State $state
    if ($state.LfsEnabled) {
      $lfs = Get-CrgCentralGuardCommand -ProjectContext $ProjectContext -Module paired-git-operation -Name Invoke-CrgPairedGitLfsPrePush
      $null = & $lfs -ProjectContext $ProjectContext -OperationLock $OperationLock -RemoteName $RemoteName -RemoteLocation $RemoteLocation -InputBytes $InputBytes
    }
    & $retention.Module {
      param($Project)
      foreach ($domain in @('public', 'private')) {
        if (-not [string]::Equals((Get-CrgRetentionRef -ProjectContext $Project -Domain $domain -Ref $Project.Domains[$domain].Ref), $Project.Domains[$domain].Parent, [StringComparison]::Ordinal)) { throw 'project branches changed during public push validation' }
      }
    } $ProjectContext
    Assert-CrgCentralGuardCustody -State $state
    return [pscustomobject]@{ CheckedUpdates = $updates.Count; CheckedCommits = $checked.Count; CompletedPairs = $seen.Count; LfsPrePush = $state.LfsEnabled; ValidationState = 'completed-public-history'; ReadyForPublication = $false }
  } catch {
    $failure = $_.Exception
    while ($null -ne $failure) {
      if ($failure.Data.Contains('CrgPairedProcessSession')) { $uncertain = $true; break }
      $failure = $failure.InnerException
    }
    if ($uncertain) { $_.Exception.Data['CrgCentralGuardCustody'] = $guard; $_.Exception.Data['CrgCentralHistoryPins'] = $historyPins }
    throw
  } finally {
    if (-not $uncertain) {
      if ($null -ne $historyPins) { foreach ($pin in $historyPins) { $pin.Handle.Dispose() } }
      Close-CrgCentralGuardCustody -GuardCustody $guard
    }
  }
}

Export-ModuleMember -Function Open-CrgCentralGuardCustody, Get-CrgCentralGuardBinding, Assert-CrgCentralPublicationGuards, Invoke-CrgCentralLfsPostCommit, Install-CrgCentralGuards, Close-CrgCentralGuardCustody, Invoke-CrgCentralPushCheck
