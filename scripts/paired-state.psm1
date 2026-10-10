# Bounded local publication records. The live coordinator owns review authority;
# these operations only preserve exact bytes and recoverable namespace changes.

function Get-CrgPairStateNative {
  param([object]$ProjectContext, [object]$OperationLock)
  $commands = @(Get-Command Assert-CrgPairedOperationLock -Module paired-diff -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  $relative = 'scripts/paired-diff.psm1'
  # Ordinal: -cne compares by culture and ignores characters such as U+00AD.
  if ($null -eq $ProjectContext -or $null -eq $ProjectContext.Runtime -or
      $ProjectContext.Runtime.Payloads -isnot [System.Collections.IDictionary] -or
      $relative -cnotin @($ProjectContext.Runtime.Payloads.Keys) -or $commands.Count -ne 1 -or
      -not [string]::Equals($commands[0].Module.Path, $ProjectContext.Runtime.Payloads[$relative].Path, [StringComparison]::Ordinal) -or
      -not [string]::Equals($OperationLock.PublicGitDirectory, $ProjectContext.Domains.public.GitDir, [StringComparison]::Ordinal)) { throw 'pair state requires the retained native module and actual project operation lock' }
  & $commands[0] -Lock $OperationLock
  return $commands[0].Module
}

function Invoke-CrgPairStateChange {
  param([object]$ProjectContext, [object]$OperationLock,
    [ValidatePattern('\A(?:crg-handoff|crg-pair|crg-attachment|crg-materialized|AGENTS\.md|CLAUDE\.md)\z', Options = 'None')][string]$Leaf,
    [AllowNull()][byte[]]$ExpectedBytes, [AllowNull()][byte[]]$Bytes, [switch]$Remove, [switch]$RootInstruction)
  if (([string]::Equals($Leaf, 'AGENTS.md', [StringComparison]::Ordinal) -or [string]::Equals($Leaf, 'CLAUDE.md', [StringComparison]::Ordinal)) -ne [bool]$RootInstruction -or ($RootInstruction -and $Remove)) { throw 'root instruction publication requires one fixed instruction file and cannot delete' }
  if ($null -eq $ExpectedBytes -and $Remove) { throw 'pair state deletion requires exact preceding bytes' }
  $maximum = if ($RootInstruction) { 16777216 } else { 65536 }
  if ((-not $Remove -and $null -eq $Bytes) -or $Bytes.Length -gt $maximum -or $ExpectedBytes.Length -gt $maximum) { throw 'pair state bytes are absent or exceed the record bound' }
  $native = Get-CrgPairStateNative -ProjectContext $ProjectContext -OperationLock $OperationLock
  return & $native {
    param($Project, $Lock, $Name, $Expected, $Candidate, $Delete, $Instruction)
    Initialize-CrgAttributeNeutralNative
    $pins = New-Object 'System.Collections.Generic.List[object]'
    $old = $null; $created = $null; $oldMoved = $false; $published = $false
    $stageLeaf = '.crg-state-' + [guid]::NewGuid().ToString('N')
    $priorLeaf = '.crg-prior-' + [guid]::NewGuid().ToString('N')
    $errorCode = 0
    try {
      $directory = if ($Instruction) { $Project.Root } else { $Project.Domains.public.GitDir }
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $directory -Pins $pins -DenyLeafRename
      $scratchParent = $parent
      if ($Instruction) {
        # Mandatory private classification covers every .crg-project child.
        # Ordinary child-directory custody keeps both renames on the root's
        # filesystem even when the private Git database occupies another volume.
        $scratchParent = Enter-CrgAttributeNeutralDirectoryChain -Path (Join-Path $Project.Root '.crg-project') -Pins $pins -DenyLeafRename
      }
      $path = Join-Path $parent.Path $Name
      $old = [CrgAttributeNeutral.NativeV1]::OpenPublicationFileRelative($parent.Handle, $Name, [ref]$errorCode)
      if ($null -eq $old -or $old.IsInvalid) {
        if ($null -ne $old) { $old.Dispose(); $old = $null }
        if ($errorCode -ne 2 -or $null -ne $Expected) { throw "pair state expected record is unavailable (Win32 error $errorCode)" }
      } else {
        if ($null -eq $Expected -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($old)) { throw 'pair state target is present unexpectedly or has invalid shape' }
        $actual = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $old }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $expectedDigest = ([BitConverter]::ToString($sha.ComputeHash($Expected))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        if ($actual.Length -ne $Expected.Length -or $actual.Sha256 -cne $expectedDigest) { throw 'pair state differs from the captured expected bytes' }
      }
      Assert-CrgPairedOperationLock -Lock $Lock
      if ($Delete) {
        if (-not [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($old, $false, [ref]$errorCode)) { throw "pair state exact deletion failed (Win32 error $errorCode)" }
        $old.Dispose(); $old = $null
        return
      }
      $created = [CrgAttributeNeutral.NativeV1]::CreatePublicationFileRelative($scratchParent.Handle, $stageLeaf, [ref]$errorCode)
      if ($null -eq $created -or $created.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($created)) { throw "pair state candidate creation failed (Win32 error $errorCode)" }
      $added = $false; $borrowed = $null; $stream = $null
      try {
        $created.DangerousAddRef([ref]$added)
        $borrowed = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($created.DangerousGetHandle(), $false)
        $stream = [IO.FileStream]::new($borrowed, [IO.FileAccess]::ReadWrite, 8192, $false)
        $stream.Write($Candidate, 0, $Candidate.Length); $stream.Flush($true)
      } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $borrowed) { $borrowed.Dispose() }
        if ($added) { $created.DangerousRelease() }
      }
      $actual = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $created }
      $sha = [Security.Cryptography.SHA256]::Create()
      try { $candidateDigest = ([BitConverter]::ToString($sha.ComputeHash($Candidate))).Replace('-', '').ToLowerInvariant() }
      finally { $sha.Dispose() }
      if ($actual.Length -ne $Candidate.Length -or $actual.Sha256 -cne $candidateDigest) { throw 'pair state candidate failed exact durable-byte validation' }
      if ($null -ne $old) {
        if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($old, $scratchParent.Handle, $priorLeaf, [ref]$errorCode)) { throw "pair state preceding record could not move aside (Win32 error $errorCode)" }
        $oldMoved = $true
      }
      if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($created, $parent.Handle, $Name, [ref]$errorCode)) { throw "pair state no-replace publication failed (Win32 error $errorCode)" }
      $published = $true
      if (-not [CrgAttributeNeutral.NativeV1]::PathNamesExactHandle($path, $created, $false, [ref]$errorCode)) { throw 'published pair state lost exact identity' }
      Assert-CrgPairedOperationLock -Lock $Lock
      if ($null -ne $old -and -not [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($old, $false, [ref]$errorCode)) { throw "pair state preceding record remains at '$(Join-Path $scratchParent.Path $priorLeaf)' (Win32 error $errorCode)" }
    } catch {
      # Recover only the exact held prior into a positively free destination.
      # A crash can leave the prior aside; the durable handoff still names the
      # immutable receipt and permits fresh-review recovery of pair bookkeeping.
      if ($oldMoved -and -not $published -and $null -ne $old) {
        if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($old, $parent.Handle, $Name, [ref]$errorCode)) {
          $_.Exception.Data['CrgPairStatePriorPath'] = Join-Path $scratchParent.Path $priorLeaf
        }
      }
      throw
    } finally {
      if ($null -ne $created) {
        if (-not $published -and -not $created.IsInvalid) { $null = [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($created, $false, [ref]$errorCode) }
        $created.Dispose()
      }
      if ($null -ne $old) { $old.Dispose() }
      for ($i = $pins.Count - 1; $i -ge 0; $i--) { $pins[$i].Handle.Dispose() }
    }
  } $ProjectContext $OperationLock $Leaf $ExpectedBytes $Bytes ([bool]$Remove) ([bool]$RootInstruction)
}

function Write-CrgPairState {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:crg-handoff|crg-pair|crg-attachment|crg-materialized)\z', Options = 'None')][string]$Leaf,
    [AllowNull()][byte[]]$ExpectedBytes, [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
  Invoke-CrgPairStateChange @PSBoundParameters
}

function Remove-CrgPairHandoff {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$ExpectedBytes)
  Invoke-CrgPairStateChange @PSBoundParameters -Leaf crg-handoff -Remove
}

function Write-CrgRootInstruction {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:AGENTS\.md|CLAUDE\.md)\z', Options = 'None')][string]$Name,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$ExpectedBytes,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
  # Unlike initial metadata, instructions require a known existing baseline.
  # An absent file is a working deletion, never permission to restore a root.
  if ($null -eq $ExpectedBytes) { throw 'instruction materialization requires exact existing working bytes' }
  Invoke-CrgPairStateChange -ProjectContext $ProjectContext -OperationLock $OperationLock -Leaf $Name -ExpectedBytes $ExpectedBytes -Bytes $Bytes -RootInstruction
}

Export-ModuleMember -Function Write-CrgPairState, Remove-CrgPairHandoff, Write-CrgRootInstruction
