# Ordinary two-index staging. Classification precedes writes; staging is not a
# review receipt or an atomic transaction across the two Git databases.

function Get-CrgStageCommand {
  param([object]$Runtime, [string]$Module, [string]$Name)
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  $relative = 'scripts/' + $Module + '.psm1'
  if ($Runtime.Payloads -isnot [Collections.IDictionary] -or $relative -cnotin @($Runtime.Payloads.Keys) -or
      $commands.Count -ne 1 -or -not [string]::Equals($commands[0].Module.Path, $Runtime.Payloads[$relative].Path, [StringComparison]::OrdinalIgnoreCase)) {
    throw "staging requires the retained '$Module/$Name' command"
  }
  return $commands[0]
}

function Read-CrgStageWorkingLeaf {
  param([object]$WorkingReads, [object]$ReadCommand, [string]$Root, [string]$Path,
    [bool]$CaptureBytes, [Collections.Generic.List[object]]$Pins)
  return & $ReadCommand.Module {
    param($Owner, $Reader, $Root, $RelativePath, $Capture, $Pins)
    $state = Get-CrgOperationReadState -Owner $Owner
    Assert-CrgOperationReadState -State $state
    $parent = Get-CrgOperationReadDirectory -State $state -Path $Root
    $parts = @($RelativePath -split '/', 0)
    for ($i = 0; $i -lt $parts.Count; $i++) {
      $leaf = $parts[$i]; $path = Join-Path $parent.Path $leaf; $errorCode = 0; $probe = $null
      try {
        $probe = [CrgAttributeNeutral.NativeV1]::OpenReadDirectoryRelative($parent.Handle, $leaf, [ref]$errorCode)
        if ($null -ne $probe -and -not $probe.IsInvalid) {
          if (-not [CrgAttributeNeutral.NativeV1]::IsOrdinaryDirectory($probe)) { throw 'staging refuses a reparse or nonordinary working directory' }
          $parent = Get-CrgOperationReadDirectory -State $state -Path $path
          if (-not [CrgAttributeNeutral.NativeV1]::SameIdentity($probe, $parent.Handle)) { throw 'staging working directory changed during retained acquisition' }
          if ($i -eq $parts.Count - 1) { return [pscustomobject]@{ Kind = 'directory'; Bytes = $null } }
          continue
        }
        if ($errorCode -in @(2, 3)) { return [pscustomobject]@{ Kind = 'absent'; Bytes = $null } }
        if ($errorCode -ne 267) { throw "staging cannot classify the working path (Win32 error $errorCode)" }
      } finally { if ($null -ne $probe) { $probe.Dispose() } }
      $file = [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($parent.Handle, $leaf, [ref]$errorCode)
      if ($null -eq $file -or $file.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryFile($file)) {
        if ($null -ne $file) { $file.Dispose() }
        throw "staging requires an ordinary no-follow working file (Win32 error $errorCode)"
      }
      $Pins.Add($file)
      # A directory-to-file replacement positively removes old descendant paths.
      if ($i -lt $parts.Count - 1) { return [pscustomobject]@{ Kind = 'absent'; Bytes = $null } }
      if ($Capture) {
        $record = & $Reader -Path $path -Maximum 16777216
        if ($null -eq $record -or $record.Present -ne $true -or $record.Bytes -isnot [byte[]]) { throw 'private staging lost captured ordinary bytes' }
        return [pscustomobject]@{ Kind = 'file'; Bytes = [byte[]]$record.Bytes.Clone() }
      }
      return [pscustomobject]@{ Kind = 'file'; Bytes = $null }
    }
    throw 'staging working path has no leaf'
  } -Owner $WorkingReads -Reader $WorkingReads.Runtime.ReadFile -Root $Root -RelativePath $Path -Capture $CaptureBytes -Pins $Pins
}

function Get-CrgPairedStageIndexState {
  param([object]$Operation)
  $states = [ordered]@{}
  foreach ($domain in @('public', 'private')) {
    $path = $Operation.ProjectContext.Domains[$domain].IndexPath
    try {
      $record = & $Operation.Runtime.ReadFile -Path $path -Maximum 67108864 -AllowAbsent
      if ($null -eq $record -or $record.Present -isnot [bool] -or $record.Bytes -isnot [byte[]]) { throw 'index acquisition returned no complete record' }
      $sha = [Security.Cryptography.SHA256]::Create()
      try { $digest = if ($record.Present) { ([BitConverter]::ToString($sha.ComputeHash($record.Bytes))).Replace('-', '').ToLowerInvariant() } else { $null } }
      finally { $sha.Dispose() }
      $states[$domain] = [pscustomobject]@{ Path = $path; State = if ($record.Present) { 'present' } else { 'absent' }; Sha256 = $digest }
    } catch { $states[$domain] = [pscustomobject]@{ Path = $path; State = 'unavailable'; Sha256 = $null } }
  }
  return $states
}

function Invoke-CrgPairedStage {
  [CmdletBinding(DefaultParameterSetName = 'Paths')]
  param([Parameter(Mandatory = $true)][object]$Operation,
    [Parameter(Mandatory = $true, ParameterSetName = 'All')][switch]$All,
    [Parameter(Mandatory = $true, ParameterSetName = 'Paths')][ValidateNotNullOrEmpty()][string[]]$Paths,
    [Parameter(ParameterSetName = 'Paths')][switch]$PendingAttachment)
  $pendingStage = [bool]$PendingAttachment
  $expectedState = if ($pendingStage) { 'held-pending-attachment-candidate' } else { 'held-project-and-preceding-pair' }
  if ($null -eq $Operation -or $Operation.ValidationState -cne $expectedState -or
      $null -eq $Operation.ReadOwner -or $null -eq $Operation.OperationLock -or $null -eq $Operation.GitExecutableOwner -or
      ($PSCmdlet.ParameterSetName -ceq 'All' -and (-not $All -or $pendingStage)) -or
      ($pendingStage -and $null -eq $Operation.GuardCustody)) { throw 'staging requires the current admitted operation and explicit selection' }
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext
  $commands = @{}
  foreach ($item in @(
    @{ Module = 'private-governance'; Names = @('Read-CrgProjectConfigBytes', 'Get-CrgPathOwnership') },
    @{ Module = 'central-context'; Names = @('Read-CrgCentralPreparationSource', 'Read-CrgCentralBlobBytes') },
    @{ Module = 'central-guards'; Names = @('Open-CrgCentralGuardCustody', 'Get-CrgCentralGuardBinding', 'Close-CrgCentralGuardCustody') },
    @{ Module = 'paired-tree'; Names = @('Read-CrgGitTreeBytes') },
    @{ Module = 'paired-operation'; Names = @('Open-CrgPairedOperationReads', 'Assert-CrgPairedOperationReads', 'Release-CrgPairedOperationReadFiles', 'Close-CrgPairedOperationReads') },
    @{ Module = 'paired-git-operation'; Names = @('Get-CrgPairedGitStageInventory', 'Set-CrgPairedGitPrivateIndex', 'Add-CrgPairedGitPublicPaths', 'Remove-CrgPairedGitIndexPaths') }
  )) { foreach ($name in $item.Names) { $commands[$name] = Get-CrgStageCommand -Runtime $runtime -Module $item.Module -Name $name } }
  $workingReads = $null; $guard = $null; $ownsGuard = -not $pendingStage
  $pins = [Collections.Generic.List[object]]::new(); $preserveCustody = $false; $writesStarted = $false
  try {
    $common = @{ ProjectContext = $project; OperationLock = $Operation.OperationLock }
    if ($pendingStage) { $guard = $Operation.GuardCustody }
    else { $guard = & $commands['Open-CrgCentralGuardCustody'] @common -Origin paired-v1 }
    foreach ($domain in @('public', 'private')) { $null = & $commands['Get-CrgCentralGuardBinding'] @common -Domain $domain }
    $before = Get-CrgPairedStageIndexState -Operation $Operation
    if ($before.public.State -cne 'present' -or $before.private.State -cne 'present') { throw 'staging requires both existing fixed indexes before classification' }
    $privateInventory = @((& $commands['Get-CrgPairedGitStageInventory'] @common -Domain private -Kind Tracked).Value)
    if ($pendingStage) {
      # Ordinal: -ceq, Select-Object -Unique and @{} keys compare by culture and ignore characters such as U+00AD.
      $governingConfigEntry = @($privateInventory | Where-Object { [string]::Equals($_.Path, '.crg-project/project.conf', [StringComparison]::Ordinal) })
      if ($governingConfigEntry.Count -gt 1 -or ($governingConfigEntry.Count -eq 1 -and $governingConfigEntry[0].Mode -cnotin @('100644', '100755'))) { throw 'pending attachment staged project configuration is malformed' }
      if ($governingConfigEntry.Count -eq 1) {
        $governingConfigBytes = & $commands['Read-CrgCentralBlobBytes'] -ProjectContext $project -Domain private -BlobOid $governingConfigEntry[0].Oid -Maximum 65536
        $governingConfig = & $commands['Read-CrgProjectConfigBytes'] -Bytes $governingConfigBytes
        $source = [pscustomobject]@{ Config = $governingConfig; ConfigBytes = $governingConfigBytes }
      } else { $source = $null }
    } else {
      $source = & $commands['Read-CrgCentralPreparationSource'] -ProjectContext $project -PublicTreeOid $project.Domains.public.ParentTree -PrivateTreeOid $project.Domains.private.ParentTree
    }
    [string[]]$selection = @()
    if (-not $All) { $selection = [string[]]$Paths.Clone() }
    $configPath = '.crg-project/project.conf'; $configSelected = [bool]$All
    foreach ($path in $selection) {
      if ([string]::Equals($configPath, $path, [StringComparison]::Ordinal) -or $configPath.StartsWith($path + '/', [StringComparison]::Ordinal)) { $configSelected = $true }
    }
    if ($pendingStage -and $null -eq $source -and -not $configSelected) { throw 'pending attachment staging requires explicit selection of the missing project configuration' }
    $roots = @([System.Linq.Enumerable]::Distinct([string[]]@($project.Root, $project.Domains.public.GitDir, $project.Domains.public.CommonDir, $project.Domains.private.GitDir), [StringComparer]::Ordinal))
    # Working files use a separate owner: releasing mutable index-read leases
    # must not release the captured config or selected public/private file pins.
    $workingReads = & $commands['Open-CrgPairedOperationReads'] -Runtime $runtime -OperationLock $Operation.OperationLock -ProjectRoots $roots -ExecutableReads @($Operation.GitExecutableOwner)
    # Unselected working config is not part of the resulting staged candidate.
    # Using it here can drop a staged reservation before public Git filters run.
    if ($configSelected) {
      $candidate = & $workingReads.Runtime.ReadFile -Path (Join-Path $project.Root $configPath) -Maximum 65536
      $candidateBytes = [byte[]]$candidate.Bytes.Clone()
    } else {
      $entry = @($privateInventory | Where-Object { [string]::Equals($_.Path, $configPath, [StringComparison]::Ordinal) })
      if ($entry.Count -ne 1 -or $entry[0].Mode -cnotin @('100644', '100755')) { throw 'unselected project configuration must be an existing regular private index entry' }
      $candidateBytes = & $commands['Read-CrgCentralBlobBytes'] -ProjectContext $project -Domain private -BlobOid $entry[0].Oid -Maximum 65536
    }
    $config = & $commands['Read-CrgProjectConfigBytes'] -Bytes $candidateBytes
    if ($pendingStage -and $null -eq $source) {
      # No private configuration exists when migration failed before its first
      # write. The explicitly selected working configuration establishes both
      # sides of this initial classification; every preserved private entry is
      # still required below to remain private under that exact configuration.
      $source = [pscustomobject]@{ Config = $config; ConfigBytes = $candidateBytes }
    }
    $privateSelectors = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($path in @('.crg-project', 'AGENTS.md', 'CLAUDE.md', 'CROSS-REVIEW-VALUES.md', 'PROJECT-MODE.md', 'PLAN.md', 'History.md') +
        @($source.Config.PrivateDirectories) + @($source.Config.PrivateFiles) + @($config.PrivateDirectories) + @($config.PrivateFiles)) { $null = $privateSelectors.Add($path) }
    $null = & $commands['Get-CrgPathOwnership'] -GoverningConfigBytes $source.ConfigBytes -CandidateConfigBytes $candidateBytes -Paths $selection
    $inventories = @{
      public = (& $commands['Get-CrgPairedGitStageInventory'] @common -Domain public -Kind Tracked).Value
      private = $privateInventory
      untracked = (& $commands['Get-CrgPairedGitStageInventory'] @common -Domain public -Kind Untracked).Value
      ignored = (& $commands['Get-CrgPairedGitStageInventory'] @common -Domain public -Kind Ignored -Paths @($privateSelectors | ForEach-Object { $_ })).Value
    }
    $allPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $tracked = @{ public = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase); private = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase) }
    $publicUntracked = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @('public', 'private', 'untracked', 'ignored')) {
      foreach ($entry in $inventories[$name]) {
        $null = $allPaths.Add($entry.Path)
        if ($name -cin @('public', 'private')) { $tracked[$name].Add($entry.Path, $entry) }
        if ($name -ceq 'untracked') { $null = $publicUntracked.Add($entry.Path) }
      }
    }
    $oldPrivate = if ($pendingStage) { @() }
      else { & $commands['Read-CrgGitTreeBytes'] -Bytes $source.PrivateTreeBytes -ObjectFormat $project.Domains.private.ObjectFormat }
    foreach ($entry in $oldPrivate) { if ($entry.Mode -cne '040000') { $null = $allPaths.Add($entry.Path) } }
    $ownership = & $commands['Get-CrgPathOwnership'] -GoverningConfigBytes $source.ConfigBytes -CandidateConfigBytes $candidateBytes -Paths @($allPaths | ForEach-Object { $_ })
    $owners = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase); foreach ($entry in $ownership) { $owners.Add($entry.Path, $entry.Ownership) }
    foreach ($entry in @($oldPrivate) + @($inventories.private)) {
      if ($entry.Mode -cne '040000' -and $owners[$entry.Path] -cne 'private') { throw "existing private tracked path '$($entry.Path)' requires explicit configuration mapping" }
    }
    $publicAdd = [Collections.Generic.List[string]]::new(); $publicRemove = [Collections.Generic.List[string]]::new()
    $privateAdd = [Collections.Generic.List[object]]::new(); $privateRemove = [Collections.Generic.List[object]]::new()
    $selected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); [long]$privateBytes = 0
    foreach ($entry in $ownership) {
      # Literal file selectors can enumerate a replacement directory's children.
      # Such public children still require ordinary public ignore eligibility.
      if ($entry.Ownership -ceq 'public' -and -not $tracked.public.ContainsKey($entry.Path) -and -not $publicUntracked.Contains($entry.Path)) { continue }
      $include = [bool]$All
      foreach ($path in $selection) { if ([string]::Equals($entry.Path, $path, [StringComparison]::Ordinal) -or $entry.Path.StartsWith($path + '/', [StringComparison]::Ordinal)) { $include = $true; $null = $selected.Add($path) } }
      if (-not $include) { continue }
      if ($pendingStage -and $entry.Ownership -cne 'private') { throw "pending attachment staging requires private ownership for selected path '$($entry.Path)'" }
      $hidden = $false
      foreach ($domain in @('public', 'private')) {
        if ($tracked[$domain].ContainsKey($entry.Path) -and ($tracked[$domain][$entry.Path].SkipWorktree -or $tracked[$domain][$entry.Path].AssumeUnchanged)) { $hidden = $true }
      }
      # Git's invisible working entries must not become accidental deletions.
      # Explicit selection requires resolving the visibility flag first.
      if ($hidden) {
        if (-not $All -or $entry.Ownership -ceq 'private') { throw "selected/private path '$($entry.Path)' has skip-worktree or assume-unchanged state requiring explicit resolution" }
        continue
      }
      $leaf = Read-CrgStageWorkingLeaf -WorkingReads $workingReads -ReadCommand $commands['Open-CrgPairedOperationReads'] -Root $project.Root -Path $entry.Path -CaptureBytes:($entry.Ownership -ceq 'private') -Pins $pins
      if ($entry.Ownership -ceq 'private') {
        if ($tracked.public.ContainsKey($entry.Path)) { $publicRemove.Add($entry.Path) }
        if ($leaf.Kind -ceq 'file') {
          $mode = '100644'
          foreach ($domain in @('public', 'private')) {
            if ($tracked[$domain].ContainsKey($entry.Path)) {
              $mode = $tracked[$domain][$entry.Path].Mode
              if ($mode -cnotin @('100644', '100755')) { throw 'private staging cannot reinterpret a tracked nonregular leaf' }
            }
          }
          $privateBytes += $leaf.Bytes.Length
          if ($privateBytes -gt 536870912) { throw 'private working capture exceeds the combined bound' }
          $privateAdd.Add([pscustomobject]@{ Path = $entry.Path; Mode = $mode; Bytes = $leaf.Bytes })
        } elseif ($tracked.private.ContainsKey($entry.Path)) {
          $privateRemove.Add([pscustomobject]@{ Path = $entry.Path; Mode = '0'; Bytes = $null })
        }
      } elseif ($leaf.Kind -ceq 'file' -or ($leaf.Kind -ceq 'directory' -and $tracked.public.ContainsKey($entry.Path) -and $tracked.public[$entry.Path].Mode -ceq '160000')) {
        $publicAdd.Add($entry.Path)
      } elseif ($tracked.public.ContainsKey($entry.Path)) { $publicRemove.Add($entry.Path) }
    }
    foreach ($path in $selection) { if (-not $selected.Contains($path)) { throw "selected literal path '$path' has no tracked or eligible untracked leaf" } }
    & $commands['Assert-CrgPairedOperationReads'] -Owner $workingReads
    & $commands['Assert-CrgPairedOperationReads'] -Owner $Operation.ReadOwner
    & $commands['Release-CrgPairedOperationReadFiles'] -Owner $Operation.ReadOwner
    $writesStarted = $true
    # Remove old leaf entries first for legitimate file/directory transitions.
    # Public exclusions remain in place even when staging only selected paths.
    $null = & $commands['Remove-CrgPairedGitIndexPaths'] @common -Domain public -Paths $publicRemove.ToArray()
    $null = & $commands['Set-CrgPairedGitPrivateIndex'] @common -Entries @($privateRemove.ToArray() + $privateAdd.ToArray())
    $exclusions = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $ownership) {
      if ($entry.Ownership -cne 'private') { continue }
      $publicDescendant = $false
      foreach ($path in $publicAdd) { if ($path.StartsWith($entry.Path + '/', [StringComparison]::Ordinal)) { $publicDescendant = $true; break } }
      # A former private file can become a directory containing public leaves;
      # a literal Git exclusion otherwise reserves descendants too. Explicit
      # private-directory reservations are added separately below.
      if (-not $publicDescendant) { $null = $exclusions.Add($entry.Path) }
    }
    foreach ($path in @($source.Config.PrivateDirectories) + @($config.PrivateDirectories)) { $null = $exclusions.Add($path) }
    $null = & $commands['Add-CrgPairedGitPublicPaths'] @common -Paths $publicAdd.ToArray() -PrivateExclusions @($exclusions | ForEach-Object { $_ })
    & $commands['Assert-CrgPairedOperationReads'] -Owner $workingReads
    $after = Get-CrgPairedStageIndexState -Operation $Operation
    if ($after.public.State -cne 'present' -or $after.private.State -cne 'present') { throw 'staging completed Git writes but cannot acquire both resulting indexes' }
    return [pscustomobject]@{ PublicPaths = $publicAdd.ToArray(); PublicRemovedPaths = $publicRemove.ToArray()
      PrivatePaths = @($privateRemove.ToArray() + $privateAdd.ToArray() | ForEach-Object { $_.Path })
      Before = $before; After = $after; ValidationState = 'staged-two-indexes'; ReadyForPublication = $false }
  } catch {
    $failure = $_.Exception
    while ($null -ne $failure) {
      if ($failure.Data.Contains('CrgPairedProcessSession') -or $failure.Data.Contains('CrgPairedGitOperationState') -or
          $failure.Data.Contains('CrgCentralGuardCustody') -or $failure.Data.Contains('CrgUncertainGitChild')) { $preserveCustody = $true; break }
      $failure = $failure.InnerException
    }
    if ($preserveCustody) {
      $_.Exception.Data['CrgPairedStageReadOwner'] = $workingReads; $_.Exception.Data['CrgPairedStagePins'] = $pins
      $_.Exception.Data['CrgPairedStageOperation'] = $Operation
      if ($null -ne $guard) { $_.Exception.Data['CrgCentralGuardCustody'] = $guard }
    } elseif ($writesStarted) {
      $state = Get-CrgPairedStageIndexState -Operation $Operation
      $_.Exception.Data['CrgPairedStageIndexState'] = $state
      Write-Host "[paired-stage] partial failure: public index=$($state.public.State), private index=$($state.private.State); no rollback was attempted."
    }
    throw
  } finally {
    if (-not $preserveCustody) {
      try { if ($ownsGuard -and $null -ne $guard) { & $commands['Close-CrgCentralGuardCustody'] -GuardCustody $guard } }
      finally {
        foreach ($pin in $pins) { $pin.Dispose() }
        if ($null -ne $workingReads) { & $commands['Close-CrgPairedOperationReads'] -Owner $workingReads }
      }
    }
  }
}

Export-ModuleMember -Function Invoke-CrgPairedStage
