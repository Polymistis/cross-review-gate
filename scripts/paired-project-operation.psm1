# Attached-project operation admission. A preceding receipt identifies governance;
# only a new owned review can authorize a subsequent publication.

function Get-CrgProjectOperationCommand {
  param([string]$Module, [string]$Name)
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($commands.Count -ne 1) { throw "project operation requires one retained '$Module/$Name' command" }
  return $commands[0]
}

function Open-CrgPairedProjectOperation {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo,
    [Parameter(Mandatory = $true)][object]$Runtime, [switch]$Recovery)
  if ($null -eq $Runtime -or $Runtime.ReadFile -isnot [scriptblock] -or
      $Runtime.Id -cnotmatch '\A[0-9a-f]{64}\z' -or $Runtime.Payloads -isnot [System.Collections.IDictionary]) { throw 'project operation requires the retained launcher runtime' }
  $capture = Get-CrgProjectOperationCommand -Module central-context -Name Get-CrgCentralProjectContext
  $readLine = & $capture.Module { Get-Command Get-CrgStatusGitLine -CommandType Function }
  $assertPath = & $capture.Module { Get-Command Assert-CrgContextAbsolutePath -CommandType Function }
  & $assertPath -Path $TargetRepo
  $gitExe = & $capture.Module { Get-CrgCentralGitExecutable }
  $publicArguments = @('-C', $TargetRepo)
  $commands = @{}
  foreach ($item in @(
    @{ Module = 'paired-diff'; Names = @('Open-CrgPairedOperationLock', 'Close-CrgPairedOperationLock') },
    @{ Module = 'paired-operation'; Names = @('Open-CrgPairedOperationReads', 'Assert-CrgPairedOperationReads', 'Close-CrgPairedOperationReads', 'Open-CrgPairedExecutableRead', 'Close-CrgPairedExecutableRead') },
    @{ Module = 'private-governance'; Names = @('Read-CrgAttachmentBytes') },
    @{ Module = 'paired-governance'; Names = @('Read-CrgCompletedPairPointerBytes') },
    @{ Module = 'paired-retention'; Names = @('Read-CrgCompletedPairRetention') }
  )) { foreach ($name in $item.Names) { $commands[$name] = Get-CrgProjectOperationCommand -Module $item.Module -Name $name } }
  $roots = New-Object 'System.Collections.Generic.List[string]'
  $lock = $null; $reads = $null; $initialReads = $null; $gitOwner = $null; $complete = $false; $retainOwners = $false
  try {
    # Installed Git may legitimately have hard-linked executable aliases. Hold
    # a dedicated read-only owner before any Git probe; project/payload files
    # keep the stronger single-link ownership required for mutation and cleanup.
    $gitOwner = & $commands['Open-CrgPairedExecutableRead'] -Path $gitExe
    $root = (& $readLine -Arguments ($publicArguments + @('rev-parse', '--show-toplevel')) -GitExe $gitExe).Replace('/', '\')
    $gitDir = (& $readLine -Arguments ($publicArguments + @('rev-parse', '--absolute-git-dir')) -GitExe $gitExe).Replace('/', '\')
    $commonDir = (& $readLine -Arguments ($publicArguments + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $gitExe).Replace('/', '\')
    if (-not [string]::Equals($TargetRepo, $root, [StringComparison]::OrdinalIgnoreCase)) { throw 'project operation target is not the actual public worktree root' }
    foreach ($path in @($root, $gitDir, $commonDir)) {
      & $assertPath -Path $path
      if (-not $roots.Contains($path)) { $roots.Add($path) }
    }
    $lock = & $commands['Open-CrgPairedOperationLock'] -PublicGitDirectory $gitDir
    $initialReads = & $commands['Open-CrgPairedOperationReads'] -Runtime $Runtime -OperationLock $lock -ProjectRoots $roots.ToArray() -ExecutableReads @($gitOwner)
    $attachmentFile = & $initialReads.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-attachment') -Maximum 16384 -AllowAbsent:$Recovery
    $attachmentLeaf = 'crg-attachment'
    if (-not $attachmentFile.Present) {
      $attachmentLeaf = 'crg-attachment-pending'
      $attachmentFile = & $initialReads.Runtime.ReadFile -Path (Join-Path $gitDir $attachmentLeaf) -Maximum 16384
    }
    $attachment = & $commands['Read-CrgAttachmentBytes'] -Bytes $attachmentFile.Bytes
    if (-not [string]::Equals($attachment.RuntimeStore, $Runtime.Store, [StringComparison]::OrdinalIgnoreCase)) { throw 'project attachment selects another runtime store' }
    if (-not $roots.Contains($attachment.PrivateGitDir)) { $roots.Add($attachment.PrivateGitDir) }
    # Acquire the expanded, explicitly named roots before releasing discovery
    # leases. The original launcher never owns mutable project leaf streams.
    $reads = & $commands['Open-CrgPairedOperationReads'] -Runtime $Runtime -OperationLock $lock -ProjectRoots $roots.ToArray() -ExecutableReads @($gitOwner)
    $currentAttachment = & $reads.Runtime.ReadFile -Path (Join-Path $gitDir $attachmentLeaf) -Maximum 16384
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$attachmentFile.Bytes, [byte[]]$currentAttachment.Bytes)) { throw 'project attachment changed during operation custody acquisition' }
    & $commands['Close-CrgPairedOperationReads'] -Owner $initialReads; $initialReads = $null
    if ($Recovery) {
      $pendingCapture = Get-CrgProjectOperationCommand -Module first-attachment-context -Name Get-CrgCentralFirstAttachmentProjectContext
      $project = & $pendingCapture -TargetRepo $TargetRepo -Context $reads.Runtime -AttachmentBytes $attachmentFile.Bytes -PendingRecovery
    } else { $project = & $capture -TargetRepo $TargetRepo -Context $reads.Runtime }
    # Ordinal: -cne compares by culture and ignores characters such as U+00AD.
    if (-not [string]::Equals($project.Domains.public.GitDir, $gitDir, [StringComparison]::Ordinal) -or
        -not [string]::Equals($project.Domains.public.CommonDir, $commonDir, [StringComparison]::Ordinal) -or
        -not [string]::Equals($project.Domains.private.GitDir, $attachment.PrivateGitDir, [StringComparison]::Ordinal)) { throw 'captured project namespace differs from the held operation roots' }
    $pending = & $reads.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-handoff') -Maximum 16384 -AllowAbsent
    if ($Recovery) {
      if ($null -eq $pending -or -not $pending.Present -or $Runtime.ResumeHandoffSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'recovery admission requires the selected exact handoff' }
      $sha = [Security.Cryptography.SHA256]::Create()
      try { $digest = ([BitConverter]::ToString($sha.ComputeHash($pending.Bytes))).Replace('-', '').ToLowerInvariant() }
      finally { $sha.Dispose() }
      if ($digest -cne $Runtime.ResumeHandoffSha256) { throw 'handoff changed after recorded runtime selection' }
      $pointer = & $reads.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-pair') -Maximum 256 -AllowAbsent
      & $commands['Assert-CrgPairedOperationReads'] -Owner $reads
      $complete = $true
      return [pscustomobject]@{ Runtime = $reads.Runtime; OriginalRuntime = $Runtime; ProjectContext = $project
        OperationLock = $lock; ReadOwner = $reads; GitExecutableOwner = $gitOwner; GuardCustody = $null
        AttachmentBytes = [byte[]]$attachmentFile.Bytes.Clone(); PendingBytes = [byte[]]$pending.Bytes.Clone()
        PointerBytes = $(if ($pointer.Present) { [byte[]]$pointer.Bytes.Clone() } else { $null })
        ValidationState = 'held-recovery-namespace-only'; ReadyForPublication = $false }
    }
    if ($null -eq $pending -or $pending.Present -isnot [bool] -or $pending.Present) { throw 'project has pending or indeterminate paired publication; Resume is required before another operation' }
    $pointerFile = & $reads.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-pair') -Maximum 256
    $pointer = & $commands['Read-CrgCompletedPairPointerBytes'] -Bytes $pointerFile.Bytes
    $retentionModule = $commands['Read-CrgCompletedPairRetention'].Module
    # A central upgrade changes the current prompt compiler, not the preceding
    # pair's identity. Validate the immutable anchor without pretending that the
    # current runtime compiled that older receipt's prepared review buffers.
    $record = & $retentionModule {
      param($ProjectContext, $Pointer)
      Read-CrgRetentionRecord -ProjectContext $ProjectContext -ReceiptSha256 $Pointer.ReceiptSha256 -ExpectedOrigin $Pointer.Origin
    } $project $pointer
    & $retentionModule {
      param($ProjectContext, $Fields, $Origin)
      Assert-CrgRetentionAttachment -ProjectContext $ProjectContext -Fields $Fields -Origin $Origin
      $expected = @{ 'project-id' = $ProjectContext.Status.ProjectId; 'public-worktree' = $ProjectContext.Root
        'public-git-dir' = $ProjectContext.Domains.public.GitDir; 'public-common-dir' = $ProjectContext.Domains.public.CommonDir
        'private-git-dir' = $ProjectContext.Domains.private.GitDir; 'public-ref' = $ProjectContext.Domains.public.Ref
        'private-ref' = $ProjectContext.Domains.private.Ref }
      # Attachment bytes can survive a worktree move. Match receipt namespace
      # fields separately; matching the attachment digest alone does not bind them.
      foreach ($name in $expected.Keys) { if (-not [string]::Equals($Fields[$name], $expected[$name], [StringComparison]::Ordinal)) { throw "preceding receipt association differs at '$name'" } }
      foreach ($domain in @('public', 'private')) {
        $selected = $ProjectContext.Domains[$domain]
        if (-not [string]::Equals($Fields[$domain + '-result'], $selected.Parent, [StringComparison]::Ordinal) -or -not [string]::Equals($Fields[$domain + '-tree'], $selected.ParentTree, [StringComparison]::Ordinal) -or
            -not [string]::Equals((Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain $domain -Ref $selected.Ref), $selected.Parent, [StringComparison]::Ordinal)) { throw 'project branches do not match the preceding completed pair' }
      }
      if (-not [string]::Equals((Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain public -Ref ('refs/crg-results/' + $Fields['public-result'])), $Fields['public-result'], [StringComparison]::Ordinal)) { throw 'preceding public result retention is absent or conflicting' }
    } $project $record.Receipt.Fields $pointer.Origin
    & $commands['Assert-CrgPairedOperationReads'] -Owner $reads
    $complete = $true
    return [pscustomobject]@{ Runtime = $reads.Runtime; ProjectContext = $project; OperationLock = $lock; ReadOwner = $reads; GitExecutableOwner = $gitOwner
      AttachmentBytes = [byte[]]$attachmentFile.Bytes.Clone(); PointerBytes = [byte[]]$pointerFile.Bytes.Clone()
      PreviousReceiptBytes = $record.ReceiptBytes; PreviousReceipt = $record.Receipt
      ValidationState = 'held-project-and-preceding-pair'; ReadyForPublication = $false }
  } catch {
    # Admission's status, capture and retention Git reads raise a child whose
    # exit they cannot confirm as an uncertain failure. That child can still be
    # running under the held reads, lock and Git executable lease, so they stay
    # open on the failure (CrgProjectAdmissionOwners) instead of being released
    # under it.
    $marked = $_.Exception
    while ($null -ne $marked) {
      foreach ($key in $marked.Data.Keys) {
        if ([System.Linq.Enumerable]::Contains([string[]]@('CrgPairedProcessSession', 'CrgPairRetentionUncertainReference', 'CrgUncertainGitChild', 'CrgPairedStageReadOwner', 'CrgCentralHistoryPins'), [string]$key, [System.StringComparer]::Ordinal)) { $retainOwners = $true }
      }
      $marked = $marked.InnerException
    }
    if ($retainOwners) { $_.Exception.Data['CrgProjectAdmissionOwners'] = [pscustomobject]@{ Reads = $reads; InitialReads = $initialReads; OperationLock = $lock; GitExecutableOwner = $gitOwner } }
    throw
  } finally {
    if (-not $complete -and -not $retainOwners) {
      # No reviewer or hook child is launched by admission. If a future caller
      # has admitted children, that caller must establish quiescence separately.
      try {
        if ($null -ne $reads) { & $commands['Close-CrgPairedOperationReads'] -Owner $reads }
        if ($null -ne $initialReads) { & $commands['Close-CrgPairedOperationReads'] -Owner $initialReads }
      } finally {
        try { if ($null -ne $lock) { & $commands['Close-CrgPairedOperationLock'] -Lock $lock; if (-not $lock.Closed) { throw 'project operation lock cleanup is unconfirmed' } } }
        finally { if ($null -ne $gitOwner) { & $commands['Close-CrgPairedExecutableRead'] -Owner $gitOwner } }
      }
    }
  }
}

function Close-CrgPairedProjectOperation {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation)
  if ($null -eq $Operation -or $null -eq $Operation.ReadOwner -or $null -eq $Operation.OperationLock -or $null -eq $Operation.GitExecutableOwner) { throw 'project operation has no retained read/lock/executable ownership' }
  $closeReads = Get-CrgProjectOperationCommand -Module paired-operation -Name Close-CrgPairedOperationReads
  $closeLock = Get-CrgProjectOperationCommand -Module paired-diff -Name Close-CrgPairedOperationLock
  # Complete current children before calling: persisted flags cannot establish
  # quiescence, and the read owner independently asserts the actual native lock.
  & $closeReads -Owner $Operation.ReadOwner
  & $closeLock -Lock $Operation.OperationLock
  if (-not $Operation.OperationLock.Closed) { throw 'project operation lock cleanup is unconfirmed' }
  $closeExecutable = Get-CrgProjectOperationCommand -Module paired-operation -Name Close-CrgPairedExecutableRead
  & $closeExecutable -Owner $Operation.GitExecutableOwner
}

Export-ModuleMember -Function Open-CrgPairedProjectOperation, Close-CrgPairedProjectOperation
