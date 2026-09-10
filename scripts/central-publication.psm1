# Current owned review is the only publication authority. Retention records
# identify prior work and recovery inputs, never permission for a new operation.
$script:CrgUncertainCentralOperations = New-Object 'System.Collections.Generic.List[object]'

function Get-CrgPublicationCommand {
  param([object]$Runtime, [string]$Module, [string]$Name)
  $relative = 'scripts/' + $Module + '.psm1'
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($null -eq $Runtime -or $Runtime.Payloads -isnot [System.Collections.IDictionary] -or
      $relative -cnotin @($Runtime.Payloads.Keys) -or $commands.Count -ne 1 -or
      $commands[0].Module.Path -cne $Runtime.Payloads[$relative].Path) { throw "central publication requires retained '$Module/$Name'" }
  return $commands[0]
}

function Get-CrgPublicationDigest {
  param([byte[]]$Bytes)
  if ($null -eq $Bytes) { throw 'publication digest requires captured bytes' }
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Save-CrgUncertainCentralOperation {
  param([object]$Operation, [object]$GuardCustody, [Exception]$Failure)
  $cause = $Failure; $uncertain = $false
  while ($null -ne $cause) {
    foreach ($key in $cause.Data.Keys) {
      if ([string]$key -cin @('CrgPairedProcessSession', 'CrgPairRetentionUncertainReference', 'CrgPairedStageReadOwner', 'CrgCentralHistoryPins')) { $uncertain = $true }
    }
    $cause = $cause.InnerException
  }
  if (-not $uncertain) { return $false }
  $runtime = $Operation.Runtime
  while ($null -ne $runtime.OriginalRuntime) { $runtime = $runtime.OriginalRuntime }
  if ($runtime.RetainFailure -is [scriptblock]) {
    $Failure.Data['CrgCentralRuntimeOwners'] = & $runtime.RetainFailure
  }
  $script:CrgUncertainCentralOperations.Add([pscustomobject]@{ Operation = $Operation; GuardCustody = $GuardCustody; Failure = $Failure })
  $Failure.Data['CrgCentralOperationRetained'] = $true
  return $true
}

function Assert-CrgCentralCapturedState {
  param([object]$Operation, [object]$CapturedInput,
    [ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin,
    [System.Collections.IDictionary]$ExpectedRefs, [AllowNull()][byte[]]$ExpectedPointerBytes,
    [AllowNull()][byte[]]$ExpectedHandoffBytes)
  $project = $Operation.ProjectContext; $runtime = $Operation.Runtime
  $assertReads = Get-CrgPublicationCommand -Runtime $runtime -Module paired-operation -Name Assert-CrgPairedOperationReads
  & $assertReads -Owner $Operation.ReadOwner
  $getIndex = Get-CrgPublicationCommand -Runtime $runtime -Module central-context -Name Get-CrgCentralIndexTree
  $assertGitState = & $getIndex.Module { Get-Command Assert-CrgCentralGitState -CommandType Function }
  & $assertGitState -Context $runtime -PublicGitDir $project.Domains.public.GitDir -PrivateGitDir $project.Domains.private.GitDir -PublicRef $project.Domains.public.Ref
  $retention = Get-CrgPublicationCommand -Runtime $runtime -Module paired-retention -Name Read-CrgCompletedPairRetention
  foreach ($domain in @('public', 'private')) {
    $index = & $getIndex -ProjectContext $project -Domain $domain
    if ($index.TreeOid -cne $CapturedInput.Indexes[$domain].TreeOid) { throw "central $domain staged tree changed from the reviewed candidate" }
    $actualRef = & $retention.Module { param($Project, $Domain) Get-CrgRetentionRef -ProjectContext $Project -Domain $Domain -Ref $Project.Domains[$Domain].Ref } $project $domain
    if ($null -eq $actualRef) { $actualRef = 'absent' }
    if ($actualRef -cne $ExpectedRefs[$domain]) { throw "central $domain branch differs from the expected publication state" }
  }
  foreach ($binding in @(@('crg-pair', $ExpectedPointerBytes), @('crg-handoff', $ExpectedHandoffBytes))) {
    $file = & $runtime.ReadFile -Path (Join-Path $project.Domains.public.GitDir $binding[0]) -Maximum 16384 -AllowAbsent
    if ($null -eq $binding[1]) {
      if ($file.Present -isnot [bool] -or $file.Present) { throw "central '$($binding[0])' appeared after capture" }
    } elseif (-not $file.Present -or (Get-CrgPublicationDigest -Bytes $file.Bytes) -cne (Get-CrgPublicationDigest -Bytes $binding[1])) { throw "central '$($binding[0])' differs from the captured publication record" }
  }
  $attachment = & $runtime.ReadFile -Path (Join-Path $project.Domains.public.GitDir 'crg-attachment') -Maximum 16384 -AllowAbsent
  if ($Origin -ceq 'paired-v1') {
    if (-not $attachment.Present -or (Get-CrgPublicationDigest -Bytes $attachment.Bytes) -cne (Get-CrgPublicationDigest -Bytes $Operation.AttachmentBytes)) { throw 'central attachment changed during publication' }
  } elseif ($attachment.Present -and (Get-CrgPublicationDigest -Bytes $attachment.Bytes) -cne (Get-CrgPublicationDigest -Bytes $Operation.AttachmentBytes)) { throw 'initial attachment conflicts with the reviewed proposal' }
  & $assertReads -Owner $Operation.ReadOwner
}

function Invoke-CrgCentralAuthorLint {
  param([object]$Operation, [object]$CapturedInput, [string]$Origin)
  $Runtime = $Operation.Runtime
  $payload = $Runtime.Payloads['scripts/shared/author-lint.ps1']
  if ($null -eq $payload -or $payload.Bytes -isnot [byte[]] -or $payload.Path -cne (Join-Path $Runtime.Root 'scripts\shared\author-lint.ps1')) { throw 'central author-lint payload is not retained' }
  $arguments = @{}
  $name = if ($Origin -ceq 'paired-v1') { 'PairedInput' } else { 'FirstAttachmentInput' }
  $inputData = @{ Runtime = $Runtime; CapturedInput = $CapturedInput }
  $fields = $CapturedInput.Bundle.Metadata.ReviewUnit.Fields
  $originalPrivateParent = $fields['private-parent']
  if ($Origin -ceq 'first-attachment-v1' -and $originalPrivateParent -cne 'absent') {
    # Mandatory review remains empty-tree-to-candidate. Added-line attribution is
    # independently derived from the original adopted parent while the operation
    # owns the exact private namespace, never from the possibly advanced ref.
    $private = $Operation.ProjectContext.Domains.private
    $candidateTree = $CapturedInput.Indexes.private.TreeOid
    if ($fields['private-tree'] -cne $candidateTree) { throw 'first-attachment lint attribution differs from the captured private identity' }
    $retention = Get-CrgPublicationCommand -Runtime $Runtime -Module paired-retention -Name Read-CrgCompletedPairRetention
    $parentCommit = & $retention.Module {
      param($ProjectContext, $ParentOid)
      $commit = Read-CrgRetentionCommit -ProjectContext $ProjectContext -Domain private -Oid $ParentOid
      $null = Read-CrgRetentionObject -ProjectContext $ProjectContext -Domain private -Oid $commit.TreeOid -Type tree -Maximum 16777216
      return $commit
    } $Operation.ProjectContext $originalPrivateParent
    if ($null -eq $parentCommit -or $parentCommit.TreeOid -isnot [string]) { throw 'first-attachment lint attribution could not verify the original private parent tree' }
    $parentTree = $parentCommit.TreeOid
    $capture = Get-CrgPublicationCommand -Runtime $Runtime -Module paired-diff -Name Get-CrgPairedGitDiffEvidence
    $diff = & $capture -ProjectContext $Operation.ProjectContext -Domain private -ParentTree $parentTree -CandidateTree $candidateTree -TempParent $private.GitDir
    if ($diff.Ok -isnot [bool] -or -not $diff.Ok -or $diff.Domain -cne 'private' -or
        $diff.ParentTree -cne $parentTree -or $diff.CandidateTree -cne $candidateTree -or
        $diff.PatchBytes -isnot [byte[]] -or $diff.NameStatusBytes -isnot [byte[]]) { throw "first-attachment private lint attribution failed: $($diff.Reason)" }
    $inputData['PrivateAttribution'] = @{
      Domain = 'private'; Parent = $originalPrivateParent; ParentTree = $parentTree; CandidateTree = $candidateTree
      PatchBytes = $diff.PatchBytes; NameStatusBytes = $diff.NameStatusBytes
    }
  }
  $arguments[$name] = $inputData
  $result = @(& $payload.Path @arguments)
  if ($result.Count -ne 1 -or $result[0].ExitCode -notin @(0, 3) -or
      $result[0].ReviewUnitSha256 -cne $CapturedInput.Bundle.Metadata.ReviewUnit.ReviewUnitSha256) { throw 'central author-lint returned an invalid result' }
  Write-Host $result[0].Report
  if ($result[0].ExitCode -eq 3) { throw 'central author-lint reported ERROR-tier findings; review has not started' }
}

function New-CrgCentralReceipt {
  param([object]$Operation, [object]$CapturedInput, [object]$Review,
    [System.Collections.IDictionary]$Results, [string]$Origin)
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext
  $name = if ($Origin -ceq 'paired-v1') { 'New-CrgPairReceiptBytes' } else { 'New-CrgFirstAttachmentReceiptBytes' }
  $constructor = Get-CrgPublicationCommand -Runtime $runtime -Module paired-governance -Name $name
  $unit = $CapturedInput.Bundle.Metadata.ReviewUnit
  if ($Review.ReviewUnitSha256 -cne $unit.ReviewUnitSha256 -or $Review.DescriptorSha256 -cne $CapturedInput.Bundle.DescriptorSha256) { throw 'current review does not bind the captured publication input' }
  $fields = [ordered]@{}
  foreach ($key in $unit.Fields.Keys) { $fields.Add($key, $unit.Fields[$key]) }
  foreach ($domain in @('public', 'private')) { $fields.Add($domain + '-result', $Results[$domain]) }
  $legs = @($Review.ReviewLegs | ForEach-Object {
    [ordered]@{ leg = [string]$_.Leg; 'preferred-provider' = $_.PreferredProvider; 'required-pass-count' = [string]$_.RequiredPassCount }
  })
  $attempts = @($Review.ReviewAttempts | ForEach-Object {
    [ordered]@{ leg = [string]$_.Leg; attempt = [string]$_.Attempt; 'actual-provider' = $_.ActualProvider
      'scheduled-pass-count' = [string]$_.ScheduledPassCount; 'observed-exit' = [string]$_.ObservedExit
      'transcript-sha256' = $_.TranscriptSha256; 'verdict-sha256' = $_.VerdictSha256; 'exhaustion-sha256' = $_.ExhaustionSha256 }
  })
  return ,(& $constructor -Fields $fields -ReviewLegs $legs -ReviewAttempts $attempts -PublicObjectFormat $project.Domains.public.ObjectFormat -PrivateObjectFormat $project.Domains.private.ObjectFormat)
}

function Invoke-CrgCentralCapturedPublication {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude')][string]$AuthoringAgent)
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext
  $guard = $null; $retained = $false; $ownsGuard = $Origin -ceq 'paired-v1'
  $openGuard = Get-CrgPublicationCommand -Runtime $runtime -Module central-guards -Name Open-CrgCentralGuardCustody
  $assertGuard = Get-CrgPublicationCommand -Runtime $runtime -Module central-guards -Name Assert-CrgCentralPublicationGuards
  $closeGuard = Get-CrgPublicationCommand -Runtime $runtime -Module central-guards -Name Close-CrgCentralGuardCustody
  $releaseReads = Get-CrgPublicationCommand -Runtime $runtime -Module paired-operation -Name Release-CrgPairedOperationReadFiles
  $writeState = Get-CrgPublicationCommand -Runtime $runtime -Module paired-state -Name Write-CrgPairState
  $removeHandoff = Get-CrgPublicationCommand -Runtime $runtime -Module paired-state -Name Remove-CrgPairHandoff
  $results = [ordered]@{ public = $project.Domains.public.Parent; private = $project.Domains.private.Parent }
  $expected = [ordered]@{ public = $results.public; private = $results.private }
  $pointerBytes = $null
  if ($Origin -ceq 'paired-v1') { $pointerBytes = $Operation.PointerBytes }
  try {
    if ($ownsGuard) { $guard = & $openGuard -ProjectContext $project -OperationLock $Operation.OperationLock -Origin $Origin }
    else { $guard = $Operation.GuardCustody }
    & $assertGuard -ProjectContext $project -OperationLock $Operation.OperationLock -CapturedInput $CapturedInput -Origin $Origin -GuardCustody $guard
    Assert-CrgCentralCapturedState -Operation $Operation -CapturedInput $CapturedInput -Origin $Origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes
    $assertInstructions = Get-CrgPublicationCommand -Runtime $runtime -Module central-instructions -Name Assert-CrgCentralInstructionDiscovery
    $null = & $assertInstructions -Operation $Operation -CapturedInput $CapturedInput
    Invoke-CrgCentralAuthorLint -Operation $Operation -CapturedInput $CapturedInput -Origin $Origin
    $reviewName = if ($Origin -ceq 'paired-v1') { 'Invoke-CrgPairedReviewSession' } else { 'Invoke-CrgFirstAttachmentReviewSession' }
    $reviewer = Get-CrgPublicationCommand -Runtime $runtime -Module paired-review-session -Name $reviewName
    # This call owns reviewer children and validates current exits/artifacts.
    # No parameter accepts a saved review result, receipt, or permission flag.
    $review = & $reviewer -Runtime $runtime -CapturedInput $CapturedInput -AuthoringAgent $AuthoringAgent
    & $assertGuard -ProjectContext $project -OperationLock $Operation.OperationLock -CapturedInput $CapturedInput -Origin $Origin -GuardCustody $guard
    Assert-CrgCentralCapturedState -Operation $Operation -CapturedInput $CapturedInput -Origin $Origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes
    $newCommit = Get-CrgPublicationCommand -Runtime $runtime -Module paired-git-operation -Name New-CrgPairedGitResultCommit
    $message = $CapturedInput.Bundle.Buffers['COMMIT-MESSAGE.txt']
    foreach ($domain in @('private', 'public')) {
      $selected = $project.Domains[$domain]
      if ($selected.Parent -ceq 'absent' -or $CapturedInput.Indexes[$domain].TreeOid -cne $selected.ParentTree) {
        $commit = & $newCommit -ProjectContext $project -OperationLock $Operation.OperationLock -Domain $domain -TreeOid $CapturedInput.Indexes[$domain].TreeOid -ParentOid $selected.Parent -MessageBytes $message
        $results[$domain] = $commit.Value.Oid
      }
    }
    $receiptBytes = New-CrgCentralReceipt -Operation $Operation -CapturedInput $CapturedInput -Review $review -Results $results -Origin $Origin
    $retentionName = if ($Origin -ceq 'paired-v1') { 'Write-CrgPairRetention' } else { 'Write-CrgFirstAttachmentRetention' }
    $retain = Get-CrgPublicationCommand -Runtime $runtime -Module paired-retention -Name $retentionName
    $retentionArguments = @{ ProjectContext = $project; OperationLock = $Operation.OperationLock; ReceiptBytes = $receiptBytes; CapturedInput = $CapturedInput; ReviewAttempts = $review.ReviewAttempts }
    if ($Origin -ceq 'first-attachment-v1') { $retentionArguments.AttachmentBytes = $Operation.AttachmentBytes }
    $record = & $retain @retentionArguments
    $promote = Get-CrgPublicationCommand -Runtime $runtime -Module paired-preparation -Name Publish-CrgPairedFollowups
    $followups = & $promote -Operation $Operation -CapturedInput $CapturedInput -Review $review -ReceiptSha256 $record.ReceiptSha256 -Origin $Origin
    $handoffName = if ($Origin -ceq 'paired-v1') { 'New-CrgPairHandoffBytes' } else { 'New-CrgFirstAttachmentHandoffBytes' }
    $newHandoff = Get-CrgPublicationCommand -Runtime $runtime -Module paired-governance -Name $handoffName
    $handoff = & $newHandoff -ReceiptBytes $receiptBytes -PublicObjectFormat $project.Domains.public.ObjectFormat -PrivateObjectFormat $project.Domains.private.ObjectFormat
    & $releaseReads -Owner $Operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-handoff'))
    & $writeState -ProjectContext $project -OperationLock $Operation.OperationLock -Leaf crg-handoff -Bytes $handoff
    if ($Origin -ceq 'first-attachment-v1') {
      $associate = Get-CrgPublicationCommand -Runtime $runtime -Module central-attachment -Name Complete-CrgCentralAttachmentAssociation
      $null = & $associate -Operation $Operation
    }
    # The durable handoff precedes every branch update. After any failure,
    # Resume inspects actual refs and obtains a fresh review of retained input.
    Assert-CrgCentralCapturedState -Operation $Operation -CapturedInput $CapturedInput -Origin $Origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes -ExpectedHandoffBytes $handoff
    $update = Get-CrgPublicationCommand -Runtime $runtime -Module paired-git-operation -Name Set-CrgPairedGitExpectedRef
    foreach ($domain in @('private', 'public')) {
      if ($results[$domain] -cne $expected[$domain]) {
        $null = & $update -ProjectContext $project -OperationLock $Operation.OperationLock -Domain $domain -ExpectedOldOid $expected[$domain] -NewOid $results[$domain]
        $expected[$domain] = $results[$domain]
      }
    }
    Assert-CrgCentralCapturedState -Operation $Operation -CapturedInput $CapturedInput -Origin $Origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes -ExpectedHandoffBytes $handoff
    if ($record.Receipt.Fields['public-parent'] -cne $record.Receipt.Fields['public-result']) {
      $postCommit = Get-CrgPublicationCommand -Runtime $runtime -Module central-guards -Name Invoke-CrgCentralLfsPostCommit
      $null = & $postCommit -ProjectContext $project -OperationLock $Operation.OperationLock -GuardCustody $guard -ExpectedPublicOid $record.Receipt.Fields['public-result']
      Assert-CrgCentralCapturedState -Operation $Operation -CapturedInput $CapturedInput -Origin $Origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes -ExpectedHandoffBytes $handoff
    }
    if ($Origin -ceq 'first-attachment-v1') {
      $installGuards = Get-CrgPublicationCommand -Runtime $runtime -Module central-guards -Name Install-CrgCentralGuards
      $syncInstructions = Get-CrgPublicationCommand -Runtime $runtime -Module central-instructions -Name Sync-CrgCentralInstructions
      $null = & $syncInstructions -Operation $Operation -Initial -CapturedInput $CapturedInput -ReceiptBytes $receiptBytes
      $null = & $installGuards -GuardCustody $guard
    }
    $newPointer = Get-CrgPublicationCommand -Runtime $runtime -Module paired-governance -Name New-CrgCompletedPairPointerBytes
    $completed = & $newPointer -Origin $Origin -ReceiptSha256 $record.ReceiptSha256
    & $releaseReads -Owner $Operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-pair'))
    & $writeState -ProjectContext $project -OperationLock $Operation.OperationLock -Leaf crg-pair -ExpectedBytes $pointerBytes -Bytes $completed
    if ($Origin -ceq 'first-attachment-v1') {
      & $releaseReads -Owner $Operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-attachment'))
      & $writeState -ProjectContext $project -OperationLock $Operation.OperationLock -Leaf crg-attachment -Bytes $Operation.AttachmentBytes
    }
    Assert-CrgCentralCapturedState -Operation $Operation -CapturedInput $CapturedInput -Origin $Origin -ExpectedRefs $expected -ExpectedPointerBytes $completed -ExpectedHandoffBytes $handoff
    & $releaseReads -Owner $Operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-handoff'))
    & $removeHandoff -ProjectContext $project -OperationLock $Operation.OperationLock -ExpectedBytes $handoff
    Assert-CrgCentralCapturedState -Operation $Operation -CapturedInput $CapturedInput -Origin 'paired-v1' -ExpectedRefs $expected -ExpectedPointerBytes $completed
    return [pscustomobject]@{ Status = 'completed'; Origin = $Origin; Runtime = $runtime.Id; ReceiptSha256 = $record.ReceiptSha256
      PublicCommit = $results.public; PrivateCommit = $results.private; ReviewOutput = $review.OutputRoot; Followups = $followups }
  } catch {
    $retained = Save-CrgUncertainCentralOperation -Operation $Operation -GuardCustody $guard -Failure $_.Exception
    throw
  } finally {
    if (-not $retained -and $ownsGuard -and $null -ne $guard) { & $closeGuard -GuardCustody $guard }
  }
}

function Invoke-CrgCentralCommit {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo, [Parameter(Mandatory = $true)][object]$Context,
    [Parameter(Mandatory = $true)][string]$MessageFile,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude')][string]$AuthoringAgent)
  $open = Get-CrgPublicationCommand -Runtime $Context -Module paired-project-operation -Name Open-CrgPairedProjectOperation
  $close = Get-CrgPublicationCommand -Runtime $Context -Module paired-project-operation -Name Close-CrgPairedProjectOperation
  $operation = & $open -TargetRepo $TargetRepo -Runtime $Context
  $retained = $false
  try {
    $messagePath = if ([IO.Path]::IsPathRooted($MessageFile)) { [IO.Path]::GetFullPath($MessageFile) }
      else { [IO.Path]::GetFullPath((Join-Path $TargetRepo $MessageFile)) }
    $message = & $operation.Runtime.ReadFile -Path $messagePath -Maximum 1048576
    $capture = Get-CrgPublicationCommand -Runtime $operation.Runtime -Module paired-preparation -Name Get-CrgCentralStagedReviewInput
    $input = & $capture -ProjectContext $operation.ProjectContext -OperationId ([guid]::NewGuid().ToString('N')) -PreviousPairSha256 $operation.PreviousReceipt.ReceiptSha256 -MessageBytes $message.Bytes -TempParent $operation.ProjectContext.Domains.private.GitDir -MaximumBlobBytes 33554432 -MaximumContextBytes 536870912
    if (-not $input.HasChanges) { return [pscustomobject]@{ Status = 'no-change'; Runtime = $Context.Id } }
    return Invoke-CrgCentralCapturedPublication -Operation $operation -CapturedInput $input -Origin paired-v1 -AuthoringAgent $AuthoringAgent
  } catch {
    $retained = Save-CrgUncertainCentralOperation -Operation $operation -Failure $_.Exception
    throw
  } finally { if (-not $retained) { & $close -Operation $operation } }
}

function Invoke-CrgCentralAttach {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo, [Parameter(Mandatory = $true)][object]$Context,
    [Parameter(Mandatory = $true)][string]$MessageFile,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude')][string]$AuthoringAgent, [string]$PrivateGitDir)
  $open = Get-CrgPublicationCommand -Runtime $Context -Module central-attachment -Name Open-CrgCentralAttachment
  $close = Get-CrgPublicationCommand -Runtime $Context -Module central-attachment -Name Close-CrgCentralAttachment
  $parameters = @{ Runtime = $Context; TargetRepo = $TargetRepo; MessageFile = $MessageFile; AuthoringAgent = $AuthoringAgent }
  if (-not [string]::IsNullOrEmpty($PrivateGitDir)) { $parameters.PrivateGitDir = $PrivateGitDir }
  $operation = $null
  $retained = $false
  try {
    $operation = & $open @parameters
    $result = Invoke-CrgCentralCapturedPublication -Operation $operation -CapturedInput $operation.CapturedInput -Origin first-attachment-v1 -AuthoringAgent $AuthoringAgent
    $cleanup = Get-CrgPublicationCommand -Runtime $operation.Runtime -Module central-attachment -Name Remove-CrgCentralAttachmentProposal
    $null = & $cleanup -Operation $operation
    return $result
  } catch {
    if ($null -eq $operation) {
      $cause = $_.Exception
      while ($null -ne $cause) {
        if ($cause.Data.Contains('CrgCentralAttachmentOperation')) { $operation = $cause.Data['CrgCentralAttachmentOperation']; break }
        $cause = $cause.InnerException
      }
    }
    $retained = Save-CrgUncertainCentralOperation -Operation $operation -GuardCustody $operation.GuardCustody -Failure $_.Exception
    throw
  } finally { if (-not $retained -and $null -ne $operation) { & $close -Operation $operation } }
}

function Invoke-CrgCentralPendingAttachmentStage {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo,
    [Parameter(Mandatory = $true)][object]$Context,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string[]]$Paths)
  $open = Get-CrgPublicationCommand -Runtime $Context -Module central-attachment -Name Open-CrgCentralAttachment
  $close = Get-CrgPublicationCommand -Runtime $Context -Module central-attachment -Name Close-CrgCentralAttachment
  $stage = Get-CrgPublicationCommand -Runtime $Context -Module paired-stage -Name Invoke-CrgPairedStage
  $operation = $null; $retained = $false
  try {
    $operation = & $open -Runtime $Context -TargetRepo $TargetRepo -StagePaths $Paths
    return & $stage -Operation $operation -Paths $Paths -PendingAttachment
  } catch {
    if ($null -eq $operation) {
      $cause = $_.Exception
      while ($null -ne $cause) {
        if ($cause.Data.Contains('CrgCentralAttachmentOperation')) { $operation = $cause.Data['CrgCentralAttachmentOperation']; break }
        $cause = $cause.InnerException
      }
    }
    if ($null -ne $operation) { $retained = Save-CrgUncertainCentralOperation -Operation $operation -GuardCustody $operation.GuardCustody -Failure $_.Exception }
    throw
  } finally { if (-not $retained -and $null -ne $operation) { & $close -Operation $operation } }
}

Export-ModuleMember -Function Invoke-CrgCentralCommit, Invoke-CrgCentralCapturedPublication, Invoke-CrgCentralAttach, Invoke-CrgCentralPendingAttachmentStage
