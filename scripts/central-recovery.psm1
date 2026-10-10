# Resume reuses immutable transaction input and result objects, never an old
# PASS. The recorded release executes a new complete review before any write.
function Write-CrgCentralRecoveryEvidence {
  param([object]$Operation, [object]$State, [object]$Review, [object]$NativeModule)
  $expectedRoot = Join-Path $Operation.ProjectContext.Domains.private.GitDir ('crg-review-state\runs\' + $State.OperationId)
  # Ordinal: -ceq/-cne compare by culture and ignore characters such as U+00AD.
  if (-not [string]::Equals($Review.OutputRoot, $expectedRoot, [StringComparison]::Ordinal) -or
      -not [string]::Equals($Review.ReviewUnitSha256, $State.ReviewUnitSha256, [StringComparison]::Ordinal) -or
      $State.ReceiptSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $Review.ReviewAttempts.Count -lt 1 -or $Review.ReviewAttempts.Count -gt 6) { throw 'recovery evidence lacks current bounded review identity' }
  $lines = New-Object 'System.Collections.Generic.List[string]'
  foreach ($line in @('crg-recovery-review v1', ('operation-id ' + $State.OperationId),
      ('receipt-sha256 ' + $State.ReceiptSha256), ('review-unit-sha256 ' + $State.ReviewUnitSha256),
      ('prepared-pair-sha256 ' + $Review.DescriptorSha256), ('runtime-manifest-sha256 ' + $State.RuntimeManifestSha256),
      ('attempt-count ' + $Review.ReviewAttempts.Count))) { $lines.Add($line) }
  foreach ($attempt in $Review.ReviewAttempts) {
    $leaf = [IO.Path]::GetFileName($attempt.Directory)
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($attempt.Directory), $expectedRoot, [StringComparison]::Ordinal) -or
        $leaf -cnotmatch '\Aleg-[12]-attempt-[123]-[0-9a-f]{32}\z' -or
        -not ([string]::Equals($attempt.ActualProvider, 'codex', [StringComparison]::Ordinal) -or [string]::Equals($attempt.ActualProvider, 'claude', [StringComparison]::Ordinal) -or
              [string]::Equals($attempt.ActualProvider, 'grok', [StringComparison]::Ordinal)) -or $attempt.ObservedExit -notin @(0, 4)) { throw 'recovery attempt is not current owned evidence' }
    foreach ($digest in @($attempt.TranscriptSha256, $attempt.VerdictSha256, $attempt.ExhaustionSha256)) {
      if ($digest -cnotmatch '\A(?:[0-9a-f]{64}|-)\z') { throw 'recovery attempt has an invalid evidence digest' }
    }
    $lines.Add(('attempt ' + $attempt.Leg + ' ' + $attempt.Attempt + ' ' + $attempt.ActualProvider + ' ' + $attempt.ScheduledPassCount + ' ' + $attempt.ObservedExit + ' ' + $attempt.TranscriptSha256 + ' ' + $attempt.VerdictSha256 + ' ' + $attempt.ExhaustionSha256 + ' ' + $leaf))
  }
  $text = ($lines.ToArray() -join "`n") + "`n"
  return & $NativeModule {
    param($Root, $Text, $Lock)
    $pins = New-Object 'System.Collections.Generic.List[object]'
    $handle = $null
    try {
      Assert-CrgPairedOperationLock -Lock $Lock
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $Root -Pins $pins -DenyLeafRename
      $leaf = 'recovery-' + [guid]::NewGuid().ToString('N') + '.txt'
      $errorCode = 0
      $handle = [CrgAttributeNeutral.NativeV1]::CreateOwnedFileRelative($parent.Handle, $leaf, [ref]$errorCode)
      if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle) -or
          -not [CrgAttributeNeutral.NativeV1]::WriteUtf8Exact($handle, $Text, [ref]$errorCode)) { throw "recovery evidence durable creation failed (Win32 error $errorCode)" }
      $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Text)
      $sha = [Security.Cryptography.SHA256]::Create()
      try { $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
      $actual = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $handle }
      if ($actual.Length -ne $bytes.Length -or -not [string]::Equals($actual.Sha256, $digest, [StringComparison]::Ordinal)) { throw 'recovery evidence differs from the complete current review record' }
      return Join-Path $parent.Path $leaf
    } finally {
      # Durable recovery correlation is forensic data, never a reusable permit.
      if ($null -ne $handle) { $handle.Dispose() }
      foreach ($pin in $pins) { $pin.Handle.Dispose() }
    }
  } $expectedRoot $text $Operation.OperationLock
}

function Invoke-CrgCentralResume {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo,
    [Parameter(Mandatory = $true)][object]$Context)
  $publication = @(Get-Command Invoke-CrgCentralCommit -Module central-publication -CommandType Function -ListImported -ErrorAction Stop)
  if ($publication.Count -ne 1 -or -not [string]::Equals($publication[0].Module.Path, $Context.Payloads['scripts/central-publication.psm1'].Path, [StringComparison]::Ordinal) -or
      $Context.ResumeHandoffSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'resume requires the retained recorded runtime and captured handoff identity' }
  $helpers = & $publication[0].Module {
    $commands = @{}
    foreach ($name in @('Get-CrgPublicationCommand', 'Get-CrgPublicationDigest', 'Assert-CrgCentralCapturedState', 'Invoke-CrgCentralAuthorLint', 'Save-CrgUncertainCentralOperation')) {
      $commands[$name] = Get-Command $name -CommandType Function
    }
    return $commands
  }
  $getCommand = $helpers['Get-CrgPublicationCommand']
  $open = & $getCommand -Runtime $Context -Module paired-project-operation -Name Open-CrgPairedProjectOperation
  $close = & $getCommand -Runtime $Context -Module paired-project-operation -Name Close-CrgPairedProjectOperation
  $operation = & $open -TargetRepo $TargetRepo -Runtime $Context -Recovery
  $guard = $null; $retained = $false; $attachmentRegistered = $false
  try {
    $runtime = $operation.Runtime; $project = $operation.ProjectContext
    $handoffBytes = $operation.PendingBytes; $pointerBytes = $operation.PointerBytes
    $recordReader = & $getCommand -Runtime $runtime -Module paired-governance -Name Read-CrgPairHandoffBytes
    $identity = & $recordReader.Module {
      param([byte[]]$Bytes)
      $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 16384
      $origin = if ([string]::Equals($lines[0], 'crg-handoff v1', [StringComparison]::Ordinal)) { 'paired-v1' }
        elseif ([string]::Equals($lines[0], 'crg-first-attachment-handoff v1', [StringComparison]::Ordinal)) { 'first-attachment-v1' }
        else { throw 'resume requires a supported exact handoff header' }
      $names = @(Get-CrgHandoffNames -Origin $origin)
      if ($lines.Count -ne $names.Count + 1) { throw 'resume handoff has an unexpected record count' }
      $key = ''
      for ($index = 0; $index -lt $names.Count; $index++) {
        $value = Read-CrgPairField -Line $lines[$index + 1] -Name $names[$index]
        if ($names[$index] -ceq 'receipt-sha256') { $key = $value }
      }
      if ($key -cnotmatch '\A[0-9a-f]{64}\z') { throw 'resume handoff has an invalid receipt identity' }
      return [pscustomobject]@{ Origin = $origin; ReceiptSha256 = $key }
    } $handoffBytes
    $origin = $identity.Origin
    $readName = if ($origin -ceq 'paired-v1') { 'Read-CrgPairRetention' } else { 'Read-CrgFirstAttachmentRetention' }
    $readRetention = & $getCommand -Runtime $runtime -Module paired-retention -Name $readName
    $arguments = @{ ProjectContext = $project; ReceiptSha256 = $identity.ReceiptSha256 }
    if ($origin -ceq 'first-attachment-v1') { $arguments.AttachmentBytes = $operation.AttachmentBytes }
    # Full record acquisition revalidates result parents/trees, association,
    # predecessor, raw buffers, private message and the exact recorded compiler.
    $record = & $readRetention @arguments
    $fields = $record.Receipt.Fields
    $classifyName = if ($origin -ceq 'paired-v1') { 'Get-CrgPairedResumeState' } else { 'Get-CrgFirstAttachmentResumeState' }
    $classify = & $getCommand -Runtime $runtime -Module paired-resume-state -Name $classifyName
    $state = & $classify -HandoffBytes $handoffBytes -ReceiptBytes $record.ReceiptBytes -PointerBytes $pointerBytes -ActualPublicOid $project.Domains.public.Parent -ActualPrivateOid $project.Domains.private.Parent -PublicObjectFormat $project.Domains.public.ObjectFormat -PrivateObjectFormat $project.Domains.private.ObjectFormat
    if (-not [string]::Equals($state.RuntimeManifestSha256, $runtime.Id, [StringComparison]::Ordinal) -or
        -not [string]::Equals($state.HandoffSha256, $Context.ResumeHandoffSha256, [StringComparison]::Ordinal)) { throw 'resume transaction differs from the selected retained release or handoff' }
    $buffers = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach ($name in $record.Files.Keys) {
      if (-not [System.Linq.Enumerable]::Contains([string[]]@('receipt.txt', 'prepared-pair.txt', 'public.tree', 'private.tree'), [string]$name, [System.StringComparer]::Ordinal) -and -not $name.StartsWith('leg-', [StringComparison]::Ordinal)) { $buffers.Add($name, $record.Files[$name]) }
    }
    $indexes = [ordered]@{}
    $getIndex = & $getCommand -Runtime $runtime -Module central-context -Name Get-CrgCentralIndexTree
    foreach ($domain in @('public', 'private')) {
      $index = & $getIndex -ProjectContext $project -Domain $domain
      if (-not [string]::Equals($index.TreeOid, $fields[$domain + '-tree'], [StringComparison]::Ordinal) -or
          -not [string]::Equals((& $helpers['Get-CrgPublicationDigest'] -Bytes $index.TreeBytes), (& $helpers['Get-CrgPublicationDigest'] -Bytes $record.Files[$domain + '.tree']), [StringComparison]::Ordinal)) { throw "resume $domain index no longer matches the recorded candidate" }
      $indexes.Add($domain, $index)
    }
    $input = [pscustomobject]@{ Schema = 1
      HasChanges = (-not [string]::Equals($fields['public-parent'], $fields['public-result'], [StringComparison]::Ordinal) -or
        -not [string]::Equals($fields['private-parent'], $fields['private-result'], [StringComparison]::Ordinal))
      Bundle = [pscustomobject]@{ DescriptorBytes = $record.Files['prepared-pair.txt']; DescriptorSha256 = $record.Metadata.Descriptor.DescriptorSha256; Buffers = $buffers; Metadata = $record.Metadata }
      Indexes = $indexes; PreparationSources = $record.Metadata.Preparations; ContextBlobBuffers = $record.ContextBlobBuffers }
    $expected = [ordered]@{ public = $state.Public.ActualOid; private = $state.Private.ActualOid }
    $openGuard = & $getCommand -Runtime $runtime -Module central-guards -Name Open-CrgCentralGuardCustody
    $assertGuard = & $getCommand -Runtime $runtime -Module central-guards -Name Assert-CrgCentralPublicationGuards
    $guard = & $openGuard -ProjectContext $project -OperationLock $operation.OperationLock -Origin $origin
    if ($origin -ceq 'first-attachment-v1') {
      $operation.GuardCustody = $guard
      $register = & $getCommand -Runtime $runtime -Module central-attachment -Name Register-CrgCentralAttachmentRecovery
      & $register -Operation $operation -AttachmentBytes $operation.AttachmentBytes
      $attachmentRegistered = $true
    }
    & $assertGuard -ProjectContext $project -OperationLock $operation.OperationLock -CapturedInput $input -Origin $origin -GuardCustody $guard
    & $helpers['Assert-CrgCentralCapturedState'] -Operation $operation -CapturedInput $input -Origin $origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes -ExpectedHandoffBytes $handoffBytes
    $assertInstructions = & $getCommand -Runtime $runtime -Module central-instructions -Name Assert-CrgCentralInstructionDiscovery
    $null = & $assertInstructions -Operation $operation -CapturedInput $input
    & $helpers['Invoke-CrgCentralAuthorLint'] -Operation $operation -CapturedInput $input -Origin $origin
    $reviewName = if ($origin -ceq 'paired-v1') { 'Invoke-CrgPairedReviewSession' } else { 'Invoke-CrgFirstAttachmentReviewSession' }
    $reviewer = & $getCommand -Runtime $runtime -Module paired-review-session -Name $reviewName
    # Infer the original route, then independently require the recorded release
    # to derive exactly that complete schedule. No resume pass-count override.
    $author = if ([string]::Equals($record.Receipt.ReviewLegs[0].PreferredProvider, 'codex', [StringComparison]::Ordinal)) { 'claude' } else { 'codex' }
    $policy = & $reviewer.Module { param($InputValue, $Author) Get-CrgPairedSessionPolicy -CapturedInput $InputValue -AuthoringAgent $Author } $input $author
    if ($policy.Legs.Count -ne $record.Receipt.ReviewLegs.Count) { throw 'resume review schedule differs from recorded policy' }
    for ($index = 0; $index -lt $policy.Legs.Count; $index++) {
      $actual = $policy.Legs[$index]; $recorded = $record.Receipt.ReviewLegs[$index]
      if ($actual.Leg -ne $recorded.Leg -or -not [string]::Equals($actual.PreferredProvider, $recorded.PreferredProvider, [StringComparison]::Ordinal) -or $actual.RequiredPassCount -ne $recorded.RequiredPassCount) { throw 'resume review leg differs from recorded policy' }
    }
    $review = & $reviewer -Runtime $runtime -CapturedInput $input -AuthoringAgent $author
    if (-not [string]::Equals($review.ReviewUnitSha256, $state.ReviewUnitSha256, [StringComparison]::Ordinal) -or
        -not [string]::Equals($review.DescriptorSha256, $input.Bundle.DescriptorSha256, [StringComparison]::Ordinal)) { throw 'fresh recovery review does not bind the immutable input' }
    & $assertGuard -ProjectContext $project -OperationLock $operation.OperationLock -CapturedInput $input -Origin $origin -GuardCustody $guard
    & $helpers['Assert-CrgCentralCapturedState'] -Operation $operation -CapturedInput $input -Origin $origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes -ExpectedHandoffBytes $handoffBytes
    $native = (& $getCommand -Runtime $runtime -Module paired-diff -Name Assert-CrgPairedOperationLock).Module
    $recoveryEvidence = Write-CrgCentralRecoveryEvidence -Operation $operation -State $state -Review $review -NativeModule $native
    $promote = & $getCommand -Runtime $runtime -Module paired-preparation -Name Publish-CrgPairedFollowups
    $followups = & $promote -Operation $operation -CapturedInput $input -Review $review -ReceiptSha256 $record.ReceiptSha256 -Origin $origin
    if ($attachmentRegistered) {
      $associate = & $getCommand -Runtime $runtime -Module central-attachment -Name Complete-CrgCentralAttachmentAssociation
      $null = & $associate -Operation $operation
    }
    $releaseReads = & $getCommand -Runtime $runtime -Module paired-operation -Name Release-CrgPairedOperationReadFiles
    $update = & $getCommand -Runtime $runtime -Module paired-git-operation -Name Set-CrgPairedGitExpectedRef
    foreach ($domain in @('private', 'public')) {
      $resultOid = $fields[$domain + '-result']
      if (-not [string]::Equals($expected[$domain], $resultOid, [StringComparison]::Ordinal)) {
        $null = & $update -ProjectContext $project -OperationLock $operation.OperationLock -Domain $domain -ExpectedOldOid $expected[$domain] -NewOid $resultOid
        $expected[$domain] = $resultOid
      }
    }
    & $helpers['Assert-CrgCentralCapturedState'] -Operation $operation -CapturedInput $input -Origin $origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes -ExpectedHandoffBytes $handoffBytes
    if (-not [string]::Equals($fields['public-parent'], $fields['public-result'], [StringComparison]::Ordinal)) {
      $postCommit = & $getCommand -Runtime $runtime -Module central-guards -Name Invoke-CrgCentralLfsPostCommit
      $null = & $postCommit -ProjectContext $project -OperationLock $operation.OperationLock -GuardCustody $guard -ExpectedPublicOid $fields['public-result']
      & $helpers['Assert-CrgCentralCapturedState'] -Operation $operation -CapturedInput $input -Origin $origin -ExpectedRefs $expected -ExpectedPointerBytes $pointerBytes -ExpectedHandoffBytes $handoffBytes
    }
    if ($attachmentRegistered) {
      $install = & $getCommand -Runtime $runtime -Module central-guards -Name Install-CrgCentralGuards
      $syncInstructions = & $getCommand -Runtime $runtime -Module central-instructions -Name Sync-CrgCentralInstructions
      $null = & $syncInstructions -Operation $operation -Initial -CapturedInput $input -ReceiptBytes $record.ReceiptBytes
      $null = & $install -GuardCustody $guard
    }
    $newPointer = & $getCommand -Runtime $runtime -Module paired-governance -Name New-CrgCompletedPairPointerBytes
    $completed = & $newPointer -Origin $origin -ReceiptSha256 $record.ReceiptSha256
    $writeState = & $getCommand -Runtime $runtime -Module paired-state -Name Write-CrgPairState
    if (-not [string]::Equals($state.PointerState, 'current', [StringComparison]::Ordinal)) {
      & $releaseReads -Owner $operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-pair'))
      & $writeState -ProjectContext $project -OperationLock $operation.OperationLock -Leaf crg-pair -ExpectedBytes $pointerBytes -Bytes $completed
    }
    if ($attachmentRegistered) {
      $attachment = & $runtime.ReadFile -Path (Join-Path $project.Domains.public.GitDir 'crg-attachment') -Maximum 16384 -AllowAbsent
      if (-not $attachment.Present) {
        & $releaseReads -Owner $operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-attachment'))
        & $writeState -ProjectContext $project -OperationLock $operation.OperationLock -Leaf crg-attachment -Bytes $operation.AttachmentBytes
      }
    }
    & $helpers['Assert-CrgCentralCapturedState'] -Operation $operation -CapturedInput $input -Origin paired-v1 -ExpectedRefs $expected -ExpectedPointerBytes $completed -ExpectedHandoffBytes $handoffBytes
    $remove = & $getCommand -Runtime $runtime -Module paired-state -Name Remove-CrgPairHandoff
    & $releaseReads -Owner $operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-handoff'))
    & $remove -ProjectContext $project -OperationLock $operation.OperationLock -ExpectedBytes $handoffBytes
    & $helpers['Assert-CrgCentralCapturedState'] -Operation $operation -CapturedInput $input -Origin paired-v1 -ExpectedRefs $expected -ExpectedPointerBytes $completed
    if ($attachmentRegistered) {
      $cleanup = & $getCommand -Runtime $runtime -Module central-attachment -Name Remove-CrgCentralAttachmentProposal
      $null = & $cleanup -Operation $operation
    }
    return [pscustomobject]@{ Status = 'completed'; ResumedFrom = $state.State; Origin = $origin; Runtime = $runtime.Id
      ReceiptSha256 = $record.ReceiptSha256; PublicCommit = $expected.public; PrivateCommit = $expected.private; FreshReviewOutput = $review.OutputRoot; FreshReviewRecord = $recoveryEvidence; Followups = $followups }
  } catch {
    $retained = & $helpers['Save-CrgUncertainCentralOperation'] -Operation $operation -GuardCustody $guard -Failure $_.Exception
    throw
  } finally {
    if (-not $retained) {
      if ($attachmentRegistered) {
        $closeAttachment = & $getCommand -Runtime $operation.Runtime -Module central-attachment -Name Close-CrgCentralAttachment
        & $closeAttachment -Operation $operation
      } else {
        if ($null -ne $guard) {
          $closeGuard = & $getCommand -Runtime $operation.Runtime -Module central-guards -Name Close-CrgCentralGuardCustody
          & $closeGuard -GuardCustody $guard
        }
        & $close -Operation $operation
      }
    }
  }
}

Export-ModuleMember -Function Invoke-CrgCentralResume
