# Initial association admission and migration staging. Only the live coordinator
# can review and publish the returned candidate; no attachment is activated here.

$script:CrgAttachmentOwners = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)

function Get-CrgAttachmentCommand {
  param([object]$Runtime, [string]$Module, [string]$Name)
  $relative = 'scripts/' + $Module + '.psm1'
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($null -eq $Runtime -or $Runtime.Payloads -isnot [System.Collections.IDictionary] -or
      -not [System.Linq.Enumerable]::Contains([string[]]@($Runtime.Payloads.Keys), [string]$relative, [System.StringComparer]::Ordinal) -or $commands.Count -ne 1 -or
      -not [string]::Equals($commands[0].Module.Path, $Runtime.Payloads[$relative].Path, [StringComparison]::OrdinalIgnoreCase)) {
    throw "attachment requires the retained '$Module/$Name' command"
  }
  return $commands[0]
}

function Get-CrgAttachmentDigest {
  param([byte[]]$Bytes)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Assert-CrgAttachmentAbsent {
  param([object]$Runtime, [string]$PublicGitDirectory)
  foreach ($leaf in @('crg-attachment', 'crg-pair', 'crg-handoff')) {
    $record = & $Runtime.ReadFile -Path (Join-Path $PublicGitDirectory $leaf) -Maximum 65536 -AllowAbsent
    if ($null -eq $record -or $record.Present -isnot [bool] -or $record.Present) {
      throw 'Attach requires an unattached worktree without pending paired publication'
    }
  }
}

function Get-CrgUnactivatedAttachmentHandoff {
  param([object]$Runtime, [string]$PublicGitDirectory)
  foreach ($leaf in @('crg-attachment', 'crg-pair')) {
    $record = & $Runtime.ReadFile -Path (Join-Path $PublicGitDirectory $leaf) -Maximum 65536 -AllowAbsent
    if ($null -eq $record -or $record.Present -isnot [bool] -or $record.Present) {
      throw 'attachment correction requires an unactivated worktree without a completed-pair pointer'
    }
  }
  $handoff = & $Runtime.ReadFile -Path (Join-Path $PublicGitDirectory 'crg-handoff') -Maximum 16384 -AllowAbsent
  if ($null -eq $handoff -or $handoff.Present -isnot [bool]) { throw 'attachment handoff presence is unconfirmed' }
  if (-not $handoff.Present) { return $null }
  if ($handoff.Bytes -isnot [byte[]]) { throw 'attachment handoff did not provide exact bytes' }
  return ,([byte[]]$handoff.Bytes.Clone())
}

function New-CrgAttachmentDirectory {
  param([object]$NativeModule, [string]$Path, [switch]$AllowExisting)
  return & $NativeModule {
    param([string]$Path, [bool]$AllowExisting)
    Initialize-CrgAttributeNeutralNative
    $pins = New-Object 'System.Collections.Generic.List[object]'
    $handle = $null; $complete = $false
    try {
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path ([IO.Path]::GetDirectoryName($Path)) -Pins $pins -DenyLeafRename
      $errorCode = 0
      $handle = [CrgAttributeNeutral.NativeV1]::CreatePersistentDirectoryRelative($parent.Handle, [IO.Path]::GetFileName($Path), [ref]$errorCode)
      if (($null -eq $handle -or $handle.IsInvalid) -and $AllowExisting -and $errorCode -in @(80, 183)) {
        if ($null -ne $handle) { $handle.Dispose() }
        $handle = [CrgAttributeNeutral.NativeV1]::OpenPinnedDirectoryNoFollowDenyRename($Path, [ref]$errorCode)
      }
      if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryDirectory($handle)) {
        throw "new private database directory creation failed (Win32 error $errorCode); any existing occupant is preserved"
      }
      $record = [pscustomobject]@{ Path = $Path; Handle = $handle; Label = 'new private database'; DeniesRename = $true; DirectoryPins = $pins }
      $handle = $null
      $complete = $true
      return $record
    } finally {
      if ($null -ne $handle) { $handle.Dispose() }
      if (-not $complete) { foreach ($pin in $pins) { $pin.Handle.Dispose() } }
    }
  } $Path ([bool]$AllowExisting)
}

function Get-CrgAttachmentInitializationBytes {
  param([byte[]]$AttachmentBytes, [string]$PublicGitDirectory, [string]$ObjectFormat)
  $text = @('crg-private-initialization v1', ('attachment-sha256 ' + (Get-CrgAttachmentDigest -Bytes $AttachmentBytes)),
    ('public-git-dir ' + $PublicGitDirectory), ('object-format ' + $ObjectFormat)) -join "`n"
  return ,([Text.UTF8Encoding]::new($false).GetBytes($text + "`n"))
}

function Write-CrgAttachmentRecord {
  param([object]$Runtime, [object]$NativeModule, [string]$Directory, [string]$Leaf, [byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 65536) { throw 'attachment record bytes are absent or exceed the bound' }
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
  & $NativeModule {
    param([string]$Directory, [string]$Leaf, [string]$Text)
    $pins = New-Object 'System.Collections.Generic.List[object]'
    $handle = $null; $published = $false
    try {
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $Directory -Pins $pins -DenyLeafRename
      $errorCode = 0
      $handle = [CrgAttributeNeutral.NativeV1]::CreatePublicationFileRelative($parent.Handle, ('.crg-attachment-record-' + [guid]::NewGuid().ToString('N')), [ref]$errorCode)
      if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) { throw "attachment record create-new failed (Win32 error $errorCode)" }
      if (-not [CrgAttributeNeutral.NativeV1]::WriteUtf8Exact($handle, $Text, [ref]$errorCode)) { throw "attachment record durable write failed (Win32 error $errorCode)" }
      if ([CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($handle, $parent.Handle, $Leaf, [ref]$errorCode)) { $published = $true }
      elseif ($errorCode -notin @(80, 183)) { throw "attachment record no-replace publication failed (Win32 error $errorCode)" }
    } finally {
      if ($null -ne $handle -and -not $handle.IsInvalid) {
        if (-not $published) {
          $deleteError = 0
          if (-not [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($handle, $false, [ref]$deleteError)) {
            $handle.Dispose()
            foreach ($pin in $pins) { $pin.Handle.Dispose() }
            throw "attachment record scratch cleanup is unconfirmed (Win32 error $deleteError)"
          }
        }
        $handle.Dispose()
      }
      foreach ($pin in $pins) { $pin.Handle.Dispose() }
    }
  } $Directory $Leaf $text
  $record = & $Runtime.ReadFile -Path (Join-Path $Directory $Leaf) -Maximum 65536
  if ($null -eq $record -or $record.Bytes -isnot [byte[]] -or
      -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $record.Bytes), (Get-CrgAttachmentDigest -Bytes $Bytes), [System.StringComparison]::Ordinal)) { throw "attachment record '$Leaf' conflicts with the proposed exact association; existing bytes remain preserved" }
}

function Register-CrgAttachmentOwner {
  param([object]$Operation)
  $reader = Get-CrgAttachmentCommand -Runtime $Operation.Runtime -Module private-governance -Name Read-CrgAttachmentBytes
  $attachment = & $reader -Bytes $Operation.AttachmentBytes
  $project = $Operation.ProjectContext
  # Ordinal: -ceq/-cne compare by culture and ignore characters such as U+00AD.
  if (-not [string]::Equals($attachment.PrivateGitDir, $project.Domains.private.GitDir, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($attachment.PublicRef, $project.Domains.public.Ref, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($attachment.PrivateRef, $project.Domains.private.Ref, [System.StringComparison]::Ordinal) -or -not [string]::Equals($attachment.ProjectId, $project.Status.ProjectId, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($attachment.RuntimeStore, $Operation.Runtime.Store, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($Operation.OperationLock.PublicGitDirectory, $project.Domains.public.GitDir, [System.StringComparison]::Ordinal)) {
    throw 'attachment owner registration differs from the held project association'
  }
  $id = [guid]::NewGuid().ToString('N')
  $operation | Add-Member -NotePropertyName AttachmentOwnerId -NotePropertyValue $id
  $refBytes = [Text.UTF8Encoding]::new($false).GetBytes($attachment.PrivateRef)
  $recordText = @('crg-private-association v1', ('public-git-dir ' + $project.Domains.public.GitDir),
    ('attachment-sha256 ' + (Get-CrgAttachmentDigest -Bytes $Operation.AttachmentBytes))) -join "`n"
  $script:CrgAttachmentOwners.Add($id, [pscustomobject]@{ Operation = $Operation; Runtime = $Operation.Runtime
    AttachmentBytes = [byte[]]$Operation.AttachmentBytes.Clone(); PublicGitDirectory = $project.Domains.public.GitDir
    PrivateGitDirectory = $attachment.PrivateGitDir; OperationLock = $Operation.OperationLock
    AssociationLeaf = ('crg-association-' + (Get-CrgAttachmentDigest -Bytes $refBytes))
    AssociationBytes = [Text.UTF8Encoding]::new($false).GetBytes($recordText + "`n") })
}

function Get-CrgAttachmentOwner {
  param([object]$Operation)
  if ($null -eq $Operation -or $Operation.Closed -or $Operation.AttachmentOwnerId -isnot [string] -or
      -not $script:CrgAttachmentOwners.ContainsKey($Operation.AttachmentOwnerId)) { throw 'attachment metadata requires the current registered owner' }
  $owner = $script:CrgAttachmentOwners[$Operation.AttachmentOwnerId]
  if (-not [object]::ReferenceEquals($owner.Operation, $Operation) -or -not [object]::ReferenceEquals($owner.OperationLock, $Operation.OperationLock) -or
      -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $Operation.AttachmentBytes), (Get-CrgAttachmentDigest -Bytes $owner.AttachmentBytes), [System.StringComparison]::Ordinal)) { throw 'attachment owner or proposed bytes changed' }
  $assertLock = Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-diff -Name Assert-CrgPairedOperationLock
  & $assertLock -Lock $owner.OperationLock
  return $owner
}

function Test-CrgAttachmentExactBytes {
  param([AllowNull()][byte[]]$Left, [AllowNull()][byte[]]$Right)
  if ($null -eq $Left -or $null -eq $Right) { return $null -eq $Left -and $null -eq $Right }
  return [Linq.Enumerable]::SequenceEqual($Left, $Right)
}

function Read-CrgCentralAttachmentCorrectionAnchor {
  param([object]$Operation, [byte[]]$ExpectedHandoffBytes, [object]$ExpectedAnchor)
  if ($null -eq $Operation -or -not [string]::Equals($Operation.Origin, 'first-attachment-v1', [System.StringComparison]::Ordinal) -or
      $null -eq $Operation.ProjectContext -or $null -eq $Operation.ReadOwner -or
      $null -eq $Operation.OperationLock -or $ExpectedHandoffBytes -isnot [byte[]]) {
    throw 'attachment correction requires the held first-attachment operation and exact preceding handoff'
  }
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext
  $actualHandoff = Get-CrgUnactivatedAttachmentHandoff -Runtime $runtime -PublicGitDirectory $project.Domains.public.GitDir
  if ($actualHandoff -isnot [byte[]] -or
      -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $actualHandoff), (Get-CrgAttachmentDigest -Bytes $ExpectedHandoffBytes), [System.StringComparison]::Ordinal)) {
    throw 'attachment correction handoff changed during admission'
  }
  $owner = Get-CrgAttachmentOwner -Operation $Operation
  $proposal = & $runtime.ReadFile -Path (Join-Path $owner.PublicGitDirectory 'crg-attachment-pending') -Maximum 16384
  if ($proposal.Bytes -isnot [byte[]] -or
      -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $proposal.Bytes), (Get-CrgAttachmentDigest -Bytes $owner.AttachmentBytes), [System.StringComparison]::Ordinal)) {
    throw 'attachment correction proposal differs from the held association'
  }
  $association = & $runtime.ReadFile -Path (Join-Path $owner.PrivateGitDirectory $owner.AssociationLeaf) -Maximum 65536
  if ($association.Bytes -isnot [byte[]] -or
      -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $association.Bytes), (Get-CrgAttachmentDigest -Bytes $owner.AssociationBytes), [System.StringComparison]::Ordinal)) {
    throw 'attachment correction requires the exact already-published private association'
  }
  $handoffReader = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-governance -Name Read-CrgFirstAttachmentHandoffBytes
  $receiptKey = & $handoffReader.Module {
    param([byte[]]$Bytes)
    $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 16384
    $names = @(Get-CrgHandoffNames -Origin 'first-attachment-v1')
    if ($lines.Count -ne $names.Count + 1 -or -not [string]::Equals($lines[0], 'crg-first-attachment-handoff v1', [System.StringComparison]::Ordinal)) {
      throw 'attachment correction requires a first-attachment handoff'
    }
    $key = ''
    for ($index = 0; $index -lt $names.Count; $index++) {
      $value = Read-CrgPairField -Line $lines[$index + 1] -Name $names[$index]
      if ($names[$index] -ceq 'receipt-sha256') { $key = $value }
    }
    if ($key -cnotmatch '\A[0-9a-f]{64}\z') { throw 'attachment correction handoff has an invalid receipt identity' }
    return $key
  } $actualHandoff
  $retention = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-retention -Name Read-CrgFirstAttachmentRetention
  # The prior release cannot be reopened outside Resume. Validate only the
  # immutable result/receipt anchor here; no prior review artifact grants credit.
  $record = & $retention.Module {
    param($ProjectContext, $ReceiptSha256)
    $item = Read-CrgRetentionRecord -ProjectContext $ProjectContext -ReceiptSha256 $ReceiptSha256 -ExpectedOrigin 'first-attachment-v1'
    $results = [ordered]@{}
    foreach ($domain in @('public', 'private')) {
      $result = Read-CrgRetentionDomainResult -ProjectContext $ProjectContext -Domain $domain -Fields $item.Receipt.Fields -Origin 'first-attachment-v1'
      $results.Add($domain, $result)
    }
    $publicRef = 'refs/crg-results/' + $item.Receipt.Fields['public-result']
    if (-not [string]::Equals((Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain public -Ref $publicRef), $item.Receipt.Fields['public-result'], [System.StringComparison]::Ordinal)) {
      throw 'attachment correction prior public result retention is absent or conflicting'
    }
    return [pscustomobject]@{ Receipt = $item.Receipt; ReceiptBytes = $item.ReceiptBytes; Results = $results }
  } $project $receiptKey
  $handoff = & $handoffReader -Bytes $actualHandoff -ReceiptBytes $record.ReceiptBytes `
    -PublicObjectFormat $project.Domains.public.ObjectFormat -PrivateObjectFormat $project.Domains.private.ObjectFormat
  $fields = $record.Receipt.Fields
  $expected = @{ 'project-id' = $project.Status.ProjectId; 'public-worktree' = $project.Root
    'public-git-dir' = $project.Domains.public.GitDir; 'public-common-dir' = $project.Domains.public.CommonDir
    'private-git-dir' = $project.Domains.private.GitDir; 'public-ref' = $project.Domains.public.Ref
    'private-ref' = $project.Domains.private.Ref }
  foreach ($name in $expected.Keys) {
    if (-not [string]::Equals($fields[$name], $expected[$name], [System.StringComparison]::Ordinal)) { throw "attachment correction prior receipt differs at '$name'" }
  }
  if (-not [string]::Equals($fields['attachment-sha256'], (Get-CrgAttachmentDigest -Bytes $owner.AttachmentBytes), [System.StringComparison]::Ordinal)) {
    throw 'attachment correction prior receipt differs from the exact proposal'
  }
  foreach ($domain in @('public', 'private')) {
    if (-not [string]::Equals($fields[$domain + '-result'], $project.Domains[$domain].Parent, [System.StringComparison]::Ordinal) -or
        -not [System.StringComparer]::Ordinal.Equals($record.Results[$domain].Result.TreeOid, $project.Domains[$domain].ParentTree) -or
        -not [string]::Equals($fields[$domain + '-tree'], $record.Results[$domain].Result.TreeOid, [System.StringComparison]::Ordinal)) {
      throw 'attachment correction requires both branches at the exact retained results'
    }
  }
  $classifier = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-resume-state -Name Get-CrgFirstAttachmentResumeState
  $state = & $classifier -HandoffBytes $actualHandoff -ReceiptBytes $record.ReceiptBytes -PointerBytes $null `
    -ActualPublicOid $project.Domains.public.Parent -ActualPrivateOid $project.Domains.private.Parent `
    -PublicObjectFormat $project.Domains.public.ObjectFormat -PrivateObjectFormat $project.Domains.private.ObjectFormat
  if (-not [string]::Equals($state.State, 'both-new', [System.StringComparison]::Ordinal) -or -not [string]::Equals($state.PointerState, 'absent', [System.StringComparison]::Ordinal) -or
      $state.RequiresFreshReview -ne $true -or $state.ReadyForPublication -ne $false) {
    throw 'attachment correction requires the exact both-new unactivated recovery state'
  }
  $anchor = [pscustomobject]@{ HandoffBytes = [byte[]]$actualHandoff.Clone(); HandoffSha256 = $handoff.HandoffSha256
    ReceiptSha256 = $record.Receipt.ReceiptSha256; RuntimeManifestSha256 = $fields['runtime-manifest-sha256']
    PublicResult = $fields['public-result']; PublicTree = $fields['public-tree']
    PrivateResult = $fields['private-result']; PrivateTree = $fields['private-tree'] }
  if ($null -ne $ExpectedAnchor) {
    foreach ($name in @('HandoffSha256', 'ReceiptSha256', 'RuntimeManifestSha256', 'PublicResult', 'PublicTree', 'PrivateResult', 'PrivateTree')) {
      if (-not [string]::Equals($anchor.$name, $ExpectedAnchor.$name, [System.StringComparison]::Ordinal)) { throw "attachment correction anchor changed at '$name'" }
    }
  }
  return $anchor
}

function Assert-CrgCentralAttachmentCorrectionCandidate {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation,
    [Parameter(Mandatory = $true)][object]$Anchor,
    [switch]$RequireChanges)
  $anchor = Read-CrgCentralAttachmentCorrectionAnchor -Operation $Operation -ExpectedHandoffBytes $Anchor.HandoffBytes -ExpectedAnchor $Anchor
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext
  $getIndex = Get-CrgAttachmentCommand -Runtime $runtime -Module central-context -Name Get-CrgCentralIndexTree
  $indexes = [ordered]@{}
  foreach ($domain in @('public', 'private')) { $indexes.Add($domain, (& $getIndex -ProjectContext $project -Domain $domain)) }
  if (-not [string]::Equals($indexes.public.TreeOid, $anchor.PublicTree, [System.StringComparison]::Ordinal)) { throw 'attachment correction cannot change the retained public result tree' }
  $readTree = Get-CrgAttachmentCommand -Runtime $runtime -Module central-context -Name Read-CrgCentralTreeBytes
  $parseTree = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-tree -Name Read-CrgGitTreeBytes
  $oldBytes = & $readTree -ProjectContext $project -Domain private -TreeOid $anchor.PrivateTree
  $oldTreeEntries = & $parseTree -Bytes $oldBytes -ObjectFormat $project.Domains.private.ObjectFormat
  $newTreeEntries = & $parseTree -Bytes $indexes.private.TreeBytes -ObjectFormat $project.Domains.private.ObjectFormat
  $oldEntries = Get-CrgAttachmentTreeEntryMap -Entries $oldTreeEntries
  $newEntries = Get-CrgAttachmentTreeEntryMap -Entries $newTreeEntries
  if ($oldEntries.Count -ne $newEntries.Count) { throw 'attachment correction cannot add or delete private paths' }
  $allowed = @('AGENTS.md', 'CLAUDE.md'); $changed = New-Object 'System.Collections.Generic.List[string]'
  foreach ($path in $oldEntries.Keys) {
    if (-not $newEntries.ContainsKey($path)) { throw 'attachment correction cannot add or delete private paths' }
    $old = $oldEntries[$path]; $new = $newEntries[$path]
    if ([string]::Equals($path, 'AGENTS.md', [System.StringComparison]::Ordinal) -or [string]::Equals($path, 'CLAUDE.md', [System.StringComparison]::Ordinal)) {
      if (-not [string]::Equals($old.Type, 'blob', [System.StringComparison]::Ordinal) -or -not [string]::Equals($new.Type, 'blob', [System.StringComparison]::Ordinal) -or
          -not ([string]::Equals($old.Mode, '100644', [System.StringComparison]::Ordinal) -or [string]::Equals($old.Mode, '100755', [System.StringComparison]::Ordinal)) -or
          -not [string]::Equals($new.Mode, $old.Mode, [System.StringComparison]::Ordinal)) {
        throw "attachment correction root instruction '$path' changed shape or mode"
      }
      if (-not [string]::Equals($new.Oid, $old.Oid, [System.StringComparison]::Ordinal)) { $changed.Add($path) }
    } elseif (-not [string]::Equals($new.Mode, $old.Mode, [System.StringComparison]::Ordinal) -or -not [string]::Equals($new.Type, $old.Type, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($new.Oid, $old.Oid, [System.StringComparison]::Ordinal)) {
      throw "attachment correction changed non-instruction private path '$path'"
    }
  }
  foreach ($path in $allowed) {
    if (-not $oldEntries.ContainsKey($path)) { throw "attachment correction requires existing private root instruction '$path'" }
  }
  if ($RequireChanges -and $changed.Count -eq 0) { throw 'attachment correction must change at least one retained root instruction' }
  $readSource = Get-CrgAttachmentCommand -Runtime $runtime -Module central-context -Name Read-CrgCentralPreparationSource
  $oldSource = & $readSource -ProjectContext $project -PublicTreeOid $anchor.PublicTree -PrivateTreeOid $anchor.PrivateTree
  $newSource = & $readSource -ProjectContext $project -PublicTreeOid $indexes.public.TreeOid -PrivateTreeOid $indexes.private.TreeOid
  if (-not (Test-CrgAttachmentExactBytes -Left $oldSource.ConfigBytes -Right $newSource.ConfigBytes) -or
      -not (Test-CrgAttachmentExactBytes -Left $oldSource.ValuesBytes -Right $newSource.ValuesBytes) -or
      $oldSource.ModePresent -ne $newSource.ModePresent -or
      -not (Test-CrgAttachmentExactBytes -Left $oldSource.ModeBytes -Right $newSource.ModeBytes)) {
    throw 'attachment correction cannot change project configuration, values, or mode sources'
  }
  return [pscustomobject]@{ Anchor = $anchor; Indexes = $indexes; ChangedInstructions = $changed.ToArray()
    ValidationState = 'validated-first-attachment-instruction-correction'; ReadyForPublication = $false }
}

function Copy-CrgAttachmentPrivateIndex {
  param([object]$Runtime, [object]$NativeModule, [string]$PublicGitDirectory, [byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 67108864) { throw 'adopted private index is absent or exceeds the capture bound' }
  $captured = [byte[]]$Bytes.Clone()
  $expectedDigest = Get-CrgAttachmentDigest -Bytes $captured
  & $NativeModule {
    param([string]$Directory, [byte[]]$Bytes, [string]$ExpectedDigest)
    $pins = New-Object 'System.Collections.Generic.List[object]'
    $handle = $null; $published = $false; $cleanupFailure = $null
    try {
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $Directory -Pins $pins -DenyLeafRename
      $errorCode = 0
      # A present fixed index is adopted on retry. Keep partial writes under an
      # inert metadata name until complete bytes can be published atomically.
      $scratchLeaf = '.crg-index-adoption-' + [guid]::NewGuid().ToString('N')
      $handle = [CrgAttributeNeutral.NativeV1]::CreatePublicationFileRelative($parent.Handle, $scratchLeaf, [ref]$errorCode)
      if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) {
        throw "adopted private index scratch creation failed (Win32 error $errorCode)"
      }
      $added = $false; $borrowed = $null; $stream = $null
      try {
        $handle.DangerousAddRef([ref]$added)
        $borrowed = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($handle.DangerousGetHandle(), $false)
        $stream = [IO.FileStream]::new($borrowed, [IO.FileAccess]::ReadWrite, 8192, $false)
        $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true)
      } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $borrowed) { $borrowed.Dispose() }
        if ($added) { $handle.DangerousRelease() }
      }
      $actual = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $handle }
      if ($actual.Length -ne $Bytes.Length -or -not [string]::Equals($actual.Sha256, $ExpectedDigest, [System.StringComparison]::Ordinal)) { throw 'adopted private index scratch differs from the preserved source bytes' }
      if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($handle, $parent.Handle, 'crg-private-index', [ref]$errorCode)) {
        throw "adopted private index no-replace publication failed (Win32 error $errorCode); any existing destination remains preserved"
      }
      $published = $true
      if (-not [CrgAttributeNeutral.NativeV1]::PathNamesExactHandle((Join-Path $parent.Path 'crg-private-index'), $handle, $false, [ref]$errorCode)) { throw 'adopted private index lost exact publication identity' }
    } finally {
      if ($null -ne $handle) {
        if (-not $published -and -not $handle.IsInvalid) {
          $deleteError = 0
          if (-not [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($handle, $false, [ref]$deleteError)) {
            $cleanupFailure = "adopted private index scratch remains at '$Directory\$scratchLeaf' (Win32 error $deleteError)"
          }
        }
        $handle.Dispose()
      }
      foreach ($pin in $pins) { $pin.Handle.Dispose() }
      if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    }
  } $PublicGitDirectory $captured $expectedDigest
  $copied = & $Runtime.ReadFile -Path (Join-Path $PublicGitDirectory 'crg-private-index') -Maximum 67108864
  if ($null -eq $copied -or $copied.Bytes -isnot [byte[]] -or
      -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $copied.Bytes), $expectedDigest, [System.StringComparison]::Ordinal)) { throw 'adopted private index readback differs from the preserved source bytes' }
}

function Get-CrgAttachmentEntryMap {
  param([object[]]$Entries)
  $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  foreach ($entry in $Entries) {
    if ($null -eq $entry -or $entry.Path -isnot [string] -or
        -not [System.Linq.Enumerable]::Contains([string[]]@('100644', '100755', '120000', '160000'), [string]$entry.Mode, [System.StringComparer]::Ordinal) -or $map.ContainsKey($entry.Path)) {
      throw 'attachment requires a unique complete ordinary index inventory'
    }
    $map.Add($entry.Path, $entry)
  }
  return ,$map
}

function Get-CrgAttachmentTreeEntryMap {
  param([object[]]$Entries)
  $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  foreach ($entry in $Entries) {
    if ($null -eq $entry -or $entry.Path -isnot [string] -or
        -not [System.Linq.Enumerable]::Contains([string[]]@('040000', '100644', '100755', '120000', '160000'), [string]$entry.Mode, [System.StringComparer]::Ordinal) -or $map.ContainsKey($entry.Path)) {
      throw 'attachment correction requires a unique complete tree inventory'
    }
    $map.Add($entry.Path, $entry)
  }
  return ,$map
}

function Update-CrgAttachmentProjectContext {
  param([object]$Operation, [object]$ReadContext)
  $project = $Operation.ProjectContext
  $arguments = @{ TargetRepo = $project.Root; Context = $Operation.Runtime; AttachmentBytes = $Operation.AttachmentBytes }
  if ($null -ne $Operation.PSObject.Properties['CorrectionAnchor']) { $arguments.PendingRecovery = $true }
  $captured = & $ReadContext @arguments
  foreach ($domain in @('public', 'private')) {
    foreach ($name in @('GitDir', 'CommonDir', 'ObjectDir', 'IndexPath', 'Ref', 'Parent', 'ObjectFormat')) {
      if (-not [string]::Equals($project.Domains[$domain].$name, $captured.Domains[$domain].$name, [System.StringComparison]::Ordinal)) { throw "first-attachment $domain association changed at '$name' during admission" }
    }
    if (-not [string]::Equals($project.Domains[$domain].Parent, 'absent', [System.StringComparison]::Ordinal) -and
        -not [string]::Equals($project.Domains[$domain].ParentTree, $captured.Domains[$domain].ParentTree, [System.StringComparison]::Ordinal)) { throw 'first-attachment parent tree changed during admission' }
  }
  # Guard custody retains this project object. Refresh only independently
  # corroborated captured fields without replacing the identity held by guards.
  $project.Domains = $captured.Domains
  $project.Status = $captured.Status
}

function Set-CrgAttachmentMigrationCandidate {
  param([object]$Operation, [byte[]]$ConfigBytes)
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext; $lock = $Operation.OperationLock
  $inventory = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-git-operation -Name Get-CrgPairedGitStageInventory
  $writePrivate = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-git-operation -Name Set-CrgPairedGitPrivateIndex
  $removePaths = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-git-operation -Name Remove-CrgPairedGitIndexPaths
  $readBlob = Get-CrgAttachmentCommand -Runtime $runtime -Module central-context -Name Read-CrgCentralBlobBytes
  $readConfig = Get-CrgAttachmentCommand -Runtime $runtime -Module private-governance -Name Read-CrgProjectConfigBytes
  $ownership = Get-CrgAttachmentCommand -Runtime $runtime -Module private-governance -Name Get-CrgPathOwnership
  $releaseReads = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-operation -Name Release-CrgPairedOperationReadFiles
  $config = & $readConfig -Bytes $ConfigBytes
  $public = Get-CrgAttachmentEntryMap -Entries @((& $inventory -ProjectContext $project -OperationLock $lock -Domain public -Kind Tracked).Value)
  $private = Get-CrgAttachmentEntryMap -Entries @((& $inventory -ProjectContext $project -OperationLock $lock -Domain private -Kind Tracked).Value)
  $readTree = Get-CrgAttachmentCommand -Runtime $runtime -Module central-context -Name Read-CrgCentralTreeBytes
  $parseTree = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-tree -Name Read-CrgGitTreeBytes
  $parentBytes = & $readTree -ProjectContext $project -Domain public -TreeOid $project.Domains.public.ParentTree
  $parentTree = & $parseTree -Bytes $parentBytes -ObjectFormat $project.Domains.public.ObjectFormat
  $parentEntries = @($parentTree | Where-Object { -not [string]::Equals($_.Mode, '040000', [System.StringComparison]::Ordinal) })
  $parentMap = Get-CrgAttachmentEntryMap -Entries $parentEntries
  $privateParentEntries = @()
  if (-not [string]::Equals($project.Domains.private.Parent, 'absent', [System.StringComparison]::Ordinal)) {
    $privateParentBytes = & $readTree -ProjectContext $project -Domain private -TreeOid $project.Domains.private.ParentTree
    $privateParentTree = & $parseTree -Bytes $privateParentBytes -ObjectFormat $project.Domains.private.ObjectFormat
    $privateParentEntries = @($privateParentTree | Where-Object { -not [string]::Equals($_.Mode, '040000', [System.StringComparison]::Ordinal) })
  }
  $privateParentMap = Get-CrgAttachmentEntryMap -Entries $privateParentEntries
  $privateDeletions = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($path in $privateParentMap.Keys) {
    if (-not $private.ContainsKey($path)) { $null = $privateDeletions.Add($path) }
  }
  $changed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($path in @($public.Keys) + @($parentMap.Keys)) {
    if (-not $public.ContainsKey($path) -or -not $parentMap.ContainsKey($path) -or
        -not [string]::Equals($public[$path].Mode, $parentMap[$path].Mode, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($public[$path].Oid, $parentMap[$path].Oid, [System.StringComparison]::Ordinal)) { $null = $changed.Add($path) }
  }
  foreach ($change in (& $ownership -GoverningConfigBytes $ConfigBytes -CandidateConfigBytes $ConfigBytes -Paths ([string[]]@($changed)))) {
    if (-not [string]::Equals($change.Ownership, 'private', [System.StringComparison]::Ordinal)) { throw "Attach preserves but does not include unrelated staged software change '$($change.Path)'; complete that candidate before migration" }
  }
  $selectorSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($path in @($config.PrivateDirectories) + @($config.PrivateFiles) + @('PROJECT-MODE.md', 'PLAN.md', 'History.md')) { $null = $selectorSet.Add($path) }
  $selectors = [string[]]@($selectorSet)
  $paths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($path in @($public.Keys) + @($private.Keys) + @($privateDeletions)) { $null = $paths.Add($path) }
  foreach ($kind in @('Untracked', 'Ignored')) {
    foreach ($entry in @((& $inventory -ProjectContext $project -OperationLock $lock -Domain public -Kind $kind -Paths $selectors).Value)) {
      if ($null -eq $entry -or $entry.Path -isnot [string]) { throw 'attachment untracked inventory is malformed' }
      $null = $paths.Add($entry.Path)
    }
  }
  $classified = & $ownership -GoverningConfigBytes $ConfigBytes -CandidateConfigBytes $ConfigBytes -Paths ([string[]]@($paths))
  $entries = New-Object 'System.Collections.Generic.List[object]'
  $removals = New-Object 'System.Collections.Generic.List[string]'
  foreach ($entry in $classified) {
    $path = $entry.Path
    if (-not [string]::Equals($entry.Ownership, 'private', [System.StringComparison]::Ordinal)) {
      if ($private.ContainsKey($path)) { throw "adopted private index contains software path '$path'; resolve classification explicitly before Attach" }
      continue
    }
    if ($privateDeletions.Contains($path)) {
      if ($public.ContainsKey($path)) { throw "public staged file conflicts with adopted private staged deletion at '$path'; resolve the intended candidate explicitly" }
      continue
    }
    if ($public.ContainsKey($path)) {
      $source = $public[$path]
      if (-not ([string]::Equals($source.Mode, '100644', [System.StringComparison]::Ordinal) -or [string]::Equals($source.Mode, '100755', [System.StringComparison]::Ordinal))) { throw "private migration requires a regular staged file at '$path'" }
      $bytes = & $readBlob -ProjectContext $project -Domain public -BlobOid $source.Oid -Maximum 16777216
      if ($private.ContainsKey($path)) {
        $existing = $private[$path]
        if (-not [string]::Equals($existing.Mode, $source.Mode, [System.StringComparison]::Ordinal)) { throw "public/private staged modes conflict at '$path'; both versions remain preserved" }
        $existingBytes = & $readBlob -ProjectContext $project -Domain private -BlobOid $existing.Oid -Maximum 16777216
        if (-not [string]::Equals((Get-CrgAttachmentDigest -Bytes $existingBytes), (Get-CrgAttachmentDigest -Bytes $bytes), [System.StringComparison]::Ordinal)) {
          throw "public/private staged contents conflict at '$path'; resolve the intended candidate explicitly"
        }
      } else { $entries.Add([pscustomobject]@{ Path = $path; Mode = $source.Mode; Bytes = $bytes }) }
      $removals.Add($path)
    } elseif (-not $private.ContainsKey($path)) {
      # Adopted staged contents win over unstaged working edits. Only newly
      # classified files enter this initial candidate from working bytes.
      $record = & $runtime.ReadFile -Path (Join-Path $project.Root $path.Replace('/', '\')) -Maximum 16777216
      if ($null -eq $record -or $record.Present -ne $true -or $record.Bytes -isnot [byte[]]) { throw 'initial private working file acquisition failed' }
      $entries.Add([pscustomobject]@{ Path = $path; Mode = '100644'; Bytes = [byte[]]$record.Bytes.Clone() })
    }
  }
  # The initial declaration must describe the exact staged configuration, not
  # a loose rewrite that silently overrides preserved adoption staging.
  $configPath = '.crg-project/project.conf'
  $candidateConfig = @($entries | Where-Object { [string]::Equals($_.Path, $configPath, [System.StringComparison]::Ordinal) })
  if ($candidateConfig.Count -eq 1) { $candidateConfigBytes = $candidateConfig[0].Bytes }
  elseif ($private.ContainsKey($configPath)) { $candidateConfigBytes = & $readBlob -ProjectContext $project -Domain private -BlobOid $private[$configPath].Oid -Maximum 65536 }
  else { throw 'initial private candidate lacks the required project configuration' }
  if (-not [string]::Equals((Get-CrgAttachmentDigest -Bytes $candidateConfigBytes), (Get-CrgAttachmentDigest -Bytes $ConfigBytes), [System.StringComparison]::Ordinal)) { throw 'working project configuration differs from the preserved staged candidate' }
  & $releaseReads -Owner $Operation.ReadOwner
  if ($entries.Count -gt 0) { $null = & $writePrivate -ProjectContext $project -OperationLock $lock -Entries $entries.ToArray() }
  if ($removals.Count -gt 0) { $null = & $removePaths -ProjectContext $project -OperationLock $lock -Domain public -Paths $removals.ToArray() }
  return [pscustomobject]@{ PrivateAdditions = @($entries | ForEach-Object { $_.Path }); PublicRemovals = $removals.ToArray() }
}

function Open-CrgCentralAttachment {
  [CmdletBinding(DefaultParameterSetName = 'Attach')]
  param([Parameter(Mandatory = $true)][object]$Runtime,
    [Parameter(Mandatory = $true)][string]$TargetRepo,
    [Parameter(Mandatory = $true, ParameterSetName = 'Attach')][string]$MessageFile,
    [Parameter(Mandatory = $true, ParameterSetName = 'Attach')][ValidatePattern('\A(?:codex|claude)\z', Options = 'None')][string]$AuthoringAgent,
    [Parameter(ParameterSetName = 'Attach')][string]$PrivateGitDir,
    [Parameter(Mandatory = $true, ParameterSetName = 'StagePaths')][ValidateNotNullOrEmpty()][string[]]$StagePaths)
  $stageOnly = $PSCmdlet.ParameterSetName -ceq 'StagePaths'
  $readContext = Get-CrgAttachmentCommand -Runtime $Runtime -Module first-attachment-context -Name Get-CrgCentralFirstAttachmentProjectContext
  $readInput = Get-CrgAttachmentCommand -Runtime $Runtime -Module first-attachment-preparation -Name Get-CrgCentralFirstAttachmentReviewInput
  $validateMessage = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-preparation -Name Assert-CrgPairedMessageBytes
  $capture = Get-CrgAttachmentCommand -Runtime $Runtime -Module central-context -Name Read-CrgCentralTreeBytes
  $readLine = & $capture.Module { Get-Command Get-CrgStatusGitLine -CommandType Function }
  $readAttachment = Get-CrgAttachmentCommand -Runtime $Runtime -Module private-governance -Name Read-CrgAttachmentBytes
  $readConfig = Get-CrgAttachmentCommand -Runtime $Runtime -Module private-governance -Name Read-CrgProjectConfigBytes
  $openLock = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-diff -Name Open-CrgPairedOperationLock
  $openReads = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-operation -Name Open-CrgPairedOperationReads
  $closeReads = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-operation -Name Close-CrgPairedOperationReads
  $releaseReads = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-operation -Name Release-CrgPairedOperationReadFiles
  $openExecutable = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-operation -Name Open-CrgPairedExecutableRead
  $initializeDatabase = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-git-operation -Name Initialize-CrgPairedPrivateDatabase
  $initializeIndex = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-git-operation -Name Initialize-CrgPairedPrivateIndex
  $emptyTree = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-git-operation -Name Write-CrgPairedPrivateEmptyTree
  $readHooksPath = Get-CrgAttachmentCommand -Runtime $Runtime -Module paired-git-operation -Name Get-CrgPairedGitHooksPath
  $openGuards = Get-CrgAttachmentCommand -Runtime $Runtime -Module central-guards -Name Open-CrgCentralGuardCustody
  & $readAttachment.Module { param($Path) Assert-CrgGovernancePath -Path $Path -Absolute -AllowGitMetadata } $TargetRepo
  if ($stageOnly) {
    if ($StagePaths.Count -eq 0 -or $StagePaths.Count -gt 4096) { throw 'pending attachment staging requires a bounded nonempty path list' }
    & $readAttachment.Module {
      param([string[]]$Paths)
      $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($path in $Paths) {
        Assert-CrgGovernancePath -Path $path
        if (-not $seen.Add($path)) { throw 'pending attachment staging paths contain duplicate or case-aliased names' }
      }
    } -Paths $StagePaths
  }
  if (-not [string]::Equals([IO.Path]::GetFullPath($TargetRepo), $TargetRepo, [System.StringComparison]::Ordinal)) { throw 'Attach requires an explicit canonical public worktree root' }
  $gitExe = & $capture.Module { Get-CrgCentralGitExecutable }
  $operation = [pscustomobject]@{ OriginalRuntime = $Runtime; Runtime = $Runtime; ProjectContext = $null; OperationLock = $null; ReadOwner = $null; GitExecutableOwner = $null
    AttachmentBytes = $null; CapturedInput = $null; GuardCustody = $null; NewDirectoryOwners = (New-Object 'System.Collections.Generic.List[object]')
    AuthoringAgent = $AuthoringAgent; Origin = 'first-attachment-v1'; Closed = $false; ReadyForPublication = $false }
  try {
    $operation.GitExecutableOwner = & $openExecutable -Path $gitExe
    $prefix = @('-C', $TargetRepo)
    $root = (& $readLine -Arguments ($prefix + @('rev-parse', '--show-toplevel')) -GitExe $gitExe).Replace('/', '\')
    $gitDir = (& $readLine -Arguments ($prefix + @('rev-parse', '--absolute-git-dir')) -GitExe $gitExe).Replace('/', '\')
    $commonDir = (& $readLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $gitExe).Replace('/', '\')
    if (-not [string]::Equals($TargetRepo, $root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Attach target is not the actual public worktree root' }
    $publicRef = & $readLine -Arguments ($prefix + @('symbolic-ref', '--no-recurse', '-q', 'HEAD')) -GitExe $gitExe
    $parent = & $readLine -Arguments ($prefix + @('rev-parse', '--verify', "$publicRef^{commit}")) -GitExe $gitExe
    $parentTree = & $readLine -Arguments ($prefix + @('rev-parse', '--verify', "$parent^{tree}")) -GitExe $gitExe
    $format = & $readLine -Arguments ($prefix + @('rev-parse', '--show-object-format')) -GitExe $gitExe
    if (-not ([string]::Equals($format, 'sha1', [System.StringComparison]::Ordinal) -or [string]::Equals($format, 'sha256', [System.StringComparison]::Ordinal))) { throw 'Attach public object format is unsupported' }
    $operation.OperationLock = & $openLock -PublicGitDirectory $gitDir
    $roots = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @($root, $gitDir, $commonDir)) { $null = $roots.Add($path) }
    $operation.ReadOwner = & $openReads -Runtime $Runtime -OperationLock $operation.OperationLock -ProjectRoots ([string[]]@($roots)) -ExecutableReads @($operation.GitExecutableOwner)
    $operation.Runtime = $operation.ReadOwner.Runtime
    $pendingHandoffBytes = Get-CrgUnactivatedAttachmentHandoff -Runtime $operation.Runtime -PublicGitDirectory $gitDir
    $pendingRecord = & $operation.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-attachment-pending') -Maximum 16384 -AllowAbsent
    if ($null -ne $pendingHandoffBytes -and -not $pendingRecord.Present) { throw 'attachment correction requires the exact pending proposal' }
    if ($stageOnly) {
      if (-not $pendingRecord.Present) { throw 'pending attachment staging requires an existing proposal' }
      $proposal = & $readAttachment -Bytes $pendingRecord.Bytes
      if (-not [string]::Equals($proposal.PublicRef, $publicRef, [System.StringComparison]::Ordinal) -or
          -not [string]::Equals($proposal.RuntimeStore, $Runtime.Store, [System.StringComparison]::Ordinal)) { throw 'pending attachment proposal differs from the retained public branch or runtime store' }
      $PrivateGitDir = $proposal.PrivateGitDir
      $validateStorage = Get-CrgAttachmentCommand -Runtime $operation.Runtime -Module private-governance -Name Assert-CrgPrivateStorageLocation
      & $validateStorage -PublicRoot $root -PublicGitDir $gitDir -PublicCommonDir $commonDir -PrivateGitDir $PrivateGitDir
      if (-not [IO.Directory]::Exists($PrivateGitDir)) { throw 'pending attachment staging requires the existing private database' }
      $initialization = & $operation.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-attachment-initialization') -Maximum 65536 -AllowAbsent
      $initialized = & $operation.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-attachment-initialized') -Maximum 65536 -AllowAbsent
      if ($initialization.Present -ne $initialized.Present) { throw 'pending attachment staging refuses incomplete private initialization records' }
      if ($initialization.Present) {
        $expectedInitialization = Get-CrgAttachmentInitializationBytes -AttachmentBytes $pendingRecord.Bytes -PublicGitDirectory $gitDir -ObjectFormat $format
        foreach ($record in @($initialization, $initialized)) {
          if (-not [string]::Equals((Get-CrgAttachmentDigest -Bytes $record.Bytes), (Get-CrgAttachmentDigest -Bytes $expectedInitialization), [System.StringComparison]::Ordinal)) { throw 'pending attachment initialization differs from the exact proposal or object format' }
        }
      }
      $null = $roots.Add($PrivateGitDir)
      $expanded = & $openReads -Runtime $Runtime -OperationLock $operation.OperationLock -ProjectRoots ([string[]]@($roots)) -ExecutableReads @($operation.GitExecutableOwner)
      & $closeReads -Owner $operation.ReadOwner
      $operation.ReadOwner = $expanded; $operation.Runtime = $expanded.Runtime
      $privatePrefix = @("--git-dir=$PrivateGitDir", "--work-tree=$root")
      $privateRef = & $readLine -Arguments ($privatePrefix + @('symbolic-ref', '--no-recurse', '-q', 'HEAD')) -GitExe $gitExe
      $privateFormat = & $readLine -Arguments ($privatePrefix + @('rev-parse', '--show-object-format')) -GitExe $gitExe
      if (-not [string]::Equals($privateRef, $proposal.PrivateRef, [System.StringComparison]::Ordinal) -or
          -not ([string]::Equals($privateFormat, 'sha1', [System.StringComparison]::Ordinal) -or [string]::Equals($privateFormat, 'sha256', [System.StringComparison]::Ordinal)) -or
          ($initialization.Present -and -not [string]::Equals($privateFormat, $format, [System.StringComparison]::Ordinal))) { throw 'pending attachment private branch or object format differs from the initialized proposal' }
      $domains = [ordered]@{
        public = [pscustomobject]@{ GitDir = $gitDir; CommonDir = $commonDir; ObjectDir = (Join-Path $commonDir 'objects'); IndexPath = (Join-Path $gitDir 'index'); Ref = $publicRef; Parent = $parent; ParentTree = $parentTree; ObjectFormat = $format }
        private = [pscustomobject]@{ GitDir = $PrivateGitDir; CommonDir = $PrivateGitDir; ObjectDir = (Join-Path $PrivateGitDir 'objects'); IndexPath = (Join-Path $gitDir 'crg-private-index'); Ref = $privateRef; Parent = 'absent'; ParentTree = ''; ObjectFormat = $privateFormat }
      }
      $project = [pscustomobject]@{ Schema = 1; Runtime = $operation.Runtime; Root = $root; GitExe = $gitExe; Domains = $domains; Status = $null }
      $operation.ProjectContext = $project
      $retention = Get-CrgAttachmentCommand -Runtime $operation.Runtime -Module paired-retention -Name Read-CrgFirstAttachmentRetention
      $privateParent = & $retention.Module { param($Project) Get-CrgRetentionRef -ProjectContext $Project -Domain private -Ref $Project.Domains.private.Ref } $project
      if ($null -ne $privateParent) {
        $domains.private.Parent = $privateParent
        $domains.private.ParentTree = & $readLine -Arguments ($privatePrefix + @('rev-parse', '--verify', "$privateParent^{tree}")) -GitExe $gitExe
      }
      $operation.AttachmentBytes = [byte[]]$pendingRecord.Bytes.Clone()
      $project.Status = [pscustomobject]@{ ProjectId = $proposal.ProjectId; Attachment = 'unactivated proposed association'; PublicRoot = $root
        PublicGitDir = $gitDir; PublicCommonDir = $commonDir; PublicRef = $publicRef; PrivateGitDir = $PrivateGitDir; PrivateRef = $privateRef }
      & $releaseReads -Owner $operation.ReadOwner
      Register-CrgAttachmentOwner -Operation $operation
      $owner = Get-CrgAttachmentOwner -Operation $operation
      $association = & $operation.Runtime.ReadFile -Path (Join-Path $PrivateGitDir $owner.AssociationLeaf) -Maximum 65536 -AllowAbsent
      if ($association.Present -and -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $association.Bytes), (Get-CrgAttachmentDigest -Bytes $owner.AssociationBytes), [System.StringComparison]::Ordinal)) { throw 'private branch is already associated with another public worktree or attachment' }
      if ($null -ne $pendingHandoffBytes) {
        foreach ($path in $StagePaths) {
          if (-not ([string]::Equals($path, 'AGENTS.md', [System.StringComparison]::Ordinal) -or [string]::Equals($path, 'CLAUDE.md', [System.StringComparison]::Ordinal))) { throw 'published attachment correction staging accepts only literal AGENTS.md or CLAUDE.md' }
          $working = & $operation.Runtime.ReadFile -Path (Join-Path $root $path) -Maximum 16777216
          if (-not $working.Present -or $working.Bytes -isnot [byte[]]) { throw "attachment correction cannot delete root instruction '$path'" }
        }
        $anchor = Read-CrgCentralAttachmentCorrectionAnchor -Operation $operation -ExpectedHandoffBytes $pendingHandoffBytes
        $null = Assert-CrgCentralAttachmentCorrectionCandidate -Operation $operation -Anchor $anchor
        $operation | Add-Member -NotePropertyName CorrectionAnchor -NotePropertyValue $anchor
      }
      $operation.GuardCustody = & $openGuards -ProjectContext $project -OperationLock $operation.OperationLock -Origin 'first-attachment-v1'
      foreach ($domain in @('public', 'private')) {
        $hooksPath = & $readHooksPath -ProjectContext $project -OperationLock $operation.OperationLock -Domain $domain
        if ($null -eq $hooksPath -or -not [string]::Equals($hooksPath.Value.State, 'unset', [System.StringComparison]::Ordinal)) { throw "$domain effective core.hooksPath must be positively unset before attachment staging" }
      }
      $fixedIndex = & $operation.Runtime.ReadFile -Path $domains.private.IndexPath -Maximum 67108864 -AllowAbsent
      if (-not $fixedIndex.Present) { throw 'pending attachment staging requires the existing fixed private index' }
      & $releaseReads -Owner $operation.ReadOwner
      Update-CrgAttachmentProjectContext -Operation $operation -ReadContext $readContext
      $operation | Add-Member -NotePropertyName ValidationState -NotePropertyValue 'held-pending-attachment-candidate'
      return $operation
    }
    $configBytes = $null
    if ($null -eq $pendingHandoffBytes) {
      $configRecord = & $operation.Runtime.ReadFile -Path (Join-Path $root '.crg-project/project.conf') -Maximum 65536
      $null = & $readConfig -Bytes $configRecord.Bytes
      $configBytes = [byte[]]$configRecord.Bytes.Clone()
    }
    $messagePath = if ([IO.Path]::IsPathRooted($MessageFile)) { [IO.Path]::GetFullPath($MessageFile) } else { [IO.Path]::GetFullPath((Join-Path $root $MessageFile)) }
    if (-not $messagePath.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Attach message file must be inside the explicit public worktree' }
    $messageRecord = & $operation.Runtime.ReadFile -Path $messagePath -Maximum 1048576
    if ($null -eq $messageRecord -or $messageRecord.Bytes -isnot [byte[]]) { throw 'Attach requires retained commit message bytes' }
    & $validateMessage -Bytes $messageRecord.Bytes
    $messageBytes = [byte[]]$messageRecord.Bytes.Clone()
    $proposal = $null
    if ($pendingRecord.Present) {
      $proposal = & $readAttachment -Bytes $pendingRecord.Bytes
      if (-not [string]::Equals($proposal.PublicRef, $publicRef, [System.StringComparison]::Ordinal) -or
          -not [string]::Equals($proposal.RuntimeStore, $Runtime.Store, [System.StringComparison]::Ordinal) -or
          (-not [string]::IsNullOrWhiteSpace($PrivateGitDir) -and -not [string]::Equals($PrivateGitDir, $proposal.PrivateGitDir, [System.StringComparison]::Ordinal))) { throw 'pending attachment proposal conflicts with the requested association' }
      $PrivateGitDir = $proposal.PrivateGitDir
    }
    $projectId = if ($null -eq $proposal) { [guid]::NewGuid().ToString('N') } else { $proposal.ProjectId }
    $explicitPrivate = -not [string]::IsNullOrWhiteSpace($PrivateGitDir)
    if (-not $explicitPrivate) { $PrivateGitDir = Join-Path $commonDir 'crg-governance.git' }
    $validateStorage = Get-CrgAttachmentCommand -Runtime $operation.Runtime -Module private-governance -Name Assert-CrgPrivateStorageLocation
    & $validateStorage -PublicRoot $root -PublicGitDir $gitDir -PublicCommonDir $commonDir -PrivateGitDir $PrivateGitDir
    $existingPrivate = [IO.Directory]::Exists($PrivateGitDir)
    if ($existingPrivate -and -not $explicitPrivate) { throw 'default private database already exists; explicit PrivateGitDir adoption is required without resetting existing history or staging' }
    $initialization = & $operation.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-attachment-initialization') -Maximum 65536 -AllowAbsent
    $initialized = & $operation.Runtime.ReadFile -Path (Join-Path $gitDir 'crg-attachment-initialized') -Maximum 65536 -AllowAbsent
    if (($initialization.Present -or $initialized.Present) -and -not $pendingRecord.Present) { throw 'private initialization records require their exact pending attachment proposal' }
    if ($initialized.Present -and (-not $initialization.Present -or -not $existingPrivate)) { throw 'completed private initialization cannot recreate a missing database' }
    $privateRef = 'refs/heads/crg-' + $projectId
    $initialBytes = $null; $initializationBytes = $null
    if ($initialization.Present -or -not $existingPrivate) {
      $initialText = @('crg-attachment v1', ('project-id ' + $projectId), ('runtime-store ' + $Runtime.Store),
        ('private-git-dir ' + $PrivateGitDir), ('public-ref ' + $publicRef), ('private-ref ' + $privateRef)) -join "`n"
      $initialBytes = [Text.UTF8Encoding]::new($false).GetBytes($initialText + "`n")
      $null = & $readAttachment -Bytes $initialBytes
      if ($pendingRecord.Present -and -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $pendingRecord.Bytes), (Get-CrgAttachmentDigest -Bytes $initialBytes), [System.StringComparison]::Ordinal)) { throw 'new private initialization differs from the pending proposal; adoption is never initialized' }
      $initializationBytes = Get-CrgAttachmentInitializationBytes -AttachmentBytes $initialBytes -PublicGitDirectory $gitDir -ObjectFormat $format
      foreach ($record in @($initialization, $initialized)) {
        if ($record.Present -and -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $record.Bytes), (Get-CrgAttachmentDigest -Bytes $initializationBytes), [System.StringComparison]::Ordinal)) { throw 'private initialization record conflicts with the exact proposal or object format' }
      }
      if ($null -eq $pendingHandoffBytes) {
        & $releaseReads -Owner $operation.ReadOwner -Paths @((Join-Path $gitDir 'crg-attachment-pending'), (Join-Path $gitDir 'crg-attachment-initialization'))
        Write-CrgAttachmentRecord -Runtime $operation.Runtime -NativeModule $openLock.Module -Directory $gitDir -Leaf 'crg-attachment-pending' -Bytes $initialBytes
        Write-CrgAttachmentRecord -Runtime $operation.Runtime -NativeModule $openLock.Module -Directory $gitDir -Leaf 'crg-attachment-initialization' -Bytes $initializationBytes
      }
    }
    $continueInitialization = $null -ne $initialBytes -and -not $initialized.Present
    $privateDirectory = $null
    if ($continueInitialization) {
      $privateDirectory = New-CrgAttachmentDirectory -NativeModule $openLock.Module -Path $PrivateGitDir -AllowExisting:$initialization.Present
      $operation.NewDirectoryOwners.Add($privateDirectory)
    }
    $null = $roots.Add($PrivateGitDir)
    $expanded = & $openReads -Runtime $Runtime -OperationLock $operation.OperationLock -ProjectRoots ([string[]]@($roots)) -ExecutableReads @($operation.GitExecutableOwner)
    & $closeReads -Owner $operation.ReadOwner
    $operation.ReadOwner = $expanded; $operation.Runtime = $expanded.Runtime
    $domains = [ordered]@{
      public = [pscustomobject]@{ GitDir = $gitDir; CommonDir = $commonDir; ObjectDir = (Join-Path $commonDir 'objects'); IndexPath = (Join-Path $gitDir 'index'); Ref = $publicRef; Parent = $parent; ParentTree = $parentTree; ObjectFormat = $format }
      private = [pscustomobject]@{ GitDir = $PrivateGitDir; CommonDir = $PrivateGitDir; ObjectDir = (Join-Path $PrivateGitDir 'objects'); IndexPath = (Join-Path $gitDir 'crg-private-index'); Ref = $privateRef; Parent = 'absent'; ParentTree = ''; ObjectFormat = $format }
    }
    $project = [pscustomobject]@{ Schema = 1; Runtime = $operation.Runtime; Root = $root; GitExe = $gitExe; Domains = $domains; Status = $null }
    $operation.ProjectContext = $project
    if ($continueInitialization) {
      $null = & $initializeDatabase -ProjectContext $project -OperationLock $operation.OperationLock -OwnedDirectory $privateDirectory -AttachmentBytes $initialBytes
      & $releaseReads -Owner $operation.ReadOwner -Paths @((Join-Path $gitDir 'crg-attachment-initialized'))
      Write-CrgAttachmentRecord -Runtime $operation.Runtime -NativeModule $openLock.Module -Directory $gitDir -Leaf 'crg-attachment-initialized' -Bytes $initializationBytes
    } else {
      $privatePrefix = @("--git-dir=$PrivateGitDir", "--work-tree=$root")
      $domains.private.Ref = & $readLine -Arguments ($privatePrefix + @('symbolic-ref', '--no-recurse', '-q', 'HEAD')) -GitExe $gitExe
      $domains.private.ObjectFormat = & $readLine -Arguments ($privatePrefix + @('rev-parse', '--show-object-format')) -GitExe $gitExe
      $retention = Get-CrgAttachmentCommand -Runtime $operation.Runtime -Module paired-retention -Name Read-CrgFirstAttachmentRetention
      $privateParent = & $retention.Module { param($Project) Get-CrgRetentionRef -ProjectContext $Project -Domain private -Ref $Project.Domains.private.Ref } $project
      if ($null -ne $privateParent) {
        $domains.private.Parent = $privateParent
        $domains.private.ParentTree = & $readLine -Arguments ($privatePrefix + @('rev-parse', '--verify', "$privateParent^{tree}")) -GitExe $gitExe
      }
    }
    $attachmentText = @('crg-attachment v1', ('project-id ' + $projectId), ('runtime-store ' + $Runtime.Store),
      ('private-git-dir ' + $PrivateGitDir), ('public-ref ' + $publicRef), ('private-ref ' + $domains.private.Ref)) -join "`n"
    $operation.AttachmentBytes = [Text.UTF8Encoding]::new($false).GetBytes($attachmentText + "`n")
    $null = & $readAttachment -Bytes $operation.AttachmentBytes
    if ($pendingRecord.Present -and -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $pendingRecord.Bytes), (Get-CrgAttachmentDigest -Bytes $operation.AttachmentBytes), [System.StringComparison]::Ordinal)) { throw 'pending proposal no longer matches the actual private branch; no association is replaced' }
    $project.Status = [pscustomobject]@{ ProjectId = $projectId; Attachment = 'unactivated proposed association'; PublicRoot = $root
      PublicGitDir = $gitDir; PublicCommonDir = $commonDir; PublicRef = $publicRef; PrivateGitDir = $PrivateGitDir; PrivateRef = $domains.private.Ref }
    if ($null -eq $pendingHandoffBytes) {
      & $releaseReads -Owner $operation.ReadOwner
      Write-CrgAttachmentRecord -Runtime $operation.Runtime -NativeModule $openLock.Module -Directory $gitDir -Leaf 'crg-attachment-pending' -Bytes $operation.AttachmentBytes
    }
    Register-CrgAttachmentOwner -Operation $operation
    $owner = Get-CrgAttachmentOwner -Operation $operation
    $association = & $operation.Runtime.ReadFile -Path (Join-Path $PrivateGitDir $owner.AssociationLeaf) -Maximum 65536 -AllowAbsent
    if ($association.Present -and -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $association.Bytes), (Get-CrgAttachmentDigest -Bytes $owner.AssociationBytes), [System.StringComparison]::Ordinal)) { throw 'private branch is already associated with another public worktree or attachment' }
    if ($null -ne $pendingHandoffBytes) {
      $anchor = Read-CrgCentralAttachmentCorrectionAnchor -Operation $operation -ExpectedHandoffBytes $pendingHandoffBytes
      $null = Assert-CrgCentralAttachmentCorrectionCandidate -Operation $operation -Anchor $anchor -RequireChanges
      $operation | Add-Member -NotePropertyName CorrectionAnchor -NotePropertyValue $anchor
    }
    $operation.GuardCustody = & $openGuards -ProjectContext $project -OperationLock $operation.OperationLock -Origin 'first-attachment-v1'
    # Index initialization and staging can invoke Git hooks. Establish the same
    # effective hook location before those writes, not only before publication.
    foreach ($domain in @('public', 'private')) {
      $hooksPath = & $readHooksPath -ProjectContext $project -OperationLock $operation.OperationLock -Domain $domain
      if ($null -eq $hooksPath -or -not [string]::Equals($hooksPath.Value.State, 'unset', [System.StringComparison]::Ordinal)) { throw "$domain effective core.hooksPath must be positively unset before attachment staging" }
    }
    $fixedIndex = & $operation.Runtime.ReadFile -Path $domains.private.IndexPath -Maximum 67108864 -AllowAbsent
    if (-not $fixedIndex.Present) {
      $adoptedIndex = & $operation.Runtime.ReadFile -Path (Join-Path $PrivateGitDir 'index') -Maximum 67108864 -AllowAbsent
      if ($existingPrivate -and $adoptedIndex.Present) {
        $bytes = [byte[]]$adoptedIndex.Bytes.Clone()
        & $releaseReads -Owner $operation.ReadOwner
        Copy-CrgAttachmentPrivateIndex -Runtime $operation.Runtime -NativeModule $openLock.Module -PublicGitDirectory $gitDir -Bytes $bytes
      } else {
        & $releaseReads -Owner $operation.ReadOwner
        $null = & $initializeIndex -ProjectContext $project -OperationLock $operation.OperationLock
      }
    }
    if ($null -eq $pendingHandoffBytes) {
      & $releaseReads -Owner $operation.ReadOwner
      $null = & $emptyTree -ProjectContext $project -OperationLock $operation.OperationLock
      Update-CrgAttachmentProjectContext -Operation $operation -ReadContext $readContext
      $migration = Set-CrgAttachmentMigrationCandidate -Operation $operation -ConfigBytes $configBytes
    } else {
      # Both published indexes already define the correction baseline. Initial
      # migration would inspect and stage unrelated working paths.
      $migration = [pscustomobject]@{ PrivateAdditions = @(); PublicRemovals = @() }
    }
    $operation | Add-Member -NotePropertyName Migration -NotePropertyValue $migration
    $message = & $operation.Runtime.ReadFile -Path $messagePath -Maximum 1048576
    if ($null -eq $message -or $message.Bytes -isnot [byte[]] -or
        -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $message.Bytes), (Get-CrgAttachmentDigest -Bytes $messageBytes), [System.StringComparison]::Ordinal)) { throw 'Attach message changed during admission' }
    if ($null -eq $pendingHandoffBytes) {
      Assert-CrgAttachmentAbsent -Runtime $operation.Runtime -PublicGitDirectory $gitDir
    } else {
      $null = Assert-CrgCentralAttachmentCorrectionCandidate -Operation $operation -Anchor $operation.CorrectionAnchor -RequireChanges
    }
    Update-CrgAttachmentProjectContext -Operation $operation -ReadContext $readContext
    $operation.CapturedInput = & $readInput -ProjectContext $operation.ProjectContext -AttachmentBytes $operation.AttachmentBytes -OperationId ([guid]::NewGuid().ToString('N')) -MessageBytes $message.Bytes -TempParent $PrivateGitDir -MaximumBlobBytes 33554432 -MaximumContextBytes 536870912
    if ($null -ne $pendingHandoffBytes -and -not $operation.CapturedInput.HasChanges) { throw 'attachment correction did not produce a changed captured pair' }
    return $operation
  } catch {
    # The caller receives live ownership even when a dependency cannot establish
    # child quiescence. No broad cleanup or new attachment follows a failed open.
    $_.Exception.Data['CrgCentralAttachmentOperation'] = $operation
    throw
  }
}

function Close-CrgCentralAttachment {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation)
  if ($null -eq $Operation -or $Operation.Closed) { throw 'attachment close requires the current open owner after child quiescence' }
  $runtime = $Operation.Runtime
  if ($null -ne $Operation.PSObject.Properties['InstructionReadOwner'] -and $null -ne $Operation.InstructionReadOwner) {
    $assertInstructions = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-operation -Name Assert-CrgPairedOperationReads
    $closeInstructions = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-operation -Name Close-CrgPairedOperationReads
    & $assertInstructions -Owner $Operation.InstructionReadOwner
    & $closeInstructions -Owner $Operation.InstructionReadOwner
    $Operation.InstructionReadOwner = $null
  }
  if ($null -ne $Operation.GuardCustody) {
    $closeGuards = Get-CrgAttachmentCommand -Runtime $runtime -Module central-guards -Name Close-CrgCentralGuardCustody
    & $closeGuards -GuardCustody $Operation.GuardCustody
  }
  if ($null -ne $Operation.ReadOwner) {
    $closeReads = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-operation -Name Close-CrgPairedOperationReads
    & $closeReads -Owner $Operation.ReadOwner
  }
  foreach ($directory in $Operation.NewDirectoryOwners) {
    $directory.Handle.Dispose()
    foreach ($pin in $directory.DirectoryPins) { $pin.Handle.Dispose() }
  }
  if ($null -ne $Operation.OperationLock) {
    $closeLock = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-diff -Name Close-CrgPairedOperationLock
    & $closeLock -Lock $Operation.OperationLock
  }
  if ($null -ne $Operation.GitExecutableOwner) {
    $closeExecutable = Get-CrgAttachmentCommand -Runtime $runtime -Module paired-operation -Name Close-CrgPairedExecutableRead
    & $closeExecutable -Owner $Operation.GitExecutableOwner
  }
  $Operation.Closed = $true
  if ($Operation.AttachmentOwnerId -is [string]) { $null = $script:CrgAttachmentOwners.Remove($Operation.AttachmentOwnerId) }
}

function Register-CrgCentralAttachmentRecovery {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation,
    [Parameter(Mandatory = $true)][byte[]]$AttachmentBytes)
  if ($null -eq $Operation -or $null -eq $Operation.ReadOwner -or $null -eq $Operation.GitExecutableOwner -or
      $null -eq $Operation.OperationLock -or $Operation.Runtime.ReadFile -isnot [scriptblock]) { throw 'attachment recovery requires actual retained operation owners' }
  $assertReads = Get-CrgAttachmentCommand -Runtime $Operation.Runtime -Module paired-operation -Name Assert-CrgPairedOperationReads
  & $assertReads -Owner $Operation.ReadOwner
  $pending = & $Operation.Runtime.ReadFile -Path (Join-Path $Operation.ProjectContext.Domains.public.GitDir 'crg-attachment-pending') -Maximum 16384
  if ($pending.Bytes -isnot [byte[]] -or -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $pending.Bytes), (Get-CrgAttachmentDigest -Bytes $AttachmentBytes), [System.StringComparison]::Ordinal)) { throw 'attachment recovery proposal differs from the independently retained transaction' }
  $Operation | Add-Member -NotePropertyName AttachmentBytes -NotePropertyValue ([byte[]]$AttachmentBytes.Clone()) -Force
  if ($null -eq $Operation.PSObject.Properties['Closed']) { $Operation | Add-Member -NotePropertyName Closed -NotePropertyValue $false }
  if ($null -eq $Operation.PSObject.Properties['NewDirectoryOwners']) { $Operation | Add-Member -NotePropertyName NewDirectoryOwners -NotePropertyValue (New-Object 'System.Collections.Generic.List[object]') }
  Register-CrgAttachmentOwner -Operation $Operation
  # This registration binds mutable metadata ownership, never historical PASS.
}

function Complete-CrgCentralAttachmentAssociation {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation)
  $owner = Get-CrgAttachmentOwner -Operation $Operation
  $project = $Operation.ProjectContext
  $handoffFile = & $owner.Runtime.ReadFile -Path (Join-Path $owner.PublicGitDirectory 'crg-handoff') -Maximum 16384
  $readHandoff = Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-governance -Name Read-CrgFirstAttachmentHandoffBytes
  $receiptKey = & $readHandoff.Module {
    param([byte[]]$Bytes)
    $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 16384
    $names = @(Get-CrgHandoffNames -Origin 'first-attachment-v1')
    if ($lines.Count -ne $names.Count + 1 -or -not [string]::Equals($lines[0], 'crg-first-attachment-handoff v1', [System.StringComparison]::Ordinal)) { throw 'association completion requires the durable first-attachment handoff' }
    $key = ''
    for ($index = 0; $index -lt $names.Count; $index++) {
      $value = Read-CrgPairField -Line $lines[$index + 1] -Name $names[$index]
      if ($names[$index] -ceq 'receipt-sha256') { $key = $value }
    }
    return $key
  } $handoffFile.Bytes
  $retention = Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-retention -Name Read-CrgFirstAttachmentRetention
  $record = & $retention.Module { param($Project, $Key) Read-CrgRetentionRecord -ProjectContext $Project -ReceiptSha256 $Key -ExpectedOrigin 'first-attachment-v1' } $project $receiptKey
  $handoff = & $readHandoff -Bytes $handoffFile.Bytes -ReceiptBytes $record.ReceiptBytes -PublicObjectFormat $project.Domains.public.ObjectFormat -PrivateObjectFormat $project.Domains.private.ObjectFormat
  if (-not [string]::Equals($handoff.Fields['attachment-sha256'], (Get-CrgAttachmentDigest -Bytes $owner.AttachmentBytes), [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($record.Receipt.Fields['public-git-dir'], $owner.PublicGitDirectory, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($record.Receipt.Fields['private-git-dir'], $owner.PrivateGitDirectory, [System.StringComparison]::Ordinal)) { throw 'durable first-attachment handoff differs from the registered association' }
  $release = Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-operation -Name Release-CrgPairedOperationReadFiles
  & $release -Owner $Operation.ReadOwner -Paths @((Join-Path $owner.PrivateGitDirectory $owner.AssociationLeaf))
  $native = (Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-diff -Name Assert-CrgPairedOperationLock).Module
  Write-CrgAttachmentRecord -Runtime $owner.Runtime -NativeModule $native -Directory $owner.PrivateGitDirectory -Leaf $owner.AssociationLeaf -Bytes $owner.AssociationBytes
  return [pscustomobject]@{ AssociationPath = (Join-Path $owner.PrivateGitDirectory $owner.AssociationLeaf); ReadyForPublication = $false }
}

function Remove-CrgCentralAttachmentProposal {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation)
  $owner = Get-CrgAttachmentOwner -Operation $Operation
  $attachment = & $owner.Runtime.ReadFile -Path (Join-Path $owner.PublicGitDirectory 'crg-attachment') -Maximum 16384
  $pointer = & $owner.Runtime.ReadFile -Path (Join-Path $owner.PublicGitDirectory 'crg-pair') -Maximum 256
  $pending = & $owner.Runtime.ReadFile -Path (Join-Path $owner.PublicGitDirectory 'crg-attachment-pending') -Maximum 16384
  $handoff = & $owner.Runtime.ReadFile -Path (Join-Path $owner.PublicGitDirectory 'crg-handoff') -Maximum 16384 -AllowAbsent
  if ($handoff.Present -or -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $attachment.Bytes), (Get-CrgAttachmentDigest -Bytes $owner.AttachmentBytes), [System.StringComparison]::Ordinal) -or
      -not [string]::Equals((Get-CrgAttachmentDigest -Bytes $pending.Bytes), (Get-CrgAttachmentDigest -Bytes $owner.AttachmentBytes), [System.StringComparison]::Ordinal)) { throw 'attachment proposal cleanup requires exact activated attachment and no pending publication' }
  $readPointer = Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-governance -Name Read-CrgCompletedPairPointerBytes
  $completed = & $readPointer -Bytes $pointer.Bytes
  if (-not [string]::Equals($completed.Origin, 'first-attachment-v1', [System.StringComparison]::Ordinal)) { throw 'initial proposal cleanup requires first-attachment completion' }
  $release = Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-operation -Name Release-CrgPairedOperationReadFiles
  & $release -Owner $Operation.ReadOwner -Paths @((Join-Path $owner.PublicGitDirectory 'crg-attachment-pending'))
  $native = (Get-CrgAttachmentCommand -Runtime $owner.Runtime -Module paired-diff -Name Assert-CrgPairedOperationLock).Module
  & $native {
    param([string]$Directory, [byte[]]$Expected)
    $pins = New-Object 'System.Collections.Generic.List[object]'
    $handle = $null
    try {
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $Directory -Pins $pins -DenyLeafRename
      $errorCode = 0
      $handle = [CrgAttributeNeutral.NativeV1]::OpenPublicationFileRelative($parent.Handle, 'crg-attachment-pending', [ref]$errorCode)
      if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) { throw 'pending attachment proposal lost exact ordinary custody' }
      $actual = Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $handle }
      $sha = [Security.Cryptography.SHA256]::Create()
      try { $expectedSha = ([BitConverter]::ToString($sha.ComputeHash($Expected))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
      if ($actual.Length -ne $Expected.Length -or -not [string]::Equals($actual.Sha256, $expectedSha, [System.StringComparison]::Ordinal)) { throw 'pending attachment proposal changed before exact cleanup' }
      if (-not [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($handle, $false, [ref]$errorCode)) { throw "pending attachment proposal exact cleanup failed (Win32 error $errorCode)" }
    } finally {
      if ($null -ne $handle) { $handle.Dispose() }
      foreach ($pin in $pins) { $pin.Handle.Dispose() }
    }
  } $owner.PublicGitDirectory $owner.AttachmentBytes
}

Export-ModuleMember -Function Open-CrgCentralAttachment, Close-CrgCentralAttachment, Register-CrgCentralAttachmentRecovery, Complete-CrgCentralAttachmentAssociation, Remove-CrgCentralAttachmentProposal, Assert-CrgCentralAttachmentCorrectionCandidate
