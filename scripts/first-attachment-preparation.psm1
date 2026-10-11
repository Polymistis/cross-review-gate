# Actual first-attachment acquisition. Bootstrap authority comes from the retained
# runtime, never adopted history, candidate policy or a constructed receipt.

function Get-CrgFirstAttachmentPreparationCommand {
  param([string]$Module, [string]$Name)
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($commands.Count -ne 1) { throw "first-attachment preparation requires one retained '$Module/$Name' command" }
  return $commands[0]
}

function Get-CrgCentralFirstAttachmentReviewInput {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$AttachmentBytes,
    [Parameter(Mandatory = $true)][string]$OperationId,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$MessageBytes,
    [Parameter(Mandatory = $true)][string]$TempParent,
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$MaximumBlobBytes,
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][long]$MaximumContextBytes)
  if ($OperationId -cnotmatch '\A[0-9a-f]{32}\z') { throw 'first-attachment preparation requires a canonical operation identity' }
  $validateMessage = Get-CrgFirstAttachmentPreparationCommand -Module paired-preparation -Name Assert-CrgPairedMessageBytes
  & $validateMessage -Bytes $MessageBytes
  if ($null -eq $ProjectContext -or $ProjectContext.Schema -ne 1 -or
      $ProjectContext.Domains -isnot [System.Collections.IDictionary] -or
      @($ProjectContext.Domains.Keys).Count -ne 2 -or
      -not [System.Linq.Enumerable]::Contains([string[]]@($ProjectContext.Domains.Keys), 'public', [System.StringComparer]::Ordinal) -or
      -not [System.Linq.Enumerable]::Contains([string[]]@($ProjectContext.Domains.Keys), 'private', [System.StringComparer]::Ordinal)) { throw 'first-attachment preparation requires both captured Git domains' }
  $runtime = $ProjectContext.Runtime
  if ($null -eq $runtime -or $runtime.ReadFile -isnot [scriptblock] -or
      $runtime.Id -cnotmatch '\A[0-9a-f]{64}\z' -or $runtime.Payloads -isnot [System.Collections.IDictionary]) { throw 'first-attachment preparation requires the retained runtime context' }
  $templatePath = 'scripts/codex/review-prompt-template.md'
  if (-not [System.Linq.Enumerable]::Contains([string[]]@($runtime.Payloads.Keys), $templatePath, [System.StringComparer]::Ordinal) -or $runtime.Payloads[$templatePath].Bytes -isnot [byte[]]) { throw 'first-attachment preparation requires retained runtime prompt bytes' }
  $template = $runtime.Payloads[$templatePath].Bytes
  $commands = @{}
  foreach ($item in @(
    @{ Module = 'private-governance'; Name = 'Read-CrgAttachmentBytes' },
    @{ Module = 'private-governance'; Name = 'Assert-CrgCandidateGrokRecord' },
    @{ Module = 'central-context'; Name = 'Read-CrgCentralTreeBytes' },
    @{ Module = 'central-context'; Name = 'Get-CrgCentralIndexTree' },
    @{ Module = 'central-context'; Name = 'Read-CrgCentralPreparationSource' },
    @{ Module = 'central-context'; Name = 'Read-CrgCentralBlobBytes' },
    @{ Module = 'central-context'; Name = 'Read-CrgCentralObjectBatch' },
    @{ Module = 'central-context'; Name = 'Read-CrgCentralCommitLogBytes' },
    @{ Module = 'central-context'; Name = 'Write-CrgCentralPrivateMessageBlob' },
    @{ Module = 'project-preparation'; Name = 'New-CrgBootstrapProjectPreparationBytes' },
    @{ Module = 'project-preparation'; Name = 'Read-CrgBootstrapProjectPreparationBytes' },
    @{ Module = 'project-preparation'; Name = 'New-CrgProjectPreparationBytes' },
    @{ Module = 'paired-tree'; Name = 'Read-CrgPairedTreeBytes' },
    @{ Module = 'paired-diff'; Name = 'Get-CrgPairedGitDiffEvidence' },
    @{ Module = 'paired-review-input'; Name = 'New-CrgPreparedFirstAttachmentBundleBytes' }
  )) { $commands[$item.Name] = Get-CrgFirstAttachmentPreparationCommand -Module $item.Module -Name $item.Name }
  # Proposed association bytes are retained caller data. Reading an installed
  # crg-attachment here would require activation before the mandatory first review.
  $attachment = & $commands['Read-CrgAttachmentBytes'] -Bytes $AttachmentBytes
  # Ordinal: -ceq/-cne compare by culture and ignore characters such as U+00AD.
  if (-not [string]::Equals($attachment.ProjectId, $ProjectContext.Status.ProjectId, [System.StringComparison]::Ordinal) -or
      -not [string]::Equals($attachment.PublicRef, $ProjectContext.Domains.public.Ref, [StringComparison]::Ordinal) -or
      -not [string]::Equals($attachment.PrivateRef, $ProjectContext.Domains.private.Ref, [StringComparison]::Ordinal) -or
      -not [string]::Equals($attachment.PrivateGitDir, $ProjectContext.Domains.private.GitDir, [StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::Equals($attachment.RuntimeStore, $runtime.Store, [StringComparison]::OrdinalIgnoreCase)) { throw 'first-attachment proposal differs from the captured association' }
  foreach ($domain in @('public', 'private')) {
    $selected = $ProjectContext.Domains[$domain]
    if (-not ([string]::Equals($selected.ObjectFormat, 'sha1', [StringComparison]::Ordinal) -or [string]::Equals($selected.ObjectFormat, 'sha256', [StringComparison]::Ordinal))) { throw 'first-attachment object format is unsupported' }
    $width = if ([string]::Equals($selected.ObjectFormat, 'sha1', [StringComparison]::Ordinal)) { 40 } else { 64 }
    $oidPattern = '\A[0-9a-f]{' + $width + '}\z'
    if ($selected.ParentTree -cnotmatch $oidPattern -or $selected.ParentTree -match '\A0+\z') { throw 'first-attachment parent tree has invalid domain identity' }
    if ([string]::Equals($domain, 'private', [StringComparison]::Ordinal) -and [string]::Equals($selected.Parent, 'absent', [StringComparison]::Ordinal)) { continue }
    if ($selected.Parent -cnotmatch $oidPattern -or $selected.Parent -match '\A0+\z') { throw 'first-attachment ancestry requires an actual parent or literal private absence' }
  }
  $emptyHash = if ([string]::Equals($ProjectContext.Domains.private.ObjectFormat, 'sha1', [StringComparison]::Ordinal)) { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
  try { $emptyTree = ([BitConverter]::ToString($emptyHash.ComputeHash([Text.Encoding]::ASCII.GetBytes('tree 0' + [char]0)))).Replace('-', '').ToLowerInvariant() }
  finally { $emptyHash.Dispose() }
  if ([string]::Equals($ProjectContext.Domains.private.Parent, 'absent', [StringComparison]::Ordinal) -and
      -not [string]::Equals($ProjectContext.Domains.private.ParentTree, $emptyTree, [StringComparison]::Ordinal)) { throw 'absent private ancestry requires the actual empty-tree baseline' }
  # The live owner creates the real empty-tree object before acquisition. An
  # adopted parent remains ancestry but never supplies the initial review baseline.
  $emptyBytes = & $commands['Read-CrgCentralTreeBytes'] -ProjectContext $ProjectContext -Domain private -TreeOid $emptyTree
  if ($emptyBytes -isnot [byte[]] -or $emptyBytes.Length -ne 0) { throw 'first-attachment private review baseline is not the actual empty tree' }
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $attachmentSha = ([BitConverter]::ToString($sha.ComputeHash($AttachmentBytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
  $indexes = [ordered]@{}
  foreach ($domain in @('public', 'private')) { $indexes[$domain] = & $commands['Get-CrgCentralIndexTree'] -ProjectContext $ProjectContext -Domain $domain }
  $hasChanges = -not [string]::Equals($indexes.public.TreeOid, $ProjectContext.Domains.public.ParentTree, [StringComparison]::Ordinal) -or
    -not [string]::Equals($indexes.private.TreeOid, $ProjectContext.Domains.private.ParentTree, [StringComparison]::Ordinal)
  $preparations = [ordered]@{}
  $preparations.governing = & $commands['New-CrgBootstrapProjectPreparationBytes'] -RuntimeSha256 $runtime.Id -TemplateBytes $template
  $sources = [ordered]@{}
  $sources.governing = & $commands['Read-CrgBootstrapProjectPreparationBytes'] -Bytes $preparations.governing -ExpectedRuntimeSha256 $runtime.Id -TemplateBytes $template
  $sources.candidate = & $commands['Read-CrgCentralPreparationSource'] -ProjectContext $ProjectContext -PublicTreeOid $indexes.public.TreeOid -PrivateTreeOid $indexes.private.TreeOid
  $source = $sources.candidate
  $preparations.candidate = & $commands['New-CrgProjectPreparationBytes'] -Kind candidate -RuntimeSha256 $runtime.Id -ConfigBytes $source.ConfigBytes -ValuesBytes $source.ValuesBytes -ModePresent $source.ModePresent -ModeBytes $source.ModeBytes -TemplateBytes $template
  $trees = & $commands['Read-CrgPairedTreeBytes'] -PublicTreeBytes $indexes.public.TreeBytes -PrivateTreeBytes $indexes.private.TreeBytes -PublicObjectFormat $ProjectContext.Domains.public.ObjectFormat -PrivateObjectFormat $ProjectContext.Domains.private.ObjectFormat -GoverningConfigBytes $sources.governing.ConfigBytes -CandidateConfigBytes $sources.candidate.ConfigBytes
  # A first attachment has no prior project record, so any legacy grok-provider record is new.
  & $commands['Assert-CrgCandidateGrokRecord'] -CandidateConfigBytes $sources.candidate.ConfigBytes
  $blobs = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  [long]$totalBytes = 0
  foreach ($domain in @('public', 'private')) {
    $entries = $trees.PublicEntries
    if ($domain -ceq 'private') { $entries = $trees.PrivateEntries }
    $regular = @($entries | Where-Object { -not ([string]::Equals($_.Mode, '040000', [StringComparison]::Ordinal) -or [string]::Equals($_.Mode, '160000', [StringComparison]::Ordinal)) })
    $requests = @(foreach ($entry in $regular) { [pscustomobject]@{ Oid = $entry.Oid; Type = 'blob'; Maximum = [int]$MaximumBlobBytes } })
    $remaining = $MaximumContextBytes - $totalBytes
    if ($remaining -lt 0) { throw 'first-attachment context exceeds the aggregate byte bound' }
    $batch = & $commands['Read-CrgCentralObjectBatch'] -ProjectContext $ProjectContext -Domain $domain -Requests @($requests) -MaximumAggregate $remaining
    foreach ($entry in $regular) {
      $bytes = $batch[$entry.Oid]
      if ($bytes -isnot [byte[]]) { throw 'first-attachment batch capture omitted a regular context blob' }
      $totalBytes += $bytes.Length
      if ($totalBytes -gt $MaximumContextBytes) { throw 'first-attachment context exceeds the aggregate byte bound' }
      $blobs.Add($entry.Path, $bytes)
    }
  }
  $evidence = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  foreach ($domain in @('public', 'private')) {
    $baseline = $ProjectContext.Domains.public.ParentTree
    if ($domain -ceq 'private') { $baseline = $emptyTree }
    $diff = & $commands['Get-CrgPairedGitDiffEvidence'] -ProjectContext $ProjectContext -Domain $domain -ParentTree $baseline -CandidateTree $indexes[$domain].TreeOid -TempParent $TempParent
    if ($diff.Ok -isnot [bool] -or -not $diff.Ok -or -not [string]::Equals($diff.Domain, $domain, [StringComparison]::Ordinal) -or
        -not [string]::Equals($diff.ParentTree, $baseline, [StringComparison]::Ordinal) -or
        -not [string]::Equals($diff.CandidateTree, $indexes[$domain].TreeOid, [StringComparison]::Ordinal)) {
      $inner = if ($diff.Failure -is [Exception]) { $diff.Failure } else { $null }
      throw [InvalidOperationException]::new("first-attachment $domain diff capture failed: $($diff.Reason)", $inner)
    }
    foreach ($item in @(@{ Suffix = '.patch'; Field = 'PatchBytes' }, @{ Suffix = '.stat'; Field = 'StatBytes' }, @{ Suffix = '.name-status'; Field = 'NameStatusBytes' })) {
      if ($diff[$item.Field] -isnot [byte[]]) { throw 'first-attachment diff did not supply a raw byte buffer' }
      $evidence.Add($domain + $item.Suffix, $diff[$item.Field])
    }
    if ([string]::Equals($domain, 'private', [StringComparison]::Ordinal) -and [string]::Equals($ProjectContext.Domains.private.Parent, 'absent', [StringComparison]::Ordinal)) {
      $evidence.Add('private.history', [byte[]]@())
    } else {
      $evidence.Add($domain + '.history', (& $commands['Read-CrgCentralCommitLogBytes'] -ProjectContext $ProjectContext -Domain $domain))
    }
  }
  $messageOid = & $commands['Write-CrgCentralPrivateMessageBlob'] -ProjectContext $ProjectContext -Bytes $MessageBytes
  $evidence.Add('COMMIT-MESSAGE.txt', $MessageBytes)
  $identity = [ordered]@{
    'operation-id' = $OperationId; 'project-id' = $attachment.ProjectId; 'attachment-sha256' = $attachmentSha
    'public-worktree' = $ProjectContext.Root; 'public-git-dir' = $ProjectContext.Domains.public.GitDir
    'public-common-dir' = $ProjectContext.Domains.public.CommonDir; 'private-git-dir' = $ProjectContext.Domains.private.GitDir
    'public-ref' = $ProjectContext.Domains.public.Ref; 'private-ref' = $ProjectContext.Domains.private.Ref
    'public-parent' = $ProjectContext.Domains.public.Parent; 'private-parent' = $ProjectContext.Domains.private.Parent
    'public-tree' = $indexes.public.TreeOid; 'private-tree' = $indexes.private.TreeOid
    'private-baseline-tree' = $emptyTree; 'runtime-manifest-sha256' = $runtime.Id
  }
  $bundle = & $commands['New-CrgPreparedFirstAttachmentBundleBytes'] -IdentityFields $identity -PublicObjectFormat $ProjectContext.Domains.public.ObjectFormat -PrivateObjectFormat $ProjectContext.Domains.private.ObjectFormat -GoverningPreparationBytes $preparations.governing -CandidatePreparationBytes $preparations.candidate -PublicTreeBytes $indexes.public.TreeBytes -PrivateTreeBytes $indexes.private.TreeBytes -RuntimeTemplateBytes $template -ContextBlobBuffers $blobs -EvidenceBuffers $evidence
  if (-not [string]::Equals($bundle.Metadata.ReviewUnit.Fields['message-private-blob'], $messageOid, [StringComparison]::Ordinal) -or
      $bundle.Metadata.ReviewUnit.RequiresReview -isnot [bool] -or -not $bundle.Metadata.ReviewUnit.RequiresReview) { throw 'first-attachment assembly differs from the private message write or mandatory review boundary' }
  return [pscustomobject]@{
    Schema = 1; HasChanges = $hasChanges; RequiresReview = $true; Indexes = $indexes; PreparationSources = $sources
    ContextBlobBuffers = $blobs; ContextByteCount = $totalBytes; MessagePrivateBlob = $messageOid; Bundle = $bundle
    ValidationState = 'captured-first-attachment-git-input-data'; ReadyForReview = $false
    PendingBindings = @('retained-bootstrap-runtime-and-project-custody', 'proposed-attachment-custody',
      'message-and-candidate-object-retention', 'materialized-context-custody', 'current-review-child-provenance', 'final-first-attachment-publication-guards')
  }
}

Export-ModuleMember -Function Get-CrgCentralFirstAttachmentReviewInput
