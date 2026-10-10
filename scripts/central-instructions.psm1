# Only reviewed root discovery and clean instruction materialization belong here.
# Receipt records bind approved bytes; the live coordinator owns review authority.

function Get-CrgInstructionCommand {
  param([object]$Runtime, [string]$Module, [string]$Name)
  $relative = 'scripts/' + $Module + '.psm1'
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($null -eq $Runtime -or $Runtime.Payloads -isnot [Collections.IDictionary] -or
      -not [System.Linq.Enumerable]::Contains([string[]]@($Runtime.Payloads.Keys), [string]$relative, [System.StringComparer]::Ordinal) -or $commands.Count -ne 1 -or
      -not [string]::Equals($commands[0].Module.Path, $Runtime.Payloads[$relative].Path, [StringComparison]::OrdinalIgnoreCase)) { throw "instructions require retained '$Module/$Name'" }
  return $commands[0]
}

function Get-CrgInstructionDigest {
  param([byte[]]$Bytes, [string]$ObjectFormat)
  # Ordinal: -ceq/-cne compare by culture and ignore characters such as U+00AD.
  $sha = if ([string]::Equals($ObjectFormat, 'sha1', [StringComparison]::Ordinal)) { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
  try {
    if (-not [string]::IsNullOrEmpty($ObjectFormat)) {
      if (-not ([string]::Equals($ObjectFormat, 'sha1', [StringComparison]::Ordinal) -or [string]::Equals($ObjectFormat, 'sha256', [StringComparison]::Ordinal))) { throw 'instruction object format is invalid' }
      $header = [Text.Encoding]::ASCII.GetBytes('blob ' + $Bytes.Length + [char]0)
      $null = $sha.TransformBlock($header, 0, $header.Length, $header, 0)
      $null = $sha.TransformFinalBlock($Bytes, 0, $Bytes.Length)
      $digest = $sha.Hash
    } else { $digest = $sha.ComputeHash($Bytes) }
    return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
  } finally { $sha.Dispose() }
}

function New-CrgCentralInstructionDiscoveryBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$RuntimeStore,
    [Parameter(Mandatory = $true)][string]$PlanPath,
    [Parameter(Mandatory = $true)][string]$HistoryPath)
  $reader = @(Get-Command Read-CrgAttachmentBytes -Module private-governance -CommandType Function -ListImported -ErrorAction Stop)
  if ($reader.Count -ne 1) { throw 'discovery construction requires the already imported governance schema' }
  & $reader[0].Module {
    param($Store, $Plan, $History)
    Assert-CrgGovernancePath -Path $Store -Absolute -AllowGitMetadata
    Assert-CrgGovernancePath -Path $Plan
    Assert-CrgGovernancePath -Path $History
  } $RuntimeStore $PlanPath $HistoryPath
  if (-not [string]::Equals([IO.Path]::GetFullPath($RuntimeStore), $RuntimeStore, [StringComparison]::Ordinal) -or [string]::Equals($PlanPath, $HistoryPath, [StringComparison]::Ordinal)) { throw 'discovery requires canonical store and distinct explicit plan/history paths' }
  $lines = @('<!-- crg-central-discovery v1 BEGIN -->', '## Central cross-review gate',
    ('Runtime launcher: ' + (Join-Path $RuntimeStore 'launcher.ps1')),
    'Project configuration: .crg-project/project.conf', ('Private plan: ' + $PlanPath), ('Private history: ' + $HistoryPath),
    '', 'Use the central launcher for Open, Stage, Commit and Resume with the explicit',
    'TargetRepo. Commit also requires MessageFile and AuthoringAgent. This workflow',
    'supersedes legacy per-project gate commands. Public software and local private',
    'governance receive mandatory combined review; native commits do not substitute.',
    'Project mode describes review treatment, not permission to work. Provider',
    'exhaustion fallback stays automatic within the gate; no session skip flag exists.',
    '<!-- crg-central-discovery v1 END -->')
  return ,([Text.UTF8Encoding]::new($false, $true).GetBytes(($lines -join "`n") + "`n"))
}

function Read-CrgInstructionDiscovery {
  param([byte[]]$Bytes, [string]$RuntimeStore)
  if ($null -eq $Bytes -or $Bytes.Length -gt 16777216 -or
      ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191)) { throw 'instructions require bounded strict UTF-8 without BOM' }
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
  $open = [regex]::Matches($text, '(?m)^<!-- crg-central-discovery v1 BEGIN -->$')
  $close = [regex]::Matches($text, '(?m)^<!-- crg-central-discovery v1 END -->$')
  if ($open.Count -ne 1 -or $close.Count -ne 1 -or $open[0].Index -ge $close[0].Index) { throw 'each root instruction requires exactly one ordered canonical discovery section' }
  $end = $close[0].Index + $close[0].Length
  if ($end -ge $text.Length -or $text[$end] -ne [char]10) { throw 'discovery section requires final LF' }
  $section = $text.Substring($open[0].Index, $end + 1 - $open[0].Index)
  $plan = [regex]::Matches($section, '(?m)^Private plan: ([^\r\n]+)$')
  $history = [regex]::Matches($section, '(?m)^Private history: ([^\r\n]+)$')
  if ($plan.Count -ne 1 -or $history.Count -ne 1) { throw 'discovery lacks explicit plan/history records' }
  $expected = New-CrgCentralInstructionDiscoveryBytes -RuntimeStore $RuntimeStore -PlanPath $plan[0].Groups[1].Value -HistoryPath $history[0].Groups[1].Value
  $actual = [Text.UTF8Encoding]::new($false, $true).GetBytes($section)
  if (-not [string]::Equals((Get-CrgInstructionDigest -Bytes $actual), (Get-CrgInstructionDigest -Bytes $expected), [StringComparison]::Ordinal)) { throw 'discovery section differs from the selected stable launcher contract' }
  return [pscustomobject]@{ Bytes = $expected; PlanPath = $plan[0].Groups[1].Value; HistoryPath = $history[0].Groups[1].Value }
}

function Assert-CrgCentralInstructionDiscovery {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Operation, [Parameter(Mandatory = $true)][object]$CapturedInput,
    [switch]$RequireWorkingBytes)
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext
  $parseTree = Get-CrgInstructionCommand -Runtime $runtime -Module paired-tree -Name Read-CrgGitTreeBytes
  $readConfig = Get-CrgInstructionCommand -Runtime $runtime -Module private-governance -Name Read-CrgProjectConfigBytes
  if ($null -eq $CapturedInput -or $CapturedInput.Indexes -isnot [Collections.IDictionary] -or
      $CapturedInput.ContextBlobBuffers -isnot [Collections.IDictionary]) { throw 'discovery requires exact captured private tree and instruction buffers' }
  $entries = & $parseTree -Bytes $CapturedInput.Indexes.private.TreeBytes -ObjectFormat $project.Domains.private.ObjectFormat
  $config = & $readConfig -Bytes $CapturedInput.PreparationSources.candidate.ConfigBytes
  $first = $null
  foreach ($name in @('AGENTS.md', 'CLAUDE.md')) {
    $entry = @($entries | Where-Object { [string]::Equals($_.Path, $name, [StringComparison]::Ordinal) })
    if ($entry.Count -ne 1 -or -not ([string]::Equals($entry[0].Mode, '100644', [StringComparison]::Ordinal) -or [string]::Equals($entry[0].Mode, '100755', [StringComparison]::Ordinal)) -or
        $CapturedInput.ContextBlobBuffers[$name] -isnot [byte[]]) { throw "candidate private instructions '$name' are absent or nonregular" }
    $bytes = $CapturedInput.ContextBlobBuffers[$name]
    if (-not [string]::Equals((Get-CrgInstructionDigest -Bytes $bytes -ObjectFormat $project.Domains.private.ObjectFormat), $entry[0].Oid, [StringComparison]::Ordinal)) { throw 'instruction buffer differs from the actual captured private blob' }
    if ($RequireWorkingBytes) {
      # Activation already requires exact bytes. Check before paid review as well:
      # Git clean conversion can leave a text-equivalent CRLF working file whose
      # LF candidate would otherwise publish refs and then fail activation.
      $working = & $runtime.ReadFile -Path (Join-Path $project.Root $name) -Maximum 16777216 -AllowAbsent
      if (-not $working.Present -or $working.Bytes -isnot [byte[]] -or
          -not [string]::Equals((Get-CrgInstructionDigest -Bytes $working.Bytes), (Get-CrgInstructionDigest -Bytes $bytes), [StringComparison]::Ordinal)) {
        throw "first attachment requires working '$name' to match the captured private blob byte-for-byte before review; preserve edits and reconcile candidate bytes, including line endings, before retrying"
      }
    }
    $section = Read-CrgInstructionDiscovery -Bytes $bytes -RuntimeStore $runtime.Store
    if ($null -ne $first -and -not [string]::Equals((Get-CrgInstructionDigest -Bytes $first.Bytes), (Get-CrgInstructionDigest -Bytes $section.Bytes), [StringComparison]::Ordinal)) { throw 'AGENTS.md and CLAUDE.md must contain the same reviewed discovery section' }
    foreach ($path in @($section.PlanPath, $section.HistoryPath)) {
      $document = @($entries | Where-Object { [string]::Equals($_.Path, $path, [StringComparison]::Ordinal) })
      $role = @($config.Roles | Where-Object { [string]::Equals($_.Path, $path, [StringComparison]::Ordinal) })
      if ($document.Count -ne 1 -or -not ([string]::Equals($document[0].Mode, '100644', [StringComparison]::Ordinal) -or [string]::Equals($document[0].Mode, '100755', [StringComparison]::Ordinal)) -or
          $role.Count -ne 1) { throw "discovery path '$path' must be an existing private document with an explicit configured role" }
    }
    $first = $section
  }
  return $first
}

function Read-CrgMaterializedBytes {
  param([byte[]]$Bytes, [string]$AttachmentSha256)
  if ($null -eq $Bytes -or $Bytes.Length -gt 1024) { throw 'materialization record is absent or oversized' }
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
  $pattern = '\Acrg-materialized v1\nattachment-sha256 ([0-9a-f]{64})\nAGENTS\.md (paired-v1|first-attachment-v1) ([0-9a-f]{64})\nCLAUDE\.md (paired-v1|first-attachment-v1) ([0-9a-f]{64})\n\z'
  if ($text -cnotmatch $pattern -or -not [string]::Equals($Matches[1], $AttachmentSha256, [StringComparison]::Ordinal)) { throw 'materialization record has an invalid shape or attachment identity' }
  return [ordered]@{
    'AGENTS.md' = [pscustomobject]@{ Origin = $Matches[2]; ReceiptSha256 = $Matches[3] }
    'CLAUDE.md' = [pscustomobject]@{ Origin = $Matches[4]; ReceiptSha256 = $Matches[5] }
  }
}

function New-CrgMaterializedBytes {
  param([Collections.IDictionary]$Records, [string]$AttachmentSha256)
  $lines = @('crg-materialized v1', ('attachment-sha256 ' + $AttachmentSha256))
  foreach ($name in @('AGENTS.md', 'CLAUDE.md')) { $lines += $name + ' ' + $Records[$name].Origin + ' ' + $Records[$name].ReceiptSha256 }
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($lines -join "`n") + "`n")
  $null = Read-CrgMaterializedBytes -Bytes $bytes -AttachmentSha256 $AttachmentSha256
  return ,$bytes
}

function Get-CrgInstructionApprovedState {
  param([object]$Operation, [object]$Receipt, [string]$Origin)
  $project = $Operation.ProjectContext; $runtime = $Operation.Runtime
  $fields = $Receipt.Fields
  foreach ($pair in @(@('attachment-sha256', (Get-CrgInstructionDigest -Bytes $Operation.AttachmentBytes)),
      @('public-worktree', $project.Root), @('public-git-dir', $project.Domains.public.GitDir),
      @('private-git-dir', $project.Domains.private.GitDir), @('private-ref', $project.Domains.private.Ref))) {
    if (-not [string]::Equals($fields[$pair[0]], $pair[1], [StringComparison]::Ordinal)) { throw 'materialization receipt differs from the current project association' }
  }
  $tree = Get-CrgInstructionCommand -Runtime $runtime -Module central-context -Name Read-CrgCentralTreeBytes
  $parse = Get-CrgInstructionCommand -Runtime $runtime -Module paired-tree -Name Read-CrgGitTreeBytes
  $blob = Get-CrgInstructionCommand -Runtime $runtime -Module central-context -Name Read-CrgCentralBlobBytes
  $treeBytes = & $tree -ProjectContext $project -Domain private -TreeOid $fields['private-tree']
  $entries = & $parse -Bytes $treeBytes -ObjectFormat $project.Domains.private.ObjectFormat
  $files = [ordered]@{}
  foreach ($name in @('AGENTS.md', 'CLAUDE.md', '.crg-project/project.conf')) {
    $entry = @($entries | Where-Object { [string]::Equals($_.Path, $name, [StringComparison]::Ordinal) })
    if ($entry.Count -ne 1 -or -not ([string]::Equals($entry[0].Mode, '100644', [StringComparison]::Ordinal) -or [string]::Equals($entry[0].Mode, '100755', [StringComparison]::Ordinal))) { throw 'approved private instruction or configuration blob is missing' }
    $maximum = if ($name -ceq '.crg-project/project.conf') { 65536 } else { 16777216 }
    $bytes = & $blob -ProjectContext $project -Domain private -BlobOid $entry[0].Oid -Maximum $maximum
    $files[$name] = [pscustomobject]@{ Bytes = $bytes; Entry = $entry[0] }
  }
  return [pscustomobject]@{ Receipt = $Receipt; Origin = $Origin; Files = $files; TreeBytes = $treeBytes }
}

function Sync-CrgCentralInstructions {
  [CmdletBinding(DefaultParameterSetName = 'Open')]
  param([Parameter(Mandatory = $true)][object]$Operation,
    [Parameter(Mandatory = $true, ParameterSetName = 'Initial')][switch]$Initial,
    [Parameter(Mandatory = $true, ParameterSetName = 'Initial')][object]$CapturedInput,
    [Parameter(Mandatory = $true, ParameterSetName = 'Initial')][byte[]]$ReceiptBytes)
  $runtime = $Operation.Runtime; $project = $Operation.ProjectContext
  $assertReads = Get-CrgInstructionCommand -Runtime $runtime -Module paired-operation -Name Assert-CrgPairedOperationReads
  $release = Get-CrgInstructionCommand -Runtime $runtime -Module paired-operation -Name Release-CrgPairedOperationReadFiles
  $inventory = Get-CrgInstructionCommand -Runtime $runtime -Module paired-git-operation -Name Get-CrgPairedGitStageInventory
  $writeRoot = Get-CrgInstructionCommand -Runtime $runtime -Module paired-state -Name Write-CrgRootInstruction
  $writeState = Get-CrgInstructionCommand -Runtime $runtime -Module paired-state -Name Write-CrgPairState
  $retention = Get-CrgInstructionCommand -Runtime $runtime -Module paired-retention -Name Read-CrgCompletedPairRetention
  & $assertReads -Owner $Operation.ReadOwner
  if ($Initial) {
    $readReceipt = Get-CrgInstructionCommand -Runtime $runtime -Module paired-governance -Name Read-CrgFirstAttachmentReceiptBytes
    $receipt = & $readReceipt -Bytes $ReceiptBytes -PublicObjectFormat $project.Domains.public.ObjectFormat -PrivateObjectFormat $project.Domains.private.ObjectFormat
    if (-not [string]::Equals($receipt.Fields['private-tree'], $CapturedInput.Indexes.private.TreeOid, [StringComparison]::Ordinal) -or
        -not [string]::Equals($receipt.Fields['review-unit-sha256'], $CapturedInput.Bundle.Metadata.ReviewUnit.ReviewUnitSha256, [StringComparison]::Ordinal)) { throw 'initial materialization receipt differs from the captured reviewed candidate' }
    $origin = 'first-attachment-v1'
    $null = Assert-CrgCentralInstructionDiscovery -Operation $Operation -CapturedInput $CapturedInput
  } else {
    if (-not [string]::Equals($Operation.ValidationState, 'held-project-and-preceding-pair', [StringComparison]::Ordinal)) { throw 'Open materialization requires the current completed-pair owner' }
    $receipt = $Operation.PreviousReceipt
    $readPointer = Get-CrgInstructionCommand -Runtime $runtime -Module paired-governance -Name Read-CrgCompletedPairPointerBytes
    $origin = (& $readPointer -Bytes $Operation.PointerBytes).Origin
  }
  $approved = Get-CrgInstructionApprovedState -Operation $Operation -Receipt $receipt -Origin $origin
  $buffers = [ordered]@{}
  foreach ($name in @('AGENTS.md', 'CLAUDE.md')) { $buffers[$name] = $approved.Files[$name].Bytes }
  $input = [pscustomobject]@{ Indexes = @{ private = @{ TreeBytes = $approved.TreeBytes } }; ContextBlobBuffers = $buffers
    PreparationSources = @{ candidate = @{ ConfigBytes = $approved.Files['.crg-project/project.conf'].Bytes } } }
  $null = Assert-CrgCentralInstructionDiscovery -Operation $Operation -CapturedInput $input
  $attachmentSha = Get-CrgInstructionDigest -Bytes $Operation.AttachmentBytes
  $recordFile = & $runtime.ReadFile -Path (Join-Path $project.Domains.public.GitDir 'crg-materialized') -Maximum 1024 -AllowAbsent
  $records = if ($recordFile.Present) { Read-CrgMaterializedBytes -Bytes $recordFile.Bytes -AttachmentSha256 $attachmentSha } else { $null }
  # Inventory must describe the index held across materialization, including
  # split-index backing bytes. A later pin cannot validate an earlier inventory.
  $getIndex = Get-CrgInstructionCommand -Runtime $runtime -Module central-context -Name Get-CrgCentralIndexTree
  $null = & $getIndex -ProjectContext $project -Domain private
  $index = @((& $inventory -ProjectContext $project -OperationLock $Operation.OperationLock -Domain private -Kind Tracked -Paths @('AGENTS.md', 'CLAUDE.md')).Value)
  $working = [ordered]@{}
  foreach ($name in @('AGENTS.md', 'CLAUDE.md')) { $working[$name] = & $runtime.ReadFile -Path (Join-Path $project.Root $name) -Maximum 16777216 -AllowAbsent }
  $next = [ordered]@{}
  $results = New-Object 'System.Collections.Generic.List[object]'
  $writes = New-Object 'System.Collections.Generic.List[object]'
  $cache = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  foreach ($name in @('AGENTS.md', 'CLAUDE.md')) {
    $desired = $approved.Files[$name]; $actual = $working[$name]
    $staged = @($index | Where-Object { [string]::Equals($_.Path, $name, [StringComparison]::Ordinal) })
    $indexMatches = $staged.Count -eq 1 -and [string]::Equals($staged[0].Mode, $desired.Entry.Mode, [StringComparison]::Ordinal) -and
      [string]::Equals($staged[0].Oid, $desired.Entry.Oid, [StringComparison]::Ordinal)
    $workingMatches = $actual.Present -and [string]::Equals((Get-CrgInstructionDigest -Bytes $actual.Bytes), (Get-CrgInstructionDigest -Bytes $desired.Bytes), [StringComparison]::Ordinal)
    if ($Initial) {
      if (-not $indexMatches -or -not $workingMatches) { throw "initial attachment preserves conflicting/staged/deleted '$name'; exact reviewed bytes must be present before activation" }
      $next[$name] = [pscustomobject]@{ Origin = $origin; ReceiptSha256 = $receipt.ReceiptSha256 }
      $results.Add([pscustomobject]@{ Path = $name; State = 'approved-bytes'; Changed = $false })
      continue
    }
    if ($null -ne $records) { $next[$name] = $records[$name] }
    $state = 'baseline-absent-preserved'
    if (-not $indexMatches -or ($staged.Count -eq 1 -and ($staged[0].SkipWorktree -or $staged[0].AssumeUnchanged))) { $state = 'staged-edits-preserved' }
    elseif (-not $actual.Present) { $state = 'working-deletion' }
    elseif ($null -ne $records) {
      $prior = $records[$name]
      $cacheKey = $prior.Origin + ':' + $prior.ReceiptSha256
      if (-not $cache.ContainsKey($cacheKey)) {
        $retained = & $retention.Module { param($Project, $Key, $Origin) Read-CrgRetentionRecord -ProjectContext $Project -ReceiptSha256 $Key -ExpectedOrigin $Origin } $project $prior.ReceiptSha256 $prior.Origin
        $cache[$cacheKey] = Get-CrgInstructionApprovedState -Operation $Operation -Receipt $retained.Receipt -Origin $prior.Origin
      }
      $baseline = $cache[$cacheKey].Files[$name].Bytes
      if ($workingMatches) { $state = 'approved-bytes'; $next[$name] = [pscustomobject]@{ Origin = $origin; ReceiptSha256 = $receipt.ReceiptSha256 } }
      elseif ([string]::Equals((Get-CrgInstructionDigest -Bytes $actual.Bytes), (Get-CrgInstructionDigest -Bytes $baseline), [StringComparison]::Ordinal)) {
        $writes.Add([pscustomobject]@{ Name = $name; Expected = [byte[]]$actual.Bytes.Clone(); Bytes = $desired.Bytes })
        $state = 'advanced-clean'; $next[$name] = [pscustomobject]@{ Origin = $origin; ReceiptSha256 = $receipt.ReceiptSha256 }
      } else { $state = 'working-edits-preserved' }
    }
    $results.Add([pscustomobject]@{ Path = $name; State = $state; Changed = ($state -ceq 'advanced-clean') })
  }
  if (-not $Initial -and $null -eq $records) { return ,$results.ToArray() }
  $nextBytes = New-CrgMaterializedBytes -Records $next -AttachmentSha256 $attachmentSha
  $expectedRecord = if ($recordFile.Present) { [byte[]]$recordFile.Bytes.Clone() } else { $null }
  $fixedIndex = & $runtime.ReadFile -Path $project.Domains.private.IndexPath -Maximum 67108864
  & $assertReads -Owner $Operation.ReadOwner
  $openReads = Get-CrgInstructionCommand -Runtime $runtime -Module paired-operation -Name Open-CrgPairedOperationReads
  $closeReads = Get-CrgInstructionCommand -Runtime $runtime -Module paired-operation -Name Close-CrgPairedOperationReads
  $phase = $null
  try {
    # Preserve the fixed private index while root publication releases ordinary
    # file leases. A staged edit cannot enter between classification and write.
    $phase = & $openReads -Runtime $runtime.OriginalRuntime -OperationLock $Operation.OperationLock -ProjectRoots @($project.Root, $project.Domains.public.GitDir) -ExecutableReads @($Operation.GitExecutableOwner)
    $heldIndex = & $phase.Runtime.ReadFile -Path $project.Domains.private.IndexPath -Maximum 67108864
    if (-not [string]::Equals((Get-CrgInstructionDigest -Bytes $heldIndex.Bytes), (Get-CrgInstructionDigest -Bytes $fixedIndex.Bytes), [StringComparison]::Ordinal)) { throw 'private staging changed before instruction materialization' }
    if ($Initial) {
      foreach ($name in @('AGENTS.md', 'CLAUDE.md')) {
        $held = & $phase.Runtime.ReadFile -Path (Join-Path $project.Root $name) -Maximum 16777216
        if (-not [string]::Equals((Get-CrgInstructionDigest -Bytes $held.Bytes), (Get-CrgInstructionDigest -Bytes $approved.Files[$name].Bytes), [StringComparison]::Ordinal)) { throw 'initial approved instructions changed before baseline publication' }
      }
    }
    # Exact expected-root validation remains inside the DELETE-capable native
    # writer. Missing or replaced roots refuse rather than becoming restoration.
    foreach ($write in $writes) {
      & $release -Owner $Operation.ReadOwner -Paths @((Join-Path $project.Root $write.Name))
      $null = & $writeRoot -ProjectContext $project -OperationLock $Operation.OperationLock -Name $write.Name -ExpectedBytes $write.Expected -Bytes $write.Bytes
      $readback = & $runtime.ReadFile -Path (Join-Path $project.Root $write.Name) -Maximum 16777216
      if (-not [string]::Equals((Get-CrgInstructionDigest -Bytes $readback.Bytes), (Get-CrgInstructionDigest -Bytes $write.Bytes), [StringComparison]::Ordinal)) { throw 'materialized instruction failed exact approved-byte readback' }
    }
    if ($null -eq $expectedRecord -or -not [string]::Equals((Get-CrgInstructionDigest -Bytes $expectedRecord), (Get-CrgInstructionDigest -Bytes $nextBytes), [StringComparison]::Ordinal)) {
      & $release -Owner $Operation.ReadOwner -Paths @((Join-Path $project.Domains.public.GitDir 'crg-materialized'))
      $null = & $writeState -ProjectContext $project -OperationLock $Operation.OperationLock -Leaf crg-materialized -ExpectedBytes $expectedRecord -Bytes $nextBytes
      $readback = & $runtime.ReadFile -Path (Join-Path $project.Domains.public.GitDir 'crg-materialized') -Maximum 1024
      if (-not [string]::Equals((Get-CrgInstructionDigest -Bytes $readback.Bytes), (Get-CrgInstructionDigest -Bytes $nextBytes), [StringComparison]::Ordinal)) { throw 'materialization baseline failed exact readback' }
    }
    foreach ($result in $results) {
      if ($result.State -cnotin @('approved-bytes', 'advanced-clean')) { continue }
      $readback = & $runtime.ReadFile -Path (Join-Path $project.Root $result.Path) -Maximum 16777216
      if (-not [string]::Equals((Get-CrgInstructionDigest -Bytes $readback.Bytes), (Get-CrgInstructionDigest -Bytes $approved.Files[$result.Path].Bytes), [StringComparison]::Ordinal)) { throw 'approved instruction changed before materialization completion' }
    }
    & $assertReads -Owner $phase
    if ($Initial) {
      if ($null -ne $Operation.PSObject.Properties['InstructionReadOwner'] -and $null -ne $Operation.InstructionReadOwner) { throw 'initial instruction custody is already retained by this operation' }
      # Later publication releases its general read-file phase to replace fixed
      # metadata. Keep these approved roots independently held until attachment
      # teardown so that release cannot open an unreviewed-instruction window.
      $Operation | Add-Member -NotePropertyName InstructionReadOwner -NotePropertyValue $phase -Force
      $phase = $null
    }
  } finally { if ($null -ne $phase) { & $closeReads -Owner $phase } }
  return ,$results.ToArray()
}

Export-ModuleMember -Function New-CrgCentralInstructionDiscoveryBytes, Assert-CrgCentralInstructionDiscovery, Sync-CrgCentralInstructions
