# Live reviewer dispatch dependency. Publication remains the operation owner's
# responsibility; saved results or caller-constructed data never grant passage.

function Get-CrgPairedSessionCommand {
  param([object]$Runtime, [string]$Module, [string]$Name)
  $relative = 'scripts/' + $Module + '.psm1'
  if ($null -eq $Runtime -or $Runtime.Payloads -isnot [System.Collections.IDictionary] -or
      $relative -cnotin @($Runtime.Payloads.Keys)) { throw "paired dispatch requires retained runtime payload '$relative'" }
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($commands.Count -ne 1 -or
      -not [string]::Equals($commands[0].Module.Path, $Runtime.Payloads[$relative].Path, [StringComparison]::OrdinalIgnoreCase)) {
    throw "paired dispatch requires the selected runtime's '$Module/$Name' command"
  }
  return $commands[0]
}

function Get-CrgPairedSessionDigest {
  param([byte[]]$Bytes)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Get-CrgPairedSessionPolicy {
  param([object]$CapturedInput, [string]$AuthoringAgent)
  # Ordinal: -ceq/-cne/-cin and string overloads compare by culture and ignore characters such as U+00AD.
  if (-not ([string]::Equals($AuthoringAgent, 'codex', [StringComparison]::Ordinal) -or [string]::Equals($AuthoringAgent, 'claude', [StringComparison]::Ordinal))) { throw 'paired dispatch requires the canonical authoring agent, not a reviewer override' }
  $protectedChange = $false
  foreach ($domain in @('public', 'private')) {
    $bytes = $CapturedInput.Bundle.Buffers[$domain + '.name-status']
    if ($bytes -isnot [byte[]]) { throw 'paired dispatch lacks captured per-domain change names' }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    foreach ($line in @($text -split '\r?\n', 0)) {
      if ($line.Length -eq 0) { continue }
      $columns = @($line -split "`t", 0)
      if ($columns.Count -lt 2 -or $columns.Count -gt 3 -or $columns[0] -cnotmatch '\A(?:[ACDMRTUXB]|[CR][0-9]{1,3})\z') {
        throw 'paired dispatch cannot classify a captured change-name record'
      }
      foreach ($path in $columns[1..($columns.Count - 1)]) {
        # These are the existing mandatory both-mode paths. Both
        # rename endpoints participate; unrelated filenames are not heuristics.
        if ([string]::Equals($path, 'scripts/codex/commit.ps1', [StringComparison]::Ordinal) -or [string]::Equals($path, 'scripts/claude/commit.ps1', [StringComparison]::Ordinal) -or
            [string]::Equals($path, 'scripts/run-gate.sh', [StringComparison]::Ordinal)) { $protectedChange = $true }
      }
    }
  }
  [string[]]$providers = if ($protectedChange) { @('codex', 'claude') } elseif ([string]::Equals($AuthoringAgent, 'codex', [StringComparison]::Ordinal)) { @('claude') } else { @('codex') }
  $legs = for ($i = 0; $i -lt $providers.Count; $i++) {
    [pscustomobject]@{ Leg = ($i + 1); PreferredProvider = $providers[$i]; RequiredPassCount = 1 }
  }
  $readConfig = @(Get-Command Read-CrgProjectConfigBytes -Module private-governance -CommandType Function -ListImported)
  if ($readConfig.Count -ne 1 -or $CapturedInput.PreparationSources.governing.ConfigBytes -isnot [byte[]]) { throw 'paired routing requires the captured governing configuration' }
  $configuration = & $readConfig[0] -Bytes $CapturedInput.PreparationSources.governing.ConfigBytes
  $maximumAttempts = if ([string]::Equals($configuration.ReviewerPolicy, 'grok-fallback', [StringComparison]::Ordinal)) { 3 } else { 2 }
  return [pscustomobject]@{ Legs = @($legs); CodexEffort = 'high'; Grok = $configuration.Grok; MaximumAttempts = $maximumAttempts }
}

function Get-CrgPairedSessionEnvironment {
  # Read raw names so case-variant Git selectors cannot survive a dictionary
  # round-trip. No environment values are logged or persisted by this builder.
  if (-not ('CrgPairedSession.EnvironmentV1' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace CrgPairedSession {
  public static class EnvironmentV1 {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr GetEnvironmentStringsW();
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool FreeEnvironmentStringsW(IntPtr block);
    public static string[] Capture() {
      IntPtr block = GetEnvironmentStringsW();
      if (block == IntPtr.Zero) { throw new Win32Exception(Marshal.GetLastWin32Error(), "paired raw environment capture failed"); }
      try {
        List<string> entries = new List<string>();
        IntPtr cursor = block;
        while (true) {
          string entry = Marshal.PtrToStringUni(cursor);
          if (entry == null) { throw new InvalidOperationException("paired raw environment entry is unavailable"); }
          if (entry.Length == 0) { return entries.ToArray(); }
          entries.Add(entry);
          cursor = IntPtr.Add(cursor, checked((entry.Length + 1) * 2));
        }
      } finally {
        if (!FreeEnvironmentStringsW(block)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "paired raw environment release failed"); }
      }
    }
  }
}
'@ -ErrorAction Stop
  }
  $effectivePath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Process)
  if ([string]::IsNullOrEmpty($effectivePath)) { throw 'paired dispatch requires a nonempty executable search path' }
  $entries = New-Object 'System.Collections.Generic.List[string]'
  foreach ($entry in [CrgPairedSession.EnvironmentV1]::Capture()) {
    $separator = if ($entry.StartsWith('=', [StringComparison]::Ordinal)) { $entry.IndexOf([char]'=', 1) } else { $entry.IndexOf([char]'=') }
    if ($separator -le 0) { throw 'paired raw environment entry has invalid name/value grammar' }
    $name = $entry.Substring(0, $separator)
    if ($name -imatch '\A(?:GIT_|CROSS_REVIEW_)' -or [string]::Equals($name, 'Path', [StringComparison]::OrdinalIgnoreCase)) { continue }
    $entries.Add($entry)
  }
  $entries.Add('Path=' + $effectivePath)
  $entries.Add('GIT_NO_REPLACE_OBJECTS=1')
  $entries.Add('GIT_NO_LAZY_FETCH=1')
  return ,$entries.ToArray()
}

function Open-CrgPairedSessionOutput {
  param([object]$Runtime, [string]$PrivateGitDir, [string]$OperationId)
  if ($PrivateGitDir -cnotmatch '\A[A-Za-z]:\\' -or $PrivateGitDir.Contains('/') -or
      -not [string]::Equals([IO.Path]::GetFullPath($PrivateGitDir), $PrivateGitDir, [StringComparison]::Ordinal) -or $OperationId -cnotmatch '\A[0-9a-f]{32}\z') {
    throw 'paired output requires the captured private database and operation identity'
  }
  $command = Get-CrgPairedSessionCommand -Runtime $Runtime -Module paired-diff -Name New-CrgPairedInputSnapshot
  return & $command.Module {
    param([string]$Root, [string]$Operation)
    $custody = @{
      DirectoryPins = [System.Collections.Generic.List[object]]::new()
      OwnedDirectories = [System.Collections.Generic.List[object]]::new()
      ControlFiles = [System.Collections.Generic.List[object]]::new()
    }
    $complete = $false
    try {
      Initialize-CrgAttributeNeutralNative
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $Root -Pins $custody.DirectoryPins -DenyLeafRename
      foreach ($leaf in @('crg-review-state', 'runs', $Operation)) {
        $path = Join-Path $parent.Path $leaf
        if ([IO.Directory]::Exists($path)) {
          $errorCode = 0
          $handle = [CrgAttributeNeutral.NativeV1]::OpenPinnedDirectoryNoFollowDenyRename($path, [ref]$errorCode)
          if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryDirectory($handle)) {
            if ($null -ne $handle) { $handle.Dispose() }
            throw "private review-state directory custody failed (Win32 error $errorCode)"
          }
          $parent = [pscustomobject]@{ Path = $path; Handle = $handle; Label = 'retained private review state'; DeniesRename = $true }
          $custody.DirectoryPins.Add($parent)
        } else {
          $parent = New-CrgAttributeNeutralOwnedDirectory -Custody $custody -Parent $parent -Leaf $leaf -Path $path -Label 'private review-state directory'
        }
      }
      Assert-CrgAttributeNeutralContextStable -Context @{ Custody = $custody } -Boundary 'private review output'
      $complete = $true
      return [pscustomobject]@{ Root = $parent.Path; Parent = $parent; Custody = $custody; Closed = $false }
    } finally {
      if (-not $complete) {
        # Review state is durable forensics, including failed setup. Do not
        # recursively remove an existing operation or guess stale ownership.
        foreach ($record in $custody.OwnedDirectories) { $record.Handle.Dispose() }
        foreach ($record in $custody.DirectoryPins) { $record.Handle.Dispose() }
      }
    }
  } -Root $PrivateGitDir -Operation $OperationId
}

function New-CrgPairedSessionAttempt {
  param([object]$Runtime, [object]$Output, [int]$Leg, [int]$Attempt)
  if ($Output.Closed -or $Leg -notin @(1, 2) -or $Attempt -notin @(1, 2, 3)) { throw 'paired attempt requires an open output owner and a bounded schedule' }
  $command = Get-CrgPairedSessionCommand -Runtime $Runtime -Module paired-diff -Name New-CrgPairedInputSnapshot
  return & $command.Module {
    param([object]$Output, [int]$Leg, [int]$Attempt)
    $leaf = 'leg-' + $Leg + '-attempt-' + $Attempt + '-' + [guid]::NewGuid().ToString('N')
    $directory = New-CrgAttributeNeutralOwnedDirectory -Custody $Output.Custody -Parent $Output.Parent -Leaf $leaf -Path (Join-Path $Output.Root $leaf) -Label 'private current review attempt'
    Assert-CrgAttributeNeutralContextStable -Context @{ Custody = $Output.Custody } -Boundary 'private current review attempt'
    return $directory
  } -Output $Output -Leg $Leg -Attempt $Attempt
}

function Read-CrgPairedSessionFile {
  param([object]$Directory, [string]$Leaf, [int]$Maximum, [System.Collections.Generic.List[object]]$Readers)
  $handle = $null; $stream = $null; $errorCode = 0
  try {
    $handle = [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($Directory.Handle, $Leaf, [ref]$errorCode)
    if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) {
      throw "paired current evidence is not a retained ordinary single-link file (Win32 error $errorCode)"
    }
    $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read); $handle = $null
    if ($stream.Length -gt $Maximum) { throw 'paired current evidence exceeds the acquisition bound' }
    $bytes = New-Object byte[] ([int]$stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($count -le 0) { throw 'paired current evidence was truncated during retained acquisition' }
      $offset += $count
    }
    $Readers.Add($stream); $stream = $null
    return ,$bytes
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
    if ($null -ne $handle) { $handle.Dispose() }
  }
}

function Invoke-CrgPairedReviewSessionCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Runtime,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude)\z', Options = 'None')][string]$AuthoringAgent,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  if ($null -eq $Runtime -or $Runtime.Id -cnotmatch '\A[0-9a-f]{64}\z' -or
      $Runtime.Payloads -isnot [System.Collections.IDictionary] -or
      $null -eq $CapturedInput -or $CapturedInput.HasChanges -isnot [bool] -or
      ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal) -and -not $CapturedInput.HasChanges)) {
    throw 'paired dispatch requires one retained runtime and captured input for the explicit origin'
  }
  $firstNames = @{
    'Read-CrgReviewUnitBytes' = 'Read-CrgFirstAttachmentUnitBytes'
    'Read-CrgSuccessfulPairArtifactBytes' = 'Read-CrgSuccessfulFirstAttachmentArtifactBytes'
    'Read-CrgPairArtifactBytes' = 'Read-CrgFirstAttachmentArtifactBytes'
    'Read-CrgPairExhaustionBytes' = 'Read-CrgFirstAttachmentExhaustionBytes'
    'Read-CrgPreparedPairDescriptorBytes' = 'Read-CrgPreparedFirstAttachmentDescriptorBytes'
  }
  $commands = @{}
  foreach ($item in @(
    @{ Module = 'paired-diff'; Names = @('New-CrgPairedInputSnapshot', 'Assert-CrgPairedInputSnapshot', 'Close-CrgPairedInputSnapshot') },
    @{ Module = 'paired-process'; Names = @('Start-CrgPairedReviewProcess', 'Wait-CrgPairedReviewProcess', 'Complete-CrgPairedReviewProcess', 'Stop-CrgPairedReviewProcess', 'Close-CrgPairedReviewProcess') },
    @{ Module = 'paired-governance'; Names = @('Read-CrgReviewUnitBytes', 'Read-CrgSuccessfulPairArtifactBytes', 'Read-CrgPairArtifactBytes', 'Read-CrgPairExhaustionBytes') },
    @{ Module = 'paired-review-input'; Names = @('Read-CrgPreparedPairDescriptorBytes') }
  )) {
    foreach ($name in $item.Names) {
      $selectedName = $name
      if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -and $firstNames.ContainsKey($name)) { $selectedName = $firstNames[$name] }
      $commands[$name] = Get-CrgPairedSessionCommand -Runtime $Runtime -Module $item.Module -Name $selectedName
    }
  }
  foreach ($relative in @('scripts/codex/auto-review.ps1', 'scripts/claude/auto-review.ps1', 'scripts/codex/review-prompt-template.md', 'scripts/review-liveness.psm1', 'scripts/review-common.ps1')) {
    if ($relative -cnotin @($Runtime.Payloads.Keys) -or $Runtime.Payloads[$relative].Bytes -isnot [byte[]] -or
        -not [string]::Equals($Runtime.Payloads[$relative].Path, (Join-Path $Runtime.Root $relative.Replace('/', '\')), [StringComparison]::Ordinal)) {
      throw 'paired dispatch lacks an exact retained provider or template payload'
    }
  }
  $template = $Runtime.Payloads['scripts/codex/review-prompt-template.md'].Bytes
  $output = $null; $snapshot = $null; $process = $null; $allQuiescent = $true; $failed = $false
  $readers = New-Object 'System.Collections.Generic.List[object]'
  $transcripts = New-Object 'System.Collections.Generic.List[object]'
  $attemptRecords = New-Object 'System.Collections.Generic.List[object]'
  try {
    # Full materialization validation precedes policy classification or launch;
    # ignore mutable caller metadata when deriving the live artifact pins.
    $descriptor = & $commands['Read-CrgPreparedPairDescriptorBytes'] -Bytes $CapturedInput.Bundle.DescriptorBytes -ExpectedSha256 $CapturedInput.Bundle.DescriptorSha256 -GoverningConfigBytes $CapturedInput.PreparationSources.governing.ConfigBytes
    $formats = @{ PublicObjectFormat = $descriptor.Fields['public-object-format']; PrivateObjectFormat = $descriptor.Fields['private-object-format'] }
    $unitBytes = $CapturedInput.Bundle.Buffers['review-unit.txt']
    $unit = & $commands['Read-CrgReviewUnitBytes'] -Bytes $unitBytes @formats
    if (-not [string]::Equals($unit.Fields['runtime-manifest-sha256'], $Runtime.Id, [StringComparison]::Ordinal)) { throw 'paired input differs from the retained runtime' }
    $snapshot = & $commands['New-CrgPairedInputSnapshot'] -CapturedInput $CapturedInput -RuntimeTemplateBytes $template -TempParent $unit.Fields['private-git-dir'] -PreparedOrigin $Origin
    $pins = @{
      ReviewUnitBytes = $unitBytes; PublicObjectFormat = $formats.PublicObjectFormat; PrivateObjectFormat = $formats.PrivateObjectFormat
      DescriptorSha256 = $snapshot.PreparedPairSha256; DisplayDiffSha256 = $descriptor.Fields['display-diff-sha256']
    }
    $policy = Get-CrgPairedSessionPolicy -CapturedInput $CapturedInput -AuthoringAgent $AuthoringAgent
    if ($null -ne $policy.Grok) {
      $relative = 'scripts/grok/auto-review.ps1'
      if ($relative -cnotin @($Runtime.Payloads.Keys) -or $Runtime.Payloads[$relative].Bytes -isnot [byte[]] -or
          -not [string]::Equals($Runtime.Payloads[$relative].Path, (Join-Path $Runtime.Root $relative.Replace('/', '\')), [StringComparison]::Ordinal)) { throw 'configured Grok route requires the exact retained adapter payload' }
    }
    $environmentEntries = Get-CrgPairedSessionEnvironment
    $output = Open-CrgPairedSessionOutput -Runtime $Runtime -PrivateGitDir $unit.Fields['private-git-dir'] -OperationId $unit.Fields['operation-id']
    $engine = Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -ceq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' })
    Write-Host '[paired-review] reviewing captured software and private governance...'
    foreach ($leg in $policy.Legs) {
      $backend = $leg.PreferredProvider
      for ($attemptNumber = 1; $attemptNumber -le $policy.MaximumAttempts; $attemptNumber++) {
        & $commands['Assert-CrgPairedInputSnapshot'] -Snapshot $snapshot
        $attempt = New-CrgPairedSessionAttempt -Runtime $Runtime -Output $output -Leg $leg.Leg -Attempt $attemptNumber
        $errorCode = 0
        $handle = [CrgAttributeNeutral.NativeV1]::CreateOwnedFileRelative($attempt.Handle, 'transcript.log', [ref]$errorCode)
        if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) {
          if ($null -ne $handle) { $handle.Dispose() }
          throw "paired transcript create-new custody failed (Win32 error $errorCode)"
        }
        try { $transcript = [IO.FileStream]::new($handle, [IO.FileAccess]::ReadWrite) }
        catch { $handle.Dispose(); throw }
        $transcripts.Add($transcript)
        $arguments = @('-NoProfile', '-NonInteractive', '-File', $Runtime.Payloads['scripts/' + $backend + '/auto-review.ps1'].Path,
          '-PreparedPairPath', $snapshot.PreparedPairPath, '-PreparedPairSha256', $snapshot.PreparedPairSha256,
          '-PreparedPublicTreeSha256', $snapshot.PublicTreeSha256, '-PreparedPrivateTreeSha256', $snapshot.PrivateTreeSha256,
          '-OutDir', $attempt.Path, '-PreparedOrigin', $Origin)
        if ($backend -ceq 'codex') { $arguments += @('-ReviewPasses', [string]$leg.RequiredPassCount, '-ReasoningEffort', $policy.CodexEffort) }
        if ($backend -ceq 'grok') { $arguments += @('-ReviewPasses', [string]$leg.RequiredPassCount) }
        $allQuiescent = $false
        try {
          $process = & $commands['Start-CrgPairedReviewProcess'] -ApplicationName $engine -Arguments $arguments -WorkingDirectory $snapshot.Root -EnvironmentEntries $environmentEntries -TranscriptStream $transcript
        } catch {
          $failure = $_.Exception
          while ($null -ne $failure -and -not $failure.Data.Contains('CrgPairedProcessSession')) { $failure = $failure.InnerException }
          if ($null -ne $failure) { $process = $failure.Data['CrgPairedProcessSession'] }
          else { $allQuiescent = $true }
          throw
        }
        $rootExitedWithDescendants = $false
        do {
          $observations = @(& $commands['Wait-CrgPairedReviewProcess'] -Session $process -TimeoutMilliseconds 10000)
          if ($observations.Count -ne 1 -or ($null -ne $observations[0].Error -and $observations[0].Error -cne 'drain-timeout')) { throw 'paired review process observation failed' }
          $observation = $observations[0]
          if ($observation.ExitObserved -and -not $observation.Quiescent) {
            # Root exit ends review execution, not ownership of descendants.
            # One further bounded wait grants drain time before owned cleanup.
            if ($rootExitedWithDescendants) { throw 'paired reviewer host exited but descendants did not drain within the additional 10-second interval; owned termination is required' }
            $rootExitedWithDescendants = $true
            Write-Host '[paired-review] reviewer host exited; waiting up to 10 seconds for descendant drain.'
          }
        } while (-not $observation.Quiescent)
        $observations = @(& $commands['Complete-CrgPairedReviewProcess'] -Session $process -TimeoutMilliseconds 0)
        if ($observations.Count -ne 1) { throw 'paired review completion returned an invalid observation count' }
        $observation = $observations[0]
        if (-not $observation.ProcessCreated -or -not $observation.ExitObserved -or $observation.ActiveProcesses -ne 0 -or
            -not $observation.Quiescent -or -not $observation.Closed -or $null -ne $observation.Error) { throw 'paired review completion did not establish actual root exit and complete descendant drain' }
        $allQuiescent = $true; $process = $null
        & $commands['Assert-CrgPairedInputSnapshot'] -Snapshot $snapshot
        $transcript.Flush($true)
        if ($transcript.Length -gt 67108864) { throw 'paired wrapper transcript exceeds the acquisition bound' }
        $null = $transcript.Seek(0, [IO.SeekOrigin]::Begin)
        $transcriptBytes = New-Object byte[] ([int]$transcript.Length)
        $offset = 0
        while ($offset -lt $transcriptBytes.Length) {
          $count = $transcript.Read($transcriptBytes, $offset, $transcriptBytes.Length - $offset)
          if ($count -le 0) { throw 'paired wrapper transcript was truncated during retained acquisition' }
          $offset += $count
        }
        if ($observation.ExitCode -notin @(0, 4)) { throw "paired review did not pass (exit $($observation.ExitCode)); private attempt evidence: $($attempt.Path)" }
        $scopePrefix = if ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal)) { 'paired-' } else { 'first-attachment-' }
        $stemPattern = '\Areview-[0-9]{8}-[0-9]{6}-' + $scopePrefix + $unit.ReviewUnitSha256.Substring(0, 12)
        $leaves = @([IO.Directory]::EnumerateFileSystemEntries($attempt.Path) | ForEach-Object { [IO.Path]::GetFileName($_) })
        $verdicts = @($leaves | Where-Object { $_ -cmatch ($stemPattern + '\.md\z') })
        $exhaustions = @($leaves | Where-Object { $_ -cmatch ($stemPattern + '\.exhaustion\.json\z') })
        if ($verdicts.Count -gt 1 -or $exhaustions.Count -gt 1) { throw 'paired attempt contains ambiguous current evidence' }
        $verdictBytes = $null; $exhaustionBytes = $null; $verdictDigest = '-'; $exhaustionDigest = '-'
        if ($verdicts.Count -eq 1) {
          $verdictBytes = Read-CrgPairedSessionFile -Directory $attempt -Leaf $verdicts[0] -Maximum 16777216 -Readers $readers
          $verdictDigest = Get-CrgPairedSessionDigest -Bytes $verdictBytes
        }
        if ($observation.ExitCode -eq 0) {
          if ($verdicts.Count -ne 1 -or $exhaustions.Count -ne 0) { throw 'paired success requires one current verdict and no exhaustion sidecar' }
          $successful = & $commands['Read-CrgSuccessfulPairArtifactBytes'] -Bytes $verdictBytes @pins -ExpectedBackend $backend -ScheduledPassCount $leg.RequiredPassCount
          if ([string]::Equals($backend, 'codex', [StringComparison]::Ordinal) -and -not [string]::Equals($successful.Effort, $policy.CodexEffort, [StringComparison]::Ordinal)) { throw 'paired successful effort differs from the scheduled effort' }
          if ([string]::Equals($backend, 'grok', [StringComparison]::Ordinal) -and -not [string]::Equals($successful.Effort, $policy.Grok.Effort, [StringComparison]::Ordinal)) { throw 'paired Grok request effort differs from the governing profile' }
          if ([string]::Equals($backend, 'grok', [StringComparison]::Ordinal) -and -not [string]::Equals($successful.RequestedModel, $policy.Grok.Model, [StringComparison]::Ordinal)) { throw 'paired Grok requested model differs from the governing profile' }
        } else {
          if ($attemptNumber -ge $policy.MaximumAttempts -or $backend -ceq 'grok' -or $exhaustions.Count -ne 1) { throw 'paired exhausted attempt cannot satisfy this review leg' }
          if ($backend -ceq 'codex' -and $verdicts.Count -ne 1) { throw 'paired Codex exhaustion is missing the producer-required forensic verdict' }
          if ($verdicts.Count -eq 1) {
            if (($verdicts[0] -replace '\.md$', '') -cne ($exhaustions[0] -replace '\.exhaustion\.json$', '')) { throw 'paired exhaustion and verdict stems differ' }
            $null = & $commands['Read-CrgPairArtifactBytes'] -Bytes $verdictBytes @pins -ExpectedBackend $backend
          }
          $exhaustionBytes = Read-CrgPairedSessionFile -Directory $attempt -Leaf $exhaustions[0] -Maximum 16777216 -Readers $readers
          $exhaustion = & $commands['Read-CrgPairExhaustionBytes'] -Bytes $exhaustionBytes @pins -ExpectedBackend $backend -ScheduledPassCount $leg.RequiredPassCount
          $exhaustionDigest = $exhaustion.ExhaustionSha256
        }
        $attemptRecords.Add([pscustomobject]@{
          Leg = $leg.Leg; Attempt = $attemptNumber; ActualProvider = $backend; ScheduledPassCount = $leg.RequiredPassCount
          ObservedExit = [int]$observation.ExitCode; TranscriptSha256 = (Get-CrgPairedSessionDigest -Bytes $transcriptBytes)
          VerdictSha256 = $verdictDigest; ExhaustionSha256 = $exhaustionDigest; Directory = $attempt.Path
          VerdictFileName = if ($verdicts.Count -eq 1) { $verdicts[0] } else { $null }
          TranscriptBytes = $transcriptBytes; VerdictBytes = $verdictBytes; ExhaustionBytes = $exhaustionBytes
        })
        if ($observation.ExitCode -eq 0) { break }
        $backend = if ($attemptNumber -eq 2) { 'grok' } elseif ($backend -ceq 'claude') { 'codex' } else { 'claude' }
      }
    }
    Write-Host '[paired-review] captured-pair review PASS - covers this source diff only, not target execution or deployment readiness; publication guards remain required.'
    return [pscustomobject]@{
      ReviewUnitSha256 = $unit.ReviewUnitSha256; DescriptorSha256 = $snapshot.PreparedPairSha256
      ReviewLegs = $policy.Legs; ReviewAttempts = $attemptRecords.ToArray(); OutputRoot = $output.Root
      ValidationState = 'current-invocation-reviewed-pair'; ReadyForPublication = $false
    }
  } catch {
    $failed = $true
    throw
  } finally {
    if ($null -ne $process) {
      try {
        $stopped = @(& $commands['Stop-CrgPairedReviewProcess'] -Session $process -TimeoutMilliseconds 10000)
        if ($stopped.Count -eq 1 -and $stopped[0].Quiescent) {
          $closed = @(& $commands['Close-CrgPairedReviewProcess'] -Session $process)
          $allQuiescent = $closed.Count -eq 1 -and $closed[0].Closed -and $closed[0].Quiescent -and $null -eq $closed[0].Error
        }
      } catch { $allQuiescent = $false }
    }
    foreach ($reader in $readers) { $reader.Dispose() }
    if ($allQuiescent) {
      if ($failed -and $null -ne $output) {
        Write-Host "[paired-review] failed dispatch evidence remains private under $($output.Root)"
        foreach ($transcript in $transcripts) {
          try {
            $transcript.Flush($true)
            $length = [int][Math]::Min(65536L, $transcript.Length)
            $null = $transcript.Seek(-$length, [IO.SeekOrigin]::End)
            $tail = New-Object byte[] $length
            $offset = 0
            while ($offset -lt $length) {
              $count = $transcript.Read($tail, $offset, $length - $offset)
              if ($count -le 0) { throw 'diagnostic transcript read was incomplete' }
              $offset += $count
            }
            # Diagnostic projection only; raw retained bytes define evidence.
            if ($transcript.Length -gt $length) { Write-Host '[paired-review] transcript tail follows; complete transcript retained privately.' }
            Write-Host ([Text.Encoding]::UTF8.GetString($tail))
          } catch { Write-Warning 'private failed-dispatch transcript projection is unavailable' }
        }
      }
      foreach ($transcript in $transcripts) { $transcript.Dispose() }
      try {
        if ($null -ne $snapshot) {
          $closedInput = & $commands['Close-CrgPairedInputSnapshot'] -Snapshot $snapshot
          if (-not $closedInput.Ok) { throw "paired input cleanup retained uncertain state: $($closedInput.Reason)" }
        }
      } finally {
        if ($null -ne $output) {
          foreach ($record in $output.Custody.OwnedDirectories) { $record.Handle.Dispose() }
          foreach ($record in $output.Custody.DirectoryPins) { $record.Handle.Dispose() }
          $output.Closed = $true
        }
      }
    } else {
      $uncertain = New-Object InvalidOperationException 'paired review descendant drain is unconfirmed; input, output and native ownership remain retained'
      $uncertain.Data['CrgPairedProcessSession'] = $process
      $uncertain.Data['CrgPairedInputSnapshot'] = $snapshot
      $uncertain.Data['CrgPairedOutputOwner'] = $output
      $uncertain.Data['CrgPairedTranscripts'] = $transcripts
      throw $uncertain
    }
  }
}

function Invoke-CrgPairedReviewSession {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Runtime,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude)\z', Options = 'None')][string]$AuthoringAgent)
  return Invoke-CrgPairedReviewSessionCore @PSBoundParameters -Origin 'paired-v1'
}

function Invoke-CrgFirstAttachmentReviewSession {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Runtime,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude)\z', Options = 'None')][string]$AuthoringAgent)
  return Invoke-CrgPairedReviewSessionCore @PSBoundParameters -Origin 'first-attachment-v1'
}

Export-ModuleMember -Function Invoke-CrgPairedReviewSession, Invoke-CrgFirstAttachmentReviewSession
