# Immutable closed-origin storage only. No branch, handoff or completed-pair activation.

function Get-CrgRetentionCommand {
  param([string]$Module, [string]$Name)
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($commands.Count -ne 1) { throw "paired retention requires one retained '$Module/$Name' command" }
  return $commands[0]
}

function Get-CrgRetentionDigest {
  param([byte[]]$Bytes, [string]$ObjectFormat, [string]$Type)
  $hash = [Security.Cryptography.SHA256]::Create()
  # Ordinal: -ceq/-cne/-cin and switch compare by culture and ignore characters such as U+00AD.
  if ([string]::Equals($ObjectFormat, 'sha1', [StringComparison]::Ordinal)) { $hash.Dispose(); $hash = [Security.Cryptography.SHA1]::Create() }
  elseif (-not ([string]::IsNullOrEmpty($ObjectFormat) -or [string]::Equals($ObjectFormat, 'sha256', [StringComparison]::Ordinal))) { $hash.Dispose(); throw 'retention object format is invalid' }
  try {
    if (-not [string]::IsNullOrEmpty($Type)) {
      if (-not [System.Linq.Enumerable]::Contains([string[]]@('blob', 'tree', 'commit'), [string]$Type, [StringComparer]::Ordinal)) { throw 'retention object type is invalid' }
      $header = [Text.Encoding]::ASCII.GetBytes($Type + ' ' + $Bytes.Length.ToString([Globalization.CultureInfo]::InvariantCulture) + [char]0)
      $null = $hash.TransformBlock($header, 0, $header.Length, $null, 0)
    }
    $null = $hash.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    return ([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant()
  } finally { $hash.Dispose() }
}

function Assert-CrgRetentionOid {
  param([string]$Oid, [string]$ObjectFormat)
  $width = if ([string]::Equals($ObjectFormat, 'sha1', [StringComparison]::Ordinal)) { 40 } elseif ([string]::Equals($ObjectFormat, 'sha256', [StringComparison]::Ordinal)) { 64 } else { throw 'retention object format is invalid' }
  if ($Oid -cnotmatch ('\A[0-9a-f]{' + $width + '}\z') -or $Oid -match '\A0+\z') { throw 'retention object identity is invalid' }
}

function Get-CrgRetentionOriginCommands {
  param([ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) {
    return @{ Receipt = 'Read-CrgFirstAttachmentReceiptBytes'; Bundle = 'Read-CrgPreparedFirstAttachmentBundleBytes'
      Artifact = 'Read-CrgFirstAttachmentArtifactBytes'; SuccessfulArtifact = 'Read-CrgSuccessfulFirstAttachmentArtifactBytes'
      Exhaustion = 'Read-CrgFirstAttachmentExhaustionBytes' }
  }
  if (-not [string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal)) { throw 'retention origin is unsupported' }
  return @{ Receipt = 'Read-CrgPairReceiptBytes'; Bundle = 'Read-CrgPreparedPairBundleBytes'
    Artifact = 'Read-CrgPairArtifactBytes'; SuccessfulArtifact = 'Read-CrgSuccessfulPairArtifactBytes'
    Exhaustion = 'Read-CrgPairExhaustionBytes' }
}

function Get-CrgRetentionGitArguments {
  param([object]$ProjectContext, [string]$Domain)
  if ($null -eq $ProjectContext -or $ProjectContext.Schema -ne 1 -or
      $ProjectContext.Domains -isnot [System.Collections.IDictionary] -or
      -not ([string]::Equals($Domain, 'public', [StringComparison]::Ordinal) -or [string]::Equals($Domain, 'private', [StringComparison]::Ordinal)) -or
      -not $ProjectContext.Domains.Contains($Domain)) { throw 'retention Git domain is invalid' }
  $selected = $ProjectContext.Domains[$Domain]
  $reader = Get-CrgRetentionCommand -Module central-context -Name Read-CrgCentralBlobBytes
  # Namespace commands do not consume a commit. Initial absence must not be
  # converted into a fabricated parent merely to obtain checked Git switches.
  & $reader.Module {
    param($Paths)
    foreach ($path in $Paths) { Assert-CrgContextAbsolutePath -Path $path }
  } @($ProjectContext.GitExe, $ProjectContext.Root, $selected.GitDir, $selected.CommonDir, $selected.ObjectDir)
  if (-not ([string]::Equals($selected.ObjectFormat, 'sha1', [StringComparison]::Ordinal) -or [string]::Equals($selected.ObjectFormat, 'sha256', [StringComparison]::Ordinal)) -or
      -not [string]::Equals($selected.ObjectDir, (Join-Path $selected.CommonDir 'objects'), [StringComparison]::OrdinalIgnoreCase)) { throw 'retention Git object namespace is invalid' }
  return ,([string[]]@("--git-dir=$($selected.GitDir)", "--work-tree=$($ProjectContext.Root)"))
}

function Invoke-CrgRetentionGit {
  param([object]$ProjectContext, [string]$Domain, [string[]]$Arguments,
    [int]$Maximum = 16384, [byte[]]$InputBytes, [int[]]$AllowedExitCodes = @(0))
  $prefix = Get-CrgRetentionGitArguments -ProjectContext $ProjectContext -Domain $Domain
  $quoted = foreach ($argument in (@('--no-pager') + $prefix + @('-c', 'core.fsmonitor=false', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false') + $Arguments)) {
    if ($null -eq $argument -or $argument.Contains([char]0)) { throw 'retention Git argument is invalid' }
    $escaped = [regex]::Replace($argument, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    '"' + $escaped + '"'
  }
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $ProjectContext.GitExe; $start.Arguments = $quoted -join ' '
  $start.UseShellExecute = $false; $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
  $start.RedirectStandardInput = $null -ne $InputBytes
  foreach ($name in @($start.EnvironmentVariables.Keys)) {
    if ($name -imatch '^GIT_') { $start.EnvironmentVariables.Remove($name) }
  }
  foreach ($entry in @{ GIT_NO_REPLACE_OBJECTS = '1'; GIT_NO_LAZY_FETCH = '1'; GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_SYSTEM = 'NUL'; GIT_CONFIG_GLOBAL = 'NUL'; GIT_OPTIONAL_LOCKS = '0' }.GetEnumerator()) {
    $start.EnvironmentVariables[$entry.Key] = $entry.Value
  }
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $start; $output = New-Object IO.MemoryStream; $started = $false
  try {
    # Match the existing capture transport's PS5 no-preamble binary stdin rule.
    $priorEncoding = $null
    if ($null -ne $InputBytes -and $null -eq $start.PSObject.Properties['StandardInputEncoding']) {
      $priorEncoding = [Console]::InputEncoding; [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    } elseif ($null -ne $InputBytes) { $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false) }
    try { $started = $process.Start() } finally { if ($null -ne $priorEncoding) { [Console]::InputEncoding = $priorEncoding } }
    if (-not $started) { throw 'retention Git launch failed' }
    $copy = $process.StandardOutput.BaseStream.CopyToAsync($output)
    $errors = $process.StandardError.ReadToEndAsync()
    if ($null -ne $InputBytes) {
      try { $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length) }
      finally { $process.StandardInput.Close() }
    }
    if (-not $process.WaitForExit(10000)) { throw 'retention Git command timed out' }
    $null = $copy.GetAwaiter().GetResult(); $errorText = $errors.GetAwaiter().GetResult()
    if ($process.ExitCode -notin $AllowedExitCodes) { throw "retention Git failed ($($process.ExitCode)): $errorText" }
    if ($output.Length -gt $Maximum) { throw 'retention Git output exceeds its bound' }
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Bytes = [byte[]]$output.ToArray() }
  } finally {
    try {
      if ($started -and -not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(2000)) { throw 'retention Git root exit is unconfirmed; preserve prepared objects' }
      }
    } finally { $output.Dispose(); $process.Dispose() }
  }
}

function Get-CrgRetentionGitLine {
  param([object]$ProjectContext, [string]$Domain, [string[]]$Arguments, [byte[]]$InputBytes)
  $result = Invoke-CrgRetentionGit -ProjectContext $ProjectContext -Domain $Domain -Arguments $Arguments -InputBytes $InputBytes
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($result.Bytes)
  if ($text -cnotmatch '\A[^\r\n]+\r?\n?\z') { throw 'retention Git did not return one complete line' }
  return $text.TrimEnd([char[]]@(13, 10))
}

function Open-CrgRetentionContext {
  param([object]$ProjectContext, [ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin = 'paired-v1')
  if ($null -eq $ProjectContext -or $ProjectContext.Schema -ne 1 -or
      $ProjectContext.Domains -isnot [System.Collections.IDictionary] -or $ProjectContext.Domains.Count -ne 2 -or
      $null -eq $ProjectContext.Runtime -or $ProjectContext.Runtime.ReadFile -isnot [scriptblock] -or
      $ProjectContext.Runtime.Id -cnotmatch '\A[0-9a-f]{64}\z' -or $ProjectContext.Runtime.Payloads -isnot [System.Collections.IDictionary]) { throw 'retention requires the retained two-domain runtime context' }
  $paths = New-Object 'System.Collections.Generic.List[string]'
  foreach ($domain in @('public', 'private')) {
    if (-not $ProjectContext.Domains.Contains($domain)) { throw 'retention domain is absent' }
    $selected = $ProjectContext.Domains[$domain]
    $null = Get-CrgRetentionGitArguments -ProjectContext $ProjectContext -Domain $domain
    if (-not [string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -or -not [string]::Equals($domain, 'private', [StringComparison]::Ordinal) -or -not [string]::Equals($selected.Parent, 'absent', [StringComparison]::Ordinal)) {
      Assert-CrgRetentionOid -Oid $selected.Parent -ObjectFormat $selected.ObjectFormat
    }
    if (-not [string]::Equals($selected.ObjectDir, (Join-Path $selected.CommonDir 'objects'), [StringComparison]::OrdinalIgnoreCase)) { throw 'retention object directory differs from its domain' }
    $paths.Add($selected.GitDir); $paths.Add($selected.CommonDir); $paths.Add($selected.ObjectDir)
  }
  if ([string]::Equals($ProjectContext.Domains.public.CommonDir, $ProjectContext.Domains.private.CommonDir, [StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::Equals($ProjectContext.Domains.private.GitDir, $ProjectContext.Domains.private.CommonDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'retention requires separate databases and a concrete private Git directory' }
  $owner = Get-CrgRetentionCommand -Module paired-diff -Name New-CrgPairedIndexCopy
  $pins = & $owner.Module {
    param([string[]]$Paths)
    Initialize-CrgAttributeNeutralNative
    $pins = New-Object 'System.Collections.Generic.List[object]'
    try {
      # A descendant chain cannot upgrade an already weak ancestor pin.
      foreach ($path in @($Paths | Sort-Object Length)) { $null = Enter-CrgAttributeNeutralDirectoryChain -Path $path -Pins $pins -DenyLeafRename }
      return ,$pins
    } catch { foreach ($pin in $pins) { $pin.Handle.Dispose() }; throw }
  } -Paths $paths.ToArray()
  try {
    foreach ($domain in @('public', 'private')) {
      $selected = $ProjectContext.Domains[$domain]
      $common = (Get-CrgRetentionGitLine -ProjectContext $ProjectContext -Domain $domain -Arguments @('rev-parse', '--path-format=absolute', '--git-common-dir')).Replace('/', '\')
      $objects = (Get-CrgRetentionGitLine -ProjectContext $ProjectContext -Domain $domain -Arguments @('rev-parse', '--path-format=absolute', '--git-path', 'objects')).Replace('/', '\')
      $format = Get-CrgRetentionGitLine -ProjectContext $ProjectContext -Domain $domain -Arguments @('rev-parse', '--show-object-format')
      if (-not [string]::Equals($common, $selected.CommonDir, [StringComparison]::OrdinalIgnoreCase) -or
          -not [string]::Equals($objects, $selected.ObjectDir, [StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($format, $selected.ObjectFormat, [StringComparison]::Ordinal)) { throw 'retention Git namespace changed under custody' }
      foreach ($leaf in @('alternates', 'http-alternates')) {
        $file = & $ProjectContext.Runtime.ReadFile -Path (Join-Path $selected.ObjectDir ('info/' + $leaf)) -Maximum 65536 -AllowAbsent
        if ($null -eq $file -or $file.Present -isnot [bool] -or $file.Present) { throw 'retention requires positively absent object alternates' }
      }
    }
    return ,$pins
  } catch { foreach ($pin in $pins) { $pin.Handle.Dispose() }; throw }
}

function Read-CrgRetentionObjects {
  param([object]$ProjectContext, [string]$Domain, [object[]]$Requests, [long]$MaximumAggregate, [switch]$ValidationOnly)
  $reader = Get-CrgRetentionCommand -Module central-context -Name Read-CrgCentralObjectBatch
  return & $reader -ProjectContext $ProjectContext -Domain $Domain -Requests $Requests -MaximumAggregate $MaximumAggregate -ValidationOnly:$ValidationOnly
}

function Read-CrgRetentionObject {
  param([object]$ProjectContext, [string]$Domain, [string]$Oid, [string]$Type, [int]$Maximum)
  $format = $ProjectContext.Domains[$Domain].ObjectFormat
  Assert-CrgRetentionOid -Oid $Oid -ObjectFormat $format
  $objects = Read-CrgRetentionObjects -ProjectContext $ProjectContext -Domain $Domain `
    -Requests @([pscustomobject]@{ Oid = $Oid; Type = $Type; Maximum = $Maximum }) -MaximumAggregate $Maximum
  $bytes = $objects[$Oid]
  if ($bytes -isnot [byte[]]) { throw 'retention object batch omitted the requested identity' }
  return ,$bytes
}

function Read-CrgRetentionCommitBytes {
  param([byte[]]$Bytes, [string]$ObjectFormat)
  $separator = -1
  for ($i = 0; $i -lt $Bytes.Length - 1; $i++) { if ($Bytes[$i] -eq 10 -and $Bytes[$i + 1] -eq 10) { $separator = $i; break } }
  if ($separator -lt 0) { throw 'retained commit has no header/message boundary' }
  # Legacy author headers need not be UTF-8. Only ASCII tree/parent records
  # determine ancestry; preserve every message byte without decoding/normalizing.
  $lines = [Text.Encoding]::GetEncoding(28591).GetString($Bytes, 0, $separator) -split "`n", 0
  if ($lines[0] -cnotmatch '\Atree ([0-9a-f]+)\z') { throw 'retained commit lacks its leading tree record' }
  $tree = [string]$Matches[1]; Assert-CrgRetentionOid -Oid $tree -ObjectFormat $ObjectFormat
  $parents = New-Object 'System.Collections.Generic.List[string]'
  for ($i = 1; $i -lt $lines.Count; $i++) {
    if ($lines[$i].StartsWith('tree ', [StringComparison]::Ordinal)) { throw 'retained commit repeats its tree record' }
    if ($lines[$i].StartsWith('parent ', [StringComparison]::Ordinal)) {
      $parent = $lines[$i].Substring(7); Assert-CrgRetentionOid -Oid $parent -ObjectFormat $ObjectFormat; $parents.Add($parent)
    }
  }
  $message = New-Object byte[] ($Bytes.Length - $separator - 2)
  [Array]::Copy($Bytes, $separator + 2, $message, 0, $message.Length)
  return [pscustomobject]@{ TreeOid = $tree; Parents = $parents.ToArray(); MessageBytes = $message }
}

function Read-CrgRetentionCommit {
  param([object]$ProjectContext, [string]$Domain, [string]$Oid)
  $bytes = Read-CrgRetentionObject -ProjectContext $ProjectContext -Domain $Domain -Oid $Oid -Type commit -Maximum 2097152
  return Read-CrgRetentionCommitBytes -Bytes $bytes -ObjectFormat $ProjectContext.Domains[$Domain].ObjectFormat
}

function Get-CrgRetentionRef {
  param([object]$ProjectContext, [string]$Domain, [string]$Ref)
  $symbolic = Invoke-CrgRetentionGit -ProjectContext $ProjectContext -Domain $Domain -Arguments @('symbolic-ref', '--quiet', '--no-recurse', $Ref) -AllowedExitCodes @(0, 1)
  if ($symbolic.ExitCode -eq 0) { throw 'retention ref must be direct, including when its symbolic target is absent' }
  $exists = Invoke-CrgRetentionGit -ProjectContext $ProjectContext -Domain $Domain -Arguments @('show-ref', '--verify', '--quiet', $Ref) -AllowedExitCodes @(0, 1)
  if ($exists.ExitCode -eq 1) { return $null }
  $line = Get-CrgRetentionGitLine -ProjectContext $ProjectContext -Domain $Domain -Arguments @('for-each-ref', '--count=2', '--format=%(refname) %(objectname) %(symref)', $Ref)
  if ($line -cnotmatch ('\A' + [regex]::Escape($Ref) + ' ([0-9a-f]+) \z')) { throw 'retention ref changed or is not one exact direct reference' }
  $oid = [string]$Matches[1]; Assert-CrgRetentionOid -Oid $oid -ObjectFormat $ProjectContext.Domains[$Domain].ObjectFormat
  return $oid
}

function New-CrgRetentionRef {
  param([object]$ProjectContext, [object]$OperationLock, [string]$Domain, [string]$Ref, [string]$Oid)
  Assert-CrgRetentionOid -Oid $Oid -ObjectFormat $ProjectContext.Domains[$Domain].ObjectFormat
  $bindHooks = Get-CrgRetentionCommand -Module central-guards -Name Get-CrgCentralGuardBinding
  $hooksPath = & $bindHooks -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $Domain
  $hookPattern = '\A' + [regex]::Escape((Join-Path $ProjectContext.Domains.private.GitDir '.crg-hooks-')) + '[0-9a-f]{32}\\' + $Domain + '\z'
  if ($hooksPath -isnot [string] -or $hooksPath -cnotmatch $hookPattern) { throw 'retention reference requires the admitted private hook projection for this domain' }
  # update-ref can invoke existing reference-transaction hooks. Preserve those
  # hooks through command-scoped binding despite mutable configuration, and
  # own the entire child lifetime, not only the Git root process.
  $commands = @{}
  foreach ($name in @('Start-CrgPairedReviewProcess', 'Wait-CrgPairedReviewProcess', 'Complete-CrgPairedReviewProcess', 'Stop-CrgPairedReviewProcess', 'Close-CrgPairedReviewProcess')) {
    $commands[$name] = Get-CrgRetentionCommand -Module paired-process -Name $name
  }
  $prefix = Get-CrgRetentionGitArguments -ProjectContext $ProjectContext -Domain $Domain
  $environmentBuilder = Get-CrgRetentionCommand -Module paired-review-session -Name Invoke-CrgPairedReviewSession
  # The native launcher requires one canonical Path entry. Share raw environment
  # normalization with review dispatch, then retain this transport's Git policy.
  $normalizedEnvironment = & $environmentBuilder.Module { return ,(Get-CrgPairedSessionEnvironment) }
  $environment = New-Object 'System.Collections.Generic.List[string]'
  foreach ($entry in $normalizedEnvironment) {
    if ($entry -inotmatch '\AGIT_') { $environment.Add($entry) }
  }
  foreach ($entry in @{ GIT_NO_REPLACE_OBJECTS = '1'; GIT_NO_LAZY_FETCH = '1'; GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_SYSTEM = 'NUL'; GIT_CONFIG_GLOBAL = 'NUL'; GIT_OPTIONAL_LOCKS = '0' }.GetEnumerator()) {
    $environment.Add($entry.Key + '=' + $entry.Value)
  }
  $zero = '0' * $Oid.Length
  $arguments = @('--no-pager') + $prefix + @('-c', 'core.fsmonitor=false', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', '-c', "core.hooksPath=$hooksPath", 'update-ref', '--no-deref', $Ref, $Oid, $zero)
  $session = $null; $closed = $false
  try {
    try {
      $session = & $commands['Start-CrgPairedReviewProcess'] -ApplicationName $ProjectContext.GitExe -Arguments $arguments -WorkingDirectory $ProjectContext.Root -EnvironmentEntries $environment.ToArray()
    } catch {
      $failure = $_.Exception
      while ($null -ne $failure -and -not $failure.Data.Contains('CrgPairedProcessSession')) { $failure = $failure.InnerException }
      if ($null -ne $failure) { $session = $failure.Data['CrgPairedProcessSession'] }
      throw
    }
    $observations = @(& $commands['Wait-CrgPairedReviewProcess'] -Session $session -TimeoutMilliseconds 10000)
    if ($observations.Count -ne 1 -or -not $observations[0].Quiescent -or $null -ne $observations[0].Error) { throw 'retention reference child did not finish within the owned lifetime bound' }
    $observations = @(& $commands['Complete-CrgPairedReviewProcess'] -Session $session -TimeoutMilliseconds 0)
    if ($observations.Count -ne 1) { throw 'retention reference completion returned an invalid observation count' }
    $observation = $observations[0]
    $closed = $observation.Closed -and $observation.Quiescent
    if (-not $observation.ProcessCreated -or -not $observation.ExitObserved -or $observation.ActiveProcesses -ne 0 -or
        -not $closed -or $null -ne $observation.Error -or $observation.ExitCode -ne 0) { throw 'retention reference transaction failed or did not establish complete child exit' }
  } finally {
    if ($null -ne $session -and -not $closed) {
      try {
        $stopped = @(& $commands['Stop-CrgPairedReviewProcess'] -Session $session -TimeoutMilliseconds 10000)
        if ($stopped.Count -ne 1 -or -not $stopped[0].Quiescent) { throw 'retention reference child cleanup is unconfirmed' }
        $completion = @(& $commands['Close-CrgPairedReviewProcess'] -Session $session)
        if ($completion.Count -ne 1 -or -not $completion[0].Closed -or -not $completion[0].Quiescent) { throw 'retention reference ownership release is unconfirmed' }
      } catch {
        $uncertain = [InvalidOperationException]::new('retention reference descendant cleanup is unconfirmed; native session and namespace ownership must remain retained', $_.Exception)
        $uncertain.Data['CrgPairedProcessSession'] = $session
        $uncertain.Data['CrgPairRetentionUncertainReference'] = $Ref
        throw $uncertain
      }
    }
  }
  if (-not [string]::Equals((& $bindHooks -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $Domain), $hooksPath, [StringComparison]::Ordinal)) { throw 'retention reference hook binding changed after the owned child' }
  if ((Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain $Domain -Ref $Ref) -cne $Oid) { throw 'new retention reference failed exact reread' }
}

function Get-CrgRetentionLeafBounds {
  param([object]$Receipt)
  $bounds = [ordered]@{ 'receipt.txt' = 65536; 'prepared-pair.txt' = 16384; 'public.tree' = 16777216; 'private.tree' = 16777216 }
  foreach ($name in @('review-unit.txt', 'governing.preparation', 'candidate.preparation', 'public.patch', 'private.patch',
      'PLAN-CONSISTENCY-REPORT.md', 'COMMIT-MESSAGE.txt', 'context-inventory.txt', 'DIFF.patch', 'SCOPE.md', 'PROMPT.md',
      'PROJECT-MODE.txt', 'public.stat', 'private.stat', 'public.name-status', 'private.name-status', 'COMMIT-LOG.txt')) {
    $bounds.Add($name, 16777216)
  }
  $bounds['governing.preparation'] = 20971520; $bounds['candidate.preparation'] = 20971520
  $getHistoryBounds = Get-CrgRetentionCommand -Module paired-review-input -Name Get-CrgPreparedHistoryBounds
  $bounds['COMMIT-LOG.txt'] = (& $getHistoryBounds).RenderedBytes
  foreach ($attempt in $Receipt.ReviewAttempts) {
    $stem = 'leg-' + $attempt.Leg + '-attempt-' + $attempt.Attempt
    $bounds.Add($stem + '.transcript', 67108864)
    if ($attempt.VerdictSha256 -cne '-') { $bounds.Add($stem + '.verdict', 16777216) }
    if ($attempt.ExhaustionSha256 -cne '-') { $bounds.Add($stem + '.exhaustion', 16777216) }
  }
  return ,$bounds
}

function Read-CrgRetentionTree {
  param([object]$ProjectContext, [string]$TreeOid)
  $null = Read-CrgRetentionObject -ProjectContext $ProjectContext -Domain private -Oid $TreeOid -Type tree -Maximum 16384
  # Without --full-tree, ls-tree lists only the part of the tree under the
  # child's directory inside the work tree. This child inherits the Windows
  # process directory (not the PowerShell location), so a gate started from a
  # project subfolder read every flat retention tree as empty (2026-10-02).
  $result = Invoke-CrgRetentionGit -ProjectContext $ProjectContext -Domain private -Arguments @('ls-tree', '--full-tree', '-z', $TreeOid) -Maximum 16384
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($result.Bytes)
  if ($text.Length -eq 0 -or $text[$text.Length - 1] -ne [char]0) { throw 'retention metadata tree is empty or truncated' }
  $entries = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
  foreach ($line in ($text.Substring(0, $text.Length - 1) -split [char]0, 0)) {
    if ($line -cnotmatch '\A100644 blob ([0-9a-f]+)\t([A-Za-z0-9][A-Za-z0-9.-]*)\z') { throw 'retention tree contains a non-fixed regular leaf' }
    $oid = [string]$Matches[1]; $name = [string]$Matches[2]
    Assert-CrgRetentionOid -Oid $oid -ObjectFormat $ProjectContext.Domains.private.ObjectFormat
    if ($entries.ContainsKey($name)) { throw 'retention tree contains duplicate leaf names' }
    $entries.Add($name, $oid)
  }
  return ,$entries
}

function Read-CrgRetentionRecord {
  param([object]$ProjectContext, [string]$ReceiptSha256, [string]$ExpectedOrigin)
  if ($ReceiptSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'retention receipt key is not canonical SHA256' }
  $ref = 'refs/crg-pairs/' + $ReceiptSha256
  $oid = Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain private -Ref $ref
  if ($null -eq $oid) { throw 'required private pair retention reference is absent' }
  $commit = Read-CrgRetentionCommit -ProjectContext $ProjectContext -Domain private -Oid $oid
  $entries = Read-CrgRetentionTree -ProjectContext $ProjectContext -TreeOid $commit.TreeOid
  if (-not $entries.ContainsKey('receipt.txt')) { throw 'retention tree lacks the immutable receipt' }
  $bytes = Read-CrgRetentionObject -ProjectContext $ProjectContext -Domain private -Oid $entries['receipt.txt'] -Type blob -Maximum 65536
  $separator = [Array]::IndexOf($bytes, [byte]10)
  if ($separator -lt 0 -or $separator -gt 64) { throw 'retained receipt lacks a bounded closed-origin header' }
  $header = [Text.Encoding]::ASCII.GetString($bytes, 0, $separator)
  $origin = if ([string]::Equals($header, 'crg-pair-receipt v1', [StringComparison]::Ordinal)) { 'paired-v1' }
    elseif ([string]::Equals($header, 'crg-first-attachment-receipt v1', [StringComparison]::Ordinal)) { 'first-attachment-v1' }
    else { throw 'retained receipt has an unsupported origin' }
  if (-not [string]::IsNullOrEmpty($ExpectedOrigin) -and -not [string]::Equals($ExpectedOrigin, $origin, [StringComparison]::Ordinal)) { throw 'retained receipt differs from the explicitly selected origin' }
  # This in-memory dispatch key is not a stored completion pointer or approval.
  # The fixed private ref and exact raw receipt supply the predecessor identity.
  $newPointer = Get-CrgRetentionCommand -Module paired-governance -Name New-CrgCompletedPairPointerBytes
  $pointerBytes = & $newPointer -Origin $origin -ReceiptSha256 $ReceiptSha256
  $readReceipt = Get-CrgRetentionCommand -Module paired-governance -Name Read-CrgCompletedPairReceiptBytes
  $receipt = & $readReceipt -Bytes $bytes -PointerBytes $pointerBytes -PublicObjectFormat $ProjectContext.Domains.public.ObjectFormat -PrivateObjectFormat $ProjectContext.Domains.private.ObjectFormat
  $message = [Text.Encoding]::ASCII.GetBytes("crg-pair-retention v1`nreceipt-sha256 $ReceiptSha256`n")
  if ($receipt.ReceiptSha256 -cne $ReceiptSha256 -or $commit.Parents.Count -ne 1 -or $commit.Parents[0] -cne $receipt.Fields['private-result'] -or
      (Get-CrgRetentionDigest -Bytes $commit.MessageBytes) -cne (Get-CrgRetentionDigest -Bytes $message)) { throw 'private retention commit differs from its receipt identity or ancestry' }
  $bounds = Get-CrgRetentionLeafBounds -Receipt $receipt
  if ($entries.Count -ne $bounds.Count) { throw 'retention tree does not contain the exact receipt evidence leaves' }
  foreach ($name in $entries.Keys) { if ($name -cnotin @($bounds.Keys)) { throw 'retention tree contains undeclared evidence' } }
  return [pscustomobject]@{ Origin = $origin; Ref = $ref; CommitOid = $oid; TreeOid = $commit.TreeOid; Entries = $entries; Bounds = $bounds; Receipt = $receipt; ReceiptBytes = $bytes }
}

function Get-CrgRetentionFiles {
  param([object]$Receipt, [byte[]]$ReceiptBytes, [byte[]]$DescriptorBytes,
    [System.Collections.IDictionary]$Buffers, [System.Collections.IDictionary]$TreeBytes, [object[]]$ReviewAttempts)
  $files = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  $files.Add('receipt.txt', $ReceiptBytes); $files.Add('prepared-pair.txt', $DescriptorBytes)
  $files.Add('public.tree', $TreeBytes.public); $files.Add('private.tree', $TreeBytes.private)
  foreach ($name in $Buffers.Keys) {
    if ($name -isnot [string]) { throw 'retention buffer names must be exact strings' }
    $files.Add($name, $Buffers[$name])
  }
  for ($i = 0; $i -lt $Receipt.ReviewAttempts.Count; $i++) {
    $record = $Receipt.ReviewAttempts[$i]; $attempt = $ReviewAttempts[$i]
    $stem = 'leg-' + $record.Leg + '-attempt-' + $record.Attempt
    foreach ($binding in @(@('TranscriptBytes', 'TranscriptSha256', '.transcript'), @('VerdictBytes', 'VerdictSha256', '.verdict'), @('ExhaustionBytes', 'ExhaustionSha256', '.exhaustion'))) {
      $bytes = $attempt.($binding[0])
      if ($record.($binding[1]) -ceq '-') {
        if ($null -ne $bytes) { throw 'retention received bytes for a positively absent artifact' }
      } else { $files.Add($stem + $binding[2], $bytes) }
    }
  }
  $bounds = Get-CrgRetentionLeafBounds -Receipt $Receipt
  [long]$total = 0
  if ($files.Count -ne $bounds.Count) { throw 'retention payload differs from the exact fixed leaf set' }
  foreach ($name in $files.Keys) {
    if (-not [System.Linq.Enumerable]::Contains([string[]]@($bounds.Keys), [string]$name, [StringComparer]::Ordinal) -or $files[$name] -isnot [byte[]] -or $files[$name].Length -gt $bounds[$name]) { throw 'retention leaf exceeds its fixed byte boundary' }
    $total += $files[$name].Length
    if ($total -gt 536870912) { throw 'retention evidence exceeds the complete 512 MiB bound' }
  }
  return ,$files
}

function Assert-CrgRetentionAttachment {
  param([object]$ProjectContext, [System.Collections.IDictionary]$Fields, [string]$Origin, [byte[]]$AttachmentBytes)
  if ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal) -and $null -ne $AttachmentBytes) { throw 'ordinary retention requires the actual attachment, not a proposed association' }
  $runtime = $ProjectContext.Runtime
  $attachment = & $runtime.ReadFile -Path (Join-Path $ProjectContext.Domains.public.GitDir 'crg-attachment') -Maximum 16384 -AllowAbsent:([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal))
  if ($null -eq $attachment -or $attachment.Present -isnot [bool]) { throw 'retention attachment presence is unconfirmed' }
  if ($attachment.Present) {
    if ($attachment.Bytes -isnot [byte[]] -or ($null -ne $AttachmentBytes -and
        (Get-CrgRetentionDigest -Bytes $AttachmentBytes) -cne (Get-CrgRetentionDigest -Bytes $attachment.Bytes))) { throw 'proposed attachment conflicts with the actual association' }
    $AttachmentBytes = $attachment.Bytes
  }
  if ($null -eq $AttachmentBytes -or (Get-CrgRetentionDigest -Bytes $AttachmentBytes) -cne $Fields['attachment-sha256']) { throw 'retained receipt attachment bytes differ or are absent' }
  $parseAttachment = Get-CrgRetentionCommand -Module private-governance -Name Read-CrgAttachmentBytes
  $parsed = & $parseAttachment -Bytes $AttachmentBytes
  if (-not [string]::Equals($parsed.ProjectId, $ProjectContext.Status.ProjectId, [StringComparison]::Ordinal) -or -not [string]::Equals($parsed.RuntimeStore, $runtime.Store, [StringComparison]::Ordinal) -or
      -not [string]::Equals($parsed.PrivateGitDir, $ProjectContext.Domains.private.GitDir, [StringComparison]::Ordinal) -or -not [string]::Equals($parsed.PublicRef, $ProjectContext.Domains.public.Ref, [StringComparison]::Ordinal) -or
      -not [string]::Equals($parsed.PrivateRef, $ProjectContext.Domains.private.Ref, [StringComparison]::Ordinal)) { throw 'retention attachment differs from the exact captured association or runtime store' }
}

function Read-CrgRetentionDomainResult {
  param([object]$ProjectContext, [string]$Domain, [System.Collections.IDictionary]$Fields, [string]$Origin)
  $parent = $null
  if ([string]::Equals($Fields[$Domain + '-parent'], 'absent', [StringComparison]::Ordinal)) {
    if (-not [string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -or -not [string]::Equals($Domain, 'private', [StringComparison]::Ordinal)) { throw 'only initial private ancestry admits absent parent' }
    $result = Read-CrgRetentionCommit -ProjectContext $ProjectContext -Domain $Domain -Oid $Fields[$Domain + '-result']
    if ($result.Parents.Count -ne 0 -or (Get-CrgRetentionDigest -Bytes $result.MessageBytes) -cne $Fields['message-sha256']) { throw 'new private result must be an actual root commit with the exact agreed message' }
  } else {
    $parent = Read-CrgRetentionCommit -ProjectContext $ProjectContext -Domain $Domain -Oid $Fields[$Domain + '-parent']
    $result = $parent
    if ($Fields[$Domain + '-result'] -cne $Fields[$Domain + '-parent']) {
      $result = Read-CrgRetentionCommit -ProjectContext $ProjectContext -Domain $Domain -Oid $Fields[$Domain + '-result']
      if ($result.Parents.Count -ne 1 -or $result.Parents[0] -cne $Fields[$Domain + '-parent'] -or
          (Get-CrgRetentionDigest -Bytes $result.MessageBytes) -cne $Fields['message-sha256']) { throw 'changed result differs from the sole parent or exact agreed message' }
      if ($result.TreeOid -ceq $parent.TreeOid) { throw 'an unchanged domain cannot introduce an empty companion commit' }
    }
  }
  if ($result.TreeOid -cne $Fields[$Domain + '-tree']) { throw 'retained result tree differs from the reviewed candidate' }
  return [pscustomobject]@{ Parent = $parent; Result = $result }
}

function Get-CrgRetentionPayload {
  param([object]$ProjectContext, [byte[]]$ReceiptBytes, [byte[]]$DescriptorBytes,
    [System.Collections.IDictionary]$Buffers, [System.Collections.IDictionary]$TreeBytes, [object[]]$ReviewAttempts,
    [ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin = 'paired-v1', [byte[]]$AttachmentBytes)
  $formats = @{ PublicObjectFormat = $ProjectContext.Domains.public.ObjectFormat; PrivateObjectFormat = $ProjectContext.Domains.private.ObjectFormat }
  $originCommands = Get-CrgRetentionOriginCommands -Origin $Origin
  $readReceipt = Get-CrgRetentionCommand -Module paired-governance -Name $originCommands.Receipt
  $receipt = & $readReceipt -Bytes $ReceiptBytes @formats
  $fields = $receipt.Fields; $runtime = $ProjectContext.Runtime
  $templateName = 'scripts/codex/review-prompt-template.md'
  if (-not [string]::Equals($runtime.Id, $fields['runtime-manifest-sha256'], [StringComparison]::Ordinal) -or $runtime.Payloads[$templateName].Bytes -isnot [byte[]]) { throw 'retention requires the exact recorded retained runtime and template' }
  $expected = @{ 'public-worktree' = $ProjectContext.Root; 'public-git-dir' = $ProjectContext.Domains.public.GitDir
    'public-common-dir' = $ProjectContext.Domains.public.CommonDir; 'private-git-dir' = $ProjectContext.Domains.private.GitDir
    'public-ref' = $ProjectContext.Domains.public.Ref; 'private-ref' = $ProjectContext.Domains.private.Ref; 'project-id' = $ProjectContext.Status.ProjectId }
  foreach ($name in $expected.Keys) { if (-not [string]::Equals($fields[$name], $expected[$name], [StringComparison]::Ordinal)) { throw "retained receipt association differs at '$name'" } }
  Assert-CrgRetentionAttachment -ProjectContext $ProjectContext -Fields $fields -Origin $Origin -AttachmentBytes $AttachmentBytes
  if ($null -eq $Buffers -or $null -eq $TreeBytes -or $TreeBytes.Count -ne 2 -or
      $TreeBytes['public'] -isnot [byte[]] -or $TreeBytes['private'] -isnot [byte[]] -or
      $null -eq $ReviewAttempts -or $ReviewAttempts.Count -ne $receipt.ReviewAttempts.Count) { throw 'retention payload has incomplete input or attempt buffers' }
  $files = Get-CrgRetentionFiles -Receipt $receipt -ReceiptBytes $ReceiptBytes -DescriptorBytes $DescriptorBytes -Buffers $Buffers -TreeBytes $TreeBytes -ReviewAttempts $ReviewAttempts
  $results = [ordered]@{}; $contextBlobs = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  $readTree = Get-CrgRetentionCommand -Module central-context -Name Read-CrgCentralTreeBytes
  $parseTree = Get-CrgRetentionCommand -Module paired-tree -Name Read-CrgGitTreeBytes
  [long]$contextTotal = 0
  foreach ($domain in @('public', 'private')) {
    $commits = Read-CrgRetentionDomainResult -ProjectContext $ProjectContext -Domain $domain -Fields $fields -Origin $Origin
    $parent = $commits.Parent; $result = $commits.Result
    $treeOids = @($result.TreeOid)
    if ($null -ne $parent) { $treeOids += $parent.TreeOid }
    foreach ($treeOid in $treeOids) {
      $null = Read-CrgRetentionObject -ProjectContext $ProjectContext -Domain $domain -Oid $treeOid -Type tree -Maximum 16777216
    }
    $actual = & $readTree -ProjectContext $ProjectContext -Domain $domain -TreeOid $result.TreeOid
    if ((Get-CrgRetentionDigest -Bytes $actual) -cne (Get-CrgRetentionDigest -Bytes $TreeBytes[$domain])) { throw 'retention tree listing differs from the actual result tree' }
    $entries = & $parseTree -Bytes $actual -ObjectFormat $ProjectContext.Domains[$domain].ObjectFormat
    $directories = New-Object 'System.Collections.Generic.List[object]'
    $regular = New-Object 'System.Collections.Generic.List[object]'
    foreach ($entry in $entries) {
      if ($entry.Mode -ceq '040000') {
        $directories.Add($entry)
        continue
      }
      if ($entry.Mode -cnotin @('100644', '100755')) { throw 'retention requires the supported regular-file review context' }
      $regular.Add($entry)
    }
    $directoryRequests = @(foreach ($entry in $directories) { [pscustomobject]@{ Oid = $entry.Oid; Type = 'tree'; Maximum = [int]16777216 } })
    # Array Count is Int32; widen before multiplication so the aggregate is the
    # exact sum of existing per-tree limits without adding a lower total cap.
    [long]$directoryMaximum = [long]$directoryRequests.Count * [long]16777216
    $null = Read-CrgRetentionObjects -ProjectContext $ProjectContext -Domain $domain -Requests $directoryRequests -MaximumAggregate $directoryMaximum -ValidationOnly
    $requests = @(foreach ($entry in $regular) { [pscustomobject]@{ Oid = $entry.Oid; Type = 'blob'; Maximum = [int]33554432 } })
    $remaining = 536870912 - $contextTotal
    if ($remaining -lt 0) { throw 'retained context exceeds its bound' }
    $batch = Read-CrgRetentionObjects -ProjectContext $ProjectContext -Domain $domain -Requests @($requests) -MaximumAggregate $remaining
    foreach ($entry in $regular) {
      $blob = $batch[$entry.Oid]
      if ($blob -isnot [byte[]]) { throw 'retention batch omitted a regular context blob' }
      $contextTotal += $blob.Length
      if ($contextTotal -gt 536870912 -or $contextBlobs.ContainsKey($entry.Path)) { throw 'retained context exceeds its bound or overlaps domains' }
      $contextBlobs.Add($entry.Path, $blob)
    }
    $results.Add($domain, [pscustomobject]@{ Parent = $parent; Result = $result })
  }
  $readSource = Get-CrgRetentionCommand -Module central-context -Name Read-CrgCentralPreparationSource
  $newPreparation = Get-CrgRetentionCommand -Module project-preparation -Name New-CrgProjectPreparationBytes
  $sources = [ordered]@{}
  foreach ($kind in @('governing', 'candidate')) {
    if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -and [string]::Equals($kind, 'governing', [StringComparison]::Ordinal)) {
      $newBootstrap = Get-CrgRetentionCommand -Module project-preparation -Name New-CrgBootstrapProjectPreparationBytes
      $readBootstrap = Get-CrgRetentionCommand -Module project-preparation -Name Read-CrgBootstrapProjectPreparationBytes
      $compiled = & $newBootstrap -RuntimeSha256 $runtime.Id -TemplateBytes $runtime.Payloads[$templateName].Bytes
      $source = & $readBootstrap -Bytes $compiled -ExpectedRuntimeSha256 $runtime.Id -TemplateBytes $runtime.Payloads[$templateName].Bytes
    } else {
      $state = if ($kind -ceq 'governing') { 'Parent' } else { 'Result' }
      $source = & $readSource -ProjectContext $ProjectContext -PublicTreeOid $results.public.$state.TreeOid -PrivateTreeOid $results.private.$state.TreeOid
      $compiled = & $newPreparation -Kind $kind -RuntimeSha256 $runtime.Id -ConfigBytes $source.ConfigBytes -ValuesBytes $source.ValuesBytes -ModePresent $source.ModePresent -ModeBytes $source.ModeBytes -TemplateBytes $runtime.Payloads[$templateName].Bytes
    }
    if ((Get-CrgRetentionDigest -Bytes $compiled) -cne $fields[$kind + '-preparation-sha256']) { throw 'retained preparation differs from exact recorded-domain source compilation' }
    $sources.Add($kind, $source)
  }
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) {
    $emptyTree = Get-CrgRetentionDigest -Bytes ([byte[]]@()) -ObjectFormat $formats.PrivateObjectFormat -Type tree
    if ($fields['private-baseline-tree'] -cne $emptyTree) { throw 'initial private evidence requires the independently computed empty tree' }
    $null = Read-CrgRetentionObject -ProjectContext $ProjectContext -Domain private -Oid $emptyTree -Type tree -Maximum 0
    $readDiff = Get-CrgRetentionCommand -Module paired-diff -Name Get-CrgPairedGitDiffEvidence
    foreach ($domain in @('public', 'private')) {
      $baseline = if ($domain -ceq 'private') { $emptyTree } else { $results.public.Parent.TreeOid }
      $diff = & $readDiff -ProjectContext $ProjectContext -Domain $domain -ParentTree $baseline -CandidateTree $results[$domain].Result.TreeOid -TempParent $ProjectContext.Domains.private.GitDir
      if ($null -eq $diff -or -not $diff.Ok) { throw "initial retained diff recapture failed: $($diff.Reason)" }
      foreach ($binding in @(@('PatchBytes', '.patch'), @('StatBytes', '.stat'), @('NameStatusBytes', '.name-status'))) {
        if ($diff.($binding[0]) -isnot [byte[]] -or
            (Get-CrgRetentionDigest -Bytes $diff.($binding[0])) -cne (Get-CrgRetentionDigest -Bytes $Buffers[$domain + $binding[1]])) { throw 'initial retained evidence differs from the exact raw baseline-to-candidate diff' }
      }
    }
  }
  $readBundle = Get-CrgRetentionCommand -Module paired-review-input -Name $originCommands.Bundle
  $descriptorSha = Get-CrgRetentionDigest -Bytes $DescriptorBytes
  $metadata = & $readBundle -DescriptorBytes $DescriptorBytes -ExpectedDescriptorSha256 $descriptorSha -Buffers $Buffers -GoverningConfigBytes $sources.governing.ConfigBytes -CandidateConfigBytes $sources.candidate.ConfigBytes -PublicTreeBytes $TreeBytes.public -PrivateTreeBytes $TreeBytes.private -RuntimeTemplateBytes $runtime.Payloads[$templateName].Bytes -ContextBlobBuffers $contextBlobs
  if (@($receipt.ReviewAttempts | Where-Object { $_.ActualProvider -ceq 'grok' }).Count -gt 0 -and
      -not [string]::Equals($metadata.Descriptor.GoverningConfig.ReviewerPolicy, 'grok-fallback', [StringComparison]::Ordinal)) { throw 'retained Grok review was not enabled by the governing private configuration' }
  if ($metadata.ReviewUnit.ReviewUnitSha256 -cne $fields['review-unit-sha256'] -or
      -not [string]::Equals($metadata.Descriptor.Fields['public-object-format'], $formats.PublicObjectFormat, [StringComparison]::Ordinal) -or
      -not [string]::Equals($metadata.Descriptor.Fields['private-object-format'], $formats.PrivateObjectFormat, [StringComparison]::Ordinal)) { throw 'retention bundle differs from the receipt unit or domain formats' }
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -and $metadata.ReviewUnit.RequiresReview -ne $true) { throw 'initial retention cannot omit mandatory review for unchanged adoption' }
  $message = Read-CrgRetentionObject -ProjectContext $ProjectContext -Domain private -Oid $fields['message-private-blob'] -Type blob -Maximum 1048576
  if ((Get-CrgRetentionDigest -Bytes $message) -cne $fields['message-sha256']) { throw 'retained private message differs from the receipt digest' }
  $pins = @{ ReviewUnitBytes = $Buffers['review-unit.txt']; DescriptorSha256 = $descriptorSha
    DisplayDiffSha256 = $metadata.Descriptor.Fields['display-diff-sha256']; PublicObjectFormat = $formats.PublicObjectFormat; PrivateObjectFormat = $formats.PrivateObjectFormat }
  foreach ($name in @($originCommands.SuccessfulArtifact, $originCommands.Artifact, $originCommands.Exhaustion)) { $null = Get-CrgRetentionCommand -Module paired-governance -Name $name }
  for ($i = 0; $i -lt $receipt.ReviewAttempts.Count; $i++) {
    $record = $receipt.ReviewAttempts[$i]; $attempt = $ReviewAttempts[$i]
    $stem = 'leg-' + $record.Leg + '-attempt-' + $record.Attempt
    foreach ($binding in @(@('TranscriptBytes', 'TranscriptSha256', '.transcript'), @('VerdictBytes', 'VerdictSha256', '.verdict'), @('ExhaustionBytes', 'ExhaustionSha256', '.exhaustion'))) {
      $bytes = $attempt.($binding[0]); $digest = $record.($binding[1])
      if ($digest -ceq '-') { if ($null -ne $bytes) { throw 'retention received bytes for a positively absent artifact' }; continue }
      if ($bytes -isnot [byte[]] -or (Get-CrgRetentionDigest -Bytes $bytes) -cne $digest) { throw 'retained attempt bytes differ from the receipt' }
    }
    if ($record.ObservedExit -eq 0) {
      $readArtifact = Get-CrgRetentionCommand -Module paired-governance -Name $originCommands.SuccessfulArtifact
      $successful = & $readArtifact -Bytes $attempt.VerdictBytes @pins -ExpectedBackend $record.ActualProvider -ScheduledPassCount $record.ScheduledPassCount
      # Retention runs only under the recorded runtime (checked above), whose
      # table the live session already bound exactly. The allowed set applied
      # here is the one push guards later apply to this pair under newer
      # releases, so evidence retained now stays revalidatable then.
      if ($record.ActualProvider -ceq 'grok') {
        $allowed = @(& (Get-CrgRetentionCommand -Module private-governance -Name Get-CrgGrokAllowedIdentities) -Config $metadata.Descriptor.GoverningConfig)
        if (-not [System.Linq.Enumerable]::Contains([string[]]@($allowed), [string]($successful.RequestedModel + '|' + $successful.Effort), [StringComparer]::Ordinal)) { throw 'retained Grok model and effort differ from every identity the governing selection could have run' }
      }
    } else {
      if ($record.ActualProvider -ceq 'codex' -and $null -eq $attempt.VerdictBytes) { throw 'retained Codex exhaustion requires its forensic verdict' }
      if ($null -ne $attempt.VerdictBytes) {
        $readArtifact = Get-CrgRetentionCommand -Module paired-governance -Name $originCommands.Artifact
        $null = & $readArtifact -Bytes $attempt.VerdictBytes @pins -ExpectedBackend $record.ActualProvider
      }
      $readExhaustion = Get-CrgRetentionCommand -Module paired-governance -Name $originCommands.Exhaustion
      $null = & $readExhaustion -Bytes $attempt.ExhaustionBytes @pins -ExpectedBackend $record.ActualProvider -ScheduledPassCount $record.ScheduledPassCount
    }
  }
  if ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal)) {
    $previous = Read-CrgRetentionRecord -ProjectContext $ProjectContext -ReceiptSha256 $fields['previous-pair']
    foreach ($name in @('project-id', 'attachment-sha256', 'public-ref', 'private-ref', 'public-worktree', 'public-git-dir', 'public-common-dir', 'private-git-dir')) {
      if (-not [string]::Equals($previous.Receipt.Fields[$name], $fields[$name], [StringComparison]::Ordinal)) { throw 'preceding retention belongs to a different association' }
    }
    foreach ($domain in @('public', 'private')) {
      if ($previous.Receipt.Fields[$domain + '-result'] -cne $fields[$domain + '-parent'] -or
          $previous.Receipt.Fields[$domain + '-tree'] -cne $results[$domain].Parent.TreeOid) { throw 'preceding retained results differ from the recorded ordinary parents or trees' }
    }
    if ((Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain public -Ref ('refs/crg-results/' + $fields['public-parent'])) -cne $fields['public-parent']) { throw 'preceding public result retention is absent or conflicting' }
  }
  return [pscustomobject]@{ Receipt = $receipt; Files = $files; Metadata = $metadata; ContextBlobBuffers = $contextBlobs; Sources = $sources; ContextBytes = $contextTotal }
}

function Read-CrgRetentionCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][string]$ReceiptSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin,
    [byte[]]$AttachmentBytes)
  $custody = Open-CrgRetentionContext -ProjectContext $ProjectContext -Origin $Origin
  try {
    $record = Read-CrgRetentionRecord -ProjectContext $ProjectContext -ReceiptSha256 $ReceiptSha256 -ExpectedOrigin $Origin
    $files = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $requests = @(foreach ($name in $record.Entries.Keys) {
      [pscustomobject]@{ Oid = $record.Entries[$name]; Type = 'blob'; Maximum = [int]$record.Bounds[$name] }
    })
    $batch = Read-CrgRetentionObjects -ProjectContext $ProjectContext -Domain private -Requests $requests -MaximumAggregate 536870912
    [long]$total = 0
    foreach ($name in $record.Entries.Keys) {
      $bytes = $batch[$record.Entries[$name]]
      if ($bytes -isnot [byte[]]) { throw 'retention evidence batch omitted a declared leaf' }
      $total += $bytes.Length
      if ($total -gt 536870912) { throw 'retained evidence exceeds the complete 512 MiB bound' }
      $files.Add($name, $bytes)
    }
    $buffers = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach ($name in $files.Keys) {
      if ($name -cnotin @('receipt.txt', 'prepared-pair.txt', 'public.tree', 'private.tree') -and -not $name.StartsWith('leg-', [StringComparison]::Ordinal)) { $buffers.Add($name, $files[$name]) }
    }
    $attempts = foreach ($attempt in $record.Receipt.ReviewAttempts) {
      $stem = 'leg-' + $attempt.Leg + '-attempt-' + $attempt.Attempt
      [pscustomobject]@{ TranscriptBytes = $files[$stem + '.transcript']; VerdictBytes = $files[$stem + '.verdict']; ExhaustionBytes = $files[$stem + '.exhaustion'] }
    }
    $payload = Get-CrgRetentionPayload -ProjectContext $ProjectContext -ReceiptBytes $record.ReceiptBytes -DescriptorBytes $files['prepared-pair.txt'] -Buffers $buffers -TreeBytes @{ public = $files['public.tree']; private = $files['private.tree'] } -ReviewAttempts @($attempts) -Origin $Origin -AttachmentBytes $AttachmentBytes
    $publicRef = 'refs/crg-results/' + $record.Receipt.Fields['public-result']
    if ((Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain public -Ref $publicRef) -cne $record.Receipt.Fields['public-result'] -or
        (Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain private -Ref $record.Ref) -cne $record.CommitOid) { throw 'pair retention references failed exact final reread' }
    $validation = if ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal)) { 'retained-ordinary-pair-identity' } else { 'retained-first-attachment-identity' }
    $result = [pscustomobject]@{ Origin = $Origin; ReceiptSha256 = $ReceiptSha256; ReceiptBytes = $record.ReceiptBytes; Receipt = $record.Receipt
      PrivateRef = $record.Ref; PrivateCommitOid = $record.CommitOid; PrivateTreeOid = $record.TreeOid; PublicRef = $publicRef
      Files = $files; Metadata = $payload.Metadata; ContextBlobBuffers = $payload.ContextBlobBuffers
      ValidationState = $validation; ReadyForPublication = $false }
  } finally { foreach ($pin in $custody) { $pin.Handle.Dispose() } }
  return $result
}

function Write-CrgRetentionCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][object[]]$ReviewAttempts,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin,
    [byte[]]$AttachmentBytes)
  $custody = Open-CrgRetentionContext -ProjectContext $ProjectContext -Origin $Origin
  $preserveCustody = $false
  try {
    if ($null -eq $CapturedInput -or $null -eq $CapturedInput.Bundle -or $CapturedInput.Bundle.DescriptorBytes -isnot [byte[]] -or
        $CapturedInput.Bundle.Buffers -isnot [System.Collections.IDictionary] -or $CapturedInput.Indexes -isnot [System.Collections.IDictionary]) { throw 'retention requires the captured fixed bundle and domain listings' }
    $payload = Get-CrgRetentionPayload -ProjectContext $ProjectContext -ReceiptBytes $ReceiptBytes -DescriptorBytes $CapturedInput.Bundle.DescriptorBytes -Buffers $CapturedInput.Bundle.Buffers -TreeBytes @{ public = $CapturedInput.Indexes.public.TreeBytes; private = $CapturedInput.Indexes.private.TreeBytes } -ReviewAttempts $ReviewAttempts -Origin $Origin -AttachmentBytes $AttachmentBytes
    if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) {
      foreach ($domain in @('public', 'private')) {
        $parent = $payload.Receipt.Fields[$domain + '-parent']
        if (-not [string]::Equals($parent, $ProjectContext.Domains[$domain].Parent, [StringComparison]::Ordinal)) { throw 'initial receipt parent differs from the actual captured ancestry' }
        $actual = Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain $domain -Ref $ProjectContext.Domains[$domain].Ref
        if (([string]::Equals($parent, 'absent', [StringComparison]::Ordinal) -and $null -ne $actual) -or
            (-not [string]::Equals($parent, 'absent', [StringComparison]::Ordinal) -and -not [string]::Equals($actual, $parent, [StringComparison]::Ordinal))) { throw 'initial retention requires the exact actual branch parent or positively absent private branch' }
      }
    }
    $receipt = $payload.Receipt; $ref = 'refs/crg-pairs/' + $receipt.ReceiptSha256
    $existing = Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain private -Ref $ref
    $publicRef = 'refs/crg-results/' + $receipt.Fields['public-result']
    $existingPublic = Get-CrgRetentionRef -ProjectContext $ProjectContext -Domain public -Ref $publicRef
    if ($null -ne $existingPublic -and $existingPublic -cne $receipt.Fields['public-result']) { throw 'public result retention ref conflicts with the exact result' }
    if ($null -eq $existing) {
      $lines = New-Object Text.StringBuilder
      [string[]]$names = @($payload.Files.Keys); [Array]::Sort($names, [StringComparer]::Ordinal)
      foreach ($name in $names) {
        $bytes = $payload.Files[$name]
        $oid = Get-CrgRetentionGitLine -ProjectContext $ProjectContext -Domain private -Arguments @('hash-object', '-w', '-t', 'blob', '--no-filters', '--stdin') -InputBytes $bytes
        if (-not [string]::Equals($oid, (Get-CrgRetentionDigest -Bytes $bytes -ObjectFormat $ProjectContext.Domains.private.ObjectFormat -Type blob), [StringComparison]::Ordinal)) { throw 'private retention blob write differs from its exact bytes' }
        [void]$lines.Append('100644 blob ' + $oid + "`t" + $name + [char]0)
      }
      $tree = Get-CrgRetentionGitLine -ProjectContext $ProjectContext -Domain private -Arguments @('mktree', '-z') -InputBytes ([Text.Encoding]::ASCII.GetBytes($lines.ToString()))
      Assert-CrgRetentionOid -Oid $tree -ObjectFormat $ProjectContext.Domains.private.ObjectFormat
      $message = [Text.Encoding]::ASCII.GetBytes("crg-pair-retention v1`nreceipt-sha256 $($receipt.ReceiptSha256)`n")
      $commit = Get-CrgRetentionGitLine -ProjectContext $ProjectContext -Domain private -Arguments @('-c', 'commit.gpgsign=false', '-c', 'user.name=Cross Review Gate', '-c', 'user.email=crg-retention@localhost', 'commit-tree', $tree, '-p', $receipt.Fields['private-result'], '--no-gpg-sign', '-F', '-') -InputBytes $message
      Assert-CrgRetentionOid -Oid $commit -ObjectFormat $ProjectContext.Domains.private.ObjectFormat
      $created = Read-CrgRetentionCommit -ProjectContext $ProjectContext -Domain private -Oid $commit
      if ($created.TreeOid -cne $tree -or $created.Parents.Count -ne 1 -or $created.Parents[0] -cne $receipt.Fields['private-result'] -or
          (Get-CrgRetentionDigest -Bytes $created.MessageBytes) -cne (Get-CrgRetentionDigest -Bytes $message)) { throw 'created retention commit differs from its exact metadata inputs' }
      New-CrgRetentionRef -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain private -Ref $ref -Oid $commit
    }
    # Private record existence is not activation. A retry may complete only this
    # public result-only retention ref after revalidating an exact private record.
    $record = Read-CrgRetentionRecord -ProjectContext $ProjectContext -ReceiptSha256 $receipt.ReceiptSha256 -ExpectedOrigin $Origin
    $requests = @(foreach ($name in $payload.Files.Keys) {
      [pscustomobject]@{ Oid = $record.Entries[$name]; Type = 'blob'; Maximum = [int]$record.Bounds[$name] }
    })
    $batch = Read-CrgRetentionObjects -ProjectContext $ProjectContext -Domain private -Requests $requests -MaximumAggregate 536870912
    [long]$readbackTotal = 0
    foreach ($name in $payload.Files.Keys) {
      $bytes = $batch[$record.Entries[$name]]
      if ($bytes -isnot [byte[]]) { throw 'private retention readback batch omitted a requested evidence leaf' }
      $readbackTotal += $bytes.Length
      if ($readbackTotal -gt 536870912) { throw 'private retention readback exceeds the complete 512 MiB bound' }
      if ((Get-CrgRetentionDigest -Bytes $bytes) -cne (Get-CrgRetentionDigest -Bytes $payload.Files[$name])) { throw 'existing private retention differs from the exact requested evidence' }
    }
    if ($null -eq $existingPublic) { New-CrgRetentionRef -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain public -Ref $publicRef -Oid $receipt.Fields['public-result'] }
    $result = Read-CrgRetentionCore -ProjectContext $ProjectContext -ReceiptSha256 $receipt.ReceiptSha256 -Origin $Origin -AttachmentBytes $AttachmentBytes
  } catch {
    $failure = $_.Exception
    while ($null -ne $failure -and -not $failure.Data.Contains('CrgPairRetentionUncertainReference')) { $failure = $failure.InnerException }
    if ($null -ne $failure) {
      # Match the existing session contract: release no namespace owner while
      # an admitted child can still use that namespace. The operation caller
      # must retain the exception and runtime context for explicit cleanup.
      $preserveCustody = $true
      $failure.Data['CrgPairRetentionNamespacePins'] = $custody
      $failure.Data['CrgPairRetentionProjectContext'] = $ProjectContext
    }
    throw
  } finally {
    if (-not $preserveCustody) { foreach ($pin in $custody) { $pin.Handle.Dispose() } }
  }
  return $result
}

function Read-CrgPairRetention {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][string]$ReceiptSha256)
  return Read-CrgRetentionCore @PSBoundParameters -Origin 'paired-v1'
}

function Write-CrgPairRetention {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][object[]]$ReviewAttempts)
  return Write-CrgRetentionCore @PSBoundParameters -Origin 'paired-v1'
}

function Read-CrgFirstAttachmentRetention {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][string]$ReceiptSha256,
    [AllowNull()][AllowEmptyCollection()][byte[]]$AttachmentBytes)
  return Read-CrgRetentionCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function Write-CrgFirstAttachmentRetention {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][object]$CapturedInput,
    [Parameter(Mandatory = $true)][object[]]$ReviewAttempts,
    [AllowNull()][AllowEmptyCollection()][byte[]]$AttachmentBytes)
  return Write-CrgRetentionCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function Read-CrgCompletedPairRetention {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$PointerBytes,
    [AllowNull()][AllowEmptyCollection()][byte[]]$AttachmentBytes)
  $readPointer = Get-CrgRetentionCommand -Module paired-governance -Name Read-CrgCompletedPairPointerBytes
  $pointer = & $readPointer -Bytes $PointerBytes
  if ([string]::Equals($pointer.Origin, 'paired-v1', [StringComparison]::Ordinal) -and $null -ne $AttachmentBytes) { throw 'ordinary completed retention cannot use proposed attachment bytes' }
  $result = Read-CrgRetentionCore -ProjectContext $ProjectContext -ReceiptSha256 $pointer.ReceiptSha256 -Origin $pointer.Origin -AttachmentBytes $AttachmentBytes
  $readReceipt = Get-CrgRetentionCommand -Module paired-governance -Name Read-CrgCompletedPairReceiptBytes
  $null = & $readReceipt -Bytes $result.ReceiptBytes -PointerBytes $PointerBytes -PublicObjectFormat $ProjectContext.Domains.public.ObjectFormat -PrivateObjectFormat $ProjectContext.Domains.private.ObjectFormat
  return $result
}

Export-ModuleMember -Function Write-CrgPairRetention, Read-CrgPairRetention, Write-CrgFirstAttachmentRetention, Read-CrgFirstAttachmentRetention, Read-CrgCompletedPairRetention
