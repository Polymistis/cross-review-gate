# Effective-config Git plumbing only. No review, attachment or publication grant.
# Every child belongs to the existing native owner; caller custody remains borrowed.

function Get-CrgOperationGitCommand {
  param([object]$Runtime, [string]$Module, [string]$Name)
  $relative = 'scripts/' + $Module + '.psm1'
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($null -eq $Runtime -or $Runtime.Payloads -isnot [System.Collections.IDictionary] -or
      $relative -cnotin @($Runtime.Payloads.Keys) -or $Runtime.Payloads[$relative].Bytes -isnot [byte[]] -or
      $Runtime.Payloads[$relative].Path -cne (Join-Path $Runtime.Root $relative.Replace('/', '\')) -or
      $commands.Count -ne 1 -or -not [string]::Equals($commands[0].Module.Path, $Runtime.Payloads[$relative].Path, [StringComparison]::OrdinalIgnoreCase)) {
    throw "effective Git requires the retained '$Module/$Name' command"
  }
  return $commands[0]
}

function Get-CrgOperationGitDigest {
  param([byte[]]$Bytes, [string]$ObjectFormat, [ValidateSet('commit', 'blob', 'tree')][string]$ObjectKind = 'commit')
  $hash = if ($ObjectFormat -ceq 'sha1') { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
  try {
    if (-not [string]::IsNullOrEmpty($ObjectFormat)) {
      if ($ObjectFormat -cnotin @('sha1', 'sha256')) { throw 'effective Git object format is invalid' }
      $header = [Text.Encoding]::ASCII.GetBytes($ObjectKind + ' ' + $Bytes.Length.ToString([Globalization.CultureInfo]::InvariantCulture) + [char]0)
      $null = $hash.TransformBlock($header, 0, $header.Length, $null, 0)
    }
    $null = $hash.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    return ([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant()
  } finally { $hash.Dispose() }
}

function Assert-CrgOperationGitOid {
  param([string]$Oid, [string]$ObjectFormat)
  $width = if ($ObjectFormat -ceq 'sha1') { 40 } elseif ($ObjectFormat -ceq 'sha256') { 64 } else { throw 'effective Git object format is invalid' }
  if ($Oid -cnotmatch ('\A[0-9a-f]{' + $width + '}\z') -or $Oid -cmatch '\A0+\z') { throw 'effective Git requires a canonical nonzero object identity' }
}

function Get-CrgOperationGitEnvironment {
  param([object]$Runtime, [string]$IndexPath)
  $initializer = Get-CrgOperationGitCommand -Runtime $Runtime -Module paired-review-session -Name Invoke-CrgPairedReviewSession
  $raw = & $initializer.Module {
    # Reuse the retained native raw-block reader, not a lossy environment map.
    $null = Get-CrgPairedSessionEnvironment
    return ,([CrgPairedSession.EnvironmentV1]::Capture())
  }
  $path = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Process)
  if ([string]::IsNullOrEmpty($path)) { throw 'effective Git requires a nonempty process Path' }
  $entries = New-Object 'System.Collections.Generic.List[string]'
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in $raw) {
    if ([string]::IsNullOrEmpty($entry) -or $entry.Contains([char]0)) { throw 'effective Git raw environment is malformed' }
    $separator = if ($entry[0] -ceq '=') { $entry.IndexOf('=', 1) } else { $entry.IndexOf('=') }
    if ($separator -le 0) { throw 'effective Git raw environment lacks a name boundary' }
    $name = $entry.Substring(0, $separator)
    if ($name -imatch '\AGIT_(?:CONFIG(?:_.*)?|ATTR_.*|GRAFT_FILE|SHALLOW_FILE|DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|NAMESPACE|REFERENCE_BACKEND|REPLACE_REF_BASE|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|EXEC_PATH|TEMPLATE_DIR|LITERAL_PATHSPECS|GLOB_PATHSPECS|NOGLOB_PATHSPECS|ICASE_PATHSPECS)\z') {
      throw "effective Git refuses ambient authority carrier '$name'"
    }
    if ($name -ieq 'Path' -or $name -imatch '\AGIT_(?:NO_REPLACE_OBJECTS|NO_LAZY_FETCH|OPTIONAL_LOCKS)\z' -or $name -imatch '\ACROSS_REVIEW_') { continue }
    # HOME/XDG, ordinary config lookup and legitimate author/committer metadata
    # remain exact. Ambiguous raw duplicate spellings are not resolved by guess.
    if (-not $seen.Add($name)) { throw "effective Git refuses duplicate raw environment name '$name'" }
    $entries.Add($entry)
  }
  $entries.Add('Path=' + $path)
  $entries.Add('GIT_NO_REPLACE_OBJECTS=1'); $entries.Add('GIT_NO_LAZY_FETCH=1'); $entries.Add('GIT_OPTIONAL_LOCKS=0')
  if (-not [string]::IsNullOrEmpty($IndexPath)) { $entries.Add('GIT_INDEX_FILE=' + $IndexPath) }
  return ,$entries.ToArray()
}

function Open-CrgOperationGitState {
  param([object]$ProjectContext, [object]$OperationLock, [string]$Domain, [string]$IndexPath)
  if ($null -eq $ProjectContext -or $ProjectContext.Schema -ne 1 -or
      $ProjectContext.Domains -isnot [System.Collections.IDictionary] -or $ProjectContext.Domains.Count -ne 2 -or
      $Domain -cnotin @('public', 'private') -or $null -eq $ProjectContext.Runtime -or
      $ProjectContext.Runtime.Id -cnotmatch '\A[0-9a-f]{64}\z' -or $ProjectContext.Runtime.ReadFile -isnot [scriptblock]) { throw 'effective Git requires a retained two-domain project context' }
  $runtime = $ProjectContext.Runtime
  $commands = @{}
  foreach ($item in @(
    @{ Module = 'paired-diff'; Names = @('Assert-CrgPairedOperationLock', 'New-CrgPairedIndexCopy') },
    @{ Module = 'paired-process'; Names = @('Start-CrgPairedReviewProcess', 'Wait-CrgPairedReviewProcess', 'Complete-CrgPairedReviewProcess', 'Stop-CrgPairedReviewProcess', 'Close-CrgPairedReviewProcess') },
    @{ Module = 'private-governance'; Names = @('Read-CrgAttachmentBytes') }
  )) { foreach ($name in $item.Names) { $commands[$name] = Get-CrgOperationGitCommand -Runtime $runtime -Module $item.Module -Name $name } }
  & $commands['Assert-CrgPairedOperationLock'] -Lock $OperationLock
  $paths = New-Object 'System.Collections.Generic.List[string]'
  $paths.Add($ProjectContext.Root); $paths.Add($ProjectContext.GitExe)
  foreach ($name in @('public', 'private')) {
    if (-not $ProjectContext.Domains.Contains($name)) { throw 'effective Git domain is absent' }
    $selected = $ProjectContext.Domains[$name]
    foreach ($path in @($selected.GitDir, $selected.CommonDir, $selected.ObjectDir, $selected.IndexPath)) { $paths.Add($path) }
    if ($selected.ObjectFormat -cnotin @('sha1', 'sha256') -or $selected.ObjectDir -cne (Join-Path $selected.CommonDir 'objects')) { throw 'effective Git object namespace is invalid' }
    $expectedIndex = if ($name -ceq 'public') { Join-Path $selected.GitDir 'index' } else { Join-Path $ProjectContext.Domains.public.GitDir 'crg-private-index' }
    if ($selected.IndexPath -cne $expectedIndex) { throw 'effective Git index is not the fixed context-associated index' }
    & $commands['Read-CrgAttachmentBytes'].Module { param($Ref) Assert-CrgGovernanceBranchRef -Ref $Ref } $selected.Ref
    if ($name -ceq 'private' -and $selected.Parent -ceq 'absent') { continue }
    Assert-CrgOperationGitOid -Oid $selected.Parent -ObjectFormat $selected.ObjectFormat
  }
  & $commands['Read-CrgAttachmentBytes'].Module {
    param($Paths)
    foreach ($path in $Paths) {
      Assert-CrgGovernancePath -Path $path -Absolute -AllowGitMetadata
      if ([IO.Path]::GetFullPath($path) -cne $path) { throw 'effective Git path is not canonical' }
    }
  } $paths.ToArray()
  if ($OperationLock.PublicGitDirectory -cne $ProjectContext.Domains.public.GitDir -or
      $ProjectContext.Domains.private.GitDir -cne $ProjectContext.Domains.private.CommonDir -or
      [string]::Equals($ProjectContext.Domains.public.CommonDir, $ProjectContext.Domains.private.CommonDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'effective Git lock or domain separation differs from the captured project' }
  if (-not [string]::IsNullOrEmpty($IndexPath) -and $IndexPath -cne $ProjectContext.Domains[$Domain].IndexPath) { throw 'effective Git refuses a caller-selected index path' }
  $environment = Get-CrgOperationGitEnvironment -Runtime $runtime -IndexPath $IndexPath
  $gitFile = & $runtime.ReadFile -Path $ProjectContext.GitExe -Maximum 16777216
  if ($null -eq $gitFile -or $gitFile.Present -ne $true -or $gitFile.Bytes -isnot [byte[]] -or
      $gitFile.Path -cne $ProjectContext.GitExe -or $gitFile.Stream -isnot [IO.FileStream] -or
      -not $gitFile.Stream.CanRead -or $gitFile.Stream.CanWrite -or $gitFile.Stream.SafeFileHandle.IsClosed) { throw 'effective Git requires the borrowed retained executable stream' }
  $native = $commands['New-CrgPairedIndexCopy'].Module
  $custody = @{ DirectoryPins = (New-Object 'System.Collections.Generic.List[object]'); OwnedDirectories = (New-Object 'System.Collections.Generic.List[object]'); ControlFiles = (New-Object 'System.Collections.Generic.List[object]') }
  $state = [pscustomobject]@{ ProjectContext = $ProjectContext; OperationLock = $OperationLock; Domain = $Domain; Commands = $commands
    NativeModule = $native; Custody = $custody; EnvironmentEntries = $environment; GitFile = $gitFile; Directory = $null
    GitParent = $null; GitSha256 = (Get-CrgOperationGitDigest -Bytes $gitFile.Bytes)
    Session = $null; Transcript = $null; BorrowedTranscriptHandle = $null; TranscriptRecord = $null; TranscriptAddedRef = $false
    LfsExecutable = $null; LfsExecutableCommands = $null; InputStream = $null; InputHandle = $null; InputRecord = $null; InputAddedRef = $false
    Observations = (New-Object 'System.Collections.Generic.List[object]'); Closed = $false }
  try {
    $state.Directory = & $native {
      param($State)
      Initialize-CrgAttributeNeutralNative
      $paths = @($State.ProjectContext.Root, [IO.Path]::GetDirectoryName($State.ProjectContext.GitExe))
      foreach ($name in @('public', 'private')) {
        $domain = $State.ProjectContext.Domains[$name]
        $paths += @($domain.GitDir, $domain.CommonDir, $domain.ObjectDir)
      }
      # Acquire ancestor roots strongly before a child chain can introduce a
      # weaker pin for the same path; native custody cannot upgrade in place.
      foreach ($path in @($paths | Sort-Object Length)) {
        $null = Enter-CrgAttributeNeutralDirectoryChain -Path $path -Pins $State.Custody.DirectoryPins -DenyLeafRename
      }
      $State.GitParent = Enter-CrgAttributeNeutralDirectoryChain -Path ([IO.Path]::GetDirectoryName($State.ProjectContext.GitExe)) -Pins $State.Custody.DirectoryPins -DenyLeafRename
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $State.ProjectContext.Domains.private.GitDir -Pins $State.Custody.DirectoryPins -DenyLeafRename
      $leaf = '.crg-git-operation-' + [guid]::NewGuid().ToString('N')
      New-CrgAttributeNeutralOwnedDirectory -Custody $State.Custody -Parent $parent -Leaf $leaf -Path (Join-Path $parent.Path $leaf) -Label 'private effective Git operation'
    } $state
    return $state
  } catch { $null = & $native { param($Custody) Close-CrgAttributeNeutralContext -Custody $Custody } $custody; throw }
}

function Assert-CrgOperationGitState {
  param([object]$State)
  if ($State.Closed) { throw 'effective Git custody is closed' }
  & $State.Commands['Assert-CrgPairedOperationLock'] -Lock $State.OperationLock
  & $State.NativeModule {
    param($Custody)
    # Match the existing PS5 operation-lock caller: generic lists reached
    # through a property must become concrete arrays before the shared check.
    $snapshot = @{ DirectoryPins = $Custody.DirectoryPins.ToArray(); OwnedDirectories = $Custody.OwnedDirectories.ToArray(); ControlFiles = $Custody.ControlFiles.ToArray() }
    Assert-CrgAttributeNeutralContextStable -Context @{ Custody = $snapshot } -Boundary 'effective Git child'
  } $State.Custody
  $errorCode = 0; $probe = $null
  try {
    # Installed executable hard links are read-only aliases, not mutable
    # project/evidence leaves. Keep the latter single-link checks unchanged.
    $probe = [CrgAttributeNeutral.NativeV1]::OpenReadFileRelative($State.GitParent.Handle, [IO.Path]::GetFileName($State.ProjectContext.GitExe), [ref]$errorCode)
    if ($null -eq $probe -or $probe.IsInvalid -or $State.GitFile.Stream.SafeFileHandle.IsClosed -or
        -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryFile($probe) -or
        -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryFile($State.GitFile.Stream.SafeFileHandle) -or
        -not [CrgAttributeNeutral.NativeV1]::SameIdentity($probe, $State.GitFile.Stream.SafeFileHandle)) { throw 'effective Git executable lost retained relative identity' }
    $actual = & $State.NativeModule { param($Handle) Get-CrgOwnedBinaryFileDigest -Record @{ Handle = $Handle } } $State.GitFile.Stream.SafeFileHandle
    if ($actual.Length -ne $State.GitFile.Bytes.Length -or $actual.Sha256 -cne $State.GitSha256 -or
        (Get-CrgOperationGitDigest -Bytes $State.GitFile.Bytes) -cne $State.GitSha256) { throw 'effective Git executable differs from the retained bytes' }
  } finally { if ($null -ne $probe) { $probe.Dispose() } }
  if ($null -ne $State.LfsExecutable) { & $State.LfsExecutableCommands.Assert -Owner $State.LfsExecutable }
}

function Close-CrgOperationGitTranscript {
  param([object]$State)
  if ($null -ne $State.Transcript) { $State.Transcript.Dispose(); $State.Transcript = $null }
  if ($null -ne $State.BorrowedTranscriptHandle) { $State.BorrowedTranscriptHandle.Dispose(); $State.BorrowedTranscriptHandle = $null }
  if ($State.TranscriptAddedRef) { $State.TranscriptRecord.Handle.DangerousRelease(); $State.TranscriptAddedRef = $false }
  $State.TranscriptRecord = $null
}

function Close-CrgOperationGitState {
  param([object]$State)
  if ($null -ne $State.Session) {
    try {
      $stopped = @(& $State.Commands['Stop-CrgPairedReviewProcess'] -Session $State.Session -TimeoutMilliseconds 10000)
      if ($stopped.Count -ne 1 -or -not $stopped[0].Quiescent -or $null -ne $stopped[0].Error) { throw 'effective Git child stop is unconfirmed' }
      $closed = @(& $State.Commands['Close-CrgPairedReviewProcess'] -Session $State.Session)
      if ($closed.Count -ne 1 -or -not $closed[0].Closed -or -not $closed[0].Quiescent -or $null -ne $closed[0].Error) { throw 'effective Git child close is unconfirmed' }
      $State.Session = $null
    } catch {
      # The state keeps every stream/pin plus the borrowed runtime and operation
      # lock reachable. Never release namespace custody on uncertain child exit.
      $failure = [InvalidOperationException]::new('effective Git descendant cleanup is unconfirmed; retain the operation and all child custody', $_.Exception)
      $failure.Data['CrgPairedProcessSession'] = $State.Session
      $failure.Data['CrgPairedGitOperationState'] = $State
      throw $failure
    }
  }
  Close-CrgOperationGitTranscript -State $State
  if ($null -ne $State.InputStream) { $State.InputStream.Dispose(); $State.InputStream = $null }
  if ($null -ne $State.InputHandle) { $State.InputHandle.Dispose(); $State.InputHandle = $null }
  if ($State.InputAddedRef) { $State.InputRecord.Handle.DangerousRelease(); $State.InputAddedRef = $false }
  if ($null -ne $State.LfsExecutable) { & $State.LfsExecutableCommands.Close -Owner $State.LfsExecutable; $State.LfsExecutable = $null }
  $closed = & $State.NativeModule { param($Custody) Close-CrgAttributeNeutralContext -Custody $Custody } $State.Custody
  $State.Closed = $true
  if (-not $closed.Ok) { throw "effective Git exact scratch cleanup failed: $($closed.Reason)" }
}

function Invoke-CrgOperationGitChild {
  param([object]$State, [string[]]$Arguments, [int]$Maximum = 65536,
    [ValidateRange(1000, 600000)][int]$TimeoutMilliseconds = 10000, [switch]$LfsPrePush, [switch]$LfsPostCommit)
  Assert-CrgOperationGitState -State $State
  if ($LfsPrePush -and $LfsPostCommit) { throw 'effective Git cannot select two Git LFS hook routes' }
  if ($null -ne $State.Session) { throw 'effective Git cannot launch over an outstanding child' }
  Close-CrgOperationGitTranscript -State $State
  $errorCode = 0
  $leaf = 'output-' + $State.Observations.Count + '.bin'
  $handle = [CrgAttributeNeutral.NativeV1]::CreateOwnedFileRelative($State.Directory.Handle, $leaf, [ref]$errorCode)
  if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) {
    if ($null -ne $handle) { $handle.Dispose() }
    throw "effective Git transcript create-new failed (Win32 error $errorCode)"
  }
  $State.TranscriptRecord = [pscustomobject]@{ Path = (Join-Path $State.Directory.Path $leaf); Handle = $handle; Label = 'effective Git transcript' }
  $State.Custody.ControlFiles.Add($State.TranscriptRecord)
  $added = $false; $handle.DangerousAddRef([ref]$added); $State.TranscriptAddedRef = $added
  $State.BorrowedTranscriptHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($handle.DangerousGetHandle(), $false)
  $State.Transcript = [IO.FileStream]::new($State.BorrowedTranscriptHandle, [IO.FileAccess]::ReadWrite, 8192, $false)
  $selected = $State.ProjectContext.Domains[$State.Domain]
  $verb = $Arguments[0]
  # Literal path selection is a Git global option, not the command. Both
  # public and private deletion routes use this existing prefixed form.
  if ($verb -ceq '--literal-pathspecs') { $verb = $Arguments[1] }
  $prefix = @('--no-pager', "--git-dir=$($selected.GitDir)", "--work-tree=$($State.ProjectContext.Root)")
  $prefix += @('-c', 'core.fsmonitor=false', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false')
  $hooksPath = $null
  $lfsHook = $LfsPrePush -or $LfsPostCommit
  if ($verb -cin @('add', 'update-index', 'read-tree', 'update-ref') -or $lfsHook) {
    $binding = Get-CrgOperationGitCommand -Runtime $State.ProjectContext.Runtime -Module central-guards -Name Get-CrgCentralGuardBinding
    $hooksPath = & $binding -ProjectContext $State.ProjectContext -OperationLock $State.OperationLock -Domain $State.Domain
    $hookPattern = '\A' + [regex]::Escape((Join-Path $State.ProjectContext.Domains.private.GitDir '.crg-hooks-')) + '[0-9a-f]{32}\\' + $State.Domain + '\z'
    if ($hooksPath -isnot [string] -or $hooksPath -cnotmatch $hookPattern) { throw 'effective Git requires the admitted private hook projection for this domain' }
  }
  if ($null -ne $hooksPath) { $prefix += @('-c', ('core.hooksPath=' + $hooksPath)) }
  $launch = @{ ApplicationName = $State.ProjectContext.GitExe; Arguments = ($prefix + $Arguments)
    WorkingDirectory = $State.ProjectContext.Root; EnvironmentEntries = $State.EnvironmentEntries; TranscriptStream = $State.Transcript }
  if ($LfsPrePush) {
    if ($null -eq $State.InputStream -or -not $State.InputStream.CanRead -or $State.InputStream.SafeFileHandle.IsClosed) { throw 'effective Git input stream lost retained readable custody' }
    $State.InputStream.Position = 0
    $launch.InputStream = $State.InputStream
  }
  $lifetime = $TimeoutMilliseconds
  if ($lfsHook) {
    if ($State.Domain -cne 'public' -or $null -eq $State.LfsExecutable -or
        ($LfsPrePush -and ($null -eq $State.InputStream -or $Arguments.Count -ne 4 -or $Arguments[0] -cne 'pre-push' -or $Arguments[1] -cne '--')) -or
        ($LfsPostCommit -and ($Arguments.Count -ne 1 -or $Arguments[0] -cne 'post-commit'))) { throw 'Git LFS launch requires one exact owned stock hook route' }
    $launch.ApplicationName = $State.LfsExecutable.Record.Path
    $launch.Arguments = $Arguments
    # Git LFS launches Git internally. Supply only the already admitted public
    # association; ambient selectors were rejected by state acquisition.
    $launch.EnvironmentEntries = $State.EnvironmentEntries + @(('GIT_DIR=' + $selected.GitDir), ('GIT_WORK_TREE=' + $State.ProjectContext.Root),
      'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=core.hooksPath', ('GIT_CONFIG_VALUE_0=' + $hooksPath))
    $lifetime = 1800000
    $lfsLabel = if ($LfsPrePush) { 'pre-push' } else { 'post-commit' }
    $lfsPrefix = if ($LfsPrePush) { '[paired-push]' } else { '[paired-publication]' }
    if ($LfsPrePush) { Write-Host '[paired-push] completed-pair history validated; Git LFS pre-push is running...' }
    else { Write-Host '[paired-publication] reviewed public result reached; Git LFS post-commit is running...' }
  }
  try {
    $State.Session = & $State.Commands['Start-CrgPairedReviewProcess'] @launch
  } catch {
    $failure = $_.Exception
    while ($null -ne $failure -and -not $failure.Data.Contains('CrgPairedProcessSession')) { $failure = $failure.InnerException }
    if ($null -ne $failure) { $State.Session = $failure.Data['CrgPairedProcessSession'] }
    throw
  }
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $nextProgress = 15000
  do {
    $observed = @(& $State.Commands['Wait-CrgPairedReviewProcess'] -Session $State.Session -TimeoutMilliseconds 250)
    if ($observed.Count -ne 1) { throw 'effective Git child observation count is invalid' }
    if ($State.Transcript.Length -gt $Maximum) { throw 'effective Git merged output exceeds its acquisition bound' }
    if ($observed[0].Quiescent) { break }
    if ($null -ne $observed[0].Error -and $observed[0].Error -cne 'drain-timeout') { throw 'effective Git child observation failed' }
    if ($timer.ElapsedMilliseconds -ge $lifetime) { throw 'effective Git child exceeded the owned lifetime bound' }
    if ($lfsHook -and $timer.ElapsedMilliseconds -ge $nextProgress) {
      Write-Host ("$lfsPrefix Git LFS $lfsLabel remains active ({0}s); operation custody is retained." -f [int]$timer.Elapsed.TotalSeconds)
      $nextProgress += 15000
    }
  } while ($true)
  $completed = @(& $State.Commands['Complete-CrgPairedReviewProcess'] -Session $State.Session -TimeoutMilliseconds 0)
  if ($completed.Count -ne 1 -or -not $completed[0].ProcessCreated -or -not $completed[0].ExitObserved -or
      -not $completed[0].Quiescent -or -not $completed[0].Closed -or $completed[0].ActiveProcesses -ne 0 -or
      $null -ne $completed[0].Error -or $null -eq $completed[0].ExitCode) { throw 'effective Git lacks a complete owned child exit' }
  $State.Session = $null
  Assert-CrgOperationGitState -State $State
  $State.Transcript.Flush($true); $State.Transcript.Position = 0
  if ($State.Transcript.Length -gt $Maximum) { throw 'effective Git merged output exceeds its completed bound' }
  $bytes = New-Object byte[] ([int]$State.Transcript.Length)
  $offset = 0
  while ($offset -lt $bytes.Length) {
    $count = $State.Transcript.Read($bytes, $offset, $bytes.Length - $offset)
    if ($count -le 0) { throw 'effective Git transcript was truncated under custody' }
    $offset += $count
  }
  $result = [pscustomobject]@{ Bytes = $bytes; ExitCode = [int]$completed[0].ExitCode; Observation = $completed[0]; ReadyForPublication = $false }
  $State.Observations.Add($result)
  return $result
}

function Get-CrgOperationGitLine {
  param([object]$Result, [switch]$AllowEmpty)
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($Result.Bytes)
  $pattern = if ($AllowEmpty) { '\A[^\x00-\x1f\x7f]*\n\z' } else { '\A[^\x00-\x1f\x7f]+\n\z' }
  if ($Result.ExitCode -ne 0 -or $text -cnotmatch $pattern) { throw 'effective Git returned failure or noncanonical merged output' }
  return $text.Substring(0, $text.Length - 1)
}

function Assert-CrgOperationGitNamespace {
  param([object]$State)
  $selected = $State.ProjectContext.Domains[$State.Domain]
  foreach ($probe in @(
    @{ Args = @('rev-parse', '--path-format=absolute', '--git-common-dir'); Expected = $selected.CommonDir; Path = $true },
    @{ Args = @('rev-parse', '--path-format=absolute', '--git-path', 'objects'); Expected = $selected.ObjectDir; Path = $true },
    @{ Args = @('rev-parse', '--show-object-format'); Expected = $selected.ObjectFormat; Path = $false }
  )) {
    $line = Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $State -Arguments $probe.Args)
    if ($probe.Path) { $line = $line.Replace('/', '\') }
    if ($line -cne $probe.Expected) { throw 'effective Git namespace differs from the captured domain' }
  }
  foreach ($leaf in @('alternates', 'http-alternates')) {
    $file = & $State.ProjectContext.Runtime.ReadFile -Path (Join-Path $selected.ObjectDir ('info/' + $leaf)) -Maximum 65536 -AllowAbsent
    if ($null -eq $file -or $file.Present -isnot [bool] -or $file.Present) { throw 'effective Git requires positively absent object alternates' }
  }
}

function Read-CrgOperationGitRef {
  param([object]$State)
  $ref = $State.ProjectContext.Domains[$State.Domain].Ref
  $symbolic = Invoke-CrgOperationGitChild -State $State -Arguments @('symbolic-ref', '--quiet', '--no-recurse', $ref)
  if ($symbolic.ExitCode -ne 1 -or $symbolic.Bytes.Length -ne 0) { throw 'effective Git branch is symbolic or indeterminate' }
  $exists = Invoke-CrgOperationGitChild -State $State -Arguments @('show-ref', '--verify', '--quiet', $ref)
  if ($exists.Bytes.Length -ne 0 -or $exists.ExitCode -notin @(0, 1)) { throw 'effective Git branch existence is indeterminate' }
  if ($exists.ExitCode -eq 1) { return 'absent' }
  $line = Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $State -Arguments @('for-each-ref', '--count=2', '--format=%(refname) %(objectname) %(symref)', $ref))
  if ($line -cnotmatch ('\A' + [regex]::Escape($ref) + ' ([0-9a-f]+) \z')) { throw 'effective Git branch is not one exact direct reference' }
  $oid = [string]$Matches[1]
  Assert-CrgOperationGitOid -Oid $oid -ObjectFormat $State.ProjectContext.Domains[$State.Domain].ObjectFormat
  return $oid
}

function Read-CrgOperationGitCommit {
  param([object]$State, [string]$Oid)
  $format = $State.ProjectContext.Domains[$State.Domain].ObjectFormat
  Assert-CrgOperationGitOid -Oid $Oid -ObjectFormat $format
  if ((Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $State -Arguments @('cat-file', '-t', $Oid))) -cne 'commit') { throw 'effective Git result is not an actual commit object' }
  $result = Invoke-CrgOperationGitChild -State $State -Arguments @('cat-file', 'commit', $Oid) -Maximum 2097152
  if ($result.ExitCode -ne 0 -or (Get-CrgOperationGitDigest -Bytes $result.Bytes -ObjectFormat $format) -cne $Oid) { throw 'effective Git raw commit differs from its object identity' }
  $separator = -1
  for ($i = 0; $i -lt $result.Bytes.Length - 1; $i++) { if ($result.Bytes[$i] -eq 10 -and $result.Bytes[$i + 1] -eq 10) { $separator = $i; break } }
  if ($separator -lt 0) { throw 'effective Git commit lacks its raw message boundary' }
  $lines = [Text.Encoding]::GetEncoding(28591).GetString($result.Bytes, 0, $separator) -split "`n", 0
  if ($lines[0] -cnotmatch '\Atree ([0-9a-f]+)\z') { throw 'effective Git commit lacks its leading tree' }
  $tree = [string]$Matches[1]; Assert-CrgOperationGitOid -Oid $tree -ObjectFormat $format
  $parents = New-Object 'System.Collections.Generic.List[string]'
  foreach ($line in $lines | Select-Object -Skip 1) {
    if ($line.StartsWith('tree ', [StringComparison]::Ordinal)) { throw 'effective Git commit repeats its tree' }
    if ($line.StartsWith('parent ', [StringComparison]::Ordinal)) {
      $parent = $line.Substring(7); Assert-CrgOperationGitOid -Oid $parent -ObjectFormat $format; $parents.Add($parent)
    }
  }
  $message = New-Object byte[] ($result.Bytes.Length - $separator - 2)
  [Array]::Copy($result.Bytes, $separator + 2, $message, 0, $message.Length)
  return [pscustomobject]@{ TreeOid = $tree; Parents = $parents.ToArray(); MessageBytes = $message; Raw = $result
    AuthorRecords = @($lines | Where-Object { $_.StartsWith('author ', [StringComparison]::Ordinal) })
    CommitterRecords = @($lines | Where-Object { $_.StartsWith('committer ', [StringComparison]::Ordinal) }) }
}

function Read-CrgOperationGitIdentity {
  param([object]$State, [string]$Kind)
  if ($State.Domain -ceq 'private') {
    # Both result commits represent one public project operation. Resolve the
    # project identity from that project's effective Git configuration rather
    # than requiring or inventing identity configuration in private storage.
    $publicState = Open-CrgOperationGitState -ProjectContext $State.ProjectContext -OperationLock $State.OperationLock -Domain public -IndexPath $null
    try {
      Assert-CrgOperationGitNamespace -State $publicState
      return Read-CrgOperationGitIdentity -State $publicState -Kind $Kind
    } catch {
      $_.Exception.Data['CrgPairedGitIdentityObservations'] = $publicState.Observations.ToArray()
      throw
    } finally { Close-CrgOperationGitState -State $publicState }
  }
  $variable = if ($Kind -ceq 'Author') { 'GIT_AUTHOR_IDENT' } elseif ($Kind -ceq 'Committer') { 'GIT_COMMITTER_IDENT' } else { throw 'effective Git identity kind is invalid' }
  $result = Invoke-CrgOperationGitChild -State $State -Arguments @('var', $variable)
  $line = Get-CrgOperationGitLine -Result $result
  if ($line -cnotmatch '\A([^<>\r\n]+) <([^<>\r\n]+)> ([0-9]+) ([+-][0-9]{4})\z') { throw 'effective Git identity output is not canonical' }
  return [pscustomobject]@{ Name = $Matches[1]; Email = $Matches[2]; Date = '@' + $Matches[3] + ' ' + $Matches[4]; Text = $line; Raw = $result }
}

function Invoke-CrgOperationGitCapability {
  param([object]$ProjectContext, [object]$OperationLock, [string]$Domain, [string]$IndexPath,
    [string]$Capability, [string]$Kind, [string]$TreeOid, [string]$ParentOid, [byte[]]$MessageBytes,
    [string]$ExpectedOldOid, [string]$NewOid)
  if ($Capability -cnotin @('HooksPath', 'Identity', 'ResultCommit', 'ExpectedRef')) { throw 'effective Git capability is unsupported' }
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $Domain -IndexPath $IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    $selected = $ProjectContext.Domains[$Domain]
    $value = $null; $result = $null
    switch -CaseSensitive ($Capability) {
      'HooksPath' {
        $result = Invoke-CrgOperationGitChild -State $state -Arguments @('config', '--get', 'core.hooksPath')
        if ($result.ExitCode -eq 1 -and $result.Bytes.Length -eq 0) { $value = [pscustomobject]@{ State = 'unset'; Value = $null } }
        elseif ($result.ExitCode -eq 0) { $value = [pscustomobject]@{ State = 'set'; Value = (Get-CrgOperationGitLine -Result $result -AllowEmpty) } }
        else { throw 'effective Git hooksPath lookup is indeterminate' }
      }
      'Identity' { $identity = Read-CrgOperationGitIdentity -State $state -Kind $Kind; $result = $identity.Raw; $value = $identity.Text }
      'ResultCommit' {
        Assert-CrgOperationGitOid -Oid $TreeOid -ObjectFormat $selected.ObjectFormat
        if ($ParentOid -cne $selected.Parent -or ($ParentOid -ceq 'absent' -and $Domain -cne 'private')) { throw 'effective Git result parent differs from the captured domain' }
        $validateMessage = Get-CrgOperationGitCommand -Runtime $ProjectContext.Runtime -Module paired-preparation -Name Assert-CrgPairedMessageBytes
        & $validateMessage -Bytes $MessageBytes
        if ((Read-CrgOperationGitRef -State $state) -cne $ParentOid) { throw 'effective Git result branch changed from the captured parent' }
        if ($ParentOid -cne 'absent') { $null = Read-CrgOperationGitCommit -State $state -Oid $ParentOid }
        if ((Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $state -Arguments @('cat-file', '-t', $TreeOid))) -cne 'tree') { throw 'effective Git candidate is not an actual tree object' }
        $messageCopy = [byte[]]$MessageBytes.Clone(); $digest = Get-CrgOperationGitDigest -Bytes $messageCopy
        $message = & $state.NativeModule {
          param($State, $Bytes, $Digest)
          New-CrgOwnedBinaryFile -Custody $State.Custody -Parent $State.Directory -Leaf 'message.bin' -Bytes $Bytes -ExpectedSha256 $Digest
        } $state $messageCopy $digest
        $author = Read-CrgOperationGitIdentity -State $state -Kind Author
        $committer = Read-CrgOperationGitIdentity -State $state -Kind Committer
        # Freeze the actual effective identities, including dates, for this result
        # child. Keep ordinary config sources available for every other Git need.
        $environment = New-Object 'System.Collections.Generic.List[string]'
        foreach ($entry in $state.EnvironmentEntries) { if ($entry -inotmatch '\AGIT_(?:AUTHOR|COMMITTER)_(?:NAME|EMAIL|DATE)=') { $environment.Add($entry) } }
        foreach ($pair in @(@('AUTHOR', $author), @('COMMITTER', $committer))) {
          $environment.Add('GIT_' + $pair[0] + '_NAME=' + $pair[1].Name)
          $environment.Add('GIT_' + $pair[0] + '_EMAIL=' + $pair[1].Email)
          $environment.Add('GIT_' + $pair[0] + '_DATE=' + $pair[1].Date)
        }
        $state.EnvironmentEntries = $environment.ToArray()
        $arguments = @('commit-tree', $TreeOid)
        if ($ParentOid -cne 'absent') { $arguments += @('-p', $ParentOid) }
        $arguments += @('-F', $message.Path)
        $result = Invoke-CrgOperationGitChild -State $state -Arguments $arguments
        $oid = Get-CrgOperationGitLine -Result $result; Assert-CrgOperationGitOid -Oid $oid -ObjectFormat $selected.ObjectFormat
        $commit = Read-CrgOperationGitCommit -State $state -Oid $oid
        $parents = if ($ParentOid -ceq 'absent') { 0 } else { 1 }
        if ($commit.TreeOid -cne $TreeOid -or $commit.Parents.Count -ne $parents -or
            ($parents -eq 1 -and $commit.Parents[0] -cne $ParentOid) -or
            (Get-CrgOperationGitDigest -Bytes $commit.MessageBytes) -cne $digest) { throw 'effective Git result differs from the exact tree, ancestry or agreed message bytes' }
        # Header extraction preserves historical non-UTF8 bytes through Latin-1;
        # newly resolved identities must exactly match the UTF-8 result headers.
        $latin = [Text.Encoding]::GetEncoding(28591); $utf8 = [Text.UTF8Encoding]::new($false, $true)
        if ($commit.AuthorRecords.Count -ne 1 -or $commit.CommitterRecords.Count -ne 1 -or
            (Get-CrgOperationGitDigest -Bytes ($latin.GetBytes($commit.AuthorRecords[0]))) -cne (Get-CrgOperationGitDigest -Bytes ($utf8.GetBytes('author ' + $author.Text))) -or
            (Get-CrgOperationGitDigest -Bytes ($latin.GetBytes($commit.CommitterRecords[0]))) -cne (Get-CrgOperationGitDigest -Bytes ($utf8.GetBytes('committer ' + $committer.Text)))) { throw 'effective Git result differs from the captured ordinary author or committer identity' }
        if ((Read-CrgOperationGitRef -State $state) -cne $ParentOid) { throw 'effective Git result creation observed a changed branch' }
        $value = [pscustomobject]@{ Oid = $oid; TreeOid = $TreeOid; ParentOid = $ParentOid; MessageSha256 = $digest; Author = $author.Text; Committer = $committer.Text }
      }
      'ExpectedRef' {
        Assert-CrgOperationGitOid -Oid $NewOid -ObjectFormat $selected.ObjectFormat
        if ($ExpectedOldOid -cne $selected.Parent -or ($ExpectedOldOid -ceq 'absent' -and $Domain -cne 'private')) { throw 'effective Git expected-old differs from the captured domain parent' }
        $commit = Read-CrgOperationGitCommit -State $state -Oid $NewOid
        $parents = if ($ExpectedOldOid -ceq 'absent') { 0 } else { 1 }
        if ($commit.Parents.Count -ne $parents -or ($parents -eq 1 -and $commit.Parents[0] -cne $ExpectedOldOid)) { throw 'effective Git replacement is not the captured parent successor' }
        if ((Read-CrgOperationGitRef -State $state) -cne $ExpectedOldOid) { throw 'effective Git reference differs from expected-old before mutation' }
        $old = if ($ExpectedOldOid -ceq 'absent') { '0' * $NewOid.Length } else { $ExpectedOldOid }
        $result = Invoke-CrgOperationGitChild -State $state -Arguments @('update-ref', '--no-deref', $selected.Ref, $NewOid, $old)
        # A successful hook may still print diagnostics. Merged nonempty output
        # is never promoted to a canonical successful command response.
        if ($result.ExitCode -ne 0 -or $result.Bytes.Length -ne 0) { throw 'effective Git reference update failed or returned noncanonical merged output; inspect actual refs' }
        if ((Read-CrgOperationGitRef -State $state) -cne $NewOid) { throw 'effective Git expected-old update failed exact direct-ref reread' }
        $value = [pscustomobject]@{ Ref = $selected.Ref; OldOid = $ExpectedOldOid; NewOid = $NewOid }
      }
    }
    Assert-CrgOperationGitState -State $state
    return [pscustomobject]@{ Capability = $Capability; Domain = $Domain; Bytes = $result.Bytes; ExitCode = $result.ExitCode
      Observation = $result.Observation; Checks = $state.Observations.ToArray(); Value = $value; ReadyForPublication = $false }
  } catch {
    $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray()
    throw
  } finally { Close-CrgOperationGitState -State $state }
}

function Get-CrgPairedGitHooksPath {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain, [string]$IndexPath)
  Invoke-CrgOperationGitCapability @PSBoundParameters -Capability HooksPath
}

function Get-CrgPairedGitIdentity {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][ValidateSet('Author', 'Committer')][string]$Kind, [string]$IndexPath)
  Invoke-CrgOperationGitCapability @PSBoundParameters -Capability Identity
}

function New-CrgPairedGitResultCommit {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][string]$TreeOid, [Parameter(Mandatory = $true)][string]$ParentOid,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$MessageBytes, [string]$IndexPath)
  Invoke-CrgOperationGitCapability @PSBoundParameters -Capability ResultCommit
}

function Set-CrgPairedGitExpectedRef {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][string]$ExpectedOldOid, [Parameter(Mandatory = $true)][string]$NewOid, [string]$IndexPath)
  Invoke-CrgOperationGitCapability @PSBoundParameters -Capability ExpectedRef
}

Export-ModuleMember -Function Get-CrgPairedGitHooksPath, Get-CrgPairedGitIdentity, New-CrgPairedGitResultCommit, Set-CrgPairedGitExpectedRef

function Assert-CrgOperationGitLiteralPaths {
  param([object]$Runtime, [AllowNull()][string[]]$Paths)
  if ($null -eq $Paths -or $Paths.Count -gt 100000) { throw 'staging requires an explicit bounded literal path array' }
  $parser = Get-CrgOperationGitCommand -Runtime $Runtime -Module private-governance -Name Read-CrgAttachmentBytes
  & $parser.Module {
    param([string[]]$Paths)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $Paths) {
      Assert-CrgGovernancePath -Path $path
      if (-not $seen.Add($path)) { throw 'staging paths contain duplicate or case-aliased names' }
    }
  } -Paths $Paths
}

function Read-CrgOperationGitInventory {
  param([object]$State, [object]$Result, [string]$Kind)
  if ($Result.ExitCode -ne 0 -or ($Result.Bytes.Length -gt 0 -and $Result.Bytes[$Result.Bytes.Length - 1] -ne 0)) { throw 'staging inventory failed or lacks its final NUL' }
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($Result.Bytes)
  $entries = [Collections.Generic.List[object]]::new()
  $records = if ($text.Length -eq 0) { @() } else { @($text.Substring(0, $text.Length - 1).Split([char]0)) }
  $width = if ($State.ProjectContext.Domains[$State.Domain].ObjectFormat -ceq 'sha1') { 40 } else { 64 }
  foreach ($record in $records) {
    if ($Kind -ceq 'Tracked') {
      if ($record -cnotmatch ('\A(100644|100755|120000|160000) ([0-9a-f]{' + $width + '}) 0\t(.+)\z')) { throw 'staging refuses unmerged or malformed index entries' }
      $entries.Add([pscustomobject]@{ Path = [string]$Matches[3]; Mode = [string]$Matches[1]; Oid = [string]$Matches[2]; SkipWorktree = $false; AssumeUnchanged = $false })
    } else { $entries.Add([pscustomobject]@{ Path = $record }) }
  }
  Assert-CrgOperationGitLiteralPaths -Runtime $State.ProjectContext.Runtime -Paths @($entries | ForEach-Object { $_.Path })
  return ,$entries.ToArray()
}

function Get-CrgPairedGitStageInventory {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][ValidateSet('Tracked', 'Untracked', 'Ignored')][string]$Kind,
    [AllowEmptyCollection()][string[]]$Paths = @())
  Assert-CrgOperationGitLiteralPaths -Runtime $ProjectContext.Runtime -Paths $Paths
  if ($Kind -ceq 'Ignored' -and $Paths.Count -eq 0) { throw 'ignored private inventory requires explicit private selectors' }
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $Domain -IndexPath $ProjectContext.Domains[$Domain].IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    $arguments = @('--literal-pathspecs', 'ls-files', '-z')
    if ($Kind -ceq 'Tracked') { $arguments += '--stage' } else { $arguments += '--others'; if ($Kind -ceq 'Untracked') { $arguments += '--exclude-standard' } }
    $batches = [Collections.Generic.List[object]]::new(); $batch = [Collections.Generic.List[string]]::new(); $length = 0
    foreach ($path in $Paths) {
      if ($path.Length -gt 8000) { throw 'staging literal path exceeds the native argument bound' }
      if ($length + $path.Length + 4 -gt 8000) { $batches.Add($batch.ToArray()); $batch.Clear(); $length = 0 }
      $batch.Add($path); $length += $path.Length + 4
    }
    if ($batch.Count -gt 0 -or $batches.Count -eq 0) { $batches.Add($batch.ToArray()) }
    $entries = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $totalBytes = 0
    foreach ($pathsBatch in $batches) {
      $result = Invoke-CrgOperationGitChild -State $state -Arguments ($arguments + @('--') + $pathsBatch) -Maximum 16777216 -TimeoutMilliseconds 120000
      $totalBytes += $result.Bytes.Length
      if ($totalBytes -gt 16777216) { throw 'combined staging inventory exceeds the acquisition bound' }
      foreach ($entry in (Read-CrgOperationGitInventory -State $state -Result $result -Kind $Kind)) {
        if (-not $entries.ContainsKey($entry.Path)) { $entries.Add($entry.Path, $entry) }
      }
    }
    if ($Kind -ceq 'Tracked') {
      $flags = Invoke-CrgOperationGitChild -State $state -Arguments @('--literal-pathspecs', 'ls-files', '-v', '-z') -Maximum 16777216 -TimeoutMilliseconds 120000
      if ($flags.ExitCode -ne 0 -or ($flags.Bytes.Length -gt 0 -and $flags.Bytes[$flags.Bytes.Length - 1] -ne 0)) { throw 'staging cannot acquire index visibility flags' }
      $flagsText = [Text.UTF8Encoding]::new($false, $true).GetString($flags.Bytes)
      $flagged = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
      if ($flagsText.Length -gt 0) {
        foreach ($record in $flagsText.Substring(0, $flagsText.Length - 1).Split([char]0)) {
          if ($record -cnotmatch '\A([HShs]) (.+)\z') { throw 'staging index visibility is unmerged or unsupported' }
          $flag = [string]$Matches[1]; $path = [string]$Matches[2]
          if ($entries.ContainsKey($path)) {
            if (-not $flagged.Add($path)) { throw 'staging index visibility repeats a tracked path' }
            $entries[$path].SkipWorktree = $flag -cin @('S', 's'); $entries[$path].AssumeUnchanged = $flag -cin @('h', 's')
          }
        }
      }
      if ($flagged.Count -ne $entries.Count) { throw 'tracked index inventory changed before visibility acquisition' }
    }
    return [pscustomobject]@{ Domain = $Domain; Kind = $Kind; Value = @($entries.Values | ForEach-Object { $_ }); Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

function Remove-CrgPairedGitIndexPaths {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Paths)
  Assert-CrgOperationGitLiteralPaths -Runtime $ProjectContext.Runtime -Paths $Paths
  if ($Paths.Count -eq 0) { return }
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain $Domain -IndexPath $ProjectContext.Domains[$Domain].IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    foreach ($path in $Paths) {
      $result = Invoke-CrgOperationGitChild -State $state -Arguments @('--literal-pathspecs', 'update-index', '--force-remove', '--', $path)
      if ($result.ExitCode -ne 0 -or $result.Bytes.Length -ne 0) { throw 'index removal failed; inspect both actual indexes before continuing' }
    }
    return [pscustomobject]@{ Domain = $Domain; RemovedPaths = [string[]]$Paths.Clone(); Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

function Set-CrgPairedGitPrivateIndex {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries)
  if ($null -eq $Entries -or $Entries.Count -gt 100000) { throw 'private staging requires a bounded entry array' }
  Assert-CrgOperationGitLiteralPaths -Runtime $ProjectContext.Runtime -Paths @($Entries | ForEach-Object { $_.Path })
  $captured = [Collections.Generic.List[object]]::new(); [long]$total = 0
  foreach ($entry in $Entries) {
    if ($entry.Mode -cnotin @('0', '100644', '100755') -or
        ($entry.Mode -ceq '0' -and $null -ne $entry.Bytes) -or
        ($entry.Mode -cne '0' -and ($entry.Bytes -isnot [byte[]] -or $entry.Bytes.Length -gt 16777216))) { throw 'private staging requires explicit removal or bounded ordinary raw file bytes' }
    $bytes = if ($entry.Mode -ceq '0') { $null } else { ,([byte[]]$entry.Bytes.Clone()) }
    if ($null -ne $bytes) { $total += $bytes.Length }
    if ($total -gt 536870912) { throw 'private staging payload exceeds the combined bound' }
    $captured.Add([pscustomobject]@{ Path = [string]$entry.Path; Mode = [string]$entry.Mode; Bytes = $bytes })
  }
  if ($captured.Count -eq 0) { return }
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain private -IndexPath $ProjectContext.Domains.private.IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    $position = 0
    foreach ($entry in $captured) {
      if ($entry.Mode -ceq '0') {
        $result = Invoke-CrgOperationGitChild -State $state -Arguments @('--literal-pathspecs', 'update-index', '--force-remove', '--', $entry.Path)
      } else {
        $digest = Get-CrgOperationGitDigest -Bytes $entry.Bytes
        $owned = & $state.NativeModule {
          param($State, $Bytes, $Digest, $Leaf)
          New-CrgOwnedBinaryFile -Custody $State.Custody -Parent $State.Directory -Leaf $Leaf -Bytes $Bytes -ExpectedSha256 $Digest
        } $state $entry.Bytes $digest ('blob-' + $position + '.bin')
        $oid = Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $state -Arguments @('hash-object', '-w', '--no-filters', '--', $owned.Path))
        $expected = Get-CrgOperationGitDigest -Bytes $entry.Bytes -ObjectFormat $ProjectContext.Domains.private.ObjectFormat -ObjectKind blob
        if ($oid -cne $expected) { throw 'private raw blob differs from captured working bytes' }
        $result = Invoke-CrgOperationGitChild -State $state -Arguments @('update-index', '--add', '--cacheinfo', $entry.Mode, $oid, $entry.Path)
      }
      if ($result.ExitCode -ne 0 -or $result.Bytes.Length -ne 0) { throw 'private index update failed; inspect both actual indexes before continuing' }
      $position++
    }
    return [pscustomobject]@{ Domain = 'private'; UpdatedPaths = @($captured | ForEach-Object { $_.Path }); Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

function Add-CrgPairedGitPublicPaths {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Paths,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$PrivateExclusions)
  Assert-CrgOperationGitLiteralPaths -Runtime $ProjectContext.Runtime -Paths $Paths
  Assert-CrgOperationGitLiteralPaths -Runtime $ProjectContext.Runtime -Paths $PrivateExclusions
  if ($Paths.Count -eq 0) { return }
  if ($PrivateExclusions.Count -eq 0) { throw 'public staging requires explicit private exclusions' }
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain public -IndexPath $ProjectContext.Domains.public.IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    $specs = @($Paths | ForEach-Object { ':(top,literal)' + $_ }) + @($PrivateExclusions | ForEach-Object { ':(top,literal,exclude)' + $_ })
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($specs -join [char]0) + [char]0)
    if ($bytes.Length -gt 16777216) { throw 'public staging pathspec inventory exceeds its bound' }
    $digest = Get-CrgOperationGitDigest -Bytes $bytes
    $owned = & $state.NativeModule {
      param($State, $Bytes, $Digest)
      New-CrgOwnedBinaryFile -Custody $State.Custody -Parent $State.Directory -Leaf 'public-pathspecs.bin' -Bytes $Bytes -ExpectedSha256 $Digest
    } $state $bytes $digest
    # Git 2.55 otherwise rejects ignored negative pathspecs as explicit ignored
    # requests. Positive paths are already public-eligible, and the complete
    # private exclusions remain authoritative before content/filter acquisition.
    $result = Invoke-CrgOperationGitChild -State $state -Arguments @('add', '--force', '--all', ('--pathspec-from-file=' + $owned.Path), '--pathspec-file-nul') -Maximum 1048576 -TimeoutMilliseconds 600000
    if ($result.ExitCode -ne 0) { throw 'public staging failed; inspect both actual indexes before continuing' }
    return [pscustomobject]@{ Domain = 'public'; UpdatedPaths = [string[]]$Paths.Clone(); DiagnosticBytes = $result.Bytes; Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

function Initialize-CrgPairedPrivateIndex {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock)
  $index = & $ProjectContext.Runtime.ReadFile -Path $ProjectContext.Domains.private.IndexPath -Maximum 67108864 -AllowAbsent
  if ($null -eq $index -or $index.Present -isnot [bool] -or $index.Present) { throw 'private index initialization requires positively absent fixed index; existing staged state must be adopted, not reset' }
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain private -IndexPath $ProjectContext.Domains.private.IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    $parent = $ProjectContext.Domains.private.Parent
    if ((Read-CrgOperationGitRef -State $state) -cne $parent) { throw 'private index initialization parent changed' }
    # The operation lock does not exclude ordinary Git writers. Never let
    # read-tree replace the fixed index after a non-reserving absence read.
    # Same-filesystem scratch permits a final atomic no-replace publication,
    # including when the private object database occupies a different volume.
    $scratch = & $state.NativeModule {
      param($State)
      $parent = Enter-CrgAttributeNeutralDirectoryChain -Path $State.ProjectContext.Domains.public.GitDir -Pins $State.Custody.DirectoryPins -DenyLeafRename
      $leaf = '.crg-index-initialize-' + [guid]::NewGuid().ToString('N')
      $directory = New-CrgAttributeNeutralOwnedDirectory -Custody $State.Custody -Parent $parent -Leaf $leaf -Path (Join-Path $parent.Path $leaf) -Label 'private index initialization scratch'
      return [pscustomobject]@{ Parent = $parent; Directory = $directory; IndexPath = (Join-Path $directory.Path 'index') }
    } $state
    $state.EnvironmentEntries = @($state.EnvironmentEntries | Where-Object { -not $_.StartsWith('GIT_INDEX_FILE=', [StringComparison]::OrdinalIgnoreCase) }) +
      @(('GIT_INDEX_FILE=' + $scratch.IndexPath), 'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=core.splitIndex', 'GIT_CONFIG_VALUE_0=false')
    # The new movable index must be self-contained, not a split/sparse view
    # whose backing path changes when the index reaches the fixed destination.
    $arguments = @('read-tree', '--no-sparse-checkout') + $(if ($parent -ceq 'absent') { @('--empty') } else { @($parent) })
    $result = Invoke-CrgOperationGitChild -State $state -Arguments $arguments
    if ($result.ExitCode -ne 0 -or $result.Bytes.Length -ne 0) { throw 'private index initialization failed; preserve and inspect the partial attachment' }
    & $state.NativeModule {
      param($State, $Scratch)
      $errorCode = 0
      $handle = [CrgAttributeNeutral.NativeV1]::OpenPublicationFileRelative($Scratch.Directory.Handle, 'index', [ref]$errorCode)
      if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) {
        if ($null -ne $handle) { $handle.Dispose() }
        throw "initialized temporary index lacks ordinary publication custody (Win32 error $errorCode)"
      }
      $record = [pscustomobject]@{ Path = $Scratch.IndexPath; Handle = $handle; Label = 'initialized temporary private index' }
      $State.Custody.ControlFiles.Add($record)
      $actual = Get-CrgOwnedBinaryFileDigest -Record $record
      if ($actual.Length -lt 32 -or $actual.Length -gt 67108864) { throw 'initialized temporary index exceeds the fixed-index byte bound' }
      Assert-CrgPairedOperationLock -Lock $State.OperationLock
      $custody = @{ DirectoryPins = $State.Custody.DirectoryPins.ToArray(); OwnedDirectories = $State.Custody.OwnedDirectories.ToArray(); ControlFiles = $State.Custody.ControlFiles.ToArray() }
      Assert-CrgAttributeNeutralContextStable -Context @{ Custody = $custody } -Boundary 'private index initialization publication'
      if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($handle, $Scratch.Parent.Handle, 'crg-private-index', [ref]$errorCode)) {
        throw "private index no-replace publication failed (Win32 error $errorCode); any concurrent fixed index remains preserved"
      }
      # The published file is permanent staged state, never scratch cleanup.
      $null = $State.Custody.ControlFiles.Remove($record)
      try {
        if (-not [CrgAttributeNeutral.NativeV1]::PathNamesExactHandle($State.ProjectContext.Domains.private.IndexPath, $handle, $false, [ref]$errorCode)) { throw 'initialized fixed index lost exact publication identity' }
        $published = Get-CrgOwnedBinaryFileDigest -Record $record
        if ($published.Length -ne $actual.Length -or $published.Sha256 -cne $actual.Sha256) { throw 'initialized fixed index differs from the held temporary bytes' }
      } finally { $handle.Dispose() }
    } $state $scratch
    return [pscustomobject]@{ IndexPath = $ProjectContext.Domains.private.IndexPath; Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

Export-ModuleMember -Function Get-CrgPairedGitStageInventory, Remove-CrgPairedGitIndexPaths, Set-CrgPairedGitPrivateIndex, Add-CrgPairedGitPublicPaths, Initialize-CrgPairedPrivateIndex

function Initialize-CrgPairedPrivateDatabase {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][object]$OwnedDirectory, [Parameter(Mandatory = $true)][byte[]]$AttachmentBytes)
  $domain = $ProjectContext.Domains.private
  if ($domain.Parent -cne 'absent' -or $OwnedDirectory.Path -cne $domain.GitDir -or $domain.GitDir -cne $domain.CommonDir -or
      $domain.ObjectFormat -cne $ProjectContext.Domains.public.ObjectFormat) { throw 'private database initialization requires the proposed absent same-format domain' }
  $runtime = $ProjectContext.Runtime
  $assertLock = Get-CrgOperationGitCommand -Runtime $runtime -Module paired-diff -Name Assert-CrgPairedOperationLock
  $readAttachment = Get-CrgOperationGitCommand -Runtime $runtime -Module private-governance -Name Read-CrgAttachmentBytes
  $capture = Get-CrgOperationGitCommand -Runtime $runtime -Module central-context -Name Read-CrgCentralTreeBytes
  & $assertLock -Lock $OperationLock
  if ($OperationLock.PublicGitDirectory -cne $ProjectContext.Domains.public.GitDir) { throw 'private initialization requires the actual public operation lock' }
  $attachment = & $readAttachment -Bytes $AttachmentBytes
  if ($attachment.PrivateGitDir -cne $domain.GitDir -or $attachment.PrivateRef -cne $domain.Ref -or
      $attachment.PublicRef -cne $ProjectContext.Domains.public.Ref -or $attachment.RuntimeStore -cne $runtime.Store -or
      $domain.Ref -cne ('refs/heads/crg-' + $attachment.ProjectId) -or $domain.ObjectFormat -cnotin @('sha1', 'sha256')) { throw 'private initialization differs from the new-database proposal' }
  $expectedText = @('crg-private-initialization v1', ('attachment-sha256 ' + (Get-CrgOperationGitDigest -Bytes $AttachmentBytes)),
    ('public-git-dir ' + $ProjectContext.Domains.public.GitDir), ('object-format ' + $domain.ObjectFormat)) -join "`n"
  $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($expectedText + "`n")
  foreach ($item in @(@{ Leaf = 'crg-attachment-pending'; Bytes = $AttachmentBytes }, @{ Leaf = 'crg-attachment-initialization'; Bytes = $expectedBytes })) {
    $record = & $runtime.ReadFile -Path (Join-Path $OperationLock.PublicGitDirectory $item.Leaf) -Maximum 65536
    if ($record.Bytes -isnot [byte[]] -or (Get-CrgOperationGitDigest -Bytes $record.Bytes) -cne (Get-CrgOperationGitDigest -Bytes $item.Bytes)) { throw 'private initialization requires exact durable proposal and initialization records' }
  }
  $completed = & $runtime.ReadFile -Path (Join-Path $OperationLock.PublicGitDirectory 'crg-attachment-initialized') -Maximum 65536 -AllowAbsent
  if ($completed.Present) { throw 'completed private initialization must use ordinary database admission, never initialization' }
  $config = "[core]`n`trepositoryformatversion = " + $(if ($domain.ObjectFormat -ceq 'sha1') { '0' } else { '1' }) + "`n`tfilemode = false`n`tbare = true`n"
  if ($domain.ObjectFormat -ceq 'sha256') { $config += "[extensions]`n`tobjectformat = sha256`n" }
  $texts = @{ HEAD = ('ref: ' + $domain.Ref + "`n"); config = $config }
  # git init rewrites metadata through intermediate states. A recorded new
  # database instead grows monotonically from absent/exact layout components;
  # adoption never gains permission to rewrite a config, ref or object store.
  & $assertLock.Module {
    param($Project, $Lock, $Owner, $Texts, $Capture)
    Initialize-CrgAttributeNeutralNative
    $pins = New-Object 'System.Collections.Generic.List[object]'
    $directories = [ordered]@{ '' = $null; 'objects' = $null; 'objects\info' = $null; 'objects\pack' = $null; 'refs' = $null; 'refs\heads' = $null; 'refs\tags' = $null }
    $present = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    try {
      $root = Enter-CrgAttributeNeutralDirectoryChain -Path $Owner.Path -Pins $pins -DenyLeafRename
      if ($Owner.Handle -isnot [Microsoft.Win32.SafeHandles.SafeFileHandle] -or $Owner.Handle.IsClosed -or $Owner.Handle.IsInvalid -or
          -not [CrgAttributeNeutral.NativeV1]::SameIdentity($root.Handle, $Owner.Handle)) { throw 'private initialization lost its retained ordinary directory identity' }
      $directories[''] = $root
      foreach ($relative in @($directories.Keys)) {
        $directory = $directories[$relative]
        if ($null -eq $directory) { continue }
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory.Path)) {
          $leaf = [IO.Path]::GetFileName($path)
          $child = if ($relative.Length -eq 0) { $leaf } else { $relative + '\' + $leaf }
          if ($child -cin @($directories.Keys)) {
            $directories[$child] = Enter-CrgAttributeNeutralDirectoryChain -Path $path -Pins $pins -DenyLeafRename
            continue
          }
          $scratch = $relative.Length -eq 0 -and $leaf -cmatch '\A\.crg-initialize-(HEAD|config)-[0-9a-f]{32}\z'
          $target = if ($scratch) { $Matches[1] } else { $leaf }
          if ($relative.Length -ne 0 -or $target -cnotin @($Texts.Keys)) { throw 'private initialization contains foreign layout data; no existing file or directory is removed' }
          $expected = [Text.UTF8Encoding]::new($false).GetBytes($Texts[$target])
          $file = & $Project.Runtime.ReadFile -Path $path -Maximum $expected.Length
          $actual = [Text.UTF8Encoding]::new($false, $true).GetString($file.Bytes)
          if (($scratch -and -not $Texts[$target].StartsWith($actual, [StringComparison]::Ordinal)) -or
              (-not $scratch -and $actual -cne $Texts[$target])) { throw 'private initialization metadata differs from the exact proposed layout; existing bytes remain preserved' }
          if (-not $scratch) { $null = $present.Add($target) }
        }
      }
      foreach ($relative in @($directories.Keys)) {
        if ($null -ne $directories[$relative]) { continue }
        $parentName = [IO.Path]::GetDirectoryName($relative)
        if ($null -eq $parentName) { $parentName = '' }
        $parent = $directories[$parentName]; $errorCode = 0
        $handle = [CrgAttributeNeutral.NativeV1]::CreatePersistentDirectoryRelative($parent.Handle, [IO.Path]::GetFileName($relative), [ref]$errorCode)
        if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinaryDirectory($handle)) {
          if ($null -ne $handle) { $handle.Dispose() }
          throw "private initialization create-new directory failed (Win32 error $errorCode); retry the recorded proposal"
        }
        $record = [pscustomobject]@{ Path = (Join-Path $root.Path $relative); Handle = $handle; DeniesRename = $true; Label = 'private initialization directory' }
        $pins.Add($record); $directories[$relative] = $record
      }
      foreach ($leaf in @('config', 'HEAD')) {
        if ($present.Contains($leaf)) { continue }
        $handle = $null; $published = $false; $errorCode = 0
        try {
          $scratchLeaf = '.crg-initialize-' + $leaf + '-' + [guid]::NewGuid().ToString('N')
          $handle = [CrgAttributeNeutral.NativeV1]::CreatePublicationFileRelative($root.Handle, $scratchLeaf, [ref]$errorCode)
          if ($null -eq $handle -or $handle.IsInvalid -or -not [CrgAttributeNeutral.NativeV1]::IsOrdinarySingleLinkFile($handle)) { throw "private initialization metadata creation failed (Win32 error $errorCode)" }
          if (-not [CrgAttributeNeutral.NativeV1]::WriteUtf8Exact($handle, $Texts[$leaf], [ref]$errorCode)) { throw "private initialization durable metadata write failed (Win32 error $errorCode)" }
          if (-not [CrgAttributeNeutral.NativeV1]::RenamePublicationFileRelative($handle, $root.Handle, $leaf, [ref]$errorCode)) { throw "private initialization no-replace publication failed (Win32 error $errorCode)" }
          $published = $true
        } finally {
          if ($null -ne $handle) {
            if (-not $published -and -not $handle.IsInvalid) { $null = [CrgAttributeNeutral.NativeV1]::DeleteHeldExact($handle, $false, [ref]$errorCode) }
            $handle.Dispose()
          }
        }
        $file = & $Project.Runtime.ReadFile -Path (Join-Path $root.Path $leaf) -Maximum 16384
        if ([Text.UTF8Encoding]::new($false, $true).GetString($file.Bytes) -cne $Texts[$leaf]) { throw 'initialized metadata failed exact retained readback' }
      }
      Assert-CrgPairedOperationLock -Lock $Lock
      # The existing read-only capture route creates no private operation
      # scratch between layout completion and the durable completion record.
      & $Capture.Module {
        param($Project)
        $domain = $Project.Domains.private
        $prefix = @("--git-dir=$($domain.GitDir)", "--work-tree=$($Project.Root)")
        foreach ($probe in @(
          @{ Args = @('rev-parse', '--path-format=absolute', '--git-common-dir'); Expected = $domain.CommonDir; Path = $true },
          @{ Args = @('rev-parse', '--path-format=absolute', '--git-path', 'objects'); Expected = $domain.ObjectDir; Path = $true },
          @{ Args = @('rev-parse', '--show-object-format'); Expected = $domain.ObjectFormat; Path = $false },
          @{ Args = @('symbolic-ref', '--no-recurse', '-q', 'HEAD'); Expected = $domain.Ref; Path = $false }
        )) {
          $line = Get-CrgStatusGitLine -Arguments ($prefix + $probe.Args) -GitExe $Project.GitExe
          if ($probe.Path) { $line = $line.Replace('/', '\') }
          if ($line -cne $probe.Expected) { throw 'initialized private namespace differs from the recorded proposal' }
        }
        $refs = Invoke-CrgStatusGit -Arguments ($prefix + @('for-each-ref', '--count=1', '--format=%(refname)')) -GitExe $Project.GitExe -Maximum 16384
        if ($refs.Length -ne 0) { throw 'new private initialization contains an existing ref' }
      } $Project
      Assert-CrgPairedOperationLock -Lock $Lock
    } finally { for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Handle.Dispose() } }
  } $ProjectContext $OperationLock $OwnedDirectory $texts $capture
  return [pscustomobject]@{ GitDir = $domain.GitDir; ReadyForPublication = $false }
}

function Write-CrgPairedPrivateEmptyTree {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock)
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain private -IndexPath $ProjectContext.Domains.private.IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    $bytes = [byte[]]@(); $digest = Get-CrgOperationGitDigest -Bytes $bytes
    $owned = & $state.NativeModule {
      param($State, $Bytes, $Digest)
      New-CrgOwnedBinaryFile -Custody $State.Custody -Parent $State.Directory -Leaf 'empty-tree.bin' -Bytes $Bytes -ExpectedSha256 $Digest
    } $state $bytes $digest
    $oid = Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $state -Arguments @('hash-object', '-w', '-t', 'tree', '--no-filters', '--', $owned.Path))
    if ($oid -cne (Get-CrgOperationGitDigest -Bytes $bytes -ObjectFormat $ProjectContext.Domains.private.ObjectFormat -ObjectKind tree)) { throw 'private empty tree has an unexpected object identity' }
    return [pscustomobject]@{ Oid = $oid; Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

Export-ModuleMember -Function Initialize-CrgPairedPrivateDatabase, Write-CrgPairedPrivateEmptyTree

function Get-CrgPairedGitOutgoingCommits {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][string]$TipOid, [Parameter(Mandatory = $true)][string]$BoundaryOid)
  $format = $ProjectContext.Domains.public.ObjectFormat
  Assert-CrgOperationGitOid -Oid $TipOid -ObjectFormat $format
  Assert-CrgOperationGitOid -Oid $BoundaryOid -ObjectFormat $format
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain public -IndexPath $ProjectContext.Domains.public.IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    foreach ($directory in @($ProjectContext.Domains.public.GitDir, $ProjectContext.Domains.public.CommonDir)) {
      foreach ($leaf in @('shallow', 'info/grafts')) {
        $record = & $ProjectContext.Runtime.ReadFile -Path (Join-Path $directory $leaf) -Maximum 65536 -AllowAbsent
        if ($null -eq $record -or $record.Present -isnot [bool] -or $record.Present) { throw 'outgoing commit enumeration requires complete ungrafted history' }
      }
    }
    # Absence alone cannot keep a later graft/shallow insertion out of rev-list.
    # Bind this owned enumeration to immutable empty history controls instead.
    $emptyDigest = Get-CrgOperationGitDigest -Bytes ([byte[]]@())
    $historyControl = & $state.NativeModule {
      param($State, $Digest)
      New-CrgOwnedBinaryFile -Custody $State.Custody -Parent $State.Directory -Leaf 'history-control' -Bytes ([byte[]]@()) -ExpectedSha256 $Digest
    } $state $emptyDigest
    $state.EnvironmentEntries += @(('GIT_GRAFT_FILE=' + $historyControl.Path), ('GIT_SHALLOW_FILE=' + $historyControl.Path))
    $tip = Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $state -Arguments @('rev-parse', '--verify', '--end-of-options', ($TipOid + '^{commit}')))
    Assert-CrgOperationGitOid -Oid $tip -ObjectFormat $format
    $null = Read-CrgOperationGitCommit -State $state -Oid $tip
    $null = Read-CrgOperationGitCommit -State $state -Oid $BoundaryOid
    $result = Invoke-CrgOperationGitChild -State $state -Arguments @('rev-list', '--topo-order', '--end-of-options', $tip, ('^' + $BoundaryOid)) -Maximum 16777216 -TimeoutMilliseconds 120000
    $actualControl = & $state.NativeModule { param($Record) Get-CrgOwnedBinaryFileDigest -Record $Record } $historyControl
    if ($actualControl.Length -ne 0 -or $actualControl.Sha256 -cne $emptyDigest) { throw 'outgoing history control differs from the retained empty bytes' }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($result.Bytes)
    if ($result.ExitCode -ne 0 -or ($text.Length -gt 0 -and -not $text.EndsWith("`n", [StringComparison]::Ordinal))) { throw 'outgoing commit enumeration failed or returned incomplete output' }
    $oids = [Collections.Generic.List[string]]::new(); $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($text.Length -gt 0) {
      foreach ($oid in $text.Substring(0, $text.Length - 1).Split([char]10)) {
        Assert-CrgOperationGitOid -Oid $oid -ObjectFormat $format
        if (-not $seen.Add($oid)) { throw 'outgoing commit enumeration contains a duplicate object' }
        $oids.Add($oid)
      }
    }
    return [pscustomobject]@{ Value = [pscustomobject]@{ TipCommitOid = $tip; CommitOids = $oids.ToArray() }; Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

Export-ModuleMember -Function Get-CrgPairedGitOutgoingCommits

function Open-CrgOperationGitLfsExecutable {
  param([object]$State)
  Assert-CrgOperationGitState -State $State
  if ($State.Domain -cne 'public' -or $null -ne $State.LfsExecutable) { throw 'Git LFS executable acquisition requires one public operation owner' }
  $execPath = (Get-CrgOperationGitLine -Result (Invoke-CrgOperationGitChild -State $State -Arguments @('--exec-path'))).Replace('/', '\')
  & $State.Commands['Read-CrgAttachmentBytes'].Module { param($Path) Assert-CrgGovernancePath -Path $Path -Absolute } $execPath
  if ($execPath -inotmatch '\\libexec\\git-core\z') { throw 'Git LFS requires the supported Git-for-Windows executable layout' }
  # The PATH cmd/git-lfs.exe on Git for Windows is a forwarding shim. Retain
  # and launch the actual adjacent distribution binary, not only that shim.
  $lfsPath = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($execPath))) 'bin\git-lfs.exe'
  $State.LfsExecutableCommands = @{}
  foreach ($entry in @(@('Open', 'Open-CrgPairedExecutableRead'), @('Assert', 'Assert-CrgPairedExecutableRead'), @('Close', 'Close-CrgPairedExecutableRead'))) {
    $State.LfsExecutableCommands[$entry[0]] = Get-CrgOperationGitCommand -Runtime $State.ProjectContext.Runtime -Module paired-operation -Name $entry[1]
  }
  $State.LfsExecutable = & $State.LfsExecutableCommands.Open -Path $lfsPath -Maximum 67108864
  Assert-CrgOperationGitState -State $State
}

function Invoke-CrgPairedGitLfsPrePush {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][string]$RemoteName, [Parameter(Mandatory = $true)][string]$RemoteLocation,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$InputBytes)
  foreach ($argument in @($RemoteName, $RemoteLocation)) {
    if ([string]::IsNullOrWhiteSpace($argument) -or $argument.Length -gt 16384 -or $argument -match '[\x00-\x1f\x7f]') { throw 'Git LFS pre-push requires bounded native remote arguments' }
  }
  if ($null -eq $InputBytes -or $InputBytes.Length -gt 1048576) { throw 'Git LFS pre-push input exceeds the captured native-input bound' }
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain public -IndexPath $ProjectContext.Domains.public.IndexPath
  try {
    Assert-CrgOperationGitNamespace -State $state
    Open-CrgOperationGitLfsExecutable -State $state
    $digest = Get-CrgOperationGitDigest -Bytes $InputBytes
    $state.InputRecord = & $state.NativeModule {
      param($State, $Bytes, $Digest)
      New-CrgOwnedBinaryFile -Custody $State.Custody -Parent $State.Directory -Leaf 'lfs-pre-push.stdin' -Bytes $Bytes -ExpectedSha256 $Digest
    } $state $InputBytes $digest
    $added = $false; $state.InputRecord.Handle.DangerousAddRef([ref]$added); $state.InputAddedRef = $added
    $state.InputHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($state.InputRecord.Handle.DangerousGetHandle(), $false)
    $state.InputStream = [IO.FileStream]::new($state.InputHandle, [IO.FileAccess]::Read, 8192, $false)
    $state.InputStream.Position = 0
    $result = Invoke-CrgOperationGitChild -State $state -Arguments @('pre-push', '--', $RemoteName, $RemoteLocation) -Maximum 16777216 -LfsPrePush
    if ($result.ExitCode -ne 0) { throw "Git LFS pre-push failed with exit code $($result.ExitCode); public push is refused" }
    $actual = & $state.NativeModule { param($Record) Get-CrgOwnedBinaryFileDigest -Record $Record } $state.InputRecord
    if ($actual.Length -ne $InputBytes.Length -or $actual.Sha256 -cne $digest -or (Get-CrgOperationGitDigest -Bytes $InputBytes) -cne $digest) { throw 'Git LFS pre-push input differs from the validated captured bytes' }
    Assert-CrgOperationGitNamespace -State $state
    Write-Host '[paired-push] Git LFS pre-push completed.'
    return [pscustomobject]@{ ExitCode = $result.ExitCode; Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

function Invoke-CrgPairedGitLfsPostCommit {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext, [Parameter(Mandatory = $true)][object]$OperationLock,
    [Parameter(Mandatory = $true)][string]$ExpectedPublicOid)
  $state = Open-CrgOperationGitState -ProjectContext $ProjectContext -OperationLock $OperationLock -Domain public -IndexPath $ProjectContext.Domains.public.IndexPath
  try {
    Assert-CrgOperationGitOid -Oid $ExpectedPublicOid -ObjectFormat $ProjectContext.Domains.public.ObjectFormat
    Assert-CrgOperationGitNamespace -State $state
    if ((Read-CrgOperationGitRef -State $state) -cne $ExpectedPublicOid) { throw 'Git LFS post-commit requires the exact reviewed public result at HEAD' }
    $null = Read-CrgOperationGitCommit -State $state -Oid $ExpectedPublicOid
    Open-CrgOperationGitLfsExecutable -State $state
    $result = Invoke-CrgOperationGitChild -State $state -Arguments @('post-commit') -Maximum 16777216 -LfsPostCommit
    if ($result.ExitCode -ne 0) { throw "Git LFS post-commit failed with exit code $($result.ExitCode); paired publication remains incomplete" }
    if ((Read-CrgOperationGitRef -State $state) -cne $ExpectedPublicOid) { throw 'public branch changed during Git LFS post-commit' }
    Assert-CrgOperationGitNamespace -State $state
    Write-Host '[paired-publication] Git LFS post-commit completed.'
    return [pscustomobject]@{ ExitCode = $result.ExitCode; Checks = $state.Observations.ToArray(); ReadyForPublication = $false }
  } catch { $_.Exception.Data['CrgPairedGitObservations'] = $state.Observations.ToArray(); throw }
  finally { Close-CrgOperationGitState -State $state }
}

Export-ModuleMember -Function Invoke-CrgPairedGitLfsPrePush, Invoke-CrgPairedGitLfsPostCommit
