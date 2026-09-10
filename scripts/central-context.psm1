# Release-local status and paired Git capture, never paired review authority.
function Invoke-CrgStatusGit {
  param([string[]]$Arguments, [int]$Maximum = 65536, [string]$GitExe, [string]$IndexPath, [string]$HistoryControlPath,
    [AllowNull()][AllowEmptyCollection()][byte[]]$InputBytes)
  $git = $GitExe
  if ([string]::IsNullOrEmpty($git)) { $git = @(Get-Command git.exe -CommandType Application -ErrorAction Stop)[0].Source }
  $quoted = foreach ($argument in $Arguments) {
    if ($null -eq $argument -or $argument.Contains([char]0)) { throw 'status Git argument is invalid' }
    $escaped = [regex]::Replace($argument, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    '"' + $escaped + '"'
  }
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $git; $start.Arguments = (@('--no-pager') + @($quoted)) -join ' '
  $start.UseShellExecute = $false; $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
  $start.RedirectStandardInput = $null -ne $InputBytes
  foreach ($name in @($start.EnvironmentVariables.Keys)) {
    if ($name -imatch '^GIT_') { $start.EnvironmentVariables.Remove($name) }
  }
  $start.EnvironmentVariables['GIT_NO_REPLACE_OBJECTS'] = '1'
  $start.EnvironmentVariables['GIT_NO_LAZY_FETCH'] = '1'
  $start.EnvironmentVariables['GIT_CONFIG_NOSYSTEM'] = '1'
  $start.EnvironmentVariables['GIT_CONFIG_SYSTEM'] = 'NUL'
  $start.EnvironmentVariables['GIT_CONFIG_GLOBAL'] = 'NUL'
  $start.EnvironmentVariables['GIT_OPTIONAL_LOCKS'] = '0'
  if (-not [string]::IsNullOrEmpty($IndexPath)) {
    Assert-CrgContextAbsolutePath -Path $IndexPath
    $start.EnvironmentVariables['GIT_INDEX_FILE'] = $IndexPath
  }
  if (-not [string]::IsNullOrEmpty($HistoryControlPath)) {
    Assert-CrgContextAbsolutePath -Path $HistoryControlPath
    $start.EnvironmentVariables['GIT_GRAFT_FILE'] = $HistoryControlPath
    $start.EnvironmentVariables['GIT_SHALLOW_FILE'] = $HistoryControlPath
  }
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $start
  $output = New-Object IO.MemoryStream
  $started = $false
  try {
    # Framework constructs an auto-flushing stdin writer before BaseStream is
    # available. Reuse bootstrap's no-preamble construction and restore rule.
    $priorInputEncoding = $null
    if ($null -ne $InputBytes -and $null -eq $start.PSObject.Properties['StandardInputEncoding']) {
      $priorInputEncoding = [Console]::InputEncoding
      [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    } elseif ($null -ne $InputBytes) { $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false) }
    try { $started = $process.Start() }
    finally { if ($null -ne $priorInputEncoding) { [Console]::InputEncoding = $priorInputEncoding } }
    if (-not $started) { throw 'status Git launch failed' }
    $copy = $process.StandardOutput.BaseStream.CopyToAsync($output)
    $errorRead = $process.StandardError.ReadToEndAsync()
    if ($null -ne $InputBytes) {
      try { $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length) }
      finally { $process.StandardInput.Close() }
    }
    if (-not $process.WaitForExit(10000)) {
      $process.Kill()
      if (-not $process.WaitForExit(2000)) { throw 'status Git timeout; root exit could not be confirmed' }
      throw 'status Git command timed out'
    }
    $null = $copy.GetAwaiter().GetResult(); $errorText = $errorRead.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "status Git failed ($($process.ExitCode)): $errorText" }
    if ($output.Length -gt $Maximum) { throw 'status Git output exceeds the requested bound' }
    return ,([byte[]]$output.ToArray())
  } finally {
    try {
      if ($started -and -not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(2000)) { throw 'status Git cleanup could not confirm root exit' }
      }
    } finally { $output.Dispose(); $process.Dispose() }
  }
}

function Get-CrgStatusGitLine {
  param([string[]]$Arguments, [string]$GitExe, [string]$IndexPath)
  $bytes = Invoke-CrgStatusGit -Arguments $Arguments -Maximum 16384 -GitExe $GitExe -IndexPath $IndexPath
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
  if ($text -cnotmatch '\A[^\r\n]+\r?\n?\z') { throw 'status Git returned other than one complete line' }
  return $text.TrimEnd([char[]]@(13, 10))
}

function Get-CrgStatusBlob {
  param([string[]]$Git, [string]$Commit, [string]$Path, [int]$Maximum, [string]$GitExe)
  $row = Get-CrgStatusGitLine -Arguments (@($Git) + @('ls-tree', '--full-tree', $Commit, '--', $Path)) -GitExe $GitExe
  if ($row -cnotmatch ('\A(100644|100755) blob (?<o>[0-9a-f]{40}|[0-9a-f]{64})\t' + [regex]::Escape($Path) + '\z')) { throw "status document '$Path' is not a regular Git blob" }
  $oid = $Matches['o']
  $size = Get-CrgStatusGitLine -Arguments (@($Git) + @('cat-file', '-s', $oid)) -GitExe $GitExe
  if ($size -cnotmatch '\A(0|[1-9][0-9]{0,7})\z' -or [int]$size -gt $Maximum) { throw "status document '$Path' is oversized" }
  $bytes = Invoke-CrgStatusGit -Arguments (@($Git) + @('cat-file', 'blob', $oid)) -Maximum $Maximum -GitExe $GitExe
  if ($bytes.Length -ne [int]$size) { throw 'status blob length differs from its object header' }
  $hash = if ($oid.Length -eq 40) { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
  try {
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)" + [char]0)
    $null = $hash.TransformBlock($header, 0, $header.Length, $header, 0)
    $null = $hash.TransformFinalBlock($bytes, 0, $bytes.Length)
    if (([BitConverter]::ToString($hash.Hash) -replace '-', '').ToLowerInvariant() -cne $oid) { throw 'status blob failed independent Git object verification' }
  } finally { $hash.Dispose() }
  return ,([byte[]]$bytes)
}

function Get-CrgCentralProjectStatus {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo, [Parameter(Mandatory = $true)][object]$Context, [string]$GitExe)
  if ($null -eq $Context -or $Context.ReadFile -isnot [scriptblock] -or $Context.Id -cnotmatch '\A[0-9a-f]{64}\z') { throw 'status requires the live launcher context' }
  if ($TargetRepo -cnotmatch '\A[A-Za-z]:\\' -or $TargetRepo.Contains('/')) { throw 'TargetRepo must be a canonical absolute local worktree root' }
  $root = [IO.Path]::GetFullPath($TargetRepo)
  $publicGit = @('-C', $root)
  $actualRoot = (Get-CrgStatusGitLine -Arguments ($publicGit + @('rev-parse', '--show-toplevel')) -GitExe $GitExe).Replace('/', '\')
  if (-not [string]::Equals($actualRoot, $root, [StringComparison]::OrdinalIgnoreCase)) { throw 'TargetRepo is not the actual public worktree root' }
  $gitDir = (Get-CrgStatusGitLine -Arguments ($publicGit + @('rev-parse', '--absolute-git-dir')) -GitExe $GitExe).Replace('/', '\')
  $commonDir = (Get-CrgStatusGitLine -Arguments ($publicGit + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $GitExe).Replace('/', '\')
  $attachmentFile = & $Context.ReadFile -Path (Join-Path $gitDir 'crg-attachment') -Maximum 16384 -AllowAbsent
  $result = [ordered]@{
    RuntimeStore = $Context.Store; RuntimeRelease = $Context.Id; RuntimeVersion = $Context.Manifest.Version
    PublicRoot = $root; PublicGitDir = $gitDir; PublicCommonDir = $commonDir
    Attachment = 'absent'; Enforcement = 'unattached; no central governance admission'
  }
  if (-not $attachmentFile.Present) { return [pscustomobject]$result }
  $attachment = Read-CrgAttachmentBytes -Bytes $attachmentFile.Bytes
  Assert-CrgPrivateStorageLocation -PublicRoot $root -PublicGitDir $gitDir -PublicCommonDir $commonDir -PrivateGitDir $attachment.PrivateGitDir
  if (-not [string]::Equals($attachment.RuntimeStore, $Context.Store, [StringComparison]::OrdinalIgnoreCase)) { throw 'attachment selects another central store' }
  $publicRef = Get-CrgStatusGitLine -Arguments ($publicGit + @('symbolic-ref', '-q', 'HEAD')) -GitExe $GitExe
  if ($publicRef -cne $attachment.PublicRef) { throw 'public branch differs from the recorded private association' }
  $privateGit = @('-C', $root, "--git-dir=$($attachment.PrivateGitDir)", "--work-tree=$root")
  $privateCommon = (Get-CrgStatusGitLine -Arguments ($privateGit + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $GitExe).Replace('/', '\')
  if (-not [string]::Equals($privateCommon, $attachment.PrivateGitDir, [StringComparison]::OrdinalIgnoreCase) -or
      [string]::Equals($privateCommon, $commonDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'attachment must select a distinct private Git database root' }
  foreach ($database in @($commonDir, $privateCommon)) {
    $alternates = & $Context.ReadFile -Path (Join-Path $database 'objects\info\alternates') -Maximum 16384 -AllowAbsent
    if ($alternates.Present -and $alternates.Bytes.Length -gt 0) { throw 'public/private object alternates are unsupported' }
  }
  $publicCommit = Get-CrgStatusGitLine -Arguments ($publicGit + @('rev-parse', '--verify', "$publicRef^{commit}")) -GitExe $GitExe
  $privateCommit = Get-CrgStatusGitLine -Arguments ($privateGit + @('rev-parse', '--verify', "$($attachment.PrivateRef)^{commit}")) -GitExe $GitExe
  if ($publicCommit -cnotmatch '\A([0-9a-f]{40}|[0-9a-f]{64})\z' -or $privateCommit -cnotmatch '\A([0-9a-f]{40}|[0-9a-f]{64})\z') { throw 'status commit identity is malformed' }
  $configBytes = Get-CrgStatusBlob -Git $privateGit -Commit $privateCommit -Path '.crg-project/project.conf' -Maximum 65536 -GitExe $GitExe
  $config = Read-CrgProjectConfigBytes -Bytes $configBytes
  $pending = & $Context.ReadFile -Path (Join-Path $gitDir 'crg-handoff') -Maximum 65536 -AllowAbsent
  $pair = & $Context.ReadFile -Path (Join-Path $gitDir 'crg-pair') -Maximum 65536 -AllowAbsent
  $discovery = foreach ($path in @('AGENTS.md', 'CLAUDE.md')) {
    $file = & $Context.ReadFile -Path (Join-Path $root $path) -Maximum 16777216 -AllowAbsent
    [pscustomobject]@{ Path = $path; Present = $file.Present }
  }
  $result.Attachment = 'validated association; inspection only'
  $result.ProjectId = $attachment.ProjectId
  $result.PublicRef = $publicRef; $result.PublicCommit = $publicCommit
  $result.PrivateGitDir = $privateCommon; $result.PrivateRef = $attachment.PrivateRef; $result.PrivateCommit = $privateCommit
  $result.Configuration = $config; $result.ConfigurationSource = ('{0}:.crg-project/project.conf' -f $privateCommit)
  $result.GoverningState = 'not established by status; private HEAD is not approval'
  $result.PendingHandoff = $pending.Present; $result.CompletedPairRecord = $pair.Present
  $result.Enforcement = if ($pending.Present) { 'pending publication; Resume required' } else { 'metadata inspected; Open validates completed-pair admission' }
  $result.DiscoveryFiles = @($discovery)
  return [pscustomobject]$result
}

function Invoke-CrgCentralOperation {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo,
    [Parameter(Mandatory = $true)][object]$Operation,
    [Parameter(Mandatory = $true)][object]$Context)
  if ($null -eq $Operation -or $Operation.Name -cnotin @('Open', 'Status', 'Stage', 'Commit', 'Resume', 'Attach', 'PushCheck')) { throw 'central operation is invalid' }
  if ($Operation.Name -ceq 'Status') { return Get-CrgCentralProjectStatus -TargetRepo $TargetRepo -Context $Context }
  if ($Operation.Name -ceq 'Resume' -and $null -eq $Context.PSObject.Properties['ResumeHandoffSha256']) {
    # Select the recorded approved release before importing any live native
    # operation module. A current central activation must not mix generations
    # with the retained transaction's compiler, reviewer hosts or cleanup owners.
    $prefix = @('-C', $TargetRepo)
    $actualRoot = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--show-toplevel'))).Replace('/', '\')
    if (-not [string]::Equals($actualRoot, $TargetRepo, [StringComparison]::OrdinalIgnoreCase)) { throw 'Resume target is not the actual public worktree root' }
    $gitDir = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--absolute-git-dir'))).Replace('/', '\')
    Assert-CrgContextAbsolutePath -Path $gitDir
    $pending = & $Context.ReadFile -Path (Join-Path $gitDir 'crg-handoff') -Maximum 16384
    try {
      $text = [Text.UTF8Encoding]::new($false, $true).GetString($pending.Bytes)
      $identities = [regex]::Matches($text, '(?m)^runtime-manifest-sha256 ([0-9a-f]{64})$')
      if ($text -cnotmatch '\Acrg-(?:first-attachment-)?handoff v1\n' -or $identities.Count -ne 1) { throw 'Resume requires a bounded recorded runtime identity' }
      $id = $identities[0].Groups[1].Value
      $sha = [Security.Cryptography.SHA256]::Create()
      try { $handoffDigest = ([BitConverter]::ToString($sha.ComputeHash($pending.Bytes))).Replace('-', '').ToLowerInvariant() }
      finally { $sha.Dispose() }
    } finally { $pending.Stream.Dispose() }
    $selected = $Context
    if ($id -cne $Context.Id) {
      if ($Context.RetainRelease -isnot [scriptblock]) { throw 'Resume cannot retain the transaction runtime' }
      $selected = & $Context.RetainRelease -Id $id
    }
    $selected | Add-Member -NotePropertyName ResumeHandoffSha256 -NotePropertyValue $handoffDigest
    if ($selected.Id -cne $Context.Id) {
      $module = Import-Module -Name $selected.Payloads['scripts/central-context.psm1'].Path -Force -Global -PassThru -ErrorAction Stop
      return & $module { param($Root, $Request, $Runtime) Invoke-CrgCentralOperation -TargetRepo $Root -Operation $Request -Context $Runtime } $TargetRepo $Operation $selected
    }
  }
  Import-CrgCentralOperationModules -Context $Context
  if ($Operation.Name -ceq 'Stage') {
    $prefix = @('-C', $TargetRepo)
    $actualRoot = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--show-toplevel'))).Replace('/', '\')
    if (-not [string]::Equals($actualRoot, $TargetRepo, [StringComparison]::OrdinalIgnoreCase)) { throw 'Stage target is not the actual public worktree root' }
    $gitDir = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--absolute-git-dir'))).Replace('/', '\')
    $attachment = & $Context.ReadFile -Path (Join-Path $gitDir 'crg-attachment') -Maximum 16384 -AllowAbsent
    $proposal = & $Context.ReadFile -Path (Join-Path $gitDir 'crg-attachment-pending') -Maximum 16384 -AllowAbsent
    if ($attachment.Present -and $proposal.Present) { throw 'Stage refuses conflicting active and pending attachment records' }
    if (-not $attachment.Present -and $proposal.Present) {
      if ($Operation.All) { throw 'pending attachment staging requires explicit paths; All is unsupported' }
      return Invoke-CrgCentralPendingAttachmentStage -TargetRepo $TargetRepo -Context $Context -Paths $Operation.Paths
    }
  }
  switch -CaseSensitive ($Operation.Name) {
    'Commit' { return Invoke-CrgCentralCommit -TargetRepo $TargetRepo -Context $Context -MessageFile $Operation.MessageFile -AuthoringAgent $Operation.AuthoringAgent }
    'Attach' { return Invoke-CrgCentralAttach -TargetRepo $TargetRepo -Context $Context -MessageFile $Operation.MessageFile -AuthoringAgent $Operation.AuthoringAgent -PrivateGitDir $Operation.PrivateGitDir }
    'Resume' { return Invoke-CrgCentralResume -TargetRepo $TargetRepo -Context $Context }
  }
  $owned = $null; $hookEnvironment = $null
  $retained = $false
  try {
    if ($Operation.Name -ceq 'PushCheck') {
      $hookEnvironment = Enter-CrgCentralPushEnvironment -TargetRepo $TargetRepo -Context $Context
      $TargetRepo = $hookEnvironment.Root
    }
    $owned = Open-CrgPairedProjectOperation -TargetRepo $TargetRepo -Runtime $Context
    switch -CaseSensitive ($Operation.Name) {
      'Stage' {
        if ($Operation.All) { return Invoke-CrgPairedStage -Operation $owned -All }
        return Invoke-CrgPairedStage -Operation $owned -Paths $Operation.Paths
      }
      'PushCheck' { return Invoke-CrgCentralPushCheck -ProjectContext $owned.ProjectContext -OperationLock $owned.OperationLock -InputBytes $Operation.PushInput -RemoteName $Operation.PushRemoteName -RemoteLocation $Operation.PushRemoteLocation }
      'Open' { return Get-CrgCentralOpenState -Operation $owned }
    }
  } catch {
    $publication = @(Get-Command Invoke-CrgCentralCommit -Module central-publication -CommandType Function -ListImported)[0]
    $retained = & $publication.Module { param($Owner, $Failure) Save-CrgUncertainCentralOperation -Operation $Owner -Failure $Failure } $owned $_.Exception
    throw
  } finally {
    try { if (-not $retained -and $null -ne $owned) { Close-CrgPairedProjectOperation -Operation $owned } }
    finally {
      if ($null -ne $hookEnvironment) {
        foreach ($name in $hookEnvironment.Saved.Keys) { [Environment]::SetEnvironmentVariable($name, $hookEnvironment.Saved[$name], [EnvironmentVariableTarget]::Process) }
      }
    }
  }
}

function Enter-CrgCentralPushEnvironment {
  param([string]$TargetRepo, [object]$Context)
  # Git exports repository selectors when invoking native hooks. Only exact
  # redundant selectors for this explicit public root are normalized here;
  # caller config/object/attribute overrides still reach the ordinary refusal.
  # Git-for-Windows pwd -W supplies drive-qualified forward-slash spelling.
  # Normalize that representation only, then corroborate the actual root.
  if ([string]::IsNullOrWhiteSpace($TargetRepo)) { throw 'pre-push requires an explicit public root' }
  $TargetRepo = $TargetRepo.Replace('/', '\')
  Assert-CrgContextAbsolutePath -Path $TargetRepo
  $gitExe = @(Get-Command git.exe -CommandType Application -ErrorAction Stop)[0].Source
  $prefix = @('-C', $TargetRepo)
  $root = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--show-toplevel')) -GitExe $gitExe).Replace('/', '\')
  if (-not [string]::Equals($root, $TargetRepo, [StringComparison]::OrdinalIgnoreCase)) { throw 'pre-push selector normalization requires the actual explicit public root' }
  $expected = @{
    GIT_DIR = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--absolute-git-dir')) -GitExe $gitExe).Replace('/', '\')
    GIT_COMMON_DIR = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $gitExe).Replace('/', '\')
    GIT_WORK_TREE = $root
    GIT_EXEC_PATH = (Get-CrgStatusGitLine -Arguments @('--exec-path') -GitExe $gitExe).Replace('/', '\')
  }
  $expected.GIT_INDEX_FILE = Join-Path $expected.GIT_DIR 'index'
  $session = @(Get-Command Invoke-CrgPairedReviewSession -Module paired-review-session -CommandType Function -ListImported -ErrorAction Stop)
  if ($session.Count -ne 1 -or $session[0].Module.Path -cne $Context.Payloads['scripts/paired-review-session.psm1'].Path) { throw 'pre-push requires the retained raw environment reader' }
  $raw = & $session[0].Module { $null = Get-CrgPairedSessionEnvironment; return ,([CrgPairedSession.EnvironmentV1]::Capture()) }
  $saved = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in $raw) {
    if ([string]::IsNullOrEmpty($entry)) { throw 'pre-push environment entry is empty' }
    $separator = if ($entry[0] -ceq '=') { $entry.IndexOf('=', 1) } else { $entry.IndexOf('=') }
    if ($separator -le 0) { throw 'pre-push environment entry has invalid grammar' }
    $name = $entry.Substring(0, $separator); $value = $entry.Substring($separator + 1)
    if (-not $expected.ContainsKey($name) -and $name -ine 'GIT_PREFIX') { continue }
    if ($saved.ContainsKey($name)) { throw 'pre-push environment has duplicate repository selectors' }
    if ($name -ieq 'GIT_PREFIX') {
      if ($value -cne '') { throw 'pre-push Git prefix is not the public root' }
    } else {
      if ([string]::IsNullOrWhiteSpace($value) -or $value -match '[\x00-\x1f\x7f]') { throw "pre-push selector '$name' is invalid" }
      $path = $value.Replace('/', '\')
      if (-not [IO.Path]::IsPathRooted($path)) { $path = Join-Path $root $path }
      $path = [IO.Path]::GetFullPath($path)
      Assert-CrgContextAbsolutePath -Path $path
      if (-not [string]::Equals($path, $expected[$name], [StringComparison]::OrdinalIgnoreCase)) { throw "pre-push selector '$name' disagrees with the captured public namespace" }
    }
    $saved.Add($name, $value)
  }
  try {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $null, [EnvironmentVariableTarget]::Process) }
  } catch {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], [EnvironmentVariableTarget]::Process) }
    throw
  }
  return [pscustomobject]@{ Root = $root; Saved = $saved }
}

function Import-CrgCentralOperationModules {
  param([object]$Context)
  foreach ($name in @('private-governance', 'paired-governance', 'paired-tree', 'review-preparation',
      'project-preparation', 'paired-review-input', 'paired-diff', 'paired-process', 'paired-operation',
      'paired-preparation', 'paired-review-session', 'paired-retention', 'paired-project-operation',
      'paired-git-operation', 'paired-stage', 'paired-state', 'paired-resume-state',
      'first-attachment-context', 'first-attachment-preparation', 'central-guards',
      'central-attachment', 'central-instructions', 'central-publication', 'central-recovery')) {
    $relative = 'scripts/' + $name + '.psm1'
    if ($Context.Payloads -isnot [Collections.IDictionary] -or $relative -cnotin @($Context.Payloads.Keys)) { throw "central operation requires release payload '$relative'" }
    $payload = $Context.Payloads[$relative]
    if ($payload.Bytes -isnot [byte[]] -or $payload.Path -cne (Join-Path $Context.Root $relative.Replace('/', '\'))) { throw 'central module path differs from the retained release' }
    Import-Module -Name $payload.Path -Force -Global -ErrorAction Stop
  }
}

function Get-CrgCentralOpenState {
  param([object]$Operation)
  $project = $Operation.ProjectContext; $runtime = $Operation.Runtime
  $source = Read-CrgCentralPreparationSource -ProjectContext $project -PublicTreeOid $project.Domains.public.ParentTree -PrivateTreeOid $project.Domains.private.ParentTree
  $template = $runtime.Payloads['scripts/codex/review-prompt-template.md'].Bytes
  $bytes = New-CrgProjectPreparationBytes -Kind governing -RuntimeSha256 $runtime.Id -ConfigBytes $source.ConfigBytes -ValuesBytes $source.ValuesBytes -ModePresent $source.ModePresent -ModeBytes $source.ModeBytes -TemplateBytes $template
  $prepared = Read-CrgProjectPreparationBytes -Bytes $bytes -ExpectedKind governing -ExpectedRuntimeSha256 $runtime.Id -TemplateBytes $template
  $mode = if ($prepared.ModeState -ceq 'valid') { $prepared.Mode.Mode } else { 'shipped' }
  $discovery = Sync-CrgCentralInstructions -Operation $Operation
  Assert-CrgPairedOperationReads -Owner $Operation.ReadOwner
  return [pscustomobject]@{ Status = 'open'; Root = $project.Root; Runtime = $runtime.Id
    ProjectMode = $mode; ModeState = $prepared.ModeState; Instructions = @($discovery)
    PublicCommit = $project.Domains.public.Parent; PrivateCommit = $project.Domains.private.Parent
    CompletedPair = $Operation.PreviousReceipt.ReceiptSha256; Governance = 'preceding-completed-private-state' }
}

function Assert-CrgContextAbsolutePath {
  param([string]$Path)
  if ($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Contains('/') -or $Path -match '[\x00-\x1f\x7f]' -or
      -not [string]::Equals([IO.Path]::GetFullPath($Path), $Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'captured Git path must be canonical and local' }
}

function Assert-CrgContextIndirection {
  param([object]$Context, [string]$Path, [string]$Base, [string]$Expected, [switch]$GitFile, [switch]$AllowAbsent)
  $file = & $Context.ReadFile -Path $Path -Maximum 16384 -AllowAbsent:$AllowAbsent
  if (-not $file.Present) {
    if (-not $AllowAbsent -or -not [string]::Equals($Base, $Expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'captured Git namespace requires a missing indirection file' }
    return
  }
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($file.Bytes)
  $pattern = if ($GitFile) { '\Agitdir: ([^\r\n]+)\r?\n?\z' } else { '\A([^\r\n]+)\r?\n?\z' }
  if ($text -cnotmatch $pattern) { throw 'captured Git indirection has invalid grammar' }
  $target = $Matches[1].Replace('/', '\')
  if (-not [IO.Path]::IsPathRooted($target)) { $target = Join-Path $Base $target }
  if (-not [string]::Equals([IO.Path]::GetFullPath($target).TrimEnd('\'), $Expected.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'retained Git indirection differs from the captured namespace' }
}

function Assert-CrgCentralGitState {
  param([object]$Context, [string]$PublicGitDir, [string]$PrivateGitDir, [string]$PublicRef)
  if ($null -eq $Context -or $Context.ReadFile -isnot [scriptblock] -or [string]::IsNullOrEmpty($PublicRef)) { throw 'central Git state requires a retained context and captured public ref' }
  foreach ($path in @($PublicGitDir, $PrivateGitDir)) { Assert-CrgContextAbsolutePath -Path $path }
  $head = & $Context.ReadFile -Path (Join-Path $PublicGitDir 'HEAD') -Maximum 4096
  if ($null -eq $head -or $head.Present -isnot [bool] -or -not $head.Present -or $head.Bytes -isnot [byte[]]) { throw 'central Git state requires the retained public HEAD' }
  $headText = [Text.UTF8Encoding]::new($false, $true).GetString($head.Bytes)
  if ($headText -cnotmatch '\Aref: ([^\r\n]+)\r?\n?\z') { throw 'central public HEAD must be an exact symbolic ref' }
  if ($Matches[1] -cne $PublicRef) { throw 'central public HEAD differs from the captured branch association' }
  foreach ($directory in @($PublicGitDir, $PrivateGitDir)) {
    foreach ($leaf in @('MERGE_HEAD', 'REBASE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'rebase-merge', 'rebase-apply', 'sequencer')) {
      $record = & $Context.ReadFile -Path (Join-Path $directory $leaf) -Maximum 65536 -AllowAbsent
      if ($null -eq $record -or $record.Present -isnot [bool] -or $record.Present) { throw 'central Git state requires explicit resolution of every in-progress operation' }
    }
  }
}

function Get-CrgCentralProjectContext {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo, [Parameter(Mandatory = $true)][object]$Context)
  if ($null -eq $Context -or $Context.ReadFile -isnot [scriptblock]) { throw 'Git capture requires the live retained launcher context' }
  $gitExe = @(Get-Command git.exe -CommandType Application -ErrorAction Stop)[0].Source
  Assert-CrgContextAbsolutePath -Path $gitExe
  $null = & $Context.ReadFile -Path $gitExe -Maximum 16777216
  $status = Get-CrgCentralProjectStatus -TargetRepo $TargetRepo -Context $Context -GitExe $gitExe
  if ($status.Attachment -ceq 'absent') { throw 'paired Git capture requires an existing validated attachment' }
  $dotGit = Join-Path $status.PublicRoot '.git'
  if (-not [string]::Equals($dotGit, $status.PublicGitDir, [StringComparison]::OrdinalIgnoreCase)) {
    Assert-CrgContextIndirection -Context $Context -Path $dotGit -Base $status.PublicRoot -Expected $status.PublicGitDir -GitFile
  }
  Assert-CrgContextIndirection -Context $Context -Path (Join-Path $status.PublicGitDir 'commondir') -Base $status.PublicGitDir -Expected $status.PublicCommonDir -AllowAbsent
  Assert-CrgContextIndirection -Context $Context -Path (Join-Path $status.PrivateGitDir 'commondir') -Base $status.PrivateGitDir -Expected $status.PrivateGitDir -AllowAbsent
  Assert-CrgCentralGitState -Context $Context -PublicGitDir $status.PublicGitDir -PrivateGitDir $status.PrivateGitDir -PublicRef $status.PublicRef
  $domains = [ordered]@{}
  foreach ($name in @('public', 'private')) {
    $directory = $status.PublicGitDir; $common = $status.PublicCommonDir
    $branch = $status.PublicRef; $parent = $status.PublicCommit
    $index = Join-Path $directory 'index'
    if ($name -ceq 'private') {
      $directory = $status.PrivateGitDir; $common = $directory
      $branch = $status.PrivateRef; $parent = $status.PrivateCommit
      $index = Join-Path $status.PublicGitDir 'crg-private-index'
    }
    foreach ($path in @($directory, $common, $index)) { Assert-CrgContextAbsolutePath -Path $path }
    $prefix = @("--git-dir=$directory", "--work-tree=$($status.PublicRoot)")
    $format = Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--show-object-format')) -GitExe $gitExe
    if ($format -cnotin @('sha1', 'sha256')) { throw 'captured Git object format is unsupported' }
    $width = if ($format -ceq 'sha1') { 40 } else { 64 }
    if ($parent -cnotmatch ('\A[0-9a-f]{' + $width + '}\z') -or $parent -match '\A0+\z') { throw 'captured parent has the wrong domain object format' }
    $actualCommon = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $gitExe).Replace('/', '\')
    $objects = (Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-path', 'objects')) -GitExe $gitExe).Replace('/', '\')
    if (-not [string]::Equals($actualCommon, $common, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($objects, (Join-Path $common 'objects'), [StringComparison]::OrdinalIgnoreCase)) { throw 'captured common/object directory differs from the explicit domain' }
    $actualParent = Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--verify', "$branch^{commit}")) -GitExe $gitExe
    if ($actualParent -cne $parent) { throw 'paired branch changed during read-only context capture' }
    $tree = Get-CrgStatusGitLine -Arguments ($prefix + @('rev-parse', '--verify', "$parent^{tree}")) -GitExe $gitExe
    if ($tree -cnotmatch ('\A[0-9a-f]{' + $width + '}\z') -or $tree -match '\A0+\z') { throw 'captured parent tree identity is invalid' }
    $domains[$name] = [pscustomobject]@{ GitDir = $directory; CommonDir = $common; ObjectDir = $objects; IndexPath = $index; Ref = $branch; Parent = $parent; ParentTree = $tree; ObjectFormat = $format }
  }
  return [pscustomobject]@{ Schema = 1; Runtime = $Context; Root = $status.PublicRoot; GitExe = $gitExe; Status = $status; Domains = $domains; ValidationState = 'read-only-captured-context' }
}

function Get-CrgContextObjectArguments {
  param([object]$ProjectContext, [string]$Domain, [string]$Oid)
  if ($null -eq $ProjectContext -or $ProjectContext.Schema -ne 1 -or $ProjectContext.Domains -isnot [System.Collections.IDictionary] -or
      $Domain -cnotin @('public', 'private') -or -not $ProjectContext.Domains.Contains($Domain)) { throw 'captured Git domain is invalid' }
  $selected = $ProjectContext.Domains[$Domain]
  foreach ($path in @($ProjectContext.GitExe, $ProjectContext.Root, $selected.GitDir)) { Assert-CrgContextAbsolutePath -Path $path }
  if ($selected.ObjectFormat -cnotin @('sha1', 'sha256')) { throw 'captured object format is invalid' }
  $width = if ($selected.ObjectFormat -ceq 'sha1') { 40 } else { 64 }
  if ($Oid -cnotmatch ('\A[0-9a-f]{' + $width + '}\z') -or $Oid -match '\A0+\z') { throw 'requested object identity is not canonical for the selected domain' }
  # Reconstruct switches from checked fields, never execute a supplied argv list.
  return ,([string[]]@("--git-dir=$($selected.GitDir)", "--work-tree=$($ProjectContext.Root)"))
}

function Read-CrgCentralBatchStreamFill {
  param([object]$State, [DateTime]$Deadline)
  if ($State.Offset -lt $State.Count) { return }
  $remaining = $Deadline - [DateTime]::UtcNow
  if ($remaining.TotalMilliseconds -le 0) { throw 'batch object read timed out' }
  $wait = [int][Math]::Min(2147483647, [Math]::Max(1, [Math]::Ceiling($remaining.TotalMilliseconds)))
  $task = $State.Stream.ReadAsync($State.Buffer, 0, $State.Buffer.Length)
  if (-not $task.Wait($wait)) { throw 'batch object read timed out' }
  $State.Offset = 0
  $State.Count = $task.GetAwaiter().GetResult()
}

function Read-CrgCentralBatchStreamByte {
  param([object]$State, [DateTime]$Deadline)
  Read-CrgCentralBatchStreamFill -State $State -Deadline $Deadline
  if ($State.Count -eq 0) { throw 'batch object output ended before a complete record' }
  $value = $State.Buffer[$State.Offset]
  $State.Offset++
  return $value
}

function Read-CrgCentralBatchStreamBytes {
  param([object]$State, [byte[]]$Destination, [DateTime]$Deadline)
  $written = 0
  while ($written -lt $Destination.Length) {
    Read-CrgCentralBatchStreamFill -State $State -Deadline $Deadline
    if ($State.Count -eq 0) { throw 'batch object output ended inside object contents' }
    $available = $State.Count - $State.Offset
    $take = [Math]::Min($available, $Destination.Length - $written)
    [Array]::Copy($State.Buffer, $State.Offset, $Destination, $written, $take)
    $State.Offset += $take
    $written += $take
  }
}

function Wait-CrgCentralBatchTask {
  param([object]$Task, [DateTime]$Deadline, [string]$Failure)
  $remaining = $Deadline - [DateTime]::UtcNow
  if ($remaining.TotalMilliseconds -le 0) { throw $Failure }
  $wait = [int][Math]::Min(2147483647, [Math]::Max(1, [Math]::Ceiling($remaining.TotalMilliseconds)))
  if (-not $Task.Wait($wait)) { throw $Failure }
  $Task.GetAwaiter().GetResult()
}

function Read-CrgCentralObjectBatch {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Requests,
    [Parameter(Mandatory = $true)][long]$MaximumAggregate,
    [switch]$ValidationOnly)
  if ($null -eq $Requests) { throw 'batch object requests are absent' }
  if ($MaximumAggregate -lt 0 -or (-not $ValidationOnly -and $MaximumAggregate -gt 2147483647)) { throw 'batch object aggregate bound is invalid' }
  $objects = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  if ($Requests.Count -eq 0) { return ,$objects }
  $specifications = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  $ordered = New-Object 'System.Collections.Generic.List[object]'
  $prefix = $null
  foreach ($request in $Requests) {
    if ($null -eq $request -or $null -eq $request.PSObject.Properties['Oid'] -or
        $null -eq $request.PSObject.Properties['Type'] -or $null -eq $request.PSObject.Properties['Maximum']) {
      throw 'batch object request is incomplete'
    }
    $oid = $request.Oid; $type = $request.Type; $maximum = $request.Maximum
    if ($oid -isnot [string] -or $type -isnot [string] -or $maximum -isnot [int] -or
        $type -cnotin @('blob', 'tree', 'commit') -or $maximum -lt 0) { throw 'batch object request has an invalid type or bound' }
    $arguments = Get-CrgContextObjectArguments -ProjectContext $ProjectContext -Domain $Domain -Oid $oid
    if ($null -eq $prefix) { $prefix = $arguments }
    if ($specifications.ContainsKey($oid)) {
      $prior = $specifications[$oid]
      if ($prior.Type -cne $type) { throw 'batch object identity has conflicting expected types' }
      if ($maximum -lt $prior.Maximum) { $prior.Maximum = $maximum }
      continue
    }
    $specification = [pscustomobject]@{ Oid = $oid; Type = $type; Maximum = $maximum }
    $specifications.Add($oid, $specification)
    $ordered.Add($specification)
  }
  $quoted = foreach ($argument in (@('--no-pager') + $prefix + @('-c', 'core.fsmonitor=false', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', 'cat-file', '--batch'))) {
    if ($null -eq $argument -or $argument.Contains([char]0)) { throw 'batch object Git argument is invalid' }
    $escaped = [regex]::Replace($argument, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    '"' + $escaped + '"'
  }
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $ProjectContext.GitExe; $start.Arguments = $quoted -join ' '
  $start.UseShellExecute = $false; $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true; $start.RedirectStandardInput = $true
  foreach ($name in @($start.EnvironmentVariables.Keys)) {
    if ($name -imatch '^GIT_') { $start.EnvironmentVariables.Remove($name) }
  }
  foreach ($entry in @{ GIT_NO_REPLACE_OBJECTS = '1'; GIT_NO_LAZY_FETCH = '1'; GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_SYSTEM = 'NUL'; GIT_CONFIG_GLOBAL = 'NUL'; GIT_OPTIONAL_LOCKS = '0' }.GetEnumerator()) {
    $start.EnvironmentVariables[$entry.Key] = $entry.Value
  }
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $start; $started = $false; $errorRead = $null
  try {
    $priorEncoding = $null
    if ($null -eq $start.PSObject.Properties['StandardInputEncoding']) {
      $priorEncoding = [Console]::InputEncoding; [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    } else { $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false) }
    try { $started = $process.Start() }
    finally { if ($null -ne $priorEncoding) { [Console]::InputEncoding = $priorEncoding } }
    if (-not $started) { throw 'batch object Git launch failed' }
    $errorRead = $process.StandardError.ReadToEndAsync()
    $state = [pscustomobject]@{ Stream = $process.StandardOutput.BaseStream; Buffer = (New-Object byte[] 65536); Offset = 0; Count = 0 }
    [long]$aggregate = 0
    $width = if ($ProjectContext.Domains[$Domain].ObjectFormat -ceq 'sha1') { 40 } else { 64 }
    foreach ($specification in $ordered) {
      $deadline = [DateTime]::UtcNow.AddSeconds(10)
      $query = [Text.Encoding]::ASCII.GetBytes($specification.Oid + "`n")
      $write = $process.StandardInput.BaseStream.WriteAsync($query, 0, $query.Length)
      $null = Wait-CrgCentralBatchTask -Task $write -Deadline $deadline -Failure 'batch object query write timed out'
      $flush = $process.StandardInput.BaseStream.FlushAsync()
      $null = Wait-CrgCentralBatchTask -Task $flush -Deadline $deadline -Failure 'batch object query flush timed out'
      $headerBytes = New-Object 'System.Collections.Generic.List[byte]'
      while ($true) {
        $value = Read-CrgCentralBatchStreamByte -State $state -Deadline $deadline
        if ($value -eq 10) { break }
        if ($headerBytes.Count -ge 255 -or $value -lt 32 -or $value -gt 126) { throw 'batch object header is unbounded or non-ASCII' }
        $headerBytes.Add($value)
      }
      $header = [Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
      if ($header -cnotmatch ('\A([0-9a-f]{' + $width + '}) (blob|tree|commit) (0|[1-9][0-9]{0,9})\z')) {
        throw 'batch object header reports a missing or malformed object'
      }
      $actualOid = [string]$Matches[1]; $actualType = [string]$Matches[2]; $size = [long]$Matches[3]
      if ($actualOid -cne $specification.Oid -or $actualType -cne $specification.Type) { throw 'batch object header differs from the requested identity or type' }
      if ($size -gt $specification.Maximum) { throw 'batch object exceeds its per-object byte bound' }
      $aggregate += $size
      if ($aggregate -gt $MaximumAggregate) { throw 'batch object contents exceed the aggregate byte bound' }
      $bytes = New-Object byte[] ([int]$size)
      Read-CrgCentralBatchStreamBytes -State $state -Destination $bytes -Deadline $deadline
      if ((Read-CrgCentralBatchStreamByte -State $state -Deadline $deadline) -ne 10) { throw 'batch object contents lack the required record terminator' }
      $hash = if ($ProjectContext.Domains[$Domain].ObjectFormat -ceq 'sha1') { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
      try {
        $objectHeader = [Text.Encoding]::ASCII.GetBytes($actualType + ' ' + $size.ToString([Globalization.CultureInfo]::InvariantCulture) + [char]0)
        $null = $hash.TransformBlock($objectHeader, 0, $objectHeader.Length, $null, 0)
        $null = $hash.TransformFinalBlock($bytes, 0, $bytes.Length)
        if (([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant() -cne $actualOid) { throw 'batch object failed independent raw identity verification' }
      } finally { $hash.Dispose() }
      if ($ValidationOnly) { $bytes = $null }
      else { $objects.Add($actualOid, $bytes) }
    }
    $process.StandardInput.Close()
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    Read-CrgCentralBatchStreamFill -State $state -Deadline $deadline
    if ($state.Offset -lt $state.Count) { throw 'batch object output contains undeclared trailing bytes' }
    $remaining = $deadline - [DateTime]::UtcNow
    $wait = [int][Math]::Min(2147483647, [Math]::Max(1, [Math]::Ceiling($remaining.TotalMilliseconds)))
    if (-not $process.WaitForExit($wait)) { throw 'batch object Git command timed out during exit' }
    $errorText = $errorRead.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "batch object Git failed ($($process.ExitCode)): $errorText" }
    return ,$objects
  } finally {
    try {
      if ($started -and -not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(2000)) { throw 'batch object Git cleanup could not confirm root exit' }
      }
    } finally { $process.Dispose() }
  }
}

function Read-CrgCentralTreeBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][string]$TreeOid)
  $prefix = Get-CrgContextObjectArguments -ProjectContext $ProjectContext -Domain $Domain -Oid $TreeOid
  if ((Get-CrgStatusGitLine -Arguments ($prefix + @('cat-file', '-t', $TreeOid)) -GitExe $ProjectContext.GitExe) -cne 'tree') { throw 'requested tree identity is not a Git tree' }
  $commands = @(Get-Command -Name Read-CrgGitTreeBytes -Module paired-tree -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($commands.Count -ne 1) { throw 'tree capture requires the already imported retained paired-tree reader' }
  $bytes = Invoke-CrgStatusGit -Arguments ($prefix + @('ls-tree', '--full-tree', '-r', '-t', '-z', $TreeOid)) -Maximum 16777216 -GitExe $ProjectContext.GitExe
  $null = & $commands[0] -Bytes $bytes -ObjectFormat $ProjectContext.Domains[$Domain].ObjectFormat
  return ,([byte[]]$bytes)
}

function Read-CrgCentralBlobBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain,
    [Parameter(Mandatory = $true)][string]$BlobOid,
    [Parameter(Mandatory = $true)][ValidateRange(0, 2147483647)][int]$Maximum)
  $objects = Read-CrgCentralObjectBatch -ProjectContext $ProjectContext -Domain $Domain `
    -Requests @([pscustomobject]@{ Oid = $BlobOid; Type = 'blob'; Maximum = $Maximum }) -MaximumAggregate $Maximum
  $bytes = $objects[$BlobOid]
  if ($bytes -isnot [byte[]]) { throw 'batch blob capture omitted the requested identity' }
  return ,$bytes
}

function Read-CrgCentralPreparationSource {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][string]$PublicTreeOid,
    [Parameter(Mandatory = $true)][string]$PrivateTreeOid)
  $parsers = @{}
  foreach ($item in @(
    @{ Name = 'Read-CrgGitTreeBytes'; Module = 'paired-tree' },
    @{ Name = 'Read-CrgProjectConfigBytes'; Module = 'private-governance' }
  )) {
    $commands = @(Get-Command -Name $item.Name -Module $item.Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
    if ($commands.Count -ne 1) { throw "preparation source requires the retained '$($item.Name)' parser" }
    $parsers[$item.Name] = $commands[0]
  }
  $publicBytes = Read-CrgCentralTreeBytes -ProjectContext $ProjectContext -Domain public -TreeOid $PublicTreeOid
  $privateBytes = Read-CrgCentralTreeBytes -ProjectContext $ProjectContext -Domain private -TreeOid $PrivateTreeOid
  $entries = @{}
  $entries.public = & $parsers['Read-CrgGitTreeBytes'] -Bytes $publicBytes -ObjectFormat $ProjectContext.Domains.public.ObjectFormat
  $entries.private = & $parsers['Read-CrgGitTreeBytes'] -Bytes $privateBytes -ObjectFormat $ProjectContext.Domains.private.ObjectFormat
  $sources = @{}
  foreach ($item in @(
    @{ Name = 'Config'; Path = '.crg-project/project.conf'; Maximum = 65536; Optional = $false },
    @{ Name = 'Values'; Path = 'CROSS-REVIEW-VALUES.md'; Maximum = 262144; Optional = $false },
    @{ Name = 'Mode'; Path = 'PROJECT-MODE.md'; Maximum = 16777216; Optional = $true }
  )) {
    $matches = @($entries.private | Where-Object { $_.Path -ceq $item.Path })
    if ($matches.Count -eq 0 -and $item.Optional) {
      $sources[$item.Name] = [pscustomobject]@{ Present = $false; Bytes = [byte[]]@(); Entry = $null }
      continue
    }
    if ($matches.Count -ne 1 -or $matches[0].Mode -cnotin @('100644', '100755') -or $matches[0].Type -cne 'blob') { throw "private preparation source '$($item.Path)' must be a regular blob" }
    $bytes = Read-CrgCentralBlobBytes -ProjectContext $ProjectContext -Domain private -BlobOid $matches[0].Oid -Maximum $item.Maximum
    $sources[$item.Name] = [pscustomobject]@{ Present = $true; Bytes = $bytes; Entry = $matches[0] }
  }
  $config = & $parsers['Read-CrgProjectConfigBytes'] -Bytes $sources.Config.Bytes
  $roles = New-Object 'System.Collections.Generic.List[object]'
  foreach ($role in $config.Roles) {
    $bindings = @()
    foreach ($domain in @('public', 'private')) {
      foreach ($entry in @($entries[$domain] | Where-Object { $_.Path -ceq $role.Path })) {
        if ($entry.Mode -cnotin @('100644', '100755') -or $entry.Type -cne 'blob') { throw "document role '$($role.Path)' is not a regular blob" }
        $bindings += [pscustomobject]@{ Domain = $domain; Path = $entry.Path; Mode = $entry.Mode; Oid = $entry.Oid }
      }
    }
    if ($bindings.Count -ne 1) { throw "document role '$($role.Path)' must resolve to exactly one domain leaf" }
    $roles.Add($bindings[0])
  }
  # Per-tree capture has no independent preceding config. Binding this config
  # into both union slots erased preceding reservations (2026-09-06 review).
  # Keep ownership validation with the caller's independently selected versions.
  return [pscustomobject]@{
    PublicTreeOid = $PublicTreeOid; PrivateTreeOid = $PrivateTreeOid
    PublicTreeBytes = $publicBytes; PrivateTreeBytes = $privateBytes
    Config = $config; ConfigBytes = $sources.Config.Bytes; ValuesBytes = $sources.Values.Bytes
    ModePresent = $sources.Mode.Present; ModeBytes = $sources.Mode.Bytes
    Sources = $sources; RoleBindings = $roles.ToArray(); ValidationState = 'captured-preparation-source'; ReadyForReview = $false
  }
}

function Get-CrgCentralIndexTree {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain)
  $prefix = Get-CrgContextObjectArguments -ProjectContext $ProjectContext -Domain $Domain -Oid $ProjectContext.Domains[$Domain].ParentTree
  if ($ProjectContext.Runtime.ReadFile -isnot [scriptblock]) { throw 'index capture requires the live retained launcher callback' }
  $selected = $ProjectContext.Domains[$Domain]
  $indexName = if ($Domain -ceq 'public') { 'index' } else { 'crg-private-index' }
  $expectedIndex = Join-Path $ProjectContext.Domains.public.GitDir $indexName
  Assert-CrgContextAbsolutePath -Path $expectedIndex
  if (-not [string]::Equals($selected.IndexPath, $expectedIndex, [StringComparison]::OrdinalIgnoreCase)) { throw 'index path differs from the captured public-worktree association' }
  $index = & $ProjectContext.Runtime.ReadFile -Path $expectedIndex -Maximum 67108864
  if (-not $index.Present -or $index.Bytes -isnot [byte[]]) { throw 'selected index did not provide a retained byte buffer' }
  $arguments = $prefix + @('-c', 'core.fsmonitor=false')
  $sharedBytes = Invoke-CrgStatusGit -Arguments ($arguments + @('rev-parse', '--path-format=absolute', '--shared-index-path')) -Maximum 16384 -GitExe $ProjectContext.GitExe -IndexPath $expectedIndex
  $sharedText = [Text.UTF8Encoding]::new($false, $true).GetString($sharedBytes)
  $shared = $null; $sharedPath = ''
  if ($sharedText.Length -gt 0 -and $sharedText -cnotin @("`n", "`r`n")) {
    if ($sharedText -cnotmatch '\A[^\r\n]+\r?\n?\z') { throw 'split-index path capture did not return one complete line' }
    $sharedPath = $sharedText.TrimEnd([char[]]@(13, 10)).Replace('/', '\')
    Assert-CrgContextAbsolutePath -Path $sharedPath
    $sharedParent = [IO.Path]::GetDirectoryName($sharedPath)
    $width = if ($selected.ObjectFormat -ceq 'sha1') { 40 } else { 64 }
    if ([IO.Path]::GetFileName($sharedPath) -cnotmatch ('\Asharedindex\.[0-9a-f]{' + $width + '}\z') -or
        (-not [string]::Equals($sharedParent, $selected.GitDir, [StringComparison]::OrdinalIgnoreCase) -and
         -not [string]::Equals($sharedParent, $selected.CommonDir, [StringComparison]::OrdinalIgnoreCase))) { throw 'split-index backing path is outside the captured domain namespace' }
    $shared = & $ProjectContext.Runtime.ReadFile -Path $sharedPath -Maximum 67108864
    if (-not $shared.Present -or $shared.Bytes -isnot [byte[]]) { throw 'split-index backing file did not provide a retained byte buffer' }
  }
  $newCopy = @(Get-Command -Name New-CrgPairedIndexCopy -Module paired-diff -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  $closeCopy = @(Get-Command -Name Close-CrgPairedIndexCopy -Module paired-diff -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($newCopy.Count -ne 1 -or $closeCopy.Count -ne 1) { throw 'index capture requires the retained paired-diff copy owner' }
  $copy = & $newCopy[0] -Bytes $index.Bytes -TempParent $ProjectContext.Domains.private.GitDir
  try {
    # write-tree takes an unconditional index lock and may run post-index-change;
    # GIT_OPTIONAL_LOCKS does not prevent either (2026-09-06 review finding).
    # Only the private owned copy receives those index operations. The explicit
    # hookless file sentinel applies solely to this capture child, never commits.
    # A copied split index still locates shared writeback/expiry in real GIT_DIR
    # (2026-09-06 merge review). Git's documented 100 threshold forbids that write.
    $copyArguments = $arguments + @('-c', "core.hooksPath=$($copy.HooksPath)", '-c', 'splitIndex.maxPercentChange=100')
    $copySharedBytes = Invoke-CrgStatusGit -Arguments ($copyArguments + @('rev-parse', '--path-format=absolute', '--shared-index-path')) -Maximum 16384 -GitExe $ProjectContext.GitExe -IndexPath $copy.IndexPath
    $copySharedText = [Text.UTF8Encoding]::new($false, $true).GetString($copySharedBytes).TrimEnd([char[]]@(13, 10)).Replace('/', '\')
    if ($copySharedText -cne $sharedPath) { throw 'copied index resolves a different split-index backing path' }
    $tree = Get-CrgStatusGitLine -Arguments ($copyArguments + @('write-tree')) -GitExe $ProjectContext.GitExe -IndexPath $copy.IndexPath
  } finally {
    $closed = & $closeCopy[0] -Copy $copy
    if (-not $closed.Ok) { throw "index-copy cleanup is unconfirmed; preserved '$($closed.Root)': $($closed.Reason)" }
  }
  $treeBytes = Read-CrgCentralTreeBytes -ProjectContext $ProjectContext -Domain $Domain -TreeOid $tree
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $indexSha = ([BitConverter]::ToString($sha.ComputeHash($index.Bytes))).Replace('-', '').ToLowerInvariant()
    $sharedSha = if ($null -eq $shared) { '-' } else { ([BitConverter]::ToString($sha.ComputeHash($shared.Bytes))).Replace('-', '').ToLowerInvariant() }
  } finally { $sha.Dispose() }
  return [pscustomobject]@{
    Domain = $Domain; IndexPath = $expectedIndex; IndexSha256 = $indexSha
    SharedIndexPath = $sharedPath; SharedIndexSha256 = $sharedSha
    TreeOid = $tree; TreeBytes = $treeBytes; ValidationState = 'copied-index-tree'; ReadyForReview = $false
  }
}

function Read-CrgCentralCommitLogBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][ValidateSet('public', 'private')][string]$Domain)
  $getHistoryBounds = @(Get-Command -Name Get-CrgPreparedHistoryBounds -Module paired-review-input -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($getHistoryBounds.Count -ne 1) { throw 'history capture requires the retained prepared-input history bounds' }
  $bounds = & $getHistoryBounds[0]
  $parent = $ProjectContext.Domains[$Domain].Parent
  $prefix = Get-CrgContextObjectArguments -ProjectContext $ProjectContext -Domain $Domain -Oid $parent
  if ((Get-CrgStatusGitLine -Arguments ($prefix + @('cat-file', '-t', $parent)) -GitExe $ProjectContext.GitExe) -cne 'commit') { throw 'history capture parent is not a commit object' }
  # Message bytes cannot delimit history records. Capture object identities
  # separately, then length-frame raw objects without pretty-format recoding.
  $newControl = @(Get-Command -Name New-CrgPairedIndexCopy -Module paired-diff -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  $closeControl = @(Get-Command -Name Close-CrgPairedIndexCopy -Module paired-diff -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($newControl.Count -ne 1 -or $closeControl.Count -ne 1) { throw 'history capture requires the retained paired-diff file owner' }
  # Replacement suppression did not exclude graft/shallow ancestry overlays
  # (2026-09-06 merge review). Retain one empty file for both explicit overrides;
  # absence probes race creation. Reuse byte-copy custody, never an index input.
  $control = & $newControl[0] -Bytes ([byte[]]@()) -TempParent $ProjectContext.Domains.private.GitDir
  $output = New-Object IO.MemoryStream
  try {
    $ids = Invoke-CrgStatusGit -Arguments ($prefix + @('rev-list', ('--max-count=' + $bounds.DomainCommitCount), $parent, '--')) -Maximum 1024 -GitExe $ProjectContext.GitExe -HistoryControlPath $control.IndexPath
    $width = if ($ProjectContext.Domains[$Domain].ObjectFormat -ceq 'sha1') { 40 } else { 64 }
    $text = [Text.Encoding]::ASCII.GetString($ids)
    if ($text -cnotmatch ('\A(?:[0-9a-f]{' + $width + '}\n){1,' + $bounds.DomainCommitCount + '}\z')) { throw 'history capture did not return a bounded canonical commit list' }
    $shas = @($text.Substring(0, $text.Length - 1) -split "`n", 0)
    if ($shas[0] -cne $parent) { throw 'history capture does not begin at the captured parent' }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $requests = @(foreach ($sha in $shas) {
      if (-not $seen.Add($sha)) { throw 'history capture returned a duplicate commit identity' }
      [pscustomobject]@{ Oid = $sha; Type = 'commit'; Maximum = [int]$bounds.CommitBytes }
    })
    # Keep the captured ancestry order and raw framing while sharing object
    # transport; batching must not trim history or pretty-format message bytes.
    $objects = Read-CrgCentralObjectBatch -ProjectContext $ProjectContext -Domain $Domain `
      -Requests $requests -MaximumAggregate ([long]$bounds.DomainCommitCount * $bounds.CommitBytes)
    $header = [Text.Encoding]::ASCII.GetBytes("crg-commit-history v1`n")
    $output.Write($header, 0, $header.Length)
    foreach ($sha in $shas) {
      $bytes = $objects[$sha]
      if ($bytes -isnot [byte[]] -or $bytes.Length -eq 0 -or $bytes.Length -gt $bounds.CommitBytes) { throw 'history capture omitted a nonempty bounded commit object' }
      $size = $bytes.Length.ToString([Globalization.CultureInfo]::InvariantCulture)
      $header = [Text.Encoding]::ASCII.GetBytes("commit $sha $size`n")
      if ($output.Length + $header.Length + $bytes.Length + 1 -gt $bounds.FramedDomainBytes) { throw 'commit-log capture overflow: framed domain history exceeds its byte cap' }
      $output.Write($header, 0, $header.Length)
      $output.Write($bytes, 0, $bytes.Length)
      $output.WriteByte(10)
    }
    return ,$output.ToArray()
  } finally {
    $output.Dispose()
    $closed = & $closeControl[0] -Copy $control
    if (-not $closed.Ok) { throw "history-control cleanup is unconfirmed; preserved '$($closed.Root)': $($closed.Reason)" }
  }
}

function Write-CrgCentralPrivateMessageBlob {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$ProjectContext,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 1048576) { throw 'private message must contain 1 through 1048576 raw bytes' }
  # This selects the validated object namespace, not commit ancestry. A first
  # attachment has an actual empty parent tree even when no private parent exists.
  $prefix = Get-CrgContextObjectArguments -ProjectContext $ProjectContext -Domain private -Oid $ProjectContext.Domains.private.ParentTree
  $output = Invoke-CrgStatusGit -Arguments ($prefix + @('hash-object', '-t', 'blob', '-w', '--no-filters', '--stdin')) -Maximum 16384 -GitExe $ProjectContext.GitExe -InputBytes $Bytes
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($output)
  if ($text -cnotmatch '\A[^\r\n]+\r?\n?\z') { throw 'private message write did not return one complete object ID' }
  $oid = $text.TrimEnd([char[]]@(13, 10))
  $readback = Read-CrgCentralBlobBytes -ProjectContext $ProjectContext -Domain private -BlobOid $oid -Maximum 1048576
  if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$Bytes, [byte[]]$readback)) { throw 'private message readback differs from the captured input bytes' }
  # Object creation is not retention or review authority. The coordinator owns
  # the message-file lease and the private receipt/retention-ref publication.
  return $oid
}

Export-ModuleMember -Function Invoke-CrgCentralOperation, Get-CrgCentralProjectContext, Read-CrgCentralObjectBatch, Read-CrgCentralTreeBytes, Read-CrgCentralBlobBytes, Read-CrgCentralPreparationSource, Get-CrgCentralIndexTree, Read-CrgCentralCommitLogBytes, Write-CrgCentralPrivateMessageBlob
