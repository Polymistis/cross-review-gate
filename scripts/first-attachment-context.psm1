# Proposed-association capture only. Database/index preparation and activation
# belong to the live attachment owner, never this read-only namespace check.

function Get-CrgFirstAttachmentContextCommand {
  param([string]$Module, [string]$Name)
  $commands = @(Get-Command -Name $Name -Module $Module -CommandType Function -ListImported -ErrorAction SilentlyContinue)
  if ($commands.Count -ne 1) { throw "first attachment requires one retained '$Module/$Name' command" }
  return $commands[0]
}

function Get-CrgCentralFirstAttachmentProjectContext {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$TargetRepo,
    [Parameter(Mandatory = $true)][object]$Context,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$AttachmentBytes,
    [switch]$PendingRecovery)
  if ($null -eq $Context -or $Context.ReadFile -isnot [scriptblock] -or
      $Context.Id -cnotmatch '\A[0-9a-f]{64}\z' -or $Context.Payloads -isnot [System.Collections.IDictionary]) { throw 'first attachment requires the retained runtime context' }
  $attachmentReader = Get-CrgFirstAttachmentContextCommand -Module private-governance -Name Read-CrgAttachmentBytes
  $attachment = & $attachmentReader -Bytes $AttachmentBytes
  if (-not [string]::Equals($attachment.RuntimeStore, $Context.Store, [StringComparison]::OrdinalIgnoreCase)) { throw 'proposed attachment selects another retained runtime store' }
  $treeReader = Get-CrgFirstAttachmentContextCommand -Module central-context -Name Read-CrgCentralTreeBytes
  $retentionReader = Get-CrgFirstAttachmentContextCommand -Module paired-retention -Name Read-CrgFirstAttachmentRetention
  $captureModule = $treeReader.Module
  # Use the same retained namespace/ref readers as ordinary capture and storage.
  # A failing Git command is never translated into a supposedly absent parent.
  $assertPath = & $captureModule { Get-Command Assert-CrgContextAbsolutePath -CommandType Function }
  $readLine = & $captureModule { Get-Command Get-CrgStatusGitLine -CommandType Function }
  $readIndirection = & $captureModule { Get-Command Assert-CrgContextIndirection -CommandType Function }
  $assertGitState = & $captureModule { Get-Command Assert-CrgCentralGitState -CommandType Function }
  $readRef = & $retentionReader.Module { Get-Command Get-CrgRetentionRef -CommandType Function }
  & $assertPath -Path $TargetRepo
  $gitExe = @(Get-Command git.exe -CommandType Application -ErrorAction Stop)[0].Source
  & $assertPath -Path $gitExe
  $gitFile = & $Context.ReadFile -Path $gitExe -Maximum 16777216
  if ($null -eq $gitFile -or $gitFile.Present -isnot [bool] -or -not $gitFile.Present) { throw 'first attachment requires the retained Git executable' }
  $publicGit = @('-C', $TargetRepo)
  $root = (& $readLine -Arguments ($publicGit + @('rev-parse', '--show-toplevel')) -GitExe $gitExe).Replace('/', '\')
  if (-not [string]::Equals($root, $TargetRepo, [StringComparison]::OrdinalIgnoreCase)) { throw 'first attachment target is not the actual public worktree root' }
  $gitDir = (& $readLine -Arguments ($publicGit + @('rev-parse', '--absolute-git-dir')) -GitExe $gitExe).Replace('/', '\')
  $commonDir = (& $readLine -Arguments ($publicGit + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $gitExe).Replace('/', '\')
  foreach ($path in @($root, $gitDir, $commonDir, $attachment.PrivateGitDir)) { & $assertPath -Path $path }
  $validateStorage = Get-CrgFirstAttachmentContextCommand -Module private-governance -Name Assert-CrgPrivateStorageLocation
  & $validateStorage -PublicRoot $root -PublicGitDir $gitDir -PublicCommonDir $commonDir -PrivateGitDir $attachment.PrivateGitDir
  $dotGit = Join-Path $root '.git'
  if (-not [string]::Equals($dotGit, $gitDir, [StringComparison]::OrdinalIgnoreCase)) {
    & $readIndirection -Context $Context -Path $dotGit -Base $root -Expected $gitDir -GitFile
  }
  foreach ($item in @(@($gitDir, $commonDir), @($attachment.PrivateGitDir, $attachment.PrivateGitDir))) {
    & $readIndirection -Context $Context -Path (Join-Path $item[0] 'commondir') -Base $item[0] -Expected $item[1] -AllowAbsent
  }
  foreach ($leaf in @('crg-attachment', 'crg-pair', 'crg-handoff')) {
    $record = & $Context.ReadFile -Path (Join-Path $gitDir $leaf) -Maximum 65536 -AllowAbsent
    if ($null -eq $record -or $record.Present -isnot [bool]) { throw 'first attachment metadata presence is indeterminate' }
    if (-not $PendingRecovery -and $record.Present) { throw 'first attachment requires a positively unattached worktree without pending publication' }
    if ($PendingRecovery -and $leaf -ceq 'crg-handoff' -and -not $record.Present) { throw 'pending context capture requires a present handoff; no review authority follows' }
    if ($PendingRecovery -and $leaf -ceq 'crg-attachment' -and $record.Present -and
        -not [Linq.Enumerable]::SequenceEqual([byte[]]$record.Bytes, [byte[]]$AttachmentBytes)) { throw 'pending context attachment differs from the captured proposal' }
  }
  $publicRef = & $readLine -Arguments ($publicGit + @('symbolic-ref', '--no-recurse', '-q', 'HEAD')) -GitExe $gitExe
  if ($publicRef -cne $attachment.PublicRef) { throw 'first attachment public branch differs from the proposed association' }
  & $assertGitState -Context $Context -PublicGitDir $gitDir -PrivateGitDir $attachment.PrivateGitDir -PublicRef $publicRef
  $domains = [ordered]@{}
  foreach ($domain in @('public', 'private')) {
    $directory = $gitDir; $common = $commonDir; $branch = $publicRef; $indexPath = Join-Path $gitDir 'index'
    if ($domain -ceq 'private') {
      $directory = $attachment.PrivateGitDir; $common = $directory; $branch = $attachment.PrivateRef
      $indexPath = Join-Path $gitDir 'crg-private-index'
    }
    $prefix = @("--git-dir=$directory", "--work-tree=$root")
    $actualCommon = (& $readLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $gitExe).Replace('/', '\')
    $objects = (& $readLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-path', 'objects')) -GitExe $gitExe).Replace('/', '\')
    $format = & $readLine -Arguments ($prefix + @('rev-parse', '--show-object-format')) -GitExe $gitExe
    if (-not [string]::Equals($actualCommon, $common, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($objects, (Join-Path $common 'objects'), [StringComparison]::OrdinalIgnoreCase) -or
        $format -cnotin @('sha1', 'sha256')) { throw 'first attachment Git namespace differs from the proposed domain' }
    foreach ($leaf in @('alternates', 'http-alternates')) {
      $record = & $Context.ReadFile -Path (Join-Path $objects ('info/' + $leaf)) -Maximum 65536 -AllowAbsent
      if ($null -eq $record -or $record.Present -isnot [bool] -or $record.Present) { throw 'first attachment requires positively absent object alternates' }
    }
    $index = & $Context.ReadFile -Path $indexPath -Maximum 268435456
    if ($null -eq $index -or $index.Present -isnot [bool] -or -not $index.Present -or $index.Bytes -isnot [byte[]]) { throw 'first attachment requires the existing captured candidate index for each domain' }
    $domains[$domain] = [pscustomobject]@{ GitDir = $directory; CommonDir = $common; ObjectDir = $objects
      IndexPath = $indexPath; Ref = $branch; Parent = $null; ParentTree = $null; ObjectFormat = $format }
  }
  $status = [pscustomobject]@{ ProjectId = $attachment.ProjectId; Attachment = 'unactivated proposed association'
    PublicRoot = $root; PublicGitDir = $gitDir; PublicCommonDir = $commonDir; PublicRef = $publicRef
    PrivateGitDir = $attachment.PrivateGitDir; PrivateRef = $attachment.PrivateRef }
  $result = [pscustomobject]@{ Schema = 1; Runtime = $Context; Root = $root; GitExe = $gitExe; Status = $status
    Domains = $domains; ValidationState = 'read-only-first-attachment-context'; ReadyForReview = $false }
  foreach ($domain in @('public', 'private')) {
    $selected = $domains[$domain]
    $parent = & $readRef -ProjectContext $result -Domain $domain -Ref $selected.Ref
    if ($null -eq $parent) {
      if ($domain -cne 'private') { throw 'first attachment requires an actual existing public commit' }
      $selected.Parent = 'absent'
      $hash = if ($selected.ObjectFormat -ceq 'sha1') { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
      try { $selected.ParentTree = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::ASCII.GetBytes('tree 0' + [char]0)))).Replace('-', '').ToLowerInvariant() }
      finally { $hash.Dispose() }
    } else {
      $prefix = @("--git-dir=$($selected.GitDir)", "--work-tree=$root")
      if ((& $readLine -Arguments ($prefix + @('cat-file', '-t', $parent)) -GitExe $gitExe) -cne 'commit') { throw 'first attachment adopted parent is not an actual commit' }
      $selected.Parent = $parent
      $selected.ParentTree = & $readLine -Arguments ($prefix + @('rev-parse', '--verify', "$parent^{tree}")) -GitExe $gitExe
    }
    # The attachment owner creates a real empty tree before new-history capture;
    # no placeholder OID establishes either object existence or adopted ancestry.
    $null = & $treeReader -ProjectContext $result -Domain $domain -TreeOid $selected.ParentTree
  }
  if ((& $readLine -Arguments ($publicGit + @('symbolic-ref', '--no-recurse', '-q', 'HEAD')) -GitExe $gitExe) -cne $publicRef) { throw 'first attachment public branch changed during capture' }
  foreach ($domain in @('public', 'private')) {
    $actual = & $readRef -ProjectContext $result -Domain $domain -Ref $domains[$domain].Ref
    $expected = $domains[$domain].Parent
    if (($expected -ceq 'absent' -and $null -ne $actual) -or ($expected -cne 'absent' -and $actual -cne $expected)) { throw 'first attachment branch parent changed during capture' }
  }
  return $result
}

Export-ModuleMember -Function Get-CrgCentralFirstAttachmentProjectContext
