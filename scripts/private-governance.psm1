# Byte-buffer parsing and literal ownership only; no filesystem or commit authority.

function Read-CrgGovernanceRecords {
  param([AllowNull()][byte[]]$Bytes, [int]$Maximum, [string]$Label)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt $Maximum -or $Bytes[$Bytes.Length - 1] -ne 10) {
    throw "$Label has an invalid byte length or missing final LF"
  }
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) { throw "$Label contains a BOM" }
  foreach ($value in $Bytes) {
    if (($value -lt 32 -and $value -ne 10) -or $value -eq 127) { throw "$Label contains a prohibited control byte" }
  }
  $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
  try { $text = $utf8.GetString($Bytes) } catch { throw "$Label is not strict UTF-8" }
  [string[]]$records = $text.Substring(0, $text.Length - 1) -split "`n", 0
  if (@($records | Where-Object { $_.Length -eq 0 }).Count -ne 0) { throw "$Label contains a blank record" }
  return ,$records
}

function Assert-CrgGovernancePath {
  param([string]$Path, [switch]$Absolute, [switch]$AllowGitMetadata)
  if ([string]::IsNullOrWhiteSpace($Path) -or $Path -cne $Path.Trim()) { throw 'governance path is empty or has surrounding whitespace' }
  if ($Absolute) {
    if ($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Contains('/')) { throw 'attachment path must use an absolute local drive and backslashes' }
    $relative = $Path.Substring(3)
    $separator = '\\'
  } else {
    $relative = $Path
    $separator = '/'
    if ($Path.Contains('\')) { throw 'governance relative path must use forward slashes' }
  }
  foreach ($part in @($relative -split $separator, 0)) {
    # Match the existing native leaf boundary; additionally reject Win32 aliases
    # before a later caller can turn these strings into literal filesystem paths.
    if ($part.Length -eq 0 -or $part -in @('.', '..') -or $part.EndsWith('.') -or $part -cne $part.Trim() -or
        $part -match '[<>:"|?*\x00-\x1f\x7f]' -or
        $part -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)' -or
        (-not $AllowGitMetadata -and $part -ieq '.git')) { throw "governance path '$Path' has an unsupported component" }
  }
}

function Assert-CrgGovernanceBranchRef {
  param([string]$Ref)
  if (-not $Ref.StartsWith('refs/heads/', [StringComparison]::Ordinal) -or $Ref -match '[\s~^?*\[\\]' -or
      $Ref.Contains('..') -or $Ref.Contains('@{')) { throw 'attachment ref must be one canonical full branch ref' }
  Assert-CrgGovernancePath -Path $Ref
  foreach ($part in @($Ref -split '/', 0)) {
    if ($part.StartsWith('.') -or $part.EndsWith('.lock', [StringComparison]::OrdinalIgnoreCase)) { throw 'attachment ref has an invalid Git ref component' }
  }
}

function Read-CrgAttachmentBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes)
  $lines = Read-CrgGovernanceRecords -Bytes $Bytes -Maximum 16384 -Label 'attachment'
  if ($lines.Count -ne 6 -or $lines[0] -cne 'crg-attachment v1') { throw 'attachment must contain the six v1 records' }
  $fields = @('project-id', 'runtime-store', 'private-git-dir', 'public-ref', 'private-ref')
  $values = @{}
  for ($i = 0; $i -lt $fields.Count; $i++) {
    $prefix = $fields[$i] + ' '
    if (-not $lines[$i + 1].StartsWith($prefix, [StringComparison]::Ordinal)) { throw "attachment is missing ordered field '$($fields[$i])'" }
    $value = $lines[$i + 1].Substring($prefix.Length)
    if ([string]::IsNullOrWhiteSpace($value)) { throw "attachment field '$($fields[$i])' is empty" }
    $values[$fields[$i]] = $value
  }
  if ($values['project-id'] -cnotmatch '\A[0-9a-f]{32}\z') { throw 'attachment project ID is not canonical lowercase hexadecimal' }
  Assert-CrgGovernancePath -Path $values['runtime-store'] -Absolute
  Assert-CrgGovernancePath -Path $values['private-git-dir'] -Absolute -AllowGitMetadata
  Assert-CrgGovernanceBranchRef -Ref $values['public-ref']
  Assert-CrgGovernanceBranchRef -Ref $values['private-ref']
  return [pscustomobject]@{
    Schema = 1; ProjectId = $values['project-id']; RuntimeStore = $values['runtime-store']
    PrivateGitDir = $values['private-git-dir']; PublicRef = $values['public-ref']; PrivateRef = $values['private-ref']
  }
}

function Assert-CrgPrivateStorageLocation {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$PublicRoot,
    [Parameter(Mandatory = $true)][string]$PublicGitDir,
    [Parameter(Mandatory = $true)][string]$PublicCommonDir,
    [Parameter(Mandatory = $true)][string]$PrivateGitDir)
  foreach ($path in @($PublicRoot, $PublicGitDir, $PublicCommonDir, $PrivateGitDir)) {
    Assert-CrgGovernancePath -Path $path -Absolute -AllowGitMetadata
    if ([IO.Path]::GetFullPath($path) -cne $path) { throw 'private storage admission requires canonical captured paths' }
  }
  $comparison = [StringComparison]::OrdinalIgnoreCase
  $publicObjects = Join-Path $PublicCommonDir 'objects'
  if ([string]::Equals($PrivateGitDir, $PublicRoot, $comparison) -or
      [string]::Equals($PrivateGitDir, $PublicGitDir, $comparison) -or
      [string]::Equals($PrivateGitDir, $PublicCommonDir, $comparison) -or
      [string]::Equals($PrivateGitDir, $publicObjects, $comparison) -or
      $PrivateGitDir.StartsWith($publicObjects + '\', $comparison) -or
      $PublicRoot.StartsWith($PrivateGitDir + '\', $comparison)) {
    throw 'private storage requires a distinct database outside the public object store and must not contain the public worktree'
  }
  if ($PrivateGitDir.StartsWith($PublicRoot + '\', $comparison)) {
    $dotGit = Join-Path $PublicRoot '.git'
    # Configured ownership cannot protect Git's internal object/review files:
    # a later public add could ingest storage beneath an ordinary worktree
    # directory. Only the actual protected .git metadata boundary is exempt;
    # a custom Git directory inside the worktree is still publicly stageable.
    $protectedMetadata = [string]::Equals($dotGit, $PublicGitDir, $comparison) -or
      [string]::Equals($dotGit, $PublicCommonDir, $comparison)
    if (-not $protectedMetadata -or -not $PrivateGitDir.StartsWith($dotGit + '\', $comparison)) {
      throw 'private storage must be outside the public worktree or beneath the actual public .git metadata directory'
    }
  }
}

function Read-CrgProjectConfigBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes)
  $lines = Read-CrgGovernanceRecords -Bytes $Bytes -Maximum 65536 -Label 'project configuration'
  if ($lines.Count -lt 7 -or $lines[0] -cne 'crg-project v1' -or $lines[1] -cnotin @('reviewer-policy default', 'reviewer-policy grok-fallback')) {
    throw 'project configuration has an invalid header, reviewer policy, or required record count'
  }
  $consistency = $null
  if ($lines[2] -cne 'consistency-document -') {
    if ($lines[2] -cnotmatch '\Aconsistency-document (private|public) (.+)\z') { throw 'consistency-document requires private/public scope and path, or -' }
    $consistency = [pscustomobject]@{ Scope = [string]$Matches[1]; Path = [string]$Matches[2] }
    Assert-CrgGovernancePath -Path $consistency.Path
  }
  $reviewerPolicy = $lines[1].Substring('reviewer-policy '.Length)
  $grok = $null; $inventoryStart = 3
  if ($reviewerPolicy -ceq 'grok-fallback') {
    # Only a reviewed transport/authentication pair enables the provider;
    # an installed CLI or available credential does not change routing policy.
    if ($lines[3] -ceq 'grok-provider api grok-4.6 xhigh environment-key') {
      $grok = [pscustomobject]@{ Transport = 'api'; Model = 'grok-4.6'; Effort = 'xhigh'; Authentication = 'environment-key' }
    } elseif ($lines[3] -ceq 'grok-provider cli grok-4.6 xhigh local-login') {
      $grok = [pscustomobject]@{ Transport = 'cli'; Model = 'grok-4.6'; Effort = 'xhigh'; Authentication = 'local-login' }
    } else { throw 'Grok fallback requires the supported API/environment-key or CLI/local-login maximum-effort record' }
    $inventoryStart = 4
  }
  $directories = New-Object 'System.Collections.Generic.List[string]'
  $files = New-Object 'System.Collections.Generic.List[string]'
  $roles = New-Object 'System.Collections.Generic.List[object]'
  $privateSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $roleSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $spellings = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
  $fixed = @('.crg-project', 'AGENTS.md', 'CLAUDE.md', 'CROSS-REVIEW-VALUES.md', 'PROJECT-MODE.md', 'PLAN.md', 'History.md')
  foreach ($path in $fixed) { $spellings.Add($path, $path) }
  $group = 0
  for ($i = $inventoryStart; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $description = $null
    if ($line -cmatch '\Aprivate-directory (.+)\z') { $kind = 1; $path = [string]$Matches[1] }
    elseif ($line -cmatch '\Aprivate-file (.+)\z') { $kind = 2; $path = [string]$Matches[1] }
    elseif ($line -cmatch '\Arole (.+) \| ([^|]+)\z') { $kind = 3; $path = [string]$Matches[1]; $description = [string]$Matches[2] }
    else { throw "project configuration record $($i + 1) has an unknown field or invalid grammar" }
    if ($kind -lt $group) { throw 'project configuration record groups are out of order' }
    $group = $kind
    Assert-CrgGovernancePath -Path $path
    if ($spellings.ContainsKey($path) -and $spellings[$path] -cne $path) { throw "project configuration path '$path' has a Windows case alias" }
    if (-not $spellings.ContainsKey($path)) { $spellings.Add($path, $path) }
    if ($kind -eq 3) {
      if (-not $roleSeen.Add($path)) { throw "document role '$path' is duplicated" }
      if ([string]::IsNullOrWhiteSpace($description) -or [Text.Encoding]::UTF8.GetByteCount($description) -gt 1024) { throw 'document role description is empty or oversized' }
      $roles.Add([pscustomobject]@{ Path = $path; Description = $description })
      if ($roles.Count -gt 128) { throw 'project configuration has too many document roles' }
    } else {
      if (-not $privateSeen.Add($path)) { throw "private inventory path '$path' is duplicated" }
      if ($kind -eq 1) { $directories.Add($path) } else { $files.Add($path) }
      if ($privateSeen.Count -gt 256) { throw 'project configuration has too many private paths' }
    }
  }
  if (-not $directories.Contains('.crg-project')) { throw 'project configuration must include private-directory .crg-project' }
  foreach ($path in @('AGENTS.md', 'CLAUDE.md', 'CROSS-REVIEW-VALUES.md')) {
    if (-not $files.Contains($path)) { throw "project configuration must include private-file $path" }
  }
  if ($null -ne $consistency) {
    if ($spellings.ContainsKey($consistency.Path) -and $spellings[$consistency.Path] -cne $consistency.Path) { throw 'consistency-document has a Windows case alias' }
    $private = $privateSeen.Contains($consistency.Path) -or $consistency.Path -cin $fixed
    foreach ($directory in $directories) {
      if ($consistency.Path.StartsWith($directory + '/', [StringComparison]::OrdinalIgnoreCase)) { $private = $true }
    }
    if (($consistency.Scope -ceq 'private') -ne $private) { throw 'consistency-document scope disagrees with private inventory' }
    if ($directories.Contains($consistency.Path)) { throw 'consistency-document names a private directory' }
  }
  return [pscustomobject]@{
    Schema = 1; ReviewerPolicy = $reviewerPolicy; Grok = $grok; ConsistencyDocument = $consistency
    PrivateDirectories = $directories.ToArray(); PrivateFiles = $files.ToArray(); Roles = $roles.ToArray()
  }
}

function Add-CrgOwnershipSpelling {
  param([string]$Path, [System.Collections.Generic.Dictionary[string,string]]$Spellings)
  Assert-CrgGovernancePath -Path $Path
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  try { $null = $utf8.GetByteCount($Path) } catch { throw 'ownership path is not representable as strict UTF-8' }
  $prefixes = New-Object 'System.Collections.Generic.List[string]'
  $prefix = ''
  foreach ($part in @($Path -split '/', 0)) {
    if ($prefix.Length -eq 0) { $prefix = $part } else { $prefix += '/' + $part }
    if ($Spellings.ContainsKey($prefix) -and $Spellings[$prefix] -cne $prefix) { throw "ownership path '$Path' has a Windows path or prefix case alias" }
    if (-not $Spellings.ContainsKey($prefix)) { $Spellings.Add($prefix, $prefix) }
    $prefixes.Add($prefix)
  }
  return ,$prefixes.ToArray()
}

function Read-CrgOwnershipInventory {
  param($Config, [string[]]$MandatoryFiles, [System.Collections.Generic.Dictionary[string,string]]$Spellings)
  $files = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  $directories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  $privateFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($path in @($Config.PrivateFiles) + $MandatoryFiles) { $null = $privateFiles.Add($path) }
  foreach ($path in $Config.PrivateDirectories) {
    $prefixes = Add-CrgOwnershipSpelling -Path $path -Spellings $Spellings
    foreach ($prefix in $prefixes) { $null = $directories.Add($prefix) }
  }
  $filePaths = @($privateFiles) + @($Config.Roles | ForEach-Object { $_.Path })
  if ($null -ne $Config.ConsistencyDocument) { $filePaths += $Config.ConsistencyDocument.Path }
  foreach ($path in $filePaths) {
    $prefixes = Add-CrgOwnershipSpelling -Path $path -Spellings $Spellings
    for ($i = 0; $i -lt $prefixes.Count - 1; $i++) { $null = $directories.Add($prefixes[$i]) }
    $null = $files.Add($path)
  }
  foreach ($path in $files) {
    if ($directories.Contains($path)) { throw "configuration path '$path' is declared as both a file and a directory prefix" }
  }
  # Shapes are checked per version; a file/directory transition across versions
  # is legitimate. The union below retains private ownership during that change.
  return [pscustomobject]@{ Files = $privateFiles; Directories = $Config.PrivateDirectories }
}

function Get-CrgPathOwnership {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$GoverningConfigBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$CandidateConfigBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][string[]]$Paths)
  $governing = Read-CrgProjectConfigBytes -Bytes $GoverningConfigBytes
  $candidate = Read-CrgProjectConfigBytes -Bytes $CandidateConfigBytes
  if ($null -eq $Paths) { throw 'ownership paths must be an explicit array, not null' }
  $mandatoryFiles = @('AGENTS.md', 'CLAUDE.md', 'CROSS-REVIEW-VALUES.md', 'PROJECT-MODE.md', 'PLAN.md', 'History.md')
  $spellings = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
  $inventories = @(
    (Read-CrgOwnershipInventory -Config $governing -MandatoryFiles $mandatoryFiles -Spellings $spellings),
    (Read-CrgOwnershipInventory -Config $candidate -MandatoryFiles $mandatoryFiles -Spellings $spellings)
  )
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($path in $Paths) {
    $null = Add-CrgOwnershipSpelling -Path $path -Spellings $spellings
    if (-not $seen.Add($path)) { throw "ownership path '$path' is duplicated" }
  }
  $results = New-Object 'System.Collections.Generic.List[object]'
  foreach ($path in $Paths) {
    $private = @($false, $false)
    for ($i = 0; $i -lt $inventories.Count; $i++) {
      $private[$i] = $inventories[$i].Files.Contains($path)
      foreach ($directory in $inventories[$i].Directories) {
        if ($path -ceq $directory -or $path.StartsWith($directory + '/', [StringComparison]::Ordinal)) { $private[$i] = $true }
      }
    }
    $mandatory = $path -cin $mandatoryFiles -or $path -ceq '.crg-project' -or $path.StartsWith('.crg-project/', [StringComparison]::Ordinal)
    $ownership = 'public'
    if ($private[0] -or $private[1] -or $mandatory) { $ownership = 'private' }
    $results.Add([pscustomobject]@{ Path = $path; Ownership = $ownership; GoverningPrivate = $private[0]; CandidatePrivate = $private[1]; MandatoryPrivate = $mandatory })
  }
  return ,$results.ToArray()
}

Export-ModuleMember -Function Read-CrgAttachmentBytes, Assert-CrgPrivateStorageLocation, Read-CrgProjectConfigBytes, Get-CrgPathOwnership
