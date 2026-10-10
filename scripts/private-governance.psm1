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
  # Ordinal: -cne/-in/-cin and string overloads compare by culture and ignore characters such as U+00AD.
  if ([string]::IsNullOrWhiteSpace($Path) -or -not [string]::Equals($Path, $Path.Trim(), [StringComparison]::Ordinal)) { throw 'governance path is empty or has surrounding whitespace' }
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
    if ($part.Length -eq 0 -or [string]::Equals($part, '.', [StringComparison]::Ordinal) -or [string]::Equals($part, '..', [StringComparison]::Ordinal) -or
        $part.EndsWith('.', [StringComparison]::Ordinal) -or -not [string]::Equals($part, $part.Trim(), [StringComparison]::Ordinal) -or
        $part -match '[<>:"|?*\x00-\x1f\x7f]' -or
        $part -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)' -or
        (-not $AllowGitMetadata -and [string]::Equals($part, '.git', [StringComparison]::OrdinalIgnoreCase))) { throw "governance path '$Path' has an unsupported component" }
  }
}

function Assert-CrgGovernanceBranchRef {
  param([string]$Ref)
  if (-not $Ref.StartsWith('refs/heads/', [StringComparison]::Ordinal) -or $Ref -match '[\s~^?*\[\\]' -or
      $Ref.Contains('..') -or $Ref.Contains('@{')) { throw 'attachment ref must be one canonical full branch ref' }
  Assert-CrgGovernancePath -Path $Ref
  foreach ($part in @($Ref -split '/', 0)) {
    if ($part.StartsWith('.', [StringComparison]::Ordinal) -or $part.EndsWith('.lock', [StringComparison]::OrdinalIgnoreCase)) { throw 'attachment ref has an invalid Git ref component' }
  }
}

function Read-CrgAttachmentBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes)
  $lines = Read-CrgGovernanceRecords -Bytes $Bytes -Maximum 16384 -Label 'attachment'
  if ($lines.Count -ne 6 -or -not [string]::Equals($lines[0], 'crg-attachment v1', [StringComparison]::Ordinal)) { throw 'attachment must contain the six v1 records' }
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
    if (-not [string]::Equals([IO.Path]::GetFullPath($path), $path, [StringComparison]::Ordinal)) { throw 'private storage admission requires canonical captured paths' }
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

# Central Grok profile table (operator ruling 2026-09-23). Projects name at most
# a profile; the runtime release owns what each profile runs, so a model or
# effort change is one reviewed release and one activation, never an edit in
# every attached project. `recommended` applies when a project names none.
function Get-CrgGrokProfileTable {
  return @{
    'recommended' = [pscustomobject]@{ Profile = 'recommended'; Model = 'grok-4.7'; Effort = 'xhigh'; Transport = 'cli'; Authentication = 'local-login' }
    'strong' = [pscustomobject]@{ Profile = 'strong'; Model = 'grok-4.7'; Effort = 'high'; Transport = 'cli'; Authentication = 'local-login' }
    'fast' = [pscustomobject]@{ Profile = 'fast'; Model = 'grok-4.7-build-fast'; Effort = 'high'; Transport = 'cli'; Authentication = 'local-login' }
  }
}

# Every (profile, model, effort) any release's table has mapped: the current
# table plus retired entries. When a table entry changes, append its old value
# to $retired; never remove one while history may still name it. Each review
# records the runtime manifest ID of the release whose table ran it, but push
# guards revalidate the whole retained chain under the current release without
# loading retained releases, so they need every mapping any release has had.
function Get-CrgGrokProfileHistory {
  $retired = @()
  return @($retired) + @((Get-CrgGrokProfileTable).Values | ForEach-Object {
    [pscustomobject]@{ Profile = $_.Profile; Model = $_.Model; Effort = $_.Effort } })
}

# The `model|effort` identities a review governed by $Config could have run:
# every historical mapping of the governing profile, plus, for a legacy
# `grok-provider` record, the exact model it named at xhigh, which is what
# releases before 2.4.0 requested. Live acceptance binds exactly to the
# current table instead; this set is for re-validating retained history.
function Get-CrgGrokAllowedIdentities {
  param([object]$Config)
  # Returned unrolled; callers collect with @(...) to get a flat string array.
  # A `return ,$array` here nests the array inside the caller's @(...), which
  # makes every membership check fail.
  if ($null -eq $Config -or -not [string]::Equals($Config.ReviewerPolicy, 'grok-fallback', [StringComparison]::Ordinal) -or $null -eq $Config.Grok) { return }
  $allowed = New-Object 'System.Collections.Generic.List[string]'
  foreach ($entry in @(Get-CrgGrokProfileHistory)) {
    if ($entry.Profile -ceq $Config.Grok.Profile) { $allowed.Add($entry.Model + '|' + $entry.Effort) }
  }
  if ($null -ne $Config.Grok.LegacyRecord) { $allowed.Add($Config.Grok.LegacyModel + '|xhigh') }
  return $allowed.ToArray()
}

function Read-CrgProjectConfigBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes)
  $lines = Read-CrgGovernanceRecords -Bytes $Bytes -Maximum 65536 -Label 'project configuration'
  if ($lines.Count -lt 7 -or -not [string]::Equals($lines[0], 'crg-project v1', [StringComparison]::Ordinal) -or
      -not ([string]::Equals($lines[1], 'reviewer-policy default', [StringComparison]::Ordinal) -or [string]::Equals($lines[1], 'reviewer-policy grok-fallback', [StringComparison]::Ordinal))) {
    throw 'project configuration has an invalid header, reviewer policy, or required record count'
  }
  $consistency = $null
  if (-not [string]::Equals($lines[2], 'consistency-document -', [StringComparison]::Ordinal)) {
    if ($lines[2] -cnotmatch '\Aconsistency-document (private|public) (.+)\z') { throw 'consistency-document requires private/public scope and path, or -' }
    $consistency = [pscustomobject]@{ Scope = [string]$Matches[1]; Path = [string]$Matches[2] }
    Assert-CrgGovernancePath -Path $consistency.Path
  }
  $reviewerPolicy = $lines[1].Substring('reviewer-policy '.Length)
  $grok = $null; $inventoryStart = 3
  if ([string]::Equals($reviewerPolicy, 'grok-fallback', [StringComparison]::Ordinal)) {
    # Only reviewed governing policy enables the provider; an installed CLI or
    # available credential does not change routing policy. The optional record
    # names a central profile. A legacy `grok-provider` record from releases
    # before 2.4.0 still parses forever (push guards and completed-pair reads
    # re-parse history) and selects the `recommended` profile's model and
    # effort (operator ruling 2026-09-23: the central runtime owns the model),
    # but keeps its own transport and authentication: the account route that
    # carries review material never changes without a reviewed record change.
    $profileName = 'recommended'; $legacy = $null; $legacyModel = $null; $legacyTransport = $null; $legacyAuthentication = $null
    if ($lines[3] -cmatch '\Agrok-profile (recommended|strong|fast)\z') {
      $profileName = [string]$Matches[1]; $inventoryStart = 4
    } elseif ($lines[3] -cmatch '\Agrok-provider ') {
      if ($lines[3] -cnotmatch '\Agrok-provider (api|cli) (grok-4\.6|grok-4\.7) xhigh (environment-key|local-login)\z' -or
          ($Matches[1] -ceq 'api') -ne ($Matches[3] -ceq 'environment-key')) {
        throw 'legacy grok-provider record has an unsupported transport, authentication, model or effort'
      }
      $legacy = $lines[3]; $legacyTransport = [string]$Matches[1]; $legacyModel = [string]$Matches[2]; $legacyAuthentication = [string]$Matches[3]
      $inventoryStart = 4
    } elseif ($lines[3] -cmatch '\Agrok-profile ') {
      throw 'grok-profile must name recommended, strong or fast'
    }
    $entry = (Get-CrgGrokProfileTable)[$profileName]
    $transport = if ($null -ne $legacy) { $legacyTransport } else { $entry.Transport }
    $authentication = if ($null -ne $legacy) { $legacyAuthentication } else { $entry.Authentication }
    $grok = [pscustomobject]@{ Profile = $entry.Profile; Model = $entry.Model; Effort = $entry.Effort
      Transport = $transport; Authentication = $authentication
      LegacyRecord = $legacy; LegacyModel = $legacyModel }
  }
  # Optional code unit-test loosening (operator ruling 2026-10-07: the ban stays
  # the default and a project may loosen it only by reviewed configuration).
  # Absent records mean banned, so every configuration written before 2.5.0
  # keeps parsing to the ban; releases before 2.5.0 reject these records.
  # Folders are quoted verbatim into the compiled review policy, so their
  # components are limited to letters, digits, '.', '_' and '-': no folder can
  # carry markup or prose into that policy, and no escaping layer is needed.
  $unitTestMode = $null
  $unitTestPaths = New-Object 'System.Collections.Generic.List[string]'
  $unitTestSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  if ($inventoryStart -lt $lines.Count -and [string]::Equals($lines[$inventoryStart], 'unit-tests allowed-in-mode prototype', [StringComparison]::Ordinal)) {
    $unitTestMode = 'prototype'; $inventoryStart++
  }
  while ($inventoryStart -lt $lines.Count -and $lines[$inventoryStart].StartsWith('unit-tests ', [StringComparison]::Ordinal)) {
    if ($lines[$inventoryStart] -cnotmatch '\Aunit-tests allowed-path (.+)\z') {
      throw "project configuration record $($inventoryStart + 1) is not a canonical unit-tests record (allowed-in-mode prototype first, then allowed-path <folder>)"
    }
    $path = [string]$Matches[1]
    Assert-CrgGovernancePath -Path $path
    if ($path -cnotmatch '\A[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*\z') {
      throw "unit-tests allowed-path '$path' may use only letters, digits, '.', '_' and '-' in each folder name"
    }
    if (-not $unitTestSeen.Add($path)) { throw "unit-tests allowed-path '$path' is duplicated or a Windows case alias" }
    $unitTestPaths.Add($path)
    if ($unitTestPaths.Count -gt 64) { throw 'project configuration has too many unit-tests allowed-path records' }
    $inventoryStart++
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
    if ($spellings.ContainsKey($path) -and -not [string]::Equals($spellings[$path], $path, [StringComparison]::Ordinal)) { throw "project configuration path '$path' has a Windows case alias" }
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
    if ($spellings.ContainsKey($consistency.Path) -and -not [string]::Equals($spellings[$consistency.Path], $consistency.Path, [StringComparison]::Ordinal)) { throw 'consistency-document has a Windows case alias' }
    $private = $privateSeen.Contains($consistency.Path) -or [System.Linq.Enumerable]::Contains([string[]]$fixed, [string]$consistency.Path, [StringComparer]::Ordinal)
    foreach ($directory in $directories) {
      if ($consistency.Path.StartsWith($directory + '/', [StringComparison]::OrdinalIgnoreCase)) { $private = $true }
    }
    if (($consistency.Scope -ceq 'private') -ne $private) { throw 'consistency-document scope disagrees with private inventory' }
    if ($directories.Contains($consistency.Path)) { throw 'consistency-document names a private directory' }
  }
  return [pscustomobject]@{
    Schema = 1; ReviewerPolicy = $reviewerPolicy; Grok = $grok; ConsistencyDocument = $consistency
    UnitTests = [pscustomobject]@{ AllowedInMode = $unitTestMode; AllowedPaths = $unitTestPaths.ToArray() }
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
    if ($Spellings.ContainsKey($prefix) -and -not [string]::Equals($Spellings[$prefix], $prefix, [StringComparison]::Ordinal)) { throw "ownership path '$Path' has a Windows path or prefix case alias" }
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
  # Unit-test folders own nothing, but they name repository paths in review
  # policy, so their spelling must agree with every other reference and the
  # captured tree.
  foreach ($path in @($Config.UnitTests.AllowedPaths)) { $null = Add-CrgOwnershipSpelling -Path $path -Spellings $Spellings }
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
        if ([string]::Equals($path, $directory, [StringComparison]::Ordinal) -or $path.StartsWith($directory + '/', [StringComparison]::Ordinal)) { $private[$i] = $true }
      }
    }
    $mandatory = [System.Linq.Enumerable]::Contains([string[]]$mandatoryFiles, [string]$path, [StringComparer]::Ordinal) -or [string]::Equals($path, '.crg-project', [StringComparison]::Ordinal) -or $path.StartsWith('.crg-project/', [StringComparison]::Ordinal)
    $ownership = 'public'
    if ($private[0] -or $private[1] -or $mandatory) { $ownership = 'private' }
    $results.Add([pscustomobject]@{ Path = $path; Ownership = $ownership; GoverningPrivate = $private[0]; CandidatePrivate = $private[1]; MandatoryPrivate = $mandatory })
  }
  return ,$results.ToArray()
}

# Capture-time only. The parser must keep accepting legacy `grok-provider`
# records because push guards and retention re-parse historical
# configuration; refusing them there would break validation of that history.
# A new review input is the only point where a candidate record can become
# governing, so new configuration is steered to `grok-profile` here: a legacy
# record may persist unchanged but may not be introduced or edited.
function Assert-CrgCandidateGrokRecord {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$CandidateConfigBytes,
    [AllowNull()][AllowEmptyCollection()][byte[]]$GoverningConfigBytes)
  $candidate = Read-CrgProjectConfigBytes -Bytes $CandidateConfigBytes
  if ($null -eq $candidate.Grok -or $null -eq $candidate.Grok.LegacyRecord) { return }
  $unchanged = $false
  if ($null -ne $GoverningConfigBytes) {
    $governing = Read-CrgProjectConfigBytes -Bytes $GoverningConfigBytes
    $unchanged = $null -ne $governing.Grok -and $governing.Grok.LegacyRecord -ceq $candidate.Grok.LegacyRecord
  }
  if (-not $unchanged) { throw 'a new or changed grok-provider record is not accepted; name a central profile with grok-profile recommended|strong|fast, or omit the record for recommended' }
}

Export-ModuleMember -Function Read-CrgAttachmentBytes, Assert-CrgPrivateStorageLocation, Read-CrgProjectConfigBytes, Get-CrgPathOwnership, Assert-CrgCandidateGrokRecord, Get-CrgGrokProfileTable, Get-CrgGrokProfileHistory, Get-CrgGrokAllowedIdentities
