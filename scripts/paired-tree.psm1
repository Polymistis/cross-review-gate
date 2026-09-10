# Tree listing syntax and namespace ownership only; no Git or filesystem access.

function Assert-CrgTreeNamespace {
  param([object[]]$Entries)
  # Preserve the existing Windows tree model. Only actual tree entries are
  # shareable containers: gitlinks and symlink blobs still occupy leaf names.
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  $prefixes = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in $Entries) {
    $path = $entry.Path
    if ([string]::IsNullOrEmpty($path) -or $path.StartsWith('/') -or $path.EndsWith('/') -or
        $path.Contains('//') -or $path.Contains('\')) { throw 'tree contains a non-canonical Windows path' }
    if (-not $seen.Add($path)) { throw "tree path '$path' is duplicated" }
    $components = @($path -split '/', 0)
    foreach ($component in $components) {
      if ([string]::IsNullOrEmpty($component) -or $component -ceq '.' -or $component -ceq '..' -or
          $component.Length -gt 255 -or $component -match '[\x00-\x1f<>:"\\|?*]' -or
          $component.EndsWith('.') -or $component.EndsWith(' ') -or
          $component -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)') {
        throw "tree path '$path' has a component that Windows cannot represent injectively"
      }
    }
    for ($i = 0; $i -lt $components.Count; $i++) {
      $prefix = [string]::Join('/', $components[0..$i])
      $kind = if ($i -lt $components.Count - 1 -or $entry.Mode -ceq '040000') { 'D' } else { 'F' }
      $existing = $null
      if ($prefixes.TryGetValue($prefix, [ref]$existing)) {
        if ($existing.Path -cne $prefix) { throw "tree path '$path' has a Windows case-folding prefix collision" }
        if ($existing.Kind -cne $kind) { throw "tree path '$path' has a file/directory-prefix collision" }
      } else { $prefixes.Add($prefix, [pscustomobject]@{ Path = $prefix; Kind = $kind }) }
    }
  }
}

function Read-CrgGitTreeBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$ObjectFormat)
  if ($null -eq $Bytes) { throw 'tree listing must be an explicit byte buffer, not null' }
  if ($Bytes.Length -gt 0 -and $Bytes[$Bytes.Length - 1] -ne 0) { throw 'tree listing is missing its final NUL' }
  $width = if ($ObjectFormat -ceq 'sha1') { 40 } elseif ($ObjectFormat -ceq 'sha256') { 64 } else { throw 'tree object format must be canonical sha1 or sha256' }
  $headerPattern = '\A(?<mode>[0-9]{6}) (?<type>blob|tree|commit) (?<oid>[0-9a-f]{' + $width + '})\z'
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  $entries = New-Object 'System.Collections.Generic.List[object]'
  $start = 0
  for ($end = 0; $end -lt $Bytes.Length; $end++) {
    if ($Bytes[$end] -ne 0) { continue }
    if ($end -eq $start) { throw 'tree listing contains an empty NUL record' }
    $tab = $start
    while ($tab -lt $end -and $Bytes[$tab] -ne 9) {
      if ($Bytes[$tab] -gt 127) { throw 'tree listing header is not ASCII' }
      $tab++
    }
    if ($tab -eq $end) { throw 'tree listing record has no header/path tab separator' }
    $header = [Text.Encoding]::ASCII.GetString($Bytes, $start, $tab - $start)
    if ($header -cnotmatch $headerPattern) { throw 'tree listing header has invalid mode, type, or object ID grammar' }
    $mode = [string]$Matches['mode']; $type = [string]$Matches['type']; $oid = [string]$Matches['oid']
    if (-not (($mode -cin @('100644', '100755', '120000') -and $type -ceq 'blob') -or
        ($mode -ceq '160000' -and $type -ceq 'commit') -or ($mode -ceq '040000' -and $type -ceq 'tree'))) {
      throw 'tree listing has an unsupported mode/type pair'
    }
    try { $path = $utf8.GetString($Bytes, $tab + 1, $end - $tab - 1) } catch { throw 'tree listing path is not strict UTF-8' }
    $entries.Add([pscustomobject]@{ Path = $path; Mode = $mode; Type = $type; Oid = $oid })
    $start = $end + 1
  }
  $result = $entries.ToArray()
  Assert-CrgTreeNamespace -Entries $result
  return ,$result
}

function Read-CrgPairedTreeBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$PublicTreeBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$PrivateTreeBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$GoverningConfigBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$CandidateConfigBytes)
  $public = Read-CrgGitTreeBytes -Bytes $PublicTreeBytes -ObjectFormat $PublicObjectFormat
  $private = Read-CrgGitTreeBytes -Bytes $PrivateTreeBytes -ObjectFormat $PrivateObjectFormat
  $combined = New-Object 'System.Collections.Generic.List[object]'
  $byPath = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in @($public) + @($private)) {
    $existing = $null
    if ($byPath.TryGetValue($entry.Path, [ref]$existing)) {
      if ($existing.Path -cne $entry.Path) { throw "paired tree path '$($entry.Path)' has a Windows case alias" }
      if ($existing.Mode -cne '040000' -or $entry.Mode -cne '040000') { throw "paired trees collide at occupied leaf '$($entry.Path)'" }
      # Sharing a container does not equate or replace separate database OIDs.
    } else { $byPath.Add($entry.Path, $entry); $combined.Add($entry) }
  }
  Assert-CrgTreeNamespace -Entries $combined.ToArray()
  [string[]]$paths = @($combined | ForEach-Object { $_.Path })
  # The retained-runtime caller imports dependencies; never resolve a module
  # through ambient search paths or treat this data parser as runtime authority.
  $classifier = @(Get-Command -Name Get-CrgPathOwnership -Module private-governance -CommandType Function -ListImported -ErrorAction Stop)
  if ($classifier.Count -ne 1) { throw 'paired tree parsing requires one already imported private-governance classifier' }
  $ownership = & $classifier[0] -GoverningConfigBytes $GoverningConfigBytes -CandidateConfigBytes $CandidateConfigBytes -Paths $paths
  $configReader = @(Get-Command -Name Read-CrgProjectConfigBytes -Module private-governance -CommandType Function -ListImported -ErrorAction Stop)
  if ($configReader.Count -ne 1) { throw 'paired tree parsing requires one already imported private-governance configuration reader' }
  $candidate = & $configReader[0] -Bytes $CandidateConfigBytes
  $declaredFiles = @($candidate.PrivateFiles) + @('AGENTS.md', 'CLAUDE.md', 'CROSS-REVIEW-VALUES.md', 'PROJECT-MODE.md', 'PLAN.md', 'History.md') + @($candidate.Roles | ForEach-Object { $_.Path })
  if ($null -ne $candidate.ConsistencyDocument) { $declaredFiles += $candidate.ConsistencyDocument.Path }
  # Only the candidate declares candidate shapes. The preceding inventory still
  # reserves private ownership, without preventing an explicit shape transition.
  foreach ($path in $declaredFiles) {
    if (($byPath.ContainsKey($path) -and $byPath[$path].Mode -ceq '040000') -or
        @($paths | Where-Object { $_.StartsWith($path + '/', [StringComparison]::Ordinal) }).Count -gt 0) { throw "candidate file declaration '$path' conflicts with a tree directory" }
  }
  foreach ($path in @($candidate.PrivateDirectories) + $declaredFiles) {
    if ($path -cin $candidate.PrivateDirectories -and $byPath.ContainsKey($path) -and $byPath[$path].Mode -cne '040000') { throw "candidate directory declaration '$path' conflicts with a tree leaf" }
    $parent = $path
    while ($parent.Contains('/')) {
      $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
      if ($byPath.ContainsKey($parent) -and $byPath[$parent].Mode -cne '040000') { throw "candidate declaration '$path' has an occupied file parent" }
    }
  }
  $owners = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
  foreach ($item in $ownership) { $owners.Add($item.Path, $item.Ownership) }
  foreach ($domain in @([pscustomobject]@{ Name = 'public'; Entries = $public }, [pscustomobject]@{ Name = 'private'; Entries = $private })) {
    foreach ($entry in $domain.Entries) {
      if ($entry.Mode -cne '040000' -and $owners[$entry.Path] -cne $domain.Name) {
        throw "$($domain.Name) tree leaf '$($entry.Path)' disagrees with preceding/candidate private ownership"
      }
    }
  }
  return [pscustomobject]@{ PublicEntries = $public; PrivateEntries = $private; Ownership = $ownership }
}

Export-ModuleMember -Function Read-CrgGitTreeBytes, Read-CrgPairedTreeBytes
