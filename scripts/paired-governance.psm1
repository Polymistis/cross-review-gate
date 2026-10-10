# Record identity only: parsed receipts cannot recreate live review authorization.

# Get-CrgPairSemanticVerdict must classify a verdict with the same grammar as the
# review hosts, so Get-VerdictExitCode comes from the shared review functions
# rather than a copy. The explicit export list keeps every dot-sourced function
# private to this module. A load failure aborts the import: without the grammar
# no artifact may be classified.
try { . (Join-Path $PSScriptRoot 'review-common.ps1') }
catch { throw "paired governance could not load the shared review functions: $($_.Exception.Message)" }

function Get-CrgPairDigest {
  param([byte[]]$Bytes)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Read-CrgPairRecords {
  param([AllowNull()][byte[]]$Bytes, [int]$Maximum)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt $Maximum -or $Bytes[$Bytes.Length - 1] -ne 10) { throw 'paired record has an invalid length or missing final LF' }
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) { throw 'paired record contains a BOM' }
  foreach ($value in $Bytes) {
    if (($value -lt 32 -and $value -ne 10) -or $value -eq 127) { throw 'paired record contains a prohibited control byte' }
  }
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  try { $text = $utf8.GetString($Bytes) } catch { throw 'paired record is not strict UTF-8' }
  [string[]]$lines = $text.Substring(0, $text.Length - 1) -split "`n", 0
  if (@($lines | Where-Object { $_.Length -eq 0 }).Count -ne 0) { throw 'paired record contains a blank record' }
  return ,$lines
}

function Get-CrgPairPrefixNames {
  param([ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin = 'paired-v1')
  $names = @('operation-id', 'project-id', 'attachment-sha256', 'public-worktree', 'public-git-dir', 'public-common-dir',
    'private-git-dir', 'public-ref', 'private-ref', 'public-parent', 'private-parent', 'public-tree', 'private-tree',
    'previous-pair', 'runtime-manifest-sha256', 'governing-preparation-sha256', 'candidate-preparation-sha256',
    'public-diff-sha256', 'private-diff-sha256', 'consistency-envelope-sha256', 'message-private-blob', 'message-sha256')
  # Ordinal: -ceq/-cne/-cin and string overloads compare by culture and ignore characters such as U+00AD.
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) { $names[13] = 'private-baseline-tree' }
  return $names
}

function Get-CrgHandoffNames {
  param([ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin = 'paired-v1')
  $names = @('operation-id', 'project-id', 'attachment-sha256', 'receipt-sha256', 'previous-pair', 'runtime-manifest-sha256',
    'public-ref', 'public-old', 'public-new', 'private-ref', 'private-old', 'private-new')
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) { return @($names | Where-Object { -not [string]::Equals($_, 'previous-pair', [StringComparison]::Ordinal) }) }
  return $names
}

function Get-CrgPairOriginHeader {
  param([ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin, [switch]$Handoff)
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) {
    if ($Handoff) { return 'crg-first-attachment-handoff v1' }
    return 'crg-first-attachment-receipt v1'
  }
  if ($Handoff) { return 'crg-handoff v1' }
  return 'crg-pair-receipt v1'
}

function Assert-CrgPairOriginField {
  param([string]$Origin, [string]$Name, [string]$Value, [string]$PublicObjectFormat, [string]$PrivateObjectFormat)
  # Initial governance is reviewed from the real empty tree, not from adopted
  # private ancestry. Absence is explicit and never masquerades as a commit OID.
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -and [string]::Equals($Name, 'private-parent', [StringComparison]::Ordinal) -and [string]::Equals($Value, 'absent', [StringComparison]::Ordinal)) { return }
  Assert-CrgPairField -Name $Name -Value $Value -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat
  if ([string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal) -and [string]::Equals($Name, 'private-baseline-tree', [StringComparison]::Ordinal)) {
    $hash = if ([string]::Equals($PrivateObjectFormat, 'sha1', [StringComparison]::Ordinal)) { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
    try { $emptyTree = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::ASCII.GetBytes('tree 0' + [char]0)))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    if ($Value -cne $emptyTree) { throw 'first attachment requires the actual empty governance tree baseline' }
  }
}

function Assert-CrgPairPath {
  param([string]$Path, [switch]$GitDirectory)
  if ($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Contains('/')) { throw 'paired path must use an absolute local drive and backslashes' }
  foreach ($part in @($Path.Substring(3) -split '\\', 0)) {
    # Same textual Windows boundary as attachment parsing; directory custody is not a byte-parser claim.
    if ($part.Length -eq 0 -or [string]::Equals($part, '.', [StringComparison]::Ordinal) -or [string]::Equals($part, '..', [StringComparison]::Ordinal) -or
        $part.EndsWith('.', [StringComparison]::Ordinal) -or -not [string]::Equals($part, $part.Trim(), [StringComparison]::Ordinal) -or
        $part -match '[<>:"|?*\x00-\x1f\x7f]' -or
        $part -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)' -or
        (-not $GitDirectory -and [string]::Equals($part, '.git', [StringComparison]::OrdinalIgnoreCase))) { throw 'paired path has an unsupported Windows component' }
  }
}

function Assert-CrgPairField {
  param([string]$Name, [string]$Value, [string]$PublicObjectFormat, [string]$PrivateObjectFormat)
  if ([string]::Equals($Name, 'operation-id', [StringComparison]::Ordinal) -or [string]::Equals($Name, 'project-id', [StringComparison]::Ordinal)) {
    if ($Value -cnotmatch '\A[0-9a-f]{32}\z') { throw "paired field '$Name' requires lowercase id32" }
  } elseif ($Name.EndsWith('-sha256', [StringComparison]::Ordinal) -or [string]::Equals($Name, 'previous-pair', [StringComparison]::Ordinal)) {
    if ($Value -cnotmatch '\A[0-9a-f]{64}\z') { throw "paired field '$Name' requires lowercase sha256" }
  } elseif ([System.Linq.Enumerable]::Contains([string[]]@('public-worktree', 'public-git-dir', 'public-common-dir', 'private-git-dir'), [string]$Name, [StringComparer]::Ordinal)) {
    Assert-CrgPairPath -Path $Value -GitDirectory:(-not [string]::Equals($Name, 'public-worktree', [StringComparison]::Ordinal))
  } elseif ([string]::Equals($Name, 'public-ref', [StringComparison]::Ordinal) -or [string]::Equals($Name, 'private-ref', [StringComparison]::Ordinal)) {
    if (-not $Value.StartsWith('refs/heads/', [StringComparison]::Ordinal) -or $Value -match '[\s~^?*\[\\:<>"|\x00-\x1f\x7f]' -or
        $Value.Contains('..') -or $Value.Contains('@{')) { throw 'paired branch ref is not canonical' }
    foreach ($part in @($Value -split '/', 0)) {
      if ($part.Length -eq 0 -or $part.StartsWith('.', [StringComparison]::Ordinal) -or $part.EndsWith('.', [StringComparison]::Ordinal) -or $part.EndsWith('.lock', [StringComparison]::OrdinalIgnoreCase) -or
          $part -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)') { throw 'paired branch ref has an unsupported component' }
    }
  } else {
    $format = $PrivateObjectFormat
    if ($Name.StartsWith('public-', [StringComparison]::Ordinal)) { $format = $PublicObjectFormat }
    $width = 64
    if ([string]::Equals($format, 'sha1', [StringComparison]::Ordinal)) { $width = 40 }
    if ($Value -cnotmatch ('\A[0-9a-f]{' + $width + '}\z') -or $Value -match '\A0+\z') { throw "paired field '$Name' has an invalid database object ID" }
  }
}

function Read-CrgPairField {
  param([string]$Line, [string]$Name)
  $prefix = $Name + ' '
  if ($null -eq $Line -or -not $Line.StartsWith($prefix, [StringComparison]::Ordinal)) { throw "paired record is missing ordered field '$Name'" }
  return $Line.Substring($prefix.Length)
}

function Get-CrgPairInputValues {
  param([System.Collections.IDictionary]$Fields, [string[]]$Names)
  if ($null -eq $Fields -or $Fields.Count -ne $Names.Count) { throw 'paired constructor fields do not match the exact schema' }
  foreach ($key in $Fields.Keys) {
    if ($key -isnot [string] -or -not [System.Linq.Enumerable]::Contains([string[]]$Names, [string]$key, [StringComparer]::Ordinal) -or $Fields[$key] -isnot [string]) { throw 'paired constructor requires exact field names and string values' }
  }
  $values = @($Names | ForEach-Object { $Fields[$_] })
  # Constructors accept one field value per record, never injected record text.
  foreach ($value in $values) {
    if ($value -match '[\x00-\x1f\x7f]') { throw 'paired constructor value contains a control character' }
  }
  return ,$values
}

function Read-CrgReviewUnitCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 65536
  $names = @(Get-CrgPairPrefixNames -Origin $Origin)
  if ($lines.Count -ne $names.Count + 1 -or -not [string]::Equals($lines[0], (Get-CrgPairOriginHeader -Origin $Origin), [StringComparison]::Ordinal)) { throw 'review unit must contain only the exact origin-specific receipt identity prefix' }
  $fields = [ordered]@{}
  for ($i = 0; $i -lt $names.Count; $i++) {
    $value = Read-CrgPairField -Line $lines[$i + 1] -Name $names[$i]
    Assert-CrgPairOriginField -Origin $Origin -Name $names[$i] -Value $value -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat
    $fields.Add($names[$i], $value)
  }
  return [pscustomobject]@{ Schema = 1; ReviewUnitSha256 = (Get-CrgPairDigest -Bytes $Bytes); Fields = $fields }
}

function New-CrgReviewUnitCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  $names = @(Get-CrgPairPrefixNames -Origin $Origin)
  $values = Get-CrgPairInputValues -Fields $Fields -Names $names
  $lines = @((Get-CrgPairOriginHeader -Origin $Origin))
  for ($i = 0; $i -lt $names.Count; $i++) { $lines += $names[$i] + ' ' + $values[$i] }
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  $bytes = $utf8.GetBytes(($lines -join "`n") + "`n")
  $null = Read-CrgReviewUnitCore -Bytes $bytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  return ,$bytes
}

function Read-CrgPairReceiptCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 65536
  if (-not [string]::Equals($lines[0], (Get-CrgPairOriginHeader -Origin $Origin), [StringComparison]::Ordinal)) { throw 'paired receipt has an unsupported origin header' }
  $prefixNames = @(Get-CrgPairPrefixNames -Origin $Origin)
  $names = $prefixNames + @('review-unit-sha256', 'public-result', 'private-result')
  if ($lines.Count -lt $names.Count + 5) { throw 'paired receipt is missing required records' }
  $fields = [ordered]@{}
  for ($i = 0; $i -lt $names.Count; $i++) {
    $value = Read-CrgPairField -Line $lines[$i + 1] -Name $names[$i]
    Assert-CrgPairOriginField -Origin $Origin -Name $names[$i] -Value $value -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat
    $fields.Add($names[$i], $value)
  }
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  $unit = Get-CrgPairDigest -Bytes $utf8.GetBytes(($lines[0..$prefixNames.Count] -join "`n") + "`n")
  if ($fields['review-unit-sha256'] -cne $unit) { throw 'paired receipt review-unit digest does not match the exact prefix' }
  if ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal) -and [string]::Equals($fields['public-parent'], $fields['public-result'], [StringComparison]::Ordinal) -and [string]::Equals($fields['private-parent'], $fields['private-result'], [StringComparison]::Ordinal)) { throw 'a both-unchanged pair cannot create a receipt' }
  $position = $names.Count + 1
  $legCount = Read-CrgPairField -Line $lines[$position++] -Name 'review-leg-count'
  if ($legCount -cnotmatch '\A[12]\z') { throw 'paired receipt requires one or two review legs' }
  $legs = New-Object 'System.Collections.Generic.List[object]'
  for ($leg = 1; $leg -le [int]$legCount; $leg++) {
    if ($position -ge $lines.Count -or $lines[$position++] -cnotmatch '\Areview-leg ([12]) (codex|claude) ([1-9]|10)\z' -or [int]$Matches[1] -ne $leg) { throw 'paired receipt review legs are invalid or out of order' }
    $legs.Add([pscustomobject]@{ Leg = $leg; PreferredProvider = [string]$Matches[2]; RequiredPassCount = [int]$Matches[3] })
  }
  if ($position -ge $lines.Count) { throw 'paired receipt has no review-attempt count' }
  $attemptCount = Read-CrgPairField -Line $lines[$position++] -Name 'review-attempt-count'
  if ($attemptCount -cnotmatch '\A[1-6]\z' -or $lines.Count - $position -ne [int]$attemptCount) { throw 'paired receipt attempt count does not match the remaining records' }
  $attempts = New-Object 'System.Collections.Generic.List[object]'
  $nextLeg = 1; $nextAttempt = 1
  while ($position -lt $lines.Count) {
    if ($lines[$position++] -cnotmatch '\Areview-attempt ([12]) ([123]) (codex|claude|grok) ([1-9]|10) (0|4) ([0-9a-f]{64}) (-|[0-9a-f]{64}) (-|[0-9a-f]{64})\z') { throw 'paired receipt review attempt has invalid grammar' }
    $attempt = [pscustomobject]@{ Leg = [int]$Matches[1]; Attempt = [int]$Matches[2]; ActualProvider = [string]$Matches[3]; ScheduledPassCount = [int]$Matches[4]
      ObservedExit = [int]$Matches[5]; TranscriptSha256 = [string]$Matches[6]; VerdictSha256 = [string]$Matches[7]; ExhaustionSha256 = [string]$Matches[8] }
    if ($attempt.Leg -ne $nextLeg -or $attempt.Attempt -ne $nextAttempt -or $nextLeg -gt $legs.Count) { throw 'paired receipt attempts are duplicated, missing, or out of order' }
    $required = $legs[$nextLeg - 1]
    $provider = $required.PreferredProvider
    if ($nextAttempt -eq 2) { if ($provider -ceq 'claude') { $provider = 'codex' } else { $provider = 'claude' } }
    if ($nextAttempt -eq 3) { $provider = 'grok' }
    if ($attempt.ActualProvider -cne $provider -or $attempt.ScheduledPassCount -ne $required.RequiredPassCount) { throw 'paired attempt must run the preferred/full leg or its complete alternate-provider leg' }
    if ($attempt.ObservedExit -eq 4) {
      if ($nextAttempt -ge 3 -or $attempt.ExhaustionSha256 -ceq '-') { throw 'only positive exhaustion before the final route can precede another full attempt' }
      $nextAttempt++
    } else {
      if ($attempt.ExhaustionSha256 -cne '-' -or $attempt.VerdictSha256 -ceq '-') { throw 'a successful final attempt requires a verdict digest and no exhaustion evidence' }
      $nextLeg++; $nextAttempt = 1
    }
    $attempts.Add($attempt)
  }
  if ($nextLeg -ne $legs.Count + 1 -or $nextAttempt -ne 1) { throw 'paired receipt has an incomplete review leg' }
  return [pscustomobject]@{ Schema = 1; ReceiptSha256 = (Get-CrgPairDigest -Bytes $Bytes); Fields = $fields; ReviewLegs = $legs.ToArray(); ReviewAttempts = $attempts.ToArray() }
}

function New-CrgPairReceiptCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewLegs,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewAttempts,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  if ($ReviewLegs.Count -lt 1 -or $ReviewLegs.Count -gt 2 -or $ReviewAttempts.Count -lt 1 -or $ReviewAttempts.Count -gt 6) { throw 'paired constructor has an unsupported review group count' }
  $prefixNames = @(Get-CrgPairPrefixNames -Origin $Origin)
  $names = $prefixNames + @('public-result', 'private-result')
  $values = Get-CrgPairInputValues -Fields $Fields -Names $names
  $lines = New-Object 'System.Collections.Generic.List[string]'
  $lines.Add((Get-CrgPairOriginHeader -Origin $Origin))
  for ($i = 0; $i -lt $prefixNames.Count; $i++) { $lines.Add($names[$i] + ' ' + $values[$i]) }
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  $unit = Get-CrgPairDigest -Bytes $utf8.GetBytes(($lines -join "`n") + "`n")
  $lines.Add('review-unit-sha256 ' + $unit)
  foreach ($name in @('public-result', 'private-result')) { $lines.Add($name + ' ' + $Fields[$name]) }
  $lines.Add('review-leg-count ' + $ReviewLegs.Count)
  foreach ($leg in $ReviewLegs) {
    $tuple = Get-CrgPairInputValues -Fields $leg -Names @('leg', 'preferred-provider', 'required-pass-count')
    $lines.Add('review-leg ' + ($tuple -join ' '))
  }
  $lines.Add('review-attempt-count ' + $ReviewAttempts.Count)
  foreach ($attempt in $ReviewAttempts) {
    $tuple = Get-CrgPairInputValues -Fields $attempt -Names @('leg', 'attempt', 'actual-provider', 'scheduled-pass-count', 'observed-exit', 'transcript-sha256', 'verdict-sha256', 'exhaustion-sha256')
    $lines.Add('review-attempt ' + ($tuple -join ' '))
  }
  $bytes = $utf8.GetBytes(($lines -join "`n") + "`n")
  $null = Read-CrgPairReceiptCore -Bytes $bytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  return ,$bytes
}

function Get-CrgHandoffFields {
  param($Receipt, [ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin = 'paired-v1')
  $fields = [ordered]@{}
  foreach ($name in @(Get-CrgHandoffNames -Origin $Origin)) {
    if ($name -ceq 'receipt-sha256') { $value = $Receipt.ReceiptSha256 }
    else { $source = $name.Replace('-old', '-parent').Replace('-new', '-result'); $value = $Receipt.Fields[$source] }
    $fields.Add($name, $value)
  }
  return $fields
}

function Read-CrgPairHandoffCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  $receipt = Read-CrgPairReceiptCore -Bytes $ReceiptBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  $expected = Get-CrgHandoffFields -Receipt $receipt -Origin $Origin
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 16384
  $names = @(Get-CrgHandoffNames -Origin $Origin)
  if ($lines.Count -ne $names.Count + 1 -or -not [string]::Equals($lines[0], (Get-CrgPairOriginHeader -Origin $Origin -Handoff), [StringComparison]::Ordinal)) { throw 'paired handoff must contain the exact origin-specific v1 records' }
  for ($i = 0; $i -lt $names.Count; $i++) {
    $value = Read-CrgPairField -Line $lines[$i + 1] -Name $names[$i]
    if (-not [string]::Equals($value, $expected[$names[$i]], [StringComparison]::Ordinal)) { throw "paired handoff field '$($names[$i])' differs from the immutable receipt" }
  }
  return [pscustomobject]@{ Schema = 1; HandoffSha256 = (Get-CrgPairDigest -Bytes $Bytes); Fields = $expected }
}

function New-CrgPairHandoffCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  $receipt = Read-CrgPairReceiptCore -Bytes $ReceiptBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  $fields = Get-CrgHandoffFields -Receipt $receipt -Origin $Origin
  $lines = @((Get-CrgPairOriginHeader -Origin $Origin -Handoff)) + @($fields.Keys | ForEach-Object { $_ + ' ' + $fields[$_] })
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  $bytes = $utf8.GetBytes(($lines -join "`n") + "`n")
  $null = Read-CrgPairHandoffCore -Bytes $bytes -ReceiptBytes $ReceiptBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  return ,$bytes
}

function Read-CrgReviewUnitBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return Read-CrgReviewUnitCore @PSBoundParameters -Origin 'paired-v1'
}

function New-CrgReviewUnitBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return ,(New-CrgReviewUnitCore @PSBoundParameters -Origin 'paired-v1')
}

function Read-CrgPairReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return Read-CrgPairReceiptCore @PSBoundParameters -Origin 'paired-v1'
}

function New-CrgPairReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewLegs,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewAttempts,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return ,(New-CrgPairReceiptCore @PSBoundParameters -Origin 'paired-v1')
}

function Read-CrgPairHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return Read-CrgPairHandoffCore @PSBoundParameters -Origin 'paired-v1'
}

function New-CrgPairHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return ,(New-CrgPairHandoffCore @PSBoundParameters -Origin 'paired-v1')
}

function Read-CrgFirstAttachmentUnitBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  $unit = Read-CrgReviewUnitCore @PSBoundParameters -Origin 'first-attachment-v1'
  $unit | Add-Member -NotePropertyName RequiresReview -NotePropertyValue $true
  return $unit
}

function New-CrgFirstAttachmentUnitBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return ,(New-CrgReviewUnitCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgFirstAttachmentReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return Read-CrgPairReceiptCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function New-CrgFirstAttachmentReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewLegs,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewAttempts,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return ,(New-CrgPairReceiptCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgFirstAttachmentHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return Read-CrgPairHandoffCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function New-CrgFirstAttachmentHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  return ,(New-CrgPairHandoffCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgCompletedPairPointerBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes)
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 256
  if ($lines.Count -ne 3 -or -not [string]::Equals($lines[0], 'crg-completed-pair v1', [StringComparison]::Ordinal)) { throw 'completed-pair pointer has an unsupported record shape' }
  $origin = Read-CrgPairField -Line $lines[1] -Name 'origin'
  $receipt = Read-CrgPairField -Line $lines[2] -Name 'receipt-sha256'
  if (-not ([string]::Equals($origin, 'paired-v1', [StringComparison]::Ordinal) -or [string]::Equals($origin, 'first-attachment-v1', [StringComparison]::Ordinal)) -or $receipt -cnotmatch '\A[0-9a-f]{64}\z') { throw 'completed-pair pointer has an unsupported origin or receipt digest' }
  return [pscustomobject]@{ Schema = 1; Origin = $origin; ReceiptSha256 = $receipt; PointerSha256 = (Get-CrgPairDigest -Bytes $Bytes) }
}

function New-CrgCompletedPairPointerBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin,
    [Parameter(Mandatory = $true)][string]$ReceiptSha256)
  if (-not ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal) -or [string]::Equals($Origin, 'first-attachment-v1', [StringComparison]::Ordinal)) -or $ReceiptSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'completed-pair pointer requires exact origin and lowercase receipt digest' }
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes("crg-completed-pair v1`norigin $Origin`nreceipt-sha256 $ReceiptSha256`n")
  $null = Read-CrgCompletedPairPointerBytes -Bytes $bytes
  return ,$bytes
}

function Read-CrgCompletedPairReceiptBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$PointerBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat)
  $pointer = Read-CrgCompletedPairPointerBytes -Bytes $PointerBytes
  $receipt = Read-CrgPairReceiptCore -Bytes $Bytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $pointer.Origin
  if ($receipt.ReceiptSha256 -cne $pointer.ReceiptSha256) { throw 'completed-pair receipt differs from the retained pointer' }
  $receipt | Add-Member -NotePropertyName Origin -NotePropertyValue $pointer.Origin
  return $receipt
}

function Get-CrgPairArtifactHeader {
  param([byte[]]$ReviewUnitBytes, [string]$PublicObjectFormat, [string]$PrivateObjectFormat,
    [string]$DescriptorSha256, [string]$DisplayDiffSha256, [string]$Backend, [string]$Effort, [string]$DurationSecs,
    [ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin = 'paired-v1', [string]$RequestedModel = '-')
  if ($DescriptorSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $DisplayDiffSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
      -not [System.Linq.Enumerable]::Contains([string[]]@('codex', 'claude', 'grok'), [string]$Backend, [StringComparer]::Ordinal) -or $DurationSecs -cnotmatch '\A(?:0|[1-9][0-9]*)\z') { throw 'paired artifact has invalid caller identity or provider metadata' }
  # Byte grammar only. The Grok model and effort come from the central profile
  # table of the release that ran the review, which may differ from the
  # current one; callers bind them exactly (live acceptance) or to the known
  # model set (historical validation).
  $modelOk = if ([string]::Equals($Backend, 'grok', [StringComparison]::Ordinal)) { $RequestedModel -cmatch '\Agrok-[0-9a-z.-]+\z' } else { [string]::Equals($RequestedModel, '-', [StringComparison]::Ordinal) }
  if (-not $modelOk) { throw 'paired artifact requested model differs from the existing provider grammar' }
  $effortOk = if ([string]::Equals($Backend, 'codex', [StringComparison]::Ordinal)) { $Effort -cmatch '\A(?:unknown|minimal|low|medium|high|xhigh|max)\z' }
    elseif ([string]::Equals($Backend, 'grok', [StringComparison]::Ordinal)) { [System.Linq.Enumerable]::Contains([string[]]@('low', 'medium', 'high', 'xhigh'), [string]$Effort, [StringComparer]::Ordinal) } else { [string]::Equals($Effort, 'n/a', [StringComparison]::Ordinal) }
  if (-not $effortOk) { throw 'paired artifact effort differs from the existing provider grammar' }
  $unit = Read-CrgReviewUnitCore -Bytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  $header = @("REVIEW-INPUT: $Origin", "PREPARED-PAIR-SHA256: $DescriptorSha256",
    "REVIEW-UNIT-SHA256: $($unit.ReviewUnitSha256)", "REVIEW-PUBLIC-TREE-OID: $($unit.Fields['public-tree'])",
    "REVIEW-PRIVATE-TREE-OID: $($unit.Fields['private-tree'])", "DIFF-SHA256: $DisplayDiffSha256",
    "REVIEW-BACKEND: $Backend", "REVIEW-EFFORT: $Effort", 'REVIEW-SEVERITY-CONTRACT: blocker-only',
    "REVIEW-DURATION-SECS: $DurationSecs")
  # Requested effort is not proof of the provider's internal work. Each Grok
  # pass retains the response JSON, including reported reasoning metadata.
  if ($Backend -ceq 'grok') { $header += @("REVIEW-REQUESTED-MODEL: $RequestedModel", 'REVIEW-PROVIDER-METADATA: per-pass-response-json') }
  return $header
}

function Read-CrgPairArtifactCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 16777216) { throw 'paired artifact has an invalid complete byte length' }
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  try { $text = $utf8.GetString($Bytes) } catch { throw 'paired artifact is not strict UTF-8' }
  $separator = $text.IndexOf("`n`n", [StringComparison]::Ordinal)
  if ($separator -lt 0 -or $separator -gt 16384) { throw 'paired artifact lacks a bounded complete header' }
  [string[]]$rows = $text.Substring(0, $separator) -split "`n", 0
  $headerCount = if ([string]::Equals($ExpectedBackend, 'grok', [StringComparison]::Ordinal)) { 12 } else { 10 }
  if ($rows.Count -ne $headerCount -or -not $rows[7].StartsWith('REVIEW-EFFORT: ', [StringComparison]::Ordinal) -or
      -not $rows[9].StartsWith('REVIEW-DURATION-SECS: ', [StringComparison]::Ordinal)) { throw 'paired artifact must contain the exact ordered header' }
  $effort = $rows[7].Substring('REVIEW-EFFORT: '.Length)
  $duration = $rows[9].Substring('REVIEW-DURATION-SECS: '.Length)
  $requestedModel = '-'
  if ([string]::Equals($ExpectedBackend, 'grok', [StringComparison]::Ordinal)) {
    if (-not $rows[10].StartsWith('REVIEW-REQUESTED-MODEL: ', [StringComparison]::Ordinal)) { throw 'paired artifact must contain the exact ordered header' }
    $requestedModel = $rows[10].Substring('REVIEW-REQUESTED-MODEL: '.Length)
  }
  $expected = Get-CrgPairArtifactHeader -ReviewUnitBytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -DescriptorSha256 $DescriptorSha256 -DisplayDiffSha256 $DisplayDiffSha256 -Backend $ExpectedBackend -Effort $effort -DurationSecs $duration -Origin $Origin -RequestedModel $requestedModel
  for ($i = 0; $i -lt $expected.Count; $i++) { if (-not [string]::Equals($rows[$i], $expected[$i], [StringComparison]::Ordinal)) { throw 'paired artifact header differs from current caller identity' } }
  $body = $text.Substring($separator + 2)
  if ([string]::IsNullOrWhiteSpace($body)) { throw 'paired artifact has no verdict body' }
  # Only the exact outer header supplies identity. The body is model prose;
  # quoted header lines, fenced or otherwise, cannot replace those validated pins.
  # Semantic verdicts, complete pass groups and observed process exits remain
  # the existing host/coordinator checks, never a conclusion of this byte reader.
  return [pscustomobject]@{
    Schema = 1; ArtifactSha256 = (Get-CrgPairDigest -Bytes $Bytes); Backend = $ExpectedBackend
    Effort = $effort; RequestedModel = $requestedModel; DurationSecs = $duration; VerdictText = $body
    ValidationState = 'paired-artifact-metadata-only'; ReadyForPublication = $false
  }
}

function Get-CrgPairSemanticVerdict {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Verdict)
  return Get-VerdictExitCode -Verdict $Verdict
}

function Read-CrgSuccessfulPairArtifactCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  $metadata = Read-CrgPairArtifactCore -Bytes $Bytes -ReviewUnitBytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -DescriptorSha256 $DescriptorSha256 -DisplayDiffSha256 $DisplayDiffSha256 -ExpectedBackend $ExpectedBackend -Origin $Origin
  $body = $metadata.VerdictText
  $results = New-Object 'System.Collections.Generic.List[object]'
  # The broad separator candidate detects malformed, unknown and indented
  # spellings before exact producer framing can exempt any part of the body.
  $separators = [regex]::Matches($body, '(?m)^[ \t]*=+[^\r\n]*(?:\r\n|\n|\r|\z)')
  if ([string]::Equals($ExpectedBackend, 'claude', [StringComparison]::Ordinal)) {
    if ($ScheduledPassCount -ne 1 -or $separators.Count -ne 0) { throw 'successful Claude paired evidence requires one unframed verdict' }
    $classification = Get-VerdictExitCode -Verdict $body
    if ($classification.ExitCode -ne 0) { throw "paired Claude verdict is not successful: $($classification.Diagnostic)" }
    $results.Add([pscustomobject]@{ Pass = 1; Verdict = $body; Cls = $classification })
  } else {
    if ($separators.Count -ne $ScheduledPassCount -or $separators[0].Index -ne 0) { throw 'paired multi-pass framing differs from the scheduled complete review' }
    for ($i = 0; $i -lt $ScheduledPassCount; $i++) {
      $marker = $separators[$i]
      $expected = "===== REVIEW PASS $($i + 1)/$ScheduledPassCount =====`n"
      if (-not [string]::Equals($marker.Value, $expected, [StringComparison]::Ordinal)) { throw 'paired multi-pass markers must be exact, ordered and contiguous' }
      $start = $marker.Index + $marker.Length
      $end = if ($i + 1 -lt $ScheduledPassCount) { $separators[$i + 1].Index } else { $body.Length }
      $segment = $body.Substring($start, $end - $start)
      # auto-review emits Verdict.TrimEnd()+LF and joins those groups with LF.
      # Preserve model bytes within each body; validate only generated edges.
      $suffix = if ($i + 1 -lt $ScheduledPassCount) { "`n`n" } else { "`n" }
      if (-not $segment.EndsWith($suffix, [StringComparison]::Ordinal)) { throw 'paired multi-pass terminator differs from the producer' }
      $verdict = $segment.Substring(0, $segment.Length - $suffix.Length)
      if ([string]::IsNullOrWhiteSpace($verdict) -or -not [string]::Equals($verdict, $verdict.TrimEnd(), [StringComparison]::Ordinal)) { throw 'paired review pass has an empty or noncanonical terminal body' }
      $classification = Get-VerdictExitCode -Verdict $verdict
      if ($classification.ExitCode -ne 0) { throw "paired review pass $($i + 1) is not successful: $($classification.Diagnostic)" }
      $results.Add([pscustomobject]@{ Pass = ($i + 1); Verdict = $verdict; Cls = $classification })
    }
  }
  return [pscustomobject]@{
    Schema = 1; ArtifactSha256 = $metadata.ArtifactSha256; Backend = $metadata.Backend
    Effort = $metadata.Effort; RequestedModel = $metadata.RequestedModel; DurationSecs = $metadata.DurationSecs; VerdictText = $body
    ScheduledPassCount = $ScheduledPassCount; PassResults = $results.ToArray()
    ValidationState = 'paired-artifact-success-body-only'; ReadyForPublication = $false
  }
}

function Read-CrgPairExhaustionCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude)\z', Options = 'None')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 16777216) { throw 'paired exhaustion has an invalid complete byte length' }
  if ($DescriptorSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $DisplayDiffSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
      -not ([string]::Equals($ExpectedBackend, 'codex', [StringComparison]::Ordinal) -or [string]::Equals($ExpectedBackend, 'claude', [StringComparison]::Ordinal))) { throw 'paired exhaustion has invalid caller identity' }
  $unit = Read-CrgReviewUnitCore -Bytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  try { $text = $utf8.GetString($Bytes) } catch { throw 'paired exhaustion is not strict UTF-8' }
  # The existing writer emits only flat machine strings. Match that finite
  # surface directly, retaining every member so duplicate names cannot collapse.
  $member = '"(?<name>[A-Za-z][A-Za-z0-9]*)"[ \t\r\n]*:[ \t\r\n]*"(?<value>[A-Za-z0-9:+.-]+)"'
  $json = [regex]::Match($text, ('\A[ \t\r\n]*\{[ \t\r\n]*' + $member + '(?:[ \t\r\n]*,[ \t\r\n]*' + $member + ')*[ \t\r\n]*\}[ \t\r\n]*\z'))
  $names = @('reviewInput', 'preparedPairSha256', 'reviewUnitSha256', 'publicTreeOid', 'privateTreeOid', 'diffSha256',
    'backend', 'kind', 'scope', 'signatureClass', 'processOutcome', 'timestamp')
  if (-not $json.Success -or $json.Groups['name'].Captures.Count -ne $names.Count) { throw 'paired exhaustion must contain the exact flat machine-string schema' }
  $fields = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
  for ($i = 0; $i -lt $names.Count; $i++) {
    $name = $json.Groups['name'].Captures[$i].Value
    if ($name -cnotin $names -or $fields.ContainsKey($name)) { throw 'paired exhaustion contains an unknown, duplicate or legacy field' }
    $fields.Add($name, $json.Groups['value'].Captures[$i].Value)
  }
  $scopePrefix = if ([string]::Equals($Origin, 'paired-v1', [StringComparison]::Ordinal)) { 'paired-' } else { 'first-attachment-' }
  $expected = [ordered]@{
    reviewInput = $Origin; preparedPairSha256 = $DescriptorSha256; reviewUnitSha256 = $unit.ReviewUnitSha256
    publicTreeOid = $unit.Fields['public-tree']; privateTreeOid = $unit.Fields['private-tree']; diffSha256 = $DisplayDiffSha256
    backend = $ExpectedBackend; kind = 'token-exhaustion'; scope = ($scopePrefix + $unit.ReviewUnitSha256.Substring(0, 12))
  }
  foreach ($name in $expected.Keys) {
    if (-not [string]::Equals($fields[$name], $expected[$name], [StringComparison]::Ordinal)) { throw "paired exhaustion field '$name' differs from the current caller identity" }
  }
  if ($ExpectedBackend -ceq 'codex') {
    $outcome = [regex]::Match($fields['processOutcome'], '\Aerrored-passes-(?<errors>[1-9]|10)-of-(?<passes>[1-9]|10)\z')
    if ($fields['signatureClass'] -cne 'cli-limit-signature' -or -not $outcome.Success -or
        [int]$outcome.Groups['passes'].Value -ne $ScheduledPassCount -or
        [int]$outcome.Groups['errors'].Value -gt $ScheduledPassCount) { throw 'paired Codex exhaustion differs from the scheduled producer outcome' }
  } else {
    if ($ScheduledPassCount -ne 1 -or $fields['signatureClass'] -cne 'cli-json-error-envelope') { throw 'paired Claude exhaustion requires the single-pass error-envelope signature' }
    $outcome = [regex]::Match($fields['processOutcome'], '\Ainvocation-exit-(?<exit>-?[1-9][0-9]*)\z')
    $exitCode = 0
    if ($fields['processOutcome'] -cne 'error-envelope-exit-0' -and
        (-not $outcome.Success -or -not [int]::TryParse($outcome.Groups['exit'].Value, [ref]$exitCode))) { throw 'paired Claude exhaustion differs from a real producer exit outcome' }
  }
  $timestamp = [DateTimeOffset]::MinValue
  $stamp = $fields['timestamp']
  $format = if ($stamp.EndsWith('Z', [StringComparison]::Ordinal)) { "yyyy-MM-dd'T'HH:mm:ss'Z'" } else { "yyyy-MM-dd'T'HH:mm:sszzz" }
  if (-not [DateTimeOffset]::TryParseExact($stamp, $format, [Globalization.CultureInfo]::InvariantCulture,
      [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$timestamp)) { throw 'paired exhaustion timestamp differs from the producer date grammar' }
  # Matching sidecar bytes never prove exit 4, positive provider classification
  # or complete child-group drain. Those remain live coordinator observations.
  return [pscustomobject]@{
    Schema = 1; ExhaustionSha256 = (Get-CrgPairDigest -Bytes $Bytes); Backend = $ExpectedBackend
    ScheduledPassCount = $ScheduledPassCount; Fields = $fields
    ValidationState = 'paired-exhaustion-metadata-only'; ReadyForPublication = $false
  }
}

function New-CrgPairArtifactCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$Backend,
    [Parameter(Mandatory = $true)][string]$Effort,
    [Parameter(Mandatory = $true)][string]$DurationSecs,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$VerdictText,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:paired-v1|first-attachment-v1)\z', Options = 'None')][string]$Origin,
    [string]$RequestedModel = '-')
  $header = Get-CrgPairArtifactHeader -ReviewUnitBytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -DescriptorSha256 $DescriptorSha256 -DisplayDiffSha256 $DisplayDiffSha256 -Backend $Backend -Effort $Effort -DurationSecs $DurationSecs -Origin $Origin -RequestedModel $RequestedModel
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  $bytes = $utf8.GetBytes(($header -join "`n") + "`n`n" + $VerdictText)
  $null = Read-CrgPairArtifactCore -Bytes $bytes -ReviewUnitBytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -DescriptorSha256 $DescriptorSha256 -DisplayDiffSha256 $DisplayDiffSha256 -ExpectedBackend $Backend -Origin $Origin
  return ,$bytes
}

# Artifact entry points also bind origin explicitly; model prose never selects
# a schema or changes the shared verdict/exhaustion acceptance contract.

function Read-CrgPairArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$ExpectedBackend)
  return Read-CrgPairArtifactCore @PSBoundParameters -Origin 'paired-v1'
}

function Read-CrgFirstAttachmentArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$ExpectedBackend)
  return Read-CrgPairArtifactCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function New-CrgPairArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$Backend,
    [Parameter(Mandatory = $true)][string]$Effort,
    [Parameter(Mandatory = $true)][string]$DurationSecs,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$VerdictText,
    [string]$RequestedModel = '-')
  return ,(New-CrgPairArtifactCore @PSBoundParameters -Origin 'paired-v1')
}

function New-CrgFirstAttachmentArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$Backend,
    [Parameter(Mandatory = $true)][string]$Effort,
    [Parameter(Mandatory = $true)][string]$DurationSecs,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$VerdictText,
    [string]$RequestedModel = '-')
  return ,(New-CrgPairArtifactCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgSuccessfulPairArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgSuccessfulPairArtifactCore @PSBoundParameters -Origin 'paired-v1'
}

function Read-CrgSuccessfulFirstAttachmentArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude|grok)\z', Options = 'None')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgSuccessfulPairArtifactCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function Read-CrgPairExhaustionBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude)\z', Options = 'None')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgPairExhaustionCore @PSBoundParameters -Origin 'paired-v1'
}

function Read-CrgFirstAttachmentExhaustionBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:sha1|sha256)\z', Options = 'None')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('\A(?:codex|claude)\z', Options = 'None')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgPairExhaustionCore @PSBoundParameters -Origin 'first-attachment-v1'
}

Export-ModuleMember -Function Read-CrgReviewUnitBytes, New-CrgReviewUnitBytes, Read-CrgPairReceiptBytes, New-CrgPairReceiptBytes, Read-CrgPairHandoffBytes, New-CrgPairHandoffBytes, Read-CrgPairArtifactBytes, New-CrgPairArtifactBytes, Read-CrgSuccessfulPairArtifactBytes, Read-CrgPairExhaustionBytes, Read-CrgFirstAttachmentUnitBytes, New-CrgFirstAttachmentUnitBytes, Read-CrgFirstAttachmentReceiptBytes, New-CrgFirstAttachmentReceiptBytes, Read-CrgFirstAttachmentHandoffBytes, New-CrgFirstAttachmentHandoffBytes, Read-CrgCompletedPairPointerBytes, New-CrgCompletedPairPointerBytes, Read-CrgCompletedPairReceiptBytes, Read-CrgFirstAttachmentArtifactBytes, New-CrgFirstAttachmentArtifactBytes, Read-CrgSuccessfulFirstAttachmentArtifactBytes, Read-CrgFirstAttachmentExhaustionBytes, Get-CrgPairSemanticVerdict
