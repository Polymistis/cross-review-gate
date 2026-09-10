# Record identity only: parsed receipts cannot recreate live review authorization.

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
  param([ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin = 'paired-v1')
  $names = @('operation-id', 'project-id', 'attachment-sha256', 'public-worktree', 'public-git-dir', 'public-common-dir',
    'private-git-dir', 'public-ref', 'private-ref', 'public-parent', 'private-parent', 'public-tree', 'private-tree',
    'previous-pair', 'runtime-manifest-sha256', 'governing-preparation-sha256', 'candidate-preparation-sha256',
    'public-diff-sha256', 'private-diff-sha256', 'consistency-envelope-sha256', 'message-private-blob', 'message-sha256')
  if ($Origin -ceq 'first-attachment-v1') { $names[13] = 'private-baseline-tree' }
  return $names
}

function Get-CrgHandoffNames {
  param([ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin = 'paired-v1')
  $names = @('operation-id', 'project-id', 'attachment-sha256', 'receipt-sha256', 'previous-pair', 'runtime-manifest-sha256',
    'public-ref', 'public-old', 'public-new', 'private-ref', 'private-old', 'private-new')
  if ($Origin -ceq 'first-attachment-v1') { return @($names | Where-Object { $_ -cne 'previous-pair' }) }
  return $names
}

function Get-CrgPairOriginHeader {
  param([ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin, [switch]$Handoff)
  if ($Origin -ceq 'first-attachment-v1') {
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
  if ($Origin -ceq 'first-attachment-v1' -and $Name -ceq 'private-parent' -and $Value -ceq 'absent') { return }
  Assert-CrgPairField -Name $Name -Value $Value -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat
  if ($Origin -ceq 'first-attachment-v1' -and $Name -ceq 'private-baseline-tree') {
    $hash = if ($PrivateObjectFormat -eq 'sha1') { [Security.Cryptography.SHA1]::Create() } else { [Security.Cryptography.SHA256]::Create() }
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
    if ($part.Length -eq 0 -or $part -in @('.', '..') -or $part.EndsWith('.') -or $part -cne $part.Trim() -or
        $part -match '[<>:"|?*\x00-\x1f\x7f]' -or
        $part -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)' -or
        (-not $GitDirectory -and $part -ieq '.git')) { throw 'paired path has an unsupported Windows component' }
  }
}

function Assert-CrgPairField {
  param([string]$Name, [string]$Value, [string]$PublicObjectFormat, [string]$PrivateObjectFormat)
  if ($Name -in @('operation-id', 'project-id')) {
    if ($Value -cnotmatch '\A[0-9a-f]{32}\z') { throw "paired field '$Name' requires lowercase id32" }
  } elseif ($Name.EndsWith('-sha256') -or $Name -ceq 'previous-pair') {
    if ($Value -cnotmatch '\A[0-9a-f]{64}\z') { throw "paired field '$Name' requires lowercase sha256" }
  } elseif ($Name -in @('public-worktree', 'public-git-dir', 'public-common-dir', 'private-git-dir')) {
    Assert-CrgPairPath -Path $Value -GitDirectory:($Name -cne 'public-worktree')
  } elseif ($Name -in @('public-ref', 'private-ref')) {
    if (-not $Value.StartsWith('refs/heads/', [StringComparison]::Ordinal) -or $Value -match '[\s~^?*\[\\:<>"|\x00-\x1f\x7f]' -or
        $Value.Contains('..') -or $Value.Contains('@{')) { throw 'paired branch ref is not canonical' }
    foreach ($part in @($Value -split '/', 0)) {
      if ($part.Length -eq 0 -or $part.StartsWith('.') -or $part.EndsWith('.') -or $part.EndsWith('.lock', [StringComparison]::OrdinalIgnoreCase) -or
          $part -match '\A(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|\z)') { throw 'paired branch ref has an unsupported component' }
    }
  } else {
    $format = $PrivateObjectFormat
    if ($Name.StartsWith('public-', [StringComparison]::Ordinal)) { $format = $PublicObjectFormat }
    $width = 64
    if ($format -eq 'sha1') { $width = 40 }
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
    if ($key -isnot [string] -or $key -cnotin $Names -or $Fields[$key] -isnot [string]) { throw 'paired constructor requires exact field names and string values' }
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 65536
  $names = @(Get-CrgPairPrefixNames -Origin $Origin)
  if ($lines.Count -ne $names.Count + 1 -or $lines[0] -cne (Get-CrgPairOriginHeader -Origin $Origin)) { throw 'review unit must contain only the exact origin-specific receipt identity prefix' }
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 65536
  if ($lines[0] -cne (Get-CrgPairOriginHeader -Origin $Origin)) { throw 'paired receipt has an unsupported origin header' }
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
  if ($Origin -ceq 'paired-v1' -and $fields['public-parent'] -ceq $fields['public-result'] -and $fields['private-parent'] -ceq $fields['private-result']) { throw 'a both-unchanged pair cannot create a receipt' }
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
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
  param($Receipt, [ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin = 'paired-v1')
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  $receipt = Read-CrgPairReceiptCore -Bytes $ReceiptBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  $expected = Get-CrgHandoffFields -Receipt $receipt -Origin $Origin
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 16384
  $names = @(Get-CrgHandoffNames -Origin $Origin)
  if ($lines.Count -ne $names.Count + 1 -or $lines[0] -cne (Get-CrgPairOriginHeader -Origin $Origin -Handoff)) { throw 'paired handoff must contain the exact origin-specific v1 records' }
  for ($i = 0; $i -lt $names.Count; $i++) {
    $value = Read-CrgPairField -Line $lines[$i + 1] -Name $names[$i]
    if ($value -cne $expected[$names[$i]]) { throw "paired handoff field '$($names[$i])' differs from the immutable receipt" }
  }
  return [pscustomobject]@{ Schema = 1; HandoffSha256 = (Get-CrgPairDigest -Bytes $Bytes); Fields = $expected }
}

function New-CrgPairHandoffCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return Read-CrgReviewUnitCore @PSBoundParameters -Origin 'paired-v1'
}

function New-CrgReviewUnitBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return ,(New-CrgReviewUnitCore @PSBoundParameters -Origin 'paired-v1')
}

function Read-CrgPairReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return Read-CrgPairReceiptCore @PSBoundParameters -Origin 'paired-v1'
}

function New-CrgPairReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewLegs,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewAttempts,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return ,(New-CrgPairReceiptCore @PSBoundParameters -Origin 'paired-v1')
}

function Read-CrgPairHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return Read-CrgPairHandoffCore @PSBoundParameters -Origin 'paired-v1'
}

function New-CrgPairHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return ,(New-CrgPairHandoffCore @PSBoundParameters -Origin 'paired-v1')
}

function Read-CrgFirstAttachmentUnitBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  $unit = Read-CrgReviewUnitCore @PSBoundParameters -Origin 'first-attachment-v1'
  $unit | Add-Member -NotePropertyName RequiresReview -NotePropertyValue $true
  return $unit
}

function New-CrgFirstAttachmentUnitBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return ,(New-CrgReviewUnitCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgFirstAttachmentReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return Read-CrgPairReceiptCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function New-CrgFirstAttachmentReceiptBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewLegs,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary[]]$ReviewAttempts,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return ,(New-CrgPairReceiptCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgFirstAttachmentHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return Read-CrgPairHandoffCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function New-CrgFirstAttachmentHandoffBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return ,(New-CrgPairHandoffCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgCompletedPairPointerBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes)
  $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 256
  if ($lines.Count -ne 3 -or $lines[0] -cne 'crg-completed-pair v1') { throw 'completed-pair pointer has an unsupported record shape' }
  $origin = Read-CrgPairField -Line $lines[1] -Name 'origin'
  $receipt = Read-CrgPairField -Line $lines[2] -Name 'receipt-sha256'
  if ($origin -cnotin @('paired-v1', 'first-attachment-v1') -or $receipt -cnotmatch '\A[0-9a-f]{64}\z') { throw 'completed-pair pointer has an unsupported origin or receipt digest' }
  return [pscustomobject]@{ Schema = 1; Origin = $origin; ReceiptSha256 = $receipt; PointerSha256 = (Get-CrgPairDigest -Bytes $Bytes) }
}

function New-CrgCompletedPairPointerBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin,
    [Parameter(Mandatory = $true)][string]$ReceiptSha256)
  if ($Origin -cnotin @('paired-v1', 'first-attachment-v1') -or $ReceiptSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'completed-pair pointer requires exact origin and lowercase receipt digest' }
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes("crg-completed-pair v1`norigin $Origin`nreceipt-sha256 $ReceiptSha256`n")
  $null = Read-CrgCompletedPairPointerBytes -Bytes $bytes
  return ,$bytes
}

function Read-CrgCompletedPairReceiptBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$PointerBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  $pointer = Read-CrgCompletedPairPointerBytes -Bytes $PointerBytes
  $receipt = Read-CrgPairReceiptCore -Bytes $Bytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $pointer.Origin
  if ($receipt.ReceiptSha256 -cne $pointer.ReceiptSha256) { throw 'completed-pair receipt differs from the retained pointer' }
  $receipt | Add-Member -NotePropertyName Origin -NotePropertyValue $pointer.Origin
  return $receipt
}

function Get-CrgPairArtifactHeader {
  param([byte[]]$ReviewUnitBytes, [string]$PublicObjectFormat, [string]$PrivateObjectFormat,
    [string]$DescriptorSha256, [string]$DisplayDiffSha256, [string]$Backend, [string]$Effort, [string]$DurationSecs,
    [ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin = 'paired-v1')
  if ($DescriptorSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $DisplayDiffSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
      $Backend -cnotin @('codex', 'claude', 'grok') -or $DurationSecs -cnotmatch '\A(?:0|[1-9][0-9]*)\z') { throw 'paired artifact has invalid caller identity or provider metadata' }
  $effortOk = if ($Backend -ceq 'codex') { $Effort -cmatch '\A(?:unknown|minimal|low|medium|high|xhigh|max)\z' }
    elseif ($Backend -ceq 'grok') { $Effort -ceq 'xhigh' } else { $Effort -ceq 'n/a' }
  if (-not $effortOk) { throw 'paired artifact effort differs from the existing provider grammar' }
  $unit = Read-CrgReviewUnitCore -Bytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -Origin $Origin
  $header = @("REVIEW-INPUT: $Origin", "PREPARED-PAIR-SHA256: $DescriptorSha256",
    "REVIEW-UNIT-SHA256: $($unit.ReviewUnitSha256)", "REVIEW-PUBLIC-TREE-OID: $($unit.Fields['public-tree'])",
    "REVIEW-PRIVATE-TREE-OID: $($unit.Fields['private-tree'])", "DIFF-SHA256: $DisplayDiffSha256",
    "REVIEW-BACKEND: $Backend", "REVIEW-EFFORT: $Effort", 'REVIEW-SEVERITY-CONTRACT: blocker-only',
    "REVIEW-DURATION-SECS: $DurationSecs")
  # Requested effort is not proof of the provider's internal work. Each Grok
  # pass retains the response JSON, including reported reasoning metadata.
  if ($Backend -ceq 'grok') { $header += @('REVIEW-REQUESTED-MODEL: grok-4.6', 'REVIEW-PROVIDER-METADATA: per-pass-response-json') }
  return $header
}

function Read-CrgPairArtifactCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 16777216) { throw 'paired artifact has an invalid complete byte length' }
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  try { $text = $utf8.GetString($Bytes) } catch { throw 'paired artifact is not strict UTF-8' }
  $separator = $text.IndexOf("`n`n", [StringComparison]::Ordinal)
  if ($separator -lt 0 -or $separator -gt 16384) { throw 'paired artifact lacks a bounded complete header' }
  [string[]]$rows = $text.Substring(0, $separator) -split "`n", 0
  $headerCount = if ($ExpectedBackend -ceq 'grok') { 12 } else { 10 }
  if ($rows.Count -ne $headerCount -or -not $rows[7].StartsWith('REVIEW-EFFORT: ', [StringComparison]::Ordinal) -or
      -not $rows[9].StartsWith('REVIEW-DURATION-SECS: ', [StringComparison]::Ordinal)) { throw 'paired artifact must contain the exact ordered header' }
  $effort = $rows[7].Substring('REVIEW-EFFORT: '.Length)
  $duration = $rows[9].Substring('REVIEW-DURATION-SECS: '.Length)
  $expected = Get-CrgPairArtifactHeader -ReviewUnitBytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -DescriptorSha256 $DescriptorSha256 -DisplayDiffSha256 $DisplayDiffSha256 -Backend $ExpectedBackend -Effort $effort -DurationSecs $duration -Origin $Origin
  for ($i = 0; $i -lt $expected.Count; $i++) { if ($rows[$i] -cne $expected[$i]) { throw 'paired artifact header differs from current caller identity' } }
  $body = $text.Substring($separator + 2)
  if ([string]::IsNullOrWhiteSpace($body)) { throw 'paired artifact has no verdict body' }
  # Only the exact outer header supplies identity. The body is model prose;
  # quoted header lines, fenced or otherwise, cannot replace those validated pins.
  # Semantic verdicts, complete pass groups and observed process exits remain
  # the existing host/coordinator checks, never a conclusion of this byte reader.
  return [pscustomobject]@{
    Schema = 1; ArtifactSha256 = (Get-CrgPairDigest -Bytes $Bytes); Backend = $ExpectedBackend
    Effort = $effort; DurationSecs = $duration; VerdictText = $body
    ValidationState = 'paired-artifact-metadata-only'; ReadyForPublication = $false
  }
}

# Private semantic classifier retained verbatim from auto-merge.ps1. Importing
# this data module never loads a review wrapper or gives a verdict authority.
function Get-VerdictExitCode {
  param([string]$Verdict)

  $base = @{
    ExitCode      = 3
    VerdictText   = ''
    Diagnostic    = ''
    BlockerCount  = 0
    QualityCount  = 0
    LegacyNbCount = 0
    NoteCount     = 0
  }

  if ([string]::IsNullOrWhiteSpace($Verdict)) {
    $base.Diagnostic = 'verdict is empty'
    return $base
  }

  $base.BlockerCount  = ([regex]::Matches($Verdict, '(?m)^BLOCKER:')).Count
  $base.QualityCount  = ([regex]::Matches($Verdict, '(?m)^QUALITY:')).Count
  $base.LegacyNbCount = ([regex]::Matches($Verdict, '(?m)^NON-BLOCKER:')).Count
  $base.NoteCount     = ([regex]::Matches($Verdict, '(?m)^NOTE:')).Count

  # Reject duplicate VERDICT lines as malformed; capture the single (or zero)
  # VERDICT line VERBATIM into VerdictText. This MIRRORS the authoritative
  # scripts/codex/auto-review.ps1 Get-VerdictExitCode EXACTLY: it does NOT
  # validate the verdict WORD up front -- a malformed word (e.g. `VERDICT: FOO`)
  # is captured as-is and only rejected later by each per-severity branch's
  # literal `-eq` comparison, so BLOCKER precedence (below) wins over a PRESENT-but-
  # wrong/malformed verdict word (exit 2). A MISSING verdict line (zero `VERDICT:`
  # lines -> VerdictText empty) is the exception: the BLOCKER branch fails closed
  # (exit 3) there, since a verdict with no VERDICT: line is malformed output, not a
  # trustworthy blocker signal. (A prior copy validated the word against
  # `(CLEAN|NON-BLOCKING|BLOCKED)` BEFORE category + BLOCKER and capped category
  # counts at 4096; both diverged from the wrapper.)
  $verdictLines = @($Verdict -split "`n" | Where-Object { $_ -match '^VERDICT:' })
  if ($verdictLines.Count -gt 1) {
    $base.VerdictText = $verdictLines[0].Trim()
    $base.Diagnostic = "verdict contains $($verdictLines.Count) VERDICT: lines (expected exactly 1)"
    return $base
  }
  $base.VerdictText = if ($verdictLines.Count -eq 1) { $verdictLines[0].Trim() } else { '' }

  # Per-category enumeration: each of the 8 named categories exactly once,
  # count bounded at 10000 (same bound as the wrapper), per-category sum ==
  # per-severity sum. Category validation runs BEFORE BLOCKER precedence so a
  # malformed category block fails closed rather than being read as a blocker.
  $requiredCategories = @(
    'PLAN-DRIFT', 'SILENT-FAILURE', 'TOMBSTONE-OR-SHIM',
    'CROSS-CRATE-CONTRACT', 'LOADER-OR-ASSET-EDGE',
    'CONVENTION-ADHERENCE', 'TEST-QUALITY', 'DOC-VS-CODE-DRIFT'
  )
  $categoryTotal = 0
  foreach ($cat in $requiredCategories) {
    $rx = [regex]("(?m)^" + [regex]::Escape($cat) + ":\s*(?<v>none|\d+)\s*$")
    $matches = $rx.Matches($Verdict)
    if ($matches.Count -ne 1) {
      $base.Diagnostic = "category '$cat' appears $($matches.Count) times (expected exactly 1)"
      return $base
    }
    $v = $matches[0].Groups['v'].Value
    if ($v -ne 'none') {
      $parsed = 0
      if (-not [int]::TryParse($v, [ref]$parsed) -or $parsed -gt 10000) {
        $base.Diagnostic = "category '$cat' has count '$v' that is non-numeric or exceeds 10000"
        return $base
      }
      $categoryTotal += $parsed
    }
  }
  $severityTotal = $base.BlockerCount + $base.QualityCount + $base.LegacyNbCount + $base.NoteCount
  if ($categoryTotal -ne $severityTotal) {
    $base.Diagnostic = "per-category sum ($categoryTotal) does not match per-severity sum ($severityTotal); verdict is malformed"
    return $base
  }

  # BLOCKER precedence -- but a MISSING VERDICT: line is malformed output, not a
  # blocker verdict. Distinguish the two cases per the prompt's precedence note
  # and the AGENTS.md verdict contract:
  #   * ZERO VERDICT: lines (VerdictText == '') -> malformed output -> exit 3
  #     (fail closed; the reviewer never emitted a verdict line at all).
  #   * a VERDICT: line is PRESENT but inconsistent/malformed-word + BLOCKER
  #     -> exit 2 (BLOCKER precedence over a wrong line; the more conservative
  #     signal wins -- a blocker WAS reported).
  if ($base.BlockerCount -gt 0) {
    if ($base.VerdictText -eq '') {
      $base.ExitCode = 3
      $base.Diagnostic = 'BLOCKER findings but no VERDICT: line (missing verdict is malformed output)'
      return $base
    }
    $base.ExitCode = 2
    return $base
  }
  # QUALITY (or legacy NON-BLOCKER) without BLOCKER -> exit 0 (PASS, non-blocking)
  # under the 2026-07 severity contract, in parity with the auto-review.ps1
  # classifiers. A wrong/missing verdict line is still malformed -> exit 3 (default).
  if ($base.QualityCount -gt 0 -or $base.LegacyNbCount -gt 0) {
    if ($base.VerdictText -ne 'VERDICT: NON-BLOCKING') {
      $base.Diagnostic = "QUALITY/legacy findings but verdict is '$($base.VerdictText)' (expected 'VERDICT: NON-BLOCKING')"
      return $base
    }
    $base.ExitCode = 0
    return $base
  }
  if ($base.NoteCount -gt 0) {
    if ($base.VerdictText -ne 'VERDICT: NON-BLOCKING') {
      $base.Diagnostic = "NOTE-only findings but verdict is '$($base.VerdictText)' (expected 'VERDICT: NON-BLOCKING')"
      return $base
    }
    $base.ExitCode = 0
    return $base
  }
  if ($base.VerdictText -ne 'VERDICT: CLEAN') {
    $base.Diagnostic = "verdict has zero findings but is not 'VERDICT: CLEAN'"
    return $base
  }
  $base.ExitCode = 0
  return $base
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  $metadata = Read-CrgPairArtifactCore -Bytes $Bytes -ReviewUnitBytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -DescriptorSha256 $DescriptorSha256 -DisplayDiffSha256 $DisplayDiffSha256 -ExpectedBackend $ExpectedBackend -Origin $Origin
  $body = $metadata.VerdictText
  $results = New-Object 'System.Collections.Generic.List[object]'
  # The broad separator candidate detects malformed, unknown and indented
  # spellings before exact producer framing can exempt any part of the body.
  $separators = [regex]::Matches($body, '(?m)^[ \t]*=+[^\r\n]*(?:\r\n|\n|\r|\z)')
  if ($ExpectedBackend -ceq 'claude') {
    if ($ScheduledPassCount -ne 1 -or $separators.Count -ne 0) { throw 'successful Claude paired evidence requires one unframed verdict' }
    $classification = Get-VerdictExitCode -Verdict $body
    if ($classification.ExitCode -ne 0) { throw "paired Claude verdict is not successful: $($classification.Diagnostic)" }
    $results.Add([pscustomobject]@{ Pass = 1; Verdict = $body; Cls = $classification })
  } else {
    if ($separators.Count -ne $ScheduledPassCount -or $separators[0].Index -ne 0) { throw 'paired multi-pass framing differs from the scheduled complete review' }
    for ($i = 0; $i -lt $ScheduledPassCount; $i++) {
      $marker = $separators[$i]
      $expected = "===== REVIEW PASS $($i + 1)/$ScheduledPassCount =====`n"
      if ($marker.Value -cne $expected) { throw 'paired multi-pass markers must be exact, ordered and contiguous' }
      $start = $marker.Index + $marker.Length
      $end = if ($i + 1 -lt $ScheduledPassCount) { $separators[$i + 1].Index } else { $body.Length }
      $segment = $body.Substring($start, $end - $start)
      # auto-review emits Verdict.TrimEnd()+LF and joins those groups with LF.
      # Preserve model bytes within each body; validate only generated edges.
      $suffix = if ($i + 1 -lt $ScheduledPassCount) { "`n`n" } else { "`n" }
      if (-not $segment.EndsWith($suffix, [StringComparison]::Ordinal)) { throw 'paired multi-pass terminator differs from the producer' }
      $verdict = $segment.Substring(0, $segment.Length - $suffix.Length)
      if ([string]::IsNullOrWhiteSpace($verdict) -or $verdict -cne $verdict.TrimEnd()) { throw 'paired review pass has an empty or noncanonical terminal body' }
      $classification = Get-VerdictExitCode -Verdict $verdict
      if ($classification.ExitCode -ne 0) { throw "paired review pass $($i + 1) is not successful: $($classification.Diagnostic)" }
      $results.Add([pscustomobject]@{ Pass = ($i + 1); Verdict = $verdict; Cls = $classification })
    }
  }
  return [pscustomobject]@{
    Schema = 1; ArtifactSha256 = $metadata.ArtifactSha256; Backend = $metadata.Backend
    Effort = $metadata.Effort; DurationSecs = $metadata.DurationSecs; VerdictText = $body
    ScheduledPassCount = $ScheduledPassCount; PassResults = $results.ToArray()
    ValidationState = 'paired-artifact-success-body-only'; ReadyForPublication = $false
  }
}

function Read-CrgPairExhaustionCore {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt 16777216) { throw 'paired exhaustion has an invalid complete byte length' }
  if ($DescriptorSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $DisplayDiffSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
      $ExpectedBackend -cnotin @('codex', 'claude')) { throw 'paired exhaustion has invalid caller identity' }
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
  $scopePrefix = if ($Origin -ceq 'paired-v1') { 'paired-' } else { 'first-attachment-' }
  $expected = [ordered]@{
    reviewInput = $Origin; preparedPairSha256 = $DescriptorSha256; reviewUnitSha256 = $unit.ReviewUnitSha256
    publicTreeOid = $unit.Fields['public-tree']; privateTreeOid = $unit.Fields['private-tree']; diffSha256 = $DisplayDiffSha256
    backend = $ExpectedBackend; kind = 'token-exhaustion'; scope = ($scopePrefix + $unit.ReviewUnitSha256.Substring(0, 12))
  }
  foreach ($name in $expected.Keys) {
    if ($fields[$name] -cne $expected[$name]) { throw "paired exhaustion field '$name' differs from the current caller identity" }
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$Backend,
    [Parameter(Mandatory = $true)][string]$Effort,
    [Parameter(Mandatory = $true)][string]$DurationSecs,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$VerdictText,
    [Parameter(Mandatory = $true)][ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  $header = Get-CrgPairArtifactHeader -ReviewUnitBytes $ReviewUnitBytes -PublicObjectFormat $PublicObjectFormat -PrivateObjectFormat $PrivateObjectFormat -DescriptorSha256 $DescriptorSha256 -DisplayDiffSha256 $DisplayDiffSha256 -Backend $Backend -Effort $Effort -DurationSecs $DurationSecs -Origin $Origin
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
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$ExpectedBackend)
  return Read-CrgPairArtifactCore @PSBoundParameters -Origin 'paired-v1'
}

function Read-CrgFirstAttachmentArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$ExpectedBackend)
  return Read-CrgPairArtifactCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function New-CrgPairArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$Backend,
    [Parameter(Mandatory = $true)][string]$Effort,
    [Parameter(Mandatory = $true)][string]$DurationSecs,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$VerdictText)
  return ,(New-CrgPairArtifactCore @PSBoundParameters -Origin 'paired-v1')
}

function New-CrgFirstAttachmentArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$Backend,
    [Parameter(Mandatory = $true)][string]$Effort,
    [Parameter(Mandatory = $true)][string]$DurationSecs,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$VerdictText)
  return ,(New-CrgPairArtifactCore @PSBoundParameters -Origin 'first-attachment-v1')
}

function Read-CrgSuccessfulPairArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgSuccessfulPairArtifactCore @PSBoundParameters -Origin 'paired-v1'
}

function Read-CrgSuccessfulFirstAttachmentArtifactBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude', 'grok')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgSuccessfulPairArtifactCore @PSBoundParameters -Origin 'first-attachment-v1'
}

function Read-CrgPairExhaustionBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgPairExhaustionCore @PSBoundParameters -Origin 'paired-v1'
}

function Read-CrgFirstAttachmentExhaustionBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReviewUnitBytes,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat,
    [Parameter(Mandatory = $true)][string]$DescriptorSha256,
    [Parameter(Mandatory = $true)][string]$DisplayDiffSha256,
    [Parameter(Mandatory = $true)][ValidateSet('codex', 'claude')][string]$ExpectedBackend,
    [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ScheduledPassCount)
  return Read-CrgPairExhaustionCore @PSBoundParameters -Origin 'first-attachment-v1'
}

Export-ModuleMember -Function Read-CrgReviewUnitBytes, New-CrgReviewUnitBytes, Read-CrgPairReceiptBytes, New-CrgPairReceiptBytes, Read-CrgPairHandoffBytes, New-CrgPairHandoffBytes, Read-CrgPairArtifactBytes, New-CrgPairArtifactBytes, Read-CrgSuccessfulPairArtifactBytes, Read-CrgPairExhaustionBytes, Read-CrgFirstAttachmentUnitBytes, New-CrgFirstAttachmentUnitBytes, Read-CrgFirstAttachmentReceiptBytes, New-CrgFirstAttachmentReceiptBytes, Read-CrgFirstAttachmentHandoffBytes, New-CrgFirstAttachmentHandoffBytes, Read-CrgCompletedPairPointerBytes, New-CrgCompletedPairPointerBytes, Read-CrgCompletedPairReceiptBytes, Read-CrgFirstAttachmentArtifactBytes, New-CrgFirstAttachmentArtifactBytes, Read-CrgSuccessfulFirstAttachmentArtifactBytes, Read-CrgFirstAttachmentExhaustionBytes, Get-CrgPairSemanticVerdict
