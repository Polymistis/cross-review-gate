# Recorded transaction identity only; no Git, filesystem or review authority.
# Actual OIDs and explicit first-pointer absence are live-owner observations,
# not conditions proved by this byte classifier.

function Get-CrgResumeStateCore {
  param([AllowNull()][AllowEmptyCollection()][byte[]]$HandoffBytes,
    [AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [AllowNull()][AllowEmptyCollection()][byte[]]$PointerBytes,
    [string]$ActualPublicOid, [string]$ActualPrivateOid,
    [string]$PublicObjectFormat, [string]$PrivateObjectFormat,
    [ValidateSet('paired-v1', 'first-attachment-v1')][string]$Origin)
  $receiptName = 'Read-CrgPairReceiptBytes'; $handoffName = 'Read-CrgPairHandoffBytes'
  if ($Origin -ceq 'first-attachment-v1') {
    $receiptName = 'Read-CrgFirstAttachmentReceiptBytes'
    $handoffName = 'Read-CrgFirstAttachmentHandoffBytes'
  }
  $commands = @{}
  foreach ($name in @($receiptName, $handoffName, 'Read-CrgCompletedPairPointerBytes')) {
    $found = @(Get-Command -Name $name -Module paired-governance -CommandType Function -ListImported -ErrorAction SilentlyContinue)
    if ($found.Count -ne 1) { throw 'resume state requires the imported strict paired record readers' }
    $commands[$name] = $found[0]
  }
  $formats = @{ PublicObjectFormat = $PublicObjectFormat; PrivateObjectFormat = $PrivateObjectFormat }
  $receipt = & $commands[$receiptName] -Bytes $ReceiptBytes @formats
  $handoff = & $commands[$handoffName] -Bytes $HandoffBytes -ReceiptBytes $ReceiptBytes @formats
  $domains = [ordered]@{}
  foreach ($domain in @('public', 'private')) {
    $old = $handoff.Fields[$domain + '-old']; $new = $handoff.Fields[$domain + '-new']
    $actual = if ($domain -ceq 'public') { $ActualPublicOid } else { $ActualPrivateOid }
    # Equality to a strictly parsed endpoint also enforces the domain's OID
    # format, including literal absent only for a new first private history.
    if ($actual -cne $old -and $actual -cne $new) { throw "resume $domain ref differs from both recorded endpoints" }
    $changed = $old -cne $new
    $position = if (-not $changed) { 'unchanged' } elseif ($actual -ceq $new) { 'new' } else { 'old' }
    $domains.Add($domain, [pscustomobject]@{
      Ref = $handoff.Fields[$domain + '-ref']; OldOid = $old; NewOid = $new
      ActualOid = $actual; Changed = $changed; State = $position
    })
  }
  $publicNew = $ActualPublicOid -ceq $domains.public.NewOid
  $privateNew = $ActualPrivateOid -ceq $domains.private.NewOid
  if ($domains.public.Changed -and $domains.private.Changed -and $publicNew -and -not $privateNew) {
    throw 'resume refuses public-new while the changed private ref remains old'
  }
  # An unchanged side already satisfies its result. Prefer both-new before
  # considering either partial state, including unchanged initial adoption.
  $state = if ($publicNew -and $privateNew) { 'both-new' }
    elseif ($privateNew) { 'private-new-public-old' } else { 'both-old' }
  $pointer = $null; $pointerState = ''
  if ($null -eq $PointerBytes -and ($Origin -ceq 'first-attachment-v1' -or $state -ceq 'both-new')) {
    # Exact no-replace pointer publication can leave the preceding pointer
    # aside after both refs advance. The retained receipt/handoff and verified
    # predecessor still bind recovery; absence never supplies review credit.
    $pointerState = 'absent'
  } else {
    $pointer = & $commands['Read-CrgCompletedPairPointerBytes'] -Bytes $PointerBytes
    if ($pointer.ReceiptSha256 -ceq $receipt.ReceiptSha256) {
      if ($pointer.Origin -cne $Origin -or $state -cne 'both-new') { throw 'resume current pointer requires matching origin and both recorded results' }
      $pointerState = 'current'
    } elseif ($Origin -ceq 'paired-v1' -and $pointer.ReceiptSha256 -ceq $receipt.Fields['previous-pair']) {
      # The predecessor may itself be an initial receipt. Its closed pointer
      # grammar and digest match do not replace live predecessor admission.
      $pointerState = 'preceding'
    } else { throw 'resume completed-pair pointer conflicts with the recorded transaction' }
  }
  return [pscustomobject]@{
    Schema = 1; Origin = $Origin; ValidationState = 'resume-identity-only'
    State = $state; PointerState = $pointerState; Pointer = $pointer
    OperationId = $handoff.Fields['operation-id']; ProjectId = $handoff.Fields['project-id']
    HandoffSha256 = $handoff.HandoffSha256; ReceiptSha256 = $receipt.ReceiptSha256
    ReviewUnitSha256 = $receipt.Fields['review-unit-sha256']
    RuntimeManifestSha256 = $handoff.Fields['runtime-manifest-sha256']
    Public = $domains.public; Private = $domains.private
    RequiresFreshReview = $true; ReadyForPublication = $false
    PendingBindings = @('live-record-ref-and-pointer-custody',
      $(if ($Origin -ceq 'first-attachment-v1') { 'bootstrap-attachment-and-ancestry' } else { 'preceding-receipt-and-association' }),
      'retained-original-runtime-and-input', 'fresh-current-review-and-publication-guards')
  }
}

function Get-CrgPairedResumeState {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$HandoffBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$PointerBytes,
    [Parameter(Mandatory = $true)][string]$ActualPublicOid,
    [Parameter(Mandatory = $true)][string]$ActualPrivateOid,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return Get-CrgResumeStateCore @PSBoundParameters -Origin 'paired-v1'
}

function Get-CrgFirstAttachmentResumeState {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$HandoffBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$ReceiptBytes,
    [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][byte[]]$PointerBytes,
    [Parameter(Mandatory = $true)][string]$ActualPublicOid,
    [Parameter(Mandatory = $true)][string]$ActualPrivateOid,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PublicObjectFormat,
    [Parameter(Mandatory = $true)][ValidateSet('sha1', 'sha256')][string]$PrivateObjectFormat)
  return Get-CrgResumeStateCore @PSBoundParameters -Origin 'first-attachment-v1'
}

Export-ModuleMember -Function Get-CrgPairedResumeState, Get-CrgFirstAttachmentResumeState
