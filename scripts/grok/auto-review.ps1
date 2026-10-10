# Optional central-runtime Grok reviewer. No provider override, alternate
# endpoint or caller-supplied prompt can enable either configured transport.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$PreparedPairPath,
  [Parameter(Mandatory = $true)][string]$PreparedPairSha256,
  [Parameter(Mandatory = $true)][string]$PreparedPublicTreeSha256,
  [Parameter(Mandatory = $true)][string]$PreparedPrivateTreeSha256,
  [Parameter(Mandatory = $true)][string]$OutDir,
  [ValidatePattern('(?-i)\A(?:paired-v1|first-attachment-v1)\z')][string]$PreparedOrigin = 'paired-v1',
  [Parameter(Mandatory = $true)][ValidateRange(1, 10)][int]$ReviewPasses
)
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false, $true)

function Write-CrgGrokEvidence {
  param([object]$HostInput, [string]$Leaf, [byte[]]$Bytes)
  if ($HostInput.Closed -or $Leaf -cnotmatch '\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,199}\z' -or
      $null -eq $Bytes -or $Bytes.Length -gt 16777216) { throw 'Grok evidence requires a bounded private attempt record' }
  $path = Join-Path $HostInput.OutDir $Leaf
  $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
  finally { $stream.Dispose() }
  return $path
}

function Open-CrgGrokPromptEvidence {
  param([object]$HostInput, [string]$Leaf, [byte[]]$Bytes)
  if ($HostInput.Closed -or $Leaf -cnotmatch '\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,199}\z' -or
      $null -eq $Bytes -or $Bytes.Length -gt 16777216) { throw 'Grok prompt requires a bounded private attempt record' }
  $path = Join-Path $HostInput.OutDir $Leaf
  $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
  try {
    $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true)
    $expected = New-Object byte[] $Bytes.Length
    [Buffer]::BlockCopy($Bytes, 0, $expected, 0, $Bytes.Length)
    return [pscustomobject]@{ Path = $path; Stream = $stream; ExpectedBytes = $expected }
  } catch {
    $stream.Dispose()
    throw
  }
}

function Assert-CrgGrokPromptEvidence {
  param([object]$Prompt)
  if ($null -eq $Prompt -or $Prompt.Stream -isnot [IO.FileStream] -or -not $Prompt.Stream.CanRead -or
      $Prompt.ExpectedBytes -isnot [byte[]] -or -not [IO.File]::Exists($Prompt.Path) -or
      $Prompt.Stream.Length -ne $Prompt.ExpectedBytes.Length) { throw 'retained Grok prompt identity is unavailable' }
  $null = $Prompt.Stream.Seek(0, [IO.SeekOrigin]::Begin)
  $actual = New-Object byte[] $Prompt.ExpectedBytes.Length
  $offset = 0
  while ($offset -lt $actual.Length) {
    $count = $Prompt.Stream.Read($actual, $offset, $actual.Length - $offset)
    if ($count -le 0) { throw 'retained Grok prompt acquisition was truncated' }
    $offset += $count
  }
  for ($index = 0; $index -lt $actual.Length; $index++) {
    if ($actual[$index] -ne $Prompt.ExpectedBytes[$index]) { throw 'retained Grok prompt bytes changed' }
  }
  $null = $Prompt.Stream.Seek(0, [IO.SeekOrigin]::Begin)
}

function Get-CrgGrokCliPath {
  $commands = @(Get-Command -Name 'grok.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
  $candidate = if ($commands.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($commands[0].Source)) {
    $commands[0].Source
  } else {
    $userProfilePath = [Environment]::GetEnvironmentVariable('USERPROFILE', [EnvironmentVariableTarget]::Process)
    if ([string]::IsNullOrWhiteSpace($userProfilePath)) { throw 'configured Grok CLI review requires a Windows user profile' }
    Join-Path $userProfilePath '.grok\bin\grok.exe'
  }
  $path = [IO.Path]::GetFullPath($candidate)
  # Ordinal compares throughout: PS 5.1 culture rules ignore characters such as U+00AD.
  if (-not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetPathRoot($path).Length -lt 3 -or
      -not [string]::Equals([IO.Path]::GetExtension($path), '.exe', [StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($path) -or
      ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'configured Grok CLI review requires an ordinary grok.exe from PATH or the standard user installation'
  }
  return $path
}

function Get-CrgGrokCliEnvironment {
  $source = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
  $entries = New-Object 'System.Collections.Generic.List[string]'
  foreach ($item in $source.GetEnumerator()) {
    $name = [string]$item.Key
    if ($name -imatch '\A(?:XAI_API_KEY|GROK_HOME|GROK_MEMORY|GROK_DISABLE_AUTOUPDATER|GROK_LOG_FILE|RUST_LOG)\z') { continue }
    if ([string]::Equals($name, 'Path', [StringComparison]::OrdinalIgnoreCase)) { $name = 'Path' }
    $entries.Add($name + '=' + [string]$item.Value)
  }
  $entries.Add('GROK_MEMORY=0')
  $entries.Add('GROK_DISABLE_AUTOUPDATER=1')
  return ,$entries.ToArray()
}

function Invoke-CrgGrokCliRequest {
  param([object]$HostInput, [object]$ProviderSnapshot, [string]$Executable, [string]$PromptPath,
    [string]$ResponseLeaf, [string]$StandardErrorLeaf, [ValidatePattern('\Agrok-[0-9a-z.-]+\z')][string]$Model,
    [ValidatePattern('\A(?:low|medium|high|xhigh)\z', Options = 'None')][string]$Effort, [int]$StallWarnMs, [string]$LivenessLeaf)
  $responsePath = Join-Path $HostInput.OutDir $ResponseLeaf
  $responseStream = [IO.File]::Open($responsePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
  try {
    $standardErrorPath = Join-Path $HostInput.OutDir $StandardErrorLeaf
    $standardErrorStream = [IO.File]::Open($standardErrorPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
  } catch {
    $responseStream.Dispose()
    throw
  }
  $session = $null; $quiescent = $true; $heartbeat = $null
  try {
    $root = $ProviderSnapshot.Root
    $permissionRoot = $root.Replace('\', '/')
    # No --max-turns and no deadline: like the Codex and Claude reviewers, a
    # Grok pass runs until it finishes (docs/reviewer-liveness-design.md).
    # Turn caps and the one-hour kill were removed in 2.4.4; a capped or
    # killed pass is an unavailable review, never a shorter one, so a bound
    # only converted slow reviews into failures. A CLI that stops on its own
    # limit still reports a non-success result, which the stream check refuses.
    $arguments = @('--no-auto-update', '--model', $Model, '--reasoning-effort', $Effort,
      '--tools', 'read_file,grep,list_dir', '--deny', 'MCPTool', '--permission-mode', 'dontAsk',
      '--allow', ('Read(' + $permissionRoot + '/**)'), '--allow', ('Grep(' + $permissionRoot + '/**)'),
      '--no-plan', '--no-subagents', '--disable-web-search', '--verbatim',
      '--output-format', 'streaming-messages-json', '--cwd', $root, '--prompt-file', $PromptPath)
    try {
      $session = Start-CrgPairedReviewProcess -ApplicationName $Executable -Arguments $arguments -WorkingDirectory $root `
        -EnvironmentEntries (Get-CrgGrokCliEnvironment) -TranscriptStream $responseStream -StandardErrorStream $standardErrorStream
      $quiescent = $false
    } catch {
      $failure = $_.Exception
      while ($null -ne $failure -and -not $failure.Data.Contains('CrgPairedProcessSession')) { $failure = $failure.InnerException }
      if ($null -ne $failure) { $session = $failure.Data['CrgPairedProcessSession']; $quiescent = $false }
      throw
    }
    # The streamed Messages transcript grows per turn and tool call, so it is
    # this pass's liveness evidence, owned by the Grok root process.
    $heartbeat = Get-AdversarialReviewHeartbeat
    $heartbeat.Start("grok-$($HostInput.ScopeTag)-$PID", 30000, $HostInput.OutDir, $ResponseLeaf, $StallWarnMs,
      (Join-Path $HostInput.OutDir $LivenessLeaf), ($ResponseLeaf + '=' + $session.ProcessId))
    $rootExitedWithDescendants = $false
    do {
      $observations = @(Wait-CrgPairedReviewProcess -Session $session -TimeoutMilliseconds 10000)
      if ($observations.Count -ne 1 -or ($null -ne $observations[0].Error -and -not [string]::Equals([string]$observations[0].Error, 'drain-timeout', [StringComparison]::Ordinal))) {
        throw 'Grok CLI process observation failed'
      }
      $observation = $observations[0]
      $responseStream.Flush(); $standardErrorStream.Flush()
      if ($responseStream.Length -gt 16777216 -or $standardErrorStream.Length -gt 16777216) {
        throw 'Grok CLI response or diagnostic transcript exceeds 16 MiB'
      }
      if ($observation.ExitObserved -and -not $observation.Quiescent) {
        if ($rootExitedWithDescendants) { throw 'Grok CLI descendants did not drain after root exit' }
        $rootExitedWithDescendants = $true
      }
    } while (-not $observation.Quiescent)
    $observations = @(Complete-CrgPairedReviewProcess -Session $session -TimeoutMilliseconds 0)
    if ($observations.Count -ne 1) { throw 'Grok CLI completion returned an invalid observation count' }
    $observation = $observations[0]
    if (-not $observation.ProcessCreated -or -not $observation.ExitObserved -or $observation.ActiveProcesses -ne 0 -or
        -not $observation.Quiescent -or -not $observation.Closed -or $null -ne $observation.Error) {
      throw 'Grok CLI completion did not establish root exit and descendant drain'
    }
    $quiescent = $true; $session = $null
    $responseStream.Flush($true); $standardErrorStream.Flush($true)
    if ($responseStream.Length -gt 16777216 -or $standardErrorStream.Length -gt 16777216) {
      throw 'Grok CLI response or diagnostic transcript exceeds 16 MiB'
    }
    $null = $responseStream.Seek(0, [IO.SeekOrigin]::Begin)
    $bytes = New-Object byte[] ([int]$responseStream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $count = $responseStream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($count -le 0) { throw 'Grok CLI response acquisition was truncated' }
      $offset += $count
    }
    if ($observation.ExitCode -ne 0) { throw "Grok CLI returned exit $($observation.ExitCode); no complete review or positive exhaustion evidence exists" }
    return ,$bytes
  } finally {
    if ($null -ne $heartbeat -and -not $heartbeat.Stop()) {
      Write-Host '[paired-review] WARN: the Grok heartbeat thread did not confirm quiescence; the retained liveness log may miss trailing records'
    }
    if ($null -ne $session) {
      try {
        $stopped = @(Stop-CrgPairedReviewProcess -Session $session -TimeoutMilliseconds 10000)
        if ($stopped.Count -eq 1 -and $stopped[0].Quiescent) {
          $closed = @(Close-CrgPairedReviewProcess -Session $session)
          $quiescent = $closed.Count -eq 1 -and $closed[0].Closed -and $closed[0].Quiescent -and $null -eq $closed[0].Error
        }
      } catch { $quiescent = $false }
    }
    $responseStream.Dispose(); $standardErrorStream.Dispose()
    if (-not $quiescent) { throw 'Grok CLI process cleanup is unconfirmed' }
  }
}

function New-CrgGrokRequestBytes {
  param([object]$HostInput, [ValidatePattern('\Agrok-[0-9a-z.-]+\z')][string]$Model,
    [ValidatePattern('\A(?:low|medium|high|xhigh)\z', Options = 'None')][string]$Effort)
  $bundle = $HostInput.InputBundle
  $records = New-Object 'System.Collections.Generic.List[object]'
  [long]$total = 0
  # The governing prompt requires the same evidence alias supplied by the
  # filesystem-backed provider snapshots, even though this transport has no tools.
  $evidence = @{ 'PLAN-CONSISTENCY.txt' = $bundle.Buffers['PLAN-CONSISTENCY-REPORT.md'] }
  # Every captured buffer and candidate blob is supplied. A bound failure is
  # an unavailable review, never permission to trim unseen source or evidence.
  foreach ($selection in @(@{ Prefix = ''; Buffers = $bundle.Buffers }, @{ Prefix = 'REVIEW_SRC/'; Buffers = $bundle.ContextBlobBuffers },
      @{ Prefix = 'CODEX_REVIEW_EVIDENCE/'; Buffers = $evidence })) {
    [string[]]$paths = @($selection.Buffers.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    foreach ($path in $paths) {
      $bytes = $selection.Buffers[$path]
      if ($bytes -isnot [byte[]]) { throw 'Grok request lacks a captured file byte buffer' }
      $total += $bytes.Length
      if ($total -gt 33554432 -or $records.Count -ge 100000) { throw 'Grok complete context exceeds the 32 MiB/100000-file request bound' }
      $encoding = 'utf-8'; $content = ''
      try { $content = $utf8.GetString($bytes) }
      catch { $encoding = 'base64'; $content = [Convert]::ToBase64String($bytes) }
      if ($encoding -ceq 'utf-8' -and $content.Contains([char]0)) { $encoding = 'base64'; $content = [Convert]::ToBase64String($bytes) }
      $records.Add([ordered]@{ path = ($selection.Prefix + $path); encoding = $encoding; content = $content })
    }
  }
  $data = ConvertTo-Json -InputObject ([ordered]@{
    kind = 'captured-review-data'; preparedPairSha256 = $bundle.DescriptorSha256
    contextEntries = $bundle.Metadata.ContextEntries; files = $records.ToArray()
  }) -Depth 12 -Compress
  $request = [ordered]@{
    model = $Model; reasoning = @{ effort = $Effort }; store = $false; stream = $false
    tools = @(); tool_choice = 'none'; truncation = 'disabled'; max_output_tokens = 32768
    input = @(
      @{ role = 'system'; content = $HostInput.FullPrompt },
      @{ role = 'user'; content = $data }
    )
  }
  $bytes = $utf8.GetBytes((ConvertTo-Json -InputObject $request -Depth 8 -Compress))
  if ($bytes.Length -gt 67108864) { throw 'Grok complete encoded request exceeds 64 MiB; no request was sent' }
  return ,$bytes
}

function Invoke-CrgGrokRequest {
  param([byte[]]$RequestBytes, [string]$ApiKey)
  Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $false
  $handler.UseDefaultCredentials = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
  $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, 'https://api.x.ai/v1/responses')
  $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $ApiKey)
  $request.Content = [Net.Http.ByteArrayContent]::new($RequestBytes)
  $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
  $response = $null; $stream = $null; $output = [IO.MemoryStream]::new()
  try {
    # No deadline, matching every other reviewer (the one-hour cancellation
    # was removed in 2.4.4); the body stays size-bounded. No redirects,
    # automatic retries, tools, stored conversation or endpoint discovery.
    $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    if ($null -eq $response.Content -or
        ($null -ne $response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -gt 16777216)) { throw 'Grok HTTP response body is absent or exceeds 16 MiB' }
    $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $buffer = New-Object byte[] 8192
    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      if ($output.Length + $count -gt 16777216) { throw 'Grok HTTP response exceeds 16 MiB' }
      $output.Write($buffer, 0, $count)
    }
    return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Bytes = $output.ToArray() }
  } catch {
    # Exception text from an HTTP stack is not an approved diagnostic surface
    # for credentials or request headers. Preserve only the failure category.
    throw 'Grok API transport/body acquisition failed; no review result or exhaustion classification was produced'
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
    if ($null -ne $response) { $response.Dispose() }
    $request.Dispose(); $output.Dispose(); $client.Dispose(); $handler.Dispose()
  }
}

function Assert-CrgGrokJsonMembers {
  param([string]$Text)
  # ConvertFrom-Json on Windows PowerShell can keep the last duplicate member.
  # Duplicate and case-alias detection must use decoded names before that projection;
  # complete value and container grammar is then checked by the JSON decoder.
  $pattern = '"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|[{}\[\],:]'
  $frames = New-Object 'System.Collections.Generic.List[object]'
  $position = 0; $count = 0; $previous = ''
  foreach ($token in [regex]::Matches($Text, $pattern)) {
    if (++$count -gt 100000 -or $Text.Substring($position, $token.Index - $position) -cnotmatch '\A[ \t\r\n]*\z') { throw 'Grok JSON has prohibited syntax or exceeds the token bound' }
    $position = $token.Index + $token.Length
    $value = $token.Value
    $frame = if ($frames.Count -gt 0) { $frames[$frames.Count - 1] } else { $null }
    if ([Array]::IndexOf([string[]]@('{', '['), [string]$value) -ge 0) {
      if ($frames.Count -ge 64) { throw 'Grok JSON exceeds the nesting bound' }
      $frames.Add([pscustomobject]@{ Kind = $value; Key = [string]::Equals($value, '{', [StringComparison]::Ordinal); Names = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)) })
    } elseif ([Array]::IndexOf([string[]]@('}', ']'), [string]$value) -ge 0) {
      if ($null -eq $frame -or [string]::Equals($previous, ',', [StringComparison]::Ordinal) -or ([string]::Equals($value, '}', [StringComparison]::Ordinal) -and -not [string]::Equals($frame.Kind, '{', [StringComparison]::Ordinal)) -or ([string]::Equals($value, ']', [StringComparison]::Ordinal) -and -not [string]::Equals($frame.Kind, '[', [StringComparison]::Ordinal))) { throw 'Grok JSON has an invalid or trailing-comma container' }
      $frames.RemoveAt($frames.Count - 1)
    } elseif ($null -ne $frame -and [string]::Equals($frame.Kind, '{', [StringComparison]::Ordinal)) {
      if ([string]::Equals($value, ',', [StringComparison]::Ordinal)) { $frame.Key = $true }
      elseif ($frame.Key -and $value.StartsWith('"', [StringComparison]::Ordinal)) {
        $decoded = ConvertFrom-Json -InputObject ('{"name":' + $value + '}') -ErrorAction Stop
        if (-not $frame.Names.Add([string]$decoded.name)) { throw 'Grok JSON contains a duplicate or case-aliased object member' }
        $frame.Key = $false
      }
    }
    $previous = $value
  }
  if ($frames.Count -ne 0 -or $Text.Substring($position) -cnotmatch '\A[ \t\r\n]*\z') { throw 'Grok JSON is truncated or contains non-JSON syntax' }
}

function Read-CrgGrokResponse {
  param([byte[]]$Bytes, [ValidatePattern('\Agrok-[0-9a-z.-]+\z')][string]$Model,
    [ValidatePattern('\A(?:low|medium|high|xhigh)\z', Options = 'None')][string]$Effort)
  try {
    $text = $utf8.GetString($Bytes)
    Assert-CrgGrokJsonMembers -Text $text
    $response = ConvertFrom-Json -InputObject $text -ErrorAction Stop
  }
  catch { throw 'Grok API body is not a complete strict-UTF8 JSON document' }
  if ($response -isnot [pscustomobject] -or $response.object -isnot [string] -or -not [string]::Equals($response.object, 'response', [StringComparison]::Ordinal) -or
      $response.status -isnot [string] -or -not [string]::Equals($response.status, 'completed', [StringComparison]::Ordinal) -or
      $response.model -isnot [string] -or $response.model -cnotmatch ('\A' + [regex]::Escape($Model) + '(?:-(?:[0-9]{4}|[0-9]{8}|[0-9]{4}-[0-9]{2}-[0-9]{2}))?\z') -or
      $response.output -isnot [Array] -or $response.output.Count -eq 0 -or
      $response.output.Count -gt 128 -or $null -ne $response.error -or $null -ne $response.incomplete_details -or
      ($null -ne $response.PSObject.Properties['store'] -and ($response.store -isnot [bool] -or $response.store))) { throw 'Grok response is incomplete, failed, mismatched, or contradicts nonstored mode' }
  if ($null -ne $response.reasoning.effort -and ($response.reasoning.effort -isnot [string] -or -not [string]::Equals($response.reasoning.effort, $Effort, [StringComparison]::Ordinal))) { throw 'Grok response reports an effort different from the requested profile effort' }
  $messages = New-Object 'System.Collections.Generic.List[object]'
  foreach ($item in $response.output) {
    if ($item -isnot [pscustomobject] -or $item.type -isnot [string] -or [Array]::IndexOf([string[]]@('reasoning', 'message'), [string]$item.type) -lt 0 -or
        ($null -ne $item.PSObject.Properties['status'] -and $null -ne $item.status -and ($item.status -isnot [string] -or -not [string]::Equals($item.status, 'completed', [StringComparison]::Ordinal)))) { throw 'Grok response contains an unfinished or unrequested output type' }
    if ([string]::Equals($item.type, 'message', [StringComparison]::Ordinal)) { $messages.Add($item) }
  }
  if ($messages.Count -ne 1 -or $messages[0].role -isnot [string] -or -not [string]::Equals($messages[0].role, 'assistant', [StringComparison]::Ordinal) -or
      $messages[0].status -isnot [string] -or -not [string]::Equals($messages[0].status, 'completed', [StringComparison]::Ordinal) -or $messages[0].content -isnot [Array] -or
      $messages[0].content.Count -ne 1 -or $messages[0].content[0].type -isnot [string] -or -not [string]::Equals($messages[0].content[0].type, 'output_text', [StringComparison]::Ordinal) -or
      $messages[0].content[0].text -isnot [string] -or [string]::IsNullOrWhiteSpace($messages[0].content[0].text)) { throw 'Grok response must contain exactly one complete assistant text verdict' }
  return $messages[0].content[0].text
}

function Read-CrgGrokCliResponse {
  param([byte[]]$Bytes, [ValidatePattern('\Agrok-[0-9a-z.-]+\z')][string]$Model)
  $modelPattern = '\A' + [regex]::Escape($Model) + '(?:-build)?\z'
  try {
    $text = $utf8.GetString($Bytes)
    $lines = @($text -split '\r?\n', 0)
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1].Length -eq 0) {
      $lines = if ($lines.Count -eq 1) { @() } else { @($lines[0..($lines.Count - 2)]) }
    }
    if ($lines.Count -lt 2 -or $lines.Count -gt 4096) { throw 'Grok CLI stream has an invalid line count' }
    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in $lines) {
      if ([string]::IsNullOrWhiteSpace($line)) { throw 'Grok CLI stream contains an empty record' }
      Assert-CrgGrokJsonMembers -Text $line
      $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop
      if ($record -isnot [pscustomobject] -or $record.type -isnot [string] -or
          $record.session_id -isnot [string] -or [string]::IsNullOrWhiteSpace($record.session_id)) {
        throw 'Grok CLI stream record lacks a scalar type or session identity'
      }
      $records.Add($record)
    }
  }
  catch { throw 'Grok CLI output is not a complete strict-UTF8 NDJSON stream' }
  $initial = $records[0]
  if (-not [string]::Equals($initial.type, 'system', [StringComparison]::Ordinal) -or $initial.subtype -isnot [string] -or -not [string]::Equals($initial.subtype, 'init', [StringComparison]::Ordinal) -or
      $initial.apiKeySource -isnot [string] -or -not [string]::Equals($initial.apiKeySource, 'oauth', [StringComparison]::Ordinal) -or
      $initial.model -isnot [string] -or $initial.model -cnotmatch $modelPattern) {
    throw 'Grok CLI stream lacks the configured local-login model initialization'
  }
  $sessionId = $initial.session_id
  $initCount = 0; $finalAssistant = $null
  foreach ($record in $records) {
    if (-not [string]::Equals($record.session_id, $sessionId, [StringComparison]::Ordinal)) { throw 'Grok CLI stream contains mismatched session identities' }
    if ([string]::Equals($record.type, 'system', [StringComparison]::Ordinal) -and $record.subtype -is [string] -and [string]::Equals($record.subtype, 'init', [StringComparison]::Ordinal)) { $initCount++ }
    if ([string]::Equals($record.type, 'result', [StringComparison]::Ordinal) -and $record -ne $records[$records.Count - 1]) { throw 'Grok CLI stream contains a nonterminal result record' }
    if ([string]::Equals($record.type, 'assistant', [StringComparison]::Ordinal)) { $finalAssistant = $record }
  }
  $response = $records[$records.Count - 1]
  if ($initCount -ne 1 -or -not [string]::Equals($response.type, 'result', [StringComparison]::Ordinal) -or $response.subtype -isnot [string] -or
      -not [string]::Equals($response.subtype, 'success', [StringComparison]::Ordinal) -or $response.is_error -isnot [bool] -or $response.is_error -or
      $response.result -isnot [string] -or [string]::IsNullOrWhiteSpace($response.result) -or
      $response.stop_reason -isnot [string] -or -not [string]::Equals($response.stop_reason, 'end_turn', [StringComparison]::Ordinal) -or
      ($response.num_turns -isnot [int] -and $response.num_turns -isnot [long]) -or
      $response.num_turns -lt 1 -or $response.modelUsage -isnot [pscustomobject]) {
    throw 'Grok CLI stream is incomplete or lacks one successful terminal verdict'
  }
  $models = @($response.modelUsage.PSObject.Properties)
  if ($models.Count -ne 1 -or $models[0].Name -cnotmatch $modelPattern -or
      $models[0].Value -isnot [pscustomobject]) {
    throw 'Grok CLI output lacks the supported single-model usage identity'
  }
  $modelCalls = $models[0].Value.PSObject.Properties['modelCalls']
  if ($null -ne $modelCalls -and
      (($modelCalls.Value -isnot [int] -and $modelCalls.Value -isnot [long]) -or
       $modelCalls.Value -lt 1 -or $modelCalls.Value -ne $response.num_turns)) {
    throw 'Grok CLI output contains invalid optional model-call usage'
  }
  if ($null -eq $finalAssistant -or $finalAssistant.PSObject.Properties['parent_tool_use_id'] -eq $null -or
      $null -ne $finalAssistant.parent_tool_use_id -or $finalAssistant.message -isnot [pscustomobject] -or
      $finalAssistant.message.role -isnot [string] -or -not [string]::Equals($finalAssistant.message.role, 'assistant', [StringComparison]::Ordinal) -or
      $finalAssistant.message.model -isnot [string] -or $finalAssistant.message.model -cnotmatch $modelPattern -or
      $finalAssistant.message.stop_reason -isnot [string] -or -not [string]::Equals($finalAssistant.message.stop_reason, 'end_turn', [StringComparison]::Ordinal) -or
      $finalAssistant.message.content -isnot [Array]) { throw 'Grok CLI stream lacks one complete final main-conversation assistant message' }
  $texts = New-Object 'System.Collections.Generic.List[string]'
  foreach ($content in $finalAssistant.message.content) {
    if ($content -isnot [pscustomobject] -or $content.type -isnot [string] -or [Array]::IndexOf([string[]]@('thinking', 'text'), [string]$content.type) -lt 0) {
      throw 'Grok CLI final assistant message contains an unsupported or unfinished content block'
    }
    if ([string]::Equals($content.type, 'text', [StringComparison]::Ordinal)) {
      if ($content.text -isnot [string]) { throw 'Grok CLI final assistant text block is malformed' }
      $texts.Add($content.text)
    } elseif ($content.thinking -isnot [string] -or
        ($null -ne $content.PSObject.Properties['signature'] -and $content.signature -isnot [string])) {
      throw 'Grok CLI final assistant thinking block is malformed'
    }
  }
  if ($texts.Count -ne 1 -or -not [string]::Equals($texts[0], $response.result, [StringComparison]::Ordinal)) {
    throw 'Grok CLI terminal result does not exactly match the final assistant text'
  }
  return $response.result
}

$pairedHost = $null; $providerSnapshot = $null; $promptOwner = $null; $exitCode = 3; $apiKey = $null
$duration = $null
try {
  $sharedScripts = Split-Path -Parent $PSScriptRoot
  foreach ($moduleName in @('private-governance', 'paired-governance', 'paired-tree', 'review-preparation',
      'project-preparation', 'paired-review-input', 'paired-diff', 'paired-preparation', 'paired-process', 'review-liveness')) {
    Import-Module -Name (Join-Path $sharedScripts ($moduleName + '.psm1')) -Force -DisableNameChecking -ErrorAction Stop
  }
  $stallResolved = Resolve-StallWarnMs -Raw $env:CROSS_REVIEW_STALL_WARN_SECS
  if (-not $stallResolved.Ok) { throw "CROSS_REVIEW_STALL_WARN_SECS='$($env:CROSS_REVIEW_STALL_WARN_SECS)' is not a valid stall-warning threshold (integer seconds, 30..86400)" }
  $pairedHost = Open-CrgPairedHostInput -HostScriptPath $PSCommandPath -PreparedPairPath $PreparedPairPath `
    -PreparedPairSha256 $PreparedPairSha256 -PreparedPublicTreeSha256 $PreparedPublicTreeSha256 `
    -PreparedPrivateTreeSha256 $PreparedPrivateTreeSha256 -OutDir $OutDir -Backend grok -PreparedOrigin $PreparedOrigin
  $configuration = $pairedHost.InputBundle.Metadata.Descriptor.GoverningConfig
  # The governing configuration names a central profile; this release's
  # profile table (resolved when the configuration was parsed) supplies the
  # model and effort, and the profile or a legacy record supplies the
  # transport and authentication that run here.
  if (-not [string]::Equals([string]$configuration.ReviewerPolicy, 'grok-fallback', [StringComparison]::Ordinal) -or $null -eq $configuration.Grok -or
      [Array]::IndexOf([string[]]@('low', 'medium', 'high', 'xhigh'), [string]$configuration.Grok.Effort) -lt 0 -or
      [Array]::IndexOf([string[]]@(Get-CrgGrokAllowedIdentities -Config $configuration), [string]($configuration.Grok.Model + '|' + $configuration.Grok.Effort)) -lt 0) { throw 'Grok review is not enabled by the captured governing configuration' }
  $model = [string]$configuration.Grok.Model
  $effort = [string]$configuration.Grok.Effort
  $transport = $configuration.Grok.Transport
  if ([string]::Equals([string]$transport, 'api', [StringComparison]::Ordinal) -and [string]::Equals([string]$configuration.Grok.Authentication, 'environment-key', [StringComparison]::Ordinal)) {
    $requestBytes = New-CrgGrokRequestBytes -HostInput $pairedHost -Model $model -Effort $effort
    # Credential acquisition occurs only inside an explicitly configured live
    # API review. The key is never accepted as an argument, inspected, or archived.
    $apiKey = [Environment]::GetEnvironmentVariable('XAI_API_KEY', [EnvironmentVariableTarget]::Process)
    if ([string]::IsNullOrWhiteSpace($apiKey) -or $apiKey.Length -gt 8192 -or $apiKey -match '[\s\x00-\x1f\x7f]') { throw 'configured Grok API review requires a valid XAI_API_KEY in the process environment' }
  } elseif ([string]::Equals([string]$transport, 'cli', [StringComparison]::Ordinal) -and [string]::Equals([string]$configuration.Grok.Authentication, 'local-login', [StringComparison]::Ordinal)) {
    $grokExecutable = Get-CrgGrokCliPath
    # The snapshot creates, owns and removes its own uniquely named root under
    # this parent, so no adapter-created directory or pathname deletion is
    # needed. Do not use the attempt directory ($pairedHost.OutDir) as the
    # parent: the session holds it open, so snapshot custody cannot pin it
    # (Win32 error 32, found by the first live gate run of the Grok CLI route
    # on 2026-09-27). Codex and Claude snapshots also live under TEMP.
    try {
      $providerSnapshot = New-CrgPairedProviderSnapshot -InputBundle $pairedHost.InputBundle `
        -RuntimeTemplateBytes $pairedHost.RuntimeTemplateBytes -TempParent $env:TEMP -Backend grok -PreparedOrigin $pairedHost.Origin
    } catch {
      $pairedHost.ProviderSnapshotFailure = $_.Exception
      throw
    }
  } else { throw 'Grok review transport and authentication do not match the captured governing configuration' }
  $stem = 'review-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture) + '-' + $pairedHost.ScopeTag
  if ([string]::Equals([string]$transport, 'cli', [StringComparison]::Ordinal)) {
    $promptOwner = Open-CrgGrokPromptEvidence -HostInput $pairedHost -Leaf ($stem + '.prompt.txt') -Bytes $utf8.GetBytes($pairedHost.FullPrompt)
    Assert-CrgGrokPromptEvidence -Prompt $promptOwner
  }
  $verdicts = New-Object 'System.Collections.Generic.List[string]'
  $exitCode = 0
  # REVIEW-DURATION-SECS anchors at the first reviewer launch, as in the
  # Codex and Claude wrappers, so adapter setup and the checks before that
  # first launch never count; the clock then runs across every later pass.
  for ($pass = 1; $pass -le $ReviewPasses; $pass++) {
    Assert-CrgPairedReadContext -Context $pairedHost.ReadContext -InputBundle $pairedHost.InputBundle
    Write-Host "[paired-review] starting full review pass $pass/$ReviewPasses"
    $responseLeaf = $stem + '.pass-' + $pass + '.response.json'
    $livenessLeaf = $stem + '.pass-' + $pass + '.liveness.jsonl'
    if ([string]::Equals([string]$transport, 'api', [StringComparison]::Ordinal)) {
      # The non-streaming API grows no evidence file until the body arrives,
      # so the beat is the timer form: visible waiting, no stall inference.
      $apiHeartbeat = Get-AdversarialReviewHeartbeat
      $apiHeartbeat.Start("grok-$($pairedHost.ScopeTag)-$PID", 30000, '', '', $stallResolved.Ms,
        (Join-Path $pairedHost.OutDir $livenessLeaf), '')
      if ($null -eq $duration) { $duration = [Diagnostics.Stopwatch]::StartNew() }
      try { $response = Invoke-CrgGrokRequest -RequestBytes $requestBytes -ApiKey $apiKey }
      finally {
        if (-not $apiHeartbeat.Stop()) { Write-Host '[paired-review] WARN: the Grok heartbeat thread did not confirm quiescence; the retained liveness log may miss trailing records' }
      }
      $null = Write-CrgGrokEvidence -HostInput $pairedHost -Leaf $responseLeaf -Bytes $response.Bytes
      if ($response.StatusCode -ne 200) {
        # xAI documents 429 as rate limiting, not positive allowance exhaustion.
        # No documented exhaustion machine code is assumed; fail closed for all
        # HTTP failures, including authentication, credit and rate-limit errors.
        throw "Grok API returned HTTP $($response.StatusCode); no complete review or positive exhaustion evidence exists"
      }
      $verdict = (Read-CrgGrokResponse -Bytes $response.Bytes -Model $model -Effort $effort).TrimEnd()
    } else {
      Assert-CrgGrokPromptEvidence -Prompt $promptOwner
      Assert-CrgPairedInputSnapshot -Snapshot $providerSnapshot
      if ($null -eq $duration) { $duration = [Diagnostics.Stopwatch]::StartNew() }
      $responseBytes = Invoke-CrgGrokCliRequest -HostInput $pairedHost -ProviderSnapshot $providerSnapshot `
        -Executable $grokExecutable -PromptPath $promptOwner.Path -ResponseLeaf $responseLeaf `
        -StandardErrorLeaf ($stem + '.pass-' + $pass + '.stderr.log') -Model $model -Effort $effort `
        -StallWarnMs $stallResolved.Ms -LivenessLeaf $livenessLeaf
      Assert-CrgPairedInputSnapshot -Snapshot $providerSnapshot
      Assert-CrgGrokPromptEvidence -Prompt $promptOwner
      $verdict = (Read-CrgGrokCliResponse -Bytes $responseBytes -Model $model).TrimEnd()
    }
    Assert-CrgPairedReadContext -Context $pairedHost.ReadContext -InputBundle $pairedHost.InputBundle
    $classification = Get-CrgPairSemanticVerdict -Verdict $verdict
    $verdicts.Add("===== REVIEW PASS $pass/$ReviewPasses =====`n" + $verdict + "`n")
    if ($classification.ExitCode -ne 0) { $exitCode = $classification.ExitCode; break }
  }
  $body = $verdicts.ToArray() -join "`n"
  $fields = $pairedHost.InputBundle.Metadata.Descriptor.Fields
  $artifact = & $pairedHost.ArtifactWriter -ReviewUnitBytes $pairedHost.InputBundle.Buffers['review-unit.txt'] `
    -PublicObjectFormat $fields['public-object-format'] -PrivateObjectFormat $fields['private-object-format'] `
    -DescriptorSha256 $pairedHost.InputBundle.DescriptorSha256 -DisplayDiffSha256 $pairedHost.DiffSha256 `
    -Backend grok -Effort $effort -DurationSecs ((Get-ReviewDurationSecs -ElapsedSeconds $duration.Elapsed.TotalSeconds).ToString([Globalization.CultureInfo]::InvariantCulture)) -VerdictText $body -RequestedModel $model
  $verdictPath = Write-CrgGrokEvidence -HostInput $pairedHost -Leaf ($stem + '.md') -Bytes $artifact
  Write-CrgPairedFollowups -HostInput $pairedHost -VerdictText $body -VerdictFile $verdictPath -Backend grok
  if ($exitCode -eq 0) {
    $readSuccess = if ($PreparedOrigin -ceq 'paired-v1') { Get-Command Read-CrgSuccessfulPairArtifactBytes -Module paired-governance }
      else { Get-Command Read-CrgSuccessfulFirstAttachmentArtifactBytes -Module paired-governance }
    $successful = & $readSuccess -Bytes $artifact -ReviewUnitBytes $pairedHost.InputBundle.Buffers['review-unit.txt'] `
      -PublicObjectFormat $fields['public-object-format'] -PrivateObjectFormat $fields['private-object-format'] `
      -DescriptorSha256 $pairedHost.InputBundle.DescriptorSha256 -DisplayDiffSha256 $pairedHost.DiffSha256 `
      -ExpectedBackend grok -ScheduledPassCount $ReviewPasses
    if (-not [string]::Equals([string]$successful.RequestedModel, $model, [StringComparison]::Ordinal) -or -not [string]::Equals([string]$successful.Effort, $effort, [StringComparison]::Ordinal)) { throw 'Grok artifact requested model or effort differs from the governing profile' }
    Write-Host '[paired-review] complete semantic review PASS - covers this source diff only, not target execution or deployment readiness'
  } else { Write-Host '[paired-review] review did not pass; private verdict evidence retained' }
} catch {
  $exitCode = 3
  Write-Host "[paired-review] Grok adapter failed: $($_.Exception.Message)"
} finally {
  $apiKey = $null
  if ($null -ne $pairedHost) {
    if (-not (Complete-CrgPairedHostInput -HostInput $pairedHost -ProviderSnapshot $providerSnapshot)) { $exitCode = 3 }
  }
  if ($null -ne $promptOwner) {
    try { Assert-CrgGrokPromptEvidence -Prompt $promptOwner }
    catch { $exitCode = 3; Write-Host "[paired-review] WARN: retained Grok prompt validation failed: $($_.Exception.Message)" }
    finally { $promptOwner.Stream.Dispose() }
  }
  if ($null -ne $duration) { $duration.Stop() }
}
exit $exitCode
