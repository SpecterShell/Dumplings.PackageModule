# SPDX-License-Identifier: MIT

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:MessageQueueRuntimeStorageKey = '__DumplingsMessageQueueRuntime'
$Script:StandaloneMessageQueueRuntime = $null
$Script:MessageQueueWorkerScript = @'
param ($Runtime, $TargetId, $LibraryPath)

$ErrorActionPreference = 'Stop'
try {
  Import-Module (Join-Path $LibraryPath 'TextContent.psm1') -Force
  Import-Module (Join-Path $LibraryPath 'Messaging.psm1') -Force
  $QueueModule = Import-Module (Join-Path $LibraryPath 'MessageQueue.psm1') -Force -PassThru
  Import-Module (Join-Path $LibraryPath 'Telegram.psm1') -Force
  Import-Module (Join-Path $LibraryPath 'Matrix.psm1') -Force
  & $QueueModule {
    param ($WorkerRuntime, $WorkerTargetId)
    Invoke-MessageQueueTargetWorker -Runtime $WorkerRuntime -TargetId $WorkerTargetId
  } $Runtime $TargetId
} catch {
  # A fatal worker initialization error must release pending waiters immediately.
  $Runtime.Broker.CancelTarget($TargetId, "The message queue worker failed: $($_.Exception.Message)")
  throw
}
'@

function Import-MessageQueueBroker {
  <#
  .SYNOPSIS
    Load the process-wide message queue broker once across runspaces.
  #>
  param ()

  if (([System.Management.Automation.PSTypeName]'Dumplings.Messaging.MessageQueueBroker').Type) { return }

  $Mutex = [Threading.Mutex]::new($false, 'Local\Dumplings-MessageQueueBroker')
  $HasLock = $false
  try {
    try { $HasLock = $Mutex.WaitOne([timespan]::FromMinutes(2)) } catch [Threading.AbandonedMutexException] { $HasLock = $true }
    if (-not $HasLock) { throw 'Timed out while loading the message queue broker' }
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.Messaging.MessageQueueBroker').Type) {
      Add-Type -Path (Join-Path $PSScriptRoot '..' 'Assets' 'Source' 'Messaging' 'MessageQueueBroker.cs')
    }
  } finally {
    if ($HasLock) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}

Import-MessageQueueBroker

function Get-MessageQueuePreferenceValue {
  param (
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][double]$DefaultValue,
    [ValidateRange(0, [double]::MaxValue)][double]$MinimumValue = 0
  )

  $PreferenceVariable = Get-Variable -Name DumplingsPreference -Scope Global -ErrorAction SilentlyContinue
  if (-not $PreferenceVariable -or $PreferenceVariable.Value -isnot [Collections.IDictionary] -or -not $PreferenceVariable.Value.Contains($Name)) {
    return $DefaultValue
  }

  $Value = 0.0
  if (-not [double]::TryParse(
      [string]$PreferenceVariable.Value[$Name],
      [Globalization.NumberStyles]::Float,
      [Globalization.CultureInfo]::InvariantCulture,
      [ref]$Value
    ) -or $Value -lt $MinimumValue) {
    Write-Warning "Ignoring invalid message queue preference '${Name}': $($PreferenceVariable.Value[$Name])"
    return $DefaultValue
  }
  return $Value
}

function New-MessageQueueRuntime {
  [OutputType([pscustomobject])]
  param ()

  return [pscustomobject]@{
    Broker                     = [Dumplings.Messaging.MessageQueueBroker]::new()
    Workers                    = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([StringComparer]::Ordinal)
    WorkerSyncRoot             = [object]::new()
    Cancellation               = [Threading.CancellationTokenSource]::new()
    IntervalSeconds            = Get-MessageQueuePreferenceValue -Name MessageQueueIntervalSeconds -DefaultValue 1 -MinimumValue 0
    MaximumRetryDelaySeconds   = [int](Get-MessageQueuePreferenceValue -Name MessageQueueMaximumRetryDelaySeconds -DefaultValue 30 -MinimumValue 0)
    MaximumTotalDelaySeconds   = [int](Get-MessageQueuePreferenceValue -Name MessageQueueMaximumTotalRetryDelaySeconds -DefaultValue 60 -MinimumValue 0)
    DefaultDrainTimeoutSeconds = [int](Get-MessageQueuePreferenceValue -Name MessageQueueDrainTimeoutSeconds -DefaultValue 300 -MinimumValue 1)
    Stopped                    = $false
  }
}

function Get-MessageQueueRuntime {
  <#
  .SYNOPSIS
    Get the runner-wide queue runtime or create a standalone fallback.
  #>
  [OutputType([pscustomobject])]
  param (
    [System.Collections.IDictionary]$Storage,
    [switch]$ExistingOnly
  )

  if (-not $PSBoundParameters.ContainsKey('Storage')) {
    $StorageVariable = Get-Variable -Name DumplingsStorage -Scope Global -ErrorAction SilentlyContinue
    $Storage = $StorageVariable ? $StorageVariable.Value : $null
  }

  if ($Storage -is [hashtable] -and $Storage.IsSynchronized) {
    [Threading.Monitor]::Enter($Storage.SyncRoot)
    try {
      if (-not $Storage.ContainsKey($Script:MessageQueueRuntimeStorageKey)) {
        if ($ExistingOnly) { return $null }
        $Storage[$Script:MessageQueueRuntimeStorageKey] = New-MessageQueueRuntime
      }
      return $Storage[$Script:MessageQueueRuntimeStorageKey]
    } finally {
      [Threading.Monitor]::Exit($Storage.SyncRoot)
    }
  }

  if ($ExistingOnly -and -not $Script:StandaloneMessageQueueRuntime) { return $null }
  if (-not $Script:StandaloneMessageQueueRuntime) { $Script:StandaloneMessageQueueRuntime = New-MessageQueueRuntime }
  return $Script:StandaloneMessageQueueRuntime
}

function Initialize-MessageQueue {
  <#
  .SYNOPSIS
    Initialize the process-wide queue before Dumplings workers start.
  #>
  param ([System.Collections.IDictionary]$Storage)

  $null = Get-MessageQueueRuntime -Storage $Storage
}

function Get-MessageQueueTargetId {
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][ValidateSet('Telegram', 'Matrix')][string]$Transport,
    [Parameter(Mandatory)][string[]]$Component
  )

  # Hash credentials together with the destination so neither is exposed through queue metadata.
  $CanonicalTarget = $Transport + "`0" + ($Component -join "`0")
  $Hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($CanonicalTarget))
  return "${Transport}:$([Convert]::ToHexString($Hash))"
}

function Start-MessageQueueTargetWorker {
  param (
    [Parameter(Mandatory)]$Runtime,
    [Parameter(Mandatory)][string]$TargetId
  )

  if ($Runtime.Workers.ContainsKey($TargetId)) { return }
  [Threading.Monitor]::Enter($Runtime.WorkerSyncRoot)
  try {
    if ($Runtime.Workers.ContainsKey($TargetId)) { return }
    if ($Runtime.Stopped -or -not $Runtime.Broker.IsAccepting) { throw 'The message queue is stopping' }

    $Runspace = [runspacefactory]::CreateRunspace()
    $PowerShell = $null
    try {
      $Runspace.Open()
      $PowerShell = [powershell]::Create()
      $PowerShell.Runspace = $Runspace
      $null = $PowerShell.AddScript($Script:MessageQueueWorkerScript).
      AddArgument($Runtime).
      AddArgument($TargetId).
      AddArgument($PSScriptRoot)
      $AsyncResult = $PowerShell.BeginInvoke()
      $Runtime.Workers[$TargetId] = [pscustomobject]@{
        TargetId    = $TargetId
        PowerShell  = $PowerShell
        Runspace    = $Runspace
        AsyncResult = $AsyncResult
      }
    } catch {
      if ($PowerShell) { $PowerShell.Dispose() }
      $Runspace.Dispose()
      throw
    }
  } finally {
    [Threading.Monitor]::Exit($Runtime.WorkerSyncRoot)
  }
}

function Get-MessageQueueSession {
  param (
    [Parameter(Mandatory)][ValidateSet('Telegram', 'Matrix')][string]$Transport,
    [Parameter(Mandatory)][string]$SessionKey,
    [Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, object]]$Sessions
  )

  if ($Sessions.ContainsKey($SessionKey)) {
    Write-Output -InputObject $Sessions[$SessionKey] -NoEnumerate
    return
  }
  if ($Transport -eq 'Telegram') {
    $Session = [System.Collections.Generic.List[System.Tuple[string, long]]]::new()
  } else {
    $Session = [System.Collections.Generic.List[System.Tuple[string, string]]]::new()
  }
  $Sessions[$SessionKey] = $Session
  Write-Output -InputObject $Session -NoEnumerate
}

function Invoke-MessageQueueTargetWorker {
  <#
  .SYNOPSIS
    Process one independently rate-limited transport target until its queue is complete.
  #>
  param (
    [Parameter(Mandatory)]$Runtime,
    [Parameter(Mandatory)][string]$TargetId
  )

  $Sessions = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  $RateLimitContext = [Dumplings.Messaging.MessageRateLimitContext]::new(
    [timespan]::FromSeconds([double]$Runtime.IntervalSeconds),
    [int]$Runtime.MaximumRetryDelaySeconds,
    [int]$Runtime.MaximumTotalDelaySeconds,
    $Runtime.Cancellation.Token
  )

  while ($true) {
    try {
      $WorkItem = $Runtime.Broker.Take($TargetId, $Runtime.Cancellation.Token)
    } catch [OperationCanceledException] {
      break
    }
    if (-not $WorkItem) { break }

    $Payload = [Collections.IDictionary]$WorkItem.Payload
    try {
      $Parameters = @{}
      foreach ($Entry in $Payload.GetEnumerator()) { $Parameters[$Entry.Key] = $Entry.Value }
      if (-not [string]::IsNullOrWhiteSpace($WorkItem.Ticket.SessionKey)) {
        $Parameters.Session = Get-MessageQueueSession -Transport $WorkItem.Ticket.Transport `
          -SessionKey $WorkItem.Ticket.SessionKey -Sessions $Sessions
      }
      $Parameters.RateLimitContext = $RateLimitContext

      if ($WorkItem.Ticket.Transport -eq 'Telegram') {
        $null = Send-TelegramMessage @Parameters
      } else {
        $null = Send-MatrixMessage @Parameters
      }
      $Runtime.Broker.Complete($WorkItem, $true, $null)
    } catch {
      $ErrorMessage = [string]$_.Exception.Message
      if ($Payload.Contains('Token') -and -not [string]::IsNullOrEmpty([string]$Payload.Token)) {
        $ErrorMessage = $ErrorMessage.Replace([string]$Payload.Token, '<redacted>')
      }
      $Runtime.Broker.Complete($WorkItem, $false, $ErrorMessage)
    }
  }
}

function Add-MessageQueueRequest {
  [OutputType([Dumplings.Messaging.MessageQueueTicket])]
  param (
    [Parameter(Mandatory)][ValidateSet('Telegram', 'Matrix')][string]$Transport,
    [Parameter(Mandatory)][string]$TargetId,
    [AllowNull()][string]$QueueKey,
    [AllowNull()][string]$SessionKey,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Payload
  )

  $Runtime = Get-MessageQueueRuntime
  $Ticket = $Runtime.Broker.Enqueue($Transport, $TargetId, $QueueKey, $SessionKey, $Payload)
  try {
    Start-MessageQueueTargetWorker -Runtime $Runtime -TargetId $TargetId
  } catch {
    # A worker startup failure must not leave a request pending forever.
    $Runtime.Broker.CancelTarget($TargetId, "The message queue worker could not start: $($_.Exception.Message)")
    throw
  }
  return $Ticket
}

function Send-QueuedTelegramMessage {
  <#
  .SYNOPSIS
    Queue a Telegram message without blocking the caller.
  .PARAMETER QueueKey
    Replace an older pending request with the same target and key.
  .PARAMETER SessionKey
    Reuse a queue-owned Telegram message session for edits.
  #>
  [CmdletBinding(DefaultParameterSetName = 'PlainText')]
  [OutputType([Dumplings.Messaging.MessageQueueTicket])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Message,
    [Parameter(DontShow, ParameterSetName = 'PlainText')][switch]$AsPlainText,
    [Parameter(ParameterSetName = 'HTML')][switch]$AsHtml,
    [Parameter(ParameterSetName = 'Markdown')][switch]$AsMarkdown,
    [AllowNull()][string]$QueueKey,
    [AllowNull()][string]$SessionKey,
    [ValidateNotNullOrWhiteSpace()][string]$ChatID = $Env:TG_CHAT_ID,
    [ValidateNotNullOrWhiteSpace()][string]$Token = $Env:TG_BOT_TOKEN,
    [ValidateRange(16, 4096)][int]$MaximumMessageLength = 4096
  )

  process {
    $null = $AsPlainText.IsPresent
    $Payload = [ordered]@{
      Message              = $Message
      ChatID               = $ChatID
      Token                = $Token
      MaximumMessageLength = $MaximumMessageLength
    }
    if ($AsHtml) { $Payload.AsHtml = $true }
    if ($AsMarkdown) { $Payload.AsMarkdown = $true }
    $TargetId = Get-MessageQueueTargetId -Transport Telegram -Component @($Token, $ChatID)
    Add-MessageQueueRequest -Transport Telegram -TargetId $TargetId -QueueKey $QueueKey -SessionKey $SessionKey -Payload $Payload
  }
}

function Send-QueuedMatrixMessage {
  <#
  .SYNOPSIS
    Queue a Matrix message without blocking the caller.
  .PARAMETER QueueKey
    Replace an older pending request with the same target and key.
  .PARAMETER SessionKey
    Reuse a queue-owned Matrix message session for edits and redactions.
  #>
  [CmdletBinding(DefaultParameterSetName = 'PlainText')]
  [OutputType([Dumplings.Messaging.MessageQueueTicket])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Message,
    [Parameter(DontShow, ParameterSetName = 'PlainText')][switch]$AsPlainText,
    [Parameter(ParameterSetName = 'HTML')][switch]$AsHtml,
    [Parameter(ParameterSetName = 'Markdown')][switch]$AsMarkdown,
    [AllowNull()][string]$QueueKey,
    [AllowNull()][string]$SessionKey,
    [ValidateNotNullOrWhiteSpace()][string]$RoomID = $Env:MT_ROOM_ID,
    [ValidateNotNullOrWhiteSpace()][string]$HomeServer = $Env:MT_HOME_SERVER ?? 'https://matrix-client.matrix.org',
    [ValidateNotNullOrWhiteSpace()][string]$Token = $Env:MT_BOT_TOKEN,
    [ValidateRange(16, [int]::MaxValue)][int]$MaximumMessageLength = 4000,
    [switch]$AllowUnencryptedInEncryptedRoom
  )

  process {
    $null = $AsPlainText.IsPresent
    $NormalizedHomeServer = $HomeServer.TrimEnd('/')
    $Payload = [ordered]@{
      Message              = $Message
      RoomID               = $RoomID
      HomeServer           = $NormalizedHomeServer
      Token                = $Token
      MaximumMessageLength = $MaximumMessageLength
    }
    if ($AsHtml) { $Payload.AsHtml = $true }
    if ($AsMarkdown) { $Payload.AsMarkdown = $true }
    if ($AllowUnencryptedInEncryptedRoom) { $Payload.AllowUnencryptedInEncryptedRoom = $true }
    $TargetId = Get-MessageQueueTargetId -Transport Matrix -Component @($Token, $NormalizedHomeServer, $RoomID)
    Add-MessageQueueRequest -Transport Matrix -TargetId $TargetId -QueueKey $QueueKey -SessionKey $SessionKey -Payload $Payload
  }
}

function Wait-MessageQueueRequest {
  <#
  .SYNOPSIS
    Wait for an asynchronous message request and return its final ticket.
  #>
  [OutputType([Dumplings.Messaging.MessageQueueTicket])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)][Dumplings.Messaging.MessageQueueTicket]$Ticket,
    [ValidateRange(-1, [int]::MaxValue)][int]$TimeoutSeconds = -1
  )

  process {
    $Timeout = $TimeoutSeconds -lt 0 ? [Threading.Timeout]::InfiniteTimeSpan : [timespan]::FromSeconds($TimeoutSeconds)
    if (-not $Ticket.Wait($Timeout)) { throw [TimeoutException]::new("Timed out waiting for message queue request '$($Ticket.RequestId)'.") }
    if ($Ticket.State -in @('Failed', 'Cancelled')) {
      throw [InvalidOperationException]::new("Message queue request '$($Ticket.RequestId)' ended as $($Ticket.State): $($Ticket.ErrorMessage)")
    }
    return $Ticket
  }
}

function Stop-MessageQueue {
  <#
  .SYNOPSIS
    Stop accepting queued messages, drain workers, and report background failures.
  #>
  [CmdletBinding()]
  param (
    [System.Collections.IDictionary]$Storage,
    [ValidateRange(1, [int]::MaxValue)][int]$DrainTimeoutSeconds,
    [switch]$StopAcceptingOnly
  )

  $RuntimeArguments = @{ ExistingOnly = $true }
  if ($PSBoundParameters.ContainsKey('Storage')) { $RuntimeArguments.Storage = $Storage }
  $Runtime = Get-MessageQueueRuntime @RuntimeArguments
  if (-not $Runtime) { return }

  $Runtime.Broker.CompleteAdding()
  if ($StopAcceptingOnly) { return }
  if ($Runtime.Stopped) { return }
  $Runtime.Stopped = $true

  if (-not $PSBoundParameters.ContainsKey('DrainTimeoutSeconds')) {
    $DrainTimeoutSeconds = [int]$Runtime.DefaultDrainTimeoutSeconds
  }
  $Deadline = [DateTime]::UtcNow.AddSeconds($DrainTimeoutSeconds)
  $Drained = $Runtime.Broker.WaitForIdle([timespan]::FromSeconds($DrainTimeoutSeconds))
  if (-not $Drained) {
    $Runtime.Broker.CancelPending("The message queue did not drain within ${DrainTimeoutSeconds} seconds.")
    $Runtime.Cancellation.Cancel()
  }

  $WorkerErrors = [System.Collections.Generic.List[string]]::new()
  foreach ($Worker in $Runtime.Workers.Values) {
    $Remaining = $Deadline - [DateTime]::UtcNow
    if ($Remaining -lt [timespan]::Zero) { $Remaining = [timespan]::Zero }
    if (-not $Worker.AsyncResult.AsyncWaitHandle.WaitOne($Remaining)) {
      try { $Worker.PowerShell.Stop() } catch {}
      $WorkerErrors.Add("Worker '$($Worker.TargetId)' did not stop before the drain timeout.")
    }
    try { $null = $Worker.PowerShell.EndInvoke($Worker.AsyncResult) } catch { $WorkerErrors.Add("Worker '$($Worker.TargetId)' failed: $($_.Exception.Message)") }
    $Worker.PowerShell.Dispose()
    $Worker.Runspace.Dispose()
  }

  $ProblemTickets = @($Runtime.Broker.GetTickets() | Where-Object State -In @('Failed', 'Cancelled'))
  if ($ProblemTickets.Count -gt 0 -or $WorkerErrors.Count -gt 0) {
    $Examples = @($ProblemTickets | Select-Object -First 5 | ForEach-Object { "$($_.Transport)/$($_.RequestId): $($_.ErrorMessage)" })
    $Details = @($Examples) + @($WorkerErrors)
    Write-Warning "The message queue stopped with $($ProblemTickets.Count) failed or unsent request(s). $($Details -join ' | ')"
  }

  $Runtime.Cancellation.Cancel()
  $Runtime.Cancellation.Dispose()
  $Runtime.Broker.Dispose()
  $Runtime.Workers.Clear()

  if ($Storage -is [hashtable] -and $Storage.IsSynchronized) {
    [Threading.Monitor]::Enter($Storage.SyncRoot)
    try { $Storage.Remove($Script:MessageQueueRuntimeStorageKey) } finally { [Threading.Monitor]::Exit($Storage.SyncRoot) }
  } elseif ($Runtime -eq $Script:StandaloneMessageQueueRuntime) {
    $Script:StandaloneMessageQueueRuntime = $null
  }
}

Export-ModuleMember -Function Send-QueuedTelegramMessage, Send-QueuedMatrixMessage, Wait-MessageQueueRequest, Stop-MessageQueue
