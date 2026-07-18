# SPDX-License-Identifier: MIT
# Matrix Client-Server API behavior: https://spec.matrix.org/latest/client-server-api/
# Matrix message hardening was independently implemented after reviewing:
# - https://github.com/NousResearch/hermes-agent
# - https://cgit.rory.gay/matrix/LibMatrix.git (AGPL-3.0-only; behavioral reference only)

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-MatrixApiException {
  [OutputType([System.InvalidOperationException])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$ErrorCode,

    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Description
  )

  $Exception = [System.InvalidOperationException]::new("Matrix API error ${ErrorCode}: ${Description}")
  $Exception.Data['MatrixErrorCode'] = $ErrorCode
  $Exception.Data['MatrixDescription'] = $Description
  return $Exception
}

function Invoke-MatrixApi {
  <#
  .SYNOPSIS
    Invoke the Matrix Client-Server API with bounded idempotent retries.
  .PARAMETER EndPoint
    Matrix endpoint relative to the homeserver.
  .PARAMETER Method
    HTTP method.
  .PARAMETER Body
    JSON request body.
  .PARAMETER HomeServer
    Matrix homeserver URL.
  .PARAMETER Token
    Matrix client access token.
  .PARAMETER TransactionID
    Stable transaction ID. A GUID is generated once for PUT requests with a body.
  .PARAMETER AllowedErrorCode
    Matrix errors that should be returned to the caller instead of thrown.
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time to establish the connection and receive response headers.
  .PARAMETER OperationTimeoutSeconds
    Maximum time without response progress.
  .PARAMETER MaximumRetryCount
    Maximum number of retries after the initial request.
  .PARAMETER RetryIntervalSec
    Default retry delay when Matrix does not provide retry_after_ms.
  .PARAMETER MaximumRetryDelaySeconds
    Maximum accepted delay for one retry.
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative retry delay for one operation.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$EndPoint,

    [Parameter(Mandatory)]
    [Microsoft.PowerShell.Commands.WebRequestMethod]$Method,

    [Parameter(ValueFromPipeline)]
    [AllowNull()]
    [System.Collections.IDictionary]$Body,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$HomeServer = $Env:MT_HOME_SERVER ?? 'https://matrix-client.matrix.org',

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:MT_BOT_TOKEN,

    [AllowNull()]
    [string]$TransactionID,

    [string[]]$AllowedErrorCode = @(),

    [ValidateRange(0, [int]::MaxValue)]
    [int]$ConnectionTimeoutSeconds = 15,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$OperationTimeoutSeconds = 15,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaximumRetryCount = 3,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$RetryIntervalSec = 3,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaximumRetryDelaySeconds = 30,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaximumTotalRetryDelaySeconds = 60,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    if ($RateLimitContext) {
      $MaximumRetryDelaySeconds = $RateLimitContext.MaximumRetryDelaySeconds
      $MaximumTotalRetryDelaySeconds = $RateLimitContext.MaximumTotalRetryDelaySeconds
    }
    $HasBody = $null -ne $Body
    $Uri = $HomeServer.TrimEnd('/') + '/' + $EndPoint.TrimStart('/')
    if ($Method -eq 'Put' -and $HasBody) {
      if ([string]::IsNullOrWhiteSpace($TransactionID)) { $TransactionID = [Guid]::NewGuid().ToString('N') }
      $Uri += '/' + [Uri]::EscapeDataString($TransactionID)
    }

    $Attempt = 0
    $TotalDelay = 0
    while ($true) {
      $Attempt++
      $StatusCode = 0
      $Parameters = @{
        Uri                      = $Uri
        Method                   = $Method
        Headers                  = @{ Authorization = "Bearer ${Token}" }
        SkipHttpErrorCheck       = $true
        StatusCodeVariable       = 'StatusCode'
        MaximumRetryCount        = 0
        ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds
        OperationTimeoutSeconds  = $OperationTimeoutSeconds
      }
      if ($HasBody) {
        $Parameters.Body = ConvertTo-Json -InputObject $Body -Compress -EscapeHandling EscapeNonAscii -Depth 20
        $Parameters.ContentType = 'application/json'
      }

      try {
        if ($RateLimitContext -and $Method -ne 'Get') { $RateLimitContext.Wait() }
        try {
          $Response = Invoke-RestMethod @Parameters
        } finally {
          if ($RateLimitContext -and $Method -ne 'Get') { $RateLimitContext.MarkAttemptCompleted() }
        }
      } catch [OperationCanceledException] {
        throw
      } catch {
        if ($Attempt -gt $MaximumRetryCount) {
          throw [System.InvalidOperationException]::new("Matrix request transport failure: $($_.Exception.Message)")
        }

        $Delay = $RetryIntervalSec
        if ($Delay -gt $MaximumRetryDelaySeconds -or $TotalDelay + $Delay -gt $MaximumTotalRetryDelaySeconds) {
          throw [System.InvalidOperationException]::new("Matrix request transport failure exceeded the retry-delay limit: $($_.Exception.Message)")
        }
        if ($RateLimitContext -and $Method -ne 'Get') { $RateLimitContext.SetRetryAfter([timespan]::FromSeconds($Delay)) } else { Start-Sleep -Seconds $Delay }
        $TotalDelay += $Delay
        continue
      }

      if (-not $Response.errcode) { return $Response }
      if ([string]$Response.errcode -in $AllowedErrorCode) { return $Response }

      $CanRetry = $Attempt -le $MaximumRetryCount -and (
        $Response.errcode -eq 'M_LIMIT_EXCEEDED' -or $StatusCode -eq 408 -or $StatusCode -eq 429 -or $StatusCode -ge 500
      )
      if (-not $CanRetry) { throw (Get-MatrixApiException -ErrorCode ([string]$Response.errcode) -Description ([string]$Response.error)) }

      $RequestedDelay = if ($Response.retry_after_ms) {
        [int][Math]::Ceiling([double]$Response.retry_after_ms / 1000)
      } else {
        $RetryIntervalSec
      }
      if ($RequestedDelay -gt $MaximumRetryDelaySeconds -or $TotalDelay + $RequestedDelay -gt $MaximumTotalRetryDelaySeconds) {
        throw (Get-MatrixApiException -ErrorCode ([string]$Response.errcode) -Description "$($Response.error) (requested retry delay ${RequestedDelay}s exceeds the configured limit)")
      }

      if ($RateLimitContext -and $Method -ne 'Get') { $RateLimitContext.SetRetryAfter([timespan]::FromSeconds($RequestedDelay)) } else { Start-Sleep -Seconds $RequestedDelay }
      $TotalDelay += $RequestedDelay
    }
  }
}

function Test-MatrixRoomEncrypted {
  <#
  .SYNOPSIS
    Test whether a Matrix room has an m.room.encryption state event.
  .PARAMETER RoomID
    Matrix room ID.
  .PARAMETER HomeServer
    Matrix homeserver URL.
  .PARAMETER Token
    Matrix client access token.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RoomID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$HomeServer = $Env:MT_HOME_SERVER ?? 'https://matrix-client.matrix.org',

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:MT_BOT_TOKEN
  )

  process {
    $EncodedRoomID = [Uri]::EscapeDataString($RoomID)
    $Response = Invoke-MatrixApi -EndPoint "/_matrix/client/v3/rooms/${EncodedRoomID}/state/m.room.encryption" `
      -Method Get -HomeServer $HomeServer -Token $Token -AllowedErrorCode 'M_NOT_FOUND'
    return $Response.errcode -ne 'M_NOT_FOUND'
  }
}

function Assert-MatrixPlaintextAllowed {
  param (
    [Parameter(Mandatory)]
    [string]$RoomID,

    [Parameter(Mandatory)]
    [string]$HomeServer,

    [Parameter(Mandatory)]
    [string]$Token,

    [switch]$AllowUnencryptedInEncryptedRoom
  )

  if (-not (Test-MatrixRoomEncrypted -RoomID $RoomID -HomeServer $HomeServer -Token $Token)) { return }
  if (-not $AllowUnencryptedInEncryptedRoom) {
    throw "Matrix room '${RoomID}' is encrypted. This module does not implement Olm/Megolm; refusing to send plaintext."
  }
  Write-Warning "Matrix room '${RoomID}' is encrypted, but -AllowUnencryptedInEncryptedRoom was specified. The message will be sent as plaintext."
}

function ConvertTo-MatrixMessageContent {
  [OutputType([System.Collections.IDictionary])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Message,

    [ValidateSet('PlainText', 'HTML', 'Markdown')]
    [string]$Format,

    [string]$EditEventID
  )

  $Content = [ordered]@{ msgtype = 'm.text'; body = $Message }
  if ($Format -ne 'PlainText') {
    $FormattedBody = if ($Format -eq 'HTML') {
      ConvertTo-SanitizedMessageHtml -Html $Message -HtmlProfile Matrix
    } else {
      $Document = Convert-MarkdownToHtml -Content $Message -Extensions 'advanced', 'hardlinebreak'
      ConvertTo-SanitizedMessageHtml -Html $Document.OuterHtml -HtmlProfile Matrix
    }
    $PlainBody = $FormattedBody | ConvertFrom-Html | Get-TextContent
    $Content.body = [string]$PlainBody
    $Content.format = 'org.matrix.custom.html'
    $Content.formatted_body = $FormattedBody
  }

  if (-not [string]::IsNullOrWhiteSpace($EditEventID)) {
    $NewContent = [ordered]@{ msgtype = 'm.text'; 'm.mentions' = @{}; body = $Content.body }
    if ($Content.format) {
      $NewContent.format = $Content.format
      $NewContent.formatted_body = $Content.formatted_body
      $Content.formatted_body = '* ' + $Content.formatted_body
    }
    $Content.body = '* ' + $Content.body
    $Content['m.new_content'] = $NewContent
    $Content['m.mentions'] = @{}
    $Content['m.relates_to'] = @{ event_id = $EditEventID; rel_type = 'm.replace' }
  }

  return $Content
}

function Invoke-MatrixMessageWrite {
  param (
    [Parameter(Mandatory)]
    [ValidateSet('New', 'Update')]
    [string]$Operation,

    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Message,

    [ValidateSet('PlainText', 'HTML', 'Markdown')]
    [string]$Format,

    [string]$EventID,

    [Parameter(Mandatory)]
    [string]$RoomID,

    [Parameter(Mandatory)]
    [string]$HomeServer,

    [Parameter(Mandatory)]
    [string]$Token,

    [AllowNull()]
    [object]$RateLimitContext
  )

  $EncodedRoomID = [Uri]::EscapeDataString($RoomID)
  $Body = ConvertTo-MatrixMessageContent -Message $Message -Format $Format -EditEventID ($Operation -eq 'Update' ? $EventID : $null)
  Invoke-MatrixApi -EndPoint "/_matrix/client/v3/rooms/${EncodedRoomID}/send/m.room.message" -Method Put `
    -Body $Body -HomeServer $HomeServer -Token $Token -RateLimitContext $RateLimitContext
}

function New-MatrixMessage {
  <#
  .SYNOPSIS
    Send a new plaintext, HTML, or Markdown message to a Matrix room.
  #>
  [CmdletBinding(DefaultParameterSetName = 'PlainText')]
  param (
    [Parameter(ValueFromPipeline, Mandatory)]
    [string]$Message,

    [Parameter(DontShow, ParameterSetName = 'PlainText')]
    [switch]$AsPlainText,

    [Parameter(ParameterSetName = 'HTML')]
    [switch]$AsHtml,

    [Parameter(ParameterSetName = 'Markdown')]
    [switch]$AsMarkdown,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RoomID = $Env:MT_ROOM_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$HomeServer = $Env:MT_HOME_SERVER ?? 'https://matrix-client.matrix.org',

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:MT_BOT_TOKEN,

    [switch]$AllowUnencryptedInEncryptedRoom,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    $null = $AsPlainText.IsPresent
    Assert-MatrixPlaintextAllowed -RoomID $RoomID -HomeServer $HomeServer -Token $Token `
      -AllowUnencryptedInEncryptedRoom:$AllowUnencryptedInEncryptedRoom
    $Format = $AsHtml ? 'HTML' : ($AsMarkdown ? 'Markdown' : 'PlainText')
    Invoke-MatrixMessageWrite -Operation New -Message $Message -Format $Format -RoomID $RoomID -HomeServer $HomeServer -Token $Token `
      -RateLimitContext $RateLimitContext
  }
}

function Remove-MatrixMessage {
  <#
  .SYNOPSIS
    Redact an event from a Matrix room.
  #>
  param (
    [Parameter(ValueFromPipeline, Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$EventID,

    [string]$Reason,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RoomID = $Env:MT_ROOM_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$HomeServer = $Env:MT_HOME_SERVER ?? 'https://matrix-client.matrix.org',

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:MT_BOT_TOKEN,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    $Body = @{}
    if ($Reason) { $Body.reason = $Reason }
    $EncodedRoomID = [Uri]::EscapeDataString($RoomID)
    $EncodedEventID = [Uri]::EscapeDataString($EventID)
    Invoke-MatrixApi -EndPoint "/_matrix/client/v3/rooms/${EncodedRoomID}/redact/${EncodedEventID}" `
      -Method Put -Body $Body -HomeServer $HomeServer -Token $Token -RateLimitContext $RateLimitContext
  }
}

function Update-MatrixMessage {
  <#
  .SYNOPSIS
    Replace an existing Matrix message event.
  #>
  [CmdletBinding(DefaultParameterSetName = 'PlainText')]
  param (
    [Parameter(ValueFromPipeline, Mandatory)]
    [string]$Message,

    [Parameter(DontShow, ParameterSetName = 'PlainText')]
    [switch]$AsPlainText,

    [Parameter(ParameterSetName = 'HTML')]
    [switch]$AsHtml,

    [Parameter(ParameterSetName = 'Markdown')]
    [switch]$AsMarkdown,

    [Parameter(Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$EventID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RoomID = $Env:MT_ROOM_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$HomeServer = $Env:MT_HOME_SERVER ?? 'https://matrix-client.matrix.org',

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:MT_BOT_TOKEN,

    [switch]$AllowUnencryptedInEncryptedRoom,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    $null = $AsPlainText.IsPresent
    Assert-MatrixPlaintextAllowed -RoomID $RoomID -HomeServer $HomeServer -Token $Token `
      -AllowUnencryptedInEncryptedRoom:$AllowUnencryptedInEncryptedRoom
    $Format = $AsHtml ? 'HTML' : ($AsMarkdown ? 'Markdown' : 'PlainText')
    Invoke-MatrixMessageWrite -Operation Update -Message $Message -Format $Format -EventID $EventID `
      -RoomID $RoomID -HomeServer $HomeServer -Token $Token -RateLimitContext $RateLimitContext
  }
}

function Send-MatrixMessage {
  <#
  .SYNOPSIS
    Send or reconcile a line-split Matrix message session.
  .PARAMETER Message
    Complete desired message content.
  .PARAMETER Session
    Mutable list containing the content and event ID of each existing message chunk.
  .PARAMETER EventID
    Legacy single-event edit input. Prefer Session for messages that may split.
  .PARAMETER MaximumMessageLength
    Maximum number of Unicode text elements in each Matrix chunk.
  .PARAMETER AllowUnencryptedInEncryptedRoom
    Explicitly allow plaintext in a room with m.room.encryption state.
  #>
  [CmdletBinding(DefaultParameterSetName = 'PlainText')]
  param (
    [Parameter(ValueFromPipeline, Mandatory)]
    [AllowEmptyString()]
    [string]$Message,

    [Parameter(DontShow, ParameterSetName = 'PlainText')]
    [switch]$AsPlainText,

    [Parameter(ParameterSetName = 'HTML')]
    [switch]$AsHtml,

    [Parameter(ParameterSetName = 'Markdown')]
    [switch]$AsMarkdown,

    [Parameter()]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[System.Tuple[string, string]]]$Session,

    [string]$EventID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$RoomID = $Env:MT_ROOM_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$HomeServer = $Env:MT_HOME_SERVER ?? 'https://matrix-client.matrix.org',

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:MT_BOT_TOKEN,

    [ValidateRange(16, [int]::MaxValue)]
    [int]$MaximumMessageLength = 4000,

    [switch]$AllowUnencryptedInEncryptedRoom,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    $null = $AsPlainText.IsPresent
    $SessionWasSupplied = $PSBoundParameters.ContainsKey('Session')
    if ($SessionWasSupplied -and -not [string]::IsNullOrWhiteSpace($EventID)) {
      throw 'Session and EventID cannot be used together'
    }
    if ($null -eq $Session) { $Session = [System.Collections.Generic.List[System.Tuple[string, string]]]::new() }
    if (-not [string]::IsNullOrWhiteSpace($EventID)) { $Session.Add([System.Tuple]::Create([string]'', [string]$EventID)) }

    Assert-MatrixPlaintextAllowed -RoomID $RoomID -HomeServer $HomeServer -Token $Token `
      -AllowUnencryptedInEncryptedRoom:$AllowUnencryptedInEncryptedRoom

    $Format = $AsHtml ? 'HTML' : ($AsMarkdown ? 'Markdown' : 'PlainText')
    $Messages = if ([string]::IsNullOrWhiteSpace($Message)) {
      [string[]]@()
    } elseif ($AsHtml) {
      @(Split-HtmlMessage -Html $Message -MaximumLength $MaximumMessageLength -LengthMode TextElement -HtmlProfile Matrix)
    } elseif ($AsMarkdown) {
      @(Split-MessageText -Message $Message -MaximumLength $MaximumMessageLength -LengthMode TextElement -Format Markdown)
    } else {
      @(Split-MessageText -Message $Message -MaximumLength $MaximumMessageLength -LengthMode TextElement -Format PlainText)
    }

    $CommonCount = [Math]::Min($Messages.Count, $Session.Count)
    for ($Index = 0; $Index -lt $CommonCount; $Index++) {
      if ($Messages[$Index] -ceq $Session[$Index].Item1) { continue }
      $null = Invoke-MatrixMessageWrite -Operation Update -Message $Messages[$Index] -Format $Format -EventID $Session[$Index].Item2 `
        -RoomID $RoomID -HomeServer $HomeServer -Token $Token -RateLimitContext $RateLimitContext
      $Session[$Index] = [System.Tuple]::Create([string]$Messages[$Index], [string]$Session[$Index].Item2)
    }

    for ($Index = $CommonCount; $Index -lt $Messages.Count; $Index++) {
      $Response = Invoke-MatrixMessageWrite -Operation New -Message $Messages[$Index] -Format $Format `
        -RoomID $RoomID -HomeServer $HomeServer -Token $Token -RateLimitContext $RateLimitContext
      $Session.Add([System.Tuple]::Create([string]$Messages[$Index], [string]$Response.event_id))
    }

    for ($Index = $Session.Count - 1; $Index -ge $Messages.Count; $Index--) {
      $null = Remove-MatrixMessage -EventID $Session[$Index].Item2 -RoomID $RoomID -HomeServer $HomeServer -Token $Token `
        -RateLimitContext $RateLimitContext
      $Session.RemoveAt($Index)
    }

    if ($SessionWasSupplied) {
      Write-Output -InputObject $Session -NoEnumerate
    } elseif ($Session.Count -eq 1) {
      return $Session[0].Item2
    } elseif ($Session.Count -gt 1) {
      Write-Output -InputObject ([string[]]@($Session | ForEach-Object Item2)) -NoEnumerate
    }
  }
}

Export-ModuleMember -Function *
