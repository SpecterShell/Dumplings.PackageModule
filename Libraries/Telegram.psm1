# SPDX-License-Identifier: MIT
# Telegram Bot API behavior: https://core.telegram.org/bots/api
# Long-message and Markdown failure behavior was independently implemented after reviewing
# https://github.com/NousResearch/hermes-agent under its repository license.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

filter ConvertTo-TelegramEscapedText {
  <#
  .SYNOPSIS
    Escape plain text for Telegram MarkdownV2.
  #>
  $_ -replace '([_*\[\]()~`>#+\-=|{}.!\\])', '\$1'
}

filter ConvertTo-TelegramEscapedCode {
  <#
  .SYNOPSIS
    Escape inline or fenced code for Telegram MarkdownV2.
  #>
  $_ -replace '([`\\])', '\$1'
}

function ConvertFrom-TelegramMarkdownV2 {
  <#
  .SYNOPSIS
    Convert Telegram MarkdownV2 to readable plain text for parse-error fallback.
  .PARAMETER Text
    Telegram MarkdownV2 text.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [AllowEmptyString()]
    [string]$Text
  )

  process {
    $Result = $Text
    $Result = $Result -replace '(?m)^```[^\r\n]*\r?\n?', '' -replace '```', ''
    $Result = $Result -replace '\[([^\]]+)\]\(([^)]+)\)', '$1 ($2)'
    $Result = $Result -replace '\*\*([^*]+)\*\*', '$1'
    $Result = $Result -replace '\*([^*]+)\*', '$1'
    $Result = $Result -replace '(?<!\w)_([^_]+)_(?!\w)', '$1'
    $Result = $Result -replace '~([^~]+)~', '$1'
    $Result = $Result -replace '\|\|([^|]+)\|\|', '$1'
    return $Result -replace '\\([_*\[\]()~`>#+\-=|{}.!\\])', '$1'
  }
}

function Get-TelegramApiException {
  [OutputType([System.InvalidOperationException])]
  param (
    [Parameter(Mandatory)]
    [int]$ErrorCode,

    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Description
  )

  $Exception = [System.InvalidOperationException]::new("Telegram API error ${ErrorCode}: ${Description}")
  $Exception.Data['TelegramErrorCode'] = $ErrorCode
  $Exception.Data['TelegramDescription'] = $Description
  return $Exception
}

function Invoke-TelegramApi {
  <#
  .SYNOPSIS
    Invoke the Telegram Bot API with bounded, operation-aware retry handling.
  .PARAMETER Method
    Telegram method to invoke, for example sendMessage.
  .PARAMETER Body
    JSON request body.
  .PARAMETER Token
    Telegram bot token.
  .PARAMETER Idempotent
    Permit transient transport and server retries for an idempotent operation.
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time to establish the connection and receive response headers.
  .PARAMETER OperationTimeoutSeconds
    Maximum time without response progress.
  .PARAMETER MaximumRetryCount
    Maximum number of retries after the initial request.
  .PARAMETER RetryIntervalSec
    Default retry delay when Telegram does not provide retry_after.
  .PARAMETER MaximumRetryDelaySeconds
    Maximum accepted delay for one retry.
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative retry delay for one API operation.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Method,

    [Parameter(ValueFromPipeline, Mandatory)]
    [System.Collections.IDictionary]$Body,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:TG_BOT_TOKEN,

    [switch]$Idempotent,

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
    $Uri = "https://api.telegram.org/bot${Token}/${Method}"
    $Attempt = 0
    $TotalDelay = 0

    while ($true) {
      $Attempt++
      try {
        if ($RateLimitContext) { $RateLimitContext.Wait() }
        try {
          # Disable PowerShell's generic retry behavior. Retrying sendMessage after an ambiguous
          # transport failure can create duplicate messages.
          $Response = Invoke-RestMethod -Uri $Uri -Method Post `
            -Body ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Compress -EscapeHandling EscapeNonAscii))) `
            -ContentType 'application/json' -SkipHttpErrorCheck -MaximumRetryCount 0 `
            -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds -OperationTimeoutSeconds $OperationTimeoutSeconds
        } finally {
          if ($RateLimitContext) { $RateLimitContext.MarkAttemptCompleted() }
        }
      } catch [OperationCanceledException] {
        throw
      } catch {
        $SanitizedMessage = $_.Exception.Message.Replace($Token, '<redacted>')
        if (-not $Idempotent -or $Attempt -gt $MaximumRetryCount) {
          throw [System.InvalidOperationException]::new("Telegram ${Method} transport failure: ${SanitizedMessage}")
        }

        $Delay = $RetryIntervalSec
        if ($Delay -gt $MaximumRetryDelaySeconds -or $TotalDelay + $Delay -gt $MaximumTotalRetryDelaySeconds) {
          throw [System.InvalidOperationException]::new("Telegram ${Method} transport failure exceeded the retry-delay limit: ${SanitizedMessage}")
        }
        if ($RateLimitContext) { $RateLimitContext.SetRetryAfter([timespan]::FromSeconds($Delay)) } else { Start-Sleep -Seconds $Delay }
        $TotalDelay += $Delay
        continue
      }

      if ($Response.ok -ne $false) { return $Response }

      $ErrorCode = [int]$Response.error_code
      $Description = [string]$Response.description
      $CanRetry = $Attempt -le $MaximumRetryCount -and ($ErrorCode -eq 429 -or ($Idempotent -and $ErrorCode -ge 500))
      if (-not $CanRetry) { throw (Get-TelegramApiException -ErrorCode $ErrorCode -Description $Description) }

      $RequestedDelay = if ($ErrorCode -eq 429 -and $Response.parameters.retry_after) {
        [int][Math]::Ceiling([double]$Response.parameters.retry_after)
      } else {
        $RetryIntervalSec
      }
      if ($RequestedDelay -gt $MaximumRetryDelaySeconds -or $TotalDelay + $RequestedDelay -gt $MaximumTotalRetryDelaySeconds) {
        throw (Get-TelegramApiException -ErrorCode $ErrorCode -Description "${Description} (requested retry delay ${RequestedDelay}s exceeds the configured limit)")
      }

      if ($RateLimitContext) { $RateLimitContext.SetRetryAfter([timespan]::FromSeconds($RequestedDelay)) } else { Start-Sleep -Seconds $RequestedDelay }
      $TotalDelay += $RequestedDelay
    }
  }
}

function New-TelegramMessage {
  <#
  .SYNOPSIS
    Send a new message to a Telegram chat.
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
    [string]$ChatID = $Env:TG_CHAT_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:TG_BOT_TOKEN,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    $null = $AsPlainText.IsPresent
    $Body = @{
      chat_id                  = $ChatID
      text                     = $Message
      disable_web_page_preview = $true
    }
    if ($AsHtml) { $Body.parse_mode = 'HTML' }
    if ($AsMarkdown) { $Body.parse_mode = 'MarkdownV2' }
    Invoke-TelegramApi -Method 'sendMessage' -Body $Body -Token $Token -RateLimitContext $RateLimitContext
  }
}

function Remove-TelegramMessage {
  <#
  .SYNOPSIS
    Delete a message from a Telegram chat.
  #>
  param (
    [Parameter(ValueFromPipeline, Mandatory)]
    [long]$MessageID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$ChatID = $Env:TG_CHAT_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:TG_BOT_TOKEN,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    Invoke-TelegramApi -Method 'deleteMessage' -Body @{ chat_id = $ChatID; message_id = $MessageID } -Token $Token -Idempotent -RateLimitContext $RateLimitContext
  }
}

function Update-TelegramMessage {
  <#
  .SYNOPSIS
    Update an existing Telegram message.
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
    [long]$MessageID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$ChatID = $Env:TG_CHAT_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:TG_BOT_TOKEN,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    $null = $AsPlainText.IsPresent
    $Body = @{
      chat_id                  = $ChatID
      message_id               = $MessageID
      text                     = $Message
      disable_web_page_preview = $true
    }
    if ($AsHtml) { $Body.parse_mode = 'HTML' }
    if ($AsMarkdown) { $Body.parse_mode = 'MarkdownV2' }
    Invoke-TelegramApi -Method 'editMessageText' -Body $Body -Token $Token -Idempotent -RateLimitContext $RateLimitContext
  }
}

function Invoke-TelegramMessageWrite {
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [ValidateSet('New', 'Update')]
    [string]$Operation,

    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Message,

    [long]$MessageID,

    [switch]$AsHtml,

    [switch]$AsMarkdown,

    [Parameter(Mandatory)]
    [string]$ChatID,

    [Parameter(Mandatory)]
    [string]$Token,

    [AllowNull()]
    [object]$RateLimitContext
  )

  $Parameters = @{ Message = $Message; ChatID = $ChatID; Token = $Token; RateLimitContext = $RateLimitContext }
  if ($AsHtml) { $Parameters.AsHtml = $true }
  if ($AsMarkdown) { $Parameters.AsMarkdown = $true }

  try {
    $Response = $Operation -eq 'New' ? (New-TelegramMessage @Parameters) : (Update-TelegramMessage @Parameters -MessageID $MessageID)
    return [pscustomobject]@{ Response = $Response; SentText = $Message; NotModified = $false }
  } catch {
    $ErrorCode = $_.Exception.Data['TelegramErrorCode']
    $Description = [string]$_.Exception.Data['TelegramDescription']

    if ($Operation -eq 'Update' -and $ErrorCode -eq 400 -and $Description -match '(?i)message is not modified') {
      return [pscustomobject]@{ Response = $null; SentText = $Message; NotModified = $true }
    }

    if (-not $AsMarkdown -or $ErrorCode -ne 400 -or $Description -notmatch '(?i)(parse|markdown|entities)') { throw }

    # Telegram did not accept the MarkdownV2 entities. The failed request did not create or
    # modify a message, so retrying once without parse_mode is safe.
    $PlainText = ConvertFrom-TelegramMarkdownV2 -Text $Message
    $Response = if ($Operation -eq 'New') {
      New-TelegramMessage -Message $PlainText -ChatID $ChatID -Token $Token -RateLimitContext $RateLimitContext
    } else {
      Update-TelegramMessage -Message $PlainText -MessageID $MessageID -ChatID $ChatID -Token $Token -RateLimitContext $RateLimitContext
    }
    return [pscustomobject]@{ Response = $Response; SentText = $PlainText; NotModified = $false }
  }
}

function Send-TelegramMessage {
  <#
  .SYNOPSIS
    Send or reconcile a line-split Telegram message session.
  .PARAMETER Message
    Complete desired message content.
  .PARAMETER AsHtml
    Send sanitized Telegram HTML.
  .PARAMETER AsMarkdown
    Send Telegram MarkdownV2.
  .PARAMETER Session
    Mutable list containing the content and ID of each existing message chunk.
  .PARAMETER MaximumMessageLength
    Telegram message length limit measured in UTF-16 code units.
  #>
  [CmdletBinding(DefaultParameterSetName = 'PlainText')]
  [OutputType([System.Collections.Generic.List[System.Tuple[string, long]]])]
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
    [System.Collections.Generic.List[System.Tuple[string, long]]]$Session,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$ChatID = $Env:TG_CHAT_ID,

    [Parameter()]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Token = $Env:TG_BOT_TOKEN,

    [ValidateRange(16, 4096)]
    [int]$MaximumMessageLength = 4096,

    [Parameter(DontShow)]
    [AllowNull()]
    [object]$RateLimitContext
  )

  process {
    $null = $AsPlainText.IsPresent
    if ($null -eq $Session) { $Session = [System.Collections.Generic.List[System.Tuple[string, long]]]::new() }

    # Materialize the complete conditional output as an array. PowerShell unwraps a one-item array
    # emitted by an individual branch into a scalar string; indexing that scalar would send only its
    # first character (normally "*" for PackageTask Markdown) to Telegram.
    [string[]]$Messages = @(
      if ([string]::IsNullOrWhiteSpace($Message)) {
        # An empty desired state removes every message currently owned by this session.
      } elseif ($AsHtml) {
        Split-HtmlMessage -Html $Message -MaximumLength $MaximumMessageLength -LengthMode UTF16 -HtmlProfile Telegram
      } elseif ($AsMarkdown) {
        Split-MessageText -Message $Message -MaximumLength $MaximumMessageLength -LengthMode UTF16 -Format MarkdownV2
      } else {
        Split-MessageText -Message $Message -MaximumLength $MaximumMessageLength -LengthMode UTF16 -Format PlainText
      }
    )

    $CommonCount = [Math]::Min($Messages.Count, $Session.Count)
    for ($Index = 0; $Index -lt $CommonCount; $Index++) {
      if ($Messages[$Index] -ceq $Session[$Index].Item1) { continue }

      $WriteResult = Invoke-TelegramMessageWrite -Operation Update -Message $Messages[$Index] -MessageID $Session[$Index].Item2 `
        -AsHtml:$AsHtml -AsMarkdown:$AsMarkdown -ChatID $ChatID -Token $Token -RateLimitContext $RateLimitContext
      $Session[$Index] = [System.Tuple]::Create([string]$WriteResult.SentText, [long]$Session[$Index].Item2)
    }

    for ($Index = $CommonCount; $Index -lt $Messages.Count; $Index++) {
      $WriteResult = Invoke-TelegramMessageWrite -Operation New -Message $Messages[$Index] `
        -AsHtml:$AsHtml -AsMarkdown:$AsMarkdown -ChatID $ChatID -Token $Token -RateLimitContext $RateLimitContext
      $Session.Add([System.Tuple]::Create([string]$WriteResult.SentText, [long]$WriteResult.Response.result.message_id))
    }

    for ($Index = $Session.Count - 1; $Index -ge $Messages.Count; $Index--) {
      $null = Remove-TelegramMessage -MessageID $Session[$Index].Item2 -ChatID $ChatID -Token $Token -RateLimitContext $RateLimitContext
      $Session.RemoveAt($Index)
    }

    Write-Output -InputObject $Session -NoEnumerate
  }
}

Export-ModuleMember -Function *
