# SPDX-License-Identifier: MIT

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

Import-Module -Name 'PowerHTML'

$Script:MessageHtmlBlockTags = @(
  'address', 'article', 'aside', 'blockquote', 'dd', 'div', 'dl', 'fieldset', 'figcaption', 'figure',
  'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'li', 'ol', 'p', 'pre',
  'section', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'ul'
)

function Get-MessageTextLength {
  <#
  .SYNOPSIS
    Measure message text using a platform-specific length unit.
  .PARAMETER Text
    The message text to measure.
  .PARAMETER LengthMode
    UTF16 counts .NET UTF-16 code units; TextElement counts Unicode grapheme clusters.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Text,

    [Parameter(Mandatory)]
    [ValidateSet('UTF16', 'TextElement')]
    [string]$LengthMode
  )

  if ($LengthMode -eq 'UTF16') { return $Text.Length }

  $Count = 0
  $Enumerator = [System.Globalization.StringInfo]::GetTextElementEnumerator($Text)
  while ($Enumerator.MoveNext()) { $Count++ }
  return $Count
}

function Get-MessagePrefixLength {
  <#
  .SYNOPSIS
    Find a grapheme-safe prefix within a platform message-length budget.
  .PARAMETER Text
    The remaining message text.
  .PARAMETER MaximumLength
    Maximum number of selected length units.
  .PARAMETER LengthMode
    The unit used to measure the selected prefix.
  .PARAMETER PreferBoundary
    Prefer the last complete line and then whitespace before using the hard grapheme boundary.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Text,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaximumLength,

    [Parameter(Mandatory)]
    [ValidateSet('UTF16', 'TextElement')]
    [string]$LengthMode,

    [switch]$PreferBoundary
  )

  $Used = 0
  $HardBoundary = 0
  $LineBoundary = 0
  $WhitespaceBoundary = 0
  $Enumerator = [System.Globalization.StringInfo]::GetTextElementEnumerator($Text)

  while ($Enumerator.MoveNext()) {
    $Element = $Enumerator.GetTextElement()
    $ElementUnits = $LengthMode -eq 'UTF16' ? $Element.Length : 1
    if ($Used + $ElementUnits -gt $MaximumLength) { break }

    $Used += $ElementUnits
    $HardBoundary = $Enumerator.ElementIndex + $Element.Length
    if ($Element.Contains("`n")) {
      $LineBoundary = $HardBoundary
    } elseif ([char]::IsWhiteSpace($Element, 0)) {
      $WhitespaceBoundary = $HardBoundary
    }
  }

  if (-not $PreferBoundary) { return $HardBoundary }
  if ($LineBoundary -gt 0) { return $LineBoundary }
  if ($WhitespaceBoundary -gt 0) { return $WhitespaceBoundary }
  return $HardBoundary
}

function Get-MessageMarkdownState {
  <#
  .SYNOPSIS
    Determine whether a Markdown fragment ends inside fenced or inline code.
  .PARAMETER Text
    Markdown text consumed by the current chunk.
  .PARAMETER FenceLanguage
    Fence language carried from the previous chunk; null means no open fence.
  .PARAMETER InlineCode
    Whether the previous chunk ended inside inline code.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Text,

    [AllowNull()]
    [object]$FenceLanguage,

    [bool]$InlineCode = $false
  )

  $InFence = $null -ne $FenceLanguage
  $Language = $FenceLanguage ?? ''
  $InInlineCode = $InlineCode
  $Index = 0

  while ($Index -lt $Text.Length) {
    if ($Text[$Index] -ne '`') { $Index++; continue }

    # Backslash-escaped backticks do not alter Markdown parser state.
    $Backslashes = 0
    for ($Cursor = $Index - 1; $Cursor -ge 0 -and $Text[$Cursor] -eq '\'; $Cursor--) { $Backslashes++ }
    if ($Backslashes % 2 -ne 0) { $Index++; continue }

    if ($Index + 2 -lt $Text.Length -and $Text.Substring($Index, 3) -eq '```') {
      if ($InFence) {
        $InFence = $false
        $Language = ''
      } elseif (-not $InInlineCode) {
        $InFence = $true
        $LineEnd = $Text.IndexOf("`n", $Index + 3)
        $TagEnd = $LineEnd -ge 0 ? $LineEnd : $Text.Length
        $Tag = $Text.Substring($Index + 3, $TagEnd - ($Index + 3)).Trim()
        $Language = $Tag -match '^(?<Language>[^\s`]+)' ? $Matches.Language : ''
      }
      $Index += 3
      continue
    }

    if (-not $InFence) { $InInlineCode = -not $InInlineCode }
    $Index++
  }

  return [pscustomobject]@{
    FenceLanguage = $InFence ? $Language : $null
    InlineCode    = $InInlineCode
  }
}

function Split-MessageText {
  <#
  .SYNOPSIS
    Split plain or Markdown message text at line-first, grapheme-safe boundaries.
  .PARAMETER Message
    The message text to split.
  .PARAMETER MaximumLength
    Maximum length of each emitted chunk.
  .PARAMETER LengthMode
    The platform-specific unit used for the maximum length.
  .PARAMETER Format
    PlainText performs only line/grapheme splitting. Markdown modes also preserve code delimiters.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [AllowEmptyString()]
    [string]$Message,

    [Parameter(Mandatory)]
    [ValidateRange(16, [int]::MaxValue)]
    [int]$MaximumLength,

    [ValidateSet('UTF16', 'TextElement')]
    [string]$LengthMode = 'TextElement',

    [ValidateSet('PlainText', 'Markdown', 'MarkdownV2')]
    [string]$Format = 'PlainText'
  )

  process {
    $Normalized = $Message.ReplaceLineEndings("`n")
    if ((Get-MessageTextLength -Text $Normalized -LengthMode $LengthMode) -le $MaximumLength) {
      return , $Normalized
    }

    $Chunks = [System.Collections.Generic.List[string]]::new()
    $Remaining = $Normalized
    $FenceLanguage = $null
    $InlineCode = $false
    $MarkdownAware = $Format -ne 'PlainText'

    while ($Remaining.Length -gt 0) {
      $Prefix = if ($null -ne $FenceLanguage) {
        "``````${FenceLanguage}`n"
      } elseif ($InlineCode) {
        '```'[0].ToString()
      } else {
        ''
      }

      if ((Get-MessageTextLength -Text ($Prefix + $Remaining) -LengthMode $LengthMode) -le $MaximumLength) {
        $Chunks.Add($Prefix + $Remaining)
        break
      }

      # Reserve room for closing either a fenced or inline code construct. The reserve is
      # intentionally applied to all Markdown chunks because the state is known only after slicing.
      $ClosingReserve = $MarkdownAware ? 4 : 0
      $BodyBudget = $MaximumLength - (Get-MessageTextLength -Text $Prefix -LengthMode $LengthMode) - $ClosingReserve
      if ($BodyBudget -lt 1) { throw "The maximum message length ${MaximumLength} is too small for Markdown continuation markers" }

      $Consumed = Get-MessagePrefixLength -Text $Remaining -MaximumLength $BodyBudget -LengthMode $LengthMode -PreferBoundary
      if ($Consumed -le 0) {
        $Consumed = Get-MessagePrefixLength -Text $Remaining -MaximumLength $BodyBudget -LengthMode $LengthMode
      }
      if ($Consumed -le 0) { throw 'Unable to advance while splitting message text' }

      $Body = $Remaining.Substring(0, $Consumed)

      # Do not leave a Markdown escape character dangling at the end of a chunk when a prior
      # grapheme boundary is available.
      if ($MarkdownAware) {
        $TrailingBackslashes = [regex]::Match($Body, '\\+$').Value.Length
        if ($TrailingBackslashes % 2 -ne 0 -and $Body.Length -gt 1) {
          $Previous = Get-MessagePrefixLength -Text $Body.Substring(0, $Body.Length - 1) -MaximumLength $BodyBudget -LengthMode $LengthMode
          if ($Previous -gt 0) {
            $Consumed = $Previous
            $Body = $Remaining.Substring(0, $Consumed)
          }
        }
      }

      $State = if ($MarkdownAware) {
        Get-MessageMarkdownState -Text $Body -FenceLanguage $FenceLanguage -InlineCode $InlineCode
      } else {
        [pscustomobject]@{ FenceLanguage = $null; InlineCode = $false }
      }

      $Chunk = $Prefix + $Body
      if ($null -ne $State.FenceLanguage) {
        $Chunk += $Chunk.EndsWith("`n") ? '```' : ("`n" + '```')
      } elseif ($State.InlineCode) {
        $Chunk += '```'[0]
      }

      if ((Get-MessageTextLength -Text $Chunk -LengthMode $LengthMode) -gt $MaximumLength) {
        throw 'Markdown continuation markers exceeded the message-length budget'
      }

      $Chunks.Add($Chunk)
      $Remaining = $Remaining.Substring($Consumed)
      $FenceLanguage = $State.FenceLanguage
      $InlineCode = $State.InlineCode
    }

    return $Chunks.ToArray()
  }
}

function Test-MessageHtmlUrl {
  [OutputType([bool])]
  param (
    [AllowEmptyString()]
    [string]$Url
  )

  $Normalized = $Url -replace '[\x00-\x1F\x7F]', ''
  if ($Normalized -notmatch '^(?<Scheme>[A-Za-z][A-Za-z0-9+.-]*):') { return $true }
  return $Matches.Scheme.ToLowerInvariant() -in @('http', 'https', 'matrix', 'mailto')
}

function Add-SanitizedMessageHtmlNode {
  param (
    [Parameter(Mandatory)]
    [HtmlAgilityPack.HtmlNode]$Node,

    [Parameter(Mandatory)]
    [System.Text.StringBuilder]$Builder,

    [Parameter(Mandatory)]
    [ValidateSet('Matrix', 'Telegram')]
    [string]$HtmlProfile
  )

  $MatrixTags = @('a', 'b', 'blockquote', 'br', 'code', 'del', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'li', 'ol', 'p', 'pre', 's', 'strike', 'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'ul')
  $TelegramTags = @('a', 'b', 'blockquote', 'br', 'code', 'del', 'em', 'i', 'ins', 'pre', 's', 'span', 'strike', 'strong', 'tg-emoji', 'u')
  $AllowedTags = $HtmlProfile -eq 'Matrix' ? $MatrixTags : $TelegramTags

  if ($Node.Name -eq '#text') {
    $null = $Builder.Append([System.Net.WebUtility]::HtmlEncode([System.Web.HttpUtility]::HtmlDecode($Node.InnerText)))
    return
  }
  if ($Node.Name -eq '#comment' -or $Node.Name -in @('script', 'style', 'svg')) { return }
  if ($Node.Name -eq '#document') {
    foreach ($Child in $Node.ChildNodes) { Add-SanitizedMessageHtmlNode -Node $Child -Builder $Builder -HtmlProfile $HtmlProfile }
    return
  }

  $Name = $Node.Name.ToLowerInvariant()
  if ($Name -notin $AllowedTags) {
    foreach ($Child in $Node.ChildNodes) { Add-SanitizedMessageHtmlNode -Node $Child -Builder $Builder -HtmlProfile $HtmlProfile }
    return
  }

  $null = $Builder.Append('<')
  $null = $Builder.Append($Name)
  foreach ($Attribute in $Node.Attributes) {
    $AttributeName = $Attribute.Name.ToLowerInvariant()
    $Value = [System.Web.HttpUtility]::HtmlDecode($Attribute.Value)
    if ($AttributeName.StartsWith('on')) { continue }

    if ($Name -eq 'a' -and $AttributeName -eq 'href' -and (Test-MessageHtmlUrl -Url $Value)) {
      $null = $Builder.Append(' href="')
      $null = $Builder.Append([System.Net.WebUtility]::HtmlEncode($Value))
      $null = $Builder.Append('"')
    } elseif ($Name -eq 'code' -and $AttributeName -eq 'class' -and $Value -cmatch '^language-[A-Za-z0-9_+.-]{1,64}$') {
      $null = $Builder.Append(' class="')
      $null = $Builder.Append($Value)
      $null = $Builder.Append('"')
    } elseif ($HtmlProfile -eq 'Telegram' -and $Name -eq 'tg-emoji' -and $AttributeName -eq 'emoji-id' -and $Value -match '^\d+$') {
      $null = $Builder.Append(' emoji-id="')
      $null = $Builder.Append($Value)
      $null = $Builder.Append('"')
    } elseif ($HtmlProfile -eq 'Telegram' -and $Name -eq 'blockquote' -and $AttributeName -eq 'expandable') {
      $null = $Builder.Append(' expandable')
    }
  }
  $null = $Builder.Append('>')

  if ($Name -notin @('br', 'hr')) {
    foreach ($Child in $Node.ChildNodes) { Add-SanitizedMessageHtmlNode -Node $Child -Builder $Builder -HtmlProfile $HtmlProfile }
    $null = $Builder.Append('</')
    $null = $Builder.Append($Name)
    $null = $Builder.Append('>')
  }
}

function ConvertTo-SanitizedMessageHtml {
  <#
  .SYNOPSIS
    Sanitize formatted message HTML against a platform-compatible allowlist.
  .PARAMETER Html
    HTML fragment to sanitize.
  .PARAMETER HtmlProfile
    Target platform whose supported elements and attributes should be retained.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [AllowEmptyString()]
    [string]$Html,

    [Parameter(Mandatory)]
    [ValidateSet('Matrix', 'Telegram')]
    [string]$HtmlProfile
  )

  process {
    try {
      $Document = $Html | ConvertFrom-Html
      $Builder = [System.Text.StringBuilder]::new()
      Add-SanitizedMessageHtmlNode -Node $Document -Builder $Builder -HtmlProfile $HtmlProfile
      return $Builder.ToString()
    } catch {
      # Encoding the entire input is a safe formatted-body fallback when malformed HTML cannot
      # be represented by the parser.
      return [System.Net.WebUtility]::HtmlEncode($Html)
    }
  }
}

function Add-MessageHtmlToken {
  param (
    [Parameter(Mandatory)]
    [HtmlAgilityPack.HtmlNode]$Node,

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[object]]$Tokens
  )

  if ($Node.Name -eq '#text') {
    $Tokens.Add([pscustomobject]@{
        Kind    = 'Text'
        Html    = [System.Net.WebUtility]::HtmlEncode([System.Web.HttpUtility]::HtmlDecode($Node.InnerText))
        Text    = [System.Web.HttpUtility]::HtmlDecode($Node.InnerText)
        Name    = $null
        Closing = $null
      })
    return
  }
  if ($Node.Name -eq '#document') {
    foreach ($Child in $Node.ChildNodes) { Add-MessageHtmlToken -Node $Child -Tokens $Tokens }
    return
  }

  $Name = $Node.Name.ToLowerInvariant()
  if ($Name -in @('br', 'hr')) {
    $Tokens.Add([pscustomobject]@{ Kind = 'Break'; Html = "<${Name}>"; Text = "`n"; Name = $Name; Closing = $null })
    return
  }

  $StartLength = $Node.OuterHtml.IndexOf('>')
  if ($StartLength -lt 0) { return }
  $Opening = $Node.OuterHtml.Substring(0, $StartLength + 1)
  $Closing = "</${Name}>"
  $Tokens.Add([pscustomobject]@{ Kind = 'Start'; Html = $Opening; Text = ''; Name = $Name; Closing = $Closing })
  foreach ($Child in $Node.ChildNodes) { Add-MessageHtmlToken -Node $Child -Tokens $Tokens }
  $Tokens.Add([pscustomobject]@{ Kind = 'End'; Html = $Closing; Text = ''; Name = $Name; Closing = $Closing })
  if ($Name -in $Script:MessageHtmlBlockTags) {
    $Tokens.Add([pscustomobject]@{ Kind = 'Boundary'; Html = ''; Text = "`n"; Name = $Name; Closing = $null })
  }
}

function Split-HtmlMessage {
  <#
  .SYNOPSIS
    Sanitize and split HTML into balanced platform-compatible fragments.
  .PARAMETER Html
    HTML message fragment.
  .PARAMETER MaximumLength
    Maximum rendered text length of each fragment.
  .PARAMETER LengthMode
    Platform-specific unit used to measure rendered text.
  .PARAMETER HtmlProfile
    Target platform HTML allowlist.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [AllowEmptyString()]
    [string]$Html,

    [Parameter(Mandatory)]
    [ValidateRange(16, [int]::MaxValue)]
    [int]$MaximumLength,

    [ValidateSet('UTF16', 'TextElement')]
    [string]$LengthMode = 'TextElement',

    [Parameter(Mandatory)]
    [ValidateSet('Matrix', 'Telegram')]
    [string]$HtmlProfile
  )

  process {
    $Sanitized = ConvertTo-SanitizedMessageHtml -Html $Html -HtmlProfile $HtmlProfile
    try {
      $Document = $Sanitized | ConvertFrom-Html
      $Tokens = [System.Collections.Generic.List[object]]::new()
      Add-MessageHtmlToken -Node $Document -Tokens $Tokens
    } catch {
      return , ([System.Net.WebUtility]::HtmlEncode($Html))
    }

    $Chunks = [System.Collections.Generic.List[string]]::new()
    $OpenTags = [System.Collections.Generic.List[object]]::new()
    $PendingOpenTags = [System.Collections.Generic.List[object]]::new()
    $Builder = [System.Text.StringBuilder]::new()
    $VisibleLength = 0

    $FlushChunk = {
      param([switch]$Force)
      if ($VisibleLength -eq 0 -and -not $Force) { return }
      for ($Index = $OpenTags.Count - 1; $Index -ge 0; $Index--) { $null = $Builder.Append($OpenTags[$Index].Closing) }
      $Chunks.Add($Builder.ToString())
      $Builder.Clear() | Out-Null
      foreach ($Tag in $OpenTags) { $null = $Builder.Append($Tag.Html) }
      $VisibleLength = 0
    }

    $FlushBeforePendingTags = {
      # Start tags appended after the last visible text belong to the next chunk. Temporarily
      # remove them so the previous chunk does not acquire empty trailing elements.
      $MovedTags = $PendingOpenTags.ToArray()
      for ($Index = $MovedTags.Count - 1; $Index -ge 0; $Index--) {
        $OpeningLength = $MovedTags[$Index].Html.Length
        if ($Builder.Length -ge $OpeningLength) { $null = $Builder.Remove($Builder.Length - $OpeningLength, $OpeningLength) }
        if ($OpenTags.Count -gt 0) { $OpenTags.RemoveAt($OpenTags.Count - 1) }
      }
      $PendingOpenTags.Clear()
      . $FlushChunk
      foreach ($Tag in $MovedTags) {
        $null = $Builder.Append($Tag.Html)
        $OpenTags.Add($Tag)
        $PendingOpenTags.Add($Tag)
      }
    }

    foreach ($Token in $Tokens) {
      switch ($Token.Kind) {
        'Start' {
          $null = $Builder.Append($Token.Html)
          $OpenTags.Add($Token)
          $PendingOpenTags.Add($Token)
        }
        'End' {
          $null = $Builder.Append($Token.Html)
          if ($OpenTags.Count -gt 0) { $OpenTags.RemoveAt($OpenTags.Count - 1) }
          if ($PendingOpenTags.Count -gt 0) { $PendingOpenTags.RemoveAt($PendingOpenTags.Count - 1) }
        }
        'Boundary' {
          if ($VisibleLength -gt 0) {
            if ($VisibleLength + 1 -gt $MaximumLength) { . $FlushChunk }
            $VisibleLength++
          }
        }
        'Break' {
          if ($VisibleLength + 1 -gt $MaximumLength) { . $FlushChunk }
          $null = $Builder.Append($Token.Html)
          $VisibleLength++
          $PendingOpenTags.Clear()
        }
        'Text' {
          $RemainingText = $Token.Text
          while ($RemainingText.Length -gt 0) {
            $RemainingBudget = $MaximumLength - $VisibleLength
            if ($RemainingBudget -le 0) {
              if ($PendingOpenTags.Count -gt 0) { . $FlushBeforePendingTags } else { . $FlushChunk }
              $RemainingBudget = $MaximumLength
            }

            $RemainingUnits = Get-MessageTextLength -Text $RemainingText -LengthMode $LengthMode
            if ($RemainingUnits -le $RemainingBudget) {
              $null = $Builder.Append([System.Net.WebUtility]::HtmlEncode($RemainingText))
              $VisibleLength += $RemainingUnits
              $PendingOpenTags.Clear()
              break
            }

            # Preserve an already accumulated complete line rather than filling its remaining
            # capacity with a partial next line.
            if ($VisibleLength -gt 0 -and -not $RemainingText.Substring(0, [Math]::Min($RemainingText.Length, $RemainingBudget)).Contains("`n")) {
              if ($PendingOpenTags.Count -gt 0) { . $FlushBeforePendingTags } else { . $FlushChunk }
              continue
            }

            $Consumed = Get-MessagePrefixLength -Text $RemainingText -MaximumLength $RemainingBudget -LengthMode $LengthMode -PreferBoundary
            if ($Consumed -le 0) { $Consumed = Get-MessagePrefixLength -Text $RemainingText -MaximumLength $RemainingBudget -LengthMode $LengthMode }
            if ($Consumed -le 0) { throw 'Unable to advance while splitting HTML message text' }

            $Part = $RemainingText.Substring(0, $Consumed)
            $null = $Builder.Append([System.Net.WebUtility]::HtmlEncode($Part))
            $VisibleLength += Get-MessageTextLength -Text $Part -LengthMode $LengthMode
            $PendingOpenTags.Clear()
            $RemainingText = $RemainingText.Substring($Consumed)
            . $FlushChunk
          }
        }
      }
    }

    if ($VisibleLength -gt 0 -or ($Chunks.Count -eq 0 -and $Builder.Length -gt 0)) { . $FlushChunk -Force }
    return $Chunks.ToArray()
  }
}

Export-ModuleMember -Function 'Get-MessageTextLength', 'Split-MessageText', 'ConvertTo-SanitizedMessageHtml', 'Split-HtmlMessage'
