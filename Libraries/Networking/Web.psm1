#Requires -Version 7.4

# Apply default function parameters supplied by the Dumplings runner.
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Split-Uri {
  <#
  .SYNOPSIS
    Split the URI
  .PARAMETER Uri
    The Uniform Resource Identifier (URI) to be splitted
  .PARAMETER Parent
    The parent part of the URI
  .PARAMETER LeftPart
    The left part of the URI
  .PARAMETER Components
    The component of the URI
  .PARAMETER Format
    Control how special characters are escaped
  #>
  [OutputType([string])]
  [CmdletBinding(DefaultParameterSetName = 'ParentSet')]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'Result', Justification = 'False positive')]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI) to be splitted')]
    [uri]$Uri,

    [Parameter(ParameterSetName = 'ParentSet', HelpMessage = 'The parent part of the URI')]
    [switch]$Parent,

    [Parameter(ParameterSetName = 'LeftPartSet', HelpMessage = 'The left part of the URI')]
    [System.UriPartial]$LeftPart = [System.UriPartial]::Path,

    [Parameter(ParameterSetName = 'ComponentSet', HelpMessage = 'The component of the URI')]
    [System.UriComponents[]]$Components,

    [Parameter(ParameterSetName = 'ComponentSet', HelpMessage = 'Control how special characters are escaped')]
    [System.UriFormat]$Format = [System.UriFormat]::UriEscaped
  )

  process {
    switch ($PSCmdlet.ParameterSetName) {
      'ParentSet' {
        return [uri]::new($Uri, '.').OriginalString
      }
      'LeftPartSet' {
        return $Uri.GetLeftPart($LeftPart)
      }
      'ComponentSet' {
        $Components = $Components | ForEach-Object -Begin { $Result = $null } -Process { $Result = $_ -bor $Result } -End { $Result }
        return $Uri.GetComponents($Components, $Format)
      }
      default {
        throw 'Invalid parameter set'
      }
    }
  }
}

function Join-Uri {
  <#
  .SYNOPSIS
    Join the URIs
  .PARAMETER Uri
    The main URI to which the child URI is appended
  .PARAMETER ChildUri
    The elements to be applied to the main URI
  .PARAMETER AdditionalChildUri
    Additional elements to be applied to the main URI
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The main URI to which the child URI is appended')]
    [uri[]]$Uri,

    [Parameter(Position = 1, Mandatory, HelpMessage = 'The elements to be applied to the main URI')]
    [string[]]$ChildUri,

    [Parameter(Position = 2, ValueFromRemainingArguments, HelpMessage = 'Additional elements to be applied to the main URI')]
    [string[]]$AdditionalChildUri
  )

  process {
    foreach ($SubUri in $Uri) {
      foreach ($SubChildUri in $ChildUri) {
        $SubUri = [uri]::new($SubUri, $SubChildUri, $true)
      }
      foreach ($SubAdditionalChildUri in $AdditionalChildUri) {
        $SubUri = [uri]::new($SubUri, $SubAdditionalChildUri, $true)
      }
      Write-Output -InputObject $SubUri.AbsoluteUri
    }
  }
}

function Get-RedirectedUrl {
  <#
  .SYNOPSIS
    Get the redirected URI for the given URI
  #>
  [OutputType([string])]
  param ()

  (Invoke-WebRequest -Method Head @args).BaseResponse.RequestMessage.RequestUri.AbsoluteUri
}

function Get-WebResponseHeader {
  <#
  .SYNOPSIS
    Get response headers without buffering the response body
  .PARAMETER Uri
    The Uniform Resource Identifier (URI)
  .PARAMETER Method
    The HTTP method for the web request
  .PARAMETER Headers
    The header hashtable for the web request
  .PARAMETER UserAgent
    The user agent string for the web request
  .PARAMETER ConnectionTimeoutSeconds
    The timeout in seconds for the web request
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI)')]
    [string]$Uri,

    [Parameter(HelpMessage = 'The HTTP method for the web request')]
    [ValidateSet('GET', 'HEAD')]
    [System.Net.Http.HttpMethod]$Method = [System.Net.Http.HttpMethod]::Get,

    [Parameter(HelpMessage = 'The header hashtable for the web request')]
    [System.Collections.IDictionary]$Headers,

    [Parameter(HelpMessage = 'The user agent string for the web request')]
    [string]$UserAgent,

    [Parameter(HelpMessage = 'The timeout in seconds for the web request')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$ConnectionTimeoutSeconds
  )

  process {
    $HttpClientHandler = [System.Net.Http.HttpClientHandler]@{ AllowAutoRedirect = $true }
    $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)
    $HttpClient.Timeout = $ConnectionTimeoutSeconds ? [timespan]::FromSeconds($ConnectionTimeoutSeconds) : [System.Threading.Timeout]::InfiniteTimeSpan
    $HttpRequest = [System.Net.Http.HttpRequestMessage]::new($Method, $Uri)
    $HttpResponse = $null

    try {
      if ($Headers) { $Headers.GetEnumerator().ForEach({ $null = $HttpRequest.Headers.TryAddWithoutValidation($_.Key, $_.Value) }) }
      if ($UserAgent) { $HttpRequest.Headers.Add('User-Agent', $UserAgent) }

      $HttpResponse = $HttpClient.Send($HttpRequest, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
      $null = $HttpResponse.EnsureSuccessStatusCode()

      $ResponseHeaders = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Header in $HttpResponse.Headers) { $ResponseHeaders[$Header.Key] = @($Header.Value) }
      foreach ($Header in $HttpResponse.Content.Headers) { $ResponseHeaders[$Header.Key] = @($Header.Value) }

      [pscustomobject]@{
        StatusCode   = [int]($HttpResponse.StatusCode)
        ReasonPhrase = $HttpResponse.ReasonPhrase
        RequestUri   = $HttpResponse.RequestMessage.RequestUri.AbsoluteUri
        Headers      = $ResponseHeaders
      }
    } finally {
      if ($HttpResponse) { $HttpResponse.Dispose() }
      $HttpRequest.Dispose()
      $HttpClient.Dispose()
      $HttpClientHandler.Dispose()
    }
  }
}

function Get-RedirectedUrls {
  <#
  .SYNOPSIS
    Get the redirected URIs for the given URI
  .PARAMETER Uri
    The Uniform Resource Identifier (URI)
  .PARAMETER Method
    The HTTP method for the web request
  .PARAMETER Headers
    The header hashtable for the web request
  .PARAMETER UserAgent
    The user agent string for the web request
  .PARAMETER ConnectionTimeoutSeconds
    The timeout in seconds for the web request
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The Uniform Resource Identifier (URI)')]
    [string]$Uri,

    [Parameter(HelpMessage = 'The HTTP method for the web request')]
    [ValidateSet('GET', 'HEAD')]
    [System.Net.Http.HttpMethod]$Method = [System.Net.Http.HttpMethod]::Head,

    [Parameter(HelpMessage = 'The header hashtable for the web request')]
    [System.Collections.IDictionary]$Headers,

    [Parameter(HelpMessage = 'The user agent string for the web request')]
    [string]$UserAgent,

    [Parameter(HelpMessage = 'The timeout in seconds for the web request')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$ConnectionTimeoutSeconds
  )

  begin {
    $HttpClientHandler = [System.Net.Http.HttpClientHandler]@{ AllowAutoRedirect = $false }
    $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)
    $HttpClient.Timeout = $ConnectionTimeoutSeconds ? [timespan]::FromSeconds($ConnectionTimeoutSeconds) : [System.Threading.Timeout]::InfiniteTimeSpan
  }

  process {
    $ShouldContinue = $true
    $HasRedirected = $false
    do {
      $HttpRequest = [System.Net.Http.HttpRequestMessage]::new($Method, $Uri)
      if ($Headers) { $Headers.GetEnumerator().ForEach({ $null = $HttpRequest.Headers.TryAddWithoutValidation($_.Key, $_.Value) }) }
      if ($UserAgent) { $HttpRequest.Headers.Add('User-Agent', $UserAgent) }

      $HttpResponse = $HttpClient.Send($HttpRequest, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)

      if ($HttpResponse.Headers.Contains('Location') -and $HttpResponse.Headers.Location.AbsoluteUri -ne $Uri) {
        $Uri = $HttpResponse.Headers.Location.AbsoluteUri
        $HasRedirected = $true
        Write-Output -InputObject $Uri
      } else {
        $ShouldContinue = $false
        # Usually, the original URI is not returned for intuition
        # But if no redirection happens, the original URI will be returned
        if (-not $HasRedirected) { Write-Output -InputObject $Uri }
      }

      $HttpResponse.Dispose()
      $HttpRequest.Dispose()
    } while ($ShouldContinue)
  }

  end {
    $HttpClient.Dispose()
  }
}

function Get-RedirectedUrl1st {
  <#
  .SYNOPSIS
    Get the first redirected URI for the given URI
  #>
  [OutputType([string])]
  param ()

  Get-RedirectedUrls @args | Select-Object -First 1
}

function Get-EmbeddedJson {
  <#
  .SYNOPSIS
    Extract embedded JSON from string. Useful for JSONP content
  .PARAMETER InputObject
    The string containing the JSON
  .PARAMETER StartsFrom
    The string indicating where the JSON starts after
  .LINK
    https://stackoverflow.com/questions/48470971/how-to-deserialize-a-jsonp-response-preferably-with-jsontextreader-and-not-a-st
  .LINK
    https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Utility/commands/utility/WebCmdlet/JsonObject.cs
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing the JSON')]
    [ValidateNotNullOrEmpty()]
    [string]$Content,

    [Parameter(HelpMessage = 'The string indicating where the JSON starts after')]
    [string]$StartsFrom
  )

  process {
    [Newtonsoft.Json.JsonConvert]::DeserializeObject(
      $Content.Substring($Content.IndexOf($StartsFrom) + $StartsFrom.Length),
      [Newtonsoft.Json.JsonSerializerSettings]@{
        TypeNameHandling         = [Newtonsoft.Json.TypeNameHandling]::None
        MetadataPropertyHandling = [Newtonsoft.Json.MetadataPropertyHandling]::Ignore
        CheckAdditionalContent   = $false
      }
    ).ToString()
  }
}

function Get-EmbeddedLinks {
  <#
  .SYNOPSIS
    Extract embedded <a>links</a> from string
  .PARAMETER InputObject
    The string containing the links
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The string containing the links')]
    [ValidateNotNullOrEmpty()]
    [string]$Content
  )

  begin {
    $LinkRegex = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject].GetNestedType('HtmlParser', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static).GetField('LinkRegex', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static).GetValue($null)
    $CreateHtmlObject = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject].GetMethod('CreateHtmlObject', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static)
  }

  process {
    foreach ($Match in $LinkRegex.Matches($Content)) {
      Write-Output -InputObject $CreateHtmlObject.Invoke($null, @($Match.Value, 'A'))
    }
  }
}

function Read-ResponseContent {
  <#
  .SYNOPSIS
    Obtain garble-free content from the stream
  .PARAMETER Response
    The stream to read (e.g. The raw content stream from Invoke-WebRequest)
  .PARAMETER Encoding
    The content encoding
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The stream to read (e.g. The raw content stream from Invoke-WebRequest)')]
    [System.IO.Stream]$RawContentStream,

    [Parameter(HelpMessage = 'The content encoding')]
    [ArgumentCompleter({ [System.Text.Encoding]::GetEncodings() | Select-Object -ExpandProperty Name | Select-String -Pattern "^$($args[2])" -Raw | ForEach-Object -Process { $_.Contains(' ') ? "'${_}'" : $_ } })]
    [string]$Encoding
  )

  process {
    # The stream of the response content passed to function may be closed.
    # Force open the stream by setting the pointer to the beginning
    $RawContentStream.Position = 0
    if ($Encoding) {
      return [System.IO.StreamReader]::new($RawContentStream, [System.Text.Encoding]::GetEncoding($Encoding)).ReadToEnd()
    } else {
      return [System.IO.StreamReader]::new($RawContentStream).ReadToEnd()
    }
  }
}

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'DumplingsDefaultUserAgent', Justification = 'This variable is part of the public module contract')]
$DumplingsDefaultUserAgent = [Microsoft.PowerShell.Commands.PSUserAgent].GetProperty('UserAgent', [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static).GetValue($null)
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'DumplingsBrowserUserAgent', Justification = 'This variable is part of the public module contract')]
$DumplingsBrowserUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0'
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'DumplingsInternetExplorerUserAgent', Justification = 'This variable is part of the public module contract')]
$DumplingsInternetExplorerUserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'

Export-ModuleMember -Function Split-Uri, Join-Uri, Get-RedirectedUrl, Get-WebResponseHeader, Get-RedirectedUrls, Get-RedirectedUrl1st, Get-EmbeddedJson, Get-EmbeddedLinks, Read-ResponseContent -Variable DumplingsDefaultUserAgent, DumplingsBrowserUserAgent, DumplingsInternetExplorerUserAgent
