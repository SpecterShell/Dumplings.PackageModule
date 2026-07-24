using module Microsoft.PowerShell.Utility

#Requires -Version 7.4

# SPDX-License-Identifier: Apache-2.0
# This module contains a checked-in ProxyCommand generated from
# Microsoft.PowerShell.Utility\Invoke-RestMethod. The generated parameter block
# is intentionally retained so GitHub requests support the same transport,
# timeout, proxy, certificate, session, output, and pipeline controls as the
# underlying PowerShell cmdlet. Its basis is
# [System.Management.Automation.ProxyCommand]::Create(
#   [System.Management.Automation.CommandMetadata]::new(
#     (Get-Command Microsoft.PowerShell.Utility\Invoke-RestMethod)))
# with the Token type and execution blocks modified below.

# Apply project-wide defaults when PackageModule loads this module through its
# normal index. Standalone imports continue to work without Core-owned globals.
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Initialize-GitHubApiRequest {
  <#
  .SYNOPSIS
    Apply GitHub authentication and JSON defaults to REST method parameters.
  .DESCRIPTION
    Mutates the proxy's bound-parameter dictionary before Invoke-RestMethod is
    initialized. An explicit token takes precedence over GH_DUMPLINGS_TOKEN.
    Caller headers are preserved while the GitHub JSON media type is supplied
    when Accept is absent.
  .PARAMETER BoundParameters
    The mutable PSBoundParameters dictionary owned by Invoke-GitHubApi.
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The mutable proxy parameter dictionary')]
    [System.Collections.IDictionary]$BoundParameters
  )

  # Remove the wrapper-only opt-out before the dictionary is forwarded to
  # Invoke-RestMethod, which does not define this parameter.
  $AllowNonGitHubUri = [bool]$BoundParameters['AllowNonGitHubUri']
  $null = $BoundParameters.Remove('AllowNonGitHubUri')

  # A bearer token must only be attached to the exact GitHub API origins. Host
  # suffix checks are deliberately avoided because names such as
  # api.github.com.example.org are controlled by an unrelated site. Preserving
  # authorization across redirects is likewise opt-in because the destination
  # cannot be validated before Invoke-RestMethod follows the response.
  $RequestUri = $BoundParameters['Uri'] -as [uri]
  if (-not $AllowNonGitHubUri) {
    $AllowedHost = $RequestUri -and (
      [string]::Equals($RequestUri.DnsSafeHost, 'api.github.com', [StringComparison]::OrdinalIgnoreCase) -or
      [string]::Equals($RequestUri.DnsSafeHost, 'uploads.github.com', [StringComparison]::OrdinalIgnoreCase)
    )
    $AllowedOrigin = $RequestUri -and $RequestUri.IsAbsoluteUri -and
    $RequestUri.Scheme -eq [uri]::UriSchemeHttps -and
    $RequestUri.Port -eq 443 -and
    [string]::IsNullOrEmpty($RequestUri.UserInfo) -and
    $AllowedHost
    if (-not $AllowedOrigin) {
      $Origin = if ($RequestUri -and $RequestUri.IsAbsoluteUri) {
        "$($RequestUri.Scheme)://$($RequestUri.DnsSafeHost):$($RequestUri.Port)"
      } else {
        '[relative URI]'
      }
      throw "Refusing to send GitHub credentials to unapproved API origin '${Origin}'. Allowed origins are https://api.github.com and https://uploads.github.com. Use -AllowNonGitHubUri only for an endpoint you trust."
    }
    if ($BoundParameters['PreserveAuthorizationOnRedirect']) {
      throw 'Refusing to preserve GitHub authorization across redirects because the destination origin cannot be validated. Use -AllowNonGitHubUri only when every redirect target is trusted.'
    }
  }

  # Preserve the project's existing plain-text token API while converting to
  # the SecureString required by Invoke-RestMethod's bearer authentication.
  $GitHubToken = $BoundParameters['Token']
  if ($null -eq $GitHubToken -and (Test-Path -LiteralPath Env:\GH_DUMPLINGS_TOKEN)) {
    $GitHubToken = $Env:GH_DUMPLINGS_TOKEN
  }
  if ($GitHubToken -is [string]) {
    if ([string]::IsNullOrWhiteSpace($GitHubToken)) { throw 'The GitHub API token is empty.' }
    $SecureGitHubToken = [securestring]::new()
    foreach ($Character in $GitHubToken.GetEnumerator()) { $SecureGitHubToken.AppendChar($Character) }
    $SecureGitHubToken.MakeReadOnly()
    $GitHubToken = $SecureGitHubToken
  } elseif ($GitHubToken -isnot [securestring]) {
    throw 'A token required to invoke GitHub API is not provided through "-Token" or GH_DUMPLINGS_TOKEN.'
  }

  $BoundParameters['Authentication'] = [Microsoft.PowerShell.Commands.WebAuthenticationType]::Bearer
  $BoundParameters['Token'] = $GitHubToken

  # Clone caller headers into a case-insensitive dictionary so Accept can be
  # defaulted without mutating a dictionary owned by the caller.
  $RequestHeaders = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
  if ($BoundParameters['Headers']) {
    foreach ($Header in $BoundParameters['Headers'].GetEnumerator()) {
      $RequestHeaders[[string]$Header.Key] = $Header.Value
    }
  }
  if (-not $RequestHeaders.ContainsKey('Accept')) { $RequestHeaders.Accept = 'application/vnd.github+json' }
  $BoundParameters['Headers'] = $RequestHeaders

  # GitHub's REST and GraphQL endpoints consume JSON. Existing string and byte
  # bodies pass through unchanged, while dictionaries receive deterministic
  # deep serialization before Invoke-RestMethod binds them.
  if ([string]::IsNullOrWhiteSpace([string]$BoundParameters['ContentType'])) {
    $BoundParameters['ContentType'] = 'application/json'
  }
  if ($BoundParameters['Body'] -is [System.Collections.IDictionary]) {
    $BoundParameters['Body'] = ConvertTo-Json -InputObject $BoundParameters['Body'] -Depth 100 -Compress -EscapeHandling EscapeNonAscii
  }
}

function ConvertTo-GitHubApiException {
  <#
  .SYNOPSIS
    Format a failed GitHub API request as one deterministic exception.
  .PARAMETER ErrorRecord
    The terminating error emitted by Invoke-RestMethod.
  .PARAMETER Uri
    The GitHub API endpoint that failed.
  .PARAMETER Method
    The HTTP method used for the request.
  .OUTPUTS
    System.InvalidOperationException containing available HTTP and GitHub error evidence.
  #>
  [OutputType([System.InvalidOperationException])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The Invoke-RestMethod error record')]
    [System.Management.Automation.ErrorRecord]$ErrorRecord,

    [Parameter(Mandatory, HelpMessage = 'The GitHub API endpoint')]
    [uri]$Uri,

    [Parameter(Mandatory, HelpMessage = 'The HTTP request method')]
    [string]$Method
  )

  $Response = $ErrorRecord.Exception.Response
  $Status = if ($Response -and $null -ne $Response.StatusCode) {
    $ReasonPhrase = [string]$Response.ReasonPhrase
    "HTTP $([int]$Response.StatusCode)$([string]::IsNullOrWhiteSpace($ReasonPhrase) ? '' : " ${ReasonPhrase}")"
  }

  # PowerShell puts GitHub's JSON error body in ErrorDetails. A malformed or
  # non-JSON body must not mask the original transport exception.
  $Payload = $null
  if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
    try { $Payload = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -Depth 100 } catch {}
  }

  $PayloadMessage = $null
  $PayloadErrors = @()
  $DocumentationUrl = $null
  if ($null -ne $Payload) {
    $PayloadMessageProperty = $Payload.PSObject.Properties['message']
    if ($PayloadMessageProperty) { $PayloadMessage = [string]$PayloadMessageProperty.Value }
    $PayloadErrorsProperty = $Payload.PSObject.Properties['errors']
    if ($PayloadErrorsProperty) { $PayloadErrors = @($PayloadErrorsProperty.Value) }
    $DocumentationProperty = $Payload.PSObject.Properties['documentation_url']
    if ($DocumentationProperty) { $DocumentationUrl = [string]$DocumentationProperty.Value }
  }
  $Message = [string]($PayloadMessage ?? $ErrorRecord.Exception.Message)

  # GitHub validation errors may be strings or objects. Keep only documented
  # fields and tolerate null or partially populated array entries.
  $Details = [System.Collections.Generic.List[string]]::new()
  foreach ($Item in $PayloadErrors) {
    if ($null -eq $Item) { continue }
    if ($Item -is [string]) {
      if (-not [string]::IsNullOrWhiteSpace($Item)) { $Details.Add($Item) }
      continue
    }

    $Fields = foreach ($Name in @('resource', 'field', 'code', 'message', 'value')) {
      $Property = $Item.PSObject.Properties[$Name]
      if ($Property -and $null -ne $Property.Value -and -not [string]::IsNullOrWhiteSpace([string]$Property.Value)) {
        "${Name}=$($Property.Value)"
      }
    }
    if ($Fields) { $Details.Add(($Fields -join ', ')) }
  }

  $RequestId = $null
  if ($Response -and $Response.Headers) {
    try { $RequestId = ($Response.Headers.GetValues('x-github-request-id') | Select-Object -First 1) } catch {}
  }

  $Segments = [System.Collections.Generic.List[string]]::new()
  if ($Status) { $Segments.Add($Status) }
  if (-not [string]::IsNullOrWhiteSpace($Message)) { $Segments.Add($Message) }
  if ($Details.Count -gt 0) { $Segments.Add("errors: $($Details -join '; ')") }
  if (-not [string]::IsNullOrWhiteSpace($DocumentationUrl)) { $Segments.Add("documentation: ${DocumentationUrl}") }
  if (-not [string]::IsNullOrWhiteSpace($RequestId)) { $Segments.Add("request ID: ${RequestId}") }

  $Diagnostic = "GitHub API request $($Method.ToUpperInvariant()) $Uri failed"
  if ($Segments.Count -gt 0) { $Diagnostic += ": $($Segments -join ' | ')" }
  return [System.InvalidOperationException]::new($Diagnostic, $ErrorRecord.Exception)
}

function Write-GitHubApiResponse {
  <#
  .SYNOPSIS
    Validate GraphQL errors and emit a GitHub API response.
  .DESCRIPTION
    GitHub GraphQL reports application failures through an errors array while
    retaining HTTP status 200. This helper turns those failures into terminating
    exceptions and otherwise preserves Invoke-RestMethod pipeline output.
  .PARAMETER InputObject
    The parsed response returned by Invoke-RestMethod.
  .PARAMETER Uri
    The GitHub endpoint used for diagnostic context.
  #>
  param (
    [Parameter(Mandatory, ValueFromPipeline, HelpMessage = 'The parsed GitHub response')]
    [AllowNull()]
    $InputObject,

    [Parameter(Mandatory, HelpMessage = 'The GitHub API endpoint')]
    [uri]$Uri
  )

  process {
    if ($null -eq $InputObject) { return }

    # Only GraphQL endpoints use HTTP 200 with an application-level errors
    # collection. REST payloads are left untouched even if they expose an
    # unrelated property with the same name.
    if ($Uri.AbsolutePath.TrimEnd('/') -eq '/graphql') {
      $ErrorsProperty = $InputObject.PSObject.Properties['errors']
      if ($ErrorsProperty -and @($ErrorsProperty.Value).Count -gt 0) {
        $Messages = foreach ($Item in @($ErrorsProperty.Value)) {
          if ($null -eq $Item) { continue }
          $MessageProperty = $Item.PSObject.Properties['message']
          $PathProperty = $Item.PSObject.Properties['path']
          $Message = $MessageProperty ? [string]$MessageProperty.Value : [string]$Item
          $Path = $PathProperty ? (@($PathProperty.Value) -join '.') : $null
          if (-not [string]::IsNullOrWhiteSpace($Path)) { "${Message} (path: ${Path})" } else { $Message }
        }
        throw [System.InvalidOperationException]::new("GitHub GraphQL API request $Uri failed: $($Messages -join '; ')")
      }
    }

    return $InputObject
  }
}

function Invoke-GitHubApi {
  <#
  .SYNOPSIS
    Invoke the GitHub REST or GraphQL API through Invoke-RestMethod.
  .DESCRIPTION
    This ProxyCommand preserves Invoke-RestMethod parameters and pipeline
    behavior, injects bearer authentication from -Token or GH_DUMPLINGS_TOKEN,
    serializes dictionary bodies as JSON, and formats GitHub REST and GraphQL
    errors as terminating PowerShell exceptions.
  .PARAMETER Token
    A GitHub token as a SecureString or plain text. GH_DUMPLINGS_TOKEN is used when omitted.
  .PARAMETER AllowNonGitHubUri
    Permit credentials to be sent to an origin other than the official GitHub
    API origins. Use only for a trusted GitHub Enterprise or compatible API.
  .FORWARDHELPTARGETNAME Microsoft.PowerShell.Utility\Invoke-RestMethod
  .FORWARDHELPCATEGORY Cmdlet
  #>
  [CmdletBinding(DefaultParameterSetName = 'StandardMethod', HelpUri = 'https://go.microsoft.com/fwlink/?LinkID=2096706')]
  param (
    [Alias('FL')]
    [switch]${FollowRelLink},

    [Alias('ML')]
    [ValidateRange(1, 2147483647)]
    [int]${MaximumFollowRelLink},

    [Alias('RHV')]
    [string]${ResponseHeadersVariable},

    [string]${StatusCodeVariable},

    [switch]${UseBasicParsing},

    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [uri]${Uri},

    [version]${HttpVersion},

    [Microsoft.PowerShell.Commands.WebRequestSession]${WebSession},

    [Alias('SV')]
    [string]${SessionVariable},

    [switch]${AllowUnencryptedAuthentication},

    [Microsoft.PowerShell.Commands.WebAuthenticationType]${Authentication},

    [pscredential]
    [System.Management.Automation.CredentialAttribute()]
    ${Credential},

    [switch]${UseDefaultCredentials},

    [ValidateNotNullOrEmpty()]
    [string]${CertificateThumbprint},

    [ValidateNotNull()]
    [X509Certificate]${Certificate},

    [switch]${SkipCertificateCheck},

    [Microsoft.PowerShell.Commands.WebSslProtocol]${SslProtocol},

    # ProxyCommand normally exposes SecureString here. Object preserves the
    # historical plain-text token calls while initialization converts safely.
    [object]${Token},

    [string]${UserAgent},

    [switch]${DisableKeepAlive},

    [Alias('TimeoutSec')]
    [ValidateRange(0, 2147483647)]
    [int]${ConnectionTimeoutSeconds},

    [ValidateRange(0, 2147483647)]
    [int]${OperationTimeoutSeconds},

    [System.Collections.IDictionary]${Headers},

    [switch]${SkipHeaderValidation},

    [switch]${AllowInsecureRedirect},

    [ValidateRange(0, 2147483647)]
    [int]${MaximumRedirection},

    [ValidateRange(0, 2147483647)]
    [int]${MaximumRetryCount},

    [switch]${PreserveAuthorizationOnRedirect},

    [ValidateRange(1, 2147483647)]
    [int]${RetryIntervalSec},

    [Parameter(ParameterSetName = 'StandardMethod')]
    [Parameter(ParameterSetName = 'StandardMethodNoProxy')]
    [Microsoft.PowerShell.Commands.WebRequestMethod]${Method},

    [Parameter(ParameterSetName = 'CustomMethod', Mandatory)]
    [Parameter(ParameterSetName = 'CustomMethodNoProxy', Mandatory)]
    [Alias('CM')]
    [ValidateNotNullOrEmpty()]
    [string]${CustomMethod},

    [switch]${PreserveHttpMethodOnRedirect},

    [ValidateNotNullOrEmpty()]
    [System.Net.Sockets.UnixDomainSocketEndPoint]${UnixSocket},

    [Parameter(ParameterSetName = 'CustomMethodNoProxy', Mandatory)]
    [Parameter(ParameterSetName = 'StandardMethodNoProxy', Mandatory)]
    [switch]${NoProxy},

    [Parameter(ParameterSetName = 'StandardMethod')]
    [Parameter(ParameterSetName = 'CustomMethod')]
    [uri]${Proxy},

    [Parameter(ParameterSetName = 'StandardMethod')]
    [Parameter(ParameterSetName = 'CustomMethod')]
    [pscredential]
    [System.Management.Automation.CredentialAttribute()]
    ${ProxyCredential},

    [Parameter(ParameterSetName = 'StandardMethod')]
    [Parameter(ParameterSetName = 'CustomMethod')]
    [switch]${ProxyUseDefaultCredentials},

    [Parameter(ValueFromPipeline)]
    [object]${Body},

    [System.Collections.IDictionary]${Form},

    [string]${ContentType},

    [ValidateSet('chunked', 'compress', 'deflate', 'gzip', 'identity')]
    [string]${TransferEncoding},

    [ValidateNotNullOrEmpty()]
    [string]${InFile},

    [ValidateNotNullOrEmpty()]
    [string]${OutFile},

    [switch]${PassThru},

    [switch]${Resume},

    [switch]${SkipHttpErrorCheck},

    # This wrapper-only parameter is removed before invoking Invoke-RestMethod.
    [switch]${AllowNonGitHubUri}
  )

  begin {
    Initialize-GitHubApiRequest -BoundParameters $PSBoundParameters
    $RequestMethod = if ($PSBoundParameters['CustomMethod']) {
      [string]$PSBoundParameters['CustomMethod']
    } elseif ($PSBoundParameters['Method']) {
      [string]$PSBoundParameters['Method']
    } else {
      'Get'
    }

    # This block follows ProxyCommand.Create output. OutBuffer is normalized to
    # preserve streaming behavior before constructing the wrapped pipeline.
    $OutBufferValue = $null
    if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$OutBufferValue)) {
      $PSBoundParameters['OutBuffer'] = 1
    }

    $WrappedCommand = $ExecutionContext.InvokeCommand.GetCommand(
      'Microsoft.PowerShell.Utility\Invoke-RestMethod',
      [System.Management.Automation.CommandTypes]::Cmdlet
    )
    $CommandScript = { & $WrappedCommand @PSBoundParameters }
    $SteppablePipeline = $CommandScript.GetSteppablePipeline($MyInvocation.CommandOrigin)
    try {
      $SteppablePipeline.Begin($PSCmdlet)
    } catch {
      throw (ConvertTo-GitHubApiException -ErrorRecord $_ -Uri $Uri -Method $RequestMethod)
    }
  }

  process {
    try {
      $Result = $SteppablePipeline.Process($_)
    } catch {
      throw (ConvertTo-GitHubApiException -ErrorRecord $_ -Uri $Uri -Method $RequestMethod)
    }
    if ($null -ne $Result) { Write-GitHubApiResponse -InputObject $Result -Uri $Uri }
  }

  end {
    try {
      $Result = $SteppablePipeline.End()
    } catch {
      throw (ConvertTo-GitHubApiException -ErrorRecord $_ -Uri $Uri -Method $RequestMethod)
    }
    if ($null -ne $Result) { Write-GitHubApiResponse -InputObject $Result -Uri $Uri }
  }

  clean {
    if ($null -ne $SteppablePipeline) { $SteppablePipeline.Clean() }
  }
}
