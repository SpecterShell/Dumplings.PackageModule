# SPDX-License-Identifier: MIT
# Native WinGet-compatible installer downloads and compatibility probes. These
# functions never execute installers; probe files are deleted unless retained.

# Apply Dumplings defaults when the module is loaded independently or by PackageModule.
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

if (-not ([System.Management.Automation.PSTypeName]'Dumplings.WinGetDownload.WinInetDownloader').Type) {
  Add-Type -Path (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'Source', 'WinGet', 'WinGetDownloadProbe.cs')
}

$Script:WinGetDownloadFallbackClientVersion = '1.0.0'
$Script:WinGetDownloadWingetMutexName = 'Local\Dumplings-WinGetCli'
$Script:WinGetDownloadWingetMutexTimeoutMilliseconds = 120000

function Invoke-WinGetDownloadWingetMutex {
  <#
  .SYNOPSIS
    Execute a native WinGet operation under the process-wide CLI mutex.
  .DESCRIPTION
    Dumplings runner invocations use Core's scoped helper. PackageModule can
    also be consumed independently, so a private equivalent is retained here
    rather than importing files outside the submodule.
  .PARAMETER ScriptBlock
    The native WinGet operation to serialize.
  #>
  param ([Parameter(Mandatory)][ValidateNotNull()][scriptblock]$ScriptBlock)

  $UseMutexCommand = Get-Command -Name Use-Mutex -CommandType Function -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($UseMutexCommand) {
    return & $UseMutexCommand -Name $Script:WinGetDownloadWingetMutexName -TimeoutMilliseconds $Script:WinGetDownloadWingetMutexTimeoutMilliseconds -ScriptBlock $ScriptBlock
  }

  $Mutex = [System.Threading.Mutex]::new($false, $Script:WinGetDownloadWingetMutexName)
  $Acquired = $false
  try {
    try {
      $Acquired = $Mutex.WaitOne($Script:WinGetDownloadWingetMutexTimeoutMilliseconds)
    } catch [System.Threading.AbandonedMutexException] {
      $Acquired = $true
    }
    if (-not $Acquired) {
      throw [System.TimeoutException]::new("Timed out waiting for the WinGet CLI mutex after $($Script:WinGetDownloadWingetMutexTimeoutMilliseconds) ms.")
    }
    & $ScriptBlock
  } finally {
    if ($Acquired) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
  }
}

function Invoke-WinGetDownloadWingetCommand {
  <#
  .SYNOPSIS
    Invoke one WinGet version-information query.
  .PARAMETER Query
    Select whether to request the client version or complete package information.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][ValidateSet('Version', 'Info')][string]$Query)

  $Arguments = $Query -ceq 'Version' ? @('--version') : @('--info')
  Invoke-WinGetDownloadWingetMutex -ScriptBlock {
    $WingetCommand = Get-Command -Name winget -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $Output = @(& $WingetCommand.Source @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) { throw "winget $($Arguments -join ' ') exited with code $LASTEXITCODE." }
    return $Output
  }
}

function Resolve-WinGetDownloadVersionInfo {
  <#
  .SYNOPSIS
    Resolve WinGet user-agent versions or return stable fallback versions.
  #>
  [OutputType([pscustomobject])]
  param ()

  $ClientVersion = $Script:WinGetDownloadFallbackClientVersion
  $DetectedClientVersion = $false
  try {
    $VersionOutput = Invoke-WinGetDownloadWingetCommand -Query Version | Select-Object -First 1
    $VersionMatch = [regex]::Match([string]$VersionOutput, '^\s*v?(?<Version>\d+(?:\.\d+){1,3})\s*$')
    if (-not $VersionMatch.Success) { throw 'The installed winget client returned an invalid version.' }
    $ClientVersion = $VersionMatch.Groups['Version'].Value
    $DetectedClientVersion = $true
  } catch {
    Write-Verbose "The installed winget client version could not be determined; using fallback version $ClientVersion. $($_.Exception.Message)"
  }

  # Desktop App Installer versions have four numeric components. If --info is
  # unavailable, derive a syntactically valid package version from the client.
  $PackageVersion = ((@($ClientVersion.Split('.')) + @('0', '0', '0', '0')) | Select-Object -First 4) -join '.'
  if ($DetectedClientVersion) {
    try {
      $Info = Invoke-WinGetDownloadWingetCommand -Query Info | Out-String
      $Package = [regex]::Match($Info, 'Microsoft\.DesktopAppInstaller\s+v(?<Version>\d+(?:\.\d+){3})')
      if ($Package.Success) { $PackageVersion = $Package.Groups['Version'].Value }
    } catch {
      Write-Verbose "The Desktop App Installer package version could not be determined; using $PackageVersion. $($_.Exception.Message)"
    }
  }

  return [pscustomobject]@{
    ClientVersion  = $ClientVersion
    PackageVersion = $PackageVersion
  }
}

function Get-WinGetDownloadVersionInfo {
  <#
  .SYNOPSIS
    Read runner-shared WinGet versions or resolve them directly when standalone.
  #>
  [OutputType([pscustomobject])]
  param ()

  # PackageModule can be consumed without Core\Index.ps1. In that case there
  # is no shared runner lifecycle, so resolve the installed version directly.
  $StorageVariable = Get-Variable -Name DumplingsStorage -Scope Global -ErrorAction SilentlyContinue
  if ($null -eq $StorageVariable -or
    $StorageVariable.Value -isnot [hashtable] -or
    -not $StorageVariable.Value.IsSynchronized) {
    return Resolve-WinGetDownloadVersionInfo
  }

  $Storage = $StorageVariable.Value
  $CacheKey = '__DumplingsWinGetDownloadVersionInfo'
  $GateKey = '__DumplingsWinGetDownloadVersionInfoGate'

  # Only hold the synchronized hashtable lock long enough to inspect or create
  # state. The winget process runs behind a dedicated gate without blocking
  # unrelated DumplingsStorage readers and writers.
  [Threading.Monitor]::Enter($Storage.SyncRoot)
  try {
    if ($Storage.ContainsKey($CacheKey)) { return $Storage[$CacheKey] }
    if (-not $Storage.ContainsKey($GateKey)) { $Storage[$GateKey] = [Threading.SemaphoreSlim]::new(1, 1) }
    $Gate = $Storage[$GateKey]
  } finally {
    [Threading.Monitor]::Exit($Storage.SyncRoot)
  }

  $null = $Gate.Wait()
  try {
    # Another worker may have populated the value while this worker waited.
    [Threading.Monitor]::Enter($Storage.SyncRoot)
    try {
      if ($Storage.ContainsKey($CacheKey)) { return $Storage[$CacheKey] }
    } finally {
      [Threading.Monitor]::Exit($Storage.SyncRoot)
    }

    $VersionInfo = Resolve-WinGetDownloadVersionInfo
    [Threading.Monitor]::Enter($Storage.SyncRoot)
    try {
      $Storage[$CacheKey] = $VersionInfo
    } finally {
      [Threading.Monitor]::Exit($Storage.SyncRoot)
    }
    return $VersionInfo
  } finally {
    $null = $Gate.Release()
  }
}

function Get-WinGetDownloadUserAgent {
  <#
  .SYNOPSIS
    Build the default WinINet user agent used by the installed winget package
  .OUTPUTS
    System.String
  #>
  [OutputType([string])]
  param ()

  $VersionInfo = Get-WinGetDownloadVersionInfo
  return "winget-cli WindowsPackageManager/$($VersionInfo.ClientVersion) DesktopAppInstaller/Microsoft.DesktopAppInstaller v$($VersionInfo.PackageVersion)"
}

function ConvertTo-WinGetDownloadHeaderDictionary {
  <#
  .SYNOPSIS
    Convert PowerShell header dictionaries to the native probe contract
  #>
  param ([Collections.IDictionary]$Header)

  $Result = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  if ($Header) {
    foreach ($Entry in $Header.GetEnumerator()) { $Result[[string]$Entry.Key] = [string]$Entry.Value }
  }
  return $Result
}

function ConvertTo-WinGetDownloadSize {
  <#
  .SYNOPSIS
    Format native byte progress for Write-Progress
  #>
  param ([Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Bytes)

  if ($Bytes -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
  if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
  if ($Bytes -ge 1MB) { return '{0:N2} MB' -f ($Bytes / 1MB) }
  if ($Bytes -ge 1KB) { return '{0:N2} KB' -f ($Bytes / 1KB) }
  return "$Bytes B"
}

function Test-WinGetDownloadRetryStatus {
  <#
  .SYNOPSIS
    Apply Invoke-WebRequest's retryable HTTP status range
  #>
  [OutputType([bool])]
  param ([AllowNull()][Nullable[int]]$StatusCode)

  return $null -ne $StatusCode -and ($StatusCode -eq 304 -or ($StatusCode -ge 400 -and $StatusCode -le 599))
}

function Get-WinGetDownloadRetryInterval {
  <#
  .SYNOPSIS
    Read a Retry-After delay for HTTP 429 responses
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)]$Result,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$DefaultSeconds,
    [datetimeoffset]$UtcNow = [datetimeoffset]::UtcNow
  )

  if ($Result.HttpStatusCode -eq 429 -and -not [string]::IsNullOrWhiteSpace($Result.ResponseHeaders)) {
    $Match = [regex]::Match([string]$Result.ResponseHeaders, '(?im)^Retry-After\s*:\s*(?<Value>[^\r\n]+?)\s*$')
    if ($Match.Success) {
      $Value = $Match.Groups['Value'].Value.Trim()
      $RetryAfter = 0L
      if ([long]::TryParse($Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$RetryAfter)) {
        return [int][Math]::Min($RetryAfter, [int]::MaxValue)
      }
      # Preserve an oversized numeric delay as a value that exceeds normal limits.
      if ($Value -match '^\d+$') { return [int]::MaxValue }

      $RetryAfterDate = [datetimeoffset]::MinValue
      $DateStyles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
      if ([datetimeoffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, $DateStyles, [ref]$RetryAfterDate)) {
        $Seconds = [Math]::Max(0, [Math]::Ceiling(($RetryAfterDate - $UtcNow).TotalSeconds))
        return [int][Math]::Min($Seconds, [int]::MaxValue)
      }
    }
  }
  return $DefaultSeconds
}

function Invoke-WinGetDownloadOperation {
  <#
  .SYNOPSIS
    Poll one native download operation with progress, cancellation, and retries
  .DESCRIPTION
    PowerShell remains on the pipeline thread while the native transport runs
    in the background. A pipeline stop therefore enters finally and cancels the
    active WinINet handles or Delivery Optimization transfer.
  #>
  param (
    [Parameter(Mandatory)][scriptblock]$StartOperation,
    [Parameter(Mandatory)][hashtable]$OperationArgument,
    [Parameter(Mandatory)][string]$Activity,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60,
    [ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(1, [int]::MaxValue)][int]$ProgressId = 174593042
  )

  $MaximumAttempts = $MaximumRetryCount + 1
  $TotalRetryDelaySeconds = 0L
  for ($Attempt = 1; $Attempt -le $MaximumAttempts; $Attempt++) {
    $Operation = & $StartOperation $Attempt $OperationArgument
    if ($null -eq $Operation) { throw 'The native downloader did not return an operation.' }
    $WroteProgress = $false
    $NextProgress = [DateTime]::UtcNow.AddSeconds(1)
    $Started = [DateTime]::UtcNow
    $LastActivity = $Started
    $LastBytes = -1L
    $ResponseStarted = $false
    try {
      while (-not $Operation.Wait(200)) {
        $Progress = $Operation.GetProgress()
        $Now = [DateTime]::UtcNow
        if ($Progress.BytesDownloaded -ne $LastBytes) {
          $LastBytes = [long]$Progress.BytesDownloaded
          $LastActivity = $Now
        }
        if (-not $ResponseStarted -and $Progress.State -in @('ResponseReceived', 'Downloading', 'Transferring', 'Transferred', 'Finalized', 'Hashing')) {
          $ResponseStarted = $true
          $LastActivity = $Now
        }
        if ($ConnectionTimeoutSeconds -gt 0 -and -not $ResponseStarted -and $Now -ge $Started.AddSeconds($ConnectionTimeoutSeconds)) {
          $Operation.Cancel()
          throw [TimeoutException]::new("$Activity exceeded the $ConnectionTimeoutSeconds-second connection timeout.")
        }
        if ($OperationTimeoutSeconds -gt 0 -and $ResponseStarted -and $Now -ge $LastActivity.AddSeconds($OperationTimeoutSeconds)) {
          $Operation.Cancel()
          throw [TimeoutException]::new("$Activity exceeded the $OperationTimeoutSeconds-second operation timeout without receiving more data.")
        }
        if ($Now -lt $NextProgress) { continue }
        $Downloaded = ConvertTo-WinGetDownloadSize -Bytes ([Math]::Max(0L, [long]$Progress.BytesDownloaded))
        $Total = if ($null -ne $Progress.ContentLength -and $Progress.ContentLength -gt 0) { ConvertTo-WinGetDownloadSize -Bytes ([long]$Progress.ContentLength) } else { '???' }
        $Percent = if ($null -ne $Progress.ContentLength -and $Progress.ContentLength -gt 0) {
          [Math]::Min(100, [int]([decimal]$Progress.BytesDownloaded * 100 / [decimal]$Progress.ContentLength))
        } else { -1 }
        Write-Progress -Id $ProgressId -Activity $Activity -Status "$($Progress.State): $Downloaded of $Total" -PercentComplete $Percent
        $WroteProgress = $true
        $NextProgress = $Now.AddSeconds(1)
      }
      $Result = $Operation.Result
      $Result.AttemptCount = $Attempt
    } finally {
      if (-not $Operation.IsCompleted) { $Operation.Cancel() }
      $Operation.Dispose()
      if ($WroteProgress) { Write-Progress -Id $ProgressId -Activity $Activity -Completed }
    }

    if ($Attempt -ge $MaximumAttempts -or -not (Test-WinGetDownloadRetryStatus -StatusCode $Result.HttpStatusCode)) { return $Result }
    $Delay = Get-WinGetDownloadRetryInterval -Result $Result -DefaultSeconds $RetryIntervalSec
    if ($Delay -gt $MaximumRetryDelaySeconds) {
      Write-Verbose "Not retrying $Activity because the requested $Delay-second delay exceeds the $MaximumRetryDelaySeconds-second per-retry limit."
      return $Result
    }
    $RemainingRetryDelaySeconds = [long]$MaximumTotalRetryDelaySeconds - $TotalRetryDelaySeconds
    if ($Delay -gt $RemainingRetryDelaySeconds) {
      Write-Verbose "Not retrying $Activity because the requested $Delay-second delay exceeds the $RemainingRetryDelaySeconds-second remaining retry-delay budget."
      return $Result
    }
    Write-Verbose "Retrying $Activity in $Delay second(s) after HTTP status $($Result.HttpStatusCode); attempt $($Attempt + 1) of $MaximumAttempts."
    Start-Sleep -Seconds $Delay
    $TotalRetryDelaySeconds += $Delay
  }
}

function Open-WinGetWinINetDownloadOperation {
  <#
  .SYNOPSIS
    Start one cancellable native WinINet operation
  #>
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$UserAgent,
    [Parameter(Mandatory)][Collections.Generic.IDictionary[string, string]]$Header,
    [AllowEmptyString()][string]$Proxy,
    [bool]$ResponseOnly,
    [int]$ConnectionTimeoutSeconds,
    [int]$OperationTimeoutSeconds
  )

  return [Dumplings.WinGetDownload.WinInetDownloader]::StartDownload(
    $Uri.AbsoluteUri, $DestinationPath, $UserAgent, $Header, $Proxy, $ResponseOnly, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds)
}

function Open-WinGetWinINetRedirectOperation {
  <#
  .SYNOPSIS
    Start one cancellable bodyless WinINet redirect request
  .PARAMETER Uri
    The HTTP or HTTPS URL to resolve
  .PARAMETER Method
    GET or HEAD; neither method reads a response body
  .PARAMETER UserAgent
    The user agent sent through WinINet
  .PARAMETER Header
    Additional request headers
  .PARAMETER Proxy
    An optional explicit proxy URI
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time allowed before response headers arrive
  .PARAMETER OperationTimeoutSeconds
    Native send and receive operation timeout
  #>
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][ValidateSet('GET', 'HEAD')][string]$Method,
    [Parameter(Mandatory)][string]$UserAgent,
    [Parameter(Mandatory)][Collections.Generic.IDictionary[string, string]]$Header,
    [AllowEmptyString()][string]$Proxy,
    [int]$ConnectionTimeoutSeconds,
    [int]$OperationTimeoutSeconds
  )

  return [Dumplings.WinGetDownload.WinInetDownloader]::StartRedirectResolution(
    $Uri.AbsoluteUri, $Method, $UserAgent, $Header, $Proxy, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds)
}

function Open-WinGetDeliveryOptimizationDownloadOperation {
  <#
  .SYNOPSIS
    Start one cancellable native Delivery Optimization operation
  #>
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$DisplayName,
    [AllowEmptyString()][string]$ExpectedSha256,
    [Parameter(Mandatory)][Collections.Generic.IDictionary[string, string]]$Header,
    [int]$NoProgressTimeoutSeconds,
    [int]$MaximumDurationSeconds,
    [bool]$ResponseOnly,
    [int]$ConnectionTimeoutSeconds,
    [int]$OperationTimeoutSeconds
  )

  return [Dumplings.WinGetDownload.DeliveryOptimizationDownloader]::StartDownload(
    $Uri.AbsoluteUri, $DestinationPath, $DisplayName, $ExpectedSha256, $Header,
    $NoProgressTimeoutSeconds, $MaximumDurationSeconds, $ResponseOnly, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds)
}

function Invoke-WinGetWinINetDownload {
  <#
  .SYNOPSIS
    Download an installer through the same native WinINet API sequence as WinGet
  .PARAMETER Uri
    The installer URL
  .PARAMETER DestinationPath
    The output file path
  .PARAMETER Header
    Optional manifest authentication headers
  .PARAMETER Proxy
    Optional explicit proxy URI; WinGet forces WinINet when a proxy is configured
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time for request connection and response headers; TimeoutSec is an alias
  .PARAMETER OperationTimeoutSeconds
    Maximum time for each response-body read operation
  .PARAMETER MaximumRetryCount
    Number of retries for HTTP 304 and 400 through 599 responses
  .PARAMETER RetryIntervalSec
    Delay between retries; HTTP 429 Retry-After takes precedence
  .PARAMETER MaximumRetryDelaySeconds
    Maximum delay permitted before any single retry
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative delay permitted across all retries
  #>
  [OutputType([Dumplings.WinGetDownload.DownloadResult])]
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Collections.IDictionary]$Header,
    [string]$Proxy,
    [string]$UserAgent = (Get-WinGetDownloadUserAgent),
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60,
    [switch]$ResponseOnly
  )

  $Headers = ConvertTo-WinGetDownloadHeaderDictionary -Header $Header
  $OperationArgument = @{
    Uri                      = $Uri
    DestinationPath          = $DestinationPath
    UserAgent                = $UserAgent
    Header                   = $Headers
    Proxy                    = $Proxy
    ResponseOnly             = $ResponseOnly.IsPresent
    ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds
    OperationTimeoutSeconds  = $OperationTimeoutSeconds
  }
  return Invoke-WinGetDownloadOperation -StartOperation {
    param($Attempt, $Argument)
    $null = $Attempt
    Open-WinGetWinINetDownloadOperation @Argument
  } -OperationArgument $OperationArgument -Activity 'Downloading installer with WinINet' -MaximumRetryCount $MaximumRetryCount -RetryIntervalSec $RetryIntervalSec `
    -MaximumRetryDelaySeconds $MaximumRetryDelaySeconds -MaximumTotalRetryDelaySeconds $MaximumTotalRetryDelaySeconds `
    -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds -OperationTimeoutSeconds $OperationTimeoutSeconds
}

function Invoke-WinGetDeliveryOptimizationDownload {
  <#
  .SYNOPSIS
    Download an installer through the Delivery Optimization COM service as WinGet does
  .PARAMETER Uri
    The installer URL
  .PARAMETER DestinationPath
    The output file path; Delivery Optimization will not overwrite it
  .PARAMETER ExpectedSha256
    The manifest installer hash used by WinGet as the Delivery Optimization ContentId
  .PARAMETER Header
    Optional manifest authentication headers
  .PARAMETER NoProgressTimeoutSeconds
    WinGet's default no-progress timeout is 60 seconds
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time for the transfer to receive an HTTP response; TimeoutSec is an alias
  .PARAMETER OperationTimeoutSeconds
    Maximum time between response-body progress updates
  .PARAMETER MaximumRetryCount
    Number of retries for HTTP 304 and 400 through 599 responses
  .PARAMETER RetryIntervalSec
    Delay between retries; HTTP 429 Retry-After takes precedence
  .PARAMETER MaximumRetryDelaySeconds
    Maximum delay permitted before any single retry
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative delay permitted across all retries
  #>
  [OutputType([Dumplings.WinGetDownload.DownloadResult])]
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][string]$DestinationPath,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [Collections.IDictionary]$Header,
    [ValidateRange(1, 3600)][int]$NoProgressTimeoutSeconds = 60,
    [ValidateRange(0, 86400)][int]$MaximumDurationSeconds = 3600,
    [string]$DisplayName = 'Windows Package Manager',
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60,
    [switch]$ResponseOnly
  )

  $Headers = ConvertTo-WinGetDownloadHeaderDictionary -Header $Header
  $OperationArgument = @{
    Uri                      = $Uri
    DestinationPath          = $DestinationPath
    DisplayName              = $DisplayName
    ExpectedSha256           = $ExpectedSha256
    Header                   = $Headers
    NoProgressTimeoutSeconds = $NoProgressTimeoutSeconds
    MaximumDurationSeconds   = $MaximumDurationSeconds
    ResponseOnly             = $ResponseOnly.IsPresent
    ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds
    OperationTimeoutSeconds  = $OperationTimeoutSeconds
  }
  return Invoke-WinGetDownloadOperation -StartOperation {
    param($Attempt, $Argument)
    $null = $Attempt
    Open-WinGetDeliveryOptimizationDownloadOperation @Argument
  } -OperationArgument $OperationArgument -Activity 'Downloading installer with Delivery Optimization' -MaximumRetryCount $MaximumRetryCount -RetryIntervalSec $RetryIntervalSec `
    -MaximumRetryDelaySeconds $MaximumRetryDelaySeconds -MaximumTotalRetryDelaySeconds $MaximumTotalRetryDelaySeconds `
    -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds -OperationTimeoutSeconds $OperationTimeoutSeconds
}

function ConvertFrom-WinGetDownloadResponseHeader {
  <#
  .SYNOPSIS
    Convert native raw response headers to the Get-WebResponseHeader contract
  .PARAMETER Result
    Native WinINet or Delivery Optimization response evidence
  .PARAMETER Uri
    Original request URI used when the transport reports no redirected URI
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Result,
    [Parameter(Mandatory)][uri]$Uri
  )

  $Headers = [hashtable]::new([StringComparer]::OrdinalIgnoreCase)
  $StatusCode = $Result.HttpStatusCode
  $ReasonPhrase = $null
  $CurrentHeader = $null
  foreach ($Line in @([string]$Result.ResponseHeaders -split '\r?\n')) {
    # WinINet may expose more than one HTTP block after proxy negotiation or
    # redirection. Clear prior fields whenever a later status line begins.
    $StatusMatch = [regex]::Match($Line, '^HTTP/\S+\s+(?<Status>\d{3})(?:\s+(?<Reason>.*?))?\s*$')
    if ($StatusMatch.Success) {
      $Headers.Clear()
      $StatusCode = [int]$StatusMatch.Groups['Status'].Value
      $ReasonPhrase = $StatusMatch.Groups['Reason'].Value
      $CurrentHeader = $null
      continue
    }
    if ([string]::IsNullOrWhiteSpace($Line)) { continue }

    # Preserve obsolete folded values when encountered rather than exposing a
    # continuation as an invalid standalone header.
    if ($Line -match '^\s+' -and $CurrentHeader) {
      $Values = @($Headers[$CurrentHeader])
      $Values[-1] = "$($Values[-1]) $($Line.Trim())"
      $Headers[$CurrentHeader] = [string[]]$Values
      continue
    }

    $Separator = $Line.IndexOf(':')
    if ($Separator -le 0) { continue }
    $Name = $Line.Substring(0, $Separator).Trim()
    $Value = $Line.Substring($Separator + 1).Trim()
    if ($Headers.ContainsKey($Name)) {
      $Headers[$Name] = [string[]](@($Headers[$Name]) + $Value)
    } else {
      $Headers[$Name] = [string[]]@($Value)
    }
    $CurrentHeader = $Name
  }

  return [pscustomobject][ordered]@{
    StatusCode   = $StatusCode
    ReasonPhrase = $ReasonPhrase
    RequestUri   = [string]($Result.FinalUri ? $Result.FinalUri : $Uri.AbsoluteUri)
    Headers      = $Headers
  }
}

function Invoke-WinGetWinINetResponseRequest {
  <#
  .SYNOPSIS
    Send one retryable WinINet request without reading its response body
  #>
  [OutputType([Dumplings.WinGetDownload.DownloadResult])]
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [ValidateSet('GET', 'HEAD')][string]$Method = 'HEAD',
    [Collections.IDictionary]$Header,
    [string]$Proxy,
    [string]$UserAgent = (Get-WinGetDownloadUserAgent),
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60
  )

  $OperationArgument = @{
    Uri                      = $Uri
    Method                   = $Method
    UserAgent                = $UserAgent
    Header                   = ConvertTo-WinGetDownloadHeaderDictionary -Header $Header
    Proxy                    = $Proxy
    ConnectionTimeoutSeconds = $ConnectionTimeoutSeconds
    OperationTimeoutSeconds  = $OperationTimeoutSeconds
  }
  return Invoke-WinGetDownloadOperation -StartOperation {
    param($Attempt, $Argument)
    $null = $Attempt
    Open-WinGetWinINetRedirectOperation @Argument
  } -OperationArgument $OperationArgument -Activity 'Reading response metadata with WinINet' `
    -MaximumRetryCount $MaximumRetryCount -RetryIntervalSec $RetryIntervalSec `
    -MaximumRetryDelaySeconds $MaximumRetryDelaySeconds -MaximumTotalRetryDelaySeconds $MaximumTotalRetryDelaySeconds `
    -ConnectionTimeoutSeconds $ConnectionTimeoutSeconds -OperationTimeoutSeconds $OperationTimeoutSeconds
}

function Invoke-WinGetDeliveryOptimizationResponseRequest {
  <#
  .SYNOPSIS
    Read Delivery Optimization response metadata and remove partial transfer data
  #>
  [OutputType([Dumplings.WinGetDownload.DownloadResult])]
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [Collections.IDictionary]$Header,
    [ValidateRange(1, 3600)][int]$NoProgressTimeoutSeconds = 60,
    [ValidateRange(0, 86400)][int]$MaximumDurationSeconds = 3600,
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60
  )

  # IDODownload requires a local path even when it is aborted after receiving
  # response metadata. Keep that implementation detail outside caller paths.
  $TemporaryPath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "Dumplings-Response-$([guid]::NewGuid().ToString('N')).tmp"
  try {
    $Arguments = @{
      Uri                           = $Uri
      DestinationPath               = $TemporaryPath
      Header                        = $Header
      NoProgressTimeoutSeconds      = $NoProgressTimeoutSeconds
      MaximumDurationSeconds        = $MaximumDurationSeconds
      ConnectionTimeoutSeconds      = $ConnectionTimeoutSeconds
      OperationTimeoutSeconds       = $OperationTimeoutSeconds
      MaximumRetryCount             = $MaximumRetryCount
      RetryIntervalSec              = $RetryIntervalSec
      MaximumRetryDelaySeconds      = $MaximumRetryDelaySeconds
      MaximumTotalRetryDelaySeconds = $MaximumTotalRetryDelaySeconds
      ResponseOnly                  = $true
    }
    if ($ExpectedSha256) { $Arguments.ExpectedSha256 = $ExpectedSha256 }
    return Invoke-WinGetDeliveryOptimizationDownload @Arguments
  } finally {
    Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
  }
}

function Get-WinGetWinINetRedirectedUrl {
  <#
  .SYNOPSIS
    Resolve the final URL through WinINet without downloading the response body
  .DESCRIPTION
    Sends a native WinINet GET or HEAD request with automatic redirection. The
    effective URL is read from the request handle after redirects complete. A
    GET request sends no Range header and deliberately leaves its response body
    unread, while HEAD asks the server not to return a body.
  .PARAMETER Uri
    The HTTP or HTTPS URL to resolve
  .PARAMETER Method
    GET for maximum server compatibility or HEAD to request headers only
  .PARAMETER Header
    Optional request headers
  .PARAMETER Proxy
    Optional explicit proxy URI
  .PARAMETER UserAgent
    Optional WinINet user agent override
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time for connection and response headers; TimeoutSec is an alias
  .PARAMETER OperationTimeoutSeconds
    Maximum time for each native send or receive operation
  .PARAMETER MaximumRetryCount
    Number of retries for HTTP 304 and 400 through 599 responses
  .PARAMETER RetryIntervalSec
    Delay between retries; HTTP 429 Retry-After takes precedence
  .PARAMETER MaximumRetryDelaySeconds
    Maximum delay permitted before any single retry
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative delay permitted across all retries
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][uri]$Uri,
    [ValidateSet('GET', 'HEAD')][string]$Method = 'HEAD',
    [Collections.IDictionary]$Header,
    [string]$Proxy,
    [string]$UserAgent = (Get-WinGetDownloadUserAgent),
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60
  )

  process {
    $Result = Invoke-WinGetWinINetResponseRequest @PSBoundParameters

    if (-not [string]::IsNullOrWhiteSpace($Result.FinalUri)) { return $Result.FinalUri }
    $Failure = Format-WinGetDownloadFailure -Method 'WinINet' -Result $Result
    throw [IO.IOException]::new("Failed to resolve the redirected URL. $Failure")
  }
}

function Get-WinGetWinINetResponseHeader {
  <#
  .SYNOPSIS
    Get final response headers through WinINet without reading the response body
  .PARAMETER Uri
    The HTTP or HTTPS URL to request
  .PARAMETER Method
    GET for maximum server compatibility or HEAD to request headers only
  .PARAMETER Header
    Optional request headers
  .PARAMETER Proxy
    Optional explicit proxy URI
  .PARAMETER UserAgent
    Optional WinINet user agent override
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time for connection and response headers; TimeoutSec is an alias
  .PARAMETER OperationTimeoutSeconds
    Maximum time for each native send or receive operation
  .PARAMETER MaximumRetryCount
    Number of retries for HTTP 304 and 400 through 599 responses
  .PARAMETER RetryIntervalSec
    Delay between retries; HTTP 429 Retry-After takes precedence
  .PARAMETER MaximumRetryDelaySeconds
    Maximum delay permitted before any single retry
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative delay permitted across all retries
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][uri]$Uri,
    [ValidateSet('GET', 'HEAD')][string]$Method = 'HEAD',
    [Collections.IDictionary]$Header,
    [string]$Proxy,
    [string]$UserAgent = (Get-WinGetDownloadUserAgent),
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60
  )

  process {
    $Result = Invoke-WinGetWinINetResponseRequest @PSBoundParameters
    if ($null -ne $Result.HttpStatusCode -or -not [string]::IsNullOrWhiteSpace($Result.ResponseHeaders)) {
      return ConvertFrom-WinGetDownloadResponseHeader -Result $Result -Uri $Uri
    }
    $Failure = Format-WinGetDownloadFailure -Method 'WinINet' -Result $Result
    throw [IO.IOException]::new("Failed to read response headers. $Failure")
  }
}

function Get-WinGetDeliveryOptimizationRedirectedUrl {
  <#
  .SYNOPSIS
    Resolve the final URL exposed by Delivery Optimization
  .DESCRIPTION
    Delivery Optimization has no HTTP HEAD or metadata-only operation. This
    function starts its normal GET transfer, reads HttpRedirectionTarget as soon
    as response metadata becomes available, aborts the transfer, and removes
    any partial local file. The service may transfer a small initial block before
    exposing response metadata, but it does not finalize or retain the installer.
  .PARAMETER Uri
    The HTTP or HTTPS URL to resolve
  .PARAMETER ExpectedSha256
    Optional WinGet installer hash used as the Delivery Optimization ContentId
  .PARAMETER Header
    Optional request headers
  .PARAMETER NoProgressTimeoutSeconds
    Maximum interval without Delivery Optimization progress
  .PARAMETER MaximumDurationSeconds
    Maximum total duration of each response-only transfer
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time before Delivery Optimization receives a response
  .PARAMETER OperationTimeoutSeconds
    Maximum interval between response progress updates
  .PARAMETER MaximumRetryCount
    Number of retries for HTTP 304 and 400 through 599 responses
  .PARAMETER RetryIntervalSec
    Delay between retries; HTTP 429 Retry-After takes precedence
  .PARAMETER MaximumRetryDelaySeconds
    Maximum delay permitted before any single retry
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative delay permitted across all retries
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][uri]$Uri,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [Collections.IDictionary]$Header,
    [ValidateRange(1, 3600)][int]$NoProgressTimeoutSeconds = 60,
    [ValidateRange(0, 86400)][int]$MaximumDurationSeconds = 3600,
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60
  )

  process {
    $Result = Invoke-WinGetDeliveryOptimizationResponseRequest @PSBoundParameters
    if (-not [string]::IsNullOrWhiteSpace($Result.FinalUri)) { return $Result.FinalUri }
    # A missing redirection target means Delivery Optimization accepted the
    # original URL without redirecting it.
    if ($Result.ResponseAccepted -or $null -ne $Result.HttpStatusCode) { return $Uri.AbsoluteUri }
    $Failure = Format-WinGetDownloadFailure -Method 'Delivery Optimization' -Result $Result
    throw [IO.IOException]::new("Failed to resolve the redirected URL. $Failure")
  }
}

function Get-WinGetDeliveryOptimizationResponseHeader {
  <#
  .SYNOPSIS
    Get final response headers exposed by Delivery Optimization
  .DESCRIPTION
    Delivery Optimization starts a GET transfer and may receive a small initial
    block before exposing headers. The transfer is then aborted and its partial
    local file is removed.
  .PARAMETER Uri
    The HTTP or HTTPS URL to request
  .PARAMETER ExpectedSha256
    Optional WinGet installer hash used as the Delivery Optimization ContentId
  .PARAMETER Header
    Optional request headers
  .PARAMETER NoProgressTimeoutSeconds
    Maximum interval without Delivery Optimization progress
  .PARAMETER MaximumDurationSeconds
    Maximum total duration of each response-only transfer
  .PARAMETER ConnectionTimeoutSeconds
    Maximum time before Delivery Optimization receives a response
  .PARAMETER OperationTimeoutSeconds
    Maximum interval between response progress updates
  .PARAMETER MaximumRetryCount
    Number of retries for HTTP 304 and 400 through 599 responses
  .PARAMETER RetryIntervalSec
    Delay between retries; HTTP 429 Retry-After takes precedence
  .PARAMETER MaximumRetryDelaySeconds
    Maximum delay permitted before any single retry
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative delay permitted across all retries
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][uri]$Uri,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [Collections.IDictionary]$Header,
    [ValidateRange(1, 3600)][int]$NoProgressTimeoutSeconds = 60,
    [ValidateRange(0, 86400)][int]$MaximumDurationSeconds = 3600,
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60
  )

  process {
    $Result = Invoke-WinGetDeliveryOptimizationResponseRequest @PSBoundParameters
    if ($null -ne $Result.HttpStatusCode -or -not [string]::IsNullOrWhiteSpace($Result.ResponseHeaders)) {
      return ConvertFrom-WinGetDownloadResponseHeader -Result $Result -Uri $Uri
    }
    $Failure = Format-WinGetDownloadFailure -Method 'Delivery Optimization' -Result $Result
    throw [IO.IOException]::new("Failed to read response headers. $Failure")
  }
}

function Test-WinGetDownloadCancellation {
  <#
  .SYNOPSIS
    Test whether a native download failure represents pipeline cancellation
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][Management.Automation.ErrorRecord]$ErrorRecord)

  $Exception = $ErrorRecord.Exception
  while ($Exception) {
    if ($Exception -is [Management.Automation.PipelineStoppedException] -or $Exception -is [OperationCanceledException]) { return $true }
    $Exception = $Exception.InnerException
  }
  return $false
}

function Format-WinGetDownloadFailure {
  <#
  .SYNOPSIS
    Format structured native download failure evidence
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Method,
    [Dumplings.WinGetDownload.DownloadResult]$Result,
    [Management.Automation.ErrorRecord]$ErrorRecord
  )

  return [Dumplings.WinGetDownload.DownloadFailureFormatter]::Format(
    $Method,
    $Result,
    ($ErrorRecord ? $ErrorRecord.Exception : $null)
  )
}

function Invoke-WinGetInstallerDownload {
  <#
  .SYNOPSIS
    Download an installer using WinGet's native transport order
  .DESCRIPTION
    Use Delivery Optimization first unless an explicit proxy forces WinINet.
    Nonfatal Delivery Optimization failures fall back to WinINet. Fatal policy
    failures, cancellation, and combined transport failures clean partial files
    and throw with structured native diagnostics.
  .PARAMETER Uri
    The installer URL
  .PARAMETER DestinationPath
    The output file path
  .PARAMETER Header
    Optional manifest authentication headers
  .PARAMETER Proxy
    Optional explicit proxy URI; WinGet forces WinINet when configured
  .PARAMETER UserAgent
    Optional WinINet user agent override
  #>
  [OutputType([Dumplings.WinGetDownload.DownloadResult])]
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Collections.IDictionary]$Header,
    [string]$Proxy,
    [string]$UserAgent
  )

  Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
  $WinINetArguments = @{ Uri = $Uri; DestinationPath = $DestinationPath }
  if ($Header) { $WinINetArguments.Header = $Header }
  if ($PSBoundParameters.ContainsKey('Proxy')) { $WinINetArguments.Proxy = $Proxy }
  if ($PSBoundParameters.ContainsKey('UserAgent')) { $WinINetArguments.UserAgent = $UserAgent }

  if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
    $WinINetResult = $null
    $WinINetError = $null
    try {
      $WinINetResult = Invoke-WinGetWinINetDownload @WinINetArguments
    } catch {
      if (Test-WinGetDownloadCancellation -ErrorRecord $_) {
        Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
        throw
      }
      $WinINetError = $_
    }
    if ($WinINetResult -and $WinINetResult.Success -and (Test-Path -LiteralPath $DestinationPath -PathType Leaf)) { return $WinINetResult }
    $WinINetFailure = Format-WinGetDownloadFailure -Method 'WinINet' -Result $WinINetResult -ErrorRecord $WinINetError
    Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
    throw [IO.IOException]::new("Installer download failed. ${WinINetFailure}")
  }

  $DeliveryOptimizationResult = $null
  $DeliveryOptimizationError = $null
  try {
    $DeliveryOptimizationArguments = @{ Uri = $Uri; DestinationPath = $DestinationPath }
    if ($Header) { $DeliveryOptimizationArguments.Header = $Header }
    $DeliveryOptimizationResult = Invoke-WinGetDeliveryOptimizationDownload @DeliveryOptimizationArguments
  } catch {
    if (Test-WinGetDownloadCancellation -ErrorRecord $_) {
      Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
      throw
    }
    $DeliveryOptimizationError = $_
  }

  if ($DeliveryOptimizationResult -and $DeliveryOptimizationResult.Success -and (Test-Path -LiteralPath $DestinationPath -PathType Leaf)) {
    return $DeliveryOptimizationResult
  }

  $DeliveryOptimizationFailure = Format-WinGetDownloadFailure -Method 'Delivery Optimization' -Result $DeliveryOptimizationResult -ErrorRecord $DeliveryOptimizationError
  if ($DeliveryOptimizationResult -and $DeliveryOptimizationResult.IsFatalDeliveryOptimizationError) {
    Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
    throw [IO.IOException]::new("Installer download failed with a fatal Delivery Optimization error. ${DeliveryOptimizationFailure}")
  }

  Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
  Write-Warning "${DeliveryOptimizationFailure}. Trying WinINet..."
  $WinINetResult = $null
  $WinINetError = $null
  try {
    $WinINetResult = Invoke-WinGetWinINetDownload @WinINetArguments
  } catch {
    if (Test-WinGetDownloadCancellation -ErrorRecord $_) {
      Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
      throw
    }
    $WinINetError = $_
  }

  if ($WinINetResult -and $WinINetResult.Success -and (Test-Path -LiteralPath $DestinationPath -PathType Leaf)) {
    $WinINetResult.FallbackOccurred = $true
    $WinINetResult.PreviousFailure = $DeliveryOptimizationFailure
    return $WinINetResult
  }

  $WinINetFailure = Format-WinGetDownloadFailure -Method 'WinINet' -Result $WinINetResult -ErrorRecord $WinINetError
  Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
  throw [IO.IOException]::new("Installer download failed. ${DeliveryOptimizationFailure}. ${WinINetFailure}")
}

function Add-WinGetDownloadProbeEvidence {
  <#
  .SYNOPSIS
    Add hash and acceptance evidence to a native downloader result
  #>
  param (
    [Parameter(Mandatory)]$Result,
    [string]$ExpectedSha256,
    [bool]$KeepDownload
  )

  $HashMatches = if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or [string]::IsNullOrWhiteSpace($Result.Sha256)) { $null } else { $Result.Sha256 -eq $ExpectedSha256 }
  $Result | Add-Member -NotePropertyName HashMatches -NotePropertyValue $HashMatches -Force
  $Result | Add-Member -NotePropertyName AcceptedByWinGet -NotePropertyValue ($Result.Success -and ($null -eq $HashMatches -or $HashMatches)) -Force
  $Result | Add-Member -NotePropertyName ServerAcceptedRequest -NotePropertyValue ($Result.ResponseAccepted -or $Result.Success) -Force
  $Result | Add-Member -NotePropertyName FileRetained -NotePropertyValue $KeepDownload -Force
  if (-not $KeepDownload -and (Test-Path -LiteralPath $Result.DestinationPath)) {
    Remove-Item -LiteralPath $Result.DestinationPath -Force -ErrorAction SilentlyContinue
  }
  return $Result
}

function Test-WinGetInstallerDownload {
  <#
  .SYNOPSIS
    Test whether WinGet's native installer download paths accept a URL
  .DESCRIPTION
    Default reproduces WinGet's Delivery Optimization first behavior and its
    nonfatal fallback to WinINet. Both tests each network stack independently.
    Download success and installer hash acceptance are reported separately.
  .PARAMETER Uri
    The installer URL to test
  .PARAMETER ExpectedSha256
    The manifest hash; required for exact Delivery Optimization ContentId behavior
  .PARAMETER Method
    Default, Both, DeliveryOptimization, or WinINet
  .PARAMETER KeepDownloads
    Retain successful probe files instead of deleting them
  .PARAMETER MaximumRetryDelaySeconds
    Maximum delay permitted before any single native transport retry
  .PARAMETER MaximumTotalRetryDelaySeconds
    Maximum cumulative delay permitted across each native transport's retries
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][uri]$Uri,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [ValidateSet('Default', 'Both', 'DeliveryOptimization', 'WinINet')][string]$Method = 'Default',
    [Collections.IDictionary]$Header,
    [string]$Proxy,
    [ValidateRange(1, 3600)][int]$NoProgressTimeoutSeconds = 60,
    [ValidateRange(0, 86400)][int]$MaximumDurationSeconds = 3600,
    [Alias('TimeoutSec')][ValidateRange(0, [int]::MaxValue)][int]$ConnectionTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$OperationTimeoutSeconds = 15,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryCount = 3,
    [ValidateRange(1, [int]::MaxValue)][int]$RetryIntervalSec = 3,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumRetryDelaySeconds = 30,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumTotalRetryDelaySeconds = 60,
    [string]$DestinationDirectory,
    [switch]$KeepDownloads,
    [switch]$ResponseOnly
  )

  process {
    $OwnsDirectory = [string]::IsNullOrWhiteSpace($DestinationDirectory)
    if ($OwnsDirectory) { $DestinationDirectory = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-WinGetDownload-$([guid]::NewGuid().ToString('N'))" }
    $null = New-Item -Path $DestinationDirectory -ItemType Directory -Force
    $Results = [Collections.Generic.List[object]]::new()
    $UserAgent = Get-WinGetDownloadUserAgent
    $FallbackOccurred = $false
    $EffectiveMethod = $null
    $DownloadControl = @{
      ConnectionTimeoutSeconds      = $ConnectionTimeoutSeconds
      OperationTimeoutSeconds       = $OperationTimeoutSeconds
      MaximumRetryCount             = $MaximumRetryCount
      RetryIntervalSec              = $RetryIntervalSec
      MaximumRetryDelaySeconds      = $MaximumRetryDelaySeconds
      MaximumTotalRetryDelaySeconds = $MaximumTotalRetryDelaySeconds
    }

    try {
      $InvokeDO = {
        param ($ProbeHeader, $ProbeNoProgressTimeoutSeconds, $ProbeMaximumDurationSeconds)
        $Path = Join-Path $DestinationDirectory 'DeliveryOptimization.download'
        $DOParams = @{
          Uri                      = $Uri
          DestinationPath          = $Path
          Header                   = $ProbeHeader
          NoProgressTimeoutSeconds = $ProbeNoProgressTimeoutSeconds
          MaximumDurationSeconds   = $ProbeMaximumDurationSeconds
          ResponseOnly             = $ResponseOnly
        }
        foreach ($Entry in $DownloadControl.GetEnumerator()) { $DOParams[$Entry.Key] = $Entry.Value }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) { $DOParams['ExpectedSha256'] = $ExpectedSha256 }
        $NativeResult = Invoke-WinGetDeliveryOptimizationDownload @DOParams
        $Result = Add-WinGetDownloadProbeEvidence -Result $NativeResult -ExpectedSha256 $ExpectedSha256 -KeepDownload $KeepDownloads.IsPresent
        $Results.Add($Result)
        return $Result
      }
      $InvokeWinINet = {
        param ($ProbeHeader)
        $Path = Join-Path $DestinationDirectory 'WinINet.download'
        $WinINetParams = @{
          Uri = $Uri; DestinationPath = $Path; Header = $ProbeHeader; Proxy = $Proxy; UserAgent = $UserAgent; ResponseOnly = $ResponseOnly
        }
        foreach ($Entry in $DownloadControl.GetEnumerator()) { $WinINetParams[$Entry.Key] = $Entry.Value }
        $NativeResult = Invoke-WinGetWinINetDownload @WinINetParams
        $Result = Add-WinGetDownloadProbeEvidence -Result $NativeResult -ExpectedSha256 $ExpectedSha256 -KeepDownload $KeepDownloads.IsPresent
        $Results.Add($Result)
        return $Result
      }

      switch ($Method) {
        'DeliveryOptimization' { $EffectiveMethod = 'DeliveryOptimization'; $null = & $InvokeDO $Header $NoProgressTimeoutSeconds $MaximumDurationSeconds }
        'WinINet' { $EffectiveMethod = 'WinINet'; $null = & $InvokeWinINet $Header }
        'Both' { $null = & $InvokeDO $Header $NoProgressTimeoutSeconds $MaximumDurationSeconds; $null = & $InvokeWinINet $Header }
        'Default' {
          if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
            $EffectiveMethod = 'WinINet'
            $null = & $InvokeWinINet $Header
          } else {
            $DOResult = & $InvokeDO $Header $NoProgressTimeoutSeconds $MaximumDurationSeconds
            if ($DOResult.AcceptedByWinGet -or ($ResponseOnly -and $DOResult.ServerAcceptedRequest)) {
              $EffectiveMethod = 'DeliveryOptimization'
            } elseif (-not $DOResult.IsFatalDeliveryOptimizationError) {
              $FallbackOccurred = $true
              $EffectiveMethod = 'WinINet'
              $null = & $InvokeWinINet $Header
            } else {
              $EffectiveMethod = 'DeliveryOptimization'
            }
          }
        }
      }

      $AcceptedResult = $Results | Where-Object AcceptedByWinGet | Select-Object -First 1
      $AcceptedRequest = $Results | Where-Object ServerAcceptedRequest | Select-Object -First 1
      $ExactDeliveryOptimizationMetadata = -not [string]::IsNullOrWhiteSpace($ExpectedSha256)
      $Recommendation = if ($AcceptedResult) {
        "WinGet accepted the download through $($AcceptedResult.Method)."
      } elseif ($ResponseOnly -and $AcceptedRequest) {
        "$($AcceptedRequest.Method) received an accepted HTTP response. Run without -ResponseOnly for definitive size and SHA256 validation."
      } elseif ($Results.Success -and -not $Results.AcceptedByWinGet) {
        'The network download succeeded, but the bytes do not match the expected installer SHA256.'
      } else {
        'WinGet-compatible download paths rejected or failed to retrieve the installer URL.'
      }

      [pscustomobject]@{
        Uri                               = $Uri.AbsoluteUri
        RequestedMethod                   = $Method
        EffectiveMethod                   = $EffectiveMethod
        FallbackOccurred                  = $FallbackOccurred
        ProxyForcedWinINet                = -not [string]::IsNullOrWhiteSpace($Proxy) -and $Method -eq 'Default'
        WinINetUserAgent                  = $UserAgent
        DeliveryOptimizationUserAgent     = 'Microsoft-Delivery-Optimization/10.0'
        ExpectedSha256                    = $ExpectedSha256
        ExactDeliveryOptimizationMetadata = $ExactDeliveryOptimizationMetadata
        ResponseOnly                      = $ResponseOnly.IsPresent
        ServerAcceptedRequest             = [bool]$AcceptedRequest
        WouldWinGetDownload               = [bool]$AcceptedResult
        Results                           = $Results.ToArray()
        Recommendation                    = $Recommendation
      }
    } finally {
      if ($OwnsDirectory -and -not $KeepDownloads) { Remove-Item -LiteralPath $DestinationDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
}

Export-ModuleMember -Function Get-WinGetDownloadUserAgent, Get-WinGetWinINetRedirectedUrl, Get-WinGetDeliveryOptimizationRedirectedUrl, Get-WinGetWinINetResponseHeader, Get-WinGetDeliveryOptimizationResponseHeader, Invoke-WinGetWinINetDownload, Invoke-WinGetDeliveryOptimizationDownload, Invoke-WinGetInstallerDownload, Test-WinGetInstallerDownload
