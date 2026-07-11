# SPDX-License-Identifier: MIT
# Native WinGet installer download compatibility probes. These functions do not
# execute installers and delete downloaded probe files unless asked to keep them.

if (-not ([System.Management.Automation.PSTypeName]'Dumplings.WinGetDownload.WinInetDownloader').Type) {
  Add-Type -Path (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'WinGetDownloadProbe.cs')
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

  $VersionOutput = & winget --version 2>$null | Select-Object -First 1
  if ([string]::IsNullOrWhiteSpace($VersionOutput)) { throw 'The installed winget client version could not be determined.' }
  $ClientVersion = $VersionOutput.Trim().TrimStart('v')
  if ([string]::IsNullOrWhiteSpace($ClientVersion)) { throw 'The installed winget client version could not be determined.' }
  $Info = & winget --info 2>$null | Out-String
  $Package = [regex]::Match($Info, 'Microsoft\.DesktopAppInstaller\s+v(?<Version>\d+(?:\.\d+){3})')
  $PackageVersion = if ($Package.Success) { $Package.Groups['Version'].Value } else { "$ClientVersion.0" }
  return "winget-cli WindowsPackageManager/$ClientVersion DesktopAppInstaller/Microsoft.DesktopAppInstaller v$PackageVersion"
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
  #>
  [OutputType([Dumplings.WinGetDownload.DownloadResult])]
  param (
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Collections.IDictionary]$Header,
    [string]$Proxy,
    [string]$UserAgent = (Get-WinGetDownloadUserAgent),
    [switch]$ResponseOnly
  )

  $Headers = ConvertTo-WinGetDownloadHeaderDictionary -Header $Header
  return [Dumplings.WinGetDownload.WinInetDownloader]::Download($Uri.AbsoluteUri, $DestinationPath, $UserAgent, $Headers, $Proxy, $ResponseOnly.IsPresent)
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
    [switch]$ResponseOnly
  )

  $Headers = ConvertTo-WinGetDownloadHeaderDictionary -Header $Header
  return [Dumplings.WinGetDownload.DeliveryOptimizationDownloader]::Download(
    $Uri.AbsoluteUri,
    $DestinationPath,
    $DisplayName,
    $ExpectedSha256,
    $Headers,
    $NoProgressTimeoutSeconds,
    $MaximumDurationSeconds,
    $ResponseOnly.IsPresent)
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
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) { $DOParams['ExpectedSha256'] = $ExpectedSha256 }
        $NativeResult = Invoke-WinGetDeliveryOptimizationDownload @DOParams
        $Result = Add-WinGetDownloadProbeEvidence -Result $NativeResult -ExpectedSha256 $ExpectedSha256 -KeepDownload $KeepDownloads.IsPresent
        $Results.Add($Result)
        return $Result
      }
      $InvokeWinINet = {
        param ($ProbeHeader)
        $Path = Join-Path $DestinationDirectory 'WinINet.download'
        $NativeResult = Invoke-WinGetWinINetDownload -Uri $Uri -DestinationPath $Path -Header $ProbeHeader -Proxy $Proxy -UserAgent $UserAgent -ResponseOnly:$ResponseOnly
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

Export-ModuleMember -Function Get-WinGetDownloadUserAgent, Invoke-WinGetWinINetDownload, Invoke-WinGetDeliveryOptimizationDownload, Test-WinGetInstallerDownload
