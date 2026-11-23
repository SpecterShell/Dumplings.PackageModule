# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Provision the browser driver a WebDriver session needs.

.DESCRIPTION
  WebDriver.psm1 never downloads a driver: it resolves msedgedriver.exe or geckodriver.exe
  from an environment variable and then from PATH. This module supplies the missing step so
  the driver can be installed with a command instead of a copied script.

  The Edge driver mirrors the browser's four-part version, so the installed browser decides
  the build to install. Firefox's geckodriver has an independent version line, so the newest
  published release is used instead.
#>

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$ErrorActionPreference = 'Stop'


function Get-DumplingsVersionTriplet {
  <#
  .SYNOPSIS
    Render the build component of a version for browser and driver comparison
  .DESCRIPTION
    See https://docs.microsoft.com/microsoft-edge/webdriver/#download-microsoft-edge-webdriver.
  .PARAMETER Version
    Version whose first three components should be rendered.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)][version]$Version
  )

  process {
    $Version.ToString(3)
  }
}

function Install-DumplingsWebDriver {
  <#
  .SYNOPSIS
    Install the driver that matches the installed browser
  .DESCRIPTION
    Downloads the vendor package for this architecture into a cache outside the repository,
    extracts it, and returns the driver executable. The caller can point EDGEWEBDRIVER or
    GECKOWEBDRIVER at the returned directory.
  .PARAMETER Browser
    Browser family whose driver should be installed.
  .PARAMETER CacheRoot
    Directory that receives the extracted driver. Defaults to a folder under the local application data.
  .PARAMETER Force
    Reinstall even when a matching driver is already cached.
  .EXAMPLE
    Install-DumplingsWebDriver -Browser Edge
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateSet('Edge', 'Firefox')][string]$Browser,
    [string]$CacheRoot,
    [switch]$Force
  )

  if (-not $CacheRoot) {
    $CacheRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Dumplings' 'WebDriver'
  }

  $DriverVersion = $null
  if ($Browser -eq 'Edge') {
    $ExecutablePath = (Get-Command -Name 'msedge.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).Source

    switch ($true) {
      (-not $ExecutablePath) {
        foreach ($Hive in 'HKLM:', 'HKCU:') {
          $AppPathKey = "$Hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
          $Candidate = (Get-ItemProperty -Path $AppPathKey -ErrorAction SilentlyContinue).'(default)'
          if ($Candidate -and (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
            $ExecutablePath = $Candidate
            break
          }
        }
      }

      (-not $ExecutablePath) {
        $ExecutablePath = & where.exe msedge.exe 2>$null | Select-Object -First 1
      }

      (-not $ExecutablePath) {
        throw "$Browser is not installed; install it before provisioning its driver."
      }
    }

    $BrowserVersion = [version](Get-Item -LiteralPath $ExecutablePath).VersionInfo.ProductVersion
    $Published = $null
    try {
      $Response = Invoke-WebRequest -Uri "https://msedgedriver.microsoft.com/LATEST_RELEASE_$($BrowserVersion.Major)" -TimeoutSec 30
      $Parsed = $null
      if (
        # The vendor answers UTF-16LE with a byte-order mark, and some endpoints answer plain text.
        [version]::TryParse(
          $(
            if ($Response.Content -is [byte[]]) {
              if ($Response.Content.Length -ge 2 -and $Response.Content[0] -eq 0xFF -and $Response.Content[1] -eq 0xFE) {
                [Text.Encoding]::Unicode.GetString($Response.Content, 2, $Response.Content.Length - 2)
              } else {
                [Text.Encoding]::UTF8.GetString($Response.Content)
              }
            } else {
              [string]$Response.Content
            }
          ).Trim(), [ref]$Parsed
        )
      ) { $Published = $Parsed }
    } catch {
      # A missing document means the vendor publishes no driver for this major version.
      $Published = $null
    }
    # The document names one build, which is only usable with a browser of the same major version.
    if ($Published -and $Published.Major -eq $BrowserVersion.Major) {
      $DriverVersion = $Published
    }
    if (-not $DriverVersion) {
      throw "No Microsoft.EdgeDriver build exists for Edge version $($BrowserVersion.Major). Download the driver manually from https://docs.microsoft.com/microsoft-edge/webdriver/#download-microsoft-edge-webdriver and check https://github.com/microsoft/winget-pkgs/tree/master/manifests/m/Microsoft/EdgeDriver for pending manifests."
    }
    if ((Get-DumplingsVersionTriplet -Version $DriverVersion) -ne (Get-DumplingsVersionTriplet -Version $BrowserVersion)) {
      Write-Warning "Edge $(Get-DumplingsVersionTriplet -Version $BrowserVersion) has no published driver. Using $DriverVersion, the nearest build in version $($BrowserVersion.Major)."
    }
    $Architecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
      'Arm64' { 'arm64' }
      'X86' { 'win32' }
      default { 'win64' }
    }
    $PackageUri = "https://msedgedriver.microsoft.com/$DriverVersion/edgedriver_$Architecture.zip"
    $ExecutableName = 'msedgedriver.exe'
  } else {
    $Release = Invoke-RestMethod -Uri 'https://api.github.com/repos/mozilla/geckodriver/releases/latest' -TimeoutSec 30 -Headers @{ 'User-Agent' = 'Dumplings' }
    $DriverVersion = [version]($Release.tag_name -replace '^v', '')
    $Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64' ? 'aarch64' : 'win64'
    $Asset = $Release.assets | Where-Object { $_.name -like "*-$Architecture.zip" } | Select-Object -First 1
    if (-not $Asset) { throw "geckodriver $DriverVersion does not publish a $Architecture package." }
    $PackageUri = $Asset.browser_download_url
    $ExecutableName = 'geckodriver.exe'
  }

  $TargetDirectory = Join-Path $CacheRoot "$Browser-$DriverVersion"
  $ExecutablePath = Join-Path $TargetDirectory $ExecutableName
  if (-not $Force -and (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
    return [pscustomobject]@{ Browser = $Browser; Version = $DriverVersion; Directory = $TargetDirectory; ExecutablePath = $ExecutablePath; Installed = $false }
  }

  $null = New-Item -Path $TargetDirectory -ItemType Directory -Force
  $PackagePath = Join-Path ([IO.Path]::GetTempPath()) "$Browser-$DriverVersion-$([guid]::NewGuid().ToString('N')).zip"
  try {
    Invoke-WebRequest -Uri $PackageUri -OutFile $PackagePath -TimeoutSec 300
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $TargetDirectory -Force
  } finally {
    Remove-Item -LiteralPath $PackagePath -Force -ErrorAction SilentlyContinue
  }

  if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
    throw "The $Browser driver package did not contain $ExecutableName."
  }

  [pscustomobject]@{ Browser = $Browser; Version = $DriverVersion; Directory = $TargetDirectory; ExecutablePath = $ExecutablePath; Installed = $true }
}

Export-ModuleMember -Function Get-DumplingsVersionTriplet, Install-DumplingsWebDriver
