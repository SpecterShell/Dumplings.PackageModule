# SPDX-License-Identifier: Apache-2.0
# This module only bridges to the independently licensed InstallerParsers CLI.
# Process boundary:
#
#   NSIS installer path -> InstallerBridge -> NSIS.GetInfo/Expand
#                         <- compiled-command, payload, and ARP evidence
#
# The GPL parser owns the aligned DEADBEEF/NullsoftInst header, compression,
# opcode normalization, and command simulation. This MIT bridge does not duplicate
# those internals. See Modules/InstallerParsers/Libraries/NSIS.psm1.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-NSISInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Nullsoft Scriptable Install System installer through the separate GPL parser module
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $Info = Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'NSIS.GetInfo' -Argument @{ Path = $InstallerPath }
    return $Info
  }
}

function Get-ElectronBuilderNSISInfo {
  <#
  .SYNOPSIS
    Get static electron-builder traits from a Nullsoft installer through the separate GPL parser module
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'NSIS.GetElectronBuilderInfo' -Argument @{
      Path = (Get-Item -Path $Path -Force).FullName
    }
  }
}

function Test-ElectronBuilder {
  <#
  .SYNOPSIS
    Test whether a Nullsoft installer was built by electron-builder through the separate GPL parser module
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'NSIS.TestElectronBuilder' -Argument @{
      Path = (Get-Item -Path $Path -Force).FullName
    }
  }
}

function Get-NSISInstallerSwitchInfo {
  <#
  .SYNOPSIS
    Extract command-line switch evidence from a Nullsoft installer through the separate GPL parser module
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'NSIS.GetInstallerSwitchInfo' -Argument @{
      Path = (Get-Item -Path $Path -Force).FullName
    }
  }
}

function ConvertFrom-ElectronBuilderUpdateFeed {
  <#
  .SYNOPSIS
    Convert electron-builder latest.yml content into update feed metadata
  .PARAMETER Content
    The already-fetched electron-builder latest.yml feed string
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The already-fetched electron-builder latest.yml feed string')]
    [string]$Content
  )

  process {
    if (-not (Get-Command -Name 'ConvertFrom-Yaml' -ErrorAction 'SilentlyContinue')) {
      throw 'ConvertFrom-ElectronBuilderUpdateFeed requires ConvertFrom-Yaml to parse the provided feed content'
    }

    # Only parse the provided string. Some update endpoints need custom request
    # headers or query parameters, so fetching remains the caller's responsibility.
    $Feed = $Content | ConvertFrom-Yaml
    if ($null -eq $Feed) { throw 'The electron-builder update feed is empty or invalid' }

    $Files = @($Feed.files | ForEach-Object -Process {
        [pscustomobject]@{
          Url          = $_.url
          Sha512       = $_.sha512
          Size         = $_.size
          BlockMapSize = $_.blockMapSize
        }
      })

    [pscustomobject]@{
      Version           = $Feed.version
      Path              = $Feed.path
      Sha512            = $Feed.sha512
      Files             = $Files
      ReleaseDate       = $Feed.releaseDate
      StagingPercentage = $Feed.stagingPercentage
    }
  }
}

function ConvertFrom-ElectronBuilderLatestYaml {
  <#
  .SYNOPSIS
    Convert electron-builder latest.yml content into update feed metadata
  .PARAMETER Content
    The already-fetched electron-builder latest.yml feed string
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'The already-fetched electron-builder latest.yml feed string')]
    [string]$Content
  )

  process {
    ConvertFrom-ElectronBuilderUpdateFeed -Content $Content
  }
}

function Read-ProtocolsFromNSIS {
  <#
  .SYNOPSIS
    Read literal URL protocol names written by an NSIS installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-NSISInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromNSIS {
  <#
  .SYNOPSIS
    Read literal file extensions written by an NSIS installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-NSISInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromNSIS {
  <#
  .SYNOPSIS
    Read the product version from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The NSIS installer does not expose a DisplayVersion value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromNSIS {
  <#
  .SYNOPSIS
    Read the product name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The NSIS installer does not expose a DisplayName value' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromNSIS {
  <#
  .SYNOPSIS
    Read the publisher from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The NSIS installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromNSIS {
  <#
  .SYNOPSIS
    Read the uninstall registry key name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    $Info = Get-NSISInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The NSIS installer does not expose an uninstall registry key' }
    return $Info.ProductCode
  }
}

function Read-AdditionalInstallerSwitchesFromNSIS {
  <#
  .SYNOPSIS
    Read non-default command-line switch candidates from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path
  )

  process {
    (Get-NSISInstallerSwitchInfo -Path $Path).AdditionalSwitches
  }
}

Export-ModuleMember -Function Get-NSISInfo, Get-NSISInstallerSwitchInfo, Read-AdditionalInstallerSwitchesFromNSIS, Test-ElectronBuilder, Get-ElectronBuilderNSISInfo, ConvertFrom-ElectronBuilderUpdateFeed, ConvertFrom-ElectronBuilderLatestYaml, Read-ProtocolsFromNSIS, Read-FileExtensionsFromNSIS, Read-ProductVersionFromNSIS, Read-ProductNameFromNSIS, Read-PublisherFromNSIS, Read-ProductCodeFromNSIS
