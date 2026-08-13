# SPDX-License-Identifier: Apache-2.0
# This module only bridges to the independently licensed InstallerParsers CLI.
# Process boundary:
#
#   NSIS installer path -> InstallerBridge -> NSIS.GetInfo/Expand
#                         <- compiled-command, payload, and ARP evidence
#
# The GPL parser owns the aligned DEADBEEF/NullsoftInst header, compression,
# opcode normalization, and command simulation. This MIT bridge does not duplicate
# those internals. See Modules/InstallerParsers/Libraries/Installers/NSIS.psm1.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-NSISFormatInfo {
  <#
  .SYNOPSIS
    Identify the serialized NSIS edition and format routes through the GPL parser bridge.
  .PARAMETER Path
    Path to the NSIS installer.
  .OUTPUTS
    Edition, version range, character mode, loader-stub architecture, selected catalog
    profile, route IDs, candidate evidence, support status, and warnings.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path
  )

  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'NSIS.GetFormatInfo' -Argument @{
      Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    }
  }
}

function Get-NSISInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Nullsoft Scriptable Install System installer through the separate GPL parser module
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used when the installer selects architecture-specific ARP metadata
  .PARAMETER Scope
    The target installation scope used when the installer selects scope-specific ARP metadata
  .PARAMETER Environment
    Virtual target environment variables used by ReadEnvStr.
  .PARAMETER CommandLine
    Virtual installer command line.
  .PARAMETER FileSystem
    Explicit virtual target filesystem facts keyed by Windows path.
  .PARAMETER FileSystemComplete
    Treat unlisted target paths as absent rather than unknown.
  .PARAMETER AnsiCodePage
    Explicit source code page for ANSI NSIS strings.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve architecture-specific ARP metadata')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve scope-specific ARP metadata')]
    [ValidateSet('user', 'machine')]
    [string]$Scope,

    [hashtable]$Environment = @{},

    [AllowEmptyString()][string]$CommandLine = '',

    [hashtable]$FileSystem = @{},

    [switch]$FileSystemComplete,

    [ValidateRange(1, 65535)][int]$AnsiCodePage
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $Arguments = @{ Path = $InstallerPath }
    if (-not [string]::IsNullOrWhiteSpace($Architecture)) { $Arguments.Architecture = $Architecture }
    if (-not [string]::IsNullOrWhiteSpace($Scope)) { $Arguments.Scope = $Scope }
    if ($Environment.Count -gt 0) { $Arguments.EnvironmentJson = $Environment | ConvertTo-Json -Compress }
    if ($FileSystem.Count -gt 0) { $Arguments.FileSystemJson = $FileSystem | ConvertTo-Json -Compress -Depth 8 }
    if ($FileSystemComplete) { $Arguments.FileSystemComplete = $true }
    if ($PSBoundParameters.ContainsKey('CommandLine')) { $Arguments.CommandLine = $CommandLine }
    if ($AnsiCodePage -gt 0) { $Arguments.AnsiCodePage = $AnsiCodePage }
    $Info = Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'NSIS.GetInfo' -Argument $Arguments
    return $Info
  }
}

function Expand-NSISInstaller {
  <#
  .SYNOPSIS
    Extract selected files from an NSIS installer through the separate GPL parser module
  .PARAMETER Path
    The path to the NSIS installer.
  .PARAMETER DestinationPath
    The directory where matching files should be written. A temporary directory is used when omitted.
  .PARAMETER Name
    A payload path or wildcard pattern. The default selects all compiled File commands.
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes written by the GPL parser, including payload aliases.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple File commands resolve to the same path.
  .PARAMETER ExternalDataPath
    Optional legacy .nsisbin file, current setupN.bin files, or their directory.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The directory where matching files should be written')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The payload path or wildcard pattern to extract')]
    [ValidateNotNullOrEmpty()]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'The maximum total number of extracted bytes')]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = 1073741824,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [string[]]$ExternalDataPath
  )

  process {
    $Arguments = @{
      Path                 = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      Name                 = $Name
      CollisionAction      = $CollisionAction
      MaximumExpandedBytes = $MaximumExpandedBytes
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) {
      $Arguments.DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    }
    if ($ExternalDataPath) { $Arguments.ExternalDataPath = @($ExternalDataPath | ForEach-Object { Resolve-InstallerFileSystemPath -Path $_ }) }
    $Result = Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'NSIS.Expand' -Argument $Arguments
    return Convert-InstallerBridgePathsToFileInfo -Path $Result
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
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific registry writes.
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific registry writes.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(ValueFromPipeline, Mandatory)][string]$Path,
    [ValidateSet('x86', 'x64', 'arm64')][string]$Architecture,
    [ValidateSet('user', 'machine')][string]$Scope
  )
  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    (Get-NSISInfo @Arguments).Protocols
  }
}

function Read-FileExtensionsFromNSIS {
  <#
  .SYNOPSIS
    Read literal file extensions written by an NSIS installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific registry writes.
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific registry writes.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(ValueFromPipeline, Mandatory)][string]$Path,
    [ValidateSet('x86', 'x64', 'arm64')][string]$Architecture,
    [ValidateSet('user', 'machine')][string]$Scope
  )
  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    (Get-NSISInfo @Arguments).FileExtensions
  }
}

function Read-ProductVersionFromNSIS {
  <#
  .SYNOPSIS
    Read the product version from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
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
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
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
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
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
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
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

Export-ModuleMember -Function Get-NSISFormatInfo, Get-NSISInfo, Expand-NSISInstaller, Get-NSISInstallerSwitchInfo, Read-AdditionalInstallerSwitchesFromNSIS, Test-ElectronBuilder, Get-ElectronBuilderNSISInfo, ConvertFrom-ElectronBuilderUpdateFeed, ConvertFrom-ElectronBuilderLatestYaml, Read-ProtocolsFromNSIS, Read-FileExtensionsFromNSIS, Read-ProductVersionFromNSIS, Read-ProductNameFromNSIS, Read-PublisherFromNSIS, Read-ProductCodeFromNSIS
