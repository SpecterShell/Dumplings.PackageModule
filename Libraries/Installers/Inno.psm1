# SPDX-License-Identifier: Apache-2.0
# This module only bridges to the independently licensed InstallerParsers CLI.
# Process boundary:
#
#   Inno installer path -> InstallerBridge -> Inno.GetInfo/Expand
#                         <- structured setup tables and ARP evidence
#
# The GPL parser owns the #11111 offset table, chunk/CRC/LZMA decoding, and
# version-specific record layouts. This MIT bridge neither copies those internals
# nor opens the installer. See Modules/InstallerParsers/Libraries/Installers/Inno.psm1.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-InnoInfo {
  <#
  .SYNOPSIS
    Get static metadata from an Inno Setup installer through the separate GPL parser module
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER IncludePascalScriptAnalysis
    Include detailed compiled Pascal Script evidence without reparsing the installer.
  .PARAMETER IncludeDisassembly
    Include bounded textual IFPS disassembly. This implies Pascal Script analysis.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from optional disassembly.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,
    [switch]$IncludePascalScriptAnalysis,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = 4194304
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Info = Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'Inno.GetInfo' -Argument @{
      Path                         = $InstallerPath
      IncludePascalScriptAnalysis  = [bool]$IncludePascalScriptAnalysis
      IncludeDisassembly           = [bool]$IncludeDisassembly
      MaximumDisassemblyCharacters = $MaximumDisassemblyCharacters
    }
    return $Info
  }
}

function Get-InnoFormatInfo {
  <#
  .SYNOPSIS
    Identify an Inno edition and its catalogued parser routes through the GPL parser process.
  .PARAMETER Path
    Path to the Inno Setup installer.
  .OUTPUTS
    Structured edition, character-mode, layout-route, and support evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'Inno.GetFormatInfo' -Argument @{ Path = $InstallerPath }
  }
}

function Get-InnoPascalScriptInfo {
  <#
  .SYNOPSIS
    Analyze compiled Inno Pascal Script through the process-isolated GPL parser.
  .PARAMETER Path
    Path to the Inno Setup installer.
  .PARAMETER IncludeDisassembly
    Include bounded textual IFPS disassembly in the result.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from the optional disassembly.
  .OUTPUTS
    Structural IFPS version, function, external-call, instruction, and optional disassembly evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = 4194304
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'Inno.GetPascalScriptInfo' -Argument @{
      Path                         = $InstallerPath
      IncludeDisassembly           = [bool]$IncludeDisassembly
      MaximumDisassemblyCharacters = $MaximumDisassemblyCharacters
    }
  }
}

function Read-ProductVersionFromInno {
  <#
  .SYNOPSIS
    Read the product version from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if (-not [string]::IsNullOrWhiteSpace($Info.AppVersion)) { return $Info.AppVersion }

    $Match = [regex]::Match($Info.AppVerName, '(\d+(?:[.-]\d+)+)')
    if ($Match.Success) { return $Match.Groups[1].Value }

    throw 'The Inno Setup installer does not expose a deterministic version value'
  }
}

function Read-ProductNameFromInno {
  <#
  .SYNOPSIS
    Read the product name from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The Inno Setup installer does not expose a product name' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromInno {
  <#
  .SYNOPSIS
    Read the publisher from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Inno Setup installer does not expose a publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromInno {
  <#
  .SYNOPSIS
    Read the built-in Apps & Features ProductCode from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Inno Setup installer does not expose a built-in Apps & Features ProductCode' }
    return $Info.ProductCode
  }
}

function Test-InnoDualScope {
  <#
  .SYNOPSIS
    Test whether an Inno Setup installer supports both user and machine scope via command-line switches
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).SupportsDualScope
  }
}

function Read-SupportedScopesFromInno {
  <#
  .SYNOPSIS
    Read the install scopes supported by an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).SupportedScopes
  }
}

function Read-UnsupportedArchitecturesFromInno {
  <#
  .SYNOPSIS
    Read Windows architectures that an Inno Setup installer does not support
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).UnsupportedArchitectures
  }
}

function Test-InnoUnsupportedArchitecture {
  <#
  .SYNOPSIS
    Test whether an Inno Setup installer does not support a Windows architecture
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER Architecture
    The Windows architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-InnoInfo -Path $Path).UnsupportedArchitectures -contains $Architecture
  }
}

function Test-InnoAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Test whether an Inno Setup installer writes its own Apps & Features registry entry
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).WritesAppsAndFeaturesEntry
  }
}

function Expand-InnoInstaller {
  <#
  .SYNOPSIS
    Extract selected files from an Inno Setup installer through the separate GPL parser module
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER DestinationPath
    The directory where matching files should be written
  .PARAMETER Name
    Optional source, destination, or base file wildcard to extract. All files are extracted when omitted.
  .PARAMETER Language
    An optional Inno Setup language name used to disambiguate language-specific payloads
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple records resolve to the same path.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate bytes written, including aliases that share one payload location.
  .PARAMETER DiskSourcePath
    Optional directories or explicit setup-*.bin files used for external multi-disk media. The setup executable directory is searched automatically.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The directory where matching files should be written')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The source, destination, or base file wildcard to extract')]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'An optional Inno Setup language name used to disambiguate language-specific payloads')]
    [string]$Language,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = 17179869184,

    [Parameter(HelpMessage = 'Directories or explicit files containing external Inno Setup disk slices')]
    [string[]]$DiskSourcePath
  )

  process {
    $Arguments = @{
      Path                 = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
      Name                 = $Name
      Language             = $Language
      CollisionAction      = $CollisionAction
      MaximumExpandedBytes = $MaximumExpandedBytes
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) {
      $Arguments.DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    }
    if ($DiskSourcePath) {
      $Arguments.DiskSourcePath = @($DiskSourcePath | ForEach-Object { Resolve-InstallerFileSystemPath -Path $_ })
    }
    $Result = Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'Inno.Expand' -Argument $Arguments

    return Convert-InstallerBridgePathsToFileInfo -Path $Result
  }
}

Export-ModuleMember -Function Get-InnoFormatInfo, Get-InnoInfo, Get-InnoPascalScriptInfo, Read-ProductVersionFromInno, Read-ProductNameFromInno, Read-PublisherFromInno, Read-ProductCodeFromInno, Test-InnoDualScope, Read-SupportedScopesFromInno, Read-UnsupportedArchitecturesFromInno, Test-InnoUnsupportedArchitecture, Test-InnoAppsAndFeaturesEntry, Expand-InnoInstaller
