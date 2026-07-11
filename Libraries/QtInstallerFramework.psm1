# SPDX-License-Identifier: MIT
# This module only bridges to the independently licensed InstallerParsers CLI.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-QtInstallerFrameworkInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Qt Installer Framework installer through the separate GPL parser module
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'QtInstallerFramework.GetInfo' -Argument @{
      Path = (Get-Item -Path $Path -Force).FullName
    }
  }
}

function Expand-QtInstallerFramework {
  <#
  .SYNOPSIS
    Extract metadata and package payloads from a Qt Installer Framework installer through the separate GPL parser module
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  .PARAMETER Name
    The file name or wildcard pattern to extract
  .PARAMETER MaximumExpandedBytes
    The maximum total number of bytes written to the destination
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'The maximum total number of expanded bytes')]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = 17179869184
  )

  process {
    return Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'QtInstallerFramework.Expand' -Argument @{
      Path                 = (Get-Item -Path $Path -Force).FullName
      DestinationPath      = $DestinationPath
      Name                 = $Name
      MaximumExpandedBytes = $MaximumExpandedBytes
    }
  }
}

function Test-QtInstallerFrameworkCLI {
  <#
  .SYNOPSIS
    Test whether a Qt Installer Framework installer contains the modern command-line interface
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).InterfaceVariant -eq 'CLI'
  }
}

function Test-QtInstallerFrameworkSilentInstallation {
  <#
  .SYNOPSIS
    Test whether a Qt Installer Framework installer supports its command-line silent installation path
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportsSilentInstallation
  }
}

function Test-QtInstallerFrameworkRequiresInstallLocation {
  <#
  .SYNOPSIS
    Test whether Qt IFW silent installation requires an explicit --root path
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).RequiresExplicitInstallLocation -eq $true
  }
}

function Test-QtInstallerFrameworkSupportsExistingInstallationOverride {
  <#
  .SYNOPSIS
    Test whether Qt IFW can install over an existing IFW installation in the target directory
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportsExistingInstallationOverride
  }
}

function Read-UpgradeBehaviorFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the recommended WinGet upgrade behavior for a Qt IFW installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).RecommendedUpgradeBehavior
  }
}

function Read-ProductVersionFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the product version from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The Qt Installer Framework installer does not expose a Version value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the package name from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.PackageName)) { throw 'The Qt Installer Framework installer does not expose a Name value' }
    return $Info.PackageName
  }
}

function Read-PublisherFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the publisher from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Qt Installer Framework installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the ProductUUID/uninstall key from a Qt Installer Framework installer when statically embedded
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Qt Installer Framework installer does not expose a deterministic ProductUUID value' }
    return $Info.ProductCode
  }
}

function Read-ScopeFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the default Apps and Features scope from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).DefaultScope
  }
}

function Read-SupportedScopesFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the statically supported Apps and Features scopes from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportedScopes
  }
}

function Test-QtInstallerFrameworkDualScope {
  <#
  .SYNOPSIS
    Test whether a Qt Installer Framework installer exposes both user and machine ARP scope paths
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportsDualScope
  }
}

Export-ModuleMember -Function Get-QtInstallerFrameworkInfo, Expand-QtInstallerFramework, Test-QtInstallerFrameworkCLI, Test-QtInstallerFrameworkSilentInstallation, Test-QtInstallerFrameworkRequiresInstallLocation, Test-QtInstallerFrameworkSupportsExistingInstallationOverride, Read-UpgradeBehaviorFromQtInstallerFramework, Read-ProductVersionFromQtInstallerFramework, Read-ProductNameFromQtInstallerFramework, Read-PublisherFromQtInstallerFramework, Read-ProductCodeFromQtInstallerFramework, Read-ScopeFromQtInstallerFramework, Read-SupportedScopesFromQtInstallerFramework, Test-QtInstallerFrameworkDualScope
