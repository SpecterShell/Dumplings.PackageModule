# SPDX-License-Identifier: MIT
# This module only bridges to the independently licensed InstallerParsers CLI.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Get-SetupFactoryInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Setup Factory 7-9 installer
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'SetupFactory.GetInfo' -Argument @{
      Path = (Get-Item -LiteralPath $Path -Force).FullName
    }
  }
}

function Expand-SetupFactoryInstaller {
  <#
  .SYNOPSIS
    Expand a Setup Factory 7-9 installer through the separate GPL parser
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'SetupFactory.Expand' -Argument @{
      Path                 = (Get-Item -LiteralPath $Path -Force).FullName
      DestinationPath      = $DestinationPath
      Name                 = $Name
      MaximumExpandedBytes = $MaximumExpandedBytes
    }
  }
}

function Test-SetupFactory {
  <#
  .SYNOPSIS
    Test whether a file is a supported Setup Factory installer
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      $null = Get-SetupFactoryInfo -Path $Path
      return $true
    } catch {
      return $false
    }
  }
}

function Read-ProtocolsFromSetupFactory {
  <#
  .SYNOPSIS
    Read literal URL protocol names from Setup Factory registry actions
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Protocols }
}
function Read-FileExtensionsFromSetupFactory {
  <#
  .SYNOPSIS
    Read literal file extensions from Setup Factory registry actions
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).FileExtensions }
}
function Read-ProductVersionFromSetupFactory {
  <#
  .SYNOPSIS
    Read the product version from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromSetupFactory {
  <#
  .SYNOPSIS
    Read the product name from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayName }
}
function Read-PublisherFromSetupFactory {
  <#
  .SYNOPSIS
    Read the publisher from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the ARP ProductCode from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).ProductCode }
}
function Read-ScopeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the installation scope from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-SetupFactoryInfo, Expand-SetupFactoryInstaller, Test-SetupFactory, Read-ProtocolsFromSetupFactory, Read-FileExtensionsFromSetupFactory, Read-ProductVersionFromSetupFactory, Read-ProductNameFromSetupFactory, Read-PublisherFromSetupFactory, Read-ProductCodeFromSetupFactory, Read-ScopeFromSetupFactory
