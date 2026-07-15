# SPDX-License-Identifier: MIT
# This module only bridges to the independently licensed InstallerParsers CLI.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Resolve-AdvancedInstallerMatch {
  <#
  .SYNOPSIS
    Resolve a deterministic Advanced Installer payload match from extracted MSI files
  .PARAMETER Item
    The candidate extracted MSI files
  .PARAMETER Pattern
    The exact file name or wildcard pattern to match
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate extracted MSI files')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The exact file name or wildcard pattern to match')]
    [string]$Pattern
  )

  if (-not $Item) { throw 'No MSI files were extracted from the Advanced Installer payload' }

  $Match = @($Item.Where({ $_.Name -like $Pattern -or $_.FullName -like $Pattern }))
  if (-not $Match) { throw "No Advanced Installer MSI matched the pattern: $Pattern" }

  $ExactMatch = @($Match.Where({ $_.Name -ieq $Pattern -or $_.FullName -ieq $Pattern }))
  if ($ExactMatch.Count -eq 1) { return $ExactMatch[0] }
  if ($Match.Count -eq 1) { return $Match[0] }

  throw "Multiple MSI files matched the Advanced Installer pattern: $Pattern"
}

function Resolve-AdvancedInstallerMsiFile {
  <#
  .SYNOPSIS
    Resolve the MSI path that the Advanced Installer bootstrapper would launch
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Item
    The extracted MSI candidates
  .PARAMETER ExtractionPath
    The extraction root used to calculate payload-relative paths
  .PARAMETER Pattern
    The optional MSI file name or wildcard constraint
  .PARAMETER Architecture
    The target host architecture whose bootstrapper path should be reproduced
  .PARAMETER NameWasSpecified
    Whether the caller explicitly supplied the pattern
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(Mandatory, HelpMessage = 'The extracted MSI candidates')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The extraction root used to calculate payload-relative paths')]
    [string]$ExtractionPath,

    [Parameter(Mandatory, HelpMessage = 'The optional MSI file name or wildcard constraint')]
    [string]$Pattern,

    [string]$Architecture,

    [bool]$NameWasSpecified
  )

  $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
  $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
  if ($Selection -and $Selection.SourceKind -eq 'Download') {
    throw "Advanced Installer obtains its main payload from MainAppURL '$($Selection.MainAppUrl)'; no embedded MSI represents the runtime selection"
  }

  $Candidates = @($Item | Where-Object {
      $_.Name -like $Pattern -or $_.FullName -like $Pattern -or ([System.IO.Path]::GetRelativePath($ExtractionPath, $_.FullName)) -like $Pattern
    })
  if (-not $Candidates) { throw "No Advanced Installer MSI matched the pattern: $Pattern" }

  $SelectedRelativePath = if ($Selection -and $Architecture) {
    $ArchitecturePropertyName = "$($Architecture.Substring(0, 1).ToUpperInvariant())$($Architecture.Substring(1))MsiPath"
    $ArchitecturePathProperty = $Selection.PSObject.Properties[$ArchitecturePropertyName]
    if ($null -eq $ArchitecturePathProperty -or [string]::IsNullOrWhiteSpace([string]$ArchitecturePathProperty.Value)) {
      throw "The Advanced Installer payload metadata does not define an MSI path for '$Architecture'"
    }
    [string]$ArchitecturePathProperty.Value
  } elseif ($Selection -and -not $Selection.AllPlatforms) {
    [string]$Selection.BaseMsiPath
  } elseif ($Selection -and $NameWasSpecified -and $Candidates.Count -eq 1) {
    return $Candidates[0]
  } elseif ($Selection -and $Selection.AllPlatforms) {
    throw 'This Advanced Installer bootstrapper selects different MSI paths by host architecture; specify -Architecture'
  } else {
    $null
  }

  if (-not [string]::IsNullOrWhiteSpace($SelectedRelativePath)) {
    $Selected = @($Candidates | Where-Object {
        [System.IO.Path]::GetRelativePath($ExtractionPath, $_.FullName).Equals($SelectedRelativePath, [System.StringComparison]::OrdinalIgnoreCase)
      })
    if ($Selected.Count -eq 1) { return $Selected[0] }
    if ($Selected.Count -gt 1) { throw "Multiple extracted MSI files have the bootstrapper-selected path: $SelectedRelativePath" }
    throw "The bootstrapper-selected MSI path was not extracted: $SelectedRelativePath"
  }

  return Resolve-AdvancedInstallerMatch -Item $Candidates -Pattern $Pattern
}

function Get-AdvancedInstallerInfo {
  <#
  .SYNOPSIS
    Get metadata from an Advanced Installer executable through the separate GPL parser module
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'AdvancedInstaller.GetInfo' -Argument @{
      Path = (Get-Item -Path $Path -Force).FullName
    }
  }
}

function Expand-AdvancedInstaller {
  <#
  .SYNOPSIS
    Extract the embedded payloads from an Advanced Installer executable through the separate GPL parser module
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER DestinationPath
    The destination directory for the extracted payloads
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The destination directory for the extracted payloads')]
    [string]$DestinationPath
  )

  process {
    $InstallerPath = switch ($PSCmdlet.ParameterSetName) {
      'Path' { (Get-Item -Path $Path -Force).FullName }
      'Installer' { (Get-Item -Path $Installer.Path -Force).FullName }
      default { throw 'Invalid parameter set.' }
    }

    return Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'AdvancedInstaller.Expand' -Argument @{
      Path            = $InstallerPath
      DestinationPath = $DestinationPath
    }
  }
}

function Get-AdvancedInstallerMsiInfo {
  <#
  .SYNOPSIS
    Read MSI metadata from a statically extracted Advanced Installer payload
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    $NameWasSpecified = $PSBoundParameters.ContainsKey('Name')
    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path $Path }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    $ExpandedPath = New-TempFolder

    try {
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath | Out-Null
      $MsiFiles = @(Get-ChildItem -Path $ExpandedPath -Filter '*.msi' -Recurse -File | Sort-Object -Property FullName)
      $MsiFile = Resolve-AdvancedInstallerMsiFile -Installer $Installer -Item $MsiFiles -ExtractionPath $ExpandedPath -Pattern $Name -Architecture $Architecture -NameWasSpecified $NameWasSpecified
      $MsiInfo = Get-MsiInstallerInfo -Path $MsiFile.FullName

      # MSI metadata validates the already selected payload; it is not used as the selector.
      if ($Architecture -and $MsiInfo.PackageArchitecture -cne $Architecture) {
        throw "Advanced Installer selected '$($MsiFile.Name)' for '$Architecture', but the MSI package architecture is '$($MsiInfo.PackageArchitecture)'"
      }

      $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
      $SelectionMethod = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.SelectionMethod
      $ArchitectureSelectionMode = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.ArchitectureSelectionMode

      return [pscustomobject]@{
        Name                         = $MsiFile.Name
        Path                         = $MsiFile.FullName
        PackageArchitecture          = $MsiInfo.PackageArchitecture
        Template                     = $MsiInfo.Template
        ProductName                  = $MsiInfo.ProductName
        ProductVersion               = $MsiInfo.ProductVersion
        Publisher                    = $MsiInfo.Publisher
        ProductCode                  = $MsiInfo.ProductCode
        UpgradeCode                  = $MsiInfo.UpgradeCode
        InstallerBuilder             = $MsiInfo.InstallerBuilder
        InstallLocationProperty      = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch        = $MsiInfo.InstallLocationSwitch
        AppsAndFeaturesInstallerType = $MsiInfo.AppsAndFeaturesInstallerType
        AppsAndFeaturesProductCode   = $MsiInfo.AppsAndFeaturesProductCode
        Protocols                    = $MsiInfo.Protocols
        FileExtensions               = $MsiInfo.FileExtensions
        RegistryAssociationInfo      = $MsiInfo.RegistryAssociationInfo
        SelectionMethod              = $SelectionMethod
        ArchitectureSelectionMode    = $ArchitectureSelectionMode
        SelectedMsiPath              = [System.IO.Path]::GetRelativePath($ExpandedPath, $MsiFile.FullName)
      }
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction 'Continue' -ProgressAction 'SilentlyContinue'
    }
  }
}

function Read-ProductVersionFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductVersion property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductVersion
  }
}

function Read-ProductCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductCode
  }
}

function Read-UpgradeCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the UpgradeCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).UpgradeCode
  }
}

Export-ModuleMember -Function Get-AdvancedInstallerInfo, Expand-AdvancedInstaller, Get-AdvancedInstallerMsiInfo, Read-ProductVersionFromAdvancedInstaller, Read-ProductCodeFromAdvancedInstaller, Read-UpgradeCodeFromAdvancedInstaller
