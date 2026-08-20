# SPDX-License-Identifier: Apache-2.0
# This module only bridges to the independently licensed InstallerParsers CLI.
#
# Process boundary (the GPL-2.0 byte parser remains in InstallerParsers):
#
#   Advanced Installer PE path
#      -> InstallerBridge -> AdvancedInstaller.GetInfo/Expand
#      <- catalog-selected payload paths, configuration, and MSI evidence
#      -> this Apache-2.0 module matches the configured architecture/name to an MSI
#
# See Modules/InstallerParsers/Libraries/Installers/AdvancedInstaller.psm1 and the focused
# installer reference for the ADVINSTSFX footer, 20/24-byte catalogs, and external-resource table.

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

  return Resolve-UniqueInstallerFile -Item $Item -Pattern $Pattern -Description 'Advanced Installer MSI'
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

  # Selection evidence is produced by the GPL parser from the SFX catalog and
  # configuration. A downloaded MainAppURL has no equivalent embedded MSI.
  $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
  $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
  if ($Selection -and $Selection.SourceKind -eq 'Download') {
    throw "Advanced Installer obtains its main payload from MainAppURL '$($Selection.MainAppUrl)'; no embedded MSI represents the runtime selection"
  }

  # The caller pattern narrows extracted files but cannot replace a configured
  # architecture path when one is available.
  $Candidates = @($Item | Where-Object {
      $_.Name -like $Pattern -or $_.FullName -like $Pattern -or ([System.IO.Path]::GetRelativePath($ExtractionPath, $_.FullName)) -like $Pattern
    })
  if (-not $Candidates) { throw "No Advanced Installer MSI matched the pattern: $Pattern" }

  # Reproduce the SFX branch for the requested host architecture. All-platform
  # packages remain ambiguous until the caller supplies that architecture.
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

  # Resolve the configured path relative to the extraction root and require one
  # exact case-insensitive match; never fall through to a wildcard on mismatch.
  if (-not [string]::IsNullOrWhiteSpace($SelectedRelativePath)) {
    $Selected = @($Candidates | Where-Object {
        [System.IO.Path]::GetRelativePath($ExtractionPath, $_.FullName).Equals($SelectedRelativePath, [System.StringComparison]::OrdinalIgnoreCase)
      })
    if ($Selected.Count -eq 1) { return $Selected[0] }
    if ($Selected.Count -gt 1) { throw "Multiple extracted MSI files have the bootstrapper-selected path: $SelectedRelativePath" }
    throw "The bootstrapper-selected MSI path was not extracted: $SelectedRelativePath"
  }

  # Only packages without usable SFX selection metadata reach the reviewed
  # deterministic matcher.
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
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $Info = Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'AdvancedInstaller.GetInfo' -Argument @{ Path = $InstallerPath }
    return $Info
  }
}

function Get-AdvancedInstallerFormatInfo {
  <#
  .SYNOPSIS
    Identify the Advanced Installer bootstrapper format profile through the separate GPL parser module.
  .PARAMETER Path
    The path to the candidate installer executable.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the candidate installer')]
    [string]$Path
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    return Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'AdvancedInstaller.GetFormatInfo' -Argument @{ Path = $InstallerPath }
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
  .PARAMETER Name
    Optional wildcard selecting payload paths or file names. All payloads are extracted when omitted.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple payloads resolve to the same path.
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The destination directory for the extracted payloads')]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt'
  )

  process {
    $InstallerPath = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf }
      'Installer' { Resolve-InstallerFileSystemPath -Path $Installer.Path -PathType Leaf }
      default { throw 'Invalid parameter set.' }
    }

    $Arguments = @{
      Path            = $InstallerPath
      Name            = $Name
      CollisionAction = $CollisionAction
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) {
      $Arguments.DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    }
    return Invoke-InstallerBridgeCommand -ModuleName 'InstallerParsers' -Action 'AdvancedInstaller.Expand' -Argument $Arguments
  }
}

function Get-AdvancedInstallerMsiTableRow {
  <#
  .SYNOPSIS
    Read every row from one known Advanced Installer-owned MSI table.
  .PARAMETER Database
    Open MSI database. The caller owns and closes the database.
  .PARAMETER TableName
    Advanced Installer table whose schema is projected dynamically so historical column additions remain compatible.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [Parameter(Mandatory)]
    [ValidateSet('AI_PreRequisite', 'AI_AppSearchEx')]
    [string]$TableName
  )

  $Table = @($Database.Tables | Where-Object Name -CEQ $TableName | Select-Object -First 1)
  if ($Table.Count -eq 0) { return }

  $Columns = @($Table[0].Columns)
  $View = $Database.OpenView("SELECT * FROM ``$TableName``")
  try {
    $View.Execute()
    while ($Record = $View.Fetch()) {
      try {
        $Row = [ordered]@{}
        for ($Index = 0; $Index -lt $Columns.Count; $Index++) {
          $FieldIndex = $Index + 1
          $Row[$Columns[$Index].Name] = if ($Record.IsNull($FieldIndex)) {
            $null
          } elseif ($Columns[$Index].Type -eq [string]) {
            $Record.GetString($FieldIndex)
          } else {
            $Record.GetInteger($FieldIndex)
          }
        }
        [pscustomobject]$Row
      } finally {
        $Record.Dispose()
      }
    }
  } finally {
    $View.Close()
  }
}

function Get-AdvancedInstallerMsiPrerequisiteInfo {
  <#
  .SYNOPSIS
    Project Advanced Installer prerequisite execution and detection metadata from its MSI tables.
  .PARAMETER Database
    Open selected main-package MSI database. The caller owns and closes the database.
  .PARAMETER Payload
    Prerequisite payload entries recovered from the outer ADVINSTSFX catalog.
  .PARAMETER Property
    MSI properties used to evaluate AI_PreRequisite.MissingCondition. The
    caller supplies target-state evidence; the parser never reads host state.
  .PARAMETER KnownPresentProperty
    MSI property names known to exist when their exact value is unavailable.
  .PARAMETER KnownAbsentProperty
    MSI property names known to be absent.
  .PARAMETER UnspecifiedPropertyState
    State assigned to properties for which the caller supplied no evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [Microsoft.Deployment.WindowsInstaller.Database]$Database,

    [AllowEmptyCollection()]
    [object[]]$Payload = @(),

    [Collections.IDictionary]$Property = @{},

    [string[]]$KnownPresentProperty = @(),

    [string[]]$KnownAbsentProperty = @(),

    [ValidateSet('Unknown', 'Absent')]
    [string]$UnspecifiedPropertyState = 'Unknown'
  )

  $RawPrerequisites = @(Get-AdvancedInstallerMsiTableRow -Database $Database -TableName 'AI_PreRequisite')
  $RawSearches = @(Get-AdvancedInstallerMsiTableRow -Database $Database -TableName 'AI_AppSearchEx')
  $Warnings = [Collections.Generic.List[string]]::new()

  [object[]]$Prerequisites = @(foreach ($Prerequisite in $RawPrerequisites) {
      $MissingCondition = [string]$Prerequisite.MissingCondition
      # AI_PreRequisite stores a real MSI conditional expression. Parse it once
      # and associate AI_AppSearchEx rows through exact property symbols instead
      # of a regex, which previously confused prefixes and quoted literals.
      $ConditionAnalysis = Resolve-MsiConditionExpression -Condition $MissingCondition -Property $Property -KnownPresentProperty $KnownPresentProperty -KnownAbsentProperty $KnownAbsentProperty -UnspecifiedSymbolState $UnspecifiedPropertyState
      $ReferencedProperties = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($Symbol in @($ConditionAnalysis.ReferencedSymbols)) {
        if ($Symbol.Kind -eq 'Property' -and -not [string]::IsNullOrWhiteSpace([string]$Symbol.Name)) {
          $null = $ReferencedProperties.Add([string]$Symbol.Name)
        }
      }
      $Searches = @($RawSearches | Where-Object {
          -not [string]::IsNullOrWhiteSpace([string]$_.Property) -and
          $ReferencedProperties.Contains([string]$_.Property)
        })
      if (-not $ConditionAnalysis.IsValid) {
        $Warnings.Add("Advanced Installer prerequisite '$($Prerequisite.DisplayName)' contains an invalid MSI missing condition at position $($ConditionAnalysis.ErrorPosition): $($ConditionAnalysis.ErrorMessage)")
      }
      $PayloadMatch = @($Payload | Where-Object Name -IEQ ([string]$Prerequisite.TargetName) | Select-Object -First 1)
      $Location = [int]$Prerequisite.Location
      $LocationType = switch ($Location) {
        0 { 'EmbeddedFile' }
        1 { 'DownloadUrl' }
        2 { 'OpenSite' }
        default { 'Unknown' }
      }
      $Options = [string]$Prerequisite.Options

      if ($Location -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$Prerequisite.TargetName) -and $PayloadMatch.Count -eq 0) {
        $Warnings.Add("Advanced Installer prerequisite '$($Prerequisite.DisplayName)' names embedded payload '$($Prerequisite.TargetName)', but the outer catalog does not contain that payload.")
      }

      [pscustomobject][ordered]@{
        Key                      = [string]$Prerequisite.PrereqKey
        DisplayName              = [string]$Prerequisite.DisplayName
        Location                 = $LocationType
        Source                   = [string]$Prerequisite.SetupFileUrl
        TargetName               = [string]$Prerequisite.TargetName
        ExpectedSize             = $Prerequisite.ExactSize -gt 0 ? [long]$Prerequisite.ExactSize : $null
        HashAlgorithm            = [string]::IsNullOrWhiteSpace([string]$Prerequisite.MD5) ? $null : 'MD5'
        Hash                     = [string]::IsNullOrWhiteSpace([string]$Prerequisite.MD5) ? $null : ([string]$Prerequisite.MD5).ToUpperInvariant()
        CommandLine              = [string]$Prerequisite.ComLine
        BasicUiCommandLine       = [string]$Prerequisite.BasicUiComLine
        SilentCommandLine        = [string]$Prerequisite.NoUiComLine
        MissingCondition         = $MissingCondition
        MissingConditionState    = $ConditionAnalysis.State
        MissingConditionAnalysis = $ConditionAnalysis
        ForceInstall             = $Options.Contains('m', [StringComparison]::Ordinal)
        CompressPayload          = $Options.Contains('z', [StringComparison]::Ordinal)
        Options                  = $Options
        Sequence                 = [int]$Prerequisite.Sequence
        Feature                  = [string]$Prerequisite.Feature_
        Languages                = [string]$Prerequisite.Languages
        ReturnValueProperty      = [string]$Prerequisite.RetValPropName
        Searches                 = [object[]]$Searches
        Payload                  = $PayloadMatch.Count -eq 0 ? $null : $PayloadMatch[0]
      }
    })

  [pscustomobject][ordered]@{
    HasPrerequisites = $Prerequisites.Count -gt 0
    Prerequisites    = [object[]]@($Prerequisites)
    Searches         = [object[]]$RawSearches
    Diagnostics      = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'AdvancedInstaller' -Kind Incomplete -Areas Metadata)
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
  .PARAMETER PrerequisiteProperty
    MSI properties used to evaluate Advanced Installer prerequisite missing conditions.
  .PARAMETER KnownPresentPrerequisiteProperty
    Prerequisite condition properties known to exist without a known value.
  .PARAMETER KnownAbsentPrerequisiteProperty
    Prerequisite condition properties known to be absent.
  .PARAMETER UnspecifiedPrerequisitePropertyState
    State assigned to prerequisite properties without caller-supplied evidence.
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
    [string]$Architecture,

    [Collections.IDictionary]$PrerequisiteProperty = @{},

    [string[]]$KnownPresentPrerequisiteProperty = @(),

    [string[]]$KnownAbsentPrerequisiteProperty = @(),

    [ValidateSet('Unknown', 'Absent')]
    [string]$UnspecifiedPrerequisitePropertyState = 'Unknown'
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
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath -CollisionAction Rename | Out-Null
      $MsiFiles = @(Get-ChildItem -Path $ExpandedPath -Filter '*.msi' -Recurse -File | Sort-Object -Property FullName)
      $MsiFile = Resolve-AdvancedInstallerMsiFile -Installer $Installer -Item $MsiFiles -ExtractionPath $ExpandedPath -Pattern $Name -Architecture $Architecture -NameWasSpecified $NameWasSpecified
      # Keep the selected MSI open once while generic MSI evidence and Advanced Installer-owned
      # prerequisite tables are projected. This avoids reparsing the database and keeps both views consistent.
      $Database = [Microsoft.Deployment.WindowsInstaller.Package.InstallPackage]::new($MsiFile.FullName, 'ReadOnly')
      try {
        $MsiInfo = Get-MsiInstallerInfo -Database $Database
        $PrerequisitePayloadProperty = $Installer.PSObject.Properties['PrerequisitePayloads']
        $PrerequisitePayloads = $null -eq $PrerequisitePayloadProperty ? [object[]]@() : [object[]]$PrerequisitePayloadProperty.Value
        $PrerequisiteInfo = Get-AdvancedInstallerMsiPrerequisiteInfo -Database $Database -Payload $PrerequisitePayloads -Property $PrerequisiteProperty -KnownPresentProperty $KnownPresentPrerequisiteProperty -KnownAbsentProperty $KnownAbsentPrerequisiteProperty -UnspecifiedPropertyState $UnspecifiedPrerequisitePropertyState
      } finally {
        $Database.Close()
      }

      # MSI metadata validates the already selected payload; it is not used as the selector.
      if ($Architecture -and $MsiInfo.PackageArchitecture -cne $Architecture) {
        throw "Advanced Installer selected '$($MsiFile.Name)' for '$Architecture', but the MSI package architecture is '$($MsiInfo.PackageArchitecture)'"
      }

      $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
      $SelectionMethod = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.SelectionMethod
      $ArchitectureSelectionMode = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.ArchitectureSelectionMode

      return [pscustomobject][ordered]@{
        Path                          = $MsiFile.FullName
        InstallerType                 = $MsiInfo.InstallerType
        ProductCode                   = $MsiInfo.ProductCode
        UpgradeCode                   = $MsiInfo.UpgradeCode
        DisplayName                   = $MsiInfo.DisplayName
        DisplayVersion                = $MsiInfo.DisplayVersion
        Publisher                     = $MsiInfo.Publisher
        Scope                         = $MsiInfo.Scope
        DefaultInstallLocation        = $MsiInfo.DefaultInstallLocation
        WritesAppsAndFeaturesEntry    = $MsiInfo.WritesAppsAndFeaturesEntry
        AppsAndFeaturesProductCode    = $MsiInfo.AppsAndFeaturesProductCode
        AppsAndFeaturesInstallerType  = $MsiInfo.AppsAndFeaturesInstallerType
        Diagnostics                   = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]@($MsiInfo.Diagnostics + $PrerequisiteInfo.Diagnostics)) -Source 'AdvancedInstaller' -Kind Incomplete -Areas Metadata)
        UnresolvedFields              = [string[]]@($MsiInfo.UnresolvedFields)
        Name                          = $MsiFile.Name
        PackageArchitecture           = $MsiInfo.PackageArchitecture
        Template                      = $MsiInfo.Template
        InstallerBuilder              = $MsiInfo.InstallerBuilder
        InstallerBuilderVersion       = $MsiInfo.InstallerBuilderVersion
        InstallerBuilderVersionSource = $MsiInfo.InstallerBuilderVersionSource
        InstallLocationProperty       = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch         = $MsiInfo.InstallLocationSwitch
        Protocols                     = $MsiInfo.Protocols
        FileExtensions                = $MsiInfo.FileExtensions
        RegistryAssociationInfo       = $MsiInfo.RegistryAssociationInfo
        HasPrerequisites              = [bool]$PrerequisiteInfo.HasPrerequisites
        Prerequisites                 = [object[]]$PrerequisiteInfo.Prerequisites
        PrerequisiteSearches          = [object[]]$PrerequisiteInfo.Searches
        PrerequisitePayloads          = [object[]]$PrerequisitePayloads
        SelectionMethod               = $SelectionMethod
        ArchitectureSelectionMode     = $ArchitectureSelectionMode
        SelectedMsiPath               = [System.IO.Path]::GetRelativePath($ExpandedPath, $MsiFile.FullName)
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
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).DisplayVersion
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

Export-ModuleMember -Function Get-AdvancedInstallerFormatInfo, Get-AdvancedInstallerInfo, Expand-AdvancedInstaller, Get-AdvancedInstallerMsiInfo, Read-ProductVersionFromAdvancedInstaller, Read-ProductCodeFromAdvancedInstaller, Read-UpgradeCodeFromAdvancedInstaller
