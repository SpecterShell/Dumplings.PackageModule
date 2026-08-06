# SPDX-License-Identifier: Apache-2.0
# Public InstallShield orchestration over container, Advanced UI, and InstallScript evidence.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$InfrastructurePath = Join-Path $PSScriptRoot '..\Infrastructure'
foreach ($Name in 'Runtime', 'Binary', 'Archive', 'PE', 'InstallerEvidence', 'Cabinet') {
  Import-Module (Join-Path $InfrastructurePath "$Name.psm1") -Force -Global
}
Import-Module (Join-Path $PSScriptRoot 'MSI.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'InstallShieldInstallScript.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'InstallShieldContainer.psm1') -Force -Global
Import-Module (Join-Path $PSScriptRoot 'InstallShieldAdvancedUI.psm1') -Force -Global

function Expand-InstallShield {
  <#
  .SYNOPSIS
    Extract files from an InstallShield executable using the in-process parser.
  .PARAMETER Path
    The path to the InstallShield installer.
  .PARAMETER DestinationPath
    The destination directory, or the legacy sibling `_u` directory when omitted.
  .PARAMETER Name
    Optional wildcard selecting payload paths or file names.
  .PARAMETER CollisionAction
    Behavior when an output path already exists.
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes decoded from the InstallShield container.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 8GB
  )
  process {
    Expand-InstallShieldInstaller -Path $Path -DestinationPath $DestinationPath -Name $Name `
      -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
  }
}

function New-InstallShieldAnalysisContext {
  <#
  .SYNOPSIS
    Build the immutable extraction and classification context for one InstallShield analysis.
  .PARAMETER Path
    Resolved installer path. The source file is opened once for both probing and extraction.
  .PARAMETER DestinationPath
    Optional extraction destination. A sibling `_u` directory is used when omitted.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [string]$DestinationPath
  )

  $ContainerFormat = 'InstallShield Overlay'
  $PackageForTheWebCabinet = $null
  $Warnings = [Collections.Generic.List[string]]::new()
  $ExtractedPath = if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
    Join-Path (Split-Path -Path $Path -Parent) ((Split-Path -Path $Path -LeafBase) + '_u')
  } else {
    Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  }

  # The outer launcher's PE manifest is independent from MSI and prerequisite
  # metadata. Preserve it as direct UAC evidence instead of inferring elevation
  # from a machine-scope payload.
  $RequestedExecutionLevel = $null
  try {
    $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Path
  } catch {
    $Warnings.Add("The InstallShield launcher's requested execution level could not be read: $($_.Exception.Message)")
  }

  $SourceStream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $SourceStream
    if ($OverlayOffset -gt 0 -and $OverlayOffset -lt $SourceStream.Length) {
      $PackageForTheWebCabinet = Get-InstallShieldPackageForTheWebCabinet -Stream $SourceStream -OverlayOffset $OverlayOffset
      if ($PackageForTheWebCabinet) { $ContainerFormat = 'PackageForTheWeb Cabinet' }
    }
    $Extraction = Invoke-InstallShieldExtraction -Path $Path -SourceStream $SourceStream -DestinationPath $ExtractedPath -CollisionAction Rename
  } finally {
    $SourceStream.Dispose()
  }

  # Proprietary media may hide setup.inx inside data*.cab. Expand only bounded support
  # metadata, then enumerate the complete extraction tree exactly once.
  $CabinetSupport = Expand-InstallShieldCabinetSupport -ExtractedPath $ExtractedPath -CollisionAction Rename
  $Files = @(Get-ChildItem -LiteralPath $ExtractedPath -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
  $MsiFiles = @($Files | Where-Object Extension -EQ '.msi')
  $InxFiles = @($Files | Where-Object Extension -In @('.inx', '.ins'))
  $CabFiles = @($Files | Where-Object Extension -In @('.cab', '.hdr'))
  $SfxFiles = @($Files | Where-Object Name -Like '*_sfx.exe')
  $Prerequisites = [Collections.Generic.List[object]]::new()
  foreach ($PrerequisiteFile in @($Files | Where-Object Extension -EQ '.prq')) {
    try { $Prerequisites.Add((Get-InstallShieldPrerequisiteInfo -Path $PrerequisiteFile.FullName)) }
    catch { $Warnings.Add("The prerequisite definition '$($PrerequisiteFile.FullName)' could not be parsed: $($_.Exception.Message)") }
  }

  $AdvancedUiInfo = $null
  $AdvancedUiSetupXml = $Files | Where-Object Name -CEQ 'Setup.xml' | Select-Object -First 1
  if ($AdvancedUiSetupXml) {
    try {
      $AdvancedUiInfo = Get-InstallShieldAdvancedUiInfo -Path $AdvancedUiSetupXml.FullName -ExtractedPath $ExtractedPath
    } catch {
      # Setup.xml also occurs in unrelated payloads; warn only for an InstallShield bootstrap namespace.
      if ((Get-Content -LiteralPath $AdvancedUiSetupXml.FullName -TotalCount 2 -ErrorAction SilentlyContinue) -match 'installshield/\d{4}/bootstrap') {
        $Warnings.Add("The Advanced UI package catalog could not be parsed: $($_.Exception.Message)")
      }
    }
  }

  $MsiSelection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile $MsiFiles
  if (-not $MsiSelection.Configuration) {
    # InstallShield 11.x and other external-media launchers keep Setup.ini and
    # the MSI beside setup.exe. Resolve only the exact configured sibling path;
    # never widen this into a directory scan or wildcard selection.
    $ExternalMsiSelection = Get-InstallShieldExternalMediaSelection -InstallerPath $Path -ExtractedPath $ExtractedPath
    if ($ExternalMsiSelection) {
      $MsiSelection = $ExternalMsiSelection
      if ($MsiSelection.SelectedMsiResolvedPath) {
        $MsiFiles = @($MsiFiles) + @(Get-Item -LiteralPath $MsiSelection.SelectedMsiResolvedPath -Force)
      }
    }
  }
  $SelectedMsiInfo = $null
  if ($MsiSelection.SelectedMsiPath) {
    try {
      $SelectionContext = [pscustomobject]@{ ExtractedPath = $ExtractedPath; MsiPayloadSelection = $MsiSelection }
      $SelectedMsiFile = Resolve-InstallShieldMsiFile -Installer $SelectionContext -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false
      $SelectedMsiInfo = Get-MsiInstallerInfo -Path $SelectedMsiFile.FullName
    } catch {
      $Warnings.Add("The selected InstallShield MSI could not be classified: $($_.Exception.Message)")
    }
  }

  $Variant = if ($AdvancedUiInfo) {
    'Advanced UI'
  } elseif ($MsiFiles) {
    $SelectedMsiInfo.InstallShieldProjectType ? $SelectedMsiInfo.InstallShieldProjectType : 'Basic MSI or InstallScript MSI'
  } elseif ($InxFiles) {
    'InstallScript'
  } elseif ($CabFiles -or $SfxFiles) {
    'InstallShield payload without MSI'
  } else {
    'Unknown'
  }

  return [pscustomobject][ordered]@{
    SourcePath              = $Path
    ContainerFormat         = $ContainerFormat
    PackageForTheWebCabinet = $PackageForTheWebCabinet
    Extraction              = $Extraction
    ExtractedPath           = $ExtractedPath
    Files                   = [object[]]$Files
    MsiFiles                = [object[]]$MsiFiles
    InxFiles                = [object[]]$InxFiles
    CabFiles                = [object[]]$CabFiles
    SfxFiles                = [object[]]$SfxFiles
    CabinetSupport          = $CabinetSupport
    SetupConfiguration      = $MsiSelection.Configuration
    MsiPayloadSelection     = $MsiSelection
    SelectedMsiInfo         = $SelectedMsiInfo
    RequestedExecutionLevel = $RequestedExecutionLevel
    PrerequisiteDefinitions = [object[]]$Prerequisites
    AdvancedUiInfo          = $AdvancedUiInfo
    Variant                 = $Variant
    ClassificationWarnings  = $Warnings
  }
}

function Merge-InstallShieldAdvancedUiResult {
  <#
  .SYNOPSIS
    Apply Advanced UI suite-owned metadata to an InstallShield result.
  .PARAMETER Result
    Mutable parser result being composed for the outer installer.
  .PARAMETER AdvancedUiInfo
    Parsed suite catalog. Suite identity remains authoritative over nested parcels.
  #>
  param ([Parameter(Mandatory)][psobject]$Result, [Parameter(Mandatory)][psobject]$AdvancedUiInfo)

  foreach ($PropertyName in @(
      'ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope',
      'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString',
      'DisplayIcon', 'URLInfoAbout', 'HelpLink', 'WritesAppsAndFeaturesEntry',
      'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType', 'ExecutedPayloads'
    )) {
    $Result.$PropertyName = $AdvancedUiInfo.$PropertyName
  }
  $Result.Warnings = [string[]]@($Result.Warnings + $AdvancedUiInfo.Warnings)
  $Result.UnresolvedFields = [string[]]@($AdvancedUiInfo.UnresolvedFields)
  return $Result
}

function Merge-InstallShieldInstallScriptResult {
  <#
  .SYNOPSIS
    Apply InstallScript-owned evidence without overriding an embedded MSI identity.
  .PARAMETER Result
    Mutable outer InstallShield result.
  .PARAMETER InstallScriptInfo
    Focused compiled-script analysis produced from the same extraction context.
  .PARAMETER Supplemental
    Retain the script as nested action evidence without applying its identity or
    standalone silent-install conclusions to the outer MSI or suite.
  #>
  param (
    [Parameter(Mandatory)][psobject]$Result,
    [Parameter(Mandatory)][psobject]$InstallScriptInfo,
    [switch]$Supplemental
  )

  $Result.InstallScriptInfo = $InstallScriptInfo
  if (-not $Supplemental -and -not $Result.HasMsi) {
    $Result.SilentSupport = $InstallScriptInfo.SilentSupport
    $Result.ResponseFileRequirement = $InstallScriptInfo.ResponseFileRequirement
    $Result.SilentSwitches = [string[]]@($InstallScriptInfo.SilentSwitches)
    foreach ($PropertyName in @(
        'ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope',
        'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString',
        'DisplayIcon', 'URLInfoAbout', 'HelpLink', 'WritesAppsAndFeaturesEntry',
        'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType',
        'AppsAndFeaturesEntries', 'RegistryWrites', 'RegistryItems', 'Protocols',
        'MediaRegistrySets', 'MediaRegistryWrites', 'ConditionalMediaRegistryWrites',
        'CabinetFileGroups', 'CabinetComponents', 'MediaSetupTypes',
        'MediaShellFolders', 'MediaShortcuts', 'ConditionalMediaShortcuts',
        'ConditionalRegistryAssociationInfo', 'ConditionalProtocols', 'ConditionalFileExtensions',
        'FileExtensions', 'ProtocolAssociations', 'FileExtensionAssociations',
        'RegistryAssociationInfo', 'ExecutedPayloads', 'FileOperations', 'DllOperations', 'Shortcuts',
        'PropertyHandlers', 'StaticCalls', 'OpcodeCoverage', 'UnsupportedOpcodes'
      )) {
      $Result.$PropertyName = $InstallScriptInfo.$PropertyName
    }
  }
  $Result.UnresolvedFields = [string[]]@((@($Result.UnresolvedFields) + @($InstallScriptInfo.UnresolvedFields)) | Select-Object -Unique)
  $Result.Warnings = [string[]]@($Result.Warnings + @($InstallScriptInfo.Warnings))
  return $Result
}

function Get-InstallShieldInfo {
  <#
  .SYNOPSIS
    Extract and classify an InstallShield installer statically
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Context = New-InstallShieldAnalysisContext -Path $InstallerPath -DestinationPath $DestinationPath
    $ContainerFormat = $Context.ContainerFormat
    $PackageForTheWebCabinet = $Context.PackageForTheWebCabinet
    $ExtractedPath = $Context.ExtractedPath
    $InstallShieldCabinetSupport = $Context.CabinetSupport
    $ExtractedFiles = [object[]]$Context.Files
    $MsiFiles = [object[]]$Context.MsiFiles
    $InxFiles = [object[]]$Context.InxFiles
    $CabFiles = [object[]]$Context.CabFiles
    $SfxFiles = [object[]]$Context.SfxFiles
    $ClassificationWarnings = $Context.ClassificationWarnings
    $PrerequisiteDefinitions = [object[]]$Context.PrerequisiteDefinitions
    $AdvancedUiInfo = $Context.AdvancedUiInfo
    $MsiPayloadSelection = $Context.MsiPayloadSelection
    $SelectedMsiInfo = $Context.SelectedMsiInfo
    $Variant = $Context.Variant
    $PayloadSelectionWarnings = if ($AdvancedUiInfo) { @() } else { @($MsiPayloadSelection.Warnings) }
    $PackageForTheWebInfo = if ($PackageForTheWebCabinet) {
      $Configuration = $MsiPayloadSelection.Configuration
      $RootSetupFiles = [object[]]@($ExtractedFiles | Where-Object {
          $_.Name -ieq 'Setup.exe' -and [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) -notmatch '[\\/]'
        })
      $NestedSetupFile = if ($RootSetupFiles.Count -eq 1) {
        $RootSetupFiles[0]
      } else {
        $AllSetupFiles = [object[]]@($ExtractedFiles | Where-Object Name -IEQ 'Setup.exe')
        $AllSetupFiles.Count -eq 1 ? $AllSetupFiles[0] : $null
      }
      $NestedPayloadPath = if ($MsiPayloadSelection.SelectedMsiPath) {
        $MsiPayloadSelection.SelectedMsiPath
      } elseif ($InxFiles.Count -eq 1) {
        [IO.Path]::GetRelativePath($ExtractedPath, $InxFiles[0].FullName)
      } else { $null }
      $NestedPayloadKind = if ($MsiPayloadSelection.SelectedMsiPath) { 'MSI' } elseif ($InxFiles.Count -eq 1) { 'InstallScript program' } else { $null }
      $ConfiguredCommandLine = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'CmdLine') : $null
      $LaunchChain = [Collections.Generic.List[object]]::new()
      if ($NestedSetupFile) {
        $LaunchChain.Add([pscustomobject][ordered]@{
            Stage     = 'PackageForTheWeb'
            Target    = [IO.Path]::GetRelativePath($ExtractedPath, $NestedSetupFile.FullName)
            Arguments = $null
            Evidence  = 'Unique root Setup.exe in the validated PackageForTheWeb cabinet'
          })
      }
      if ($NestedPayloadPath) {
        $LaunchChain.Add([pscustomobject][ordered]@{
            Stage     = 'InstallShield setup launcher'
            Target    = $NestedPayloadPath
            Arguments = $ConfiguredCommandLine
            Evidence  = $MsiPayloadSelection.SelectedMsiPath ? 'Setup.ini package Location' : 'Sole extracted InstallScript program'
          })
      }
      [pscustomobject][ordered]@{
        Cabinet                 = $PackageForTheWebCabinet
        SetupIniPath            = $MsiPayloadSelection.SetupIniPath
        Product                 = $Configuration ? ((Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'Product') ?? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'AppName')) : $null
        ProductGuid             = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'ProductGUID') : $null
        ConfiguredCommandLine   = $ConfiguredCommandLine
        PackageName             = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'PackageName') : $null
        NestedSetupPath         = $NestedSetupFile ? [IO.Path]::GetRelativePath($ExtractedPath, $NestedSetupFile.FullName) : $null
        NestedSetupResolvedPath = $NestedSetupFile ? $NestedSetupFile.FullName : $null
        NestedPayloadPath       = $NestedPayloadPath
        NestedPayloadKind       = $NestedPayloadKind
        LaunchChain             = [object[]]$LaunchChain
        ExtractedFiles          = [string[]]@($ExtractedFiles | ForEach-Object { [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) })
      }
    } else { $null }
    # Setup.ini is authoritative for setup-level prerequisites. MSI table rows
    # retain feature prerequisite evidence, so merge both sources while
    # suppressing only exact duplicate names.
    $SetupPrerequisiteReferences = $MsiPayloadSelection.Configuration ? [object[]]@(
      Get-InstallShieldSetupPrerequisiteReference -Configuration $MsiPayloadSelection.Configuration
    ) : [object[]]@()
    $MsiPrerequisiteReferences = $SelectedMsiInfo ? [object[]]@($SelectedMsiInfo.InstallShieldPrerequisiteReferences) : [object[]]@()
    $PrerequisiteReferenceList = [Collections.Generic.List[object]]::new()
    $SeenPrerequisiteReferences = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($PrerequisiteReference in @($SetupPrerequisiteReferences) + @($MsiPrerequisiteReferences)) {
      $ReferenceName = [string]$PrerequisiteReference.Name
      if ([string]::IsNullOrWhiteSpace($ReferenceName) -or -not $SeenPrerequisiteReferences.Add($ReferenceName)) { continue }
      $PrerequisiteReferenceList.Add($PrerequisiteReference)
    }
    $PrerequisiteReferences = [object[]]$PrerequisiteReferenceList
    $PrerequisiteEvidence = [object[]]@(Join-InstallShieldPrerequisiteEvidence -Reference $PrerequisiteReferences -Definition ([object[]]$PrerequisiteDefinitions))
    foreach ($PrerequisiteWarning in @($PrerequisiteEvidence | Where-Object { $_.Reference -and $_.Warning } | ForEach-Object Warning)) {
      $ClassificationWarnings.Add($PrerequisiteWarning)
    }
    $ElevationRequirementEvidence = Get-InstallShieldElevationInfo `
      -RequestedExecutionLevel $Context.RequestedExecutionLevel `
      -PrerequisiteEvidence $PrerequisiteEvidence
    foreach ($ElevationWarning in @($ElevationRequirementEvidence.Warnings)) {
      $ClassificationWarnings.Add($ElevationWarning)
    }

    # The InstallShield launcher classification does not prove which nested
    # package owns ARP. Get-InstallShieldMsiInfo supplies identity only after
    # Setup.ini has selected an MSI payload.
    $Result = [pscustomobject][ordered]@{
      Path                               = $InstallerPath
      InstallerType                      = 'InstallShield'
      ProductCode                        = $null
      UpgradeCode                        = $null
      DisplayName                        = $null
      DisplayVersion                     = $null
      Publisher                          = $null
      Scope                              = $null
      ElevationRequirement               = $ElevationRequirementEvidence.ElevationRequirement
      RequestedExecutionLevel            = $Context.RequestedExecutionLevel
      ElevationRequirementEvidence       = $ElevationRequirementEvidence
      DefaultInstallLocation             = $null
      UninstallString                    = $null
      QuietUninstallString               = $null
      DisplayIcon                        = $null
      URLInfoAbout                       = $null
      HelpLink                           = $null
      WritesAppsAndFeaturesEntry         = $null
      AppsAndFeaturesProductCode         = $null
      AppsAndFeaturesInstallerType       = $null
      Warnings                           = [string[]]@($PayloadSelectionWarnings + $InstallShieldCabinetSupport.Warnings + $ClassificationWarnings + @($SelectedMsiInfo.InstallShieldScriptInfo.Warnings) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
      UnresolvedFields                   = [string[]]@()
      AppsAndFeaturesEntries             = [object[]]@()
      RegistryWrites                     = [object[]]@()
      RegistryItems                      = [object[]]@()
      MediaRegistrySets                  = [object[]]@()
      MediaRegistryWrites                = [object[]]@()
      ConditionalMediaRegistryWrites     = [object[]]@()
      CabinetFileGroups                  = [object[]]$InstallShieldCabinetSupport.CabinetFileGroups
      CabinetComponents                  = [object[]]$InstallShieldCabinetSupport.CabinetComponents
      MediaSetupTypes                    = [object[]]$InstallShieldCabinetSupport.MediaSetupTypes
      MediaShellFolders                  = [object[]]@()
      MediaShortcuts                     = [object[]]@()
      ConditionalMediaShortcuts          = [object[]]@()
      ConditionalRegistryAssociationInfo = $null
      ConditionalProtocols               = [string[]]@()
      ConditionalFileExtensions          = [string[]]@()
      Protocols                          = [string[]]@()
      FileExtensions                     = [string[]]@()
      ProtocolAssociations               = [object[]]@()
      FileExtensionAssociations          = [object[]]@()
      RegistryAssociationInfo            = $null
      ExecutedPayloads                   = [object[]]@()
      FileOperations                     = [object[]]@()
      DllOperations                      = [object[]]@()
      PropertyHandlers                   = [object[]]@()
      Shortcuts                          = [object[]]@()
      StaticCalls                        = [object[]]@()
      OpcodeCoverage                     = [object[]]@()
      UnsupportedOpcodes                 = [string[]]@()
      ExtractedPath                      = $ExtractedPath
      ExtractedFiles                     = [string[]]@($ExtractedFiles | Select-Object -ExpandProperty FullName)
      ContainerFormat                    = $ContainerFormat
      PackageForTheWebCabinet            = $PackageForTheWebCabinet
      PackageForTheWebInfo               = $PackageForTheWebInfo
      InstallShieldCabinetSupport        = $InstallShieldCabinetSupport
      Variant                            = $Variant
      HasMsi                             = [bool]$MsiFiles
      HasInstallScript                   = [bool]($InxFiles -or $SelectedMsiInfo.HasInstallScript)
      MsiFiles                           = @($MsiFiles | Select-Object -ExpandProperty FullName)
      SetupIniPath                       = $MsiPayloadSelection.SetupIniPath
      SetupConfiguration                 = $MsiPayloadSelection.Configuration
      MsiPayloadSelection                = $MsiPayloadSelection
      SelectedMsiPath                    = $MsiPayloadSelection.SelectedMsiPath
      SelectedMsiInfo                    = $SelectedMsiInfo
      InstallShieldProjectType           = $SelectedMsiInfo.InstallShieldProjectType
      InstallShieldProjectTypeEvidence   = $SelectedMsiInfo.InstallShieldProjectTypeEvidence
      InstallShieldLauncherRequirement   = $SelectedMsiInfo.InstallShieldLauncherRequirement
      PrerequisiteDefinitions            = [object[]]$PrerequisiteDefinitions
      PrerequisiteReferences             = $PrerequisiteReferences
      PrerequisiteEvidence               = $PrerequisiteEvidence
      InxFiles                           = @($InxFiles | Select-Object -ExpandProperty FullName)
      CabFiles                           = @($CabFiles | Select-Object -ExpandProperty FullName)
      SfxFiles                           = @($SfxFiles | Select-Object -ExpandProperty FullName)
      InstallScriptInfo                  = $SelectedMsiInfo.InstallShieldScriptInfo
      SilentSupport                      = $null
      ResponseFileRequirement            = $null
      SilentSwitches                     = [string[]]@()
      AdvancedUiInfo                     = $AdvancedUiInfo
      SuitePackages                      = $AdvancedUiInfo ? [object[]]@($AdvancedUiInfo.Packages) : [object[]]@()
    }

    if ($AdvancedUiInfo) {
      # Advanced UI owns its ARP identity through SuiteId. Nested MSI metadata
      # describes parcel installation only and must not replace the outer key.
      $Result = Merge-InstallShieldAdvancedUiResult -Result $Result -AdvancedUiInfo $AdvancedUiInfo
    }

    # Advanced UI CallInstallScript actions name the exact compiled functions
    # dispatched by suite events. Analyze only those roots and keep suite ARP
    # identity and command-line behavior authoritative.
    if ($AdvancedUiInfo -and $AdvancedUiInfo.InstallScriptEntryPoints -and $InxFiles -and (Get-Command Get-InstallShieldInstallScriptInfo -ErrorAction SilentlyContinue)) {
      try {
        $InstallScriptInfo = Get-InstallShieldInstallScriptInfo -Installer $Result `
          -EntryPoint $AdvancedUiInfo.InstallScriptEntryPoints -AnalysisScope EmbeddedAction
        $Result = Merge-InstallShieldInstallScriptResult -Result $Result -InstallScriptInfo $InstallScriptInfo -Supplemental
      } catch {
        $Result.Warnings = [string[]]@($Result.Warnings + "Advanced UI InstallScript action analysis failed: $($_.Exception.Message)")
      }
      # Reuse this extraction and analyze setup.inx/setup.iss once for a
      # standalone InstallScript package, where the script owns ARP and silent behavior.
    } elseif (-not $AdvancedUiInfo -and $InxFiles -and (Get-Command Get-InstallShieldInstallScriptInfo -ErrorAction SilentlyContinue)) {
      try {
        $InstallScriptInfo = Get-InstallShieldInstallScriptInfo -Installer $Result
        $Result = Merge-InstallShieldInstallScriptResult -Result $Result -InstallScriptInfo $InstallScriptInfo
      } catch {
        $Result.Warnings = [string[]]@($Result.Warnings + "InstallScript analysis failed: $($_.Exception.Message)")
      }
    }
    return $Result
  }
}

Export-ModuleMember -Function Get-InstallShieldInfo, Get-InstallShieldAdvancedUiInfo, Get-InstallShieldAdvancedUiPackageEligibility, Get-InstallShieldAdvancedUiNestedPackageInfo, Resolve-InstallShieldSuiteCondition, Get-InstallShieldPrerequisiteInfo, Expand-InstallShield, Expand-InstallShieldInstaller, Expand-InstallShieldCabinet, Get-InstallShieldMsiInfo, Read-ProductVersionFromInstallShield, Read-ProductCodeFromInstallShield, Read-UpgradeCodeFromInstallShield
