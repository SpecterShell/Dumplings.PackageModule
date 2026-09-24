# SPDX-License-Identifier: Apache-2.0
# Static DeployMaster parser derived from controlled DeployMaster 7.7 builds,
# validated legacy packages, and the documented installer command-line behavior.
# Reference: https://www.deploymaster.com/manual.html
# Version history: https://www.deploymaster.com/history.html
#
# Binary structure consumed here (absolute offsets and little-endian integers):
#
#   PE image (DeployMaster 6.0 and later)
#   +-- [0x80] package locator
#   |   +-- PackageOffset:u32 -> overlay
#   |   +-- IntegrityLength:u32 and CRC32:u32
#   |   `-- ExpectedFileSize:u64 and Reserved:u32
#   +-- optional zero padding to an eight-byte boundary
#   +-- optional Authenticode certificate table outside ExpectedFileSize
#   `-- overlay at PackageOffset
#       +-- raw-LZMA properties[5]
#       +-- catalog-selected 66-, 70-, or 74-byte control header
#       +-- architecture-specific compressed runtime core(s)
#       +-- optional UTF-16 expiration message selected by header date fields
#       +-- language and identity data blocks
#       +-- current package settings and portable-folder block
#       +-- metadata-resident readme, license, and support-DLL records
#       +-- component block and CRLF file-name block
#       +-- parallel file catalog: offsets, sizes, dates, attributes, CRC32
#       +-- install-tree, registry, and file-association blocks
#       +-- prerequisite, completion, uninstall, and update records
#       `-- file payload ranges at absolute catalog offsets
#
#   DataBlock := Size:i32
#     Size == 0  -> empty
#     Size < 0   -> -Size stored bytes
#     Size > 0   -> CompressedSize:i32 + raw-LZMA bytes yielding Size bytes
#
#   Classic DeployMaster 2.x overlay
#   +-- BZip2-compressed installer runtime
#   +-- FF FF FF FF end marker
#   +-- Length:u32 + zlib language record
#   +-- Length:u32 + zlib form-feed identity record
#   +-- legacy installation metadata records
#   +-- Length:u32 + zlib CRLF file-name catalog
#   +-- zlib behavior records, including registry and file associations
#   `-- contiguous Length:u32 + zlib payload records through logical EOF
#
# The CRC covers only the declared integrity range. Undocumented header fields
# remain observed evidence; scope/architecture fields are decoded only for
# controlled layouts whose size and record boundaries validate.

# Apply default function parameters

# DeployMaster Public layer. Internal modules are imported locally; public commands stay in the facade.
Import-Module (Join-Path $PSScriptRoot 'DeployMasterModern.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'DeployMasterClassic.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function ConvertTo-DeployMasterRegistryWrite {
  <#
  .SYNOPSIS
    Build the explicit built-in DeployMaster uninstall-entry evidence
  .PARAMETER PackageData
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER Value
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Root
    Concrete registry hive or conditional root used by the projected write.
  .PARAMETER Key
    Registry key relative to the selected root.
  .PARAMETER Type
    Registry value type written by the DeployMaster runtime.
  .PARAMETER Evidence
    Source description attached to the registry operation.
  .PARAMETER Condition
    Optional scope condition for a dual-scope registration variant.
  #>
  param (
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][string]$Name,
    [AllowNull()][object]$Value,
    [string]$Root = $PackageData.Identity.RegistryRoot,
    [string]$Key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($PackageData.Identity.DisplayName)",
    [ValidateSet('REG_SZ', 'REG_DWORD', 'REG_BINARY')][string]$Type = 'REG_SZ',
    [string]$Evidence = 'DeployMaster structured identity and built-in uninstaller configuration',
    [string]$Condition
  )

  [pscustomobject]@{
    Root      = $Root
    Key       = $Key
    Name      = $Name
    Value     = $Value
    Type      = $Type
    Condition = $Condition
    Evidence  = $Evidence
  }
}

function Get-DeployMasterBuiltInRegistration {
  <#
  .SYNOPSIS
    Reconstruct one scope-specific DeployMaster uninstall registration.
  .PARAMETER PackageData
    Parsed DeployMaster package model containing the structured identity and format route.
  .PARAMETER Scope
    Normal-install scope whose concrete registry hive and installation path are projected.
  .PARAMETER InstallLocation
    Manifest-safe destination path compiled for this scope.
  .PARAMETER RegistryView
    Registry view selected by the compiled application architecture mode.
  .PARAMETER TargetArchitecture
    Concrete application architecture used to select an architecture-specific generated uninstaller.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][ValidateSet('user', 'machine')][string]$Scope,
    [Parameter(Mandatory)][string]$InstallLocation,
    [Parameter(Mandatory)][string]$RegistryView,
    [ValidateSet('x86', 'x64')][string]$TargetArchitecture
  )

  $Root = $Scope -eq 'machine' ? 'HKLM' : 'HKCU'
  $Condition = $PackageData.Identity.SupportsDualScope ? "Normal installation uses $Scope scope" : $null
  $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($PackageData.Identity.DisplayName)"
  $UninstallerFileName = switch ($PackageData.Header.ApplicationArchitectureMode) {
    'x86AndX64Application' {
      if (-not $TargetArchitecture) { throw 'A concrete target architecture is required for a mixed-architecture DeployMaster uninstall registration.' }
      # Mixed media stores distinguishable UnDeploy32/UnDeploy64 payload records, but the runtime
      # installs the selected x86 payload under the ordinary UnDeploy.exe name.
      $TargetArchitecture -eq 'x64' ? 'UnDeploy64.exe' : 'UnDeploy.exe'
    }
    'x64Application' { 'UnDeploy64.exe' }
    default { 'UnDeploy.exe' }
  }
  $UninstallerPath = "$($InstallLocation.TrimEnd('\'))\$UninstallerFileName"
  $DeploymentLogPath = "$($InstallLocation.TrimEnd('\'))\Deploy.log"

  # DeployMaster 7.2 quotes both paths. Controlled VM installations of archived 6.0.1 and 6.5.1
  # media prove that the earlier runtime left the executable path unquoted but quoted the log.
  $UninstallString = switch ($PackageData.Header.UninstallCommandRoute) {
    'QuotedExecutableAndLog' { "`"$UninstallerPath`" `"$DeploymentLogPath`"" }
    'UnquotedExecutableQuotedLog' { "$UninstallerPath `"$DeploymentLogPath`"" }
    default { throw "Unsupported DeployMaster uninstall command route '$($PackageData.Header.UninstallCommandRoute)'." }
  }
  $Writes = [Collections.Generic.List[object]]::new()
  # The runtime writes HelpLink and URLInfoUpdate from the application URL and falls back to the
  # publisher URL when no application URL is configured; the dual-conditional gate is byte-identical
  # in the 6.0.1 through 7.7.0 runtime decompiles.
  $HelpLinkValue = $PackageData.Identity.PackageUrl
  if ([string]::IsNullOrWhiteSpace([string]$HelpLinkValue)) {
    $HelpLinkValue = $PackageData.Identity.PublisherUrl
  }
  $ValueRecords = @(
    [pscustomobject]@{ Name = 'DisplayName'; Value = $PackageData.Identity.DisplayName; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'UninstallString'; Value = $UninstallString; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'NoModify'; Value = 1; Type = 'REG_DWORD' }
    [pscustomobject]@{ Name = 'NoRepair'; Value = 1; Type = 'REG_DWORD' }
    [pscustomobject]@{ Name = 'InstallLocation'; Value = $InstallLocation; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'DisplayVersion'; Value = $PackageData.Identity.DisplayVersion; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'Publisher'; Value = $PackageData.Identity.Publisher; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'HelpLink'; Value = $HelpLinkValue; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'URLInfoUpdate'; Value = $HelpLinkValue; Type = 'REG_SZ' }
    [pscustomobject]@{ Name = 'URLInfoAbout'; Value = $PackageData.Identity.PublisherUrl; Type = 'REG_SZ' }
  )
  # The runtime writes the first two dot-separated DisplayVersion components as string values;
  # live installs confirm "12.34.56" -> "12"/"34" and "DEMO 6.1.2" -> "DEMO 6"/"1".
  $VersionComponents = @(([string]$PackageData.Identity.DisplayVersion) -split '\.')
  $VersionMajorValue = $VersionComponents.Count -ge 2 ? $VersionComponents[0] : $null
  $VersionMinorValue = $VersionComponents.Count -ge 2 ? $VersionComponents[1] : $null
  if ($null -ne $VersionMajorValue) {
    $ValueRecords += [pscustomobject]@{ Name = 'VersionMajor'; Value = $VersionMajorValue; Type = 'REG_SZ' }
    $ValueRecords += [pscustomobject]@{ Name = 'VersionMinor'; Value = $VersionMinorValue; Type = 'REG_SZ' }
  }
  foreach ($Record in $ValueRecords) {
    if ($null -eq $Record.Value -or ($Record.Value -is [string] -and [string]::IsNullOrWhiteSpace($Record.Value))) { continue }
    $Writes.Add((ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Root $Root -Key $UninstallKey -Name $Record.Name -Value $Record.Value -Type $Record.Type -Condition $Condition))
  }

  # DeployMaster records the deployment log under its vendor key so later installations can find
  # an existing package. The adjacent Stub value contains the runtime source path and is generated
  # during installation, so it is reported as dynamic evidence rather than guessed here.
  $TrackingWrite = ConvertTo-DeployMasterRegistryWrite -PackageData $PackageData -Root $Root -Key 'Software\JGsoft\DeployIT' -Name $PackageData.Identity.DisplayName -Value $DeploymentLogPath -Condition $Condition -Evidence 'DeployMaster built-in deployment-log tracking convention'
  [pscustomobject][ordered]@{
    Scope                      = $Scope
    Root                       = $Root
    RegistryView               = $RegistryView
    Architecture               = $TargetArchitecture
    ProductCode                = $PackageData.Identity.DisplayName
    UninstallKey               = $UninstallKey
    DisplayName                = $PackageData.Identity.DisplayName
    DisplayVersion             = $PackageData.Identity.DisplayVersion
    Publisher                  = $PackageData.Identity.Publisher
    HelpLink                   = $HelpLinkValue
    URLInfoUpdate              = $HelpLinkValue
    URLInfoAbout               = $PackageData.Identity.PublisherUrl
    InstallLocation            = $InstallLocation
    UninstallerPath            = $UninstallerPath
    DeploymentLogPath          = $DeploymentLogPath
    UninstallString            = $UninstallString
    QuietUninstallString       = $null
    DisplayIcon                = $null
    NoModify                   = $true
    NoRepair                   = $true
    VersionMajor               = $VersionMajorValue
    VersionMinor               = $VersionMinorValue
    RegistryWrites             = $Writes.ToArray()
    DeploymentTrackingWrite    = $TrackingWrite
    RuntimeGeneratedValueNames = @('EstimatedSize', 'InstallDate', 'Stub')
    Evidence                   = 'DeployMaster structured identity plus controlled user-scope and machine-scope installations'
  }
}

function Get-DeployMasterCustomAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Project explicit Registry-tab uninstall writes into ARP entries.
  .PARAMETER RegistryWrite
    Parsed DeployMaster registry writes. Conditional keep-existing writes are retained as raw evidence but excluded from authoritative ARP values.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $Groups = @($RegistryWrite | Where-Object {
      -not $_.OnlyIfMissing -and $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)(?<ProductCode>[^\\]+)$'
    } | Group-Object Root, Key)
  foreach ($Group in $Groups) {
    $Values = [ordered]@{}
    foreach ($Write in $Group.Group) { $Values[[string]$Write.Name] = $Write.Value }
    # Windows hides entries without DisplayName and entries explicitly marked as system components.
    # Keep their registry writes in CustomRegistryWrites, but do not present them as visible ARP rows.
    $SystemComponent = 0L
    $IsHidden = $Values.Contains('SystemComponent') -and [long]::TryParse([string]$Values.SystemComponent, [ref]$SystemComponent) -and $SystemComponent -ne 0
    if (-not $Values.Contains('DisplayName') -or [string]::IsNullOrWhiteSpace([string]$Values.DisplayName) -or $IsHidden) { continue }
    $ProductCode = ([string]$Group.Group[0].Key -split '\\')[-1]
    $Entry = [ordered]@{ ProductCode = $ProductCode; InstallerType = 'exe' }
    foreach ($Name in 'DisplayName', 'DisplayVersion', 'Publisher') {
      if ($Values.Contains($Name) -and -not [string]::IsNullOrWhiteSpace([string]$Values[$Name])) { $Entry[$Name] = [string]$Values[$Name] }
    }
    [pscustomobject]$Entry
  }
}

function Merge-DeployMasterAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Merge built-in and explicit DeployMaster uninstall records by ProductCode.
  .PARAMETER Entry
    ARP projections in precedence order. Later explicit registry values replace corresponding built-in values.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entry)

  $ByProductCode = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Candidate in $Entry) {
    $ProductCode = [string]$Candidate.ProductCode
    if ([string]::IsNullOrWhiteSpace($ProductCode)) { continue }
    $Values = [ordered]@{}
    if ($ByProductCode.Contains($ProductCode)) {
      foreach ($Property in $ByProductCode[$ProductCode].PSObject.Properties) { $Values[$Property.Name] = $Property.Value }
    }
    foreach ($Property in $Candidate.PSObject.Properties) {
      if ($null -ne $Property.Value -and -not ($Property.Value -is [string] -and [string]::IsNullOrWhiteSpace($Property.Value))) {
        $Values[$Property.Name] = $Property.Value
      }
    }
    $ByProductCode[$ProductCode] = [pscustomobject]$Values
  }
  return [object[]]@($ByProductCode.Values)
}

function Get-DeployMasterClassicBuiltInRegistration {
  <#
  .SYNOPSIS
    Reconstruct the built-in uninstall registration written by the classic 2.5 runtime.
  .PARAMETER PackageData
    Validated classic package model containing identity and installation-path evidence.
  .OUTPUTS
    The exact static HKLM 32-bit ARP values and deployment-log tracking value confirmed by a
    controlled 2.5.3 installation. Runtime-only Stub data is named but not guessed.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$PackageData)

  $Identity = $PackageData.Identity
  $ProductCode = [string]$Identity.DisplayName
  $InstallLocation = [string]$Identity.MachineInstallLocation
  if ([string]::IsNullOrWhiteSpace($ProductCode) -or [string]::IsNullOrWhiteSpace($InstallLocation)) { return }
  $DisplayName = (@($Identity.Publisher, $Identity.DisplayName, $Identity.DisplayVersion) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ' '
  $DeploymentLogPath = "$InstallLocation\Deploy.log"
  $UninstallerPath = '%WINDOWS%\UnDeploy.exe'
  $UninstallString = "$UninstallerPath `"$DeploymentLogPath`""
  $Key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
  $Writes = @(
    [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = $Key; Name = 'DisplayName'; Value = $DisplayName; Type = 'REG_SZ' }
    [pscustomobject]@{ Root = 'HKLM'; RegistryView = '32-bit'; Key = $Key; Name = 'UninstallString'; Value = $UninstallString; Type = 'REG_SZ' }
  )
  $TrackingWrite = [pscustomobject]@{
    Root = 'HKLM'; RegistryView = '32-bit'; Key = 'Software\JGsoft\DeployIT'; Name = $ProductCode
    Value = $DeploymentLogPath; Type = 'REG_SZ'
  }
  return [pscustomobject]@{
    ProductCode                = $ProductCode
    Root                       = 'HKLM'
    RegistryView               = '32-bit'
    Scope                      = 'machine'
    Architecture               = 'x86'
    Key                        = $Key
    DisplayName                = $DisplayName
    DisplayVersion             = $null
    Publisher                  = $null
    InstallLocation            = $null
    UninstallerPath            = $UninstallerPath
    DeploymentLogPath          = $DeploymentLogPath
    UninstallString            = $UninstallString
    QuietUninstallString       = $null
    DisplayIcon                = $null
    NoModify                   = $null
    NoRepair                   = $null
    RegistryWrites             = $Writes
    DeploymentTrackingWrite    = $TrackingWrite
    RuntimeGeneratedValueNames = @('Stub')
    Evidence                   = 'Classic 2.5 runtime decompile plus controlled 2.5.3 HKLM 32-bit installed-state evidence'
  }
}

function ConvertTo-DeployMasterClassicInfo {
  <#
  .SYNOPSIS
    Compose provider-neutral parser evidence for a validated classic DeployMaster package.
  .PARAMETER File
    Resolved installer FileInfo object.
  .PARAMETER PackageData
    Classic package model returned by Read-DeployMasterClassicPackageData.
  .PARAMETER VersionInfo
    Trusted outer PE version information.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][psobject]$PackageData,
    [Parameter(Mandatory)][Diagnostics.FileVersionInfo]$VersionInfo
  )

  $Identity = $PackageData.Identity
  $CustomRegistryWrites = @($PackageData.BehaviorMetadata.Registry.RegistryWrites)
  $DeletedRegistryKeys = @($PackageData.BehaviorMetadata.Registry.DeletedKeys)
  $FileAssociations = @($PackageData.BehaviorMetadata.FileAssociations)
  $InstalledFiles = @($PackageData.BehaviorMetadata.InstalledFiles)
  $Shortcuts = @($PackageData.BehaviorMetadata.Shortcuts)
  $UrlShortcuts = @($PackageData.BehaviorMetadata.UrlShortcuts)
  $InstallationItems = @($InstalledFiles) + @($Shortcuts) + @($UrlShortcuts)
  $InstallationFolderByPath = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Folder in @($PackageData.BehaviorMetadata.InstallationFolders)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$Folder.FullName) -and -not $InstallationFolderByPath.Contains([string]$Folder.FullName)) {
      $InstallationFolderByPath.Add([string]$Folder.FullName, $Folder)
    }
  }
  $BuiltInRegistration = Get-DeployMasterClassicBuiltInRegistration -PackageData $PackageData
  $BuiltInAppsAndFeaturesEntry = [pscustomobject]@{ ProductCode = $BuiltInRegistration.ProductCode; DisplayName = $BuiltInRegistration.DisplayName; InstallerType = 'exe' }
  $CustomAppsAndFeaturesEntries = @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $CustomRegistryWrites)
  $AppsAndFeaturesEntries = @(Merge-DeployMasterAppsAndFeaturesEntry -Entry (@($BuiltInAppsAndFeaturesEntry) + $CustomAppsAndFeaturesEntries))
  $RegistryWrites = @($BuiltInRegistration.RegistryWrites) + @($BuiltInRegistration.DeploymentTrackingWrite) + $CustomRegistryWrites
  $CustomAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $CustomRegistryWrites
  $FileExtensions = @((@($FileAssociations | Select-Object -ExpandProperty FileExtension) + @($CustomAssociationInfo.FileExtensions)) | Sort-Object -Unique)
  $RegistryAssociationInfo = [pscustomobject]@{
    Protocols                 = @($CustomAssociationInfo.Protocols)
    FileExtensions            = $FileExtensions
    ProtocolAssociations      = @($CustomAssociationInfo.ProtocolAssociations)
    FileExtensionAssociations = @($FileAssociations) + @($CustomAssociationInfo.FileExtensionAssociations)
    RegistryWrites            = @($CustomAssociationInfo.RegistryWrites)
    Diagnostics               = @($CustomAssociationInfo.Diagnostics)
  }
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $Diagnostics.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.ClassicInteractiveOnly' -Source 'DeployMaster' -Message 'The classic DeployMaster 2.5 runtime has no unattended command-line route and is interactive-only.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $PackageData.Route))
  $Diagnostics.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.ClassicEffectsPartial' -Source 'DeployMaster' -Message 'Classic components, recursive destination trees, files, shortcuts, URL shortcuts, registry operations, and file associations are decoded. Prerequisites and completion records remain unresolved.' -Kind Incomplete -Areas Metadata -AffectedFields Prerequisites, ExecutedPayloads -Evidence $PackageData.Route))
  foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }
  $UnresolvedFields = [Collections.Generic.List[string]]::new()
  $UnresolvedFields.Add('Prerequisites')
  $SupportDlls = @(
    if (-not [string]::IsNullOrWhiteSpace($Identity.SupportDll32FileName)) {
      [pscustomobject]@{ Architecture = 'x86'; FileName = $Identity.SupportDll32FileName }
    }
  )
  if ($SupportDlls.Count) {
    # The classic runtime invokes the packaged support DLL the same way modern media does, so its
    # custom validation and post-install effects need the same manual-validation warning.
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.SupportDllEffectsOpaque' -Source 'DeployMaster' -Message 'The installer invokes one or more DeployMaster support DLLs. Their custom validation, folder, registry, and post-install effects require separate static inspection or VM validation.' -Kind ManualValidation -Areas Metadata, Installability, Security -Evidence $SupportDlls))
    $UnresolvedFields.Add('SupportDllEffects')
  }
  return [pscustomobject][ordered]@{
    Path                                  = $File.FullName
    InstallerType                         = 'exe'
    ProductCode                           = $BuiltInRegistration.ProductCode
    UpgradeCode                           = $null
    DisplayName                           = $Identity.DisplayName
    DisplayVersion                        = $Identity.DisplayVersion
    Publisher                             = $Identity.Publisher
    Scope                                 = 'machine'
    DefaultInstallLocation                = $Identity.MachineInstallLocation
    WritesAppsAndFeaturesEntry            = $true
    AppsAndFeaturesProductCode            = $BuiltInRegistration.ProductCode
    AppsAndFeaturesInstallerType          = 'exe'
    AppsAndFeaturesEntries                = $AppsAndFeaturesEntries
    UninstallString                       = $BuiltInRegistration.UninstallString
    QuietUninstallString                  = $null
    DisplayIcon                           = $null
    HelpLink                              = $null
    URLInfoUpdate                         = $null
    URLInfoAbout                          = $null
    Diagnostics                           = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
    UnresolvedFields                      = $UnresolvedFields.ToArray()
    Family                                = 'DeployMaster'
    ProductCodeEvidence                   = $BuiltInRegistration.Evidence
    PublisherUrl                          = $Identity.PublisherUrl
    PackageUrl                            = $Identity.PackageUrl
    Copyright                             = $Identity.Copyright
    Description                           = $Identity.Description
    ReadmeFileName                        = $Identity.ReadmeFileName
    LicenseFileName                       = $Identity.LicenseFileName
    LicenseRequiredEveryInstall           = $false
    SupportDlls                           = $SupportDlls
    ReleaseDate                           = $Identity.ReleaseDate
    MachineInstallLocation                = $Identity.MachineInstallLocation
    UserInstallLocation                   = $Identity.UserInstallLocation
    RawMachineInstallLocation             = $Identity.RawMachineInstallLocation
    RawUserInstallLocation                = $Identity.RawUserInstallLocation
    CommonFilesLocation                   = $null
    CommonPublisherLocation               = $null
    MachineMenuLocation                   = $Identity.MachineMenuLocation
    UserMenuLocation                      = $Identity.UserMenuLocation
    RawMachineMenuLocation                = $Identity.RawMachineMenuLocation
    RawUserMenuLocation                   = $Identity.RawUserMenuLocation
    CommonDataLocation                    = $null
    UserDataLocation                      = $null
    RuntimeProductName                    = ([string]$VersionInfo.ProductName).Trim()
    FileDescription                       = ([string]$VersionInfo.FileDescription).Trim()
    DefaultScope                          = 'machine'
    SupportedScopes                       = @('machine')
    SupportsDualScope                     = $false
    RequiresAdministrativeRights          = $true
    InstallerArchitecture                 = $PackageData.Runtime.Architecture
    ApplicationArchitectureMode           = $null
    ApplicationArchitectures              = @()
    SupportedArchitectures                = @()
    SupportedOperatingSystemArchitectures = @()
    RegistryView                          = '32-bit'
    SupportedWindowsVersions              = @()
    SupportsFutureWindowsVersions         = $null
    MinimumWindows10VersionCode           = $null
    MaximumWindows10VersionCode           = $null
    MinimumWindows11VersionCode           = $null
    MaximumWindows11VersionCode           = $null
    RequestedExecutionLevel               = Get-PERequestedExecutionLevel -Path $File.FullName
    InstallerSwitches                     = [ordered]@{}
    InstallModes                          = @('interactive')
    CommandLineSwitches                   = [pscustomobject]@{}
    UninstallerSwitches                   = [ordered]@{}
    BuiltInRegistration                   = $BuiltInRegistration
    BuiltInRegistrationVariants           = @($BuiltInRegistration)
    DeploymentLogPath                     = $BuiltInRegistration.DeploymentLogPath
    RuntimeGeneratedArpFields             = @()
    RegistryWrites                        = $RegistryWrites
    CustomRegistryWrites                  = $CustomRegistryWrites
    DeletedRegistryKeys                   = $DeletedRegistryKeys
    RegistryAssociationInfo               = $RegistryAssociationInfo
    Protocols                             = $RegistryAssociationInfo.Protocols
    FileExtensions                        = $RegistryAssociationInfo.FileExtensions
    FileAssociations                      = $FileAssociations
    Components                            = @($PackageData.Components)
    InstallationItemGroups                = @($PackageData.BehaviorMetadata.InstallItemGroups)
    InstallationItems                     = $InstallationItems
    InstallationFolders                   = @($InstallationFolderByPath.Values)
    InstalledFiles                        = $InstalledFiles
    Shortcuts                             = $Shortcuts
    UrlShortcuts                          = $UrlShortcuts
    ExecutedPayloads                      = @()
    Prerequisites                         = @()
    DotNetFrameworkRequirement            = $null
    CompletionActions                     = $null
    UninstallConfiguration                = $null
    UpdatePolicy                          = $null
    ExpirationPolicy                      = $null
    PackageSettings                       = $null
    RuntimeFeatures                       = [pscustomobject]@{ PortableSwitch = $false }
    FileEntries                           = $PackageData.FileEntries
    ExtractedFiles                        = @($PackageData.FileEntries | Select-Object -ExpandProperty FullName)
    ClassicFileCatalog                    = [pscustomobject]@{
      CatalogOffset       = $PackageData.FileCatalog.CatalogOffset
      CatalogLength       = $PackageData.FileCatalog.CatalogLength
      EntryCount          = $PackageData.FileEntries.Count
      AuxiliaryEntryCount = $PackageData.FileCatalog.AuxiliaryCount
      ObservedTailBytes   = $PackageData.FileCatalog.ObservedTailBytes
      DestinationRoot     = $PackageData.FileCatalog.DestinationRoot
    }
    OverlayInfo                           = [pscustomobject]@{
      OverlayOffset         = $PackageData.OverlayOffset
      OverlayLength         = $PackageData.LogicalEnd - $PackageData.OverlayOffset
      PhysicalFileSize      = $File.Length
      LogicalFileSize       = $PackageData.LogicalEnd
      HasSignedEnvelope     = $PackageData.LogicalEnd -lt $File.Length
      RuntimeCompressedSize = $PackageData.Runtime.CompressedSize
      RuntimeExpandedSize   = $PackageData.Runtime.UncompressedSize
      HeaderSize            = $null
      FormatProfile         = $PackageData.Route.Id
      FormatVersion         = 2
      ObservedRuntimeRange  = $PackageData.Route.ObservedRuntimeRange
      ProfileEvidence       = $PackageData.Route.Evidence
      PackageDataOffset     = $PackageData.Runtime.MarkerOffset + 4
    }
    CanExpand                             = $true
    ParserVersionInfo                     = [pscustomobject]@{
      Parser         = 'Dumplings.PackageModule.DeployMaster'
      ParserMajor    = 7
      CatalogVersion = [int](Get-DeployMasterCatalogVersion)
      FormatProfile  = $PackageData.Route.Id
      Sources        = @('DeployMaster 2.x BZip2 runtime member', 'length-prefixed zlib metadata and payload records', 'classic component descriptors', 'classic offset, expanded-size, CRC32, and destination-root file catalog', 'flat classic file and shortcut streams', 'classic null-terminated registry stream', 'classic form-feed file-association stream', 'archived DeployMaster 2.5.x media')
    }
  }
}

function Get-DeployMasterInfo {
  <#
  .SYNOPSIS
    Read structured DeployMaster identity, scope, ARP, and payload evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $RuntimeIdentity = "$($VersionInfo.ProductName)`n$($VersionInfo.FileDescription)`n$($VersionInfo.Comments)"
    $ClassicPackageData = $null
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $ClassicRoute = Get-DeployMasterClassicRoute -Stream $Stream -RuntimeIdentity $RuntimeIdentity
      if ($ClassicRoute) {
        $ClassicPackageData = Read-DeployMasterClassicPackageData -Stream $Stream -Route $ClassicRoute
      } else {
        # Parse the complete package model while one stream is open, then separately corroborate the
        # overlay location and PE runtime identity.
        $PackageData = Read-DeployMasterPackageData -Stream $Stream
        $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
        $PELayout = Get-PELayout -Stream $Stream
        $VersionStrings = Get-PEVersionStringTable -Path $File.FullName
      }
    } finally { $Stream.Dispose() }

    if ($ClassicPackageData) { return ConvertTo-DeployMasterClassicInfo -File $File -PackageData $ClassicPackageData -VersionInfo $VersionInfo }

    if ($OverlayOffset -ne $PackageData.Locator.PackageOffset) { throw 'The DeployMaster package locator does not point to the PE overlay.' }
    $RuntimeProductName = ([string]$VersionInfo.ProductName).Trim()
    $RuntimeComments = ([string]$VersionStrings.Comments).Trim()
    if ($RuntimeProductName -notmatch '(?i)DeployMaster' -and $RuntimeComments -notmatch '(?i)DeployMaster') { throw 'The validated package overlay is not paired with a DeployMaster runtime identity.' }

    $Identity = $PackageData.Identity
    $InstallerArchitecture = switch ($PELayout.MachineName) { 'I386' { 'x86' } 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { $null } }
    # Distinguish a pure x64 installer from an x86 bootstrapper that deploys a 64-bit application.
    $ApplicationArchitectureMode = if ($PackageData.Header.ApplicationArchitectureMode -eq 'x64Application') {
      if ($InstallerArchitecture -eq 'x86') { 'x64ApplicationWithX86InstallerStub' } else { 'x64ApplicationWithX64Installer' }
    } else { $PackageData.Header.ApplicationArchitectureMode }
    $RegistryView = switch ($ApplicationArchitectureMode) {
      { $_ -in 'x86ApplicationForX86WindowsOnly', 'x86ApplicationForX86AndX64Windows' } { '32-bit'; break }
      { $_ -in 'x64ApplicationWithX86InstallerStub', 'x64ApplicationWithX64Installer', 'x64Application' } { '64-bit'; break }
      'x86AndX64Application' { 'architecture-selected'; break }
      default { 'default' }
    }
    $InstallLocation = switch ($Identity.Scope) {
      'user' { $Identity.UserInstallLocation }
      'machine' { $Identity.MachineInstallLocation }
      default { $null }
    }
    # "Always" portable media bypasses every host-system effect, including the built-in ARP entry.
    # User-choice media retains both a normal installation route and a separate portable route.
    $NormalInstallSupported = $null -eq $PackageData.Settings -or $PackageData.Settings.PortableInstallationMode -ne 'Always'
    $BuiltInRegistrations = [Collections.Generic.List[object]]::new()
    if ($NormalInstallSupported) {
      $RegistrationArchitectures = switch ($ApplicationArchitectureMode) {
        'x86AndX64Application' {
          [pscustomobject]@{ Architecture = 'x86'; RegistryView = '32-bit' }
          [pscustomobject]@{ Architecture = 'x64'; RegistryView = '64-bit' }
        }
        { $_ -in 'x64ApplicationWithX86InstallerStub', 'x64ApplicationWithX64Installer', 'x64Application' } { [pscustomobject]@{ Architecture = 'x64'; RegistryView = '64-bit' }; break }
        default { [pscustomobject]@{ Architecture = 'x86'; RegistryView = '32-bit' } }
      }
      foreach ($RegistrationScope in $Identity.SupportedScopes) {
        $RegistrationLocation = $RegistrationScope -eq 'machine' ? $Identity.MachineInstallLocation : $Identity.UserInstallLocation
        if ([string]::IsNullOrWhiteSpace([string]$RegistrationLocation)) { continue }
        foreach ($RegistrationArchitecture in $RegistrationArchitectures) {
          $BuiltInRegistrations.Add((Get-DeployMasterBuiltInRegistration -PackageData $PackageData -Scope $RegistrationScope -InstallLocation $RegistrationLocation -RegistryView $RegistrationArchitecture.RegistryView -TargetArchitecture $RegistrationArchitecture.Architecture))
        }
      }
    }
    $PrimaryRegistration = if ($Identity.Scope -and $RegistrationArchitectures.Count -eq 1) { $BuiltInRegistrations | Where-Object Scope -EQ $Identity.Scope | Select-Object -First 1 } elseif ($BuiltInRegistrations.Count -eq 1) { $BuiltInRegistrations[0] } else { $null }
    $BuiltInRegistryWrites = @($BuiltInRegistrations | ForEach-Object { @($_.RegistryWrites) + $_.DeploymentTrackingWrite })
    $CustomRegistryWrites = if ($PackageData.StructuredMetadata) { @($PackageData.StructuredMetadata.Registry.RegistryWrites) } else { @() }
    $RegistryWrites = if ($NormalInstallSupported) { @($BuiltInRegistryWrites) + @($CustomRegistryWrites) } else { @() }
    $CustomAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $CustomRegistryWrites
    $FileExtensions = @((@($PackageData.FileAssociations | Select-Object -ExpandProperty FileExtension) + @($CustomAssociationInfo.FileExtensions)) | Sort-Object -Unique)
    $RegistryAssociationInfo = [pscustomobject]@{
      Protocols                 = @($CustomAssociationInfo.Protocols)
      FileExtensions            = $FileExtensions
      ProtocolAssociations      = @($CustomAssociationInfo.ProtocolAssociations)
      FileExtensionAssociations = @($PackageData.FileAssociations) + @($CustomAssociationInfo.FileExtensionAssociations)
      RegistryWrites            = @($CustomAssociationInfo.RegistryWrites)
      Diagnostics               = @($CustomAssociationInfo.Diagnostics)
    }
    $AppsAndFeaturesCandidates = [Collections.Generic.List[object]]::new()
    if ($NormalInstallSupported) {
      $AppsAndFeaturesCandidates.Add([pscustomobject]@{
          ProductCode = $Identity.DisplayName; DisplayName = $Identity.DisplayName; DisplayVersion = $Identity.DisplayVersion
          Publisher = $Identity.Publisher; InstallerType = 'exe'
        })
      foreach ($CustomEntry in @(Get-DeployMasterCustomAppsAndFeaturesEntry -RegistryWrite $CustomRegistryWrites)) { $AppsAndFeaturesCandidates.Add($CustomEntry) }
    }
    [object[]]$AppsAndFeaturesEntries = if ($AppsAndFeaturesCandidates.Count) { @(Merge-DeployMasterAppsAndFeaturesEntry -Entry $AppsAndFeaturesCandidates.ToArray()) } else { @() }
    $Warnings = [Collections.Generic.List[object]]::new()
    foreach ($Warning in $PackageData.Diagnostics) { $Warnings.Add($Warning) }
    foreach ($Warning in $RegistryAssociationInfo.Diagnostics) { $Warnings.Add($Warning) }
    if ($PackageData.Header.ExpirationPolicy.IsTimeLimited) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.TimeLimited' -Source 'DeployMaster' -Message "This installer stops working after $($PackageData.Header.ExpirationPolicy.ExpirationDate.ToString('yyyy-MM-dd')); use a non-expiring release artifact when one is available." -Kind Risk -Areas Installability -Evidence $PackageData.Header.ExpirationPolicy))
    }
    $SupportDlls = @(
      if (-not [string]::IsNullOrWhiteSpace($Identity.SupportDll32FileName)) { [pscustomobject]@{ Architecture = 'x86'; FileName = $Identity.SupportDll32FileName } }
      if (-not [string]::IsNullOrWhiteSpace($Identity.SupportDll64FileName)) { [pscustomobject]@{ Architecture = 'x64'; FileName = $Identity.SupportDll64FileName } }
    )
    if ($SupportDlls.Count) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Installability.SupportDllEffectsOpaque' -Source 'DeployMaster' -Message 'The installer invokes one or more DeployMaster support DLLs. Their custom validation, folder, registry, and post-install effects require separate static inspection or VM validation.' -Kind ManualValidation -Areas Metadata, Installability, Security -Evidence $SupportDlls))
    }
    if (-not $NormalInstallSupported) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.PortableOnlyNoArp' -Source 'DeployMaster' -Message 'This package always creates a portable installation, so DeployMaster does not write its built-in Apps & Features entry or other host-system changes.' -Kind Information -Areas Metadata, Installability -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $PackageData.Settings))
    } elseif ($BuiltInRegistrations.Count -and -not $PrimaryRegistration -and -not $Identity.SupportsDualScope) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Metadata.ArpRegistrationUnresolved' -Source 'DeployMaster' -Message 'The built-in DeployMaster uninstall registration could not be resolved to a concrete supported scope.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $Identity))
    }
    if ($Identity.SupportsDualScope) { $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Scope.Dual' -Source 'DeployMaster' -Message 'This DeployMaster package supports both user and machine scope; validate the default scope and any elevation-sensitive behavior in a VM.' -Kind ManualValidation -Areas Metadata, Installability -AffectedFields Scope -Evidence $Identity.SupportedScopes)) }
    if ($PackageData.FileAssociations.Actions | Where-Object { $_.Executable32FileIndex -lt 0 -and $_.Executable64FileIndex -lt 0 }) {
      $Warnings.Add((New-InstallerDiagnostic -Id 'DeployMaster.Association.ExecutableUnresolved' -Source 'DeployMaster' -Message 'One or more DeployMaster file-type actions do not resolve to packaged executable indexes and will not create an open command.' -Kind Incomplete -Areas Metadata -AffectedFields FileExtensions, Protocols -Evidence $PackageData.FileAssociations))
    }
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    if (-not $PackageData.StructuredMetadata) {
      foreach ($Field in 'Components', 'InstallationItems', 'RegistryWrites', 'Prerequisites', 'CompletionActions', 'UpdatePolicy') { $UnresolvedFields.Add($Field) }
    }
    if ($SupportDlls.Count) { $UnresolvedFields.Add('SupportDllEffects') }
    $Components = [object[]]@()
    $InstallationFolders = [object[]]@()
    $InstalledFiles = [object[]]@()
    $Shortcuts = [object[]]@()
    $UrlShortcuts = [object[]]@()
    $Prerequisites = [object[]]@()
    $DeletedRegistryKeys = [object[]]@()
    $CompletionActions = $null
    $UninstallConfiguration = $null
    $UpdatePolicy = $null
    $ExecutedPayloads = [Collections.Generic.List[object]]::new()
    if ($PackageData.StructuredMetadata) {
      $Components = [object[]]@($PackageData.StructuredMetadata.Components)
      $InstallationFolders = [object[]]@($PackageData.StructuredMetadata.InstallTree.Folders)
      $InstalledFiles = [object[]]@($PackageData.StructuredMetadata.InstallTree.Files)
      $Shortcuts = [object[]]@($PackageData.StructuredMetadata.InstallTree.Shortcuts)
      $UrlShortcuts = [object[]]@($PackageData.StructuredMetadata.InstallTree.UrlShortcuts)
      $Prerequisites = [object[]]@($PackageData.StructuredMetadata.TrailingMetadata.Prerequisites)
      $DeletedRegistryKeys = [object[]]@($PackageData.StructuredMetadata.Registry.DeletedKeys)
      $CompletionActions = $PackageData.StructuredMetadata.TrailingMetadata.Completion
      $UninstallConfiguration = $PackageData.StructuredMetadata.TrailingMetadata.Uninstall
      $UpdatePolicy = $PackageData.StructuredMetadata.TrailingMetadata.Update
      foreach ($Execution in @(
          [pscustomobject]@{ Stage = 'AfterInstall'; Architecture = 'x86'; FileIndex = $CompletionActions.Launch32FileIndex; Arguments = $CompletionActions.LaunchArguments },
          [pscustomobject]@{ Stage = 'AfterInstall'; Architecture = 'x64'; FileIndex = $CompletionActions.Launch64FileIndex; Arguments = $CompletionActions.LaunchArguments },
          [pscustomobject]@{ Stage = 'BeforeUninstall'; Architecture = 'x86'; FileIndex = $UninstallConfiguration.PreUninstall32FileIndex; Arguments = $UninstallConfiguration.PreUninstallArguments },
          [pscustomobject]@{ Stage = 'BeforeUninstall'; Architecture = 'x64'; FileIndex = $UninstallConfiguration.PreUninstall64FileIndex; Arguments = $UninstallConfiguration.PreUninstallArguments }
        )) {
        if ($Execution.FileIndex -ge 0 -and $Execution.FileIndex -lt $PackageData.FileEntries.Count) {
          $ExecutedPayloads.Add([pscustomobject]@{
              Stage        = $Execution.Stage
              Architecture = $Execution.Architecture
              FileIndex    = $Execution.FileIndex
              FileName     = $PackageData.FileEntries[$Execution.FileIndex].Name
              Arguments    = $Execution.Arguments
              Evidence     = 'DeployMaster completion or pre-uninstall file index'
            })
        }
      }
    }
    $InstallationItems = [object[]]@($InstallationFolders) + @($InstalledFiles) + @($Shortcuts) + @($UrlShortcuts)
    $HelpLink = if (-not $NormalInstallSupported) {
      $null
    } elseif ([string]::IsNullOrWhiteSpace([string]$Identity.PackageUrl)) {
      $Identity.PublisherUrl
    } else {
      $Identity.PackageUrl
    }

    [pscustomobject][ordered]@{
      Path                                  = $File.FullName
      InstallerType                         = 'exe'
      ProductCode                           = $NormalInstallSupported ? $Identity.DisplayName : $null
      UpgradeCode                           = $null
      DisplayName                           = $Identity.DisplayName
      DisplayVersion                        = $Identity.DisplayVersion
      Publisher                             = $Identity.Publisher
      Scope                                 = $Identity.Scope
      DefaultInstallLocation                = $InstallLocation
      WritesAppsAndFeaturesEntry            = $NormalInstallSupported
      AppsAndFeaturesProductCode            = $NormalInstallSupported ? $Identity.DisplayName : $null
      AppsAndFeaturesInstallerType          = $NormalInstallSupported ? 'exe' : $null
      AppsAndFeaturesEntries                = $AppsAndFeaturesEntries
      UninstallString                       = $PrimaryRegistration ? $PrimaryRegistration.UninstallString : $null
      QuietUninstallString                  = $null
      DisplayIcon                           = $PrimaryRegistration ? $PrimaryRegistration.DisplayIcon : $null
      HelpLink                              = $HelpLink
      URLInfoUpdate                         = $HelpLink
      URLInfoAbout                          = $NormalInstallSupported ? $Identity.PublisherUrl : $null
      Diagnostics                           = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'DeployMaster' -Kind Incomplete -Areas Metadata))
      UnresolvedFields                      = $UnresolvedFields.ToArray()
      Family                                = 'DeployMaster'
      ProductCodeEvidence                   = $NormalInstallSupported ? 'DeployMaster structured identity and built-in uninstall-key convention' : $null
      PublisherUrl                          = $Identity.PublisherUrl
      PackageUrl                            = $Identity.PackageUrl
      Copyright                             = $Identity.Copyright
      ReadmeFileName                        = $Identity.ReadmeFileName
      LicenseFileName                       = $Identity.LicenseFileName
      LicenseRequiredEveryInstall           = $Identity.LicenseRequiredEveryInstall
      SupportDlls                           = $SupportDlls
      ReleaseDate                           = $Identity.ReleaseDate
      MachineInstallLocation                = $Identity.MachineInstallLocation
      UserInstallLocation                   = $Identity.UserInstallLocation
      RawMachineInstallLocation             = $Identity.RawMachineInstallLocation
      RawUserInstallLocation                = $Identity.RawUserInstallLocation
      CommonFilesLocation                   = $Identity.CommonFilesLocation
      CommonPublisherLocation               = $Identity.CommonPublisherLocation
      MachineMenuLocation                   = $Identity.MachineMenuLocation
      UserMenuLocation                      = $Identity.UserMenuLocation
      CommonDataLocation                    = $Identity.CommonDataLocation
      UserDataLocation                      = $Identity.UserDataLocation
      RawCommonFilesLocation                = $Identity.RawCommonFilesLocation
      RawCommonPublisherLocation            = $Identity.RawCommonPublisherLocation
      RawMachineMenuLocation                = $Identity.RawMachineMenuLocation
      RawUserMenuLocation                   = $Identity.RawUserMenuLocation
      RawCommonDataLocation                 = $Identity.RawCommonDataLocation
      RawUserDataLocation                   = $Identity.RawUserDataLocation
      RuntimeProductName                    = $RuntimeProductName
      FileDescription                       = ([string]$VersionInfo.FileDescription).Trim()
      DefaultScope                          = $Identity.DefaultScope
      SupportedScopes                       = $Identity.SupportedScopes
      SupportsDualScope                     = $Identity.SupportsDualScope
      RequiresAdministrativeRights          = $Identity.RequiresAdministrativeRights
      InstallerArchitecture                 = $InstallerArchitecture
      ApplicationArchitectureMode           = $ApplicationArchitectureMode
      ApplicationArchitectures              = $PackageData.Header.ApplicationArchitectures
      SupportedArchitectures                = $PackageData.Header.ApplicationArchitectures
      SupportedOperatingSystemArchitectures = $PackageData.Header.SupportedOperatingSystemArchitectures
      RegistryView                          = $RegistryView
      SupportedWindowsVersions              = $PackageData.Header.SupportedWindowsVersions
      SupportsFutureWindowsVersions         = $PackageData.Header.SupportsFutureWindowsVersions
      MinimumWindows10VersionCode           = $PackageData.Header.MinimumWindows10VersionCode
      MaximumWindows10VersionCode           = $PackageData.Header.MaximumWindows10VersionCode
      MinimumWindows11VersionCode           = $PackageData.Header.MinimumWindows11VersionCode
      MaximumWindows11VersionCode           = $PackageData.Header.MaximumWindows11VersionCode
      RequestedExecutionLevel               = Get-PERequestedExecutionLevel -Path $File.FullName
      InstallerSwitches                     = [ordered]@{ Silent = '/silent'; SilentWithProgress = '/silent'; InstallLocation = $PackageData.Settings.PortableInstallationMode -eq 'Always' ? '/portable "<INSTALLPATH>"' : '/appfolder "<INSTALLPATH>"' }
      InstallModes                          = @('interactive', 'silent')
      CommandLineSwitches                   = [pscustomobject]@{
        Silent                   = @('/s', '/silent')
        SuppressDesktopShortcuts = '/nodesktop'
        ForceX86                 = if ($ApplicationArchitectureMode -eq 'x86AndX64Application') { '/32' } else { $null }
        Portable                 = if ($PackageData.RuntimeFeatures.PortableSwitch) { '/portable "<PATH>"' } else { $null }
        InstallForAllUsers       = if ($PackageData.Header.HasInstallForAllUsersSwitch -and $Identity.SupportsDualScope) { '/userall' } else { $null }
        SkipElevation            = if ($PackageData.RuntimeFeatures.SkipElevationSwitch) { '/noadmin' } else { $null }
        TemporaryFolder          = '/temp "<PATH>"'
        InstallationFolders      = [ordered]@{
          Application = '/appfolder "<PATH>"'
          CommonFiles = '/appcommonfolder "<PATH>"'
          StartMenu   = '/appmenu "<PATH>"'
          UserData    = '/userdata "<PATH>"'
        }
      }
      UninstallerSwitches                   = [ordered]@{ Silent = '/silent' }
      BuiltInRegistration                   = $PrimaryRegistration
      BuiltInRegistrationVariants           = $BuiltInRegistrations.ToArray()
      DeploymentLogPath                     = $PrimaryRegistration ? $PrimaryRegistration.DeploymentLogPath : $null
      RuntimeGeneratedArpFields             = $NormalInstallSupported ? @('EstimatedSize', 'InstallDate') : @()
      RegistryWrites                        = $RegistryWrites
      CustomRegistryWrites                  = $CustomRegistryWrites
      DeletedRegistryKeys                   = $DeletedRegistryKeys
      RegistryAssociationInfo               = $RegistryAssociationInfo
      Protocols                             = $RegistryAssociationInfo.Protocols
      FileExtensions                        = $RegistryAssociationInfo.FileExtensions
      FileAssociations                      = $PackageData.FileAssociations
      Components                            = $Components
      InstallationItems                     = $InstallationItems
      InstallationFolders                   = $InstallationFolders
      InstalledFiles                        = $InstalledFiles
      Shortcuts                             = $Shortcuts
      UrlShortcuts                          = $UrlShortcuts
      ExecutedPayloads                      = $ExecutedPayloads.ToArray()
      Prerequisites                         = $Prerequisites
      DotNetFrameworkRequirement            = if ($PackageData.StructuredMetadata) { $PackageData.StructuredMetadata.TrailingMetadata.DotNetFramework } else { $null }
      CompletionActions                     = $CompletionActions
      UninstallConfiguration                = $UninstallConfiguration
      UpdatePolicy                          = $UpdatePolicy
      ExpirationPolicy                      = $PackageData.Header.ExpirationPolicy
      PackageSettings                       = $PackageData.Settings
      RuntimeFeatures                       = $PackageData.RuntimeFeatures
      FileEntries                           = $PackageData.FileEntries
      ExtractedFiles                        = @($PackageData.FileEntries | Select-Object -ExpandProperty FullName)
      OverlayInfo                           = [pscustomobject]@{
        OverlayOffset         = $PackageData.Locator.PackageOffset
        OverlayLength         = $File.Length - $PackageData.Locator.PackageOffset
        IntegrityLength       = $PackageData.Locator.IntegrityLength
        ExpectedCrc32         = $PackageData.Locator.ExpectedCrc32
        ActualCrc32           = $PackageData.Locator.ActualCrc32
        ExpectedFileSize      = $PackageData.Locator.ExpectedFileSize
        PhysicalFileSize      = $PackageData.Locator.PhysicalFileSize
        HasSignedEnvelope     = $PackageData.Locator.HasSignedEnvelope
        CertificateOffset     = $PackageData.Locator.CertificateOffset
        CertificateSize       = $PackageData.Locator.CertificateSize
        DictionarySize        = $PackageData.Header.DictionarySize
        HeaderSize            = $PackageData.Header.HeaderSize
        FormatProfile         = $PackageData.Header.FormatProfile
        FormatVersion         = $PackageData.Header.FormatVersion
        UninstallCommandRoute = $PackageData.Header.UninstallCommandRoute
        ObservedRuntimeRange  = $PackageData.Header.ObservedRuntimeRange
        ProfileEvidence       = $PackageData.Header.ProfileEvidence
        PackageDataOffset     = $PackageData.Locator.PackageDataOffset
      }
      CanExpand                             = $true
      ParserVersionInfo                     = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.DeployMaster'; ParserMajor = 7; CatalogVersion = [int](Get-DeployMasterCatalogVersion); FormatProfile = $PackageData.Header.FormatProfile; Sources = @('DeployMaster 0x80 package locator', 'CRC32-protected package-control header', 'stored and bounded LZMA data blocks', 'controlled builder outputs and installed-state evidence', 'DeployMaster builder help and version history') }
    }
  }
}

function Export-DeployMasterRange {
  <#
  .SYNOPSIS
    Export one stored or raw-LZMA DeployMaster range
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER Properties
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Entry,
    [AllowEmptyCollection()][byte[]]$Properties = [byte[]]::new(0),
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][long]$MaximumBytes
  )

  # A bounded source range prevents the decoder from consuming the next package record.
  $Output = [IO.File]::Open($DestinationPath, 'CreateNew', 'Write', 'None')
  $InputStream = New-BoundedReadStream -Stream $Stream -Offset $Entry.Offset -Length $Entry.CompressedSize -LeaveOpen
  $Completed = $false
  try {
    if ($Entry.Compression -eq 'Store') {
      $CopyArguments = @{ Source = $InputStream; Destination = $Output; MaximumBytes = $MaximumBytes }
      if ($null -ne $Entry.UncompressedSize) { $CopyArguments.ExpectedBytes = [long]$Entry.UncompressedSize }
      $null = Copy-BoundedStream @CopyArguments
    } else {
      $ExpandArguments = @{
        Algorithm      = [string]$Entry.Compression
        Stream         = $InputStream
        Destination    = $Output
        MaximumBytes   = $MaximumBytes
        CompressedSize = [long]$Entry.CompressedSize
      }
      if ($Properties.Count) { $ExpandArguments.Properties = $Properties }
      if ($null -ne $Entry.UncompressedSize) { $ExpandArguments.UncompressedSize = [long]$Entry.UncompressedSize }
      $null = Expand-InstallerCompressedStream @ExpandArguments
    }
    $Completed = $true
  } finally {
    $InputStream.Dispose()
    $Output.Dispose()
    if (-not $Completed) { Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction Ignore }
  }
  # The final catalog column is CRC32 over the expanded file. Reject damaged payloads before the
  # caller can consume them, and remove the partial output on failure.
  if ($Entry.PSObject.Properties['Crc32']) {
    $ActualCrc32 = [uint32](Get-BinaryCrc32 -Path $DestinationPath -MaximumBytes $MaximumBytes)
    if ($ActualCrc32 -ne [uint32]$Entry.Crc32) {
      Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction Ignore
      throw "The DeployMaster payload CRC32 check failed for '$($Entry.FullName)'."
    }
  }
  Get-Item -LiteralPath $DestinationPath -Force
}

function Expand-DeployMasterInstaller {
  <#
  .SYNOPSIS
    Expand validated DeployMaster runtime, metadata, and payload files
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-DeployMaster-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Results = [Collections.Generic.List[object]]::new()
    $ExpandedBytes = 0L
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
      $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
      $RuntimeIdentity = "$($VersionInfo.ProductName)`n$($VersionInfo.FileDescription)`n$($VersionInfo.Comments)"
      $ClassicRoute = Get-DeployMasterClassicRoute -Stream $Stream -RuntimeIdentity $RuntimeIdentity
      $PackageData = $ClassicRoute ? (Read-DeployMasterClassicPackageData -Stream $Stream -Route $ClassicRoute) : (Read-DeployMasterPackageData -Stream $Stream)
      # Normalize runtime cores, decoded metadata blocks, and application files into one extraction
      # catalog so selection and accounting follow the same path.
      $Items = [Collections.Generic.List[object]]::new()
      foreach ($Core in $PackageData.Header.CoreEntries) {
        $Compression = $Core.PSObject.Properties['Compression'] ? [string]$Core.Compression : 'Lzma'
        $Items.Add([pscustomobject]@{ FullName = "Runtime/DeployMasterCore-$($Core.Architecture).exe"; Kind = 'Compressed'; Offset = $Core.Offset; CompressedSize = $Core.CompressedSize; UncompressedSize = $Core.UncompressedSize; Compression = $Compression })
      }
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Language.txt'; Kind = 'Bytes'; Bytes = $PackageData.LanguageBlock.Bytes; UncompressedSize = $PackageData.LanguageBlock.Bytes.Length })
      $Items.Add([pscustomobject]@{ FullName = 'Metadata/Identity.txt'; Kind = 'Bytes'; Bytes = $PackageData.IdentityBlock.Bytes; UncompressedSize = $PackageData.IdentityBlock.Bytes.Length })
      if ($PackageData.PSObject.Properties['FileNameBlock']) {
        $Items.Add([pscustomobject]@{ FullName = 'Metadata/FileNames.txt'; Kind = 'Bytes'; Bytes = $PackageData.FileNameBlock.Bytes; UncompressedSize = $PackageData.FileNameBlock.Bytes.Length })
      }
      foreach ($Entry in $PackageData.FileEntries) {
        $Items.Add([pscustomobject]@{ FullName = "Payload/$($Entry.FullName)"; Kind = 'Compressed'; Offset = $Entry.Offset; CompressedSize = $Entry.CompressedSize; UncompressedSize = $Entry.UncompressedSize; Compression = $Entry.Compression })
      }

      # Check the aggregate uncompressed size and destination identity before writing each item.
      foreach ($Item in $Items) {
        if (-not (Test-ExtractionPattern -Path $Item.FullName -Pattern $Name)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Item.FullName `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        if ($null -ne $Item.UncompressedSize -and $ExpandedBytes + [long]$Item.UncompressedSize -gt $MaximumExpandedBytes) { throw "The DeployMaster expansion exceeds the $MaximumExpandedBytes-byte output limit." }
        $OutputPath = $Target.Path
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        if ($Item.Kind -eq 'Bytes') {
          [IO.File]::WriteAllBytes($OutputPath, $Item.Bytes)
          $Result = Get-Item -LiteralPath $OutputPath -Force
        } else {
          $Result = Export-DeployMasterRange -Stream $Stream -Entry $Item -Properties $PackageData.Header.LzmaProperties -DestinationPath $OutputPath -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes)
        }
        $ExpandedBytes += $Result.Length
        $Results.Add($Result)
      }
    } finally { $Stream.Dispose() }
    $Results.ToArray()
  }
}

function Test-DeployMaster {
  <#
  .SYNOPSIS
    Test whether a file contains a validated DeployMaster package
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try { $null = Get-DeployMasterInfo -Path $Path; return $true }
    catch { return $false }
  }
}

function Read-ProtocolsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal URL protocol names from DeployMaster registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromDeployMaster {
  <#
  .SYNOPSIS
    Read literal file extensions from DeployMaster registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster package display name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).DisplayName }
}

function Read-PublisherFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromDeployMaster {
  <#
  .SYNOPSIS
    Read the built-in DeployMaster uninstall-key identity
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).ProductCode }
}

function Read-ScopeFromDeployMaster {
  <#
  .SYNOPSIS
    Read the structured DeployMaster installation scope
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-DeployMasterInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-DeployMasterInfo, Expand-DeployMasterInstaller, Test-DeployMaster, Read-ProtocolsFromDeployMaster, Read-FileExtensionsFromDeployMaster, Read-ProductVersionFromDeployMaster, Read-ProductNameFromDeployMaster, Read-PublisherFromDeployMaster, Read-ProductCodeFromDeployMaster, Read-ScopeFromDeployMaster
