# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

$ManifestHeader = '# Created with YamlCreate.ps1 Dumplings Mod'

$Culture = 'en-US'
$WinGetUserAgent = 'Microsoft-Delivery-Optimization/10.0'
$WinGetBackupUserAgent = 'winget-cli WindowsPackageManager/1.7.10661 DesktopAppInstaller/Microsoft.DesktopAppInstaller v1.22.10661.0'
$WinGetTempInstallerFiles = [ordered]@{}
$WinGetInstallerFiles = [ordered]@{}

filter UniqueItems {
  [string]$($_.Split(',').Trim() | Select-Object -Unique)
}

filter ToLower {
  [string]$_.ToLower()
}

filter NoWhitespace {
  [string]$_ -replace '\s+', '-'
}

function Move-KeysToInstallerLevel {
  param (
    [Parameter(Position = 0, Mandatory)]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Position = 1, Mandatory)]
    [System.Collections.IDictionary[]]$Installers,
    [Parameter(Position = 2)]
    [string[]]$Property,
    [Parameter()]
    [int]$Depth = 2,
    [Parameter(DontShow)]
    [int]$CurrentDepth = 0
  )

  if ($CurrentDepth -ge $Depth) { return }
  foreach ($Key in @($Manifest.Keys)) {
    if ($Property -and $Key -cnotin $Property) { continue }
    $ToRemove = $true
    if ($Manifest.$Key -is [System.Collections.IDictionary]) {
      $PreservedManifestKeys = [System.Collections.Generic.HashSet[string]]::new()
      foreach ($Installer in $Installers) {
        $ManifestEntry = $Manifest.$Key | Copy-Object
        $InstallerEntry = $Installer.Contains($Key) -and $Installer.$Key ? $Installer.$Key : [ordered]@{}
        Move-KeysToInstallerLevel -Manifest $ManifestEntry -Installers $InstallerEntry -Depth $Depth -CurrentDepth ($CurrentDepth + 1)
        $PreservedManifestKeys.UnionWith([string[]]($ManifestEntry.Keys))
        if ($InstallerEntry.Count -gt 0) { $Installer.$Key = $InstallerEntry }
      }
      if ($PreservedManifestKeys.Count -gt 0) {
        $ToRemove = $false
        foreach ($KeyToRemove in $Manifest.$Key.Keys.Where({ $_ -cnotin $PreservedManifestKeys })) { $Manifest.$Key.Remove($KeyToRemove) }
      }
    } elseif ($Manifest.$Key -is [System.Collections.IEnumerable] -and $Manifest.$Key -isnot [string]) {
      $ManifestEntry = $Manifest.$Key
      $ManifestEntryHash = ConvertTo-Json -InputObject $ManifestEntry -Depth 10 -Compress
      foreach ($Installer in $Installers) {
        if (-not $Installer.Contains($Key)) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and -not $Installer.$Key) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and (ConvertTo-Json -InputObject $Installer.$Key -Depth 10 -Compress) -cne $ManifestEntryHash) {
          $ToRemove = $false
        }
      }
    } else {
      foreach ($Installer in $Installers) {
        if (-not $Installer.Contains($Key)) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and -not $Installer.$Key) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and $Installer.$Key -cne $Manifest.$Key) {
          $ToRemove = $false
        }
      }
    }
    if ($ToRemove) {
      $Manifest.Remove($Key)
    }
  }
}

function Move-KeysToManifestLevel {
  param (
    [Parameter(Position = 0, Mandatory)]
    [System.Collections.IDictionary[]]$Installers,
    [Parameter(Position = 1, Mandatory)]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Position = 2)]
    [string[]]$Property,
    [Parameter()]
    [int]$Depth = 2,
    [Parameter(DontShow)]
    [int]$CurrentDepth = 0
  )

  if ($CurrentDepth -ge $Depth) { return }
  $AllKeys = @($Installers | ForEach-Object -Process { $_.Keys } | Select-Object -Unique)
  foreach ($Key in $AllKeys) {
    if ($Property -and $Key -cnotin $Property) { continue }
    if ($Installers.Where({ $_.Contains($Key) -and $_.$Key -is [System.Collections.IDictionary] })) {
      $InstallersEntry = @($Installers | ForEach-Object -Process { $_.Contains($Key) -and $_.$Key ? $_.$Key : [ordered]@{} })
      $ManifestEntry = $Manifest.Contains($Key) -and $Manifest.$Key ? $Manifest.$Key : [ordered]@{}

      # Move the same elements across all the objects to the manifest level
      Move-KeysToManifestLevel -Installers $InstallersEntry -Manifest $ManifestEntry -Depth $Depth -CurrentDepth ($CurrentDepth + 1)

      # If the manifest entry is not empty, add it to the manifest
      if ($ManifestEntry.Count -gt 0) {
        $Manifest.$Key = $ManifestEntry
      }
      # If the installer entry is empty, remove it from the installers
      foreach ($Installer in $Installers) {
        if ($Installer.Contains($Key) -and $Installer.$Key.Count -eq 0) {
          $Installer.Remove($Key)
        }
      }
    } elseif ($Installers.Where({ $_.Contains($Key) -and $_.$Key -is [System.Collections.IEnumerable] -and $_.$Key -isnot [string] })) {
      if ($Manifest.Contains($Key)) {
        $ManifestEntryHash = ConvertTo-Json -InputObject $Manifest.$Key -Depth 10 -Compress
        foreach ($Installer in $Installers) {
          $InstallersEntryHash = ConvertTo-Json -InputObject $Installer.$Key -Depth 10 -Compress
          if ($ManifestEntryHash -ceq $InstallersEntryHash) {
            $Installer.Remove($Key)
          }
        }
      } elseif (-not $Manifest.Contains($Key) -and -not ($Installers.Where({ -not $_.Contains($Key) })) -and @($Installers | Sort-Object -Property { ConvertTo-Json -InputObject $_.$Key -Depth 10 -Compress } -Unique).Count -eq 1) {
        $Manifest.$Key = $Installers[0].$Key
        foreach ($Installer in $Installers) {
          $Installer.Remove($Key)
        }
      }
    } else {
      if ($Manifest.Contains($Key)) {
        foreach ($Installer in $Installers) {
          if ($Installer.$Key -ceq $Manifest.$Key) {
            $Installer.Remove($Key)
          }
        }
      } elseif (-not $Manifest.Contains($Key) -and -not ($Installers.Where({ -not $_.Contains($Key) })) -and @($Installers | Sort-Object -Property { $_.$Key } -Unique).Count -eq 1) {
        $Manifest.$Key = $Installers[0].$Key
        foreach ($Installer in $Installers) {
          $Installer.Remove($Key)
        }
      }
    }
  }
}

function Get-WinGetInstallerMetadataProperty {
  <#
  .SYNOPSIS
    Read the first available installer metadata property from parser outputs
  .PARAMETER InputObject
    The parser outputs, in priority order
  .PARAMETER Name
    The property names, in priority order
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parser outputs, in priority order')]
    [AllowEmptyCollection()]
    [psobject[]]$InputObject,

    [Parameter(Mandatory, HelpMessage = 'The property names, in priority order')]
    [string[]]$Name
  )

  foreach ($PropertyName in $Name) {
    foreach ($ParserOutput in $InputObject) {
      if ($null -eq $ParserOutput) { continue }
      if ($ParserOutput -is [System.Collections.IDictionary]) {
        if ($ParserOutput.Contains($PropertyName)) {
          $Value = $ParserOutput[$PropertyName]
          if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) { continue }
          return [pscustomobject]@{ Found = $true; Value = $Value }
        }
      } elseif ($ParserOutput.PSObject.Properties.Name -ccontains $PropertyName) {
        $Value = $ParserOutput.$PropertyName
        if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) { continue }
        return [pscustomobject]@{ Found = $true; Value = $Value }
      }
    }
  }

  [pscustomobject]@{ Found = $false; Value = $null }
}

function ConvertTo-WinGetInstallerManifestMetadata {
  <#
  .SYNOPSIS
    Normalize installer-family parser outputs for manifest updates
  .PARAMETER InputObject
    The parser outputs, in priority order
  .PARAMETER InstallerType
    The effective WinGet installer type
  .PARAMETER OldInstaller
    The existing installer entry, used when normalizing parser metadata for manifest updates
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parser outputs, in priority order')]
    [AllowEmptyCollection()]
    [psobject[]]$InputObject,

    [Parameter(Mandatory, HelpMessage = 'The effective WinGet installer type')]
    [string]$InstallerType,

    [Parameter(Mandatory, HelpMessage = 'The old installer entry')]
    [System.Collections.IDictionary]$OldInstaller
  )

  $Metadata = [ordered]@{}
  # Scope, associations, dependencies, and locale identity remain author-controlled.
  # Publisher here is used only for an existing AppsAndFeaturesEntries.Publisher field.
  $PropertyMap = [ordered]@{
    ProductCode                  = @('AppsAndFeaturesProductCode', 'ProductCode')
    UpgradeCode                  = @('UpgradeCode')
    DisplayName                  = @('DisplayName', 'ProductName')
    DisplayVersion               = @('DisplayVersion', 'ProductVersion', 'Version')
    Publisher                    = $InstallerType -cin @('msix', 'appx') ? @('PublisherDisplayName') : @('Publisher', 'Manufacturer', 'Authors')
    DefaultInstallLocation       = @('DefaultInstallLocation')
    AppsAndFeaturesInstallerType = @('AppsAndFeaturesInstallerType')
    WritesAppsAndFeaturesEntry   = @('WritesAppsAndFeaturesEntry')
    SignatureSha256              = @('SignatureSha256')
    PackageFamilyName            = @('PackageFamilyName')
    Platform                     = @('Platform')
    MinimumOSVersion             = @('MinimumOSVersion')
    Capabilities                 = @('Capabilities')
    RestrictedCapabilities       = @('RestrictedCapabilities')
    UnresolvedFields             = @('UnresolvedFields')
  }

  foreach ($TargetProperty in $PropertyMap.Keys) {
    $Property = Get-WinGetInstallerMetadataProperty -InputObject $InputObject -Name $PropertyMap[$TargetProperty]
    if ($Property.Found) { $Metadata[$TargetProperty] = $Property.Value }
  }

  $Metadata
}

function Get-WinGetKnownInstallerManifestInfo {
  <#
  .SYNOPSIS
    Validate and parse a manifest-declared WinGet installer family
  .PARAMETER Path
    The installer path
  .PARAMETER InstallerType
    The manifest-declared effective installer type
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The manifest-declared effective installer type')]
    [ValidateSet('msi', 'wix', 'burn', 'nullsoft', 'inno', 'msix', 'appx')]
    [string]$InstallerType
  )

  try {
    switch ($InstallerType) {
      { $_ -cin @('msi', 'wix') } {
        $Info = Get-MsiInstallerInfo -Path $Path
        if ($InstallerType -ceq 'wix' -and $Info.InstallerBuilder -cne 'WiX') {
          throw "The MSI builder is '$($Info.InstallerBuilder)', not WiX"
        }
        $ScopeInfo = [pscustomobject]@{ Scope = $Info.AllUsers -ceq '1' ? 'machine' : $null }
        return [pscustomobject]@{ ParserName = 'Windows Installer'; InputObject = @($ScopeInfo, $Info) }
      }
      'burn' {
        $null = Get-BurnInfo -Path $Path
        $Manifest = Get-BurnManifest -Path $Path
        $Registration = $Manifest.BurnManifest.Registration
        $Arp = $Registration.Arp
        $RelatedBundle = $Manifest.BurnManifest.RelatedBundle | Select-Object -First 1
        $ProductCode = $Registration.HasAttribute('Code') ? [string]$Registration.Code : [string]$Registration.Id
        $UpgradeCode = if ($RelatedBundle) { $RelatedBundle.HasAttribute('Code') ? [string]$RelatedBundle.Code : [string]$RelatedBundle.Id } else { $null }
        $Scope = switch -Regex ([string]$Registration.PerMachine) {
          '^(?i)(yes|1|true)$' { 'machine'; break }
          '^(?i)(no|0|false)$' { 'user'; break }
          default { $null }
        }
        $Info = [pscustomobject]@{
          InstallerType  = 'Burn'
          ProductCode    = $ProductCode
          UpgradeCode    = $UpgradeCode
          DisplayName    = [string]$Arp.DisplayName
          DisplayVersion = [string]$Arp.DisplayVersion
          Publisher      = [string]$Arp.Publisher
          Scope          = $Scope
        }
        if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { $Info.DisplayName = Read-ProductNameFromBurn -Path $Path }
        if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { $Info.DisplayVersion = Read-ProductVersionFromExe -Path $Path }
        return [pscustomobject]@{ ParserName = 'Burn'; InputObject = @($Info) }
      }
      'nullsoft' {
        $Info = Get-NSISInfo -Path $Path
        if ($Info.PSObject.Properties.Name -contains 'InstallerType' -and $Info.InstallerType -cne 'Nullsoft') {
          throw "The parser identified '$($Info.InstallerType)', not Nullsoft"
        }
        return [pscustomobject]@{ ParserName = 'NSIS'; InputObject = @($Info) }
      }
      'inno' {
        $Info = Get-InnoInfo -Path $Path
        if ($Info.PSObject.Properties.Name -contains 'InstallerType' -and $Info.InstallerType -cne 'Inno') {
          throw "The parser identified '$($Info.InstallerType)', not Inno"
        }
        return [pscustomobject]@{ ParserName = 'Inno Setup'; InputObject = @($Info) }
      }
      { $_ -cin @('msix', 'appx') } {
        $Info = Get-MSIXInfo -Path $Path -InstallerTypeHint $InstallerType
        if ($Info.InstallerType -cne $InstallerType) {
          throw "The package is '$($Info.InstallerType)', not '$InstallerType'"
        }
        $ManifestIdentityInfo = [pscustomobject]@{
          DisplayVersion = $Info.Version
          Publisher      = $Info.PublisherDisplayName
        }
        return [pscustomobject]@{ ParserName = 'MSIX/AppX'; InputObject = @($ManifestIdentityInfo, $Info) }
      }
    }
  } catch {
    throw "Failed to validate and parse the manifest-declared '$InstallerType' installer: $($_.Exception.Message)"
  }
}

function Get-WinGetGenericInstallerManifestInfo {
  <#
  .SYNOPSIS
    Detect and parse the likely family of a generic EXE installer
  .PARAMETER Path
    The installer path
  .PARAMETER Architecture
    The architecture of the installer entry
  .PARAMETER InstallerSwitches
    The installer switches used to resolve command-line-selected identities
  .PARAMETER Logger
    The scriptblock or method used for warnings
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$Path,

    [Parameter(HelpMessage = 'The architecture of the installer entry')]
    [ValidateSet('x86', 'x64', 'arm64', 'neutral')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The installer switches used by the manifest')]
    [System.Collections.IDictionary]$InstallerSwitches,

    [Parameter(Mandatory, HelpMessage = 'The scriptblock or method used for warnings')]
    $Logger
  )

  try {
    $Analysis = Get-WinGetInstallerAnalysis -Path $Path
  } catch {
    $Logger.Invoke("Failed to detect the generic EXE installer family: $($_.Exception.Message)", 'Warning')
    return $null
  }

  $SuccessfulParser = $Analysis.ParserResults | Where-Object { $_.Success -and $_.Result } | Select-Object -First 1
  if ($SuccessfulParser) {
    # Analyzer parser results are produced by the corresponding Get-*Info function.
    $Metadata = $SuccessfulParser.Result.PSObject.Properties.Name -contains 'Metadata' ? $SuccessfulParser.Result.Metadata : $null
    if ($SuccessfulParser.Name -ceq 'Advanced Installer') {
      if (-not $Metadata) { throw 'Advanced Installer detection did not return parser metadata' }
      $SelectionProperty = $Metadata.PSObject.Properties['MsiPayloadSelection']
      $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
      if ($Selection -and $Selection.SourceKind -ceq 'Download') {
        throw "Advanced Installer selects the online MSI from MainAppURL '$($Selection.MainAppUrl)'; the embedded files do not represent the installer payload"
      }
      $MsiInfoArguments = @{ Installer = $Metadata }
      if ($Architecture -cin @('x86', 'x64', 'arm64')) { $MsiInfoArguments.Architecture = $Architecture }
      $MsiInfo = Get-AdvancedInstallerMsiInfo @MsiInfoArguments
    } else {
      $MsiInfo = $SuccessfulParser.Result.PSObject.Properties.Name -contains 'MsiInfo' ? $SuccessfulParser.Result.MsiInfo : $null
    }
    $CommandLineMetadata = $null
    if ($SuccessfulParser.Name -ceq 'Chromium Setup' -and $InstallerSwitches) {
      $ProductCode = Resolve-ChromiumSetupProductCode -Info $SuccessfulParser.Result -InstallerSwitches $InstallerSwitches
      if (-not [string]::IsNullOrWhiteSpace($ProductCode)) {
        $CommandLineMetadata = [pscustomobject]@{ ProductCode = $ProductCode }
      }
    }
    $ParserOutputs = @($MsiInfo, $CommandLineMetadata, $Metadata, $SuccessfulParser.Result) | Where-Object { $null -ne $_ }
    $WarningsProperty = $null -eq $Metadata ? $null : $Metadata.PSObject.Properties['Warnings']
    return [pscustomobject]@{
      ParserName      = $SuccessfulParser.Name
      InputObject     = @($ParserOutputs)
      SelectedMsiPath = $null -eq $MsiInfo ? $null : $MsiInfo.SelectedMsiPath
      SelectionMethod = $null -eq $MsiInfo ? $null : $MsiInfo.SelectionMethod
      Warnings        = $null -eq $WarningsProperty ? @() : @($WarningsProperty.Value)
    }
  }

  # InstallShield currently has reliable bounded markers but no analyzer parser action.
  $InstallShieldCandidate = $Analysis.FamilyCandidates | Where-Object { $_.Family -ceq 'InstallShield' } | Select-Object -First 1
  if ($InstallShieldCandidate) {
    $TemporaryPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Path -DestinationPath $TemporaryPath
      if (-not $Info.HasMsi) {
        throw "The InstallShield '$($Info.Variant)' payload does not contain an MSI selected by the bootstrapper"
      }
      $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info
      return [pscustomobject]@{
        ParserName      = 'InstallShield'
        InputObject     = @($MsiInfo, $Info)
        SelectedMsiPath = $MsiInfo.SelectedMsiPath
        SelectionMethod = $MsiInfo.SelectionMethod
        Warnings        = @($Info.Warnings)
      }
    } catch {
      $Logger.Invoke("InstallShield was detected, but its metadata parser failed: $($_.Exception.Message)", 'Warning')
      return $null
    } finally {
      Remove-Item -LiteralPath $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue -ProgressAction SilentlyContinue
    }
  }

  $CandidateNames = @($Analysis.FamilyCandidates | Select-Object -ExpandProperty Family -Unique)
  $FailedParsers = @($Analysis.ParserResults | Where-Object { $_.Success -eq $false -and $_.Error } | ForEach-Object { "$($_.Name): $($_.Error)" })
  $Evidence = if ($CandidateNames.Count -gt 0) { " Candidates: $($CandidateNames -join ',')." } else { '' }
  if ($FailedParsers.Count -gt 0 -and $CandidateNames.Count -gt 0) { $Evidence += " Parser errors: $($FailedParsers -join '; ')" }
  $Logger.Invoke("No supported generic EXE parser produced installer metadata.$Evidence", 'Warning')
  return $null
}

function Set-WinGetInstallerManifestMetadata {
  <#
  .SYNOPSIS
    Update fields already present in an installer entry from normalized parser metadata
  .PARAMETER Installer
    The installer entry to update
  .PARAMETER OldInstaller
    The previous installer entry
  .PARAMETER InstallerEntry
    Explicit task input that takes priority over parser metadata
  .PARAMETER Metadata
    Normalized parser metadata
  .PARAMETER ParserName
    The parser name used in diagnostics
  .PARAMETER Strict
    Throw instead of warning when an existing field cannot be updated
  .PARAMETER Logger
    The scriptblock or method used for warnings
  #>
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Installer,
    [Parameter(Mandatory)][System.Collections.IDictionary]$OldInstaller,
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerEntry,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Metadata,
    [Parameter(Mandatory)][string]$ParserName,
    [switch]$Strict,
    [Parameter(Mandatory)]$Logger
  )

  $ReportFailure = {
    param([string]$Field)
    $Message = "$ParserName did not return a value for existing installer field '$Field'"
    if ($Strict) { throw $Message }
    $Logger.Invoke($Message, 'Warning')
  }
  $HasScalarValue = { param($Value) $null -ne $Value -and -not ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) }
  $UnresolvedFields = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Field in @($Metadata['UnresolvedFields'])) {
    if (-not [string]::IsNullOrWhiteSpace($Field)) { $null = $UnresolvedFields.Add([string]$Field) }
  }

  $NeedsAppsAndFeaturesMetadata = ($Installer.Contains('ProductCode') -and -not $InstallerEntry.Contains('ProductCode')) -or ([bool]$Installer['AppsAndFeaturesEntries'] -and -not $InstallerEntry.Contains('AppsAndFeaturesEntries'))
  if ($Metadata.Contains('WritesAppsAndFeaturesEntry') -and -not [bool]$Metadata.WritesAppsAndFeaturesEntry -and $NeedsAppsAndFeaturesMetadata) {
    $Message = "$ParserName reports that the outer installer does not write a visible Apps & Features entry; existing ARP metadata belongs to a nested payload or custom registration"
    if ($Strict) { throw $Message }
    $Logger.Invoke($Message, 'Warning')
    return
  }

  foreach ($Field in @('ProductCode', 'SignatureSha256', 'PackageFamilyName', 'MinimumOSVersion')) {
    if (-not $Installer.Contains($Field) -or $InstallerEntry.Contains($Field) -or $UnresolvedFields.Contains($Field)) { continue }
    if ($Metadata.Contains($Field) -and (& $HasScalarValue $Metadata[$Field])) {
      $Installer[$Field] = $Metadata[$Field]
    } else {
      & $ReportFailure $Field
    }
  }

  foreach ($Field in @('Platform', 'Capabilities', 'RestrictedCapabilities')) {
    if (-not $Installer.Contains($Field) -or $InstallerEntry.Contains($Field)) { continue }
    if ($Metadata.Contains($Field)) {
      $Installer[$Field] = @($Metadata[$Field])
    } else {
      & $ReportFailure $Field
    }
  }

  $TaskOverridesDefaultInstallLocation = $InstallerEntry.Contains('InstallationMetadata') -and $InstallerEntry.InstallationMetadata -is [System.Collections.IDictionary] -and $InstallerEntry.InstallationMetadata.Contains('DefaultInstallLocation')
  if ($Installer.Contains('InstallationMetadata') -and $Installer.InstallationMetadata -is [System.Collections.IDictionary] -and $Installer.InstallationMetadata.Contains('DefaultInstallLocation') -and -not $TaskOverridesDefaultInstallLocation -and -not $UnresolvedFields.Contains('DefaultInstallLocation')) {
    if ($Metadata.Contains('DefaultInstallLocation') -and (& $HasScalarValue $Metadata.DefaultInstallLocation)) {
      $Installer.InstallationMetadata.DefaultInstallLocation = $Metadata.DefaultInstallLocation
    } elseif (-not $Strict) {
      & $ReportFailure 'InstallationMetadata.DefaultInstallLocation'
    }
  }

  if (-not $Installer.Contains('AppsAndFeaturesEntries') -or -not $Installer.AppsAndFeaturesEntries -or $InstallerEntry.Contains('AppsAndFeaturesEntries')) { return }

  $UpgradeCode = $Metadata['UpgradeCode']
  $MatchingEntries = @($Installer.AppsAndFeaturesEntries | Where-Object {
      ($UpgradeCode -and $_['UpgradeCode'] -and $UpgradeCode -ceq $_.UpgradeCode) -or
      ($OldInstaller['ProductCode'] -and $_['ProductCode'] -and $OldInstaller.ProductCode -ceq $_.ProductCode) -or
      ($Installer.AppsAndFeaturesEntries.Count -eq 1)
    })
  if ($MatchingEntries.Count -eq 0) {
    $Message = "$ParserName metadata did not match any existing AppsAndFeaturesEntries item"
    if ($Strict) { throw $Message }
    $Logger.Invoke($Message, 'Warning')
    return
  }

  $AppsAndFeaturesMap = [ordered]@{
    DisplayName    = 'DisplayName'
    DisplayVersion = 'DisplayVersion'
    Publisher      = 'Publisher'
    ProductCode    = 'ProductCode'
    UpgradeCode    = 'UpgradeCode'
    InstallerType  = 'AppsAndFeaturesInstallerType'
  }
  foreach ($Entry in $MatchingEntries) {
    if ($Metadata.Contains('AppsAndFeaturesInstallerType') -and (& $HasScalarValue $Metadata.AppsAndFeaturesInstallerType)) {
      $InheritedInstallerType = [string]($Installer.Contains('NestedInstallerType') ? $Installer['NestedInstallerType'] : $Installer['InstallerType'])
      if ($Metadata.AppsAndFeaturesInstallerType -ceq $InheritedInstallerType) {
        # The ARP entry inherits the effective installer type; remove redundant values left by earlier updates.
        if ($Entry.Contains('InstallerType')) { $Entry.Remove('InstallerType') }
      } elseif (-not $Entry.Contains('InstallerType')) {
        # Materialize an incompatible ARP type, such as a WiX MSI exposing an EXE-style custom uninstall key.
        $Entry['InstallerType'] = $Metadata.AppsAndFeaturesInstallerType
      }
    }
    foreach ($Field in $AppsAndFeaturesMap.Keys) {
      if (-not $Entry.Contains($Field)) { continue }
      $MetadataField = $AppsAndFeaturesMap[$Field]
      if ($UnresolvedFields.Contains($MetadataField)) { continue }
      if ($Metadata.Contains($MetadataField) -and (& $HasScalarValue $Metadata[$MetadataField])) {
        $Entry[$Field] = $Metadata[$MetadataField]
      } else {
        & $ReportFailure "AppsAndFeaturesEntries.$Field"
      }
    }
  }
}

function Update-WinGetInstallerManifestInstallerMetadata {
  <#
  .SYNOPSIS
    Update the metadata of the installer entry
  .DESCRIPTION
    Update the metadata of the installer entry using the provided installer metadata
  .PARAMETER Installer
    The installer to update
  .PARAMETER OldInstaller
    The old installer for reference
  .PARAMETER InstallerEntry
    The installer entry to use for updating the installer
  .PARAMETER Installers
    The installers that have updated for reference (e.g., hashes)
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The installer to update')]
    [System.Collections.IDictionary]$Installer,
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installer for reference')]
    [System.Collections.IDictionary]$OldInstaller,
    [Parameter(Mandatory, HelpMessage = 'The installer entry to use for updating the installer')]
    [System.Collections.IDictionary]$InstallerEntry,
    [Parameter(HelpMessage = 'The installers that have updated for reference')]
    [System.Collections.IDictionary[]]$Installers = @(),
    [Parameter(HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  # Replace the whitespace in the installer URL with %20 to make it clickable
  # Keep the original URL for reference in downloading
  $OriginalInstallerUrl = $Installer.InstallerUrl
  $Installer.InstallerUrl = $Installer.InstallerUrl.Replace(' ', '%20')

  # Update the installer using the matching installer
  # The same bootstrapper URL can select different nested payloads by host architecture.
  $MatchingInstaller = $Installers | Where-Object -FilterScript { $_.InstallerUrl -ceq $Installer.InstallerUrl -and $_.Architecture -ceq $Installer.Architecture } | Select-Object -First 1
  if ($MatchingInstaller -and ($Installer.Contains('NestedInstallerFiles') ? ((ConvertTo-Json -InputObject $Installer.NestedInstallerFiles -Depth 10 -Compress) -ceq (ConvertTo-Json -InputObject $MatchingInstaller.NestedInstallerFiles -Depth 10 -Compress)) : $true)) {
    foreach ($Key in @('InstallerSha256', 'SignatureSha256', 'PackageFamilyName', 'ProductCode', 'ReleaseDate', 'AppsAndFeaturesEntries')) {
      if ($MatchingInstaller.Contains($Key) -and -not $InstallerEntry.Contains($Key)) {
        $Installer.$Key = $MatchingInstaller.$Key
      } elseif (-not $MatchingInstaller.Contains($Key) -and $Installer.Contains($Key)) {
        $Installer.Remove($Key)
      }
    }
  }

  # Analyze cached installer files even when the task supplied a hash for update detection.
  $HasCachedInstallerFile = $InstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $InstallerFiles[$OriginalInstallerUrl])
  if (-not $Installer.Contains('InstallerSha256') -or $HasCachedInstallerFile) {
    if ($Script:WinGetTempInstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $Script:WinGetTempInstallerFiles[$OriginalInstallerUrl])) {
      # Skip downloading if the installer file is already downloaded
      $InstallerPath = $Script:WinGetTempInstallerFiles[$OriginalInstallerUrl]
    } elseif ($InstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $InstallerFiles[$OriginalInstallerUrl])) {
      # Skip downloading if the installer file was previously downloaded
      $InstallerPath = $InstallerFiles[$OriginalInstallerUrl]
    } elseif ($Script:WinGetInstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $Script:WinGetInstallerFiles[$OriginalInstallerUrl])) {
      # Skip downloading if the installer file was previously downloaded
      $InstallerPath = $Script:WinGetInstallerFiles[$OriginalInstallerUrl]
    } else {
      $Logger.Invoke("Downloading $($Installer.InstallerUrl)", 'Verbose')
      $InstallerPath = New-TempFile
      $DownloadResult = Invoke-WinGetInstallerDownload -Uri $Installer.InstallerUrl -DestinationPath $InstallerPath
      $Script:WinGetTempInstallerFiles[$OriginalInstallerUrl] = $InstallerPath = $DownloadResult.DestinationPath
    }

    $Logger.Invoke('Processing installer data...', 'Verbose')

    # Get installer SHA256
    $Installer.InstallerSha256 = (Get-FileHash -Path $InstallerPath -Algorithm SHA256).Hash

    # Extract only the selected nested installer instead of expanding a potentially giant ZIP archive.
    $EffectiveInstallerType = $Installer.Contains('NestedInstallerType') ? $Installer.NestedInstallerType : $Installer.InstallerType
    $EffectiveInstallerPath = if ($Installer.InstallerType -cin @('zip') -and $Installer.NestedInstallerType -cne 'portable') {
      $NestedInstallerRelativePath = $Installer.NestedInstallerFiles[0].RelativeFilePath
      Expand-TempArchive -Path $InstallerPath -RelativeFilePath $NestedInstallerRelativePath | Join-Path -ChildPath $NestedInstallerRelativePath
    } else {
      $InstallerPath
    }

    $KnownInstallerTypes = @('msi', 'wix', 'burn', 'nullsoft', 'inno', 'msix', 'appx')
    if ($EffectiveInstallerType -cin $KnownInstallerTypes) {
      # Known WinGet types are authoritative: family validation, parsing, and field updates must all succeed.
      $ParserInfo = Get-WinGetKnownInstallerManifestInfo -Path $EffectiveInstallerPath -InstallerType $EffectiveInstallerType
      $WarningsProperty = $ParserInfo.PSObject.Properties['Warnings']
      $ParserWarnings = $null -eq $WarningsProperty ? @() : @($WarningsProperty.Value)
      foreach ($Warning in @($ParserWarnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)) {
        $Logger.Invoke("$($ParserInfo.ParserName): $Warning", 'Warning')
      }
      $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject $ParserInfo.InputObject -InstallerType $EffectiveInstallerType -OldInstaller $OldInstaller
      Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $InstallerEntry -Metadata $Metadata -ParserName $ParserInfo.ParserName -Strict -Logger $Logger
    } elseif ($EffectiveInstallerType -ceq 'exe') {
      # Generic EXE families are best effort because static detection can be ambiguous or unsupported.
      try {
        $ParserInfoArguments = @{
          Path         = $EffectiveInstallerPath
          Architecture = $Installer.Architecture
          Logger       = $Logger
        }
        if ($Installer.Contains('InstallerSwitches') -and $Installer.InstallerSwitches -is [System.Collections.IDictionary]) {
          $ParserInfoArguments.InstallerSwitches = $Installer.InstallerSwitches
        }
        $ParserInfo = Get-WinGetGenericInstallerManifestInfo @ParserInfoArguments
        if ($ParserInfo) {
          $WarningsProperty = $ParserInfo.PSObject.Properties['Warnings']
          $ParserWarnings = $null -eq $WarningsProperty ? @() : @($WarningsProperty.Value)
          foreach ($Warning in @($ParserWarnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)) {
            $Logger.Invoke("$($ParserInfo.ParserName): $Warning", 'Warning')
          }
          if (-not [string]::IsNullOrWhiteSpace([string]$ParserInfo.SelectedMsiPath)) {
            $Logger.Invoke("$($ParserInfo.ParserName) selected MSI '$($ParserInfo.SelectedMsiPath)' using '$($ParserInfo.SelectionMethod)'", 'Verbose')
          }
          $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject $ParserInfo.InputObject -InstallerType $EffectiveInstallerType -OldInstaller $OldInstaller
          Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $InstallerEntry -Metadata $Metadata -ParserName $ParserInfo.ParserName -Logger $Logger
        }
      } catch {
        $Logger.Invoke("Failed to update generic EXE metadata: $($_.Exception.Message)", 'Warning')
      }
    }
  }

  # Beautify entries
  if ($Installer.Contains('Commands')) { $Installer.Commands = @($Installer.Commands | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
  if ($Installer.Contains('Protocols')) { $Installer.Protocols = @($Installer.Protocols | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
  if ($Installer.Contains('FileExtensions')) { $Installer.FileExtensions = @($Installer.FileExtensions | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }

  return $Installer
}

function Update-WinGetInstallerManifestInstallers {
  <#
  .SYNOPSIS
    Update the installers of the manifest
  .DESCRIPTION
    Iterate over the installers of the old manifest and update them using the provided installer entries
  .PARAMETER OldInstallers
    The old installers to update
  .PARAMETER InstallerEntries
    The installer entries to use for updating the installers
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installers to update')]
    [System.Collections.IDictionary[]]$OldInstallers,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installers')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  $iteration = 0
  $Installers = @()
  foreach ($OldInstaller in $OldInstallers) {
    $iteration += 1
    $Logger.Invoke("Updating installer #${iteration}/$($OldInstallers.Count) [$($OldInstaller['InstallerLocale']), $($OldInstaller['Architecture']), $($OldInstaller['InstallerType']), $($OldInstaller['NestedInstallerType']), $($OldInstaller['Scope'])]", 'Verbose')

    # Apply inputs
    $MatchingInstallerEntry = $null
    foreach ($InstallerEntry in $InstallerEntries) {
      $Updatable = $true
      # Find matching installer entry
      if ($InstallerEntry.Contains('Query')) {
        if ($InstallerEntry.Query -is [scriptblock]) {
          # The installer entry will be chosen if the scriptblock passed with the installer entry returns something
          if (-not (Invoke-Command -ScriptBlock $InstallerEntry.Query -InputObject $OldInstaller)) {
            $Updatable = $false
          }
        } elseif ($InstallerEntry.Query -is [System.Collections.IDictionary]) {
          # The installer entry will be chosen if the installer contain all the keys present in the installer entry Query field, and their values are the same
          foreach ($Key in $InstallerEntry.Query.Keys) {
            if ($OldInstaller.Contains($Key) -and $OldInstaller.$Key -cne $InstallerEntry.Query.$Key) {
              # Skip this entry if the installer has this key, but with a different value
              $Updatable = $false
            } elseif (-not $OldInstaller.Contains($Key)) {
              # Skip this entry if the installer doesn't have this key
              $Updatable = $false
            }
          }
        } else {
          throw 'The installer entry Query field should be either a scriptblock or a dictionary'
        }
      } else {
        # The installer entry will be chosen if the installer contain all the keys present in the installer entry, and their values are the same
        foreach ($Key in @('InstallerLocale', 'Architecture', 'InstallerType', 'NestedInstallerType', 'Scope')) {
          if ($InstallerEntry.Contains($Key) -and $OldInstaller.Contains($Key) -and $OldInstaller.$Key -cne $InstallerEntry.$Key) {
            # Skip this entry if the installer has this key, but with a different value
            $Updatable = $false
          } elseif ($InstallerEntry.Contains($Key) -and -not $OldInstaller.Contains($Key)) {
            # Skip this entry if the installer doesn't have this key
            $Updatable = $false
          }
        }
      }
      # If the installer entry matches the installer, use the last matching entry for updating the installer
      if ($Updatable) {
        $MatchingInstallerEntry = $InstallerEntry
      }
    }
    # If no matching installer entry is found, throw an error
    if (-not $MatchingInstallerEntry) {
      throw "No matching installer entry for [$($OldInstaller['InstallerLocale']), $($OldInstaller['Architecture']), $($OldInstaller['InstallerType']), $($OldInstaller['tNestedInstallerType']), $($OldInstaller['Scope'])]"
    }

    # Deep copy the old installer
    $Installer = $OldInstaller | Copy-Object

    # Clean up volatile fields
    $Installer.Remove('InstallerSha256')
    if ($Installer.Contains('ReleaseDate')) { $Installer.Remove('ReleaseDate') }

    # Update the installer using the matching installer entry
    foreach ($Key in $MatchingInstallerEntry.Keys) {
      if ($Key -ceq 'Query') {
        # Skip the entries used for matching
        continue
      } elseif (-not $MatchingInstallerEntry.Contains('Query') -and $Key -cin @('InstallerLocale', 'Architecture', 'InstallerType', 'NestedInstallerType', 'Scope')) {
        # Skip the entries used for matching if Query is not present
        continue
      } elseif ($Key -cnotin (Get-WinGetManifestSchema -ManifestType 'installer').definitions.Installer.properties.Keys) {
        # Check if the key is a valid installer property
        throw "The installer entry has an invalid key: ${Key}"
      } else {
        try {
          $null = Test-YamlObject -InputObject $MatchingInstallerEntry.$Key -Schema (Get-WinGetManifestSchema -ManifestType 'installer').properties.Installers.items.properties.$Key -WarningAction Stop
          $Installer.$Key = $MatchingInstallerEntry.$Key
        } catch {
          $Logger.Invoke("The new value of the installer property `"${Key}`" is invalid and thus discarded: ${_}", 'Warning')
        }
      }
    }

    $Installer = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $MatchingInstallerEntry -Installers $Installers -InstallerFiles $InstallerFiles -Logger $Logger

    # Add the updated installer to the new installers array
    $Installers += $Installer
  }

  # Remove the downloaded files
  foreach ($InstallerPath in $Script:WinGetTempInstallerFiles.Values) {
    Remove-Item -Path $InstallerPath -Force -ErrorAction 'Continue'
  }
  $Script:WinGetTempInstallerFiles.Clear()

  return $Installers
}

function Set-WinGetInstallerManifestInstallers {
  <#
  .SYNOPSIS
    Replace the installers of the manifest
  .DESCRIPTION
    Iterate over the installer entries and update the matching installers using the provided installer entries
  .PARAMETER OldInstallers
    The old installers to update
  .PARAMETER InstallerEntries
    The installer entries to use for updating the installers
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installers to update')]
    [System.Collections.IDictionary[]]$OldInstallers,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installers')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  $iteration = 0
  $Installers = @()
  foreach ($InstallerEntry in $InstallerEntries) {
    $iteration += 1
    $Logger.Invoke("Applying installer entry #${iteration}/$($InstallerEntries.Count)", 'Verbose')

    # Find matching installer
    $MatchingInstaller = $null
    foreach ($OldInstaller in $OldInstallers) {
      $Updatable = $true
      # If Query is present, select the installer based on the query. If not, select the first installer
      if ($InstallerEntry.Contains('Query')) {
        # The installer will be chosen if the scriptblock passed with the installer returns something
        if ($InstallerEntry.Query -is [scriptblock]) {
          if (-not (Invoke-Command -ScriptBlock $InstallerEntry.Query -InputObject $OldInstaller)) {
            $Updatable = $false
          }
        } elseif ($InstallerEntry.Query -is [System.Collections.IDictionary]) {
          # The installer will be chosen if the installer contain all the keys present in the installer entry Query field, and their values are the same
          foreach ($Key in $InstallerEntry.Query.Keys) {
            if ($OldInstaller.Contains($Key) -and $OldInstaller.$Key -cne $InstallerEntry.Query.$Key) {
              # Skip this entry if the installer has this key, but with a different value
              $Updatable = $false
            } elseif (-not $OldInstaller.Contains($Key)) {
              # Skip this entry if the installer doesn't have this key
              $Updatable = $false
            }
          }
        } else {
          throw 'The installer entry Query field should be either a scriptblock or a dictionary'
        }
      }
      # If the installer entry matches the installers, use the first matching installer for updating
      if ($Updatable) {
        $MatchingInstaller = $OldInstaller
        break
      }
    }
    # If no matching installer entry is found, throw an error
    if (-not $MatchingInstaller) {
      throw 'No matching installer for the installer entry'
    }

    # Deep copy the old installer
    $Installer = $MatchingInstaller | Copy-Object

    # Clean up volatile fields
    $Installer.Remove('InstallerSha256')
    if ($Installer.Contains('ReleaseDate')) { $Installer.Remove('ReleaseDate') }

    # Update the installer using the matching installer entry
    foreach ($Key in $InstallerEntry.Keys) {
      if ($Key -ceq 'Query') {
        # Skip the entries used for matching
        continue
      } elseif ($Key -cnotin (Get-WinGetManifestSchema -ManifestType 'installer').definitions.Installer.properties.Keys) {
        # Check if the key is a valid installer property
        throw "The installer entry has an invalid key: ${Key}"
      } else {
        try {
          $null = Test-YamlObject -InputObject $InstallerEntry.$Key -Schema (Get-WinGetManifestSchema -ManifestType 'installer').properties.Installers.items.properties.$Key -WarningAction Stop
          $Installer.$Key = $InstallerEntry.$Key
        } catch {
          $Logger.Invoke("The new value of the installer property `"${Key}`" is invalid and thus discarded: ${_}", 'Warning')
        }
      }
    }

    $Installer = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $MatchingInstaller -InstallerEntry $InstallerEntry -Installers $Installers -InstallerFiles $InstallerFiles -Logger $Logger

    # Add the updated installer to the new installers array
    $Installers += $Installer
  }

  # Remove the downloaded files
  foreach ($InstallerPath in $Script:WinGetTempInstallerFiles.Values) {
    Remove-Item -Path $InstallerPath -Force -ErrorAction 'Continue'
  }
  $Script:WinGetTempInstallerFiles.Clear()

  return $Installers
}

function Update-WinGetVersionManifest {
  <#
  .SYNOPSIS
    Update the version manifest
  .DESCRIPTION
    Update the version manifest using the provided package version
  .PARAMETER OldVersionManifest
    The old version manifest to update
  .PARAMETER PackageVersion
    The package version to use for updating the version manifest
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old version manifest to update')]
    [System.Collections.IDictionary]$OldVersionManifest,
    [Parameter(Mandatory, HelpMessage = 'The package version to use for updating the version manifest')]
    [string]$PackageVersion
  )

  # Deep copy the old version manifest
  $VersionManifest = $OldVersionManifest | Copy-Object

  return ConvertTo-SortedYamlObject -InputObject $VersionManifest -Schema (Get-WinGetManifestSchema -ManifestType 'version') -Culture $Script:Culture
}

function Update-WinGetInstallerManifest {
  <#
  .SYNOPSIS
    Update the installer manifest
  .DESCRIPTION
    Update the installer manifest using the provided installer entries
  .PARAMETER OldInstallerManifest
    The old installer manifest to update
  .PARAMETER InstallerEntries
    The installer entries to use for updating the installer manifest
  .PARAMETER PackageVersion
    The package version to use for updating the installer manifest
  .PARAMETER Replace
    Replace the installers rather than updating them
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installer manifest to update')]
    [System.Collections.IDictionary]$OldInstallerManifest,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installer manifest')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(Mandatory, HelpMessage = 'The package version to use for updating the installer manifest')]
    [string]$PackageVersion,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles,
    [Parameter(HelpMessage = 'Replace the installers rather than updating them')]
    [switch]$Replace = $false,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  # Deep copy the old installer manifest
  $InstallerManifest = $OldInstallerManifest | Copy-Object

  # Move Manifest Level Keys to installer Level
  $InstallerSchema = Get-WinGetManifestSchema -ManifestType 'installer'
  Move-KeysToInstallerLevel -Manifest $InstallerManifest -Installers $InstallerManifest.Installers -Property $InstallerSchema.definitions.Installer.properties.Keys.Where({ $_ -cin $InstallerSchema.properties.Keys })
  # Update installer entries
  if (-not $Replace) {
    $InstallerManifest.Installers = Update-WinGetInstallerManifestInstallers -OldInstallers $InstallerManifest.Installers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles -Logger $Logger
  } else {
    $InstallerManifest.Installers = Set-WinGetInstallerManifestInstallers -OldInstallers $InstallerManifest.Installers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles -Logger $Logger
  }
  # Move Installer Level Keys to Manifest Level
  $InstallerSchema = Get-WinGetManifestSchema -ManifestType 'installer'
  Move-KeysToManifestLevel -Installers $InstallerManifest.Installers -Manifest $InstallerManifest -Property $InstallerSchema.definitions.Installer.properties.Keys.Where({ $_ -cin $InstallerSchema.properties.Keys })

  return ConvertTo-SortedYamlObject -InputObject $InstallerManifest -Schema $InstallerSchema -Culture $Script:Culture
}

function Update-WinGetLocaleManifest {
  <#
  .SYNOPSIS
    Update the locale manifest
  .DESCRIPTION
    Update the locale manifest using the provided locale entries
  .PARAMETER PackageVersion
    The package version to use for updating the locale manifest
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old locale manifests to update')]
    [System.Collections.IDictionary[]]$OldLocaleManifests,
    [Parameter(HelpMessage = 'The locale entries to use for updating the locale manifests')]
    [System.Collections.IDictionary[]]$LocaleEntries = @(),
    [Parameter(Mandatory, HelpMessage = 'The package version to use for updating the locale manifest')]
    [string]$PackageVersion,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  $LocaleManifests = @()

  # Installer parser metadata is not authoritative for locale PackageName or Publisher.
  # Locale identity changes only when a task supplies an explicit locale entry.
  # Copy over all locale files from previous version that aren't the same
  foreach ($OldLocaleManifest in $OldLocaleManifests) {
    $LocaleManifest = $OldLocaleManifest | Copy-Object

    # Clean up volatile fields
    if ($LocaleManifest.Contains('ReleaseNotes')) { $LocaleManifest.Remove('ReleaseNotes') }
    # Update Copyright
    if ($LocaleManifest.Contains('Copyright')) {
      $Match = [regex]::Matches($LocaleManifest.Copyright, '20\d{2}(?!-)')
      if ($Match.Count -gt 0) {
        $LatestYear = $Match.Value | Sort-Object -Bottom 1
        $Match.Where({ $_.Value -eq $LatestYear }).ForEach({ $LocaleManifest.Copyright = $LocaleManifest.Copyright.Remove($_.Index, $_.Length).Insert($_.Index, (Get-Date).Year.ToString()) })
      }
    }

    # Apply inputs
    if ($LocaleEntries) {
      foreach ($LocaleEntry in $LocaleEntries) {
        if (-not $LocaleEntry.Contains('Key') -or -not $LocaleEntry.Contains('Value') -or [string]::IsNullOrWhiteSpace($LocaleEntry.Key)) {
          # Check if the locale entry contains the required properties
          throw 'The locale entry does not contain the required properties'
        } elseif ($LocaleEntry.Contains('Locale') -and $LocaleEntry.Locale -notmatch (Get-WinGetManifestSchema -ManifestType $LocaleManifest.ManifestType).properties.PackageLocale.pattern) {
          # Check if the locale property is a valid locale
          throw "The locale entry has an invalid locale `"$($LocaleEntry.Locale)`" contains an invalid locale"
        } elseif ($LocaleEntry.Contains('Locale') -and $LocaleEntry.Locale -notcontains $LocaleManifest.PackageLocale) {
          # If the locale entry contains a locale property, only match the locale manifests with these locales
          continue
        } elseif ($LocaleEntry.Key -cnotin (Get-WinGetManifestSchema -ManifestType $LocaleManifest.ManifestType).properties.Keys) {
          # Check if the key property is a valid locale property
          throw "The locale entry has an invalid key `"$($LocaleEntry.Key)`""
        } elseif ($null -ceq $LocaleEntry.Value) {
          # If the value is null, remove the key from the locale manifest
          $LocaleManifest.Remove($LocaleEntry.Key)
        } elseif ($LocaleEntry.Value -is [scriptblock]) {
          $LocaleManifest[$LocaleEntry.Key] = $LocaleManifest[$LocaleEntry.Key] | ForEach-Object -Process $LocaleEntry.Value
        } else {
          try {
            if (Test-YamlObject -InputObject $LocaleEntry.Value -Schema (Get-WinGetManifestSchema -ManifestType $LocaleManifest.ManifestType).properties[$LocaleEntry.Key] -WarningAction Stop) {
              $LocaleManifest[$LocaleEntry.Key] = $LocaleEntry.Value
            } else {
              $Logger.Invoke("The locale entry `"$($LocaleEntry.Key)`" has an invalid value and thus discarded", 'Warning')
            }
          } catch {
            $Logger.Invoke("The locale entry `"$($LocaleEntry.Key)`" has an invalid value and thus discarded: ${_}", 'Warning')
          }
        }
      }
    }

    if ($LocaleManifest.Contains('Tags')) { $LocaleManifest.Tags = @($LocaleManifest.Tags | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
    if ($LocaleManifest.Contains('Moniker')) {
      if ($LocaleManifest.ManifestType -ceq 'defaultLocale') {
        $LocaleManifest['Moniker'] = $LocaleManifest['Moniker'] | ToLower | NoWhitespace
      } else {
        $LocaleManifest.Remove('Moniker')
      }
    }

    $Schema = Get-WinGetManifestSchema -ManifestType $LocaleManifest.ManifestType
    $LocaleManifests += ConvertTo-SortedYamlObject -InputObject $LocaleManifest -Schema $Schema -Culture $Script:Culture
  }

  return $LocaleManifests
}

function Update-WinGetManifestPackageVersion {
  <#
  .SYNOPSIS
    Update the package version in the manifests
  .DESCRIPTION
    Update the package version in the installer, locale and version manifests
  .PARAMETER Manifest
    The manifests to update
  .PARAMETER PackageVersion
    The package version to use for updating the manifests
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(ValueFromPipeline, Position = 0, Mandatory, HelpMessage = 'The manifests to update')]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Mandatory, HelpMessage = 'The package version to use for updating the manifests')]
    [string]$PackageVersion
  )

  process {
    $Manifest.PackageVersion = $PackageVersion
    return $Manifest
  }
}

function Update-WinGetManifestVersion {
  <#
  .SYNOPSIS
    Update the manifest version in the manifests
  .DESCRIPTION
    Update the manifest version in the installer, locale and version manifests
  .PARAMETER Manifest
    The manifests to update
  .PARAMETER ManifestVersion
    The manifest version to use for updating the manifests
  #>
  param (
    [Parameter(ValueFromPipeline, Position = 0, Mandatory, HelpMessage = 'The manifests to update')]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(HelpMessage = 'The manifest version to use for updating the manifests')]
    [string]$ManifestVersion = $ManifestVersion
  )

  process {
    $Manifest.ManifestVersion = $ManifestVersion
    return $Manifest
  }
}

function Update-WinGetManifestPackageIdentifier {
  <#
  .SYNOPSIS
    Update the package identifier in the manifests
  .DESCRIPTION
    Update the package identifier in the installer, locale and version manifests
  .PARAMETER Manifest
    The manifests to update
  .PARAMETER PackageIdentifier
    The package identifier to use for updating the manifests
  #>
  param (
    [Parameter(ValueFromPipeline, Position = 0, Mandatory, HelpMessage = 'The manifests to update')]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Mandatory, HelpMessage = 'The package identifier to use for updating the manifests')]
    [string]$PackageIdentifier
  )

  process {
    $Manifest.PackageIdentifier = $PackageIdentifier
    return $Manifest
  }
}

function Update-WinGetManifests {
  <#
  .SYNOPSIS
    Update WinGet package manifests
  .DESCRIPTION
    Update WinGet package manifests using the provided installer and locale entries
  .PARAMETER NewPackageIdentifier
    The new package identifier of the manifests
  .PARAMETER PackageVersion
    The package version of the manifest
  .PARAMETER VersionManifest
    The version manifest to update
  .PARAMETER InstallerManifest
    The installer manifest to update
  .PARAMETER LocaleManifests
    The locale manifests to update
  .PARAMETER InstallerEntries
    The installer entries to be applied to the installer manifest
  .PARAMETER LocaleEntries
    The locale entries to be applied to the locale manifest
  .PARAMETER ReplaceInstallers
    Replace the installers rather than updating them
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(HelpMessage = 'The new package identifier of the manifests')]
    [string]$NewPackageIdentifier,
    [Parameter(Mandatory, HelpMessage = 'The package version of the manifest')]
    [string]$PackageVersion,
    [Parameter(Mandatory, HelpMessage = 'The version manifest to update')]
    [System.Collections.IDictionary]$VersionManifest,
    [Parameter(Mandatory, HelpMessage = 'The installer manifest to update')]
    [System.Collections.IDictionary]$InstallerManifest,
    [Parameter(Mandatory, HelpMessage = 'The locale manifests to update')]
    [System.Collections.IDictionary[]]$LocaleManifests,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to be applied to the installer manifest')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(HelpMessage = 'The locale entries to be applied to the locale manifest')]
    [System.Collections.IDictionary[]]$LocaleEntries = @(),
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles = @(),
    [Parameter(HelpMessage = 'Replace the installers rather than updating them')]
    [switch]$ReplaceInstallers = $false,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  return [ordered]@{
    Installer = Update-WinGetInstallerManifest -OldInstallerManifest $InstallerManifest -InstallerEntries $InstallerEntries -PackageVersion $PackageVersion -InstallerFiles $InstallerFiles -Replace:$ReplaceInstallers -Logger $Logger | Update-WinGetManifestPackageVersion -PackageVersion $PackageVersion | Update-WinGetManifestVersion | Update-WinGetManifestPackageIdentifier -PackageIdentifier $NewPackageIdentifier
    Locale    = Update-WinGetLocaleManifest -OldLocaleManifests $LocaleManifests -LocaleEntries $LocaleEntries -PackageVersion $PackageVersion -Logger $Logger | Update-WinGetManifestPackageVersion -PackageVersion $PackageVersion | Update-WinGetManifestVersion | Update-WinGetManifestPackageIdentifier -PackageIdentifier $NewPackageIdentifier
    Version   = Update-WinGetVersionManifest -OldVersionManifest $VersionManifest -PackageVersion $PackageVersion | Update-WinGetManifestPackageVersion -PackageVersion $PackageVersion | Update-WinGetManifestVersion | Update-WinGetManifestPackageIdentifier -PackageIdentifier $NewPackageIdentifier
  }
}

function Convert-WinGetManifestsFromYaml {
  <#
  .SYNOPSIS
    Read the manifests for a package
  .DESCRIPTION
    Read the installer, locale and version manifests for a package using the provided package identifier and manifests path
  .PARAMETER Manifests
    The manifest(s) to read
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The manifest(s) to read')]
    $Manifests
  )

  process {
    # Read the main manifest to check the manifest type
    $MainManifest = $Manifests.Version | ConvertFrom-Yaml -Ordered
    if ($MainManifest.ManifestType -ceq 'version') {
      $ManifestType = 'MultiManifest'
      $PackageLocale = $MainManifest.DefaultLocale
    } elseif ($MainManifest.ManifestType -ceq 'singleton') {
      $ManifestType = 'SingletonManifest'
      $PackageLocale = $MainManifest.PackageLocale
    } else {
      throw "Unrecognized manifest type $($MainManifest.ManifestType)"
    }

    if ($ManifestType -ceq 'MultiManifest') {
      # If the manifest type is MultiManifest, read the remaining installer and locale manifests
      $VersionManifest = $MainManifest
      if ([string]::IsNullOrWhiteSpace($Manifests.Installer)) { throw 'The installer manifest is missing or empty' }
      $InstallerManifest = $Manifests.Installer | ConvertFrom-Yaml -Ordered
      if (-not $Manifests.Locale) { throw 'The locale manifest is missing' }
      $LocaleManifests = $Manifests.Locale.GetEnumerator().ForEach({ if ([string]::IsNullOrWhiteSpace($_.Value)) { throw 'One of the locale manifests is empty' }; ConvertFrom-Yaml -Yaml $_.Value -Ordered })
    } elseif ($ManifestType -ceq 'Singleton') {
      $SingletonManifest = $MainManifest
      # Parse version keys to version manifest
      $VersionManifest = [ordered]@{}
      foreach ($Key in $SingletonManifest.Keys.Where({ $_ -cin (Get-WinGetManifestSchema -ManifestType 'version').properties.Keys })) {
        $VersionManifest[$Key] = $SingletonManifest.$Key
      }
      $VersionManifest['DefaultLocale'] = $PackageLocale
      $VersionManifest['ManifestType'] = 'version'
      # Parse installer keys to installer manifest
      $InstallerManifest = [ordered]@{}
      foreach ($Key in $SingletonManifest.Keys.Where({ $_ -cin (Get-WinGetManifestSchema -ManifestType 'installer').properties.Keys })) {
        $InstallerManifest[$Key] = $SingletonManifest.$Key
      }
      $InstallerManifest['ManifestType'] = 'installer'
      # Parse default locale keys to default locale manifest
      $DefaultLocaleManifest = [ordered]@{}
      foreach ($Key in $SingletonManifest.Keys.Where({ $_ -cin (Get-WinGetManifestSchema -ManifestType 'defaultLocale').properties.Keys })) {
        $DefaultLocaleManifest[$Key] = $SingletonManifest.$Key
      }
      $DefaultLocaleManifest['ManifestType'] = 'defaultLocale'
      # Create locale manifests
      $LocaleManifests = @($DefaultLocaleManifest)
    } else {
      throw "Version ${LastVersion} does not contain the required manifests"
    }

    return [ordered]@{
      Installer = $InstallerManifest
      Locale    = $LocaleManifests
      Version   = $VersionManifest
    }
  }
}

function Convert-WinGetManifestContentToYaml {
  param (
    [Parameter(Position = 1, Mandatory)]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Position = 2, Mandatory)]
    [string]$SchemaUri
  )

  @"
${Script:ManifestHeader}
# yaml-language-server: `$schema=${SchemaUri}

$((ConvertTo-Yaml -Data $Manifest -Options DisableAliases).TrimEnd())

"@
}

function Convert-WinGetManifestsToYaml {
  <#
  .SYNOPSIS
    Write the new manifests for a WinGet package
  .DESCRIPTION
    Write the new manifests for a WinGet package using the provided version, installer and locale manifests
  .PARAMETER Manifests
    The manifest(s) to write
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The manifest(s) to write')]
    [System.Object[]]$Manifests
  )

  process {
    $LocaleManifestContent = [System.Collections.Specialized.OrderedDictionary]::new()
    $Manifests.Locale | ForEach-Object -Process { $LocaleManifestContent[$_.PackageLocale] = Convert-WinGetManifestContentToYaml -Manifest $_ -SchemaUri (Get-WinGetManifestSchemaUrl -ManifestType ($_.ManifestType -ceq 'defaultLocale' ? 'defaultLocale' : 'locale')) }

    [ordered]@{
      Installer = Convert-WinGetManifestContentToYaml -Manifest $Manifests.Installer -SchemaUri (Get-WinGetManifestSchemaUrl -ManifestType 'installer')
      Locale    = $LocaleManifestContent
      Version   = Convert-WinGetManifestContentToYaml -Manifest $Manifests.Version -Schema (Get-WinGetManifestSchemaUrl -ManifestType 'version')
    }
  }
}

Export-ModuleMember -Function '*' -Variable 'WinGetUserAgent', 'WinGetBackupUserAgent', 'WinGetInstallerFiles'
