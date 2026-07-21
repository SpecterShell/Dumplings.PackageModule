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
$Script:WinGetAuthoringManifestVersion = '1.12.0'

filter UniqueItems {
  [string]$($_.Split(',').Trim() | Select-Object -Unique)
}

filter ToLower {
  [string]$_.ToLower()
}

filter NoWhitespace {
  [string]$_ -replace '\s+', '-'
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
    ProductCode                   = @('AppsAndFeaturesProductCode', 'ProductCode')
    UpgradeCode                   = @('UpgradeCode')
    DisplayName                   = @('DisplayName', 'ProductName')
    DisplayVersion                = @('DisplayVersion', 'ProductVersion', 'Version')
    Publisher                     = $InstallerType -cin @('msix', 'appx') ? @('PublisherDisplayName') : @('Publisher', 'Manufacturer', 'Authors')
    DefaultInstallLocation        = @('DefaultInstallLocation')
    AppsAndFeaturesInstallerType  = @('AppsAndFeaturesInstallerType')
    WritesAppsAndFeaturesEntry    = @('WritesAppsAndFeaturesEntry')
    SignatureSha256               = @('SignatureSha256')
    PackageFamilyName             = @('PackageFamilyName')
    Platform                      = @('Platform')
    MinimumOSVersion              = @('MinimumOSVersion')
    Capabilities                  = @('Capabilities')
    RestrictedCapabilities        = @('RestrictedCapabilities')
    UnresolvedFields              = @('UnresolvedFields')
    DelegatesAppsAndFeaturesEntry = @('DelegatesAppsAndFeaturesEntry')
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
        # Unknown means the MSI retained no source-backed authoring signature; it is not positive
        # evidence that contradicts a manifest-declared WiX type.
        if ($InstallerType -ceq 'wix' -and $Info.InstallerBuilder -cnotin @('WiX', 'Unknown')) {
          throw "The MSI builder is '$($Info.InstallerBuilder)', not WiX"
        }
        $ScopeInfo = [pscustomobject]@{ Scope = $Info.AllUsers -ceq '1' ? 'machine' : $null }
        $TypeInfo = $null
        if ($InstallerType -ceq 'wix' -and $Info.InstallerBuilder -ceq 'Unknown' -and $Info.AppsAndFeaturesInstallerType -ceq 'msi' -and -not $Info.HasCustomAppsAndFeaturesEntry) {
          # An unknown builder is inconclusive rather than contradictory. For a normal MSI ARP
          # entry, retain the manifest-declared WiX family so AppsAndFeaturesEntries does not gain
          # a redundant `InstallerType: msi` solely because authoring signatures were stripped.
          $TypeInfo = [pscustomobject]@{ AppsAndFeaturesInstallerType = 'wix' }
        }
        $ParserInput = [System.Collections.Generic.List[psobject]]::new()
        $ParserInput.Add($ScopeInfo)
        if ($TypeInfo) { $ParserInput.Add($TypeInfo) }
        $ParserInput.Add($Info)
        return [pscustomobject]@{ ParserName = 'Windows Installer'; InputObject = $ParserInput.ToArray() }
      }
      'burn' {
        $null = Get-BurnInfo -Path $Path
        $Manifest = Get-BurnManifest -Path $Path
        $Registration = @($Manifest.GetElementsByTagName('Registration') | Select-Object -First 1)
        if ($Registration.Count -eq 0) { throw 'The Burn manifest does not contain a Registration element' }
        $Registration = $Registration[0]
        $Arp = @($Registration.ChildNodes | Where-Object LocalName -EQ 'Arp' | Select-Object -First 1)
        $RelatedBundle = @($Manifest.GetElementsByTagName('RelatedBundle') | Select-Object -First 1)
        $ProductCode = $Registration.GetAttribute('Code')
        if ([string]::IsNullOrWhiteSpace($ProductCode)) { $ProductCode = $Registration.GetAttribute('Id') }
        $UpgradeCode = if ($RelatedBundle.Count -gt 0) {
          $Value = $RelatedBundle[0].GetAttribute('Code')
          [string]::IsNullOrWhiteSpace($Value) ? $RelatedBundle[0].GetAttribute('Id') : $Value
        } else { $null }
        $ScopeInfo = Get-BurnScopeInfo -Path $Path
        $Info = [pscustomobject]@{
          InstallerType  = 'Burn'
          ProductCode    = $ProductCode
          UpgradeCode    = $UpgradeCode
          DisplayName    = $Arp.Count -gt 0 ? $Arp[0].GetAttribute('DisplayName') : $null
          DisplayVersion = $Arp.Count -gt 0 ? $Arp[0].GetAttribute('DisplayVersion') : $null
          Publisher      = $Arp.Count -gt 0 ? $Arp[0].GetAttribute('Publisher') : $null
          Scope          = $ScopeInfo.DefaultScope
        }
        if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { $Info.DisplayName = Read-ProductNameFromBurn -Path $Path }
        if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { $Info.DisplayVersion = Read-ProductVersionFromExe -Path $Path }
        return [pscustomobject]@{ ParserName = 'Burn'; InputObject = @($ScopeInfo, $Info) }
      }
      'nullsoft' {
        $Info = Get-NSISInfo -Path $Path
        if ($Info.PSObject.Properties.Name -contains 'InstallerType' -and $Info.InstallerType -cne 'Nullsoft') {
          throw "The parser identified '$($Info.InstallerType)', not Nullsoft"
        }
        $WarningsProperty = $Info.PSObject.Properties['Warnings']
        return [pscustomobject]@{ ParserName = 'NSIS'; InputObject = @($Info); Warnings = $null -eq $WarningsProperty ? @() : @($WarningsProperty.Value) }
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
    # An outer stub that writes no visible Apps & Features entry cannot
    # authoritatively replace ARP metadata owned by a nested payload or custom
    # registration. Preserve the existing fields and report the unresolved
    # evidence as a warning instead of failing the update.
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

function Get-WinGetInstallerReleaseDate {
  <#
  .SYNOPSIS
    Resolve the installer release date from the Last-Modified response header
  .DESCRIPTION
    Best-effort evidence for installer entries without a task-provided
    ReleaseDate. Uses the headers of the fresh download response when
    available, otherwise issues a lightweight header request. Returns $null
    when the server does not provide a usable Last-Modified value.
  .PARAMETER Uri
    The installer URL
  .PARAMETER DownloadResult
    The native download result when the installer was downloaded in this run
  .PARAMETER Logger
    The scriptblock or method used for diagnostics
  .OUTPUTS
    The release date in yyyy-MM-dd format, or $null when unavailable.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer URL')]
    [uri]$Uri,
    [Parameter(HelpMessage = 'The native download result when the installer was downloaded in this run')]
    $DownloadResult,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for diagnostics')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  if ($Uri.Scheme -cnotin @('http', 'https')) { return $null }

  $HeaderInfo = $null
  if ($DownloadResult -and -not [string]::IsNullOrWhiteSpace([string]$DownloadResult.ResponseHeaders)) {
    $HeaderInfo = ConvertFrom-WinGetDownloadResponseHeader -Result $DownloadResult -Uri $Uri
  } else {
    # Some servers reject HEAD, so fall back to a headers-only GET.
    foreach ($Method in @([System.Net.Http.HttpMethod]::Head, [System.Net.Http.HttpMethod]::Get)) {
      try {
        $HeaderInfo = Get-WebResponseHeader -Uri $Uri.AbsoluteUri -Method $Method -ConnectionTimeoutSeconds 30
        break
      } catch {
        $HeaderInfo = $null
        $LastHeaderError = $_
      }
    }
    if (-not $HeaderInfo) {
      $Logger.Invoke("Failed to read the Last-Modified header from ${Uri}: $($LastHeaderError.Exception.Message)", 'Verbose')
      return $null
    }
  }

  $LastModified = [string]@($HeaderInfo.Headers['Last-Modified'])[0]
  if ([string]::IsNullOrWhiteSpace($LastModified)) { return $null }

  $Parsed = [System.DateTimeOffset]::MinValue
  if (-not [System.DateTimeOffset]::TryParse($LastModified, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Parsed)) {
    $Logger.Invoke("The Last-Modified header from ${Uri} is not a valid HTTP date: ${LastModified}", 'Verbose')
    return $null
  }
  return $Parsed.ToUniversalTime().ToString('yyyy-MM-dd')
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
  $DownloadResult = $null
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

  # Fill the release date from the Last-Modified response header when neither
  # the existing installer entry nor the task provides one.
  if (-not $Installer.Contains('ReleaseDate') -and -not $InstallerEntry.Contains('ReleaseDate')) {
    $ReleaseDate = Get-WinGetInstallerReleaseDate -Uri $OriginalInstallerUrl -DownloadResult $DownloadResult -Logger $Logger
    if ($ReleaseDate) {
      $Installer.ReleaseDate = $ReleaseDate
      $Logger.Invoke("Using the Last-Modified response header as the release date: $ReleaseDate", 'Verbose')
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
      throw "No matching installer entry for [$($OldInstaller['InstallerLocale']), $($OldInstaller['Architecture']), $($OldInstaller['InstallerType']), $($OldInstaller['NestedInstallerType']), $($OldInstaller['Scope'])]"
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
          if (-not (Test-YamlObject -InputObject $MatchingInstallerEntry.$Key -Schema (Get-WinGetManifestSchema -ManifestType 'installer').properties.Installers.items.properties.$Key)) {
            throw "The installer property '${Key}' does not satisfy the manifest schema"
          }
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
          if (-not (Test-YamlObject -InputObject $InstallerEntry.$Key -Schema (Get-WinGetManifestSchema -ManifestType 'installer').properties.Installers.items.properties.$Key)) {
            throw "The installer property '${Key}' does not satisfy the manifest schema"
          }
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

function Update-WinGetManifest {
  <#
  .SYNOPSIS
    Update a logical WinGet manifest from Dumplings installer and locale state.
  .DESCRIPTION
    Mutates a detached copy of the logical model. Installer parsing operates on
    effective authored entries; serialization later recomputes legal root-level
    defaults and installer overrides without persisting WinGet runtime defaults.
  .PARAMETER Manifest
    Logical manifest model returned by Read-WinGetManifest or
    ConvertFrom-WinGetManifestYaml.
  .PARAMETER NewPackageIdentifier
    Optional replacement package identifier.
  .PARAMETER PackageVersion
    Package version for the updated manifest.
  .PARAMETER InstallerEntries
    Dumplings current-state installer entries.
  .PARAMETER LocaleEntries
    Dumplings locale update entries.
  .PARAMETER InstallerFiles
    Already downloaded installer files keyed by installer URL.
  .PARAMETER ReplaceInstallers
    Replace instead of matching and updating existing installer entries.
  .PARAMETER Logger
    Dumplings logging callback.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory)]$Manifest,
    [string]$NewPackageIdentifier,
    [Parameter(Mandatory)][string]$PackageVersion,
    [Parameter(Mandatory)][System.Collections.IDictionary[]]$InstallerEntries,
    [System.Collections.IDictionary[]]$LocaleEntries = @(),
    [System.Collections.IDictionary]$InstallerFiles = @{},
    [switch]$ReplaceInstallers,
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType Method })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  $PackageIdentifier = [string]::IsNullOrWhiteSpace($NewPackageIdentifier) ? [string]$Manifest.PackageIdentifier : $NewPackageIdentifier
  $OldInstallers = [System.Collections.IDictionary[]]@($Manifest.Installers | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
  if ($ReplaceInstallers) {
    $UpdatedInstallers = @(Set-WinGetInstallerManifestInstallers -OldInstallers $OldInstallers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles -Logger $Logger)
  } else {
    $UpdatedInstallers = @(Update-WinGetInstallerManifestInstallers -OldInstallers $OldInstallers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles -Logger $Logger)
  }

  # Locale update behavior is retained, but identity/document fields are added
  # only for that operation and removed again before storing logical locale data.
  $LocaleDocuments = [System.Collections.Generic.List[object]]::new()
  $DefaultLocaleDocument = [ordered]@{
    PackageIdentifier = $PackageIdentifier
    PackageVersion    = $PackageVersion
  }
  foreach ($Key in $Manifest.DefaultLocalization.Keys) {
    $DefaultLocaleDocument[$Key] = Copy-WinGetManifestValue -Value $Manifest.DefaultLocalization[$Key]
  }
  $DefaultLocaleDocument['ManifestType'] = 'defaultLocale'
  $DefaultLocaleDocument['ManifestVersion'] = $Script:WinGetAuthoringManifestVersion
  $LocaleDocuments.Add($DefaultLocaleDocument)
  foreach ($Localization in @($Manifest.Localizations)) {
    $LocaleDocument = [ordered]@{
      PackageIdentifier = $PackageIdentifier
      PackageVersion    = $PackageVersion
    }
    foreach ($Key in $Localization.Keys) { $LocaleDocument[$Key] = Copy-WinGetManifestValue -Value $Localization[$Key] }
    $LocaleDocument['ManifestType'] = 'locale'
    $LocaleDocument['ManifestVersion'] = $Script:WinGetAuthoringManifestVersion
    $LocaleDocuments.Add($LocaleDocument)
  }
  $UpdatedLocaleDocuments = @(Update-WinGetLocaleManifest -OldLocaleManifests ([System.Collections.IDictionary[]]$LocaleDocuments.ToArray()) -LocaleEntries $LocaleEntries -PackageVersion $PackageVersion -Logger $Logger)

  $DefaultLocalization = [ordered]@{}
  $Localizations = [System.Collections.Generic.List[object]]::new()
  foreach ($LocaleDocument in $UpdatedLocaleDocuments) {
    $Localization = [ordered]@{}
    foreach ($Key in $LocaleDocument.Keys) {
      if ($Key -cnotin @('PackageIdentifier', 'PackageVersion', 'ManifestType', 'ManifestVersion')) {
        $Localization[$Key] = Copy-WinGetManifestValue -Value $LocaleDocument[$Key]
      }
    }
    if ([string]$LocaleDocument['ManifestType'] -ceq 'defaultLocale') {
      $DefaultLocalization = $Localization
    } else {
      $Localizations.Add($Localization)
    }
  }

  $UpdatedModel = New-WinGetManifestModel -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -Channel ([string]$Manifest.Channel) -Moniker ([string]$Manifest.Moniker) -ManifestVersion $Script:WinGetAuthoringManifestVersion -InstallerDefaults ([ordered]@{}) -Installers ([System.Collections.IDictionary[]]$UpdatedInstallers) -DefaultLocalization $DefaultLocalization -Localizations ([System.Collections.IDictionary[]]$Localizations.ToArray()) -SourceFormat Memory
  $Compacted = Get-WinGetManifestCompactedInstallerData -Manifest $UpdatedModel
  $UpdatedModel.InstallerDefaults = $Compacted.Defaults
  return $UpdatedModel
}

Export-ModuleMember -Function Update-WinGetManifest -Variable 'WinGetUserAgent', 'WinGetBackupUserAgent', 'WinGetInstallerFiles'
