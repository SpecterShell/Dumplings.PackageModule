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
$Script:WinGetSharedInstallerFiles = [ordered]@{}
# Expose the established cache variable as the same mutable dictionary while
# retaining a private reference that parent-module re-export cannot detach.
$WinGetInstallerFiles = $Script:WinGetSharedInstallerFiles
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
  # Scope, elevation, associations, dependencies, and locale identity remain
  # author-controlled. Parser elevation evidence is useful for review, but one
  # artifact cannot safely rewrite scope-specific manifest behavior.
  # Publisher here is used only for an existing AppsAndFeaturesEntries.Publisher field.
  $PropertyMap = [ordered]@{
    ProductCode                  = @('AppsAndFeaturesProductCode', 'ProductCode')
    UpgradeCode                  = @('UpgradeCode')
    DisplayName                  = @('DisplayName')
    DisplayVersion               = @('DisplayVersion')
    Publisher                    = @('Publisher')
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
  .PARAMETER Architecture
    The target architecture from the effective WinGet installer entry
  .PARAMETER Scope
    The target scope from the effective WinGet installer entry
  .PARAMETER CommandLine
    Virtual NSIS command line assembled from authored silent and custom switches
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The manifest-declared effective installer type')]
    [ValidateSet('msi', 'wix', 'burn', 'nullsoft', 'inno', 'msix', 'appx')]
    [string]$InstallerType,

    [Parameter(HelpMessage = 'The target architecture from the effective WinGet installer entry')]
    [ValidateSet('x86', 'x64', 'arm64', 'neutral')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target scope from the effective WinGet installer entry')]
    [ValidateSet('user', 'machine')]
    [string]$Scope,

    [AllowEmptyString()]
    [Parameter(HelpMessage = 'The virtual NSIS command line used for static branch selection')]
    [string]$CommandLine
  )

  try {
    $DiagnosticsFor = {
      param($Info)
      $DiagnosticsProperty = $Info.PSObject.Properties['Diagnostics']
      return $null -eq $DiagnosticsProperty ? @() : @($DiagnosticsProperty.Value)
    }
    $InstallerTypeFor = {
      param($Info)
      $InstallerTypeProperty = $Info.PSObject.Properties['InstallerType']
      return $null -eq $InstallerTypeProperty ? $null : [string]$InstallerTypeProperty.Value
    }
    switch ($InstallerType) {
      { $_ -cin @('msi', 'wix') } {
        $Info = Get-MsiInstallerInfo -Path $Path
        return [pscustomobject]@{
          ParserName            = 'Windows Installer'
          DetectedInstallerType = (& $InstallerTypeFor $Info)
          InputObject           = @($Info)
          Diagnostics           = (& $DiagnosticsFor $Info)
        }
      }
      'burn' {
        $Info = Get-BurnInfo -Path $Path
        return [pscustomobject]@{ ParserName = 'Burn'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Diagnostics = (& $DiagnosticsFor $Info) }
      }
      'nullsoft' {
        $Arguments = @{ Path = $Path }
        if ($Architecture -in @('x86', 'x64', 'arm64')) { $Arguments.Architecture = $Architecture }
        if ($Scope -in @('user', 'machine')) { $Arguments.Scope = $Scope }
        if ($PSBoundParameters.ContainsKey('CommandLine')) { $Arguments.CommandLine = $CommandLine }
        $Info = Get-NSISInfo @Arguments
        return [pscustomobject]@{ ParserName = 'NSIS'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Diagnostics = (& $DiagnosticsFor $Info) }
      }
      'inno' {
        $Info = Get-InnoInfo -Path $Path
        return [pscustomobject]@{ ParserName = 'Inno Setup'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Diagnostics = (& $DiagnosticsFor $Info) }
      }
      { $_ -cin @('msix', 'appx') } {
        $Info = Get-MSIXInfo -Path $Path -InstallerTypeHint $InstallerType
        return [pscustomobject]@{ ParserName = 'MSIX/AppX'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Diagnostics = (& $DiagnosticsFor $Info) }
      }
    }
  } catch {
    throw "Failed to parse metadata from the manifest-declared '$InstallerType' installer: $($_.Exception.Message)"
  }
}

function Get-WinGetInstallerTypeGroup {
  <#
  .SYNOPSIS
    Normalize installer types into physical format groups used for compatibility checks.
  .PARAMETER InstallerType
    A WinGet installer type or an analyzer generic-EXE type label.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$InstallerType)

  if ([string]::IsNullOrWhiteSpace($InstallerType)) { return $null }
  $Normalized = $InstallerType.Trim().ToLowerInvariant()
  if ($Normalized.StartsWith('exe')) { return 'exe' }
  if ($Normalized -in @('msi', 'wix')) { return 'msi' }
  if ($Normalized -in @('msix', 'appx')) { return 'msix' }
  if ($Normalized -in @('nullsoft', 'nsis')) { return 'nullsoft' }
  if ($Normalized -eq 'inno setup') { return 'inno' }
  return $Normalized
}

function Test-WinGetInstallerTypeCompatibility {
  <#
  .SYNOPSIS
    Test whether two installer labels describe the same physical installer family.
  .PARAMETER DeclaredInstallerType
    The effective installer type authored in the manifest.
  .PARAMETER DetectedInstallerType
    The type returned by a parser or structural probe.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][string]$DeclaredInstallerType,
    [Parameter(Mandatory)][string]$DetectedInstallerType
  )

  return (Get-WinGetInstallerTypeGroup -InstallerType $DeclaredInstallerType) -ceq (Get-WinGetInstallerTypeGroup -InstallerType $DetectedInstallerType)
}

function Get-WinGetInstallerCandidateType {
  <#
  .SYNOPSIS
    Read the WinGet installer type represented by an analyzer family candidate.
  .PARAMETER Candidate
    A family candidate returned by Get-WinGetInstallerAnalysis.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)]$Candidate)

  $SuggestedProperty = $Candidate.PSObject.Properties['SuggestedManifestFields']
  $Suggested = $null -eq $SuggestedProperty ? $null : $SuggestedProperty.Value
  $TypeProperty = $null -eq $Suggested ? $null : $Suggested.PSObject.Properties['InstallerType']
  if ($null -ne $TypeProperty -and -not [string]::IsNullOrWhiteSpace([string]$TypeProperty.Value)) {
    return [string]$TypeProperty.Value
  }

  # Synthetic tests and older analyzer records may expose only the family name.
  $InstallerType = switch ([string]$Candidate.Family) {
    'MSI' { 'msi' }
    'Burn' { 'burn' }
    'NSIS/Nullsoft' { 'nullsoft' }
    'Inno Setup' { 'inno' }
    'MSIX/AppX' { 'msix' }
    default { $null }
  }
  return $InstallerType
}

function Get-WinGetDeclaredInstallerFormatEvidence {
  <#
  .SYNOPSIS
    Classify a failed declared-family parse as matched, mismatched, or indeterminate.
  .DESCRIPTION
    This function is called only after the declared parser fails. Container magic
    and high-confidence structural family candidates may prove a match or mismatch.
    Low- and medium-confidence text candidates remain routing hints and cannot turn
    a metadata extraction failure into a fatal manifest type mismatch.
  .PARAMETER InstallerType
    The effective installer type authored in the manifest.
  .PARAMETER Analysis
    Static installer analysis returned by Get-WinGetInstallerAnalysis.
  .OUTPUTS
    An object with Status (Matched, NotMatched, or Indeterminate), optional detected
    installer type, and concise structural evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$InstallerType,
    [AllowNull()]$Analysis
  )

  if ($null -eq $Analysis) {
    return [pscustomobject]@{ Status = 'Indeterminate'; DetectedInstallerType = $null; Evidence = 'Static format analysis was unavailable.' }
  }

  $DeclaredGroup = Get-WinGetInstallerTypeGroup -InstallerType $InstallerType
  $FileTypeProperty = $Analysis.PSObject.Properties['DetectedFileType']
  $FileType = if ($null -ne $FileTypeProperty -and $null -ne $FileTypeProperty.Value) { [string]$FileTypeProperty.Value.Type } else { $null }

  # Container signatures prove several families before installer-specific parsing.
  switch ([string]$FileType) {
    'MSI' {
      if ($DeclaredGroup -ceq 'msi') { return [pscustomobject]@{ Status = 'Matched'; DetectedInstallerType = 'msi'; Evidence = 'The CFB root storage CLSID identifies a Windows Installer package.' } }
      return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = 'msi'; Evidence = 'The CFB root storage CLSID identifies a Windows Installer package.' }
    }
    { $_ -cin @('MSP', 'MST') } {
      return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = $_.ToLowerInvariant(); Evidence = "The CFB root storage CLSID identifies a Windows Installer $_ file." }
    }
    'WindowsInstallerDatabase' {
      if ($DeclaredGroup -cne 'msi') {
        return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = 'Windows Installer database'; Evidence = 'The file is CFB structured storage rather than a PE installer.' }
      }
    }
    'MSIXAppX' {
      if ($DeclaredGroup -ceq 'msix') { return [pscustomobject]@{ Status = 'Matched'; DetectedInstallerType = 'msix/appx'; Evidence = 'The OPC archive contains AppX/MSIX package entries.' } }
      return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = 'msix/appx'; Evidence = 'The OPC archive contains AppX/MSIX package entries.' }
    }
    'PE' {
      if ($DeclaredGroup -cin @('msi', 'msix')) {
        return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = 'exe'; Evidence = 'The file is a PE executable rather than a CFB or AppX/MSIX package.' }
      }
    }
    'ZipArchive' {
      # A malformed AppX/MSIX package may still be a ZIP whose package entries
      # could not be read, so keep that case indeterminate rather than misclassifying it.
      if ($DeclaredGroup -notin @('msix')) {
        return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = 'zip'; Evidence = 'The file is a ZIP archive rather than the declared installer executable.' }
      }
    }
    'HTMLDocument' {
      return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = 'HTML document'; Evidence = 'Content detection identified an HTML response instead of an installer.' }
    }
    { $_ -cin @('Unknown', '') } { }
    default {
      if (-not [string]::IsNullOrWhiteSpace($FileType) -and $DeclaredGroup -cin @('msi', 'msix')) {
        return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = $FileType.ToLowerInvariant(); Evidence = "Content detection identified '$FileType'." }
      }
    }
  }

  # New analyzer results separate confirmed families from weak routing hints.
  # Fall back to the compatibility projection for older callers and test doubles.
  $CandidatesProperty = $Analysis.PSObject.Properties['DetectedFamilies']
  $UsesLegacyCandidates = $null -eq $CandidatesProperty
  if ($UsesLegacyCandidates) { $CandidatesProperty = $Analysis.PSObject.Properties['FamilyCandidates'] }
  $Candidates = $null -eq $CandidatesProperty ? @() : @($CandidatesProperty.Value)
  $HighConfidenceTypes = [System.Collections.Generic.List[string]]::new()
  $MatchingEvidence = [System.Collections.Generic.List[string]]::new()
  foreach ($Candidate in $Candidates) {
    $ConfidenceProperty = $Candidate.PSObject.Properties['Confidence']
    if ($UsesLegacyCandidates -and ($null -eq $ConfidenceProperty -or [string]$ConfidenceProperty.Value -cne 'high')) { continue }
    $CandidateType = Get-WinGetInstallerCandidateType -Candidate $Candidate
    if ([string]::IsNullOrWhiteSpace($CandidateType)) { continue }
    if (Test-WinGetInstallerTypeCompatibility -DeclaredInstallerType $InstallerType -DetectedInstallerType $CandidateType) {
      $MarkersProperty = $Candidate.PSObject.Properties['MatchedMarkers']
      $Markers = $null -eq $MarkersProperty ? @() : @($MarkersProperty.Value)
      $MatchingEvidence.Add($(if ($Markers.Count) { "$($Candidate.Family): $($Markers -join ', ')" } else { [string]$Candidate.Family }))
    } else {
      $HighConfidenceTypes.Add($CandidateType)
    }
  }

  # Positive outer-family evidence wins over unrelated structures embedded in
  # the installer payload, which prevents nested CreateInstall/GEA data from
  # overriding a structurally valid NSIS or Inno wrapper.
  if ($MatchingEvidence.Count -gt 0) {
    return [pscustomobject]@{ Status = 'Matched'; DetectedInstallerType = $InstallerType; Evidence = "Structural evidence matches the declared family: $($MatchingEvidence -join '; ')." }
  }

  $DistinctAlternatives = @($HighConfidenceTypes | Sort-Object -Unique)
  if ($DistinctAlternatives.Count -eq 1) {
    return [pscustomobject]@{ Status = 'NotMatched'; DetectedInstallerType = $DistinctAlternatives[0]; Evidence = 'A different installer family has high-confidence structural evidence.' }
  }

  $Evidence = if ($DistinctAlternatives.Count -gt 1) {
    "Conflicting high-confidence alternatives were detected: $($DistinctAlternatives -join ', ')."
  } else {
    'No high-confidence structural evidence proved or disproved the declared family.'
  }
  return [pscustomobject]@{ Status = 'Indeterminate'; DetectedInstallerType = $null; Evidence = $Evidence }
}

function Get-WinGetGenericInstallerManifestInfo {
  <#
  .SYNOPSIS
    Detect and parse the likely family of a generic EXE installer
  .PARAMETER Path
    The installer path
  .PARAMETER Architecture
    The architecture of the installer entry
  .PARAMETER Analysis
    A previously computed installer analysis to reuse instead of re-analyzing the file
  .PARAMETER Logger
    Logger used for immediate progress messages. Parser diagnostics are returned to the caller.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer path')]
    [string]$Path,

    [Parameter(HelpMessage = 'The architecture of the installer entry')]
    [ValidateSet('x86', 'x64', 'arm64', 'neutral')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'A previously computed installer analysis to reuse instead of re-analyzing the file')]
    $Analysis,

    [Parameter(Mandatory, HelpMessage = 'The scriptblock or method used for warnings')]
    $Logger
  )

  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  if (-not $Analysis) {
    try {
      $Analysis = Get-WinGetInstallerAnalysis -Path $Path
    } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'WinGetManifestUpdate.GenericExe.DetectionFailed' -Source 'WinGetManifestUpdate' -Message "Failed to detect the generic EXE installer family: $($_.Exception.Message)" -Kind Incomplete -Areas Detection, Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries, DefaultInstallLocation))
      return [pscustomobject]@{ ParserName = 'Generic EXE'; InputObject = @(); Diagnostics = $Diagnostics.ToArray() }
    }
  }
  $AnalysisDiagnosticProperty = $Analysis.PSObject.Properties['Diagnostics']
  if ($AnalysisDiagnosticProperty) {
    foreach ($Diagnostic in @($AnalysisDiagnosticProperty.Value)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
  }

  $SuccessfulParsers = @($Analysis.ParserResults | Where-Object { $_.Success -and $_.Result })
  $SuccessfulFamilies = @($SuccessfulParsers | ForEach-Object {
      $FamilyProperty = $_.Result.PSObject.Properties['Family']
      if ($null -ne $FamilyProperty -and -not [string]::IsNullOrWhiteSpace([string]$FamilyProperty.Value)) {
        [string]$FamilyProperty.Value
      } else {
        [string]$_.Name
      }
    } | Sort-Object -Unique)
  if ($SuccessfulFamilies.Count -gt 1) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'WinGetManifestUpdate.GenericExe.ConflictingFamilies' -Source 'WinGetManifestUpdate' -Message "Multiple generic EXE parsers produced conflicting installer families: $($SuccessfulFamilies -join ', '). Existing installer fields are preserved." -Kind Mismatch -Areas Detection, Metadata, Installability -AffectedFields InstallerType -Evidence $SuccessfulFamilies))
    return [pscustomobject]@{ ParserName = 'Generic EXE'; InputObject = @(); Diagnostics = $Diagnostics.ToArray() }
  }
  $SuccessfulParser = $SuccessfulParsers | Select-Object -First 1
  if ($SuccessfulParser) {
    # Analyzer parser results are produced by the corresponding Get-*Info function.
    $Metadata = $SuccessfulParser.Result.PSObject.Properties.Name -contains 'Metadata' ? $SuccessfulParser.Result.Metadata : $null
    if ($SuccessfulParser.Name -ceq 'Advanced Installer') {
      if (-not $Metadata) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'AdvancedInstaller.MetadataUnavailable' -Source 'Advanced Installer' -Message 'Advanced Installer detection did not return parser metadata.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries, DefaultInstallLocation))
        return [pscustomobject]@{ ParserName = 'Advanced Installer'; InputObject = @(); Diagnostics = $Diagnostics.ToArray() }
      }
      $SelectionProperty = $Metadata.PSObject.Properties['MsiPayloadSelection']
      $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
      if ($Selection -and $Selection.SourceKind -ceq 'Download') {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'AdvancedInstaller.OnlinePayloadSelected' -Source 'Advanced Installer' -Message "Advanced Installer selects the online MSI from MainAppURL '$($Selection.MainAppUrl)'; the embedded files do not represent the installer payload." -Kind Unsupported -Areas Extraction, Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $Selection))
        return [pscustomobject]@{ ParserName = 'Advanced Installer'; InputObject = @(); Diagnostics = $Diagnostics.ToArray() }
      }
      $PlatformSelectionProperty = $Metadata.PSObject.Properties['PlatformPayloadSelection']
      $PlatformSelection = $null -eq $PlatformSelectionProperty ? $null : $PlatformSelectionProperty.Value
      if ($PlatformSelection -and $PlatformSelection.LegacyMsiSelection) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'AdvancedInstaller.PlatformPayloadAmbiguous' -Source 'Advanced Installer' -Message 'Advanced Installer selects an MSIX/AppX package on supported Windows versions and an MSI on older systems. Existing installed-state fields are preserved until both nested packages are analyzed.' -Kind Ambiguous -Areas Metadata, Installability -AffectedFields ProductCode, PackageFamilyName, AppsAndFeaturesEntries -Evidence $PlatformSelection))
        return [pscustomobject]@{ ParserName = 'Advanced Installer'; InputObject = @(); Diagnostics = $Diagnostics.ToArray() }
      }
      $MsiInfoArguments = @{ Installer = $Metadata }
      if ($Architecture -cin @('x86', 'x64', 'arm64')) { $MsiInfoArguments.Architecture = $Architecture }
      $MsiInfo = Get-AdvancedInstallerMsiInfo @MsiInfoArguments
    } else {
      # InstallShield and Advanced Installer analyzer actions parse selected
      # nested MSI metadata before their temporary extraction trees are removed.
      $MsiInfo = $SuccessfulParser.Result.PSObject.Properties.Name -contains 'MsiInfo' ? $SuccessfulParser.Result.MsiInfo : $null
    }
    $ParserOutputs = @($MsiInfo, $Metadata, $SuccessfulParser.Result) | Where-Object { $null -ne $_ }
    foreach ($Source in $ParserOutputs) {
      $Property = $Source.PSObject.Properties['Diagnostics']
      if ($Property) { foreach ($Diagnostic in @($Property.Value)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } } }
    }
    return [pscustomobject]@{
      ParserName      = $SuccessfulParser.Name
      InputObject     = @($ParserOutputs)
      SelectedMsiPath = $null -eq $MsiInfo ? $null : $MsiInfo.SelectedMsiPath
      SelectionMethod = $null -eq $MsiInfo ? $null : $MsiInfo.SelectionMethod
      Diagnostics     = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
    }
  }

  # InstallShield routing covers both MSI-backed launchers and InstallScript-only
  # media. Parse the outer container once, then select the nested MSI metadata or
  # the focused InstallScript ARP/silent result according to the extracted variant.
  $DetectedProperty = $Analysis.PSObject.Properties['DetectedFamilies']
  $RoutingProperty = $Analysis.PSObject.Properties['RoutingHints']
  $LegacyProperty = $Analysis.PSObject.Properties['FamilyCandidates']
  $InstallShieldEvidence = @(
    if ($null -ne $DetectedProperty) { @($DetectedProperty.Value) }
    if ($null -ne $RoutingProperty) { @($RoutingProperty.Value) }
    if ($null -eq $DetectedProperty -and $null -eq $RoutingProperty -and $null -ne $LegacyProperty) { @($LegacyProperty.Value) }
  )
  $InstallShieldCandidate = $InstallShieldEvidence | Where-Object { $_.Family -ceq 'InstallShield' } | Select-Object -First 1
  if ($InstallShieldCandidate) {
    $TemporaryPath = New-TempFolder
    try {
      $Info = Get-InstallShieldInfo -Path $Path -DestinationPath $TemporaryPath
      if ($Info.Variant -ceq 'Advanced UI') {
        return [pscustomobject]@{
          ParserName      = 'InstallShield Advanced UI'
          InputObject     = @($Info.AdvancedUiInfo, $Info)
          SelectedMsiPath = $null
          SelectionMethod = 'AdvancedUiSuiteCatalog'
          Diagnostics     = @(Merge-InstallerDiagnostics -Diagnostic @($Diagnostics, $Info.Diagnostics))
        }
      }

      if ($Info.HasMsi) {
        $MsiInfo = Get-InstallShieldMsiInfo -Installer $Info
        return [pscustomobject]@{
          ParserName      = 'InstallShield'
          InputObject     = @($MsiInfo, $Info)
          SelectedMsiPath = $MsiInfo.SelectedMsiPath
          SelectionMethod = $MsiInfo.SelectionMethod
          Diagnostics     = @(Merge-InstallerDiagnostics -Diagnostic @($Diagnostics, $Info.Diagnostics, $MsiInfo.Diagnostics))
        }
      }

      if ($Info.Variant -ceq 'InstallScript' -and $Info.InstallScriptInfo) {
        return [pscustomobject]@{
          ParserName      = 'InstallShield InstallScript'
          InputObject     = @($Info.InstallScriptInfo, $Info)
          SelectedMsiPath = $null
          SelectionMethod = 'InstallScriptMaintenanceStart'
          Diagnostics     = @(Merge-InstallerDiagnostics -Diagnostic @($Diagnostics, $Info.Diagnostics, $Info.InstallScriptInfo.Diagnostics))
        }
      }
      throw "The InstallShield '$($Info.Variant)' payload has neither a selected MSI nor supported InstallScript metadata"
    } catch {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'InstallShield.RoutingRejected' -Source 'InstallShield' -Message "InstallShield structural evidence was confirmed, but its metadata parser could not complete: $($_.Exception.Message)" -Kind Incomplete -Areas Detection, Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries, DefaultInstallLocation))
      return [pscustomobject]@{ ParserName = 'InstallShield'; InputObject = @(); Diagnostics = $Diagnostics.ToArray() }
    } finally {
      Remove-Item -LiteralPath $TemporaryPath -Recurse -Force -ErrorAction SilentlyContinue -ProgressAction SilentlyContinue
    }
  }

  $Confirmed = $null -eq $DetectedProperty ? @() : @($DetectedProperty.Value)
  $RejectedProperty = $Analysis.PSObject.Properties['RejectedCandidates']
  $Rejected = $null -eq $RejectedProperty ? @() : @($RejectedProperty.Value)
  $StrongFailures = @($Rejected | Where-Object { $_.EvidenceKind -ceq 'Structural' -and $_.IsOuterContainer })
  if ($StrongFailures.Count -gt 0 -or $Confirmed.Count -gt 0) {
    $Names = @(@($Confirmed | ForEach-Object Family) + @($StrongFailures | ForEach-Object Family) | Where-Object { $_ } | Sort-Object -Unique)
    $Errors = @($StrongFailures | ForEach-Object { @($_.Diagnostics).Message } | Where-Object { $_ })
    $Detail = $(if ($Errors.Count) { " Parser errors: $($Errors -join '; ')" } else { '' })
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'WinGetManifestUpdate.GenericExe.ConfirmedFamilyIncomplete' -Source 'WinGetManifestUpdate' -Message "A confirmed generic EXE family did not produce usable installer metadata. Families: $($Names -join ',').$Detail" -Kind Incomplete -Areas Detection, Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries, DefaultInstallLocation -Evidence $Names))
  } elseif ($Rejected.Count -gt 0) {
    $Details = @($Rejected | ForEach-Object { "$($_.Family): $(@($_.Diagnostics).Message -join '; ')" })
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'WinGetManifestUpdate.GenericExe.RoutingHintsRejected' -Source 'WinGetManifestUpdate' -Message "Generic EXE routing hints were rejected by their parsers: $($Details -join '; ')" -Kind Fallback -Areas Detection -Evidence $Rejected))
  } else {
    $HintNames = $null -eq $RoutingProperty ? @() : @($RoutingProperty.Value | Select-Object -ExpandProperty Family -Unique)
    $Detail = $HintNames.Count ? " Remaining routing hints: $($HintNames -join ',')." : ''
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'WinGetManifestUpdate.GenericExe.NoParserMetadata' -Source 'WinGetManifestUpdate' -Message "No supported generic EXE parser produced installer metadata.$Detail" -Kind Fallback -Areas Detection))
  }
  return [pscustomobject]@{ ParserName = 'Generic EXE'; InputObject = @(); Diagnostics = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray()) }
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
  .PARAMETER DiagnosticCollection
    Manifest-wide buffer that receives resolved diagnostics after each field update attempt.
  .PARAMETER ConfirmedFamily
    Indicates that structural evidence confirmed the parser family.
  #>
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Installer,
    [Parameter(Mandatory)][System.Collections.IDictionary]$OldInstaller,
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerEntry,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Metadata,
    [Parameter(Mandatory)][string]$ParserName,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$DiagnosticCollection,
    [switch]$ConfirmedFamily
  )

  $ReportFailure = {
    param([string]$Field)
    $Message = "$ParserName did not return a value for existing installer field '$Field'"
    $Diagnostic = New-InstallerDiagnostic -Id "$($ParserName -replace '[^A-Za-z0-9]+', '.').Missing.$(($Field -replace '[^A-Za-z0-9]+', '.').Trim('.'))" -Source $ParserName -Message $Message -Kind Incomplete -Areas Metadata -AffectedFields $Field
    Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily:$ConfirmedFamily
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
    $Diagnostic = New-InstallerDiagnostic -Id "$($ParserName -replace '[^A-Za-z0-9]+', '.').VisibleArpUnavailable" -Source $ParserName -Message $Message -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries
    Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily:$ConfirmedFamily
    return
  }

  # ProductCode remains parser-owned whenever the authored entry already
  # contains it. ElevationRequirement is deliberately excluded: package updates
  # must preserve author-selected behavior, including different requirements
  # for separate scope entries that share one installer artifact.
  if ($Installer.Contains('ProductCode') -and -not $InstallerEntry.Contains('ProductCode') -and -not $UnresolvedFields.Contains('ProductCode')) {
    if ($Metadata.Contains('ProductCode') -and (& $HasScalarValue $Metadata.ProductCode)) {
      $Installer.ProductCode = $Metadata.ProductCode
    } else {
      & $ReportFailure 'ProductCode'
    }
  }

  $EffectiveInstallerType = [string]($Installer.Contains('NestedInstallerType') ? $Installer.NestedInstallerType : $Installer.InstallerType)
  $IsPackageInstaller = $EffectiveInstallerType -cin @('msix', 'appx')
  if ($IsPackageInstaller) {
    # These fields describe AppX/MSIX package identity and package-manifest
    # capabilities. In a mixed manifest they can be inherited by MSI/EXE
    # entries, but those parsers cannot authoritatively reproduce them.
    foreach ($Field in @('SignatureSha256', 'PackageFamilyName', 'MinimumOSVersion')) {
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
  } elseif ($Installer.Contains('MinimumOSVersion') -and -not $InstallerEntry.Contains('MinimumOSVersion') -and -not $UnresolvedFields.Contains('MinimumOSVersion') -and $Metadata.Contains('MinimumOSVersion') -and (& $HasScalarValue $Metadata.MinimumOSVersion)) {
    # Non-package installers may expose a trustworthy minimum OS version. Use
    # it when available, but otherwise preserve the authored/inherited value
    # without asking an unrelated parser to synthesize package metadata.
    $Installer.MinimumOSVersion = $Metadata.MinimumOSVersion
  }

  $TaskOverridesDefaultInstallLocation = $InstallerEntry.Contains('InstallationMetadata') -and $InstallerEntry.InstallationMetadata -is [System.Collections.IDictionary] -and $InstallerEntry.InstallationMetadata.Contains('DefaultInstallLocation')
  if ($Installer.Contains('InstallationMetadata') -and $Installer.InstallationMetadata -is [System.Collections.IDictionary] -and $Installer.InstallationMetadata.Contains('DefaultInstallLocation') -and -not $TaskOverridesDefaultInstallLocation -and -not $UnresolvedFields.Contains('DefaultInstallLocation')) {
    if ($Metadata.Contains('DefaultInstallLocation') -and (& $HasScalarValue $Metadata.DefaultInstallLocation)) {
      $Installer.InstallationMetadata.DefaultInstallLocation = $Metadata.DefaultInstallLocation
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
    $Diagnostic = New-InstallerDiagnostic -Id "$($ParserName -replace '[^A-Za-z0-9]+', '.').AppsAndFeaturesEntryUnmatched" -Source $ParserName -Message $Message -Kind Mismatch -Areas Metadata -AffectedFields AppsAndFeaturesEntries
    Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily:$ConfirmedFamily
    return
  }

  $AppsAndFeaturesMap = [ordered]@{
    DisplayName    = 'DisplayName'
    DisplayVersion = 'DisplayVersion'
    Publisher      = 'Publisher'
    ProductCode    = 'ProductCode'
    UpgradeCode    = 'UpgradeCode'
  }
  foreach ($Entry in $MatchingEntries) {
    if ($Metadata.Contains('AppsAndFeaturesInstallerType') -and (& $HasScalarValue $Metadata.AppsAndFeaturesInstallerType)) {
      $InheritedInstallerType = [string]($Installer.Contains('NestedInstallerType') ? $Installer['NestedInstallerType'] : $Installer['InstallerType'])
      if ($Metadata.AppsAndFeaturesInstallerType -ceq $InheritedInstallerType) {
        # Remove only values that restate the effective installer type. An authored
        # type that disagrees is author intent and must be preserved: an MSI with
        # ARPSYSTEMCOMPONENT=1 hides its native entry and lets a nested payload,
        # such as an NSIS installer, write the visible ARP entry, which static
        # parsing cannot see and would otherwise normalize back to the MSI family.
        if ($Entry.Contains('InstallerType') -and $Entry['InstallerType'] -ceq $InheritedInstallerType) { $Entry.Remove('InstallerType') }
      } else {
        # The parser identified a different ARP family, which is explicit evidence
        # such as an EXE-style custom uninstall key. Update or materialize the value.
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

function Remove-WinGetEmptyManifestValue {
  <#
  .SYNOPSIS
    Remove structurally empty dictionaries and arrays from an installer entry.
  .DESCRIPTION
    Parser normalization can remove the final field from a nested dictionary or
    the final item from an array, leaving values that serialize as invalid `{}`
    or `[]` collections. This helper recursively drops empty dictionary and
    array values, including null and emptied items nested inside arrays, while
    preserving every meaningful value without rewriting it.
  .PARAMETER Installer
    The mutable dictionary to normalize, such as an effective installer entry.
  #>
  [OutputType([void])]
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Installer
  )

  foreach ($Key in @($Installer.Keys)) {
    $Value = $Installer[$Key]
    if ($Value -is [System.Collections.IDictionary]) {
      Remove-WinGetEmptyManifestValue -Installer $Value
      if ($Value.Count -eq 0) { $Installer.Remove($Key) }
    } elseif ($Value -is [System.Collections.IList]) {
      $Items = [System.Collections.Generic.List[object]]::new()
      foreach ($Item in @($Value)) {
        # Null items and dictionaries with no remaining fields have no schema-valid
        # manifest representation.
        if ($null -eq $Item) { continue }
        if ($Item -is [System.Collections.IDictionary]) {
          Remove-WinGetEmptyManifestValue -Installer $Item
          if ($Item.Count -eq 0) { continue }
        }
        $Items.Add($Item)
      }
      if ($Items.Count -eq 0) {
        $Installer.Remove($Key)
      } elseif ($Items.Count -ne $Value.Count) {
        $Installer[$Key] = $Items.ToArray()
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

function Get-WinGetManifestUpdateAffectedField {
  <#
  .SYNOPSIS
    Determine which parser-managed fields are relevant to one partial manifest update.
  .PARAMETER Installer
    Effective installer entry being refreshed.
  .PARAMETER InstallerEntry
    Task-provided overrides that take precedence over parser evidence.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Installer,
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerEntry
  )

  $Fields = [System.Collections.Generic.List[string]]::new()
  foreach ($Field in @('ProductCode', 'SignatureSha256', 'PackageFamilyName', 'MinimumOSVersion', 'Platform', 'Capabilities', 'RestrictedCapabilities', 'AppsAndFeaturesEntries')) {
    if ($Installer.Contains($Field) -and -not $InstallerEntry.Contains($Field)) { $Fields.Add($Field) }
  }
  if ($Installer.Contains('AppsAndFeaturesEntries') -and -not $InstallerEntry.Contains('AppsAndFeaturesEntries')) {
    foreach ($Field in @('DisplayName', 'DisplayVersion', 'Publisher', 'UpgradeCode', 'AppsAndFeaturesInstallerType')) { $Fields.Add($Field) }
  }
  if ($Installer.Contains('InstallationMetadata') -and $Installer.InstallationMetadata -is [System.Collections.IDictionary] -and
    $Installer.InstallationMetadata.Contains('DefaultInstallLocation')) {
    $OverridesLocation = $InstallerEntry.Contains('InstallationMetadata') -and $InstallerEntry.InstallationMetadata -is [System.Collections.IDictionary] -and
    $InstallerEntry.InstallationMetadata.Contains('DefaultInstallLocation')
    if (-not $OverridesLocation) {
      $Fields.Add('DefaultInstallLocation')
      $Fields.Add('InstallationMetadata.DefaultInstallLocation')
    }
  }
  return [string[]]@($Fields | Sort-Object -Unique)
}

function Add-WinGetManifestUpdateDiagnostic {
  <#
  .SYNOPSIS
    Resolve diagnostics for one installer entry and append them to a manifest-wide buffer.
  .PARAMETER Collection
    Shared collection flushed after all installer entries are processed.
  .PARAMETER Diagnostic
    Context-neutral or previously resolved diagnostics.
  .PARAMETER Installer
    Effective installer entry being refreshed.
  .PARAMETER InstallerEntry
    Task-provided overrides that take precedence over parser evidence.
  .PARAMETER ConfirmedFamily
    Indicates that the declared installer family was structurally confirmed.
  #>
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Collection,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Diagnostic,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Installer,
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerEntry,
    [switch]$ConfirmedFamily
  )

  $AffectedFields = Get-WinGetManifestUpdateAffectedField -Installer $Installer -InstallerEntry $InstallerEntry
  foreach ($Item in @(Resolve-InstallerDiagnostics -Diagnostic $Diagnostic -Scenario ManifestUpdate -AffectedField $AffectedFields -ConfirmedFamily:$ConfirmedFamily)) {
    $Collection.Add($Item)
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
  .PARAMETER SkipInstallerAnalysis
    Skip nested payload extraction, installer-family detection, and static metadata parsers
  .PARAMETER DiagnosticCollection
    Manifest-wide resolved installer diagnostic buffer.
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
    [Parameter(HelpMessage = 'Skip nested payload extraction, installer-family detection, and static metadata parsers')]
    [switch]$SkipInstallerAnalysis,
    [Parameter(DontShow)]
    [System.Collections.Generic.List[object]]$DiagnosticCollection = [System.Collections.Generic.List[object]]::new(),
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  $OwnDiagnosticCollection = -not $PSBoundParameters.ContainsKey('DiagnosticCollection')

  # Replace the whitespace in the installer URL with %20 to make it clickable
  # Keep the original URL for reference in downloading
  $OriginalInstallerUrl = $Installer.InstallerUrl
  $Installer.InstallerUrl = $Installer.InstallerUrl.Replace(' ', '%20')

  # Update the installer using the matching installer
  # Reuse metadata only for the same effective manifest branch. One URL can
  # expose different payloads by architecture or different ARP keys by scope.
  $MatchingInstaller = $Installers | Where-Object -FilterScript {
    $_.InstallerUrl -ceq $Installer.InstallerUrl -and
    $_['Architecture'] -ceq $Installer['Architecture'] -and
    $_['Scope'] -ceq $Installer['Scope']
  } | Select-Object -First 1
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
    } elseif ($Script:WinGetSharedInstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $Script:WinGetSharedInstallerFiles[$OriginalInstallerUrl])) {
      # Skip downloading if the installer file was previously downloaded
      $InstallerPath = $Script:WinGetSharedInstallerFiles[$OriginalInstallerUrl]
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
    # This extraction exists solely for static analysis and is omitted when the caller opts out.
    $EffectiveInstallerType = $Installer.Contains('NestedInstallerType') ? $Installer.NestedInstallerType : $Installer.InstallerType
    $EffectiveInstallerPath = if ($SkipInstallerAnalysis) {
      $InstallerPath
    } elseif ($Installer.InstallerType -cin @('zip') -and $Installer.NestedInstallerType -cne 'portable') {
      $NestedInstallerRelativePath = $Installer.NestedInstallerFiles[0].RelativeFilePath
      Expand-TempArchive -Path $InstallerPath -RelativeFilePath $NestedInstallerRelativePath -CollisionAction Rename | Join-Path -ChildPath $NestedInstallerRelativePath
    } else {
      $InstallerPath
    }

    $KnownInstallerTypes = $SkipInstallerAnalysis ? @() : @('msi', 'wix', 'burn', 'nullsoft', 'inno', 'msix', 'appx')
    if ($EffectiveInstallerType -cin $KnownInstallerTypes) {
      # The declared parser is authoritative when it succeeds. This avoids
      # broad generic-family candidates, including structures embedded inside
      # NSIS/Inno payloads, from overriding a valid outer installer family.
      $ParserInfo = $null
      try {
        $KnownParserArguments = @{
          Path          = $EffectiveInstallerPath
          InstallerType = $EffectiveInstallerType
          Architecture  = $Installer.Architecture
        }
        # Scope remains author-controlled and is forwarded only when present.
        # Avoid reading an absent dictionary key under strict mode.
        if ($Installer.Contains('Scope') -and $Installer.Scope -in @('user', 'machine')) {
          $KnownParserArguments.Scope = $Installer.Scope
        }
        if ($EffectiveInstallerType -ceq 'nullsoft' -and $Installer.Contains('InstallerSwitches') -and
          $Installer.InstallerSwitches -is [Collections.IDictionary]) {
          $Switches = $Installer.InstallerSwitches
          $HasSilentSwitch = $Switches.Contains('Silent') -and -not [string]::IsNullOrWhiteSpace([string]$Switches.Silent)
          $HasCustomSwitch = $Switches.Contains('Custom') -and -not [string]::IsNullOrWhiteSpace([string]$Switches.Custom)
          if ($HasSilentSwitch -or $HasCustomSwitch) {
            # Model the command WinGet uses for silent installation. NSIS /S
            # is implicit when the manifest only supplies a Custom switch.
            $SilentSwitch = $HasSilentSwitch ? [string]$Switches.Silent : '/S'
            $CustomSwitch = $HasCustomSwitch ? [string]$Switches.Custom : ''
            $KnownParserArguments.CommandLine = ('"' + $EffectiveInstallerPath + '" ' + $SilentSwitch + ' ' + $CustomSwitch).Trim()
          }
        }
        $ParserInfo = Get-WinGetKnownInstallerManifestInfo @KnownParserArguments
      } catch {
        $ParserFailure = $_
        $Analysis = try { Get-WinGetInstallerAnalysis -Path $EffectiveInstallerPath } catch { $null }
        $FormatEvidence = Get-WinGetDeclaredInstallerFormatEvidence -InstallerType $EffectiveInstallerType -Analysis $Analysis
        if ($FormatEvidence.Status -ceq 'NotMatched') {
          $Message = "The manifest-declared '$EffectiveInstallerType' installer was detected as '$($FormatEvidence.DetectedInstallerType)'. $($FormatEvidence.Evidence) Parser error: $($ParserFailure.Exception.Message)"
          $Diagnostic = New-InstallerDiagnostic -Id 'WinGetManifestUpdate.DeclaredFamilyMismatch' -Source 'WinGetManifestUpdate' -Message $Message -Kind Mismatch -Areas Detection -AffectedFields InstallerType -Evidence $FormatEvidence
          Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily
          $null = Write-InstallerDiagnostics -Diagnostic @($DiagnosticCollection | Where-Object Id -CEQ $Diagnostic.Id) -Scenario ManifestUpdate -Logger $Logger
          throw $Message
        }
        $AffectedFields = Get-WinGetManifestUpdateAffectedField -Installer $Installer -InstallerEntry $InstallerEntry
        $Diagnostic = New-InstallerDiagnostic -Id "$($EffectiveInstallerType).ParserIncomplete" -Source 'WinGetManifestUpdate' -Message "$($ParserFailure.Exception.Message) $($FormatEvidence.Evidence) Existing installer fields are preserved." -Kind Incomplete -Areas Detection, Metadata -AffectedFields $AffectedFields
        Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily:($FormatEvidence.Status -ceq 'Matched')
      }

      if ($ParserInfo) {
        $DetectedType = [string]$ParserInfo.DetectedInstallerType
        if (-not [string]::IsNullOrWhiteSpace($DetectedType)) {
          $Compatible = Test-WinGetInstallerTypeCompatibility -DeclaredInstallerType $EffectiveInstallerType -DetectedInstallerType $DetectedType
          $ExactPackageTypeRequired = $EffectiveInstallerType -cin @('msix', 'appx')
          if (-not $Compatible -or ($ExactPackageTypeRequired -and $DetectedType -cne $EffectiveInstallerType)) {
            $Message = "The manifest-declared '$EffectiveInstallerType' installer was detected as '$DetectedType'"
            $Diagnostic = New-InstallerDiagnostic -Id 'WinGetManifestUpdate.DeclaredFamilyMismatch' -Source $ParserInfo.ParserName -Message $Message -Kind Mismatch -Areas Detection -AffectedFields InstallerType -Evidence ([ordered]@{ Declared = $EffectiveInstallerType; Detected = $DetectedType })
            Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily
            $null = Write-InstallerDiagnostics -Diagnostic @($DiagnosticCollection | Where-Object Id -CEQ $Diagnostic.Id) -Scenario ManifestUpdate -Logger $Logger
            throw $Message
          }
          if ($DetectedType -cne $EffectiveInstallerType -and $EffectiveInstallerType -cin @('msi', 'wix')) {
            $Diagnostic = New-InstallerDiagnostic -Id 'WindowsInstaller.DeclaredBuilderRetained' -Source 'Windows Installer' -Message "The Windows Installer parser identified '$DetectedType' while the manifest declares '$EffectiveInstallerType'; the declared type is retained." -Kind Mismatch -Areas Metadata -AffectedFields InstallerType -Evidence ([ordered]@{ Declared = $EffectiveInstallerType; Detected = $DetectedType })
            Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily
          }
        }

        Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($ParserInfo.Diagnostics) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily

        # Apply each resolved value independently. Missing or explicitly
        # unresolved parser fields warn and retain their existing manifest
        # values instead of rolling back unrelated metadata updates.
        $InstallerBackup = $Installer | Copy-Object
        try {
          $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject $ParserInfo.InputObject -InstallerType $EffectiveInstallerType -OldInstaller $OldInstaller
          Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $InstallerEntry -Metadata $Metadata -ParserName $ParserInfo.ParserName -DiagnosticCollection $DiagnosticCollection -ConfirmedFamily
        } catch {
          foreach ($Key in @($Installer.Keys)) {
            if ($Key -ceq 'InstallerSha256') { continue }
            if ($InstallerBackup.Contains($Key)) { $Installer[$Key] = $InstallerBackup[$Key] } else { $Installer.Remove($Key) }
          }
          foreach ($Key in @($InstallerBackup.Keys)) {
            if ($Key -ceq 'InstallerSha256' -or $Installer.Contains($Key)) { continue }
            $Installer[$Key] = $InstallerBackup[$Key]
          }
          $AffectedFields = Get-WinGetManifestUpdateAffectedField -Installer $Installer -InstallerEntry $InstallerEntry
          $Diagnostic = New-InstallerDiagnostic -Id "$($ParserInfo.ParserName -replace '[^A-Za-z0-9]+', '.').MetadataApplicationFailed" -Source $ParserInfo.ParserName -Message "Failed to apply $($ParserInfo.ParserName) metadata: $($_.Exception.Message); existing fields are preserved." -Kind Incomplete -Areas Metadata -AffectedFields $AffectedFields
          Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry -ConfirmedFamily
        }
      }
    } elseif ($EffectiveInstallerType -ceq 'exe' -and -not $SkipInstallerAnalysis) {
      # Generic EXE families remain best effort because static detection can be
      # ambiguous and the manifest intentionally does not declare a known type.
      try {
        $ParserInfoArguments = @{
          Path         = $EffectiveInstallerPath
          Architecture = $Installer.Architecture
          Logger       = $Logger
        }
        $ParserInfo = Get-WinGetGenericInstallerManifestInfo @ParserInfoArguments
        if ($ParserInfo) {
          Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($ParserInfo.Diagnostics) -Installer $Installer -InstallerEntry $InstallerEntry
          if (@($ParserInfo.InputObject).Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$ParserInfo.SelectedMsiPath)) {
            $Logger.Invoke("$($ParserInfo.ParserName) selected MSI '$($ParserInfo.SelectedMsiPath)' using '$($ParserInfo.SelectionMethod)'", 'Verbose')
          }
          if (@($ParserInfo.InputObject).Count -gt 0) {
            $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject $ParserInfo.InputObject -InstallerType $EffectiveInstallerType -OldInstaller $OldInstaller
            Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $InstallerEntry -Metadata $Metadata -ParserName $ParserInfo.ParserName -DiagnosticCollection $DiagnosticCollection
          }
        }
      } catch {
        $AffectedFields = Get-WinGetManifestUpdateAffectedField -Installer $Installer -InstallerEntry $InstallerEntry
        $Diagnostic = New-InstallerDiagnostic -Id 'WinGetManifestUpdate.GenericExe.MetadataUpdateFailed' -Source 'WinGetManifestUpdate' -Message "Failed to update generic EXE metadata: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields $AffectedFields
        Add-WinGetManifestUpdateDiagnostic -Collection $DiagnosticCollection -Diagnostic @($Diagnostic) -Installer $Installer -InstallerEntry $InstallerEntry
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

  # A parser may remove the final field of a nested value, such as a redundant
  # AppsAndFeaturesEntries.InstallerType. Do not let structurally empty
  # dictionaries or arrays survive into YAML as `{}` or `[]` collections.
  Remove-WinGetEmptyManifestValue -Installer $Installer

  # Beautify entries
  if ($Installer.Contains('Commands')) { $Installer.Commands = @($Installer.Commands | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
  if ($Installer.Contains('Protocols')) { $Installer.Protocols = @($Installer.Protocols | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
  if ($Installer.Contains('FileExtensions')) { $Installer.FileExtensions = @($Installer.FileExtensions | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }

  if ($OwnDiagnosticCollection) {
    $null = Write-InstallerDiagnostics -Diagnostic $DiagnosticCollection.ToArray() -Scenario ManifestUpdate -Logger $Logger
  }

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
  .PARAMETER SkipInstallerAnalysis
    Skip nested payload extraction, installer-family detection, and static metadata parsers
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installers to update')]
    [System.Collections.IDictionary[]]$OldInstallers,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installers')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles,
    [Parameter(HelpMessage = 'Skip nested payload extraction, installer-family detection, and static metadata parsers')]
    [switch]$SkipInstallerAnalysis,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  # Parser diagnostics are resolved per effective entry, then deduplicated and
  # rendered once after the complete manifest update.
  $InstallerLogger = $Logger
  $InstallerDiagnostics = [System.Collections.Generic.List[object]]::new()
  $iteration = 0
  $Installers = @()
  foreach ($OldInstaller in $OldInstallers) {
    $iteration += 1
    $InstallerLogger.Invoke("Updating installer #${iteration}/$($OldInstallers.Count) [$($OldInstaller['InstallerLocale']), $($OldInstaller['Architecture']), $($OldInstaller['InstallerType']), $($OldInstaller['NestedInstallerType']), $($OldInstaller['Scope'])]", 'Verbose')

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
          $InstallerLogger.Invoke("The new value of the installer property `"${Key}`" is invalid and thus discarded: ${_}", 'Warning')
        }
      }
    }

    $Installer = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $MatchingInstallerEntry -Installers $Installers -InstallerFiles $InstallerFiles -SkipInstallerAnalysis:$SkipInstallerAnalysis -DiagnosticCollection $InstallerDiagnostics -Logger $InstallerLogger

    # Add the updated installer to the new installers array
    $Installers += $Installer
  }

  # Remove the downloaded files
  foreach ($InstallerPath in $Script:WinGetTempInstallerFiles.Values) {
    Remove-Item -Path $InstallerPath -Force -ErrorAction 'Continue'
  }
  $Script:WinGetTempInstallerFiles.Clear()

  $null = Write-InstallerDiagnostics -Diagnostic $InstallerDiagnostics.ToArray() -Scenario ManifestUpdate -Logger $Logger

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
  .PARAMETER SkipInstallerAnalysis
    Skip nested payload extraction, installer-family detection, and static metadata parsers
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installers to update')]
    [System.Collections.IDictionary[]]$OldInstallers,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installers')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles,
    [Parameter(HelpMessage = 'Skip nested payload extraction, installer-family detection, and static metadata parsers')]
    [switch]$SkipInstallerAnalysis,
    [Parameter(DontShow, HelpMessage = 'The scriptblock or method for logging')]
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType 'Method' })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  $InstallerLogger = $Logger
  $InstallerDiagnostics = [System.Collections.Generic.List[object]]::new()
  $iteration = 0
  $Installers = @()
  foreach ($InstallerEntry in $InstallerEntries) {
    $iteration += 1
    $InstallerLogger.Invoke("Applying installer entry #${iteration}/$($InstallerEntries.Count)", 'Verbose')

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
          $InstallerLogger.Invoke("The new value of the installer property `"${Key}`" is invalid and thus discarded: ${_}", 'Warning')
        }
      }
    }

    $Installer = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $MatchingInstaller -InstallerEntry $InstallerEntry -Installers $Installers -InstallerFiles $InstallerFiles -SkipInstallerAnalysis:$SkipInstallerAnalysis -DiagnosticCollection $InstallerDiagnostics -Logger $InstallerLogger

    # Add the updated installer to the new installers array
    $Installers += $Installer
  }

  # Remove the downloaded files
  foreach ($InstallerPath in $Script:WinGetTempInstallerFiles.Values) {
    Remove-Item -Path $InstallerPath -Force -ErrorAction 'Continue'
  }
  $Script:WinGetTempInstallerFiles.Clear()

  $null = Write-InstallerDiagnostics -Diagnostic $InstallerDiagnostics.ToArray() -Scenario ManifestUpdate -Logger $Logger

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
  .PARAMETER SkipInstallerAnalysis
    Skip nested payload extraction, installer-family detection, and static metadata parsers.
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
    [switch]$SkipInstallerAnalysis,
    [ValidateScript({ Get-Member -InputObject $_ -Name 'Invoke' -MemberType Method })]
    $Logger = { param($Message, $Level) Write-Host $Message }
  )

  $PackageIdentifier = [string]::IsNullOrWhiteSpace($NewPackageIdentifier) ? [string]$Manifest.PackageIdentifier : $NewPackageIdentifier
  $OldInstallers = [System.Collections.IDictionary[]]@($Manifest.Installers | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
  if ($ReplaceInstallers) {
    $UpdatedInstallers = @(Set-WinGetInstallerManifestInstallers -OldInstallers $OldInstallers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles -SkipInstallerAnalysis:$SkipInstallerAnalysis -Logger $Logger)
  } else {
    $UpdatedInstallers = @(Update-WinGetInstallerManifestInstallers -OldInstallers $OldInstallers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles -SkipInstallerAnalysis:$SkipInstallerAnalysis -Logger $Logger)
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
  # Return the same post-processed authored state that serialization emits so
  # task callers do not observe redundant locale or ARP fields temporarily.
  $UpdatedModel = Optimize-WinGetManifest -Manifest $UpdatedModel
  $Compacted = Get-WinGetManifestCompactedInstallerData -Manifest $UpdatedModel
  $UpdatedModel.InstallerDefaults = $Compacted.Defaults
  return $UpdatedModel
}

Export-ModuleMember -Function Update-WinGetManifest -Variable 'WinGetUserAgent', 'WinGetBackupUserAgent', 'WinGetInstallerFiles'
