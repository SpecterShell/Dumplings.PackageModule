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
    $WarningsFor = {
      param($Info)
      $WarningsProperty = $Info.PSObject.Properties['Warnings']
      return $null -eq $WarningsProperty ? @() : @($WarningsProperty.Value)
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
          Warnings              = (& $WarningsFor $Info)
        }
      }
      'burn' {
        $Info = Get-BurnInfo -Path $Path
        return [pscustomobject]@{ ParserName = 'Burn'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Warnings = (& $WarningsFor $Info) }
      }
      'nullsoft' {
        $Info = Get-NSISInfo -Path $Path
        return [pscustomobject]@{ ParserName = 'NSIS'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Warnings = (& $WarningsFor $Info) }
      }
      'inno' {
        $Info = Get-InnoInfo -Path $Path
        return [pscustomobject]@{ ParserName = 'Inno Setup'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Warnings = (& $WarningsFor $Info) }
      }
      { $_ -cin @('msix', 'appx') } {
        $Info = Get-MSIXInfo -Path $Path -InstallerTypeHint $InstallerType
        return [pscustomobject]@{ ParserName = 'MSIX/AppX'; DetectedInstallerType = (& $InstallerTypeFor $Info); InputObject = @($Info); Warnings = (& $WarningsFor $Info) }
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
  .PARAMETER InstallerSwitches
    The installer switches used to resolve command-line-selected identities
  .PARAMETER Analysis
    A previously computed installer analysis to reuse instead of re-analyzing the file
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

    [Parameter(HelpMessage = 'A previously computed installer analysis to reuse instead of re-analyzing the file')]
    $Analysis,

    [Parameter(Mandatory, HelpMessage = 'The scriptblock or method used for warnings')]
    $Logger
  )

  if (-not $Analysis) {
    try {
      $Analysis = Get-WinGetInstallerAnalysis -Path $Path
    } catch {
      $Logger.Invoke("Failed to detect the generic EXE installer family: $($_.Exception.Message)", 'Warning')
      return $null
    }
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
    $Logger.Invoke("Multiple generic EXE parsers produced conflicting installer families: $($SuccessfulFamilies -join ', '). Existing installer fields are preserved.", 'Warning')
    return $null
  }
  $SuccessfulParser = $SuccessfulParsers | Select-Object -First 1
  if ($SuccessfulParser) {
    # Analyzer parser results are produced by the corresponding Get-*Info function.
    $Metadata = $SuccessfulParser.Result.PSObject.Properties.Name -contains 'Metadata' ? $SuccessfulParser.Result.Metadata : $null
    if ($SuccessfulParser.Name -ceq 'Advanced Installer') {
      if (-not $Metadata) {
        $Logger.Invoke('Advanced Installer detection did not return parser metadata', 'Warning')
        return $null
      }
      $SelectionProperty = $Metadata.PSObject.Properties['MsiPayloadSelection']
      $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
      if ($Selection -and $Selection.SourceKind -ceq 'Download') {
        $Logger.Invoke("Advanced Installer selects the online MSI from MainAppURL '$($Selection.MainAppUrl)'; the embedded files do not represent the installer payload", 'Warning')
        return $null
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

  # InstallShield currently has bounded routing markers but no analyzer parser
  # action. Attempt its parser explicitly, while keeping a rejection diagnostic
  # separate from confirmed-family evidence.
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
      $Logger.Invoke("InstallShield routing evidence was rejected by its metadata parser: $($_.Exception.Message)", 'Verbose')
      return $null
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
    $Errors = @($StrongFailures | ForEach-Object { "$($_.ParserName): $($_.Error)" })
    $Detail = $(if ($Errors.Count) { " Parser errors: $($Errors -join '; ')" } else { '' })
    $Logger.Invoke("A confirmed generic EXE family did not produce usable installer metadata. Families: $($Names -join ',').$Detail", 'Warning')
  } elseif ($Rejected.Count -gt 0) {
    $Details = @($Rejected | ForEach-Object { "$($_.Family): $($_.Error)" })
    $Logger.Invoke("Generic EXE routing hints were rejected by their parsers: $($Details -join '; ')", 'Verbose')
  } else {
    $HintNames = $null -eq $RoutingProperty ? @() : @($RoutingProperty.Value | Select-Object -ExpandProperty Family -Unique)
    $Detail = $HintNames.Count ? " Remaining routing hints: $($HintNames -join ',')." : ''
    $Logger.Invoke("No supported generic EXE parser produced installer metadata.$Detail", 'Verbose')
  }
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
  .PARAMETER Logger
    The scriptblock or method used for warnings
  #>
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Installer,
    [Parameter(Mandatory)][System.Collections.IDictionary]$OldInstaller,
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerEntry,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Metadata,
    [Parameter(Mandatory)][string]$ParserName,
    [Parameter(Mandatory)]$Logger
  )

  $ReportFailure = {
    param([string]$Field)
    $Message = "$ParserName did not return a value for existing installer field '$Field'"
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
    $Logger.Invoke($Message, 'Warning')
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
      # The declared parser is authoritative when it succeeds. This avoids
      # broad generic-family candidates, including structures embedded inside
      # NSIS/Inno payloads, from overriding a valid outer installer family.
      $ParserInfo = $null
      try {
        $ParserInfo = Get-WinGetKnownInstallerManifestInfo -Path $EffectiveInstallerPath -InstallerType $EffectiveInstallerType
      } catch {
        $ParserFailure = $_
        $Analysis = try { Get-WinGetInstallerAnalysis -Path $EffectiveInstallerPath } catch { $null }
        $FormatEvidence = Get-WinGetDeclaredInstallerFormatEvidence -InstallerType $EffectiveInstallerType -Analysis $Analysis
        if ($FormatEvidence.Status -ceq 'NotMatched') {
          throw "The manifest-declared '$EffectiveInstallerType' installer was detected as '$($FormatEvidence.DetectedInstallerType)'. $($FormatEvidence.Evidence) Parser error: $($ParserFailure.Exception.Message)"
        }
        $Logger.Invoke("$($ParserFailure.Exception.Message) $($FormatEvidence.Evidence) Existing installer fields are preserved.", 'Warning')
      }

      if ($ParserInfo) {
        $DetectedType = [string]$ParserInfo.DetectedInstallerType
        if (-not [string]::IsNullOrWhiteSpace($DetectedType)) {
          $Compatible = Test-WinGetInstallerTypeCompatibility -DeclaredInstallerType $EffectiveInstallerType -DetectedInstallerType $DetectedType
          $ExactPackageTypeRequired = $EffectiveInstallerType -cin @('msix', 'appx')
          if (-not $Compatible -or ($ExactPackageTypeRequired -and $DetectedType -cne $EffectiveInstallerType)) {
            throw "The manifest-declared '$EffectiveInstallerType' installer was detected as '$DetectedType'"
          }
          if ($DetectedType -cne $EffectiveInstallerType -and $EffectiveInstallerType -cin @('msi', 'wix')) {
            $Logger.Invoke("The Windows Installer parser identified '$DetectedType' while the manifest declares '$EffectiveInstallerType'; the declared type is retained", 'Warning')
          }
        }

        $WarningsProperty = $ParserInfo.PSObject.Properties['Warnings']
        $ParserWarnings = $null -eq $WarningsProperty ? @() : @($WarningsProperty.Value)
        foreach ($Warning in @($ParserWarnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)) {
          $Logger.Invoke("$($ParserInfo.ParserName): $Warning", 'Warning')
        }

        # Apply each resolved value independently. Missing or explicitly
        # unresolved parser fields warn and retain their existing manifest
        # values instead of rolling back unrelated metadata updates.
        $InstallerBackup = $Installer | Copy-Object
        try {
          $Metadata = ConvertTo-WinGetInstallerManifestMetadata -InputObject $ParserInfo.InputObject -InstallerType $EffectiveInstallerType -OldInstaller $OldInstaller
          Set-WinGetInstallerManifestMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $InstallerEntry -Metadata $Metadata -ParserName $ParserInfo.ParserName -Logger $Logger
        } catch {
          foreach ($Key in @($Installer.Keys)) {
            if ($Key -ceq 'InstallerSha256') { continue }
            if ($InstallerBackup.Contains($Key)) { $Installer[$Key] = $InstallerBackup[$Key] } else { $Installer.Remove($Key) }
          }
          foreach ($Key in @($InstallerBackup.Keys)) {
            if ($Key -ceq 'InstallerSha256' -or $Installer.Contains($Key)) { continue }
            $Installer[$Key] = $InstallerBackup[$Key]
          }
          $Logger.Invoke("Failed to apply $($ParserInfo.ParserName) metadata: $($_.Exception.Message); existing fields are preserved", 'Warning')
        }
      }
    } elseif ($EffectiveInstallerType -ceq 'exe') {
      # Generic EXE families remain best effort because static detection can be
      # ambiguous and the manifest intentionally does not declare a known type.
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

  # A parser may remove the final field of a nested value, such as a redundant
  # AppsAndFeaturesEntries.InstallerType. Do not let structurally empty
  # dictionaries or arrays survive into YAML as `{}` or `[]` collections.
  Remove-WinGetEmptyManifestValue -Installer $Installer

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
