# WinGet manifest authoring operations.
#
# This module composes the logical manifest model, static installer analyzer,
# serializer, optimizer, and validator. It never executes installers and keeps
# all mutations detached from caller-owned model objects.

Set-StrictMode -Version 3

$Script:WinGetAuthoringManifestVersion = '1.12.0'
$Script:WinGetAuthoringArchitectures = @('x86', 'x64', 'arm64')

function ConvertTo-WinGetAuthoringDictionary {
  <#
  .SYNOPSIS
    Convert a dictionary-like value to a detached ordered dictionary.
  .PARAMETER InputObject
    Hashtable, ordered dictionary, or PSCustomObject to convert.
  #>
  [OutputType([System.Collections.IDictionary])]
  param ([Parameter(Mandatory)][object]$InputObject)

  if ($InputObject -is [System.Collections.IDictionary]) {
    return Copy-WinGetManifestValue -Value $InputObject
  }
  $Result = [ordered]@{}
  foreach ($Property in $InputObject.PSObject.Properties) {
    $Value = $Property.Value
    if ($Value -is [pscustomobject]) {
      $Value = ConvertTo-WinGetAuthoringDictionary -InputObject $Value
    } elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
      $Value = @($Value | ForEach-Object {
          if ($_ -is [pscustomobject]) { ConvertTo-WinGetAuthoringDictionary -InputObject $_ } else { Copy-WinGetManifestValue -Value $_ }
        })
    }
    $Result[$Property.Name] = Copy-WinGetManifestValue -Value $Value
  }
  return $Result
}

function Copy-WinGetAuthoringManifestModel {
  <#
  .SYNOPSIS
    Create a detached copy of a logical manifest model.
  .PARAMETER Manifest
    Logical Dumplings WinGet manifest model.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$Manifest)

  return New-WinGetManifestModel -PackageIdentifier ([string]$Manifest.PackageIdentifier) `
    -PackageVersion ([string]$Manifest.PackageVersion) -Channel ([string]$Manifest.Channel) `
    -Moniker ([string]$Manifest.Moniker) -ManifestVersion ([string]$Manifest.ManifestVersion) `
    -InstallerDefaults (ConvertTo-WinGetAuthoringDictionary -InputObject $Manifest.InstallerDefaults) `
    -Installers ([System.Collections.IDictionary[]]@($Manifest.Installers | ForEach-Object { ConvertTo-WinGetAuthoringDictionary -InputObject $_ })) `
    -DefaultLocalization (ConvertTo-WinGetAuthoringDictionary -InputObject $Manifest.DefaultLocalization) `
    -Localizations ([System.Collections.IDictionary[]]@($Manifest.Localizations | ForEach-Object { ConvertTo-WinGetAuthoringDictionary -InputObject $_ })) `
    -SourceFormat Memory
}

function Merge-WinGetAuthoringPatch {
  <#
  .SYNOPSIS
    Recursively apply an authoring patch to a detached dictionary.
  .DESCRIPTION
    Dictionaries merge recursively, arrays and scalars replace their target,
    and null patch values remove the corresponding field.
  .PARAMETER Target
    Dictionary to patch.
  .PARAMETER Patch
    Patch dictionary.
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Target,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Patch
  )

  $Result = Copy-WinGetManifestValue -Value $Target
  foreach ($Key in $Patch.Keys) {
    $PatchValue = $Patch[$Key]
    if ($null -eq $PatchValue) {
      if ($Result.Contains($Key)) { $Result.Remove($Key) }
      continue
    }
    if ($Result.Contains($Key) -and $Result[$Key] -is [System.Collections.IDictionary] -and $PatchValue -is [System.Collections.IDictionary]) {
      $Result[$Key] = Merge-WinGetAuthoringPatch -Target $Result[$Key] -Patch $PatchValue
      continue
    }
    $Result[$Key] = Copy-WinGetManifestValue -Value $PatchValue
  }
  return $Result
}

function Get-WinGetAuthoringInstallerIndex {
  <#
  .SYNOPSIS
    Resolve exactly one installer by zero-based index or exact-match fields.
  .PARAMETER Manifest
    Logical manifest model.
  .PARAMETER Index
    Zero-based installer index.
  .PARAMETER Match
    Dictionary whose fields must structurally equal fields on one installer.
  #>
  [OutputType([int])]
  [CmdletBinding(DefaultParameterSetName = 'Index')]
  param (
    [Parameter(Mandatory)]$Manifest,
    [Parameter(Mandatory, ParameterSetName = 'Index')][ValidateRange(0, [int]::MaxValue)][int]$Index,
    [Parameter(Mandatory, ParameterSetName = 'Match')][System.Collections.IDictionary]$Match
  )

  $Installers = @($Manifest.Installers)
  if ($PSCmdlet.ParameterSetName -ceq 'Index') {
    if ($Index -ge $Installers.Count) { throw "Installer index $Index is outside the manifest installer list." }
    return $Index
  }

  if ($Match.Count -eq 0) { throw 'The installer exact-match selector cannot be empty.' }
  $SelectorMatches = [System.Collections.Generic.List[int]]::new()
  for ($CandidateIndex = 0; $CandidateIndex -lt $Installers.Count; $CandidateIndex++) {
    $Candidate = $Installers[$CandidateIndex]
    $IsMatch = $true
    foreach ($Key in $Match.Keys) {
      if (-not $Candidate.Contains($Key) -or -not (Test-WinGetManifestValueEqual -Left $Candidate[$Key] -Right $Match[$Key])) {
        $IsMatch = $false
        break
      }
    }
    if ($IsMatch) { $SelectorMatches.Add($CandidateIndex) }
  }
  if ($SelectorMatches.Count -ne 1) { throw "The installer selector matched $($SelectorMatches.Count) entries; exactly one is required." }
  return $SelectorMatches[0]
}

function Get-WinGetAuthoringLocaleIndex {
  <#
  .SYNOPSIS
    Resolve an additional locale by case-insensitive BCP47 tag.
  .PARAMETER Manifest
    Logical manifest model.
  .PARAMETER PackageLocale
    Locale tag to locate.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)]$Manifest,
    [Parameter(Mandatory)][string]$PackageLocale
  )

  $LocaleMatches = @()
  for ($Index = 0; $Index -lt @($Manifest.Localizations).Count; $Index++) {
    if ([string]$Manifest.Localizations[$Index]['PackageLocale'] -ieq $PackageLocale) { $LocaleMatches += $Index }
  }
  if ($LocaleMatches.Count -ne 1) { throw "Locale '$PackageLocale' matched $($LocaleMatches.Count) additional locale manifests; exactly one is required." }
  return [int]$LocaleMatches[0]
}

function Assert-WinGetAuthoringInstallerEntry {
  <#
  .SYNOPSIS
    Validate one effective installer entry against the selected WinGet schema.
  .PARAMETER Installer
    Effective authored installer dictionary.
  .PARAMETER ManifestVersion
    Manifest schema version.
  #>
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Installer,
    [Parameter(Mandatory)][string]$ManifestVersion
  )

  $Schema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion $ManifestVersion
  $EntrySchema = $Schema['definitions']['Installer']
  $Result = Get-YamlSchemaValidationResult -InputObject $Installer -Schema $EntrySchema -RootSchema $Schema -ValidatePropertyNames
  if (-not $Result.IsValid) {
    $Messages = @($Result.Diagnostics | ForEach-Object { "$($_.ObjectPath): $($_.Message)" })
    throw "The installer entry does not satisfy the WinGet manifest schema:`n$($Messages -join "`n")"
  }
}

function Get-WinGetAuthoringPropertyValue {
  <#
  .SYNOPSIS
    Return the first nonempty named property from ordered evidence sources.
  .PARAMETER Source
    Parser/analyzer evidence objects in priority order.
  .PARAMETER Name
    Property names in priority order.
  #>
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Source,
    [Parameter(Mandatory)][string[]]$Name
  )

  foreach ($CandidateSource in $Source) {
    if ($null -eq $CandidateSource) { continue }
    foreach ($CandidateName in $Name) {
      $Property = if ($CandidateSource -is [System.Collections.IDictionary]) {
        if ($CandidateSource.Contains($CandidateName)) { [pscustomobject]@{ Value = $CandidateSource[$CandidateName] } }
      } else {
        $CandidateSource.PSObject.Properties[$CandidateName]
      }
      if ($null -eq $Property -or $null -eq $Property.Value) { continue }
      if ($Property.Value -is [string] -and [string]::IsNullOrWhiteSpace([string]$Property.Value)) { continue }
      return $Property.Value
    }
  }
  return $null
}

function ConvertTo-WinGetAuthoringInstallerType {
  <#
  .SYNOPSIS
    Normalize analyzer family labels to schema-valid WinGet installer types.
  .PARAMETER InstallerType
    Analyzer installer type label.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$InstallerType)

  if ([string]::IsNullOrWhiteSpace($InstallerType)) { return $null }
  $Type = ($InstallerType -split '\s+#\s+', 2)[0].Trim().ToLowerInvariant()
  switch ($Type) {
    'appxbundle' { return 'appx' }
    'msixbundle' { return 'msix' }
    default { return $Type }
  }
}

function ConvertTo-WinGetAuthoringArchitecture {
  <#
  .SYNOPSIS
    Normalize a parser architecture label to a concrete WinGet architecture.
  .PARAMETER Architecture
    Parser architecture label.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Architecture)

  if ([string]::IsNullOrWhiteSpace($Architecture)) { return $null }
  switch -Regex ($Architecture.Trim().ToLowerInvariant()) {
    '^(x86|i[3-6]86|win32)$' { return 'x86' }
    '^(x64|amd64|x86_64|win64)$' { return 'x64' }
    '^(arm64|aarch64)$' { return 'arm64' }
    default { return $null }
  }
}

function Get-WinGetAuthoringReleaseDate {
  <#
  .SYNOPSIS
    Parse Last-Modified evidence returned by a WinGet download transport.
  .PARAMETER DownloadResult
    WinGet downloader result containing raw response headers.
  #>
  [OutputType([string])]
  param ([AllowNull()]$DownloadResult)

  if ($null -eq $DownloadResult -or [string]::IsNullOrWhiteSpace([string]$DownloadResult.ResponseHeaders)) { return $null }
  $Match = [regex]::Match([string]$DownloadResult.ResponseHeaders, '(?im)^Last-Modified\s*:\s*(?<value>[^\r\n]+)')
  if (-not $Match.Success) { return $null }
  $Date = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($Match.Groups['value'].Value.Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$Date)) { return $null }
  return $Date.UtcDateTime.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-WinGetAuthoringAnalysisProjection {
  <#
  .SYNOPSIS
    Project one analyzer result to conservative manifest evidence.
  .PARAMETER Analysis
    Result from Get-WinGetInstallerAnalysis.
  .PARAMETER PackageVersion
    Optional package version used to identify meaningful ARP version differences.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]$Analysis,
    [AllowNull()][string]$PackageVersion
  )

  $SuccessfulParsers = @($Analysis.ParserResults | Where-Object { $_.Success -and $null -ne $_.Result })
  $Warnings = [System.Collections.Generic.List[string]]::new()
  $Suggestions = [ordered]@{}
  $BlockingIssues = [System.Collections.Generic.List[string]]::new()
  foreach ($Issue in @($Analysis.BlockingIssues)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$Issue)) { $BlockingIssues.Add([string]$Issue) }
  }

  if ($Analysis.DetectedFileType.Type -cin @('MSP', 'MST', 'WindowsInstallerDatabase')) {
    $BlockingIssues.Add("'$($Analysis.DetectedFileType.Type)' is not a confirmed standalone MSI installer.")
  }

  $ParserResult = $SuccessfulParsers | Select-Object -First 1
  $Result = if ($ParserResult) { $ParserResult.Result } else { $null }
  $PortableEvidence = $Analysis.PortableEvidence
  if ($null -eq $Result -and $PortableEvidence) {
    $Suggestions['InstallerType'] = 'portable'
    $BlockingIssues.Add('No installer family was confirmed. Specify InstallerType=portable explicitly only after confirming that the PE is a portable command target.')
  } elseif ($null -eq $Result) {
    $BlockingIssues.Add('Static analysis did not confirm a supported installer family.')
  }

  $Sources = @($Result)
  if ($Result) {
    if ($Result.PSObject.Properties['Metadata']) { $Sources += $Result.Metadata }
    if ($Result.PSObject.Properties['MsiInfo']) { $Sources += $Result.MsiInfo }
  }
  $Sources = @($Sources | Where-Object { $null -ne $_ })
  $ConfirmedInstallerTypes = @($SuccessfulParsers | ForEach-Object {
      ConvertTo-WinGetAuthoringInstallerType -InstallerType ([string](Get-WinGetAuthoringPropertyValue -Source @($_.Result) -Name InstallerType))
    } | Where-Object { $_ } | Select-Object -Unique)
  $ConfirmedFamilies = @($SuccessfulParsers | ForEach-Object {
      [string](Get-WinGetAuthoringPropertyValue -Source @($_.Result) -Name Family)
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
  if ($ConfirmedInstallerTypes.Count -gt 1) {
    $BlockingIssues.Add("Confirmed parsers disagree on the installer type: $($ConfirmedInstallerTypes -join ', ').")
  }
  if ($ConfirmedFamilies.Count -gt 1) {
    $BlockingIssues.Add("Confirmed parsers disagree on the installer family: $($ConfirmedFamilies -join ', ').")
  }
  $InstallerType = ConvertTo-WinGetAuthoringInstallerType -InstallerType ([string](Get-WinGetAuthoringPropertyValue -Source $Sources -Name InstallerType))
  $ProductCode = Get-WinGetAuthoringPropertyValue -Source $Sources -Name @('ProductCode', 'AppsAndFeaturesProductCode')
  $UpgradeCode = Get-WinGetAuthoringPropertyValue -Source $Sources -Name UpgradeCode
  $DisplayVersion = Get-WinGetAuthoringPropertyValue -Source $Sources -Name @('DisplayVersion', 'ProductVersion')
  $Scope = Get-WinGetAuthoringPropertyValue -Source $Sources -Name Scope
  $SupportedScopes = @(Get-WinGetAuthoringPropertyValue -Source $Sources -Name SupportedScopes)
  $Architecture = ConvertTo-WinGetAuthoringArchitecture -Architecture ([string](Get-WinGetAuthoringPropertyValue -Source $Sources -Name @('PackageArchitecture', 'Architecture', 'RecommendedWinGetArchitecture')))
  $SupportedArchitectures = @(
    @(Get-WinGetAuthoringPropertyValue -Source $Sources -Name @('RecommendedWinGetArchitectures', 'SupportedArchitectures')) |
      ForEach-Object { ConvertTo-WinGetAuthoringArchitecture -Architecture ([string]$_) } |
      Where-Object { $_ } |
      Select-Object -Unique
  )
  $SupportsSilentInstallation = Get-WinGetAuthoringPropertyValue -Source $Sources -Name SupportsSilentInstallation
  if ($null -ne $SupportsSilentInstallation -and -not [bool]$SupportsSilentInstallation) {
    $BlockingIssues.Add('Static parser evidence reports that this installer does not support unattended installation.')
  }

  foreach ($Source in $Sources) {
    foreach ($Warning in @(Get-WinGetAuthoringPropertyValue -Source @($Source) -Name Warnings)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Warning)) { $Warnings.Add([string]$Warning) }
    }
    foreach ($Field in @(Get-WinGetAuthoringPropertyValue -Source @($Source) -Name UnresolvedFields)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Field)) { $Warnings.Add("Unresolved installer field: $Field") }
    }
  }
  $AnalysisWarnings = @($Analysis.WrapperWarnings | ForEach-Object { if ($_.PSObject.Properties['Warning']) { $_.Warning } })
  foreach ($Warning in $AnalysisWarnings) {
    if (-not [string]::IsNullOrWhiteSpace([string]$Warning)) { $Warnings.Add([string]$Warning) }
  }
  if (@($Analysis.SuggestedNextSteps).Count -gt 0) {
    $Suggestions['AnalyzerNextSteps'] = @($Analysis.SuggestedNextSteps)
  }

  if ($SupportedScopes.Count -gt 1) {
    $Suggestions['Scope'] = @($SupportedScopes)
    $Scope = $null
  }
  if (-not $Architecture -and $SupportedArchitectures.Count -gt 1) {
    $Suggestions['Architectures'] = @($SupportedArchitectures)
  } elseif (-not $Architecture -and $SupportedArchitectures.Count -eq 1) {
    $Architecture = $SupportedArchitectures[0]
  }

  $ManifestFields = [ordered]@{}
  if ($InstallerType) { $ManifestFields['InstallerType'] = $InstallerType }
  if ($Architecture) { $ManifestFields['Architecture'] = $Architecture }
  if ($ProductCode) { $ManifestFields['ProductCode'] = [string]$ProductCode }
  if ([string]$Scope -cin @('user', 'machine')) { $ManifestFields['Scope'] = [string]$Scope }

  foreach ($Field in @('PackageFamilyName', 'SignatureSha256', 'MinimumOSVersion')) {
    $Value = Get-WinGetAuthoringPropertyValue -Source $Sources -Name $Field
    if ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value)) { $ManifestFields[$Field] = $Value }
  }
  $DefaultInstallLocation = Get-WinGetAuthoringPropertyValue -Source $Sources -Name DefaultInstallLocation
  if (-not [string]::IsNullOrWhiteSpace([string]$DefaultInstallLocation)) {
    $ManifestFields['InstallationMetadata'] = [ordered]@{ DefaultInstallLocation = [string]$DefaultInstallLocation }
  }
  foreach ($Field in @('Platform', 'Capabilities', 'RestrictedCapabilities')) {
    $Value = @(Get-WinGetAuthoringPropertyValue -Source $Sources -Name $Field | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($Value.Count -gt 0) { $ManifestFields[$Field] = $Value }
  }

  # Only known package mappings from MSIX or portable runtime analysis are
  # authoritative enough to author automatically.
  $Dependencies = Get-WinGetAuthoringPropertyValue -Source $Sources -Name Dependencies
  if ($Dependencies -is [System.Collections.IDictionary] -and $Dependencies.Count -gt 0) {
    $ManifestFields['Dependencies'] = Copy-WinGetManifestValue -Value $Dependencies
  } elseif ($PortableEvidence -and @($PortableEvidence.RecommendedPackageDependencies).Count -gt 0) {
    $ManifestFields['Dependencies'] = [ordered]@{ PackageDependencies = @($PortableEvidence.RecommendedPackageDependencies | ForEach-Object { ConvertTo-WinGetAuthoringDictionary -InputObject $_ }) }
  }

  $InstallLocationSwitch = Get-WinGetAuthoringPropertyValue -Source $Sources -Name InstallLocationSwitch
  if (-not [string]::IsNullOrWhiteSpace([string]$InstallLocationSwitch)) {
    $ManifestFields['InstallerSwitches'] = [ordered]@{ InstallLocation = [string]$InstallLocationSwitch }
  }

  $AppsAndFeaturesEntry = [ordered]@{}
  if ($UpgradeCode) { $AppsAndFeaturesEntry['UpgradeCode'] = [string]$UpgradeCode }
  $AppsAndFeaturesProductCode = Get-WinGetAuthoringPropertyValue -Source $Sources -Name AppsAndFeaturesProductCode
  if ($AppsAndFeaturesProductCode -and [string]$AppsAndFeaturesProductCode -ine [string]$ProductCode) {
    $AppsAndFeaturesEntry['ProductCode'] = [string]$AppsAndFeaturesProductCode
  }
  $AppsAndFeaturesInstallerType = ConvertTo-WinGetAuthoringInstallerType -InstallerType ([string](Get-WinGetAuthoringPropertyValue -Source $Sources -Name AppsAndFeaturesInstallerType))
  if ($AppsAndFeaturesInstallerType -and $AppsAndFeaturesInstallerType -ine $InstallerType) {
    $AppsAndFeaturesEntry['InstallerType'] = $AppsAndFeaturesInstallerType
  }
  if ($DisplayVersion -and $PackageVersion -and [string]$DisplayVersion -cne $PackageVersion) {
    $AppsAndFeaturesEntry['DisplayVersion'] = [string]$DisplayVersion
  }
  if ($AppsAndFeaturesEntry.Count -gt 0) { $ManifestFields['AppsAndFeaturesEntries'] = @($AppsAndFeaturesEntry) }

  # Parser-returned associations come from literal registry/package structures.
  # First-run-only or incomplete associations never reach these fields and
  # remain manual VM evidence instead.
  foreach ($Field in @('Protocols', 'FileExtensions')) {
    $Value = @(Get-WinGetAuthoringPropertyValue -Source $Sources -Name $Field | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($Value.Count -gt 0) { $ManifestFields[$Field] = $Value }
  }
  $UnknownDependencies = @(Get-WinGetAuthoringPropertyValue -Source $Sources -Name UnknownPackageDependencies | Where-Object { $null -ne $_ })
  if ($UnknownDependencies.Count -gt 0) { $Suggestions['UnknownPackageDependencies'] = $UnknownDependencies }
  $DisplayName = Get-WinGetAuthoringPropertyValue -Source $Sources -Name @('DisplayName', 'ProductName')
  $Publisher = Get-WinGetAuthoringPropertyValue -Source $Sources -Name Publisher
  if ($DisplayName -or $Publisher) {
    $Suggestions['AppsAndFeaturesIdentity'] = [ordered]@{ DisplayName = $DisplayName; Publisher = $Publisher }
  }
  $SuggestedFields = Get-WinGetAuthoringPropertyValue -Source $Sources -Name SuggestedManifestFields
  if ($SuggestedFields) { $Suggestions['FamilyDefaults'] = $SuggestedFields }

  return [pscustomobject]@{
    InstallerType   = $InstallerType
    ManifestFields  = $ManifestFields
    Architecture    = $Architecture
    Suggestions     = $Suggestions
    Warnings        = @($Warnings | Select-Object -Unique)
    BlockingIssues  = @($BlockingIssues | Select-Object -Unique)
    ParserResult    = $ParserResult
  }
}

function New-WinGetManifest {
  <#
  .SYNOPSIS
    Create a complete validated logical WinGet manifest model.
  .PARAMETER PackageIdentifier
    WinGet package identifier.
  .PARAMETER PackageVersion
    Package version.
  .PARAMETER DefaultLocalization
    Complete default-locale fields, including PackageLocale and required text fields.
  .PARAMETER Installer
    One or more complete effective installer entries.
  .PARAMETER InstallerDefaults
    Optional authored installer-manifest root defaults.
  .PARAMETER Localization
    Optional additional locale dictionaries.
  .PARAMETER Channel
    Optional package channel.
  .PARAMETER Moniker
    Optional package moniker.
  .PARAMETER ManifestVersion
    WinGet schema version; Dumplings authoring defaults to 1.12.0.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a detached in-memory model and changes no external state.')]
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PackageIdentifier,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PackageVersion,
    [Parameter(Mandatory)][System.Collections.IDictionary]$DefaultLocalization,
    [Parameter(Mandatory)][Alias('Installers')][ValidateNotNullOrEmpty()][System.Collections.IDictionary[]]$Installer,
    [System.Collections.IDictionary]$InstallerDefaults = [ordered]@{},
    [Alias('Localizations')][System.Collections.IDictionary[]]$Localization = @(),
    [AllowNull()][string]$Channel,
    [AllowNull()][string]$Moniker,
    [ValidateNotNullOrEmpty()][string]$ManifestVersion = $Script:WinGetAuthoringManifestVersion
  )

  $Model = New-WinGetManifestModel -PackageIdentifier $PackageIdentifier -PackageVersion $PackageVersion -Channel $Channel -Moniker $Moniker `
    -ManifestVersion $ManifestVersion -InstallerDefaults (ConvertTo-WinGetAuthoringDictionary -InputObject $InstallerDefaults) `
    -Installers ([System.Collections.IDictionary[]]@($Installer | ForEach-Object { ConvertTo-WinGetAuthoringDictionary -InputObject $_ })) `
    -DefaultLocalization (ConvertTo-WinGetAuthoringDictionary -InputObject $DefaultLocalization) `
    -Localizations ([System.Collections.IDictionary[]]@($Localization | ForEach-Object { ConvertTo-WinGetAuthoringDictionary -InputObject $_ })) -SourceFormat Memory
  $Validation = Get-WinGetManifestValidationResult -Manifest $Model
  if ($Validation.HasErrors) {
    throw "The new manifest is incomplete or invalid:`n$(@($Validation.Errors | ForEach-Object { "[$($_.Id)] $($_.Message)" }) -join "`n")"
  }
  foreach ($Warning in $Validation.Warnings) { Write-Warning "[$($Warning.Id)] $($Warning.Message)" }
  return $Model
}

function Get-WinGetInstallerManifestSuggestion {
  <#
  .SYNOPSIS
    Analyze an installer once and propose conservative WinGet installer entries.
  .DESCRIPTION
    Downloads through WinGet-compatible transports when InstallerPath is not
    supplied. The installer is never executed. Heuristic evidence remains under
    Suggestions and blocking evidence prevents Add-WinGetManifestInstaller.
  .PARAMETER InstallerUrl
    Public installer URL written to the manifest.
  .PARAMETER InstallerPath
    Optional local copy of the same installer.
  .PARAMETER Architecture
    Explicit concrete architecture when static evidence is absent or ambiguous.
    Multiple values create separate effective entries.
  .PARAMETER Scope
    Explicit user or machine scope override.
  .PARAMETER NestedInstallerFile
    Exact archive-relative payload path when a ZIP has multiple candidates.
  .PARAMETER Override
    Explicit schema-validated fields applied after analyzer evidence.
  .PARAMETER PackageVersion
    Optional package version used to author meaningful ARP version differences.
  .PARAMETER Header
    Optional download request headers.
  .PARAMETER Proxy
    Optional explicit proxy passed to the WinGet downloader.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][uri]$InstallerUrl,
    [string]$InstallerPath,
    [ValidateSet('x86', 'x64', 'arm64')][string[]]$Architecture,
    [ValidateSet('user', 'machine')][string]$Scope,
    [string]$NestedInstallerFile,
    [System.Collections.IDictionary]$Override = [ordered]@{},
    [AllowNull()][string]$PackageVersion,
    [System.Collections.IDictionary]$Header,
    [string]$Proxy
  )

  $TemporaryFolder = $null
  $NestedTemporaryFolder = $null
  $DownloadResult = $null
  try {
    if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
      $TemporaryFolder = New-TempFolder
      $FileName = [IO.Path]::GetFileName($InstallerUrl.AbsolutePath)
      if ([string]::IsNullOrWhiteSpace($FileName)) { $FileName = 'installer.bin' }
      $InstallerPath = Join-Path $TemporaryFolder $FileName
      $DownloadArguments = @{ Uri = $InstallerUrl; DestinationPath = $InstallerPath }
      if ($Header) { $DownloadArguments.Header = $Header }
      if ($PSBoundParameters.ContainsKey('Proxy')) { $DownloadArguments.Proxy = $Proxy }
      $DownloadResult = Invoke-WinGetInstallerDownload @DownloadArguments
    } else {
      $InstallerPath = Convert-Path -LiteralPath $InstallerPath
    }

    $Hash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
    $Analysis = Get-WinGetInstallerAnalysis -Path $InstallerPath -ExtractEmbeddedMsi
    $ProjectionAnalysis = $Analysis
    $NestedAnalysis = $null
    $PhysicalInstallerType = $null
    $SelectedNestedFile = $null

    if ($Analysis.DetectedFileType.Type -ceq 'ZipArchive') {
      $ZipResult = @($Analysis.ParserResults | Where-Object { $_.Success -and $_.Result.Family -ceq 'ZIP/archive' } | Select-Object -First 1)[0]
      if ($null -eq $ZipResult) {
        $Analysis.BlockingIssues += 'The ZIP archive catalog could not be parsed.'
        $NestedCandidates = @()
      } else {
        $NestedCandidates = @($ZipResult.Result.NestedInstallerFiles)
      }
      if ($NestedCandidates.Count -eq 0) {
        $NestedCandidates = if ($ZipResult) { @($ZipResult.Result.PortableCandidates) } else { @() }
      }
      if ($NestedCandidates.Count -eq 0) {
        $Analysis.BlockingIssues += 'The ZIP archive contains no supported nested installer or portable PE candidate.'
      } elseif ([string]::IsNullOrWhiteSpace($NestedInstallerFile) -and $NestedCandidates.Count -gt 1) {
        $Analysis.BlockingIssues += "The ZIP archive contains $($NestedCandidates.Count) installer candidates; specify NestedInstallerFile."
      } else {
        $SelectedNestedFile = if ($NestedInstallerFile) {
          @($NestedCandidates | Where-Object { ([string]$_.FullName).Replace('\', '/') -ieq $NestedInstallerFile.Replace('\', '/') })
        } else { @($NestedCandidates[0]) }
        if ($SelectedNestedFile.Count -ne 1) {
          $Analysis.BlockingIssues += "NestedInstallerFile '$NestedInstallerFile' matched $($SelectedNestedFile.Count) archive entries; exactly one is required."
          $SelectedNestedFile = $null
        } else {
          $SelectedNestedFile = $SelectedNestedFile[0]
          $NestedTemporaryFolder = New-TempFolder
          $NestedPath = Join-Path $NestedTemporaryFolder ([IO.Path]::GetFileName([string]$SelectedNestedFile.FullName))
          $Archive = Get-InstallerArchive -Path $InstallerPath
          try {
            $ArchiveEntry = @(Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -ceq $SelectedNestedFile.FullName })[0]
            $null = Export-InstallerArchiveEntry -Entry $ArchiveEntry -DestinationPath $NestedPath -MaximumBytes 2147483648 -CollisionAction Overwrite
          } finally {
            $Archive.Dispose()
          }
          $NestedAnalysis = Get-WinGetInstallerAnalysis -Path $NestedPath -ExtractEmbeddedMsi
          $ProjectionAnalysis = $NestedAnalysis
          $PhysicalInstallerType = 'zip'
        }
      }
    }

    $Projection = Get-WinGetAuthoringAnalysisProjection -Analysis $ProjectionAnalysis -PackageVersion $PackageVersion
    $BlockingIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($Issue in @($Analysis.BlockingIssues + $Projection.BlockingIssues)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$Issue)) { $BlockingIssues.Add([string]$Issue) }
    }
    # An explicit portable override resolves the analyzer's conservative
    # no-family warning when static PE architecture/dependency evidence exists.
    $ExplicitTypeField = $PhysicalInstallerType -ceq 'zip' ? 'NestedInstallerType' : 'InstallerType'
    $ExplicitInstallerType = ConvertTo-WinGetAuthoringInstallerType -InstallerType ([string]$Override[$ExplicitTypeField])
    if ($ExplicitInstallerType -ceq 'portable' -and $ProjectionAnalysis.PortableEvidence) {
      $ResolvedMessage = 'No installer family was confirmed. Specify InstallerType=portable explicitly only after confirming that the PE is a portable command target.'
      $null = $BlockingIssues.Remove($ResolvedMessage)
    }

    $Fields = Copy-WinGetManifestValue -Value $Projection.ManifestFields
    if ($PhysicalInstallerType -ceq 'zip') {
      $NestedType = $Fields['InstallerType']
      $Fields['InstallerType'] = 'zip'
      if ($NestedType) { $Fields['NestedInstallerType'] = $NestedType }
      if ($SelectedNestedFile) { $Fields['NestedInstallerFiles'] = @([ordered]@{ RelativeFilePath = [string]$SelectedNestedFile.FullName }) }
    }
    $Fields['InstallerUrl'] = $InstallerUrl.AbsoluteUri
    $Fields['InstallerSha256'] = $Hash

    $ReleaseDate = Get-WinGetAuthoringReleaseDate -DownloadResult $DownloadResult
    if ($ReleaseDate) { $Fields['ReleaseDate'] = $ReleaseDate }
    if ($Scope) { $Fields['Scope'] = $Scope }

    $Architectures = @($Architecture | Where-Object { $_ } | Select-Object -Unique)
    if ($Architectures.Count -eq 0 -and $Projection.Architecture) { $Architectures = @($Projection.Architecture) }
    if ($Architectures.Count -eq 0) {
      $BlockingIssues.Add('A concrete x86, x64, or arm64 architecture is required because static analysis did not prove exactly one architecture.')
    }

    $Installers = [System.Collections.Generic.List[System.Collections.IDictionary]]::new()
    foreach ($ConcreteArchitecture in $Architectures) {
      $Entry = Copy-WinGetManifestValue -Value $Fields
      $Entry['Architecture'] = $ConcreteArchitecture
      $Entry = Merge-WinGetAuthoringPatch -Target $Entry -Patch (ConvertTo-WinGetAuthoringDictionary -InputObject $Override)
      if ($Entry.Contains('UnsupportedOSArchitectures')) {
        $BlockingIssues.Add('UnsupportedOSArchitectures is not authored by this workflow.')
        $Entry.Remove('UnsupportedOSArchitectures')
      }
      try {
        Assert-WinGetAuthoringInstallerEntry -Installer $Entry -ManifestVersion $Script:WinGetAuthoringManifestVersion
      } catch {
        $BlockingIssues.Add($_.Exception.Message)
      }
      $Installers.Add($Entry)
    }

    return [pscustomobject]@{
      PSTypeName       = 'Dumplings.WinGet.InstallerManifestSuggestion'
      InstallerUrl     = $InstallerUrl.AbsoluteUri
      InstallerPath    = $InstallerPath
      Installers       = @($Installers)
      ProposedInstallers = @($Installers)
      AppliedEvidence  = [pscustomobject]@{ Sha256 = $Hash; AnalyzerFields = $Projection.ManifestFields; ReleaseDate = $ReleaseDate }
      Suggestions      = $Projection.Suggestions
      UnresolvedSuggestions = $Projection.Suggestions
      Warnings         = @($Projection.Warnings | Select-Object -Unique)
      BlockingIssues   = @($BlockingIssues | Select-Object -Unique)
      Analysis         = $Analysis
      RawAnalysis      = $Analysis
      NestedAnalysis   = $NestedAnalysis
      DownloadResult   = $DownloadResult
    }
  } finally {
    if ($NestedTemporaryFolder) { Remove-Item -LiteralPath $NestedTemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue }
    if ($TemporaryFolder) { Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

function Add-WinGetManifestInstaller {
  <#
  .SYNOPSIS
    Append analyzed installer entries to a detached logical manifest model.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER Suggestion
    Precomputed result from Get-WinGetInstallerManifestSuggestion.
  .PARAMETER InstallerUrl
    Installer URL to analyze when Suggestion is not supplied.
  .PARAMETER InstallerPath
    Optional local copy of InstallerUrl.
  .PARAMETER Architecture
    Explicit concrete architectures.
  .PARAMETER Scope
    Explicit installer scope.
  .PARAMETER NestedInstallerFile
    Exact nested payload path for an archive with multiple candidates.
  .PARAMETER Override
    Explicit installer fields applied after analyzer evidence.
  .PARAMETER Header
    Optional download request headers.
  .PARAMETER Proxy
    Optional download proxy.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Analyze')]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory, ParameterSetName = 'Suggestion')]$Suggestion,
    [Parameter(Mandatory, ParameterSetName = 'Analyze')][uri]$InstallerUrl,
    [Parameter(ParameterSetName = 'Analyze')][string]$InstallerPath,
    [Parameter(ParameterSetName = 'Analyze')][ValidateSet('x86', 'x64', 'arm64')][string[]]$Architecture,
    [Parameter(ParameterSetName = 'Analyze')][ValidateSet('user', 'machine')][string]$Scope,
    [Parameter(ParameterSetName = 'Analyze')][string]$NestedInstallerFile,
    [Parameter(ParameterSetName = 'Analyze')][System.Collections.IDictionary]$Override = [ordered]@{},
    [Parameter(ParameterSetName = 'Analyze')][System.Collections.IDictionary]$Header,
    [Parameter(ParameterSetName = 'Analyze')][string]$Proxy
  )

  process {
    if ($PSCmdlet.ParameterSetName -ceq 'Analyze') {
      $Arguments = @{ InstallerUrl = $InstallerUrl; PackageVersion = [string]$Manifest.PackageVersion; Override = $Override }
      foreach ($Name in @('InstallerPath', 'Architecture', 'Scope', 'NestedInstallerFile', 'Header', 'Proxy')) {
        if ($PSBoundParameters.ContainsKey($Name)) { $Arguments[$Name] = $PSBoundParameters[$Name] }
      }
      $Suggestion = Get-WinGetInstallerManifestSuggestion @Arguments
    }
    if (@($Suggestion.BlockingIssues).Count -gt 0) {
      throw "The installer suggestion contains blocking issues:`n$(@($Suggestion.BlockingIssues) -join "`n")"
    }
    foreach ($Warning in @($Suggestion.Warnings)) { Write-Warning $Warning }
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    $Installers = [System.Collections.Generic.List[System.Collections.IDictionary]]::new()
    $Installers.AddRange([System.Collections.IDictionary[]]@($Copy.Installers))
    foreach ($Installer in @($Suggestion.Installers)) {
      Assert-WinGetAuthoringInstallerEntry -Installer $Installer -ManifestVersion ([string]$Copy.ManifestVersion)
      $Installers.Add((ConvertTo-WinGetAuthoringDictionary -InputObject $Installer))
    }
    $Copy.Installers = $Installers.ToArray()
    return Optimize-WinGetManifest -Manifest $Copy
  }
}

function Set-WinGetManifestInstaller {
  <#
  .SYNOPSIS
    Recursively patch exactly one installer on a detached manifest model.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER Index
    Zero-based installer index.
  .PARAMETER Match
    Exact-match selector dictionary.
  .PARAMETER Patch
    Recursive patch. Arrays replace and null values remove fields.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a detached in-memory model and changes no caller-owned state.')]
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Index')]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory, ParameterSetName = 'Index')][ValidateRange(0, [int]::MaxValue)][int]$Index,
    [Parameter(Mandatory, ParameterSetName = 'Match')][System.Collections.IDictionary]$Match,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Patch
  )

  process {
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    $Selector = @{ Manifest = $Copy }
    if ($PSCmdlet.ParameterSetName -ceq 'Index') { $Selector.Index = $Index } else { $Selector.Match = $Match }
    $SelectedIndex = Get-WinGetAuthoringInstallerIndex @Selector
    $Copy.Installers[$SelectedIndex] = Merge-WinGetAuthoringPatch -Target $Copy.Installers[$SelectedIndex] -Patch $Patch
    Assert-WinGetAuthoringInstallerEntry -Installer $Copy.Installers[$SelectedIndex] -ManifestVersion ([string]$Copy.ManifestVersion)
    return $Copy
  }
}

function Remove-WinGetManifestInstaller {
  <#
  .SYNOPSIS
    Remove exactly one installer from a detached manifest model.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER Index
    Zero-based installer index.
  .PARAMETER Match
    Exact-match selector dictionary.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a detached in-memory model and changes no caller-owned state.')]
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Index')]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory, ParameterSetName = 'Index')][ValidateRange(0, [int]::MaxValue)][int]$Index,
    [Parameter(Mandatory, ParameterSetName = 'Match')][System.Collections.IDictionary]$Match
  )

  process {
    if (@($Manifest.Installers).Count -le 1) { throw 'The last installer entry cannot be removed.' }
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    $Selector = @{ Manifest = $Copy }
    if ($PSCmdlet.ParameterSetName -ceq 'Index') { $Selector.Index = $Index } else { $Selector.Match = $Match }
    $SelectedIndex = Get-WinGetAuthoringInstallerIndex @Selector
    $Copy.Installers = @(for ($CandidateIndex = 0; $CandidateIndex -lt @($Copy.Installers).Count; $CandidateIndex++) {
        if ($CandidateIndex -ne $SelectedIndex) { $Copy.Installers[$CandidateIndex] }
      })
    return $Copy
  }
}

function Add-WinGetManifestLocale {
  <#
  .SYNOPSIS
    Add one additional locale to a detached manifest model.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER Localization
    Locale dictionary containing PackageLocale.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Localization
  )

  process {
    $Locale = [string]$Localization['PackageLocale']
    if ([string]::IsNullOrWhiteSpace($Locale)) { throw 'Localization must contain PackageLocale.' }
    if ([string]$Manifest.DefaultLocalization['PackageLocale'] -ieq $Locale -or @($Manifest.Localizations | Where-Object { [string]$_['PackageLocale'] -ieq $Locale }).Count -gt 0) {
      throw "Locale '$Locale' already exists."
    }
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    $Copy.Localizations = @($Copy.Localizations) + @(ConvertTo-WinGetAuthoringDictionary -InputObject $Localization)
    return $Copy
  }
}

function Set-WinGetManifestLocale {
  <#
  .SYNOPSIS
    Recursively patch the default or an additional locale.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER PackageLocale
    Case-insensitive locale selector.
  .PARAMETER Patch
    Recursive patch dictionary.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a detached in-memory model and changes no caller-owned state.')]
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory)][string]$PackageLocale,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Patch
  )

  process {
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    $IsDefaultLocale = [string]$Copy.DefaultLocalization['PackageLocale'] -ieq $PackageLocale
    if ($IsDefaultLocale) {
      $Copy.DefaultLocalization = Merge-WinGetAuthoringPatch -Target $Copy.DefaultLocalization -Patch $Patch
    } else {
      $Index = Get-WinGetAuthoringLocaleIndex -Manifest $Copy -PackageLocale $PackageLocale
      $Copy.Localizations[$Index] = Merge-WinGetAuthoringPatch -Target $Copy.Localizations[$Index] -Patch $Patch
    }
    $ResultLocale = if ($IsDefaultLocale) { [string]$Copy.DefaultLocalization['PackageLocale'] } else { [string]$Copy.Localizations[$Index]['PackageLocale'] }
    if ([string]::IsNullOrWhiteSpace($ResultLocale)) { throw 'A locale patch cannot remove PackageLocale.' }
    $LocaleOccurrences = @([string]$Copy.DefaultLocalization['PackageLocale']) + @($Copy.Localizations | ForEach-Object { [string]$_['PackageLocale'] })
    if (@($LocaleOccurrences | Where-Object { $_ -ieq $ResultLocale }).Count -gt 1) { throw "Locale '$ResultLocale' already exists." }
    return $Copy
  }
}

function Remove-WinGetManifestLocale {
  <#
  .SYNOPSIS
    Remove one additional locale from a detached manifest model.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER PackageLocale
    Case-insensitive locale selector. The default locale cannot be removed.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a detached in-memory model and changes no caller-owned state.')]
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory)][string]$PackageLocale
  )

  process {
    if ([string]$Manifest.DefaultLocalization['PackageLocale'] -ieq $PackageLocale) { throw 'The default locale cannot be removed.' }
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    $Index = Get-WinGetAuthoringLocaleIndex -Manifest $Copy -PackageLocale $PackageLocale
    $Copy.Localizations = @(for ($CandidateIndex = 0; $CandidateIndex -lt @($Copy.Localizations).Count; $CandidateIndex++) {
        if ($CandidateIndex -ne $Index) { $Copy.Localizations[$CandidateIndex] }
      })
    return $Copy
  }
}

function ConvertFrom-WinGetAuthoringPointer {
  <#
  .SYNOPSIS
    Decode an RFC 6901 property path into segments.
  .PARAMETER Path
    RFC 6901 path beginning with a slash.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][string]$Path)

  if ([string]::IsNullOrEmpty($Path) -or $Path[0] -cne '/') { throw 'The property path must be a nonempty RFC 6901 path beginning with /.' }
  return @($Path.Substring(1).Split('/') | ForEach-Object { $_ -replace '~1', '/' -replace '~0', '~' })
}

function Set-WinGetAuthoringPointerValue {
  <#
  .SYNOPSIS
    Set or remove a dictionary field addressed by an RFC 6901 path.
  .PARAMETER Root
    Mutable root dictionary.
  .PARAMETER Path
    RFC 6901 property path.
  .PARAMETER Value
    Detached replacement value.
  .PARAMETER Remove
    Remove the addressed field instead of setting it.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Mutates only an internal detached dictionary.')]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Root,
    [Parameter(Mandatory)][string]$Path,
    [AllowNull()]$Value,
    [switch]$Remove
  )

  [string[]]$Segments = @(ConvertFrom-WinGetAuthoringPointer -Path $Path)
  $Current = $Root
  for ($Index = 0; $Index -lt $Segments.Count - 1; $Index++) {
    $Segment = $Segments[$Index]
    if ($Current -isnot [System.Collections.IDictionary]) { throw "Property path '$Path' does not address a dictionary at '$Segment'." }
    # Set operations may create missing dictionary parents. Remove operations
    # remain exact and fail when any addressed field is absent.
    if (-not $Current.Contains($Segment)) {
      if ($Remove) { throw "Property path '$Path' does not exist at '$Segment'." }
      $Current[$Segment] = [ordered]@{}
    }
    $Current = $Current[$Segment]
  }
  if ($Current -isnot [System.Collections.IDictionary]) { throw "Property path '$Path' does not address a dictionary field." }
  $Leaf = $Segments[-1]
  if ($Remove) {
    if (-not $Current.Contains($Leaf)) { throw "Property path '$Path' does not exist." }
    $Current.Remove($Leaf)
  } else {
    $Current[$Leaf] = Copy-WinGetManifestValue -Value $Value
  }
}

function Get-WinGetAuthoringModelState {
  <#
  .SYNOPSIS
    Convert a logical model to a mutable dictionary for property-path edits.
  .PARAMETER Manifest
    Logical manifest model.
  #>
  [OutputType([System.Collections.IDictionary])]
  param ([Parameter(Mandatory)]$Manifest)

  return [ordered]@{
    PackageIdentifier   = [string]$Manifest.PackageIdentifier
    PackageVersion      = [string]$Manifest.PackageVersion
    Channel             = [string]$Manifest.Channel
    Moniker             = [string]$Manifest.Moniker
    ManifestVersion     = [string]$Manifest.ManifestVersion
    InstallerDefaults   = ConvertTo-WinGetAuthoringDictionary -InputObject $Manifest.InstallerDefaults
    Installers          = @($Manifest.Installers | ForEach-Object { ConvertTo-WinGetAuthoringDictionary -InputObject $_ })
    DefaultLocalization = ConvertTo-WinGetAuthoringDictionary -InputObject $Manifest.DefaultLocalization
    Localizations       = @($Manifest.Localizations | ForEach-Object { ConvertTo-WinGetAuthoringDictionary -InputObject $_ })
  }
}

function ConvertTo-WinGetAuthoringModelFromState {
  <#
  .SYNOPSIS
    Reconstruct a detached logical model from a mutable state dictionary.
  .PARAMETER State
    Model state from Get-WinGetAuthoringModelState.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][System.Collections.IDictionary]$State)

  return New-WinGetManifestModel -PackageIdentifier ([string]$State['PackageIdentifier']) -PackageVersion ([string]$State['PackageVersion']) `
    -Channel ([string]$State['Channel']) -Moniker ([string]$State['Moniker']) -ManifestVersion ([string]$State['ManifestVersion']) `
    -InstallerDefaults $State['InstallerDefaults'] -Installers ([System.Collections.IDictionary[]]@($State['Installers'])) `
    -DefaultLocalization $State['DefaultLocalization'] -Localizations ([System.Collections.IDictionary[]]@($State['Localizations'])) -SourceFormat Memory
}

function Set-WinGetManifestValue {
  <#
  .SYNOPSIS
    Set a package, installer, or locale field by RFC 6901 property path.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER Target
    Package, Installer, or Locale target.
  .PARAMETER Path
    RFC 6901 property path relative to the selected target.
  .PARAMETER Value
    Replacement value.
  .PARAMETER Index
    Zero-based installer selector.
  .PARAMETER Match
    Exact installer selector.
  .PARAMETER PackageLocale
    Locale selector.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a detached in-memory model and changes no caller-owned state.')]
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory)][ValidateSet('Package', 'Installer', 'Locale')][string]$Target,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][AllowNull()]$Value,
    [ValidateRange(0, [int]::MaxValue)][int]$Index,
    [System.Collections.IDictionary]$Match,
    [string]$PackageLocale
  )

  process {
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    switch ($Target) {
      'Package' {
        $State = Get-WinGetAuthoringModelState -Manifest $Copy
        Set-WinGetAuthoringPointerValue -Root $State -Path $Path -Value $Value
        return ConvertTo-WinGetAuthoringModelFromState -State $State
      }
      'Installer' {
        $Selector = @{ Manifest = $Copy }
        if ($PSBoundParameters.ContainsKey('Match')) { $Selector.Match = $Match } elseif ($PSBoundParameters.ContainsKey('Index')) { $Selector.Index = $Index } else { throw 'Installer target requires Index or Match.' }
        $SelectedIndex = Get-WinGetAuthoringInstallerIndex @Selector
        Set-WinGetAuthoringPointerValue -Root $Copy.Installers[$SelectedIndex] -Path $Path -Value $Value
        Assert-WinGetAuthoringInstallerEntry -Installer $Copy.Installers[$SelectedIndex] -ManifestVersion ([string]$Copy.ManifestVersion)
        return $Copy
      }
      'Locale' {
        if ([string]::IsNullOrWhiteSpace($PackageLocale)) { throw 'Locale target requires PackageLocale.' }
        if ([string]$Copy.DefaultLocalization['PackageLocale'] -ieq $PackageLocale) {
          Set-WinGetAuthoringPointerValue -Root $Copy.DefaultLocalization -Path $Path -Value $Value
        } else {
          $LocaleIndex = Get-WinGetAuthoringLocaleIndex -Manifest $Copy -PackageLocale $PackageLocale
          Set-WinGetAuthoringPointerValue -Root $Copy.Localizations[$LocaleIndex] -Path $Path -Value $Value
        }
        return $Copy
      }
    }
  }
}

function Remove-WinGetManifestValue {
  <#
  .SYNOPSIS
    Remove a package, installer, or locale field by RFC 6901 property path.
  .PARAMETER Manifest
    Source logical manifest model.
  .PARAMETER Target
    Package, Installer, or Locale target.
  .PARAMETER Path
    RFC 6901 property path relative to the selected target.
  .PARAMETER Index
    Zero-based installer selector.
  .PARAMETER Match
    Exact installer selector.
  .PARAMETER PackageLocale
    Locale selector.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns a detached in-memory model and changes no caller-owned state.')]
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory)][ValidateSet('Package', 'Installer', 'Locale')][string]$Target,
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(0, [int]::MaxValue)][int]$Index,
    [System.Collections.IDictionary]$Match,
    [string]$PackageLocale
  )

  process {
    $Copy = Copy-WinGetAuthoringManifestModel -Manifest $Manifest
    switch ($Target) {
      'Package' {
        $State = Get-WinGetAuthoringModelState -Manifest $Copy
        Set-WinGetAuthoringPointerValue -Root $State -Path $Path -Remove
        return ConvertTo-WinGetAuthoringModelFromState -State $State
      }
      'Installer' {
        $Selector = @{ Manifest = $Copy }
        if ($PSBoundParameters.ContainsKey('Match')) { $Selector.Match = $Match } elseif ($PSBoundParameters.ContainsKey('Index')) { $Selector.Index = $Index } else { throw 'Installer target requires Index or Match.' }
        $SelectedIndex = Get-WinGetAuthoringInstallerIndex @Selector
        Set-WinGetAuthoringPointerValue -Root $Copy.Installers[$SelectedIndex] -Path $Path -Remove
        Assert-WinGetAuthoringInstallerEntry -Installer $Copy.Installers[$SelectedIndex] -ManifestVersion ([string]$Copy.ManifestVersion)
        return $Copy
      }
      'Locale' {
        if ([string]::IsNullOrWhiteSpace($PackageLocale)) { throw 'Locale target requires PackageLocale.' }
        if ([string]$Copy.DefaultLocalization['PackageLocale'] -ieq $PackageLocale) {
          Set-WinGetAuthoringPointerValue -Root $Copy.DefaultLocalization -Path $Path -Remove
        } else {
          $LocaleIndex = Get-WinGetAuthoringLocaleIndex -Manifest $Copy -PackageLocale $PackageLocale
          Set-WinGetAuthoringPointerValue -Root $Copy.Localizations[$LocaleIndex] -Path $Path -Remove
        }
        return $Copy
      }
    }
  }
}

function Save-WinGetManifest {
  <#
  .SYNOPSIS
    Validate and atomically write a complete logical manifest set.
  .DESCRIPTION
    Writes to a sibling staging directory, validates the physical output, then
    replaces the leaf target. If replacement fails, the original directory is
    restored. Unexpected files or nested directories in an existing target are
    rejected before any write.
  .PARAMETER Manifest
    Complete logical manifest model.
  .PARAMETER Path
    Leaf package-version directory to replace.
  .PARAMETER ErrorOnWarning
    Treat validation warnings as blocking failures.
  .PARAMETER PassThru
    Return the manifest, path, and validation evidence.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(SupportsShouldProcess)]
  param (
    [Parameter(Mandatory, ValueFromPipeline)]$Manifest,
    [Parameter(Mandatory)][string]$Path,
    [switch]$ErrorOnWarning,
    [switch]$PassThru
  )

  process {
    $OptimizedManifest = Optimize-WinGetManifest -Manifest (Copy-WinGetAuthoringManifestModel -Manifest $Manifest)
    $InMemoryValidation = Get-WinGetManifestValidationResult -Manifest $OptimizedManifest
    foreach ($Warning in $InMemoryValidation.Warnings) { Write-Warning "[$($Warning.Id)] $($Warning.Message)" }
    if ($InMemoryValidation.HasErrors -or ($ErrorOnWarning -and $InMemoryValidation.HasWarnings)) {
      $Failures = $InMemoryValidation.HasErrors ? $InMemoryValidation.Errors : $InMemoryValidation.Warnings
      throw "Manifest validation failed before writing:`n$(@($Failures | ForEach-Object { "[$($_.Id)] $($_.Message)" }) -join "`n")"
    }

    $TargetPath = [IO.Path]::GetFullPath($Path, (Get-Location).ProviderPath)
    if ([string]::IsNullOrWhiteSpace([IO.Path]::GetFileName($TargetPath)) -or [string]::IsNullOrWhiteSpace([IO.Path]::GetDirectoryName($TargetPath))) {
      throw "Target path '$TargetPath' is not a leaf package-version directory."
    }
    if (Test-Path -LiteralPath $TargetPath) {
      if (-not (Test-Path -LiteralPath $TargetPath -PathType Container)) { throw "Target path '$TargetPath' is not a directory." }
      $UnexpectedDirectories = @(Get-ChildItem -LiteralPath $TargetPath -Directory -Force)
      $ManifestNamePattern = '^{0}(?:\.installer|\.locale\.[A-Za-z0-9-]+)?\.yaml$' -f [regex]::Escape([string]$OptimizedManifest.PackageIdentifier)
      $UnexpectedFiles = @(Get-ChildItem -LiteralPath $TargetPath -File -Force | Where-Object { $_.Name -cnotmatch $ManifestNamePattern })
      if ($UnexpectedDirectories.Count -gt 0 -or $UnexpectedFiles.Count -gt 0) {
        throw "Target directory '$TargetPath' contains nested directories or non-manifest files."
      }
    }

    if (-not $PSCmdlet.ShouldProcess($TargetPath, 'Atomically replace WinGet manifest set')) {
      if ($PassThru) {
        return [pscustomobject]@{ PSTypeName = 'Dumplings.WinGet.ManifestSaveResult'; Path = $TargetPath; Manifest = $OptimizedManifest; Validation = $InMemoryValidation; Written = $false }
      }
      return
    }

    $ParentPath = [IO.Path]::GetDirectoryName($TargetPath)
    $LeafName = [IO.Path]::GetFileName($TargetPath)
    $StagePath = Join-Path $ParentPath ".$LeafName.stage.$([guid]::NewGuid().ToString('N'))"
    $BackupPath = Join-Path $ParentPath ".$LeafName.backup.$([guid]::NewGuid().ToString('N'))"
    $TargetMoved = $false
    try {
      $null = New-Item -Path $ParentPath -ItemType Directory -Force
      $Bundle = ConvertTo-WinGetManifestYaml -Manifest $OptimizedManifest
      Add-WinGetLocalManifests -PackageIdentifier ([string]$OptimizedManifest.PackageIdentifier) -Path $StagePath -Manifest $Bundle
      $PhysicalValidation = Get-WinGetManifestValidationResult -Path $StagePath
      foreach ($Warning in $PhysicalValidation.Warnings) { Write-Warning "[$($Warning.Id)] $($Warning.Message)" }
      if ($PhysicalValidation.HasErrors -or ($ErrorOnWarning -and $PhysicalValidation.HasWarnings)) {
        $Failures = $PhysicalValidation.HasErrors ? $PhysicalValidation.Errors : $PhysicalValidation.Warnings
        throw "Staged manifest validation failed:`n$(@($Failures | ForEach-Object { "[$($_.Id)] $($_.Message)" }) -join "`n")"
      }

      if (Test-Path -LiteralPath $TargetPath) {
        Move-Item -LiteralPath $TargetPath -Destination $BackupPath
        $TargetMoved = $true
      }
      Move-Item -LiteralPath $StagePath -Destination $TargetPath
      if ($TargetMoved) { Remove-Item -LiteralPath $BackupPath -Recurse -Force }

      if ($PassThru) {
        return [pscustomobject]@{ PSTypeName = 'Dumplings.WinGet.ManifestSaveResult'; Path = $TargetPath; Manifest = $OptimizedManifest; Validation = $PhysicalValidation; Written = $true }
      }
    } catch {
      if ($TargetMoved -and -not (Test-Path -LiteralPath $TargetPath) -and (Test-Path -LiteralPath $BackupPath)) {
        Move-Item -LiteralPath $BackupPath -Destination $TargetPath -ErrorAction SilentlyContinue
      }
      throw
    } finally {
      Remove-Item -LiteralPath $StagePath -Recurse -Force -ErrorAction SilentlyContinue
      if ((Test-Path -LiteralPath $BackupPath) -and (Test-Path -LiteralPath $TargetPath)) {
        Remove-Item -LiteralPath $BackupPath -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

Export-ModuleMember -Function New-WinGetManifest, Get-WinGetInstallerManifestSuggestion, Add-WinGetManifestInstaller, Set-WinGetManifestInstaller, Remove-WinGetManifestInstaller, Add-WinGetManifestLocale, Set-WinGetManifestLocale, Remove-WinGetManifestLocale, Set-WinGetManifestValue, Remove-WinGetManifestValue, Save-WinGetManifest
