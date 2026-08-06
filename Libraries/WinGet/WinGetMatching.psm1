# SPDX-License-Identifier: Apache-2.0
# WinGet normalization and manifest-to-installed-state matching.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
Set-StrictMode -Version 3

$script:WinGetLegalEntitySuffixes = @(
  'AB', 'AD', 'AG', 'APS', 'AS', 'ASA', 'BV', 'CO', 'COMPANY', 'CORP', 'CORPORATION', 'CV', 'DOO',
  'EV', 'GES', 'GESMBH', 'GMBH', 'HOLDING', 'HOLDINGS', 'INC', 'INCORPORATED', 'KG', 'KS', 'LIMITED',
  'LLC', 'LP', 'LTD', 'LTDA', 'MBH', 'NV', 'PLC', 'PS', 'PTY', 'PVT', 'SA', 'SARL', 'SC', 'SCA',
  'SL', 'SP', 'SPA', 'SRL', 'SRO', 'SUBSIDIARY'
)

function Get-WinGetInstalledARPEntry {
  <#
  .SYNOPSIS
    Enumerate installed ARP records and append WinGet-normalized match fields.
  .PARAMETER IncludeSystemComponent
    Include hidden records whose SystemComponent value is set.
  #>
  [OutputType([pscustomobject])]
  param ([switch]$IncludeSystemComponent)
  foreach ($Entry in Get-InstalledARPEntry -IncludeSystemComponent:$IncludeSystemComponent) {
    $Normalized = ConvertTo-WinGetNormalizedNameAndPublisher -Name $Entry.DisplayName -Publisher $Entry.Publisher
    $Entry | Add-Member -NotePropertyName NormalizedName -NotePropertyValue $Normalized.NormalizedName -Force
    $Entry | Add-Member -NotePropertyName NormalizedPublisher -NotePropertyValue $Normalized.NormalizedPublisher -Force
    $Entry | Add-Member -NotePropertyName NormalizedNameAndPublisher -NotePropertyValue $Normalized.NormalizedNameAndPublisher -Force
    $Entry
  }
}


function Get-WinGetDictionaryValue {
  param (
    [Parameter()]
    $InputObject,

    [Parameter(Mandatory)]
    [string]$Key
  )

  if ($null -eq $InputObject) { return $null }

  if ($InputObject -is [System.Collections.IDictionary]) {
    if ($InputObject.Contains($Key)) { return $InputObject[$Key] }
    return $null
  }

  $Property = $InputObject.PSObject.Properties[$Key]
  if ($Property) { return $Property.Value }

  return $null
}

function ConvertTo-WinGetArray {
  param (
    [Parameter()]
    $InputObject
  )

  if ($null -eq $InputObject) { return @() }
  if ($InputObject -is [string]) { return @($InputObject) }
  if ($InputObject -is [System.Collections.IDictionary]) { return @($InputObject) }
  if ($InputObject -is [System.Collections.IEnumerable]) { return @($InputObject) }
  return @($InputObject)
}

function Add-WinGetUniqueString {
  param (
    [Parameter()]
    [System.Collections.Generic.List[string]]$List,

    [Parameter()]
    [System.Collections.Generic.HashSet[string]]$Set,

    [Parameter()]
    $Value
  )

  if ($null -eq $Value) { return }

  $StringValue = [string]$Value
  if ([string]::IsNullOrWhiteSpace($StringValue)) { return }

  if ($Set.Add($StringValue)) { $List.Add($StringValue) }
}

function ConvertTo-WinGetNameWithoutNoise {
  param (
    [Parameter()]
    [string]$Value,

    [Parameter()]
    [switch]$Publisher
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return '' }

  $Result = $Value.Normalize([System.Text.NormalizationForm]::FormC).Trim()
  $AtIndex = $Result.IndexOf('@@', 3, [System.StringComparison]::Ordinal)
  if ($AtIndex -ge 0) { $Result = $Result.Substring(0, $AtIndex).Trim() }

  while ($Result.Length -ge 2 -and (($Result[0] -eq '"' -and $Result[-1] -eq '"') -or ($Result[0] -eq '(' -and $Result[-1] -eq ')'))) {
    $Result = $Result.Substring(1, $Result.Length - 2).Trim()
  }

  if (-not $Publisher) {
    $Result = $Result -replace '\((KB\d+)\)', '$1'
    $Result = $Result -replace '(?i)(?<=^|[^\p{L}\p{Nd}])((64[\\/]|32[\\/])?32[\\/ ]?64[\p{Pd}\p{Pc}\p{Z}]?bit)s?(?:\s+edition)?(?=\P{Nd}|$)', ' '
    $Result = $Result -replace '(?i)(?<=^|[^\p{L}\p{Nd}])(x64|amd64|x86[\p{Pd}\p{Pc}]64|64[\p{Pd}\p{Pc}\p{Z}]?bit)s?(?:\s+edition)?(?=\P{Nd}|$)', ' '
    $Result = $Result -replace '(?i)(?<=^|[^\p{L}\p{Nd}])(x32|x86|32[\p{Pd}\p{Pc}\p{Z}]?bit)s?(?:\s+edition)?(?=\P{Nd}|$)', ' '
    $Result = $Result -replace '(?i)(?<![A-Z])(?:[A-Z]{2,3}(?:-(?:CANS|CYRL|LATN|MONG))?-[A-Z]{2}(?:-VALENCIA)?)(?![A-Z])', ' '
    $Result = $Result -replace '(?i)^\(.*?\)', ' '
    $Result = $Result -replace '(?i)(\(\s*\)|\[\s*\]|"\s*")', ' '
    $Result = $Result -replace '(?i)\(change #\d{1,2} to [CDEF]:\\(.+?\\)*[^\s]*\\?\)', ' '
    $Result = $Result -replace '(?i)\([CDEF]:\\(.+?\\)*[^\s]*\\?\)', ' '
    $Result = $Result -replace '(?i)"[CDEF]:\\(.+?\\)*[^\s]*\\?"', ' '
    $Result = $Result -replace '(?i)((installed\s+at|in)\s+)?[CDEF]:\\(.+?\\)*[^\s]*\\?', ' '
    $Result = $Result -replace '(?i)(?<!\p{L})(?:http[s]?|ftp)://', ' '
    $Result = $Result -replace '(?i)((?<!\p{L})(?:v|ver|version|versie|wersja|build|release|rc|sp)\P{L}?)?\p{Nd}+([\p{Po}\p{Pd}\p{Pc}]\p{Nd}?(rc|b|a|r|sp|k)?\p{Nd}+)+([\p{Po}\p{Pd}\p{Pc}]?[\p{L}\p{Nd}]+)*', ' '
    $Result = $Result -replace '(?i)(for\s)?(?<!\p{L})(?:p|v|r|ver|version|versie|wersja|build|release|rc|sp)(?:\P{L}|\P{L}\p{L})?(\p{Nd}|\.\p{Nd})+(?:rc|b|a|r|v|sp)?\p{Nd}?', ' '
    $Result = $Result -replace '(?i)(?<!\p{L})(?:(?:v|ver|version|versie|wersja|build|release|rc|sp)\P{L})?\p{Lu}\p{Nd}+(?:[\p{Po}\p{Pd}\p{Pc}]\p{Nd}+)+', ' '
    $Result = $Result -replace '(?i)\([^\(\)]*\)|\[[^\[\]]*\]', ' '
    $Result = $Result -replace '(?i)(?:\p{Ps}.*\p{Pe}|".*")', ' '
    $Result = $Result -replace '(?i)\sEN\s*$', ' '
    $Result = $Result -replace '^[^\p{L}\p{Nd}]+', ' '
    $Result = $Result -replace '[^\p{L}\p{Nd}]+$', ' '
  } else {
    $Result = $Result -replace '(?i)(?<!\p{L})(?:http[s]?|ftp)://', ' '
    $Result = $Result -replace '(?i)((?<!\p{L})(?:v|ver|version|versie|wersja|build|release|rc|sp)\P{L}?)?\p{Nd}+([\p{Po}\p{Pd}\p{Pc}]\p{Nd}?(rc|b|a|r|sp|k)?\p{Nd}+)+([\p{Po}\p{Pd}\p{Pc}]?[\p{L}\p{Nd}]+)*', ' '
    $Result = $Result -replace '(?i)(for\s)?(?<!\p{L})(?:p|v|r|ver|version|versie|wersja|build|release|rc|sp)(?:\P{L}|\P{L}\p{L})?(\p{Nd}|\.\p{Nd})+(?:rc|b|a|r|v|sp)?\p{Nd}?', ' '
    $Result = $Result -replace '(?i)\([^\(\)]*\)|\[[^\[\]]*\]', ' '
    $Result = $Result -replace '(?i)(?:\p{Ps}.*\p{Pe}|".*")', ' '
    $Result = $Result -replace '(?i)(?<=^|\s)[^\p{L}]+(?=\s|$)', ' '
    $Result = $Result -replace '\P{L}+$', ' '
  }

  return $Result.Trim()
}

function ConvertTo-WinGetNormalizedTokenString {
  param (
    [Parameter()]
    [string]$Value,

    [Parameter()]
    [switch]$Publisher
  )

  $Cleaned = ConvertTo-WinGetNameWithoutNoise -Value $Value -Publisher:$Publisher
  if ([string]::IsNullOrWhiteSpace($Cleaned)) { return '' }

  $SplitExpression = $Publisher ? '[^\p{L}\p{Nd}]+' : '[^\p{L}\p{Nd}\+&]+'
  $Tokens = [regex]::Split($Cleaned, $SplitExpression) | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) }

  $Output = [System.Collections.Generic.List[string]]::new()
  foreach ($Token in $Tokens) {
    $FoldedToken = $Token.ToUpperInvariant()

    if ($Output.Count -gt 0 -and $script:WinGetLegalEntitySuffixes -ccontains $FoldedToken) {
      if ($Publisher) { break }
      continue
    }

    $Output.Add($Token)
  }

  ([string]::Concat($Output) -replace '[^\p{L}\p{Nd}]', '')
}

function ConvertTo-WinGetNormalizedNameAndPublisher {
  <#
  .SYNOPSIS
    Generate a WinGet-style normalized name and publisher pair
  .DESCRIPTION
    Generate the normalized package name, normalized publisher, and combined normalized pair used by Dumplings installed-entry matching.
    This follows WinGet's NameNormalizer behavior closely enough for validation workflows, but WinGet itself remains the authority for final repository matching.
  .PARAMETER Name
    The package display name to normalize
  .PARAMETER Publisher
    The package publisher to normalize
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName, HelpMessage = 'The package display name to normalize')]
    [Alias('DisplayName', 'PackageName')]
    [string]$Name,

    [Parameter(Position = 1, ValueFromPipelineByPropertyName, HelpMessage = 'The package publisher to normalize')]
    [AllowNull()]
    [string]$Publisher
  )

  process {
    $NormalizedName = ConvertTo-WinGetNormalizedTokenString -Value $Name
    $NormalizedPublisher = ConvertTo-WinGetNormalizedTokenString -Value $Publisher -Publisher

    [pscustomobject]@{
      Name                       = $Name
      Publisher                  = $Publisher
      NormalizedName             = $NormalizedName
      NormalizedPublisher        = $NormalizedPublisher
      NormalizedNameAndPublisher = "${NormalizedPublisher}.${NormalizedName}"
    }
  }
}

function Get-WinGetInstalledAppXEntry {
  <#
  .SYNOPSIS
    Collect installed AppX/MSIX packages for PackageFamilyName matching
  .DESCRIPTION
    Collect installed AppX/MSIX packages with Get-AppxPackage and return the PackageFamilyName values WinGet uses for AppX/MSIX matching.
  .PARAMETER AllUsers
    Query packages for all users. This may require elevation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'Query packages for all users. This may require elevation.')]
    [switch]$AllUsers
  )

  $Command = Get-Command -Name 'Get-AppxPackage' -ErrorAction 'SilentlyContinue'
  if (-not $Command) { return }

  $Parameters = @{}
  if ($AllUsers) { $Parameters['AllUsers'] = $true }

  Get-AppxPackage @Parameters | ForEach-Object -Process {
    $Publisher = [string]($_.PublisherDisplayName ?? $_.Publisher)
    $Normalized = ConvertTo-WinGetNormalizedNameAndPublisher -Name $_.Name -Publisher $Publisher

    [pscustomobject]@{
      Source                     = 'AppX'
      ProductCode                = $null
      UpgradeCode                = $null
      PackageFamilyName          = [string]$_.PackageFamilyName
      PackageFullName            = [string]$_.PackageFullName
      DisplayName                = [string]$_.Name
      PackageName                = [string]$_.Name
      Publisher                  = $Publisher
      Version                    = [string]$_.Version
      DisplayVersion             = [string]$_.Version
      InstallerType              = 'msix'
      Architecture               = [string]$_.Architecture
      Scope                      = $AllUsers ? 'allUsers' : 'user'
      IsFramework                = [bool]$_.IsFramework
      IsResourcePackage          = [bool]$_.IsResourcePackage
      NonRemovable               = [bool]$_.NonRemovable
      SignatureKind              = [string]$_.SignatureKind
      Status                     = [string]$_.Status
      InstallLocation            = [string]$_.InstallLocation
      PackageUserInformation     = $_.PackageUserInformation
      NormalizedName             = $Normalized.NormalizedName
      NormalizedPublisher        = $Normalized.NormalizedPublisher
      NormalizedNameAndPublisher = $Normalized.NormalizedNameAndPublisher
    }
  }
}

function Get-WinGetInstalledEntry {
  <#
  .SYNOPSIS
    Collect WinGet-matchable installed entries
  .DESCRIPTION
    Collect non-AppX/MSIX ARP entries and AppX/MSIX installed packages in the shape used by Dumplings dynamic validation.
  .PARAMETER Kind
    The installed entry source to collect
  .PARAMETER IncludeSystemComponent
    Include ARP entries hidden from WinGet's installed source by SystemComponent=1
  .PARAMETER AllUsers
    Query AppX/MSIX packages for all users. This may require elevation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'The installed entry source to collect')]
    [ValidateSet('All', 'ARP', 'AppX')]
    [string]$Kind = 'All',

    [Parameter(HelpMessage = 'Include ARP entries hidden from WinGet installed source by SystemComponent=1')]
    [switch]$IncludeSystemComponent,

    [Parameter(HelpMessage = 'Query AppX/MSIX packages for all users. This may require elevation.')]
    [switch]$AllUsers
  )

  if ($Kind -cin @('All', 'ARP')) { Get-WinGetInstalledARPEntry -IncludeSystemComponent:$IncludeSystemComponent }
  if ($Kind -cin @('All', 'AppX')) { Get-WinGetInstalledAppXEntry -AllUsers:$AllUsers }
}

function Get-WinGetManifestBundleForMatching {
  param (
    [Parameter(Mandatory)]
    $Manifest
  )

  # The logical model already contains effective authored installers. Adapt it
  # to the small internal view used by the matching helpers without rebuilding
  # a physical installer/default-locale manifest set.
  if ($Manifest.PSTypeNames -contains 'Dumplings.WinGet.ManifestModel') {
    $DefaultLocale = Copy-WinGetManifestValue -Value $Manifest.DefaultLocalization
    $DefaultLocale['ManifestType'] = 'defaultLocale'
    $Locales = [System.Collections.Generic.List[object]]::new()
    $Locales.Add($DefaultLocale)
    foreach ($Localization in @($Manifest.Localizations)) {
      $Locale = Copy-WinGetManifestValue -Value $Localization
      $Locale['ManifestType'] = 'locale'
      $Locales.Add($Locale)
    }
    return [pscustomobject]@{
      Installer = [ordered]@{ Installers = @($Manifest.Installers) }
      Locale    = $Locales.ToArray()
      Version   = [ordered]@{ DefaultLocale = [string]$Manifest.DefaultLocalization['PackageLocale'] }
    }
  }

  $InstallerManifest = Get-WinGetDictionaryValue -InputObject $Manifest -Key 'Installer'
  $LocaleManifests = Get-WinGetDictionaryValue -InputObject $Manifest -Key 'Locale'
  $VersionManifest = Get-WinGetDictionaryValue -InputObject $Manifest -Key 'Version'

  if ($InstallerManifest -and $VersionManifest) {
    return [pscustomobject]@{
      Installer = $InstallerManifest
      Locale    = ConvertTo-WinGetArray -InputObject $LocaleManifests
      Version   = $VersionManifest
    }
  }

  return [pscustomobject]@{
    Installer = $Manifest
    Locale    = @($Manifest)
    Version   = $Manifest
  }
}

function Get-WinGetManifestLocalizationForMatching {
  param (
    [Parameter(Mandatory)]
    $Bundle
  )

  $VersionManifest = $Bundle.Version
  $Locales = ConvertTo-WinGetArray -InputObject $Bundle.Locale
  $DefaultLocaleName = Get-WinGetDictionaryValue -InputObject $VersionManifest -Key 'DefaultLocale'
  if (-not $DefaultLocaleName) { $DefaultLocaleName = Get-WinGetDictionaryValue -InputObject $VersionManifest -Key 'PackageLocale' }

  $DefaultLocale = $Locales | Where-Object -FilterScript {
    (Get-WinGetDictionaryValue -InputObject $_ -Key 'ManifestType') -ceq 'defaultLocale' -or
    ($DefaultLocaleName -and (Get-WinGetDictionaryValue -InputObject $_ -Key 'PackageLocale') -ceq $DefaultLocaleName)
  } | Select-Object -First 1

  if (-not $DefaultLocale) {
    $DefaultLocale = $Locales | Where-Object -FilterScript { Get-WinGetDictionaryValue -InputObject $_ -Key 'PackageName' } | Select-Object -First 1
  }

  [pscustomobject]@{
    DefaultName      = [string](Get-WinGetDictionaryValue -InputObject $DefaultLocale -Key 'PackageName')
    DefaultPublisher = [string](Get-WinGetDictionaryValue -InputObject $DefaultLocale -Key 'Publisher')
    Localizations    = @($Locales | Where-Object -FilterScript { $_ -ne $DefaultLocale })
  }
}

function Get-WinGetManifestInstallersForMatching {
  param (
    [Parameter(Mandatory)]
    $InstallerManifest
  )

  $Installers = ConvertTo-WinGetArray -InputObject (Get-WinGetDictionaryValue -InputObject $InstallerManifest -Key 'Installers')
  foreach ($Installer in $Installers) {
    $MergedInstaller = [ordered]@{}

    if ($Installer -is [System.Collections.IDictionary]) {
      foreach ($Key in $Installer.Keys) { $MergedInstaller[$Key] = $Installer[$Key] }
    } else {
      foreach ($Property in $Installer.PSObject.Properties) { $MergedInstaller[$Property.Name] = $Property.Value }
    }

    # These fields can be authored at installer-manifest level and copied to installer entries by WinGet/Dumplings.
    foreach ($InheritedKey in @('PackageFamilyName', 'ProductCode', 'AppsAndFeaturesEntries')) {
      if (-not $MergedInstaller.Contains($InheritedKey)) {
        $InheritedValue = Get-WinGetDictionaryValue -InputObject $InstallerManifest -Key $InheritedKey
        if ($null -ne $InheritedValue) { $MergedInstaller[$InheritedKey] = $InheritedValue }
      }
    }

    $MergedInstaller
  }
}

function Add-WinGetManifestNamePair {
  param (
    [Parameter()]
    [System.Collections.Generic.List[pscustomobject]]$List,

    [Parameter()]
    [System.Collections.Generic.HashSet[string]]$Set,

    [Parameter()]
    [string]$Name,

    [Parameter()]
    [AllowNull()]
    [string]$Publisher,

    [Parameter()]
    [string]$Source
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return }

  $Normalized = ConvertTo-WinGetNormalizedNameAndPublisher -Name $Name -Publisher $Publisher
  if ($Set.Add($Normalized.NormalizedNameAndPublisher)) {
    $List.Add([pscustomobject]@{
        Source                     = $Source
        Name                       = $Name
        Publisher                  = $Publisher
        NormalizedName             = $Normalized.NormalizedName
        NormalizedPublisher        = $Normalized.NormalizedPublisher
        NormalizedNameAndPublisher = $Normalized.NormalizedNameAndPublisher
      })
  }
}

function Get-WinGetManifestMatchKey {
  <#
  .SYNOPSIS
    Build WinGet-style exact-match keys from manifests
  .DESCRIPTION
    Build the ProductCode, UpgradeCode, PackageFamilyName, and NormalizedNameAndPublisher candidates used to match installed entries.
    The input is the logical model returned by Read-WinGetManifest or
    ConvertFrom-WinGetManifestYaml.
  .PARAMETER Manifest
    The manifest object to inspect
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The manifest object to inspect')]
    $Manifest
  )

  process {
    $Bundle = Get-WinGetManifestBundleForMatching -Manifest $Manifest
    $Localization = Get-WinGetManifestLocalizationForMatching -Bundle $Bundle
    $Installers = @(Get-WinGetManifestInstallersForMatching -InstallerManifest $Bundle.Installer)

    $ProductCodes = [System.Collections.Generic.List[string]]::new()
    $ProductCodeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $UpgradeCodes = [System.Collections.Generic.List[string]]::new()
    $UpgradeCodeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $PackageFamilyNames = [System.Collections.Generic.List[string]]::new()
    $PackageFamilyNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $NamePairs = [System.Collections.Generic.List[pscustomobject]]::new()
    $NamePairSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    Add-WinGetManifestNamePair -List $NamePairs -Set $NamePairSet -Name $Localization.DefaultName -Publisher $Localization.DefaultPublisher -Source 'DefaultLocalization'

    foreach ($Locale in $Localization.Localizations) {
      $LocaleName = Get-WinGetDictionaryValue -InputObject $Locale -Key 'PackageName'
      $LocalePublisher = Get-WinGetDictionaryValue -InputObject $Locale -Key 'Publisher'
      if ($LocaleName -or $LocalePublisher) {
        Add-WinGetManifestNamePair -List $NamePairs -Set $NamePairSet -Name ($LocaleName ?? $Localization.DefaultName) -Publisher ($LocalePublisher ?? $Localization.DefaultPublisher) -Source 'Localization'
      }
    }

    foreach ($Installer in $Installers) {
      Add-WinGetUniqueString -List $ProductCodes -Set $ProductCodeSet -Value (Get-WinGetDictionaryValue -InputObject $Installer -Key 'ProductCode')
      Add-WinGetUniqueString -List $PackageFamilyNames -Set $PackageFamilyNameSet -Value (Get-WinGetDictionaryValue -InputObject $Installer -Key 'PackageFamilyName')

      foreach ($Entry in ConvertTo-WinGetArray -InputObject (Get-WinGetDictionaryValue -InputObject $Installer -Key 'AppsAndFeaturesEntries')) {
        $EntryDisplayName = Get-WinGetDictionaryValue -InputObject $Entry -Key 'DisplayName'
        $EntryPublisher = Get-WinGetDictionaryValue -InputObject $Entry -Key 'Publisher'

        if ($EntryDisplayName) {
          Add-WinGetManifestNamePair -List $NamePairs -Set $NamePairSet -Name $EntryDisplayName -Publisher ($EntryPublisher ?? $Localization.DefaultPublisher) -Source 'AppsAndFeaturesEntries'
        }

        Add-WinGetUniqueString -List $ProductCodes -Set $ProductCodeSet -Value (Get-WinGetDictionaryValue -InputObject $Entry -Key 'ProductCode')
        Add-WinGetUniqueString -List $UpgradeCodes -Set $UpgradeCodeSet -Value (Get-WinGetDictionaryValue -InputObject $Entry -Key 'UpgradeCode')
      }
    }

    [pscustomobject]@{
      PackageIdentifier          = [string](Get-WinGetDictionaryValue -InputObject $Bundle.Version -Key 'PackageIdentifier')
      PackageVersion             = [string](Get-WinGetDictionaryValue -InputObject $Bundle.Version -Key 'PackageVersion')
      ProductCodes               = $ProductCodes.ToArray()
      UpgradeCodes               = $UpgradeCodes.ToArray()
      PackageFamilyNames         = $PackageFamilyNames.ToArray()
      NormalizedNameAndPublisher = $NamePairs.ToArray()
    }
  }
}

function Find-WinGetManifestInstalledEntryMatch {
  <#
  .SYNOPSIS
    Find installed entries that can be matched by a WinGet manifest
  .DESCRIPTION
    Compare manifest exact-match keys against installed entries collected by Get-WinGetInstalledEntry or provided explicitly.
    This function reports ProductCode, UpgradeCode, PackageFamilyName, and NormalizedNameAndPublisher matches.
  .PARAMETER Manifest
    The manifest object to inspect
  .PARAMETER InstalledEntry
    Installed entries to check. If omitted, the current system is queried.
  .PARAMETER IncludeNonMatching
    Return all checked entries, including entries that did not match
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The manifest object to inspect')]
    $Manifest,

    [Parameter(Position = 1, ValueFromPipeline, HelpMessage = 'Installed entries to check. If omitted, the current system is queried.')]
    [psobject[]]$InstalledEntry,

    [Parameter(HelpMessage = 'Return all checked entries, including entries that did not match')]
    [switch]$IncludeNonMatching
  )

  begin {
    $Keys = Get-WinGetManifestMatchKey -Manifest $Manifest
    $ProductCodes = [System.Collections.Generic.HashSet[string]]::new([string[]]$Keys.ProductCodes, [System.StringComparer]::OrdinalIgnoreCase)
    $UpgradeCodes = [System.Collections.Generic.HashSet[string]]::new([string[]]$Keys.UpgradeCodes, [System.StringComparer]::OrdinalIgnoreCase)
    $PackageFamilyNames = [System.Collections.Generic.HashSet[string]]::new([string[]]$Keys.PackageFamilyNames, [System.StringComparer]::OrdinalIgnoreCase)
    $NormalizedNamePairs = [System.Collections.Generic.HashSet[string]]::new([string[]]($Keys.NormalizedNameAndPublisher | ForEach-Object -Process { $_.NormalizedNameAndPublisher }), [System.StringComparer]::OrdinalIgnoreCase)
    $Entries = [System.Collections.Generic.List[psobject]]::new()
  }

  process {
    if ($InstalledEntry) {
      foreach ($Entry in $InstalledEntry) { $Entries.Add($Entry) }
    }
  }

  end {
    if ($Entries.Count -eq 0 -and -not $PSBoundParameters.ContainsKey('InstalledEntry')) {
      foreach ($Entry in Get-WinGetInstalledEntry) { $Entries.Add($Entry) }
    }

    foreach ($Entry in $Entries) {
      $MatchedFields = [System.Collections.Generic.List[string]]::new()
      $MatchedValues = [ordered]@{}

      $ProductCode = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'ProductCode')
      if (-not [string]::IsNullOrWhiteSpace($ProductCode) -and $ProductCodes.Contains($ProductCode)) {
        $MatchedFields.Add('ProductCode')
        $MatchedValues['ProductCode'] = $ProductCode
      }

      $UpgradeCode = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'UpgradeCode')
      if (-not [string]::IsNullOrWhiteSpace($UpgradeCode) -and $UpgradeCodes.Contains($UpgradeCode)) {
        $MatchedFields.Add('UpgradeCode')
        $MatchedValues['UpgradeCode'] = $UpgradeCode
      }

      $PackageFamilyName = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'PackageFamilyName')
      if (-not [string]::IsNullOrWhiteSpace($PackageFamilyName) -and $PackageFamilyNames.Contains($PackageFamilyName)) {
        $MatchedFields.Add('PackageFamilyName')
        $MatchedValues['PackageFamilyName'] = $PackageFamilyName
      }

      $NormalizedNameAndPublisher = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'NormalizedNameAndPublisher')
      if ([string]::IsNullOrWhiteSpace($NormalizedNameAndPublisher)) {
        $Name = [string]((Get-WinGetDictionaryValue -InputObject $Entry -Key 'DisplayName') ?? (Get-WinGetDictionaryValue -InputObject $Entry -Key 'PackageName'))
        $Publisher = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'Publisher')
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
          $NormalizedNameAndPublisher = (ConvertTo-WinGetNormalizedNameAndPublisher -Name $Name -Publisher $Publisher).NormalizedNameAndPublisher
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($NormalizedNameAndPublisher) -and $NormalizedNamePairs.Contains($NormalizedNameAndPublisher)) {
        $MatchedFields.Add('NormalizedNameAndPublisher')
        $MatchedValues['NormalizedNameAndPublisher'] = $NormalizedNameAndPublisher
      }

      if ($MatchedFields.Count -gt 0 -or $IncludeNonMatching) {
        [pscustomobject]@{
          IsMatch       = $MatchedFields.Count -gt 0
          MatchFields   = $MatchedFields.ToArray()
          MatchedValues = $MatchedValues
          Entry         = $Entry
        }
      }
    }
  }
}

function Test-WinGetManifestInstalledEntryMatch {
  <#
  .SYNOPSIS
    Test whether a manifest can match at least one installed entry
  .PARAMETER Manifest
    The manifest object to inspect
  .PARAMETER InstalledEntry
    Installed entries to check. If omitted, the current system is queried.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The manifest object to inspect')]
    $Manifest,

    [Parameter(Position = 1, ValueFromPipeline, HelpMessage = 'Installed entries to check. If omitted, the current system is queried.')]
    [psobject[]]$InstalledEntry
  )

  begin {
    $Entries = [System.Collections.Generic.List[psobject]]::new()
  }

  process {
    if ($InstalledEntry) {
      foreach ($Entry in $InstalledEntry) { $Entries.Add($Entry) }
    }
  }

  end {
    if ($PSBoundParameters.ContainsKey('InstalledEntry')) {
      return [bool](Find-WinGetManifestInstalledEntryMatch -Manifest $Manifest -InstalledEntry $Entries | Select-Object -First 1)
    }

    return [bool](Find-WinGetManifestInstalledEntryMatch -Manifest $Manifest | Select-Object -First 1)
  }
}

function Get-WinGetInstalledEntryIdentity {
  param (
    [Parameter(Mandatory)]
    $Entry
  )

  $Source = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'Source')
  $Version = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'Version')

  if ($Source -ceq 'AppX') {
    return "AppX|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'PackageFamilyName'))|${Version}"
  }

  return "ARP|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'Scope'))|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'ArchitectureView'))|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'ProductCode'))|${Version}"
}

function Compare-WinGetInstalledEntrySnapshot {
  <#
  .SYNOPSIS
    Compare installed-entry snapshots before and after installation
  .DESCRIPTION
    Compare snapshots from Get-WinGetInstalledEntry and return NewOrUpdated, Removed, and Unchanged entries using the same identity idea as winget-cli's ARP snapshot.
  .PARAMETER Before
    Installed entries collected before installation
  .PARAMETER After
    Installed entries collected after installation
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'Installed entries collected before installation')]
    [psobject[]]$Before,

    [Parameter(Position = 1, Mandatory, HelpMessage = 'Installed entries collected after installation')]
    [psobject[]]$After
  )

  $BeforeMap = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $Before) { $null = $BeforeMap.Add((Get-WinGetInstalledEntryIdentity -Entry $Entry)) }

  $AfterMap = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $After) { $null = $AfterMap.Add((Get-WinGetInstalledEntryIdentity -Entry $Entry)) }

  foreach ($Entry in $After) {
    $Identity = Get-WinGetInstalledEntryIdentity -Entry $Entry
    [pscustomobject]@{
      Status   = $BeforeMap.Contains($Identity) ? 'Unchanged' : 'NewOrUpdated'
      Identity = $Identity
      Entry    = $Entry
    }
  }

  foreach ($Entry in $Before) {
    $Identity = Get-WinGetInstalledEntryIdentity -Entry $Entry
    if (-not $AfterMap.Contains($Identity)) {
      [pscustomobject]@{
        Status   = 'Removed'
        Identity = $Identity
        Entry    = $Entry
      }
    }
  }
}

Export-ModuleMember -Function Get-WinGetInstalledARPEntry, Get-WinGetInstalledAppXEntry, Get-WinGetInstalledEntry, ConvertTo-WinGetNormalizedNameAndPublisher, Get-WinGetManifestMatchKey, Find-WinGetManifestInstalledEntryMatch, Test-WinGetManifestInstalledEntryMatch, Compare-WinGetInstalledEntrySnapshot
