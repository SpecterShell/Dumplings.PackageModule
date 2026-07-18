# Logical WinGet manifest model and authored installer inheritance.
#
# The shape follows the effective Manifest object used by winget-cli while
# retaining ordered PowerShell dictionaries suitable for Dumplings mutation.
# winget-create's explicit model/serialization boundary also informed this
# module: https://github.com/microsoft/winget-create

Set-StrictMode -Version 3

$Script:WinGetManifestIdentityFields = @('PackageIdentifier', 'PackageVersion', 'ManifestType', 'ManifestVersion')
$Script:WinGetArchiveInstallerTypes = @('zip')
$Script:WinGetProductCodeInstallerTypes = @('exe', 'inno', 'msi', 'nullsoft', 'wix', 'burn', 'portable')
$Script:WinGetPackageFamilyNameInstallerTypes = @('msix', 'msstore')

function Copy-WinGetManifestValue {
  <#
  .SYNOPSIS
    Deep-copy a manifest value without changing dictionary or array ordering.
  .PARAMETER Value
    The scalar, dictionary, or sequence to copy.
  #>
  param ([AllowNull()]$Value)

  if ($Value -is [System.Collections.IDictionary]) {
    $Result = [ordered]@{}
    foreach ($Key in $Value.Keys) {
      $Result[$Key] = Copy-WinGetManifestValue -Value $Value[$Key]
    }
    return $Result
  }
  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    return , @($Value | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
  }
  return $Value
}

function Test-WinGetManifestValueEqual {
  <#
  .SYNOPSIS
    Compare two authored manifest values structurally and case-sensitively.
  .PARAMETER Left
    The first value.
  .PARAMETER Right
    The second value.
  #>
  [OutputType([bool])]
  param ([AllowNull()]$Left, [AllowNull()]$Right)

  if ($null -eq $Left -or $null -eq $Right) {
    return $null -eq $Left -and $null -eq $Right
  }
  if ($Left -is [System.Collections.IDictionary]) {
    if ($Right -isnot [System.Collections.IDictionary] -or $Left.Count -ne $Right.Count) { return $false }
    foreach ($Key in $Left.Keys) {
      $RightKey = $Right.Keys | Where-Object { $_ -ceq $Key } | Select-Object -First 1
      if ($null -eq $RightKey -or -not (Test-WinGetManifestValueEqual -Left $Left[$Key] -Right $Right[$RightKey])) { return $false }
    }
    return $true
  }
  if ($Left -is [System.Collections.IEnumerable] -and $Left -isnot [string]) {
    if ($Right -isnot [System.Collections.IEnumerable] -or $Right -is [string]) { return $false }
    $LeftItems = @($Left)
    $RightItems = @($Right)
    if ($LeftItems.Count -ne $RightItems.Count) { return $false }
    for ($Index = 0; $Index -lt $LeftItems.Count; $Index++) {
      if (-not (Test-WinGetManifestValueEqual -Left $LeftItems[$Index] -Right $RightItems[$Index])) { return $false }
    }
    return $true
  }
  return $Left -ceq $Right
}

function Merge-WinGetManifestDictionary {
  <#
  .SYNOPSIS
    Recursively apply installer-level dictionary overrides to root defaults.
  .DESCRIPTION
    Dictionary atoms inherit recursively. Arrays and all other values are
    atomic and are replaced as a whole when an override is authored.
  .PARAMETER Base
    The authored root-level values.
  .PARAMETER Override
    The authored installer-level values.
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Base,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Override
  )

  $Result = Copy-WinGetManifestValue -Value $Base
  foreach ($Key in $Override.Keys) {
    if ($Result.Contains($Key) -and
      $Result[$Key] -is [System.Collections.IDictionary] -and
      $Override[$Key] -is [System.Collections.IDictionary]) {
      $Result[$Key] = Merge-WinGetManifestDictionary -Base $Result[$Key] -Override $Override[$Key]
    } else {
      $Result[$Key] = Copy-WinGetManifestValue -Value $Override[$Key]
    }
  }
  return $Result
}

function Get-WinGetManifestEffectiveInstallerType {
  <#
  .SYNOPSIS
    Resolve the installer technology that owns switches and system references.
  .PARAMETER Installer
    An effective installer entry.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][System.Collections.IDictionary]$Installer)

  $BaseType = ([string]$Installer['InstallerType']).ToLowerInvariant()
  $Type = if ($BaseType -cin $Script:WinGetArchiveInstallerTypes) {
    ([string]$Installer['NestedInstallerType']).ToLowerInvariant()
  } else {
    $BaseType
  }
  if ($Type -cin @('appx', 'msixbundle', 'appxbundle')) { return 'msix' }
  if ($Type -ceq 'pwa') { return 'msstore' }
  return $Type
}

function Test-WinGetManifestDependenciesPresent {
  <#
  .SYNOPSIS
    Test whether a Dependencies dictionary contains authored dependency data.
  .PARAMETER Dependencies
    The dependency dictionary to inspect.
  #>
  [OutputType([bool])]
  param ([AllowNull()]$Dependencies)

  if ($Dependencies -isnot [System.Collections.IDictionary]) { return $false }
  foreach ($Key in @('WindowsFeatures', 'WindowsLibraries', 'PackageDependencies', 'ExternalDependencies')) {
    if ($Dependencies.Contains($Key) -and $null -ne $Dependencies[$Key] -and @($Dependencies[$Key]).Count -gt 0) {
      return $true
    }
  }
  return $false
}

function Get-WinGetInstallerPropertyCatalog {
  <#
  .SYNOPSIS
    Return installer fields supported by a manifest schema revision.
  .PARAMETER ManifestVersion
    The manifest schema version.
  .PARAMETER RootOnly
    Return only fields that may be authored at both root and installer level.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][string]$ManifestVersion,
    [switch]$RootOnly
  )

  $SchemaVersion = if ((Resolve-WinGetManifestSchemaVersion $ManifestVersion) -ceq '0.1.0') { '1.0.0' } else { $ManifestVersion }
  $Schema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion $SchemaVersion
  $EntryKeys = @($Schema['definitions']['Installer']['properties'].Keys)
  if (-not $RootOnly) { return $EntryKeys }
  $RootKeys = @($Schema['properties'].Keys)
  return @($EntryKeys | Where-Object { $_ -cin $RootKeys })
}

function Get-WinGetAuthoredEffectiveInstallers {
  <#
  .SYNOPSIS
    Apply authored installer defaults without adding WinGet runtime defaults.
  .PARAMETER InstallerDefaults
    Root-level authored installer values.
  .PARAMETER Installers
    Physical installer entries.
  .PARAMETER ManifestVersion
    Manifest version used to select the installer property catalog.
  #>
  [OutputType([System.Collections.IDictionary[]])]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerDefaults,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.IDictionary[]]$Installers,
    [Parameter(Mandatory)][string]$ManifestVersion
  )

  $AllowedKeys = Get-WinGetInstallerPropertyCatalog -ManifestVersion $ManifestVersion
  $SchemaVersion = if ((Resolve-WinGetManifestSchemaVersion $ManifestVersion) -ceq '0.1.0') { '1.0.0' } else { $ManifestVersion }
  $InstallerEntrySchema = (Get-WinGetManifestSchema -ManifestType installer -ManifestVersion $SchemaVersion)['definitions']['Installer']
  $Defaults = [ordered]@{}
  foreach ($Key in $AllowedKeys) {
    if ($InstallerDefaults.Contains($Key)) {
      $Defaults[$Key] = Copy-WinGetManifestValue -Value $InstallerDefaults[$Key]
    }
  }

  $Results = [System.Collections.Generic.List[object]]::new()
  foreach ($Entry in $Installers) {
    $Effective = Merge-WinGetManifestDictionary -Base $Defaults -Override $Entry
    $BaseType = ([string]$Effective['InstallerType']).ToLowerInvariant()
    $EffectiveType = Get-WinGetManifestEffectiveInstallerType -Installer $Effective

    # winget-cli conditionally inherits system-reference and archive fields.
    # An explicitly authored non-empty installer value always wins. Empty
    # values are treated as absent for these fields.
    foreach ($SpecialKey in @('AppsAndFeaturesEntries', 'PackageFamilyName', 'ProductCode', 'Dependencies', 'NestedInstallerFiles', 'NestedInstallerType')) {
      $EntryHasValue = if (-not $Entry.Contains($SpecialKey)) { $false } else {
        switch ($SpecialKey) {
          'AppsAndFeaturesEntries' { @($Entry[$SpecialKey]).Count -gt 0 }
          'PackageFamilyName' { -not [string]::IsNullOrEmpty([string]$Entry[$SpecialKey]) }
          'ProductCode' { -not [string]::IsNullOrEmpty([string]$Entry[$SpecialKey]) }
          'Dependencies' { Test-WinGetManifestDependenciesPresent -Dependencies $Entry[$SpecialKey] }
          'NestedInstallerFiles' { @($Entry[$SpecialKey]).Count -gt 0 }
          'NestedInstallerType' { -not [string]::IsNullOrEmpty([string]$Entry[$SpecialKey]) }
        }
      }
      if ($EntryHasValue) {
        # Dependencies and all other arrays are atomic installer overrides.
        $Effective[$SpecialKey] = Copy-WinGetManifestValue -Value $Entry[$SpecialKey]
        continue
      }
      if (-not $Defaults.Contains($SpecialKey)) {
        $Effective.Remove($SpecialKey)
        continue
      }

      $CopyDefault = switch ($SpecialKey) {
        'AppsAndFeaturesEntries' { $EffectiveType -cin $Script:WinGetProductCodeInstallerTypes }
        'PackageFamilyName' {
          $EffectiveType -cin $Script:WinGetPackageFamilyNameInstallerTypes -or
          ($Effective.Contains('AppsAndFeaturesEntries') -and
          @($Effective['AppsAndFeaturesEntries']).Where({ ([string]$_['InstallerType']).ToLowerInvariant() -cin @('appx', 'msix') }, 'First'))
        }
        'ProductCode' { $EffectiveType -cin $Script:WinGetProductCodeInstallerTypes }
        'Dependencies' { $true }
        'NestedInstallerFiles' { $BaseType -cin $Script:WinGetArchiveInstallerTypes }
        'NestedInstallerType' { $BaseType -cin $Script:WinGetArchiveInstallerTypes }
      }
      if ($CopyDefault) {
        $Effective[$SpecialKey] = Copy-WinGetManifestValue -Value $Defaults[$SpecialKey]
      } else {
        $Effective.Remove($SpecialKey)
      }
    }
    # Canonical schema ordering makes logically identical singleton and
    # multi-file inputs produce byte-comparable effective installer objects.
    $Results.Add((ConvertTo-SortedYamlObject -InputObject $Effective -Schema $InstallerEntrySchema -Culture ([Globalization.CultureInfo]::GetCultureInfo('en-US'))))
  }
  return $Results.ToArray()
}

function Move-WinGetCommonDictionaryValues {
  <#
  .SYNOPSIS
    Move recursively common values from installer dictionaries into defaults.
  .PARAMETER Installers
    Mutable dictionaries at the current hierarchy level.
  .PARAMETER Defaults
    Mutable destination dictionary.
  .PARAMETER MaximumDepth
    Maximum dictionary recursion depth.
  .PARAMETER Depth
    Current recursion depth.
  #>
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.IDictionary[]]$Installers,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Defaults,
    [ValidateRange(1, 128)][int]$MaximumDepth = 32,
    [int]$Depth = 0
  )

  if ($Installers.Count -eq 0 -or $Depth -ge $MaximumDepth) { return }
  $AllKeys = [System.Collections.Generic.List[string]]::new()
  foreach ($Installer in $Installers) {
    foreach ($Key in $Installer.Keys) {
      if ($Key -cnotin $AllKeys) { $AllKeys.Add([string]$Key) }
    }
  }

  foreach ($Key in $AllKeys) {
    if (@($Installers | Where-Object { -not $_.Contains($Key) }).Count -gt 0) { continue }
    # Add values directly to avoid PowerShell unrolling a one-item array into
    # its item, which would change an atomic schema array into a dictionary.
    $ValueList = [System.Collections.Generic.List[object]]::new()
    foreach ($Installer in $Installers) { $ValueList.Add($Installer[$Key]) }
    $Values = $ValueList.ToArray()

    # Dictionaries support recursive atom inheritance; move only common child
    # fields and leave differing children at installer level.
    if (@($Values | Where-Object { $_ -isnot [System.Collections.IDictionary] }).Count -eq 0) {
      $ChildDefaults = [ordered]@{}
      Move-WinGetCommonDictionaryValues -Installers ([System.Collections.IDictionary[]]$Values) -Defaults $ChildDefaults -MaximumDepth $MaximumDepth -Depth ($Depth + 1)
      if ($ChildDefaults.Count -gt 0) { $Defaults[$Key] = $ChildDefaults }
      foreach ($Installer in $Installers) {
        if ($Installer[$Key].Count -eq 0) { $Installer.Remove($Key) }
      }
      continue
    }

    # Arrays are atomic and retain their authored order. Scalars follow the
    # same all-installers equality rule.
    $First = $Values[0]
    if (@($Values | Select-Object -Skip 1 | Where-Object { -not (Test-WinGetManifestValueEqual -Left $First -Right $_) }).Count -eq 0) {
      $Defaults[$Key] = Copy-WinGetManifestValue -Value $First
      foreach ($Installer in $Installers) { $Installer.Remove($Key) }
    }
  }
}

function Get-WinGetManifestCompactedInstallerData {
  <#
  .SYNOPSIS
    Recompute root installer defaults and physical installer overrides.
  .PARAMETER Manifest
    The logical manifest model.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$Manifest)

  $Installers = @($Manifest.Installers | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
  $RootCandidates = Get-WinGetInstallerPropertyCatalog -ManifestVersion $Manifest.ManifestVersion -RootOnly
  $CandidateInstallers = [System.Collections.Generic.List[object]]::new()
  foreach ($Installer in $Installers) {
    $Candidate = [ordered]@{}
    foreach ($Key in $RootCandidates) {
      if ($Installer.Contains($Key)) { $Candidate[$Key] = $Installer[$Key] }
    }
    $CandidateInstallers.Add($Candidate)
  }

  $Defaults = [ordered]@{}
  Move-WinGetCommonDictionaryValues -Installers ([System.Collections.IDictionary[]]$CandidateInstallers.ToArray()) -Defaults $Defaults
  for ($Index = 0; $Index -lt $Installers.Count; $Index++) {
    foreach ($Key in $RootCandidates) {
      if ($Installers[$Index].Contains($Key)) { $Installers[$Index].Remove($Key) }
    }
    foreach ($Key in $CandidateInstallers[$Index].Keys) {
      $Installers[$Index][$Key] = $CandidateInstallers[$Index][$Key]
    }
  }

  return [pscustomobject]@{
    Defaults   = $Defaults
    Installers = $Installers
  }
}

function New-WinGetManifestModel {
  <#
  .SYNOPSIS
    Create a detached logical WinGet manifest model.
  .PARAMETER PackageIdentifier
    Package identifier shared by every physical document.
  .PARAMETER PackageVersion
    Package version shared by every physical document.
  .PARAMETER Channel
    Optional package channel.
  .PARAMETER Moniker
    Optional package moniker.
  .PARAMETER ManifestVersion
    WinGet manifest schema version.
  .PARAMETER InstallerDefaults
    Authored root-level installer defaults.
  .PARAMETER Installers
    Effective authored installer entries.
  .PARAMETER DefaultLocalization
    Default localization fields without document identity fields.
  .PARAMETER Localizations
    Additional localization dictionaries without document identity fields.
  .PARAMETER SourceFormat
    Physical source format, such as MultiFile or Singleton.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$PackageIdentifier,
    [Parameter(Mandatory)][string]$PackageVersion,
    [AllowNull()][string]$Channel,
    [AllowNull()][string]$Moniker,
    [Parameter(Mandatory)][string]$ManifestVersion,
    [Parameter(Mandatory)][System.Collections.IDictionary]$InstallerDefaults,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.IDictionary[]]$Installers,
    [Parameter(Mandatory)][System.Collections.IDictionary]$DefaultLocalization,
    [AllowEmptyCollection()][System.Collections.IDictionary[]]$Localizations = @(),
    [ValidateSet('MultiFile', 'Singleton', 'Merged', 'Memory')][string]$SourceFormat = 'Memory'
  )

  # Channel and Moniker are promoted into the logical contract even though
  # WinGet physically stores them in installer and default-locale documents.
  $InstallerDefaultsCopy = Copy-WinGetManifestValue -Value $InstallerDefaults
  if ([string]::IsNullOrEmpty($Channel) -and $InstallerDefaultsCopy.Contains('Channel')) {
    $Channel = [string]$InstallerDefaultsCopy['Channel']
  }
  if ($InstallerDefaultsCopy.Contains('Channel')) { $InstallerDefaultsCopy.Remove('Channel') }

  $DefaultLocalizationCopy = Copy-WinGetManifestValue -Value $DefaultLocalization
  if ([string]::IsNullOrEmpty($Moniker) -and $DefaultLocalizationCopy.Contains('Moniker')) {
    $Moniker = [string]$DefaultLocalizationCopy['Moniker']
  }
  if ($DefaultLocalizationCopy.Contains('Moniker')) { $DefaultLocalizationCopy.Remove('Moniker') }

  return [pscustomobject]@{
    PSTypeName          = 'Dumplings.WinGet.ManifestModel'
    PackageIdentifier   = $PackageIdentifier
    PackageVersion      = $PackageVersion
    Channel             = $Channel
    Moniker             = $Moniker
    ManifestVersion     = $ManifestVersion
    InstallerDefaults   = $InstallerDefaultsCopy
    Installers          = @($Installers | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
    DefaultLocalization = $DefaultLocalizationCopy
    Localizations       = @($Localizations | Where-Object { $null -ne $_ } | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
    SourceFormat        = $SourceFormat
  }
}

function ConvertFrom-WinGetMergedManifest {
  <#
  .SYNOPSIS
    Construct a logical model from a singleton or merged manifest dictionary.
  .PARAMETER Manifest
    The singleton or merged dictionary.
  .PARAMETER SourceFormat
    The physical source format represented by the dictionary.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][System.Collections.IDictionary]$Manifest,
    [ValidateSet('Singleton', 'Merged', 'Memory')][string]$SourceFormat = 'Merged'
  )

  process {
    $ManifestVersion = [string]$Manifest['ManifestVersion']
    $InstallerSchemaVersion = if ((Resolve-WinGetManifestSchemaVersion $ManifestVersion) -ceq '0.1.0') { '1.0.0' } else { $ManifestVersion }
    $InstallerSchema = Get-WinGetManifestSchema -ManifestType installer -ManifestVersion $InstallerSchemaVersion
    $DefaultLocaleSchema = Get-WinGetManifestSchema -ManifestType defaultLocale -ManifestVersion $InstallerSchemaVersion
    $InstallerKeys = @($InstallerSchema['definitions']['Installer']['properties'].Keys)

    $Defaults = [ordered]@{}
    foreach ($Key in $InstallerKeys) {
      if ($Manifest.Contains($Key)) { $Defaults[$Key] = Copy-WinGetManifestValue -Value $Manifest[$Key] }
    }
    $PhysicalInstallers = @($Manifest['Installers'])
    $EffectiveInstallers = @(Get-WinGetAuthoredEffectiveInstallers -InstallerDefaults $Defaults -Installers ([System.Collections.IDictionary[]]$PhysicalInstallers) -ManifestVersion $InstallerSchemaVersion)

    $DefaultLocalization = [ordered]@{}
    foreach ($Key in $DefaultLocaleSchema['properties'].Keys) {
      if ($Key -cnotin $Script:WinGetManifestIdentityFields -and $Key -cne 'Moniker' -and $Manifest.Contains($Key)) {
        $DefaultLocalization[$Key] = Copy-WinGetManifestValue -Value $Manifest[$Key]
      }
    }
    [System.Collections.IDictionary[]]$Localizations = @()
    if ($Manifest.Contains('Localization') -and $null -ne $Manifest['Localization']) {
      $Localizations = [System.Collections.IDictionary[]]@(@($Manifest['Localization']) | Where-Object { $null -ne $_ } | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
    }

    return New-WinGetManifestModel -PackageIdentifier ([string]$Manifest['PackageIdentifier']) -PackageVersion ([string]$Manifest['PackageVersion']) -Channel ([string]$Manifest['Channel']) -Moniker ([string]$Manifest['Moniker']) -ManifestVersion $ManifestVersion -InstallerDefaults $Defaults -Installers ([System.Collections.IDictionary[]]$EffectiveInstallers) -DefaultLocalization $DefaultLocalization -Localizations ([System.Collections.IDictionary[]]$Localizations) -SourceFormat $SourceFormat
  }
}

function ConvertTo-WinGetMergedManifest {
  <#
  .SYNOPSIS
    Project a logical model into WinGet's flat merged manifest shape.
  .PARAMETER Manifest
    The logical manifest model.
  #>
  [OutputType([System.Collections.IDictionary])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)]$Manifest)

  process {
    $Compacted = Get-WinGetManifestCompactedInstallerData -Manifest $Manifest
    $Merged = [ordered]@{
      PackageIdentifier = [string]$Manifest.PackageIdentifier
      PackageVersion    = [string]$Manifest.PackageVersion
    }
    if (-not [string]::IsNullOrEmpty([string]$Manifest.Channel)) { $Merged['Channel'] = [string]$Manifest.Channel }
    if (-not [string]::IsNullOrEmpty([string]$Manifest.Moniker)) { $Merged['Moniker'] = [string]$Manifest.Moniker }
    foreach ($Key in $Compacted.Defaults.Keys) { $Merged[$Key] = Copy-WinGetManifestValue -Value $Compacted.Defaults[$Key] }
    $Merged['Installers'] = @($Compacted.Installers | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
    foreach ($Key in $Manifest.DefaultLocalization.Keys) { $Merged[$Key] = Copy-WinGetManifestValue -Value $Manifest.DefaultLocalization[$Key] }
    if (@($Manifest.Localizations).Count -gt 0) {
      $Merged['Localization'] = @($Manifest.Localizations | ForEach-Object { Copy-WinGetManifestValue -Value $_ })
    }
    $Merged['ManifestType'] = 'merged'
    $Merged['ManifestVersion'] = [string]$Manifest.ManifestVersion
    return $Merged
  }
}

Export-ModuleMember -Function Copy-WinGetManifestValue, Test-WinGetManifestValueEqual, Merge-WinGetManifestDictionary, Get-WinGetManifestEffectiveInstallerType, Get-WinGetInstallerPropertyCatalog, Get-WinGetAuthoredEffectiveInstallers, Get-WinGetManifestCompactedInstallerData, New-WinGetManifestModel, ConvertFrom-WinGetMergedManifest, ConvertTo-WinGetMergedManifest
