# WinGet manifest YAML parsing, document sets, formatting, and serialization.
#
# Parsing and model construction are deliberately separate from update logic.
# This mirrors winget-cli's parser/populator boundary and winget-create's
# explicit serialization boundary: https://github.com/microsoft/winget-create

Set-StrictMode -Version 3

$Script:WinGetManifestHeader = '# Created with YamlCreate.ps1 Dumplings Mod'
$Script:WinGetAuthoringManifestVersion = '1.12.0'
$Script:WinGetManifestCulture = [Globalization.CultureInfo]::GetCultureInfo('en-US')
$Script:WinGetIntegerFields = @('InstallerSuccessCodes', 'InstallerReturnCode')
$Script:WinGetBooleanFields = @(
  'InstallerAbortsTerminal', 'InstallLocationRequired', 'RequireExplicitUpgrade',
  'DisplayInstallWarnings', 'DownloadCommandProhibited', 'ArchiveBinariesDependOnPath'
)
$Script:WinGetDocumentIdentityFields = @('PackageIdentifier', 'PackageVersion', 'ManifestType', 'ManifestVersion')

function ConvertTo-WinGetManifestScalarType {
  <#
  .SYNOPSIS
    Apply WinGet's field-specific YAML scalar conversion rules.
  .PARAMETER Value
    Parsed YAML value to convert recursively.
  .PARAMETER FieldName
    Name of the field containing the current value.
  #>
  param ($Value, [string]$FieldName)

  if ($null -eq $Value) { return $null }
  if ($Value -is [System.Collections.IDictionary]) {
    $Result = [ordered]@{}
    foreach ($Key in $Value.Keys) {
      $Result[$Key] = ConvertTo-WinGetManifestScalarType -Value $Value[$Key] -FieldName ([string]$Key)
    }
    return $Result
  }
  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    return , @($Value | ForEach-Object { ConvertTo-WinGetManifestScalarType -Value $_ -FieldName $FieldName })
  }

  # WinGet parses most YAML scalars as strings. Only fields represented by
  # integer or Boolean model members are converted to typed values.
  if ($FieldName -cin $Script:WinGetIntegerFields) {
    $ParsedInteger = 0L
    if ([long]::TryParse([string]$Value, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$ParsedInteger)) {
      return $ParsedInteger
    }
    return $Value
  }
  if ($FieldName -cin $Script:WinGetBooleanFields) {
    $ParsedBoolean = $false
    if ([bool]::TryParse([string]$Value, [ref]$ParsedBoolean)) { return $ParsedBoolean }
    return $Value
  }
  if ($Value -is [IFormattable]) { return $Value.ToString($null, [Globalization.CultureInfo]::InvariantCulture) }
  return [string]$Value
}

function ConvertFrom-WinGetManifestDocumentContent {
  <#
  .SYNOPSIS
    Parse one physical manifest document and preserve header evidence.
  .PARAMETER Content
    Raw YAML content.
  .PARAMETER FileName
    Logical or physical file name used in diagnostics.
  .PARAMETER Path
    Optional resolved physical path.
  .PARAMETER AllowInvalid
    Return parse diagnostics rather than throwing a YAML parse failure.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
    [Parameter(Mandatory)][string]$FileName,
    [string]$Path,
    [switch]$AllowInvalid
  )

  $Data = $null
  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  try {
    $Data = ConvertFrom-Yaml -Yaml $Content -Ordered
    if ($Data -isnot [System.Collections.IDictionary]) {
      throw 'The YAML document root must be a mapping'
    }
  } catch {
    $YamlException = $_.Exception
    while ($YamlException.InnerException) { $YamlException = $YamlException.InnerException }
    $Line = if ($YamlException.PSObject.Properties['Start']) { [int]$YamlException.Start.Line } else { $null }
    $Column = if ($YamlException.PSObject.Properties['Start']) { [int]$YamlException.Start.Column } else { $null }
    $Id = if ($YamlException.Message -match '^Duplicate key\s+(?<Key>.+)$') { 'FieldDuplicate' } else { 'YamlParseError' }
    $Diagnostics.Add([pscustomobject]@{
        Id = $Id; Message = $YamlException.Message
        Field = ($Id -ceq 'FieldDuplicate' ? $Matches.Key : $null)
        File = $FileName; Line = $Line; Column = $Column
      })
    if (-not $AllowInvalid) { throw "Failed to parse WinGet manifest '${FileName}': $($YamlException.Message)" }
  }

  $HeaderLine = $null
  $HeaderValue = $null
  $LineNumber = 0
  foreach ($LineText in $Content -split '\r?\n') {
    $LineNumber++
    if ($LineText -match '^\s*#\s*yaml-language-server\s*:\s*\$schema\s*=\s*(?<Url>\S+)\s*$') {
      $HeaderLine = $LineNumber
      $HeaderValue = $Matches.Url
      break
    }
  }

  $TypedData = if ($null -ne $Data) { ConvertTo-WinGetManifestScalarType -Value $Data } else { $null }
  return [pscustomobject]@{
    PSTypeName   = 'Dumplings.WinGet.ManifestDocument'
    Path         = $Path
    FileName     = $FileName
    RawContent   = $Content
    Data         = $Data
    TypedData    = $TypedData
    ManifestType = if ($null -ne $TypedData) { ([string]$TypedData['ManifestType']).ToLowerInvariant() } else { $null }
    SchemaHeader = $HeaderValue
    HeaderLine   = $HeaderLine
    Diagnostics  = $Diagnostics.ToArray()
  }
}

function Get-WinGetManifestDocumentSet {
  <#
  .SYNOPSIS
    Read all physical YAML documents from a file or one manifest directory.
  .PARAMETER Path
    Manifest file or leaf manifest directory.
  .PARAMETER AllowInvalid
    Retain YAML parse failures for validation instead of throwing immediately.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory)][string]$Path,
    [switch]$AllowInvalid
  )

  $ResolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction Stop
  if (Test-Path -LiteralPath $ResolvedPath -PathType Leaf) {
    $Content = Get-Content -LiteralPath $ResolvedPath -Raw
    $Documents = @(ConvertFrom-WinGetManifestDocumentContent -Content $Content -FileName ([IO.Path]::GetFileName($ResolvedPath)) -Path $ResolvedPath.Path -AllowInvalid:$AllowInvalid)
  } else {
    $Children = @(Get-ChildItem -LiteralPath $ResolvedPath -Force | Sort-Object Name)
    $Subdirectory = $Children | Where-Object PSIsContainer | Select-Object -First 1
    if ($Subdirectory) { throw "Subdirectory not supported in manifest path: $($Subdirectory.FullName)" }
    $Files = @($Children | Where-Object { -not $_.PSIsContainer -and $_.Extension -in @('.yaml', '.yml') })
    if ($Files.Count -eq 0) { throw "No manifest file found in ${ResolvedPath}" }
    $Documents = @($Files | ForEach-Object {
        ConvertFrom-WinGetManifestDocumentContent -Content (Get-Content -LiteralPath $_.FullName -Raw) -FileName $_.Name -Path $_.FullName -AllowInvalid:$AllowInvalid
      })
  }

  return [pscustomobject]@{
    PSTypeName = 'Dumplings.WinGet.ManifestDocumentSet'
    Documents  = $Documents
    SourcePath = $ResolvedPath.Path
  }
}

function Assert-WinGetManifestDocumentSet {
  <#
  .SYNOPSIS
    Reject physical document layouts that cannot form one WinGet manifest.
  .PARAMETER DocumentSet
    Parsed document set.
  #>
  param ([Parameter(Mandatory)]$DocumentSet)

  $Documents = @($DocumentSet.Documents)
  if ($Documents.Count -eq 0) { throw 'The manifest document set is empty' }
  $ParseFailure = $Documents | Where-Object { @($_.Diagnostics).Count -gt 0 -or $null -eq $_.TypedData } | Select-Object -First 1
  if ($ParseFailure) { throw "The manifest document '$($ParseFailure.FileName)' could not be parsed" }

  $Types = @($Documents | ForEach-Object { $_.ManifestType })
  if ($Documents.Count -eq 1 -and $Types[0] -ceq 'singleton') { return }
  if ($Documents.Count -eq 1 -and $Types[0] -ceq 'preview') { return }
  if ($Types | Where-Object { $_ -notin @('version', 'installer', 'defaultlocale', 'locale') }) {
    throw "Unsupported manifest type in document set: $((@($Types | Where-Object { $_ -notin @('version', 'installer', 'defaultlocale', 'locale') }) -join ', '))"
  }
  foreach ($RequiredType in @('version', 'installer', 'defaultlocale')) {
    $Count = @($Documents | Where-Object ManifestType -EQ $RequiredType).Count
    if ($Count -ne 1) { throw "The manifest document set must contain exactly one '${RequiredType}' document; found ${Count}" }
  }

  $Identity = $Documents[0].TypedData
  foreach ($Document in $Documents | Select-Object -Skip 1) {
    foreach ($Field in @('PackageIdentifier', 'PackageVersion', 'ManifestVersion')) {
      if ([string]$Document.TypedData[$Field] -cne [string]$Identity[$Field]) {
        throw "The manifest document '$($Document.FileName)' has an inconsistent ${Field}"
      }
    }
  }

  $VersionDocument = $Documents | Where-Object ManifestType -EQ version | Select-Object -First 1
  $DefaultLocaleDocument = $Documents | Where-Object ManifestType -EQ defaultlocale | Select-Object -First 1
  if ([string]$VersionDocument.TypedData['DefaultLocale'] -cne [string]$DefaultLocaleDocument.TypedData['PackageLocale']) {
    throw 'The version manifest DefaultLocale does not match the default locale manifest PackageLocale'
  }
  $LocaleNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Document in $Documents | Where-Object { $_.ManifestType -in @('defaultlocale', 'locale') }) {
    if (-not $LocaleNames.Add([string]$Document.TypedData['PackageLocale'])) {
      throw "Duplicate locale manifest: $($Document.TypedData['PackageLocale'])"
    }
  }
}

function ConvertTo-WinGetManifestModelFromDocumentSet {
  <#
  .SYNOPSIS
    Populate the logical manifest model from parsed physical documents.
  .PARAMETER DocumentSet
    Parsed and structurally valid document set.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$DocumentSet)

  Assert-WinGetManifestDocumentSet -DocumentSet $DocumentSet
  $Documents = @($DocumentSet.Documents)
  if ($Documents.Count -eq 1 -and $Documents[0].ManifestType -ceq 'singleton') {
    return ConvertFrom-WinGetMergedManifest -Manifest $Documents[0].TypedData -SourceFormat Singleton
  }
  if ($Documents.Count -eq 1 -and $Documents[0].ManifestType -ceq 'preview') {
    throw 'Preview manifests cannot be represented by the authored v1 logical model'
  }

  $Version = ($Documents | Where-Object ManifestType -EQ version | Select-Object -First 1).TypedData
  $Installer = ($Documents | Where-Object ManifestType -EQ installer | Select-Object -First 1).TypedData
  $DefaultLocale = ($Documents | Where-Object ManifestType -EQ defaultlocale | Select-Object -First 1).TypedData
  $ManifestVersion = [string]$Version['ManifestVersion']
  $InstallerKeys = Get-WinGetInstallerPropertyCatalog -ManifestVersion $ManifestVersion

  $Defaults = [ordered]@{}
  foreach ($Key in $InstallerKeys) {
    if ($Installer.Contains($Key)) { $Defaults[$Key] = Copy-WinGetManifestValue -Value $Installer[$Key] }
  }
  $EffectiveInstallers = @(Get-WinGetAuthoredEffectiveInstallers -InstallerDefaults $Defaults -Installers ([System.Collections.IDictionary[]]@($Installer['Installers'])) -ManifestVersion $ManifestVersion)

  $DefaultLocalization = [ordered]@{}
  foreach ($Key in $DefaultLocale.Keys) {
    if ($Key -cnotin $Script:WinGetDocumentIdentityFields -and $Key -cne 'Moniker') {
      $DefaultLocalization[$Key] = Copy-WinGetManifestValue -Value $DefaultLocale[$Key]
    }
  }
  $Localizations = [System.Collections.Generic.List[object]]::new()
  foreach ($Document in $Documents | Where-Object ManifestType -EQ locale) {
    $Localization = [ordered]@{}
    foreach ($Key in $Document.TypedData.Keys) {
      if ($Key -cnotin $Script:WinGetDocumentIdentityFields) {
        $Localization[$Key] = Copy-WinGetManifestValue -Value $Document.TypedData[$Key]
      }
    }
    $Localizations.Add($Localization)
  }

  return New-WinGetManifestModel -PackageIdentifier ([string]$Version['PackageIdentifier']) -PackageVersion ([string]$Version['PackageVersion']) -Channel ([string]$Installer['Channel']) -Moniker ([string]$DefaultLocale['Moniker']) -ManifestVersion $ManifestVersion -InstallerDefaults $Defaults -Installers ([System.Collections.IDictionary[]]$EffectiveInstallers) -DefaultLocalization $DefaultLocalization -Localizations ([System.Collections.IDictionary[]]$Localizations.ToArray()) -SourceFormat MultiFile
}

function Read-WinGetManifest {
  <#
  .SYNOPSIS
    Parse a manifest file or directory into the logical manifest model.
  .PARAMETER Path
    Singleton file or leaf multi-file manifest directory.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    return ConvertTo-WinGetManifestModelFromDocumentSet -DocumentSet (Get-WinGetManifestDocumentSet -Path $Path)
  }
}

function ConvertFrom-WinGetManifestYaml {
  <#
  .SYNOPSIS
    Parse a Dumplings raw-content bundle into the logical manifest model.
  .PARAMETER Content
    Raw singleton content or a bundle with Version, Installer, and Locale data.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)]$Content)

  process {
    if ($Content -is [string]) {
      $Documents = @(ConvertFrom-WinGetManifestDocumentContent -Content $Content -FileName 'manifest.yaml')
    } elseif ($Content -is [System.Collections.IDictionary] -or $Content.PSObject.Properties['Version']) {
      $Documents = [System.Collections.Generic.List[object]]::new()
      if (-not [string]::IsNullOrWhiteSpace([string]$Content.Version)) {
        $Documents.Add((ConvertFrom-WinGetManifestDocumentContent -Content ([string]$Content.Version) -FileName 'version.yaml'))
      }
      if (-not [string]::IsNullOrWhiteSpace([string]$Content.Installer)) {
        $Documents.Add((ConvertFrom-WinGetManifestDocumentContent -Content ([string]$Content.Installer) -FileName 'installer.yaml'))
      }
      if ($Content.Locale) {
        foreach ($Entry in $Content.Locale.GetEnumerator()) {
          if ([string]::IsNullOrWhiteSpace([string]$Entry.Value)) { throw "The locale manifest '$($Entry.Key)' is empty" }
          $Documents.Add((ConvertFrom-WinGetManifestDocumentContent -Content ([string]$Entry.Value) -FileName "$($Entry.Key).yaml"))
        }
      }
      $Documents = $Documents.ToArray()
    } else {
      throw 'Unsupported WinGet manifest YAML input'
    }
    return ConvertTo-WinGetManifestModelFromDocumentSet -DocumentSet ([pscustomobject]@{ Documents = $Documents; SourcePath = $null })
  }
}

function Set-WinGetManifestTagOrder {
  <#
  .SYNOPSIS
    Sort the Tags field deterministically without changing other arrays.
  .PARAMETER Manifest
    Mutable manifest dictionary.
  #>
  param ([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest)

  if ($Manifest.Contains('Tags') -and $null -ne $Manifest['Tags']) {
    $Manifest['Tags'] = @($Manifest['Tags'] | Sort-Object -Culture $Script:WinGetManifestCulture.Name -Unique)
  }
}

function Format-WinGetManifest {
  <#
  .SYNOPSIS
    Normalize legal field levels and key order without updating metadata.
  .DESCRIPTION
    The function deep-copies the input. It may move equivalent installer fields
    between root and installer levels, but it never infers or deletes authored
    metadata. Unknown properties and every array except Tags retain their order.
  .PARAMETER Manifest
    One individually authored WinGet manifest dictionary.
  #>
  [OutputType([System.Collections.IDictionary])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][System.Collections.IDictionary]$Manifest)

  process {
    if (-not $Manifest.Contains('ManifestType') -or [string]::IsNullOrWhiteSpace([string]$Manifest['ManifestType'])) {
      throw 'The manifest does not contain a ManifestType'
    }
    $Formatted = Copy-WinGetManifestValue -Value $Manifest
    $ManifestType = ([string]$Formatted['ManifestType']).ToLowerInvariant()
    $ManifestVersion = [string]$Formatted['ManifestVersion']
    if ([string]::IsNullOrWhiteSpace($ManifestVersion)) { $ManifestVersion = $Script:WinGetAuthoringManifestVersion }

    if ($ManifestType -ceq 'installer') {
      if (-not $Formatted.Contains('Installers') -or @($Formatted['Installers']).Count -eq 0) {
        throw 'The installer manifest does not contain installer entries'
      }
      $InstallerKeys = Get-WinGetInstallerPropertyCatalog -ManifestVersion $ManifestVersion
      $Defaults = [ordered]@{}
      foreach ($Key in $InstallerKeys) {
        if ($Formatted.Contains($Key)) { $Defaults[$Key] = Copy-WinGetManifestValue -Value $Formatted[$Key] }
      }
      # Formatting must preserve even semantically invalid authored fields so
      # validation can report them afterward. Apply only generic precedence
      # here; WinGet's conditional ProductCode/PFN/archive inheritance belongs
      # to logical model construction, not a non-destructive formatter.
      $Effective = @($Formatted['Installers'] | ForEach-Object {
          Merge-WinGetManifestDictionary -Base $Defaults -Override $_
        })
      $TemporaryModel = [pscustomobject]@{ ManifestVersion = $ManifestVersion; Installers = $Effective }
      $Compacted = Get-WinGetManifestCompactedInstallerData -Manifest $TemporaryModel
      foreach ($Key in $InstallerKeys) { if ($Formatted.Contains($Key)) { $Formatted.Remove($Key) } }
      foreach ($Key in $Compacted.Defaults.Keys) { $Formatted[$Key] = $Compacted.Defaults[$Key] }
      $Formatted['Installers'] = $Compacted.Installers
    }

    Set-WinGetManifestTagOrder -Manifest $Formatted
    $SchemaType = $ManifestType -ceq 'defaultlocale' ? 'defaultLocale' : $ManifestType
    $Schema = Get-WinGetManifestSchema -ManifestType $SchemaType -ManifestVersion $ManifestVersion
    return ConvertTo-SortedYamlObject -InputObject $Formatted -Schema $Schema -Culture $Script:WinGetManifestCulture
  }
}

function ConvertTo-WinGetManifestDocumentSet {
  <#
  .SYNOPSIS
    Split a logical model into ordered multi-file manifest dictionaries.
  .PARAMETER Manifest
    Logical WinGet manifest model.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)]$Manifest)

  process {
    $Version = [ordered]@{
      PackageIdentifier = [string]$Manifest.PackageIdentifier
      PackageVersion    = [string]$Manifest.PackageVersion
      DefaultLocale     = [string]$Manifest.DefaultLocalization['PackageLocale']
    }
    $Version['ManifestType'] = 'version'
    $Version['ManifestVersion'] = [string]$Manifest.ManifestVersion

    $Compacted = Get-WinGetManifestCompactedInstallerData -Manifest $Manifest
    $Installer = [ordered]@{
      PackageIdentifier = [string]$Manifest.PackageIdentifier
      PackageVersion    = [string]$Manifest.PackageVersion
    }
    foreach ($Key in $Compacted.Defaults.Keys) { $Installer[$Key] = $Compacted.Defaults[$Key] }
    if (-not [string]::IsNullOrEmpty([string]$Manifest.Channel)) { $Installer['Channel'] = [string]$Manifest.Channel }
    $Installer['Installers'] = $Compacted.Installers
    $Installer['ManifestType'] = 'installer'
    $Installer['ManifestVersion'] = [string]$Manifest.ManifestVersion

    $DefaultLocale = [ordered]@{
      PackageIdentifier = [string]$Manifest.PackageIdentifier
      PackageVersion    = [string]$Manifest.PackageVersion
    }
    foreach ($Key in $Manifest.DefaultLocalization.Keys) { $DefaultLocale[$Key] = Copy-WinGetManifestValue -Value $Manifest.DefaultLocalization[$Key] }
    if (-not [string]::IsNullOrEmpty([string]$Manifest.Moniker)) { $DefaultLocale['Moniker'] = [string]$Manifest.Moniker }
    $DefaultLocale['ManifestType'] = 'defaultLocale'
    $DefaultLocale['ManifestVersion'] = [string]$Manifest.ManifestVersion

    $Locales = [System.Collections.Generic.List[object]]::new()
    foreach ($Localization in @($Manifest.Localizations)) {
      $Locale = [ordered]@{
        PackageIdentifier = [string]$Manifest.PackageIdentifier
        PackageVersion    = [string]$Manifest.PackageVersion
      }
      foreach ($Key in $Localization.Keys) { $Locale[$Key] = Copy-WinGetManifestValue -Value $Localization[$Key] }
      $Locale['ManifestType'] = 'locale'
      $Locale['ManifestVersion'] = [string]$Manifest.ManifestVersion
      $Locales.Add((Format-WinGetManifest -Manifest $Locale))
    }

    return [pscustomobject]@{
      PSTypeName    = 'Dumplings.WinGet.ManifestOutputDocumentSet'
      Version       = Format-WinGetManifest -Manifest $Version
      Installer     = Format-WinGetManifest -Manifest $Installer
      DefaultLocale = Format-WinGetManifest -Manifest $DefaultLocale
      Locales       = $Locales.ToArray()
    }
  }
}

function ConvertTo-WinGetManifestDocumentYaml {
  <#
  .SYNOPSIS
    Serialize one ordered document with fixed Dumplings headers.
  .PARAMETER Manifest
    Ordered physical manifest dictionary.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest)

  $Type = ([string]$Manifest['ManifestType']).ToLowerInvariant()
  $SchemaType = $Type -ceq 'defaultlocale' ? 'defaultLocale' : $Type
  $SchemaUrl = Get-WinGetManifestSchemaUrl -ManifestType $SchemaType -ManifestVersion ([string]$Manifest['ManifestVersion'])
  return @"
$Script:WinGetManifestHeader
# yaml-language-server: `$schema=${SchemaUrl}

$((ConvertTo-Yaml -Data $Manifest -Options DisableAliases).TrimEnd())

"@
}

function ConvertTo-WinGetManifestYaml {
  <#
  .SYNOPSIS
    Serialize a logical model to the Dumplings raw multi-file content bundle.
  .PARAMETER Manifest
    Logical WinGet manifest model.
  #>
  [OutputType([System.Collections.IDictionary])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)]$Manifest)

  process {
    $Documents = ConvertTo-WinGetManifestDocumentSet -Manifest $Manifest
    $LocaleContent = [ordered]@{}
    $LocaleContent[[string]$Documents.DefaultLocale['PackageLocale']] = ConvertTo-WinGetManifestDocumentYaml -Manifest $Documents.DefaultLocale
    foreach ($Locale in $Documents.Locales) {
      $LocaleContent[[string]$Locale['PackageLocale']] = ConvertTo-WinGetManifestDocumentYaml -Manifest $Locale
    }
    return [ordered]@{
      Version   = ConvertTo-WinGetManifestDocumentYaml -Manifest $Documents.Version
      Installer = ConvertTo-WinGetManifestDocumentYaml -Manifest $Documents.Installer
      Locale    = $LocaleContent
    }
  }
}

Export-ModuleMember -Function ConvertTo-WinGetManifestScalarType, ConvertFrom-WinGetManifestDocumentContent, Get-WinGetManifestDocumentSet, Assert-WinGetManifestDocumentSet, ConvertTo-WinGetManifestModelFromDocumentSet, Read-WinGetManifest, ConvertFrom-WinGetManifestYaml, Format-WinGetManifest, ConvertTo-WinGetManifestDocumentSet, ConvertTo-WinGetManifestYaml
