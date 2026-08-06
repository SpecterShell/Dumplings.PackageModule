# WinGet manifest validation follows the MIT-licensed Windows Package Manager
# YamlParser, ManifestSchemaValidation, ManifestYamlPopulator, ManifestValidation,
# ManifestCommon, and MsiExecArguments implementations:
# https://github.com/microsoft/winget-cli

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

if (-not ([System.Management.Automation.PSTypeName]'Dumplings.WinGet.ManifestLocale').Type) {
  try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Dumplings.WinGet
{
    // Mirrors winget-cli Locale.cpp. WinGet accepts the locale when neither
    // Windows BCP 47 implementation is available on a downlevel system.
    public static class ManifestLocale
    {
        [DllImport("bcp47mrm.dll", EntryPoint = "IsWellFormedTag", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool IsWellFormedModern(string value);

        [DllImport("bcp47langs.dll", EntryPoint = "IsWellFormedTag", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool IsWellFormedDownlevel(string value);

        public static bool IsWellFormed(string value)
        {
            try { return IsWellFormedModern(value); }
            catch (DllNotFoundException)
            {
                try { return IsWellFormedDownlevel(value); }
                catch (DllNotFoundException) { return true; }
                catch (EntryPointNotFoundException) { return true; }
            }
            catch (EntryPointNotFoundException) { return true; }
        }
    }
}
'@
  } catch {
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.WinGet.ManifestLocale').Type) { throw }
  }
}

$Script:WinGetIntegerFields = @('InstallerSuccessCodes', 'InstallerReturnCode')
$Script:WinGetBooleanFields = @(
  'InstallerAbortsTerminal',
  'InstallLocationRequired',
  'RequireExplicitUpgrade',
  'DisplayInstallWarnings',
  'DownloadCommandProhibited',
  'ArchiveBinariesDependOnPath'
)
$Script:WinGetProductCodeTypes = @('exe', 'inno', 'msi', 'nullsoft', 'wix', 'burn', 'portable')
$Script:WinGetPackageFamilyNameTypes = @('msix', 'msstore')
$Script:WinGetArchiveTypes = @('zip')
$Script:WinGetPortableFileTypes = @('.exe')
$Script:WinGetFontFileTypes = @('.otf', '.ttf', '.fnt', '.ttc', '.otc')
$Script:WinGetDefaultSwitches = @{
  burn     = [ordered]@{ Silent = '/quiet /norestart'; SilentWithProgress = '/passive /norestart'; Log = '/log "<LOGPATH>"'; InstallLocation = 'TARGETDIR="<INSTALLPATH>"' }
  wix      = [ordered]@{ Silent = '/quiet /norestart'; SilentWithProgress = '/passive /norestart'; Log = '/log "<LOGPATH>"'; InstallLocation = 'TARGETDIR="<INSTALLPATH>"' }
  msi      = [ordered]@{ Silent = '/quiet /norestart'; SilentWithProgress = '/passive /norestart'; Log = '/log "<LOGPATH>"'; InstallLocation = 'TARGETDIR="<INSTALLPATH>"' }
  nullsoft = [ordered]@{ Silent = '/S'; SilentWithProgress = '/S'; InstallLocation = '/D=<INSTALLPATH>' }
  inno     = [ordered]@{ Silent = '/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'; SilentWithProgress = '/SP- /SILENT /SUPPRESSMSGBOXES /NORESTART'; Log = '/LOG="<LOGPATH>"'; InstallLocation = '/DIR="<INSTALLPATH>"' }
}
$Script:WinGetDefaultReturnCodes = @{
  burn = [ordered]@{
    1618 = 'installInProgress'; 112 = 'diskFull'; 1601 = 'contactSupport'; 3010 = 'rebootRequiredToFinish'; 1641 = 'rebootInitiated'
    1602 = 'cancelledByUser'; 1638 = 'alreadyInstalled'; 1654 = 'systemNotSupported'; 1625 = 'blockedByPolicy'
    1644 = 'blockedByPolicy'; 1643 = 'blockedByPolicy'; 1649 = 'blockedByPolicy'; 1640 = 'blockedByPolicy'
    87 = 'invalidParameter'; 1628 = 'invalidParameter'; 1639 = 'invalidParameter'; 1650 = 'invalidParameter'
    1623 = 'systemNotSupported'; 1633 = 'systemNotSupported'
  }
  wix  = $null
  msi  = $null
  inno = [ordered]@{ 2 = 'cancelledByUser'; 5 = 'cancelledByUser'; 8 = 'rebootRequiredForInstall' }
  msix = [ordered]@{
    2147958003 = 'missingDependency'; 2147958004 = 'diskFull'; 2147958008 = 'cancelledByUser'; 2147958011 = 'alreadyInstalled'
    2147958013 = 'missingDependency'; 2147958015 = 'blockedByPolicy'; 2147958017 = 'blockedByPolicy'; 2147958018 = 'packageInUse'
    2147958022 = 'downgrade'; 2147958032 = 'systemNotSupported'; 2147958034 = 'missingDependency'
    2147958035 = 'systemNotSupported'; 2147958045 = 'systemNotSupported'; 2147958058 = 'systemNotSupported'
  }
}
$Script:WinGetDefaultReturnCodes.wix = $Script:WinGetDefaultReturnCodes.burn
$Script:WinGetDefaultReturnCodes.msi = $Script:WinGetDefaultReturnCodes.burn

function New-WinGetManifestDiagnostic {
  <#
  .SYNOPSIS
    Create one structured WinGet validation diagnostic.
  .PARAMETER Severity
    Error or warning severity.
  .PARAMETER Id
    Stable WinGet-compatible diagnostic identifier.
  .PARAMETER Message
    Human-readable diagnostic text.
  .PARAMETER Field
    Related manifest field.
  .PARAMETER Value
    Invalid or noteworthy value.
  .PARAMETER File
    Physical source file name.
  .PARAMETER Line
    One-based source line when available.
  .PARAMETER Column
    One-based source column when available.
  .PARAMETER ObjectPath
    JSONPath-like location in the logical manifest.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateSet('Error', 'Warning')][string]$Severity,
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$Message,
    [string]$Field,
    $Value,
    [string]$File,
    [Nullable[int]]$Line,
    [Nullable[int]]$Column,
    [string]$ObjectPath
  )

  return [pscustomobject]@{
    PSTypeName = 'Dumplings.WinGet.ManifestValidationDiagnostic'
    Severity   = $Severity
    Id         = $Id
    Message    = $Message
    Field      = $Field
    Value      = $Value
    File       = $File
    Line       = $Line
    Column     = $Column
    ObjectPath = $ObjectPath
  }
}

function Read-WinGetManifestValidationDocument {
  <#
  .SYNOPSIS
    Read one validation document through the shared serialization boundary.
  .PARAMETER Path
    Physical YAML manifest path.
  #>
  param ([Parameter(Mandatory)][string]$Path)

  $ResolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  $Document = ConvertFrom-WinGetManifestDocumentContent -Content (Get-Content -LiteralPath $ResolvedPath -Raw) -FileName ([IO.Path]::GetFileName($ResolvedPath)) -Path $ResolvedPath -AllowInvalid
  $Diagnostics = @($Document.Diagnostics | ForEach-Object {
      New-WinGetManifestDiagnostic -Severity Error -Id $_.Id -Message $_.Message -Field $_.Field -File $_.File -Line $_.Line -Column $_.Column
    })
  $Document.Diagnostics = $Diagnostics
  return $Document
}

function Get-WinGetManifestValidationDocuments {
  <#
  .SYNOPSIS
    Read validation documents from a file or leaf directory.
  .PARAMETER Path
    Manifest file or leaf manifest directory.
  #>
  param ([Parameter(Mandatory)][string]$Path)

  $DocumentSet = Get-WinGetManifestDocumentSet -Path $Path -AllowInvalid
  foreach ($Document in $DocumentSet.Documents) {
    $Document.Diagnostics = @($Document.Diagnostics | ForEach-Object {
        New-WinGetManifestDiagnostic -Severity Error -Id $_.Id -Message $_.Message -Field $_.Field -File $_.File -Line $_.Line -Column $_.Column
      })
  }
  return $DocumentSet.Documents
}

function Get-WinGetManifestTypeName {
  <#
  .SYNOPSIS
    Normalize a manifest type to WinGet's canonical spelling.
  .PARAMETER ManifestType
    Manifest type text.
  #>
  param ([string]$ManifestType)

  switch ($ManifestType.ToLowerInvariant()) {
    'defaultlocale' { return 'defaultLocale' }
    'installer' { return 'installer' }
    'locale' { return 'locale' }
    'merged' { return 'merged' }
    'singleton' { return 'singleton' }
    'version' { return 'version' }
    'shadow' { return 'shadow' }
    default { return 'unknown' }
  }
}

function Get-WinGetEffectiveInstallers {
  <#
  .SYNOPSIS
    Add WinGet runtime defaults to authored effective installer entries.
  .DESCRIPTION
    Authored inheritance is delegated to WinGetManifestModel. This function
    adds only runtime-derived switches and return codes used by validation.
  .PARAMETER Manifest
    Flat merged manifest projection.
  #>
  param ([System.Collections.IDictionary]$Manifest)

  $AuthoredModel = ConvertFrom-WinGetMergedManifest -Manifest $Manifest -SourceFormat Merged
  $Results = [System.Collections.Generic.List[object]]::new()
  foreach ($Entry in @($AuthoredModel.Installers)) {
    $Effective = Copy-WinGetManifestValue -Value $Entry
    $EffectiveType = Get-WinGetManifestEffectiveInstallerType -Installer $Effective
    if ($Script:WinGetDefaultSwitches.Contains($EffectiveType)) {
      $Switches = if ($Effective.Contains('InstallerSwitches')) { Copy-WinGetManifestValue $Effective.InstallerSwitches } else { [ordered]@{} }
      foreach ($Key in $Script:WinGetDefaultSwitches[$EffectiveType].Keys) {
        if (-not $Switches.Contains($Key)) { $Switches[$Key] = $Script:WinGetDefaultSwitches[$EffectiveType][$Key] }
      }
      $Effective['InstallerSwitches'] = $Switches
    }
    if ($Script:WinGetDefaultReturnCodes.Contains($EffectiveType)) {
      $ExpectedReturnCodes = [System.Collections.Generic.List[object]]::new()
      $KnownReturnCodes = [System.Collections.Generic.HashSet[long]]::new()
      foreach ($ReturnCode in @($Effective['InstallerSuccessCodes'])) { $null = $KnownReturnCodes.Add([long]$ReturnCode) }
      foreach ($ReturnCode in @($Effective['ExpectedReturnCodes'])) {
        if ($null -eq $ReturnCode) { continue }
        $ExpectedReturnCodes.Add((Copy-WinGetManifestValue -Value $ReturnCode))
        $null = $KnownReturnCodes.Add([long]$ReturnCode['InstallerReturnCode'])
      }
      foreach ($DefaultReturnCode in $Script:WinGetDefaultReturnCodes[$EffectiveType].GetEnumerator()) {
        if ($KnownReturnCodes.Add([long]$DefaultReturnCode.Key)) {
          $ExpectedReturnCodes.Add([ordered]@{ InstallerReturnCode = [long]$DefaultReturnCode.Key; ReturnResponse = $DefaultReturnCode.Value })
        }
      }
      $Effective['ExpectedReturnCodes'] = $ExpectedReturnCodes.ToArray()
    }
    $Effective['_EffectiveInstallerType'] = $EffectiveType
    $Results.Add($Effective)
  }

  return $Results.ToArray()
}

function ConvertFrom-WinGetPreviewManifest {
  <#
  .SYNOPSIS
    Convert a historical 0.1 preview manifest for semantic validation.
  .PARAMETER Manifest
    Parsed preview manifest dictionary.
  #>
  param ([System.Collections.IDictionary]$Manifest)

  $Result = [ordered]@{
    PackageIdentifier = [string]$Manifest['Id']
    PackageVersion    = [string]$Manifest['Version']
    ManifestType      = 'merged'
    # Get-WinGetEffectiveInstallers uses this only to select the installer
    # property catalog; the original document is still validated as 0.1.0.
    ManifestVersion   = '1.0.0'
  }
  foreach ($Key in @('Channel', 'Commands', 'Protocols', 'FileExtensions', 'PackageFamilyName', 'ProductCode')) {
    if ($Manifest.Contains($Key)) { $Result[$Key] = Copy-WinGetManifestValue -Value $Manifest[$Key] }
  }
  if ($Manifest.Contains('InstallerType')) { $Result['InstallerType'] = [string]$Manifest['InstallerType'] }
  if ($Manifest.Contains('UpdateBehavior')) { $Result['UpgradeBehavior'] = [string]$Manifest['UpdateBehavior'] }
  if ($Manifest.Contains('MinOSVersion')) { $Result['MinimumOSVersion'] = [string]$Manifest['MinOSVersion'] }
  if ($Manifest.Contains('Switches')) { $Result['InstallerSwitches'] = Copy-WinGetManifestValue -Value $Manifest['Switches'] }

  $Installers = [System.Collections.Generic.List[object]]::new()
  foreach ($PreviewInstaller in @($Manifest['Installers'])) {
    if ($null -eq $PreviewInstaller) { continue }
    $Installer = [ordered]@{}
    foreach ($Mapping in @(
        @('Arch', 'Architecture'), @('Url', 'InstallerUrl'), @('Sha256', 'InstallerSha256'),
        @('SignatureSha256', 'SignatureSha256'), @('Language', 'InstallerLocale'), @('Scope', 'Scope'),
        @('InstallerType', 'InstallerType'), @('UpdateBehavior', 'UpgradeBehavior'),
        @('PackageFamilyName', 'PackageFamilyName'), @('ProductCode', 'ProductCode'), @('Switches', 'InstallerSwitches')
      )) {
      if ($PreviewInstaller.Contains($Mapping[0])) {
        $Installer[$Mapping[1]] = Copy-WinGetManifestValue -Value $PreviewInstaller[$Mapping[0]]
      }
    }
    $Installers.Add($Installer)
  }
  $Result['Installers'] = $Installers.ToArray()

  $Localizations = [System.Collections.Generic.List[object]]::new()
  foreach ($PreviewLocalization in @($Manifest['Localization'])) {
    if ($null -eq $PreviewLocalization) { continue }
    $Localization = [ordered]@{}
    if ($PreviewLocalization.Contains('Language')) { $Localization['PackageLocale'] = [string]$PreviewLocalization['Language'] }
    foreach ($Key in @('Description', 'Homepage', 'LicenseUrl')) {
      if ($PreviewLocalization.Contains($Key)) { $Localization[$Key] = Copy-WinGetManifestValue -Value $PreviewLocalization[$Key] }
    }
    $Localizations.Add($Localization)
  }
  if ($Localizations.Count -gt 0) { $Result['Localization'] = $Localizations.ToArray() }
  return $Result
}

function Test-WinGetManifestInputSet {
  <#
  .SYNOPSIS
    Validate physical manifest-set structure and shared identity fields.
  .PARAMETER Documents
    Parsed physical manifest documents.
  #>
  param ([object[]]$Documents)

  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  foreach ($Document in $Documents) { $Diagnostics.AddRange(@($Document.Diagnostics)) }
  if ($Diagnostics.Where({ $_.Severity -ceq 'Error' }, 'First')) {
    return [pscustomobject]@{ Diagnostics = $Diagnostics.ToArray(); ManifestVersion = $null; PackageIdentifier = $null; PackageVersion = $null; IsMultiFile = $Documents.Count -gt 1 }
  }

  foreach ($Document in $Documents) {
    if ($Document.TypedData -isnot [System.Collections.IDictionary]) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidRootNode -Message 'The manifest does not contain a valid mapping root.' -File $Document.FileName))
    }
  }
  if ($Diagnostics.Count -gt 0) {
    return [pscustomobject]@{ Diagnostics = $Diagnostics.ToArray(); ManifestVersion = $null; PackageIdentifier = $null; PackageVersion = $null; IsMultiFile = $Documents.Count -gt 1 }
  }

  $First = $Documents[0].TypedData
  $ManifestVersion = if ($First.Contains('ManifestVersion')) { [string]$First.ManifestVersion } else { '0.1.0' }
  $PackageIdentifier = if ($First.Contains('PackageIdentifier')) { [string]$First.PackageIdentifier } elseif ($First.Contains('Id')) { [string]$First.Id } else { $null }
  $PackageVersion = if ($First.Contains('PackageVersion')) { [string]$First.PackageVersion } elseif ($First.Contains('Version')) { [string]$First.Version } else { $null }
  try { $SchemaVersion = Resolve-WinGetManifestSchemaVersion -ManifestVersion $ManifestVersion } catch {
    $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id UnsupportedManifestVersion -Message $_.Exception.Message -Field ManifestVersion -Value $ManifestVersion -File $Documents[0].FileName))
    return [pscustomobject]@{ Diagnostics = $Diagnostics.ToArray(); ManifestVersion = $ManifestVersion; PackageIdentifier = $PackageIdentifier; PackageVersion = $PackageVersion; IsMultiFile = $Documents.Count -gt 1 }
  }

  $IsV1 = $SchemaVersion -cne '0.1.0'
  $IsMultiFile = $Documents.Count -gt 1
  if (-not $IsV1) {
    if ($IsMultiFile) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id IncompleteMultiFileManifest -Message 'Preview manifests do not support multi-file format.'))
    }
    return [pscustomobject]@{ Diagnostics = $Diagnostics.ToArray(); ManifestVersion = $ManifestVersion; PackageIdentifier = $PackageIdentifier; PackageVersion = $PackageVersion; IsMultiFile = $IsMultiFile }
  }

  foreach ($Document in $Documents) {
    $Data = $Document.TypedData
    foreach ($Required in @('PackageIdentifier', 'PackageVersion', 'ManifestVersion', 'ManifestType')) {
      if (-not $Data.Contains($Required)) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message "Required field '${Required}' is missing." -Field $Required -File $Document.FileName))
      }
    }
    $Type = if ($Data.Contains('ManifestType')) { Get-WinGetManifestTypeName -ManifestType ([string]$Data.ManifestType) } else { 'unknown' }
    $Document | Add-Member -NotePropertyName ManifestType -NotePropertyValue $Type -Force
    if ($Type -cin @('singleton', 'defaultLocale', 'locale') -and -not $Data.Contains('PackageLocale')) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message "Required field 'PackageLocale' is missing." -Field PackageLocale -File $Document.FileName))
    }
    if ($Type -ceq 'version' -and -not $Data.Contains('DefaultLocale')) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message "Required field 'DefaultLocale' is missing." -Field DefaultLocale -File $Document.FileName))
    }
  }
  if ($Diagnostics.Count -gt 0) {
    return [pscustomobject]@{ Diagnostics = $Diagnostics.ToArray(); ManifestVersion = $ManifestVersion; PackageIdentifier = $PackageIdentifier; PackageVersion = $PackageVersion; IsMultiFile = $IsMultiFile }
  }

  $PackageIdentifier = [string]$First.PackageIdentifier
  $PackageVersion = [string]$First.PackageVersion
  foreach ($Document in $Documents) {
    foreach ($Field in @('PackageIdentifier', 'PackageVersion', 'ManifestVersion')) {
      $Expected = switch ($Field) { PackageIdentifier { $PackageIdentifier }; PackageVersion { $PackageVersion }; ManifestVersion { $ManifestVersion } }
      if ([string]$Document.TypedData[$Field] -cne $Expected) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InconsistentMultiFileManifestFieldValue -Message "The multi-file manifest has an inconsistent ${Field}." -Field $Field -Value $Document.TypedData[$Field] -File $Document.FileName))
      }
    }
  }

  if ($IsMultiFile) {
    $AllowedTypes = @('version', 'installer', 'defaultLocale', 'locale')
    foreach ($Document in $Documents) {
      if ($Document.ManifestType -cnotin $AllowedTypes) {
        $Id = if ($Document.ManifestType -ceq 'shadow') { 'ShadowManifestNotAllowed' } else { 'UnsupportedMultiFileManifestType' }
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id $Id -Message "Manifest type '$($Document.ManifestType)' is not supported in this manifest set." -Field ManifestType -Value $Document.ManifestType -File $Document.FileName))
      }
    }

    foreach ($RequiredType in @('version', 'installer', 'defaultLocale')) {
      $MatchingDocuments = @($Documents | Where-Object ManifestType -CEQ $RequiredType)
      if ($MatchingDocuments.Count -eq 0) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id IncompleteMultiFileManifest -Message "The multi-file manifest is missing the ${RequiredType} manifest." -Field ManifestType -Value $RequiredType))
      } elseif ($MatchingDocuments.Count -gt 1) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id DuplicateMultiFileManifestType -Message "The multi-file manifest contains more than one ${RequiredType} manifest." -Field ManifestType -Value $RequiredType))
      }
    }

    $Locales = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($Document in $Documents | Where-Object { $_.ManifestType -cin @('defaultLocale', 'locale') }) {
      $Locale = [string]$Document.TypedData.PackageLocale
      if (-not $Locales.Add($Locale)) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id DuplicateMultiFileManifestLocale -Message "The multi-file manifest contains duplicate locale '${Locale}'." -Field PackageLocale -Value $Locale -File $Document.FileName))
      }
    }

    $VersionDocument = $Documents | Where-Object ManifestType -CEQ version | Select-Object -First 1
    $DefaultLocaleDocument = $Documents | Where-Object ManifestType -CEQ defaultLocale | Select-Object -First 1
    if ($VersionDocument -and $DefaultLocaleDocument -and [string]$VersionDocument.TypedData.DefaultLocale -cne [string]$DefaultLocaleDocument.TypedData.PackageLocale) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InconsistentMultiFileManifestDefaultLocale -Message 'DefaultLocale does not match the default locale manifest PackageLocale.'))
    }
  } else {
    if ($Documents[0].ManifestType -ceq 'merged') {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id FieldValueNotSupported -Message "ManifestType 'merged' is unsupported by full validation." -Field ManifestType -Value merged -File $Documents[0].FileName))
    } elseif ($Documents[0].ManifestType -cne 'singleton') {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id IncompleteMultiFileManifest -Message 'A single-file v1 manifest must use ManifestType singleton.' -Field ManifestType -Value $Documents[0].ManifestType -File $Documents[0].FileName))
    }
  }

  return [pscustomobject]@{
    Diagnostics       = $Diagnostics.ToArray()
    ManifestVersion   = $ManifestVersion
    PackageIdentifier = $PackageIdentifier
    PackageVersion    = $PackageVersion
    IsMultiFile       = $IsMultiFile
  }
}

function Test-WinGetManifestSchemas {
  <#
  .SYNOPSIS
    Validate each physical manifest document against its official schema.
  .PARAMETER Documents
    Parsed physical manifest documents.
  .PARAMETER ManifestVersion
    Manifest version used to select the nearest supported schema revision.
  #>
  param (
    [object[]]$Documents,
    [string]$ManifestVersion
  )

  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  foreach ($Document in $Documents) {
    $SchemaType = if ((Resolve-WinGetManifestSchemaVersion $ManifestVersion) -ceq '0.1.0') { 'preview' } else { $Document.ManifestType }
    if ($SchemaType -cin @('shadow', 'merged', 'unknown')) { continue }
    try {
      # The shared schema engine owns reference resolution, keyword validation,
      # unknown-field detection, and ordinal property-casing diagnostics.
      $Schema = Get-WinGetManifestSchema -ManifestType $SchemaType -ManifestVersion $ManifestVersion -Raw
      $SchemaResult = Get-YamlSchemaValidationResult -InputObject $Document.TypedData -Schema $Schema -RootSchema $Schema -ValidatePropertyNames
      foreach ($SchemaDiagnostic in @($SchemaResult.Diagnostics)) {
        $Id = switch ($SchemaDiagnostic.Reason) {
          'PropertyNameCase' { 'FieldIsNotPascalCase' }
          'UnknownProperty' { 'FieldUnknown' }
          default { 'SchemaError' }
        }
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id $Id -Message $SchemaDiagnostic.Message -Field $SchemaDiagnostic.Field -Value $SchemaDiagnostic.Value -File $Document.FileName -ObjectPath $SchemaDiagnostic.ObjectPath))
      }
    } catch {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id SchemaError -Message $_.Exception.Message -File $Document.FileName))
    }
  }
  return $Diagnostics.ToArray()
}

function Test-WinGetManifestSchemaHeaders {
  <#
  .SYNOPSIS
    Validate yaml-language-server schema header comments.
  .PARAMETER Documents
    Parsed physical manifest documents.
  .PARAMETER ManifestVersion
    Declared manifest version.
  #>
  param (
    [object[]]$Documents,
    [string]$ManifestVersion
  )

  if ([version](Resolve-WinGetManifestSchemaVersion $ManifestVersion) -lt [version]'1.7.0') { return }
  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  foreach ($Document in $Documents) {
    if ($Document.ManifestType -ceq 'shadow') { continue }
    if ([string]::IsNullOrWhiteSpace($Document.SchemaHeader)) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id SchemaHeaderNotFound -Message 'Schema header not found.' -File $Document.FileName))
      continue
    }

    if ($Document.SchemaHeader -notmatch 'winget-manifest\.(?<Type>\w+)\.(?<Version>[\d\.]+)\.schema\.json$') {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id SchemaHeaderUrlPatternMismatch -Message 'The schema header URL does not match the expected pattern.' -Value $Document.SchemaHeader -File $Document.FileName -Line $Document.HeaderLine))
      continue
    }

    if ((Get-WinGetManifestTypeName $Matches.Type) -cne $Document.ManifestType) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id SchemaHeaderManifestTypeMismatch -Message 'The schema header manifest type does not match ManifestType.' -Value $Matches.Type -File $Document.FileName -Line $Document.HeaderLine))
    }
    if ($Matches.Version -cne $ManifestVersion) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id SchemaHeaderManifestVersionMismatch -Message 'The schema header manifest version does not match ManifestVersion.' -Value $Matches.Version -File $Document.FileName -Line $Document.HeaderLine))
    }

    try {
      $Schema = Get-WinGetManifestSchema -ManifestType $Document.ManifestType -ManifestVersion $ManifestVersion -Raw
      if ($Document.SchemaHeader -ine $Schema['$id']) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id SchemaHeaderUrlPatternMismatch -Message 'The schema header URL does not match the official schema identifier.' -Value $Document.SchemaHeader -File $Document.FileName -Line $Document.HeaderLine))
      }
    } catch {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id InvalidSchemaHeader -Message $_.Exception.Message -Value $Document.SchemaHeader -File $Document.FileName -Line $Document.HeaderLine))
    }
  }
  return $Diagnostics.ToArray()
}

function Merge-WinGetManifestValidationSet {
  <#
  .SYNOPSIS
    Build the legacy flat projection used for preview validation.
  .PARAMETER Documents
    Parsed preview or multi-file documents.
  #>
  param ([object[]]$Documents)

  if ($Documents.Count -eq 1) { return Copy-WinGetManifestValue -Value $Documents[0].TypedData }

  $InstallerDocument = $Documents | Where-Object ManifestType -CEQ installer | Select-Object -First 1
  $DefaultLocaleDocument = $Documents | Where-Object ManifestType -CEQ defaultLocale | Select-Object -First 1
  $Merged = Copy-WinGetManifestValue -Value $InstallerDocument.TypedData
  $CommonFields = @('PackageIdentifier', 'PackageVersion', 'ManifestType', 'ManifestVersion')
  foreach ($Key in $DefaultLocaleDocument.TypedData.Keys) {
    if ($Key -cnotin $CommonFields) { $Merged[$Key] = Copy-WinGetManifestValue -Value $DefaultLocaleDocument.TypedData[$Key] }
  }

  $Localizations = [System.Collections.Generic.List[object]]::new()
  foreach ($Document in $Documents | Where-Object ManifestType -CEQ locale) {
    $Localization = [ordered]@{}
    foreach ($Key in $Document.TypedData.Keys) {
      if ($Key -cnotin $CommonFields) { $Localization[$Key] = Copy-WinGetManifestValue -Value $Document.TypedData[$Key] }
    }
    $Localizations.Add($Localization)
  }
  if ($Localizations.Count -gt 0) { $Merged['Localization'] = $Localizations.ToArray() }
  $Merged['ManifestType'] = 'merged'
  return $Merged
}

function Test-WinGetBcp47Tag {
  <#
  .SYNOPSIS
    Test a locale using Windows' BCP 47 implementation.
  .PARAMETER Value
    Locale tag to test.
  #>
  param ([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 84) { return $false }
  return [Dumplings.WinGet.ManifestLocale]::IsWellFormed($Value)
}

function Test-WinGetPathEscapesBaseDirectory {
  <#
  .SYNOPSIS
    Test whether an archive-relative path escapes its base directory.
  .PARAMETER Path
    Relative archive path or command alias.
  #>
  param ([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  if ([IO.Path]::IsPathRooted($Path)) { return $true }

  $Depth = 0
  foreach ($Part in $Path.Replace('/', '\').Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
    if ($Part -ceq '.') { continue }
    if ($Part -ceq '..') {
      if ($Depth -eq 0) { return $true }
      $Depth--
    } else {
      $Depth++
    }
  }
  return $false
}

function Split-WinGetMsiArguments {
  <#
  .SYNOPSIS
    Tokenize MSI arguments while retaining quoted property assignments.
  .PARAMETER Arguments
    MSI command-line arguments.
  #>
  param ([string]$Arguments)

  $Tokens = [System.Collections.Generic.List[string]]::new()
  $Start = 0
  while ($Start -lt $Arguments.Length) {
    while ($Start -lt $Arguments.Length -and $Arguments[$Start] -in @(' ', "`t")) { $Start++ }
    if ($Start -ge $Arguments.Length) { break }

    $Position = $Start + 1
    $SeekingSpace = $Arguments[$Start] -cne '"'
    $WithinQuotes = $false
    while ($Position -lt $Arguments.Length) {
      $Character = $Arguments[$Position]
      if ($SeekingSpace) {
        if ($Character -ceq '"') { $WithinQuotes = -not $WithinQuotes }
        elseif ($Character -in @(' ', "`t") -and -not $WithinQuotes) { break }
      } elseif ($Character -ceq '"') {
        $Position++
        break
      }
      $Position++
    }
    $Tokens.Add($Arguments.Substring($Start, $Position - $Start))
    $Start = $Position
  }
  return $Tokens.ToArray()
}

function Test-WinGetMsiArguments {
  <#
  .SYNOPSIS
    Validate MSI switch syntax and blocked public properties.
  .PARAMETER Arguments
    MSI command-line arguments.
  #>
  param ([string]$Arguments)

  $Result = [ordered]@{ IsValid = $true; BlockedProperty = $null; Error = $null }
  try {
    $Tokens = [System.Collections.Generic.List[string]]::new()
    foreach ($Token in @(Split-WinGetMsiArguments -Arguments $Arguments)) {
      if ($Token -match '^[/-](?i:quiet)$') { $Tokens.Add('/qn'); continue }
      if ($Token -match '^[/-](?i:passive)$') { $Tokens.Add('/qb!-'); $Tokens.Add('REBOOTPROMPT=S'); continue }
      if ($Token -match '^[/-](?i:norestart)$') { $Tokens.Add('REBOOT=ReallySuppress'); continue }
      if ($Token -match '^[/-](?i:forcerestart)$') { $Tokens.Add('REBOOT=Force'); continue }
      if ($Token -match '^[/-](?i:promptrestart)$') { $Tokens.Add('REBOOTPROMPT=""'); continue }
      if ($Token -match '^[/-](?i:log)$') { $Tokens.Add('/l*'); continue }
      $Tokens.Add($Token)
    }

    for ($Index = 0; $Index -lt $Tokens.Count; $Index++) {
      $Token = $Tokens[$Index]
      if ($Token.StartsWith('/') -or $Token.StartsWith('-')) {
        if ($Token.Length -le 1) { throw 'Empty MSI switch' }
        $Option = [char]::ToLowerInvariant($Token[1])
        $Modifier = $Token.Substring(2)
        if ($Option -ceq 'q') {
          if ([string]::IsNullOrEmpty($Modifier)) { continue }
          if ($Modifier[0] -notin @('f', 'F', 'r', 'R', 'b', 'B', '+', 'n', 'N')) { throw 'Invalid MSI quiet modifier' }
          for ($ModifierIndex = 1; $ModifierIndex -lt $Modifier.Length; $ModifierIndex++) {
            if ($Modifier[$ModifierIndex] -in @('-', '!') -and $Modifier[0] -notin @('b', 'B')) { throw 'Invalid MSI quiet modifier' }
          }
          continue
        }
        if ($Option -ceq 'l') {
          foreach ($Character in $Modifier.ToCharArray()) {
            if ($Character -notin @('m', 'M', 'e', 'E', 'w', 'W', 'u', 'U', 'i', 'I', 'o', 'O', 'a', 'A', 'r', 'R', 'p', 'P', 'c', 'C', 'v', 'V', 'x', 'X', '*', '+', '!')) {
              throw 'Invalid MSI log modifier'
            }
          }
          $Index++
          if ($Index -ge $Tokens.Count -or [string]::IsNullOrWhiteSpace($Tokens[$Index].Trim('"'))) { throw 'Missing MSI log file' }
          continue
        }
        throw "Unsupported MSI switch '${Token}'"
      }

      if ($Token -notmatch '^(?<Name>[%A-Za-z0-9][^\s=]*)=(?<Value>.*)$') { throw "Invalid MSI property '${Token}'" }
      $Name = $Matches.Name
      $Value = $Matches.Value
      if ($Value.StartsWith('"') -and (-not $Value.EndsWith('"') -or $Value.Length -eq 1)) { throw "Invalid quoted MSI property '${Token}'" }
      if (-not $Value.StartsWith('"') -and $Value -match '\s') { throw "Invalid unquoted MSI property '${Token}'" }
      if ($Name.ToLowerInvariant() -cin @('transforms', 'patch', 'msinewinstance', 'adminproperties') -and -not $Result.BlockedProperty) {
        $Result.BlockedProperty = $Name
      }
    }
  } catch {
    $Result.IsValid = $false
    $Result.Error = $_.Exception.Message
  }
  return [pscustomobject]$Result
}

function Test-WinGetManifestVersionValue {
  <#
  .SYNOPSIS
    Validate a package or Apps and Features version value.
  .PARAMETER Value
    Version text.
  .PARAMETER Field
    Field containing the version.
  .PARAMETER ObjectPath
    Location of the field.
  #>
  param (
    [string]$Value,
    [string]$Field,
    [string]$ObjectPath
  )

  try {
    $Version = [Dumplings.Versioning.WinGetVersion]::new($Value)
    if ($Version.IsApproximate) {
      return New-WinGetManifestDiagnostic -Severity Error -Id ApproximateVersionNotAllowed -Message "Approximate version '${Value}' is not allowed." -Field $Field -Value $Value -ObjectPath $ObjectPath
    }
  } catch {
    return New-WinGetManifestDiagnostic -Severity Error -Id InvalidFieldValue -Message "The value '${Value}' is not a valid version." -Field $Field -Value $Value -ObjectPath $ObjectPath
  }
}

function Test-WinGetManifestLocalization {
  <#
  .SYNOPSIS
    Validate locale tags and agreement completeness.
  .PARAMETER Localization
    Merged or additional localization dictionary.
  .PARAMETER ObjectPath
    Location of the localization.
  #>
  param (
    [System.Collections.IDictionary]$Localization,
    [string]$ObjectPath
  )

  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  if ($Localization.Contains('PackageLocale') -and -not (Test-WinGetBcp47Tag -Value ([string]$Localization.PackageLocale))) {
    $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidBcp47Value -Message 'The locale value is not a well-formed BCP 47 language tag.' -Field PackageLocale -Value $Localization.PackageLocale -ObjectPath $ObjectPath))
  }
  $Agreements = @(if ($Localization.Contains('Agreements')) { $Localization['Agreements'] })
  foreach ($Agreement in $Agreements) {
    if ($null -eq $Agreement) { continue }
    if ([string]::IsNullOrWhiteSpace([string]$Agreement['AgreementLabel']) -and
      [string]::IsNullOrWhiteSpace([string]$Agreement['Agreement']) -and
      [string]::IsNullOrWhiteSpace([string]$Agreement['AgreementUrl'])) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidFieldValue -Message 'An agreement must contain a label, text, or URL.' -Field Agreements -ObjectPath $ObjectPath))
    }
  }
  return $Diagnostics.ToArray()
}

function Get-WinGetManifestDependencies {
  <#
  .SYNOPSIS
    Aggregate unique dependencies from runtime-effective installers.
  .PARAMETER Installers
    Runtime-effective installer entries.
  #>
  param ([object[]]$Installers)

  $Results = [System.Collections.Generic.List[object]]::new()
  $Seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Installer in $Installers) {
    if (-not $Installer.Contains('Dependencies') -or $Installer['Dependencies'] -isnot [System.Collections.IDictionary]) { continue }
    $Dependencies = $Installer['Dependencies']
    foreach ($Type in @('WindowsFeatures', 'WindowsLibraries', 'ExternalDependencies')) {
      foreach ($Identifier in @($Dependencies[$Type])) {
        if ([string]::IsNullOrWhiteSpace([string]$Identifier)) { continue }
        $Key = "${Type}|${Identifier}"
        if ($Seen.Add($Key)) {
          $Results.Add([pscustomobject]@{ Type = $Type; PackageIdentifier = $null; Id = [string]$Identifier; MinimumVersion = $null })
        }
      }
    }
    foreach ($Dependency in @($Dependencies['PackageDependencies'])) {
      if ($null -eq $Dependency) { continue }
      $Identifier = [string]$Dependency['PackageIdentifier']
      $MinimumVersion = [string]$Dependency['MinimumVersion']
      $Key = "Package|${Identifier}|${MinimumVersion}"
      if ($Seen.Add($Key)) {
        $Results.Add([pscustomobject]@{ Type = 'Package'; PackageIdentifier = $Identifier; Id = $Identifier; MinimumVersion = $MinimumVersion })
      }
    }
  }
  return $Results.ToArray()
}

function Test-WinGetManifestSemantics {
  <#
  .SYNOPSIS
    Apply WinGet semantic validation families to a merged manifest.
  .PARAMETER Manifest
    Flat merged manifest projection.
  .PARAMETER EffectiveInstallers
    Installer entries expanded with runtime defaults.
  #>
  param (
    [System.Collections.IDictionary]$Manifest,
    [object[]]$EffectiveInstallers
  )

  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  if ($Manifest.Contains('Channel') -and -not [string]::IsNullOrWhiteSpace([string]$Manifest.Channel)) {
    $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id FieldNotSupported -Message 'Channel is not supported.' -Field Channel -Value $Manifest.Channel -ObjectPath '$'))
  }
  $VersionDiagnostic = Test-WinGetManifestVersionValue -Value ([string]$Manifest.PackageVersion) -Field PackageVersion -ObjectPath '$'
  if ($VersionDiagnostic) { $Diagnostics.Add($VersionDiagnostic) }
  $Diagnostics.AddRange(@(Test-WinGetManifestLocalization -Localization $Manifest -ObjectPath '$'))

  $InstallerKeys = [System.Collections.Generic.List[object]]::new()
  $UrlToHash = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
  $HashToUrl = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  for ($InstallerIndex = 0; $InstallerIndex -lt $EffectiveInstallers.Count; $InstallerIndex++) {
    $Installer = $EffectiveInstallers[$InstallerIndex]
    $ObjectPath = "$.Installers[${InstallerIndex}]"
    $BaseType = ([string]$Installer['InstallerType']).ToLowerInvariant()
    $EffectiveType = [string]$Installer['_EffectiveInstallerType']
    $Scope = if ($Installer.Contains('Scope')) { [string]$Installer['Scope'] } else { '' }
    $InstallerKey = [pscustomobject]@{ Type = $EffectiveType; BaseType = $BaseType; Architecture = [string]$Installer['Architecture']; Locale = [string]$Installer['InstallerLocale']; Scope = $Scope }
    foreach ($Existing in $InstallerKeys) {
      $SameType = $Existing.Type -ceq $InstallerKey.Type -and $Existing.BaseType -ceq $InstallerKey.BaseType
      $SameIdentity = $SameType -and $Existing.Architecture -ceq $InstallerKey.Architecture -and $Existing.Locale -ceq $InstallerKey.Locale
      $SameScope = $Existing.Scope -ceq $InstallerKey.Scope -or [string]::IsNullOrEmpty($Existing.Scope) -or [string]::IsNullOrEmpty($InstallerKey.Scope)
      if ($SameIdentity -and $SameScope) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id DuplicateInstallerEntry -Message 'Duplicate installer entry found.' -ObjectPath $ObjectPath))
        break
      }
    }
    $InstallerKeys.Add($InstallerKey)

    if ([string]::IsNullOrWhiteSpace([string]$Installer['Architecture'])) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidFieldValue -Message 'Architecture is invalid.' -Field Architecture -ObjectPath $ObjectPath))
    }
    if ([string]::IsNullOrWhiteSpace($EffectiveType)) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidFieldValue -Message 'InstallerType is invalid.' -Field InstallerType -ObjectPath $ObjectPath))
    }
    if ($Installer.Contains('UpgradeBehavior') -and [string]::IsNullOrWhiteSpace([string]$Installer.UpgradeBehavior)) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidFieldValue -Message 'UpgradeBehavior is invalid.' -Field UpgradeBehavior -ObjectPath $ObjectPath))
    }

    $AppsAndFeaturesEntries = @(if ($Installer.Contains('AppsAndFeaturesEntries')) { $Installer['AppsAndFeaturesEntries'] })
    $AppsAndFeaturesUseMsix = $AppsAndFeaturesEntries.Where({ ([string]$_['InstallerType']).ToLowerInvariant() -cin @('appx', 'msix') }, 'First')
    if ($Installer.Contains('PackageFamilyName') -and $EffectiveType -cnotin $Script:WinGetPackageFamilyNameTypes -and -not $AppsAndFeaturesUseMsix) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id InstallerTypeDoesNotSupportPackageFamilyName -Message 'The installer type does not normally support PackageFamilyName.' -Field InstallerType -Value $EffectiveType -ObjectPath $ObjectPath))
    }
    if ($Installer.Contains('ProductCode') -and $EffectiveType -cnotin $Script:WinGetProductCodeTypes) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InstallerTypeDoesNotSupportProductCode -Message 'The installer type does not support ProductCode.' -Field InstallerType -Value $EffectiveType -ObjectPath $ObjectPath))
    }
    if ($AppsAndFeaturesEntries.Count -gt 0 -and $EffectiveType -cnotin $Script:WinGetProductCodeTypes) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InstallerTypeDoesNotWriteAppsAndFeaturesEntry -Message 'The installer type does not write an Apps and Features entry.' -Field InstallerType -Value $EffectiveType -ObjectPath $ObjectPath))
    }

    if ($EffectiveType -ceq 'msstore') {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id FieldValueNotSupported -Message 'MSStore installers are unsupported in the community repository.' -Field InstallerType -Value $EffectiveType -ObjectPath $ObjectPath))
      if ([string]::IsNullOrWhiteSpace([string]$Installer['ProductId'])) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message 'ProductId is required.' -Field ProductId -ObjectPath $ObjectPath))
      }
    } else {
      $InstallerUrl = [string]$Installer['InstallerUrl']
      $InstallerSha256 = [string]$Installer['InstallerSha256']
      if ([string]::IsNullOrWhiteSpace($InstallerUrl)) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message 'InstallerUrl is required.' -Field InstallerUrl -ObjectPath $ObjectPath))
      }
      if ([string]::IsNullOrWhiteSpace($InstallerSha256)) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message 'InstallerSha256 is required.' -Field InstallerSha256 -ObjectPath $ObjectPath))
      }
      if ($Installer.Contains('ProductId') -and -not [string]::IsNullOrWhiteSpace([string]$Installer['ProductId'])) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id FieldNotSupported -Message 'ProductId is not supported for this installer type.' -Field ProductId -ObjectPath $ObjectPath))
      }
      if (-not [string]::IsNullOrWhiteSpace($InstallerUrl) -and -not [string]::IsNullOrWhiteSpace($InstallerSha256)) {
        if ($UrlToHash.ContainsKey($InstallerUrl) -and $UrlToHash[$InstallerUrl] -cne $InstallerSha256) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InconsistentInstallerHash -Message 'The same InstallerUrl maps to different hashes.' -Field InstallerUrl -Value $InstallerUrl -ObjectPath $ObjectPath))
        } else { $UrlToHash[$InstallerUrl] = $InstallerSha256 }
        if ($HashToUrl.ContainsKey($InstallerSha256) -and $HashToUrl[$InstallerSha256] -cne $InstallerUrl) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id DuplicateInstallerHash -Message 'Multiple installer URLs use the same InstallerSha256.' -Field InstallerSha256 -Value $InstallerSha256 -ObjectPath $ObjectPath))
        } else { $HashToUrl[$InstallerSha256] = $InstallerUrl }
      }
    }

    if ($EffectiveType -ceq 'exe' -and
      (-not $Installer.Contains('InstallerSwitches') -or -not $Installer['InstallerSwitches'].Contains('Silent') -or -not $Installer['InstallerSwitches'].Contains('SilentWithProgress'))) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id ExeInstallerMissingSilentSwitches -Message 'Silent and SilentWithProgress switches are not specified for InstallerType exe.' -Field InstallerSwitches -ObjectPath $ObjectPath))
    }
    if ($BaseType -ceq 'portable' -and @($Installer['Commands']).Count -gt 1) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id ExceededCommandsLimit -Message 'Only zero or one Commands value is allowed for portable installers.' -Field Commands -ObjectPath $ObjectPath))
    }
    if ($EffectiveType -ceq 'portable') {
      if ($AppsAndFeaturesEntries.Count -gt 1) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id ExceededAppsAndFeaturesEntryLimit -Message 'Only zero or one AppsAndFeaturesEntries item is allowed for portable installers.' -Field AppsAndFeaturesEntries -ObjectPath $ObjectPath))
      }
      if (-not [string]::IsNullOrEmpty($Scope)) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id ScopeNotSupported -Message 'Scope is not supported for portable installers.' -Field Scope -Value $Scope -ObjectPath $ObjectPath))
      }
    }

    if ($BaseType -cin $Script:WinGetArchiveTypes) {
      $NestedType = ([string]$Installer['NestedInstallerType']).ToLowerInvariant()
      $NestedFiles = @(if ($Installer.Contains('NestedInstallerFiles')) { $Installer['NestedInstallerFiles'] })
      $IsPortable = $NestedType -ceq 'portable'
      $IsFont = $NestedType -ceq 'font'
      if ([string]::IsNullOrWhiteSpace($NestedType)) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message 'NestedInstallerType is required for archive installers.' -Field NestedInstallerType -ObjectPath $ObjectPath))
      }
      if ($NestedFiles.Count -eq 0) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message 'NestedInstallerFiles is required for archive installers.' -Field NestedInstallerFiles -ObjectPath $ObjectPath))
      }
      if (-not $IsPortable -and -not $IsFont -and $NestedFiles.Count -ne 1) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id ExceededNestedInstallerFilesLimit -Message 'Only one nested file is allowed for non-portable and non-font archives.' -Field NestedInstallerFiles -ObjectPath $ObjectPath))
      }
      $Paths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $Aliases = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      for ($NestedIndex = 0; $NestedIndex -lt $NestedFiles.Count; $NestedIndex++) {
        $NestedFile = $NestedFiles[$NestedIndex]
        $NestedPath = "${ObjectPath}.NestedInstallerFiles[${NestedIndex}]"
        $RelativePath = [string]$NestedFile['RelativeFilePath']
        if ([string]::IsNullOrWhiteSpace($RelativePath)) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RequiredFieldMissing -Message 'RelativeFilePath is required.' -Field RelativeFilePath -ObjectPath $NestedPath))
          continue
        }
        if (Test-WinGetPathEscapesBaseDirectory -Path $RelativePath) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id RelativeFilePathEscapesDirectory -Message 'Relative file path escapes the archive directory.' -Field RelativeFilePath -Value $RelativePath -ObjectPath $NestedPath))
        }
        if (-not $Paths.Add($RelativePath)) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id DuplicateRelativeFilePath -Message 'Duplicate relative file path found.' -Field RelativeFilePath -Value $RelativePath -ObjectPath $NestedPath))
        }
        $Alias = [string]$NestedFile['PortableCommandAlias']
        if (-not [string]::IsNullOrWhiteSpace($Alias)) {
          if (Test-WinGetPathEscapesBaseDirectory -Path $Alias) {
            $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id PortableCommandAliasEscapesDirectory -Message 'Portable command alias escapes the base directory.' -Field PortableCommandAlias -Value $Alias -ObjectPath $NestedPath))
          }
          if (-not $Aliases.Add($Alias)) {
            $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id DuplicatePortableCommandAlias -Message 'Duplicate portable command alias found.' -Field PortableCommandAlias -Value $Alias -ObjectPath $NestedPath))
          }
        }
        $Extension = [IO.Path]::GetExtension($RelativePath).ToLowerInvariant()
        if ($IsPortable -and $Extension -and $Extension -cnotin $Script:WinGetPortableFileTypes) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidPortableFiletype -Message 'The referenced portable file type is not allowed.' -Field RelativeFilePath -Value $RelativePath -ObjectPath $NestedPath))
        }
        if ($IsFont -and $Extension -and $Extension -cnotin $Script:WinGetFontFileTypes) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidFontFiletype -Message 'The referenced font file type is not allowed.' -Field RelativeFilePath -Value $RelativePath -ObjectPath $NestedPath))
        }
      }
    }

    $InstallerUri = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$Installer['InstallerUrl']) -and
      (-not [uri]::TryCreate([string]$Installer['InstallerUrl'], [UriKind]::Absolute, [ref]$InstallerUri) -or $InstallerUri.Scheme -notin @('http', 'https'))) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidFieldValue -Message 'InstallerUrl is invalid.' -Field InstallerUrl -Value $Installer['InstallerUrl'] -ObjectPath $ObjectPath))
    }
    if ($Installer.Contains('InstallerLocale') -and -not [string]::IsNullOrWhiteSpace([string]$Installer['InstallerLocale']) -and -not (Test-WinGetBcp47Tag -Value ([string]$Installer['InstallerLocale']))) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidBcp47Value -Message 'InstallerLocale is not a well-formed BCP 47 language tag.' -Field InstallerLocale -Value $Installer['InstallerLocale'] -ObjectPath $ObjectPath))
    }
    if ($Installer.Contains('Markets') -and @($Installer['Markets']['AllowedMarkets']).Count -gt 0 -and @($Installer['Markets']['ExcludedMarkets']).Count -gt 0) {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id BothAllowedAndExcludedMarketsDefined -Message 'AllowedMarkets and ExcludedMarkets cannot both be defined.' -Field Markets -ObjectPath $ObjectPath))
    }

    $ReturnCodes = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($ReturnCode in @($Installer['InstallerSuccessCodes'])) { $null = $ReturnCodes.Add([long]$ReturnCode) }
    foreach ($ExpectedReturnCode in @($Installer['ExpectedReturnCodes'])) {
      if ($null -ne $ExpectedReturnCode -and -not $ReturnCodes.Add([long]$ExpectedReturnCode['InstallerReturnCode'])) {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id DuplicateReturnCodeEntry -Message 'Duplicate installer return code found.' -Field ExpectedReturnCodes -Value $ExpectedReturnCode['InstallerReturnCode'] -ObjectPath $ObjectPath))
        break
      }
    }
    foreach ($Entry in $AppsAndFeaturesEntries) {
      if ($null -eq $Entry -or [string]::IsNullOrWhiteSpace([string]$Entry['DisplayVersion'])) { continue }
      $DisplayVersionDiagnostic = Test-WinGetManifestVersionValue -Value ([string]$Entry['DisplayVersion']) -Field DisplayVersion -ObjectPath "${ObjectPath}.AppsAndFeaturesEntries"
      if ($DisplayVersionDiagnostic) { $Diagnostics.Add($DisplayVersionDiagnostic) }
    }
    if ($Installer.Contains('Authentication') -and $Installer['Authentication'] -is [System.Collections.IDictionary] -and
      ([string]$Installer['Authentication']['AuthenticationType']).ToLowerInvariant() -cne 'none') {
      $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id FieldNotSupported -Message 'Authentication is unsupported in the community repository.' -Field Authentication -ObjectPath $ObjectPath))
    }
    $WindowsFeatures = @(if ($Installer.Contains('Dependencies')) { $Installer['Dependencies']['WindowsFeatures'] })
    foreach ($WindowsFeature in $WindowsFeatures) {
      if ($null -eq $WindowsFeature) { continue }
      if ([string]::IsNullOrWhiteSpace([string]$WindowsFeature) -or [string]$WindowsFeature -notmatch '^[A-Za-z0-9_-]+$') {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidWindowsFeatureName -Message 'The provided value is not a valid Windows feature name.' -Field WindowsFeatures -Value $WindowsFeature -ObjectPath $ObjectPath))
      }
    }
    foreach ($Container in @($Installer['DesiredStateConfiguration'])) {
      if ($null -eq $Container) { continue }
      if (([string]$Container['Type']).ToLowerInvariant() -ceq 'powershell') {
        $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id FieldNotSupported -Message 'PowerShell desired-state configuration is unsupported in the community repository.' -Field DesiredStateConfiguration.PowerShell -ObjectPath $ObjectPath))
        break
      }
    }

    if ($Installer.Contains('InstallerSwitches')) {
      foreach ($SwitchName in $Installer['InstallerSwitches'].Keys) {
        $SwitchValue = [string]$Installer['InstallerSwitches'][$SwitchName]
        if ([string]::IsNullOrWhiteSpace($SwitchValue)) { continue }
        if ($EffectiveType -cin @('msi', 'wix')) {
          $MsiResult = Test-WinGetMsiArguments -Arguments $SwitchValue
          if (-not $MsiResult.IsValid) {
            $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id InvalidMsiSwitches -Message 'Installer switch contains invalid MSI arguments.' -Field "InstallerSwitches.${SwitchName}" -Value $SwitchValue -ObjectPath $ObjectPath))
          } elseif ($MsiResult.BlockedProperty) {
            $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id BlockedMsiProperty -Message "Installer switch contains blocked MSI property '$($MsiResult.BlockedProperty)'." -Field "InstallerSwitches.${SwitchName}" -Value $MsiResult.BlockedProperty -ObjectPath $ObjectPath))
          }
        }
        if ($SwitchValue.Contains('\\')) {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Error -Id ContainsNetworkAddress -Message 'Installer switch contains a network share address.' -Field "InstallerSwitches.${SwitchName}" -Value $SwitchValue -ObjectPath $ObjectPath))
        } elseif ($SwitchValue -match '(?i)(?:https?|ftp)://') {
          $Diagnostics.Add((New-WinGetManifestDiagnostic -Severity Warning -Id ContainsNetworkAddress -Message 'Installer switch contains a network address.' -Field "InstallerSwitches.${SwitchName}" -Value $SwitchValue -ObjectPath $ObjectPath))
        }
      }
    }
  }

  [object[]]$Localizations = @()
  if ($Manifest.Contains('Localization') -and $null -ne $Manifest['Localization']) {
    $Localizations = @($Manifest['Localization'])
  }
  for ($LocalizationIndex = 0; $LocalizationIndex -lt $Localizations.Count; $LocalizationIndex++) {
    $Diagnostics.AddRange(@(Test-WinGetManifestLocalization -Localization $Localizations[$LocalizationIndex] -ObjectPath "$.Localization[${LocalizationIndex}]"))
  }
  return $Diagnostics.ToArray()
}

function Get-WinGetManifestValidationResult {
  <#
  .SYNOPSIS
    Validate a WinGet manifest file or multi-file manifest directory.
  .DESCRIPTION
    Performs the local validation path used by winget validate without starting
    winget.exe, downloading installers, or querying the WinGet source index.
  .PARAMETER Path
    Singleton manifest file or leaf multi-file manifest directory to validate.
  .PARAMETER Manifest
    Logical manifest model to validate after projecting it to physical documents.
  .OUTPUTS
    Dumplings.WinGet.ManifestValidationResult containing the logical model,
    merged projection, runtime-expanded installers, dependencies, and diagnostics.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter(Mandatory, ParameterSetName = 'Manifest')]
    $Manifest
  )

  try {
    if ($PSCmdlet.ParameterSetName -ceq 'Path') {
      # Physical parsing retains source paths, schema headers, and YAML parser
      # locations so diagnostics can identify the authored document.
      $Documents = @(Get-WinGetManifestValidationDocuments -Path $Path)
    } else {
      # Model validation serializes to canonical multi-file YAML first. This
      # exercises the same parsing and schema path without persisting files.
      $YamlBundle = ConvertTo-WinGetManifestYaml -Manifest $Manifest
      $Documents = [System.Collections.Generic.List[object]]::new()
      $Documents.Add((ConvertFrom-WinGetManifestDocumentContent -Content $YamlBundle.Version -FileName 'version.yaml'))
      $Documents.Add((ConvertFrom-WinGetManifestDocumentContent -Content $YamlBundle.Installer -FileName 'installer.yaml'))
      foreach ($Entry in $YamlBundle.Locale.GetEnumerator()) {
        $Documents.Add((ConvertFrom-WinGetManifestDocumentContent -Content $Entry.Value -FileName "$($Entry.Key).yaml"))
      }
      $Documents = $Documents.ToArray()
    }
  } catch {
    $Diagnostic = New-WinGetManifestDiagnostic -Severity Error -Id InvalidManifestPath -Message $_.Exception.Message -File ($PSCmdlet.ParameterSetName -ceq 'Path' ? $Path : $null)
    return [pscustomobject]@{
      PSTypeName = 'Dumplings.WinGet.ManifestValidationResult'; IsValid = $false; HasErrors = $true; HasWarnings = $false
      PackageIdentifier = $null; PackageVersion = $null; ManifestVersion = $null; Files = @(); Dependencies = @()
      Manifest = $null; MergedManifest = $null; EffectiveInstallers = @(); Diagnostics = @($Diagnostic); Errors = @($Diagnostic); Warnings = @()
    }
  }

  # Structural validation establishes package identity and ensures that a
  # complete singleton or multi-file set exists before model population.
  $InputResult = Test-WinGetManifestInputSet -Documents $Documents
  $Diagnostics = [System.Collections.Generic.List[object]]::new()
  $Diagnostics.AddRange(@($InputResult.Diagnostics))
  $LogicalManifest = $null
  $MergedManifest = $null
  $EffectiveInstallers = @()
  $Dependencies = @()

  if (-not $Diagnostics.Where({ $_.Severity -ceq 'Error' }, 'First')) {
    # Validate physical fields before inheritance can hide an invalid root or
    # installer-level representation.
    $Diagnostics.AddRange(@(Test-WinGetManifestSchemas -Documents $Documents -ManifestVersion $InputResult.ManifestVersion))
    if (-not $Diagnostics.Where({ $_.Severity -ceq 'Error' }, 'First')) {
      if ((Resolve-WinGetManifestSchemaVersion $InputResult.ManifestVersion) -ceq '0.1.0') {
        # Historical preview manifests have no v1 document model. Preserve the
        # legacy conversion solely for semantic validation.
        $MergedManifest = Merge-WinGetManifestValidationSet -Documents $Documents
        $SemanticManifest = ConvertFrom-WinGetPreviewManifest -Manifest $MergedManifest
      } else {
        $LogicalManifest = if ($PSCmdlet.ParameterSetName -ceq 'Manifest') {
          New-WinGetManifestModel -PackageIdentifier $Manifest.PackageIdentifier -PackageVersion $Manifest.PackageVersion -Channel $Manifest.Channel -Moniker $Manifest.Moniker -ManifestVersion $Manifest.ManifestVersion -InstallerDefaults $Manifest.InstallerDefaults -Installers ([System.Collections.IDictionary[]]@($Manifest.Installers)) -DefaultLocalization $Manifest.DefaultLocalization -Localizations ([System.Collections.IDictionary[]]@($Manifest.Localizations)) -SourceFormat Memory
        } else {
          ConvertTo-WinGetManifestModelFromDocumentSet -DocumentSet ([pscustomobject]@{ Documents = $Documents; SourcePath = $Path })
        }
        $MergedManifest = ConvertTo-WinGetMergedManifest -Manifest $LogicalManifest
        $SemanticManifest = $MergedManifest
      }

      # Runtime defaults such as known switches and return codes are derived
      # for semantic validation only and never written back to the model.
      $EffectiveInstallers = @(Get-WinGetEffectiveInstallers -Manifest $SemanticManifest)
      $Diagnostics.AddRange(@(Test-WinGetManifestSemantics -Manifest $SemanticManifest -EffectiveInstallers $EffectiveInstallers))

      # Dependency aggregation is reporting evidence; it does not mutate the
      # authored Dependencies dictionaries.
      $Dependencies = @(Get-WinGetManifestDependencies -Installers $EffectiveInstallers)

      # Schema headers are warnings from manifest version 1.7 onward, matching
      # winget validate's strict-warning exit option.
      $Diagnostics.AddRange(@(Test-WinGetManifestSchemaHeaders -Documents $Documents -ManifestVersion $InputResult.ManifestVersion))
    }
  }

  $DiagnosticArray = $Diagnostics.ToArray()
  $Errors = @($DiagnosticArray | Where-Object Severity -CEQ Error)
  $Warnings = @($DiagnosticArray | Where-Object Severity -CEQ Warning)
  return [pscustomobject]@{
    PSTypeName          = 'Dumplings.WinGet.ManifestValidationResult'
    IsValid             = $Errors.Count -eq 0
    HasErrors           = $Errors.Count -gt 0
    HasWarnings         = $Warnings.Count -gt 0
    PackageIdentifier   = $InputResult.PackageIdentifier
    PackageVersion      = $InputResult.PackageVersion
    ManifestVersion     = $InputResult.ManifestVersion
    Files               = @($Documents | ForEach-Object { [pscustomobject]@{ Path = $_.Path; FileName = $_.FileName; ManifestType = if ($_.PSObject.Properties['ManifestType']) { $_.ManifestType } else { 'unknown' }; SchemaHeader = $_.SchemaHeader } })
    Dependencies        = $Dependencies
    Manifest            = $LogicalManifest
    MergedManifest      = $MergedManifest
    EffectiveInstallers = $EffectiveInstallers
    Diagnostics         = $DiagnosticArray
    Errors              = $Errors
    Warnings            = $Warnings
  }
}

function Test-WinGetManifest {
  <#
  .SYNOPSIS
    Test a WinGet manifest using the process-safe PowerShell validator.
  .PARAMETER Path
    Singleton manifest file or leaf multi-file manifest directory.
  .PARAMETER ErrorOnWarning
    Treat warning diagnostics as validation failures, matching winget validate.
  .PARAMETER PassThru
    Return the structured validation result. Successful validation otherwise
    emits no pipeline output.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [switch]$ErrorOnWarning,

    [switch]$PassThru
  )

  $Result = Get-WinGetManifestValidationResult -Path $Path
  foreach ($WarningDiagnostic in $Result.Warnings) {
    Write-Warning "[$($WarningDiagnostic.Id)] $($WarningDiagnostic.Message)"
  }
  if (($Result.HasErrors) -or ($ErrorOnWarning -and $Result.HasWarnings)) {
    $FailureDiagnostics = if ($Result.HasErrors) { $Result.Errors } else { $Result.Warnings }
    $Message = $FailureDiagnostics | ForEach-Object { "[$($_.Id)] $($_.Message)" }
    throw "Failed to pass manifest validation:`n$($Message -join "`n")"
  }
  if ($PassThru) { return $Result }
}

Export-ModuleMember -Function Get-WinGetManifestValidationResult, Test-WinGetManifest
