# SPDX-License-Identifier: Apache-2.0
# Static Actual Installer parser. The PE contains one or more independent ZIP
# ranges; the archive containing aisetup.ini is the setup-metadata container.
# Binary structure consumed here:
#
#   PE launcher
#   +-- ZIP payload range -> local records + central directory + matching EOCD
#   `-- ZIP metadata range -> aisetup.ini, *ai.lng, helper files
#
# Embedded ZIP offsets are absolute; ZIP-local offsets are relative to the
# selected range. Each EOCD, entry count, size, and extraction path is validated.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:ActualInstallerMaximumArchiveBytes = 2147483648
$Script:ActualInstallerMaximumEntryBytes = 16777216

function Get-ActualInstallerArchiveData {
  <#
  .SYNOPSIS
    Locate the Actual Installer ZIP that contains aisetup.ini
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)
  $File = Get-Item -LiteralPath $Path -Force

  # A launcher may contain several independent ZIP ranges. Only the range whose
  # validated central directory exposes aisetup.ini is the project metadata archive.
  foreach ($Range in @(Get-EmbeddedZipArchiveRange -Path $Path)) {
    # Ignore unrelated or implausibly large embedded ZIPs before opening a decoder.
    if ($Range.Length -gt $Script:ActualInstallerMaximumArchiveBytes) { continue }
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $File.FullName -Range $Range
      $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive | ForEach-Object {
          [pscustomobject]@{ FullName = $_.FullName; Length = $_.Length }
        })
      $IniEntry = $Entries | Where-Object { $_.FullName -ieq 'aisetup.ini' } | Select-Object -First 1
      if (-not $IniEntry) { continue }
      return [pscustomobject]@{ SourcePath = $File.FullName; Range = $Range; Entries = $Entries; IniEntryName = $IniEntry.FullName; IniEntryLength = $IniEntry.Length }
    } catch {
      # A malformed candidate is not conclusive because another embedded ZIP may
      # still be the Actual Installer metadata container.
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }
  throw 'The file does not contain an Actual Installer aisetup.ini archive'
}

function ConvertFrom-ActualInstallerIni {
  <#
  .SYNOPSIS
    Parse an Actual Installer project INI without interpreting its commands
  .PARAMETER Content
    Raw configuration or metadata text to parse without executing commands.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][string]$Content)
  $Result = @{}; $Section = $null

  # Preserve section/key text verbatim; this parser deliberately does not expand
  # installer variables or interpret command values from the project file.
  foreach ($Line in ($Content -split "`r?`n")) {
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith(';')) { continue }
    if ($Trimmed -match '^\[(.+)\]$') { $Section = $Matches[1]; if (-not $Result.ContainsKey($Section)) { $Result[$Section] = @{} }; continue }
    if ($Section -and $Trimmed -match '^([^=]+)=(.*)$') { $Result[$Section][$Matches[1].Trim()] = $Matches[2].Trim() }
  }
  return $Result
}

function Get-ActualInstallerInfo {
  <#
  .SYNOPSIS
    Read static metadata from an Actual Installer embedded aisetup.ini file
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $ArchiveData = Get-ActualInstallerArchiveData -Path $Path
    $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
    try {
      # Reopen the selected bounded range and decode only the small project INI.
      $Archive = $Context.Archive
      $IniEntry = Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -ieq $ArchiveData.IniEntryName } | Select-Object -First 1
      if (-not $IniEntry -or $IniEntry.Length -gt $Script:ActualInstallerMaximumEntryBytes) { throw 'The Actual Installer project INI exceeds the configured size limit' }
      $Stream = Open-InstallerArchiveEntry -Entry $IniEntry
      $Reader = [IO.StreamReader]::new($Stream, [Text.Encoding]::UTF8, $true)
      try { $Ini = ConvertFrom-ActualInstallerIni -Content $Reader.ReadToEnd() } finally { $Reader.Dispose(); $Stream.Dispose() }
      $Setup = $Ini['Setup']; $Registry = $Ini['Registry']

      # Actual Installer's Registry section is project data, not proof of the
      # final ARP key. It is retained as explicit static association evidence.
      $RegistryWrites = if ($Registry) { foreach ($Key in @($Registry.Keys)) { [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\\Softeza\\Actual Installer'; Name = $Key; Value = $Registry[$Key]; Type = 'REG_SZ' } } } else { @() }
      $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
      $ProductCode = $Setup['GUID']
      $DisplayVersion = $Setup['AppVersion']
      $Warnings = [System.Collections.Generic.List[string]]::new()

      # Builder placeholders must not escape as version evidence when a project
      # was packaged without substituting AppVersion.
      if ($DisplayVersion -match '^<[^>]+>$') {
        $Warnings.Add("The Actual Installer AppVersion '$DisplayVersion' is a build-time placeholder and is not usable as manifest version evidence.")
        $DisplayVersion = $null
      }
      $Warnings.Add('Actual Installer GUID is project identity evidence, not proof of the visible ARP key. /CU and /RUNAS /ALL select user or machine installation; validate the selected scope and ARP entry in a VM.')
      $WritesAppsAndFeaturesEntry = $Setup['ShowAddRemove'] -eq '1'

      [pscustomobject][ordered]@{
        Path                           = $File.FullName
        InstallerType                  = 'Actual Installer'
        ProductCode                    = $ProductCode
        UpgradeCode                    = $null
        DisplayName                    = $Setup['AppName']
        DisplayVersion                 = $DisplayVersion
        Publisher                      = $Setup['CompanyName']
        Scope                          = $null
        DefaultInstallLocation         = $Setup['InstallDir']
        WritesAppsAndFeaturesEntry     = $WritesAppsAndFeaturesEntry
        AppsAndFeaturesProductCode     = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
        AppsAndFeaturesInstallerType   = $WritesAppsAndFeaturesEntry ? 'exe' : $null
        Warnings                       = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
        UnresolvedFields               = [string[]]@()
        PublisherUrl                   = $Setup['WebSite']
        AlternateInstallationDirectory = $Setup['AltInstallDir']
        MainExecutable                 = $Setup['MainExe']
        Uninstaller                    = $Setup['UninstallFile']
        ShowsAppsAndFeaturesEntry      = $Setup['ShowAddRemove'] -eq '1'
        SupportedScopes                = @('user', 'machine')
        RegistryWrites                 = @($RegistryWrites)
        RegistryAssociationInfo        = $RegistryAssociationInfo
        Protocols                      = $RegistryAssociationInfo.Protocols
        FileExtensions                 = $RegistryAssociationInfo.FileExtensions
        EmbeddedFiles                  = @($ArchiveData.Entries.FullName)
        ArchiveRange                   = $ArchiveData.Range
        ParserVersionInfo              = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.ActualInstaller'; ParserMajor = 1; Sources = @('Validated embedded ZIP archive', 'aisetup.ini') }
      }
    } finally { Close-InstallerArchiveRange -Context $Context }
  }
}

function Expand-ActualInstallerInstaller {
  <#
  .SYNOPSIS
    Extract files from the Actual Installer project ZIP without executing them
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Extraction root. Relative payload paths are resolved beneath this directory and cannot escape it.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum cumulative extracted output, in bytes; exceeding it rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    $ArchiveData = Get-ActualInstallerArchiveData -Path $Path
    $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-ActualInstaller-$([guid]::NewGuid().ToString('N'))") }
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Archive = $Context.Archive
      $Written = 0L; $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

      # Filter against catalog names before extraction, account declared output
      # cumulatively, and resolve every result beneath the destination root.
      foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
        if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
        $Written += $Entry.Length
        if ($Written -gt $MaximumExpandedBytes) { throw 'Actual Installer extraction exceeds the configured output limit' }
        $Result.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath (Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName) -MaximumBytes $MaximumExpandedBytes))
      }
      if ($Result.Count -eq 0) { throw "No Actual Installer files matched '$Name'" }
      return $Result.ToArray()
    } finally { Close-InstallerArchiveRange -Context $Context }
  }
}

function Test-ActualInstaller {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable Actual Installer project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])] param([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-ActualInstallerInfo -Path $Path; $true } catch { $false } }
}
function Read-ProtocolsFromActualInstaller {
  <#
  .SYNOPSIS
    Read literal URL protocol names from Actual Installer registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromActualInstaller {
  <#
  .SYNOPSIS
    Read literal file extensions from Actual Installer registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromActualInstaller {
  <#
  .SYNOPSIS
    Read the resolved Actual Installer project version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromActualInstaller {
  <#
  .SYNOPSIS
    Read the Actual Installer project name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).DisplayName }
}
function Read-PublisherFromActualInstaller {
  <#
  .SYNOPSIS
    Read the Actual Installer project publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromActualInstaller {
  <#
  .SYNOPSIS
    Read the Actual Installer project GUID
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).ProductCode }
}

Export-ModuleMember -Function Get-ActualInstallerInfo, Expand-ActualInstallerInstaller, Test-ActualInstaller, Read-ProtocolsFromActualInstaller, Read-FileExtensionsFromActualInstaller, Read-ProductVersionFromActualInstaller, Read-ProductNameFromActualInstaller, Read-PublisherFromActualInstaller, Read-ProductCodeFromActualInstaller
