# SPDX-License-Identifier: MIT
# This module only bridges to the independently licensed InstallerParsers CLI.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:ActualInstallerMaximumArchiveBytes = 2147483648
$Script:ActualInstallerMaximumEntryBytes = 16777216

function Get-ActualInstallerArchiveData {
  <#
  .SYNOPSIS
    Locate the Actual Installer ZIP that contains aisetup.ini
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)
  foreach ($Range in @(Get-EmbeddedZipArchiveRange -Path $Path)) {
    if ($Range.Length -gt $Script:ActualInstallerMaximumArchiveBytes) { continue }
    $TemporaryPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-ActualInstaller-$([guid]::NewGuid().ToString('N')).zip")
    $Archive = $null
    try {
      $Source = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      $Destination = [IO.File]::Open($TemporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { Copy-BinaryStreamRange -Source $Source -Destination $Destination -Offset $Range.Offset -Length $Range.Length } finally { $Destination.Dispose(); $Source.Dispose() }
      $Archive = Get-InstallerArchive -Path $TemporaryPath
      $Entries = @(Get-InstallerArchiveEntry -Archive $Archive)
      $IniEntry = $Entries | Where-Object { $_.FullName -ieq 'aisetup.ini' } | Select-Object -First 1
      if (-not $IniEntry) { continue }
      return [pscustomobject]@{ Range = $Range; ArchivePath = $TemporaryPath; Entries = $Entries; IniEntryName = $IniEntry.FullName; IniEntryLength = $IniEntry.Length }
    } catch {
      Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
    } finally {
      if ($Archive) { $Archive.Dispose() }
    }
  }
  throw 'The file does not contain an Actual Installer aisetup.ini archive'
}

function ConvertFrom-ActualInstallerIni {
  <#
  .SYNOPSIS
    Parse an Actual Installer project INI without interpreting its commands
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][string]$Content)
  $Result = @{}; $Section = $null
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
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $ArchiveData = Get-ActualInstallerArchiveData -Path $Path
    try {
      $Archive = Get-InstallerArchive -Path $ArchiveData.ArchivePath
      try {
        $IniEntry = Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -ieq $ArchiveData.IniEntryName } | Select-Object -First 1
        if (-not $IniEntry -or $IniEntry.Length -gt $Script:ActualInstallerMaximumEntryBytes) { throw 'The Actual Installer project INI exceeds the configured size limit' }
        $Stream = Open-InstallerArchiveEntry -Entry $IniEntry
        $Reader = [IO.StreamReader]::new($Stream, [Text.Encoding]::UTF8, $true)
        try { $Ini = ConvertFrom-ActualInstallerIni -Content $Reader.ReadToEnd() } finally { $Reader.Dispose(); $Stream.Dispose() }
      } finally { $Archive.Dispose() }
      $Setup = $Ini['Setup']; $Registry = $Ini['Registry']
      $RegistryWrites = if ($Registry) { foreach ($Key in @($Registry.Keys)) { [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\\Softeza\\Actual Installer'; Name = $Key; Value = $Registry[$Key]; Type = 'REG_SZ' } } } else { @() }
      $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
      $ProductCode = $Setup['GUID']
      $DisplayVersion = $Setup['AppVersion']
      $Warnings = [System.Collections.Generic.List[string]]::new()
      if ($DisplayVersion -match '^<[^>]+>$') {
        $Warnings.Add("The Actual Installer AppVersion '$DisplayVersion' is a build-time placeholder and is not usable as manifest version evidence.")
        $DisplayVersion = $null
      }
      $Warnings.Add('Actual Installer GUID is project identity evidence, not proof of the visible ARP key. /CU and /RUNAS /ALL select user or machine installation; validate the selected scope and ARP entry in a VM.')
      [pscustomobject]@{
        InstallerType                = 'Actual Installer'
        ProductCode                  = $ProductCode
        PackageName                  = $Setup['AppName']
        DisplayName                  = $Setup['AppName']
        ProductName                  = $Setup['AppName']
        DisplayVersion               = $DisplayVersion
        Publisher                    = $Setup['CompanyName']
        PublisherUrl                 = $Setup['WebSite']
        DefaultInstallationDirectory = $Setup['InstallDir']
        AlternateInstallationDirectory = $Setup['AltInstallDir']
        MainExecutable               = $Setup['MainExe']
        Uninstaller                  = $Setup['UninstallFile']
        ShowsAppsAndFeaturesEntry    = $Setup['ShowAddRemove'] -eq '1'
        Scope                        = $null
        SupportedScopes              = @('user', 'machine')
        RegistryWrites               = @($RegistryWrites)
        RegistryAssociationInfo      = $RegistryAssociationInfo
        Protocols                    = $RegistryAssociationInfo.Protocols
        FileExtensions               = $RegistryAssociationInfo.FileExtensions
        EmbeddedFiles                = @($ArchiveData.Entries.FullName)
        ArchiveRange                 = $ArchiveData.Range
        WritesAppsAndFeaturesEntry   = if ($Setup['ShowAddRemove'] -eq '1') { $true } else { $false }
        Warnings                     = @($Warnings)
        ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.ActualInstaller'; ParserMajor = 1; Sources = @('Validated embedded ZIP archive', 'aisetup.ini') }
      }
    } finally { Remove-Item -LiteralPath $ArchiveData.ArchivePath -Force -ErrorAction SilentlyContinue }
  }
}

function Expand-ActualInstallerInstaller {
  <#
  .SYNOPSIS
    Extract files from the Actual Installer project ZIP without executing them
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
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-ActualInstaller-$([guid]::NewGuid().ToString('N'))") }
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Archive = Get-InstallerArchive -Path $ArchiveData.ArchivePath
      $Written = 0L; $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
      try {
        foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
          if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
          $Written += $Entry.Length
          if ($Written -gt $MaximumExpandedBytes) { throw 'Actual Installer extraction exceeds the configured output limit' }
          $Result.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath (Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName) -MaximumBytes $MaximumExpandedBytes))
        }
      } finally { $Archive.Dispose() }
      if ($Result.Count -eq 0) { throw "No Actual Installer files matched '$Name'" }
      return $Result.ToArray()
    } finally { Remove-Item -LiteralPath $ArchiveData.ArchivePath -Force -ErrorAction SilentlyContinue }
  }
}

function Test-ActualInstaller {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable Actual Installer project
  #>
  [OutputType([bool])] param([Parameter(Position=0,ValueFromPipeline,Mandatory)][string]$Path)
  process { try { $null = Get-ActualInstallerInfo -Path $Path; $true } catch { $false } }
}
function Read-ProtocolsFromActualInstaller {
  <#
  .SYNOPSIS
    Read literal URL protocol names from Actual Installer registry evidence
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromActualInstaller {
  <#
  .SYNOPSIS
    Read literal file extensions from Actual Installer registry evidence
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromActualInstaller {
  <#
  .SYNOPSIS
    Read the resolved Actual Installer project version
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromActualInstaller {
  <#
  .SYNOPSIS
    Read the Actual Installer project name
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).DisplayName }
}
function Read-PublisherFromActualInstaller {
  <#
  .SYNOPSIS
    Read the Actual Installer project publisher
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromActualInstaller {
  <#
  .SYNOPSIS
    Read the Actual Installer project GUID
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-ActualInstallerInfo -Path $Path).ProductCode }
}

Export-ModuleMember -Function Get-ActualInstallerInfo, Expand-ActualInstallerInstaller, Test-ActualInstaller, Read-ProtocolsFromActualInstaller, Read-FileExtensionsFromActualInstaller, Read-ProductVersionFromActualInstaller, Read-ProductNameFromActualInstaller, Read-PublisherFromActualInstaller, Read-ProductCodeFromActualInstaller
