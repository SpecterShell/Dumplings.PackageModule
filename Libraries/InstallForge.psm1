# SPDX-License-Identifier: MIT
# Static InstallForge parser. InstallForge stores project configuration in a
# named PE resource and payload files in a 7z archive after the PE image.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallForgeMaximumConfigurationBytes = 16777216
$Script:InstallForgeMaximumArchiveBytes = 4294967296
$Script:InstallForgeMaximumEntryBytes = 268435456

function ConvertFrom-InstallForgeEncodedPathSegment {
  <#
  .SYNOPSIS
    Decode one base64-encoded UTF-16LE InstallForge archive path segment
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Segment)

  if ($Segment -ieq 'empty.empty') { return $Segment }
  try {
    $Bytes = [Convert]::FromBase64String($Segment)
    if ($Bytes.Length -eq 0 -or ($Bytes.Length % 2) -ne 0) { return $Segment }
    $Decoded = [Text.Encoding]::Unicode.GetString($Bytes).TrimEnd([char]0)
    if ([string]::IsNullOrWhiteSpace($Decoded) -or $Decoded.IndexOf([char]0) -ge 0) { return $Segment }
    return $Decoded
  } catch {
    return $Segment
  }
}

function ConvertFrom-InstallForgeEncodedPath {
  <#
  .SYNOPSIS
    Decode every segment of an InstallForge archive path
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Path)

  $Segments = @($Path -split '[\\/]')
  return (($Segments | ForEach-Object { ConvertFrom-InstallForgeEncodedPathSegment -Segment $_ }) -join [IO.Path]::DirectorySeparatorChar)
}

function ConvertFrom-InstallForgeIni {
  <#
  .SYNOPSIS
    Parse an InstallForge project INI without evaluating project variables
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][string]$Content)

  $Result = @{}
  $Section = $null
  foreach ($Line in ($Content -split "`r?`n")) {
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith(';') -or $Trimmed.StartsWith('#')) { continue }
    if ($Trimmed -match '^\[(.+)\]$') {
      $Section = $Matches[1]
      if (-not $Result.ContainsKey($Section)) { $Result[$Section] = @{} }
      continue
    }
    if ($Section -and $Trimmed -match '^([^=]+)=(.*)$') {
      $Result[$Section][$Matches[1].Trim()] = $Matches[2].Trim()
    }
  }
  return $Result
}

function Get-InstallForgeConfigurationArchiveData {
  <#
  .SYNOPSIS
    Open the named InstallForge configuration resource and locate SC.dat
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $Resource = Get-PEResourceInfo -Path $Path |
    Where-Object { $_.TypeId -eq 10 -and $_.Name -ieq 'SETUPCONFIGURATION' } |
    Select-Object -First 1
  if (-not $Resource) { throw 'The PE does not contain an InstallForge SETUPCONFIGURATION resource' }
  if ($Resource.Size -le 0 -or $Resource.Size -gt $Script:InstallForgeMaximumConfigurationBytes) {
    throw 'The InstallForge configuration resource exceeds the configured size limit'
  }

  $TemporaryPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallForge-$([guid]::NewGuid().ToString('N')).7z")
  $Archive = $null
  try {
    $null = Export-PEResourceData -Resource $Resource -DestinationPath $TemporaryPath -MaximumBytes $Script:InstallForgeMaximumConfigurationBytes
    $Archive = Get-InstallerArchive -Path $TemporaryPath
    $Entries = @(Get-InstallerArchiveEntry -Archive $Archive | ForEach-Object {
        [pscustomobject]@{
          EncodedName = $_.FullName
          FullName    = ConvertFrom-InstallForgeEncodedPath -Path $_.FullName
          Length      = $_.Length
          NativeEntry = $_.NativeEntry
        }
      })
    $ConfigurationEntry = $Entries | Where-Object { $_.FullName -ieq 'SC.dat' } | Select-Object -First 1
    if (-not $ConfigurationEntry) { throw 'The InstallForge configuration archive does not contain SC.dat' }
    return [pscustomobject]@{
      ArchivePath            = $TemporaryPath
      Entries                = $Entries
      ConfigurationEntryName = $ConfigurationEntry.EncodedName
      Resource               = $Resource
    }
  } catch {
    Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
    throw
  } finally {
    if ($Archive) { $Archive.Dispose() }
  }
}

function Get-InstallForgePayloadArchiveData {
  <#
  .SYNOPSIS
    Locate and validate the InstallForge payload 7z archive after the PE image
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try { $OverlayOffset = Get-PEOverlayOffset -Stream $Stream } finally { $Stream.Dispose() }
  if ($OverlayOffset -le 0 -or $OverlayOffset -ge $File.Length) { throw 'The InstallForge PE has no payload overlay' }

  foreach ($Range in @(Get-EmbeddedSevenZipArchiveRange -Path $File.FullName -StartOffset $OverlayOffset -MaximumArchives 16 -MaximumArchiveBytes $Script:InstallForgeMaximumArchiveBytes)) {
    $Offset = $Range.Offset
    $Length = $Range.Length
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $File.FullName -Range $Range
      $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive | ForEach-Object {
          [pscustomobject]@{
            EncodedName = $_.FullName
            FullName    = ConvertFrom-InstallForgeEncodedPath -Path $_.FullName
            Length      = $_.Length
          }
        })
      if ($Entries.Count -eq 0 -or -not ($Entries | Where-Object { $_.EncodedName -ne $_.FullName } | Select-Object -First 1)) { continue }
      return [pscustomobject]@{ SourcePath = $File.FullName; Range = $Range; Entries = $Entries; Offset = [long]$Offset; Length = [long]$Length }
    } catch {
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }
  throw 'The PE overlay does not contain a validated InstallForge payload archive'
}

function Read-InstallForgeConfigurationText {
  <#
  .SYNOPSIS
    Read a bounded decoded file from the InstallForge configuration archive
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][psobject]$ArchiveData,
    [Parameter(Mandatory)][string]$Name
  )

  $Archive = Get-InstallerArchive -Path $ArchiveData.ArchivePath
  try {
    $EntryData = $ArchiveData.Entries | Where-Object { $_.FullName -ieq $Name } | Select-Object -First 1
    if (-not $EntryData) { return $null }
    if ($EntryData.Length -gt $Script:InstallForgeMaximumEntryBytes) { throw "The InstallForge configuration entry '$Name' exceeds the configured size limit" }
    $Entry = Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -ieq $EntryData.EncodedName } | Select-Object -First 1
    if (-not $Entry) { throw "The InstallForge configuration entry '$Name' could not be reopened" }
    $EntryStream = Open-InstallerArchiveEntry -Entry $Entry
    $Reader = [IO.StreamReader]::new($EntryStream, [Text.Encoding]::UTF8, $true)
    try { return $Reader.ReadToEnd() } finally { $Reader.Dispose(); $EntryStream.Dispose() }
  } finally {
    $Archive.Dispose()
  }
}

function Resolve-InstallForgeScope {
  <#
  .SYNOPSIS
    Resolve scope from explicit InstallForge installation-directory tokens
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$InstallDirectory)

  if ($InstallDirectory -match '(?i)<(?:ProgramFiles|CommonFiles|Windows|System)>') { return 'machine' }
  if ($InstallDirectory -match '(?i)<(?:AppData|LocalAppData|UserProfile|Desktop|Documents)>') { return 'user' }
  return $null
}

function Get-InstallForgeInfo {
  <#
  .SYNOPSIS
    Read explicit metadata from an InstallForge setup configuration
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $ConfigurationData = Get-InstallForgeConfigurationArchiveData -Path $File.FullName
    $PayloadData = $null
    try {
      $Configuration = ConvertFrom-InstallForgeIni -Content (Read-InstallForgeConfigurationText -ArchiveData $ConfigurationData -Name 'SC.dat')
      $Setup = $Configuration['Setup']
      if (-not $Setup -or [string]::IsNullOrWhiteSpace($Setup['Appname'])) { throw 'The InstallForge SC.dat file does not contain a usable Setup/Appname value' }
      try { $PayloadData = Get-InstallForgePayloadArchiveData -Path $File.FullName } catch { $PayloadData = $null }

      $Warnings = [System.Collections.Generic.List[string]]::new()
      $Scope = Resolve-InstallForgeScope -InstallDirectory $Setup['InstallDir']
      if (-not $Scope) { $Warnings.Add('InstallForge scope could not be resolved from the configured installation directory; validate it in a VM.') }
      $Warnings.Add('InstallForge does not provide a WinGet-compatible silent installation mode; use this parser for analysis and rejection, not to invent silent switches.')
      $Warnings.Add('The InstallForge project name is display metadata, not sufficient evidence for ProductCode. Validate the visible uninstall key in a VM when ProductCode is required.')
      if (-not $PayloadData) { $Warnings.Add('The InstallForge payload archive could not be opened; metadata was read from the configuration resource only.') }

      $RegistryWrites = @()
      $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
      $WritesAppsAndFeaturesEntry = $Setup['Uninstaller'] -eq '1'
      [pscustomobject]@{
        InstallerType                = 'InstallForge'
        ProductCode                  = $null
        PackageName                  = $Setup['Appname']
        DisplayName                  = $Setup['Appname']
        ProductName                  = $Setup['Appname']
        DisplayVersion               = $Setup['Version']
        Publisher                    = $Setup['Company']
        PublisherUrl                 = $Setup['Website1']
        DefaultInstallationDirectory = $Setup['InstallDir']
        MainExecutable               = $Setup['ProgramRun']
        MainExecutableArguments      = $Setup['ProgramRunArguments']
        Uninstaller                  = if ($Setup['Uninstaller'] -eq '1') { "$($Setup['UninstallerFilename']).exe" } else { $null }
        Scope                        = $Scope
        SupportedScopes              = if ($Scope) { @($Scope) } else { @() }
        SupportsSilentInstallation   = $false
        InstallModes                 = @('interactive')
        RegistryWrites               = $RegistryWrites
        RegistryAssociationInfo      = $RegistryAssociationInfo
        Protocols                    = $RegistryAssociationInfo.Protocols
        FileExtensions               = $RegistryAssociationInfo.FileExtensions
        WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
        ConfigurationFiles           = @($ConfigurationData.Entries.FullName)
        ExtractedFiles               = if ($PayloadData) { @($PayloadData.Entries | Where-Object { [IO.Path]::GetFileName($_.FullName) -ine 'empty.empty' } | Select-Object -ExpandProperty FullName) } else { @() }
        ArchiveOffset                = if ($PayloadData) { $PayloadData.Offset } else { $null }
        Warnings                     = @($Warnings)
        ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallForge'; ParserMajor = 1; Sources = @('SETUPCONFIGURATION PE resource', 'SC.dat', 'validated embedded 7z payload') }
      }
    } finally {
      Remove-Item -LiteralPath $ConfigurationData.ArchivePath -Force -ErrorAction SilentlyContinue
    }
  }
}

function Expand-InstallForgeInstaller {
  <#
  .SYNOPSIS
    Extract decoded InstallForge payload files without executing the installer
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $ArchiveData = Get-InstallForgePayloadArchiveData -Path $Path
    $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallForge-$([guid]::NewGuid().ToString('N'))") }
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Archive = $Context.Archive
      $Written = 0L
      $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
      foreach ($EntryData in $ArchiveData.Entries) {
        if ([IO.Path]::GetFileName($EntryData.FullName) -ieq 'empty.empty' -or -not (Test-ExtractionPattern -Path $EntryData.FullName -Pattern $Name)) { continue }
        $Written += $EntryData.Length
        if ($Written -gt $MaximumExpandedBytes) { throw 'InstallForge extraction exceeds the configured output limit' }
        $Entry = Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -ieq $EntryData.EncodedName } | Select-Object -First 1
        if (-not $Entry) { throw "The InstallForge payload entry '$($EntryData.FullName)' could not be reopened" }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $EntryData.FullName
        $Result.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
      }
      if ($Result.Count -eq 0) { throw "No InstallForge payload files matched '$Name'" }
      return $Result.ToArray()
    } finally { Close-InstallerArchiveRange -Context $Context }
  }
}

function Test-InstallForge {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable InstallForge project
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-InstallForgeInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromInstallForge {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallForge registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallForge {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallForge registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallForge {
  <#
  .SYNOPSIS
    Read the InstallForge project version
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromInstallForge {
  <#
  .SYNOPSIS
    Read the InstallForge project name
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).DisplayName }
}

function Read-PublisherFromInstallForge {
  <#
  .SYNOPSIS
    Read the InstallForge project publisher
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromInstallForge {
  <#
  .SYNOPSIS
    Read a literal InstallForge uninstall key when available
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).ProductCode }
}

function Read-ScopeFromInstallForge {
  <#
  .SYNOPSIS
    Read InstallForge scope from explicit project configuration
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallForgeInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-InstallForgeInfo, Expand-InstallForgeInstaller, Test-InstallForge, Read-ProtocolsFromInstallForge, Read-FileExtensionsFromInstallForge, Read-ProductVersionFromInstallForge, Read-ProductNameFromInstallForge, Read-PublisherFromInstallForge, Read-ProductCodeFromInstallForge, Read-ScopeFromInstallForge
