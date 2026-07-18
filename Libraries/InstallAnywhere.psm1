# SPDX-License-Identifier: MIT
# Static InstallAnywhere parser. It reads embedded ZIP/XML project data and
# never starts the installer or its Java launcher.
# Binary structure consumed here:
#
#   native PE launcher -> self-contained ZIP range
#     +-- InstallerData/Execute.zip -> InstallScript.iap_xml
#     +-- IAClasses.zip
#     `-- Resource1.zip and payload entries
#
# The archive base is derived from a matching EOCD and central-directory offset,
# not the first PK local-header marker. Nested ZIPs receive independent bounds,
# safe-path checks, and entry limits. XML product/action records supply metadata.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallAnywhereMaximumArchiveBytes = 2147483648
$Script:InstallAnywhereMaximumEntryBytes = 268435456

function Get-InstallAnywhereArchiveData {
  <#
  .SYNOPSIS
    Locate the InstallAnywhere ZIP archive and enumerate its payload names
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force

  # Test each independently validated ZIP range because launchers may append
  # signatures or auxiliary archives around the InstallAnywhere payload.
  foreach ($Range in @(Get-EmbeddedZipArchiveRange -Path $Path)) {
    if ($Range.Length -gt $Script:InstallAnywhereMaximumArchiveBytes) { continue }
    $Context = $null
    try {
      $Context = Open-InstallerArchiveRange -Path $File.FullName -Range $Range
      $Entries = @(Get-InstallerArchiveEntry -Archive $Context.Archive | ForEach-Object {
          [pscustomobject]@{ FullName = $_.FullName; Length = $_.Length }
        })
      $Names = @($Entries.FullName)

      # Require InstallAnywhere-specific project/runtime names instead of
      # classifying an arbitrary embedded ZIP by container type alone.
      if ($Names -notcontains 'InstallerData/Execute.zip' -and $Names -notcontains 'InstallerData/IAClasses.zip' -and -not ($Names -match 'InstallScript\.iap_xml$')) { continue }
      return [pscustomobject]@{ SourcePath = $File.FullName; Range = $Range; Entries = $Entries; EntryNames = $Names }
    } catch {
      # Continue to later ranges when a candidate central directory or entry is malformed.
      continue
    } finally {
      if ($Context) { Close-InstallerArchiveRange -Context $Context }
    }
  }
  throw 'The file does not contain a recognized InstallAnywhere embedded ZIP archive'
}

function Get-InstallAnywhereProjectXml {
  <#
  .SYNOPSIS
    Read InstallScript.iap_xml from the outer archive or nested Execute.zip.
  .PARAMETER ArchiveData
    Validated outer ZIP range and catalog returned by Get-InstallAnywhereArchiveData. Nested streams are disposed internally.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)]$ArchiveData)
  $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
  try {
    # Newer installers place the project XML inside Execute.zip. Convert the
    # nested entry to a bounded seekable stream before opening its ZIP directory.
    $NestedEntry = Get-InstallerArchiveEntry -Archive $Context.Archive | Where-Object { $_.FullName -ieq 'InstallerData/Execute.zip' } | Select-Object -First 1
    if ($NestedEntry) {
      if ($NestedEntry.Length -gt $Script:InstallAnywhereMaximumEntryBytes) { throw 'The InstallAnywhere Execute.zip entry exceeds the configured size limit' }
      $EntryStream = Open-InstallerArchiveEntry -Entry $NestedEntry
      $SeekableContext = $null
      $ProjectArchive = $null
      try {
        $SeekableContext = New-InstallerSeekableStream -SourceStream $EntryStream -MaximumBytes $Script:InstallAnywhereMaximumEntryBytes
        $ProjectArchive = Get-InstallerArchive -Stream $SeekableContext.Stream
        $ProjectEntry = Get-InstallerArchiveEntry -Archive $ProjectArchive | Where-Object { $_.FullName -ieq 'InstallScript.iap_xml' } | Select-Object -First 1
        if ($ProjectEntry) {
          $ProjectBytes = Read-InstallerArchiveEntryBytes -Entry $ProjectEntry -MaximumBytes ([int]$Script:InstallAnywhereMaximumEntryBytes)
          return [Text.Encoding]::UTF8.GetString($ProjectBytes)
        }
      } finally {
        if ($ProjectArchive) { $ProjectArchive.Dispose() }
        if ($SeekableContext) { $SeekableContext.Dispose() }
        $EntryStream.Dispose()
      }
    }

    # Older generations expose InstallScript.iap_xml directly in the outer archive.
    $ProjectName = $ArchiveData.EntryNames | Where-Object { $_ -match 'InstallScript\.iap_xml$' } | Select-Object -First 1
    if (-not $ProjectName) { return $null }
    $ProjectEntry = Get-InstallerArchiveEntry -Archive $Context.Archive | Where-Object { $_.FullName -ieq $ProjectName } | Select-Object -First 1
    if (-not $ProjectEntry) { return $null }
    if ($ProjectEntry.Length -gt $Script:InstallAnywhereMaximumEntryBytes) { throw "The InstallAnywhere entry '$ProjectName' exceeds the configured size limit" }
    $ProjectBytes = Read-InstallerArchiveEntryBytes -Entry $ProjectEntry -MaximumBytes ([int]$Script:InstallAnywhereMaximumEntryBytes)
    return [Text.Encoding]::UTF8.GetString($ProjectBytes)
  } finally {
    Close-InstallerArchiveRange -Context $Context
  }
}

function Get-InstallAnywherePropertyText {
  <#
  .SYNOPSIS
    Read one non-empty named property from InstallAnywhere project XML.
  .PARAMETER Xml
    Parsed InstallScript.iap_xml document.
  .PARAMETER Name
    Exact Java-bean property name to query.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][xml]$Xml, [Parameter(Mandatory)][string]$Name)
  $Property = $Xml.SelectSingleNode("//property[@name='$Name']")
  if (-not $Property) { return $null }
  $Value = $Property.InnerText.Trim()
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value
}

function Get-InstallAnywhereVersion {
  <#
  .SYNOPSIS
    Assemble the structured InstallAnywhere productVersion components.
  .PARAMETER Xml
    Parsed InstallScript.iap_xml document containing productVersion properties.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][xml]$Xml)
  $Property = $Xml.SelectSingleNode("//property[@name='productVersion']")
  if (-not $Property) { return $null }

  # InstallAnywhere serializes version components as child bean properties;
  # omit absent trailing components rather than manufacturing zero values.
  $Parts = foreach ($Name in @('major', 'minor', 'revision', 'subRevision')) {
    $Value = $Property.SelectSingleNode(".//property[@name='$Name']/*")
    if ($Value) { $Value.InnerText.Trim() } else { $null }
  }
  $Parts = @($Parts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($Parts.Count) { return $Parts -join '.' }
  return $null
}

function Get-InstallAnywhereRegistryWrite {
  <#
  .SYNOPSIS
    Return only literal uninstall registry paths present in project XML.
  .PARAMETER ProjectXml
    Raw InstallScript.iap_xml text. Built-in computed uninstall registration is intentionally not inferred.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string]$ProjectXml)
  # Built-in InstallAnywhere uninstall registration is not represented as a
  # literal registry action. Only return explicit uninstall-path evidence.
  foreach ($Match in [regex]::Matches($ProjectXml, '(?is)(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER).*?Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\([^<\s""\\]+)')) {
    [pscustomobject]@{ Root = $Match.Groups[1].Value; Key = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$($Match.Groups[2].Value)"; Name = $null; Value = $null; Type = $null }
  }
}

function Get-InstallAnywhereInfo {
  <#
  .SYNOPSIS
    Read static product metadata from an InstallAnywhere installer
  .DESCRIPTION
    Parses the embedded InstallAnywhere project XML. Product identity is
    explicit, while built-in uninstall registration may require VM validation.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $ArchiveData = Get-InstallAnywhereArchiveData -Path $Path
    $ProjectXml = Get-InstallAnywhereProjectXml -ArchiveData $ArchiveData
    if ([string]::IsNullOrWhiteSpace($ProjectXml)) { throw 'The InstallAnywhere archive does not expose InstallScript.iap_xml' }
    $Xml = [xml]$ProjectXml.TrimStart([char]0xFEFF)
    $RegistryWrites = @(Get-InstallAnywhereRegistryWrite -ProjectXml $ProjectXml)
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Scope = if ($RegistryWrites.Root -match 'HKLM|HKEY_LOCAL_MACHINE') { 'machine' } elseif ($RegistryWrites.Root -match 'HKCU|HKEY_CURRENT_USER') { 'user' } else { $null }
    [pscustomobject]@{
      InstallerType                = 'InstallAnywhere'
      ProductCode                  = Get-InstallAnywherePropertyText -Xml $Xml -Name 'productID'
      UpgradeCode                  = Get-InstallAnywherePropertyText -Xml $Xml -Name 'upgradeCode'
      PackageName                  = Get-InstallAnywherePropertyText -Xml $Xml -Name 'productName'
      DisplayName                  = Get-InstallAnywherePropertyText -Xml $Xml -Name 'productName'
      ProductName                  = Get-InstallAnywherePropertyText -Xml $Xml -Name 'productName'
      DisplayVersion               = Get-InstallAnywhereVersion -Xml $Xml
      Publisher                    = Get-InstallAnywherePropertyText -Xml $Xml -Name 'vendorName'
      PublisherUrl                 = Get-InstallAnywherePropertyText -Xml $Xml -Name 'vendorURL'
      DefaultInstallationDirectory = Get-InstallAnywherePropertyText -Xml $Xml -Name 'defaultInstallDir'
      Scope                        = $Scope
      RegistryWrites               = $RegistryWrites
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      EmbeddedFiles                = @($ArchiveData.EntryNames)
      ArchiveRange                 = $ArchiveData.Range
      WritesAppsAndFeaturesEntry   = if ($RegistryWrites.Count) { $true } else { $null }
      Warnings                     = @('InstallAnywhere can create its uninstall registration from built-in project metadata. Validate the visible ARP entry and scope in a VM when no explicit uninstall registry action was found.')
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallAnywhere'; ParserMajor = 1; Sources = @('Validated embedded ZIP archive', 'InstallerData/Execute.zip', 'InstallScript.iap_xml') }
    }
  }
}

function Expand-InstallAnywhereInstaller {
  <#
  .SYNOPSIS
    Extract InstallAnywhere outer ZIP payload files without executing the installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )
  process {
    $ArchiveData = Get-InstallAnywhereArchiveData -Path $Path
    $Context = Open-InstallerArchiveRange -Path $ArchiveData.SourcePath -Range $ArchiveData.Range
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallAnywhere-$([guid]::NewGuid().ToString('N'))") }
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Archive = $Context.Archive
      $Written = 0L; $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
      foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
        if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
        $Written += $Entry.Length
        if ($Written -gt $MaximumExpandedBytes) { throw 'InstallAnywhere extraction exceeds the configured output limit' }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
        $Result.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
      }
      if ($Result.Count -eq 0) { throw "No InstallAnywhere files matched '$Name'" }
      return $Result.ToArray()
    } finally { Close-InstallerArchiveRange -Context $Context }
  }
}

function Test-InstallAnywhereInstaller {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable InstallAnywhere project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])] param([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-InstallAnywhereInfo -Path $Path; $true } catch { $false } }
}
function Read-ProtocolsFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallAnywhere registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallAnywhere registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere product version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere product name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).DisplayName }
}
function Read-PublisherFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the InstallAnywhere project product identifier
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).ProductCode }
}

Export-ModuleMember -Function Get-InstallAnywhereInfo, Expand-InstallAnywhereInstaller, Test-InstallAnywhereInstaller, Read-ProtocolsFromInstallAnywhere, Read-FileExtensionsFromInstallAnywhere, Read-ProductVersionFromInstallAnywhere, Read-ProductNameFromInstallAnywhere, Read-PublisherFromInstallAnywhere, Read-ProductCodeFromInstallAnywhere
