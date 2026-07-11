# SPDX-License-Identifier: MIT
# Static InstallAnywhere parser. It reads embedded ZIP/XML project data and
# never starts the installer or its Java launcher.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallAnywhereMaximumArchiveBytes = 2147483648
$Script:InstallAnywhereMaximumEntryBytes = 268435456

function Copy-InstallAnywhereEmbeddedArchive {
  <#
  .SYNOPSIS
    Materialize a validated embedded ZIP range as a temporary archive file
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Range
  )

  if ($Range.Length -gt $Script:InstallAnywhereMaximumArchiveBytes) { throw 'The embedded InstallAnywhere ZIP exceeds the configured size limit' }
  $TemporaryPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallAnywhere-$([guid]::NewGuid().ToString('N')).zip")
  $Source = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $Destination = [IO.File]::Open($TemporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    Copy-BinaryStreamRange -Source $Source -Destination $Destination -Offset $Range.Offset -Length $Range.Length
    return $TemporaryPath
  } finally {
    $Destination.Dispose()
    $Source.Dispose()
  }
}

function Get-InstallAnywhereArchiveData {
  <#
  .SYNOPSIS
    Locate the InstallAnywhere ZIP archive and enumerate its payload names
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  foreach ($Range in @(Get-EmbeddedZipArchiveRange -Path $Path)) {
    $TemporaryPath = $null
    $Archive = $null
    try {
      $TemporaryPath = Copy-InstallAnywhereEmbeddedArchive -Path $Path -Range $Range
      $Archive = Get-InstallerArchive -Path $TemporaryPath
      $Entries = @(Get-InstallerArchiveEntry -Archive $Archive)
      $Names = @($Entries.FullName)
      if ($Names -notcontains 'InstallerData/Execute.zip' -and $Names -notcontains 'InstallerData/IAClasses.zip' -and -not ($Names -match 'InstallScript\.iap_xml$')) { continue }
      return [pscustomobject]@{ Range = $Range; ArchivePath = $TemporaryPath; Entries = $Entries; EntryNames = $Names }
    } catch {
      if ($TemporaryPath) { Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue }
      continue
    } finally {
      if ($Archive) { $Archive.Dispose() }
    }
  }
  throw 'The file does not contain a recognized InstallAnywhere embedded ZIP archive'
}

function Read-InstallAnywhereEntryContent {
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][string]$ArchivePath, [Parameter(Mandatory)][string]$Name)
  $Archive = Get-InstallerArchive -Path $ArchivePath
  try {
    $Entry = Get-InstallerArchiveEntry -Archive $Archive | Where-Object { $_.FullName -ieq $Name } | Select-Object -First 1
    if (-not $Entry) { return $null }
    if ($Entry.Length -gt $Script:InstallAnywhereMaximumEntryBytes) { throw "The InstallAnywhere entry '$Name' exceeds the configured size limit" }
    return Read-InstallerArchiveEntryBytes -Entry $Entry -MaximumBytes ([int]$Script:InstallAnywhereMaximumEntryBytes)
  } finally {
    $Archive.Dispose()
  }
}

function Get-InstallAnywhereProjectXml {
  [OutputType([string])]
  param ([Parameter(Mandatory)]$ArchiveData)
  $NestedBytes = Read-InstallAnywhereEntryContent -ArchivePath $ArchiveData.ArchivePath -Name 'InstallerData/Execute.zip'
  if ($NestedBytes) {
    $NestedPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallAnywhere-Execute-$([guid]::NewGuid().ToString('N')).zip")
    try {
      [IO.File]::WriteAllBytes($NestedPath, $NestedBytes)
      $ProjectBytes = Read-InstallAnywhereEntryContent -ArchivePath $NestedPath -Name 'InstallScript.iap_xml'
      if ($ProjectBytes) { return [Text.Encoding]::UTF8.GetString($ProjectBytes) }
    } finally {
      Remove-Item -LiteralPath $NestedPath -Force -ErrorAction SilentlyContinue
    }
  }
  $ProjectName = @($ArchiveData.EntryNames | Where-Object { $_ -match 'InstallScript\.iap_xml$' } | Select-Object -First 1)
  if ($ProjectName) { return [Text.Encoding]::UTF8.GetString((Read-InstallAnywhereEntryContent -ArchivePath $ArchiveData.ArchivePath -Name $ProjectName)) }
  return $null
}

function Get-InstallAnywherePropertyText {
  [OutputType([string])]
  param ([Parameter(Mandatory)][xml]$Xml, [Parameter(Mandatory)][string]$Name)
  $Property = $Xml.SelectSingleNode("//property[@name='$Name']")
  if (-not $Property) { return $null }
  $Value = $Property.InnerText.Trim()
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value
}

function Get-InstallAnywhereVersion {
  [OutputType([string])]
  param ([Parameter(Mandatory)][xml]$Xml)
  $Property = $Xml.SelectSingleNode("//property[@name='productVersion']")
  if (-not $Property) { return $null }
  $Parts = foreach ($Name in @('major', 'minor', 'revision', 'subRevision')) {
    $Value = $Property.SelectSingleNode(".//property[@name='$Name']/*")
    if ($Value) { $Value.InnerText.Trim() } else { $null }
  }
  $Parts = @($Parts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($Parts.Count) { return $Parts -join '.' }
  return $null
}

function Get-InstallAnywhereRegistryWrite {
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
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $ArchiveData = Get-InstallAnywhereArchiveData -Path $Path
    try {
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
    } finally {
      Remove-Item -LiteralPath $ArchiveData.ArchivePath -Force -ErrorAction SilentlyContinue
    }
  }
}

function Expand-InstallAnywhereInstaller {
  <#
  .SYNOPSIS
    Extract InstallAnywhere outer ZIP payload files without executing the installer
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
    try {
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-InstallAnywhere-$([guid]::NewGuid().ToString('N'))") }
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force
      $Archive = Get-InstallerArchive -Path $ArchiveData.ArchivePath
      $Written = 0L; $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
      try {
        foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
          if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
          $Written += $Entry.Length
          if ($Written -gt $MaximumExpandedBytes) { throw 'InstallAnywhere extraction exceeds the configured output limit' }
          $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
          $Result.Add((Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $MaximumExpandedBytes))
        }
      } finally { $Archive.Dispose() }
      if ($Result.Count -eq 0) { throw "No InstallAnywhere files matched '$Name'" }
      return $Result.ToArray()
    } finally { Remove-Item -LiteralPath $ArchiveData.ArchivePath -Force -ErrorAction SilentlyContinue }
  }
}

function Test-InstallAnywhereInstaller {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable InstallAnywhere project
  #>
  [OutputType([bool])] param([Parameter(Position=0,ValueFromPipeline,Mandatory)][string]$Path)
  process { try { $null = Get-InstallAnywhereInfo -Path $Path; $true } catch { $false } }
}
function Read-ProtocolsFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read literal URL protocol names from InstallAnywhere registry evidence
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read literal file extensions from InstallAnywhere registry evidence
  #>
  [OutputType([string[]])]
  param([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere product version
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere product name
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).DisplayName }
}
function Read-PublisherFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the explicit InstallAnywhere publisher
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromInstallAnywhere {
  <#
  .SYNOPSIS
    Read the InstallAnywhere project product identifier
  #>
  param([Parameter(ValueFromPipeline,Mandatory)][string]$Path)
  process { (Get-InstallAnywhereInfo -Path $Path).ProductCode }
}

Export-ModuleMember -Function Get-InstallAnywhereInfo, Expand-InstallAnywhereInstaller, Test-InstallAnywhereInstaller, Read-ProtocolsFromInstallAnywhere, Read-FileExtensionsFromInstallAnywhere, Read-ProductVersionFromInstallAnywhere, Read-ProductNameFromInstallAnywhere, Read-PublisherFromInstallAnywhere, Read-ProductCodeFromInstallAnywhere
