# SPDX-License-Identifier: Apache-2.0
# Static Wise Installation System wrapper parser. Wise has several product
# generations; this module handles the validated Wise-for-Windows-Installer
# variant that embeds a Windows Installer database without executing setup.
# Binary structure consumed here:
#
#   Wise PE launcher -> embedded CFB range
#     D0 CF 11 E0 A1 B1 1A E1 -> FAT/directory -> Root Entry CLSID
#     000C1084-0000-0000-C000-000000000046 -> MSI table streams
#
# Wise engine markers establish the outer family; CFB/root validation establishes
# the nested MSI. The carved range ends before the certificate table or EOF.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:WiseMsiClassId = '{000C1084-0000-0000-C000-000000000046}'
$Script:WiseMaximumEmbeddedMsiBytes = 4294967296

function Read-WiseCfbRootStorageClassId {
  <#
  .SYNOPSIS
    Read an embedded CFB root-storage CLSID relative to its file offset
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  #>
  [OutputType([guid])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset
  )

  if ($Offset + 512 -gt $Stream.Length) { return $null }
  $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 512

  # Validate the CFB signature, little-endian marker, and supported sector size
  # before resolving any sector-relative pointer.
  if ([Convert]::ToHexString($Header, 0, 8) -ne 'D0CF11E0A1B11AE1') { return $null }
  if ([BitConverter]::ToUInt16($Header, 0x1C) -ne 0xFFFE) { return $null }

  $SectorShift = [BitConverter]::ToUInt16($Header, 0x1E)
  if ($SectorShift -notin @(9, 12)) { return $null }
  $SectorSize = 1L -shl $SectorShift
  $DirectorySector = [BitConverter]::ToUInt32($Header, 0x30)
  if ($DirectorySector -eq [uint32]::MaxValue) { return $null }

  $RootOffset = $Offset + (([long]$DirectorySector + 1) * $SectorSize)
  if ($RootOffset + 128 -gt $Stream.Length) { return $null }
  $Root = Read-BinaryBytes -Stream $Stream -Offset $RootOffset -Count 128

  # Directory object type 5 identifies the CFB root storage whose CLSID
  # distinguishes MSI databases from other compound documents.
  if ($Root[0x42] -ne 5) { return $null }
  $ClassIdBytes = [byte[]]::new(16)
  [Array]::Copy($Root, 0x50, $ClassIdBytes, 0, 16)
  return [guid]::new($ClassIdBytes)
}

function Get-WiseEmbeddedMsiInfo {
  <#
  .SYNOPSIS
    Locate and validate the MSI database embedded by a Wise wrapper
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not (Get-PELayout -Path $File.FullName)) { throw 'The file is not a valid PE image.' }

  $WiseMarkers = @('.WISE', 'WiseForWindowsInstaller', 'Wise for Windows Installer', 'WISE_SETUP_EXE_PATH')
  $StrongWiseMarkers = @('WiseForWindowsInstaller', 'Wise for Windows Installer', 'WISE_SETUP_EXE_PATH')

  # Require a strong engine marker; the short .WISE token alone is too common
  # to classify an arbitrary PE as a supported Wise wrapper.
  $MatchedMarkers = foreach ($Marker in $WiseMarkers) {
    if (Find-BinaryPattern -Path $File.FullName -Pattern ([Text.Encoding]::ASCII.GetBytes($Marker)) -Maximum 1) { $Marker }
  }
  if (-not (@($MatchedMarkers) | Where-Object { $_ -in $StrongWiseMarkers })) { throw 'The PE does not contain supported Wise-for-Windows-Installer engine evidence.' }

  $CfbMagic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # Examine each bounded CFB signature and accept only an MSI root CLSID.
    foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $CfbMagic -Maximum 32)) {
      $ClassId = Read-WiseCfbRootStorageClassId -Stream $Stream -Offset $Offset
      if ($ClassId -and $ClassId.ToString('B').ToUpperInvariant() -eq $Script:WiseMsiClassId) {
        $Layout = Get-PELayout -Path $File.FullName
        $Certificate = $Layout.DataDirectories.Certificate
        # IMAGE_DIRECTORY_ENTRY_SECURITY stores a file offset rather than an RVA.

        # Exclude Authenticode data from the carved MSI range when it follows the
        # embedded database; otherwise stop at physical EOF.
        $EndOffset = if ($Certificate -and $Certificate.Rva -gt $Offset -and $Certificate.Rva -le $File.Length) { [long]$Certificate.Rva } else { [long]$File.Length }
        $Length = $EndOffset - $Offset
        if ($Length -le 0 -or $Length -gt $Script:WiseMaximumEmbeddedMsiBytes) { throw 'The embedded Wise MSI range exceeds the configured size limit.' }
        return [pscustomobject]@{
          Offset         = [long]$Offset
          Length         = [long]$Length
          ClassId        = $ClassId.ToString('B').ToUpperInvariant()
          MatchedMarkers = @($MatchedMarkers)
        }
      }
    }
  } finally {
    $Stream.Dispose()
  }
  throw 'A validated Windows Installer database was not found in the Wise wrapper.'
}

function Expand-WiseInstaller {
  <#
  .SYNOPSIS
    Export the validated MSI database embedded in a Wise installer
  .PARAMETER Path
    The path to the Wise installer
  .PARAMETER DestinationPath
    The output MSI path; a temporary file is used when omitted
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath
  )

  process {
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $EmbeddedMsi = Get-WiseEmbeddedMsiInfo -Path $File.FullName
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = New-TempFile }
    if ([IO.Path]::GetExtension($DestinationPath) -ine '.msi') { $DestinationPath = [IO.Path]::ChangeExtension($DestinationPath, '.msi') }
    return Export-InstallerArchiveRange -Path $File.FullName -Offset $EmbeddedMsi.Offset -Length $EmbeddedMsi.Length -DestinationPath $DestinationPath
  }
}

function Get-WiseInfo {
  <#
  .SYNOPSIS
    Read static Wise wrapper and nested MSI manifest evidence
  .PARAMETER Path
    The path to the Wise installer
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $EmbeddedMsi = Get-WiseEmbeddedMsiInfo -Path $File.FullName
    $TemporaryFolder = New-TempFolder
    $MsiPath = Join-Path $TemporaryFolder 'embedded.msi'
    try {
      # The nested MSI is authoritative for product identity, associations, and
      # architecture. Outer PE version resources remain secondary evidence only.
      $null = Expand-WiseInstaller -Path $File.FullName -DestinationPath $MsiPath
      $MsiInfo = Get-MsiInstallerInfo -Path $MsiPath
      $Publisher = try { Read-MsiProperty -Path $MsiPath -Query "SELECT `Value` FROM `Property` WHERE `Property`='Manufacturer'" } catch { $null }
      $AllUsers = try { Read-MsiProperty -Path $MsiPath -Query "SELECT `Value` FROM `Property` WHERE `Property`='ALLUSERS'" } catch { $null }

      # Only an explicit ALLUSERS=1 authoring value proves machine scope here.
      $Scope = if ($AllUsers -eq '1') { 'machine' } else { $null }
      $VersionStrings = @(Get-PEVersionStringTable -Path $File.FullName)[0]

      [pscustomobject]@{
        InstallerType                = 'Wise MSI'
        WiseVariant                  = 'Wise for Windows Installer'
        DisplayName                  = $MsiInfo.ProductName
        ProductName                  = $MsiInfo.ProductName
        DisplayVersion               = $MsiInfo.ProductVersion
        Publisher                    = $Publisher
        ProductCode                  = $MsiInfo.ProductCode
        UpgradeCode                  = $MsiInfo.UpgradeCode
        Scope                        = $Scope
        SupportedScopes              = if ($Scope) { @($Scope) } else { @() }
        InstallLocationProperty      = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch        = $MsiInfo.InstallLocationSwitch
        NestedInstallerBuilder       = $MsiInfo.InstallerBuilder
        AppsAndFeaturesInstallerType = $MsiInfo.AppsAndFeaturesInstallerType
        AppsAndFeaturesProductCode   = $MsiInfo.AppsAndFeaturesProductCode
        AppsAndFeaturesEntries       = $MsiInfo.AppsAndFeaturesEntries
        RegistryAssociationInfo      = $MsiInfo.RegistryAssociationInfo
        Protocols                    = @($MsiInfo.Protocols)
        FileExtensions               = @($MsiInfo.FileExtensions)
        SupportedArchitectures       = @($MsiInfo.SupportedArchitectures)
        UnsupportedArchitectures     = @($MsiInfo.UnsupportedArchitectures)
        WritesAppsAndFeaturesEntry   = $true
        EmbeddedMsi                  = $EmbeddedMsi
        ExtractedFiles               = @([IO.Path]::GetFileName($MsiPath))
        CanExpand                    = $true
        OuterVersionInfo             = $VersionStrings
        Warnings                     = @(
          'Wise is the outer bootstrapper; the embedded MSI is authoritative for ProductCode, UpgradeCode, associations, and visible Windows Installer ARP behavior.'
          if (-not $Scope) { 'The nested MSI does not explicitly set ALLUSERS=1. Omit Scope unless VM validation proves the final installation scope.' }
        )
        ParserVersionInfo            = [pscustomobject]@{
          Parser      = 'Dumplings.PackageModule.Wise'
          ParserMajor = 1
          Sources     = @('Wise engine markers', 'validated embedded MSI CFB root CLSID', 'MSI tables')
        }
      }
    } finally {
      Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Test-WiseInstaller {
  <#
  .SYNOPSIS
    Test whether a PE is a supported Wise MSI wrapper
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-WiseEmbeddedMsiInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProductVersionFromWise {
  <#
  .SYNOPSIS
    Read the nested MSI product version from a Wise wrapper
  .PARAMETER Path
    The path to the Wise installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromWise {
  <#
  .SYNOPSIS
    Read the nested MSI product name from a Wise wrapper
  .PARAMETER Path
    The path to the Wise installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).DisplayName }
}

function Read-PublisherFromWise {
  <#
  .SYNOPSIS
    Read the nested MSI publisher from a Wise wrapper
  .PARAMETER Path
    The path to the Wise installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromWise {
  <#
  .SYNOPSIS
    Read the nested MSI ProductCode from a Wise wrapper
  .PARAMETER Path
    The path to the Wise installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).ProductCode }
}

function Read-UpgradeCodeFromWise {
  <#
  .SYNOPSIS
    Read the nested MSI UpgradeCode from a Wise wrapper
  .PARAMETER Path
    The path to the Wise installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).UpgradeCode }
}

function Read-ScopeFromWise {
  <#
  .SYNOPSIS
    Read explicit nested MSI scope evidence from a Wise wrapper
  .PARAMETER Path
    The path to the Wise installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).Scope }
}

function Read-ProtocolsFromWise {
  <#
  .SYNOPSIS
    Read protocol associations from the nested Wise MSI
  .PARAMETER Path
    The path to the Wise installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromWise {
  <#
  .SYNOPSIS
    Read file-extension associations from the nested Wise MSI
  .PARAMETER Path
    The path to the Wise installer
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-WiseInfo -Path $Path).FileExtensions }
}

Export-ModuleMember -Function Get-WiseInfo, Expand-WiseInstaller, Test-WiseInstaller, Read-ProductVersionFromWise, Read-ProductNameFromWise, Read-PublisherFromWise, Read-ProductCodeFromWise, Read-UpgradeCodeFromWise, Read-ScopeFromWise, Read-ProtocolsFromWise, Read-FileExtensionsFromWise
