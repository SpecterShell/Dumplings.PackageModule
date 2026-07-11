# SPDX-License-Identifier: MIT
# Static CreateInstall parser for Gentee GEA v2 archives. The container logic
# is PowerShell; the adaptive-Huffman LZGE decoder is an attributed MIT asset.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:CreateInstallMaximumHeaderBytes = 268435456
$Script:CreateInstallMaximumInfoBytes = 268435456
$Script:CreateInstallMaximumEntries = 1000000
$Script:CreateInstallMaximumBlockBytes = 268435456
$Script:CreateInstallFlagPassword = 0x0001
$Script:CreateInstallFlagCompressedInfo = 0x0002
$Script:CreateInstallFileFlagAttribute = 0x0001
$Script:CreateInstallFileFlagFolder = 0x0010
$Script:CreateInstallFileFlagVersion = 0x0020
$Script:CreateInstallFileFlagGroup = 0x0040
$Script:CreateInstallFileFlagProtect = 0x0080
$Script:CreateInstallFileFlagSolid = 0x0100

function Import-CreateInstallLzgeDecoder {
  <#
  .SYNOPSIS
    Load the MIT-licensed managed Gentee LZGE decoder once
  #>
  if (-not ([Management.Automation.PSTypeName]'Dumplings.Gentee.LzgeDecoder').Type) {
    $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'GenteeLzgeDecoder.cs'
    if (-not (Test-Path -LiteralPath $SourcePath)) { throw "The Gentee LZGE decoder source is missing: $SourcePath" }
    Add-Type -Path $SourcePath
  }
}

function Read-CreateInstallNullTerminatedString {
  <#
  .SYNOPSIS
    Read one bounded UTF-8 null-terminated string from a byte array
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$Offset,
    [ValidateRange(1, 1048576)][int]$MaximumBytes = 65536
  )

  if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) { throw 'The GEA string offset is outside the metadata table' }
  $End = [Array]::IndexOf($Bytes, [byte]0, $Offset, [Math]::Min($MaximumBytes, $Bytes.Length - $Offset))
  if ($End -lt 0) { throw 'The GEA metadata contains an unterminated string' }
  [pscustomobject]@{ Value = [Text.Encoding]::UTF8.GetString($Bytes, $Offset, $End - $Offset); NextOffset = $End + 1 }
}

function Read-CreateInstallArchiveLogicalRange {
  <#
  .SYNOPSIS
    Read a logical GEA data range across normal and moved data regions
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Count
  )

  if ($Offset -lt 0 -or $Offset + $Count -gt $Layout.SummarySize) { throw 'The requested GEA logical range is outside the compressed data stream' }
  $Result = [byte[]]::new($Count)
  if ($Count -eq 0) { return $Result }
  $Stream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Remaining = $Count
    $LogicalOffset = $Offset
    $DestinationOffset = 0
    while ($Remaining -gt 0) {
      if ($LogicalOffset -lt $Layout.OrdinaryDataLength) {
        $Available = $Layout.OrdinaryDataLength - $LogicalOffset
        $PhysicalOffset = $Layout.ArchiveOffset + $Layout.HeaderSize + $Layout.MovedSize + $LogicalOffset
      } else {
        $MovedOffset = $LogicalOffset - $Layout.OrdinaryDataLength
        $Available = $Layout.MovedSize - $MovedOffset
        $PhysicalOffset = $Layout.ArchiveOffset + $Layout.HeaderSize + $MovedOffset
      }
      $ReadCount = [int][Math]::Min($Remaining, $Available)
      if ($ReadCount -le 0) { throw 'The GEA logical range crosses an unavailable volume' }
      $Chunk = Read-BinaryBytes -Stream $Stream -Offset $PhysicalOffset -Count $ReadCount
      [Array]::Copy($Chunk, 0, $Result, $DestinationOffset, $ReadCount)
      $Remaining -= $ReadCount
      $DestinationOffset += $ReadCount
      $LogicalOffset += $ReadCount
    }
  } finally { $Stream.Dispose() }
  return $Result
}

function ConvertFrom-CreateInstallFileTable {
  <#
  .SYNOPSIS
    Parse packed GEA v1/v2 file descriptors from an expanded metadata table
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateSet(1, 2)][int]$MajorVersion
  )

  $Offset = 0
  $LogicalOffset = 0L
  $CurrentAttribute = 0
  $CurrentGroup = 0
  $CurrentPassword = 0
  $CurrentFolder = ''
  $Entries = [System.Collections.Generic.List[object]]::new()
  while ($Offset -lt $Bytes.Length) {
    if ($Entries.Count -ge $Script:CreateInstallMaximumEntries) { throw 'The GEA metadata exceeds the configured entry-count limit' }
    $BaseSize = if ($MajorVersion -ge 2) { 30 } else { 22 }
    if ($Offset + $BaseSize -gt $Bytes.Length) { throw 'The GEA file descriptor table is truncated' }
    $Flags = [BitConverter]::ToUInt16($Bytes, $Offset); $Offset += 2
    $FileTime = [BitConverter]::ToInt64($Bytes, $Offset); $Offset += 8
    if ($MajorVersion -ge 2) {
      $Size = [BitConverter]::ToUInt64($Bytes, $Offset); $Offset += 8
      $CompressedSize = [BitConverter]::ToUInt64($Bytes, $Offset); $Offset += 8
    } else {
      $Size = [uint64][BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
      $CompressedSize = [uint64][BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
    }
    $Crc32 = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4
    $VersionHigh = $null; $VersionLow = $null
    if (($Flags -band $Script:CreateInstallFileFlagAttribute) -ne 0) { $CurrentAttribute = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    if (($Flags -band $Script:CreateInstallFileFlagVersion) -ne 0) { $VersionHigh = [BitConverter]::ToUInt32($Bytes, $Offset); $VersionLow = [BitConverter]::ToUInt32($Bytes, $Offset + 4); $Offset += 8 }
    if (($Flags -band $Script:CreateInstallFileFlagGroup) -ne 0) { $CurrentGroup = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    if (($Flags -band $Script:CreateInstallFileFlagProtect) -ne 0) { $CurrentPassword = [BitConverter]::ToUInt32($Bytes, $Offset); $Offset += 4 }
    $NameData = Read-CreateInstallNullTerminatedString -Bytes $Bytes -Offset $Offset; $Name = $NameData.Value; $Offset = $NameData.NextOffset
    if (($Flags -band $Script:CreateInstallFileFlagFolder) -ne 0) { $FolderData = Read-CreateInstallNullTerminatedString -Bytes $Bytes -Offset $Offset; $CurrentFolder = $FolderData.Value; $Offset = $FolderData.NextOffset }
    if ([string]::IsNullOrWhiteSpace($Name)) { throw 'The GEA metadata contains an empty file name' }
    $RelativePath = if ($CurrentFolder) { Join-Path $CurrentFolder $Name } else { $Name }
    $Entries.Add([pscustomobject]@{
        Index          = $Entries.Count
        Flags          = [uint16]$Flags
        FileTime       = [long]$FileTime
        Size           = [uint64]$Size
        CompressedSize = [uint64]$CompressedSize
        Crc32          = [uint32]$Crc32
        Attributes     = [uint32]$CurrentAttribute
        VersionHigh    = $VersionHigh
        VersionLow     = $VersionLow
        GroupId        = [uint32]$CurrentGroup
        PasswordId     = [uint32]$CurrentPassword
        IsSolid        = ($Flags -band $Script:CreateInstallFileFlagSolid) -ne 0
        Name           = $Name
        Folder         = $CurrentFolder
        FullName       = $RelativePath
        DataOffset     = [long]$LogicalOffset
      })
    $LogicalOffset += [long]$CompressedSize
  }
  return $Entries.ToArray()
}

function Get-CreateInstallArchiveLayout {
  <#
  .SYNOPSIS
    Locate and parse the self-extracting CreateInstall GEA archive
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  Import-CreateInstallLzgeDecoder
  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try { $OverlayOffset = Get-PEOverlayOffset -Stream $Stream } finally { $Stream.Dispose() }
  $Signature = [byte[]](0x47, 0x45, 0x41, 0x00)
  foreach ($ArchiveOffset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Signature -StartOffset $OverlayOffset -Maximum 16)) {
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      if ($ArchiveOffset + 73 -gt $Stream.Length) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count 73
      $VolumeNumber = [BitConverter]::ToUInt16($Header, 4)
      $UniqueId = [BitConverter]::ToUInt32($Header, 6)
      $MajorVersion = $Header[10]
      $MinorVersion = $Header[11]
      if ($VolumeNumber -ne 0 -or $MajorVersion -notin @(1, 2)) { continue }
      $Flags = [BitConverter]::ToUInt32($Header, 20)
      $VolumeCount = [BitConverter]::ToUInt16($Header, 24)
      $HeaderSize = [BitConverter]::ToUInt32($Header, 26)
      $SummarySize = [BitConverter]::ToInt64($Header, 30)
      $InfoSize = [BitConverter]::ToUInt32($Header, 38)
      $ArchiveFileSize = [BitConverter]::ToInt64($Header, 42)
      $VolumeSize = [BitConverter]::ToInt64($Header, 50)
      $LastVolumeSize = [BitConverter]::ToInt64($Header, 58)
      $MovedSize = [BitConverter]::ToUInt32($Header, 66)
      $Memory = $Header[70]
      $BlockMultiplier = $Header[71]
      $SolidMultiplier = $Header[72]
      if ($VolumeCount -ne 1 -or $HeaderSize -lt 74 -or $HeaderSize -gt $Script:CreateInstallMaximumHeaderBytes -or $InfoSize -gt $Script:CreateInstallMaximumInfoBytes) { continue }
      if ($ArchiveFileSize -le $ArchiveOffset -or $ArchiveFileSize -gt $File.Length -or $HeaderSize -gt $ArchiveFileSize - $ArchiveOffset) { continue }
      if ($SummarySize -lt 0 -or $MovedSize -gt $SummarySize) { continue }
      $OrdinaryDataLength = $ArchiveFileSize - $MovedSize - $HeaderSize - $ArchiveOffset
      if ($OrdinaryDataLength -lt 0 -or $OrdinaryDataLength + $MovedSize -ne $SummarySize) { continue }

      $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count ([int]$HeaderSize)
      $PatternData = Read-CreateInstallNullTerminatedString -Bytes $HeaderBytes -Offset 73
      $MetadataOffset = $PatternData.NextOffset
      if (($Flags -band $Script:CreateInstallFlagPassword) -ne 0) {
        if ($MetadataOffset + 2 -gt $HeaderBytes.Length) { continue }
        $PasswordCount = [BitConverter]::ToUInt16($HeaderBytes, $MetadataOffset)
        $MetadataOffset += 2 + ($PasswordCount * 4)
      } else { $PasswordCount = 0 }
      if ($MetadataOffset -gt $HeaderBytes.Length) { continue }
      if (($Flags -band $Script:CreateInstallFlagCompressedInfo) -ne 0) {
        $CompressedInfo = [byte[]]::new($HeaderBytes.Length - $MetadataOffset)
        [Array]::Copy($HeaderBytes, $MetadataOffset, $CompressedInfo, 0, $CompressedInfo.Length)
        $Metadata = [Dumplings.Gentee.LzgeDecoder]::Decode($CompressedInfo, [int]$InfoSize)
      } else {
        if ($MetadataOffset + $InfoSize -gt $HeaderBytes.Length) { continue }
        $Metadata = [byte[]]::new([int]$InfoSize)
        [Array]::Copy($HeaderBytes, $MetadataOffset, $Metadata, 0, [int]$InfoSize)
      }
      $Entries = @(ConvertFrom-CreateInstallFileTable -Bytes $Metadata -MajorVersion $MajorVersion)
      if ($Entries.Count -eq 0 -or ($Entries[-1].DataOffset + [long]$Entries[-1].CompressedSize) -ne $SummarySize) { continue }
      return [pscustomobject]@{
        Path               = $File.FullName
        ArchiveOffset      = [long]$ArchiveOffset
        UniqueId           = [uint32]$UniqueId
        MajorVersion       = [byte]$MajorVersion
        MinorVersion       = [byte]$MinorVersion
        Flags              = [uint32]$Flags
        VolumeCount        = [uint16]$VolumeCount
        HeaderSize         = [long]$HeaderSize
        SummarySize        = [long]$SummarySize
        InfoSize           = [long]$InfoSize
        ArchiveFileSize    = [long]$ArchiveFileSize
        VolumeSize         = [long]$VolumeSize
        LastVolumeSize     = [long]$LastVolumeSize
        MovedSize          = [long]$MovedSize
        OrdinaryDataLength = [long]$OrdinaryDataLength
        PasswordCount      = [int]$PasswordCount
        MemoryMegabytes    = [int]$Memory
        BlockSize          = [long]$BlockMultiplier * 0x40000
        SolidSize          = [long]$SolidMultiplier * 0x40000
        VolumePattern      = $PatternData.Value
        Entries            = $Entries
      }
    } catch {
      continue
    } finally { $Stream.Dispose() }
  }
  throw 'The PE overlay does not contain a supported CreateInstall GEA archive'
}

function Get-CreateInstallBlockInfo {
  <#
  .SYNOPSIS
    Enumerate compression block headers for one GEA file entry
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][psobject]$Layout, [Parameter(Mandatory)][psobject]$Entry)

  $LogicalOffset = [long]$Entry.DataOffset
  $CompressedRemaining = [long]$Entry.CompressedSize
  $OutputRemaining = [long]$Entry.Size
  $HeaderSize = if ($Layout.MajorVersion -ge 2) { 9 } else { 5 }
  while ($OutputRemaining -gt 0) {
    if ($CompressedRemaining -lt $HeaderSize) { throw "The GEA data for '$($Entry.FullName)' is truncated" }
    $Header = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $LogicalOffset -Count $HeaderSize
    $RawOrder = $Header[0]
    $StoredOrder = $RawOrder -band 0x7F
    $CompressedSize = if ($Layout.MajorVersion -ge 2) { [uint64][BitConverter]::ToUInt64($Header, 1) } else { [uint64][BitConverter]::ToUInt32($Header, 1) }
    if ($CompressedSize -gt [long]::MaxValue -or $CompressedSize -gt $CompressedRemaining - $HeaderSize) { throw "The GEA block for '$($Entry.FullName)' exceeds its file data range" }
    $CompressionType = $StoredOrder -shr 4
    $CompressionOrder = ($StoredOrder -band 0x0F) + 1
    $OutputSize = if ($CompressionType -eq 0) { [long]$CompressedSize } else { [Math]::Min([long]$Layout.BlockSize, $OutputRemaining) }
    if ($OutputSize -le 0 -or $OutputSize -gt $OutputRemaining) { throw "The GEA block for '$($Entry.FullName)' has an invalid output size" }
    [pscustomobject]@{
      RawOrder        = [byte]$RawOrder
      CompressionType = [int]$CompressionType
      CompressionName = switch ($CompressionType) { 0 { 'Store' } 1 { 'LZGE' } 2 { 'PPMd' } default { 'Unknown' } }
      CompressionOrder = [int]$CompressionOrder
      HeaderOffset    = [long]$LogicalOffset
      DataOffset      = [long]($LogicalOffset + $HeaderSize)
      CompressedSize  = [long]$CompressedSize
      OutputSize      = [long]$OutputSize
    }
    $LogicalOffset += $HeaderSize + [long]$CompressedSize
    $CompressedRemaining -= $HeaderSize + [long]$CompressedSize
    $OutputRemaining -= $OutputSize
  }
  if ($CompressedRemaining -ne 0) { throw "The GEA file '$($Entry.FullName)' has trailing compressed data" }
}

function Get-CreateInstallInfo {
  <#
  .SYNOPSIS
    Read static CreateInstall identity and GEA payload evidence
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $File = Get-Item -LiteralPath $Path -Force
    $Layout = Get-CreateInstallArchiveLayout -Path $File.FullName
    $VersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $ExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    $CompressionMethods = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Entry in $Layout.Entries) { foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry)) { $null = $CompressionMethods.Add($Block.CompressionName) } }
    $RegistryWrites = @()
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Warnings.Add('CreateInstall PE version resources identify the package but do not prove the visible uninstall key. Validate ProductCode and ARP fields in a VM.')
    if ($ExecutionLevel -ieq 'requireAdministrator') { $Warnings.Add('Machine scope is inferred from an explicit requireAdministrator application manifest.') }
    if ($Layout.PasswordCount -gt 0 -or ($Layout.Entries | Where-Object PasswordId -gt 0 | Select-Object -First 1)) { $Warnings.Add('The GEA archive contains password-protected files; encrypted entries are intentionally unsupported.') }
    if ($CompressionMethods.Contains('PPMd')) { $Warnings.Add('The GEA archive uses PPMd blocks, which are not yet supported by the CreateInstall extractor.') }

    [pscustomobject]@{
      InstallerType              = 'CreateInstall'
      ProductCode                = $null
      PackageName                = ([string]$VersionInfo.ProductName).Trim()
      DisplayName                = ([string]$VersionInfo.ProductName).Trim()
      ProductName                = ([string]$VersionInfo.ProductName).Trim()
      DisplayVersion             = ([string]$VersionInfo.ProductVersion).Trim()
      Publisher                  = ([string]$VersionInfo.CompanyName).Trim()
      FileDescription            = ([string]$VersionInfo.FileDescription).Trim()
      Scope                      = if ($ExecutionLevel -ieq 'requireAdministrator') { 'machine' } else { $null }
      SupportedScopes            = if ($ExecutionLevel -ieq 'requireAdministrator') { @('machine') } else { @() }
      RequestedExecutionLevel    = $ExecutionLevel
      RegistryWrites             = $RegistryWrites
      RegistryAssociationInfo    = $RegistryAssociationInfo
      Protocols                  = $RegistryAssociationInfo.Protocols
      FileExtensions             = $RegistryAssociationInfo.FileExtensions
      WritesAppsAndFeaturesEntry = $null
      GEA                        = [pscustomobject]@{ MajorVersion = $Layout.MajorVersion; MinorVersion = $Layout.MinorVersion; ArchiveOffset = $Layout.ArchiveOffset; HeaderSize = $Layout.HeaderSize; SummarySize = $Layout.SummarySize; MovedSize = $Layout.MovedSize; BlockSize = $Layout.BlockSize; SolidSize = $Layout.SolidSize; EntryCount = $Layout.Entries.Count; CompressionMethods = @($CompressionMethods | Sort-Object); PasswordCount = $Layout.PasswordCount }
      ExtractedFiles             = @($Layout.Entries.FullName)
      CanExpand                  = $Layout.PasswordCount -eq 0 -and -not $CompressionMethods.Contains('PPMd') -and -not $CompressionMethods.Contains('Unknown')
      Warnings                   = @($Warnings)
      ParserVersionInfo          = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.CreateInstall'; ParserMajor = 1; Sources = @('PE version resource', 'PE application manifest', 'Gentee GEA v1/v2 structures', 'Gentee LZGE decoder') }
    }
  }
}

function Expand-CreateInstallInstaller {
  <#
  .SYNOPSIS
    Extract stored and LZGE-compressed files from a CreateInstall GEA archive
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    Import-CreateInstallLzgeDecoder
    $Layout = Get-CreateInstallArchiveLayout -Path $Path
    if ($Layout.PasswordCount -gt 0) { throw 'Password-protected CreateInstall GEA archives are intentionally unsupported' }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-CreateInstall-$([guid]::NewGuid().ToString('N'))") }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $ExpandedBytes = 0L
    $SolidHistory = [byte[]]::new(0)
    foreach ($Entry in $Layout.Entries) {
      if ($Entry.PasswordId -gt 0) { throw "The CreateInstall entry '$($Entry.FullName)' is password-protected and cannot be extracted" }
      if (-not $Entry.IsSolid) { $SolidHistory = [byte[]]::new(0) }
      $Selected = Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name
      if ($Selected) {
        $ExpandedBytes += [long]$Entry.Size
        if ($ExpandedBytes -gt $MaximumExpandedBytes) { throw 'CreateInstall extraction exceeds the configured output limit' }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      } else { $Output = $null }
      try {
        foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry)) {
          if ($Block.CompressedSize -gt $Script:CreateInstallMaximumBlockBytes -or $Block.OutputSize -gt $Script:CreateInstallMaximumBlockBytes) { throw "The CreateInstall block for '$($Entry.FullName)' exceeds the configured block limit" }
          $InputBytes = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $Block.DataOffset -Count ([int]$Block.CompressedSize)
          switch ($Block.CompressionType) {
            0 { $Decoded = $InputBytes; $SolidHistory = [byte[]]::new(0) }
            1 {
              $Prefix = if ($Block.CompressionOrder -eq 1) { $SolidHistory } else { [byte[]]::new(0) }
              $Decoded = [Dumplings.Gentee.LzgeDecoder]::Decode($InputBytes, [int]$Block.OutputSize, $Prefix)
              $Combined = if ($Prefix.Length -gt 0) { $Prefix + $Decoded } else { $Decoded }
              $Keep = [int][Math]::Min($Layout.SolidSize, $Combined.Length)
              $SolidHistory = [byte[]]::new($Keep)
              if ($Keep -gt 0) { [Array]::Copy($Combined, $Combined.Length - $Keep, $SolidHistory, 0, $Keep) }
            }
            2 { throw "The CreateInstall entry '$($Entry.FullName)' uses unsupported PPMd compression" }
            default { throw "The CreateInstall entry '$($Entry.FullName)' uses an unknown compression method" }
          }
          if ($Output) { $Output.Write($Decoded, 0, $Decoded.Length) }
        }
      } finally { if ($Output) { $Output.Dispose() } }
      if ($Selected) { $Result.Add((Get-Item -LiteralPath $OutputPath -Force)) }
    }
    if ($Result.Count -eq 0) { throw "No CreateInstall files matched '$Name'" }
    return $Result.ToArray()
  }
}

function Test-CreateInstall {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable CreateInstall GEA archive
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process { try { $null = Get-CreateInstallInfo -Path $Path; return $true } catch { return $false } }
}

function Read-ProtocolsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal URL protocol names from CreateInstall registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromCreateInstall {
  <#
  .SYNOPSIS
    Read literal file extensions from CreateInstall registry evidence
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product version
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE product name
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).DisplayName }
}

function Read-PublisherFromCreateInstall {
  <#
  .SYNOPSIS
    Read the CreateInstall PE publisher
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromCreateInstall {
  <#
  .SYNOPSIS
    Read a literal CreateInstall uninstall key when available
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).ProductCode }
}

function Read-ScopeFromCreateInstall {
  <#
  .SYNOPSIS
    Read CreateInstall scope from explicit elevation evidence
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-CreateInstallInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-CreateInstallInfo, Expand-CreateInstallInstaller, Test-CreateInstall, Read-ProtocolsFromCreateInstall, Read-FileExtensionsFromCreateInstall, Read-ProductVersionFromCreateInstall, Read-ProductNameFromCreateInstall, Read-PublisherFromCreateInstall, Read-ProductCodeFromCreateInstall, Read-ScopeFromCreateInstall
