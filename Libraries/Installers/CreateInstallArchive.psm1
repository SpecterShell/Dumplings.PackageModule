# SPDX-License-Identifier: Apache-2.0
# Internal CreateInstall implementation. See CreateInstall.psm1 for format sources and the binary layout.
# Pass parsed contexts explicitly and keep caller-owned streams local.

# CreateInstall archive implementation, imported locally by the public facade.
Import-Module (Join-Path $PSScriptRoot 'CreateInstallGentee.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:CreateInstallMaximumHeaderBytes = 268435456

$Script:CreateInstallMaximumInfoBytes = 268435456

$Script:CreateInstallMaximumEntries = 1000000

$Script:CreateInstallMaximumVolumes = 1024

$Script:CreateInstallMaximumBlockBytes = 268435456

$Script:CreateInstallFlagPassword = 0x0001

$Script:CreateInstallFlagCompressedInfo = 0x0002

$Script:CreateInstallFileFlagAttribute = 0x0001

$Script:CreateInstallFileFlagFolder = 0x0010

$Script:CreateInstallFileFlagVersion = 0x0020

$Script:CreateInstallFileFlagGroup = 0x0040

$Script:CreateInstallFileFlagProtect = 0x0080

$Script:CreateInstallFileFlagSolid = 0x0100

function Import-CreateInstallPpmdDecoder {
  <#
  .SYNOPSIS
    Load the source-shipped SharpCompress Gentee PPMd provider once.
  .DESCRIPTION
    Loads an AnyCPU managed companion provider. No native architecture selection or
    external CreateInstall/GEA executable is involved.
  #>
  param ()

  $AssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Providers', 'SharpCompress.Gentee', 'SharpCompress.Gentee.dll'
  $null = Import-InstallerManagedAssembly -Path $AssemblyPath -TypeName 'SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder'
}

function Read-CreateInstallNullTerminatedString {
  <#
  .SYNOPSIS
    Read one bounded UTF-8 null-terminated string from a byte array
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
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

function Resolve-CreateInstallVolumeName {
  <#
  .SYNOPSIS
    Expand one source-defined GEA volume-number placeholder.
  .PARAMETER Pattern
    GEA volume pattern stored in the main archive header.
  .PARAMETER Number
    One-based physical volume number passed to Gentee's str.out4 formatter.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Pattern,
    [Parameter(Mandatory)][ValidateRange(2, 65535)][int]$Number
  )

  # CreateInstall writes printf-style %i/%d/%u placeholders, optionally with a zero-padded width.
  # Requiring exactly one placeholder avoids guessing how arbitrary format strings are evaluated.
  $Placeholders = [regex]::Matches($Pattern, '%(?<Zero>0?)(?<Width>[1-9][0-9]?)?[diu]', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
  if ($Placeholders.Count -ne 1) { throw "The GEA volume pattern '$Pattern' does not contain exactly one supported number placeholder" }
  $Match = $Placeholders[0]
  $Width = $Match.Groups['Width'].Success ? [int]$Match.Groups['Width'].Value : 0
  $NumberText = $Number.ToString([Globalization.CultureInfo]::InvariantCulture)
  if ($Width -gt 0) {
    # str.out4 follows printf width semantics: a leading zero requests zero padding, otherwise
    # the decimal value is space padded. Spaces are legal in companion-volume file names.
    $NumberText = $NumberText.PadLeft($Width, $Match.Groups['Zero'].Value -eq '0' ? '0' : ' ')
  }
  return $Pattern.Substring(0, $Match.Index) + $NumberText + $Pattern.Substring($Match.Index + $Match.Length)
}

function Resolve-CreateInstallVolumePath {
  <#
  .SYNOPSIS
    Resolve a generated GEA companion name beneath an explicitly selected directory.
  .PARAMETER Directory
    Directory containing the companion volumes.
  .PARAMETER Name
    Generated relative companion name.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Directory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name
  )

  if ([IO.Path]::IsPathRooted($Name)) { throw "The GEA companion name '$Name' is rooted" }
  $Root = [IO.Path]::GetFullPath($Directory)
  $RootPrefix = $Root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $Candidate = [IO.Path]::GetFullPath((Join-Path $Root $Name))
  if (-not $Candidate.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "The GEA companion name '$Name' escapes the volume directory" }
  return $Candidate
}

function Read-CreateInstallArchiveLogicalRange {
  <#
  .SYNOPSIS
    Read a logical GEA data range across normal and moved data regions
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Count
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  .PARAMETER Stream
    Optional caller-owned seekable installer stream. Its position is restored by bounded reads and
    the helper never disposes it. When omitted, this function opens and closes the layout path.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Count,
    [AllowNull()][System.IO.Stream]$Stream
  )

  if ($Offset -lt 0 -or $Offset + $Count -gt $Layout.SummarySize) { throw 'The requested GEA logical range is outside the compressed data stream' }
  # GEA exposes one logical compressed stream across the main file, companion volumes, and the
  # moved prefix in the main header. Translate slices without joining the archive in memory.
  $Result = [byte[]]::new($Count)
  if ($Count -eq 0) { return , $Result }
  $OwnedStream = $null
  if ($null -eq $Stream) {
    $OwnedStream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $Stream = $OwnedStream
  }
  try {
    $Remaining = $Count
    $LogicalOffset = $Offset
    $DestinationOffset = 0
    while ($Remaining -gt 0) {
      $Segment = @($Layout.DataSegments | Where-Object { $LogicalOffset -ge $_.LogicalOffset -and $LogicalOffset -lt $_.LogicalOffset + $_.Length } | Select-Object -First 1)
      if ($Segment.Count -ne 1) { throw 'The GEA logical range crosses an unavailable volume' }
      $Segment = $Segment[0]
      if (-not $Segment.Available) { throw "The GEA companion volume '$($Segment.Path)' is unavailable" }
      $SegmentOffset = $LogicalOffset - $Segment.LogicalOffset
      $Available = $Segment.Length - $SegmentOffset
      $PhysicalOffset = $Segment.PhysicalOffset + $SegmentOffset
      $ReadCount = [int][Math]::Min($Remaining, $Available)
      if ($ReadCount -le 0) { throw 'The GEA logical range crosses an unavailable volume' }
      $SegmentOwnedStream = $null
      $SegmentStream = if ($Segment.Path -ieq $Layout.Path) { $Stream } else {
        $SegmentOwnedStream = [IO.File]::Open($Segment.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $SegmentOwnedStream
      }
      try { $Chunk = Read-BinaryBytes -Stream $SegmentStream -Offset $PhysicalOffset -Count $ReadCount } finally { if ($SegmentOwnedStream) { $SegmentOwnedStream.Dispose() } }
      [Array]::Copy($Chunk, 0, $Result, $DestinationOffset, $ReadCount)
      $Remaining -= $ReadCount
      $DestinationOffset += $ReadCount
      $LogicalOffset += $ReadCount
    }
  } finally { if ($OwnedStream) { $OwnedStream.Dispose() } }
  return , $Result
}

function ConvertFrom-CreateInstallFileTable {
  <#
  .SYNOPSIS
    Parse packed GEA v1/v2 file descriptors from an expanded metadata table
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER MajorVersion
    Detected format variant controlling version-specific parsing rules.
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
  # Descriptor flags make several fields stateful: omitted attributes, groups, passwords, and
  # folders inherit the most recently declared value.
  while ($Offset -lt $Bytes.Length) {
    if ($Entries.Count -ge $Script:CreateInstallMaximumEntries) { throw 'The GEA metadata exceeds the configured entry-count limit' }
    $BaseSize = if ($MajorVersion -ge 2) { 30 } else { 22 }
    if ($Offset + $BaseSize -gt $Bytes.Length) { throw 'The GEA file descriptor table is truncated' }
    $Flags = [BitConverter]::ToUInt16($Bytes, $Offset); $Offset += 2
    $FileTime = [BitConverter]::ToInt64($Bytes, $Offset); $Offset += 8
    # GEA v2 widens both file sizes to 64 bits; the surrounding descriptor remains the same.
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
    # DataOffset is in the logical compressed stream, not an absolute file position.
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
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER VolumePath
    Optional directory containing GEA companion volumes. The source installer's directory is used
    by default. Companion names are always derived from the validated main-header pattern.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [AllowNull()][string]$VolumePath
  )

  Import-CreateInstallLzgeDecoder
  $Signature = [byte[]](0x47, 0x45, 0x41, 0x00)
  $File = Get-Item -LiteralPath $Path -Force
  $VolumeDirectory = if ([string]::IsNullOrWhiteSpace($VolumePath)) {
    $File.DirectoryName
  } else {
    $VolumeDirectoryItem = Get-Item -LiteralPath $VolumePath -Force
    if (-not $VolumeDirectoryItem.PSIsContainer) { throw "The GEA volume path '$VolumePath' is not a directory" }
    $VolumeDirectoryItem.FullName
  }
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # SETUP_TEMP is stored as a standalone GEA resource inside CreateInstall's PE. Reuse this
    # layout parser for that bounded resource by recognizing GEA at offset zero; ordinary setup
    # executables continue scanning only after their validated PE image.
    $Prefix = if ($Stream.Length -ge $Signature.Length) { Read-BinaryBytes -Stream $Stream -Offset 0 -Count $Signature.Length } else { [byte[]]::new(0) }
    $OverlayOffset = if ($Prefix.Length -eq $Signature.Length -and (Test-BinarySequence -Left $Prefix -Right $Signature)) { 0L } else { Get-PEOverlayOffset -Stream $Stream }
  } finally { $Stream.Dispose() }
  # Search only after the PE image and validate every GEA candidate through its complete size map;
  # compiled signature strings in the setup stub are not archive evidence.
  foreach ($ArchiveOffset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Signature -StartOffset $OverlayOffset -Maximum 16)) {
    $StrongCandidate = $false
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      if ($ArchiveOffset + 73 -gt $Stream.Length) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count 73
      $VolumeNumber = [BitConverter]::ToUInt16($Header, 4)
      $UniqueId = [BitConverter]::ToUInt32($Header, 6)
      $MajorVersion = $Header[10]
      $MinorVersion = $Header[11]
      $ArchiveProfile = @((Get-CreateInstallCatalogProfile -Section ArchiveProfiles) | Where-Object { [int]$_.MajorVersion -eq [int]$MajorVersion })
      if ($VolumeNumber -ne 0 -or $ArchiveProfile.Count -ne 1) { continue }
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
      if ($VolumeCount -lt 1 -or $VolumeCount -gt $Script:CreateInstallMaximumVolumes -or $HeaderSize -lt 74 -or $HeaderSize -gt $Script:CreateInstallMaximumHeaderBytes -or $InfoSize -gt $Script:CreateInstallMaximumInfoBytes) { continue }
      if ($ArchiveFileSize -le $ArchiveOffset -or $ArchiveFileSize -gt $File.Length -or $HeaderSize -gt $ArchiveFileSize - $ArchiveOffset) { continue }
      if ($SummarySize -lt 0 -or $MovedSize -gt $SummarySize) { continue }
      $MainDataLength = $ArchiveFileSize - $MovedSize - $HeaderSize - $ArchiveOffset
      if ($MainDataLength -lt 0) { continue }

      # Variable header data starts with the volume pattern, then optional password IDs, then the
      # compressed or stored file descriptor table.
      $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset $ArchiveOffset -Count ([int]$HeaderSize)
      $PatternData = Read-CreateInstallNullTerminatedString -Bytes $HeaderBytes -Offset 73
      if ($VolumeCount -gt 1 -and [string]::IsNullOrWhiteSpace($PatternData.Value)) { continue }
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
      # Require the catalog's final logical data extent to equal SummarySize before accepting the
      # candidate archive.
      $Entries = @(ConvertFrom-CreateInstallFileTable -Bytes $Metadata -MajorVersion $MajorVersion)
      if ($Entries.Count -eq 0 -or ($Entries[-1].DataOffset + [long]$Entries[-1].CompressedSize) -ne $SummarySize) { continue }
      $StrongCandidate = $true

      # The decoder exposes a single logical byte stream. It consists of ordinary bytes in the
      # main SFX, bytes in each companion after its ten-byte geavolume header, then moved bytes
      # stored immediately after the main variable header. Missing companions do not invalidate
      # the catalog, but extraction remains unavailable until every required segment is present.
      $DataSegments = [Collections.Generic.List[object]]::new([int]$VolumeCount + 1)
      $VolumeFiles = [Collections.Generic.List[object]]::new([int]$VolumeCount)
      $MissingVolumes = [Collections.Generic.List[object]]::new()
      $LogicalOffset = 0L
      $DataSegments.Add([pscustomobject]@{ Index = 0; LogicalOffset = $LogicalOffset; Length = [long]$MainDataLength; Path = $File.FullName; PhysicalOffset = [long]$ArchiveOffset + $HeaderSize + $MovedSize; Available = $true })
      $VolumeFiles.Add([pscustomobject]@{ Index = 0; VolumeNumber = 0; DisplayNumber = 1; Path = $File.FullName; ExpectedSize = [long]$ArchiveFileSize; ActualSize = [long]$File.Length; Available = $true })
      $LogicalOffset += $MainDataLength

      for ($VolumeIndex = 1; $VolumeIndex -lt $VolumeCount; $VolumeIndex++) {
        $ExpectedSize = if ($VolumeIndex -eq $VolumeCount - 1) { $LastVolumeSize } else { $VolumeSize }
        if ($ExpectedSize -lt 10) { throw "GEA companion volume $($VolumeIndex + 1) has an invalid declared size" }
        $VolumeName = Resolve-CreateInstallVolumeName -Pattern $PatternData.Value -Number ($VolumeIndex + 1)
        $CompanionPath = Resolve-CreateInstallVolumePath -Directory $VolumeDirectory -Name $VolumeName
        $Available = Test-Path -LiteralPath $CompanionPath -PathType Leaf
        $ActualSize = $null
        if ($Available) {
          $Companion = Get-Item -LiteralPath $CompanionPath -Force
          $ActualSize = [long]$Companion.Length
          if ($Companion.Length -lt $ExpectedSize) { throw "GEA companion volume '$CompanionPath' is shorter than its declared size" }
          $CompanionStream = [IO.File]::Open($Companion.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
          try { $CompanionHeader = Read-BinaryBytes -Stream $CompanionStream -Offset 0 -Count 10 } finally { $CompanionStream.Dispose() }
          if ([BitConverter]::ToUInt32($CompanionHeader, 0) -ne 0x00414547 -or [BitConverter]::ToUInt16($CompanionHeader, 4) -ne $VolumeIndex -or [BitConverter]::ToUInt32($CompanionHeader, 6) -ne $UniqueId) {
            throw "GEA companion volume '$CompanionPath' does not belong to this archive"
          }
        }
        $VolumeEvidence = [pscustomobject]@{ Index = $VolumeIndex; VolumeNumber = $VolumeIndex; DisplayNumber = $VolumeIndex + 1; Name = $VolumeName; Path = $CompanionPath; ExpectedSize = [long]$ExpectedSize; ActualSize = $ActualSize; Available = $Available }
        $VolumeFiles.Add($VolumeEvidence)
        if (-not $Available) { $MissingVolumes.Add($VolumeEvidence) }
        $SegmentLength = $ExpectedSize - 10
        $DataSegments.Add([pscustomobject]@{ Index = $VolumeIndex; LogicalOffset = $LogicalOffset; Length = [long]$SegmentLength; Path = $CompanionPath; PhysicalOffset = 10L; Available = $Available })
        $LogicalOffset += $SegmentLength
      }
      if ($MovedSize -gt 0) {
        $DataSegments.Add([pscustomobject]@{ Index = $VolumeCount; LogicalOffset = $LogicalOffset; Length = [long]$MovedSize; Path = $File.FullName; PhysicalOffset = [long]$ArchiveOffset + $HeaderSize; Available = $true })
        $LogicalOffset += $MovedSize
      }
      if ($LogicalOffset -ne $SummarySize) { throw 'The GEA physical volume map does not equal the declared logical data size' }

      return [pscustomobject]@{
        Path                = $File.FullName
        ArchiveOffset       = [long]$ArchiveOffset
        UniqueId            = [uint32]$UniqueId
        MajorVersion        = [byte]$MajorVersion
        MinorVersion        = [byte]$MinorVersion
        ArchiveProfile      = [string]$ArchiveProfile[0].Id
        Flags               = [uint32]$Flags
        VolumeCount         = [uint16]$VolumeCount
        HeaderSize          = [long]$HeaderSize
        SummarySize         = [long]$SummarySize
        InfoSize            = [long]$InfoSize
        ArchiveFileSize     = [long]$ArchiveFileSize
        VolumeSize          = [long]$VolumeSize
        LastVolumeSize      = [long]$LastVolumeSize
        MovedSize           = [long]$MovedSize
        OrdinaryDataLength  = [long]($SummarySize - $MovedSize)
        MainDataLength      = [long]$MainDataLength
        PasswordCount       = [int]$PasswordCount
        MemoryMegabytes     = [int]$Memory
        BlockSize           = [long]$BlockMultiplier * 0x40000
        SolidSize           = [long]$SolidMultiplier * 0x40000
        VolumePattern       = $PatternData.Value
        VolumeDirectory     = $VolumeDirectory
        VolumeFiles         = $VolumeFiles.ToArray()
        MissingVolumes      = $MissingVolumes.ToArray()
        AllVolumesAvailable = $MissingVolumes.Count -eq 0
        DataSegments        = $DataSegments.ToArray()
        Entries             = $Entries
      }
    } catch {
      # Once the complete catalog and logical size agree, this is no longer a coincidental magic
      # string. Preserve companion-volume and segment-integrity errors for actionable diagnostics.
      if ($StrongCandidate) { throw }
      # A structurally invalid candidate may be payload data containing GEA\0; continue scanning.
      continue
    } finally { $Stream.Dispose() }
  }
  throw 'The PE overlay does not contain a supported CreateInstall GEA archive'
}

function Get-CreateInstallBlockInfo {
  <#
  .SYNOPSIS
    Enumerate compression block headers for one GEA file entry
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER Entry
    Validated archive or catalog entry whose bounded content is read or exported.
  .PARAMETER Stream
    Optional caller-owned stream reused for block-header reads.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][psobject]$Layout, [Parameter(Mandatory)][psobject]$Entry, [AllowNull()][System.IO.Stream]$Stream)

  $LogicalOffset = [long]$Entry.DataOffset
  $CompressedRemaining = [long]$Entry.CompressedSize
  $OutputRemaining = [long]$Entry.Size
  $HeaderSize = if ($Layout.MajorVersion -ge 2) { 9 } else { 5 }
  # Walk each entry's complete block stream and verify that compressed and expanded totals converge
  # exactly at the declared file boundaries.
  while ($OutputRemaining -gt 0) {
    if ($CompressedRemaining -lt $HeaderSize) { throw "The GEA data for '$($Entry.FullName)' is truncated" }
    $Header = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $LogicalOffset -Count $HeaderSize -Stream $Stream
    $RawOrder = $Header[0]
    $StoredOrder = $RawOrder -band 0x7F
    $CompressedSize = if ($Layout.MajorVersion -ge 2) { [uint64][BitConverter]::ToUInt64($Header, 1) } else { [uint64][BitConverter]::ToUInt32($Header, 1) }
    if ($CompressedSize -gt [long]::MaxValue -or $CompressedSize -gt $CompressedRemaining - $HeaderSize) { throw "The GEA block for '$($Entry.FullName)' exceeds its file data range" }
    # The high nibble selects Store/LZGE/PPMd; the low nibble carries the compression-order mode.
    $CompressionType = $StoredOrder -shr 4
    $CompressionOrder = ($StoredOrder -band 0x0F) + 1
    $OutputSize = if ($CompressionType -eq 0) { [long]$CompressedSize } else { [Math]::Min([long]$Layout.BlockSize, $OutputRemaining) }
    if ($OutputSize -le 0 -or $OutputSize -gt $OutputRemaining) { throw "The GEA block for '$($Entry.FullName)' has an invalid output size" }
    [pscustomobject]@{
      RawOrder         = [byte]$RawOrder
      CompressionType  = [int]$CompressionType
      CompressionName  = switch ($CompressionType) { 0 { 'Store' } 1 { 'LZGE' } 2 { 'PPMd' } default { 'Unknown' } }
      CompressionOrder = [int]$CompressionOrder
      HeaderOffset     = [long]$LogicalOffset
      DataOffset       = [long]($LogicalOffset + $HeaderSize)
      CompressedSize   = [long]$CompressedSize
      OutputSize       = [long]$OutputSize
    }
    $LogicalOffset += $HeaderSize + [long]$CompressedSize
    $CompressedRemaining -= $HeaderSize + [long]$CompressedSize
    $OutputRemaining -= $OutputSize
  }
  if ($CompressedRemaining -ne 0) { throw "The GEA file '$($Entry.FullName)' has trailing compressed data" }
}

function Export-CreateInstallArchiveSelection {
  <#
  .SYNOPSIS
    Expand selected entries from an already parsed CreateInstall archive layout.
  .PARAMETER Layout
    Validated layout returned by Get-CreateInstallArchiveLayout. The source file is not reparsed.
  .PARAMETER DestinationPath
    Resolved extraction root beneath which archive-relative paths are written.
  .PARAMETER Name
    One or more exact names or wildcard patterns. An entry is selected when any pattern matches.
  .PARAMETER CollisionAction
    Behavior applied only when a selected output path collides.
  .PARAMETER MaximumExpandedBytes
    Maximum total expanded size of selected output files.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Layout,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Name,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Rename',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  Import-CreateInstallLzgeDecoder
  if ($Layout.PasswordCount -gt 0) { throw 'Password-protected CreateInstall GEA archives are intentionally unsupported' }
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
  $ExpandedBytes = 0L
  $SolidHistory = [byte[]]::new(0)
  $PpmdDecoder = $null
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  # Resolve all output paths before decoding. Solid compression requires walking every physical
  # entry through the last selected index even when only a small analysis subset is written.
  $SelectedEntries = [bool[]]::new($Layout.Entries.Count)
  $OutputTargets = [object[]]::new($Layout.Entries.Count)
  $FirstSelectedIndex = -1
  $LastSelectedIndex = -1
  for ($EntryIndex = 0; $EntryIndex -lt $Layout.Entries.Count; $EntryIndex++) {
    $EntryMatches = $false
    foreach ($Pattern in $Name) {
      if (Test-ExtractionPattern -Path $Layout.Entries[$EntryIndex].FullName -Pattern $Pattern) { $EntryMatches = $true; break }
    }
    if (-not $EntryMatches) { continue }
    $SelectedEntries[$EntryIndex] = $true
    $OutputTargets[$EntryIndex] = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Layout.Entries[$EntryIndex].FullName -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if ($FirstSelectedIndex -lt 0) { $FirstSelectedIndex = $EntryIndex }
    $LastSelectedIndex = $EntryIndex
  }
  if ($LastSelectedIndex -lt 0) { throw "No CreateInstall files matched '$($Name -join ', ')'" }

  $SourceStream = [IO.File]::Open($Layout.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # A solid entry only depends on the nearest preceding model reset, not the archive beginning.
    # Walk backward to a non-solid entry, stored block, or explicit compression order and start
    # there. Old builder archives otherwise decode hundreds of unrelated files for one selection.
    $FirstDecodeIndex = 0
    for ($EntryIndex = $FirstSelectedIndex; $EntryIndex -ge 0; $EntryIndex--) {
      $FirstBlock = @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Layout.Entries[$EntryIndex] -Stream $SourceStream)[0]
      if (-not $Layout.Entries[$EntryIndex].IsSolid -or $FirstBlock.CompressionType -eq 0 -or $FirstBlock.CompressionOrder -gt 1) { $FirstDecodeIndex = $EntryIndex; break }
    }
    for ($EntryIndex = $FirstDecodeIndex; $EntryIndex -le $LastSelectedIndex; $EntryIndex++) {
      $Entry = $Layout.Entries[$EntryIndex]
      if ($Entry.PasswordId -gt 0) { throw "The CreateInstall entry '$($Entry.FullName)' is password-protected and cannot be extracted" }
      if (-not $Entry.IsSolid) { $SolidHistory = [byte[]]::new(0) }
      $Selected = $SelectedEntries[$EntryIndex] -and $OutputTargets[$EntryIndex].ShouldWrite
      $OutputPath = $null
      if ($Selected) {
        $ExpandedBytes += [long]$Entry.Size
        if ($ExpandedBytes -gt $MaximumExpandedBytes) { throw 'CreateInstall extraction exceeds the configured output limit' }
        $OutputPath = $OutputTargets[$EntryIndex].Path
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      } else { $Output = $null }
      try {
        foreach ($Block in @(Get-CreateInstallBlockInfo -Layout $Layout -Entry $Entry -Stream $SourceStream)) {
          if ($Block.CompressedSize -gt $Script:CreateInstallMaximumBlockBytes -or $Block.OutputSize -gt $Script:CreateInstallMaximumBlockBytes) { throw "The CreateInstall block for '$($Entry.FullName)' exceeds the configured block limit" }
          $InputBytes = Read-CreateInstallArchiveLogicalRange -Layout $Layout -Offset $Block.DataOffset -Count ([int]$Block.CompressedSize) -Stream $SourceStream
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
            2 {
              if (-not $PpmdDecoder) {
                if ($Layout.MemoryMegabytes -le 0) { throw 'The GEA header declares no PPMd model memory' }
                Import-CreateInstallPpmdDecoder
                $PpmdDecoder = [SharpCompress.Compressors.PPMd.Gentee.GenteePpmdDecoder]::new([int]([uint32]$Layout.MemoryMegabytes * 1MB))
              }
              $InputStream = [IO.MemoryStream]::new($InputBytes, $false)
              try { $Decoded = $PpmdDecoder.DecodeBlock($InputStream, $InputBytes.Length, [int]$Block.OutputSize, $Block.CompressionOrder) } finally { $InputStream.Dispose() }
              $SolidHistory = [byte[]]::new(0)
            }
            default { throw "The CreateInstall entry '$($Entry.FullName)' uses an unknown compression method" }
          }
          if ($Output) { $Output.Write($Decoded, 0, $Decoded.Length) }
        }
      } catch {
        if ($Output) { $Output.Dispose(); $Output = $null }
        if ($OutputPath) { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue }
        throw
      } finally { if ($Output) { $Output.Dispose() } }
      if (-not $Selected) { continue }
      $OutputFile = Get-Item -LiteralPath $OutputPath -Force
      if ($OutputFile.Length -ne [long]$Entry.Size) {
        Remove-Item -LiteralPath $OutputFile.FullName -Force -ErrorAction SilentlyContinue
        throw "The extracted CreateInstall file '$($Entry.FullName)' has an unexpected length"
      }
      $GenteeCrc32 = [uint32]((Get-BinaryCrc32 -Path $OutputFile.FullName -MaximumBytes $MaximumExpandedBytes) -bxor [uint32]::MaxValue)
      if ($GenteeCrc32 -ne [uint32]$Entry.Crc32) {
        Remove-Item -LiteralPath $OutputFile.FullName -Force -ErrorAction SilentlyContinue
        throw "The extracted CreateInstall file '$($Entry.FullName)' failed its GEA CRC32 check"
      }
      $Result.Add($OutputFile)
    }
  } finally {
    if ($PpmdDecoder) { $PpmdDecoder.Dispose() }
    $SourceStream.Dispose()
  }
  return $Result.ToArray()
}

Export-ModuleMember -Function Import-CreateInstallPpmdDecoder, Read-CreateInstallNullTerminatedString, Resolve-CreateInstallVolumeName, Resolve-CreateInstallVolumePath, Read-CreateInstallArchiveLogicalRange, ConvertFrom-CreateInstallFileTable, Get-CreateInstallArchiveLayout, Get-CreateInstallBlockInfo, Export-CreateInstallArchiveSelection
