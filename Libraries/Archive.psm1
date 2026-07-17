# SPDX-License-Identifier: MIT
# Shared verbatim with Modules\InstallerParsers\Libraries\Archive.psm1.

function Get-InstallerArchive {
  <#
  .SYNOPSIS
    Open an archive from a path or seekable stream
  #>
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][System.IO.Stream]$Stream
  )
  Import-InstallerArchiveDependency
  if ($PSCmdlet.ParameterSetName -eq 'Path') {
    return [SharpCompress.Archives.ArchiveFactory]::Open((Get-Item -LiteralPath $Path -Force).FullName)
  }
  return [SharpCompress.Archives.ArchiveFactory]::Open($Stream)
}

function Open-InstallerArchiveRange {
  <#
  .SYNOPSIS
    Open an exact embedded archive range without materializing a temporary file
  .DESCRIPTION
    The returned context owns the archive, bounded range stream, and source file
    stream. Pass it to Close-InstallerArchiveRange when archive access is done.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Range')]$Range,
    [Parameter(Mandatory, ParameterSetName = 'Coordinates')][ValidateRange(0, [long]::MaxValue)][long]$Offset,
    [Parameter(Mandatory, ParameterSetName = 'Coordinates')][ValidateRange(1, [long]::MaxValue)][long]$Length
  )

  if ($PSCmdlet.ParameterSetName -eq 'Range') {
    $Offset = [long]$Range.Offset
    $Length = [long]$Range.Length
  }
  $Source = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $RangeStream = $null
  $Archive = $null
  try {
    $RangeStream = New-BoundedReadStream -Stream $Source -Offset $Offset -Length $Length -LeaveOpen
    $Archive = Get-InstallerArchive -Stream $RangeStream
    return [pscustomobject]@{
      Archive      = $Archive
      RangeStream  = $RangeStream
      SourceStream = $Source
      Offset       = $Offset
      Length       = $Length
    }
  } catch {
    if ($Archive) { $Archive.Dispose() }
    if ($RangeStream) { $RangeStream.Dispose() }
    $Source.Dispose()
    throw
  }
}

function Close-InstallerArchiveRange {
  <#
  .SYNOPSIS
    Dispose a context returned by Open-InstallerArchiveRange
  #>
  param ([Parameter(Mandatory, ValueFromPipeline)]$Context)
  process {
    try {
      if ($Context.Archive) { $Context.Archive.Dispose() }
    } finally {
      try {
        if ($Context.RangeStream) { $Context.RangeStream.Dispose() }
      } finally {
        if ($Context.SourceStream) { $Context.SourceStream.Dispose() }
      }
    }
  }
}

function Get-InstallerArchiveEntry {
  <#
  .SYNOPSIS
    Return normalized non-directory archive entries
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)]$Archive)

  foreach ($Entry in $Archive.Entries) {
    if ($Entry.IsDirectory) { continue }
    [pscustomobject]@{
      Key            = [string]$Entry.Key
      FullName       = [string]$Entry.Key
      Length         = [long]$Entry.Size
      Size           = [long]$Entry.Size
      CompressedSize = [long]$Entry.CompressedSize
      LinkTarget     = if ($Entry.PSObject.Properties.Name -contains 'LinkTarget') { [string]$Entry.LinkTarget } else { $null }
      NativeEntry    = $Entry
    }
  }
}

function Open-InstallerArchiveEntry {
  <#
  .SYNOPSIS
    Open the decompressed stream for a normalized or native archive entry
  #>
  [OutputType([System.IO.Stream])]
  param ([Parameter(Mandatory)]$Entry)
  $NativeEntry = if ($Entry.PSObject.Properties.Name -contains 'NativeEntry') { $Entry.NativeEntry } else { $Entry }
  return $NativeEntry.OpenEntryStream()
}

function Read-InstallerArchiveEntryBytes {
  <#
  .SYNOPSIS
    Read one archive entry into memory with a hard output limit
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)]$Entry,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes
  )
  $EntryStream = Open-InstallerArchiveEntry -Entry $Entry
  try {
    $Length = if ($Entry.PSObject.Properties.Name -contains 'Length' -and [long]$Entry.Length -ge 0) { [long]$Entry.Length } else { -1L }
    return , ([Dumplings.InstallerInfrastructure.BinaryIO]::ReadBounded($EntryStream, $MaximumBytes, $Length))
  } finally {
    $EntryStream.Dispose()
  }
}

function Read-InstallerArchiveEntryText {
  <#
  .SYNOPSIS
    Read one bounded archive entry as BOM-aware text
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]$Entry,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes,
    [Text.Encoding]$Encoding = [Text.UTF8Encoding]::new($false, $true)
  )
  $Bytes = Read-InstallerArchiveEntryBytes -Entry $Entry -MaximumBytes $MaximumBytes
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
    return [Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3)
  }
  if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
    return [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
  }
  return $Encoding.GetString($Bytes)
}

function Export-InstallerArchiveEntry {
  <#
  .SYNOPSIS
    Export one bounded archive entry to a validated destination
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)]$Entry,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  $Length = if ($Entry.PSObject.Properties.Name -contains 'Length') { [long]$Entry.Length } else { [long]$Entry.Size }
  if ($Length -gt $MaximumBytes) { throw "The archive entry exceeds the $MaximumBytes-byte output limit" }
  $Parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($DestinationPath))
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $EntryStream = Open-InstallerArchiveEntry -Entry $Entry
  $Output = [IO.File]::Open($DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    $CopyArguments = @{ Source = $EntryStream; Destination = $Output; MaximumBytes = $MaximumBytes }
    if ($Length -ge 0) { $CopyArguments.ExpectedBytes = $Length }
    $null = Copy-BoundedStream @CopyArguments
  } finally {
    $Output.Dispose()
    $EntryStream.Dispose()
  }
  return Get-Item -LiteralPath $DestinationPath
}

function Export-InstallerArchiveSelection {
  <#
  .SYNOPSIS
    Export selected entries with aggregate limits and safe path handling
  #>
  param (
    [Parameter(Mandatory)]$Archive,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 2147483648,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumEntries = 65536
  )
  $Files = [Collections.Generic.List[IO.FileInfo]]::new()
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ExpandedBytes = 0L
  $EntryCount = 0
  foreach ($Entry in Get-InstallerArchiveEntry -Archive $Archive) {
    if (-not (Test-ExtractionPattern -Path $Entry.FullName -Pattern $Name)) { continue }
    if (++$EntryCount -gt $MaximumEntries) { throw "The archive selection exceeds the $MaximumEntries-entry limit." }
    if (-not [string]::IsNullOrWhiteSpace($Entry.LinkTarget)) { throw "Archive links are not extracted: $($Entry.FullName)" }
    $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.FullName
    if (-not $Seen.Add($OutputPath)) { throw "The archive contains a duplicate output path: $($Entry.FullName)" }
    if (Test-Path -LiteralPath $OutputPath) { throw "The archive output already exists: $OutputPath" }
    $Remaining = $MaximumExpandedBytes - $ExpandedBytes
    if ($Remaining -le 0 -or $Entry.Length -gt $Remaining) { throw "The archive selection exceeds the $MaximumExpandedBytes-byte output limit." }
    $File = Export-InstallerArchiveEntry -Entry $Entry -DestinationPath $OutputPath -MaximumBytes $Remaining
    $ExpandedBytes += $File.Length
    $Files.Add($File)
  }
  [pscustomobject]@{ Files = @($Files); ExpandedBytes = $ExpandedBytes; EntryCount = $EntryCount }
}

function Export-InstallerArchiveRange {
  <#
  .SYNOPSIS
    Export an exact embedded archive range from a larger file
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$Length,
    [Parameter(Mandatory)][string]$DestinationPath
  )

  $Parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($DestinationPath))
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $Source = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $Destination = [IO.File]::Open($DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { Copy-BinaryStreamRange -Source $Source -Destination $Destination -Offset $Offset -Length $Length } finally { $Destination.Dispose(); $Source.Dispose() }
  return Get-Item -LiteralPath $DestinationPath -Force
}

function Get-EmbeddedZipArchiveRange {
  <#
  .SYNOPSIS
    Locate valid ZIP archives embedded in a larger file without trusting raw PK markers
  .PARAMETER Path
    The file containing one or more ZIP archives
  .PARAMETER MaximumArchives
    The maximum number of valid embedded archives to return
  .NOTES
    ZIP central-directory offsets are relative to the beginning of the ZIP
    archive.  The EOCD record therefore lets this function derive and validate
    the archive start even when a PE stub precedes it.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1, 64)][int]$MaximumArchives = 16
  )

  $File = Get-Item -LiteralPath $Path -Force
  $EocdSignature = [byte[]](0x50, 0x4B, 0x05, 0x06)
  $Ranges = [System.Collections.Generic.List[object]]::new()
  $SeenOffsets = [System.Collections.Generic.HashSet[long]]::new()
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    # EOCD comments are limited to UInt16, so every EOCD must end within this
    # bounded tail window. Larger self-extractors can still contain many ZIPs;
    # the reverse matcher finds their EOCD records without reading them all.
    $Offsets = @(Find-BinaryPattern -Path $File.FullName -Pattern $EocdSignature -Maximum 512 -Reverse)
    foreach ($EocdOffset in $Offsets) {
      if ($Ranges.Count -ge $MaximumArchives) { break }
      if ($EocdOffset + 22 -gt $Stream.Length) { continue }
      $Eocd = Read-BinaryBytes -Stream $Stream -Offset $EocdOffset -Count 22
      $CommentLength = [BitConverter]::ToUInt16($Eocd, 20)
      $ArchiveEnd = $EocdOffset + 22 + $CommentLength
      if ($ArchiveEnd -gt $Stream.Length) { continue }

      $CentralDirectorySize = [BitConverter]::ToUInt32($Eocd, 12)
      $CentralDirectoryOffset = [BitConverter]::ToUInt32($Eocd, 16)
      if ($CentralDirectorySize -eq 0 -or $CentralDirectoryOffset -gt $EocdOffset) { continue }
      $ArchiveStart = $EocdOffset - $CentralDirectorySize - $CentralDirectoryOffset
      $CentralDirectoryStart = $ArchiveStart + $CentralDirectoryOffset
      if ($ArchiveStart -lt 0 -or $CentralDirectoryStart -lt $ArchiveStart -or $CentralDirectoryStart + 4 -gt $EocdOffset) { continue }
      $CentralDirectory = Read-BinaryBytes -Stream $Stream -Offset $CentralDirectoryStart -Count 4
      if ($CentralDirectory[0] -ne 0x50 -or $CentralDirectory[1] -ne 0x4B -or $CentralDirectory[2] -ne 0x01 -or $CentralDirectory[3] -ne 0x02) { continue }
      if ($SeenOffsets.Add($ArchiveStart)) {
        $Ranges.Add([pscustomobject]@{
            Offset                 = [long]$ArchiveStart
            Length                 = [long]($ArchiveEnd - $ArchiveStart)
            EndOfCentralDirectory  = [long]$EocdOffset
            CentralDirectoryOffset = [long]$CentralDirectoryOffset
            CentralDirectorySize   = [long]$CentralDirectorySize
          })
      }
    }
  } finally {
    $Stream.Dispose()
  }
  return @($Ranges | Sort-Object Offset)
}

function Get-EmbeddedSevenZipArchiveRange {
  <#
  .SYNOPSIS
    Locate and validate 7z archives embedded in a larger file
  .PARAMETER Path
    The file containing one or more 7z archives
  .PARAMETER StartOffset
    The first file offset included in the bounded signature scan
  .PARAMETER MaximumArchives
    The maximum number of valid embedded archives to return
  .NOTES
    A 7z start header records the next-header offset and size relative to the
    32-byte signature header. These fields define an exact archive range; each
    candidate is then opened by SharpCompress to reject accidental signatures.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(0, [long]::MaxValue)][long]$StartOffset = 0,
    [ValidateRange(1, 64)][int]$MaximumArchives = 16,
    [ValidateRange(32, [long]::MaxValue)][long]$MaximumArchiveBytes = 4294967296
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($StartOffset -ge $File.Length) { return }
  $Signature = [byte[]](0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)
  $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    foreach ($Offset in @(Find-BinaryPattern -Path $File.FullName -Pattern $Signature -StartOffset $StartOffset -Maximum ($MaximumArchives * 8))) {
      if ($Offset + 32 -gt $Stream.Length) { continue }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count 32
      if ($Header[6] -ne 0) { continue }
      $NextHeaderOffset = [BitConverter]::ToUInt64($Header, 12)
      $NextHeaderSize = [BitConverter]::ToUInt64($Header, 20)
      if ($NextHeaderOffset -gt [long]::MaxValue -or $NextHeaderSize -gt [long]::MaxValue) { continue }
      $ArchiveLength = 32L + [long]$NextHeaderOffset + [long]$NextHeaderSize
      if ($ArchiveLength -lt 32 -or $ArchiveLength -gt $MaximumArchiveBytes -or $ArchiveLength -gt $Stream.Length - $Offset) { continue }

      $Archive = $null
      $ArchiveStream = $null
      try {
        $ArchiveStream = New-BoundedReadStream -Stream $Stream -Offset $Offset -Length $ArchiveLength -LeaveOpen
        $Archive = Get-InstallerArchive -Stream $ArchiveStream
        $EntryCount = @(Get-InstallerArchiveEntry -Archive $Archive).Count
        if ($EntryCount -eq 0) { continue }
        [pscustomobject]@{
          Offset           = [long]$Offset
          Length           = [long]$ArchiveLength
          MajorVersion     = [byte]$Header[6]
          MinorVersion     = [byte]$Header[7]
          EntryCount       = [int]$EntryCount
          NextHeaderOffset = [uint64]$NextHeaderOffset
          NextHeaderSize   = [uint64]$NextHeaderSize
        }
        if (--$MaximumArchives -le 0) { break }
      } catch {
        continue
      } finally {
        if ($Archive) { $Archive.Dispose() }
        if ($ArchiveStream) { $ArchiveStream.Dispose() }
      }
    }
  } finally {
    $Stream.Dispose()
  }
}

function Read-RarArchiveComment {
  <#
  .SYNOPSIS
    Read a bounded RAR archive comment, including the RAR4 CMT service entry
  .PARAMETER Path
    The path to a RAR archive whose marker starts at offset zero
  .PARAMETER MaximumBytes
    The maximum number of decompressed comment bytes
  .NOTES
    SharpCompress does not expose old RAR4 CMT service entries through its
    public archive-entry collection. This function uses the matching
    SharpCompress 0.39 RAR header and entry types from the bundled assembly.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1, 1048576)][int]$MaximumBytes = 262144
  )

  Import-InstallerArchiveDependency
  $Archive = Get-InstallerArchive -Path $Path
  $Stream = [IO.File]::OpenRead((Get-Item -LiteralPath $Path -Force).FullName)
  try {
    $Volume = @($Archive.Volumes)[0]
    if ($Volume.Comment) {
      if ([Text.Encoding]::UTF8.GetByteCount($Volume.Comment) -gt $MaximumBytes) { throw 'The RAR comment exceeds the configured output limit.' }
      return $Volume.Comment
    }

    $Assembly = [SharpCompress.Archives.ArchiveFactory].Assembly
    $FactoryType = $Assembly.GetType('SharpCompress.Common.Rar.Headers.RarHeaderFactory', $true)
    $StreamingModeType = $Assembly.GetType('SharpCompress.IO.StreamingMode', $true)
    $Options = [SharpCompress.Readers.ReaderOptions]::new()
    $Constructor = $FactoryType.GetConstructors([Reflection.BindingFlags]'Instance,Public,NonPublic')[0]
    $Factory = $Constructor.Invoke(@([Enum]::Parse($StreamingModeType, 'Seekable'), $Options))
    $ReadHeaders = $FactoryType.GetMethod('ReadHeaders', [Reflection.BindingFlags]'Instance,Public,NonPublic')
    $MarkHeader = $null
    $CommentHeader = $null

    foreach ($WrappedHeader in $ReadHeaders.Invoke($Factory, @($Stream))) {
      $Header = $WrappedHeader.PSObject.BaseObject
      if ($Header.GetType().Name -eq 'MarkHeader') {
        $MarkHeader = $Header
        continue
      }
      if ($Header.GetType().Name -ne 'FileHeader' -or $Header.HeaderType.ToString() -ne 'NewSub') { continue }

      $HeaderType = $Header.GetType()
      $CompressedSize = [long]$HeaderType.GetProperty('CompressedSize', [Reflection.BindingFlags]'Instance,Public,NonPublic').GetValue($Header)
      $UncompressedSize = [long]$HeaderType.GetProperty('UncompressedSize', [Reflection.BindingFlags]'Instance,Public,NonPublic').GetValue($Header)
      $DataOffset = [long]$HeaderType.GetProperty('DataStartPosition', [Reflection.BindingFlags]'Instance,Public,NonPublic').GetValue($Header)
      if ($UncompressedSize -gt $MaximumBytes) { throw 'The RAR comment exceeds the configured output limit.' }

      # RAR4 SFX comments use a NewSub entry named CMT. SharpCompress 0.39
      # does not retain that three-byte name, so validate it in the raw header.
      $HeaderSize = [int]$HeaderType.GetProperty('HeaderSize', [Reflection.BindingFlags]'Instance,Public,NonPublic').GetValue($Header)
      $HeaderStart = $DataOffset - $HeaderSize
      $HeaderBytes = Read-BinaryBytes -Stream $Stream -Offset $HeaderStart -Count $HeaderSize
      if ([Text.Encoding]::ASCII.GetString($HeaderBytes) -notmatch 'CMT') { continue }
      if ($CompressedSize -lt 0 -or $DataOffset + $CompressedSize -gt $Stream.Length) { throw 'The RAR comment data range is invalid.' }
      $CommentHeader = $Header
      break
    }

    if (-not $MarkHeader -or -not $CommentHeader) { return $null }
    $NativeVolume = $Volume.PSObject.BaseObject
    $CreateFilePart = $NativeVolume.GetType().BaseType.GetMethod('CreateFilePart', [Reflection.BindingFlags]'Instance,Public,NonPublic')
    $FilePart = $CreateFilePart.Invoke($NativeVolume, [object[]]@($MarkHeader, $CommentHeader))
    $PartType = $Assembly.GetType('SharpCompress.Common.Rar.RarFilePart', $true)
    $PartListType = [System.Collections.Generic.List``1].MakeGenericType($PartType)
    $Parts = [Activator]::CreateInstance($PartListType)
    $Parts.Add($FilePart)
    $EntryType = $Assembly.GetType('SharpCompress.Archives.Rar.RarArchiveEntry', $true)
    $EntryConstructor = $EntryType.GetConstructors([Reflection.BindingFlags]'Instance,Public,NonPublic')[0]
    $CommentEntry = $EntryConstructor.Invoke([object[]]@($Archive.PSObject.BaseObject, $Parts, $Options))
    $CommentStream = $CommentEntry.OpenEntryStream()
    try {
      $Buffer = [byte[]]::new($MaximumBytes + 1)
      $ReadTotal = 0
      while (($Read = $CommentStream.Read($Buffer, $ReadTotal, $Buffer.Length - $ReadTotal)) -gt 0) {
        $ReadTotal += $Read
        if ($ReadTotal -gt $MaximumBytes) { throw 'The RAR comment exceeds the configured output limit.' }
      }
      $Encoding = if ($ReadTotal -ge 2 -and $Buffer[0] -eq 0xFF -and $Buffer[1] -eq 0xFE) { [Text.Encoding]::Unicode } else { [Text.Encoding]::GetEncoding(1252) }
      return $Encoding.GetString($Buffer, 0, $ReadTotal).TrimEnd([char]0)
    } finally {
      $CommentStream.Dispose()
    }
  } finally {
    $Stream.Dispose()
    $Archive.Dispose()
  }
}

Export-ModuleMember -Function Get-InstallerArchive, Open-InstallerArchiveRange, Close-InstallerArchiveRange, Get-InstallerArchiveEntry, Open-InstallerArchiveEntry, Read-InstallerArchiveEntryBytes, Read-InstallerArchiveEntryText, Export-InstallerArchiveEntry, Export-InstallerArchiveSelection, Export-InstallerArchiveRange, Get-EmbeddedZipArchiveRange, Get-EmbeddedSevenZipArchiveRange, Read-RarArchiveComment
