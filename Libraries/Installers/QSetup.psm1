# SPDX-License-Identifier: Apache-2.0
# Static QSetup parser. QSetup EXE packages store length-prefixed zlib records
# after the PE image; Setup.txt contains explicit project and ARP directives.
# Binary structures consumed here (overlay-relative, LE integers):
#
#   releases 1-2: records begin directly at the PE overlay
#   releases 3-5: Version:u32, "||", PreambleLength:u32, UTF-8 preamble
#   releases 7+:  Version:u32, Format:u8, PreambleLength:u32, UTF-8 preamble
#   split media:  [DescriptorLength:u32][|source|file|mode|secret|length?|]
#   records:    [CompressedLength:u32 LE][zlib -> |Name[*]?|Stamp| + NUL + bytes]*
#   footer 1-2: RecordCount:u32, OverlayOffset:u32, Magic:0x4A3B2C1D
#   footer 3+:  Version:u32, OverlayOffset:u32, RecordCount:u32,
#               Magic:0x4A3B2C1D, generation fields, FooterLength:u32
#   signature:  optional zero alignment followed by the PE certificate table
#   span media:  the main EXE followed byte-for-byte by .001, .002, ... parts
#
# Every record advances by exactly 4 + CompressedLength. Setup.txt is interpreted
# only from a complete framed record. The footer identifies the record boundary,
# so its bytes and an Authenticode certificate are never offered to zlib. Preamble,
# count, header, input/output, next offset, and extraction path limits reject
# malformed packages.
#
# Format references:
# - https://www.pantaray.com/execute.html
# - https://www.pantaray.com/execution_cmd.html
# - https://www.panta-ray.com/pdf/qsetup_manual.pdf
# - https://web.archive.org/web/*/https://www.panta-ray.com/qstp.exe

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:QSetupMaximumRecordBytes = 2147483648
$Script:QSetupMaximumConfigurationBytes = 16777216
$Script:QSetupMaximumRecords = 100000
$Script:QSetupMaximumFooterBytes = 1048576
$Script:QSetupMaximumCertificateBytes = 67108864
$Script:QSetupMaximumDescriptorBytes = 1048576
$Script:QSetupMaximumPayloadAnalysisBytes = 536870912
$Script:QSetupFooterMagic = [uint32]0x4A3B2C1D
$Script:QSetupFooterMarker = [uint32]1234
$Script:QSetupFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'QSetupFormatCatalog.psd1')

function Test-QSetupZlibHeader {
  <#
  .SYNOPSIS
    Test the two-byte RFC 1950 header used by a QSetup record.
  .PARAMETER Header
    Two bytes beginning at the compressed member.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][ValidateCount(2, 2)][byte[]]$Header)

  $HeaderValue = ([int]$Header[0] -shl 8) -bor $Header[1]
  return ($Header[0] -band 0x0F) -eq 8 -and ($Header[0] -shr 4) -le 7 -and $HeaderValue % 31 -eq 0
}

function Test-QSetupPreambleText {
  <#
  .SYNOPSIS
    Validate the pipe-delimited update preamble used by QSetup 3 and later.
  .PARAMETER Value
    UTF-8 preamble text decoded from the overlay.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

  if ($Value.Length -gt 1048576 -or -not $Value.StartsWith('|') -or -not $Value.EndsWith('|')) { return $false }
  $Fields = $Value.Split('|')
  return $Fields.Count -ge 5 -and @($Fields | Where-Object { $_ -match '(?i)\.exe$' }).Count -gt 0
}

function Get-QSetupRecordStartOffset {
  <#
  .SYNOPSIS
    Validate the QSetup overlay preamble and return its first record offset
  .PARAMETER Path
    Resolved path to the installer. The helper opens and closes the file.
  .PARAMETER Stream
    Seekable caller-owned installer stream. The helper does not dispose it.
  .PARAMETER PackageOffset
    Absolute offset of a raw QSetup package stream. Omit it to locate the PE overlay.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [ValidateRange(-1, [long]::MaxValue)][long]$PackageOffset = -1
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  try {
    $OverlayOffset = if ($PackageOffset -ge 0) { $PackageOffset } else { Get-PEOverlayOffset -Stream $Stream }
    if (($PackageOffset -lt 0 -and $OverlayOffset -le 0) -or $OverlayOffset -lt 0 -or $OverlayOffset + 6 -gt $Stream.Length) { throw 'The QSetup PE has no valid package overlay' }
    $Prefix = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count ([int][Math]::Min(16, $Stream.Length - $OverlayOffset))

    # QSetup 1 and 2 place the first compressed record directly at the overlay.
    # Validate both its length and RFC 1950 header before selecting this route.
    $DirectLength = [uint32][BitConverter]::ToUInt32($Prefix, 0)
    if ($DirectLength -gt 2 -and $DirectLength -le $Script:QSetupMaximumRecordBytes -and $DirectLength -le $Stream.Length - $OverlayOffset - 4 -and
      (Test-QSetupZlibHeader -Header $Prefix[4..5])) {
      return [pscustomobject][ordered]@{
        OverlayOffset     = [long]$OverlayOffset
        RecordStartOffset = [long]$OverlayOffset
        FormatVersion     = $null
        CompressionFormat = 2
        Preamble          = $null
        StructuralRoute   = 'DirectRecords'
      }
    }

    $Version = [uint32](Read-BinaryInteger -Stream $Stream -Offset $OverlayOffset -Size 4)
    if ($Version -eq 0) { throw 'The QSetup overlay preamble is invalid' }

    # QSetup 3 through 5 insert a literal two-byte || marker before the length.
    if ($Prefix[4] -eq 0x7C -and $Prefix[5] -eq 0x7C) {
      if ($OverlayOffset + 10 -gt $Stream.Length) { throw 'The QSetup double-pipe preamble is truncated' }
      $PreambleLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 6) -Size 4)
      $PreambleOffset = $OverlayOffset + 10
      $Route = 'DoublePipePreamble'
      $Format = $null
    } else {
      # QSetup 7 and later carry an explicit compression-format byte.
      if ($OverlayOffset + 9 -gt $Stream.Length) { throw 'The QSetup versioned preamble is truncated' }
      $Format = [byte](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 4) -Size 1)
      $PreambleLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($OverlayOffset + 5) -Size 4)
      $PreambleOffset = $OverlayOffset + 9
      $Route = 'VersionedPreamble'
    }

    if ($PreambleLength -eq 0 -or $PreambleLength -gt 1048576 -or $PreambleLength -gt $Stream.Length - $PreambleOffset) {
      throw 'The QSetup overlay preamble is invalid'
    }
    $Preamble = [Text.Encoding]::UTF8.GetString((Read-BinaryBytes -Stream $Stream -Offset $PreambleOffset -Count ([int]$PreambleLength)))
    if (-not (Test-QSetupPreambleText -Value $Preamble)) { throw 'The QSetup overlay preamble marker is invalid' }
    [pscustomobject][ordered]@{
      OverlayOffset     = [long]$OverlayOffset
      RecordStartOffset = [long]($PreambleOffset + $PreambleLength)
      FormatVersion     = $Version
      CompressionFormat = $Format
      Preamble          = $Preamble
      StructuralRoute   = $Route
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }
}

function Read-QSetupSplitDescriptor {
  <#
  .SYNOPSIS
    Decode the bounded split-media descriptor that precedes QSetup records.
  .PARAMETER Stream
    Seekable caller-owned stream. Its position is not significant and is not retained.
  .PARAMETER Offset
    Absolute offset of DescriptorLength in the current package stream.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset
  )

  if ($Offset + 5 -gt $Stream.Length) { return $null }
  $Length = [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
  if ($Length -eq 0 -or $Length -gt $Script:QSetupMaximumDescriptorBytes -or $Length -gt $Stream.Length - $Offset - 4) { return $null }
  if ((Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 1) -ne 0x7C) { return $null }

  $Text = [Text.Encoding]::UTF8.GetString((Read-BinaryBytes -Stream $Stream -Offset ($Offset + 4) -Count ([int]$Length)))
  $Fields = $Text.Split('|')
  if ($Fields.Count -notin @(6, 7) -or $Fields[0] -ne '' -or $Fields[-1] -ne '' -or
    [string]::IsNullOrWhiteSpace($Fields[2]) -or [IO.Path]::GetFileName($Fields[2]) -cne $Fields[2] -or
    $Fields[3] -notmatch '^\d+$' -or $Fields[4] -notmatch '^[a-z]{16,128}$' -or ($Fields.Count -eq 7 -and $Fields[5] -notmatch '^\d+$')) {
    throw 'The QSetup split-media descriptor is malformed.'
  }

  return [pscustomobject][ordered]@{
    Offset          = $Offset
    Length          = [long](4 + $Length)
    SourceDirectory = $Fields[1]
    CompanionName   = $Fields[2]
    Mode            = [uint32]$Fields[3]
    Secret          = $Fields[4]
    DeclaredLength  = $Fields.Count -eq 7 ? [long]$Fields[5] : $null
    NextOffset      = [long]($Offset + 4 + $Length)
    RawValue        = $Text
  }
}

function Read-QSetupRecord {
  <#
  .SYNOPSIS
    Read one bounded QSetup zlib record header and optional content
  .PARAMETER Path
    Resolved path to the installer. The helper opens and closes the file.
  .PARAMETER Stream
    Seekable caller-owned installer stream. The helper does not dispose it.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER ReadContent
    Controls whether bounded entry content is decoded in addition to catalog metadata.
  .PARAMETER MaximumContentBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER EndOffset
    Exclusive absolute boundary of the record table. The default uses the physical file length for compatibility with direct calls.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [switch]$ReadContent,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumContentBytes = $Script:QSetupMaximumConfigurationBytes,
    [ValidateRange(-1, [long]::MaxValue)][long]$EndOffset = -1
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  try {
    $RecordTableEnd = if ($EndOffset -ge 0) { $EndOffset } else { $Stream.Length }
    if ($RecordTableEnd -gt $Stream.Length) { throw 'The QSetup record boundary exceeds the file length' }
    if ($Offset -lt 0 -or $Offset + 4 -gt $RecordTableEnd) { throw 'The QSetup record length is truncated' }
    # Each record is independently framed by a compressed length, so malformed
    # data cannot make the decoder consume the next record.
    $CompressedLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
    if ($CompressedLength -eq 0 -or $CompressedLength -gt $Script:QSetupMaximumRecordBytes) { throw 'The QSetup record length is invalid' }
    if ($CompressedLength -gt $RecordTableEnd - $Offset - 4) { throw 'The QSetup record data is truncated' }
    $CompressedRange = New-BoundedReadStream -Stream $Stream -Offset ($Offset + 4) -Length $CompressedLength -LeaveOpen
    $Decoder = New-InstallerDecompressionStream -Algorithm Zlib -Stream $CompressedRange -LeaveOpen
    try {
      # Decode only through the third pipe delimiter to enumerate a record. The
      # potentially large body is materialized only when the caller requests it.
      $HeaderBytes = [System.Collections.Generic.List[byte]]::new()
      $PipeCount = 0
      while ($HeaderBytes.Count -lt 4096 -and $PipeCount -lt 3) {
        $Value = $Decoder.ReadByte()
        if ($Value -lt 0) { break }
        $HeaderBytes.Add([byte]$Value)
        if ($Value -eq 0x7C) { $PipeCount++ }
      }
      $Header = [Text.Encoding]::ASCII.GetString($HeaderBytes.ToArray())
      $Match = [regex]::Match($Header, '^\|(?<Name>[^|*]+)(?<Required>\*)?\|(?<Stamp>\d+)\|$')
      if (-not $Match.Success) { throw 'The QSetup record header is invalid' }
      # Every verified generation terminates catalog metadata with one NUL byte.
      # It is record framing and must not become the first byte of the payload.
      if ($Decoder.ReadByte() -ne 0) { throw 'The QSetup record body marker is invalid' }

      $Content = $null
      $ContentLength = $null
      if ($ReadContent) {
        # Setup.txt and other requested bodies are accumulated under an explicit
        # expanded-size limit to reject zlib bombs deterministically.
        $Output = [IO.MemoryStream]::new()
        try {
          $Buffer = [byte[]]::new(1048576)
          $Written = 0L
          while (($Read = $Decoder.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
            $Written += $Read
            if ($Written -gt $MaximumContentBytes) { throw "The QSetup record exceeds the $MaximumContentBytes-byte content limit" }
            $Output.Write($Buffer, 0, $Read)
          }
          $Content = $Output.ToArray()
          $ContentLength = $Written
        } finally { $Output.Dispose() }
      }
      [pscustomobject]@{
        Name             = $Match.Groups['Name'].Value
        Required         = $Match.Groups['Required'].Success
        Stamp            = $Match.Groups['Stamp'].Value
        Offset           = [long]$Offset
        CompressedLength = [long]$CompressedLength
        NextOffset       = [long]($Offset + 4 + $CompressedLength)
        ContentLength    = $ContentLength
        Content          = $Content
      }
    } finally { $Decoder.Dispose(); $CompressedRange.Dispose() }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() }
  }
}

function Get-QSetupTrailingCertificateInfo {
  <#
  .SYNOPSIS
    Validate optional alignment and WIN_CERTIFICATE records after a QSetup footer.
  .PARAMETER Stream
    Seekable caller-owned installer stream positioned by absolute offsets.
  .PARAMETER Offset
    Absolute byte immediately after the candidate footer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset
  )

  for ($PaddingLength = 0; $PaddingLength -le 7; $PaddingLength++) {
    $CertificateOffset = $Offset + $PaddingLength
    if ($CertificateOffset -gt $Stream.Length) { break }
    if ($PaddingLength -gt 0) {
      $Padding = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $PaddingLength
      if (@($Padding | Where-Object { $_ -ne 0 }).Count -gt 0) { break }
    }

    if ($CertificateOffset -eq $Stream.Length) {
      return [pscustomobject][ordered]@{ IsValid = $true; Offset = 0L; Size = 0L; AlignmentPadding = $PaddingLength; EntryCount = 0 }
    }
    $CertificateSize = $Stream.Length - $CertificateOffset
    if ($CertificateSize -lt 8 -or $CertificateSize -gt $Script:QSetupMaximumCertificateBytes) { continue }

    # A certificate table can contain multiple aligned WIN_CERTIFICATE records.
    # Validate every record to avoid mistaking arbitrary trailer bytes for a signature.
    $EntryOffset = $CertificateOffset
    $EntryCount = 0
    $Valid = $true
    while ($EntryOffset -lt $Stream.Length) {
      if ($Stream.Length - $EntryOffset -lt 8) { $Valid = $false; break }
      $EntryLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset $EntryOffset -Size 4)
      $Revision = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($EntryOffset + 4) -Size 2)
      $CertificateType = [uint16](Read-BinaryInteger -Stream $Stream -Offset ($EntryOffset + 6) -Size 2)
      if ($EntryLength -lt 8 -or $EntryLength -gt $Stream.Length - $EntryOffset -or $Revision -notin @(0x0100, 0x0200) -or $CertificateType -ne 2) {
        $Valid = $false
        break
      }
      $EntryOffset += (($EntryLength + 7) -band -bnot 7)
      $EntryCount++
    }
    if ($Valid -and $EntryOffset -eq $Stream.Length) {
      return [pscustomobject][ordered]@{
        IsValid          = $true
        Offset           = [long]$CertificateOffset
        Size             = [long]$CertificateSize
        AlignmentPadding = [int]$PaddingLength
        EntryCount       = [int]$EntryCount
      }
    }
  }

  return [pscustomobject][ordered]@{ IsValid = $false; Offset = 0L; Size = 0L; AlignmentPadding = 0; EntryCount = 0 }
}

function Get-QSetupTerminalInfo {
  <#
  .SYNOPSIS
    Validate the QSetup footer and optional Authenticode trailer at a record boundary.
  .PARAMETER Stream
    Seekable caller-owned installer stream.
  .PARAMETER Offset
    Absolute offset where the next record or footer would begin.
  .PARAMETER Preamble
    Validated preamble and overlay evidence.
  .PARAMETER RecordCount
    Number of structurally valid records preceding the candidate footer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][psobject]$Preamble,
    [Parameter(Mandatory)][ValidateRange(0, 100000)][int]$RecordCount
  )

  if ($Offset -eq $Stream.Length) {
    return [pscustomobject][ordered]@{ IsValid = $true; DataEndOffset = $Offset; Footer = $null; Certificate = $null; StructuralRoute = 'Footerless' }
  }

  # QSetup 3 and later use a 74-byte footer. Releases before the modern marker
  # retain opaque generation fields at +0x10, so those bytes are reported but
  # never assigned invented semantics.
  if ($Stream.Length - $Offset -ge 74) {
    $FooterLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 70) -Size 4)
    $FooterVersion = [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
    $RecordedOverlayOffset = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4)
    $DeclaredRecordCount = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 8) -Size 4)
    $Magic = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 12) -Size 4)
    if ($FooterLength -eq 74 -and $FooterVersion -gt 0 -and $RecordedOverlayOffset -eq $Preamble.OverlayOffset -and
      $DeclaredRecordCount -eq $RecordCount -and $Magic -eq $Script:QSetupFooterMagic) {
      $Trailer = Get-QSetupTrailingCertificateInfo -Stream $Stream -Offset ($Offset + 74)
      if ($Trailer.IsValid) {
        $Marker = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 16) -Size 4)
        $Route = $Marker -eq $Script:QSetupFooterMarker ? 'Modern74' : 'Legacy74'
        return [pscustomobject][ordered]@{
          IsValid         = $true
          DataEndOffset   = [long]$Offset
          StructuralRoute = $Route
          Footer          = [pscustomobject][ordered]@{
            RouteId             = $Route
            Offset              = [long]$Offset
            Length              = 74L
            Version             = $FooterVersion
            OverlayOffset       = [long]$RecordedOverlayOffset
            DeclaredRecordCount = [int]$DeclaredRecordCount
            Magic               = ('0x{0:X8}' -f $Magic)
            Marker              = $Marker -eq $Script:QSetupFooterMarker ? $Marker : $null
            ObservedField10     = $Marker -eq $Script:QSetupFooterMarker ? $null : ('0x{0:X8}' -f $Marker)
          }
          Certificate     = $Trailer.Offset -gt 0 ? [pscustomobject][ordered]@{ Offset = $Trailer.Offset; Size = $Trailer.Size; AlignmentPadding = $Trailer.AlignmentPadding; EntryCount = $Trailer.EntryCount } : $null
        }
      }
    }
  }

  # QSetup 1 and 2 end with only record count, overlay offset, and magic.
  if ($Stream.Length - $Offset -ge 12) {
    $DeclaredRecordCount = [uint32](Read-BinaryInteger -Stream $Stream -Offset $Offset -Size 4)
    $RecordedOverlayOffset = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 4) -Size 4)
    $Magic = [uint32](Read-BinaryInteger -Stream $Stream -Offset ($Offset + 8) -Size 4)
    if ($DeclaredRecordCount -eq $RecordCount -and $RecordedOverlayOffset -eq $Preamble.OverlayOffset -and $Magic -eq $Script:QSetupFooterMagic) {
      $Trailer = Get-QSetupTrailingCertificateInfo -Stream $Stream -Offset ($Offset + 12)
      if ($Trailer.IsValid) {
        return [pscustomobject][ordered]@{
          IsValid         = $true
          DataEndOffset   = [long]$Offset
          StructuralRoute = 'Compact12'
          Footer          = [pscustomobject][ordered]@{
            RouteId             = 'Compact12'
            Offset              = [long]$Offset
            Length              = 12L
            Version             = $null
            OverlayOffset       = [long]$RecordedOverlayOffset
            DeclaredRecordCount = [int]$DeclaredRecordCount
            Magic               = ('0x{0:X8}' -f $Magic)
            Marker              = $null
            ObservedField10     = $null
          }
          Certificate     = $Trailer.Offset -gt 0 ? [pscustomobject][ordered]@{ Offset = $Trailer.Offset; Size = $Trailer.Size; AlignmentPadding = $Trailer.AlignmentPadding; EntryCount = $Trailer.EntryCount } : $null
        }
      }
    }
  }

  return [pscustomobject][ordered]@{ IsValid = $false; DataEndOffset = [long]$Stream.Length; Footer = $null; Certificate = $null; StructuralRoute = 'Unknown' }
}

function Get-QSetupLayout {
  <#
  .SYNOPSIS
    Enumerate bounded QSetup record headers without expanding payload bodies
  .PARAMETER Path
    Resolved path to the installer. The helper opens and closes the file.
  .PARAMETER Stream
    Seekable caller-owned installer stream. Its position is preserved.
  .PARAMETER MaximumRecords
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  .PARAMETER PackageOffset
    Absolute offset of a raw package stream. Use zero for a split companion without a PE stub.
  #>
  [OutputType([pscustomobject])]
  [CmdletBinding(DefaultParameterSetName = 'Path')]
  param (
    [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Stream')][IO.Stream]$Stream,
    [ValidateRange(1, 100000)][int]$MaximumRecords = $Script:QSetupMaximumRecords,
    [ValidateRange(-1, [long]::MaxValue)][long]$PackageOffset = -1
  )

  $OwnsStream = $PSCmdlet.ParameterSetName -eq 'Path'
  if ($OwnsStream) {
    $File = Get-Item -LiteralPath $Path -Force
    $Stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
  if (-not $Stream.CanRead -or -not $Stream.CanSeek) { throw 'QSetup layout parsing requires a readable, seekable stream.' }
  $OriginalPosition = $Stream.Position
  try {
    $Preamble = if ($PackageOffset -ge 0) {
      Get-QSetupRecordStartOffset -Stream $Stream -PackageOffset $PackageOffset
    } else {
      Get-QSetupRecordStartOffset -Stream $Stream
    }
    $Records = [System.Collections.Generic.List[object]]::new()
    $Diagnostics = [System.Collections.Generic.List[object]]::new()
    $Offset = $Preamble.RecordStartOffset
    # Split media inserts one stored descriptor before the ordinary zlib table.
    # A zlib member cannot begin with '|', so this test is unambiguous.
    $SplitDescriptor = Read-QSetupSplitDescriptor -Stream $Stream -Offset $Offset
    if ($SplitDescriptor) { $Offset = $SplitDescriptor.NextOffset }
    $RecordFailure = $null

    # Records are physically adjacent. A failed record decode is not immediately
    # corruption because every known generation places its footer at that point.
    while ($Offset + 4 -le $Stream.Length -and $Records.Count -lt $MaximumRecords) {
      try {
        $Record = Read-QSetupRecord -Stream $Stream -Offset $Offset -EndOffset $Stream.Length
      } catch {
        $RecordFailure = $_.Exception.Message
        break
      }
      $Records.Add($Record)
      if ($Record.NextOffset -le $Offset) {
        $RecordFailure = 'The QSetup record table does not advance.'
        break
      }
      $Offset = $Record.NextOffset
    }

    $Terminal = Get-QSetupTerminalInfo -Stream $Stream -Offset $Offset -Preamble $Preamble -RecordCount $Records.Count
    $Complete = [bool]$Terminal.IsValid
    if ($Records.Count -eq $MaximumRecords -and -not $Complete) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.RecordTable.CountLimit' -Source QSetup -Message "The QSetup record count exceeds the $MaximumRecords-record limit." -Kind Invalid -Areas Extraction -AffectedFields ExtractedFiles))
    } elseif (-not $Complete) {
      $Reason = [string]::IsNullOrWhiteSpace($RecordFailure) ? 'The record table has unrecognized trailing data.' : $RecordFailure
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.RecordTable.Incomplete' -Source QSetup -Message $Reason -Kind Incomplete -Areas Extraction, Metadata -AffectedFields ExtractedFiles))
    }

    $Generation = switch ($Preamble.StructuralRoute) {
      'DirectRecords' { 'Legacy1-2' }
      'DoublePipePreamble' { 'Legacy3-6' }
      'VersionedPreamble' { $Terminal.StructuralRoute -eq 'Modern74' ? 'Modern12' : 'Legacy7-11' }
      default { 'Unknown' }
    }
    $StructuralRoutes = [Collections.Generic.List[string]]::new()
    $StructuralRoutes.Add($Preamble.StructuralRoute)
    if ($SplitDescriptor) { $StructuralRoutes.Add('SplitDescriptor') }
    $StructuralRoutes.Add('Record/Zlib')
    $StructuralRoutes.Add($Terminal.StructuralRoute)
    [pscustomobject][ordered]@{
      Preamble         = $Preamble
      Records          = $Records.ToArray()
      Complete         = $Complete
      ParsedEndOffset  = [long]$Offset
      DataEndOffset    = [long]$Terminal.DataEndOffset
      Footer           = $Terminal.Footer
      Certificate      = $Terminal.Certificate
      SplitDescriptor  = $SplitDescriptor
      FormatGeneration = $Generation
      StructuralRoutes = $StructuralRoutes.ToArray()
      Diagnostics      = [object[]]$Diagnostics.ToArray()
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
  }
}

function ConvertFrom-QSetupDirectiveText {
  <#
  .SYNOPSIS
    Parse literal SET_* directives from QSetup Setup.txt
  .PARAMETER Content
    Raw text to parse as format metadata without executing embedded commands.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][string]$Content)

  $Result = @{}
  foreach ($Record in Get-QSetupDirectiveRecord -Content $Content) {
    $Name = $Record.Name
    $Value = $Record.Value
    if (-not $Result.ContainsKey($Name)) { $Result[$Name] = [System.Collections.Generic.List[object]]::new() }
    $Result[$Name].Add($Value)
  }
  return $Result
}

function Get-QSetupDirectiveRecord {
  <#
  .SYNOPSIS
    Parse literal Setup.txt directives while preserving source order.
  .PARAMETER Content
    UTF-8 Setup.txt content. Dynamic expressions are retained as literal values.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][string]$Content)

  $Result = [Collections.Generic.List[object]]::new()
  $LineNumber = 0
  foreach ($Line in ($Content.TrimStart([char]0, [char]0xFEFF) -split "`r?`n")) {
    $LineNumber++
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith('//')) { continue }
    $Match = [regex]::Match($Trimmed, '^(?<Name>SET_[A-Z0-9_]+)(?:\((?<Value>.*)\))?;?$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $Match.Success) { continue }
    $Result.Add([pscustomobject][ordered]@{
        Name       = $Match.Groups['Name'].Value.ToUpperInvariant()
        Value      = $Match.Groups['Value'].Success ? $Match.Groups['Value'].Value : $true
        LineNumber = $LineNumber
      })
  }
  return $Result.ToArray()
}

function Get-QSetupDirectiveValue {
  <#
  .SYNOPSIS
    Return the first literal value for a parsed QSetup directive
  .PARAMETER Directive
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  param ([Parameter(Mandatory)][hashtable]$Directive, [Parameter(Mandatory)][string]$Name)
  if (-not $Directive.ContainsKey($Name)) { return $null }
  return @($Directive[$Name])[0]
}

function Get-QSetupDirectiveTextValue {
  <#
  .SYNOPSIS
    Return the first non-empty literal value, optionally falling back to another directive.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  .PARAMETER Name
    Primary directive name.
  .PARAMETER FallbackName
    Directive used when the primary value is absent or empty.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][hashtable]$Directive,
    [Parameter(Mandatory)][string]$Name,
    [string]$FallbackName
  )

  $Value = Get-QSetupDirectiveValue -Directive $Directive -Name $Name
  if (-not [string]::IsNullOrWhiteSpace([string]$Value)) { return [string]$Value }
  if ($FallbackName) {
    $Value = Get-QSetupDirectiveValue -Directive $Directive -Name $FallbackName
    if (-not [string]::IsNullOrWhiteSpace([string]$Value)) { return [string]$Value }
  }
  return $null
}

function Test-QSetupDirectiveEnabled {
  <#
  .SYNOPSIS
    Interpret an optional QSetup flag directive without treating an explicit false value as enabled.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  .PARAMETER Name
    Flag directive to inspect.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][hashtable]$Directive,
    [Parameter(Mandatory)][string]$Name
  )

  if (-not $Directive.ContainsKey($Name)) { return $false }
  $Value = @($Directive[$Name])[0]
  if ($Value -is [bool]) { return $Value }
  if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $true }
  return [string]$Value -notmatch '^(?i:0|false|no|off|disabled)$'
}

function Resolve-QSetupAliasText {
  <#
  .SYNOPSIS
    Resolve a bounded set of case-insensitive QSetup aliases in one literal path expression.
  .PARAMETER Text
    Literal path expression from Setup.txt.
  .PARAMETER Alias
    Alias-to-path dictionary. Values can themselves contain aliases and are expanded for at most eight passes.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Text,
    [Parameter(Mandatory)][hashtable]$Alias
  )

  $Result = $Text.Trim().Trim('"')
  for ($Depth = 0; $Depth -lt 8; $Depth++) {
    $Before = $Result
    foreach ($Entry in $Alias.GetEnumerator()) {
      $Result = $Result.Replace([string]$Entry.Key, [string]$Entry.Value, [StringComparison]::OrdinalIgnoreCase)
    }
    if ($Result -ceq $Before) { break }
  }
  return $Result
}

function ConvertTo-QSetupNormalizedPath {
  <#
  .SYNOPSIS
    Normalize separators and literal dot segments while preserving a WinGet environment-variable or drive root.
  .PARAMETER Value
    Alias-expanded Windows path.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Value)

  $Normalized = $Value.Replace('/', '\') -replace '\\+', '\'
  $Root = ''
  $Tail = $Normalized
  if ($Normalized -match '^(?<Root>%[^%]+%|[A-Za-z]:)(?:\\)?(?<Tail>.*)$') {
    $Root = $Matches.Root
    $Tail = $Matches.Tail
  } elseif ($Normalized.StartsWith('\')) {
    $Root = '\'
    $Tail = $Normalized.TrimStart('\')
  }

  $Segments = [Collections.Generic.List[string]]::new()
  foreach ($Segment in $Tail.Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
    if ($Segment -eq '.') { continue }
    if ($Segment -eq '..') {
      if ($Segments.Count -eq 0) { return $null }
      $Segments.RemoveAt($Segments.Count - 1)
      continue
    }
    $Segments.Add($Segment)
  }
  if (-not $Root) { return ($Segments -join '\') }
  if ($Segments.Count -eq 0) { return $Root }
  return $Root.TrimEnd('\') + '\' + ($Segments -join '\')
}

function ConvertTo-QSetupManifestPath {
  <#
  .SYNOPSIS
    Resolve deterministic QSetup directory aliases to manifest-safe paths.
  .PARAMETER Value
    QSetup path expression.
  .PARAMETER Directive
    Parsed Setup.txt directives supplying application, common, and auxiliary roots.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][hashtable]$Directive
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $BaseAliases = [ordered]@{
    '<ProgramFilesDir>'     = '%ProgramFiles%'
    '<Program Files Dir>'   = '%ProgramFiles%'
    '<ProgramFiles>'        = '%ProgramFiles%'
    '<CommonFilesDir>'      = '%CommonProgramFiles%'
    '<WinDir>'              = '%WINDIR%'
    '<Windows Directory>'   = '%WINDIR%'
    '<WinSys32Dir>'         = '%WINDIR%\System32'
    '<System Directory>'    = '%WINDIR%\System32'
    '<WinSys16Dir>'         = '%WINDIR%\System'
    '<System 16 Directory>' = '%WINDIR%\System'
    '<FontDir>'             = '%WINDIR%\Fonts'
    '<UserLocalAppDataDir>' = '%LOCALAPPDATA%'
    '<UserAppDataDir>'      = '%APPDATA%'
    '<AllUsersAppDataDir>'  = '%ProgramData%'
    '<UserDir>'             = '%USERPROFILE%'
    '<MyDocumentsDir>'      = '%USERPROFILE%\Documents'
    '<TempDir>'             = '%TEMP%'
    '<AbsoluteDir>'         = ''
  }

  $TargetRaw = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_TARGET_DIR'
  $Target = $TargetRaw ? (Resolve-QSetupAliasText -Text $TargetRaw -Alias $BaseAliases) : $null
  $ApplicationAliases = @{}
  foreach ($Entry in $BaseAliases.GetEnumerator()) { $ApplicationAliases[$Entry.Key] = $Entry.Value }
  if ($Target) {
    $TargetRoot = $Target.TrimEnd('\') + '\'
    $ApplicationAliases['<Application Folder>'] = $TargetRoot
    $ApplicationAliases['<InstallDir>'] = $TargetRoot
  }

  $CommonRaw = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_COMMON_DIR'
  $Common = $CommonRaw ? (Resolve-QSetupAliasText -Text $CommonRaw -Alias $ApplicationAliases) : $null
  $AuxiliaryRaw = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_AUX_DIR'
  $Auxiliary = $AuxiliaryRaw ? (Resolve-QSetupAliasText -Text $AuxiliaryRaw -Alias $ApplicationAliases) : $null
  if ($Common) {
    $ApplicationAliases['<Common Folder>'] = $Common.TrimEnd('\') + '\'
    $ApplicationAliases['<InstallCommonDir>'] = $Common.TrimEnd('\') + '\'
  }
  if ($Auxiliary) {
    $ApplicationAliases['<Auxiliary Folder>'] = $Auxiliary.TrimEnd('\') + '\'
    $ApplicationAliases['<InstallAuxDir>'] = $Auxiliary.TrimEnd('\') + '\'
  }

  $Result = ConvertTo-QSetupNormalizedPath -Value (Resolve-QSetupAliasText -Text $Value -Alias $ApplicationAliases)
  if (-not $Result) { return $null }
  if ($Result -match '<[^>]+>') { return $null }
  return $Result.TrimEnd('\')
}

function ConvertTo-QSetupExtractionPath {
  <#
  .SYNOPSIS
    Convert an installed QSetup destination to a safe path beneath an extraction root.
  .PARAMETER Payload
    Payload-catalog entry containing the resolved installed path and physical record name.
  .PARAMETER InstallLocation
    Resolved application root. Files beneath it retain their installed relative paths.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][psobject]$Payload,
    [AllowNull()][string]$InstallLocation
  )

  $InstalledPath = [string]$Payload.InstalledPath
  $InstallRoot = $InstallLocation ? $InstallLocation.TrimEnd('\') : $null
  if ($InstallRoot -and $InstalledPath.StartsWith($InstallRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    return $InstalledPath.Substring($InstallRoot.Length + 1)
  }
  if ($InstallRoot -and $InstalledPath.Equals($InstallRoot, [StringComparison]::OrdinalIgnoreCase)) {
    return [string]$Payload.InstalledName
  }
  if ($InstalledPath -match '^%(?<Root>[^%]+)%\\?(?<Tail>.*)$') {
    return Join-Path (Join-Path '_destinations' $Matches.Root) $Matches.Tail
  }
  if ($InstalledPath -match '^(?<Drive>[A-Za-z]):\\?(?<Tail>.*)$') {
    return Join-Path (Join-Path '_destinations' "Drive-$($Matches.Drive.ToUpperInvariant())") $Matches.Tail
  }
  if ($InstalledPath.StartsWith('\')) {
    return Join-Path (Join-Path '_destinations' 'Root') $InstalledPath.TrimStart('\')
  }
  if (-not [string]::IsNullOrWhiteSpace($InstalledPath)) {
    return Join-Path (Join-Path '_destinations' 'Relative') $InstalledPath
  }
  return Join-Path '_unresolved' ([string]$Payload.InstalledName)
}

function Get-QSetupPayloadCatalog {
  <#
  .SYNOPSIS
    Map physical QSetup records to the installed paths encoded by Setup.txt.
  .PARAMETER DirectiveRecord
    Ordered literal directives returned by Get-QSetupDirectiveRecord.
  .PARAMETER Directive
    Parsed directive dictionary used to resolve destination aliases.
  .PARAMETER Record
    Structurally validated physical record catalog.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][object[]]$DirectiveRecord,
    [Parameter(Mandatory)][hashtable]$Directive,
    [Parameter(Mandatory)][object[]]$Record
  )

  $RecordByName = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in $Record) { if (-not $RecordByName.ContainsKey([string]$Item.Name)) { $RecordByName.Add([string]$Item.Name, $Item) } }
  $Result = [Collections.Generic.List[object]]::new()
  $DestinationExpression = $null
  $DestinationFlags = $null
  foreach ($Item in $DirectiveRecord) {
    if ($Item.Name -eq 'SET_SUB_DIR') {
      # The optional decimal prefix is an observed copy/destination flag word.
      # Preserve it separately and never treat it as part of the path expression.
      $DestinationMatch = [regex]::Match([string]$Item.Value, '^(?:(?<Flags>\d*)\*)?(?<Path>.*)$')
      $DestinationExpression = $DestinationMatch.Groups['Path'].Value
      $DestinationFlags = $DestinationMatch.Groups['Flags'].Success -and $DestinationMatch.Groups['Flags'].Value ? [uint32]$DestinationMatch.Groups['Flags'].Value : $null
      continue
    }
    if ($Item.Name -ne 'SET_COPY_FILES' -or [string]::IsNullOrWhiteSpace([string]$Item.Value)) { continue }
    # QSetup 1 and 2 separate copy descriptors with commas. Later composers use
    # pipes; select one grammar per directive so commas in modern file names are
    # not interpreted as record separators.
    $CopyValue = [string]$Item.Value
    $Separator = $CopyValue.Contains('|') ? '|' : ','
    foreach ($FileDescriptor in $CopyValue.Split($Separator, [StringSplitOptions]::RemoveEmptyEntries)) {
      $Match = [regex]::Match($FileDescriptor, '^(?:(?<Flags>\d+)\*)?(?<RecordName>.+)$')
      if (-not $Match.Success) { continue }
      $RecordName = $Match.Groups['RecordName'].Value
      $PhysicalRecord = $null
      $IsEmbedded = $RecordByName.TryGetValue($RecordName, [ref]$PhysicalRecord)
      $InstalledName = $RecordName -replace '^\d+#', ''
      $ResolvedDirectory = ConvertTo-QSetupManifestPath -Value $DestinationExpression -Directive $Directive
      $InstalledPath = $ResolvedDirectory ? ($ResolvedDirectory.TrimEnd('\') + '\' + $InstalledName) : $null
      $Result.Add([pscustomobject][ordered]@{
          RecordName            = $RecordName
          InstalledName         = $InstalledName
          Flags                 = $Match.Groups['Flags'].Success ? [uint32]$Match.Groups['Flags'].Value : 0
          DestinationFlags      = $DestinationFlags
          DestinationExpression = [string]::IsNullOrWhiteSpace($DestinationExpression) ? $null : $DestinationExpression
          ResolvedDirectory     = $ResolvedDirectory
          InstalledPath         = $InstalledPath
          Record                = $PhysicalRecord
          IsEmbedded            = $IsEmbedded
          Storage               = $IsEmbedded ? 'EmbeddedRecord' : 'ExternalCompanion'
        })
    }
  }
  return $Result.ToArray()
}

function Get-QSetupConditionClassification {
  <#
  .SYNOPSIS
    Classify one documented QSetup Execution Engine predicate by required runtime evidence.
  .PARAMETER Predicate
    Condition name serialized in a modern SET_PERFORM_EXECUTE_OP slot.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][string]$Predicate)

  $Category = switch -Regex ($Predicate) {
    '^File |^Directory |^Drive |Text Found in File' { 'FileSystem'; break }
    '^Application ' { 'ApplicationRegistration'; break }
    'Running|HWindow|Last Executable Exit Code' { 'ProcessState'; break }
    '^Service ' { 'Service'; break }
    'Operating System|64 Bit State|Running on 64 Bit' { 'OperatingSystem'; break }
    'Language' { 'Localization'; break }
    'Internet|HTTP' { 'Network'; break }
    '^Printer ' { 'Printer'; break }
    '^Registry ' { 'Registry'; break }
    '^Environment ' { 'Environment'; break }
    'Memory|CPU|Screen|Color Depth|Disk Free Space' { 'Hardware'; break }
    'Framework|Runtime|Version|Installed$|DirectX|JDK|JRE|ODBC|BDE|DAO|IIS|JET|Flash|Acrobat' { 'Dependency'; break }
    '^Ask ' { 'UserInteraction'; break }
    'Setup Type|Group Selected|Auto Update|Billboard' { 'InstallerState'; break }
    'User Name|Company Name|Serial Number|Privilege|ADMINISTRATOR' { 'UserIdentity'; break }
    '^Control ' { 'DialogState'; break }
    'Variable' { 'VariableState'; break }
    default { 'Unknown' }
  }
  [pscustomobject][ordered]@{
    Category                = $Category
    RequiresRuntimeState    = -not [string]::IsNullOrWhiteSpace($Predicate)
    RequiresUserInteraction = $Category -eq 'UserInteraction'
  }
}

function Get-QSetupExecutionCondition {
  <#
  .SYNOPSIS
    Project the three fixed modern QSetup condition slots without guessing runtime truth.
  .PARAMETER Fields
    Complete 73-field modern execution-action record.
  .PARAMETER IsUnconditional
    Indicates that the action ignores the serialized condition slots.
  .PARAMETER ArgumentStart
    Zero-based field index of the first condition-argument slot for the selected execution-record profile.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string[]]$Fields,
    [Parameter(Mandatory)][bool]$IsUnconditional,
    [Parameter(Mandatory)][ValidateRange(0, 1024)][int]$ArgumentStart
  )

  $Definitions = @(
    @{ Slot = 1; Descriptor = 6; Length = 4; Arguments = $ArgumentStart },
    @{ Slot = 2; Descriptor = 10; Length = 5; Arguments = $ArgumentStart + 4 },
    @{ Slot = 3; Descriptor = 15; Length = 5; Arguments = $ArgumentStart + 8 }
  )
  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Definition in $Definitions) {
    $Descriptor = [string[]]$Fields[$Definition.Descriptor..($Definition.Descriptor + $Definition.Length - 1)]
    $Arguments = [string[]]$Fields[$Definition.Arguments..($Definition.Arguments + 3)]
    $PredicateOffset = $Definition.Slot -eq 1 ? 2 : 3
    $Predicate = $Descriptor[$PredicateOffset]
    if (($Predicate -eq 'File Found' -or [string]::IsNullOrWhiteSpace($Predicate)) -and @($Arguments | Where-Object { $_ }).Count -eq 0) { continue }
    $Classification = Get-QSetupConditionClassification -Predicate $Predicate
    $Result.Add([pscustomobject][ordered]@{
        Slot                    = $Definition.Slot
        Predicate               = $Predicate
        Category                = $Classification.Category
        Argument1               = $Arguments[0]
        Operator                = $Arguments[1]
        Argument2               = $Arguments[2]
        Argument3               = $Arguments[3]
        JoinCode                = $Definition.Slot -eq 1 ? $null : $Descriptor[0]
        ObservedFlags           = $Definition.Slot -eq 1 ? [string[]]$Descriptor[0..1] : [string[]]$Descriptor[1..2]
        State                   = $IsUnconditional ? 'Ignored' : 'Unknown'
        RequiresRuntimeState    = $Classification.RequiresRuntimeState
        RequiresUserInteraction = $Classification.RequiresUserInteraction
      })
  }
  return $Result.ToArray()
}

function Resolve-QSetupLiteralText {
  <#
  .SYNOPSIS
    Replace deterministic QSetup path aliases inside a command or registry string without changing quoting.
  .PARAMETER Value
    Literal metadata text that can contain one or more angle-bracket aliases.
  .PARAMETER Directive
    Parsed Setup.txt directives used to resolve each alias token.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Value, [Parameter(Mandatory)][hashtable]$Directive)

  if ($null -eq $Value) { return $null }
  $Result = $Value
  foreach ($Match in @([regex]::Matches($Value, '<[^<>]+>') | Select-Object -ExpandProperty Value -Unique)) {
    $Resolved = ConvertTo-QSetupManifestPath -Value $Match -Directive $Directive
    if ($Resolved) { $Result = $Result.Replace($Match, $Resolved, [StringComparison]::OrdinalIgnoreCase) }
  }
  return $Result
}

function ConvertFrom-QSetupExecutionAction {
  <#
  .SYNOPSIS
    Decode one fixed-slot QSetup Execution Engine directive.
  .PARAMETER Content
    Literal SET_PERFORM_EXECUTE_OP value from Setup.txt.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

  $Fields = [regex]::Split($Content, '\|')
  $LayoutProfile = $Script:QSetupFormatCatalog.ExecutionRoutes | Where-Object { $Fields.Count -in $_.FieldCounts } | Select-Object -First 1
  if (-not $LayoutProfile -or $Fields[0] -notin @('*', '^') -or $Fields[$LayoutProfile.MiddleSentinel] -ne $Fields[0] -or $Fields[-1] -ne $Fields[0]) {
    throw 'The QSetup execution-action record does not use the supported fixed-slot layout.'
  }

  $Commands = [Collections.Generic.List[object]]::new()
  # Every profile stores command descriptors and command arguments in separate
  # fixed-width arrays. Pair the slots without evaluating runtime conditions.
  for ($Index = 0; $Index -lt $LayoutProfile.CommandCount; $Index++) {
    $DescriptorOffset = $LayoutProfile.CommandStart + ($Index * 3)
    $ArgumentOffset = $LayoutProfile.ArgumentStart + ($Index * 3)
    if ($Fields[$DescriptorOffset] -ne '1' -or [string]::IsNullOrWhiteSpace($Fields[$DescriptorOffset + 1])) { continue }
    $Commands.Add([pscustomobject][ordered]@{
        Slot      = $Index + 1
        Name      = $Fields[$DescriptorOffset + 1]
        Argument1 = $Fields[$ArgumentOffset]
        Argument2 = $Fields[$ArgumentOffset + 1]
        Argument3 = $Fields[$ArgumentOffset + 2]
      })
  }

  $HasStructuredConditions = [bool]$LayoutProfile.HasStructuredConditions
  $IsUnconditional = $HasStructuredConditions -and $Fields[5] -eq 'UnConditional'
  $Conditions = $HasStructuredConditions ? @(Get-QSetupExecutionCondition -Fields $Fields -IsUnconditional $IsUnconditional -ArgumentStart $LayoutProfile.ConditionArgumentStart) : @()
  $ObservedTrailingFields = if ($null -ne $LayoutProfile.TrailingStart -and $null -ne $LayoutProfile.TrailingEnd) {
    [string[]]$Fields[$LayoutProfile.TrailingStart..$LayoutProfile.TrailingEnd]
  } else { @() }

  return [pscustomobject][ordered]@{
    LayoutRoute            = $LayoutProfile.Id
    Name                   = $Fields[2]
    Stage                  = $Fields[3]
    Sequence               = $HasStructuredConditions ? $Fields[4] : $null
    ConditionMode          = $HasStructuredConditions ? $Fields[5] : 'Legacy'
    AppliesDuring          = $Fields[0] -eq '*' ? 'Setup' : 'Uninstall'
    IsConditional          = $HasStructuredConditions ? -not $IsUnconditional : $true
    ConditionState         = $IsUnconditional ? 'True' : 'Unknown'
    Conditions             = [object[]]$Conditions
    ConditionDescriptors   = [string[]]($HasStructuredConditions ? $Fields[6..19] : $Fields[5..19])
    ConditionArguments     = [string[]]($HasStructuredConditions ? $Fields[$LayoutProfile.ConditionArgumentStart..($LayoutProfile.ConditionArgumentStart + 11)] : $Fields[34..45])
    Commands               = [object[]]$Commands.ToArray()
    ObservedTrailingFields = $ObservedTrailingFields
    RawValue               = $Content
  }
}

function Get-QSetupExecutionActionInfo {
  <#
  .SYNOPSIS
    Project QSetup Execution Engine records and nested process launches.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][hashtable]$Directive)

  $Actions = [Collections.Generic.List[object]]::new()
  $ExecutedPayloads = [Collections.Generic.List[object]]::new()
  $Warnings = [Collections.Generic.List[object]]::new()
  $Values = $Directive.ContainsKey('SET_PERFORM_EXECUTE_OP') ? @($Directive['SET_PERFORM_EXECUTE_OP']) : @()
  foreach ($Value in $Values) {
    try {
      $Action = ConvertFrom-QSetupExecutionAction -Content ([string]$Value)
      $Actions.Add($Action)
      foreach ($Command in $Action.Commands) {
        if ($Command.Name -notmatch '^(?:Run (?:Application|Executable|Batch File|MSI File)(?: and Wait)?|Shell Execute(?: and Wait)?|Run DLL(?: No Wait)?)$') { continue }
        $ExecutedPayloads.Add([pscustomobject][ordered]@{
            Command       = $Command.Argument1
            Parameters    = $Command.Argument2
            ShowCommand   = $Command.Argument3
            Operation     = $Command.Name
            Wait          = $Command.Name -match ' and Wait$|^Run DLL$'
            ActionName    = $Action.Name
            Stage         = $Action.Stage
            AppliesDuring = $Action.AppliesDuring
            Conditional   = $Action.IsConditional
            Source        = 'SET_PERFORM_EXECUTE_OP'
          })
      }
    } catch {
      $Warnings.Add("A QSetup execution-action record is malformed or unsupported: $($_.Exception.Message)")
    }
  }

  return [pscustomobject][ordered]@{
    Actions          = [object[]]$Actions.ToArray()
    ExecutedPayloads = [object[]]$ExecutedPayloads.ToArray()
    Diagnostics      = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'QSetup' -Kind Incomplete -Areas Metadata)
  }
}

function Get-QSetupExecutionCommandCategory {
  <#
  .SYNOPSIS
    Map a documented QSetup Execution Engine command to its observable system-effect family.
  .PARAMETER Name
    Command name serialized in an execution-action command slot.
  #>
  [OutputType([string])]
  param ([AllowNull()][string]$Name)

  switch -Regex ($Name) {
    'File Association' { return 'FileAssociation' }
    '^Run DLL' { return 'ExternalDll' }
    'Service' { return 'Service' }
    'Reg(?:ister|Svr)|COM|ActiveX|GAC' { return 'COMRegistration' }
    'Registry|REG File' { return 'Registry' }
    'INI ' { return 'IniFile' }
    'Environment' { return 'Environment' }
    'Font' { return 'Font' }
    'Download|HTTP|URL' { return 'Download' }
    'Restart|Reboot|Delayed' { return 'Restart' }
    'Merge Module|MSI' { return 'WindowsInstaller' }
    '^Run (?:Application|Executable|Batch File)|^Shell Execute' { return 'NestedExecution' }
    'Set (?:32|64) Bit State|Restore Original Setup State' { return 'ArchitectureState' }
    'Browse for |Select one of many|Input text string' { return 'UserInteraction' }
    'Set Dialog|Enable (?:Setup Dialog|Dialog Button)|Set Edit Text|Set Control Property|Get Control Property|Set Setup Type|Set Group' { return 'InstallerControl' }
    'Variable' { return 'VariableState' }
    'Shut Down Executable|Wait \(MS\)|Set Setup Exit Code|^Exit$|^Break$' { return 'ProcessControl' }
    'Restore Point' { return 'RestorePoint' }
    'Permission|Full Access' { return 'Security' }
    'Text (?:to|in) (?:a )?File' { return 'TextFile' }
    'File|Folder|Directory|CAB' { return 'FileSystem' }
    default { return 'Other' }
  }
}

function Get-QSetupSystemEffectInfo {
  <#
  .SYNOPSIS
    Classify structured execution commands and direct setup directives by observable system effect.
  .PARAMETER ExecutionAction
    Decoded QSetup execution actions.
  .PARAMETER DirectiveRecord
    Ordered Setup.txt directive records.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$ExecutionAction, [AllowNull()][object[]]$DirectiveRecord)

  $Effects = [Collections.Generic.List[object]]::new()
  foreach ($Action in @($ExecutionAction)) {
    foreach ($Command in @($Action.Commands)) {
      $Category = Get-QSetupExecutionCommandCategory -Name $Command.Name
      if ($Category -eq 'Other' -and $Command.Name -match '^Display |^Show |^Hide |^Ask ') { continue }
      $Effects.Add([pscustomobject][ordered]@{
          Category       = $Category
          Operation      = $Command.Name
          Argument1      = $Command.Argument1
          Argument2      = $Command.Argument2
          Argument3      = $Command.Argument3
          Stage          = $Action.Stage
          AppliesDuring  = $Action.AppliesDuring
          ConditionState = $Action.ConditionState
          Conditions     = $Action.Conditions
          Source         = 'SET_PERFORM_EXECUTE_OP'
        })
    }
  }

  foreach ($Record in @($DirectiveRecord)) {
    $Category = switch -Regex ($Record.Name) {
      'SERVICE' { 'Service'; break }
      'REG_FILES|REGISTER_(?:DLL|OCX)|COM_' { 'COMRegistration'; break }
      'FONT' { 'Font'; break }
      'DOWNLOAD' { 'Download'; break }
      'RESTART|REBOOT' { 'Restart'; break }
      'MERGE_MODULE|MSI_CODES' { 'WindowsInstaller'; break }
      'EXECUTION_DLL' { 'ExternalDll'; break }
      default { $null }
    }
    if (-not $Category) { continue }
    $Effects.Add([pscustomobject][ordered]@{
        Category = $Category; Operation = $Record.Name; Argument1 = $Record.Value
        Argument2 = $null; Argument3 = $null; Stage = 'Configuration'; AppliesDuring = 'Setup'
        ConditionState = 'Unknown'; Conditions = @(); Source = $Record.Name
      })
  }

  [pscustomobject][ordered]@{
    SystemEffects               = $Effects.ToArray()
    Services                    = @($Effects | Where-Object Category -EQ Service)
    ComRegistrations            = @($Effects | Where-Object Category -EQ COMRegistration)
    FontOperations              = @($Effects | Where-Object Category -EQ Font)
    Downloads                   = @($Effects | Where-Object Category -EQ Download)
    RestartOperations           = @($Effects | Where-Object Category -EQ Restart)
    WindowsInstallers           = @($Effects | Where-Object Category -EQ WindowsInstaller)
    ExternalDllActions          = @($Effects | Where-Object Category -EQ ExternalDll)
    FileAssociations            = @($Effects | Where-Object Category -EQ FileAssociation)
    RegistryOperations          = @($Effects | Where-Object Category -EQ Registry)
    IniFileOperations           = @($Effects | Where-Object Category -EQ IniFile)
    EnvironmentOperations       = @($Effects | Where-Object Category -EQ Environment)
    ArchitectureStateOperations = @($Effects | Where-Object Category -EQ ArchitectureState)
    UserInteractionOperations   = @($Effects | Where-Object Category -EQ UserInteraction)
    ProcessControlOperations    = @($Effects | Where-Object Category -EQ ProcessControl)
  }
}

function Get-QSetupUninstallerInfo {
  <#
  .SYNOPSIS
    Resolve explicit or composer-generated QSetup uninstaller naming.
  .PARAMETER Directive
    Parsed Setup.txt directives containing media name, program stamp, and uninstall settings.
  .PARAMETER InstallLocation
    Resolved default application directory.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][hashtable]$Directive, [AllowNull()][string]$InstallLocation)

  $Name = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_UNINSTALL_EXE_NAME'
  $Generated = $false
  $NamingRoute = $Name ? 'ExplicitName' : $null
  if (-not $Name) {
    # Older composers write the generated uninstaller path into a Start-menu
    # shortcut even when SET_UNINSTALL_EXE_NAME is absent. This artifact-local
    # value is stronger than a release-based naming fallback.
    $ProgramStamp = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_PROG_STAMP'
    foreach ($ShortcutValue in @($Directive['SET_START_PROGRAM_LINK_ITEM'])) {
      $ShortcutMatch = [regex]::Match([string]$ShortcutValue, '(?i)(?<Name>UnInstall_(?<Stamp>\d+)\.exe)(?=\s*(?:[|,)]|$))')
      if ($ShortcutMatch.Success -and $ProgramStamp -match '^\d+$' -and $ShortcutMatch.Groups['Stamp'].Value -eq $ProgramStamp) {
        $Name = $ShortcutMatch.Groups['Name'].Value
        $Generated = $true
        $NamingRoute = 'CompiledShortcutTarget'
        break
      }
    }
  }
  if (-not $Name) {
    $MediaName = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_MEDIA_NAME'
    $MediaLeaf = $MediaName ? [IO.Path]::GetFileNameWithoutExtension([IO.Path]::GetFileName($MediaName)) : $null
    if ($ProgramStamp -match '^\d+$') {
      $ComposerBuild = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_COMPOSER_BUILD'
      $ComposerMajor = 0
      if ([int]::TryParse(($ComposerBuild -split '\.')[0], [ref]$ComposerMajor)) {
        # Generations 8 through 11 have no fallback until a
        # blank-name fixture proves which runtime formula they use.
        $Route = @($Script:QSetupFormatCatalog.UninstallerRoutes | Where-Object {
            (-not $_.ContainsKey('MinimumMajor') -or $ComposerMajor -ge $_.MinimumMajor) -and
            (-not $_.ContainsKey('MaximumMajor') -or $ComposerMajor -le $_.MaximumMajor)
          } | Select-Object -First 1)
        if ($Route.Count -eq 1 -and ($Route[0].Template -notmatch '\{Media\}' -or $MediaLeaf)) {
          $Name = $Route[0].Template.Replace('{Media}', $MediaLeaf).Replace('{Stamp}', $ProgramStamp)
          $Generated = $true
          $NamingRoute = $Route[0].Id
        }
      }
    }
  } elseif (-not [IO.Path]::HasExtension($Name)) {
    $Name += '.exe'
  }
  $DirectoryExpression = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_UNINSTALL_EXE_DIR'
  $Directory = $DirectoryExpression ? (ConvertTo-QSetupManifestPath -Value $DirectoryExpression -Directive $Directive) : $InstallLocation
  [pscustomobject][ordered]@{
    Name = $Name; Generated = $Generated; NamingRoute = $NamingRoute; DirectoryExpression = $DirectoryExpression
    Directory = $Directory
    Path = $Name -and $Directory ? ($Directory.TrimEnd('\') + '\' + $Name) : $null
    RegistryCommand = $Name -and $Directory ? ('"' + $Directory.TrimEnd('\') + '\' + $Name + '"') : $null
  }
}

function Get-QSetupRegistryViewInfo {
  <#
  .SYNOPSIS
    Resolve the registry view used by the initial QSetup runtime state.
  .PARAMETER OuterMachine
    PE machine name of the setup launcher.
  .PARAMETER AllowedOperatingSystems
    Literal SET_ALLOWED_OS value from Setup.txt.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$OuterMachine,
    [AllowNull()][string]$AllowedOperatingSystems
  )

  # The QSetup manual states that Create 64-bit Setup makes the setup a 64-bit
  # runtime state while retaining a 32-bit launcher. In compiled media the
  # durable evidence is an x64-only SET_ALLOWED_OS list. Otherwise ordinary
  # registry redirection follows the native launcher machine.
  $Has64BitTarget = $AllowedOperatingSystems -match '(?i)(?:^|,)[^,]+\.64(?:,|$)'
  $Has32BitTarget = $AllowedOperatingSystems -match '(?i)(?:^|,)(?:95|98|ME|NT|2000|2003|XP|Vista|7|8|8\.1|10|11)(?:,|$)'
  if ($Has64BitTarget -and -not $Has32BitTarget) {
    return [pscustomobject]@{ RegistryView = '64-bit'; Evidence = 'SET_ALLOWED_OS contains only 64-bit targets (QSetup 64-bit setup state)' }
  }

  switch ($OuterMachine) {
    'I386' { return [pscustomobject]@{ RegistryView = '32-bit'; Evidence = 'PE machine I386' } }
    { $_ -in 'Amd64', 'AMD64', 'Arm64', 'ARM64' } { return [pscustomobject]@{ RegistryView = '64-bit'; Evidence = "PE machine $OuterMachine" } }
    default { return [pscustomobject]@{ RegistryView = 'default'; Evidence = $null } }
  }
}

function Get-QSetupShortcutInfo {
  <#
  .SYNOPSIS
    Decode legacy compact and modern extended Start/Programs shortcut records.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][hashtable]$Directive)

  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Value in @($Directive['SET_START_PROGRAM_LINK_ITEM'])) {
    $Text = [string]$Value
    $Fields = [regex]::Split($Text, '\|')
    if ($Fields.Count -ge 10 -and $Fields[0] -eq '') {
      $LayoutRoute = 'ExtendedPipe'
      $Name = $Fields[1].Trim()
      $TargetExpression = $Fields[2].Trim()
      $Subfolder = $Fields[3].Trim()
      $Parameters = $Fields[4].Trim()
      $WorkingDirectoryExpression = $Fields[5].Trim()
      $WindowStyle = $Fields[6].Trim()
      $IconExpression = $Fields[7].Trim()
      $IconIndex = $Fields[8].Trim() -match '^\d+$' ? [int]$Fields[8].Trim() : $null
      $ObservedFlags = [string[]]$Fields[9..($Fields.Count - 2)]
    } else {
      # QSetup 1-3 used two comma-separated values. Later historical media use
      # the same compact name/target pair with optional pipe sentinels.
      $CompactFields = $Text.Contains('|') ? [regex]::Split($Text.Trim('|'), '\|') : $Text.Split(',', 2)
      if ($CompactFields.Count -lt 2) { continue }
      $LayoutRoute = $Text.Contains('|') ? 'CompactPipe' : 'CompactComma'
      $Name = $CompactFields[0].Trim()
      $TargetExpression = $CompactFields[1].Trim()
      $Subfolder = $null
      $Parameters = $null
      $WorkingDirectoryExpression = $null
      $WindowStyle = $null
      $IconExpression = $null
      $IconIndex = $null
      $ObservedFlags = $CompactFields.Count -gt 2 ? [string[]]$CompactFields[2..($CompactFields.Count - 1)] : @()
    }
    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($TargetExpression)) { continue }
    $Target = if ($TargetExpression -match '^[A-Za-z][A-Za-z0-9+.-]*:') { $TargetExpression } else { ConvertTo-QSetupManifestPath -Value $TargetExpression -Directive $Directive }
    $Result.Add([pscustomobject][ordered]@{
        LayoutRoute                = $LayoutRoute
        Name                       = $Name
        TargetExpression           = $TargetExpression
        Target                     = $Target
        Subfolder                  = $Subfolder
        Parameters                 = $Parameters
        WorkingDirectoryExpression = $WorkingDirectoryExpression
        WorkingDirectory           = $WorkingDirectoryExpression ? (ConvertTo-QSetupManifestPath -Value $WorkingDirectoryExpression -Directive $Directive) : $null
        WindowStyle                = $WindowStyle
        IconExpression             = $IconExpression
        Icon                       = $IconExpression ? (ConvertTo-QSetupManifestPath -Value $IconExpression -Directive $Directive) : $null
        IconIndex                  = $IconIndex
        ObservedFlags              = [string[]]$ObservedFlags
        Source                     = 'SET_START_PROGRAM_LINK_ITEM'
      })
  }
  return $Result.ToArray()
}

function Get-QSetupEnvironmentChange {
  <#
  .SYNOPSIS
    Decode literal QSetup environment-variable operations.
  .PARAMETER Directive
    Parsed Setup.txt directive dictionary.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][hashtable]$Directive)

  $Result = [Collections.Generic.List[object]]::new()
  foreach ($Value in @($Directive['SET_PERFORM_ENVIRONMENT_OP'])) {
    $Fields = ([string]$Value).Split('|')
    if ($Fields.Count -lt 5 -or [string]::IsNullOrWhiteSpace($Fields[0])) { continue }
    $Result.Add([pscustomobject][ordered]@{
        Name            = $Fields[0].Trim()
        Value           = $Fields[1]
        Operation       = $Fields[2].Trim()
        UninstallAction = $Fields[3].Trim()
        Scope           = switch -Regex ($Fields[4].Trim()) { '^User$' { 'user'; break } '^System$|^Machine$' { 'machine'; break } default { $null } }
        RawScope        = $Fields[4].Trim()
        Source          = 'SET_PERFORM_ENVIRONMENT_OP'
      })
  }
  return $Result.ToArray()
}

function ConvertFrom-QSetupRegistryOperation {
  <#
  .SYNOPSIS
    Decode one source-backed SET_PERFORM_REGISTRY_OP record.
  .PARAMETER Content
    Pipe-delimited registry record from Setup.txt.
  .PARAMETER Directive
    Parsed directives used to resolve deterministic path aliases in string data.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
    [Parameter(Mandatory)][hashtable]$Directive
  )

  $Fields = $Content.Split('|')
  if ($Fields.Count -ne 8 -or $Fields[0] -ne '' -or $Fields[7] -ne '') { throw 'The QSetup registry-operation record does not use the supported eight-field layout.' }
  $KeyMatch = [regex]::Match($Fields[1].Trim(), '^(?<Root>HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\(?<Key>.+)$', 'IgnoreCase')
  if (-not $KeyMatch.Success) { throw 'The QSetup registry operation has an unsupported or missing registry root.' }
  $Root = switch ($KeyMatch.Groups['Root'].Value.ToUpperInvariant()) {
    { $_ -in @('HKLM', 'HKEY_LOCAL_MACHINE') } { 'HKLM'; break }
    { $_ -in @('HKCU', 'HKEY_CURRENT_USER') } { 'HKCU'; break }
    { $_ -in @('HKCR', 'HKEY_CLASSES_ROOT') } { 'HKCR'; break }
    { $_ -in @('HKU', 'HKEY_USERS') } { 'HKU'; break }
    default { 'HKCC' }
  }
  $Type = switch -Regex ($Fields[6].Trim()) {
    '^String$' { 'REG_SZ'; break }
    '^Integer$' { 'REG_DWORD'; break }
    '^Hex$' { 'REG_BINARY'; break }
    '^MultiString$' { 'REG_MULTI_SZ'; break }
    '^ExpandString$' { 'REG_EXPAND_SZ'; break }
    default { throw "The QSetup registry value type '$($Fields[6].Trim())' is unsupported." }
  }
  $RawData = $Fields[3]
  $Data = switch ($Type) {
    'REG_DWORD' {
      $Number = 0L
      if (-not [long]::TryParse($RawData.Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Number) -or $Number -lt [int]::MinValue -or $Number -gt [uint32]::MaxValue) {
        throw 'The QSetup REG_DWORD value is not a bounded integer.'
      }
      $Number
    }
    'REG_BINARY' {
      $Hex = $RawData -replace '(?i)0x|[^0-9a-f]', ''
      if ($Hex.Length % 2 -ne 0) { throw 'The QSetup REG_BINARY value has an odd number of hexadecimal digits.' }
      [Convert]::FromHexString($Hex)
    }
    'REG_MULTI_SZ' { [string[]]($RawData -split '<0>', 0, 'SimpleMatch') }
    default { Resolve-QSetupLiteralText -Value $RawData -Directive $Directive }
  }

  [pscustomobject][ordered]@{
    Root            = $Root
    Key             = $KeyMatch.Groups['Key'].Value.Trim('\')
    Name            = $Fields[2]
    Value           = $Data
    Type            = $Type
    SetupAction     = $Fields[4].Trim()
    UninstallAction = $Fields[5].Trim()
    Source          = 'SET_PERFORM_REGISTRY_OP'
    RawValue        = $Content
  }
}

function ConvertFrom-QSetupIniOperation {
  <#
  .SYNOPSIS
    Decode one SET_PERFORM_INI_OP record using the builder-documented field order.
  .PARAMETER Content
    Pipe-delimited INI operation from Setup.txt.
  .PARAMETER Directive
    Parsed directives used for deterministic target-path resolution.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Content, [Parameter(Mandatory)][hashtable]$Directive)

  $Fields = $Content.Split('|')
  if ($Fields.Count -ne 8 -or $Fields[0] -ne '' -or $Fields[7] -ne '' -or [string]::IsNullOrWhiteSpace($Fields[1])) {
    throw 'The QSetup INI-operation record does not use the supported eight-field layout.'
  }
  [pscustomobject][ordered]@{
    PathExpression  = $Fields[1]
    Path            = ConvertTo-QSetupManifestPath -Value $Fields[1] -Directive $Directive
    Section         = $Fields[2]
    Name            = $Fields[3]
    Value           = $Fields[4]
    SetupAction     = $Fields[5].Trim()
    UninstallAction = $Fields[6].Trim()
    Source          = 'SET_PERFORM_INI_OP'
    RawValue        = $Content
  }
}

function ConvertFrom-QSetupXmlOperation {
  <#
  .SYNOPSIS
    Decode one SET_PERFORM_XML_OP record using the builder-documented field order.
  .PARAMETER Content
    Pipe-delimited XML operation from Setup.txt.
  .PARAMETER Directive
    Parsed directives used for deterministic target-path resolution.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Content, [Parameter(Mandatory)][hashtable]$Directive)

  $Fields = $Content.Split('|')
  if ($Fields.Count -ne 7 -or $Fields[0] -ne '' -or $Fields[6] -ne '' -or [string]::IsNullOrWhiteSpace($Fields[1])) {
    throw 'The QSetup XML-operation record does not use the supported seven-field layout.'
  }
  [pscustomobject][ordered]@{
    PathExpression  = $Fields[1]
    Path            = ConvertTo-QSetupManifestPath -Value $Fields[1] -Directive $Directive
    NodePath        = $Fields[2]
    Value           = $Fields[3]
    SetupAction     = $Fields[4].Trim()
    UninstallAction = $Fields[5].Trim()
    Source          = 'SET_PERFORM_XML_OP'
    RawValue        = $Content
  }
}

function Get-QSetupStructuredOperationInfo {
  <#
  .SYNOPSIS
    Decode all registry, INI, and XML records while retaining malformed records as diagnostics.
  .PARAMETER Directive
    Parsed Setup.txt directives.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][hashtable]$Directive)

  $Registry = [Collections.Generic.List[object]]::new()
  $Ini = [Collections.Generic.List[object]]::new()
  $Xml = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Definition in @(
      @{ Names = @('SET_PERFORM_REGISTRY_OP'); Target = $Registry; Parser = 'Registry' },
      # Composer 12 writes SET_PERFORM_INIFILE_OP/SET_PERFORM_XMLFILE_OP (controlled QSReg build);
      # older documentation and synthetic samples used the short names.
      @{ Names = @('SET_PERFORM_INI_OP', 'SET_PERFORM_INIFILE_OP'); Target = $Ini; Parser = 'Ini' },
      @{ Names = @('SET_PERFORM_XML_OP', 'SET_PERFORM_XMLFILE_OP'); Target = $Xml; Parser = 'Xml' }
    )) {
    foreach ($Name in $Definition.Names) {
      foreach ($Value in @($Directive[$Name] | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })) {
        try {
          $Parsed = switch ($Definition.Parser) {
            'Registry' { ConvertFrom-QSetupRegistryOperation -Content ([string]$Value) -Directive $Directive }
            'Ini' { ConvertFrom-QSetupIniOperation -Content ([string]$Value) -Directive $Directive }
            'Xml' { ConvertFrom-QSetupXmlOperation -Content ([string]$Value) -Directive $Directive }
          }
          $Parsed.Source = $Name
          $Definition.Target.Add($Parsed)
        } catch {
          $Diagnostics.Add((New-InstallerDiagnostic -Id "QSetup.Operation.$($Definition.Parser).Malformed" -Source QSetup -Message $_.Exception.Message -Kind Incomplete -Areas Metadata -Evidence @{ Directive = $Name; RawValue = [string]$Value }))
        }
      }
    }
  }
  [pscustomobject][ordered]@{
    RegistryOperations = $Registry.ToArray()
    IniFileOperations  = $Ini.ToArray()
    XmlOperations      = $Xml.ToArray()
    Diagnostics        = $Diagnostics.ToArray()
  }
}

function ConvertTo-QSetupRegistryEvidence {
  <#
  .SYNOPSIS
    Convert explicit QSetup ARP and association directives to registry evidence
  .PARAMETER Directive
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Scope
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  .PARAMETER InstallLocation
    Manifest-safe installation directory resolved from QSetup aliases.
  .PARAMETER RegistryOperation
    Decoded custom registry operations. Only explicit create actions become write evidence.
  .PARAMETER RegistryView
    Registry view selected by the compiled QSetup runtime state.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][hashtable]$Directive,
    [AllowNull()][string]$Scope,
    [AllowNull()][string]$InstallLocation,
    [AllowNull()][object[]]$RegistryOperation,
    [ValidateSet('32-bit', '64-bit', 'default')][string]$RegistryView = 'default'
  )

  $Root = if ($Scope -eq 'machine') { 'HKLM' } elseif ($Scope -eq 'user') { 'HKCU' } else { $null }
  $ClassRoot = $Root ? $Root : 'HKCR'
  $Writes = [System.Collections.Generic.List[object]]::new()
  $DisplayName = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME' -FallbackName 'SET_PROG_NAME'
  # An ARP entry exists only when both uninstall generation and Add/Remove
  # registration are enabled. The official manual defines the program name as
  # the fallback when the optional ARP display-name field is empty.
  $WritesArp = $Root -and (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_CREATE_UNINSTALL') -and
  (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS') -and $DisplayName
  if ($WritesArp) {
    $UninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$DisplayName"
    $Uninstaller = Get-QSetupUninstallerInfo -Directive $Directive -InstallLocation $InstallLocation
    $UninstallString = $Uninstaller.RegistryCommand
    $DisplayIcon = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_ICON'
    if ($DisplayIcon) { $DisplayIcon = ConvertTo-QSetupManifestPath -Value $DisplayIcon -Directive $Directive }
    foreach ($Value in @(
        @{ Name = 'DisplayName'; Value = $DisplayName },
        @{ Name = 'DisplayVersion'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROG_VERSION' },
        @{ Name = 'Publisher'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPANY_NAME' },
        @{ Name = 'InstallLocation'; Value = $InstallLocation ? ('"' + $InstallLocation + '"') : $null },
        @{ Name = 'UninstallString'; Value = $UninstallString },
        @{ Name = 'DisplayIcon'; Value = $DisplayIcon },
        @{ Name = 'HelpLink'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_HELP_LINK' },
        @{ Name = 'URLUpdateInfo'; Value = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_UPDATE_INFO_URL' }
      )) {
      if ($null -ne $Value.Value) { $Writes.Add([pscustomobject]@{ Root = $Root; RegistryView = $RegistryView; Key = $UninstallKey; Name = $Value.Name; Value = $Value.Value; Type = 'REG_SZ'; Source = 'QSetup built-in uninstall configuration' }) }
    }
  }

  # Association records are pipe-delimited structured directives. Emit only
  # literal, syntactically valid extensions and their explicit ProgID command.
  foreach ($Association in @($Directive['SET_ADD_ASSOCIATION_ITEM'])) {
    $Fields = @($Association -split '\|')
    if ($Fields.Count -lt 7) { continue }
    $ProgId = $Fields[1].Trim()
    $Description = $Fields[2].Trim()
    $Extension = $Fields[3].Trim()
    $Executable = ConvertTo-QSetupManifestPath -Value $Fields[5].Trim() -Directive $Directive
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]*$' -or [string]::IsNullOrWhiteSpace($ProgId)) { continue }
    if ($Fields.Count -gt 8 -and $Fields[8].Trim() -and $Fields[8].Trim() -notmatch '^(?i:Create|1|True)$') { continue }
    $Writes.Add([pscustomobject]@{ Root = $ClassRoot; RegistryView = $RegistryView; Key = "Software\Classes\$Extension"; Name = $null; Value = $ProgId; Type = 'REG_SZ' })
    $Writes.Add([pscustomobject]@{ Root = $ClassRoot; RegistryView = $RegistryView; Key = "Software\Classes\$ProgId"; Name = $null; Value = $Description; Type = 'REG_SZ' })
    if ($Executable) {
      $Parameters = $Fields.Count -gt 10 ? $Fields[10].Trim() : $null
      $Command = "`"$Executable`""
      if ($Parameters) { $Command += " $Parameters" }
      $Writes.Add([pscustomobject]@{ Root = $ClassRoot; RegistryView = $RegistryView; Key = "Software\Classes\$ProgId\shell\open\command"; Name = $null; Value = $Command; Type = 'REG_SZ' })
    }
    $Icon = ConvertTo-QSetupManifestPath -Value $Fields[6].Trim() -Directive $Directive
    if ($Icon) {
      $IconNumber = $Fields[7].Trim()
      $IconValue = $IconNumber ? "$Icon,$IconNumber" : $Icon
      $Writes.Add([pscustomobject]@{ Root = $ClassRoot; RegistryView = $RegistryView; Key = "Software\Classes\$ProgId\DefaultIcon"; Name = $null; Value = $IconValue; Type = 'REG_SZ' })
    }
  }

  # Custom project registry actions are stronger evidence than defaults because
  # they name the exact root, key, value, type, and setup action compiled by the builder.
  foreach ($Operation in @($RegistryOperation)) {
    if ($Operation.SetupAction -notmatch '^(?i:Create|Create if not Exist)$') { continue }
    $OperationRegistryView = $Operation.Key -match '^(?i:Software\\Wow6432Node)(?:\\|$)' ? '32-bit' : $RegistryView
    $Writes.Add([pscustomobject]@{
        Root = $Operation.Root; RegistryView = $OperationRegistryView; Key = $Operation.Key; Name = $Operation.Name; Value = $Operation.Value
        Type = $Operation.Type; Source = $Operation
      })
  }
  return $Writes.ToArray()
}

function Get-QSetupCustomArpInfo {
  <#
  .SYNOPSIS
    Reconstruct explicit custom Apps & Features keys from decoded registry writes.
  .PARAMETER RegistryWrite
    Literal registry writes including their QSetup operation source.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $Result = [Collections.Generic.List[object]]::new()
  $Groups = @($RegistryWrite | Where-Object {
      $_.Source -isnot [string] -and $_.Root -in @('HKLM', 'HKCU') -and $_.Key -match '^(?i:Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\)(?<Code>.+)$'
    } | Group-Object -Property Root, Key)
  foreach ($Group in $Groups) {
    $Writes = @($Group.Group)
    $Key = [string]$Writes[0].Key
    $Code = $Key.Substring($Key.LastIndexOf('\') + 1)
    $Values = @{}
    foreach ($Write in $Writes) { $Values[[string]$Write.Name] = $Write.Value }
    $SystemComponent = $Values.ContainsKey('SystemComponent') ? [int64]$Values['SystemComponent'] : 0
    $Result.Add([pscustomobject][ordered]@{
        Root                 = $Writes[0].Root
        Key                  = $Key
        ProductCode          = $Code
        Scope                = $Writes[0].Root -eq 'HKLM' ? 'machine' : 'user'
        RegistryView         = $Writes[0].RegistryView ? $Writes[0].RegistryView : 'default'
        DisplayName          = $Values['DisplayName']
        DisplayVersion       = $Values['DisplayVersion']
        Publisher            = $Values['Publisher']
        InstallLocation      = $Values['InstallLocation']
        UninstallString      = $Values['UninstallString']
        QuietUninstallString = $Values['QuietUninstallString']
        DisplayIcon          = $Values['DisplayIcon']
        SystemComponent      = $SystemComponent
        Visible              = $SystemComponent -ne 1
        RegistryWrites       = $Writes
      })
  }
  return $Result.ToArray()
}

function Get-QSetupCompanionInventory {
  <#
  .SYNOPSIS
    Enumerate only caller-supplied companion files and explicit directory trees.
  .PARAMETER CompanionPath
    Exact companion files or directories. No neighboring files are discovered implicitly.
  #>
  [OutputType([pscustomobject[]])]
  param ([AllowNull()][string[]]$CompanionPath)

  $Result = [Collections.Generic.List[object]]::new()
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($InputPath in @($CompanionPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    $Resolved = Resolve-InstallerFileSystemPath -Path $InputPath
    $Item = Get-Item -LiteralPath $Resolved -Force
    $Files = $Item.PSIsContainer ? @(Get-ChildItem -LiteralPath $Item.FullName -File -Recurse) : @($Item)
    foreach ($File in $Files) {
      if (-not $Seen.Add($File.FullName)) { throw "The QSetup companion path was supplied more than once: $($File.FullName)" }
      $RelativePath = $Item.PSIsContainer ? [IO.Path]::GetRelativePath($Item.FullName, $File.FullName) : $File.Name
      $Result.Add([pscustomobject][ordered]@{ FullName = $File.FullName; Name = $File.Name; Length = $File.Length; RelativePath = $RelativePath; Root = $Item.FullName })
      if ($Result.Count -gt $Script:QSetupMaximumRecords) { throw 'The QSetup companion inventory exceeds the entry limit.' }
    }
  }
  return $Result.ToArray()
}

function Get-QSetupPhysicalMediaContext {
  <#
  .SYNOPSIS
    Bind one parsed setup kernel to its authenticated physical record source.
  .PARAMETER InstallerPath
    Resolved path of the setup kernel or single-file setup.
  .PARAMETER MainLayout
    Validated layout parsed from InstallerPath.
  .PARAMETER CompanionFile
    Explicit companion inventory used to resolve a split descriptor.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][psobject]$MainLayout,
    [AllowNull()][object[]]$CompanionFile
  )

  $File = Get-Item -LiteralPath $InstallerPath -Force
  $MediaRoute = 'SingleFileSfx'
  $MediaParts = [Collections.Generic.List[string]]::new()
  $MediaParts.Add($File.FullName)
  $Layout = $MainLayout
  $Records = [Collections.Generic.List[object]]::new()
  foreach ($Record in $MainLayout.Records) {
    $Record | Add-Member -NotePropertyName SourcePath -NotePropertyValue $File.FullName -Force
    $Record | Add-Member -NotePropertyName SourceRole -NotePropertyValue 'Main' -Force
    $Record | Add-Member -NotePropertyName DataEndOffset -NotePropertyValue $MainLayout.DataEndOffset -Force
    $Records.Add($Record)
  }

  # A split kernel has a zero-record footer and names one authenticated raw
  # companion stream. Resolve that exact file only from caller-supplied paths.
  if ($MainLayout.SplitDescriptor -and $MainLayout.Records.Count -eq 0) {
    $MatchingCompanions = @($CompanionFile | Where-Object Name -IEQ $MainLayout.SplitDescriptor.CompanionName)
    if ($MatchingCompanions.Count -eq 0) { throw "The QSetup split kernel requires the explicitly supplied companion '$($MainLayout.SplitDescriptor.CompanionName)'." }
    if ($MatchingCompanions.Count -gt 1) { throw "More than one supplied file matches the QSetup split companion '$($MainLayout.SplitDescriptor.CompanionName)'." }
    if ($MainLayout.SplitDescriptor.DeclaredLength -and $MatchingCompanions[0].Length -ne $MainLayout.SplitDescriptor.DeclaredLength) { throw 'The QSetup split companion length does not match the kernel descriptor.' }
    $CompanionLayout = Get-QSetupLayout -Path $MatchingCompanions[0].FullName -PackageOffset 0
    if (-not $CompanionLayout.Complete -or -not $CompanionLayout.SplitDescriptor -or
      $CompanionLayout.Preamble.Preamble -cne $MainLayout.Preamble.Preamble -or
      $CompanionLayout.SplitDescriptor.Secret -cne $MainLayout.SplitDescriptor.Secret -or
      $CompanionLayout.SplitDescriptor.CompanionName -ine $MainLayout.SplitDescriptor.CompanionName) {
      throw 'The supplied QSetup split companion does not authenticate against the kernel descriptor.'
    }
    $Records.Clear()
    foreach ($Record in $CompanionLayout.Records) {
      $Record | Add-Member -NotePropertyName SourcePath -NotePropertyValue $MatchingCompanions[0].FullName -Force
      $Record | Add-Member -NotePropertyName SourceRole -NotePropertyValue 'SplitCompanion' -Force
      $Record | Add-Member -NotePropertyName DataEndOffset -NotePropertyValue $CompanionLayout.DataEndOffset -Force
      $Records.Add($Record)
    }
    $Layout = $CompanionLayout
    $MediaRoute = 'SplitKernel'
    $MediaParts.Add($MatchingCompanions[0].FullName)
    $CompanionFile = @($CompanionFile | Where-Object FullName -INE $MatchingCompanions[0].FullName)
  }

  [pscustomobject][ordered]@{
    MainLayout             = $MainLayout
    Layout                 = $Layout
    Records                = $Records.ToArray()
    MediaRoute             = $MediaRoute
    MediaParts             = $MediaParts.ToArray()
    RemainingCompanionFile = [object[]]$CompanionFile
  }
}

function Disconnect-QSetupEphemeralMediaReference {
  <#
  .SYNOPSIS
    Detach returned metadata from a temporary reconstructed or nested media file.
  .PARAMETER Info
    QSetup result whose payload and record source paths refer to temporary media.
  .PARAMETER SourceRole
    Stable logical role retained after the temporary source path is removed.
  #>
  param (
    [Parameter(Mandatory)][psobject]$Info,
    [Parameter(Mandatory)][string]$SourceRole
  )

  foreach ($Record in @($Info.Records)) {
    $Record.SourcePath = $null
    $Record.SourceRole = $SourceRole
  }
  foreach ($Payload in @($Info.PayloadCatalog)) {
    if (-not $Payload.Record) { continue }
    $Payload.Record.SourcePath = $null
    $Payload.Record.SourceRole = $SourceRole
  }
}

function Get-QSetupSpannedPartPath {
  <#
  .SYNOPSIS
    Validate a complete caller-supplied .001, .002, ... sequence for one setup EXE.
  .PARAMETER InstallerPath
    Resolved path of the first spanned-media file.
  .PARAMETER CompanionFile
    Explicit companion file inventory.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][string]$InstallerPath, [AllowNull()][object[]]$CompanionFile)

  $MainName = [IO.Path]::GetFileName($InstallerPath)
  $Parts = [Collections.Generic.List[object]]::new()
  foreach ($File in @($CompanionFile)) {
    $Match = [regex]::Match($File.Name, '^' + [regex]::Escape($MainName) + '\.(?<Part>\d{3})$', 'IgnoreCase')
    if (-not $Match.Success) { continue }
    $Parts.Add([pscustomobject]@{ Number = [int]$Match.Groups['Part'].Value; Path = $File.FullName })
  }
  if ($Parts.Count -eq 0) { return @() }
  $Ordered = @($Parts | Sort-Object Number)
  for ($Index = 0; $Index -lt $Ordered.Count; $Index++) {
    if ($Ordered[$Index].Number -ne $Index + 1) { throw "The QSetup spanned media is missing part $($MainName).$('{0:D3}' -f ($Index + 1))." }
  }
  return [string[]]$Ordered.Path
}

function Join-QSetupSpannedMedia {
  <#
  .SYNOPSIS
    Concatenate a validated spanned QSetup stream into an automatically deleted temporary file.
  .PARAMETER InstallerPath
    Resolved first media file.
  .PARAMETER PartPath
    Strictly ordered continuation files.
  .PARAMETER MaximumBytes
    Aggregate byte limit for the reconstructed stream.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][string[]]$PartPath,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes = 34359738368
  )

  $TemporaryPath = New-TempFile
  $Output = [IO.File]::Open($TemporaryPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    $Written = 0L
    foreach ($SourcePath in @($InstallerPath) + $PartPath) {
      $InputStream = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        $Remaining = $MaximumBytes - $Written
        if ($Remaining -le 0) { throw 'The QSetup spanned media exceeds the reconstruction limit.' }
        $Written += Copy-BoundedStream -Source $InputStream -Destination $Output -MaximumBytes $Remaining
      } finally { $InputStream.Dispose() }
    }
  } catch {
    $Output.Dispose()
    Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
    throw
  } finally {
    if ($Output) { $Output.Dispose() }
  }
  return $TemporaryPath
}

function Resolve-QSetupExternalPayload {
  <#
  .SYNOPSIS
    Resolve one non-SFX payload against an explicit companion inventory.
  .PARAMETER Payload
    QSetup payload catalog entry.
  .PARAMETER CompanionFile
    Explicit files available for exact relative-path or filename matching.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Payload, [AllowNull()][object[]]$CompanionFile)

  $Names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Name in @($Payload.RecordName, $Payload.InstalledName)) {
    if ($Name) { $null = $Names.Add($Name); $null = $Names.Add("$Name._z") }
  }
  $MatchingFiles = @($CompanionFile | Where-Object { $Names.Contains($_.Name) -or $Names.Contains($_.RelativePath) })
  if ($MatchingFiles.Count -gt 1) { throw "More than one explicit QSetup companion matches '$($Payload.RecordName)'." }
  if ($MatchingFiles.Count -eq 0) { return $null }
  [pscustomobject][ordered]@{
    Path        = $MatchingFiles[0].FullName
    Compression = $MatchingFiles[0].Name.EndsWith('._z', [StringComparison]::OrdinalIgnoreCase) ? 'Zlib' : 'Stored'
    Length      = $MatchingFiles[0].Length
  }
}

function Export-QSetupPayload {
  <#
  .SYNOPSIS
    Export one embedded or explicitly supplied QSetup payload through a common bounded path.
  .PARAMETER Payload
    Catalog entry containing either Record.SourcePath or ExternalSource.
  .PARAMETER OutputPath
    Validated output path.
  .PARAMETER MaximumBytes
    Maximum decoded bytes written.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][psobject]$Payload,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  if ($Payload.Record) {
    $SourcePath = [string]$Payload.Record.SourcePath
    if (-not $SourcePath) { throw "QSetup record '$($Payload.RecordName)' has no source-media identity." }
    $Source = [IO.File]::Open($SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try { return Export-QSetupRecord -Stream $Source -Record $Payload.Record -OutputPath $OutputPath -MaximumBytes $MaximumBytes } finally { $Source.Dispose() }
  }
  if (-not $Payload.ExternalSource) { throw "QSetup payload '$($Payload.RecordName)' requires an explicit non-SFX companion file." }

  $Parent = [IO.Path]::GetDirectoryName($OutputPath)
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $InputStream = [IO.File]::Open($Payload.ExternalSource.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  $Decoder = $null
  $Output = $null
  try {
    $ReadStream = $InputStream
    if ($Payload.ExternalSource.Compression -eq 'Zlib') {
      $Decoder = New-InstallerDecompressionStream -Algorithm Zlib -Stream $InputStream -LeaveOpen
      $ReadStream = $Decoder
    }
    $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $null = Copy-BoundedStream -Source $ReadStream -Destination $Output -MaximumBytes $MaximumBytes
  } finally {
    if ($Output) { $Output.Dispose() }
    if ($Decoder) { $Decoder.Dispose() }
    $InputStream.Dispose()
  }
  return Get-Item -LiteralPath $OutputPath -Force
}

function Get-QSetupPayloadAnalysis {
  <#
  .SYNOPSIS
    Materialize only the configured main executable and bounded adjacent sidecars for PE analysis.
  .PARAMETER PayloadCatalog
    Resolved installed payload catalog.
  .PARAMETER MainExecutable
    Manifest-safe configured main executable path.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$PayloadCatalog, [AllowNull()][string]$MainExecutable)

  $Diagnostics = [Collections.Generic.List[object]]::new()
  if (-not $MainExecutable) { return [pscustomobject]@{ Architecture = $null; Dependencies = $null; InspectedFiles = @(); Diagnostics = @() } }
  $MainName = [IO.Path]::GetFileName($MainExecutable)
  $Primary = @($PayloadCatalog | Where-Object { $_.InstalledPath -ieq $MainExecutable })
  if ($Primary.Count -eq 0) { $Primary = @($PayloadCatalog | Where-Object { $_.InstalledName -ieq $MainName }) }
  if ($Primary.Count -ne 1) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Payload.MainExecutableUnresolved' -Source QSetup -Message "The configured main executable '$MainExecutable' does not resolve to one payload record." -Kind Incomplete -Areas Metadata -AffectedFields Architecture, Dependencies))
    return [pscustomobject]@{ Architecture = $null; Dependencies = $null; InspectedFiles = @(); Diagnostics = $Diagnostics.ToArray() }
  }

  $Directory = [IO.Path]::GetDirectoryName([string]$Primary[0].InstalledPath)
  $Selected = [Collections.Generic.List[object]]::new()
  $Selected.Add($Primary[0])
  foreach ($Payload in @($PayloadCatalog | Where-Object {
        $_ -ne $Primary[0] -and [IO.Path]::GetDirectoryName([string]$_.InstalledPath) -ieq $Directory -and
        ([IO.Path]::GetExtension([string]$_.InstalledName) -ieq '.dll' -or $_.InstalledName -match '(?i)\.(?:runtimeconfig|deps)\.json$')
      } | Select-Object -First 64)) { $Selected.Add($Payload) }

  $TemporaryDirectory = New-TempFolder
  try {
    $Materialized = [Collections.Generic.List[string]]::new()
    $Inspected = [Collections.Generic.List[string]]::new()
    $Written = 0L
    foreach ($Payload in $Selected) {
      if (-not $Payload.Record -and -not $Payload.ExternalSource) { continue }
      $OutputPath = Resolve-SafeExtractionPath -DestinationPath $TemporaryDirectory -RelativePath $Payload.InstalledName
      $Remaining = $Script:QSetupMaximumPayloadAnalysisBytes - $Written
      if ($Remaining -le 0) { break }
      $File = Export-QSetupPayload -Payload $Payload -OutputPath $OutputPath -MaximumBytes $Remaining
      $Written += $File.Length
      $Materialized.Add($File.FullName)
      $Inspected.Add($Payload.InstalledPath)
    }
    if ($Materialized.Count -eq 0) { return [pscustomobject]@{ Architecture = $null; Dependencies = $null; InspectedFiles = @(); Diagnostics = @() } }
    $Architecture = Get-PEArchitectureInfo -Path $Materialized[0] -RelatedFile @($Materialized | Select-Object -Skip 1 | Where-Object { [IO.Path]::GetExtension($_) -ieq '.dll' })
    $Dependencies = Get-PEDependencyInfo -Path $Materialized[0] -RelatedFile @($Materialized | Select-Object -Skip 1)
    foreach ($Diagnostic in @($Architecture.Diagnostics + $Dependencies.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    [pscustomobject][ordered]@{
      Architecture   = [pscustomobject][ordered]@{
        IsManaged = $Architecture.IsManaged; IsAnyCpu = $Architecture.IsAnyCpu; MachineName = $Architecture.MachineName
        SupportedArchitectures = $Architecture.SupportedArchitectures; RecommendedArchitecture = $Architecture.RecommendedWinGetArchitecture
        TargetFramework = $Architecture.TargetFramework
      }
      Dependencies   = [pscustomobject][ordered]@{
        ImportedDlls = @($Dependencies.ImportedDlls | Select-Object Directory, DllName)
        DependsOnVCRedist = $Dependencies.DependsOnVCRedist; DependsOnUcrt = $Dependencies.DependsOnUcrt
        DependsOnDotNetRuntime = $Dependencies.DependsOnDotNetRuntime
        RecommendedPackageDependencyIds = $Dependencies.RecommendedPackageDependencyIds
        RecommendedPackageDependencies = $Dependencies.RecommendedPackageDependencies
      }
      InspectedFiles = $Inspected.ToArray()
      Diagnostics    = $Diagnostics.ToArray()
    }
  } catch {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Payload.PEAnalysisFailed' -Source QSetup -Message "QSetup payload PE analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture, Dependencies))
    [pscustomobject]@{ Architecture = $null; Dependencies = $null; InspectedFiles = @(); Diagnostics = $Diagnostics.ToArray() }
  } finally {
    Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-QSetupInfo {
  <#
  .SYNOPSIS
    Read QSetup project, ARP, scope, architecture, and association metadata
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER CompanionPath
    Explicit split, spanned, or non-SFX companion files/directories. Neighboring files are never guessed.
  .PARAMETER MaximumWrapperDepth
    Maximum nested QSetup wrapper depth. Used internally to bound tiny-wrapper recursion.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string[]]$CompanionPath,
    [ValidateRange(0, 4)][int]$MaximumWrapperDepth = 2
  )

  process {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $File = Get-Item -LiteralPath $ResolvedPath -Force
    $CompanionInventory = @(Get-QSetupCompanionInventory -CompanionPath $CompanionPath)
    $SpannedPartPath = @(Get-QSetupSpannedPartPath -InstallerPath $File.FullName -CompanionFile $CompanionInventory)
    $MainLayoutError = $null
    $Source = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      try { $MainLayout = Get-QSetupLayout -Stream $Source } catch { $MainLayoutError = $_.Exception; $MainLayout = $null }
    } finally { $Source.Dispose() }

    # Spanned output is a byte-for-byte continuation of the main setup. Rebuild
    # it only from an explicit, gap-free part list, parse it recursively, and
    # remove the temporary stream before returning detached metadata.
    if ($SpannedPartPath.Count -gt 0 -and (-not $MainLayout -or -not $MainLayout.Complete)) {
      $CombinedPath = Join-QSetupSpannedMedia -InstallerPath $File.FullName -PartPath $SpannedPartPath
      try {
        $RemainingCompanionPath = @($CompanionInventory | Where-Object FullName -NotIn $SpannedPartPath | Select-Object -ExpandProperty FullName)
        $SpannedInfo = Get-QSetupInfo -Path $CombinedPath -CompanionPath $RemainingCompanionPath
        Disconnect-QSetupEphemeralMediaReference -Info $SpannedInfo -SourceRole 'SpannedLogicalStream'
        $SpannedInfo.Path = $File.FullName
        $SpannedInfo | Add-Member -NotePropertyName MediaRoute -NotePropertyValue 'SpannedConcatenation' -Force
        $SpannedInfo | Add-Member -NotePropertyName MediaParts -NotePropertyValue ([string[]]@($File.FullName) + $SpannedPartPath) -Force
        $SpannedInfo.StructuralRoutes = [string[]]@('SpannedConcatenation') + @($SpannedInfo.StructuralRoutes | Where-Object { $_ -ne 'SingleFileSfx' })
        return $SpannedInfo
      } finally { Remove-Item -LiteralPath $CombinedPath -Force -ErrorAction SilentlyContinue }
    }
    if (-not $MainLayout) { throw $MainLayoutError }

    $MediaContext = Get-QSetupPhysicalMediaContext -InstallerPath $File.FullName -MainLayout $MainLayout -CompanionFile $CompanionInventory
    $MediaRoute = $MediaContext.MediaRoute
    $MediaParts = $MediaContext.MediaParts
    $Layout = $MediaContext.Layout
    $Records = $MediaContext.Records
    $CompanionInventory = $MediaContext.RemainingCompanionFile

    # Setup.txt is authoritative. Read it from the media file that owns its
    # validated record instead of scanning payload strings or the outer PE.
    $SetupRecord = $Records | Where-Object Name -ieq 'Setup.txt' | Select-Object -First 1
    if (-not $SetupRecord -and $MaximumWrapperDepth -gt 0) {
      $NestedCandidates = @($Records | Where-Object { $_.Name -match '(?i)\.exe$' -and $_.CompressedLength -le $Script:QSetupMaximumPayloadAnalysisBytes })
      foreach ($Candidate in $NestedCandidates) {
        $TemporaryPath = New-TempFile
        try {
          $NestedPayload = [pscustomobject]@{ Record = $Candidate; RecordName = $Candidate.Name; ExternalSource = $null }
          $null = Export-QSetupPayload -Payload $NestedPayload -OutputPath $TemporaryPath -MaximumBytes $Script:QSetupMaximumPayloadAnalysisBytes
          try { $NestedInfo = Get-QSetupInfo -Path $TemporaryPath -MaximumWrapperDepth ($MaximumWrapperDepth - 1) } catch { continue }
          Disconnect-QSetupEphemeralMediaReference -Info $NestedInfo -SourceRole 'NestedLogicalStream'
          $NestedInfo.Path = $File.FullName
          $NestedInfo | Add-Member -NotePropertyName MediaRoute -NotePropertyValue 'NestedSfxWrapper' -Force
          $NestedInfo | Add-Member -NotePropertyName MediaParts -NotePropertyValue ([string[]]@($File.FullName)) -Force
          $NestedInfo | Add-Member -NotePropertyName NestedInstallerRecord -NotePropertyValue $Candidate.Name -Force
          $NestedInfo.StructuralRoutes = [string[]]@('NestedSfxWrapper') + @($NestedInfo.StructuralRoutes)
          return $NestedInfo
        } finally { Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue }
      }
    }
    if (-not $SetupRecord) { throw 'The QSetup package does not contain Setup.txt in its parsed records' }
    $SetupSource = [IO.File]::Open($SetupRecord.SourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $SetupData = Read-QSetupRecord -Stream $SetupSource -Offset $SetupRecord.Offset -ReadContent -MaximumContentBytes $Script:QSetupMaximumConfigurationBytes -EndOffset $SetupRecord.DataEndOffset
    } finally { $SetupSource.Dispose() }
    $SetupText = [Text.Encoding]::UTF8.GetString($SetupData.Content).TrimStart([char]0, [char]0xFEFF)
    $DirectiveRecord = @(Get-QSetupDirectiveRecord -Content $SetupText)
    $Directive = ConvertFrom-QSetupDirectiveText -Content $SetupText
    if (-not $Directive.ContainsKey('SET_COMPOSER_BUILD')) { throw 'The Setup.txt record does not contain QSetup composer evidence' }
    $ExecutionActionInfo = Get-QSetupExecutionActionInfo -Directive $Directive
    $PayloadCatalog = @(Get-QSetupPayloadCatalog -DirectiveRecord $DirectiveRecord -Directive $Directive -Record $Records)
    foreach ($Payload in $PayloadCatalog) {
      if (-not $Payload.IsEmbedded) { $Payload | Add-Member -NotePropertyName ExternalSource -NotePropertyValue (Resolve-QSetupExternalPayload -Payload $Payload -CompanionFile $CompanionInventory) -Force }
    }
    $Shortcuts = @(Get-QSetupShortcutInfo -Directive $Directive)
    $EnvironmentChanges = @(Get-QSetupEnvironmentChange -Directive $Directive)
    $StructuredOperations = Get-QSetupStructuredOperationInfo -Directive $Directive
    $SystemEffectInfo = Get-QSetupSystemEffectInfo -ExecutionAction $ExecutionActionInfo.Actions -DirectiveRecord $DirectiveRecord

    $DisplayName = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_ADD_REMOVE_PROGRAMS_DISPLAY_NAME' -FallbackName 'SET_PROG_NAME'
    $DisplayVersion = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_PROG_VERSION'
    $Publisher = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_COMPANY_NAME'
    $InstallLocation = ConvertTo-QSetupManifestPath -Value (Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_TARGET_DIR') -Directive $Directive
    $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $File.FullName
    $AllowedOs = [string](Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_ALLOWED_OS')
    $Only64BitOs = $AllowedOs -match '(?i)\.64' -and $AllowedOs -notmatch '(?i)(?:^|,)(?:XP|Vista|7|8|8\.1|10|11)(?:,|$)'
    $OuterMachine = (Get-PELayout -Path $File.FullName).MachineName
    $OuterArchitecture = switch ($OuterMachine) { 'I386' { 'x86' } 'Amd64' { 'x64' } 'AMD64' { 'x64' } 'Arm64' { 'arm64' } 'ARM64' { 'arm64' } default { $null } }
    $RegistryViewInfo = Get-QSetupRegistryViewInfo -OuterMachine $OuterMachine -AllowedOperatingSystems $AllowedOs

    # Explicit current/all-user directives win. Newer launchers also carry an
    # authoritative UAC manifest; machine-only destinations are secondary evidence.
    $Scope = if ($Directive.ContainsKey('SET_ALL_USERS')) {
      'machine'
    } elseif ($Directive.ContainsKey('SET_CURRENT_USER')) {
      'user'
    } elseif ($RequestedExecutionLevel -eq 'requireAdministrator') {
      'machine'
    } elseif ($InstallLocation -match '^%(?:LOCALAPPDATA|APPDATA|USERPROFILE)%') {
      'user'
    } elseif ($InstallLocation -match '^%(?:ProgramFiles|CommonProgramFiles|ProgramData|WINDIR)%') {
      'machine'
    } else {
      $null
    }
    $ScopeEvidence = if ($Directive.ContainsKey('SET_ALL_USERS')) {
      'SET_ALL_USERS'
    } elseif ($Directive.ContainsKey('SET_CURRENT_USER')) {
      'SET_CURRENT_USER'
    } elseif ($RequestedExecutionLevel -eq 'requireAdministrator') {
      'PE requestedExecutionLevel=requireAdministrator'
    } elseif ($Scope) {
      'Resolved installation destination'
    } else {
      $null
    }

    $BuiltInWritesArp = (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_CREATE_UNINSTALL') -and
    (Test-QSetupDirectiveEnabled -Directive $Directive -Name 'SET_ADD_UNINSTALL_TO_ADD_REMOVE_PROGRAMS') -and
    -not [string]::IsNullOrWhiteSpace($DisplayName)
    $RegistryWrites = @(ConvertTo-QSetupRegistryEvidence -Directive $Directive -Scope $Scope -InstallLocation $InstallLocation -RegistryOperation $StructuredOperations.RegistryOperations -RegistryView $RegistryViewInfo.RegistryView)
    $CustomArpEntries = @(Get-QSetupCustomArpInfo -RegistryWrite $RegistryWrites)
    $VisibleCustomArpEntries = @($CustomArpEntries | Where-Object Visible)
    $WritesAppsAndFeaturesEntry = $VisibleCustomArpEntries.Count -gt 0 -or $BuiltInWritesArp
    $ProductCode = $BuiltInWritesArp ? $DisplayName : $null
    $UninstallerInfo = Get-QSetupUninstallerInfo -Directive $Directive -InstallLocation $InstallLocation
    if ($VisibleCustomArpEntries.Count -gt 0) {
      $Scopes = @($VisibleCustomArpEntries.Scope | Sort-Object -Unique)
      if ($Scopes.Count -eq 1) { $Scope = $Scopes[0]; $ScopeEvidence = 'SET_PERFORM_REGISTRY_OP uninstall key' }
      if ($VisibleCustomArpEntries.Count -eq 1) {
        $CustomArp = $VisibleCustomArpEntries[0]
        $ProductCode = $CustomArp.ProductCode
        if ($CustomArp.DisplayName) { $DisplayName = $CustomArp.DisplayName }
        if ($CustomArp.DisplayVersion) { $DisplayVersion = $CustomArp.DisplayVersion }
        if ($CustomArp.Publisher) { $Publisher = $CustomArp.Publisher }
        if ($CustomArp.InstallLocation) { $InstallLocation = $CustomArp.InstallLocation }
      } else { $ProductCode = $null }
    }
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    # Execution Engine associations do not necessarily have literal registry
    # rows in Setup.txt. Promote only unconditional setup-time creation; retain
    # every other association command as conditional system-effect evidence.
    $ExecutionAssociationExtensions = @($SystemEffectInfo.FileAssociations | Where-Object {
        $_.Operation -eq 'Create File Association' -and $_.AppliesDuring -eq 'Setup' -and $_.ConditionState -eq 'True'
      } | ForEach-Object {
        $Extension = ([string]$_.Argument3).Trim().TrimStart('.')
        if ($Extension -match '^[^\s.\\/:*?"<>|]+$') { $Extension }
      } | Sort-Object -Culture en-US -Unique)
    $FileExtensions = @($RegistryAssociationInfo.FileExtensions + $ExecutionAssociationExtensions | Where-Object { $_ } | Sort-Object -Culture en-US -Unique)
    $ArpWrites = @($RegistryWrites | Where-Object { $_.Key -match '(?i)\\Uninstall\\' })
    $ArpRegistryViews = @($VisibleCustomArpEntries.RegistryView | Where-Object { $_ } | Sort-Object -Unique)
    $RegistryView = $ArpRegistryViews.Count -eq 1 ? $ArpRegistryViews[0] : $RegistryViewInfo.RegistryView
    $UninstallString = if ($VisibleCustomArpEntries.Count -eq 1 -and $VisibleCustomArpEntries[0].UninstallString) { $VisibleCustomArpEntries[0].UninstallString } else { $UninstallerInfo.RegistryCommand }
    $QuietUninstallString = $VisibleCustomArpEntries.Count -eq 1 ? $VisibleCustomArpEntries[0].QuietUninstallString : $null
    $DisplayIcon = if ($VisibleCustomArpEntries.Count -eq 1 -and $VisibleCustomArpEntries[0].DisplayIcon) { $VisibleCustomArpEntries[0].DisplayIcon } else { $ArpWrites | Where-Object Name -ieq 'DisplayIcon' | Select-Object -Last 1 -ExpandProperty Value }

    # Allowed OS values describe payload compatibility rather than the PE stub.
    # An exclusively 64-bit set is useful package-architecture evidence; mixed
    # media falls back to the launcher machine only when the configured payload
    # executable cannot provide stronger architecture evidence.
    $MainExecutable = ConvertTo-QSetupManifestPath -Value (Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_PROG_EXE_NAME') -Directive $Directive
    $PayloadAnalysis = Get-QSetupPayloadAnalysis -PayloadCatalog $PayloadCatalog -MainExecutable $MainExecutable
    $PayloadArchitecture = $PayloadAnalysis.Architecture.RecommendedArchitecture
    $PackageArchitecture = $PayloadArchitecture ? $PayloadArchitecture : ($Only64BitOs ? 'x64' : $OuterArchitecture)
    $SupportedArchitectures = $PayloadAnalysis.Architecture.SupportedArchitectures.Count -gt 0 ? @($PayloadAnalysis.Architecture.SupportedArchitectures) : ($PackageArchitecture ? @($PackageArchitecture) : @())

    $DialogList = Get-QSetupDirectiveTextValue -Directive $Directive -Name 'SET_DIALOGS'
    $HasUserInformationDialog = $DialogList -match '(?i)User(?:Information|Info)|InformationDlg' -or
    $Directive.ContainsKey('SET_REQUEST_USER_NAME') -or $Directive.ContainsKey('SET_REQUEST_COMPANY_NAME') -or $Directive.ContainsKey('SET_REQUEST_SERIAL_ALSO')
    $SupportsSilentInstallation = -not $HasUserInformationDialog
    $InstallModes = $SupportsSilentInstallation ? @('interactive', 'silent', 'silentWithProgress') : @('interactive')
    $InstallerSwitches = [ordered]@{ InstallLocation = '/InstallDir="<INSTALLPATH>"' }
    if ($SupportsSilentInstallation) {
      $InstallerSwitches['Silent'] = '/hide'
      $InstallerSwitches['SilentWithProgress'] = '/silent'
    }

    $AppsAndFeaturesEntries = [Collections.Generic.List[object]]::new()
    if ($VisibleCustomArpEntries.Count -gt 0) {
      foreach ($CustomArp in $VisibleCustomArpEntries) {
        $Entry = [ordered]@{}
        foreach ($Property in ([ordered]@{ DisplayName = $CustomArp.DisplayName; DisplayVersion = $CustomArp.DisplayVersion; Publisher = $CustomArp.Publisher; ProductCode = $CustomArp.ProductCode; InstallerType = 'exe' }).GetEnumerator()) {
          if ($null -ne $Property.Value -and -not [string]::IsNullOrWhiteSpace([string]$Property.Value)) { $Entry[$Property.Key] = $Property.Value }
        }
        $AppsAndFeaturesEntries.Add([pscustomobject]$Entry)
      }
    } elseif ($BuiltInWritesArp) {
      $Entry = [ordered]@{}
      foreach ($Property in ([ordered]@{ DisplayName = $DisplayName; DisplayVersion = $DisplayVersion; Publisher = $Publisher; ProductCode = $ProductCode; InstallerType = 'exe' }).GetEnumerator()) {
        if ($null -ne $Property.Value -and -not [string]::IsNullOrWhiteSpace([string]$Property.Value)) { $Entry[$Property.Key] = $Property.Value }
      }
      $AppsAndFeaturesEntries.Add([pscustomobject]$Entry)
    }

    $Diagnostics = [Collections.Generic.List[object]]::new()
    foreach ($Diagnostic in @($MainLayout.Diagnostics + $Layout.Diagnostics + $ExecutionActionInfo.Diagnostics + $StructuredOperations.Diagnostics + $RegistryAssociationInfo.Diagnostics + $PayloadAnalysis.Diagnostics)) { if ($Diagnostic) { $Diagnostics.Add($Diagnostic) } }
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    if (-not $Scope) {
      $UnresolvedFields.Add('Scope')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Scope.Unresolved' -Source QSetup -Message 'QSetup scope is not explicit in structured evidence and requires VM validation.' -Kind Incomplete -Areas Installability, Metadata -AffectedFields Scope))
    }
    if ($WritesAppsAndFeaturesEntry -and -not $UninstallString) {
      $UnresolvedFields.Add('UninstallString')
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.UninstallString.Unresolved' -Source QSetup -Message 'QSetup uninstall registration is enabled, but neither an explicit name, compiled shortcut target, nor a generation-verified naming formula can be resolved.' -Kind Incomplete -Areas Metadata -AffectedFields AppsAndFeaturesEntries))
    }
    if ($HasUserInformationDialog) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Silent.UserInformationDialog' -Source QSetup -Message 'The compiled User Information dialog disables QSetup /silent and /hide behavior.' -Kind Unsupported -Areas Installability -AffectedFields InstallModes, InstallerSwitches))
    }
    if ($ExecutionActionInfo.Actions.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.ExecutionActions.Present' -Source QSetup -Message "QSetup defines $($ExecutionActionInfo.Actions.Count) structured execution action(s); review ExecutionActions and ExecutedPayloads for prerequisites and side effects." -Kind Information -Areas Installability))
    }
    if (@($PayloadCatalog | Where-Object { -not $_.InstalledPath }).Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.PayloadPath.Unresolved' -Source QSetup -Message 'One or more payload destinations contain unresolved QSetup aliases.' -Kind Incomplete -Areas Extraction -AffectedFields ExtractedFiles))
    }
    $MissingExternalPayloads = @($PayloadCatalog | Where-Object { -not $_.IsEmbedded -and -not $_.ExternalSource })
    if ($MissingExternalPayloads.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Payload.ExternalCompanionRequired' -Source QSetup -Message "$($MissingExternalPayloads.Count) non-SFX QSetup payload(s) require explicitly supplied companion files for extraction or PE analysis." -Kind Incomplete -Areas Extraction -AffectedFields ExtractedFiles -Evidence @{ Files = @($MissingExternalPayloads.RecordName) }))
    }
    $ConditionalActions = @($ExecutionActionInfo.Actions | Where-Object ConditionState -EQ Unknown)
    if ($ConditionalActions.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.ExecutionConditions.RuntimeDependent' -Source QSetup -Message "$($ConditionalActions.Count) execution action(s) depend on runtime predicates; their system effects are reported conditionally." -Kind ManualValidation -Areas Installability -Evidence @{ Actions = @($ConditionalActions.Name) }))
    }
    $InteractiveConditions = @($ExecutionActionInfo.Actions | ForEach-Object { $_.Conditions } | Where-Object RequiresUserInteraction)
    $InteractiveOperations = @($SystemEffectInfo.UserInteractionOperations)
    if ($InteractiveConditions.Count -gt 0 -or $InteractiveOperations.Count -gt 0) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.Execution.UserInteraction' -Source QSetup -Message 'The QSetup Execution Engine contains a condition or command that requests user input; verify unattended behavior in a VM.' -Kind ManualValidation -Areas Installability -AffectedFields InstallModes, InstallerSwitches -Evidence @{ Conditions = @($InteractiveConditions.Predicate); Commands = @($InteractiveOperations.Operation) }))
    }
    if ($VisibleCustomArpEntries.Count -gt 1) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'QSetup.ARP.MultipleCustomEntries' -Source QSetup -Message 'QSetup writes multiple visible custom uninstall keys; AppsAndFeaturesEntries preserves each row while installer-level ProductCode remains unresolved.' -Kind Ambiguous -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
      if (-not $UnresolvedFields.Contains('ProductCode')) { $UnresolvedFields.Add('ProductCode') }
    }

    $DotNetRequirementText = [string](Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_DOT_NET_FRAMEWORK_REQ_VER')
    $DotNetRequirements = @($DotNetRequirementText.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object Trim | Where-Object { $_ })
    $MsiCodes = @(([string](Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_MSI_CODES')).Split('|', [StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_ -match '^\{[0-9A-Fa-f-]{36}\}$' })
    $StructuralRoutes = [Collections.Generic.List[string]]::new()
    $StructuralRoutes.Add($MediaRoute)
    if ($MediaRoute -eq 'SplitKernel') { $StructuralRoutes.Add('SplitCompanion') }
    foreach ($Route in @($Layout.StructuralRoutes)) { if (-not $StructuralRoutes.Contains($Route)) { $StructuralRoutes.Add($Route) } }
    if (@($PayloadCatalog | Where-Object { -not $_.IsEmbedded }).Count -gt 0) { $StructuralRoutes.Add('ExternalPayload') }

    [pscustomobject][ordered]@{
      Path                           = $File.FullName
      InstallerType                  = 'exe'
      ProductCode                    = $ProductCode
      UpgradeCode                    = $null
      DisplayName                    = $DisplayName
      DisplayVersion                 = $DisplayVersion
      Publisher                      = $Publisher
      Scope                          = $Scope
      DefaultInstallLocation         = $InstallLocation
      WritesAppsAndFeaturesEntry     = [bool]$WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode     = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
      AppsAndFeaturesInstallerType   = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      Diagnostics                    = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())

      UnresolvedFields               = [string[]]$UnresolvedFields.ToArray()
      Family                         = 'QSetup'
      PublisherUrl                   = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPANY_URL'
      ProjectName                    = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PROJECT_NAME'
      ProjectStamp                   = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_PC_STAMP'
      ComposerBuild                  = Get-QSetupDirectiveValue -Directive $Directive -Name 'SET_COMPOSER_BUILD'
      MainExecutable                 = $MainExecutable
      SupportedScopes                = if ($Scope) { @($Scope) } else { @() }
      SupportedArchitectures         = $SupportedArchitectures
      PackageArchitecture            = $PackageArchitecture
      OuterArchitecture              = $OuterArchitecture
      AllowedOperatingSystems        = $AllowedOs
      RequestedExecutionLevel        = $RequestedExecutionLevel
      ElevationRequirement           = $RequestedExecutionLevel -eq 'requireAdministrator' ? 'elevationRequired' : $null
      ScopeEvidence                  = $ScopeEvidence
      RegistryView                   = $RegistryView
      RegistryViewEvidence           = $ArpRegistryViews.Count -eq 1 ? 'Explicit custom uninstall registry operation' : $RegistryViewInfo.Evidence
      InstallModes                   = [string[]]$InstallModes
      InstallerSwitches              = $InstallerSwitches
      SupportsSilentInstallation     = $SupportsSilentInstallation
      HasUserInformationDialog       = $HasUserInformationDialog
      AppsAndFeaturesEntries         = [object[]]$AppsAndFeaturesEntries.ToArray()
      CustomArpEntries               = [object[]]$CustomArpEntries
      InstallLocation                = $InstallLocation
      UninstallString                = $UninstallString
      QuietUninstallString           = $QuietUninstallString
      DisplayIcon                    = $DisplayIcon
      RegistryWrites                 = $RegistryWrites
      RegistryAssociationInfo        = $RegistryAssociationInfo
      Protocols                      = $RegistryAssociationInfo.Protocols
      FileExtensions                 = [string[]]$FileExtensions
      Shortcuts                      = [object[]]$Shortcuts
      EnvironmentChanges             = [object[]]$EnvironmentChanges
      RegistryOperations             = [object[]]$StructuredOperations.RegistryOperations
      IniFileOperations              = [object[]]$StructuredOperations.IniFileOperations
      XmlOperations                  = [object[]]$StructuredOperations.XmlOperations
      Records                        = @($Records | Select-Object Name, Required, Stamp, Offset, CompressedLength, SourcePath, SourceRole)
      PayloadCatalog                 = [object[]]$PayloadCatalog
      ExtractedFiles                 = @($PayloadCatalog | ForEach-Object { $_.InstalledPath ? $_.InstalledPath : $_.InstalledName })
      CanExpand                      = [bool]$Layout.Complete
      CanExpandAllPayloads           = [bool]($Layout.Complete -and $MissingExternalPayloads.Count -eq 0)
      ExecutionActions               = [object[]]$ExecutionActionInfo.Actions
      ExecutedPayloads               = [object[]]$ExecutionActionInfo.ExecutedPayloads
      SystemEffects                  = [object[]]$SystemEffectInfo.SystemEffects
      Services                       = [object[]]$SystemEffectInfo.Services
      ComRegistrations               = [object[]]$SystemEffectInfo.ComRegistrations
      FontOperations                 = [object[]]$SystemEffectInfo.FontOperations
      DownloadOperations             = [object[]]$SystemEffectInfo.Downloads
      RestartOperations              = [object[]]$SystemEffectInfo.RestartOperations
      WindowsInstallerOperations     = [object[]]$SystemEffectInfo.WindowsInstallers
      ExternalDllActions             = [object[]]$SystemEffectInfo.ExternalDllActions
      FileAssociationOperations      = [object[]]$SystemEffectInfo.FileAssociations
      ExecutionRegistryOperations    = [object[]]$SystemEffectInfo.RegistryOperations
      ExecutionIniFileOperations     = [object[]]$SystemEffectInfo.IniFileOperations
      ExecutionEnvironmentOperations = [object[]]$SystemEffectInfo.EnvironmentOperations
      ArchitectureStateOperations    = [object[]]$SystemEffectInfo.ArchitectureStateOperations
      UserInteractionOperations      = [object[]]$SystemEffectInfo.UserInteractionOperations
      ProcessControlOperations       = [object[]]$SystemEffectInfo.ProcessControlOperations
      PayloadArchitectureInfo        = $PayloadAnalysis.Architecture
      PayloadDependencyInfo          = $PayloadAnalysis.Dependencies
      InspectedPayloadFiles          = [string[]]$PayloadAnalysis.InspectedFiles
      Uninstaller                    = $UninstallerInfo
      PackageFooter                  = $Layout.Footer
      Certificate                    = $Layout.Certificate
      FormatGeneration               = $Layout.FormatGeneration
      StructuralRoutes               = $StructuralRoutes.ToArray()
      MediaRoute                     = $MediaRoute
      MediaParts                     = [string[]]$MediaParts
      SplitDescriptor                = $MainLayout.SplitDescriptor
      SetupDirectives                = $Directive
      DirectiveRecords               = [object[]]$DirectiveRecord
      DotNetFrameworkRequirements    = [string[]]$DotNetRequirements
      MsiCodes                       = [string[]]$MsiCodes
      ParserVersionInfo              = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.QSetup'; ParserMajor = 7; FormatCatalogVersion = $Script:QSetupFormatCatalog.CatalogVersion; Sources = @('validated QSetup generation-specific preamble, zlib record, footer, split descriptor, and certificate routes', 'Setup.txt directives and versioned Execution Engine records', 'official QSetup manual defaults, conditions, commands, and operation field order', 'compiled QSetup 1.0 through 11.0 shortcut and uninstaller records', 'controlled QSetup 12 split, non-SFX, spanned-media, uninstaller, ARP, and process-result observations') }
    }
  }
}

function Export-QSetupRecord {
  <#
  .SYNOPSIS
    Export one QSetup record body to a validated destination
  .PARAMETER Stream
    Seekable caller-owned installer stream. The function consumes only the bounded record and restores no position.
  .PARAMETER Record
    Current structured format node or record being interpreted.
  .PARAMETER OutputPath
    Fully resolved output path selected by the caller after safe-path and collision handling.
  .PARAMETER MaximumBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Record,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  $CompressedRange = New-BoundedReadStream -Stream $Stream -Offset ($Record.Offset + 4) -Length $Record.CompressedLength -LeaveOpen
  $Decoder = New-InstallerDecompressionStream -Algorithm Zlib -Stream $CompressedRange -LeaveOpen
  try {
    $PipeCount = 0
    $HeaderLength = 0
    # Consume the metadata prefix before exporting the remaining decoded bytes
    # as the actual file body named by the validated catalog record.
    while ($HeaderLength -lt 4096 -and $PipeCount -lt 3) { $Value = $Decoder.ReadByte(); if ($Value -lt 0) { break }; $HeaderLength++; if ($Value -eq 0x7C) { $PipeCount++ } }
    if ($PipeCount -ne 3) { throw 'The QSetup record header is invalid during extraction' }
    if ($Decoder.ReadByte() -ne 0) { throw 'The QSetup record body marker is invalid during extraction' }
    $Parent = [IO.Path]::GetDirectoryName($OutputPath)
    if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
    $Output = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $null = Copy-BoundedStream -Source $Decoder -Destination $Output -MaximumBytes $MaximumBytes
    } finally { $Output.Dispose() }
    return Get-Item -LiteralPath $OutputPath -Force
  } finally { $Decoder.Dispose(); $CompressedRange.Dispose() }
}

function Expand-QSetupInstaller {
  <#
  .SYNOPSIS
    Extract QSetup zlib records without executing the installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Optional exact name or wildcard selecting an installed path/file name, or a physical record in RawRecords mode. Omit it to expand all entries.
  .PARAMETER CompanionPath
    Explicit split, spanned, or non-SFX companion files/directories. Neighboring files are never guessed.
  .PARAMETER RawRecords
    Export physical QSetup records under _qsetup\records instead of reconstructing installed payload paths.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name,
    [string[]]$CompanionPath,
    [switch]$RawRecords,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184
  )

  process {
    $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $CompanionInventory = @(Get-QSetupCompanionInventory -CompanionPath $CompanionPath)
    $SpannedPartPath = @(Get-QSetupSpannedPartPath -InstallerPath $ResolvedPath -CompanionFile $CompanionInventory)
    if ($SpannedPartPath.Count -gt 0) {
      $CombinedPath = Join-QSetupSpannedMedia -InstallerPath $ResolvedPath -PartPath $SpannedPartPath
      try {
        $RemainingCompanionPath = @($CompanionInventory | Where-Object FullName -NotIn $SpannedPartPath | Select-Object -ExpandProperty FullName)
        return Expand-QSetupInstaller -Path $CombinedPath -DestinationPath $DestinationPath -Name $Name -CompanionPath $RemainingCompanionPath -RawRecords:$RawRecords -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
      } finally { Remove-Item -LiteralPath $CombinedPath -Force -ErrorAction SilentlyContinue }
    }
    if (-not $RawRecords) {
      try { $OuterLayout = Get-QSetupLayout -Path $ResolvedPath } catch { $OuterLayout = $null }
      if ($OuterLayout -and $OuterLayout.Complete -and -not ($OuterLayout.Records | Where-Object Name -IEQ 'Setup.txt')) {
        foreach ($Candidate in @($OuterLayout.Records | Where-Object { $_.Name -match '(?i)\.exe$' -and $_.CompressedLength -le $Script:QSetupMaximumPayloadAnalysisBytes })) {
          $Candidate | Add-Member -NotePropertyName SourcePath -NotePropertyValue $ResolvedPath -Force
          $TemporaryPath = New-TempFile
          try {
            $NestedPayload = [pscustomobject]@{ Record = $Candidate; RecordName = $Candidate.Name; ExternalSource = $null }
            $null = Export-QSetupPayload -Payload $NestedPayload -OutputPath $TemporaryPath -MaximumBytes $Script:QSetupMaximumPayloadAnalysisBytes
            if (Test-QSetup -Path $TemporaryPath) {
              return Expand-QSetupInstaller -Path $TemporaryPath -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
            }
          } finally { Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue }
        }
      }
    }
    if ($RawRecords) {
      # Raw mode exports the physical records of the requested media layer. It
      # does not follow an embedded setup wrapper, whose records
      # are a separate physical container selected by normal installed mode.
      $MainLayout = Get-QSetupLayout -Path $ResolvedPath
      $PhysicalContext = Get-QSetupPhysicalMediaContext -InstallerPath $ResolvedPath -MainLayout $MainLayout -CompanionFile $CompanionInventory
      $PhysicalRecords = @($PhysicalContext.Records | Select-Object Name, Required, Stamp, Offset, CompressedLength, SourcePath, SourceRole, DataEndOffset)
      $Info = $null
    } else {
      $Info = Get-QSetupInfo -Path $ResolvedPath -CompanionPath $CompanionPath
    }
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) { $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ("Dumplings-QSetup-$([guid]::NewGuid().ToString('N'))") }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $Pattern = [string]::IsNullOrWhiteSpace($Name) ? '*' : $Name
    $Entries = [Collections.Generic.List[object]]::new()
    if ($RawRecords) {
      foreach ($Record in $PhysicalRecords) {
        $Entries.Add([pscustomobject]@{ Payload = [pscustomobject]@{ Record = $Record; RecordName = $Record.Name; ExternalSource = $null }; SelectionPath = $Record.Name; RelativePath = Join-Path '_qsetup\records' $Record.Name })
      }
    } else {
      foreach ($Payload in $Info.PayloadCatalog) {
        $RelativePath = ConvertTo-QSetupExtractionPath -Payload $Payload -InstallLocation $Info.DefaultInstallLocation
        $Entries.Add([pscustomobject]@{ Payload = $Payload; SelectionPath = $Payload.InstalledPath ? $Payload.InstalledPath : $Payload.InstalledName; RelativePath = $RelativePath })
      }
    }

    $Written = 0L
    $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    # Enforce one aggregate output budget across all selected records, not a new
    # full allowance for each independently compressed member.
    foreach ($Entry in $Entries) {
      if (-not (Test-ExtractionPattern -Path $Entry.SelectionPath -Pattern $Pattern)) { continue }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.RelativePath `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if (-not $Target.ShouldWrite) { continue }
      $Remaining = $MaximumExpandedBytes - $Written
      if ($Remaining -le 0) { throw 'QSetup extraction exceeds the configured output limit' }
      $File = Export-QSetupPayload -Payload $Entry.Payload -OutputPath $Target.Path -MaximumBytes $Remaining
      $Written += $File.Length
      $Result.Add($File)
    }
    if ($Result.Count -eq 0) { throw "No QSetup extraction entries matched '$Pattern'" }
    return $Result.ToArray()
  }
}

function Test-QSetup {
  <#
  .SYNOPSIS
    Test whether a file contains a parseable QSetup project
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER CompanionPath
    Optional explicit split or spanned companion paths used for complete validation.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionPath)
  process {
    try { $null = Get-QSetupInfo -Path $Path -CompanionPath $CompanionPath; return $true } catch {
      # A split kernel is structurally QSetup even before its caller supplies the
      # authenticated companion needed for metadata and payload parsing.
      try {
        $Layout = Get-QSetupLayout -Path (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf)
        return [bool]($Layout.Complete -and $Layout.SplitDescriptor -and $Layout.Records.Count -eq 0)
      } catch { return $false }
    }
  }
}

function Read-ProtocolsFromQSetup {
  <#
  .SYNOPSIS
    Read literal URL protocol names from QSetup registry evidence
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromQSetup {
  <#
  .SYNOPSIS
    Read literal file extensions from QSetup association directives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).FileExtensions }
}

function Read-ProductVersionFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project version
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).DisplayVersion }
}

function Read-ProductNameFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project display name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).DisplayName }
}

function Read-PublisherFromQSetup {
  <#
  .SYNOPSIS
    Read the QSetup project publisher
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Publisher }
}

function Read-ProductCodeFromQSetup {
  <#
  .SYNOPSIS
    Read the explicit QSetup Apps & Features key name
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).ProductCode }
}

function Read-ScopeFromQSetup {
  <#
  .SYNOPSIS
    Read scope from explicit QSetup all-users/current-user directives
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-QSetupInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-QSetupInfo, Expand-QSetupInstaller, Test-QSetup, Read-ProtocolsFromQSetup, Read-FileExtensionsFromQSetup, Read-ProductVersionFromQSetup, Read-ProductNameFromQSetup, Read-PublisherFromQSetup, Read-ProductCodeFromQSetup, Read-ScopeFromQSetup
