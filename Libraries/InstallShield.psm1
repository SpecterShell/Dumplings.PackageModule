# SPDX-License-Identifier: Apache-2.0
# Format sources: https://github.com/lifenjoiner/ISx
# Setup.ini source: https://docs.revenera.com/installshield26helplib/helplibrary/SetupIniExe.htm
# Supported InstallShield binary structures:
#
#   PE launcher -> overlay -> optional "NB10" prefix
#     +-- encoded "InstallShield"/"ISSetupStream" 46-byte header
#     |   -> old 0x138-byte or stream attributes -> transformed/zlib ranges
#     `-- plain ANSI/UTF-16 records -> adjacent bounded payloads
#
# File names and lengths come from decoded records. A nested MSI path is selected
# from catalog/setup metadata, never a recursive wildcard. Unsupported generation
# fields remain observed, and malformed next offsets or output paths are rejected.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:InstallShieldMagic = [byte[]](0x13, 0x35, 0x86, 0x07)
$Script:InstallShieldPreferredBlockSize = 4096 * 64
$Script:InstallShieldOldAttributeSize = 0x138

function ConvertFrom-InstallShieldCString {
  <#
  .SYNOPSIS
    Decode a NUL-terminated string from an InstallShield record field.
  .PARAMETER Bytes
    Fixed-size record field bytes. Decoding stops at the first NUL sequence.
  .PARAMETER Encoding
    Encoding used by the current record generation; defaults to the Windows ANSI code page.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [byte[]]$Bytes,

    [Parameter()]
    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::Default
  )

  $Length = [Array]::IndexOf($Bytes, [byte]0)
  if ($Length -lt 0) { $Length = $Bytes.Length }
  return $Encoding.GetString($Bytes, 0, $Length).TrimEnd([char]0)
}

function Save-InstallShieldRange {
  <#
  .SYNOPSIS
    Save a byte range from the installer stream to a destination file
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Length
    Declared size or parser bound in bytes or characters, as named by the field; ranges are validated before reading.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [long]$Length,

    [Parameter(Mandatory)]
    [string]$Path
  )

  $Parent = Split-Path -Path $Path -Parent
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }

  $Output = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try {
    Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Offset -Length $Length
  } finally {
    $Output.Dispose()
  }

  return $Path
}

function Join-InstallShieldSafePath {
  <#
  .SYNOPSIS
    Join a payload relative path under an extraction root without allowing path escape
  .PARAMETER Root
    Current structured format node or record being interpreted.
  .PARAMETER RelativePath
    Installer-relative path resolved without allowing traversal outside the selected root.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [string]$Root,

    [Parameter(Mandatory)]
    [string]$RelativePath
  )

  Resolve-SafeExtractionPath -DestinationPath $Root -RelativePath $RelativePath
}

function Test-InstallShieldZlibStream {
  <#
  .SYNOPSIS
    Test the decoded payload prefix for a structurally valid zlib header
  .PARAMETER Stream
    Caller-owned binary stream. Sequential readers may advance its byte position; helpers do not dispose it.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream
  )

  if (-not $Stream.CanSeek -or $Stream.Length -lt 2) { return $false }
  $Header = Read-BinaryBytes -Stream $Stream -Offset 0 -Count 2
  $Value = ([int]$Header[0] -shl 8) -bor $Header[1]
  return ($Header[0] -band 0x0F) -eq 8 -and ($Header[0] -shr 4) -le 7 -and $Value % 31 -eq 0
}

function Get-InstallShieldHeader {
  <#
  .SYNOPSIS
    Validate and decode a 46-byte InstallShield stream header.
  .PARAMETER Stream
    Seekable installer stream owned by the caller. Its position is restored by shared random-access reads.
  .PARAMETER Offset
    Absolute file offset of the candidate InstallShield or ISSetupStream header.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset
  )

  # Reject truncated candidates before interpreting the fixed stream header. A
  # textual signature alone is not sufficient evidence of an archive record.
  if ($Offset + 46 -gt $Stream.Length) { return $null }
  $Bytes = Read-PEFileBytes -Stream $Stream -Offset $Offset -Count 46
  $Signature = ConvertFrom-InstallShieldCString -Bytes $Bytes[0..13] -Encoding ([System.Text.Encoding]::ASCII)
  if ($Signature -notin @('InstallShield', 'ISSetupStream')) { return $null }

  # Only the observed record-layout variants are accepted. This prevents an
  # incidental signature in payload data from driving variable-length reads.
  $Type = [System.BitConverter]::ToUInt32($Bytes, 16)
  if ($Type -gt 4) { return $null }

  [pscustomobject]@{
    Signature     = $Signature
    NumFiles      = [System.BitConverter]::ToUInt16($Bytes, 14)
    Type          = $Type
    NextOffset    = $Offset + 46
    IsSetupStream = $Signature -eq 'ISSetupStream'
  }
}

function Get-InstallShieldOldAttribute {
  <#
  .SYNOPSIS
    Decode one legacy 0x138-byte InstallShield file attribute record.
  .PARAMETER Stream
    Seekable installer stream owned by the caller.
  .PARAMETER Offset
    Absolute file offset of the fixed attribute record; payload data follows the record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset
  )

  # Legacy records use a fixed 0x138-byte attribute block followed immediately
  # by the encoded file bytes, so both ranges can be validated without seeking.
  if ($Offset + $Script:InstallShieldOldAttributeSize -gt $Stream.Length) { return $null }
  $Bytes = Read-PEFileBytes -Stream $Stream -Offset $Offset -Count $Script:InstallShieldOldAttributeSize
  $FileName = ConvertFrom-InstallShieldCString -Bytes $Bytes[0..259]
  $FileLength = [System.BitConverter]::ToUInt32($Bytes, 268)
  $DataOffset = $Offset + $Script:InstallShieldOldAttributeSize
  if ([string]::IsNullOrWhiteSpace($FileName) -or $FileLength -gt $Stream.Length - $DataOffset) { return $null }

  [pscustomobject]@{
    FileName          = $FileName
    Seed              = [System.Text.Encoding]::UTF8.GetBytes($FileName)
    EncodedFlags      = [System.BitConverter]::ToUInt32($Bytes, 260)
    FileLength        = $FileLength
    IsUnicodeLauncher = [System.BitConverter]::ToUInt16($Bytes, 280)
    DataOffset        = $DataOffset
    NextOffset        = $DataOffset
  }
}

function Get-InstallShieldStreamAttribute {
  <#
  .SYNOPSIS
    Decode one ISSetupStream variable-name file attribute record.
  .PARAMETER Stream
    Seekable installer stream owned by the caller.
  .PARAMETER Offset
    Absolute file offset of the 24-byte fixed attribute prefix.
  .PARAMETER Type
    Stream header record type. Type 4 inserts an additional 24-byte field before the name.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [uint32]$Type
  )

  # ISSetupStream records separate a fixed prefix from a bounded UTF-16 name.
  # Type 4 inserts another fixed field before that name.
  if ($Offset + 24 -gt $Stream.Length) { return $null }
  $Bytes = Read-PEFileBytes -Stream $Stream -Offset $Offset -Count 24
  $FileNameLength = [System.BitConverter]::ToUInt32($Bytes, 0)
  if ($FileNameLength -le 0 -or $FileNameLength -gt 520) { return $null }

  $NameOffset = $Offset + 24
  if ($Type -eq 4) { $NameOffset += 24 }
  if ($NameOffset + $FileNameLength -gt $Stream.Length) { return $null }

  $NameBytes = Read-PEFileBytes -Stream $Stream -Offset $NameOffset -Count $FileNameLength
  $FileName = [System.Text.Encoding]::Unicode.GetString($NameBytes).TrimEnd([char]0)
  $DataOffset = $NameOffset + $FileNameLength
  $FileLength = [System.BitConverter]::ToUInt32($Bytes, 10)
  if ([string]::IsNullOrWhiteSpace($FileName) -or $FileLength -gt $Stream.Length - $DataOffset) { return $null }

  [pscustomobject]@{
    FileName          = $FileName
    Seed              = [System.Text.Encoding]::UTF8.GetBytes($FileName)
    EncodedFlags      = [System.BitConverter]::ToUInt32($Bytes, 4)
    FileLength        = $FileLength
    IsUnicodeLauncher = [System.BitConverter]::ToUInt16($Bytes, 22)
    DataOffset        = $DataOffset
    NextOffset        = $DataOffset
  }
}

function Skip-InstallShieldNb10Prefix {
  <#
  .SYNOPSIS
    Skip the optional bounded NB10/debug prefix before InstallShield records.
  .PARAMETER Stream
    Seekable installer stream owned by the caller.
  .PARAMETER Offset
    Absolute overlay offset to probe. The returned value is an absolute candidate record offset.
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset
  )

  if ($Offset + 4 -gt $Stream.Length) { return $Offset }
  $Prefix = [System.Text.Encoding]::ASCII.GetString((Read-PEFileBytes -Stream $Stream -Offset $Offset -Count 4))
  if ($Prefix -ne 'NB10') { return $Offset }

  # Some launchers retain a short CodeView/debug prefix at the overlay start.
  # Scan only its bounded printable fields rather than searching arbitrarily
  # for a later archive signature that might belong to embedded content.
  $Scan = $Offset + 4
  $PrintableRuns = 0
  $InPrintable = $false
  while ($Scan -lt $Stream.Length -and $Scan -lt $Offset + 1024) {
    $Stream.Position = $Scan
    $Byte = $Stream.ReadByte()
    if ($Byte -ge 0x20 -and $Byte -le 0xFE) {
      if (-not $InPrintable) {
        $PrintableRuns++
        $InPrintable = $true
      }
    } else {
      $InPrintable = $false
    }
    $Scan++
    if ($PrintableRuns -ge 2 -and $Byte -lt 0x20) { return $Scan }
  }

  return $Offset
}

function Export-InstallShieldDecodedFile {
  <#
  .SYNOPSIS
    Decode and export one bounded InstallShield catalog entry.
  .PARAMETER Stream
    Seekable installer stream containing the encoded payload range; caller retains ownership.
  .PARAMETER Attribute
    Validated record with absolute DataOffset, FileLength, and file-name evidence.
  .PARAMETER DestinationPath
    Extraction root. The record name is resolved beneath this root with traversal checks.
  .PARAMETER StreamMode
    Select the ISSetupStream block transform instead of the legacy transform.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [psobject]$Attribute,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [Parameter()]
    [switch]$StreamMode
  )

  # The record flags select the InstallShield byte transform independently of
  # the optional zlib layer applied by Unicode launcher records.
  $HasType2Or4 = ($Attribute.EncodedFlags -band 6) -ne 0
  $HasType4 = ($Attribute.EncodedFlags -band 4) -ne 0
  $OutputPath = Join-InstallShieldSafePath -Root $DestinationPath -RelativePath $Attribute.FileName
  $Parent = Split-Path -Path $OutputPath -Parent
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }

  $Range = New-BoundedReadStream -Stream $Stream -Offset $Attribute.DataOffset -Length $Attribute.FileLength -LeaveOpen
  $PayloadStream = $Range
  $Output = $null
  $Succeeded = $false
  try {
    if ($HasType2Or4) {
      Import-BinaryPatternSearch
      # Type 4 uses 1024-byte encoded blocks. Type 2 applies one transform over
      # the complete payload, matching the reference extractor's second pass.
      $BlockSize = $HasType4 ? 1024L : [long]$Attribute.FileLength
      $PayloadStream = [Dumplings.InstallerInfrastructure.InstallShieldDecodedStream]::new(
        $Range,
        $BlockSize,
        $Attribute.Seed,
        $Script:InstallShieldMagic,
        $StreamMode.IsPresent,
        $true
      )
    }

    $Output = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    # Probe the transformed stream for a valid zlib header before decoding;
    # launcher flags alone are not trusted to imply compressed data.
    if ($Attribute.IsUnicodeLauncher -ne 0 -and (Test-InstallShieldZlibStream -Stream $PayloadStream)) {
      $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $PayloadStream -Destination $Output -MaximumBytes 1073741824
    } else {
      $null = Copy-BoundedStream -Source $PayloadStream -Destination $Output -MaximumBytes $Attribute.FileLength -ExpectedBytes $Attribute.FileLength
    }
    $Succeeded = $true
    return $OutputPath
  } finally {
    if ($Output) { $Output.Dispose() }
    if (-not [object]::ReferenceEquals($PayloadStream, $Range)) { $PayloadStream.Dispose() }
    $Range.Dispose()
    if (-not $Succeeded) { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue }
  }
}

function Expand-InstallShieldEncryptedPayload {
  <#
  .SYNOPSIS
    Iterate an encoded InstallShield stream catalog and export its files.
  .PARAMETER Stream
    Seekable installer stream owned by the caller.
  .PARAMETER Offset
    Absolute offset of the decoded InstallShield/ISSetupStream header candidate.
  .PARAMETER DestinationPath
    Safe extraction root for decoded entries.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [string]$DestinationPath
  )

  # Authenticate the catalog header before selecting the generation-specific
  # attribute reader. Each successful record advances over its adjacent data.
  $Header = Get-InstallShieldHeader -Stream $Stream -Offset $Offset
  if (-not $Header) { return $null }

  $Cursor = $Header.NextOffset
  $Files = [System.Collections.Generic.List[string]]::new()
  for ($Index = 0; $Index -lt $Header.NumFiles; $Index++) {
    $Attribute = if ($Header.IsSetupStream) {
      Get-InstallShieldStreamAttribute -Stream $Stream -Offset $Cursor -Type $Header.Type
    } else {
      Get-InstallShieldOldAttribute -Stream $Stream -Offset $Cursor
    }
    # Stop at the first malformed or non-advancing record. Continuing would
    # reinterpret payload bytes as catalog entries and could amplify output.
    if (-not $Attribute -or $Attribute.NextOffset -le $Cursor) { break }

    $Files.Add((Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $DestinationPath -StreamMode:$Header.IsSetupStream))
    $Cursor = $Attribute.NextOffset + $Attribute.FileLength
  }

  if ($Files.Count -eq 0) { return $null }

  [pscustomobject]@{
    Format         = $Header.Signature
    ConsumedOffset = $Cursor
    ExtractedFiles = @($Files)
  }
}

function Read-InstallShieldTextToken {
  <#
  .SYNOPSIS
    Read one bounded text token from a plain InstallShield record.
  .PARAMETER Stream
    Seekable installer stream owned by the caller.
  .PARAMETER Cursor
    Mutable absolute file cursor advanced past the token and record padding.
  .PARAMETER Unicode
    Decode UTF-16LE code units instead of ANSI bytes.
  .PARAMETER MaximumCharacters
    Maximum characters accepted for this token before the candidate is rejected.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [ref]$Cursor,

    [Parameter()]
    [switch]$Unicode,

    [Parameter(Mandatory)]
    [int]$MaximumCharacters
  )

  # Plain records have no explicit token lengths. Read a bounded printable run
  # using the generation-selected character width, then consume its delimiter.
  $Bytes = [System.Collections.Generic.List[byte]]::new()
  $Stream.Position = $Cursor.Value
  while ($Stream.Position -lt $Stream.Length -and $Bytes.Count -lt $MaximumCharacters * $(if ($Unicode) { 2 } else { 1 })) {
    $Byte = $Stream.ReadByte()
    if ($Byte -lt 0) { break }
    if (-not $Unicode) {
      if ($Byte -ge 0x20 -and $Byte -le 0xFE) {
        $Bytes.Add([byte]$Byte)
      } elseif ($Bytes.Count -gt 0) {
        break
      }
    } else {
      $Byte2 = $Stream.ReadByte()
      if ($Byte2 -lt 0) { break }
      if (($Byte -ne 0 -or $Byte2 -ne 0) -and -not ($Byte -lt 0x20 -and $Byte2 -eq 0)) {
        $Bytes.Add([byte]$Byte)
        $Bytes.Add([byte]$Byte2)
      } elseif ($Bytes.Count -gt 0) {
        break
      }
    }
  }

  # Advance across non-printable separator/padding bytes so the next token begins
  # at the first printable ANSI byte or non-control UTF-16 code unit.
  $Cursor.Value = $Stream.Position
  while ($Cursor.Value -lt $Stream.Length) {
    $Stream.Position = $Cursor.Value
    $Byte = $Stream.ReadByte()
    if ($Byte -lt 0) { break }
    if (-not $Unicode) {
      if ($Byte -ge 0x20 -and $Byte -le 0xFE) { break }
      $Cursor.Value = $Stream.Position
    } else {
      $Byte2 = $Stream.ReadByte()
      if ($Byte -ge 0x20 -or $Byte2 -ne 0) { break }
      $Cursor.Value = $Stream.Position
    }
  }

  # Decode only after the cursor has been advanced, preserving sequential record
  # parsing even when the token itself is empty.
  if ($Unicode) {
    return [System.Text.Encoding]::Unicode.GetString($Bytes.ToArray()).TrimEnd([char]0)
  }
  return ConvertFrom-InstallShieldCString -Bytes $Bytes.ToArray()
}

function Get-InstallShieldPlainRecord {
  <#
  .SYNOPSIS
    Decode one plain ANSI or UTF-16 InstallShield file record.
  .PARAMETER Stream
    Seekable installer stream owned by the caller.
  .PARAMETER Offset
    Absolute record offset. Returned DataOffset points to the adjacent payload bytes.
  .PARAMETER Unicode
    Interpret text tokens as UTF-16LE rather than ANSI.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter()]
    [switch]$Unicode
  )

  # Plain records encode four bounded text tokens followed immediately by the
  # payload. The decimal length token is part of the format, not a file guess.
  $Cursor = $Offset
  $FileName = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 260
  $DestinationName = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 260
  $Version = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 32
  $LengthText = Read-InstallShieldTextToken -Stream $Stream -Cursor ([ref]$Cursor) -Unicode:$Unicode -MaximumCharacters 32

  $Length = 0
  if ([string]::IsNullOrWhiteSpace($FileName) -or [string]::IsNullOrWhiteSpace($DestinationName) -or -not [uint32]::TryParse($LengthText, [ref]$Length)) {
    return $null
  }
  if ($Length -gt $Stream.Length - $Cursor) { return $null }

  [pscustomobject]@{
    FileName        = $FileName
    DestinationName = $DestinationName
    Version         = $Version
    FileLength      = [uint32]$Length
    DataOffset      = [long]$Cursor
  }
}

function Expand-InstallShieldPlainPayload {
  <#
  .SYNOPSIS
    Export sequential plain InstallShield records from an overlay.
  .PARAMETER Stream
    Seekable installer stream owned by the caller.
  .PARAMETER Offset
    Absolute offset of the first plain record; Unicode layouts skip their four-byte prefix.
  .PARAMETER DestinationPath
    Safe extraction root for record destination names.
  .PARAMETER Unicode
    Select the UTF-16LE plain-record layout.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [Parameter()]
    [switch]$Unicode
  )

  # The Unicode layout has a four-byte prefix before its first UTF-16 token;
  # ANSI records begin directly at the candidate overlay offset.
  $Cursor = if ($Unicode) { $Offset + 4 } else { $Offset }
  $Files = [System.Collections.Generic.List[string]]::new()
  while ($Cursor -lt $Stream.Length) {
    $Record = Get-InstallShieldPlainRecord -Stream $Stream -Offset $Cursor -Unicode:$Unicode
    # A failed record terminates this layout attempt. The caller can then try
    # another known layout without scanning through untrusted payload bytes.
    if (-not $Record) { break }
    $OutputPath = Join-InstallShieldSafePath -Root $DestinationPath -RelativePath $Record.DestinationName
    $Files.Add((Save-InstallShieldRange -Stream $Stream -Offset $Record.DataOffset -Length $Record.FileLength -Path $OutputPath))
    $Cursor = $Record.DataOffset + $Record.FileLength
  }

  if ($Files.Count -eq 0) { return $null }

  [pscustomobject]@{
    Format         = if ($Unicode) { 'PlainUnicode' } else { 'Plain' }
    ConsumedOffset = $Cursor
    ExtractedFiles = @($Files)
  }
}

function Invoke-InstallShieldExtraction {
  <#
  .SYNOPSIS
    Extract InstallShield payload records without executing external tools
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [string]$DestinationPath
  )

  $File = Get-Item -Path $Path -Force
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    # InstallShield records live after the complete PE image. Preserve the PE
    # launcher separately, then parse only the bounded overlay as archive data.
    $DataOffset = Get-PEOverlayOffset -Stream $Stream
    if ($DataOffset -le 0) { throw 'Not a PE InstallShield file.' }
    if ($DataOffset -ge $Stream.Length) { throw 'No InstallShield overlay data found.' }

    $LauncherPath = Join-Path $DestinationPath ($File.BaseName + '_sfx' + $File.Extension)
    $LauncherPath = Save-InstallShieldRange -Stream $Stream -Offset 0 -Length $DataOffset -Path $LauncherPath
    $CandidateOffset = Skip-InstallShieldNb10Prefix -Stream $Stream -Offset $DataOffset

    # Prefer authenticated encoded catalogs. Plain Unicode and ANSI records are
    # generation-specific fallbacks attempted only from the same overlay start.
    $Result = Expand-InstallShieldEncryptedPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath
    if (-not $Result) {
      $Result = Expand-InstallShieldPlainPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath -Unicode
    }
    if (-not $Result) {
      $Result = Expand-InstallShieldPlainPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath
    }

    if (-not $Result) {
      Remove-Item -Path $LauncherPath -Force -ErrorAction SilentlyContinue
      throw 'No InstallShield payload records were decoded.'
    }

    [pscustomobject]@{
      DestinationPath = (Get-Item -Path $DestinationPath -Force).FullName
      DataOffset      = $DataOffset
      ConsumedOffset  = $Result.ConsumedOffset
      Format          = $Result.Format
      ExtractedFiles  = @($LauncherPath) + @($Result.ExtractedFiles)
    }
  } finally {
    $Stream.Dispose()
  }
}

function Resolve-InstallShieldMatch {
  <#
  .SYNOPSIS
    Resolve a deterministic extracted InstallShield payload match
  .PARAMETER Item
    The candidate extracted files
  .PARAMETER Pattern
    The exact file name or wildcard pattern to match
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The candidate extracted files')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The exact file name or wildcard pattern to match')]
    [string]$Pattern
  )

  if (-not $Item) { throw 'No matching files were extracted from the InstallShield payload' }

  $Match = @($Item.Where({ $_.Name -like $Pattern -or $_.FullName -like $Pattern }))
  if (-not $Match) { throw "No InstallShield payload matched the pattern: $Pattern" }

  $ExactMatch = @($Match.Where({ $_.Name -ieq $Pattern -or $_.FullName -ieq $Pattern }))
  if ($ExactMatch.Count -eq 1) { return $ExactMatch[0] }
  if ($Match.Count -eq 1) { return $Match[0] }

  throw "Multiple InstallShield payloads matched the pattern: $Pattern"
}

function Read-InstallShieldIniConfiguration {
  <#
  .SYNOPSIS
    Read a bounded extracted InstallShield Setup.ini file
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [Parameter(Mandatory)]
    [string]$Path
  )

  $File = Get-Item -LiteralPath $Path -Force
  if ($File.Length -gt 4194304) { throw 'The extracted InstallShield Setup.ini exceeds the 4 MiB metadata limit' }

  $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $Bytes = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([int]$File.Length)
  } finally {
    $Stream.Dispose()
  }
  $Text = if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
    [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
  } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
    [System.Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $Bytes.Length - 2)
  } elseif ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
    [System.Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3)
  } elseif ($Bytes.Length -ge 4 -and $Bytes[1] -eq 0 -and $Bytes[3] -eq 0) {
    [System.Text.Encoding]::Unicode.GetString($Bytes)
  } else {
    [System.Text.Encoding]::Default.GetString($Bytes)
  }

  return $Text | ConvertFrom-Ini -IgnoreComments
}

function Get-InstallShieldIniValue {
  <#
  .SYNOPSIS
    Read one case-insensitive value from parsed InstallShield INI metadata
  .PARAMETER Configuration
    Parsed format configuration used to resolve static installer metadata and payload selection.
  .PARAMETER Section
    Current structured format node or record being interpreted.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Configuration,

    [Parameter(Mandatory)]
    [string]$Section,

    [Parameter(Mandatory)]
    [string]$Name
  )

  $SectionKey = @($Configuration.Keys | Where-Object { [string]$_ -ieq $Section }) | Select-Object -First 1
  if ($null -eq $SectionKey) { return $null }
  $SectionValue = $Configuration[$SectionKey]
  if ($SectionValue -isnot [System.Collections.IDictionary]) { return $null }

  $ValueKey = @($SectionValue.Keys | Where-Object { [string]$_ -ieq $Name }) | Select-Object -First 1
  return $null -eq $ValueKey ? $null : $SectionValue[$ValueKey]
}

function ConvertTo-InstallShieldPayloadPath {
  <#
  .SYNOPSIS
    Normalize a Setup.ini payload path for comparison with extracted records
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string])]
  param (
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $Result = $Path.Trim().Trim('"').Trim("'")
  if ([System.Uri]::IsWellFormedUriString($Result, [System.UriKind]::Absolute)) { return $Result }
  $Result = $Result.Replace('/', '\')
  while ($Result.StartsWith('.\', [System.StringComparison]::Ordinal)) { $Result = $Result.Substring(2) }
  return $Result.TrimStart('\')
}

function Get-InstallShieldMsiPayloadSelection {
  <#
  .SYNOPSIS
    Resolve the MSI path selected by the extracted InstallShield Setup.ini
  .PARAMETER ExtractedPath
    The extraction root
  .PARAMETER MsiFile
    The extracted MSI candidates
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$ExtractedPath,

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.IO.FileInfo[]]$MsiFile
  )

  $Warnings = [System.Collections.Generic.List[string]]::new()
  # The root Setup.ini is the bootstrapper's primary configuration. A sole
  # nested copy is accepted, but multiple copies are deliberately ambiguous.
  $SetupIniFiles = @(Get-ChildItem -LiteralPath $ExtractedPath -Filter 'Setup.ini' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
  $RootSetupIni = @($SetupIniFiles | Where-Object {
      [System.IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) -ieq 'Setup.ini'
    })
  $SetupIni = if ($RootSetupIni.Count -eq 1) {
    $RootSetupIni[0]
  } elseif ($SetupIniFiles.Count -eq 1) {
    $SetupIniFiles[0]
  } else {
    if ($SetupIniFiles.Count -gt 1) { $Warnings.Add('Multiple extracted Setup.ini files prevent deterministic InstallShield MSI selection.') }
    $null
  }

  $Configuration = $null
  $PackageName = $null
  $PackageLocation = $null
  if ($SetupIni) {
    # Startup.PackageName names a package section; that section's Location can
    # provide the exact embedded path used by the launcher.
    $Configuration = Read-InstallShieldIniConfiguration -Path $SetupIni.FullName
    $PackageName = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'PackageName')
    if (-not [string]::IsNullOrWhiteSpace($PackageName)) {
      $PackageLocation = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section $PackageName -Name 'Location')
    }
  }

  $RelativeMsiFiles = @($MsiFile | ForEach-Object {
      [pscustomobject]@{
        File         = $_
        RelativePath = ConvertTo-InstallShieldPayloadPath -Path ([System.IO.Path]::GetRelativePath($ExtractedPath, $_.FullName))
      }
    })
  $ConfiguredPaths = @(@($PackageLocation, $PackageName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
      ConvertTo-InstallShieldPayloadPath -Path $_
    } | Select-Object -Unique)

  $Selected = $null
  # Match configured paths before considering any fallback. Basename matching
  # is allowed only when Setup.ini did not include a directory component.
  foreach ($ConfiguredPath in $ConfiguredPaths) {
    if ([System.Uri]::IsWellFormedUriString($ConfiguredPath, [System.UriKind]::Absolute)) { continue }
    $HasDirectory = $ConfiguredPath.Contains('\')
    $MatchingMsiFiles = @($RelativeMsiFiles | Where-Object {
        $_.RelativePath -ieq $ConfiguredPath -or (-not $HasDirectory -and $_.File.Name -ieq $ConfiguredPath)
      })
    if ($MatchingMsiFiles.Count -eq 1) {
      $Selected = $MatchingMsiFiles[0]
      break
    }
    if ($MatchingMsiFiles.Count -gt 1) {
      $Warnings.Add("Setup.ini path '$ConfiguredPath' matches multiple extracted MSI files.")
      break
    }
  }

  $SelectionMethod = 'Unresolved'
  $SourceKind = 'None'
  if ($Selected) {
    $SelectionMethod = 'SetupIni'
    $SourceKind = 'Embedded'
  } elseif (-not [string]::IsNullOrWhiteSpace($PackageName)) {
    $SelectionMethod = 'SetupIniUnresolved'
    $SourceKind = 'ExternalOrMissing'
    $Warnings.Add("Setup.ini selects '$PackageName', but that MSI path was not extracted.")
  } elseif ($RelativeMsiFiles.Count -eq 1) {
    # A single MSI is a bounded, reviewable fallback. Multiple MSI files cannot
    # be selected by wildcard because the launcher may apply product logic.
    $Selected = $RelativeMsiFiles[0]
    $SelectionMethod = 'SingleExtractedMsi'
    $SourceKind = 'Embedded'
    $Warnings.Add('Setup.ini did not identify the MSI; the only extracted MSI is used as a bounded fallback.')
  } elseif ($RelativeMsiFiles.Count -gt 1) {
    $Warnings.Add('Multiple MSI files were extracted, but Setup.ini did not identify which package the bootstrapper launches.')
  }

  return [pscustomobject]@{
    SelectionMethod = $SelectionMethod
    SourceKind      = $SourceKind
    SetupIniPath    = $null -eq $SetupIni ? $null : [System.IO.Path]::GetRelativePath($ExtractedPath, $SetupIni.FullName)
    PackageName     = [string]::IsNullOrWhiteSpace($PackageName) ? $null : $PackageName
    PackageLocation = [string]::IsNullOrWhiteSpace($PackageLocation) ? $null : $PackageLocation
    ConfiguredPaths = @($ConfiguredPaths)
    SelectedMsiPath = $null -eq $Selected ? $null : $Selected.RelativePath
    Configuration   = $Configuration
    Warnings        = @($Warnings)
  }
}

function Resolve-InstallShieldMsiFile {
  <#
  .SYNOPSIS
    Resolve the exact MSI path selected by the InstallShield bootstrapper
  .PARAMETER Installer
    Parsed context or metadata object produced by the corresponding format reader.
  .PARAMETER Item
    MSI files extracted from validated InstallShield records and considered for the configured payload path.
  .PARAMETER Pattern
    Selection expression applied to validated records without executing installer logic.
  .PARAMETER NameWasSpecified
    Indicates whether the caller explicitly constrained payload selection by name.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)]
    [psobject]$Installer,

    [Parameter(Mandatory)]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory)]
    [string]$Pattern,

    [bool]$NameWasSpecified
  )

  if (-not $Item) { throw 'No MSI files were extracted from the InstallShield payload' }
  $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
  $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
  $SelectedRelativePath = $null -eq $Selection ? $null : [string]$Selection.SelectedMsiPath

  # A parser-derived Setup.ini selection remains authoritative even when the
  # caller supplied a wildcard; the wildcard is only a review constraint.
  if (-not [string]::IsNullOrWhiteSpace($SelectedRelativePath)) {
    $Selected = @($Item | Where-Object {
        [System.IO.Path]::GetRelativePath($Installer.ExtractedPath, $_.FullName).Equals($SelectedRelativePath, [System.StringComparison]::OrdinalIgnoreCase)
      })
    if ($Selected.Count -ne 1) { throw "The Setup.ini-selected MSI path was not extracted uniquely: $SelectedRelativePath" }
    if ($NameWasSpecified -and -not ($Selected[0].Name -like $Pattern -or $Selected[0].FullName -like $Pattern -or $SelectedRelativePath -like $Pattern)) {
      throw "The Setup.ini-selected MSI path '$SelectedRelativePath' does not match the requested pattern: $Pattern"
    }
    return $Selected[0]
  }

  # Never silently choose among unresolved MSI payloads. An explicit name is a
  # caller-reviewed override and uses the deterministic exact-match helper.
  if (-not $NameWasSpecified) {
    $Reason = $null -eq $Selection ? 'no Setup.ini selection metadata is available' : "selection method '$($Selection.SelectionMethod)' did not resolve an embedded MSI"
    throw "InstallShield MSI selection is ambiguous because $Reason; specify -Name for a reviewed manual override"
  }

  return Resolve-InstallShieldMatch -Item $Item -Pattern $Pattern
}

function Expand-InstallShieldInstaller {
  <#
  .SYNOPSIS
    Extract files from an InstallShield executable using the in-process parser
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path (Split-Path -Path $InstallerPath -Parent) ((Split-Path -Path $InstallerPath -LeafBase) + '_u')
    }

    $DestinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationPath)
    Invoke-InstallShieldExtraction -Path $InstallerPath -DestinationPath $DestinationPath | Out-Null
    return $DestinationPath
  }
}

function Expand-InstallShield {
  <#
  .SYNOPSIS
    Extract files from an InstallShield executable using the in-process parser.
  .DESCRIPTION
    Preserves the original Dumplings helper name while delegating to the managed
    parser. The former ISx.exe path override is intentionally unsupported because
    extraction no longer launches an external executable.
  .PARAMETER Path
    The path to the InstallShield installer.
  .PARAMETER DestinationPath
    The destination directory for extracted files. When omitted, extraction uses
    the legacy sibling directory named after the installer with an `_u` suffix.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath
  )

  process {
    # Keep existing callers on the same output contract while routing all bytes
    # through the bounded in-process InstallShield parser.
    Expand-InstallShieldInstaller -Path $Path -DestinationPath $DestinationPath
  }
}

function Get-InstallShieldInfo {
  <#
  .SYNOPSIS
    Extract and classify an InstallShield installer statically
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $ExtractedPath = Expand-InstallShieldInstaller -Path $InstallerPath -DestinationPath $DestinationPath

    # Classify the extracted payload from format artifacts rather than launcher
    # branding, which is shared by Basic MSI and InstallScript variants.
    $MsiFiles = @(Get-ChildItem -Path $ExtractedPath -Filter '*.msi' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
    $InxFiles = @(Get-ChildItem -Path $ExtractedPath -Include '*.inx', '*.ins' -Recurse -File -ErrorAction SilentlyContinue)
    $CabFiles = @(Get-ChildItem -Path $ExtractedPath -Include '*.cab', '*.hdr' -Recurse -File -ErrorAction SilentlyContinue)
    $SfxFiles = @(Get-ChildItem -Path $ExtractedPath -Filter '*_sfx.exe' -Recurse -File -ErrorAction SilentlyContinue)
    $MsiPayloadSelection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile $MsiFiles

    $Variant = if ($MsiFiles) {
      'Basic MSI or InstallScript MSI'
    } elseif ($InxFiles) {
      'InstallScript'
    } elseif ($CabFiles -or $SfxFiles) {
      'InstallShield payload without MSI'
    } else {
      'Unknown'
    }

    # The InstallShield launcher classification does not prove which nested
    # package owns ARP. Get-InstallShieldMsiInfo supplies identity only after
    # Setup.ini has selected an MSI payload.
    [pscustomobject][ordered]@{
      Path                         = $InstallerPath
      InstallerType                = 'InstallShield'
      ProductCode                  = $null
      UpgradeCode                  = $null
      DisplayName                  = $null
      DisplayVersion               = $null
      Publisher                    = $null
      Scope                        = $null
      DefaultInstallLocation       = $null
      WritesAppsAndFeaturesEntry   = $null
      AppsAndFeaturesProductCode   = $null
      AppsAndFeaturesInstallerType = $null
      Warnings                     = [string[]]@($MsiPayloadSelection.Warnings)
      UnresolvedFields             = [string[]]@()
      ExtractedPath                = $ExtractedPath
      Variant                      = $Variant
      HasMsi                       = [bool]$MsiFiles
      HasInstallScript             = [bool]$InxFiles
      MsiFiles                     = @($MsiFiles | Select-Object -ExpandProperty FullName)
      SetupIniPath                 = $MsiPayloadSelection.SetupIniPath
      SetupConfiguration           = $MsiPayloadSelection.Configuration
      MsiPayloadSelection          = $MsiPayloadSelection
      SelectedMsiPath              = $MsiPayloadSelection.SelectedMsiPath
      InxFiles                     = @($InxFiles | Select-Object -ExpandProperty FullName)
      CabFiles                     = @($CabFiles | Select-Object -ExpandProperty FullName)
      SfxFiles                     = @($SfxFiles | Select-Object -ExpandProperty FullName)
    }
  }
}

function Get-InstallShieldMsiInfo {
  <#
  .SYNOPSIS
    Read MSI metadata from a statically extracted InstallShield payload
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER Installer
    The parsed InstallShield metadata object
  .PARAMETER Name
    An optional reviewed file name or wildcard constraint; Setup.ini selection remains authoritative
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed InstallShield metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    $NameWasSpecified = $PSBoundParameters.ContainsKey('Name')
    $TemporaryPath = $null
    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' {
        $TemporaryPath = New-TempFolder
        Get-InstallShieldInfo -Path $Path -DestinationPath $TemporaryPath
      }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    try {
      # Resolve the same MSI the bootstrapper names, then delegate database
      # semantics to the canonical MSI reader instead of duplicating table logic.
      $MsiFiles = @($Installer.MsiFiles | ForEach-Object { Get-Item -Path $_ -Force })
      $MsiFile = Resolve-InstallShieldMsiFile -Installer $Installer -Item $MsiFiles -Pattern $Name -NameWasSpecified $NameWasSpecified
      $MsiInfo = Get-MsiInstallerInfo -Path $MsiFile.FullName
      $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
      $SelectionMethod = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.SelectionMethod

      [pscustomobject][ordered]@{
        Path                         = $MsiFile.FullName
        InstallerType                = $MsiInfo.InstallerType
        ProductCode                  = $MsiInfo.ProductCode
        UpgradeCode                  = $MsiInfo.UpgradeCode
        DisplayName                  = $MsiInfo.DisplayName
        DisplayVersion               = $MsiInfo.DisplayVersion
        Publisher                    = $MsiInfo.Publisher
        Scope                        = $MsiInfo.Scope
        DefaultInstallLocation       = $MsiInfo.DefaultInstallLocation
        WritesAppsAndFeaturesEntry   = $MsiInfo.WritesAppsAndFeaturesEntry
        AppsAndFeaturesProductCode   = $MsiInfo.AppsAndFeaturesProductCode
        AppsAndFeaturesInstallerType = $MsiInfo.AppsAndFeaturesInstallerType
        Warnings                     = [string[]]@($MsiInfo.Warnings)
        UnresolvedFields             = [string[]]@($MsiInfo.UnresolvedFields)
        Name                         = $MsiFile.Name
        SelectedMsiPath              = [System.IO.Path]::GetRelativePath($Installer.ExtractedPath, $MsiFile.FullName)
        SelectionMethod              = $SelectionMethod
        PackageArchitecture          = $MsiInfo.PackageArchitecture
        Template                     = $MsiInfo.Template
        InstallerBuilder             = $MsiInfo.InstallerBuilder
        InstallLocationProperty      = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch        = $MsiInfo.InstallLocationSwitch
        IsWiX                        = $MsiInfo.InstallerBuilder -ceq 'WiX'
        Protocols                    = $MsiInfo.Protocols
        FileExtensions               = $MsiInfo.FileExtensions
        RegistryAssociationInfo      = $MsiInfo.RegistryAssociationInfo
      }
    } finally {
      if ($TemporaryPath) {
        Remove-Item -Path $TemporaryPath -Recurse -Force -ErrorAction 'Continue' -ProgressAction 'SilentlyContinue'
      }
    }
  }
}

function Read-ProductVersionFromInstallShield {
  <#
  .SYNOPSIS
    Read ProductVersion from the MSI payload inside an InstallShield executable
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Installer
    Parsed context or metadata object produced by the corresponding format reader.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory)]
    [psobject]$Installer,

    [string]$Name = '*.msi'
  )

  process { (Get-InstallShieldMsiInfo @PSBoundParameters).DisplayVersion }
}

function Read-ProductCodeFromInstallShield {
  <#
  .SYNOPSIS
    Read ProductCode from the MSI payload inside an InstallShield executable
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Installer
    Parsed context or metadata object produced by the corresponding format reader.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory)]
    [psobject]$Installer,

    [string]$Name = '*.msi'
  )

  process { (Get-InstallShieldMsiInfo @PSBoundParameters).ProductCode }
}

function Read-UpgradeCodeFromInstallShield {
  <#
  .SYNOPSIS
    Read UpgradeCode from the MSI payload inside an InstallShield executable
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Installer
    Parsed context or metadata object produced by the corresponding format reader.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory)]
    [psobject]$Installer,

    [string]$Name = '*.msi'
  )

  process { (Get-InstallShieldMsiInfo @PSBoundParameters).UpgradeCode }
}

Export-ModuleMember -Function Get-InstallShieldInfo, Expand-InstallShield, Expand-InstallShieldInstaller, Get-InstallShieldMsiInfo, Read-ProductVersionFromInstallShield, Read-ProductCodeFromInstallShield, Read-UpgradeCodeFromInstallShield
