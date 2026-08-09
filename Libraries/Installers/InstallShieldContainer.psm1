# SPDX-License-Identifier: Apache-2.0
# Format sources: https://github.com/lifenjoiner/ISx
# Setup.ini source: https://docs.revenera.com/installshield26helplib/helplibrary/SetupIniExe.htm
# Advanced UI source: https://docs.revenera.com/installshield26helplib/helplibrary/SteOverview.htm
# Advanced UI conditions: https://docs.revenera.com/installshield26helplib/helplibrary/SteBuildingConditions.htm
# Advanced UI package order: https://docs.revenera.com/installshield26helplib/helplibrary/SteInstallOrder.htm
# Prerequisite format: https://docs.revenera.com/installshield26helplib/helplibrary/SetupPrereqEditor.htm
# Prerequisite elevation: https://docs.revenera.com/installshield27helplib/helplibrary/SetupPrereqEditorAdminPrivs.htm
# Launcher execution level: https://docs.revenera.com/installshield26helplib/helplibrary/SpecifyingRequiredExecution.htm
# Cabinet reader source: https://github.com/wixtoolset/wix3
# Supported InstallShield binary structures:
#
#   PE launcher -> overlay
#     +-- PackageForTheWeb metadata -> embedded Microsoft Cabinet to EOF
#     |   `-- Setup.exe, Setup.ini, setup.inx, and data*.cab
#     `-- optional "NB10" prefix
#         +-- encoded "InstallShield"/"ISSetupStream" 46-byte header
#         |   -> old 0x138-byte or stream attributes -> transformed/zlib ranges
#         `-- plain ANSI/UTF-16 records -> adjacent bounded payloads
#
#   Legacy external Basic MSI media (physical sibling files)
#     +-- setup.exe: InstallShield bootstrapper
#     +-- Setup.ini
#     |   +-- [Startup] PackageName -> package section name
#     |   `-- [PackageName] Location -> exact media-relative MSI path
#     `-- selected sibling MSI: parsed only after safe exact-path resolution
#
# File names and lengths come from decoded records. A nested MSI path is selected
# from catalog/setup metadata, never a recursive wildcard. Unsupported generation
# fields remain observed, and malformed next offsets or output paths are rejected.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:InstallShieldMagic = [byte[]](0x13, 0x35, 0x86, 0x07)
$Script:InstallShieldPreferredBlockSize = 4096 * 64
$Script:InstallShieldOldAttributeSize = 0x138
$Script:InstallShieldPackageForTheWebScanBytes = 16MB
$Script:InstallShieldPackageForTheWebMaximumEntries = 4096
$Script:InstallShieldPackageForTheWebMaximumExpandedBytes = 8GB
$Script:InstallShieldCabinetSupportMaximumExpandedBytes = 64MB
$Script:InstallShieldCabinetMaximumExpandedBytes = 8GB
$Script:InstallShieldOverlayMaximumExpandedBytes = 8GB

# PackageForTheWeb uses the generic cabinet module. Only the proprietary data1.hdr
# reader needs format-specific managed source.
$InstallShieldCabinetSource = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..\..\Assets\Source\InstallShield') -Filter '*.cs' -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
$null = Import-InstallerManagedSource -Path $InstallShieldCabinetSource -TypeName 'Dumplings.InstallShield.InstallShieldCabinetExtractor'

# InstallShield extraction and PackageForTheWeb handling.

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

function Test-InstallShieldFileTimeBlock {
  <#
  .SYNOPSIS
    Test an observed ISSetupStream metadata block containing three Windows FILETIME values.
  .PARAMETER Bytes
    Exactly 24 bytes read immediately after the fixed stream-attribute prefix.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -ne 24) { return $false }
  for ($Offset = 0; $Offset -lt 24; $Offset += 8) {
    try {
      $Timestamp = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($Bytes, $Offset))
    } catch {
      return $false
    }
    # InstallShield postdates 1980. A distant upper bound rejects UTF-16 file
    # names reinterpreted as integers without coupling parsing to the host date.
    if ($Timestamp.Year -lt 1980 -or $Timestamp.Year -gt 3000) { return $false }
  }
  return $true
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
    Stream header record type. Type 4 and some type 3 variants insert a
    24-byte timestamp field before the name.
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
  # Type 4 always carries an extra field. Type 3 exists both with and without
  # three 64-bit FILETIME values, so validate that block instead of choosing a
  # layout from the type alone.
  if ($Offset + 24 -gt $Stream.Length) { return $null }
  $Bytes = Read-PEFileBytes -Stream $Stream -Offset $Offset -Count 24
  $FileNameLength = [System.BitConverter]::ToUInt32($Bytes, 0)
  if ($FileNameLength -le 0 -or $FileNameLength -gt 520) { return $null }

  $NameOffset = $Offset + 24
  if ($Type -eq 4) {
    $NameOffset += 24
  } elseif ($Type -eq 3 -and $NameOffset + 24 -le $Stream.Length) {
    $Metadata = Read-PEFileBytes -Stream $Stream -Offset $NameOffset -Count 24
    if (Test-InstallShieldFileTimeBlock -Bytes $Metadata) { $NameOffset += 24 }
  }
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
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  .PARAMETER ReservedPath
    Output paths already assigned during the current extraction operation.
  .PARAMETER MaximumBytes
    Maximum decoded bytes accepted for this record. The caller supplies the
    remaining operation-wide extraction budget.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [psobject]$Attribute,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename',

    [System.Collections.Generic.ISet[string]]$ReservedPath,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumBytes = $Script:InstallShieldOverlayMaximumExpandedBytes,

    [Parameter()]
    [switch]$StreamMode
  )

  # The record flags select the InstallShield byte transform independently of
  # the optional zlib layer applied by Unicode launcher records.
  $HasType2Or4 = ($Attribute.EncodedFlags -band 6) -ne 0
  $HasType4 = ($Attribute.EncodedFlags -band 4) -ne 0
  $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Attribute.FileName `
    -CollisionAction $CollisionAction -ReservedPath $ReservedPath
  if (-not $Target.ShouldWrite) { return $null }
  $OutputPath = $Target.Path
  $Parent = Split-Path -Path $OutputPath -Parent
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }

  $Range = New-BoundedReadStream -Stream $Stream -Offset $Attribute.DataOffset -Length $Attribute.FileLength -LeaveOpen
  $PayloadStream = $Range
  $Output = $null
  $Succeeded = $false
  try {
    if ($HasType2Or4) {
      Import-InstallerInfrastructure
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
      $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $PayloadStream -Destination $Output -MaximumBytes $MaximumBytes
    } else {
      $null = Copy-BoundedStream -Source $PayloadStream -Destination $Output -MaximumBytes $MaximumBytes -ExpectedBytes $Attribute.FileLength
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
  .PARAMETER Name
    Optional wildcard matched against logical payload paths and base names.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  .PARAMETER ReservedPath
    Output paths already assigned during the current extraction operation.
  .PARAMETER MaximumExpandedBytes
    Maximum total decoded bytes written for selected records in this catalog.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename',

    [System.Collections.Generic.ISet[string]]$ReservedPath,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $Script:InstallShieldOverlayMaximumExpandedBytes
  )

  # Authenticate the catalog header before selecting the generation-specific
  # attribute reader. Each successful record advances over its adjacent data.
  $Header = Get-InstallShieldHeader -Stream $Stream -Offset $Offset
  if (-not $Header) { return $null }

  $Cursor = $Header.NextOffset
  $Files = [System.Collections.Generic.List[string]]::new()
  $RecordCount = 0
  $ExpandedBytes = 0L
  for ($Index = 0; $Index -lt $Header.NumFiles; $Index++) {
    $Attribute = if ($Header.IsSetupStream) {
      Get-InstallShieldStreamAttribute -Stream $Stream -Offset $Cursor -Type $Header.Type
    } else {
      Get-InstallShieldOldAttribute -Stream $Stream -Offset $Cursor
    }
    # Stop at the first malformed or non-advancing record. Continuing would
    # reinterpret payload bytes as catalog entries and could amplify output.
    if (-not $Attribute -or $Attribute.NextOffset -le $Cursor) { break }
    $RecordCount++
    if (Test-ExtractionPattern -Path $Attribute.FileName -Pattern $Name) {
      if ($ExpandedBytes -ge $MaximumExpandedBytes) {
        throw "Selected InstallShield overlay records exceed the $MaximumExpandedBytes-byte expansion limit."
      }
      $ExtractedPath = Export-InstallShieldDecodedFile -Stream $Stream -Attribute $Attribute -DestinationPath $DestinationPath `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPath -StreamMode:$Header.IsSetupStream `
        -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes)
      if ($ExtractedPath) {
        $ExpandedBytes += (Get-Item -LiteralPath $ExtractedPath -Force).Length
        $Files.Add($ExtractedPath)
      }
    }
    $Cursor = $Attribute.NextOffset + $Attribute.FileLength
  }

  if ($RecordCount -eq 0) { return $null }

  [pscustomobject]@{
    Format         = $Header.Signature
    ConsumedOffset = $Cursor
    ExtractedFiles = @($Files)
    RecordCount    = $RecordCount
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
  .PARAMETER Name
    Optional wildcard matched against logical payload paths and base names.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or is selected more than once.
  .PARAMETER ReservedPath
    Output paths already assigned during the current extraction operation.
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes written for selected records in this payload.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$Offset,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename',

    [System.Collections.Generic.ISet[string]]$ReservedPath,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $Script:InstallShieldOverlayMaximumExpandedBytes,

    [Parameter()]
    [switch]$Unicode
  )

  # The Unicode layout has a four-byte prefix before its first UTF-16 token;
  # ANSI records begin directly at the candidate overlay offset.
  $Cursor = if ($Unicode) { $Offset + 4 } else { $Offset }
  $Files = [System.Collections.Generic.List[string]]::new()
  $RecordCount = 0
  $ExpandedBytes = 0L
  while ($Cursor -lt $Stream.Length) {
    $Record = Get-InstallShieldPlainRecord -Stream $Stream -Offset $Cursor -Unicode:$Unicode
    # A failed record terminates this layout attempt. The caller can then try
    # another known layout without scanning through untrusted payload bytes.
    if (-not $Record) { break }
    $RecordCount++
    if (Test-ExtractionPattern -Path $Record.DestinationName -Pattern $Name) {
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Record.DestinationName `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPath
      if ($Target.ShouldWrite) {
        if ([long]$Record.FileLength -gt $MaximumExpandedBytes - $ExpandedBytes) {
          throw "Selected InstallShield plain records exceed the $MaximumExpandedBytes-byte expansion limit."
        }
        $Parent = Split-Path -Path $Target.Path -Parent
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        $Output = [IO.File]::Open($Target.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Record.DataOffset -Length $Record.FileLength }
        finally { $Output.Dispose() }
        $ExpandedBytes += [long]$Record.FileLength
        $Files.Add($Target.Path)
      }
    }
    $Cursor = $Record.DataOffset + $Record.FileLength
  }

  if ($RecordCount -eq 0) { return $null }

  [pscustomobject]@{
    Format         = if ($Unicode) { 'PlainUnicode' } else { 'Plain' }
    ConsumedOffset = $Cursor
    ExtractedFiles = @($Files)
    RecordCount    = $RecordCount
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
  .PARAMETER Name
    Optional wildcard selecting payload paths or file names. All files are extracted when omitted.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or another payload resolves to the same path.
  .PARAMETER SourceStream
    Optional caller-owned seekable installer stream. The helper restores its position and does not dispose it.
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes decoded from an encoded or plain InstallShield overlay.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename',

    [IO.Stream]$SourceStream,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $Script:InstallShieldOverlayMaximumExpandedBytes
  )

  $File = Get-Item -LiteralPath $Path -Force
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $OwnsStream = $null -eq $SourceStream
  $Stream = $OwnsStream ? [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite) : $SourceStream
  if (-not $Stream.CanRead -or -not $Stream.CanSeek) { throw 'InstallShield extraction requires a readable seekable stream.' }
  $OriginalPosition = $Stream.Position
  try {
    # InstallShield records live after the complete PE image. Preserve the PE
    # launcher separately, then parse only the bounded overlay as archive data.
    $DataOffset = Get-PEOverlayOffset -Stream $Stream
    if ($DataOffset -le 0) { throw 'Not a PE InstallShield file.' }
    if ($DataOffset -ge $Stream.Length) { throw 'No InstallShield overlay data found.' }

    $LauncherPath = $null
    $LauncherName = $File.BaseName + '_sfx' + $File.Extension
    if (Test-ExtractionPattern -Path $LauncherName -Pattern $Name) {
      $LauncherTarget = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $LauncherName `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if ($LauncherTarget.ShouldWrite) {
        $Output = [IO.File]::Open($LauncherTarget.Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset 0 -Length $DataOffset }
        finally { $Output.Dispose() }
        $LauncherPath = $LauncherTarget.Path
      }
    }
    $CandidateOffset = Skip-InstallShieldNb10Prefix -Stream $Stream -Offset $DataOffset

    # PackageForTheWeb wraps the complete InstallShield media in a standard
    # Microsoft Cabinet after a small overlay preamble. Validate that bounded
    # range before attempting InstallShield's own stream-record generations.
    $PackageForTheWebCabinet = Get-InstallShieldPackageForTheWebCabinet -Stream $Stream -OverlayOffset $DataOffset
    if ($PackageForTheWebCabinet) {
      $Result = Expand-InstallShieldPackageForTheWebCabinet -Stream $Stream -Cabinet $PackageForTheWebCabinet `
        -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    } else {
      $Result = $null
    }

    # Prefer authenticated encoded catalogs. Plain Unicode and ANSI records are
    # generation-specific fallbacks attempted only from the same overlay start.
    if (-not $Result) {
      $Result = Expand-InstallShieldEncryptedPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath `
        -Name $Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths -MaximumExpandedBytes $MaximumExpandedBytes
    }
    if (-not $Result) {
      $Result = Expand-InstallShieldPlainPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath `
        -Name $Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths -MaximumExpandedBytes $MaximumExpandedBytes -Unicode
    }
    if (-not $Result) {
      $Result = Expand-InstallShieldPlainPayload -Stream $Stream -Offset $CandidateOffset -DestinationPath $DestinationPath `
        -Name $Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths -MaximumExpandedBytes $MaximumExpandedBytes
    }

    if (-not $Result) {
      if ($LauncherPath) { Remove-Item -LiteralPath $LauncherPath -Force -ErrorAction SilentlyContinue }
      throw 'No InstallShield payload records were decoded.'
    }

    [pscustomobject]@{
      DestinationPath = (Get-Item -Path $DestinationPath -Force).FullName
      DataOffset      = $DataOffset
      ConsumedOffset  = $Result.ConsumedOffset
      Format          = $Result.Format
      ExtractedFiles  = @($LauncherPath | Where-Object { $_ }) + @($Result.ExtractedFiles)
    }
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
  }
}

function Get-InstallShieldPackageForTheWebCabinet {
  <#
  .SYNOPSIS
    Locate and validate a PackageForTheWeb Microsoft Cabinet in a PE overlay.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Random-access reads restore its position.
  .PARAMETER OverlayOffset
    Absolute offset immediately after the mapped PE image. The bounded scan starts here.
  .OUTPUTS
    Cabinet offset, length, catalog counts, flags, and version, or null when no validated layout exists.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [long]$OverlayOffset
  )

  if (-not $Stream.CanSeek -or $OverlayOffset -lt 0 -or $OverlayOffset -ge $Stream.Length) { return $null }
  $ScanLength = [Math]::Min([long]$Script:InstallShieldPackageForTheWebScanBytes, $Stream.Length - $OverlayOffset)
  $Magic = [Text.Encoding]::ASCII.GetBytes('MSCF')
  foreach ($CandidateOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Magic -StartOffset $OverlayOffset -Length $ScanLength -Maximum 32)) {
    # CFHEADER is 36 bytes before optional reserve/previous/next fields. Only
    # self-contained cabinets ending exactly at EOF are accepted as the outer
    # PackageForTheWeb payload; incidental MSCF strings cannot satisfy this.
    if ($CandidateOffset + 36 -gt $Stream.Length) { continue }
    $Header = Read-BinaryBytes -Stream $Stream -Offset $CandidateOffset -Count 36
    $CabinetLength = [BitConverter]::ToUInt32($Header, 8)
    $FileTableOffset = [BitConverter]::ToUInt32($Header, 16)
    $VersionMinor = $Header[24]
    $VersionMajor = $Header[25]
    $FolderCount = [BitConverter]::ToUInt16($Header, 26)
    $FileCount = [BitConverter]::ToUInt16($Header, 28)
    $Flags = [BitConverter]::ToUInt16($Header, 30)
    if ($CabinetLength -lt 36 -or $CabinetLength -gt $Stream.Length - $CandidateOffset) { continue }
    if ($CandidateOffset + $CabinetLength -ne $Stream.Length) { continue }
    if ($FileTableOffset -lt 36 -or $FileTableOffset -ge $CabinetLength) { continue }
    if ($VersionMajor -ne 1 -or $VersionMinor -ne 3) { continue }
    if ($FolderCount -eq 0 -or $FolderCount -gt 4096) { continue }
    if ($FileCount -eq 0 -or $FileCount -gt $Script:InstallShieldPackageForTheWebMaximumEntries) { continue }
    # Embedded PFTW cabinets must not request previous/next cabinet media.
    if (($Flags -band 0x0003) -ne 0) { continue }

    return [pscustomobject][ordered]@{
      Offset          = [long]$CandidateOffset
      Length          = [long]$CabinetLength
      FileTableOffset = [long]$FileTableOffset
      VersionMajor    = [int]$VersionMajor
      VersionMinor    = [int]$VersionMinor
      FolderCount     = [int]$FolderCount
      FileCount       = [int]$FileCount
      Flags           = [int]$Flags
    }
  }
  return $null
}

function Expand-InstallShieldPackageForTheWebCabinet {
  <#
  .SYNOPSIS
    Extract a validated PackageForTheWeb cabinet through the bounded cabinet API.
  .PARAMETER Stream
    Caller-owned installer stream containing the exact cabinet range.
  .PARAMETER Cabinet
    Layout returned by Get-InstallShieldPackageForTheWebCabinet.
  .PARAMETER DestinationPath
    Resolved extraction root.
  .PARAMETER Name
    Optional wildcard selecting cabinet paths or file names.
  .PARAMETER CollisionAction
    Existing-file and duplicate-name policy resolved before decompression.
  .PARAMETER ReservedPath
    Case-insensitive target set shared with the outer launcher extraction.
  .OUTPUTS
    InstallShield extraction evidence containing the written paths and consumed offset.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [IO.Stream]$Stream,

    [Parameter(Mandatory)]
    [psobject]$Cabinet,

    [Parameter(Mandatory)]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename',

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [Collections.Generic.ISet[string]]$ReservedPath
  )

  $TemporaryPath = New-TempFile
  $TemporaryCabinetPath = "$TemporaryPath.cab"
  try {
    Move-Item -LiteralPath $TemporaryPath -Destination $TemporaryCabinetPath -Force
    $Output = [IO.File]::Open($TemporaryCabinetPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $null = Copy-BinaryStreamRange -Source $Stream -Offset $Cabinet.Offset -Length $Cabinet.Length -Destination $Output
    } finally {
      $Output.Dispose()
    }
    $Entries = @(Get-CabinetEntry -Path $TemporaryCabinetPath -MaximumEntries $Script:InstallShieldPackageForTheWebMaximumEntries)
    if ($Entries.Count -ne $Cabinet.FileCount) {
      throw "PackageForTheWeb cabinet catalog count mismatch: header $($Cabinet.FileCount), decoded $($Entries.Count)."
    }

    $SelectedEntries = @($Entries | Where-Object { Test-ExtractionPattern -Path $_.FullName.TrimStart('/', '\') -Pattern $Name })
    $ExpandedBytes = [long](($SelectedEntries | Measure-Object -Property Length -Sum).Sum)
    $ExtractedFiles = @(Export-CabinetEntry -Path $TemporaryCabinetPath -DestinationPath $DestinationPath -Name $Name `
        -CollisionAction $CollisionAction -MaximumEntries $Script:InstallShieldPackageForTheWebMaximumEntries `
        -MaximumExpandedBytes $Script:InstallShieldPackageForTheWebMaximumExpandedBytes -ReservedPath $ReservedPath)

    return [pscustomobject][ordered]@{
      Format         = 'PackageForTheWeb Cabinet'
      ConsumedOffset = [long]($Cabinet.Offset + $Cabinet.Length)
      ExtractedFiles = [string[]]$ExtractedFiles
      ExpandedBytes  = $ExpandedBytes
      EntryCount     = $Entries.Count
      Cabinet        = $Cabinet
    }
  } finally {
    Remove-Item -LiteralPath $TemporaryPath, $TemporaryCabinetPath -Force -ErrorAction SilentlyContinue
  }
}

function Expand-InstallShieldCabinetSupport {
  <#
  .SYNOPSIS
    Extract bounded InstallScript support files from proprietary data*.cab media.
  .DESCRIPTION
    InstallShield script-driven media often stores setup.inx inside an ISc(
    cabinet set rather than beside Setup.exe. This helper enumerates data*.hdr
    catalogs and extracts only setup.inx, setup.ins, or setup.iss. Application
    payloads remain compressed, avoiding a potentially multi-gigabyte expansion.
    The same bounded header read returns registry sets, shell objects, setup
    types, feature/component topology, and cabinet file-group ranges.
  .PARAMETER ExtractedPath
    Resolved outer InstallShield extraction root containing data*.hdr/cab files.
  .PARAMETER CollisionAction
    Existing-file policy applied before selected support files are decoded.
  .OUTPUTS
    Catalog and extracted-file evidence plus non-fatal warnings.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$ExtractedPath,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename'
  )

  $Warnings = [Collections.Generic.List[string]]::new()
  $SupportEntries = [Collections.Generic.List[object]]::new()
  $RegistrySets = [Collections.Generic.List[object]]::new()
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $CabinetFileGroups = [Collections.Generic.List[object]]::new()
  $CabinetComponents = [Collections.Generic.List[object]]::new()
  $MediaSetupTypes = [Collections.Generic.List[object]]::new()
  $ShellFolders = [Collections.Generic.List[object]]::new()
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $CatalogEntryCount = 0
  $ExtractedFiles = [Collections.Generic.List[string]]::new()
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ExpandedBytes = 0L
  # Only canonical dataN.hdr names are proprietary cabinet catalogs. This also
  # excludes collision-renamed leftovers such as data1 (1).hdr and unrelated
  # InstallShield support headers from repeated analysis of the same directory.
  $HeaderFiles = @(Get-ChildItem -LiteralPath $ExtractedPath -Filter '*.hdr' -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object Name -CMatch '^data\d+\.hdr$' | Sort-Object FullName)
  foreach ($HeaderFile in $HeaderFiles) {
    try {
      # The managed reader validates ISc(, version, descriptor/table ranges,
      # record counts, per-entry ranges, Deflate framing, expanded size, and MD5.
      $Inspection = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Inspect($HeaderFile.FullName)
      $Entries = @($Inspection.Entries)
      $CatalogEntryCount += $Entries.Count

      # The same bounded header read also exposes author-authored registry and
      # shell records. Named registry sets are definitions, not proof that the
      # compiled script invokes them; InstallShieldInstallScript.psm1 performs
      # that reachability selection after setup.inx has been analyzed.
      foreach ($Warning in @($Inspection.MediaMetadata.Warnings)) {
        $Warnings.Add("$($HeaderFile.Name): $Warning")
      }
      foreach ($RegistrySet in @($Inspection.MediaMetadata.RegistrySets)) {
        $RegistrySets.Add([pscustomobject][ordered]@{
            HeaderPath    = $HeaderFile.FullName
            QualifiedName = [string]$RegistrySet.QualifiedName
            Name          = [string]$RegistrySet.Name
            IsDefault     = [bool]$RegistrySet.IsDefault
            Components    = [string[]]@($RegistrySet.Components)
          })
      }
      foreach ($FileGroup in @($Inspection.MediaMetadata.FileGroups)) {
        $CabinetFileGroups.Add([pscustomobject][ordered]@{
            HeaderPath     = $HeaderFile.FullName
            Name           = [string]$FileGroup.Name
            FirstFileIndex = [int]$FileGroup.FirstFileIndex
            LastFileIndex  = [int]$FileGroup.LastFileIndex
            Source         = 'InstallShieldCabinetFileGroup'
          })
      }
      foreach ($Component in @($Inspection.MediaMetadata.Components)) {
        $CabinetComponents.Add([pscustomobject][ordered]@{
            HeaderPath = $HeaderFile.FullName
            Name       = [string]$Component.Name
            FileGroups = [string[]]@($Component.FileGroups)
            Source     = 'InstallShieldCabinetComponent'
          })
      }
      foreach ($SetupType in @($Inspection.MediaMetadata.SetupTypes)) {
        $MediaSetupTypes.Add([pscustomobject][ordered]@{
            HeaderPath  = $HeaderFile.FullName
            Language    = [uint32]$SetupType.Language
            Ordinal     = [int]$SetupType.Ordinal
            Name        = [string]$SetupType.Name
            Description = [string]$SetupType.Description
            DisplayName = [string]$SetupType.DisplayName
            Features    = [string[]]@($SetupType.Features)
            Source      = 'InstallShieldMediaSetupType'
          })
      }
      foreach ($RegistryWrite in @($Inspection.MediaMetadata.RegistryWrites)) {
        $RootCandidates = if ($RegistryWrite.Root -eq 'SHCTX') { [string[]]@('HKCU', 'HKLM') } else { [string[]]@([string]$RegistryWrite.Root) }
        $RegistryWrites.Add([pscustomobject][ordered]@{
            HeaderPath           = $HeaderFile.FullName
            Root                 = [string]$RegistryWrite.Root
            RootCandidates       = $RootCandidates
            Key                  = [string]$RegistryWrite.Key
            Name                 = [string]$RegistryWrite.Name
            Type                 = [string]$RegistryWrite.Type
            TypeCode             = [int]$RegistryWrite.TypeCode
            Data                 = $RegistryWrite.Data
            RegistrySet          = [string]$RegistryWrite.RegistrySet
            QualifiedRegistrySet = [string]$RegistryWrite.QualifiedRegistrySet
            IsDefaultSet         = [bool]$RegistryWrite.IsDefaultSet
            Components           = [string[]]@($RegistryWrite.Components)
            Features             = [string[]]@($RegistryWrite.Features)
            SetupTypes           = [string[]]@($RegistryWrite.SetupTypes)
            Complete             = [bool]$RegistryWrite.Complete
            Source               = 'InstallShieldMediaRegistrySet'
            Confidence           = $RegistryWrite.IsDefaultSet ? 'DefaultMediaSet' : 'ConditionalMediaSet'
          })
      }
      foreach ($ShellFolder in @($Inspection.MediaMetadata.ShellFolders)) {
        $ShellFolders.Add([pscustomobject][ordered]@{
            HeaderPath        = $HeaderFile.FullName
            InstallShieldName = [string]$ShellFolder.InstallShieldName
            DirectoryName     = [string]$ShellFolder.DirectoryName
            ShortcutCount     = @($ShellFolder.Shortcuts).Count
            Source            = 'InstallShieldMediaShellObjects'
          })
      }
      foreach ($Shortcut in @($Inspection.MediaMetadata.Shortcuts)) {
        $Shortcuts.Add([pscustomobject][ordered]@{
            HeaderPath        = $HeaderFile.FullName
            Name              = [string]$Shortcut.Name
            InstallShieldName = [string]$Shortcut.InstallShieldName
            Target            = [string]$Shortcut.Target
            Arguments         = [string]$Shortcut.Arguments
            WorkingDirectory  = [string]$Shortcut.WorkingDirectory
            Component         = [string]$Shortcut.Component
            Folder            = [string]$Shortcut.Folder
            EncodedProperties = [string]$Shortcut.EncodedProperties
            HotKey            = $Shortcut.HotKey
            ShowCommand       = [uint32]$Shortcut.ShowCommand
            Features          = [string[]]@($Shortcut.Features)
            SetupTypes        = [string[]]@($Shortcut.SetupTypes)
            Source            = 'InstallShieldMediaShellObjects'
            Confidence        = 'ConditionalMediaRecord'
          })
      }

      $SelectedEntries = @($Entries | Where-Object {
          $_.IsValid -and ($_.Name -cin @('setup.inx', 'setup.ins', 'setup.iss') -or $_.Name -like 'StringTable_*.ips')
        })
      if (-not $SelectedEntries) { continue }
      $Targets = [Collections.Generic.Dictionary[int, string]]::new()
      foreach ($Entry in $SelectedEntries) {
        $SupportEntries.Add([pscustomobject][ordered]@{
            HeaderPath     = $HeaderFile.FullName
            Index          = $Entry.Index
            Directory      = $Entry.Directory
            Name           = $Entry.Name
            ExpandedSize   = $Entry.ExpandedSize
            CompressedSize = $Entry.CompressedSize
            Flags          = $Entry.Flags
            Volume         = $Entry.Volume
            DataOffset     = $Entry.DataOffset
          })
        if ([long]$Entry.ExpandedSize -gt $Script:InstallShieldCabinetSupportMaximumExpandedBytes - $ExpandedBytes) {
          throw 'Selected InstallShield cabinet support metadata exceeds the 64 MiB expansion limit.'
        }
        $ExpandedBytes += [long]$Entry.ExpandedSize
        # Keep each ordinal in its own directory. The catalog may legitimately
        # contain duplicate setup.inx names for different components.
        $RelativePath = Join-Path '_InstallShieldCabinet' (Join-Path $HeaderFile.BaseName (Join-Path ([string]$Entry.Index) ([string]$Entry.Name)))
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $ExtractedPath -RelativePath $RelativePath `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if ($Target.ShouldWrite) { $Targets.Add([int]$Entry.Index, [string]$Target.Path) }
      }

      foreach ($OutputPath in @([Dumplings.InstallShield.InstallShieldCabinetExtractor]::Extract(
            $HeaderFile.FullName,
            $Targets,
            $Script:InstallShieldCabinetSupportMaximumExpandedBytes
          ))) {
        $ExtractedFiles.Add([string]$OutputPath)
      }
    } catch {
      $Warnings.Add("InstallShield cabinet support metadata could not be decoded from '$($HeaderFile.Name)': $($_.Exception.Message)")
    }
  }

  return [pscustomobject][ordered]@{
    HeaderFiles       = [string[]]@($HeaderFiles | Select-Object -ExpandProperty FullName)
    CatalogEntryCount = $CatalogEntryCount
    SupportEntries    = [object[]]$SupportEntries.ToArray()
    RegistrySets      = [object[]]$RegistrySets.ToArray()
    RegistryWrites    = [object[]]$RegistryWrites.ToArray()
    CabinetFileGroups = [object[]]$CabinetFileGroups.ToArray()
    CabinetComponents = [object[]]$CabinetComponents.ToArray()
    MediaSetupTypes   = [object[]]$MediaSetupTypes.ToArray()
    ShellFolders      = [object[]]$ShellFolders.ToArray()
    Shortcuts         = [object[]]$Shortcuts.ToArray()
    ExtractedFiles    = [string[]]$ExtractedFiles.ToArray()
    ExpandedBytes     = $ExpandedBytes
    Warnings          = [string[]]$Warnings.ToArray()
  }
}

function ConvertTo-InstallShieldCabinetRelativePath {
  <#
  .SYNOPSIS
    Convert one InstallShield cabinet directory and file name to a safe relative path.
  .PARAMETER Directory
    Catalog directory string. InstallShield variables such as <TARGETDIR> are
    preserved as `_TARGETDIR_` path components rather than resolved or guessed.
  .PARAMETER Name
    Catalog file name from the validated file descriptor.
  .OUTPUTS
    A relative path suitable for Resolve-InstallerExtractionTarget.
  #>
  [OutputType([string])]
  param (
    [AllowEmptyString()]
    [string]$Directory,

    [Parameter(Mandatory)]
    [string]$Name
  )

  $Parts = [Collections.Generic.List[string]]::new()
  foreach ($Part in @($Directory.Replace('/', '\').Split('\', [StringSplitOptions]::RemoveEmptyEntries)) + @($Name)) {
    if ($Part -in '.', '..') { throw "An InstallShield cabinet path contains an unsafe segment: $Part" }
    # Catalog directories are logical InstallShield destinations, not host
    # paths. Keep variable identity while replacing Windows-invalid syntax.
    $Safe = [regex]::Replace($Part, '<(?<Name>[^<>]+)>', '_${Name}_')
    $Safe = [regex]::Replace($Safe, '[\x00-\x1F<>:"/\\|?*]', '_').TrimEnd('.', ' ')
    if ([string]::IsNullOrWhiteSpace($Safe)) { $Safe = '_' }
    $Parts.Add($Safe)
  }
  return [IO.Path]::Combine($Parts.ToArray())
}

function Expand-InstallShieldCabinet {
  <#
  .SYNOPSIS
    Extract selected files from an InstallShield 6+ data*.hdr/data*.cab set.
  .DESCRIPTION
    The managed extractor validates the ISc( catalog, every selected volume
    range, Deflate framing, expanded sizes, and MD5 digests. Files are streamed
    to disk; the complete cabinet entry is not materialized in memory. Split
    payloads stream across validated numbered-volume ranges, and linked catalog
    records resolve to the descriptor that owns their stored bytes.
  .PARAMETER Path
    Path to the data*.hdr catalog. The path is resolved before C# is called.
  .PARAMETER DestinationPath
    Output directory. When omitted, a sibling `<header-base>_u` directory is used.
  .PARAMETER Name
    Optional wildcard matched against both the catalog file name and logical
    relative path. Omit it to extract every valid catalog entry.
  .PARAMETER CollisionAction
    Existing-file policy. Prompt asks only after a collision is encountered;
    parser-internal callers pass Rename explicitly for unattended operation.
  .PARAMETER MaximumExpandedBytes
    Aggregate expanded-byte limit for selected entries. The default is 8 GiB.
  .OUTPUTS
    The resolved destination directory.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string]$Path,

    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $Script:InstallShieldCabinetMaximumExpandedBytes
  )

  process {
    $HeaderPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path (Split-Path -Path $HeaderPath -Parent) ((Split-Path -Path $HeaderPath -LeafBase) + '_u')
    }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    $Entries = @([Dumplings.InstallShield.InstallShieldCabinetExtractor]::List($HeaderPath))
    $Selected = @($Entries | Where-Object {
        if (-not $_.IsValid) { return $false }
        $RelativePath = ConvertTo-InstallShieldCabinetRelativePath -Directory $_.Directory -Name $_.Name
        $_.Name -like $Name -or $RelativePath -like $Name
      })
    if (-not $Selected) { throw "No valid InstallShield cabinet entries matched '$Name'." }

    $ExpandedBytes = 0L
    $Targets = [Collections.Generic.Dictionary[int, string]]::new()
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($Entry in $Selected) {
      if ([long]$Entry.ExpandedSize -gt $MaximumExpandedBytes - $ExpandedBytes) {
        throw 'Selected InstallShield cabinet output exceeds the configured expansion limit.'
      }
      $ExpandedBytes += [long]$Entry.ExpandedSize
      $RelativePath = ConvertTo-InstallShieldCabinetRelativePath -Directory $Entry.Directory -Name $Entry.Name
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if ($Target.ShouldWrite) { $Targets.Add([int]$Entry.Index, [string]$Target.Path) }
    }

    if ($Targets.Count) {
      $null = [Dumplings.InstallShield.InstallShieldCabinetExtractor]::Extract($HeaderPath, $Targets, $MaximumExpandedBytes)
    }
    return (Get-Item -LiteralPath $DestinationPath -Force).FullName
  }
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

  return ConvertFrom-Ini -Path $Path -MaximumBytes 4MB -DuplicateKeyAction Last -IgnoreComments
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

  $SectionValue = $Configuration[$Section]
  if ($SectionValue -isnot [System.Collections.IDictionary]) { return $null }
  return $SectionValue[$Name]
}

function Get-InstallShieldSetupPrerequisiteReference {
  <#
  .SYNOPSIS
    Read the setup prerequisites selected by an extracted Setup.ini file.
  .DESCRIPTION
    InstallShield serializes setup-level prerequisite selection under
    [ISSetupPrerequisites] as ordered PreReqN values. These references prove
    that a definition belongs to the current setup release; finding an
    unreferenced .prq file in the media does not provide that evidence.
  .PARAMETER Configuration
    Parsed Setup.ini dictionary returned by Read-InstallShieldIniConfiguration.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Configuration
  )

  $Section = $Configuration['ISSetupPrerequisites']
  if ($Section -isnot [System.Collections.IDictionary]) { return }

  # Numeric ordering preserves the launcher's authored prerequisite order even
  # when an INI writer emits PreReq10 before PreReq2 lexically.
  $References = [Collections.Generic.List[object]]::new()
  foreach ($Key in $Section.Keys) {
    if ([string]$Key -notmatch '^PreReq(?<Order>\d+)$') { continue }
    $Name = [string]$Section[$Key]
    if ([string]::IsNullOrWhiteSpace($Name)) { continue }
    $References.Add([pscustomobject][ordered]@{
        Name            = $Name.Trim()
        Order           = [int]$Matches.Order
        BuildSourcePath = $null
        SetupLocation   = $null
        ReleaseFlags    = $null
        ReferenceSource = 'Setup.ini [ISSetupPrerequisites]'
      })
  }

  $References | Sort-Object Order, Name
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
  .PARAMETER SetupIniFile
    Optional authoritative Setup.ini file. This supports external-media
    launchers whose configuration and MSI remain beside setup.exe.
  .PARAMETER SelectionRoot
    Root used to resolve Setup.ini package paths. Defaults to ExtractedPath.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$ExtractedPath,

    [AllowNull()]
    [AllowEmptyCollection()]
    [System.IO.FileInfo[]]$MsiFile,

    [System.IO.FileInfo]$SetupIniFile,

    [string]$SelectionRoot = $ExtractedPath
  )

  $Warnings = [System.Collections.Generic.List[string]]::new()
  $MsiFile = [IO.FileInfo[]]@($MsiFile | Where-Object { $null -ne $_ })
  # The root Setup.ini is the bootstrapper's primary configuration. A sole
  # nested copy is accepted, but multiple copies are deliberately ambiguous.
  $SelectionRoot = Resolve-InstallerFileSystemPath -Path $SelectionRoot -PathType Container
  $SetupIniFiles = if ($SetupIniFile) {
    @($SetupIniFile)
  } else {
    @(Get-ChildItem -LiteralPath $ExtractedPath -Filter 'Setup.ini' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
  }
  $RootSetupIni = @($SetupIniFiles | Where-Object {
      [System.IO.Path]::GetRelativePath($SelectionRoot, $_.FullName) -ieq 'Setup.ini'
    })
  $SetupIni = if ($SetupIniFile) {
    $SetupIniFile
  } elseif ($RootSetupIni.Count -eq 1) {
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
        RelativePath = ConvertTo-InstallShieldPayloadPath -Path ([System.IO.Path]::GetRelativePath($SelectionRoot, $_.FullName))
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
    $SourceKind = $SelectionRoot -ieq (Resolve-InstallerFileSystemPath -Path $ExtractedPath -PathType Container) ? 'Embedded' : 'ExternalSibling'
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
    SelectionMethod         = $SelectionMethod
    SourceKind              = $SourceKind
    SetupIniPath            = $null -eq $SetupIni ? $null : [System.IO.Path]::GetRelativePath($SelectionRoot, $SetupIni.FullName)
    SetupIniResolvedPath    = $null -eq $SetupIni ? $null : $SetupIni.FullName
    SelectionRoot           = $SelectionRoot
    PackageName             = [string]::IsNullOrWhiteSpace($PackageName) ? $null : $PackageName
    PackageLocation         = [string]::IsNullOrWhiteSpace($PackageLocation) ? $null : $PackageLocation
    ConfiguredPaths         = @($ConfiguredPaths)
    SelectedMsiPath         = $null -eq $Selected ? $null : $Selected.RelativePath
    SelectedMsiResolvedPath = $null -eq $Selected ? $null : $Selected.File.FullName
    Configuration           = $Configuration
    Warnings                = @($Warnings)
  }
}

function Get-InstallShieldExternalMediaSelection {
  <#
  .SYNOPSIS
    Resolve an external-media MSI selected by Setup.ini beside setup.exe.
  .DESCRIPTION
    Older InstallShield bootstrap media commonly stores Setup.ini and the MSI as
    sibling files. Only Startup.PackageName and that section's Location are
    considered; the directory is never recursively searched for MSI candidates.
  .PARAMETER InstallerPath
    Resolved path to the InstallShield setup launcher.
  .PARAMETER ExtractedPath
    Existing extraction root used to preserve the normal result contract.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][string]$ExtractedPath
  )

  $MediaRoot = [IO.Path]::GetDirectoryName($InstallerPath)
  $SetupIniPath = Join-Path $MediaRoot 'Setup.ini'
  if (-not (Test-Path -LiteralPath $SetupIniPath -PathType Leaf)) { return $null }

  $SetupIniFile = Get-Item -LiteralPath $SetupIniPath -Force
  $Configuration = Read-InstallShieldIniConfiguration -Path $SetupIniFile.FullName
  $PackageName = [string](Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'PackageName')
  $PackageLocation = if ([string]::IsNullOrWhiteSpace($PackageName)) {
    $null
  } else {
    [string](Get-InstallShieldIniValue -Configuration $Configuration -Section $PackageName -Name 'Location')
  }

  # Location is authoritative when present; PackageName remains the documented
  # fallback. Resolve-SafeExtractionPath rejects rooted and traversing paths.
  $ConfiguredPath = ConvertTo-InstallShieldPayloadPath -Path ($PackageLocation ?? $PackageName)
  if ([string]::IsNullOrWhiteSpace($ConfiguredPath) -or
    [Uri]::IsWellFormedUriString($ConfiguredPath, [UriKind]::Absolute)) {
    return Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile ([IO.FileInfo[]]@()) `
      -SetupIniFile $SetupIniFile -SelectionRoot $MediaRoot
  }

  try {
    $CandidatePath = Resolve-SafeExtractionPath -DestinationPath $MediaRoot -RelativePath $ConfiguredPath
  } catch {
    $Selection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile ([IO.FileInfo[]]@()) `
      -SetupIniFile $SetupIniFile -SelectionRoot $MediaRoot
    $Selection.Warnings = [string[]]@($Selection.Warnings + "Setup.ini selected an unsafe external package path '$ConfiguredPath': $($_.Exception.Message)")
    return $Selection
  }

  [IO.FileInfo[]]$Candidate = if ([IO.Path]::GetExtension($CandidatePath) -ieq '.msi' -and
    (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) {
    @(Get-Item -LiteralPath $CandidatePath -Force)
  } else {
    @()
  }
  return Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile $Candidate `
    -SetupIniFile $SetupIniFile -SelectionRoot $MediaRoot
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
    $SelectedResolvedPath = [string]$Selection.SelectedMsiResolvedPath
    $Selected = @($Item | Where-Object {
        if (-not [string]::IsNullOrWhiteSpace($SelectedResolvedPath)) {
          $_.FullName -ieq $SelectedResolvedPath
        } else {
          [System.IO.Path]::GetRelativePath($Installer.ExtractedPath, $_.FullName) -ieq $SelectedRelativePath
        }
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

  return Resolve-UniqueInstallerFile -Item $Item -Pattern $Pattern -BasePath $Installer.ExtractedPath -Description 'InstallShield payload'
}

function Expand-InstallShieldInstaller {
  <#
  .SYNOPSIS
    Extract files from an InstallShield executable using the in-process parser
  .PARAMETER Path
    The path to the InstallShield installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes decoded from an encoded or plain InstallShield overlay.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the InstallShield installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $Script:InstallShieldOverlayMaximumExpandedBytes
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path (Split-Path -Path $InstallerPath -Parent) ((Split-Path -Path $InstallerPath -LeafBase) + '_u')
    }

    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    Invoke-InstallShieldExtraction -Path $InstallerPath -DestinationPath $DestinationPath -Name $Name `
      -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes | Out-Null
    return $DestinationPath
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
      $CachedMsiInfo = $Installer.PSObject.Properties['SelectedMsiInfo']?.Value
      $MsiInfo = if ($CachedMsiInfo -and $CachedMsiInfo.Path -and (Convert-Path -LiteralPath $CachedMsiInfo.Path) -eq $MsiFile.FullName) {
        $CachedMsiInfo
      } else {
        Get-MsiInstallerInfo -Path $MsiFile.FullName
      }
      $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
      $SelectionMethod = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.SelectionMethod

      [pscustomobject][ordered]@{
        Path                                = $MsiFile.FullName
        InstallerType                       = $MsiInfo.InstallerType
        ProductCode                         = $MsiInfo.ProductCode
        UpgradeCode                         = $MsiInfo.UpgradeCode
        DisplayName                         = $MsiInfo.DisplayName
        DisplayVersion                      = $MsiInfo.DisplayVersion
        Publisher                           = $MsiInfo.Publisher
        Scope                               = $MsiInfo.Scope
        DefaultInstallLocation              = $MsiInfo.DefaultInstallLocation
        WritesAppsAndFeaturesEntry          = $MsiInfo.WritesAppsAndFeaturesEntry
        AppsAndFeaturesProductCode          = $MsiInfo.AppsAndFeaturesProductCode
        AppsAndFeaturesInstallerType        = $MsiInfo.AppsAndFeaturesInstallerType
        Warnings                            = [string[]]@($MsiInfo.Warnings)
        UnresolvedFields                    = [string[]]@($MsiInfo.UnresolvedFields)
        Name                                = $MsiFile.Name
        SelectedMsiPath                     = $Installer.MsiPayloadSelection.SelectedMsiPath ?? [System.IO.Path]::GetRelativePath($Installer.ExtractedPath, $MsiFile.FullName)
        SelectionMethod                     = $SelectionMethod
        PackageArchitecture                 = $MsiInfo.PackageArchitecture
        Template                            = $MsiInfo.Template
        InstallerBuilder                    = $MsiInfo.InstallerBuilder
        InstallShieldProjectType            = $MsiInfo.InstallShieldProjectType
        InstallShieldProjectTypeEvidence    = $MsiInfo.InstallShieldProjectTypeEvidence
        InstallShieldLauncherRequirement    = $MsiInfo.InstallShieldLauncherRequirement
        SummaryWordCount                    = $MsiInfo.SummaryWordCount
        AllowsInstallWithoutElevation       = $MsiInfo.AllowsInstallWithoutElevation
        InstallShieldScriptActions          = [object[]]@($MsiInfo.InstallShieldScriptActions)
        MsiSequenceRows                     = [object[]]@($MsiInfo.MsiSequenceRows)
        InstallShieldPrerequisiteReferences = [object[]]@($MsiInfo.InstallShieldPrerequisiteReferences)
        InstallShieldFeaturePrerequisites   = [object[]]@($MsiInfo.InstallShieldFeaturePrerequisites)
        InstallLocationProperty             = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch               = $MsiInfo.InstallLocationSwitch
        IsWiX                               = $MsiInfo.InstallerBuilder -ceq 'WiX'
        Protocols                           = $MsiInfo.Protocols
        FileExtensions                      = $MsiInfo.FileExtensions
        RegistryAssociationInfo             = $MsiInfo.RegistryAssociationInfo
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

Export-ModuleMember -Function *
