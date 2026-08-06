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
$InstallShieldCabinetSource = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..\Assets\Source\InstallShield') -Filter '*.cs' -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
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
  $HeaderFiles = @(Get-ChildItem -LiteralPath $ExtractedPath -Filter '*.hdr' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
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

# InstallShield MSI selection and result composition.
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
  .PARAMETER Name
    Optional wildcard selecting payload paths or file names. All files are extracted when omitted.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or another payload resolves to the same path.
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
    # Keep existing callers on the same output contract while routing all bytes
    # through the bounded in-process InstallShield parser.
    Expand-InstallShieldInstaller -Path $Path -DestinationPath $DestinationPath -Name $Name `
      -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
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

function New-InstallShieldAnalysisContext {
  <#
  .SYNOPSIS
    Build the immutable extraction and classification context for one InstallShield analysis.
  .PARAMETER Path
    Resolved installer path. The source file is opened once for both probing and extraction.
  .PARAMETER DestinationPath
    Optional extraction destination. A sibling `_u` directory is used when omitted.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [string]$DestinationPath
  )

  $ContainerFormat = 'InstallShield Overlay'
  $PackageForTheWebCabinet = $null
  $Warnings = [Collections.Generic.List[string]]::new()
  $ExtractedPath = if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
    Join-Path (Split-Path -Path $Path -Parent) ((Split-Path -Path $Path -LeafBase) + '_u')
  } else {
    Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  }

  # The outer launcher's PE manifest is independent from MSI and prerequisite
  # metadata. Preserve it as direct UAC evidence instead of inferring elevation
  # from a machine-scope payload.
  $RequestedExecutionLevel = $null
  try {
    $RequestedExecutionLevel = Get-PERequestedExecutionLevel -Path $Path
  } catch {
    $Warnings.Add("The InstallShield launcher's requested execution level could not be read: $($_.Exception.Message)")
  }

  $SourceStream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $OverlayOffset = Get-PEOverlayOffset -Stream $SourceStream
    if ($OverlayOffset -gt 0 -and $OverlayOffset -lt $SourceStream.Length) {
      $PackageForTheWebCabinet = Get-InstallShieldPackageForTheWebCabinet -Stream $SourceStream -OverlayOffset $OverlayOffset
      if ($PackageForTheWebCabinet) { $ContainerFormat = 'PackageForTheWeb Cabinet' }
    }
    $Extraction = Invoke-InstallShieldExtraction -Path $Path -SourceStream $SourceStream -DestinationPath $ExtractedPath -CollisionAction Rename
  } finally {
    $SourceStream.Dispose()
  }

  # Proprietary media may hide setup.inx inside data*.cab. Expand only bounded support
  # metadata, then enumerate the complete extraction tree exactly once.
  $CabinetSupport = Expand-InstallShieldCabinetSupport -ExtractedPath $ExtractedPath -CollisionAction Rename
  $Files = @(Get-ChildItem -LiteralPath $ExtractedPath -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
  $MsiFiles = @($Files | Where-Object Extension -EQ '.msi')
  $InxFiles = @($Files | Where-Object Extension -In @('.inx', '.ins'))
  $CabFiles = @($Files | Where-Object Extension -In @('.cab', '.hdr'))
  $SfxFiles = @($Files | Where-Object Name -Like '*_sfx.exe')
  $Prerequisites = [Collections.Generic.List[object]]::new()
  foreach ($PrerequisiteFile in @($Files | Where-Object Extension -EQ '.prq')) {
    try { $Prerequisites.Add((Get-InstallShieldPrerequisiteInfo -Path $PrerequisiteFile.FullName)) }
    catch { $Warnings.Add("The prerequisite definition '$($PrerequisiteFile.FullName)' could not be parsed: $($_.Exception.Message)") }
  }

  $AdvancedUiInfo = $null
  $AdvancedUiSetupXml = $Files | Where-Object Name -CEQ 'Setup.xml' | Select-Object -First 1
  if ($AdvancedUiSetupXml) {
    try {
      $AdvancedUiInfo = Get-InstallShieldAdvancedUiInfo -Path $AdvancedUiSetupXml.FullName -ExtractedPath $ExtractedPath
    } catch {
      # Setup.xml also occurs in unrelated payloads; warn only for an InstallShield bootstrap namespace.
      if ((Get-Content -LiteralPath $AdvancedUiSetupXml.FullName -TotalCount 2 -ErrorAction SilentlyContinue) -match 'installshield/\d{4}/bootstrap') {
        $Warnings.Add("The Advanced UI package catalog could not be parsed: $($_.Exception.Message)")
      }
    }
  }

  $MsiSelection = Get-InstallShieldMsiPayloadSelection -ExtractedPath $ExtractedPath -MsiFile $MsiFiles
  if (-not $MsiSelection.Configuration) {
    # InstallShield 11.x and other external-media launchers keep Setup.ini and
    # the MSI beside setup.exe. Resolve only the exact configured sibling path;
    # never widen this into a directory scan or wildcard selection.
    $ExternalMsiSelection = Get-InstallShieldExternalMediaSelection -InstallerPath $Path -ExtractedPath $ExtractedPath
    if ($ExternalMsiSelection) {
      $MsiSelection = $ExternalMsiSelection
      if ($MsiSelection.SelectedMsiResolvedPath) {
        $MsiFiles = @($MsiFiles) + @(Get-Item -LiteralPath $MsiSelection.SelectedMsiResolvedPath -Force)
      }
    }
  }
  $SelectedMsiInfo = $null
  if ($MsiSelection.SelectedMsiPath) {
    try {
      $SelectionContext = [pscustomobject]@{ ExtractedPath = $ExtractedPath; MsiPayloadSelection = $MsiSelection }
      $SelectedMsiFile = Resolve-InstallShieldMsiFile -Installer $SelectionContext -Item $MsiFiles -Pattern '*.msi' -NameWasSpecified $false
      $SelectedMsiInfo = Get-MsiInstallerInfo -Path $SelectedMsiFile.FullName
    } catch {
      $Warnings.Add("The selected InstallShield MSI could not be classified: $($_.Exception.Message)")
    }
  }

  $Variant = if ($AdvancedUiInfo) {
    'Advanced UI'
  } elseif ($MsiFiles) {
    $SelectedMsiInfo.InstallShieldProjectType ? $SelectedMsiInfo.InstallShieldProjectType : 'Basic MSI or InstallScript MSI'
  } elseif ($InxFiles) {
    'InstallScript'
  } elseif ($CabFiles -or $SfxFiles) {
    'InstallShield payload without MSI'
  } else {
    'Unknown'
  }

  return [pscustomobject][ordered]@{
    SourcePath              = $Path
    ContainerFormat         = $ContainerFormat
    PackageForTheWebCabinet = $PackageForTheWebCabinet
    Extraction              = $Extraction
    ExtractedPath           = $ExtractedPath
    Files                   = [object[]]$Files
    MsiFiles                = [object[]]$MsiFiles
    InxFiles                = [object[]]$InxFiles
    CabFiles                = [object[]]$CabFiles
    SfxFiles                = [object[]]$SfxFiles
    CabinetSupport          = $CabinetSupport
    SetupConfiguration      = $MsiSelection.Configuration
    MsiPayloadSelection     = $MsiSelection
    SelectedMsiInfo         = $SelectedMsiInfo
    RequestedExecutionLevel = $RequestedExecutionLevel
    PrerequisiteDefinitions = [object[]]$Prerequisites
    AdvancedUiInfo          = $AdvancedUiInfo
    Variant                 = $Variant
    ClassificationWarnings  = $Warnings
  }
}

function Merge-InstallShieldAdvancedUiResult {
  <#
  .SYNOPSIS
    Apply Advanced UI suite-owned metadata to an InstallShield result.
  .PARAMETER Result
    Mutable parser result being composed for the outer installer.
  .PARAMETER AdvancedUiInfo
    Parsed suite catalog. Suite identity remains authoritative over nested parcels.
  #>
  param ([Parameter(Mandatory)][psobject]$Result, [Parameter(Mandatory)][psobject]$AdvancedUiInfo)

  foreach ($PropertyName in @(
      'ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope',
      'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString',
      'DisplayIcon', 'URLInfoAbout', 'HelpLink', 'WritesAppsAndFeaturesEntry',
      'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType', 'ExecutedPayloads'
    )) {
    $Result.$PropertyName = $AdvancedUiInfo.$PropertyName
  }
  $Result.Warnings = [string[]]@($Result.Warnings + $AdvancedUiInfo.Warnings)
  $Result.UnresolvedFields = [string[]]@($AdvancedUiInfo.UnresolvedFields)
  return $Result
}

function Merge-InstallShieldInstallScriptResult {
  <#
  .SYNOPSIS
    Apply InstallScript-owned evidence without overriding an embedded MSI identity.
  .PARAMETER Result
    Mutable outer InstallShield result.
  .PARAMETER InstallScriptInfo
    Focused compiled-script analysis produced from the same extraction context.
  .PARAMETER Supplemental
    Retain the script as nested action evidence without applying its identity or
    standalone silent-install conclusions to the outer MSI or suite.
  #>
  param (
    [Parameter(Mandatory)][psobject]$Result,
    [Parameter(Mandatory)][psobject]$InstallScriptInfo,
    [switch]$Supplemental
  )

  $Result.InstallScriptInfo = $InstallScriptInfo
  if (-not $Supplemental -and -not $Result.HasMsi) {
    $Result.SilentSupport = $InstallScriptInfo.SilentSupport
    $Result.ResponseFileRequirement = $InstallScriptInfo.ResponseFileRequirement
    $Result.SilentSwitches = [string[]]@($InstallScriptInfo.SilentSwitches)
    foreach ($PropertyName in @(
        'ProductCode', 'DisplayName', 'DisplayVersion', 'Publisher', 'Scope',
        'DefaultInstallLocation', 'UninstallString', 'QuietUninstallString',
        'DisplayIcon', 'URLInfoAbout', 'HelpLink', 'WritesAppsAndFeaturesEntry',
        'AppsAndFeaturesProductCode', 'AppsAndFeaturesInstallerType',
        'AppsAndFeaturesEntries', 'RegistryWrites', 'RegistryItems', 'Protocols',
        'MediaRegistrySets', 'MediaRegistryWrites', 'ConditionalMediaRegistryWrites',
        'CabinetFileGroups', 'CabinetComponents', 'MediaSetupTypes',
        'MediaShellFolders', 'MediaShortcuts', 'ConditionalMediaShortcuts',
        'ConditionalRegistryAssociationInfo', 'ConditionalProtocols', 'ConditionalFileExtensions',
        'FileExtensions', 'ProtocolAssociations', 'FileExtensionAssociations',
        'RegistryAssociationInfo', 'ExecutedPayloads', 'FileOperations', 'DllOperations', 'Shortcuts',
        'PropertyHandlers', 'StaticCalls', 'OpcodeCoverage', 'UnsupportedOpcodes'
      )) {
      $Result.$PropertyName = $InstallScriptInfo.$PropertyName
    }
  }
  $Result.UnresolvedFields = [string[]]@((@($Result.UnresolvedFields) + @($InstallScriptInfo.UnresolvedFields)) | Select-Object -Unique)
  $Result.Warnings = [string[]]@($Result.Warnings + @($InstallScriptInfo.Warnings))
  return $Result
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
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Context = New-InstallShieldAnalysisContext -Path $InstallerPath -DestinationPath $DestinationPath
    $ContainerFormat = $Context.ContainerFormat
    $PackageForTheWebCabinet = $Context.PackageForTheWebCabinet
    $ExtractedPath = $Context.ExtractedPath
    $InstallShieldCabinetSupport = $Context.CabinetSupport
    $ExtractedFiles = [object[]]$Context.Files
    $MsiFiles = [object[]]$Context.MsiFiles
    $InxFiles = [object[]]$Context.InxFiles
    $CabFiles = [object[]]$Context.CabFiles
    $SfxFiles = [object[]]$Context.SfxFiles
    $ClassificationWarnings = $Context.ClassificationWarnings
    $PrerequisiteDefinitions = [object[]]$Context.PrerequisiteDefinitions
    $AdvancedUiInfo = $Context.AdvancedUiInfo
    $MsiPayloadSelection = $Context.MsiPayloadSelection
    $SelectedMsiInfo = $Context.SelectedMsiInfo
    $Variant = $Context.Variant
    $PayloadSelectionWarnings = if ($AdvancedUiInfo) { @() } else { @($MsiPayloadSelection.Warnings) }
    $PackageForTheWebInfo = if ($PackageForTheWebCabinet) {
      $Configuration = $MsiPayloadSelection.Configuration
      $RootSetupFiles = [object[]]@($ExtractedFiles | Where-Object {
          $_.Name -ieq 'Setup.exe' -and [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) -notmatch '[\\/]'
        })
      $NestedSetupFile = if ($RootSetupFiles.Count -eq 1) {
        $RootSetupFiles[0]
      } else {
        $AllSetupFiles = [object[]]@($ExtractedFiles | Where-Object Name -IEQ 'Setup.exe')
        $AllSetupFiles.Count -eq 1 ? $AllSetupFiles[0] : $null
      }
      $NestedPayloadPath = if ($MsiPayloadSelection.SelectedMsiPath) {
        $MsiPayloadSelection.SelectedMsiPath
      } elseif ($InxFiles.Count -eq 1) {
        [IO.Path]::GetRelativePath($ExtractedPath, $InxFiles[0].FullName)
      } else { $null }
      $NestedPayloadKind = if ($MsiPayloadSelection.SelectedMsiPath) { 'MSI' } elseif ($InxFiles.Count -eq 1) { 'InstallScript program' } else { $null }
      $ConfiguredCommandLine = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'CmdLine') : $null
      $LaunchChain = [Collections.Generic.List[object]]::new()
      if ($NestedSetupFile) {
        $LaunchChain.Add([pscustomobject][ordered]@{
            Stage     = 'PackageForTheWeb'
            Target    = [IO.Path]::GetRelativePath($ExtractedPath, $NestedSetupFile.FullName)
            Arguments = $null
            Evidence  = 'Unique root Setup.exe in the validated PackageForTheWeb cabinet'
          })
      }
      if ($NestedPayloadPath) {
        $LaunchChain.Add([pscustomobject][ordered]@{
            Stage     = 'InstallShield setup launcher'
            Target    = $NestedPayloadPath
            Arguments = $ConfiguredCommandLine
            Evidence  = $MsiPayloadSelection.SelectedMsiPath ? 'Setup.ini package Location' : 'Sole extracted InstallScript program'
          })
      }
      [pscustomobject][ordered]@{
        Cabinet                 = $PackageForTheWebCabinet
        SetupIniPath            = $MsiPayloadSelection.SetupIniPath
        Product                 = $Configuration ? ((Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'Product') ?? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'AppName')) : $null
        ProductGuid             = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'ProductGUID') : $null
        ConfiguredCommandLine   = $ConfiguredCommandLine
        PackageName             = $Configuration ? (Get-InstallShieldIniValue -Configuration $Configuration -Section 'Startup' -Name 'PackageName') : $null
        NestedSetupPath         = $NestedSetupFile ? [IO.Path]::GetRelativePath($ExtractedPath, $NestedSetupFile.FullName) : $null
        NestedSetupResolvedPath = $NestedSetupFile ? $NestedSetupFile.FullName : $null
        NestedPayloadPath       = $NestedPayloadPath
        NestedPayloadKind       = $NestedPayloadKind
        LaunchChain             = [object[]]$LaunchChain
        ExtractedFiles          = [string[]]@($ExtractedFiles | ForEach-Object { [IO.Path]::GetRelativePath($ExtractedPath, $_.FullName) })
      }
    } else { $null }
    # Setup.ini is authoritative for setup-level prerequisites. MSI table rows
    # retain feature prerequisite evidence, so merge both sources while
    # suppressing only exact duplicate names.
    $SetupPrerequisiteReferences = $MsiPayloadSelection.Configuration ? [object[]]@(
      Get-InstallShieldSetupPrerequisiteReference -Configuration $MsiPayloadSelection.Configuration
    ) : [object[]]@()
    $MsiPrerequisiteReferences = $SelectedMsiInfo ? [object[]]@($SelectedMsiInfo.InstallShieldPrerequisiteReferences) : [object[]]@()
    $PrerequisiteReferenceList = [Collections.Generic.List[object]]::new()
    $SeenPrerequisiteReferences = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($PrerequisiteReference in @($SetupPrerequisiteReferences) + @($MsiPrerequisiteReferences)) {
      $ReferenceName = [string]$PrerequisiteReference.Name
      if ([string]::IsNullOrWhiteSpace($ReferenceName) -or -not $SeenPrerequisiteReferences.Add($ReferenceName)) { continue }
      $PrerequisiteReferenceList.Add($PrerequisiteReference)
    }
    $PrerequisiteReferences = [object[]]$PrerequisiteReferenceList
    $PrerequisiteEvidence = [object[]]@(Join-InstallShieldPrerequisiteEvidence -Reference $PrerequisiteReferences -Definition ([object[]]$PrerequisiteDefinitions))
    foreach ($PrerequisiteWarning in @($PrerequisiteEvidence | Where-Object { $_.Reference -and $_.Warning } | ForEach-Object Warning)) {
      $ClassificationWarnings.Add($PrerequisiteWarning)
    }
    $ElevationRequirementEvidence = Get-InstallShieldElevationInfo `
      -RequestedExecutionLevel $Context.RequestedExecutionLevel `
      -PrerequisiteEvidence $PrerequisiteEvidence
    foreach ($ElevationWarning in @($ElevationRequirementEvidence.Warnings)) {
      $ClassificationWarnings.Add($ElevationWarning)
    }

    # The InstallShield launcher classification does not prove which nested
    # package owns ARP. Get-InstallShieldMsiInfo supplies identity only after
    # Setup.ini has selected an MSI payload.
    $Result = [pscustomobject][ordered]@{
      Path                               = $InstallerPath
      InstallerType                      = 'InstallShield'
      ProductCode                        = $null
      UpgradeCode                        = $null
      DisplayName                        = $null
      DisplayVersion                     = $null
      Publisher                          = $null
      Scope                              = $null
      ElevationRequirement               = $ElevationRequirementEvidence.ElevationRequirement
      RequestedExecutionLevel            = $Context.RequestedExecutionLevel
      ElevationRequirementEvidence       = $ElevationRequirementEvidence
      DefaultInstallLocation             = $null
      UninstallString                    = $null
      QuietUninstallString               = $null
      DisplayIcon                        = $null
      URLInfoAbout                       = $null
      HelpLink                           = $null
      WritesAppsAndFeaturesEntry         = $null
      AppsAndFeaturesProductCode         = $null
      AppsAndFeaturesInstallerType       = $null
      Warnings                           = [string[]]@($PayloadSelectionWarnings + $InstallShieldCabinetSupport.Warnings + $ClassificationWarnings + @($SelectedMsiInfo.InstallShieldScriptInfo.Warnings) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
      UnresolvedFields                   = [string[]]@()
      AppsAndFeaturesEntries             = [object[]]@()
      RegistryWrites                     = [object[]]@()
      RegistryItems                      = [object[]]@()
      MediaRegistrySets                  = [object[]]@()
      MediaRegistryWrites                = [object[]]@()
      ConditionalMediaRegistryWrites     = [object[]]@()
      CabinetFileGroups                  = [object[]]$InstallShieldCabinetSupport.CabinetFileGroups
      CabinetComponents                  = [object[]]$InstallShieldCabinetSupport.CabinetComponents
      MediaSetupTypes                    = [object[]]$InstallShieldCabinetSupport.MediaSetupTypes
      MediaShellFolders                  = [object[]]@()
      MediaShortcuts                     = [object[]]@()
      ConditionalMediaShortcuts          = [object[]]@()
      ConditionalRegistryAssociationInfo = $null
      ConditionalProtocols               = [string[]]@()
      ConditionalFileExtensions          = [string[]]@()
      Protocols                          = [string[]]@()
      FileExtensions                     = [string[]]@()
      ProtocolAssociations               = [object[]]@()
      FileExtensionAssociations          = [object[]]@()
      RegistryAssociationInfo            = $null
      ExecutedPayloads                   = [object[]]@()
      FileOperations                     = [object[]]@()
      DllOperations                      = [object[]]@()
      PropertyHandlers                   = [object[]]@()
      Shortcuts                          = [object[]]@()
      StaticCalls                        = [object[]]@()
      OpcodeCoverage                     = [object[]]@()
      UnsupportedOpcodes                 = [string[]]@()
      ExtractedPath                      = $ExtractedPath
      ExtractedFiles                     = [string[]]@($ExtractedFiles | Select-Object -ExpandProperty FullName)
      ContainerFormat                    = $ContainerFormat
      PackageForTheWebCabinet            = $PackageForTheWebCabinet
      PackageForTheWebInfo               = $PackageForTheWebInfo
      InstallShieldCabinetSupport        = $InstallShieldCabinetSupport
      Variant                            = $Variant
      HasMsi                             = [bool]$MsiFiles
      HasInstallScript                   = [bool]($InxFiles -or $SelectedMsiInfo.HasInstallScript)
      MsiFiles                           = @($MsiFiles | Select-Object -ExpandProperty FullName)
      SetupIniPath                       = $MsiPayloadSelection.SetupIniPath
      SetupConfiguration                 = $MsiPayloadSelection.Configuration
      MsiPayloadSelection                = $MsiPayloadSelection
      SelectedMsiPath                    = $MsiPayloadSelection.SelectedMsiPath
      SelectedMsiInfo                    = $SelectedMsiInfo
      InstallShieldProjectType           = $SelectedMsiInfo.InstallShieldProjectType
      InstallShieldProjectTypeEvidence   = $SelectedMsiInfo.InstallShieldProjectTypeEvidence
      InstallShieldLauncherRequirement   = $SelectedMsiInfo.InstallShieldLauncherRequirement
      PrerequisiteDefinitions            = [object[]]$PrerequisiteDefinitions
      PrerequisiteReferences             = $PrerequisiteReferences
      PrerequisiteEvidence               = $PrerequisiteEvidence
      InxFiles                           = @($InxFiles | Select-Object -ExpandProperty FullName)
      CabFiles                           = @($CabFiles | Select-Object -ExpandProperty FullName)
      SfxFiles                           = @($SfxFiles | Select-Object -ExpandProperty FullName)
      InstallScriptInfo                  = $SelectedMsiInfo.InstallShieldScriptInfo
      SilentSupport                      = $null
      ResponseFileRequirement            = $null
      SilentSwitches                     = [string[]]@()
      AdvancedUiInfo                     = $AdvancedUiInfo
      SuitePackages                      = $AdvancedUiInfo ? [object[]]@($AdvancedUiInfo.Packages) : [object[]]@()
    }

    if ($AdvancedUiInfo) {
      # Advanced UI owns its ARP identity through SuiteId. Nested MSI metadata
      # describes parcel installation only and must not replace the outer key.
      $Result = Merge-InstallShieldAdvancedUiResult -Result $Result -AdvancedUiInfo $AdvancedUiInfo
    }

    # Advanced UI CallInstallScript actions name the exact compiled functions
    # dispatched by suite events. Analyze only those roots and keep suite ARP
    # identity and command-line behavior authoritative.
    if ($AdvancedUiInfo -and $AdvancedUiInfo.InstallScriptEntryPoints -and $InxFiles -and (Get-Command Get-InstallShieldInstallScriptInfo -ErrorAction SilentlyContinue)) {
      try {
        $InstallScriptInfo = Get-InstallShieldInstallScriptInfo -Installer $Result `
          -EntryPoint $AdvancedUiInfo.InstallScriptEntryPoints -AnalysisScope EmbeddedAction
        $Result = Merge-InstallShieldInstallScriptResult -Result $Result -InstallScriptInfo $InstallScriptInfo -Supplemental
      } catch {
        $Result.Warnings = [string[]]@($Result.Warnings + "Advanced UI InstallScript action analysis failed: $($_.Exception.Message)")
      }
      # Reuse this extraction and analyze setup.inx/setup.iss once for a
      # standalone InstallScript package, where the script owns ARP and silent behavior.
    } elseif (-not $AdvancedUiInfo -and $InxFiles -and (Get-Command Get-InstallShieldInstallScriptInfo -ErrorAction SilentlyContinue)) {
      try {
        $InstallScriptInfo = Get-InstallShieldInstallScriptInfo -Installer $Result
        $Result = Merge-InstallShieldInstallScriptResult -Result $Result -InstallScriptInfo $InstallScriptInfo
      } catch {
        $Result.Warnings = [string[]]@($Result.Warnings + "InstallScript analysis failed: $($_.Exception.Message)")
      }
    }
    return $Result
  }
}

# InstallShield Advanced UI parsing.
function Resolve-InstallShieldSuiteString {
  <#
  .SYNOPSIS
    Resolve an Advanced UI string-table identifier in the default language.
  .PARAMETER Xml
    Parsed Setup.xml document using an installshield/<year>/bootstrap namespace.
  .PARAMETER Value
    Literal text or XML element name used as a localized string identifier.
  .PARAMETER Language
    Default LCID selected by the suite's LanguageSelection element.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][xml]$Xml,
    [string]$Value,
    [string]$Language
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  if ($Value -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*$') { return $Value }

  # Element names are fixed builder identifiers, so namespace-agnostic XPath
  # avoids coupling the parser to a particular InstallShield release year.
  $LanguageNode = if ($Language) {
    $Xml.SelectSingleNode("/*[local-name()='Setup']/*[local-name()='Languages']/*[local-name()='Language' and @lcid='$Language']")
  } else {
    $null
  }
  if (-not $LanguageNode) { $LanguageNode = $Xml.SelectSingleNode("/*[local-name()='Setup']/*[local-name()='Languages']/*[local-name()='Language'][1]") }
  $StringNode = if ($LanguageNode) { $LanguageNode.SelectSingleNode("./*[local-name()='$Value']") } else { $null }
  if ($StringNode -and -not [string]::IsNullOrWhiteSpace($StringNode.InnerText)) { return $StringNode.InnerText.Trim() }
  return $Value
}

function ConvertFrom-InstallShieldSuiteCondition {
  <#
  .SYNOPSIS
    Convert one Advanced UI condition subtree into bounded structured evidence.
  .DESCRIPTION
    InstallShield condition elements are declarative expression nodes such as
    All, Any, Not, RegistryValue, Platform, and ParcelRef. This function keeps
    their exact attributes and hierarchy. It does not evaluate registry,
    installed-state, property, or custom predicates against the analysis host.
  .PARAMETER Node
    Condition element whose offsets are XML-relative rather than installer-byte-relative.
  .PARAMETER Depth
    Internal recursion depth. Setup.xml trees deeper than 32 nodes are rejected.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
    [ValidateRange(0, 32)][int]$Depth = 0
  )

  if ($Depth -ge 32) { throw 'The Advanced UI condition tree exceeds the 32-level parser limit.' }
  $Attributes = [ordered]@{}
  foreach ($Attribute in @($Node.Attributes)) { $Attributes[$Attribute.Name] = $Attribute.Value }
  $ElementChildren = @($Node.ChildNodes | Where-Object NodeType -EQ ([Xml.XmlNodeType]::Element))
  $Children = foreach ($Child in $ElementChildren) {
    ConvertFrom-InstallShieldSuiteCondition -Node $Child -Depth ($Depth + 1)
  }
  $Text = if ($ElementChildren.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($Node.InnerText)) { $Node.InnerText.Trim() } else { $null }

  [pscustomobject][ordered]@{
    Type       = $Node.LocalName
    Attributes = $Attributes
    Value      = $Text
    Children   = [object[]]@($Children)
  }
}

function ConvertTo-InstallShieldSuiteConditionResult {
  <#
  .SYNOPSIS
    Create one normalized three-valued Advanced UI condition result.
  .PARAMETER State
    Static result: True, False, or Unknown.
  .PARAMETER ConditionType
    InstallShield XML element that produced the result.
  .PARAMETER Reasons
    Human-readable evidence explaining the known result.
  .PARAMETER UnknownPredicates
    Predicates that require target-machine or run-time state.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateSet('True', 'False', 'Unknown')][string]$State,
    [Parameter(Mandatory)][string]$ConditionType,
    [string[]]$Reasons = @(),
    [string[]]$UnknownPredicates = @()
  )

  [pscustomobject][ordered]@{
    State             = $State
    ConditionType     = $ConditionType
    Reasons           = [string[]]@($Reasons | Where-Object { $_ } | Select-Object -Unique)
    UnknownPredicates = [string[]]@($UnknownPredicates | Where-Object { $_ } | Select-Object -Unique)
  }
}

function Merge-InstallShieldSuiteConditionResult {
  <#
  .SYNOPSIS
    Apply InstallShield All, Any, or Not group semantics to child results.
  .PARAMETER Type
    Group operation. When and Eligible use All semantics; Not means none of its children.
  .PARAMETER Result
    Child condition results to combine.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateSet('All', 'Any', 'Not', 'When', 'Eligible')][string]$Type,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result
  )

  $Results = [object[]]@($Result)
  $Reasons = [string[]]@($Results.Reasons)
  $UnknownPredicates = [string[]]@($Results.UnknownPredicates)
  if ($Results.Count -eq 0) {
    return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType $Type -Reasons "The $Type condition group has no child predicates."
  }

  # InstallShield calls the Not group "None": it succeeds only when no child
  # condition succeeds, so multiple children are negated as an Any group.
  $EffectiveType = $Type -in @('When', 'Eligible') ? 'All' : $Type
  $Operator = $EffectiveType -eq 'Not' ? 'None' : $EffectiveType
  $State = Merge-InstallerConditionState -State ([string[]]$Results.State) -Operator $Operator

  ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType $Type -Reasons $Reasons -UnknownPredicates $UnknownPredicates
}

function Test-InstallShieldSuiteRange {
  <#
  .SYNOPSIS
    Evaluate an InstallShield exact/minimum/maximum numeric or version range.
  .PARAMETER Value
    Target value supplied by the caller, never read from the analysis host.
  .PARAMETER Range
    Authored exact value or range such as 6.1, 6.1-, -10.0, or 6.1-10.0.
  .PARAMETER Version
    Parse the values as System.Version rather than integers.
  #>
  [OutputType([Nullable[bool]])]
  param (
    [Parameter(Mandatory)][string]$Value,
    [Parameter(Mandatory)][string]$Range,
    [switch]$Version
  )

  try {
    $Convert = if ($Version) {
      { param($InputValue) [version]$InputValue }
    } else {
      { param($InputValue) [long]::Parse($InputValue, [Globalization.CultureInfo]::InvariantCulture) }
    }
    $Actual = & $Convert $Value
    if ($Range -notmatch '-') { return $Actual -eq (& $Convert $Range) }

    $Parts = $Range -split '-', 2
    if ($Parts[0] -and $Actual -lt (& $Convert $Parts[0])) { return $false }
    if ($Parts[1] -and $Actual -gt (& $Convert $Parts[1])) { return $false }
    return $true
  } catch {
    return $null
  }
}

function Resolve-InstallShieldSuiteCondition {
  <#
  .SYNOPSIS
    Evaluate the statically knowable portion of an Advanced UI condition tree.
  .DESCRIPTION
    The evaluator is intentionally three-valued. Platform facts supplied by the
    caller can produce True or False. Registry, file, installed-product,
    property, locale, package-reference, UWP, and extension-DLL predicates stay
    Unknown because evaluating them against the analysis host would be unsafe
    and would not describe the eventual target system.
  .PARAMETER Condition
    Structured condition returned by ConvertFrom-InstallShieldSuiteCondition.
  .PARAMETER Architecture
    Optional target architecture: x86, x64, arm, arm64, or ia64.
  .PARAMETER OSVersion
    Optional target Windows major/minor version, such as 10.0.
  .PARAMETER BuildNumber
    Optional target Windows build number.
  .PARAMETER ServicePack
    Optional target service-pack major number.
  .PARAMETER CSDVersion
    Optional target CSD display string.
  .PARAMETER ProductType
    Optional target product type: Workstation, Server, or DomainController.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Condition,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [string]$CSDVersion,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    if (-not $Condition.Type) {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Unknown -Reasons 'The condition object has no element type.'
    }

    $Type = [string]$Condition.Type
    if ($Type -in @('All', 'Any', 'Not', 'When', 'Eligible')) {
      $ChildResults = foreach ($Child in @($Condition.Children)) {
        Resolve-InstallShieldSuiteCondition -Condition $Child -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType
      }
      return Merge-InstallShieldSuiteConditionResult -Type $Type -Result ([object[]]@($ChildResults))
    }

    if ($Type -ne 'Platform') {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType $Type -UnknownPredicates $Type -Reasons "The $Type predicate depends on target or run-time state."
    }

    $Checks = [Collections.Generic.List[object]]::new()
    $Attributes = $Condition.Attributes
    if ($Attributes['Architecture']) {
      if (-not $Architecture) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.Architecture' -Reasons 'No target architecture was supplied.'))
      } else {
        $AcceptedArchitectures = [string[]]@($Attributes['Architecture'] -split '[,;|\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
        $MatchesArchitecture = $Architecture.ToLowerInvariant() -in $AcceptedArchitectures
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesArchitecture ? 'True' : 'False') -ConditionType Platform -Reasons "Target architecture '$Architecture' $($MatchesArchitecture ? 'matches' : 'does not match') '$($Attributes['Architecture'])'."))
      }
    }
    if ($Attributes['OSVersion']) {
      if (-not $OSVersion) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.OSVersion' -Reasons 'No target OS version was supplied.'))
      } else {
        $RangeResult = Test-InstallShieldSuiteRange -Value $OSVersion -Range $Attributes['OSVersion'] -Version
        $State = $null -eq $RangeResult ? 'Unknown' : ($RangeResult ? 'True' : 'False')
        $Unknown = $null -eq $RangeResult ? 'Platform.OSVersion' : @()
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType Platform -UnknownPredicates $Unknown -Reasons "Target OS version '$OSVersion' was compared with '$($Attributes['OSVersion'])'."))
      }
    }
    if ($Attributes['BuildNumber']) {
      if ($null -eq $BuildNumber) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.BuildNumber' -Reasons 'No target build number was supplied.'))
      } else {
        $MinimumBuild = 0L
        $Parsed = [long]::TryParse($Attributes['BuildNumber'], [ref]$MinimumBuild)
        $State = -not $Parsed ? 'Unknown' : ([long]$BuildNumber -ge $MinimumBuild ? 'True' : 'False')
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType Platform -UnknownPredicates (-not $Parsed ? 'Platform.BuildNumber' : @()) -Reasons "Target build '$BuildNumber' was compared with minimum '$($Attributes['BuildNumber'])'."))
      }
    }
    if ($Attributes['ServicePack']) {
      if ($null -eq $ServicePack) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.ServicePack' -Reasons 'No target service-pack number was supplied.'))
      } else {
        $RangeResult = Test-InstallShieldSuiteRange -Value ([string]$ServicePack) -Range $Attributes['ServicePack']
        $State = $null -eq $RangeResult ? 'Unknown' : ($RangeResult ? 'True' : 'False')
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State $State -ConditionType Platform -UnknownPredicates ($null -eq $RangeResult ? 'Platform.ServicePack' : @()) -Reasons "Target service pack '$ServicePack' was compared with '$($Attributes['ServicePack'])'."))
      }
    }
    if ($Attributes['CSDVersion']) {
      if (-not $CSDVersion) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.CSDVersion' -Reasons 'No target CSD version was supplied.'))
      } else {
        $MatchesCsd = $CSDVersion -ieq $Attributes['CSDVersion']
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesCsd ? 'True' : 'False') -ConditionType Platform -Reasons "Target CSD version '$CSDVersion' $($MatchesCsd ? 'matches' : 'does not match') '$($Attributes['CSDVersion'])'."))
      }
    }
    if ($Attributes['ProductType']) {
      if (-not $ProductType) {
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates 'Platform.ProductType' -Reasons 'No target product type was supplied.'))
      } else {
        $AcceptedProductTypes = [string[]]@($Attributes['ProductType'] -split '[,;|\s]+' | Where-Object { $_ })
        $MatchesProductType = $ProductType -in $AcceptedProductTypes
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesProductType ? 'True' : 'False') -ConditionType Platform -Reasons "Target product type '$ProductType' $($MatchesProductType ? 'matches' : 'does not match') '$($Attributes['ProductType'])'."))
      }
    }

    if ($Checks.Count -eq 0) {
      return ConvertTo-InstallShieldSuiteConditionResult -State Unknown -ConditionType Platform -UnknownPredicates Platform -Reasons 'The Platform predicate contains no supported static attributes.'
    }
    Merge-InstallShieldSuiteConditionResult -Type All -Result ([object[]]$Checks)
  }
}

function Get-InstallShieldAdvancedUiPackageEligibility {
  <#
  .SYNOPSIS
    Resolve static eligibility for every package in an Advanced UI catalog.
  .DESCRIPTION
    Package architecture, package-level Eligible conditions, and SelectionTree
    install conditions are combined. Detect conditions are intentionally not
    considered: they describe installed state and operation planning, not
    whether a package can run on the target platform.
  .PARAMETER Info
    Result from Get-InstallShieldAdvancedUiInfo.
  .PARAMETER Architecture
    Optional target architecture.
  .PARAMETER OSVersion
    Optional target Windows major/minor version.
  .PARAMETER BuildNumber
    Optional target Windows build number.
  .PARAMETER ServicePack
    Optional target service-pack number.
  .PARAMETER CSDVersion
    Optional target CSD version text.
  .PARAMETER ProductType
    Optional target product type.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Info,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [string]$CSDVersion,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    foreach ($Package in @($Info.Packages)) {
      $Checks = [Collections.Generic.List[object]]::new()
      if ($Architecture -and $Package.Architecture) {
        $MatchesArchitecture = $Architecture -ieq $Package.Architecture
        $Checks.Add((ConvertTo-InstallShieldSuiteConditionResult -State ($MatchesArchitecture ? 'True' : 'False') -ConditionType PackageArchitecture -Reasons "Package architecture '$($Package.Architecture)' $($MatchesArchitecture ? 'matches' : 'does not match') target '$Architecture'."))
      }
      if ($Package.EligibilityCondition) {
        $Checks.Add((Resolve-InstallShieldSuiteCondition -Condition $Package.EligibilityCondition -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType))
      }

      # Multiple selections can install the same parcel. Any applicable
      # selection is sufficient, whereas all independent package checks must pass.
      $InstallSelections = [object[]]@($Info.Selections | Where-Object { $Package.Id -in $_.InstallPackageIds })
      if ($InstallSelections.Count -gt 0) {
        $SelectionResults = foreach ($Selection in $InstallSelections) {
          if ($Selection.Condition) {
            Resolve-InstallShieldSuiteCondition -Condition $Selection.Condition -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType
          } else {
            ConvertTo-InstallShieldSuiteConditionResult -State True -ConditionType Selection -Reasons "Selection '$($Selection.Name)' has no condition."
          }
        }
        $Checks.Add((Merge-InstallShieldSuiteConditionResult -Type Any -Result ([object[]]@($SelectionResults))))
      }

      $Combined = if ($Checks.Count -gt 0) {
        Merge-InstallShieldSuiteConditionResult -Type All -Result ([object[]]$Checks)
      } else {
        ConvertTo-InstallShieldSuiteConditionResult -State True -ConditionType Package -Reasons 'The package has no authored static eligibility restrictions.'
      }
      [pscustomobject][ordered]@{
        PackageId         = $Package.Id
        Type              = $Package.Type
        Architecture      = $Package.Architecture
        State             = $Combined.State
        Reasons           = [string[]]$Combined.Reasons
        UnknownPredicates = [string[]]$Combined.UnknownPredicates
        SelectedBy        = [string[]]@($InstallSelections.Name)
      }
    }
  }
}

function Get-InstallShieldAdvancedUiPackageTargetFile {
  <#
  .SYNOPSIS
    Resolve the exact locally extracted file launched by an Advanced UI parcel.
  .PARAMETER Package
    Package record returned in Get-InstallShieldAdvancedUiInfo.Packages.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][object]$Package)

  $Files = [object[]]@($Package.Files)
  $InstallOperation = $Package.Operations | Where-Object Name -CEQ 'Install' | Select-Object -First 1
  $Target = [string]$InstallOperation.Target
  if ($Target) {
    # Operation.Target normally contains a basename while File.Name can include
    # a GUID staging directory. Compare both normalized relative path and basename.
    $NormalizedTarget = $Target.Replace('/', '\').TrimStart('.\')
    $TargetMatches = [object[]]@($Files | Where-Object {
        $RelativePath = ([string]$_.RelativePath).Replace('/', '\').TrimStart('.\')
        $RelativePath -ceq $NormalizedTarget -or [IO.Path]::GetFileName($RelativePath) -ceq [IO.Path]::GetFileName($NormalizedTarget)
      })
    if ($TargetMatches.Count -eq 1) {
      return [pscustomobject][ordered]@{ File = $TargetMatches[0]; Target = $Target; SelectionMethod = 'OperationTarget'; Warning = $null }
    }
    if ($TargetMatches.Count -gt 1) {
      return [pscustomobject][ordered]@{ File = $null; Target = $Target; SelectionMethod = 'AmbiguousOperationTarget'; Warning = "Operation target '$Target' matches more than one catalog file." }
    }
  }

  $Extensions = switch ($Package.Type) {
    'Msi' { @('.msi') }
    'Msp' { @('.msp') }
    { $_ -in @('Exe', 'IsmMsi', 'IsmIsp', 'InstallScript') } { @('.exe'); break }
    'Appx' { @('.appx', '.msix') }
    'AppxBundle' { @('.appxbundle', '.msixbundle') }
    { $_ -in @('Prq', 'Prerequisite') } { @('.prq'); break }
    default { @() }
  }
  $Candidates = if ($Extensions.Count -gt 0) {
    [object[]]@($Files | Where-Object { [IO.Path]::GetExtension([string]$_.RelativePath) -in $Extensions })
  } else {
    [object[]]@()
  }
  if ($Candidates.Count -eq 1) {
    return [pscustomobject][ordered]@{ File = $Candidates[0]; Target = $Target; SelectionMethod = 'SingleTypedCatalogFile'; Warning = $null }
  }

  $Warning = if ($Target) {
    "Operation target '$Target' does not resolve to one local catalog file."
  } elseif ($Candidates.Count -gt 1) {
    "The parcel contains $($Candidates.Count) format-matching files but no exact install operation target."
  } else {
    'The parcel does not identify one supported nested target file.'
  }
  [pscustomobject][ordered]@{ File = $null; Target = $Target; SelectionMethod = 'Unresolved'; Warning = $Warning }
}

function Get-InstallShieldAdvancedUiNestedPackageInfo {
  <#
  .SYNOPSIS
    Dispatch local Advanced UI parcel targets to their canonical static parsers.
  .DESCRIPTION
    Statically false packages are skipped. True and Unknown packages are parsed
    when their exact target is present beneath the extracted suite. External
    SourceUrl payloads are never downloaded by this function.
  .PARAMETER Info
    Result from Get-InstallShieldAdvancedUiInfo.
  .PARAMETER Architecture
    Optional target architecture used by package eligibility.
  .PARAMETER OSVersion
    Optional target Windows major/minor version used by package eligibility.
  .PARAMETER BuildNumber
    Optional target Windows build number used by package eligibility.
  .PARAMETER ServicePack
    Optional target service-pack number used by package eligibility.
  .PARAMETER CSDVersion
    Optional target CSD version used by package eligibility.
  .PARAMETER ProductType
    Optional target product type used by package eligibility.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][object]$Info,
    [ValidateSet('x86', 'x64', 'arm', 'arm64', 'ia64')][string]$Architecture,
    [string]$OSVersion,
    [Nullable[int]]$BuildNumber,
    [Nullable[int]]$ServicePack,
    [string]$CSDVersion,
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -in @('Workstation', 'Server', 'DomainController') })][string]$ProductType
  )

  process {
    $Eligibility = [object[]]@(Get-InstallShieldAdvancedUiPackageEligibility -Info $Info -Architecture $Architecture -OSVersion $OSVersion -BuildNumber $BuildNumber -ServicePack $ServicePack -CSDVersion $CSDVersion -ProductType $ProductType)
    foreach ($Package in @($Info.Packages)) {
      $PackageEligibility = $Eligibility | Where-Object PackageId -CEQ $Package.Id | Select-Object -First 1
      $Warnings = [Collections.Generic.List[string]]::new()
      $Parser = $null
      $NestedInfo = $null
      $Success = $false
      $TargetInfo = $null

      if ($PackageEligibility.State -eq 'False') {
        $Warnings.Add('The package is statically ineligible for the supplied target facts and was not parsed.')
      } else {
        $TargetInfo = Get-InstallShieldAdvancedUiPackageTargetFile -Package $Package
        if ($TargetInfo.Warning) { $Warnings.Add($TargetInfo.Warning) }
        $TargetFile = $TargetInfo.File
        if ($TargetFile -and -not $TargetFile.ResolvedPath) {
          $SourceUrl = [string]$TargetFile.SourceUrl
          $Warnings.Add($SourceUrl ? "The exact parcel target is external or was not extracted; it was not downloaded from '$SourceUrl'." : 'The exact parcel target is not present beneath the extracted suite path.')
        } elseif ($TargetFile -and $TargetFile.ResolvedPath) {
          try {
            # Package types select format-specific parsers. Generic EXE and MSP
            # targets use the analyzer so content magic, not the catalog label,
            # determines the nested installer family.
            switch ($Package.Type) {
              'Msi' {
                $Parser = 'Windows Installer'
                $NestedInfo = Get-MsiInstallerInfo -Path $TargetFile.ResolvedPath
              }
              { $_ -in @('Appx', 'AppxBundle') } {
                $Parser = 'MSIX/AppX'
                $NestedInfo = Get-MSIXInfo -Path $TargetFile.ResolvedPath
                break
              }
              { $_ -in @('IsmMsi', 'IsmIsp', 'InstallScript') } {
                $Parser = 'InstallShield'
                $NestedInfo = Get-InstallShieldInfo -Path $TargetFile.ResolvedPath
                break
              }
              { $_ -in @('Prq', 'Prerequisite') } {
                $Parser = 'InstallShield prerequisite'
                $NestedInfo = Get-InstallShieldPrerequisiteInfo -Path $TargetFile.ResolvedPath
                break
              }
              { $_ -in @('Exe', 'Msp') } {
                $Parser = 'WinGet installer analyzer'
                if (-not (Get-Command Get-WinGetInstallerAnalysis -ErrorAction SilentlyContinue)) {
                  throw 'Get-WinGetInstallerAnalysis is not loaded in the current runspace.'
                }
                $NestedInfo = Get-WinGetInstallerAnalysis -Path $TargetFile.ResolvedPath
                break
              }
              default {
                $Warnings.Add("No static nested parser is registered for Advanced UI package type '$($Package.Type)'.")
              }
            }
            $Success = $null -ne $NestedInfo
          } catch {
            $Warnings.Add("$Parser nested analysis failed: $($_.Exception.Message)")
          }
        }
      }

      [pscustomobject][ordered]@{
        PackageId          = $Package.Id
        PackageType        = $Package.Type
        EligibilityState   = $PackageEligibility.State
        EligibilityReasons = [string[]]@($PackageEligibility.Reasons)
        UnknownPredicates  = [string[]]@($PackageEligibility.UnknownPredicates)
        Target             = $TargetInfo ? $TargetInfo.Target : $null
        SourcePath         = ($TargetInfo -and $TargetInfo.File) ? $TargetInfo.File.ResolvedPath : $null
        SourceUrl          = ($TargetInfo -and $TargetInfo.File) ? $TargetInfo.File.SourceUrl : $null
        SelectionMethod    = $TargetInfo ? $TargetInfo.SelectionMethod : $null
        Parser             = $Parser
        Success            = $Success
        Info               = $NestedInfo
        Warnings           = [string[]]$Warnings
      }
    }
  }
}

function ConvertFrom-InstallShieldIntegerList {
  <#
  .SYNOPSIS
    Parse a bounded InstallShield comma/semicolon-delimited integer list.
  .PARAMETER Value
    Raw property or XML attribute value containing decimal return codes.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][string]$Value)

  $Values = [Collections.Generic.List[int]]::new()
  $InvalidValues = [Collections.Generic.List[string]]::new()
  foreach ($Part in @($Value -split '[,;]' | ForEach-Object Trim | Where-Object { $_ })) {
    $Code = 0
    if ([int]::TryParse($Part, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Code)) {
      $Values.Add($Code)
    } else {
      $InvalidValues.Add($Part)
    }
  }
  [pscustomobject][ordered]@{
    Values        = [int[]]$Values
    InvalidValues = [string[]]$InvalidValues
  }
}

function Join-InstallShieldPrerequisiteEvidence {
  <#
  .SYNOPSIS
    Correlate MSI prerequisite table references with extracted .prq definitions.
  .DESCRIPTION
    Only exact identifiers, descriptions, filenames, or filename stems are
    accepted. Fuzzy matching could attach the wrong download or silent command
    to a similarly named prerequisite and is therefore intentionally omitted.
  .PARAMETER Reference
    ISSetupPrerequisites table rows from Get-MsiInstallerInfo.
  .PARAMETER Definition
    Parsed .prq records from Get-InstallShieldPrerequisiteInfo.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [AllowEmptyCollection()][object[]]$Reference = @(),
    [AllowEmptyCollection()][object[]]$Definition = @()
  )

  $MatchedDefinitionPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($ReferenceItem in @($Reference)) {
    $ReferenceName = [string]$ReferenceItem.Name
    $DefinitionMatches = [object[]]@($Definition | Where-Object {
        $FileName = [IO.Path]::GetFileName([string]$_.Path)
        $FileStem = [IO.Path]::GetFileNameWithoutExtension($FileName)
        $ReferenceName -ieq $_.Id -or $ReferenceName -ieq $_.Description -or $ReferenceName -ieq $FileName -or $ReferenceName -ieq $FileStem
      })
    $Match = $DefinitionMatches.Count -eq 1 ? $DefinitionMatches[0] : $null
    if ($Match) { [void]$MatchedDefinitionPaths.Add([string]$Match.Path) }
    [pscustomobject][ordered]@{
      Reference   = $ReferenceItem
      Definition  = $Match
      MatchMethod = $Match ? 'ExactIdentityOrName' : ($DefinitionMatches.Count -gt 1 ? 'Ambiguous' : 'Unresolved')
      Warning     = if ($DefinitionMatches.Count -gt 1) {
        "Prerequisite reference '$ReferenceName' matches more than one extracted definition."
      } elseif (-not $Match) {
        "Prerequisite reference '$ReferenceName' has no exact extracted definition."
      } else { $null }
    }
  }

  # Preserve definitions that are present on the media but not referenced by
  # the selected MSI. Presence alone does not prove they run for this release.
  foreach ($DefinitionItem in @($Definition)) {
    if ($MatchedDefinitionPaths.Contains([string]$DefinitionItem.Path)) { continue }
    [pscustomobject][ordered]@{
      Reference   = $null
      Definition  = $DefinitionItem
      MatchMethod = 'UnreferencedDefinition'
      Warning     = 'The prerequisite definition is present but is not referenced by the selected MSI.'
    }
  }
}

function Get-InstallShieldElevationInfo {
  <#
  .SYNOPSIS
    Derive a conservative WinGet elevation recommendation from InstallShield metadata.
  .DESCRIPTION
    A requireAdministrator PE manifest is direct evidence. An exactly matched,
    release-selected .prq definition is also sufficient when its Behavior page
    requires administrative privileges. Machine scope and unreferenced .prq
    files are intentionally not treated as elevation evidence.
  .PARAMETER RequestedExecutionLevel
    requestedExecutionLevel read from the outer InstallShield PE manifest.
  .PARAMETER PrerequisiteEvidence
    Exact reference-to-definition correlations produced by
    Join-InstallShieldPrerequisiteEvidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][string]$RequestedExecutionLevel,
    [AllowEmptyCollection()][object[]]$PrerequisiteEvidence = @()
  )

  $Reasons = [Collections.Generic.List[string]]::new()
  $Warnings = [Collections.Generic.List[string]]::new()
  $AdministrativePrerequisites = [Collections.Generic.List[object]]::new()
  $SeenDefinitionPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  if ($RequestedExecutionLevel -ieq 'requireAdministrator') {
    $Reasons.Add('The outer PE manifest requests requireAdministrator.')
  }

  foreach ($Evidence in @($PrerequisiteEvidence)) {
    # Only an exact release reference proves that this definition can run.
    # Unreferenced definitions may be builder/media residue from another setup.
    if (-not $Evidence.Reference -or $Evidence.MatchMethod -ne 'ExactIdentityOrName' -or -not $Evidence.Definition) { continue }
    if ($Evidence.Definition.RequiresAdministrativePrivileges -ne $true) { continue }
    $DefinitionPath = [string]$Evidence.Definition.Path
    if (-not $SeenDefinitionPaths.Add($DefinitionPath)) { continue }

    $AdministrativePrerequisites.Add($Evidence.Definition)
    $PrerequisiteName = [string]$Evidence.Definition.Description
    if ([string]::IsNullOrWhiteSpace($PrerequisiteName)) { $PrerequisiteName = [string]$Evidence.Reference.Name }
    $Reasons.Add("The selected prerequisite '$PrerequisiteName' requires administrative privileges.")

    # Elevation can make the prerequisite runnable, but it cannot manufacture
    # an unattended command line that the prerequisite author did not provide.
    if ([string]::IsNullOrWhiteSpace([string]$Evidence.Definition.SilentCommandLine)) {
      $Warnings.Add("Selected prerequisite '$PrerequisiteName' requires administrative privileges but does not define a silent command line; elevation does not prove unattended installation support.")
    }
  }

  $HasDirectLauncherEvidence = $RequestedExecutionLevel -ieq 'requireAdministrator'
  $HasPrerequisiteEvidence = $AdministrativePrerequisites.Count -gt 0
  [pscustomobject][ordered]@{
    ElevationRequirement                = ($HasDirectLauncherEvidence -or $HasPrerequisiteEvidence) ? 'elevationRequired' : $null
    RequestedExecutionLevel             = [string]::IsNullOrWhiteSpace($RequestedExecutionLevel) ? $null : $RequestedExecutionLevel
    Confidence                          = $HasDirectLauncherEvidence ? 'DirectPEManifest' : ($HasPrerequisiteEvidence ? 'SelectedPrerequisiteDefinition' : 'Unknown')
    SelectedAdministrativePrerequisites = [object[]]$AdministrativePrerequisites
    Reasons                             = [string[]]$Reasons
    Warnings                            = [string[]]$Warnings
  }
}

function Get-InstallShieldPrerequisiteInfo {
  <#
  .SYNOPSIS
    Parse one InstallShield setup-prerequisite definition.
  .DESCRIPTION
    A .prq XML file defines prerequisite detection conditions, supported OS
    conditions, payload URLs/checksums, invocation arguments, and reboot codes.
    Parsing the definition does not prove that a particular release embeds or
    selects it; correlate the Id/name with MSI or suite package evidence.
  .PARAMETER Path
    Path to an extracted or official InstallShield .prq XML definition.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $PrerequisitePath = (Get-Item -LiteralPath $Path -Force).FullName
    [xml]$Xml = Get-Content -LiteralPath $PrerequisitePath -Raw
    $Root = $Xml.DocumentElement
    if ($Root.LocalName -ne 'SetupPrereq') { throw "'$PrerequisitePath' is not an InstallShield setup-prerequisite definition." }

    $PropertiesNode = $Root.SelectSingleNode('./properties')
    $ExecuteNode = $Root.SelectSingleNode('./execute')
    $BehaviorNode = $Root.SelectSingleNode('./behavior')
    $Files = foreach ($FileNode in @($Root.SelectNodes('./files/file'))) {
      $SizeParts = @($FileNode.GetAttribute('FileSize') -split ',')
      $Size = 0L
      if ($SizeParts.Count -and -not [long]::TryParse($SizeParts[-1], [ref]$Size)) { $Size = 0 }
      [pscustomobject][ordered]@{
        LocalFile = $FileNode.GetAttribute('LocalFile')
        Url       = $FileNode.GetAttribute('URL')
        Checksum  = $FileNode.GetAttribute('CheckSum')
        Size      = $Size
      }
    }
    $DetectionConditions = foreach ($Node in @($Root.SelectNodes('./conditions/condition'))) {
      ConvertFrom-InstallShieldSuiteCondition -Node $Node
    }
    $OperatingSystemConditions = foreach ($Node in @($Root.SelectNodes('./operatingsystemconditions/operatingsystemcondition'))) {
      ConvertFrom-InstallShieldSuiteCondition -Node $Node
    }
    $RebootCodeInfo = ConvertFrom-InstallShieldIntegerList -Value ($ExecuteNode ? $ExecuteNode.GetAttribute('returncodetoreboot') : $null)
    # The prerequisite editor writes Lua="1" only when "The prerequisite
    # requires administrative privileges" is cleared. The default checked
    # state is represented by omitting Lua from the behavior element.
    $LimitedUserCompatible = if ($BehaviorNode) { $BehaviorNode.GetAttribute('Lua') -eq '1' } else { $null }
    $RequiresAdministrativePrivileges = if ($null -eq $LimitedUserCompatible) { $null } else { -not $LimitedUserCompatible }
    $Dependencies = foreach ($DependencyNode in @($Root.SelectNodes('./dependencies/dependency'))) {
      $DependencyFile = $DependencyNode.GetAttribute('File')
      if (-not [string]::IsNullOrWhiteSpace($DependencyFile)) { $DependencyFile }
    }

    [pscustomobject][ordered]@{
      Path                             = $PrerequisitePath
      Id                               = $PropertiesNode ? $PropertiesNode.GetAttribute('Id') : $null
      Description                      = $PropertiesNode ? $PropertiesNode.GetAttribute('Description') : $null
      AlternateDefinitionUrl           = $PropertiesNode ? $PropertiesNode.GetAttribute('AltPrqURL') : $null
      Files                            = [object[]]@($Files)
      DetectionConditions              = [object[]]@($DetectionConditions)
      OperatingSystemConditions        = [object[]]@($OperatingSystemConditions)
      Executable                       = $ExecuteNode ? $ExecuteNode.GetAttribute('file') : $null
      CommandLine                      = $ExecuteNode ? $ExecuteNode.GetAttribute('cmdline') : $null
      SilentCommandLine                = $ExecuteNode ? $ExecuteNode.GetAttribute('cmdlinesilent') : $null
      HasSilentCommandLine             = $ExecuteNode -and -not [string]::IsNullOrWhiteSpace($ExecuteNode.GetAttribute('cmdlinesilent'))
      ReturnCodesToReboot              = [int[]]$RebootCodeInfo.Values
      InvalidReturnCodesToReboot       = [string[]]$RebootCodeInfo.InvalidValues
      RebootBehavior                   = $BehaviorNode ? $BehaviorNode.GetAttribute('Reboot') : $null
      Hidden                           = $BehaviorNode ? $BehaviorNode.GetAttribute('Hidden') -eq '1' : $null
      LimitedUserCompatible            = $LimitedUserCompatible
      RequiresAdministrativePrivileges = $RequiresAdministrativePrivileges
      Dependencies                     = [string[]]@($Dependencies)
    }
  }
}

function Get-InstallShieldAdvancedUiInfo {
  <#
  .SYNOPSIS
    Parse an extracted InstallShield Advanced UI or Suite/Advanced UI catalog.
  .DESCRIPTION
    Setup.xml is authoritative for the outer suite ARP identity and for the
    ordered nested-package execution catalog. Nested MSI ProductCodes do not
    replace the SuiteId when the suite itself owns the visible ARP entry.
  .PARAMETER Path
    Path to the extracted Setup.xml file.
  .PARAMETER ExtractedPath
    Optional root used to resolve catalog file names to extracted files.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$ExtractedPath
  )

  process {
    $SetupXmlPath = (Get-Item -LiteralPath $Path -Force).FullName
    [xml]$Xml = Get-Content -LiteralPath $SetupXmlPath -Raw
    $Root = $Xml.DocumentElement
    if ($Root.LocalName -ne 'Setup' -or $Root.NamespaceURI -notmatch '^installshield/\d{4}/bootstrap$') {
      throw 'Setup.xml is not an InstallShield Advanced UI bootstrap catalog'
    }

    $LanguageSelection = $Root.SelectSingleNode("./*[local-name()='LanguageSelection']")
    $DefaultLanguage = if ($LanguageSelection) { $LanguageSelection.GetAttribute('Default') } else { $null }
    $ArpInfo = $Root.SelectSingleNode("./*[local-name()='ARPInfo']")
    $SuiteId = $Root.GetAttribute('SuiteId')
    $ReadArpValue = {
      param([string]$Name)
      $Node = if ($ArpInfo) { $ArpInfo.SelectSingleNode("./*[local-name()='$Name']") } else { $null }
      if (-not $Node) { return $null }
      Resolve-InstallShieldSuiteString -Xml $Xml -Value $Node.InnerText.Trim() -Language $DefaultLanguage
    }

    # SelectionTree is the source-backed relationship between user-visible
    # features and package IDs. A disabled selection control is preserved as
    # authored evidence, but is not interpreted as proof that every parcel runs
    # because the attached condition can still reject the selection.
    $Selections = [Collections.Generic.List[object]]::new()
    foreach ($SelectionNode in @($Root.SelectNodes("./*[local-name()='SelectionTree']/*[local-name()='Selection']"))) {
      $WhenNode = $SelectionNode.SelectSingleNode("./*[local-name()='When']")
      $Selections.Add([pscustomobject][ordered]@{
          Name                 = $SelectionNode.GetAttribute('Name')
          DisplayName          = Resolve-InstallShieldSuiteString -Xml $Xml -Value $SelectionNode.GetAttribute('DisplayName') -Language $DefaultLanguage
          AllowSelectionChange = $SelectionNode.GetAttribute('AllowSelectionChange')
          InstallPackageIds    = [string[]]@($SelectionNode.GetAttribute('Install') -split '\s+' | Where-Object { $_ })
          RemovePackageIds     = [string[]]@($SelectionNode.GetAttribute('Remove') -split '\s+' | Where-Object { $_ })
          Condition            = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
        })
    }

    $Modes = foreach ($ModeNode in @($Root.SelectNodes("./*[local-name()='Mode']/*"))) {
      $WhenNode = $ModeNode.SelectSingleNode("./*[local-name()='When']")
      [pscustomobject][ordered]@{
        Name      = $ModeNode.LocalName
        Condition = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
      }
    }

    $Actions = foreach ($ActionNode in @($Root.SelectNodes("./*[local-name()='Actions']/*"))) {
      $Attributes = [ordered]@{}
      foreach ($Attribute in @($ActionNode.Attributes)) { $Attributes[$Attribute.Name] = $Attribute.Value }
      [pscustomobject][ordered]@{ Type = $ActionNode.LocalName; Id = $ActionNode.GetAttribute('Id'); Attributes = $Attributes }
    }
    $Events = foreach ($EventNode in @($Root.SelectNodes("./*[local-name()='Events']/*"))) {
      foreach ($ActionNode in @($EventNode.SelectNodes("./*[local-name()='Action']"))) {
        $WhenNode = $ActionNode.SelectSingleNode("./*[local-name()='When']")
        [pscustomobject][ordered]@{
          Event     = $EventNode.LocalName
          ActionId  = $ActionNode.GetAttribute('Id')
          Condition = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
        }
      }
    }
    $AbortConditions = foreach ($MessageNode in @($Root.SelectNodes("./*[local-name()='AbortConditions']/*[local-name()='Message']"))) {
      $WhenNode = $MessageNode.SelectSingleNode("./*[local-name()='When']")
      [pscustomobject][ordered]@{
        MessageToken = $MessageNode.GetAttribute('Text')
        Message      = Resolve-InstallShieldSuiteString -Xml $Xml -Value $MessageNode.GetAttribute('Text') -Language $DefaultLanguage
        Condition    = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
      }
    }
    $Transactions = foreach ($TransactionNode in @($Root.SelectNodes("./*[local-name()='Transactions']/* | ./*[local-name()='Parcels']/*[local-name()='Transaction']"))) {
      $Attributes = [ordered]@{}
      foreach ($Attribute in @($TransactionNode.Attributes)) { $Attributes[$Attribute.Name] = $Attribute.Value }
      $WhenNode = $TransactionNode.SelectSingleNode("./*[local-name()='When']")
      [pscustomobject][ordered]@{
        Type       = $TransactionNode.LocalName
        Id         = $TransactionNode.GetAttribute('Id')
        Attributes = $Attributes
        ParcelIds  = [string[]]@($TransactionNode.SelectNodes(".//*[local-name()='ParcelRef']") | ForEach-Object { $_.GetAttribute('Id') } | Where-Object { $_ })
        Condition  = $WhenNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $WhenNode) : $null
      }
    }
    $WindowsFeatures = foreach ($DefinitionNode in @($Root.SelectNodes("./*[local-name()='WindowsFeaturesDefinitions']/*"))) {
      $Mappings = [ordered]@{}
      foreach ($MappingNode in @($DefinitionNode.ChildNodes | Where-Object NodeType -EQ ([Xml.XmlNodeType]::Element))) {
        $Mappings[$MappingNode.LocalName] = [string[]]@($MappingNode.InnerText -split ';' | Where-Object { $_ })
      }
      [pscustomobject][ordered]@{ Name = $DefinitionNode.LocalName; PlatformMappings = $Mappings }
    }

    # Record the exact package target and every operation-specific command line.
    # The physical file can live beneath a GUID folder while Target contains only
    # the basename that the suite launches after staging the parcel.
    $Packages = [Collections.Generic.List[object]]::new()
    foreach ($PackageNode in $Root.SelectNodes("./*[local-name()='Parcels']/*")) {
      # Transactions are ordered catalog entries, but are not installer
      # payloads. They are projected separately so callers do not try to map a
      # transaction boundary to a WinGet NestedInstallerType.
      if ($PackageNode.LocalName -eq 'Transaction') { continue }
      $UiProperties = $PackageNode.SelectSingleNode("./*[local-name()='UIProperties']")
      $PackageIdNode = if ($UiProperties) { $UiProperties.SelectSingleNode("./*[local-name()='Id']") } else { $null }
      $DisplayNameNode = if ($UiProperties) { $UiProperties.SelectSingleNode("./*[local-name()='DisplayName']") } else { $null }
      $PackageId = if ($PackageIdNode) { $PackageIdNode.InnerText.Trim() } else { $null }
      $DisplayNameToken = if ($DisplayNameNode) { $DisplayNameNode.InnerText.Trim() } else { $null }
      $Files = [Collections.Generic.List[object]]::new()
      foreach ($FileNode in $PackageNode.SelectNodes("./*[local-name()='Package']/*[local-name()='Folder']/*[local-name()='File']")) {
        $FolderNode = $FileNode.ParentNode
        $RelativePath = $FileNode.GetAttribute('Name')
        $ResolvedPath = $null
        if ($ExtractedPath -and $RelativePath) {
          $Candidate = Resolve-SafeExtractionPath -DestinationPath $ExtractedPath -RelativePath $RelativePath
          if (Test-Path -LiteralPath $Candidate -PathType Leaf) { $ResolvedPath = $Candidate }
        }
        $Files.Add([pscustomobject][ordered]@{
            RelativePath = $RelativePath
            ResolvedPath = $ResolvedPath
            SourceUrl    = $FolderNode.GetAttribute('Url')
            Stream       = $FolderNode.GetAttribute('Stream')
            Size         = $FileNode.GetAttribute('Size')
            MD5          = $FileNode.GetAttribute('MD5')
          })
      }

      $Operations = [Collections.Generic.List[object]]::new()
      foreach ($OperationNode in $PackageNode.SelectNodes("./*[local-name()='Operation']")) {
        $OperationProperties = [ordered]@{}
        foreach ($PropertyNode in $OperationNode.SelectNodes("./*[local-name()='Property']")) {
          $OperationProperties[$PropertyNode.GetAttribute('Name')] = $PropertyNode.InnerText.Trim()
        }
        $CommandLineNode = $OperationNode.SelectSingleNode("./*[local-name()='CommandLine']")
        $SilentNode = $OperationNode.SelectSingleNode("./*[local-name()='Silent']")
        $RebootCodeInfo = ConvertFrom-InstallShieldIntegerList -Value $OperationProperties['RebootCodes']
        $Operations.Add([pscustomobject][ordered]@{
            Name               = $OperationNode.GetAttribute('Name')
            Target             = $OperationNode.GetAttribute('Target')
            CommandLine        = $CommandLineNode ? $CommandLineNode.InnerText.Trim() : $null
            Silent             = $SilentNode ? $SilentNode.InnerText.Trim() : $null
            ExitBehavior       = $OperationProperties['ExitBehavior']
            RebootRequest      = $OperationProperties['RebootRequest']
            RebootCodes        = [int[]]$RebootCodeInfo.Values
            InvalidRebootCodes = [string[]]$RebootCodeInfo.InvalidValues
            Properties         = $OperationProperties
          })
      }
      $PackageProperties = [ordered]@{}
      foreach ($PropertyNode in $PackageNode.SelectNodes("./*[local-name()='Property']")) {
        $PackageProperties[$PropertyNode.GetAttribute('Name')] = $PropertyNode.InnerText.Trim()
      }
      $DetectionNode = $PackageNode.SelectSingleNode("./*[local-name()='Detect']")
      $EligibilityNode = $PackageNode.SelectSingleNode("./*[local-name()='Eligible']")
      $Platform = $PackageNode.GetAttribute('Platform')
      $Architecture = switch -Regex ($Platform) {
        '^(?i:x64|amd64)$' { 'x64'; break }
        '^(?i:x86|intel)$' { 'x86'; break }
        '^(?i:arm64)$' { 'arm64'; break }
        default { $null }
      }
      $ManifestInstallerType = switch ($PackageNode.LocalName) {
        'Msi' { 'msi' }
        'Exe' { 'exe' }
        'Appx' { 'appx' }
        'AppxBundle' { 'appx' }
        default { $null }
      }
      $PackageFamily = switch ($PackageNode.LocalName) {
        'Msi' { 'Windows Installer Package' }
        'Msp' { 'Windows Installer Patch' }
        'Exe' { 'Executable Package' }
        'IsmMsi' { 'InstallShield Basic MSI Project' }
        'IsmIsp' { 'InstallShield InstallScript Project' }
        'InstallScript' { 'InstallShield InstallScript Package' }
        'Appx' { 'AppX Package' }
        'AppxBundle' { 'AppX Bundle' }
        'WebDeploy' { 'Web Deploy Package' }
        'WinGet' { 'Windows Package Manager Package' }
        { $_ -in @('Prq', 'Prerequisite') } { 'InstallShield Prerequisite'; break }
        default { 'Unknown Suite Package' }
      }
      $Packages.Add([pscustomobject][ordered]@{
          Id                      = $PackageId
          Type                    = $PackageNode.LocalName
          PackageFamily           = $PackageFamily
          DisplayName             = Resolve-InstallShieldSuiteString -Xml $Xml -Value $DisplayNameToken -Language $DefaultLanguage
          ProductCode             = $PackageNode.GetAttribute('ProductCode')
          ProductVersion          = $PackageNode.GetAttribute('ProductVersion')
          PackageCode             = $PackageNode.GetAttribute('PackageCode')
          Platform                = $Platform
          Architecture            = $Architecture
          ManifestInstallerType   = $ManifestInstallerType
          Elevation               = $PackageProperties['Elevation']
          UpgradeType             = $PackageProperties['UpgradeType']
          TransactionMode         = $PackageProperties['TransactionMode']
          Properties              = $PackageProperties
          Files                   = [object[]]$Files
          Operations              = [object[]]$Operations
          DetectionConditionXml   = $DetectionNode ? $DetectionNode.OuterXml : $null
          DetectionCondition      = $DetectionNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $DetectionNode) : $null
          EligibilityConditionXml = $EligibilityNode ? $EligibilityNode.OuterXml : $null
          EligibilityCondition    = $EligibilityNode ? (ConvertFrom-InstallShieldSuiteCondition -Node $EligibilityNode) : $null
          Selections              = [string[]]@($Selections | Where-Object { $PackageId -in $_.InstallPackageIds -or $PackageId -in $_.RemovePackageIds } | ForEach-Object Name)
          HidesNestedArp          = (@($Operations.CommandLine) -match '(?i)(?:^|\s)ARPSYSTEMCOMPONENT\s*=\s*1(?:\s|$)').Count -gt 0
        })
    }

    # Preserve the physical launch order across both packages and transaction
    # boundaries. Package/transaction detail remains in the focused arrays.
    $CatalogOrder = [Collections.Generic.List[object]]::new()
    $CatalogIndex = 0
    foreach ($CatalogNode in @($Root.SelectNodes("./*[local-name()='Parcels']/*"))) {
      $CatalogIdNode = $CatalogNode.SelectSingleNode("./*[local-name()='UIProperties']/*[local-name()='Id']")
      if (-not $CatalogIdNode) { $CatalogIdNode = $CatalogNode.SelectSingleNode("./*[local-name()='Id']") }
      $CatalogOrder.Add([pscustomobject][ordered]@{
          Order = $CatalogIndex++
          Kind  = $CatalogNode.LocalName -eq 'Transaction' ? 'Transaction' : 'Package'
          Type  = $CatalogNode.LocalName
          Id    = $CatalogIdNode ? $CatalogIdNode.InnerText.Trim() : $CatalogNode.GetAttribute('Id')
        })
    }

    # A suite can author its own install directory and use that value when
    # composing nested package command lines.
    $InstallDirectoryNode = $Root.SelectSingleNode("./*[local-name()='SetProperty' and @Name='INSTALLDIR']")
    $InstallDirectoryExpression = if ($InstallDirectoryNode) { $InstallDirectoryNode.GetAttribute('Value') } else { $null }
    $DefaultInstallLocation = if ($InstallDirectoryExpression) {
      $InstallDirectoryExpression.Replace('[ProgramFiles64Folder]', '%ProgramFiles%\').Replace('[ProgramFilesFolder]', '%ProgramFiles(x86)%\')
    } else {
      $null
    }

    # The mode/downgrade checks reveal the exact hive used by the suite ARP key.
    $SuiteRegistryChecks = @($Root.SelectNodes(".//*[local-name()='RegistryValue']") | Where-Object { $_.GetAttribute('Key') -match [regex]::Escape("\Uninstall\$SuiteId") })
    $SuiteRegistryKeys = @($SuiteRegistryChecks | ForEach-Object { $_.GetAttribute('Key') })
    $Scope = if ($SuiteRegistryKeys -match '^HKLM\\') { 'machine' } elseif ($SuiteRegistryKeys -match '^HKCU\\') { 'user' } else { $null }
    $WritesArp = [bool]($ArpInfo -and $SuiteId)
    $Warnings = [Collections.Generic.List[string]]::new()
    if (-not $WritesArp) { $Warnings.Add('The Advanced UI catalog does not contain both SuiteId and ARPInfo; visible outer ARP ownership is unresolved.') }
    if ($Packages.Count -eq 0) { $Warnings.Add('The Advanced UI catalog contains no package parcels.') }

    # CallInstallScript.Arguments begins with the authored InstallScript
    # function name. Preserve only literal identifiers; dynamic expressions
    # remain unresolved rather than being guessed from nearby strings.
    $InstallScriptEntryPoints = [Collections.Generic.List[string]]::new()
    foreach ($Action in @($Actions | Where-Object Type -EQ 'CallInstallScript')) {
      $Arguments = [string]$Action.Attributes['Arguments']
      $Match = [regex]::Match($Arguments, '^\s*([A-Za-z_][A-Za-z0-9_]*)')
      if ($Match.Success) {
        $Function = $Match.Groups[1].Value
        if ($Function -notin $InstallScriptEntryPoints) { $InstallScriptEntryPoints.Add($Function) }
      } else {
        $Warnings.Add("Advanced UI CallInstallScript action '$($Action.Id)' does not contain a literal function name.")
      }
    }

    $ExecutedPayloads = [Collections.Generic.List[object]]::new()
    foreach ($Package in $Packages) {
      foreach ($Operation in $Package.Operations) {
        if (-not [string]::IsNullOrWhiteSpace($Operation.Target)) {
          $ExecutedPayloads.Add([pscustomobject][ordered]@{
              PackageId       = $Package.Id
              Target          = $Operation.Target
              Arguments       = $Operation.CommandLine
              SilentArguments = $Operation.Silent
            })
        }
      }
    }

    [pscustomobject][ordered]@{
      Path                         = $SetupXmlPath
      InstallerType                = 'InstallShield Advanced UI'
      ProductCode                  = $WritesArp ? $SuiteId : $null
      UpgradeCode                  = $null
      DisplayName                  = & $ReadArpValue 'DisplayName'
      DisplayVersion               = & $ReadArpValue 'Version'
      Publisher                    = & $ReadArpValue 'Publisher'
      Scope                        = $Scope
      DefaultInstallLocation       = $DefaultInstallLocation
      UninstallString              = $null
      QuietUninstallString         = $null
      DisplayIcon                  = & $ReadArpValue 'Icon'
      URLInfoAbout                 = & $ReadArpValue 'URLInfoAbout'
      HelpLink                     = & $ReadArpValue 'HelpLink'
      WritesAppsAndFeaturesEntry   = $WritesArp
      AppsAndFeaturesProductCode   = $WritesArp ? $SuiteId : $null
      AppsAndFeaturesInstallerType = $WritesArp ? 'exe' : $null
      Warnings                     = [string[]]$Warnings
      UnresolvedFields             = [string[]]@()
      Variant                      = 'Advanced UI'
      SuiteId                      = $SuiteId
      Namespace                    = $Root.NamespaceURI
      DefaultLanguage              = $DefaultLanguage
      Packages                     = [object[]]$Packages
      Selections                   = [object[]]$Selections
      Modes                        = [object[]]@($Modes)
      Actions                      = [object[]]@($Actions)
      InstallScriptEntryPoints     = [string[]]$InstallScriptEntryPoints.ToArray()
      Events                       = [object[]]@($Events)
      AbortConditions              = [object[]]@($AbortConditions)
      Transactions                 = [object[]]@($Transactions)
      CatalogOrder                 = [object[]]$CatalogOrder
      WindowsFeatures              = [object[]]@($WindowsFeatures)
      PackageArchitectures         = [string[]]@($Packages.Architecture | Where-Object { $_ } | Sort-Object -Unique)
      ExecutedPayloads             = [object[]]$ExecutedPayloads
      InstallDirectoryExpression   = $InstallDirectoryExpression
      ParserVersionInfo            = [pscustomobject]@{ Parser = 'Dumplings.PackageModule.InstallShield.AdvancedUI'; ParserMajor = 3; Sources = @('Setup.xml bootstrap catalog', 'ARPInfo', 'Parcels', 'SelectionTree', 'Mode', 'Actions', 'Events', 'Operation', 'Eligibility conditions', 'Nested package dispatch') }
    }
  }
}

Export-ModuleMember -Function Get-InstallShieldInfo, Get-InstallShieldAdvancedUiInfo, Get-InstallShieldAdvancedUiPackageEligibility, Get-InstallShieldAdvancedUiNestedPackageInfo, Resolve-InstallShieldSuiteCondition, Get-InstallShieldPrerequisiteInfo, Expand-InstallShield, Expand-InstallShieldInstaller, Expand-InstallShieldCabinet, Get-InstallShieldMsiInfo, Read-ProductVersionFromInstallShield, Read-ProductCodeFromInstallShield, Read-UpgradeCodeFromInstallShield
