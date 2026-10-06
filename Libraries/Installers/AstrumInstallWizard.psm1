# SPDX-License-Identifier: Apache-2.0
# Format references:
# - https://www.thraexsoftware.com/
# - https://web.archive.org/web/20130816053259/http://www.thraexsoftware.com/download/aiw.exe
# - https://web.archive.org/cdx/search/cdx?url=www.thraexsoftware.com/aiw/download.html&output=json&filter=statuscode:200&filter=mimetype:text/html&collapse=digest
# - Astrum InstallWizard 2.29.50 builder help and sample project
#
# This parser is an independent implementation based on builder documentation, controlled builder
# output, and static analysis of the shipped runtime. No proprietary builder files are redistributed.
#
# AstrumInstallWizardFormatCatalog.psd1 stores generation-specific footer offsets, record widths,
# configuration routes, container capabilities, and sparse option fields. Runtime code selects one
# immutable descriptor from validated structure instead of branching on authored application versions.
#
# Astrum InstallWizard 1.x and 2.x structures consumed by this parser:
#
#   PE32 setup runtime
#   +-- PE manifest/version resources
#   +-- NUL/whitespace-delimited native command-line option table
#   +-- protected configuration block
#   |   `-- registry tree, shortcuts, operations, requirements, and fixed metadata
#   +-- optional generated-uninstaller gzip member
#   +-- installation-item catalog
#   +-- repeated file records
#   |   +-- 60-byte 1.x or 64-byte 2.x little-endian descriptor
#   |   +-- optional 2.x condition record
#   |   +-- bit-permuted destination name
#   |   +-- volume-offset table
#   |   `-- stored bytes or one gzip member
#   |       `<ResourceDir>\...` destinations are early builder Resource files
#   +-- big-endian footer route table (0xE8 bytes in 1.x, 0xEC bytes in 2.x)
#   +-- footer pointer + optional signature block
#   `-- optional 1.95+/2.x trailer: 3E 2D 1C 0B 78 56 34 12
#
#   Tiny or tiny-verbose wrapper
#   +-- PE32 self-extractor stub
#   +-- one GZip member containing the complete inner Astrum installer
#   `-- 96-byte wrapper descriptor
#       +-- extraction display flag at +0x48
#       `-- total length, overlay offset, and compressed end at +0x54..+0x5C
#
# Trailer-relative layout:
#
#   Offset                         Size  Field
#   -----------------------------  ----  ---------------------------------------------
#   logical end - 8                   8  Optional LE magic 0x0B1C2D3E, 0x12345678
#   end - trailer - 4                 4  Optional signature-block length, LE UInt32
#   end - trailer - 8 - signature     4  Footer absolute file offset, LE UInt32
#   footer + 0x00                      4  Configuration offset, BE UInt32
#   footer + 0x04                      4  Protected configuration size, BE UInt32
#   footer + 0xA4/0xA8                 4  Uninstaller gzip size, BE UInt32 (1.x/2.x)
#   footer + 0xA8/0xAC                 4  Uninstaller gzip offset, BE UInt32 (1.x/2.x)
#   footer + 0xAC/0xB0                 4  Installation-item count, BE UInt32 (1.x/2.x)
#   footer + 0xB0/0xB4                 4  Installation-item table offset, BE UInt32 (1.x/2.x)
#   footer + 0xB4/0xB8                 4  Installation-item table size, BE UInt32 (1.x/2.x)
#   footer + 0xB8/0xBC                 4  File-record count, BE UInt32 (1.x/2.x)
#   footer + 0xBC/0xC0                 4  First file-record offset, BE UInt32 (1.x/2.x)
#   footer + 0xC0/0xC4                 4  Catalog and payload byte count, BE UInt32 (1.x/2.x)
#   footer + 0xC4/0xC8                 4  Aggregate expanded-size evidence (1.x/2.x)
#   footer + 0xC8/0xCC                 4  Aggregate installed-size evidence (1.x/2.x)
#   footer + 0xE4/0xE8                 4  Self pointer, BE UInt32 (1.x/2.x)
#
# Modern option offsets are relative to the byte after the uninstaller command. Fields after the
# variable-length Java version string are relative to the byte following its NUL terminator:
#
#   Offset       Size/order  Field
#   -----------  ----------  ---------------------------------------------
#   +0x48        4 / BE      minimum CPU speed in MHz
#   +0x58        4 / BE      minimum memory in MiB
#   +0x5C        4 / BE      Windows-family bit mask
#   +0x64/+0x68  4+4 / BE    minimum Windows NT major and minor
#   +0x70        2+2 / BE    minimum DirectX major and minor
#   +0x74        4+4+4 / BE  minimum display width, height, and bits per pixel
#   +0x80        4 / BE      minimum .NET Framework selector
#   +0x84        variable    NUL-terminated minimum Java version
#   JavaEnd+0x0C 4 / BE      wave-playback requirement
#   JavaEnd+0x10 4 / BE      MIDI-playback requirement
#   JavaEnd+0x14 4 / BE      joystick requirement
#   JavaEnd+0x18 4 / BE      User Information field flags
#   JavaEnd+0x68 4 / BE      silent-by-default flag
#   JavaEnd+0x6C 4 / BE      no-generated-uninstaller flag
#   JavaEnd+0xA9 4 / BE      x64-compliance flag
#   JavaEnd+0xAD 4 / BE      require-administrator flag
#   end-29       1           direct license approval
#   end-25       1           prohibit silent installation without approval
#
# Authenticode may follow the logical Astrum trailer. In that route the PE security directory points
# to the certificate table and up to eight alignment bytes are skipped before validating the trailer.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$Script:AstrumTrailerMagic = [byte[]](0x3E, 0x2D, 0x1C, 0x0B, 0x78, 0x56, 0x34, 0x12)
$Script:AstrumGZipMagic = [byte[]](0x1F, 0x8B)
$Script:AstrumFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'AstrumInstallWizardFormatCatalog.psd1')
if ([int]$Script:AstrumFormatCatalog.CatalogVersion -ne 1) { throw "Unsupported Astrum format catalog version '$($Script:AstrumFormatCatalog.CatalogVersion)'." }
$Script:AstrumFormatsByFooterLength = @{}
$Script:AstrumFormatsByGeneration = @{}
foreach ($CatalogFormat in $Script:AstrumFormatCatalog.Formats) {
  $Format = [pscustomobject]$CatalogFormat
  if ($Script:AstrumFormatsByFooterLength.ContainsKey([int]$Format.FooterLength)) { throw "The Astrum format catalog contains duplicate footer length '$($Format.FooterLength)'." }
  if ($Script:AstrumFormatsByGeneration.ContainsKey([string]$Format.Generation)) { throw "The Astrum format catalog contains duplicate generation '$($Format.Generation)'." }
  $Script:AstrumFormatsByFooterLength[[int]$Format.FooterLength] = $Format
  $Script:AstrumFormatsByGeneration[[string]$Format.Generation] = $Format
}
$Script:AstrumConfigurationProfiles = @{}
foreach ($Entry in $Script:AstrumFormatCatalog.ConfigurationProfiles.GetEnumerator()) { $Script:AstrumConfigurationProfiles[[string]$Entry.Key] = [pscustomobject]$Entry.Value }
$Script:AstrumOperationSemantics = [pscustomobject]$Script:AstrumFormatCatalog.OperationSemantics
$Script:AstrumVariableSemantics = [pscustomobject]$Script:AstrumFormatCatalog.VariableSemantics
foreach ($Format in $Script:AstrumFormatsByFooterLength.Values) {
  if ($Format.InteractiveOperationRoute -notin 'LegacyWithoutTail', 'CurrentWithCondition') { throw "Astrum format '$($Format.Id)' declares an unsupported interactive-operation route." }
  if ([int]$Format.InteractiveActionCount -lt 1 -or [int]$Format.InteractiveActionCount -gt @($Script:AstrumOperationSemantics.InteractiveActions).Count) { throw "Astrum format '$($Format.Id)' declares an invalid interactive-action count." }
  foreach ($ProfileId in @($Format.DefaultConfigurationProfile, $Format.RuntimeWordProfile) | Where-Object { $_ }) {
    if (-not $Script:AstrumConfigurationProfiles.ContainsKey([string]$ProfileId)) { throw "Astrum format '$($Format.Id)' references missing configuration profile '$ProfileId'." }
  }
}
$Script:AstrumMaximumFooterBytes = 1000
$Script:AstrumMaximumSignatureBytes = 1000
$Script:AstrumMaximumConfigurationBytes = 4194304
$Script:AstrumMaximumConfigurationRecords = 65536
$Script:AstrumMaximumConfigurationDepth = 64
$Script:AstrumMaximumFiles = 65536
$Script:AstrumMaximumGroups = 4096
$Script:AstrumMaximumStringBytes = 1048576
$Script:AstrumMaximumAnalysisBytes = 536870912L
$Script:AstrumMaximumTinyExpandedBytes = [long][uint32]::MaxValue
$Script:AstrumTinyFooterSize = 96
$Script:AstrumAnsi = [Text.Encoding]::GetEncoding(1252)
$Script:AstrumLicenseDialogMarker = [Text.Encoding]::ASCII.GetBytes('<LangID=1>License agreement</LangID=1>')
$Script:AstrumUserInformationDialogMarker = [Text.Encoding]::ASCII.GetBytes('<LangID=1>User information</LangID=1>')

function Read-AstrumUInt32FromBytes {
  <#
  .SYNOPSIS
    Read one bounded UInt32 from an in-memory Astrum structure.
  .PARAMETER Bytes
    Source bytes.
  .PARAMETER Offset
    Zero-based byte-array offset.
  .PARAMETER Endian
    Integer byte order.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset,
    [ValidateSet('LittleEndian', 'BigEndian')][string]$Endian = 'LittleEndian'
  )

  if ($Offset -gt $Bytes.Length - 4) { throw "The Astrum UInt32 at offset $Offset is truncated." }
  if ($Endian -eq 'LittleEndian') { return [BitConverter]::ToUInt32($Bytes, $Offset) }
  return ([uint32]$Bytes[$Offset] -shl 24) -bor ([uint32]$Bytes[$Offset + 1] -shl 16) -bor ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3]
}

function Test-AstrumRange {
  <#
  .SYNOPSIS
    Test whether an absolute file range is contained by a declared boundary.
  .PARAMETER Offset
    Absolute range start.
  .PARAMETER Length
    Range length in bytes.
  .PARAMETER Limit
    Exclusive upper boundary.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][long]$Length,
    [Parameter(Mandatory)][long]$Limit
  )
  return $Offset -ge 0 -and $Length -ge 0 -and $Offset -le $Limit -and $Length -le $Limit - $Offset
}

function Get-AstrumFormatDescriptor {
  <#
  .SYNOPSIS
    Resolve one immutable Astrum wire-layout descriptor by validated footer length.
  .PARAMETER FooterLength
    Byte distance from the footer pointer target to the trailer pointer slot.
  .OUTPUTS
    The matching entry from AstrumInstallWizardFormatCatalog.psd1.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$FooterLength)

  $Format = $Script:AstrumFormatsByFooterLength[$FooterLength]
  if (-not $Format) { throw "The Astrum footer has an unsupported $FooterLength-byte length." }
  return $Format
}

function Get-AstrumConfigurationProfile {
  <#
  .SYNOPSIS
    Select the configuration layout named by an Astrum format descriptor.
  .PARAMETER Format
    Generation descriptor selected from the validated footer length.
  .PARAMETER Bytes
    Complete twice-decoded configuration bytes.
  .PARAMETER Offset
    Start of the generation-dependent fixed metadata region.
  .OUTPUTS
    A configuration profile from AstrumInstallWizardFormatCatalog.psd1.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$Format,
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset
  )

  $ProfileId = switch ([string]$Format.ConfigurationProfileRoute) {
    'Fixed' { [string]$Format.DefaultConfigurationProfile }
    'LeadingRuntimeWord' {
      $Candidate = Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset $Offset -Endian BigEndian
      $Candidate -le [uint32]$Format.RuntimeWordMaximum ? [string]$Format.RuntimeWordProfile : [string]$Format.DefaultConfigurationProfile
    }
    default { throw "Astrum format '$($Format.Id)' uses an unsupported configuration-profile route '$($Format.ConfigurationProfileRoute)'." }
  }
  $ConfigurationDescriptor = $Script:AstrumConfigurationProfiles[$ProfileId]
  if (-not $ConfigurationDescriptor -or $ConfigurationDescriptor.Generation -cne $Format.Generation) { throw "Astrum format '$($Format.Id)' does not resolve a compatible configuration profile." }
  return $ConfigurationDescriptor
}

function Get-AstrumLogicalBoundary {
  <#
  .SYNOPSIS
    Locate the end of the logical installer image before an optional certificate table.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Layout
    Parsed PE layout for the same stream.
  .OUTPUTS
    The exclusive logical end and whether an Authenticode certificate follows it.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Layout
  )

  # The PE security-directory address is a file offset, unlike ordinary RVA-based directories.
  $Security = $Layout.DataDirectories['Certificate']
  if (-not $Security -or [long]$Security.Rva -le 0 -or [long]$Security.Size -le 0) {
    return [pscustomobject]@{ LogicalEnd = [long]$Stream.Length; HasCertificate = $false; CertificateOffset = $null }
  }
  $CertificateOffset = [long]$Security.Rva
  if (-not (Test-AstrumRange -Offset $CertificateOffset -Length ([long]$Security.Size) -Limit $Stream.Length)) { throw 'The PE certificate table is outside the installer.' }
  $LogicalEnd = $CertificateOffset
  # WIN_CERTIFICATE starts on an eight-byte boundary, so alignment padding belongs to neither the
  # Astrum image nor the certificate. Strip only the maximum possible alignment run.
  for ($Index = 0; $Index -lt 8 -and $LogicalEnd -gt 0; $Index++) {
    if ((Read-BinaryBytes -Stream $Stream -Offset ($LogicalEnd - 1) -Count 1)[0] -ne 0) { break }
    $LogicalEnd--
  }
  if ($LogicalEnd -lt 8) { throw 'The logical installer image before the certificate table is truncated.' }
  return [pscustomobject]@{ LogicalEnd = $LogicalEnd; HasCertificate = $true; CertificateOffset = $CertificateOffset }
}

function Test-AstrumRuntimeIdentity {
  <#
  .SYNOPSIS
    Verify source-backed Astrum and Thraex identity inside the PE image, excluding appended payloads.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER OverlayOffset
    Exclusive end of PE section data.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$OverlayOffset
  )

  if ($OverlayOffset -le 0 -or $OverlayOffset -gt [int]::MaxValue) { return $false }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset 0 -Count ([int]$OverlayOffset)
  $AnsiText = $Script:AstrumAnsi.GetString($Bytes)
  $UnicodeText = [Text.Encoding]::Unicode.GetString($Bytes)
  $HasAstrum = $AnsiText.Contains('Astrum InstallWizard', [StringComparison]::OrdinalIgnoreCase) -or $UnicodeText.Contains('Astrum InstallWizard', [StringComparison]::OrdinalIgnoreCase)
  $HasThraex = $AnsiText.Contains('Thraex Software', [StringComparison]::OrdinalIgnoreCase) -or $UnicodeText.Contains('Thraex Software', [StringComparison]::OrdinalIgnoreCase)
  return $HasAstrum -and $HasThraex
}

function Read-AstrumTrailer {
  <#
  .SYNOPSIS
    Resolve the generation-specific Astrum trailer, signature block, and footer pointer.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Layout
    Parsed PE layout for the same stream.
  .PARAMETER OverlayOffset
    End of PE section data, used to validate legacy runtime identity and footer placement.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][long]$OverlayOffset
  )

  $Boundary = Get-AstrumLogicalBoundary -Stream $Stream -Layout $Layout
  $LogicalEnd = [long]$Boundary.LogicalEnd
  $HasMagic = $false
  if ($LogicalEnd -ge 8) {
    $HasMagic = Test-BinarySequence -Left (Read-BinaryBytes -Stream $Stream -Offset ($LogicalEnd - 8) -Count 8) -Right $Script:AstrumTrailerMagic
  }
  $TrailerSize = $HasMagic ? 8 : 0
  $SignatureLengthOffset = $LogicalEnd - $TrailerSize - 4
  if ($SignatureLengthOffset -lt 4) { throw 'The Astrum trailer is truncated.' }
  $SignatureLength = [uint32](Read-BinaryInteger -Stream $Stream -Offset $SignatureLengthOffset -Size 4)
  if ($SignatureLength -eq [uint32]::MaxValue) { $SignatureLength = 0 }
  if ($SignatureLength -gt $Script:AstrumMaximumSignatureBytes) { throw "The Astrum optional signature block exceeds the $Script:AstrumMaximumSignatureBytes-byte limit." }
  $PointerOffset = $SignatureLengthOffset - 4 - [long]$SignatureLength
  if ($PointerOffset -lt 4) { throw 'The Astrum footer pointer is outside the logical image.' }
  $FooterOffset = [long](Read-BinaryInteger -Stream $Stream -Offset $PointerOffset -Size 4)
  $FooterLength = $PointerOffset - $FooterOffset
  $Format = Get-AstrumFormatDescriptor -FooterLength $FooterLength
  $TrailerRoute = $HasMagic ? 'DualMagic' : 'LegacyNoMagic'
  if (@($Format.TrailerRoutes) -cnotcontains $TrailerRoute) { throw "Astrum format '$($Format.Id)' does not support the '$TrailerRoute' trailer route." }
  if (-not $HasMagic -and $Format.RequireRuntimeIdentityWithoutMagic -and -not (Test-AstrumRuntimeIdentity -Stream $Stream -OverlayOffset $OverlayOffset)) { throw 'The legacy Astrum trailer lacks trusted runtime identity.' }
  if ($FooterOffset -lt $OverlayOffset -or -not (Test-AstrumRange -Offset $FooterOffset -Length $FooterLength -Limit $LogicalEnd)) { throw 'The Astrum footer range is outside the PE overlay.' }

  [pscustomobject][ordered]@{
    LogicalEnd            = $LogicalEnd
    HasCertificate        = [bool]$Boundary.HasCertificate
    HasMagic              = $HasMagic
    TrailerSize           = $TrailerSize
    SignatureLength       = [int]$SignatureLength
    SignatureLengthOffset = $SignatureLengthOffset
    PointerOffset         = $PointerOffset
    FooterOffset          = $FooterOffset
    FooterLength          = $FooterLength
    TrailerRoute          = $TrailerRoute
    FormatId              = [string]$Format.Id
    FormatGeneration      = [string]$Format.Generation
    Profile               = $Format
  }
}

function Read-AstrumFooter {
  <#
  .SYNOPSIS
    Parse and validate the Astrum footer route table.
  .PARAMETER Stream
    Caller-owned seekable installer stream.
  .PARAMETER Trailer
    Validated generation-specific trailer returned by Read-AstrumTrailer.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)]$Trailer
  )

  $FooterOffset = [long]$Trailer.FooterOffset
  $FooterLength = [long]$Trailer.FooterLength
  if ($FooterLength -gt $Script:AstrumMaximumFooterBytes) { throw "The Astrum footer exceeds the $Script:AstrumMaximumFooterBytes-byte limit." }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $FooterOffset -Count ([int]$FooterLength)
  $Read = { param([int]$Offset) Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset $Offset -Endian BigEndian }
  $FooterOffsets = $Trailer.Profile.FooterOffsets
  $ReadField = { param([string]$Name) & $Read ([int]$FooterOffsets[$Name]) }
  if ((& $ReadField 'SelfPointer') -ne $FooterOffset) { throw 'The Astrum footer self pointer does not match its physical offset.' }

  $ConfigurationOffset = [long](& $ReadField 'ConfigurationOffset')
  $ConfigurationSize = [long](& $ReadField 'ConfigurationSize')
  $GroupCount = [long](& $ReadField 'InstallationItemCount')
  $GroupOffset = [long](& $ReadField 'InstallationItemOffset')
  $GroupSize = [long](& $ReadField 'InstallationItemSize')
  $FileCount = [long](& $ReadField 'FileCount')
  $FileOffset = [long](& $ReadField 'FileOffset')
  $PayloadSize = [long](& $ReadField 'PayloadSize')
  foreach ($Range in @(
      @($ConfigurationOffset, $ConfigurationSize, 'configuration'),
      @($GroupOffset, $GroupSize, 'installation-item table'),
      @($FileOffset, $PayloadSize, 'file catalog')
    )) {
    if ($Range[1] -gt 0 -and (-not (Test-AstrumRange -Offset $Range[0] -Length $Range[1] -Limit $FooterOffset))) { throw "The Astrum $($Range[2]) is outside the logical payload." }
  }
  if ($ConfigurationSize -le 0 -or $ConfigurationSize -gt $Script:AstrumMaximumConfigurationBytes) { throw 'The Astrum protected configuration has an invalid size.' }
  if ($GroupCount -gt $Script:AstrumMaximumGroups -or $FileCount -gt $Script:AstrumMaximumFiles) { throw 'The Astrum catalog exceeds its record-count limit.' }
  if ($FileOffset + $PayloadSize -ne $FooterOffset) { throw 'The Astrum catalog and payload range does not terminate at the footer.' }

  [pscustomobject][ordered]@{
    Offset                    = $FooterOffset
    Length                    = $FooterLength
    PointerOffset             = [long]$Trailer.PointerOffset
    SignatureLength           = [int]$Trailer.SignatureLength
    FormatId                  = [string]$Trailer.Profile.Id
    FormatGeneration          = $Trailer.FormatGeneration
    FormatProfile             = $Trailer.Profile
    ConfigurationOffset       = $ConfigurationOffset
    ConfigurationSize         = $ConfigurationSize
    InstallationItemCount     = [int]$GroupCount
    InstallationItemOffset    = $GroupOffset
    InstallationItemSize      = $GroupSize
    FileCount                 = [int]$FileCount
    FileOffset                = $FileOffset
    PayloadSize               = $PayloadSize
    UninstallerCompressedSize = [long](& $ReadField 'UninstallerCompressedSize')
    UninstallerOffset         = [long](& $ReadField 'UninstallerOffset')
    ExpandedSize              = [long](& $ReadField 'ExpandedSize')
    InstalledSize             = [long](& $ReadField 'InstalledSize')
    RawBytes                  = $Bytes
  }
}

function ConvertFrom-AstrumProtectedBlock {
  <#
  .SYNOPSIS
    Validate and decode one Astrum checksum-protected byte block.
  .PARAMETER Bytes
    Encoded block ending in two cipher bytes and eight checksum bytes.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -lt 10) { throw 'The Astrum protected block is truncated.' }
  $Checksum = [byte[]]::new(8)
  for ($Index = 0; $Index -lt $Bytes.Length - 8; $Index++) {
    $Slot = $Index % 8
    $Checksum[$Slot] = [byte](($Checksum[$Slot] + $Bytes[$Index]) -band 0xFF)
  }
  for ($Index = 0; $Index -lt 8; $Index++) {
    if ($Checksum[$Index] -ne $Bytes[$Bytes.Length - 8 + $Index]) { throw 'The Astrum protected block checksum is invalid.' }
  }
  $Step = $Bytes[$Bytes.Length - 10]
  $Accumulator = $Bytes[$Bytes.Length - 9]
  $Decoded = [byte[]]::new($Bytes.Length - 10)
  for ($Index = 0; $Index -lt $Decoded.Length; $Index++) {
    $Accumulator = [byte](($Accumulator + $Step) -band 0xFF)
    $Decoded[$Index] = [byte](($Bytes[$Index] - $Accumulator) -band 0xFF)
  }
  return , $Decoded
}

function New-AstrumConfigurationReader {
  <#
  .SYNOPSIS
    Create a bounded cursor over decoded Astrum configuration bytes.
  .PARAMETER Bytes
    Twice-decoded configuration bytes.
  .PARAMETER Format
    Catalog descriptor controlling generation-specific record framing.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][pscustomobject]$Format
  )
  return [pscustomobject]@{ Bytes = $Bytes; Position = 0; Records = 0; Format = $Format }
}

function Read-AstrumConfigurationUInt32 {
  <#
  .SYNOPSIS
    Consume one big-endian UInt32 from an Astrum configuration cursor.
  .PARAMETER Reader
    Mutable reader returned by New-AstrumConfigurationReader.
  #>
  [OutputType([uint32])]
  param ([Parameter(Mandatory)]$Reader)
  $Value = Read-AstrumUInt32FromBytes -Bytes $Reader.Bytes -Offset $Reader.Position -Endian BigEndian
  $Reader.Position += 4
  return $Value
}

function Read-AstrumConfigurationCount {
  <#
  .SYNOPSIS
    Consume and validate one configuration table count.
  .PARAMETER Reader
    Mutable decoded-configuration cursor.
  .PARAMETER TableName
    Human-readable table name used in malformed-input errors.
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory)]$Reader,
    [Parameter(Mandatory)][string]$TableName
  )

  $Count = Read-AstrumConfigurationUInt32 -Reader $Reader
  if ($Count -gt $Script:AstrumMaximumConfigurationRecords) { throw "The Astrum $TableName table exceeds its record-count limit." }
  return $Count
}

function Read-AstrumConfigurationString {
  <#
  .SYNOPSIS
    Consume one bounded null-terminated Windows-1252 string.
  .PARAMETER Reader
    Mutable decoded-configuration cursor.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)]$Reader)
  $Start = $Reader.Position
  $Limit = [Math]::Min($Reader.Bytes.Length, $Start + $Script:AstrumMaximumStringBytes + 1)
  while ($Reader.Position -lt $Limit -and $Reader.Bytes[$Reader.Position] -ne 0) { $Reader.Position++ }
  if ($Reader.Position -ge $Limit) { throw "The Astrum string at decoded offset $Start is unterminated or oversized." }
  $Value = $Script:AstrumAnsi.GetString($Reader.Bytes, $Start, $Reader.Position - $Start)
  $Reader.Position++
  return $Value
}

function Get-AstrumOperationSemanticName {
  <#
  .SYNOPSIS
    Resolve a compiled Astrum enum value through the source-backed builder ordering.
  .PARAMETER Code
    Zero-based UInt32 value serialized by the Astrum compiler.
  .PARAMETER Names
    Ordered names recovered from the corresponding builder control and help topic.
  .PARAMETER MaximumCount
    Optional generation-specific number of supported values. Astrum 1.x, for example, exposes only the first eight interactive actions.
  .OUTPUTS
    The exact builder label, or null when the value is unsupported by the selected generation.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][uint32]$Code,
    [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names,
    [ValidateRange(0, [int]::MaxValue)][int]$MaximumCount = $Names.Count
  )

  if ($Code -ge [uint32]$MaximumCount -or $Code -ge [uint32]$Names.Count) { return $null }
  return $Names[[int]$Code]
}

function Get-AstrumVariableSourceName {
  <#
  .SYNOPSIS
    Resolve the serialized variable-source enum through the builder's source list.
  .PARAMETER Code
    Unsigned source value stored in a compiled variable record. Astrum serializes Nowhere as UInt32.MaxValue.
  .OUTPUTS
    Registry, INI, Find file location, Nowhere, or null for an unknown value.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][uint32]$Code)

  $Key = [string]$Code
  return $Script:AstrumVariableSemantics.Sources.ContainsKey($Key) ? [string]$Script:AstrumVariableSemantics.Sources[$Key] : $null
}

function Read-AstrumConfigurationCondition {
  <#
  .SYNOPSIS
    Consume one source-backed Astrum condition expression.
  .PARAMETER Reader
    Mutable decoded-configuration cursor.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$Reader)
  # The selected wire-layout profile states whether this generation serialized condition records.
  if (-not $Reader.Format.HasRecordConditions) { return $null }
  $Kind = Read-AstrumConfigurationUInt32 -Reader $Reader
  if ($Kind -eq 0) { return $null }
  $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'condition-term'
  $Terms = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Left = Read-AstrumConfigurationString -Reader $Reader
    $Operator = Read-AstrumConfigurationUInt32 -Reader $Reader
    $Right = Read-AstrumConfigurationString -Reader $Reader
    $Terms.Add([pscustomobject][ordered]@{
        Left         = $Left
        Operator     = $Operator
        OperatorName = Get-AstrumOperationSemanticName -Code $Operator -Names @($Script:AstrumOperationSemantics.ConditionOperators)
        Right        = $Right
      })
  }
  # The serialized leading value is the builder's osmask attribute. Preserve Kind for existing callers.
  return [pscustomobject][ordered]@{ Kind = $Kind; OperatingSystemMask = $Kind; Terms = @($Terms) }
}

function Read-AstrumOperationTail {
  <#
  .SYNOPSIS
    Consume the generation-specific trailing field of a system-change record.
  .PARAMETER Reader
    Mutable decoded-configuration cursor.
  .OUTPUTS
    An envelope containing a parsed 2.x condition or the preserved 1.x UInt32 tail.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$Reader)

  switch ([string]$Reader.Format.OperationTailRoute) {
    'ObservedUInt32' { return [pscustomobject]@{ Condition = $null; ObservedValue = Read-AstrumConfigurationUInt32 -Reader $Reader } }
    'Condition' { return [pscustomobject]@{ Condition = Read-AstrumConfigurationCondition -Reader $Reader; ObservedValue = $null } }
    default { throw "Astrum format '$($Reader.Format.Id)' uses an unsupported operation-tail route '$($Reader.Format.OperationTailRoute)'." }
  }
}

function Read-AstrumConfigurationOptionUInt32 {
  <#
  .SYNOPSIS
    Read a sparse fixed-option UInt32 when that offset exists in the decoded configuration.
  .PARAMETER Bytes
    Complete twice-decoded configuration bytes.
  .PARAMETER BaseOffset
    Absolute decoded-configuration offset where the fixed option block begins.
  .PARAMETER RelativeOffset
    Option-block-relative byte offset established by controlled 2.29.50 builds.
  .PARAMETER Endian
    Byte order of this particular fixed option.
  #>
  [OutputType([Nullable[uint32]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$BaseOffset,
    [Parameter(Mandatory)][int]$RelativeOffset,
    [ValidateSet('LittleEndian', 'BigEndian')][string]$Endian = 'BigEndian'
  )

  $Offset = $BaseOffset + $RelativeOffset
  if ($BaseOffset -lt 0 -or $RelativeOffset -lt 0 -or $Offset -gt $Bytes.Length - 4) { return $null }
  return Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset $Offset -Endian $Endian
}

function Read-AstrumConfigurationOptionUInt16 {
  <#
  .SYNOPSIS
    Read a sparse big-endian UInt16 when that offset exists in the decoded configuration.
  .PARAMETER Bytes
    Complete twice-decoded configuration bytes.
  .PARAMETER BaseOffset
    Absolute decoded-configuration offset where the fixed option block begins.
  .PARAMETER RelativeOffset
    Option-block-relative byte offset established by controlled 2.29.50 builds.
  #>
  [OutputType([Nullable[uint16]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$BaseOffset,
    [Parameter(Mandatory)][int]$RelativeOffset
  )

  $Offset = $BaseOffset + $RelativeOffset
  if ($BaseOffset -lt 0 -or $RelativeOffset -lt 0 -or $Offset -gt $Bytes.Length - 2) { return $null }
  return ([uint16]$Bytes[$Offset] -shl 8) -bor [uint16]$Bytes[$Offset + 1]
}

function ConvertTo-AstrumConfigurationBoolean {
  <#
  .SYNOPSIS
    Convert an optional compiled integer flag without turning absent evidence into false.
  .PARAMETER Value
    Nullable integer read from a sparse fixed-option offset.
  #>
  [OutputType([Nullable[bool]])]
  param ([AllowNull()][object]$Value)

  if ($null -eq $Value) { return $null }
  return [uint32]$Value -eq 1
}

function Read-AstrumConfigurationProfileOptions {
  <#
  .SYNOPSIS
    Decode sparse option fields declared by one configuration profile.
  .PARAMETER Bytes
    Complete twice-decoded configuration bytes.
  .PARAMETER BaseOffset
    Start of the profile-specific option block.
  .PARAMETER ConfigurationProfile
    Configuration profile selected from AstrumInstallWizardFormatCatalog.psd1.
  .OUTPUTS
    Stable Requirements and Configuration objects plus a byte-range map distinguishing assigned profile fields from opaque option bytes.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$BaseOffset,
    [Parameter(Mandatory)][pscustomobject]$ConfigurationProfile
  )

  $Requirements = [ordered]@{}
  foreach ($Name in 'MinimumCpuSpeedMHz', 'CpuManufacturerCode', 'CpuVendorMask', 'CpuFeatureFlags', 'MinimumMemoryMiB', 'WindowsPlatformMask', 'MinimumWindows9xVersion', 'MinimumWindows9xBuild', 'MinimumWindowsNtMajor', 'MinimumWindowsNtMinor', 'MinimumWindowsNtVersion', 'MinimumNtServicePack', 'MinimumDirectXMajor', 'MinimumDirectXMinor', 'MinimumResolutionWidth', 'MinimumResolutionHeight', 'MinimumResolutionBitsPerPixel', 'MinimumDotNetFrameworkCode', 'MinimumDotNetFramework', 'MinimumJavaVersion', 'RequiresWavePlayback', 'RequiresMidiPlayback', 'RequiresJoystick') { $Requirements[$Name] = $null }
  $Configuration = [ordered]@{
    UserInformationFlags       = $null
    SilentInstallationDefault  = $null
    NoUninstallation           = $null
    X64ComplianceMode          = $null
    RequireAdmin               = $null
    DirectLicenseApproval      = $false
    ProhibitSilentInstallation = $false
  }
  if ($ConfigurationProfile.OptionRoute -notin 'Opaque', 'SparseModern2') { throw "Astrum configuration profile '$($ConfigurationProfile.Id)' uses an unsupported option route '$($ConfigurationProfile.OptionRoute)'." }

  # Track only bytes whose meaning is established by controlled builder output. This preserves the
  # unknown portions as bounded evidence without misreporting the complete option block as unread.
  $OptionBlockSize = $Bytes.Length - $BaseOffset
  $AssignedBytes = [bool[]]::new($OptionBlockSize)
  $AssignedFields = [Collections.Generic.List[object]]::new()
  $AfterJavaVersionOffset = $null

  foreach ($Field in @($ConfigurationProfile.OptionFields)) {
    $FixedFieldSize = switch ([string]$Field.Type) {
      'UInt32' { 4 }
      'BooleanUInt32' { 4 }
      'UInt16' { 2; break }
      'BooleanByte' { 1; break }
      'NullTerminatedString' { 0; break }
      default { throw "Astrum option '$($Field.Name)' uses an unsupported type '$($Field.Type)'." }
    }
    $RelativeOffset = switch ([string]$Field.Origin) {
      'Option' { [int]$Field.Offset }
      'AfterJavaVersion' {
        if ($null -eq $AfterJavaVersionOffset) { throw "Astrum option '$($Field.Name)' depends on a Java-version boundary that has not been decoded." }
        [int]$AfterJavaVersionOffset + [int]$Field.Offset
      }
      'End' { $Bytes.Length - [int]$Field.Distance - $BaseOffset }
      default { throw "Astrum option '$($Field.Name)' uses an unsupported origin '$($Field.Origin)'." }
    }
    $FieldSize = $FixedFieldSize
    if ($Field.Type -ceq 'NullTerminatedString') {
      $StringOffset = $BaseOffset + $RelativeOffset
      if ($RelativeOffset -lt 0 -or $StringOffset -ge $Bytes.Length) { throw "Astrum option '$($Field.Name)' is outside the decoded option block." }
      $StringLimit = [Math]::Min($Bytes.Length, $StringOffset + $Script:AstrumMaximumStringBytes + 1)
      $StringEnd = $StringOffset
      while ($StringEnd -lt $StringLimit -and $Bytes[$StringEnd] -ne 0) { $StringEnd++ }
      if ($StringEnd -ge $StringLimit) { throw "Astrum option '$($Field.Name)' is unterminated or oversized." }
      $FieldSize = $StringEnd - $StringOffset + 1
      $Value = $Script:AstrumAnsi.GetString($Bytes, $StringOffset, $FieldSize - 1)
      if ($Field.Name -ceq 'MinimumJavaVersion') { $AfterJavaVersionOffset = $RelativeOffset + $FieldSize }
    } elseif ($RelativeOffset -lt 0 -or $FixedFieldSize -gt $OptionBlockSize - $RelativeOffset) {
      $Value = $null
    } else {
      $Value = switch ([string]$Field.Type) {
        'UInt32' { Read-AstrumConfigurationOptionUInt32 -Bytes $Bytes -BaseOffset $BaseOffset -RelativeOffset $RelativeOffset -Endian ([string]$Field.Endian) }
        'UInt16' {
          if ($Field.Endian -cne 'BigEndian') { throw "Astrum option '$($Field.Name)' declares an unsupported UInt16 byte order." }
          Read-AstrumConfigurationOptionUInt16 -Bytes $Bytes -BaseOffset $BaseOffset -RelativeOffset $RelativeOffset
        }
        'BooleanUInt32' { ConvertTo-AstrumConfigurationBoolean (Read-AstrumConfigurationOptionUInt32 -Bytes $Bytes -BaseOffset $BaseOffset -RelativeOffset $RelativeOffset -Endian ([string]$Field.Endian)) }
        'BooleanByte' { $Bytes[$BaseOffset + $RelativeOffset] -eq 1 }
        default { throw "Astrum option '$($Field.Name)' uses an unsupported type '$($Field.Type)'." }
      }
    }
    if ($RelativeOffset -ge 0 -and $FieldSize -le $OptionBlockSize - $RelativeOffset) {
      for ($ByteIndex = $RelativeOffset; $ByteIndex -lt $RelativeOffset + $FieldSize; $ByteIndex++) { $AssignedBytes[$ByteIndex] = $true }
      $AssignedFields.Add([pscustomobject][ordered]@{ Name = [string]$Field.Name; Offset = $RelativeOffset; Size = $FieldSize })
    }
    switch ([string]$Field.Group) {
      'Requirements' {
        if (-not $Requirements.Contains([string]$Field.Name)) { throw "Astrum option '$($Field.Name)' is not a supported requirement field." }
        $Requirements[[string]$Field.Name] = $Value
      }
      'Configuration' {
        if (-not $Configuration.Contains([string]$Field.Name)) { throw "Astrum option '$($Field.Name)' is not a supported configuration field." }
        $Configuration[[string]$Field.Name] = $Value
      }
      default { throw "Astrum option '$($Field.Name)' uses an unsupported output group '$($Field.Group)'." }
    }
  }

  # The builder stores Windows selectors as a bit mask plus NT major/minor values, .NET as a
  # dropdown index, and Java as the selected version string. Keep the raw fields alongside the
  # source-backed labels so future profiles can be compared without lossy normalization.
  $Requirements.MinimumWindows9xVersion = switch ([uint32]$Requirements.WindowsPlatformMask -band 0x0B) {
    0x08 { 'Windows ME' }
    0x02 { 'Windows 98' }
    0x01 { 'Windows 95' }
    default { $null }
  }
  if (([uint32]$Requirements.WindowsPlatformMask -band 0x04) -ne 0) {
    $NtVersion = '{0}.{1}' -f [uint32]$Requirements.MinimumWindowsNtMajor, [uint32]$Requirements.MinimumWindowsNtMinor
    $Requirements.MinimumWindowsNtVersion = switch ($NtVersion) {
      '4.0' { 'Windows NT 4.0' }
      '5.0' { 'Windows 2000' }
      '5.1' { 'Windows XP' }
      '5.2' { 'Windows Server 2003' }
      '6.0' { 'Windows Vista / Server 2008' }
      '6.1' { 'Windows 7 / Server 2008 R2' }
      default { $null }
    }
  }
  $Requirements.MinimumDotNetFramework = switch ([uint32]$Requirements.MinimumDotNetFrameworkCode) {
    1 { '1.0' }
    2 { '1.1' }
    3 { '2.0' }
    4 { '3.0' }
    5 { '3.5' }
    6 { '3.5 SP1' }
    7 { '4.0 Client' }
    8 { '4.0 Full' }
    default { $null }
  }
  if ([string]::IsNullOrWhiteSpace([string]$Requirements.MinimumJavaVersion)) { $Requirements.MinimumJavaVersion = $null }

  # Collapse adjacent opaque bytes into ranges so callers can compare layouts without retaining a
  # second copy of the decoded configuration or materializing one evidence object per byte.
  $UnassignedRanges = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index -lt $OptionBlockSize; ) {
    if ($AssignedBytes[$Index]) { $Index++; continue }
    $Start = $Index
    $NonZeroByteCount = 0
    while ($Index -lt $OptionBlockSize -and -not $AssignedBytes[$Index]) {
      if ($Bytes[$BaseOffset + $Index] -ne 0) { $NonZeroByteCount++ }
      $Index++
    }
    $UnassignedRanges.Add([pscustomobject][ordered]@{ Offset = $Start; Length = $Index - $Start; NonZeroByteCount = $NonZeroByteCount })
  }
  $AssignedByteCount = 0
  foreach ($AssignedByte in $AssignedBytes) { if ($AssignedByte) { $AssignedByteCount++ } }
  $OptionBlockEvidence = [pscustomobject][ordered]@{
    Offset            = $BaseOffset
    Size              = $OptionBlockSize
    AssignedByteCount = $AssignedByteCount
    AssignedFields    = @($AssignedFields)
    UnassignedRanges  = @($UnassignedRanges)
  }

  return [pscustomobject]@{ Requirements = [pscustomobject]$Requirements; Configuration = [pscustomobject]$Configuration; OptionBlockEvidence = $OptionBlockEvidence }
}

function Read-AstrumRegistryTree {
  <#
  .SYNOPSIS
    Consume one recursive Astrum registry-key record.
  .PARAMETER Reader
    Mutable decoded-configuration cursor.
  .PARAMETER Root
    Registry root name for returned writes.
  .PARAMETER Key
    Current path below Root.
  .PARAMETER Depth
    Current recursion depth.
  .PARAMETER Writes
    Mutable output list receiving value writes.
  #>
  param (
    [Parameter(Mandatory)]$Reader,
    [Parameter(Mandatory)][string]$Root,
    [string]$Key = '',
    [int]$Depth = 0,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Writes
  )
  if ($Depth -gt $Script:AstrumMaximumConfigurationDepth) { throw 'The Astrum registry tree exceeds the recursion limit.' }
  $ValueCount = Read-AstrumConfigurationCount -Reader $Reader -TableName 'registry-value'
  for ($Index = 0; $Index -lt $ValueCount; $Index++) {
    $Reader.Records++
    if ($Reader.Records -gt $Script:AstrumMaximumConfigurationRecords) { throw 'The Astrum configuration exceeds the record-count limit.' }
    $Writes.Add([pscustomobject][ordered]@{
        Root          = $Root
        Key           = $Key
        Name          = Read-AstrumConfigurationString -Reader $Reader
        Value         = Read-AstrumConfigurationString -Reader $Reader
        TypeCode      = Read-AstrumConfigurationUInt32 -Reader $Reader
        UninstallType = Read-AstrumConfigurationUInt32 -Reader $Reader
        Condition     = Read-AstrumConfigurationCondition -Reader $Reader
        Source        = 'Astrum compiled registry tree'
      })
  }
  $ChildCount = Read-AstrumConfigurationCount -Reader $Reader -TableName 'registry-child'
  for ($Index = 0; $Index -lt $ChildCount; $Index++) {
    $Name = Read-AstrumConfigurationString -Reader $Reader
    # Registry child framing changed independently from value framing, so the catalog owns this route.
    switch ([string]$Reader.Format.RegistryChildRoute) {
      'NameOnly' { $UninstallType = $null; $Condition = $null }
      'UninstallAndCondition' { $UninstallType = Read-AstrumConfigurationUInt32 -Reader $Reader; $Condition = Read-AstrumConfigurationCondition -Reader $Reader }
      default { throw "Astrum format '$($Reader.Format.Id)' uses an unsupported registry-child route '$($Reader.Format.RegistryChildRoute)'." }
    }
    $ChildKey = [string]::IsNullOrEmpty($Key) ? $Name : "$Key\$Name"
    $Before = $Writes.Count
    Read-AstrumRegistryTree -Reader $Reader -Root $Root -Key $ChildKey -Depth ($Depth + 1) -Writes $Writes
    for ($WriteIndex = $Before; $WriteIndex -lt $Writes.Count; $WriteIndex++) {
      if (-not $Writes[$WriteIndex].Condition -and $Condition) { $Writes[$WriteIndex].Condition = $Condition }
      $Writes[$WriteIndex] | Add-Member -NotePropertyName KeyUninstallType -NotePropertyValue $UninstallType -Force
    }
  }
}

function Read-AstrumConfiguration {
  <#
  .SYNOPSIS
    Decode Astrum registry, operation, association, shortcut, and fixed metadata records.
  .PARAMETER Bytes
    Twice-decoded configuration bytes.
  .PARAMETER Format
    Catalog descriptor controlling generation-specific configuration records.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][pscustomobject]$Format
  )

  $Reader = New-AstrumConfigurationReader -Bytes $Bytes -Format $Format
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  foreach ($Root in 'HKCR', 'HKCU', 'HKLM', 'HKU') { Read-AstrumRegistryTree -Reader $Reader -Root $Root -Writes $RegistryWrites }

  # System-change tables follow the builder project order. Associations are materialized as ordinary
  # registry writes, so there is no separate association record table in this sequence.
  $Shortcuts = [Collections.Generic.List[object]]::new()
  $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'shortcut'
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Record = [ordered]@{ Target = Read-AstrumConfigurationString $Reader; LinkName = Read-AstrumConfigurationString $Reader; Arguments = Read-AstrumConfigurationString $Reader; WorkingDirectory = Read-AstrumConfigurationString $Reader; Icon = Read-AstrumConfigurationString $Reader }
    $Tail = Read-AstrumOperationTail $Reader
    $Record.Condition = $Tail.Condition
    $Record.ObservedOperationTail = $Tail.ObservedValue
    $Shortcuts.Add([pscustomobject]$Record)
  }
  $IniOperations = [Collections.Generic.List[object]]::new()
  $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'INI-operation'
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Record = [ordered]@{ Path = Read-AstrumConfigurationString $Reader; Section = Read-AstrumConfigurationString $Reader; Value = Read-AstrumConfigurationString $Reader }
    $Tail = Read-AstrumOperationTail $Reader
    $Record.Condition = $Tail.Condition
    $Record.ObservedOperationTail = $Tail.ObservedValue
    $IniOperations.Add([pscustomobject]$Record)
  }
  $TextOperations = [Collections.Generic.List[object]]::new()
  $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'text-operation'
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $OperationCode = Read-AstrumConfigurationUInt32 $Reader
    $Record = [ordered]@{ Operation = $OperationCode; OperationName = Get-AstrumOperationSemanticName -Code $OperationCode -Names @($Script:AstrumOperationSemantics.TextActions); Path = Read-AstrumConfigurationString $Reader; Search = Read-AstrumConfigurationString $Reader; Value = Read-AstrumConfigurationString $Reader }
    $Tail = Read-AstrumOperationTail $Reader
    $Record.Condition = $Tail.Condition
    $Record.ObservedOperationTail = $Tail.ObservedValue
    $TextOperations.Add([pscustomobject]$Record)
  }
  $FileOperations = [Collections.Generic.List[object]]::new()
  $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'advanced-file-operation'
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $ActionCode = Read-AstrumConfigurationUInt32 $Reader
    $Source = Read-AstrumConfigurationString $Reader
    $Destination = Read-AstrumConfigurationString $Reader
    $Timing = Read-AstrumConfigurationUInt32 $Reader
    $Record = [ordered]@{ ActionCode = $ActionCode; ActionName = Get-AstrumOperationSemanticName -Code $ActionCode -Names @($Script:AstrumOperationSemantics.FileActions); Source = $Source; Destination = $Destination; Timing = $Timing; TimingName = Get-AstrumOperationSemanticName -Code $Timing -Names @($Script:AstrumOperationSemantics.Timings) }
    $Tail = Read-AstrumOperationTail $Reader
    $Record.Condition = $Tail.Condition
    $Record.ObservedOperationTail = $Tail.ObservedValue
    $FileOperations.Add([pscustomobject]$Record)
  }
  $Variables = [Collections.Generic.List[object]]::new()
  $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'variable'
  for ($Index = 0; $Index -lt $Count; $Index++) {
    # Use the XML field names: type, get-from, default-value, location1..3, and
    # flags. Keep the source enum distinct from the option bit mask.
    $Name = Read-AstrumConfigurationString $Reader
    $TypeCode = Read-AstrumConfigurationUInt32 $Reader
    $SourceCode = Read-AstrumConfigurationUInt32 $Reader
    $DefaultValue = Read-AstrumConfigurationString $Reader
    $Location1 = Read-AstrumConfigurationString $Reader
    $Location2 = Read-AstrumConfigurationString $Reader
    $Location3 = Read-AstrumConfigurationString $Reader
    $VariableFlags = Read-AstrumConfigurationUInt32 $Reader
    $Variables.Add([pscustomobject][ordered]@{
        Name            = $Name
        TypeCode        = $TypeCode
        TypeName        = Get-AstrumOperationSemanticName -Code $TypeCode -Names @($Script:AstrumVariableSemantics.Types)
        SourceCode      = $SourceCode
        SourceName      = Get-AstrumVariableSourceName -Code $SourceCode
        DefaultValue    = $DefaultValue
        Location1       = $Location1
        Location2       = $Location2
        Location3       = $Location3
        Flags           = $VariableFlags
        StoreDriveOnly  = ($VariableFlags -band [uint32]$Script:AstrumVariableSemantics.Flags.StoreDriveOnly) -ne 0
        SetTrueIfExists = ($VariableFlags -band [uint32]$Script:AstrumVariableSemantics.Flags.SetTrueIfExists) -ne 0
        UserVisible     = ($VariableFlags -band [uint32]$Script:AstrumVariableSemantics.Flags.UserVisible) -ne 0
      })
  }
  $InteractiveOperations = [Collections.Generic.List[object]]::new()
  $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'advanced-interactive-operation'
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $ActionCode = Read-AstrumConfigurationUInt32 $Reader
    $File = Read-AstrumConfigurationString $Reader
    $Arguments = Read-AstrumConfigurationString $Reader
    $WorkingDirectory = Read-AstrumConfigurationString $Reader
    $Timing = Read-AstrumConfigurationUInt32 $Reader
    $Record = [ordered]@{ ActionCode = $ActionCode; ActionName = Get-AstrumOperationSemanticName -Code $ActionCode -Names @($Script:AstrumOperationSemantics.InteractiveActions) -MaximumCount ([int]$Format.InteractiveActionCount); File = $File; Arguments = $Arguments; WorkingDirectory = $WorkingDirectory; Timing = $Timing; TimingName = Get-AstrumOperationSemanticName -Code $Timing -Names @($Script:AstrumOperationSemantics.Timings); ExecuteCount = Read-AstrumConfigurationUInt32 $Reader }
    # Astrum 1.x stops this record after ExecuteCount. Reading the later flags/message/tail fields
    # consumes the beginning of ApplicationName when an old package contains an interactive action.
    # Astrum 2.x adds those fields and the normal condition envelope.
    switch ([string]$Reader.Format.InteractiveOperationRoute) {
      'LegacyWithoutTail' {
        $Record.Flags = $null
        $Record.CustomMessage = $null
        $Record.Condition = $null
        $Record.ObservedOperationTail = $null
      }
      'CurrentWithCondition' {
        $Record.Flags = Read-AstrumConfigurationUInt32 $Reader
        $Record.CustomMessage = Read-AstrumConfigurationString $Reader
        $Tail = Read-AstrumOperationTail $Reader
        $Record.Condition = $Tail.Condition
        $Record.ObservedOperationTail = $Tail.ObservedValue
      }
      default { throw "Astrum format '$($Reader.Format.Id)' uses an unsupported interactive-operation route '$($Reader.Format.InteractiveOperationRoute)'." }
    }
    $InteractiveOperations.Add([pscustomobject]$Record)
  }
  $PostInteractiveRecords = [Collections.Generic.List[object]]::new()
  if ($Format.HasPostInteractiveTable) {
    $Count = Read-AstrumConfigurationCount -Reader $Reader -TableName 'post-interactive'
    for ($Index = 0; $Index -lt $Count; $Index++) {
      $Record = [ordered]@{ ObservedUInt32A = Read-AstrumConfigurationUInt32 $Reader; ObservedUInt32B = Read-AstrumConfigurationUInt32 $Reader; ObservedStringA = Read-AstrumConfigurationString $Reader; ObservedStringB = Read-AstrumConfigurationString $Reader; ObservedStringC = Read-AstrumConfigurationString $Reader; ObservedStringD = Read-AstrumConfigurationString $Reader }
      $Tail = Read-AstrumOperationTail $Reader
      $Record.Condition = $Tail.Condition
      $Record.ObservedOperationTail = $Tail.ObservedValue
      $PostInteractiveRecords.Add([pscustomobject]$Record)
    }
  }

  # Profile selection is structural. Modern media prefixes this region with a bounded runtime word;
  # legacy identity records begin directly with a length-prefixed application name.
  $ConfigurationProfile = Get-AstrumConfigurationProfile -Format $Format -Bytes $Bytes -Offset $Reader.Position
  if ($ConfigurationProfile.IdentityRoute -eq 'Modern') {
    $RuntimeFormat = Read-AstrumConfigurationUInt32 $Reader
    $ApplicationName = Read-AstrumConfigurationString $Reader
    $ApplicationName2 = Read-AstrumConfigurationString $Reader
    $CompanyName = Read-AstrumConfigurationString $Reader
    $CompanyName2 = Read-AstrumConfigurationString $Reader
  } elseif ($ConfigurationProfile.IdentityRoute -eq 'Legacy') {
    $RuntimeFormat = $null
    $ApplicationName = Read-AstrumConfigurationString $Reader
    $ApplicationName2 = $ApplicationName
    $CompanyName = Read-AstrumConfigurationString $Reader
    $CompanyName2 = $CompanyName
  } else { throw "Astrum configuration profile '$($ConfigurationProfile.Id)' uses an unsupported identity route '$($ConfigurationProfile.IdentityRoute)'." }
  $InstallPath = Read-AstrumConfigurationString $Reader
  $InstallPathFlags = Read-AstrumConfigurationUInt32 $Reader
  $InstallRegistryRoot = Read-AstrumConfigurationUInt32 $Reader
  $InstallRegistryPath = Read-AstrumConfigurationString $Reader
  $InstallRegistryValue = Read-AstrumConfigurationString $Reader
  $ShortcutPath = Read-AstrumConfigurationString $Reader
  $InterfaceStrings = for ($Index = 0; $Index -lt 6; $Index++) { Read-AstrumConfigurationString $Reader }
  $UninstallRegistryRoot = Read-AstrumConfigurationUInt32 $Reader
  $FixedStrings = for ($Index = 0; $Index -lt 8; $Index++) { Read-AstrumConfigurationString $Reader }
  if ($ConfigurationProfile.IdentityRoute -eq 'Modern') {
    $DefaultLanguage = Read-AstrumConfigurationUInt32 $Reader
    $UninstallerName = Read-AstrumConfigurationString $Reader
    $UninstallerCommand = Read-AstrumConfigurationString $Reader
    $InstallIcon = $FixedStrings[5]
    $LanguageDialogTitle = $FixedStrings[6]
    $LanguageDialogText = $FixedStrings[7]
  } else {
    $DefaultLanguage = $null
    $UninstallerName = $FixedStrings[7]
    $UninstallerCommand = Read-AstrumConfigurationString $Reader
    $InstallIcon = $null
    $LanguageDialogTitle = $FixedStrings[5]
    $LanguageDialogText = $FixedStrings[6]
  }
  $OptionOffset = $Reader.Position

  # The catalog owns sparse offsets and byte order. Profiles with opaque tails return stable nulls.
  $ProfileOptions = Read-AstrumConfigurationProfileOptions -Bytes $Bytes -BaseOffset $OptionOffset -ConfigurationProfile $ConfigurationProfile
  $Requirements = $ProfileOptions.Requirements
  $Options = $ProfileOptions.Configuration

  return [pscustomobject][ordered]@{
    RuntimeFormat                            = $RuntimeFormat
    FormatId                                 = [string]$Format.Id
    ConfigurationProfile                     = [string]$ConfigurationProfile.Id
    ConfigurationProfileObservedVersionRange = [string]$ConfigurationProfile.ObservedVersionRange
    ConfigurationProfileRoute                = [string]$Format.ConfigurationProfileRoute
    OptionRoute                              = [string]$ConfigurationProfile.OptionRoute
    SilentRoute                              = [string]$ConfigurationProfile.SilentRoute
    UserInformationBlocksSilent              = $ConfigurationProfile.UserInformationBlocksSilent -ne $false ? $true : $false
    UserInformationEvidence                  = [string]$ConfigurationProfile.UserInformationEvidence
    ApplicationName                          = $ApplicationName
    InternalApplicationName                  = $ApplicationName2
    CompanyName                              = $CompanyName
    InternalCompanyName                      = $CompanyName2
    InstallPath                              = $InstallPath
    InstallPathFlags                         = $InstallPathFlags
    InstallRegistryRoot                      = $InstallRegistryRoot
    InstallRegistryPath                      = $InstallRegistryPath
    InstallRegistryValue                     = $InstallRegistryValue
    ShortcutPath                             = $ShortcutPath
    InterfaceStrings                         = @($InterfaceStrings)
    UninstallRegistryRoot                    = $UninstallRegistryRoot
    PreviousVersionRegistryPath              = $FixedStrings[0]
    PreviousVersionRegistryValue             = $FixedStrings[1]
    PreviousVersionMinimum                   = $FixedStrings[2]
    ApplicationVersion                       = $FixedStrings[3]
    FileVersion                              = $FixedStrings[4]
    InstallIcon                              = $InstallIcon
    LanguageDialogTitle                      = $LanguageDialogTitle
    LanguageDialogText                       = $LanguageDialogText
    DefaultLanguage                          = $DefaultLanguage
    UninstallerName                          = $UninstallerName
    UninstallerCommand                       = $UninstallerCommand
    RegistryWrites                           = @($RegistryWrites)
    Shortcuts                                = @($Shortcuts)
    IniOperations                            = @($IniOperations)
    TextOperations                           = @($TextOperations)
    FileOperations                           = @($FileOperations)
    Variables                                = @($Variables)
    InteractiveOperations                    = @($InteractiveOperations)
    PostInteractiveRecords                   = @($PostInteractiveRecords)
    Requirements                             = $Requirements
    UserInformationFlags                     = $Options.UserInformationFlags
    SilentInstallationDefault                = $Options.SilentInstallationDefault
    NoUninstallation                         = $Options.NoUninstallation
    X64ComplianceMode                        = $Options.X64ComplianceMode
    RequireAdmin                             = $Options.RequireAdmin
    DirectLicenseApproval                    = $Options.DirectLicenseApproval
    ProhibitSilentInstallation               = $Options.ProhibitSilentInstallation
    OptionOffset                             = $OptionOffset
    OptionBlockSize                          = $ProfileOptions.OptionBlockEvidence.Size
    OptionBlockEvidence                      = $ProfileOptions.OptionBlockEvidence
    DecodedBytes                             = $Bytes
  }
}

function ConvertFrom-AstrumNameBytes {
  <#
  .SYNOPSIS
    Reverse the per-byte bit permutation used for file destination names.
  .PARAMETER Bytes
    Encoded path bytes from a file record.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)
  $Decoded = [byte[]]::new($Bytes.Length)
  for ($Index = 0; $Index -lt $Bytes.Length; $Index++) {
    $Value = [int]$Bytes[$Index]
    $Part1 = (((($Value -shr 4) -band 4) -bor ($Value -band 0x30)) -shr 2)
    $Part2 = ((($Value -band 0x0C) -bor (($Value -shl 4) -band 0xFF)) -shl 2)
    $Part3 = ($Value -shr 6) -band 2
    $Decoded[$Index] = [byte](($Part1 -bor $Part2 -bor $Part3) -band 0xFF)
  }
  return $Script:AstrumAnsi.GetString($Decoded)
}

function Get-AstrumRawConditionLength {
  <#
  .SYNOPSIS
    Validate and measure an optional little-endian file-record condition.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Offset
    Absolute condition start immediately after the 64-byte 2.x file header.
  .PARAMETER Kind
    Descriptor condition kind; zero means no condition bytes are present.
  .PARAMETER Limit
    Exclusive catalog boundary.
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][uint32]$Kind,
    [Parameter(Mandatory)][long]$Limit
  )
  if ($Kind -eq 0) { return 0 }
  $Cursor = $Offset
  $Count = [long](Read-BinaryInteger -Stream $Stream -Offset $Cursor -Size 4)
  $Cursor += 4
  if ($Count -gt $Script:AstrumMaximumConfigurationRecords) { throw 'The Astrum file condition exceeds its term-count limit.' }
  for ($Index = 0; $Index -lt $Count; $Index++) {
    foreach ($HasOperator in $false, $true) {
      $Length = [long](Read-BinaryInteger -Stream $Stream -Offset $Cursor -Size 4)
      $Cursor += 4
      if ($Length -gt $Script:AstrumMaximumStringBytes -or -not (Test-AstrumRange $Cursor $Length $Limit)) { throw 'The Astrum file condition contains an invalid string range.' }
      $Cursor += $Length
      if (-not $HasOperator) { $Cursor += 4 }
    }
  }
  if ($Cursor -gt $Limit) { throw 'The Astrum file condition extends beyond the catalog.' }
  return [int]($Cursor - $Offset)
}

function Read-AstrumInstallationItems {
  <#
  .SYNOPSIS
    Parse the big-endian installation-item table.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Footer
    Validated footer route table.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Footer)
  if ($Footer.InstallationItemCount -eq 0) { return @() }
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Footer.InstallationItemOffset -Count ([int]$Footer.InstallationItemSize)
  $Offset = 0
  $Items = [Collections.Generic.List[object]]::new()
  for ($Index = 0; $Index -lt $Footer.InstallationItemCount; $Index++) {
    $NameLength = [int](Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian); $Offset += 4
    if ($NameLength -gt $Script:AstrumMaximumStringBytes -or $NameLength -gt $Bytes.Length - $Offset) { throw 'The Astrum installation-item name is truncated.' }
    $Name = $Script:AstrumAnsi.GetString($Bytes, $Offset, $NameLength); $Offset += $NameLength
    $Flags = Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian; $Offset += 4
    $DescriptionLength = [int](Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian); $Offset += 4
    if ($DescriptionLength -gt $Script:AstrumMaximumStringBytes -or $DescriptionLength -gt $Bytes.Length - $Offset) { throw 'The Astrum installation-item description is truncated.' }
    $Description = $Script:AstrumAnsi.GetString($Bytes, $Offset, $DescriptionLength); $Offset += $DescriptionLength
    if ($Offset -gt $Bytes.Length - 20) { throw 'The Astrum installation-item totals are truncated.' }
    $Enabled = Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian; $Offset += 4
    $ExpandedSize = Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian; $Offset += 4
    $Observed1 = Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian; $Offset += 4
    $Observed2 = Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian; $Offset += 4
    $InstalledSize = Read-AstrumUInt32FromBytes $Bytes $Offset BigEndian; $Offset += 4
    $Items.Add([pscustomobject][ordered]@{ Index = $Index; Name = $Name; Description = $Description; Flags = $Flags; Enabled = $Enabled -ne 0; ExpandedSize = [long]$ExpandedSize; InstalledSize = [long]$InstalledSize; ObservedValues = @($Observed1, $Observed2) })
  }
  if ($Offset -ne $Bytes.Length) { throw 'The Astrum installation-item table contains trailing or unconsumed data.' }
  return @($Items)
}

function Read-AstrumFileCatalog {
  <#
  .SYNOPSIS
    Parse bounded Astrum file descriptors and physical payload ranges.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Footer
    Validated footer route table.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Footer)
  $Files = [Collections.Generic.List[object]]::new()
  $Offset = [long]$Footer.FileOffset
  $Format = $Footer.FormatProfile
  $DescriptorSize = [int]$Format.FileDescriptorSize
  for ($Index = 0; $Index -lt $Footer.FileCount; $Index++) {
    if (-not (Test-AstrumRange $Offset $DescriptorSize $Footer.Offset)) { throw "The Astrum file descriptor $Index is truncated." }
    $Header = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $DescriptorSize
    $Values = [uint32[]]::new($DescriptorSize / 4)
    for ($Field = 0; $Field -lt $Values.Length; $Field++) { $Values[$Field] = Read-AstrumUInt32FromBytes $Header ($Field * 4) }
    $NameLength = [long]$Values[11]
    $VolumeCount = [long]$Values[12]
    $DataLength = [long]$Values[13]
    if ($NameLength -le 0 -or $NameLength -gt $Script:AstrumMaximumStringBytes -or $VolumeCount -gt 4096) { throw "The Astrum file descriptor $Index has invalid variable fields." }
    # A nonnegative catalog index names the condition selector word; -1 means the descriptor has no condition field.
    $ConditionWordIndex = [int]$Format.FileConditionWordIndex
    $ConditionKind = $ConditionWordIndex -ge 0 ? $Values[$ConditionWordIndex] : $null
    $ConditionLength = $ConditionWordIndex -ge 0 ? (Get-AstrumRawConditionLength -Stream $Stream -Offset ($Offset + $DescriptorSize) -Kind $ConditionKind -Limit $Footer.Offset) : 0
    $NameOffset = $Offset + $DescriptorSize + $ConditionLength
    $VolumeOffset = $NameOffset + $NameLength
    $DataOffset = $VolumeOffset + ($VolumeCount * 4)
    if (-not (Test-AstrumRange $NameOffset $NameLength $Footer.Offset) -or -not (Test-AstrumRange $VolumeOffset ($VolumeCount * 4) $Footer.Offset) -or -not (Test-AstrumRange $DataOffset $DataLength $Footer.Offset)) { throw "The Astrum file record $Index extends beyond the catalog." }
    $Path = ConvertFrom-AstrumNameBytes -Bytes (Read-BinaryBytes -Stream $Stream -Offset $NameOffset -Count ([int]$NameLength))
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "The Astrum file record $Index has an empty destination path." }
    $VolumeOffsets = [Collections.Generic.List[long]]::new()
    for ($VolumeIndex = 0; $VolumeIndex -lt $VolumeCount; $VolumeIndex++) { $VolumeOffsets.Add([long](Read-BinaryInteger -Stream $Stream -Offset ($VolumeOffset + $VolumeIndex * 4) -Size 4)) }
    $Prefix = $DataLength -ge 2 ? (Read-BinaryBytes -Stream $Stream -Offset $DataOffset -Count 2) : [byte[]]::new(0)
    $Compression = $Prefix.Length -eq 2 -and (Test-BinarySequence $Prefix $Script:AstrumGZipMagic) ? 'GZip' : 'Stored'
    $ExpectedSize = if ($Compression -eq 'GZip' -and $DataLength -ge 18) { [long](Read-BinaryInteger -Stream $Stream -Offset ($DataOffset + $DataLength - 4) -Size 4) } else { $DataLength }
    # Version-capable descriptors store VS_FIXEDFILEINFO version halves followed by the packed
    # code-page/language translation. A 0xFFFFFFFF version pair marks a record without this data.
    $HasVersionResource = $Values[8] -ne [uint32]::MaxValue -and $Values[9] -ne [uint32]::MaxValue
    $VersionResourceEvidence = if ($HasVersionResource) {
      [pscustomobject][ordered]@{
        FileVersion     = '{0}.{1}.{2}.{3}' -f ($Values[8] -shr 16), ($Values[8] -band 0xFFFF), ($Values[9] -shr 16), ($Values[9] -band 0xFFFF)
        FileMajorPart   = [int]($Values[8] -shr 16)
        FileMinorPart   = [int]($Values[8] -band 0xFFFF)
        FileBuildPart   = [int]($Values[9] -shr 16)
        FilePrivatePart = [int]($Values[9] -band 0xFFFF)
        LanguageId      = [int]($Values[10] -band 0xFFFF)
        CodePage        = [int]($Values[10] -shr 16)
        RawTranslation  = $Values[10]
      }
    } else { $null }
    $Files.Add([pscustomobject][ordered]@{
        Index = $Index; InstallationItemIndex = [int]$Values[0]; RecordOffset = $Offset; Path = $Path; NameOffset = $NameOffset
        DataOffset = $DataOffset; CompressedSize = $DataLength; ExpectedSize = $ExpectedSize; Compression = $Compression
        Flags = $Values[2]; Attributes = $Values[3]; OverwriteModeCode = [int](($Values[2] -shr 12) -band 0xF)
        RegistrationPriority = [int]$Values[14]; VersionResourceEvidence = $VersionResourceEvidence
        ObservedDescriptorWord10 = $HasVersionResource ? $null : $Values[10]; ConditionKind = $ConditionKind
        VolumeOffsets = @($VolumeOffsets); IsConditional = $ConditionWordIndex -ge 0 -and $ConditionKind -ne 0
        IsResourceFile = $Path.StartsWith('<ResourceDir>\', [StringComparison]::OrdinalIgnoreCase)
      })
    $Offset = $DataOffset + $DataLength
  }
  if ($Offset -ne $Footer.Offset) { throw 'The Astrum file records do not consume the declared catalog and payload range.' }
  return @($Files)
}

function Test-AstrumLiteralVariable {
  <#
  .SYNOPSIS
    Test whether a compiled custom variable resolves from its literal default value.
  .DESCRIPTION
    A Nowhere variable resolves from its default value. The parser also accepts the observed
    Registry/HKEY_CLASSES_ROOT record with empty key and value locations: the Astrum runtime falls
    back to its default value, as proven by live installation of the BreakAlube package. Other
    Registry, INI, and file-search sources read runtime state and stay unresolved.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)]$Variable,
    [AllowEmptyCollection()][string[]]$ReservedNames = @()
  )
  if ($Name -notmatch '^<[^<>]+>$' -or $Name -in $ReservedNames) { return $false }
  $LocationsAreEmpty = [string]::IsNullOrEmpty([string]$Variable.Location2) -and [string]::IsNullOrEmpty([string]$Variable.Location3)
  $UsesLiteralSource = [uint32]$Variable.SourceCode -eq [uint32]::MaxValue -and [string]::IsNullOrEmpty([string]$Variable.Location1) -and $LocationsAreEmpty
  $UsesObservedEmptyRegistrySource = [uint32]$Variable.SourceCode -eq 0 -and [int64]$Variable.Location1 -eq -2147483648 -and $LocationsAreEmpty
  return ($UsesLiteralSource -or $UsesObservedEmptyRegistrySource) -and -not [string]::IsNullOrEmpty([string]$Variable.DefaultValue)
}

function Resolve-AstrumVariables {
  <#
  .SYNOPSIS
    Resolve deterministic Astrum variables into metadata-safe Windows paths.
  .PARAMETER Value
    Compiled string containing Astrum angle-bracket variables.
  .PARAMETER Configuration
    Parsed fixed configuration values.
  .PARAMETER InstallLocation
    Manifest-safe default installation path.
  .PARAMETER RegistryView
    Registry and known-folder view used by the installer runtime. A 32-bit view maps the
    Program Files variables to their x86 variants on 64-bit Windows.
  .PARAMETER MaximumDepth
    Maximum replacement passes used to resolve nested deterministic variables and stop cycles.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)]$Configuration,
    [AllowNull()][string]$InstallLocation,
    [ValidateSet('32-bit', '64-bit', 'default')][string]$RegistryView = 'default',
    [ValidateRange(1, 64)][int]$MaximumDepth = 16
  )
  if ($null -eq $Value) { return $null }
  $FileNameSafeApplicationName = [regex]::Replace([string]$Configuration.ApplicationName, '[<>:"/\\|?*]', '_')
  $ProgramFiles = $RegistryView -eq '32-bit' ? '%ProgramFiles(x86)%' : '%ProgramFiles%'
  $CommonProgramFiles = $RegistryView -eq '32-bit' ? '%CommonProgramFiles(x86)%' : '%CommonProgramFiles%'
  $Map = [ordered]@{
    '<AppName>' = $Configuration.ApplicationName; '<AppVersion>' = $Configuration.ApplicationVersion; '<CompanyName>' = $Configuration.CompanyName
    '<AppNameInFileNameFormat>' = $FileNameSafeApplicationName; '<__AppName__>' = $FileNameSafeApplicationName; '<Organization>' = $Configuration.CompanyName
    '<InstallDir>' = $InstallLocation; '<ProgramFiles>' = $ProgramFiles; '<CommonFiles>' = $CommonProgramFiles
    '<WindowsDir>' = '%WINDIR%'; '<SystemDir>' = '%WINDIR%\System32'; '<TempDir>' = '%TEMP%'; '<FontDir>' = '%WINDIR%\Fonts'
    '<StartMenu>' = '%APPDATA%\Microsoft\Windows\Start Menu'; '<StartMenuNt>' = '%ProgramData%\Microsoft\Windows\Start Menu'
    '<ProgramsDir>' = '%APPDATA%\Microsoft\Windows\Start Menu\Programs'; '<ProgramsDirNt>' = '%ProgramData%\Microsoft\Windows\Start Menu\Programs'
    '<StartUp>' = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'; '<StartUpNt>' = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'
    '<Desktop>' = '%USERPROFILE%\Desktop'; '<DesktopNt>' = '%PUBLIC%\Desktop'; '<MyDocuments>' = '%USERPROFILE%\Documents'
    '<RoamingAppData>' = '%APPDATA%'; '<LocalAppData>' = '%LOCALAPPDATA%'; '<CommonAppData>' = '%ProgramData%'; '<SystemDrive>' = '%SystemDrive%'
    '<UninstallerName>' = $Configuration.UninstallerName
  }
  # Builder help defines a custom variable whose source is "Nowhere" as its literal default value.
  # Compiled records with any source arguments may read registry, INI, files, dialogs, or DLL state
  # at runtime and therefore remain unresolved. Built-ins retain precedence over custom names.
  foreach ($Variable in @($Configuration.Variables)) {
    if (-not (Test-AstrumLiteralVariable -Name ([string]$Variable.Name) -Variable $Variable -ReservedNames @($Map.Keys))) { continue }
    $Map[[string]$Variable.Name] = [string]$Variable.DefaultValue
  }
  $Result = $Value
  for ($Depth = 0; $Depth -lt $MaximumDepth; $Depth++) {
    $Previous = $Result
    # A null string parameter is coerced to an empty string by PowerShell. Treat empty variable
    # values as unresolved so a missing install path cannot silently become a root-relative path.
    foreach ($Pair in $Map.GetEnumerator()) { if (-not [string]::IsNullOrEmpty([string]$Pair.Value)) { $Result = $Result.Replace($Pair.Key, [string]$Pair.Value, [StringComparison]::OrdinalIgnoreCase) } }
    if ($Result -ceq $Previous) { break }
  }
  return $Result
}

function ConvertTo-AstrumManifestPath {
  <#
  .SYNOPSIS
    Convert a compiled Astrum install path to WinGet-safe environment syntax.
  .PARAMETER Value
    Compiled default installation path.
  .PARAMETER Configuration
    Parsed package-name and publisher evidence.
  .PARAMETER RegistryView
    Registry and known-folder view used by the installer runtime.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)]$Configuration,
    [ValidateSet('32-bit', '64-bit', 'default')][string]$RegistryView = 'default'
  )
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $ProgramFiles = $RegistryView -eq '32-bit' ? '%ProgramFiles(x86)%' : '%ProgramFiles%'
  $CommonProgramFiles = $RegistryView -eq '32-bit' ? '%CommonProgramFiles(x86)%' : '%CommonProgramFiles%'
  $Result = $Value.Replace('<ProgramFiles>', $ProgramFiles, [StringComparison]::OrdinalIgnoreCase).Replace('<CommonFiles>', $CommonProgramFiles, [StringComparison]::OrdinalIgnoreCase)
  $Result = $Result.Replace('<AppName>', [string]$Configuration.ApplicationName, [StringComparison]::OrdinalIgnoreCase).Replace('<CompanyName>', [string]$Configuration.CompanyName, [StringComparison]::OrdinalIgnoreCase)
  # Deterministic custom variables (literal "Nowhere" source) also resolve here; the live BreakAlube
  # package proves install paths compose them. Non-literal sources still leave the marker in place.
  foreach ($Variable in @($Configuration.Variables)) {
    if (-not (Test-AstrumLiteralVariable -Name ([string]$Variable.Name) -Variable $Variable -ReservedNames @('<ProgramFiles>', '<CommonFiles>', '<AppName>', '<CompanyName>'))) { continue }
    $Result = $Result.Replace([string]$Variable.Name, [string]$Variable.DefaultValue, [StringComparison]::OrdinalIgnoreCase)
  }
  return $Result.Contains('<', [StringComparison]::Ordinal) ? $null : $Result
}

function ConvertTo-AstrumRegistryWrites {
  <#
  .SYNOPSIS
    Normalize compiled Astrum registry records and deterministic variables.
  .PARAMETER Configuration
    Parsed configuration containing raw registry records.
  .PARAMETER InstallLocation
    Resolved default install location.
  .PARAMETER RegistryView
    32-bit, 64-bit, or default view evidence.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)]$Configuration, [AllowNull()][string]$InstallLocation, [Parameter(Mandatory)][string]$RegistryView)
  $HiveMap = @{ HKCR = 'HKEY_CLASSES_ROOT'; HKCU = 'HKEY_CURRENT_USER'; HKLM = 'HKEY_LOCAL_MACHINE'; HKU = 'HKEY_USERS' }
  $TypeMap = @{ 0 = 'REG_BINARY'; 1 = 'REG_DWORD'; 2 = 'REG_SZ'; 3 = 'REG_MULTI_SZ'; 4 = 'REG_EXPAND_SZ' }
  foreach ($Write in $Configuration.RegistryWrites) {
    $Key = Resolve-AstrumVariables -Value $Write.Key -Configuration $Configuration -InstallLocation $InstallLocation -RegistryView $RegistryView
    $Value = Resolve-AstrumVariables -Value ([string]$Write.Value) -Configuration $Configuration -InstallLocation $InstallLocation -RegistryView $RegistryView
    [pscustomobject][ordered]@{
      Hive = $HiveMap[$Write.Root]; Root = $Write.Root; View = $RegistryView; Key = $Key; Name = $Write.Name; Value = $Value
      Type = $TypeMap[[int]$Write.TypeCode] ?? "Observed($($Write.TypeCode))"; Condition = $Write.Condition
      IsConditional = $null -ne $Write.Condition; UninstallType = $Write.UninstallType; Source = $Write.Source
    }
  }
}

function Get-AstrumArpEntries {
  <#
  .SYNOPSIS
    Project explicit uninstall-registry writes into visible Apps & Features entries.
  .PARAMETER RegistryWrites
    Normalized compiled registry writes.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryWrites)
  $Groups = $RegistryWrites | Where-Object { -not $_.IsConditional -and $_.Key -match '(?i)^Software[\\]Microsoft[\\]Windows[\\]CurrentVersion[\\]Uninstall[\\](?<Code>[^\\]+)$' } | Group-Object Root, Key
  foreach ($Group in $Groups) {
    $Values = [ordered]@{}
    foreach ($Write in $Group.Group) { $Values[[string]$Write.Name] = $Write.Value }
    # Astrum writes the generated uninstall executable as a quoted command even when the compiled
    # registry template contains only the unquoted path. Preserve existing arguments verbatim.
    if ($Values.Contains('UninstallString') -and -not [string]::IsNullOrWhiteSpace([string]$Values.UninstallString)) {
      $UninstallCommand = [string]$Values.UninstallString
      if (-not $UninstallCommand.StartsWith('"', [StringComparison]::Ordinal)) {
        $ExecutableMatch = [regex]::Match($UninstallCommand, '^(?<Executable>.*?\.exe)(?<Arguments>\s+.*)?$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($ExecutableMatch.Success) { $Values.UninstallString = '"{0}"{1}' -f $ExecutableMatch.Groups['Executable'].Value, $ExecutableMatch.Groups['Arguments'].Value }
      }
    }
    $SystemComponent = $Values.Contains('SystemComponent') ? [int]$Values.SystemComponent : 0
    $Root = $Group.Group[0].Root
    [pscustomobject][ordered]@{
      ProductCode = [regex]::Match($Group.Group[0].Key, '(?i)[\\]Uninstall[\\](?<Code>[^\\]+)$').Groups['Code'].Value
      Root = $Root; Hive = $Group.Group[0].Hive; View = $Group.Group[0].View; Scope = $Root -eq 'HKLM' ? 'machine' : ($Root -eq 'HKCU' ? 'user' : $null)
      DisplayName = $Values['DisplayName']; DisplayVersion = $Values['DisplayVersion']; Publisher = $Values['Publisher']
      InstallLocation = $Values['InstallLocation']; UninstallString = $Values['UninstallString']; QuietUninstallString = $Values['QuietUninstallString']
      DisplayIcon = $Values['DisplayIcon']; URLInfoAbout = $Values['URLInfoAbout']; HelpLink = $Values['HelpLink']; Comments = $Values['Comments']
      SystemComponent = $SystemComponent; IsVisible = $SystemComponent -ne 1 -and -not [string]::IsNullOrWhiteSpace([string]$Values['DisplayName']); Values = $Values
    }
  }
}

function Test-AstrumResolvedValue {
  <#
  .SYNOPSIS
    Test whether a compiled Astrum value is free of unresolved angle-bracket variables.
  .PARAMETER Value
    Compiled or partly resolved value.
  #>
  [OutputType([bool])]
  param ([AllowNull()][object]$Value)

  if ($null -eq $Value) { return $false }
  return [string]$Value -notmatch '<[^<>]+>'
}

function Test-AstrumCompiledDialog {
  <#
  .SYNOPSIS
    Test for one selected standard dialog in the bounded compiled UI region.
  .PARAMETER Context
    Validated Astrum analysis context whose stream remains open.
  .PARAMETER Marker
    Exact ASCII resource marker emitted by the standard 2.29.50 dialog template.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)][byte[]]$Marker
  )

  $StartOffset = [long]$Context.Footer.ConfigurationOffset
  $EndOffset = [long]$Context.Footer.InstallationItemOffset
  if ($EndOffset -le $StartOffset) { return $false }
  return @(Find-BinaryPattern -Stream $Context.Stream -Pattern $Marker -StartOffset $StartOffset -Length ($EndOffset - $StartOffset) -Maximum 1).Count -gt 0
}

function Get-AstrumRuntimeCommandLineEvidence {
  <#
  .SYNOPSIS
    Locate exact command-line tokens compiled into the native Astrum runtime image.
  .PARAMETER Stream
    Caller-owned seekable installer stream. Searches are bounded to the PE image before its overlay.
  .OUTPUTS
    Runtime switch names and absolute string offsets; no application payload bytes are searched.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  $RuntimeEnd = Get-PEOverlayOffset -Stream $Stream
  $Switches = [Collections.Generic.List[string]]::new()
  $Offsets = [ordered]@{}
  foreach ($CommandLineSwitch in '/SILENT', '/ACCEPTLICENSE') {
    $Pattern = [Text.Encoding]::ASCII.GetBytes($CommandLineSwitch)
    $PatternOffsets = @(Find-BinaryPattern -Stream $Stream -Pattern $Pattern -StartOffset 0 -Length $RuntimeEnd -Maximum 16)
    foreach ($Offset in $PatternOffsets) {
      $Before = $Offset -gt 0 ? (Read-BinaryBytes -Stream $Stream -Offset ($Offset - 1) -Count 1)[0] : 0
      $AfterOffset = $Offset + $Pattern.Length
      $After = $AfterOffset -lt $RuntimeEnd ? (Read-BinaryBytes -Stream $Stream -Offset $AfterOffset -Count 1)[0] : 0
      # Runtime option tables delimit tokens with NUL or ASCII whitespace. This excludes a matching
      # substring embedded in an unrelated identifier while allowing the observed "/SILENT /NOREMOVE" table.
      if ($Before -notin 0, 9, 10, 13, 32, 34 -or $After -notin 0, 9, 10, 13, 32, 34) { continue }
      $Normalized = $CommandLineSwitch.ToLowerInvariant()
      if (-not $Switches.Contains($Normalized)) { $Switches.Add($Normalized) }
      $Offsets[$Normalized] = [long]$Offset
      break
    }
  }
  return [pscustomobject]@{
    RuntimeEndOffset = $RuntimeEnd
    Switches         = $Switches.ToArray()
    Offsets          = [pscustomobject]$Offsets
    SupportsSilent   = $Switches.Contains('/silent')
  }
}

function ConvertTo-AstrumAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Produce one schema-safe manifest ARP entry from explicit registry evidence.
  .PARAMETER Entry
    Parsed Astrum uninstall-key record.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)]$Entry)

  $Result = [ordered]@{}
  if (Test-AstrumResolvedValue -Value $Entry.ProductCode) { $Result.ProductCode = $Entry.ProductCode }
  foreach ($Name in 'DisplayName', 'DisplayVersion', 'Publisher') {
    $Value = $Entry.$Name
    if (-not [string]::IsNullOrWhiteSpace([string]$Value) -and (Test-AstrumResolvedValue -Value $Value)) { $Result[$Name] = $Value }
  }
  if ($Result.Count -eq 0) { return $null }
  return [pscustomobject]$Result
}

function Get-AstrumUninstallerRelativePath {
  <#
  .SYNOPSIS
    Resolve the configured ARP uninstaller to an installed payload-relative path.
  .PARAMETER UninstallString
    Resolved uninstall command from the explicit ARP record.
  .PARAMETER InstallLocation
    Resolved default installation root.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$UninstallString,
    [AllowNull()][string]$InstallLocation
  )

  if ([string]::IsNullOrWhiteSpace($UninstallString) -or [string]::IsNullOrWhiteSpace($InstallLocation)) { return $null }
  $Command = $UninstallString.Trim()
  if ($Command.StartsWith('"')) {
    $EndQuote = $Command.IndexOf('"', 1)
    if ($EndQuote -le 1) { return $null }
    $Command = $Command.Substring(1, $EndQuote - 1)
  } else {
    $ExecutableMatch = [regex]::Match($Command, '(?i)^.*?\.exe(?=\s|$)')
    if (-not $ExecutableMatch.Success) { return $null }
    $Command = $ExecutableMatch.Value
  }

  $Prefix = $InstallLocation.TrimEnd('\') + '\'
  if (-not $Command.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) { return $null }
  $RelativePath = $Command.Substring($Prefix.Length)
  if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath -match '<[^<>]+>') { return $null }
  return $RelativePath
}

function Get-AstrumInstalledRelativePath {
  <#
  .SYNOPSIS
    Map an Astrum destination to a traversal-safe extraction-relative path.
  .PARAMETER Path
    Decoded compiled destination.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Path)
  $Normalized = $Path.Replace('/', '\')
  if ($Normalized -match '^(?i)<InstallDir>[\\](?<Rest>.+)$') { return $Matches.Rest }
  if ($Normalized -match '^<(?<Root>[A-Za-z0-9]+)>[\\]?(?<Rest>.*)$') {
    $Rest = $Matches.Rest
    return [string]::IsNullOrWhiteSpace($Rest) ? "_destinations\$($Matches.Root)" : "_destinations\$($Matches.Root)\$Rest"
  }
  return "_destinations\Other\$($Normalized.TrimStart('\'))"
}

function Get-AstrumPreCatalogRawRanges {
  <#
  .SYNOPSIS
    Locate pre-catalog bytes not owned by the decoded configuration or generated uninstaller routes.
  .PARAMETER Context
    Validated Astrum context containing overlay, footer, and routed ranges.
  .OUTPUTS
    Bounded raw ranges that may contain compiled dialogs, images, or other runtime resources.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)]$Context)

  $Start = [long]$Context.OverlayOffset
  $End = [long]$Context.Footer.InstallationItemOffset
  if ($End -le $Start) { return @() }
  $Owned = [Collections.Generic.List[object]]::new()
  $Owned.Add([pscustomobject]@{ Offset = [long]$Context.Footer.ConfigurationOffset; Length = [long]$Context.Footer.ConfigurationSize })
  if ($Context.Footer.UninstallerCompressedSize -gt 0) { $Owned.Add([pscustomobject]@{ Offset = [long]$Context.Footer.UninstallerOffset; Length = [long]$Context.Footer.UninstallerCompressedSize }) }
  $Cursor = $Start
  $Ranges = [Collections.Generic.List[object]]::new()
  foreach ($Range in @($Owned | Sort-Object Offset)) {
    $RangeStart = [Math]::Max($Start, [long]$Range.Offset)
    $RangeEnd = [Math]::Min($End, [long]$Range.Offset + [long]$Range.Length)
    if ($RangeEnd -le $Start -or $RangeStart -ge $End) { continue }
    if ($RangeStart -gt $Cursor) { $Ranges.Add([pscustomobject]@{ Offset = $Cursor; Length = $RangeStart - $Cursor }) }
    $Cursor = [Math]::Max($Cursor, $RangeEnd)
  }
  if ($Cursor -lt $End) { $Ranges.Add([pscustomobject]@{ Offset = $Cursor; Length = $End - $Cursor }) }
  return @($Ranges)
}

function Export-AstrumFileRecord {
  <#
  .SYNOPSIS
    Export one stored or gzip-compressed Astrum file record.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Record
    Validated file-catalog record.
  .PARAMETER DestinationPath
    Exact resolved output path.
  .PARAMETER MaximumBytes
    Remaining output allowance.
  #>
  [OutputType([IO.FileInfo])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$DestinationPath, [Parameter(Mandatory)][long]$MaximumBytes)
  if ($Record.ExpectedSize -gt $MaximumBytes) { throw "Astrum payload '$($Record.Path)' exceeds the remaining $MaximumBytes-byte output limit." }
  $Parent = Split-Path -Parent $DestinationPath
  if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
  $Output = [IO.File]::Open($DestinationPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    if ($Record.Compression -eq 'GZip') {
      $CompressedStream = New-BoundedReadStream -Stream $Stream -Offset $Record.DataOffset -Length $Record.CompressedSize -LeaveOpen
      try { $null = Expand-InstallerCompressedStream -Algorithm GZip -Stream $CompressedStream -Destination $Output -MaximumBytes $MaximumBytes -CompressedSize $Record.CompressedSize -UncompressedSize $Record.ExpectedSize } finally { $CompressedStream.Dispose() }
    } else {
      Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $Record.DataOffset -Length $Record.CompressedSize
    }
  } catch {
    $Output.Dispose()
    Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
    throw
  } finally { if ($Output) { $Output.Dispose() } }
  return Get-Item -LiteralPath $DestinationPath -Force
}

function Get-AstrumInstallWizardContext {
  <#
  .SYNOPSIS
    Build one reusable Astrum layout, configuration, and payload context.
  .PARAMETER File
    Resolved installer file.
  .PARAMETER Stream
    Caller-owned installer stream.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.FileInfo]$File, [Parameter(Mandatory)][IO.Stream]$Stream)
  $Layout = Get-PELayout -Stream $Stream
  if (-not $Layout) { throw 'The file is not a valid PE image.' }
  $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
  $Trailer = Read-AstrumTrailer -Stream $Stream -Layout $Layout -OverlayOffset $OverlayOffset
  $Footer = Read-AstrumFooter -Stream $Stream -Trailer $Trailer
  $Encoded = Read-BinaryBytes -Stream $Stream -Offset $Footer.ConfigurationOffset -Count ([int]$Footer.ConfigurationSize)
  $Decoded = ConvertFrom-AstrumProtectedBlock -Bytes (ConvertFrom-AstrumProtectedBlock -Bytes $Encoded)
  $Configuration = Read-AstrumConfiguration -Bytes $Decoded -Format $Trailer.Profile
  if ([string]::IsNullOrWhiteSpace($Configuration.ApplicationName) -or [string]::IsNullOrWhiteSpace($Configuration.CompanyName)) { throw 'The Astrum compiled configuration lacks package identity.' }
  $Items = @(Read-AstrumInstallationItems -Stream $Stream -Footer $Footer)
  $Files = @(Read-AstrumFileCatalog -Stream $Stream -Footer $Footer)
  foreach ($Record in $Files) {
    if ($Record.InstallationItemIndex -ge $Items.Count) { throw "Astrum file '$($Record.Path)' references an absent installation-item group." }
  }
  [pscustomobject]@{ File = $File; Stream = $Stream; Layout = $Layout; OverlayOffset = $OverlayOffset; LogicalEnd = $Trailer.LogicalEnd; Trailer = $Trailer; Footer = $Footer; Configuration = $Configuration; InstallationItems = $Items; Files = $Files }
}

function Read-AstrumTinyWrapper {
  <#
  .SYNOPSIS
    Validate the 2.29 tiny self-extractor descriptor and locate its inner GZip member.
  .PARAMETER Stream
    Caller-owned seekable outer PE stream.
  .PARAMETER OverlayOffset
    Absolute end of outer PE section data.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$OverlayOffset
  )

  if ($Stream.Length -lt $OverlayOffset + 18 + $Script:AstrumTinyFooterSize) { throw 'The Astrum tiny wrapper is too short.' }
  $FooterOffset = $Stream.Length - $Script:AstrumTinyFooterSize
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $FooterOffset -Count $Script:AstrumTinyFooterSize
  if ($Bytes[0..63] | Where-Object { $_ -ne 0 } | Select-Object -First 1) { throw 'The Astrum tiny wrapper reserved prefix is invalid.' }
  $Version = Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x40
  $Reserved1 = Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x44
  $SilentExtraction = Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x48
  $Reserved2 = Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x4C
  $Reserved3 = Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x50
  $DeclaredLength = [long](Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x54)
  $DeclaredOverlay = [long](Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x58)
  $CompressedEnd = [long](Read-AstrumUInt32FromBytes -Bytes $Bytes -Offset 0x5C)
  if ($Version -ne 1 -or $Reserved1 -ne 0 -or $Reserved2 -ne 0 -or $Reserved3 -ne 0 -or $SilentExtraction -notin 0, 1) { throw 'The Astrum tiny wrapper descriptor flags are unsupported.' }
  if ($DeclaredLength -ne $Stream.Length -or $DeclaredOverlay -ne $OverlayOffset -or $CompressedEnd -ne $FooterOffset) { throw 'The Astrum tiny wrapper descriptor does not match its physical ranges.' }
  $Prefix = Read-BinaryBytes -Stream $Stream -Offset $OverlayOffset -Count 2
  if (-not (Test-BinarySequence -Left $Prefix -Right $Script:AstrumGZipMagic)) { throw 'The Astrum tiny wrapper does not contain the expected inner GZip member.' }

  [pscustomobject][ordered]@{
    Offset           = $FooterOffset
    Length           = $Script:AstrumTinyFooterSize
    Version          = $Version
    Variant          = $SilentExtraction -eq 1 ? 'Tiny' : 'TinyVerbose'
    SilentExtraction = $SilentExtraction -eq 1
    DataOffset       = $OverlayOffset
    CompressedSize   = $CompressedEnd - $OverlayOffset
    RawBytes         = $Bytes
  }
}

function Open-AstrumSpannedContainer {
  <#
  .SYNOPSIS
    Reconstruct the logical Astrum address space from a main setup and explicitly ordered volume files.
  .PARAMETER Stream
    Caller-owned main setup stream.
  .PARAMETER CompanionFile
    Resolved companion volumes in their physical sequence.
  .OUTPUTS
    A temporary seekable context whose Stream and Path must be disposed and deleted by the caller.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][IO.FileInfo[]]$CompanionFile
  )

  if ($CompanionFile.Count -eq 0) { throw 'Astrum spanned media requires explicitly ordered companion files.' }
  $Layout = Get-PELayout -Stream $Stream
  if (-not $Layout) { throw 'The Astrum spanned main file is not a valid PE.' }
  $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
  $Trailer = Read-AstrumTrailer -Stream $Stream -Layout $Layout -OverlayOffset $OverlayOffset
  if (-not $Trailer.Profile.SupportsSpanned -or $Trailer.TrailerRoute -cne 'DualMagic') { throw "Astrum spanned reconstruction is unsupported for format '$($Trailer.FormatId)' and trailer route '$($Trailer.TrailerRoute)'." }
  $LogicalEnd = [long]$Trailer.LogicalEnd
  $FooterOffset = [long]$Trailer.FooterOffset
  $FooterLength = [long]$Trailer.FooterLength
  $FooterBytes = Read-BinaryBytes -Stream $Stream -Offset $FooterOffset -Count ([int]$FooterLength)
  $FooterOffsets = $Trailer.Profile.FooterOffsets
  if ((Read-AstrumUInt32FromBytes -Bytes $FooterBytes -Offset ([int]$FooterOffsets.SelfPointer) -Endian BigEndian) -ne $FooterOffset) { throw 'The Astrum spanned footer self pointer is invalid.' }
  $FileOffset = [long](Read-AstrumUInt32FromBytes -Bytes $FooterBytes -Offset ([int]$FooterOffsets.FileOffset) -Endian BigEndian)
  $PayloadSize = [long](Read-AstrumUInt32FromBytes -Bytes $FooterBytes -Offset ([int]$FooterOffsets.PayloadSize) -Endian BigEndian)
  $VirtualFooterOffset = $FileOffset + $PayloadSize
  $RequiredContinuation = $VirtualFooterOffset - $FooterOffset
  $CompanionLength = [long](($CompanionFile | Measure-Object Length -Sum).Sum)
  if ($RequiredContinuation -le 0 -or $CompanionLength -ne $RequiredContinuation) { throw "The Astrum companion volumes contain $CompanionLength bytes; the catalog requires $RequiredContinuation bytes." }
  if ($VirtualFooterOffset -gt [uint32]::MaxValue) { throw 'The Astrum spanned logical footer exceeds the 32-bit address space.' }

  $TemporaryPath = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-Astrum-$([guid]::NewGuid().ToString('N')).tmp"
  $Output = [IO.File]::Open($TemporaryPath, 'CreateNew', 'ReadWrite', 'Read')
  try {
    Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset 0 -Length $FooterOffset
    foreach ($Companion in $CompanionFile) {
      $Volume = [IO.File]::Open($Companion.FullName, 'Open', 'Read', 'Read')
      try { Copy-BinaryStreamRange -Source $Volume -Destination $Output -Offset 0 -Length $Volume.Length } finally { $Volume.Dispose() }
    }
    Copy-BinaryStreamRange -Source $Stream -Destination $Output -Offset $FooterOffset -Length ($LogicalEnd - $FooterOffset)

    # The catalog uses virtual offsets already. Only the footer self pointer and trailer pointer were physical to the main EXE.
    $BigEndianFooter = [BitConverter]::GetBytes([uint32]$VirtualFooterOffset)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($BigEndianFooter) }
    $Output.Position = $VirtualFooterOffset + [int]$FooterOffsets.SelfPointer
    $Output.Write($BigEndianFooter, 0, 4)
    $Output.Position = $Trailer.PointerOffset + $RequiredContinuation
    $LittleEndianFooter = [BitConverter]::GetBytes([uint32]$VirtualFooterOffset)
    $Output.Write($LittleEndianFooter, 0, 4)
    $Output.Flush()
    $Output.Position = 0
    $VirtualFile = Get-Item -LiteralPath $TemporaryPath -Force
    $Context = Get-AstrumInstallWizardContext -File $VirtualFile -Stream $Output
    return [pscustomobject]@{ Context = $Context; Path = $TemporaryPath; Stream = $Output; VirtualFooterOffset = $VirtualFooterOffset; CompanionFiles = @($CompanionFile.FullName) }
  } catch {
    $Output.Dispose()
    Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
    throw
  }
}

function Close-AstrumInstallWizardContainer {
  <#
  .SYNOPSIS
    Dispose temporary resources owned by a resolved Astrum container envelope.
  .PARAMETER Container
    Envelope returned by Open-AstrumInstallWizardContainer.
  #>
  param ([AllowNull()]$Container)

  if (-not $Container -or -not $Container.OwnedResource) { return }
  if ($Container.OwnedResource -is [IDisposable]) {
    $Container.OwnedResource.Dispose()
    return
  }
  if ($Container.OwnedResource.Stream) { $Container.OwnedResource.Stream.Dispose() }
  if ($Container.OwnedResource.Path) { Remove-Item -LiteralPath $Container.OwnedResource.Path -Force -ErrorAction SilentlyContinue }
}

function Open-AstrumInstallWizardContainer {
  <#
  .SYNOPSIS
    Open a normal or tiny Astrum container and return one reusable inner analysis context.
  .PARAMETER File
    Resolved outer installer file.
  .PARAMETER Stream
    Caller-owned outer installer stream.
  .PARAMETER CompanionFile
    Resolved companion volumes in physical order when the outer setup uses spanned media.
  .OUTPUTS
    A context envelope. Dispose OwnedResource when it is non-null; the caller retains ownership of Stream.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [IO.FileInfo[]]$CompanionFile = @()
  )

  try {
    $Context = Get-AstrumInstallWizardContext -File $File -Stream $Stream
    $RoutePrefix = [string]$Context.Trailer.Profile.ContainerRoutePrefix
    $RouteVariant = if ($Context.Trailer.HasCertificate) { 'SignedSingleFile' } elseif (-not $Context.Trailer.HasMagic) { 'LegacySingleFile' } else { 'SingleFile' }
    $Route = "$RoutePrefix/$RouteVariant"
    return [pscustomobject]@{ Context = $Context; ContainerRoute = $Route; AnalysisPath = $File.FullName; TinyWrapper = $null; SpannedMedia = $null; OwnedResource = $null }
  } catch {
    $DirectFailure = $_
  }

  $SpannedFailure = $null
  if ($CompanionFile.Count -gt 0) {
    try {
      $Spanned = Open-AstrumSpannedContainer -Stream $Stream -CompanionFile $CompanionFile
      return [pscustomobject]@{ Context = $Spanned.Context; ContainerRoute = 'Astrum2/Spanned'; AnalysisPath = $Spanned.Path; TinyWrapper = $null; SpannedMedia = $Spanned; OwnedResource = $Spanned }
    } catch {
      $SpannedFailure = $_
    }
  }

  $OuterLayout = Get-PELayout -Stream $Stream
  if (-not $OuterLayout) { throw $DirectFailure }
  $OuterOverlay = Get-PEOverlayOffset -Stream $Stream
  try { $Tiny = Read-AstrumTinyWrapper -Stream $Stream -OverlayOffset $OuterOverlay } catch { if ($SpannedFailure) { throw $SpannedFailure }; throw $DirectFailure }

  $Range = New-BoundedReadStream -Stream $Stream -Offset $Tiny.DataOffset -Length $Tiny.CompressedSize -LeaveOpen
  $Decoder = [IO.Compression.GZipStream]::new($Range, [IO.Compression.CompressionMode]::Decompress, $false)
  try {
    # Force a temporary-file spill so path-only PE metadata helpers can inspect the inner runtime without buffering it.
    $Owned = New-InstallerSeekableStream -SourceStream $Decoder -MaximumBytes $Script:AstrumMaximumTinyExpandedBytes -MemoryThresholdBytes 1
  } finally {
    $Decoder.Dispose()
  }
  try {
    $InnerFile = Get-Item -LiteralPath $Owned.TemporaryPath -Force
    $Context = Get-AstrumInstallWizardContext -File $InnerFile -Stream $Owned.Stream
    if (-not $Context.Trailer.Profile.SupportsTiny) { throw "Astrum tiny-wrapper handling is unsupported for format '$($Context.Trailer.FormatId)'." }
    return [pscustomobject]@{ Context = $Context; ContainerRoute = "$($Context.Trailer.Profile.ContainerRoutePrefix)/$($Tiny.Variant)"; AnalysisPath = $Owned.TemporaryPath; TinyWrapper = $Tiny; SpannedMedia = $null; OwnedResource = $Owned }
  } catch {
    $Owned.Dispose()
    throw
  }
}

function Get-AstrumInstallWizardInfo {
  <#
  .SYNOPSIS
    Read Astrum InstallWizard metadata, ARP, operations, payload, and installability evidence.
  .PARAMETER Path
    Path to a structurally supported Astrum InstallWizard 1.x or 2.x installer. The file is opened once and never executed.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  .OUTPUTS
    The shared installer parser contract with additive Astrum format evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string[]]$CompanionFile = @()
  )
  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
    $ResolvedCompanions = @($CompanionFile | ForEach-Object { Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $_ -PathType Leaf) -Force })
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $ResolvedContainer = $null
    try {
      $ResolvedContainer = Open-AstrumInstallWizardContainer -File $File -Stream $Stream -CompanionFile $ResolvedCompanions
      $Context = $ResolvedContainer.Context
      $Configuration = $Context.Configuration
      $ExecutionLevel = Get-PERequestedExecutionLevel -Path $ResolvedContainer.AnalysisPath
      $OuterArchitecture = Get-PEArchitectureInfo -Path $ResolvedContainer.AnalysisPath
      $RuntimeCommandLineEvidence = Get-AstrumRuntimeCommandLineEvidence -Stream $Context.Stream
      # Astrum's x64-compliance option selects the native 64-bit registry view even
      # though the 2.29 setup runtime itself remains a 32-bit PE.
      $RegistryView = if ($Configuration.X64ComplianceMode) { '64-bit' } elseif ($OuterArchitecture.NativeArchitecture -eq 'x86') { '32-bit' } elseif ($OuterArchitecture.NativeArchitecture -in 'x64', 'arm64') { '64-bit' } else { 'default' }
      $InstallLocation = ConvertTo-AstrumManifestPath -Value $Configuration.InstallPath -Configuration $Configuration -RegistryView $RegistryView
      $RegistryWrites = @(ConvertTo-AstrumRegistryWrites -Configuration $Configuration -InstallLocation $InstallLocation -RegistryView $RegistryView)
      $ArpEntries = @(Get-AstrumArpEntries -RegistryWrites $RegistryWrites)
      $VisibleArp = @($ArpEntries | Where-Object IsVisible)
      $ArpScopes = @($ArpEntries.Scope | Where-Object { $_ -in 'user', 'machine' } | Sort-Object -Unique)
      $PrimaryArp = $VisibleArp.Count -eq 1 ? $VisibleArp[0] : $null
      $Diagnostics = [Collections.Generic.List[object]]::new()
      $UnresolvedFields = [Collections.Generic.List[string]]::new()
      if ($ResolvedContainer.TinyWrapper) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Container.TinyWrapper' -Source 'Astrum InstallWizard' -Message "The outer $($ResolvedContainer.TinyWrapper.Variant) self-extractor contains a validated GZip-compressed Astrum installer; metadata and payload evidence come from the inner installer." -Kind Information -Areas Detection, Extraction -Evidence $ResolvedContainer.TinyWrapper)) }
      if ($ResolvedContainer.SpannedMedia) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Container.SpannedMedia' -Source 'Astrum InstallWizard' -Message "The logical Astrum catalog was reconstructed from $($ResolvedCompanions.Count) explicitly ordered companion volume(s)." -Kind Information -Areas Detection, Extraction -Evidence $ResolvedContainer.SpannedMedia.CompanionFiles)) }
      if ($VisibleArp.Count -gt 1) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Arp.Ambiguous' -Source 'Astrum InstallWizard' -Message 'The compiled installer contains more than one visible unconditional Apps & Features registration.' -Kind Ambiguous -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence $VisibleArp)) }
      if ($ArpScopes.Count -gt 1) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Scope.Ambiguous' -Source 'Astrum InstallWizard' -Message 'The compiled installer contains unconditional uninstall registry entries in both user and machine hives.' -Kind Ambiguous -Areas Metadata, Installability -AffectedFields Scope -Evidence $ArpEntries)) }
      foreach ($Entry in $VisibleArp) {
        if (-not (Test-AstrumResolvedValue -Value $Entry.ProductCode)) {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Arp.Unresolved.ProductCode' -Source 'Astrum InstallWizard' -Message 'The compiled Apps & Features key contains an unresolved Astrum variable and was retained only as raw ARP evidence.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries -Evidence ([ordered]@{ ProductCode = $Entry.ProductCode })))
        }
        foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'InstallLocation', 'UninstallString', 'QuietUninstallString', 'DisplayIcon') {
          $Value = $Entry.$Field
          if (-not [string]::IsNullOrWhiteSpace([string]$Value) -and -not (Test-AstrumResolvedValue -Value $Value)) {
            $UnresolvedFields.Add($Field)
            $Diagnostics.Add((New-InstallerDiagnostic -Id "Astrum.Arp.Unresolved.$Field" -Source 'Astrum InstallWizard' -Message "The compiled Apps & Features $Field contains an unresolved Astrum variable and was retained only as raw ARP evidence." -Kind Incomplete -Areas Metadata -AffectedFields $Field, AppsAndFeaturesEntries -Evidence ([ordered]@{ ProductCode = $Entry.ProductCode; Value = $Value })))
          }
        }
      }
      if ($Context.Files | Where-Object IsConditional) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Payload.Conditional' -Source 'Astrum InstallWizard' -Message 'Some payload files are conditional; extraction returns their physical content but installed-state selection requires condition or VM evidence.' -Kind ManualValidation -Areas Extraction, Installability -AffectedFields InstallationMetadata)) }
      # Both execute variants launch an external program. The wait variant differs only in whether
      # Astrum blocks until the child exits, so it requires the same nested-payload analysis.
      $ExecutedPayloads = @($Configuration.InteractiveOperations | Where-Object { $_.ActionCode -in 0, 6 })
      if ($ExecutedPayloads.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Execution.NestedPayload' -Source 'Astrum InstallWizard' -Message 'The compiled configuration executes one or more nested programs; their side effects require separate analysis.' -Kind ManualValidation -Areas Installability, Security -AffectedFields InstallerSwitches -Evidence $ExecutedPayloads)) }
      $UnknownOperationEvidence = [Collections.Generic.List[object]]::new()
      foreach ($Record in $Configuration.TextOperations) { if ([string]::IsNullOrWhiteSpace([string]$Record.OperationName)) { $UnknownOperationEvidence.Add([pscustomobject]@{ Table = 'Text'; Code = $Record.Operation }) } }
      foreach ($Record in $Configuration.FileOperations) {
        if ([string]::IsNullOrWhiteSpace([string]$Record.ActionName)) { $UnknownOperationEvidence.Add([pscustomobject]@{ Table = 'File'; Code = $Record.ActionCode }) }
        if ([string]::IsNullOrWhiteSpace([string]$Record.TimingName)) { $UnknownOperationEvidence.Add([pscustomobject]@{ Table = 'FileTiming'; Code = $Record.Timing }) }
      }
      foreach ($Record in $Configuration.InteractiveOperations) {
        if ([string]::IsNullOrWhiteSpace([string]$Record.ActionName)) { $UnknownOperationEvidence.Add([pscustomobject]@{ Table = 'Interactive'; Code = $Record.ActionCode }) }
        if ([string]::IsNullOrWhiteSpace([string]$Record.TimingName)) { $UnknownOperationEvidence.Add([pscustomobject]@{ Table = 'InteractiveTiming'; Code = $Record.Timing }) }
      }
      if ($UnknownOperationEvidence.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Operation.UnknownCode' -Source 'Astrum InstallWizard' -Message 'The compiled configuration contains operation or timing values outside the source-backed Astrum enum tables.' -Kind Unsupported -Areas Metadata, Installability -Evidence @($UnknownOperationEvidence))) }
      $UnknownVariableEvidence = [Collections.Generic.List[object]]::new()
      $KnownVariableFlags = [uint32]$Script:AstrumVariableSemantics.Flags.StoreDriveOnly -bor [uint32]$Script:AstrumVariableSemantics.Flags.SetTrueIfExists -bor [uint32]$Script:AstrumVariableSemantics.Flags.UserVisible
      foreach ($Variable in $Configuration.Variables) {
        if ([string]::IsNullOrWhiteSpace([string]$Variable.TypeName)) { $UnknownVariableEvidence.Add([pscustomobject]@{ Variable = $Variable.Name; Field = 'TypeCode'; Value = $Variable.TypeCode }) }
        if ([string]::IsNullOrWhiteSpace([string]$Variable.SourceName)) { $UnknownVariableEvidence.Add([pscustomobject]@{ Variable = $Variable.Name; Field = 'SourceCode'; Value = $Variable.SourceCode }) }
        $UnknownFlags = [uint32]$Variable.Flags -band (-bnot $KnownVariableFlags)
        if ($UnknownFlags -ne 0) { $UnknownVariableEvidence.Add([pscustomobject]@{ Variable = $Variable.Name; Field = 'Flags'; Value = $Variable.Flags; UnknownBits = $UnknownFlags }) }
      }
      if ($UnknownVariableEvidence.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Variable.UnknownCode' -Source 'Astrum InstallWizard' -Message 'The compiled configuration contains custom-variable values outside the source-backed Astrum type, source, or option tables.' -Kind Unsupported -Areas Metadata, Installability -Evidence @($UnknownVariableEvidence))) }
      if ($Configuration.PostInteractiveRecords.Count) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.PostInteractive.SemanticsIncomplete' -Source 'Astrum InstallWizard' -Message 'The compiled configuration contains additional 2.x post-interactive records whose field semantics remain only partly assigned.' -Kind Incomplete -Areas Metadata, Installability -Evidence $Configuration.PostInteractiveRecords)) }
      $Scope = $ArpScopes.Count -eq 1 ? $ArpScopes[0] : $null
      if (-not $Scope) {
        if ($ExecutionLevel -eq 'requireAdministrator') { $Scope = 'machine' }
        elseif ($ExecutionLevel -eq 'asInvoker' -and $InstallLocation -match '^%(?:LOCALAPPDATA|APPDATA|USERPROFILE)%') { $Scope = 'user' }
      }
      if (-not $Scope) { $UnresolvedFields.Add('Scope') }
      $SupportedScopes = $Scope ? @($Scope) : @('machine', 'user')
      # A manifest requesting asInvoker does not make machine-protected writes usable without
      # elevation. Controlled Modern2 validation proves that this route refuses cleanly when
      # unelevated, while the same artifact installs when its caller is already elevated.
      $RequiresProtectedMachineWrites = $Scope -eq 'machine' -and (
        @($RegistryWrites | Where-Object Root -EQ 'HKLM').Count -gt 0 -or
        $InstallLocation -match '^%(?:ProgramFiles(?:\(x86\))?|WINDIR|SystemRoot)%'
      )
      $ElevationRequirement = if ($ExecutionLevel -eq 'requireAdministrator' -or $Configuration.RequireAdmin -or $RequiresProtectedMachineWrites) { 'elevationRequired' } else { $null }
      if ($RequiresProtectedMachineWrites -and $ExecutionLevel -eq 'asInvoker' -and -not $Configuration.RequireAdmin) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Elevation.CallerRequired' -Source 'Astrum InstallWizard' -Message 'The installer requests as-invoker execution but targets machine-protected registry or file-system state. It must be started by an elevated caller; controlled VM validation shows that unelevated /silent execution refuses without partial installation.' -Kind Information -Areas Installability -AffectedFields ElevationRequirement -Evidence ([ordered]@{ RequestedExecutionLevel = $ExecutionLevel; Scope = $Scope; InstallLocation = $InstallLocation })))
      }
      $AssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
      foreach ($Diagnostic in $AssociationInfo.Diagnostics) { $Diagnostics.Add($Diagnostic) }

      $PayloadArchitectureInfo = @()
      $PayloadDependencyInfo = $null
      $PayloadArchitectures = @()
      $AnalysisRecords = [Collections.Generic.List[object]]::new()
      $AnalysisBytes = 0L
      foreach ($Record in $Context.Files) {
        if ($AnalysisRecords.Count -ge 32 -or $Record.Path -notmatch '(?i)\.(?:exe|dll)$' -or $Record.ExpectedSize -gt $Script:AstrumMaximumAnalysisBytes - $AnalysisBytes) { continue }
        $AnalysisRecords.Add($Record)
        $AnalysisBytes += $Record.ExpectedSize
      }
      if ($AnalysisRecords.Count) {
        $TemporaryDirectory = New-TempFolder
        try {
          $MaterializedPaths = [Collections.Generic.List[string]]::new()
          $RemainingAnalysisBytes = $Script:AstrumMaximumAnalysisBytes
          for ($Index = 0; $Index -lt $AnalysisRecords.Count; $Index++) {
            $Record = $AnalysisRecords[$Index]
            $TemporaryPath = Join-Path $TemporaryDirectory ('{0:D3}-{1}' -f $Index, [IO.Path]::GetFileName($Record.Path))
            $null = Export-AstrumFileRecord -Stream $Context.Stream -Record $Record -DestinationPath $TemporaryPath -MaximumBytes $RemainingAnalysisBytes
            $MaterializedPaths.Add($TemporaryPath)
            $RemainingAnalysisBytes -= $Record.ExpectedSize
          }
          $ArchitectureResults = [Collections.Generic.List[object]]::new()
          foreach ($MaterializedPath in $MaterializedPaths) {
            try { $ArchitectureResults.Add((Get-PEArchitectureInfo -Path $MaterializedPath)) } catch { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Payload.ArchitectureUnavailable' -Source 'Astrum InstallWizard' -Message "Payload architecture analysis failed for '$([IO.Path]::GetFileName($MaterializedPath))': $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Architecture)) }
          }
          $PayloadArchitectureInfo = @($ArchitectureResults)
          $PayloadArchitectures = @($ArchitectureResults.RecommendedWinGetArchitectures | Where-Object { $_ -in 'x86', 'x64', 'arm64' } | Sort-Object -Unique)
          try { $PayloadDependencyInfo = Get-PEDependencyInfo -Path $MaterializedPaths[0] -RelatedFile @($MaterializedPaths | Select-Object -Skip 1) } catch { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Payload.DependenciesUnavailable' -Source 'Astrum InstallWizard' -Message "Payload dependency analysis failed: $($_.Exception.Message)" -Kind Incomplete -Areas Metadata -AffectedFields Dependencies)) }
        } finally { Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
      }

      $DisplayName = $PrimaryArp -and (Test-AstrumResolvedValue -Value $PrimaryArp.DisplayName) ? $PrimaryArp.DisplayName : $Configuration.ApplicationName
      $DisplayVersion = $PrimaryArp -and (Test-AstrumResolvedValue -Value $PrimaryArp.DisplayVersion) ? $PrimaryArp.DisplayVersion : $Configuration.ApplicationVersion
      $Publisher = $PrimaryArp -and (Test-AstrumResolvedValue -Value $PrimaryArp.Publisher) ? $PrimaryArp.Publisher : $Configuration.CompanyName
      if (-not $DisplayVersion) { $UnresolvedFields.Add('DisplayVersion') }
      # Keep dynamic uninstall-key templates in ArpEntries, but never expose them as matching
      # evidence. A guessed ProductCode can bind WinGet to an unrelated installed package.
      $ProductCode = $PrimaryArp -and (Test-AstrumResolvedValue -Value $PrimaryArp.ProductCode) ? $PrimaryArp.ProductCode : $null
      if (-not $ProductCode) { $UnresolvedFields.Add('ProductCode') }
      $WritesArp = $VisibleArp.Count -gt 0
      $AppsAndFeaturesEntries = @($VisibleArp | ForEach-Object { ConvertTo-AstrumAppsAndFeaturesEntry -Entry $_ })
      $LicenseDialogSelected = Test-AstrumCompiledDialog -Context $Context -Marker $Script:AstrumLicenseDialogMarker
      # The compiled User Information dialog only blocks /silent for generations whose profile keeps
      # the documented claim; VM installations of Modern2 media prove the 2.29.50 runtime skips it.
      $UserInformationBlocksSilent = (Test-AstrumCompiledDialog -Context $Context -Marker $Script:AstrumUserInformationDialogMarker) -and $Configuration.UserInformationBlocksSilent
      $LicenseRequired = $LicenseDialogSelected -and $Configuration.ProhibitSilentInstallation
      $SupportsSilentInstallation = switch ($Configuration.SilentRoute) {
        'RuntimeSwitchEvidence' { $RuntimeCommandLineEvidence.SupportsSilent ? (-not $UserInformationBlocksSilent) : $null }
        'Documented2' { -not $UserInformationBlocksSilent }
        default { throw "Astrum configuration profile '$($Configuration.ConfigurationProfile)' uses an unsupported silent-installation route '$($Configuration.SilentRoute)'." }
      }
      $InstallerSwitches = [ordered]@{}
      $InstallModes = @('interactive')
      if ($SupportsSilentInstallation -eq $true) {
        $InstallerSwitches['Silent'] = '/silent'
        $InstallerSwitches['SilentWithProgress'] = '/silent'
        if ($LicenseRequired) { $InstallerSwitches['Custom'] = '/AcceptLicense' }
        $InstallModes = @('interactive', 'silent')
      }
      if ($UserInformationBlocksSilent) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Silent.UserInformationDialog' -Source 'Astrum InstallWizard' -Message 'The compiled installer includes the standard User Information dialog. Astrum documents that this dialog makes /silent fail, so this artifact is interactive-only.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $Configuration.UserInformationEvidence))
      } elseif (Test-AstrumCompiledDialog -Context $Context -Marker $Script:AstrumUserInformationDialogMarker) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Silent.UserInformationDialogIgnored' -Source 'Astrum InstallWizard' -Message 'The compiled installer includes the standard User Information dialog, but this generation''s runtime skips it under /silent; VM installation evidence shows unattended installation succeeds.' -Kind Information -Areas Installability -Evidence $Configuration.UserInformationEvidence))
      }
      if ($LicenseRequired) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Silent.LicenseAcceptance' -Source 'Astrum InstallWizard' -Message 'The selected license dialog prohibits unattended installation unless /AcceptLicense is supplied.' -Kind Information -Areas Installability -AffectedFields InstallerSwitches)) }
      if ($null -eq $SupportsSilentInstallation) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Silent.LegacyRuntimeVersionRequired' -Source 'Astrum InstallWizard' -Message 'This Astrum 1.x runtime does not expose a validated /SILENT token in its bounded native option table. Establish the builder subversion or validate unattended behavior in a VM before authoring it.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes)) }
      if ($Configuration.NoUninstallation) { $Diagnostics.Add((New-InstallerDiagnostic -Id 'Astrum.Uninstall.Disabled' -Source 'Astrum InstallWizard' -Message 'The compiled configuration disables generated uninstallation. Explicit ARP registry records are retained as evidence, but their uninstall command may be unusable unless custom logic supplies it.' -Kind Risk -Areas Metadata, Installability -AffectedFields ProductCode, AppsAndFeaturesEntries)) }

      [pscustomobject][ordered]@{
        Path                                     = $File.FullName
        InstallerType                            = 'exe'
        Family                                   = 'Astrum InstallWizard'
        ProductCode                              = $ProductCode
        UpgradeCode                              = $null
        DisplayName                              = $DisplayName
        DisplayVersion                           = $DisplayVersion
        Publisher                                = $Publisher
        Scope                                    = $Scope
        DefaultInstallLocation                   = $PrimaryArp -and $PrimaryArp.InstallLocation ? $PrimaryArp.InstallLocation : $InstallLocation
        WritesAppsAndFeaturesEntry               = $WritesArp
        AppsAndFeaturesProductCode               = $ProductCode
        AppsAndFeaturesInstallerType             = $null
        AppsAndFeaturesEntries                   = $AppsAndFeaturesEntries
        CanExpand                                = $true
        ExtractedFiles                           = @($Context.Files.Path)
        FormatCatalogId                          = [string]$Context.Trailer.FormatId
        FormatGeneration                         = $Context.Trailer.FormatGeneration
        ConfigurationProfile                     = $Configuration.ConfigurationProfile
        ConfigurationProfileObservedVersionRange = $Configuration.ConfigurationProfileObservedVersionRange
        ContainerRoute                           = $ResolvedContainer.ContainerRoute
        TinyWrapper                              = $ResolvedContainer.TinyWrapper
        CompanionFiles                           = @($ResolvedCompanions.FullName)
        RequestedExecutionLevel                  = $ExecutionLevel
        ElevationRequirement                     = $ElevationRequirement
        SupportedScopes                          = $SupportedScopes
        RegistryView                             = $RegistryView
        RegistryWrites                           = $RegistryWrites
        ArpEntries                               = $ArpEntries
        UninstallString                          = $PrimaryArp -and (Test-AstrumResolvedValue -Value $PrimaryArp.UninstallString) ? $PrimaryArp.UninstallString : $null
        QuietUninstallString                     = $PrimaryArp -and (Test-AstrumResolvedValue -Value $PrimaryArp.QuietUninstallString) ? $PrimaryArp.QuietUninstallString : $null
        DisplayIcon                              = $PrimaryArp -and (Test-AstrumResolvedValue -Value $PrimaryArp.DisplayIcon) ? $PrimaryArp.DisplayIcon : $null
        Protocols                                = @($AssociationInfo.Protocols)
        FileExtensions                           = @($AssociationInfo.FileExtensions)
        ProtocolAssociations                     = @($AssociationInfo.ProtocolAssociations)
        FileExtensionAssociations                = @($AssociationInfo.FileExtensionAssociations)
        RegistryAssociationInfo                  = $AssociationInfo
        Shortcuts                                = @($Configuration.Shortcuts)
        IniOperations                            = @($Configuration.IniOperations)
        TextOperations                           = @($Configuration.TextOperations)
        FileOperations                           = @($Configuration.FileOperations)
        InteractiveOperations                    = @($Configuration.InteractiveOperations)
        PostInteractiveRecords                   = @($Configuration.PostInteractiveRecords)
        ExecutedPayloads                         = $ExecutedPayloads
        Variables                                = @($Configuration.Variables)
        Requirements                             = $Configuration.Requirements
        Conditions                               = @($RegistryWrites.Condition | Where-Object { $_ }) + @($Context.Files | Where-Object IsConditional)
        InstallationItems                        = @($Context.InstallationItems)
        PayloadCatalog                           = @($Context.Files)
        ResourceFiles                            = @($Context.Files | Where-Object IsResourceFile)
        CompressionEvidence                      = @($Context.Files | Group-Object Compression | ForEach-Object { [pscustomobject]@{ Algorithm = $_.Name; Count = $_.Count } })
        OuterArchitectureInfo                    = $OuterArchitecture
        PayloadArchitectureInfo                  = $PayloadArchitectureInfo
        PayloadArchitectures                     = $PayloadArchitectures
        DependencyInfo                           = $PayloadDependencyInfo
        InstallerSwitches                        = $InstallerSwitches
        InstallModes                             = $InstallModes
        InstallerSuccessCodes                    = @($Context.Trailer.Profile.InstallerSuccessCodes)
        SupportsSilentInstallation               = $SupportsSilentInstallation
        RuntimeCommandLineEvidence               = $RuntimeCommandLineEvidence
        LicenseDialogSelected                    = $LicenseDialogSelected
        LicenseAcceptanceRequired                = $LicenseRequired
        UserInformationBlocksSilent              = $UserInformationBlocksSilent
        SilentInstallationDefault                = $Configuration.SilentInstallationDefault
        NoUninstallation                         = $Configuration.NoUninstallation
        X64ComplianceMode                        = $Configuration.X64ComplianceMode
        RequireAdmin                             = $Configuration.RequireAdmin
        Trailer                                  = $Context.Trailer
        Footer                                   = $Context.Footer
        Configuration                            = $Configuration
        ParserVersionInfo                        = [pscustomobject]@{ Parser = 'Astrum InstallWizard'; CatalogVersion = [int]$Script:AstrumFormatCatalog.CatalogVersion; FormatId = [string]$Context.Trailer.FormatId; FormatGeneration = $Context.Trailer.FormatGeneration; ConfigurationProfile = $Configuration.ConfigurationProfile; ConfigurationProfileObservedVersionRange = $Configuration.ConfigurationProfileObservedVersionRange; RuntimeFormat = $Configuration.RuntimeFormat; ContainerRoute = $ResolvedContainer.ContainerRoute; Evidence = @('validated catalog-selected trailer/footer', 'twice checksum-protected configuration', 'installation-item and file catalogs', 'compiled standard-dialog resources', 'bounded native runtime command-line option table', 'catalog-selected configuration and file descriptors') }
        Diagnostics                              = @(Merge-InstallerDiagnostics -Diagnostic @($Diagnostics))
        UnresolvedFields                         = @($UnresolvedFields | Sort-Object -Unique)
      }
    } finally {
      Close-AstrumInstallWizardContainer -Container $ResolvedContainer
      $Stream.Dispose()
    }
  }
}

function Test-AstrumInstallWizard {
  <#
  .SYNOPSIS
    Test whether a PE contains a structurally valid Astrum InstallWizard payload.
  .PARAMETER Path
    Candidate installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string[]]$CompanionFile = @()
  )
  process {
    try {
      $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
      $ResolvedCompanions = @($CompanionFile | ForEach-Object { Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $_ -PathType Leaf) -Force })
      $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
      $ResolvedContainer = $null
      try { $ResolvedContainer = Open-AstrumInstallWizardContainer -File $File -Stream $Stream -CompanionFile $ResolvedCompanions; return $true } finally { Close-AstrumInstallWizardContainer -Container $ResolvedContainer; $Stream.Dispose() }
    } catch { return $false }
  }
}

function Expand-AstrumInstallWizard {
  <#
  .SYNOPSIS
    Expand installed or raw records from an Astrum InstallWizard installer.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER DestinationPath
    Output directory. Relative paths are resolved before managed stream access.
  .PARAMETER Name
    Optional wildcard matched against decoded installer destinations. Omission expands all payload files.
  .PARAMETER CollisionAction
    Existing-output policy. Prompt asks only after a collision is found.
  .PARAMETER RawEntries
    Include decoded configuration, footer, record headers, pre-catalog ranges, companion volumes, and otherwise unplaced uninstaller data under `_astrum`.
  .PARAMETER CompanionFile
    Explicit companion-volume paths in physical sequence for spanned media.
  .PARAMETER MaximumExpandedBytes
    Aggregate output bound in bytes.
  .PARAMETER MaximumEntries
    Maximum number of output files.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [switch]$RawEntries,
    [string[]]$CompanionFile = @(),
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 17179869184,
    [ValidateRange(1, 65536)][int]$MaximumEntries = $Script:AstrumMaximumFiles
  )
  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
    $Destination = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $Destination -ItemType Directory -Force
    $ResolvedCompanions = @($CompanionFile | ForEach-Object { Resolve-InstallerFileSystemPath -Path $_ -PathType Leaf })
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $ResolvedContainer = $null
    try {
      $ResolvedContainer = Open-AstrumInstallWizardContainer -File $File -Stream $Stream -CompanionFile @($ResolvedCompanions | ForEach-Object { Get-Item -LiteralPath $_ -Force })
      $Context = $ResolvedContainer.Context
      $Pattern = [string]::IsNullOrWhiteSpace($Name) ? '*' : $Name
      $Selected = @($Context.Files | Where-Object { Test-ExtractionPattern -Path $_.Path -Pattern $Pattern })
      $RegistryView = $Context.Configuration.X64ComplianceMode ? '64-bit' : '32-bit'
      $InstallLocation = ConvertTo-AstrumManifestPath -Value $Context.Configuration.InstallPath -Configuration $Context.Configuration -RegistryView $RegistryView
      $RegistryWrites = @(ConvertTo-AstrumRegistryWrites -Configuration $Context.Configuration -InstallLocation $InstallLocation -RegistryView $RegistryView)
      $PrimaryArp = @(Get-AstrumArpEntries -RegistryWrites $RegistryWrites | Where-Object IsVisible | Select-Object -First 1)[0]
      $UninstallerRelativePath = if ($Context.Footer.UninstallerCompressedSize -gt 0) {
        $FromArp = $PrimaryArp ? (Get-AstrumUninstallerRelativePath -UninstallString $PrimaryArp.UninstallString -InstallLocation $InstallLocation) : $null
        if ($FromArp) { $FromArp } else {
          $ConfiguredUninstaller = Resolve-AstrumVariables -Value $Context.Configuration.UninstallerName -Configuration $Context.Configuration -InstallLocation $InstallLocation -RegistryView $RegistryView
          Get-AstrumUninstallerRelativePath -UninstallString $ConfiguredUninstaller -InstallLocation $InstallLocation
        }
      } else { $null }
      $IncludeInstalledUninstaller = $UninstallerRelativePath -and (Test-ExtractionPattern -Path "<InstallDir>\$UninstallerRelativePath" -Pattern $Pattern)
      $RawPreCatalogRanges = $RawEntries ? @(Get-AstrumPreCatalogRawRanges -Context $Context) : @()
      $RawWrapperEntryCount = [int][bool]($RawEntries -and $ResolvedContainer.TinyWrapper) + ($RawEntries ? $ResolvedCompanions.Count : 0)
      $RequestedEntryCount = $Selected.Count + [int][bool]$IncludeInstalledUninstaller + ($RawEntries ? 2 + $Context.Files.Count + $RawPreCatalogRanges.Count + [int]($Context.Footer.UninstallerCompressedSize -gt 0 -and -not $IncludeInstalledUninstaller) + $RawWrapperEntryCount : 0)
      if ($RequestedEntryCount -gt $MaximumEntries) { throw "The Astrum selection exceeds the $MaximumEntries-entry limit." }
      $Files = [Collections.Generic.List[IO.FileInfo]]::new()
      $Reserved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $Expanded = 0L
      foreach ($Record in $Selected) {
        if ($Record.ExpectedSize -gt $MaximumExpandedBytes - $Expanded) { throw "The Astrum selection exceeds the $MaximumExpandedBytes-byte output limit." }
        $RelativePath = Get-AstrumInstalledRelativePath -Path $Record.Path
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $Reserved
        if (-not $Target.ShouldWrite) { continue }
        $Output = Export-AstrumFileRecord -Stream $Context.Stream -Record $Record -DestinationPath $Target.Path -MaximumBytes ($MaximumExpandedBytes - $Expanded)
        $Expanded += $Output.Length
        $Files.Add($Output)
      }
      if ($IncludeInstalledUninstaller) {
        if (-not (Test-AstrumRange $Context.Footer.UninstallerOffset $Context.Footer.UninstallerCompressedSize $Context.Footer.Offset)) { throw 'The Astrum uninstaller range is malformed.' }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath $UninstallerRelativePath -CollisionAction $CollisionAction -ReservedPath $Reserved
        if ($Target.ShouldWrite) {
          $CompressedStream = New-BoundedReadStream -Stream $Context.Stream -Offset $Context.Footer.UninstallerOffset -Length $Context.Footer.UninstallerCompressedSize -LeaveOpen
          $OutputStream = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
          try { $Size = Expand-InstallerCompressedStream -Algorithm GZip -Stream $CompressedStream -Destination $OutputStream -MaximumBytes ($MaximumExpandedBytes - $Expanded) } finally { $OutputStream.Dispose(); $CompressedStream.Dispose() }
          $Output = Get-Item -LiteralPath $Target.Path -Force
          $Expanded += $Size
          $Files.Add($Output)
        }
      }
      if ($RawEntries) {
        $Raw = @(
          @{ RelativePath = '_astrum\configuration.decoded.bin'; Bytes = $Context.Configuration.DecodedBytes },
          @{ RelativePath = '_astrum\footer.bin'; Bytes = $Context.Footer.RawBytes }
        )
        if ($ResolvedContainer.TinyWrapper) { $Raw += @{ RelativePath = '_astrum\tiny-wrapper-footer.bin'; Bytes = $ResolvedContainer.TinyWrapper.RawBytes } }
        foreach ($Entry in $Raw) {
          if ($Files.Count -ge $MaximumEntries -or $Entry.Bytes.Length -gt $MaximumExpandedBytes - $Expanded) { throw 'The Astrum raw output exceeds its aggregate limit.' }
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath $Entry.RelativePath -CollisionAction $CollisionAction -ReservedPath $Reserved
          if (-not $Target.ShouldWrite) { continue }
          $Parent = Split-Path -Parent $Target.Path; if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          [IO.File]::WriteAllBytes($Target.Path, $Entry.Bytes)
          $Output = Get-Item -LiteralPath $Target.Path -Force; $Expanded += $Output.Length; $Files.Add($Output)
        }
        # Raw record headers stop at DataOffset, so the physical descriptor, condition, encoded path,
        # and volume-offset table are inspectable without duplicating potentially huge payload bytes.
        foreach ($Record in $Context.Files) {
          $HeaderLength = [long]$Record.DataOffset - [long]$Record.RecordOffset
          if ($HeaderLength -le 0 -or $HeaderLength -gt $MaximumExpandedBytes - $Expanded) { throw 'The Astrum raw record header exceeds its aggregate limit.' }
          $RelativePath = '_astrum\records\{0:D5}-{1:X8}.record.bin' -f $Record.Index, $Record.RecordOffset
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $Reserved
          if (-not $Target.ShouldWrite) { continue }
          $Parent = Split-Path -Parent $Target.Path
          if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          $OutputStream = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
          try { Copy-BinaryStreamRange -Source $Context.Stream -Destination $OutputStream -Offset $Record.RecordOffset -Length $HeaderLength } finally { $OutputStream.Dispose() }
          $Output = Get-Item -LiteralPath $Target.Path -Force
          $Expanded += $Output.Length
          $Files.Add($Output)
        }
        # The footer does not name every compiled UI/resource range. Preserve each validated gap as
        # raw evidence rather than calling unknown bytes a specific proprietary structure.
        for ($Index = 0; $Index -lt $RawPreCatalogRanges.Count; $Index++) {
          $Range = $RawPreCatalogRanges[$Index]
          if ($Range.Length -gt $MaximumExpandedBytes - $Expanded) { throw 'The Astrum raw pre-catalog range exceeds its aggregate limit.' }
          $RelativePath = '_astrum\pre-catalog\{0:D3}-{1:X8}.bin' -f $Index, $Range.Offset
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $Reserved
          if (-not $Target.ShouldWrite) { continue }
          $Parent = Split-Path -Parent $Target.Path
          if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          $OutputStream = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
          try { Copy-BinaryStreamRange -Source $Context.Stream -Destination $OutputStream -Offset $Range.Offset -Length $Range.Length } finally { $OutputStream.Dispose() }
          $Output = Get-Item -LiteralPath $Target.Path -Force
          $Expanded += $Output.Length
          $Files.Add($Output)
        }
        foreach ($Companion in $ResolvedCompanions) {
          $RelativePath = "_astrum\volumes\$([IO.Path]::GetFileName($Companion))"
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $Reserved
          if (-not $Target.ShouldWrite) { continue }
          $Parent = Split-Path -Parent $Target.Path
          if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
          $SourceStream = [IO.File]::Open($Companion, 'Open', 'Read', 'Read')
          $OutputStream = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
          try { $Size = Copy-BoundedStream -Source $SourceStream -Destination $OutputStream -MaximumBytes ($MaximumExpandedBytes - $Expanded) -ExpectedBytes $SourceStream.Length } catch { $OutputStream.Dispose(); Remove-Item -LiteralPath $Target.Path -Force -ErrorAction SilentlyContinue; throw } finally { $OutputStream.Dispose(); $SourceStream.Dispose() }
          $Output = Get-Item -LiteralPath $Target.Path -Force
          $Expanded += $Size
          $Files.Add($Output)
        }
        if ($Context.Footer.UninstallerCompressedSize -gt 0 -and -not $IncludeInstalledUninstaller) {
          if (-not (Test-AstrumRange $Context.Footer.UninstallerOffset $Context.Footer.UninstallerCompressedSize $Context.Footer.Offset)) { throw 'The Astrum uninstaller range is malformed.' }
          $UninstallerName = 'uninstaller.exe'
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $Destination -RelativePath "_astrum\$UninstallerName" -CollisionAction $CollisionAction -ReservedPath $Reserved
          if ($Target.ShouldWrite) {
            $CompressedStream = New-BoundedReadStream -Stream $Context.Stream -Offset $Context.Footer.UninstallerOffset -Length $Context.Footer.UninstallerCompressedSize -LeaveOpen
            $OutputStream = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
            try { $Size = Expand-InstallerCompressedStream -Algorithm GZip -Stream $CompressedStream -Destination $OutputStream -MaximumBytes ($MaximumExpandedBytes - $Expanded) } finally { $OutputStream.Dispose(); $CompressedStream.Dispose() }
            $Output = Get-Item -LiteralPath $Target.Path -Force; $Expanded += $Size; $Files.Add($Output)
          }
        }
      }
      return @($Files)
    } finally {
      Close-AstrumInstallWizardContainer -Container $ResolvedContainer
      $Stream.Dispose()
    }
  }
}

function Read-ProductVersionFromAstrumInstallWizard {
  <#
  .SYNOPSIS
    Read the explicit Astrum Apps & Features version.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionFile = @())
  process { return (Get-AstrumInstallWizardInfo -Path $Path -CompanionFile $CompanionFile).DisplayVersion }
}

function Read-ProductNameFromAstrumInstallWizard {
  <#
  .SYNOPSIS
    Read the Astrum application or ARP display name.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionFile = @())
  process { return (Get-AstrumInstallWizardInfo -Path $Path -CompanionFile $CompanionFile).DisplayName }
}

function Read-PublisherFromAstrumInstallWizard {
  <#
  .SYNOPSIS
    Read the Astrum application or ARP publisher.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionFile = @())
  process { return (Get-AstrumInstallWizardInfo -Path $Path -CompanionFile $CompanionFile).Publisher }
}

function Read-ProductCodeFromAstrumInstallWizard {
  <#
  .SYNOPSIS
    Read the proven Astrum uninstall-key name.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionFile = @())
  process { return (Get-AstrumInstallWizardInfo -Path $Path -CompanionFile $CompanionFile).ProductCode }
}

function Read-ScopeFromAstrumInstallWizard {
  <#
  .SYNOPSIS
    Read the resolved Astrum installation scope.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([string])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionFile = @())
  process { return (Get-AstrumInstallWizardInfo -Path $Path -CompanionFile $CompanionFile).Scope }
}

function Read-ProtocolsFromAstrumInstallWizard {
  <#
  .SYNOPSIS
    Read literal protocols from Astrum registry records.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionFile = @())
  process { return @((Get-AstrumInstallWizardInfo -Path $Path -CompanionFile $CompanionFile).Protocols) }
}

function Read-FileExtensionsFromAstrumInstallWizard {
  <#
  .SYNOPSIS
    Read literal file extensions from Astrum registry and association records.
  .PARAMETER Path
    Astrum installer path.
  .PARAMETER CompanionFile
    Explicitly ordered companion volumes for spanned media.
  #>
  [OutputType([string[]])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path, [string[]]$CompanionFile = @())
  process { return @((Get-AstrumInstallWizardInfo -Path $Path -CompanionFile $CompanionFile).FileExtensions) }
}

Export-ModuleMember -Function Get-AstrumInstallWizardInfo, Test-AstrumInstallWizard, Expand-AstrumInstallWizard, Read-ProductVersionFromAstrumInstallWizard, Read-ProductNameFromAstrumInstallWizard, Read-PublisherFromAstrumInstallWizard, Read-ProductCodeFromAstrumInstallWizard, Read-ScopeFromAstrumInstallWizard, Read-ProtocolsFromAstrumInstallWizard, Read-FileExtensionsFromAstrumInstallWizard
