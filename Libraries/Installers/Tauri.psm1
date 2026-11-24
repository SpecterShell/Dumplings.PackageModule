# SPDX-License-Identifier: Apache-2.0
#
# Static Tauri application-executable asset parser.
# Sources:
# - https://github.com/tauri-apps/tauri/blob/tauri-v1.0.0/core/tauri-codegen/src/embedded_assets.rs
# - https://github.com/tauri-apps/tauri/blob/tauri-v1.0.0/core/tauri/scripts/pattern.js
# - https://github.com/tauri-apps/tauri/blob/tauri-v1.0.0/core/tauri/src/manager.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-codegen/src/embedded_assets.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-codegen/src/context.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-utils/src/assets.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-utils/src/platform.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-bundler/src/bundle.rs
# - https://github.com/tauri-apps/tauri/blob/tauri-v2.9.5/crates/tauri-bundler/src/bundle/windows/util.rs
# - https://github.com/tauri-apps/tauri/blob/tauri-v2.9.5/crates/tauri-utils/src/platform.rs
# Behavioral reference only: https://github.com/Mas0nShi/tauri-dumper
#
# Binary structure consumed by this module:
#
# Windows PE image
# +-- DOS/PE/COFF headers                 machine, image base, subsystem
# +-- section table                       VA <-> file-offset mapping
# +-- VERSIONINFO resource                product/company/version strings
# +-- .taubndl (Tauri 2.7 through 2.9)    &str pointer and three-byte bundle tag
# +-- writable initialized data            mutable &str selecting the Tauri 2.10+ runtime bundle token
# `-- read-only initialized data
#     +-- Rust PHF entry slice            one or more contiguous maps
#     |   `-- (&str, &[u8]) records
#     +-- HTML CSP PHF values             CspHash::Script(&str) slices
#     +-- rooted UTF-8 asset names        /index.html, /assets/app.js, ...
#     +-- Brotli or raw asset bytes       include_bytes! output
#     `-- Tauri literals                  v1/v2 framework and bundle markers
#
# Pointer-sized PHF record (record-relative offsets, little endian):
#
# Offset       PE32 size  PE32+ size  Field
# ------------ ---------- ----------- ----------------------------------------
# 0x00         4          8           absolute VA of UTF-8 asset name
# ptr          4          8           asset-name byte length
# ptr * 2      4          8           absolute VA of stored payload
# ptr * 3      4          8           stored payload byte length
#
# PE32 records are 16 bytes; PE32+ records are 32 bytes. The pointed-to name
# and payload ranges need not be physically adjacent to the record. Tauri's
# compression feature applies Brotli to every entry in one generated map;
# builds without that feature store the source bytes verbatim.

$Script:TauriMaximumAssetCount = 100000
$Script:TauriMaximumNameBytes = 4096
$Script:TauriMaximumStoredAssetBytes = 1073741824
$Script:TauriMaximumExpandedAssetBytes = 1073741824
$Script:TauriMaximumMeasuredExpandedBytes = 8589934592
$Script:TauriMaximumMeasuredStoredBytes = 8589934592
$Script:TauriMaximumIdentifierCandidates = 128
$Script:TauriMaximumScannedDataBytes = 1073741824
$Script:TauriMaximumRecordCandidateOffsets = 67108864
$Script:TauriMaximumDataReferenceCandidates = 16777216
$Script:TauriMaximumBundleReferences = 64
$Script:TauriMaximumMarkerOccurrences = 32
$Script:TauriMaximumCspHashValidationEntries = 65536

# Compile the bounded record scanner once. Installer infrastructure has already
# been loaded by PackageModule's deterministic module order.
$TauriScannerSource = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Source', 'Tauri', 'TauriExecutableScanner.cs'
$null = Import-InstallerManagedSource -Path $TauriScannerSource -TypeName 'Dumplings.Tauri.TauriExecutableScanner'

function Test-TauriReadOnlyDataSection {
  <#
  .SYNOPSIS
    Test whether a PE section can contain immutable Tauri records and strings.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][psobject]$Section)

  if ($Section.Name -eq '.rdata') { return $true }
  $Characteristics = [uint32]$Section.Characteristics
  return ($Characteristics -band 0x00000040) -ne 0 -and ($Characteristics -band 0x40000000) -ne 0 -and
  ($Characteristics -band 0xA0000000L) -eq 0
}

function Test-TauriWritableDataSection {
  <#
  .SYNOPSIS
    Test whether a PE section can contain Tauri's mutable runtime bundle string.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][psobject]$Section)

  if ($Section.Name -eq '.data') { return $true }
  $Characteristics = [uint32]$Section.Characteristics
  return ($Characteristics -band 0x00000040) -ne 0 -and ($Characteristics -band 0x80000000L) -ne 0 -and
  ($Characteristics -band 0x20000000) -eq 0
}

function ConvertTo-TauriPeSectionArray {
  <#
  .SYNOPSIS
    Convert the shared PE layout into the scanner's source-visible section contract.
  .PARAMETER Layout
    Parsed PE layout whose section RVAs and raw ranges use image-relative and absolute-file units respectively.
  .OUTPUTS
    Dumplings.Tauri.TauriPeSection[].
  #>
  [OutputType([Dumplings.Tauri.TauriPeSection[]])]
  param ([Parameter(Mandatory)][psobject]$Layout)

  $Sections = [Collections.Generic.List[Dumplings.Tauri.TauriPeSection]]::new()
  foreach ($Section in $Layout.Sections) {
    $Sections.Add([Dumplings.Tauri.TauriPeSection]@{
        Name            = [string]$Section.Name
        VirtualAddress  = [uint32]$Section.VirtualAddress
        RawOffset       = [uint32]$Section.RawOffset
        RawSize         = [uint32]$Section.RawSize
        Characteristics = [uint32]$Section.Characteristics
      })
  }
  return $Sections.ToArray()
}

function Open-TauriExecutableContext {
  <#
  .SYNOPSIS
    Open and validate one supported Windows Tauri application PE candidate.
  .PARAMETER Path
    Existing filesystem path. It is resolved before .NET opens the file.
  .OUTPUTS
    A context containing the caller-owned FileStream, PE layout, pointer size, architecture, and scanner sections.
  .NOTES
    The caller owns Context.Stream and must dispose it.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $Stream = [IO.File]::Open($ResolvedPath, 'Open', 'Read', 'Read')
  try {
    $Layout = Get-PELayout -Stream $Stream
    if (-not $Layout) { throw 'The file is not a supported PE image.' }
    if (($Layout.Characteristics -band 0x2000) -ne 0) { throw 'Tauri executable parsing does not accept PE DLL images.' }

    $Architecture = switch ([uint16]$Layout.Machine) {
      0x014C { 'x86' }
      0x8664 { 'x64' }
      0xAA64 { 'arm64' }
      default { throw "The Tauri executable PE machine '$($Layout.MachineName)' is unsupported." }
    }
    $PointerSize = if ($Layout.OptionalHeaderFormat -eq 'PE32') { 4 } elseif ($Layout.OptionalHeaderFormat -eq 'PE32+') { 8 } else { 0 }
    if (($Architecture -eq 'x86' -and $PointerSize -ne 4) -or ($Architecture -ne 'x86' -and $PointerSize -ne 8)) {
      throw 'The PE machine and optional-header pointer width are inconsistent.'
    }
    $Sections = ConvertTo-TauriPeSectionArray -Layout $Layout
    if (@($Sections | Where-Object { Test-TauriReadOnlyDataSection $_ }).Count -eq 0) {
      throw 'The PE does not contain a read-only initialized-data section required for generated Tauri assets.'
    }
    $ScannedDataBytes = 0L
    foreach ($Section in $Sections | Where-Object { (Test-TauriReadOnlyDataSection $_) -or (Test-TauriWritableDataSection $_) }) {
      if ([long]$Section.RawSize -gt $Script:TauriMaximumScannedDataBytes - $ScannedDataBytes) {
        throw "The Tauri PE data scan exceeds the $Script:TauriMaximumScannedDataBytes-byte limit."
      }
      $ScannedDataBytes += [long]$Section.RawSize
    }

    return [pscustomobject]@{
      Path         = $ResolvedPath
      Stream       = $Stream
      Layout       = $Layout
      Sections     = $Sections
      PointerSize  = $PointerSize
      RecordSize   = $PointerSize * 4
      Architecture = $Architecture
    }
  } catch {
    $Stream.Dispose()
    throw
  }
}

function Read-TauriLegacyBundleMarker {
  <#
  .SYNOPSIS
    Read the Tauri 2.7 through 2.9 bundle tag through its dedicated PE section.
  .PARAMETER Context
    Open Tauri PE context. The function restores the stream position after bounded reads.
  .OUTPUTS
    A validated bundle marker for each source-shaped .taubndl section.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][psobject]$Context)

  $Markers = [Collections.Generic.List[object]]::new()
  foreach ($BundleSection in $Context.Sections | Where-Object Name -EQ '.taubndl') {
    $FatPointerSize = $Context.PointerSize * 2
    if ([long]$BundleSection.RawSize -lt $FatPointerSize -or [long]$BundleSection.RawOffset -gt $Context.Stream.Length - $FatPointerSize) { continue }

    $Pointer = if ($Context.PointerSize -eq 4) {
      [uint64](Read-PEUInt32 -Stream $Context.Stream -Offset $BundleSection.RawOffset)
    } else {
      Read-PEUInt64 -Stream $Context.Stream -Offset $BundleSection.RawOffset
    }
    $Length = if ($Context.PointerSize -eq 4) {
      [uint64](Read-PEUInt32 -Stream $Context.Stream -Offset ($BundleSection.RawOffset + $Context.PointerSize))
    } else {
      Read-PEUInt64 -Stream $Context.Stream -Offset ($BundleSection.RawOffset + $Context.PointerSize)
    }
    if ($Length -ne 3 -or $Pointer -lt [uint64]$Context.Layout.ImageBase) { continue }

    $Rva64 = $Pointer - [uint64]$Context.Layout.ImageBase
    if ($Rva64 -gt [uint32]::MaxValue) { continue }
    $Rva = [uint32]$Rva64
    $TargetSection = $Context.Sections | Where-Object {
      (Test-TauriReadOnlyDataSection $_) -and [uint64]$_.RawSize -ge 3 -and
      $Rva -ge [uint32]$_.VirtualAddress -and
      [uint64]($Rva - [uint32]$_.VirtualAddress) -le [uint64]$_.RawSize - 3
    } | Select-Object -First 1
    if (-not $TargetSection) { continue }

    $ValueOffset = [long]$TargetSection.RawOffset + ($Rva - [uint32]$TargetSection.VirtualAddress)
    if ($ValueOffset -lt 0 -or $ValueOffset -gt $Context.Stream.Length - 3) { continue }
    $Value = [Text.Encoding]::ASCII.GetString((Read-PEFileBytes -Stream $Context.Stream -Offset $ValueOffset -Count 3))
    $Marker = switch ($Value) {
      'NSS' { [pscustomobject]@{ Name = 'BundleTypeNsis'; BundleType = 'NSIS' } }
      'MSI' { [pscustomobject]@{ Name = 'BundleTypeMsi'; BundleType = 'MSI' } }
      'UNK' { [pscustomobject]@{ Name = 'BundleTypeUnknown'; BundleType = 'Unknown' } }
      default { $null }
    }
    if ($Marker) {
      $Markers.Add([pscustomobject]@{
          Name            = $Marker.Name
          Value           = $Value
          Offset          = $ValueOffset
          BundleType      = $Marker.BundleType
          Format          = 'LegacySection'
          HeaderOffset    = [long]$BundleSection.RawOffset
          ReferenceOffset = [long]$BundleSection.RawOffset
          IsRuntimeValue  = $true
        })
    }
  }
  return $Markers.ToArray()
}

function Resolve-TauriLongBundleMarkerReference {
  <#
  .SYNOPSIS
    Identify the long bundle token referenced by Tauri's mutable runtime string.
  .PARAMETER Context
    Open Tauri PE context.
  .PARAMETER Marker
    Long-token and framework markers recovered from read-only data.
  .PARAMETER TokenDefinition
    Source-backed long bundle-token definitions.
  .OUTPUTS
    The input marker records with runtime-reference evidence populated.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Marker,
    [Parameter(Mandatory)][object[]]$TokenDefinition
  )

  $Resolved = [Collections.Generic.List[object]]::new()
  foreach ($Item in $Marker) { $Resolved.Add($Item) }
  $References = @([Dumplings.Tauri.TauriExecutableScanner]::FindBundleTypeReferences(
      $Context.Stream, [uint64]$Context.Layout.ImageBase, $Context.PointerSize, $Context.Sections,
      [string[]]$TokenDefinition.Value, $Script:TauriMaximumBundleReferences, $Script:TauriMaximumScannedDataBytes,
      $Script:TauriMaximumDataReferenceCandidates))
  foreach ($Reference in $References) {
    $Definition = $TokenDefinition | Where-Object Value -CEQ $Reference.Value | Select-Object -First 1
    if (-not $Definition) { continue }
    $Candidate = $Resolved | Where-Object {
      $_.Format -eq 'LongToken' -and -not $_.IsRuntimeValue -and [long]$_.Offset -eq [long]$Reference.Offset
    } | Select-Object -First 1
    if (-not $Candidate) {
      $Candidate = [pscustomobject]@{
        Name            = $Definition.Name
        Value           = $Definition.Value
        Offset          = [long]$Reference.Offset
        BundleType      = $Definition.BundleType
        Format          = 'LongToken'
        HeaderOffset    = $null
        ReferenceOffset = $null
        IsRuntimeValue  = $false
      }
      $Resolved.Add($Candidate)
    }
    $Candidate.ReferenceOffset = [long]$Reference.ReferenceOffset
    $Candidate.IsRuntimeValue = $true
  }
  return $Resolved.ToArray()
}

function Find-TauriExecutableMarker {
  <#
  .SYNOPSIS
    Locate source-backed Tauri framework and bundle-type marker strings.
  .PARAMETER Context
    Open Tauri PE context. The function restores the stream position after every bounded search.
  .OUTPUTS
    A catalog containing marker records and definitions truncated by the evidence cap.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Context)

  $MarkerDefinitions = @(
    [pscustomobject]@{ Name = 'AssetOrigin'; Value = 'tauri://localhost'; BundleType = $null; Format = 'StringLiteral' }
    [pscustomobject]@{ Name = 'LegacyPattern'; Value = '__TAURI_PATTERN__'; BundleType = $null; Format = 'StringLiteral' }
    [pscustomobject]@{ Name = 'LegacyMetadata'; Value = '__TAURI_METADATA__'; BundleType = $null; Format = 'StringLiteral' }
    [pscustomobject]@{ Name = 'Internals'; Value = '__TAURI_INTERNALS__'; BundleType = $null; Format = 'StringLiteral' }
    [pscustomobject]@{ Name = 'BundleTypeUnknown'; Value = '__TAURI_BUNDLE_TYPE_VAR_UNK'; BundleType = 'Unknown'; Format = 'LongToken' }
    [pscustomobject]@{ Name = 'BundleTypeNsis'; Value = '__TAURI_BUNDLE_TYPE_VAR_NSS'; BundleType = 'NSIS'; Format = 'LongToken' }
    [pscustomobject]@{ Name = 'BundleTypeMsi'; Value = '__TAURI_BUNDLE_TYPE_VAR_MSI'; BundleType = 'MSI'; Format = 'LongToken' }
  )
  $LongTokenDefinitions = @($MarkerDefinitions | Where-Object Format -EQ 'LongToken')
  $Markers = [Collections.Generic.List[object]]::new()
  $TruncatedDefinitions = [Collections.Generic.List[string]]::new()
  foreach ($Marker in @(Read-TauriLegacyBundleMarker -Context $Context)) { $Markers.Add($Marker) }
  foreach ($Definition in $MarkerDefinitions) {
    $DefinitionOffsets = [Collections.Generic.List[long]]::new()
    foreach ($Section in $Context.Sections | Where-Object { Test-TauriReadOnlyDataSection $_ }) {
      $Remaining = ($Script:TauriMaximumMarkerOccurrences + 1) - $DefinitionOffsets.Count
      if ($Remaining -le 0) { break }
      $Pattern = [Text.Encoding]::ASCII.GetBytes($Definition.Value)
      foreach ($Offset in @(Find-BinaryPattern -Stream $Context.Stream -Pattern $Pattern -StartOffset $Section.RawOffset -Length $Section.RawSize -Maximum $Remaining)) {
        $DefinitionOffsets.Add([long]$Offset)
      }
    }
    if ($Definition.Format -eq 'LongToken' -and $DefinitionOffsets.Count -gt $Script:TauriMaximumMarkerOccurrences) {
      $TruncatedDefinitions.Add($Definition.Name)
    }
    foreach ($Offset in $DefinitionOffsets | Select-Object -First $Script:TauriMaximumMarkerOccurrences) {
      $Markers.Add([pscustomobject]@{
          Name            = $Definition.Name
          Value           = $Definition.Value
          Offset          = [long]$Offset
          BundleType      = $Definition.BundleType
          Format          = $Definition.Format
          HeaderOffset    = $null
          ReferenceOffset = $null
          IsRuntimeValue  = $false
        })
    }
  }
  $ResolvedMarkers = @(Resolve-TauriLongBundleMarkerReference -Context $Context -Marker $Markers.ToArray() -TokenDefinition $LongTokenDefinitions | Sort-Object Offset, ReferenceOffset)
  return [pscustomobject]@{
    Markers              = $ResolvedMarkers
    TruncatedDefinitions = $TruncatedDefinitions.ToArray()
  }
}

function Split-TauriAssetRecordRun {
  <#
  .SYNOPSIS
    Group scanner records into Rust PHF entry slices.
  .PARAMETER Record
    Structurally valid candidate records sorted by absolute header offset.
  .PARAMETER RecordSize
    Pointer-width-dependent record size in bytes.
  .OUTPUTS
    Objects whose Records property contains one contiguous candidate run.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
    [Parameter(Mandatory)][ValidateSet(16, 32)][int]$RecordSize
  )

  $Runs = [Collections.Generic.List[object]]::new()
  $Current = [Collections.Generic.List[object]]::new()
  $CurrentNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($Item in $Record | Sort-Object HeaderOffset) {
    # PHF map keys are unique. A repeated key at the next record is therefore
    # the boundary between adjacent generated maps even when the linker leaves
    # no padding between their entry slices.
    if ($Current.Count -gt 0 -and (
        [long]$Item.HeaderOffset -ne ([long]$Current[$Current.Count - 1].HeaderOffset + $RecordSize) -or
        $CurrentNames.Contains([string]$Item.Name))) {
      $Runs.Add([pscustomobject]@{ Records = $Current.ToArray() })
      $Current = [Collections.Generic.List[object]]::new()
      $CurrentNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    }
    $Current.Add($Item)
    $null = $CurrentNames.Add([string]$Item.Name)
  }
  if ($Current.Count -gt 0) { $Runs.Add([pscustomobject]@{ Records = $Current.ToArray() }) }
  return $Runs.ToArray()
}

function Test-TauriAssetRelativePath {
  <#
  .SYNOPSIS
    Validate a rooted Tauri asset name for safe Windows projection.
  .PARAMETER Name
    Rooted UTF-8 Tauri asset key such as /assets/app.js.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][string]$Name)

  if (-not $Name.StartsWith('/', [StringComparison]::Ordinal) -or $Name.Length -le 1 -or $Name.Contains('\')) { return $false }
  $InvalidCharacters = [IO.Path]::GetInvalidFileNameChars()
  foreach ($Component in $Name.Substring(1).Split('/')) {
    if ([string]::IsNullOrWhiteSpace($Component) -or $Component -in '.', '..' -or $Component.EndsWith(' ') -or $Component.EndsWith('.')) { return $false }
    if ($Component.IndexOfAny($InvalidCharacters) -ge 0) { return $false }
    if ($Component -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { return $false }
  }
  return $true
}

function Measure-TauriBrotliPayload {
  <#
  .SYNOPSIS
    Validate and count one bounded Brotli payload without materializing it.
  .PARAMETER Stream
    Caller-owned seekable PE stream. Its underlying position is not semantically consumed.
  .PARAMETER Offset
    Absolute file offset of the stored payload.
  .PARAMETER Length
    Stored payload length in bytes.
  .PARAMETER MaximumExpandedBytes
    Maximum decompressed bytes accepted for this asset.
  .PARAMETER MaximumStoredBytes
    Maximum stored bytes read while probing this asset.
  .OUTPUTS
    A result containing Success, ExpandedSize, and an error string for classification.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Length,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes,
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumStoredBytes = [long]::MaxValue
  )

  return [Dumplings.Tauri.TauriExecutableScanner]::MeasureBrotli($Stream, $Offset, $Length, $MaximumExpandedBytes, $MaximumStoredBytes)
}

function Test-TauriRawEntryPage {
  <#
  .SYNOPSIS
    Check whether a raw entry-page payload starts like HTML.
  .PARAMETER Stream
    Caller-owned PE stream.
  .PARAMETER Record
    Candidate /index.html or other HTML record.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][psobject]$Record)

  if ($Record.StoredSize -le 0 -or $Record.DataOffset -lt 0) { return $false }
  $Count = [int][Math]::Min([long]4096, [long]$Record.StoredSize)
  $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Record.DataOffset -Count $Count
  try { $Text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) } catch { return $false }
  return $Text.TrimStart([char]0xFEFF, [char]0x20, [char]0x09, [char]0x0D, [char]0x0A) -match '^(?is:<!doctype\s+html\b|<html(?:\s|>)|<head(?:\s|>)|<body(?:\s|>))'
}

function Test-TauriRawPayloadEvidence {
  <#
  .SYNOPSIS
    Confirm that at least one stored payload agrees with its asset-name extension.
  .PARAMETER Stream
    Caller-owned PE stream.
  .PARAMETER Record
    Candidate records from one generated map.
  .OUTPUTS
    True when text structure or a standard binary magic supports raw storage.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][object[]]$Record)

  foreach ($Item in $Record) {
    if ($Item.StoredSize -le 0 -or $Item.DataOffset -lt 0) { continue }
    $Count = [int][Math]::Min([long]4096, [long]$Item.StoredSize)
    $Bytes = Read-BinaryBytes -Stream $Stream -Offset $Item.DataOffset -Count $Count
    $Extension = [IO.Path]::GetExtension($Item.Name).ToLowerInvariant()
    switch ($Extension) {
      '.html' { if (Test-TauriRawEntryPage -Stream $Stream -Record $Item) { return $true } }
      '.htm' { if (Test-TauriRawEntryPage -Stream $Stream -Record $Item) { return $true } }
      '.png' { if ($Bytes.Length -ge 8 -and [Convert]::ToHexString([byte[]]$Bytes[0..7]) -eq '89504E470D0A1A0A') { return $true } }
      '.jpg' { if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xD8 -and $Bytes[2] -eq 0xFF) { return $true } }
      '.jpeg' { if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xD8 -and $Bytes[2] -eq 0xFF) { return $true } }
      '.gif' { if ($Bytes.Length -ge 6 -and [Text.Encoding]::ASCII.GetString($Bytes, 0, 6) -in 'GIF87a', 'GIF89a') { return $true } }
      '.wasm' { if ($Bytes.Length -ge 4 -and [Convert]::ToHexString([byte[]]$Bytes[0..3]) -eq '0061736D') { return $true } }
      '.ico' { if ($Bytes.Length -ge 4 -and [Convert]::ToHexString([byte[]]$Bytes[0..3]) -eq '00000100') { return $true } }
      { $_ -in '.css', '.js', '.json', '.map', '.mjs', '.svg', '.txt', '.xml' } {
        try { $Text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) } catch { continue }
        if ($Text.IndexOf([char]0) -ge 0) { continue }
        $Printable = 0
        $RuneCount = 0
        foreach ($Character in $Text.EnumerateRunes()) {
          $RuneCount++
          if (-not [Text.Rune]::IsControl($Character) -or $Character.Value -in 9, 10, 13) { $Printable++ }
        }
        if ($RuneCount -gt 0 -and $Printable / $RuneCount -ge 0.8) { return $true }
      }
    }
  }
  return $false
}

function Resolve-TauriVirtualAddressOffset {
  <#
  .SYNOPSIS
    Resolve a bounded absolute PE virtual-address range to its file offset.
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(Mandatory)][uint64]$VirtualAddress,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Length,
    [switch]$ReadOnlyData
  )

  if ($VirtualAddress -lt [uint64]$Context.Layout.ImageBase) { return -1L }
  $Rva = $VirtualAddress - [uint64]$Context.Layout.ImageBase
  foreach ($Section in $Context.Sections) {
    if ($ReadOnlyData -and -not (Test-TauriReadOnlyDataSection $Section)) { continue }
    if ($Rva -lt [uint64]$Section.VirtualAddress) { continue }
    $Delta = $Rva - [uint64]$Section.VirtualAddress
    if ($Delta -gt [uint64]$Section.RawSize -or [uint64]$Length -gt [uint64]$Section.RawSize - $Delta) { continue }
    $Offset = [uint64]$Section.RawOffset + $Delta
    if ($Offset -gt [uint64][long]::MaxValue -or $Offset -gt [uint64]$Context.Stream.Length -or
      [uint64]$Length -gt [uint64]$Context.Stream.Length - $Offset) { return -1L }
    return [long]$Offset
  }
  return -1L
}

function Get-TauriHtmlCspHashMapEvidence {
  <#
  .SYNOPSIS
    Validate the Rust CspHash slices used by Tauri's HTML-to-hash PHF map.
  .PARAMETER Context
    Open Tauri PE context.
  .PARAMETER Record
    One contiguous candidate PHF record run.
  .PARAMETER ValidationWork
    Aggregate count of CSP enum elements examined across the current parser operation.
  .PARAMETER AllowEmptySlice
    Accept zero-element slices when matching non-empty HTML records prove an adjacent generated map boundary.
  .OUTPUTS
    Structural evidence when every value is a valid CspHash::Script slice.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(Mandatory)][object[]]$Record,
    [Parameter(Mandatory)][ref]$ValidationWork,
    [switch]$AllowEmptySlice
  )

  if ($Record.Count -eq 0 -or @($Record | Where-Object Name -NotMatch '(?i)\.html?$').Count -gt 0) { return $null }
  $ElementSize = $Context.PointerSize * 3
  $HashCount = 0L
  foreach ($Item in $Record) {
    $Count = [long]$Item.StoredSize
    if ($Count -eq 0) {
      if (-not $AllowEmptySlice -or $Item.DataOffset -ge 0) { return $null }
      continue
    }
    if ($Count -gt 4096 -or $Item.DataOffset -lt 0 -or $Count -gt [long]::MaxValue / $ElementSize) { return $null }
    $SliceLength = $Count * $ElementSize
    if ([long]$Item.DataOffset -gt $Context.Stream.Length - $SliceLength) { return $null }
    for ($Index = 0L; $Index -lt $Count; $Index++) {
      if ([long]$ValidationWork.Value -ge $Script:TauriMaximumCspHashValidationEntries) {
        throw "Tauri CSP hash validation exceeds the $Script:TauriMaximumCspHashValidationEntries-entry parser work limit."
      }
      $ValidationWork.Value = [long]$ValidationWork.Value + 1
      $ElementOffset = [long]$Item.DataOffset + ($Index * $ElementSize)
      $Discriminant = if ($Context.PointerSize -eq 4) { [uint64](Read-PEUInt32 -Stream $Context.Stream -Offset $ElementOffset) } else { Read-PEUInt64 -Stream $Context.Stream -Offset $ElementOffset }
      if ($Discriminant -ne 0) { return $null }
      $StringPointerOffset = $ElementOffset + $Context.PointerSize
      $StringPointer = if ($Context.PointerSize -eq 4) { [uint64](Read-PEUInt32 -Stream $Context.Stream -Offset $StringPointerOffset) } else { Read-PEUInt64 -Stream $Context.Stream -Offset $StringPointerOffset }
      $StringLengthOffset = $StringPointerOffset + $Context.PointerSize
      $StringLength = if ($Context.PointerSize -eq 4) { [uint64](Read-PEUInt32 -Stream $Context.Stream -Offset $StringLengthOffset) } else { Read-PEUInt64 -Stream $Context.Stream -Offset $StringLengthOffset }
      if ($StringLength -ne 53) { return $null }
      $StringOffset = Resolve-TauriVirtualAddressOffset -Context $Context -VirtualAddress $StringPointer -Length 53 -ReadOnlyData
      if ($StringOffset -lt 0) { return $null }
      $Hash = [Text.Encoding]::ASCII.GetString((Read-PEFileBytes -Stream $Context.Stream -Offset $StringOffset -Count 53))
      if ($Hash -cnotmatch "^'sha256-[A-Za-z0-9+/]{43}='$") { return $null }
    }
    $HashCount += $Count
  }
  return [pscustomobject]@{ HashCount = $HashCount; Directive = 'script-src'; ElementSize = $ElementSize }
}

function Get-TauriAssetCatalog {
  <#
  .SYNOPSIS
    Validate generated Tauri PHF maps and classify their storage mode.
  .PARAMETER Context
    Open executable context.
  .PARAMETER Markers
    Source-backed framework markers used to reject unrelated Rust slices.
  .OUTPUTS
    Validated maps, asset descriptors, aggregate sizes, expansion capability, and warnings.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Context,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Markers
  )

  $CandidateRecords = @([Dumplings.Tauri.TauriExecutableScanner]::FindAssetRecords(
      $Context.Stream,
      [uint64]$Context.Layout.ImageBase,
      $Context.PointerSize,
      $Context.Sections,
      $Script:TauriMaximumNameBytes,
      $Script:TauriMaximumStoredAssetBytes,
      $Script:TauriMaximumAssetCount,
      $Script:TauriMaximumScannedDataBytes,
      $Script:TauriMaximumRecordCandidateOffsets
    ))
  $Runs = @(Split-TauriAssetRecordRun -Record $CandidateRecords -RecordSize $Context.RecordSize)
  $Maps = [Collections.Generic.List[object]]::new()
  $AuxiliaryMaps = [Collections.Generic.List[object]]::new()
  $Assets = [Collections.Generic.List[object]]::new()
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $MeasuredExpandedBytes = 0L
  $MeasuredBrotliExpandedBytes = 0L
  $MeasuredBrotliStoredBytes = 0L
  $CspHashValidationWork = 0L
  $MeasurementCache = @{}
  $HasRejectedMap = $false
  $NonEmptyRecordNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($Record in $CandidateRecords | Where-Object StoredSize -GT 0) { $null = $NonEmptyRecordNames.Add([string]$Record.Name) }

  foreach ($Run in $Runs) {
    $Records = @($Run.Records)
    $EntryRecords = @($Records | Where-Object Name -Match '(?i)/(?:index|main)(?:\.[^/]+)?\.html?$|(?i)/index\.html?$')
    $HasFrameworkMarker = $Markers.Count -gt 0
    if ($EntryRecords.Count -eq 0 -and $Records.Count -lt 2 -and -not $HasFrameworkMarker) { continue }

    # An unsafe member inside an otherwise coherent record run means the map
    # cannot be exported completely; rejecting it avoids partial-map recovery.
    $UnsafeRecords = @($Records | Where-Object { -not $_.IsSafeName -or -not (Test-TauriAssetRelativePath -Name $_.Name) })
    if ($UnsafeRecords.Count -gt 0) {
      if ($EntryRecords.Count -eq 0 -and $Records.Count -lt 2) { continue }
      $HasRejectedMap = $true
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.AssetMap.UnsafePath' -Source 'Tauri' `
            -Message "A structurally coherent Tauri asset map contains an unsafe path and was rejected as a complete unit: $($UnsafeRecords[0].Name)" `
            -Kind Invalid -Areas @('Extraction', 'Security') -AffectedFields 'EmbeddedAssets' `
            -Evidence ([pscustomobject]@{ HeaderOffset = [long]$Records[0].HeaderOffset; Paths = [string[]]$UnsafeRecords.Name })))
      continue
    }

    $Measurements = [Collections.Generic.List[object]]::new()
    foreach ($Record in $Records) {
      $MeasurementKey = "$([long]$Record.DataOffset):$([long]$Record.StoredSize)"
      if ($MeasurementCache.ContainsKey($MeasurementKey)) {
        $Measurements.Add($MeasurementCache[$MeasurementKey])
        continue
      }
      $RemainingExpandedWork = $Script:TauriMaximumMeasuredExpandedBytes - $MeasuredBrotliExpandedBytes
      $RemainingStoredWork = $Script:TauriMaximumMeasuredStoredBytes - $MeasuredBrotliStoredBytes
      if ($RemainingExpandedWork -le 0 -or $RemainingStoredWork -le 0) {
        throw 'Tauri Brotli validation exceeds the cumulative parser work limit.'
      }
      $ExpandedLimit = [Math]::Min([long]$Script:TauriMaximumExpandedAssetBytes, [long]$RemainingExpandedWork)
      $Measurement = Measure-TauriBrotliPayload -Stream $Context.Stream -Offset ([Math]::Max(0L, [long]$Record.DataOffset)) `
        -Length $Record.StoredSize -MaximumExpandedBytes $ExpandedLimit -MaximumStoredBytes $RemainingStoredWork
      $MeasuredBrotliExpandedBytes += [long]$Measurement.ExpandedSize
      $MeasuredBrotliStoredBytes += [long]$Measurement.StoredBytesRead
      if ($Measurement.StoredLimitExceeded -or ($Measurement.LimitExceeded -and $ExpandedLimit -lt $Script:TauriMaximumExpandedAssetBytes)) {
        throw 'Tauri Brotli validation exceeds the cumulative parser work limit.'
      }
      $MeasurementCache[$MeasurementKey] = $Measurement
      $Measurements.Add($Measurement)
    }
    $BrotliCount = @($Measurements | Where-Object Success).Count
    $Compression = if ($BrotliCount -eq $Records.Count) { 'Brotli' } elseif ($BrotliCount -eq 0) { 'None' } else { 'Mixed' }

    # Raw maps need marker support or payload bytes consistent with the named
    # file type. Successful Brotli framing is stronger evidence by itself.
    $HasRawPayloadEvidence = if ($Compression -eq 'None' -or $Compression -eq 'Mixed') {
      Test-TauriRawPayloadEvidence -Stream $Context.Stream -Record $Records
    } else { $false }
    # EmbeddedAssets also contains a PHF map from HTML paths to CspHash slices.
    # Its value word is an element count rather than a byte count, so it looks
    # like a tiny raw or mixed-compression asset run. Catalog it separately and never
    # expose those Rust enum records as frontend file bytes.
    $EmptySliceRecords = @($Records | Where-Object StoredSize -EQ 0)
    $AllowEmptyCspSlice = $EmptySliceRecords.Count -gt 0 -and
    @($EmptySliceRecords | Where-Object { -not $NonEmptyRecordNames.Contains([string]$_.Name) }).Count -eq 0
    $HtmlHashMapEvidence = if ($Compression -ne 'Brotli' -and -not $HasRawPayloadEvidence) {
      Get-TauriHtmlCspHashMapEvidence -Context $Context -Record $Records -ValidationWork ([ref]$CspHashValidationWork) -AllowEmptySlice:$AllowEmptyCspSlice
    } else { $null }
    if ($HtmlHashMapEvidence) {
      $AuxiliaryMaps.Add([pscustomobject]@{
          Type         = 'HtmlCspHashMap'
          HeaderOffset = [long]$Records[0].HeaderOffset
          RecordCount  = $Records.Count
          Names        = @($Records.Name)
          HashCount    = [long]$HtmlHashMapEvidence.HashCount
          Directive    = $HtmlHashMapEvidence.Directive
        })
      continue
    }
    if ($Compression -eq 'None' -and -not $HasRawPayloadEvidence) {
      if ($HasFrameworkMarker -and $EntryRecords.Count -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.AssetMap.Unvalidated' -Source 'Tauri' `
              -Message "A Tauri-like asset run at 0x$($Records[0].HeaderOffset.ToString('X')) could not be validated as complete Brotli or source-supported raw data." `
              -Kind Incomplete -Areas @('Metadata', 'Extraction') -AffectedFields 'EmbeddedAssets' `
              -Evidence ([pscustomobject]@{ HeaderOffset = [long]$Records[0].HeaderOffset; RecordCount = $Records.Count })))
      }
      continue
    }
    if ($Compression -eq 'Brotli' -and -not $HasFrameworkMarker -and $EntryRecords.Count -eq 0 -and $Records.Count -lt 2) { continue }

    $MapIndex = $Maps.Count
    $MapCanExpand = $Compression -ne 'Mixed'
    if (-not $MapCanExpand) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.AssetMap.MixedCompression' -Source 'Tauri' `
            -Message "Tauri asset map $MapIndex mixes Brotli and non-Brotli payloads; source-supported maps use one mode, so extraction is disabled." `
            -Kind Incomplete -Areas @('Metadata', 'Extraction') -AffectedFields 'EmbeddedAssets' `
            -Evidence ([pscustomobject]@{ MapIndex = $MapIndex; HeaderOffset = [long]$Records[0].HeaderOffset })))
    }
    $MapAssets = [Collections.Generic.List[object]]::new()
    for ($Index = 0; $Index -lt $Records.Count; $Index++) {
      $Record = $Records[$Index]
      $ExpandedSize = if ($Compression -eq 'Brotli') { [long]$Measurements[$Index].ExpandedSize } elseif ($Compression -eq 'None') { [long]$Record.StoredSize } else { $null }
      if ($null -ne $ExpandedSize) {
        if ($ExpandedSize -gt $Script:TauriMaximumMeasuredExpandedBytes - $MeasuredExpandedBytes) {
          throw 'The cumulative expanded size of the Tauri assets exceeds the parser limit.'
        }
        $MeasuredExpandedBytes += $ExpandedSize
      }
      $Descriptor = [pscustomobject]@{
        MapIndex     = $MapIndex
        Name         = [string]$Record.Name
        RelativePath = $Record.Name.TrimStart('/')
        HeaderOffset = [long]$Record.HeaderOffset
        NameOffset   = [long]$Record.NameOffset
        DataOffset   = [long]$Record.DataOffset
        StoredSize   = [long]$Record.StoredSize
        ExpandedSize = $ExpandedSize
        Compression  = $Compression
      }
      $MapAssets.Add($Descriptor)
      $Assets.Add($Descriptor)
    }
    $Maps.Add([pscustomobject]@{
        Index        = $MapIndex
        HeaderOffset = [long]$Records[0].HeaderOffset
        RecordCount  = $Records.Count
        Compression  = $Compression
        CanExpand    = $MapCanExpand
        Assets       = $MapAssets.ToArray()
      })
  }

  $CompressionModes = @($Maps | Select-Object -ExpandProperty Compression -Unique)
  $CanExpand = $Maps.Count -gt 0 -and -not $HasRejectedMap -and -not ($Maps.CanExpand -contains $false) -and $CompressionModes.Count -eq 1
  if ($CompressionModes.Count -gt 1) {
    $CanExpand = $false
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.AssetMap.InconsistentCompression' -Source 'Tauri' `
          -Message 'The executable contains generated Tauri asset maps with different compression modes; extraction is disabled pending manual review.' `
          -Kind Incomplete -Areas @('Metadata', 'Extraction') -AffectedFields 'EmbeddedAssets' `
          -Evidence ([pscustomobject]@{ CompressionModes = [string[]]$CompressionModes })))
  }
  return [pscustomobject]@{
    Maps                 = $Maps.ToArray()
    AuxiliaryMaps        = $AuxiliaryMaps.ToArray()
    Assets               = $Assets.ToArray()
    Compression          = if ($CompressionModes.Count -eq 1) { $CompressionModes[0] } elseif ($CompressionModes.Count -gt 1) { 'Mixed' } else { $null }
    TotalStoredBytes     = [long](($Assets | Measure-Object StoredSize -Sum).Sum ?? 0)
    TotalExpandedBytes   = if ($Assets.Count -gt 0 -and -not ($Assets.ExpandedSize -contains $null)) { [long](($Assets | Measure-Object ExpandedSize -Sum).Sum ?? 0) } else { $null }
    CanExpand            = $CanExpand
    CandidateRecordCount = $CandidateRecords.Count
    ValidationWork       = [pscustomobject]@{
      UniquePayloadCount     = $MeasurementCache.Count
      StoredBytesRead        = $MeasuredBrotliStoredBytes
      ExpandedBytesDecoded   = $MeasuredBrotliExpandedBytes
      CspHashEntriesExamined = $CspHashValidationWork
    }
    Diagnostics          = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
  }
}

function Test-TauriAssetEvidence {
  <#
  .SYNOPSIS
    Perform a bounded early-exit check for one generated asset map.
  .PARAMETER Context
    Open executable context.
  .PARAMETER Markers
    Tauri framework markers already found in .rdata.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][psobject]$Context, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Markers)

  $Records = @([Dumplings.Tauri.TauriExecutableScanner]::FindAssetRecords(
      $Context.Stream, [uint64]$Context.Layout.ImageBase, $Context.PointerSize, $Context.Sections,
      $Script:TauriMaximumNameBytes, $Script:TauriMaximumStoredAssetBytes, $Script:TauriMaximumAssetCount,
      $Script:TauriMaximumScannedDataBytes, $Script:TauriMaximumRecordCandidateOffsets))
  $MeasurementCache = @{}
  $MeasuredBrotliExpandedBytes = 0L
  $MeasuredBrotliStoredBytes = 0L
  foreach ($Run in @(Split-TauriAssetRecordRun -Record $Records -RecordSize $Context.RecordSize)) {
    $RunRecords = @($Run.Records)
    if ($RunRecords | Where-Object { -not $_.IsSafeName -or -not (Test-TauriAssetRelativePath $_.Name) }) { continue }
    if ($Markers.Count -gt 0 -and $RunRecords.Count -ge 2) { return $true }
    $EntryRecords = @($RunRecords | Where-Object Name -Match '(?i)/index\.html?$')
    $ProbeRecords = if ($EntryRecords.Count -gt 0) { $EntryRecords } elseif ($Markers.Count -gt 0 -and $RunRecords.Count -eq 1) { $RunRecords } else { @() }
    foreach ($Probe in $ProbeRecords) {
      $MeasurementKey = "$([long]$Probe.DataOffset):$([long]$Probe.StoredSize)"
      if ($MeasurementCache.ContainsKey($MeasurementKey)) {
        $Measurement = $MeasurementCache[$MeasurementKey]
      } else {
        $RemainingExpandedWork = $Script:TauriMaximumMeasuredExpandedBytes - $MeasuredBrotliExpandedBytes
        $RemainingStoredWork = $Script:TauriMaximumMeasuredStoredBytes - $MeasuredBrotliStoredBytes
        if ($RemainingExpandedWork -le 0 -or $RemainingStoredWork -le 0) {
          throw 'Tauri Brotli validation exceeds the cumulative parser work limit.'
        }
        $ExpandedLimit = [Math]::Min(134217728L, [long]$RemainingExpandedWork)
        $Measurement = Measure-TauriBrotliPayload -Stream $Context.Stream -Offset ([Math]::Max(0L, [long]$Probe.DataOffset)) `
          -Length $Probe.StoredSize -MaximumExpandedBytes $ExpandedLimit -MaximumStoredBytes $RemainingStoredWork
        $MeasuredBrotliExpandedBytes += [long]$Measurement.ExpandedSize
        $MeasuredBrotliStoredBytes += [long]$Measurement.StoredBytesRead
        if ($Measurement.StoredLimitExceeded -or ($Measurement.LimitExceeded -and $ExpandedLimit -lt 134217728L)) {
          throw 'Tauri Brotli validation exceeds the cumulative parser work limit.'
        }
        $MeasurementCache[$MeasurementKey] = $Measurement
      }
      if ($Measurement.Success -or ($Probe.Name -match '(?i)/index\.html?$' -and (Test-TauriRawEntryPage -Stream $Context.Stream -Record $Probe))) { return $true }
    }
    if ($Markers.Count -gt 0) {
      if (Test-TauriRawPayloadEvidence -Stream $Context.Stream -Record $RunRecords) { return $true }
    }
  }
  return $false
}

function Get-TauriExecutableInfoInternal {
  <#
  .SYNOPSIS
    Build aggregate Tauri evidence from one already-open executable.
  .PARAMETER Context
    Open context whose stream remains owned by the caller.
  .OUTPUTS
    Structured PE, Tauri map, marker, candidate, and warning evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Context)

  $MarkerCatalog = Find-TauriExecutableMarker -Context $Context
  $Markers = @($MarkerCatalog.Markers)
  $Catalog = Get-TauriAssetCatalog -Context $Context -Markers $Markers
  $MarkerClasses = @($Markers | ForEach-Object { if ($_.Name -like 'BundleType*') { 'BundleType' } else { $_.Name } } | Select-Object -Unique)
  if ($Catalog.Maps.Count -eq 0 -and $MarkerClasses.Count -lt 2) {
    throw 'The PE does not contain a supported generated Tauri asset map or sufficient framework marker evidence.'
  }

  $Diagnostics = [Collections.Generic.List[object]]::new()
  foreach ($Diagnostic in $Catalog.Diagnostics) { $Diagnostics.Add($Diagnostic) }
  if ($MarkerCatalog.TruncatedDefinitions.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.MarkerEvidence.Truncated' -Source 'Tauri' `
          -Message 'Tauri marker evidence exceeded the per-definition catalog limit; runtime bundle references were resolved independently from writable data.' `
          -Kind Information -Areas @('Detection', 'Metadata') -AffectedFields 'TauriMarkerEvidence' `
          -Evidence ([pscustomobject]@{ Definitions = [string[]]$MarkerCatalog.TruncatedDefinitions; MaximumOccurrences = $Script:TauriMaximumMarkerOccurrences })))
  }
  if ($Catalog.Maps.Count -eq 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.AssetMap.NotRecovered' -Source 'Tauri' `
          -Message 'Tauri framework markers were found, but no standard generated embedded asset map was recovered. The application may use a custom or URL-backed asset provider.' `
          -Kind Incomplete -Areas @('Detection', 'Metadata', 'Extraction') -AffectedFields 'EmbeddedAssets' `
          -Evidence ([pscustomobject]@{ CandidateRecordCount = $Catalog.CandidateRecordCount; MarkerClasses = [string[]]$MarkerClasses })))
  }

  # Tauri 2.7 through 2.9 identifies the exact string through .taubndl. Tauri
  # 2.10 and later keeps a mutable &str in .data that references the long token
  # patched by the bundler. Other tokens can remain as match-arm literals.
  $BundleMarkers = @($Markers | Where-Object Name -Like 'BundleType*' | Sort-Object Offset)
  $RuntimeBundleMarkers = @($BundleMarkers | Where-Object IsRuntimeValue)
  $UsedUniqueTokenFallback = $RuntimeBundleMarkers.Count -eq 0 -and @($BundleMarkers.BundleType | Select-Object -Unique).Count -eq 1
  $AuthoritativeBundleMarkers = if ($RuntimeBundleMarkers.Count -gt 0) {
    $RuntimeBundleMarkers
  } elseif ($UsedUniqueTokenFallback) {
    $BundleMarkers
  } else { @() }
  $DistinctAuthoritativeBundleTypes = @($AuthoritativeBundleMarkers.BundleType | Select-Object -Unique)
  $BundleMarker = if ($DistinctAuthoritativeBundleTypes.Count -eq 1) {
    $AuthoritativeBundleMarkers | Sort-Object @{ Expression = { $_.Format -ne 'LegacySection' } }, Offset | Select-Object -First 1
  } else { $null }
  $BundleType = if ($BundleMarker) { $BundleMarker.BundleType } else { $null }
  $HasBundleConflict = if ($RuntimeBundleMarkers.Count -gt 0) {
    @($RuntimeBundleMarkers.BundleType | Select-Object -Unique).Count -gt 1
  } else {
    @($BundleMarkers.BundleType | Select-Object -Unique).Count -gt 1
  }
  if ($HasBundleConflict) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.BundleType.Conflict' -Source 'Tauri' `
          -Message 'The executable contains conflicting Tauri bundle tags backed by runtime references, so BundleType remains unresolved.' `
          -Kind Ambiguous -Areas Metadata -AffectedFields 'BundleType' `
          -Evidence @($BundleMarkers | Select-Object BundleType, Format, Offset, HeaderOffset, ReferenceOffset, IsRuntimeValue)))
  }
  if ($BundleMarker -and $UsedUniqueTokenFallback) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.BundleType.UniqueTokenFallback' -Source 'Tauri' `
          -Message 'BundleType uses the only long bundle token found because no mutable runtime reference was recovered; treat the value as non-authoritative evidence.' `
          -Kind Fallback -Areas Metadata -AffectedFields 'BundleType' `
          -Evidence ($BundleMarker | Select-Object BundleType, Format, Offset, ReferenceOffset, IsRuntimeValue)))
  }
  $LegacyBundleSections = @($Context.Sections | Where-Object Name -EQ '.taubndl')
  if ($LegacyBundleSections.Count -gt 0 -and @($BundleMarkers | Where-Object Format -EQ 'LegacySection').Count -eq 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.BundleType.InvalidLegacySection' -Source 'Tauri' `
          -Message 'The Tauri .taubndl section does not contain a valid pointer-sized string record and three-byte bundle tag.' `
          -Kind Incomplete -Areas Metadata -AffectedFields 'BundleType' `
          -Evidence @($LegacyBundleSections | Select-Object RawOffset, RawSize, VirtualAddress)))
  }

  $CandidateData = @([Dumplings.Tauri.TauriExecutableScanner]::FindIdentifierCandidates(
      $Context.Stream, $Context.Sections, $Script:TauriMaximumIdentifierCandidates, 256,
      $Script:TauriMaximumScannedDataBytes))
  $PackageIdentifierCandidates = @($CandidateData | Where-Object Kind -EQ 'PackageIdentifier' | ForEach-Object {
      [pscustomobject]@{ Value = $_.Value; Offset = [long]$_.Offset; Confidence = 'low'; Reason = 'Reverse-domain string in read-only PE data; ownership by Tauri config is not preserved.' }
    })
  $AclPermissionCandidates = @($CandidateData | Where-Object Kind -EQ 'AclPermission' | ForEach-Object {
      [pscustomobject]@{ Value = $_.Value; Offset = [long]$_.Offset; Confidence = 'low'; Reason = 'Tauri ACL-shaped string in read-only PE data; inclusion does not prove that the permission is granted.' }
    })
  if ($PackageIdentifierCandidates.Count -gt 0 -or $AclPermissionCandidates.Count -gt 0) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'Tauri.IdentifierCandidates.NonAuthoritative' -Source 'Tauri' `
          -Message 'Identifier and ACL strings are non-authoritative candidates because optimized Rust binaries do not preserve their original configuration context.' `
          -Kind Information -Areas Metadata `
          -Evidence ([pscustomobject]@{ PackageIdentifierCount = $PackageIdentifierCandidates.Count; AclPermissionCount = $AclPermissionCandidates.Count })))
  }

  # VERSIONINFO is the authoritative source for the application identity strings
  # Tauri emits at build time. Missing fields remain null rather than being guessed.
  $VersionResources = Get-PEVersionStringTable -Stream $Context.Stream -Layout $Context.Layout
  $UnresolvedFields = [Collections.Generic.List[string]]::new()
  if ($Catalog.Maps.Count -eq 0) { $UnresolvedFields.Add('EmbeddedAssets') }
  if (-not $BundleType -or $BundleType -eq 'Unknown') { $UnresolvedFields.Add('BundleType') }

  return [pscustomobject]@{
    Path                         = $Context.Path
    FileKind                     = 'Executable'
    Framework                    = 'Tauri'
    Architecture                 = $Context.Architecture
    Machine                      = $Context.Layout.MachineName
    Subsystem                    = $Context.Layout.SubsystemName
    DetectionConfidence          = if ($Catalog.Maps.Count -gt 0) { 'high' } else { 'medium' }
    BundleType                   = $BundleType
    BundleTypeEvidenceConfidence = if ($BundleMarker -and $BundleMarker.IsRuntimeValue) { 'high' } elseif ($BundleMarker) { 'medium' } else { $null }
    BundleTypeMarker             = $BundleMarker
    VersionResources             = $VersionResources
    FileVersion                  = $VersionResources.FileVersion
    ProductVersion               = $VersionResources.ProductVersion
    ProductName                  = $VersionResources.ProductName
    CompanyName                  = $VersionResources.CompanyName
    FileDescription              = $VersionResources.FileDescription
    LegalCopyright               = $VersionResources.LegalCopyright
    AssetCompression             = $Catalog.Compression
    AssetMapCount                = $Catalog.Maps.Count
    AssetCount                   = $Catalog.Assets.Count
    TotalStoredBytes             = $Catalog.TotalStoredBytes
    TotalExpandedBytes           = $Catalog.TotalExpandedBytes
    ValidationWork               = $Catalog.ValidationWork
    EntryPageCandidates          = @($Catalog.Assets | Where-Object Name -Match '(?i)\.html?$' | Select-Object -ExpandProperty Name -Unique)
    AssetMaps                    = $Catalog.Maps
    AuxiliaryMaps                = $Catalog.AuxiliaryMaps
    AuxiliaryMapCount            = $Catalog.AuxiliaryMaps.Count
    AssetDescriptors             = $Catalog.Assets
    CanExpand                    = [bool]$Catalog.CanExpand
    TauriMarkerEvidence          = $Markers
    PackageIdentifierCandidates  = $PackageIdentifierCandidates
    AclPermissionCandidates      = $AclPermissionCandidates

    Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
    UnresolvedFields             = $UnresolvedFields.ToArray()
    ParserVersionInfo            = [pscustomobject]@{
      Format       = 'Tauri generated EmbeddedAssets PHF map'
      RecordWidth  = $Context.RecordSize
      PointerWidth = $Context.PointerSize
      Compression  = 'Brotli or source-supported raw bytes'
    }
  }
}

function Test-TauriExecutable {
  <#
  .SYNOPSIS
    Test whether a Windows application PE contains supported Tauri structure.
  .PARAMETER Path
    Path to a Windows application executable. Filename extension is ignored.
  .OUTPUTS
    True only when a generated asset map or sufficient source-backed framework marker evidence is present.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Context = $null
    try {
      $Context = Open-TauriExecutableContext -Path $Path
      $MarkerCatalog = Find-TauriExecutableMarker -Context $Context
      $Markers = @($MarkerCatalog.Markers)
      if (Test-TauriAssetEvidence -Context $Context -Markers $Markers) { return $true }
      $MarkerClasses = @($Markers | ForEach-Object { if ($_.Name -like 'BundleType*') { 'BundleType' } else { $_.Name } } | Select-Object -Unique)
      return $MarkerClasses.Count -ge 2
    } catch {
      return $false
    } finally {
      if ($Context) { $Context.Stream.Dispose() }
    }
  }
}

function Get-TauriExecutableInfo {
  <#
  .SYNOPSIS
    Read PE metadata and generated embedded-asset evidence from a Tauri application executable.
  .PARAMETER Path
    Path to a Windows application executable. NSIS/MSI wrappers are rejected unless the supplied PE is itself the application binary.
  .OUTPUTS
    Structured architecture, subsystem, VERSIONINFO, bundle, asset-map, candidate, notice, warning, and unresolved-field evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    $Context = Open-TauriExecutableContext -Path $Path
    try { Get-TauriExecutableInfoInternal -Context $Context }
    finally { $Context.Stream.Dispose() }
  }
}

function Expand-TauriExecutable {
  <#
  .SYNOPSIS
    Extract selected generated frontend assets from a Tauri application executable.
  .PARAMETER Path
    Path to the Tauri application PE. The path is resolved before .NET opens it.
  .PARAMETER DestinationPath
    Extraction root. Omission creates a temporary Dumplings directory.
  .PARAMETER Name
    Wildcard matched against rooted asset names, relative paths, and leaf names. Omission selects every asset.
  .PARAMETER CollisionAction
    Prompt on an actual collision, fail, skip, overwrite, or append a deterministic numeric suffix.
  .PARAMETER MaximumExpandedBytes
    Maximum cumulative bytes written for selected assets.
  .OUTPUTS
    System.IO.FileInfo[] for files written by this invocation.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 2147483648
  )

  process {
    $Context = Open-TauriExecutableContext -Path $Path
    try {
      $Info = Get-TauriExecutableInfoInternal -Context $Context
      if (-not $Info.CanExpand) { throw 'The Tauri executable does not contain one uniformly encoded, expandable generated asset map.' }
      if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
        $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) "Dumplings-Tauri-$([guid]::NewGuid().ToString('N'))"
      }
      $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
      $null = New-Item -Path $DestinationPath -ItemType Directory -Force

      # Reserve every destination before decoding so duplicate names and existing
      # files follow one consistent collision policy.
      $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      $Selections = [Collections.Generic.List[object]]::new()
      foreach ($Asset in $Info.AssetDescriptors) {
        if (-not (Test-ExtractionPattern -Path $Asset.Name -Pattern $Name)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Asset.RelativePath `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        $Selections.Add([pscustomobject]@{ Asset = $Asset; Target = $Target })
      }
      if ($Selections.Count -eq 0) { throw "No Tauri assets matched '$Name'." }

      $ExpandedBytes = 0L
      $Files = [Collections.Generic.List[IO.FileInfo]]::new()
      foreach ($Selection in $Selections) {
        if (-not $Selection.Target.ShouldWrite) { continue }
        $Asset = $Selection.Asset
        if ($null -eq $Asset.ExpandedSize -or $Asset.ExpandedSize -gt $MaximumExpandedBytes - $ExpandedBytes) {
          throw 'Tauri asset extraction exceeds the configured cumulative output limit.'
        }

        $Parent = Split-Path -Path $Selection.Target.Path -Parent
        $null = New-Item -Path $Parent -ItemType Directory -Force
        $TemporaryPath = "$($Selection.Target.Path).partial-$([guid]::NewGuid().ToString('N'))"
        try {
          $Output = [IO.File]::Open($TemporaryPath, 'CreateNew', 'Write', 'None')
          try {
            if ($Asset.StoredSize -eq 0) {
              $Written = 0L
            } else {
              $Range = New-BoundedReadStream -Stream $Context.Stream -Offset $Asset.DataOffset -Length $Asset.StoredSize -LeaveOpen
              try {
                if ($Asset.Compression -eq 'Brotli') {
                  $Decoder = [IO.Compression.BrotliStream]::new($Range, [IO.Compression.CompressionMode]::Decompress, $true)
                  try {
                    $Written = Copy-BoundedStream -Source $Decoder -Destination $Output -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes) -ExpectedBytes $Asset.ExpandedSize
                    if ($Range.Position -ne $Range.Length) { throw "The Tauri asset '$($Asset.Name)' has trailing Brotli bytes." }
                  } finally { $Decoder.Dispose() }
                } elseif ($Asset.Compression -eq 'None') {
                  $Written = Copy-BoundedStream -Source $Range -Destination $Output -MaximumBytes ($MaximumExpandedBytes - $ExpandedBytes) -ExpectedBytes $Asset.StoredSize
                } else {
                  throw "The Tauri asset '$($Asset.Name)' uses unsupported mixed compression evidence."
                }
              } finally { $Range.Dispose() }
            }
          } finally { $Output.Dispose() }

          [IO.File]::Move($TemporaryPath, $Selection.Target.Path, $true)
          $ExpandedBytes += $Written
          $Files.Add((Get-Item -LiteralPath $Selection.Target.Path -Force))
        } finally {
          Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
        }
      }
      return $Files.ToArray()
    } finally {
      $Context.Stream.Dispose()
    }
  }
}

Export-ModuleMember -Function Test-TauriExecutable, Get-TauriExecutableInfo, Expand-TauriExecutable
