# SPDX-License-Identifier: Apache-2.0
#
# Static Tauri application-executable asset parser.
# Sources:
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-codegen/src/embedded_assets.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-codegen/src/context.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-utils/src/assets.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-utils/src/platform.rs
# - https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-bundler/src/bundle.rs
# Behavioral reference only: https://github.com/Mas0nShi/tauri-dumper
#
# Binary structure consumed by this module:
#
# Windows PE image
# +-- DOS/PE/COFF headers                 machine, image base, subsystem
# +-- section table                       VA <-> file-offset mapping
# +-- VERSIONINFO resource                product/company/version strings
# `-- .rdata
#     +-- Rust PHF entry slice            one or more contiguous maps
#     |   `-- (&str, &[u8]) records
#     +-- rooted UTF-8 asset names        /index.html, /assets/app.js, ...
#     +-- Brotli or raw asset bytes       include_bytes! output
#     `-- Tauri literals                  bundle type and framework markers
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
$Script:TauriMaximumIdentifierCandidates = 128
$Script:TauriBundleMarkerPrefix = '__TAURI_BUNDLE_TYPE_VAR_'

# Compile the bounded record scanner once. Installer infrastructure has already
# been loaded by PackageModule's deterministic module order.
$TauriScannerSource = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Assets', 'Source', 'Tauri', 'TauriExecutableScanner.cs'
$null = Import-InstallerManagedSource -Path $TauriScannerSource -TypeName 'Dumplings.Tauri.TauriExecutableScanner'

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
        Name           = [string]$Section.Name
        VirtualAddress = [uint32]$Section.VirtualAddress
        RawOffset      = [uint32]$Section.RawOffset
        RawSize        = [uint32]$Section.RawSize
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
  $Stream = [IO.File]::Open($ResolvedPath, 'Open', 'Read', 'ReadWrite')
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
    if (-not ($Sections.Name -contains '.rdata')) { throw 'The PE does not contain the .rdata section required for generated Tauri assets.' }

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

function Find-TauriExecutableMarker {
  <#
  .SYNOPSIS
    Locate source-backed Tauri framework and bundle-type marker strings.
  .PARAMETER Context
    Open Tauri PE context. The function restores the stream position after every bounded search.
  .OUTPUTS
    Marker records with name, literal value, and absolute file offset.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][psobject]$Context)

  $MarkerDefinitions = @(
    [pscustomobject]@{ Name = 'AssetOrigin'; Value = 'tauri://localhost' }
    [pscustomobject]@{ Name = 'Internals'; Value = '__TAURI_INTERNALS__' }
    [pscustomobject]@{ Name = 'BundleTypeUnknown'; Value = '__TAURI_BUNDLE_TYPE_VAR_UNK' }
    [pscustomobject]@{ Name = 'BundleTypeNsis'; Value = '__TAURI_BUNDLE_TYPE_VAR_NSS' }
    [pscustomobject]@{ Name = 'BundleTypeMsi'; Value = '__TAURI_BUNDLE_TYPE_VAR_MSI' }
  )
  $Markers = [Collections.Generic.List[object]]::new()
  foreach ($Section in $Context.Sections | Where-Object Name -EQ '.rdata') {
    foreach ($Definition in $MarkerDefinitions) {
      $Pattern = [Text.Encoding]::ASCII.GetBytes($Definition.Value)
      foreach ($Offset in @(Find-BinaryPattern -Stream $Context.Stream -Pattern $Pattern -StartOffset $Section.RawOffset -Length $Section.RawSize -Maximum 32)) {
        $Markers.Add([pscustomobject]@{ Name = $Definition.Name; Value = $Definition.Value; Offset = [long]$Offset })
      }
    }
  }
  return @($Markers | Sort-Object Offset)
}

function Split-TauriAssetRecordRun {
  <#
  .SYNOPSIS
    Group scanner records into contiguous Rust PHF entry slices.
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
  foreach ($Item in $Record | Sort-Object HeaderOffset) {
    if ($Current.Count -gt 0 -and [long]$Item.HeaderOffset -ne ([long]$Current[$Current.Count - 1].HeaderOffset + $RecordSize)) {
      $Runs.Add([pscustomobject]@{ Records = $Current.ToArray() })
      $Current = [Collections.Generic.List[object]]::new()
    }
    $Current.Add($Item)
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
  .OUTPUTS
    A result containing Success, ExpandedSize, and an error string for classification.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Length,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes
  )

  return [Dumplings.Tauri.TauriExecutableScanner]::MeasureBrotli($Stream, $Offset, $Length, $MaximumExpandedBytes)
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
      $Script:TauriMaximumAssetCount
    ))
  $Runs = @(Split-TauriAssetRecordRun -Record $CandidateRecords -RecordSize $Context.RecordSize)
  $Maps = [Collections.Generic.List[object]]::new()
  $AuxiliaryMaps = [Collections.Generic.List[object]]::new()
  $Assets = [Collections.Generic.List[object]]::new()
  $Warnings = [Collections.Generic.List[string]]::new()
  $MeasuredExpandedBytes = 0L

  foreach ($Run in $Runs) {
    $Records = @($Run.Records)
    $EntryRecords = @($Records | Where-Object Name -Match '(?i)/(?:index|main)(?:\.[^/]+)?\.html?$|(?i)/index\.html?$')
    $HasFrameworkMarker = $Markers.Count -gt 0
    if ($EntryRecords.Count -eq 0 -and $Records.Count -lt 2) { continue }

    # An unsafe member inside an otherwise coherent record run means the map
    # cannot be exported completely; rejecting it avoids partial-map recovery.
    $UnsafeRecords = @($Records | Where-Object { -not $_.IsSafeName -or -not (Test-TauriAssetRelativePath -Name $_.Name) })
    if ($UnsafeRecords.Count -gt 0) {
      throw "A Tauri asset map contains an unsafe path: $($UnsafeRecords[0].Name)"
    }

    $Measurements = [Collections.Generic.List[object]]::new()
    foreach ($Record in $Records) {
      $Measurements.Add((Measure-TauriBrotliPayload -Stream $Context.Stream -Offset ([Math]::Max(0L, [long]$Record.DataOffset)) `
            -Length $Record.StoredSize -MaximumExpandedBytes $Script:TauriMaximumExpandedAssetBytes))
    }
    $BrotliCount = @($Measurements | Where-Object Success).Count
    $Compression = if ($BrotliCount -eq $Records.Count) { 'Brotli' } elseif ($BrotliCount -eq 0) { 'None' } else { 'Mixed' }

    # Raw maps need marker support or a recognizable entry page. Successful
    # Brotli framing is stronger evidence by itself but still needs either an
    # entry page, multiple coherent records, or a Tauri marker.
    $HasRawEntryPage = $false
    foreach ($EntryRecord in $EntryRecords) {
      if (Test-TauriRawEntryPage -Stream $Context.Stream -Record $EntryRecord) { $HasRawEntryPage = $true; break }
    }
    $HasRawPayloadEvidence = if ($Compression -eq 'None' -or $Compression -eq 'Mixed') {
      Test-TauriRawPayloadEvidence -Stream $Context.Stream -Record $Records
    } else { $false }
    # EmbeddedAssets also contains a PHF map from HTML paths to CspHash slices.
    # Its value word is an element count rather than a byte count, so it may look
    # like a tiny mixed-compression asset run. Catalog it separately and never
    # expose those Rust enum records as frontend file bytes.
    $IsHtmlHashMap = $Compression -eq 'Mixed' -and -not $HasRawEntryPage -and
    @($Records | Where-Object Name -NotMatch '(?i)\.html?$').Count -eq 0 -and
    [long](($Records | Measure-Object StoredSize -Maximum).Maximum ?? 0) -le 4096
    if ($IsHtmlHashMap) {
      $AuxiliaryMaps.Add([pscustomobject]@{
          Type         = 'HtmlCspHashMap'
          HeaderOffset = [long]$Records[0].HeaderOffset
          RecordCount  = $Records.Count
          Names        = @($Records.Name)
        })
      continue
    }
    if ($Compression -eq 'None' -and -not $HasRawPayloadEvidence) {
      if ($HasFrameworkMarker -and $EntryRecords.Count -gt 0) {
        $Warnings.Add("A Tauri-like asset run at 0x$($Records[0].HeaderOffset.ToString('X')) could not be validated as complete Brotli or source-supported raw data.")
      }
      continue
    }
    if ($Compression -eq 'Brotli' -and -not $HasFrameworkMarker -and $EntryRecords.Count -eq 0 -and $Records.Count -lt 2) { continue }

    $MapIndex = $Maps.Count
    $MapCanExpand = $Compression -ne 'Mixed'
    if (-not $MapCanExpand) {
      $Warnings.Add("Tauri asset map $MapIndex mixes Brotli and non-Brotli payloads; source-supported maps use one mode, so extraction is disabled.")
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
  $CanExpand = $Maps.Count -gt 0 -and -not ($Maps.CanExpand -contains $false) -and $CompressionModes.Count -eq 1
  if ($CompressionModes.Count -gt 1) {
    $CanExpand = $false
    $Warnings.Add('The executable contains generated Tauri asset maps with different compression modes; extraction is disabled pending manual review.')
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
    Warnings             = $Warnings.ToArray()
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
      $Script:TauriMaximumNameBytes, $Script:TauriMaximumStoredAssetBytes, $Script:TauriMaximumAssetCount))
  foreach ($Run in @(Split-TauriAssetRecordRun -Record $Records -RecordSize $Context.RecordSize)) {
    $RunRecords = @($Run.Records)
    if ($RunRecords | Where-Object { -not $_.IsSafeName -or -not (Test-TauriAssetRelativePath $_.Name) }) { continue }
    if ($Markers.Count -gt 0 -and $RunRecords.Count -ge 2) { return $true }
    foreach ($Entry in $RunRecords | Where-Object Name -Match '(?i)/index\.html?$') {
      $Measurement = Measure-TauriBrotliPayload -Stream $Context.Stream -Offset ([Math]::Max(0L, [long]$Entry.DataOffset)) `
        -Length $Entry.StoredSize -MaximumExpandedBytes 134217728
      if ($Measurement.Success -or (Test-TauriRawEntryPage -Stream $Context.Stream -Record $Entry)) { return $true }
    }
    if ($Markers.Count -gt 0 -and (Test-TauriRawPayloadEvidence -Stream $Context.Stream -Record $RunRecords)) { return $true }
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

  $Markers = @(Find-TauriExecutableMarker -Context $Context)
  $Catalog = Get-TauriAssetCatalog -Context $Context -Markers $Markers
  $MarkerClasses = @($Markers | ForEach-Object { if ($_.Name -like 'BundleType*') { 'BundleType' } else { $_.Name } } | Select-Object -Unique)
  if ($Catalog.Maps.Count -eq 0 -and $MarkerClasses.Count -lt 2) {
    throw 'The PE does not contain a supported generated Tauri asset map or sufficient framework marker evidence.'
  }

  $Warnings = [Collections.Generic.List[string]]::new()
  $Notices = [Collections.Generic.List[string]]::new()
  foreach ($Warning in $Catalog.Warnings) { $Warnings.Add($Warning) }
  if ($Catalog.Maps.Count -eq 0) {
    $Warnings.Add('Tauri framework markers were found, but no standard generated embedded asset map was recovered. The application may use a custom or URL-backed asset provider.')
  }

  # Tauri's bundler patches the first UNK placeholder. Retain the earliest token
  # as runtime evidence and report later conflicting literals separately.
  $BundleMarkers = @($Markers | Where-Object Name -Like 'BundleType*' | Sort-Object Offset)
  $BundleMarker = $BundleMarkers | Select-Object -First 1
  $BundleType = if ($BundleMarker) {
    switch ($BundleMarker.Value.Substring($Script:TauriBundleMarkerPrefix.Length)) {
      'NSS' { 'NSIS' }
      'MSI' { 'MSI' }
      'UNK' { 'Unknown' }
      default { 'Unknown' }
    }
  } else { $null }
  $DistinctBundleValues = @($BundleMarkers.Value | Select-Object -Unique)
  if ($DistinctBundleValues.Count -gt 1) {
    $Notices.Add("Additional Tauri bundle tokens differ from the earliest patched token at 0x$($BundleMarker.Offset.ToString('X')); the earliest token is authoritative for this evidence.")
  }

  $CandidateData = @([Dumplings.Tauri.TauriExecutableScanner]::FindIdentifierCandidates(
      $Context.Stream, $Context.Sections, $Script:TauriMaximumIdentifierCandidates, 256))
  $PackageIdentifierCandidates = @($CandidateData | Where-Object Kind -EQ 'PackageIdentifier' | ForEach-Object {
      [pscustomobject]@{ Value = $_.Value; Offset = [long]$_.Offset; Confidence = 'low'; Reason = 'Reverse-domain string in read-only PE data; ownership by Tauri config is not preserved.' }
    })
  $AclPermissionCandidates = @($CandidateData | Where-Object Kind -EQ 'AclPermission' | ForEach-Object {
      [pscustomobject]@{ Value = $_.Value; Offset = [long]$_.Offset; Confidence = 'low'; Reason = 'Tauri ACL-shaped string in read-only PE data; inclusion does not prove that the permission is granted.' }
    })
  if ($PackageIdentifierCandidates.Count -gt 0 -or $AclPermissionCandidates.Count -gt 0) {
    $Notices.Add('Identifier and ACL strings are non-authoritative candidates because optimized Rust binaries do not preserve their original configuration context.')
  }

  # VERSIONINFO is the authoritative source for the application identity strings
  # Tauri emits at build time. Missing fields remain null rather than being guessed.
  $VersionResources = Get-PEVersionStringTable -Stream $Context.Stream -Layout $Context.Layout
  $UnresolvedFields = [Collections.Generic.List[string]]::new()
  if ($Catalog.Maps.Count -eq 0) { $UnresolvedFields.Add('EmbeddedAssets') }
  if (-not $BundleType -or $BundleType -eq 'Unknown') { $UnresolvedFields.Add('BundleType') }

  return [pscustomobject]@{
    Path                        = $Context.Path
    FileKind                    = 'Executable'
    Framework                   = 'Tauri'
    Architecture                = $Context.Architecture
    Machine                     = $Context.Layout.MachineName
    Subsystem                   = $Context.Layout.SubsystemName
    DetectionConfidence         = if ($Catalog.Maps.Count -gt 0) { 'high' } else { 'medium' }
    BundleType                  = $BundleType
    BundleTypeMarker            = $BundleMarker
    VersionResources            = $VersionResources
    FileVersion                 = $VersionResources.FileVersion
    ProductVersion              = $VersionResources.ProductVersion
    ProductName                 = $VersionResources.ProductName
    CompanyName                 = $VersionResources.CompanyName
    FileDescription             = $VersionResources.FileDescription
    LegalCopyright              = $VersionResources.LegalCopyright
    AssetCompression            = $Catalog.Compression
    AssetMapCount               = $Catalog.Maps.Count
    AssetCount                  = $Catalog.Assets.Count
    TotalStoredBytes            = $Catalog.TotalStoredBytes
    TotalExpandedBytes          = $Catalog.TotalExpandedBytes
    EntryPageCandidates         = @($Catalog.Assets | Where-Object Name -Match '(?i)\.html?$' | Select-Object -ExpandProperty Name -Unique)
    AssetMaps                   = $Catalog.Maps
    AuxiliaryMaps               = $Catalog.AuxiliaryMaps
    AuxiliaryMapCount           = $Catalog.AuxiliaryMaps.Count
    AssetDescriptors            = $Catalog.Assets
    CanExpand                   = [bool]$Catalog.CanExpand
    TauriMarkerEvidence         = $Markers
    PackageIdentifierCandidates = $PackageIdentifierCandidates
    AclPermissionCandidates     = $AclPermissionCandidates
    Notices                     = $Notices.ToArray()
    Warnings                    = $Warnings.ToArray()
    UnresolvedFields            = $UnresolvedFields.ToArray()
    ParserVersionInfo           = [pscustomobject]@{
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
      $Markers = @(Find-TauriExecutableMarker -Context $Context)
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
